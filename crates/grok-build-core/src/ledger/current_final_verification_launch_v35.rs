//! Additive schema-v35 final-verifier launch and capture-intent authority.
//!
//! A fresh atomic commit binds one exact schema-v34 operational attempt to
//! every later lifecycle reservation, exact command and authority inputs, and
//! a real `LaunchCommitted` event.  The returned capture-acquisition permit is
//! private and move-only.  Replays and restart readback never recreate it.
//! This module does not acquire capture storage, spawn a runner, initialize
//! V13, dispatch a command, or route production work.

use std::cell::RefCell;
use std::collections::BTreeSet;
use std::fmt::{self, Debug, Formatter};

use rusqlite::{Connection, OptionalExtension, Transaction, TransactionBehavior, params};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

use crate::{
    CommandOutputArtifactSourceV1, CommandOutputCaptureIntentV1, CommandSpec,
    CompiledExecutionPolicy, ContractError, CurrentFinalVerificationAuthorityEventKindV1,
    CurrentFinalVerificationAuthorityEventV1, CurrentFinalVerificationLifecycleReservationFieldsV2,
    CurrentFinalVerificationLifecycleReservationSetV2,
    CurrentFinalVerificationNativeContainmentBackendV2, Digest, ExecutionNetwork, ExecutionPolicy,
    IssuedWorkspaceGrant, MAX_CURRENT_FINAL_VERIFICATION_CANONICAL_BYTES_V2,
    MAX_CURRENT_FINAL_VERIFICATION_IDENTIFIER_BYTES_V2, MutationMode,
    OperationalCurrentFinalVerificationAttemptV1,
    PersistedOperationalCurrentFinalVerificationAttemptV1,
    SensitiveOutputDetectionPolicyReferenceV1, SprintSpecV2, WorkspaceGrant,
    validate_current_direct_exec_command_v1,
};

use super::{EventLedger, LedgerError, secure_database_files};

pub(super) const MIGRATION_V35: &str = include_str!("current_final_verification_launch_v35.sql");

const LAUNCH_VERSION_V1: u32 = 1;
const RUNNER_PROTOCOL_VERSION_V13: u32 = 13;
const LAUNCH_REQUEST_DIGEST_DOMAIN_V1: &[u8] =
    b"grok-build/current-final-verification-launch-request-v1/canonical-json\0";
const LAUNCH_PREPARATION_DIGEST_DOMAIN_V1: &[u8] =
    b"grok-build/current-final-verification-launch-preparation-v1/canonical-json\0";
const LAUNCH_AUTHORITY_DIGEST_DOMAIN_V1: &[u8] =
    b"grok-build/current-final-verification-launch-authority-v1/canonical-json\0";
const LIFECYCLE_RESERVATION_ID_DOMAIN_V1: &[u8] =
    b"grok-build/current-final-verification-lifecycle-reservation-v1/id\0";

/// Computes the exact plain-SHA-256 request digest required by the V13
/// final-verifier command envelope.
///
/// This is intentionally distinct from the domain-separated operational
/// command digest. Keeping both commitments prevents a later wire adapter from
/// silently substituting one digest domain for the other.
///
/// # Errors
///
/// Returns an error when the command is invalid or cannot be canonically
/// encoded.
pub fn current_final_verification_v13_command_request_digest(
    command: &CommandSpec,
) -> Result<Digest, ContractError> {
    validate_current_direct_exec_command_v1(command)?;
    Ok(Digest::sha256(&encode_canonical(command)?))
}

/// Computes the exact dispatch-claim identity used by output-capture V1 and
/// the V13 wire contract for one reserved effect.
///
/// # Errors
///
/// Returns an error when `effect_id` is not one canonical core identity.
pub fn current_final_verification_dispatch_claim_id(
    effect_id: &str,
) -> Result<String, ContractError> {
    require_core_identity("current_final_verification.effect_id", effect_id)?;
    Ok(super::command_output_capture_authority::expected_dispatch_claim_id(effect_id))
}

impl CurrentFinalVerificationNativeContainmentBackendV2 {
    const fn launch_sql_kind(self) -> &'static str {
        match self {
            Self::MacOsDedicatedIdentitySeatbelt => "MacOsDedicatedIdentitySeatbelt",
            Self::LinuxBubblewrapLandlockSeccompCgroupV2 => {
                "LinuxBubblewrapLandlockSeccompCgroupV2"
            }
        }
    }
}

/// Exact logical native launch plan committed before physical capture work.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CurrentFinalVerificationLaunchPreparationV1 {
    /// Contract discriminator.
    pub preparation_version: u32,
    /// Stable identity of this exact logical preparation.
    pub preparation_id: String,
    /// Selected native containment family.
    pub containment_backend: CurrentFinalVerificationNativeContainmentBackendV2,
    /// Exact target image/manifest identity.
    pub target_identity_digest: Digest,
    /// Exact compiled native containment-policy identity.
    pub native_policy_digest: Digest,
    /// Content digest of the admitted runner binary.
    pub runner_binary_digest: Digest,
    /// Exact runner-binary byte length.
    pub runner_binary_size_bytes: u64,
    /// Closed current runner wire version; v35 admits only V13.
    pub runner_protocol_version: u32,
    /// Exact protocol/schema identity.
    pub runner_protocol_digest: Digest,
    /// Stable private-state namespace identity.
    pub private_state_id: String,
    /// Exact private-state identity digest.
    pub private_state_digest: Digest,
}

impl CurrentFinalVerificationLaunchPreparationV1 {
    fn validate(&self) -> Result<(), ContractError> {
        require_version(
            "launch_preparation.preparation_version",
            self.preparation_version,
        )?;
        require_identifier("launch_preparation.preparation_id", &self.preparation_id)?;
        require_identifier(
            "launch_preparation.private_state_id",
            &self.private_state_id,
        )?;
        if self.runner_binary_size_bytes == 0 {
            return Err(ContractError::new(
                "launch_preparation.runner_binary_size_bytes",
                "must be greater than zero",
            ));
        }
        if self.runner_protocol_version != RUNNER_PROTOCOL_VERSION_V13 {
            return Err(ContractError::new(
                "launch_preparation.runner_protocol_version",
                format!("must equal current runner wire V{RUNNER_PROTOCOL_VERSION_V13}"),
            ));
        }
        require_canonical_bound("launch_preparation", &encode_canonical(self)?)
    }

    fn canonical_digest(&self) -> Result<Digest, ContractError> {
        self.validate()?;
        Ok(domain_digest(
            LAUNCH_PREPARATION_DIGEST_DOMAIN_V1,
            &encode_canonical(self)?,
        ))
    }
}

/// Sealed proof that a trusted native-admission boundary authenticated one
/// exact launch preparation.
///
/// Schema v35 intentionally provides no production constructor. A later
/// native-admission tranche must mint this move-only value from its own exact
/// admitted plan/assets parent; it does not claim that native preparation,
/// release, or cleanup has occurred. A caller-authored plan DTO can never
/// substitute.
#[derive(Debug)]
#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "schema-v35 launch is deliberately unreachable until native admission supplies the sealed production constructor"
    )
)]
pub(crate) struct AuthenticatedCurrentFinalVerificationNativePreparationV1 {
    preparation: CurrentFinalVerificationLaunchPreparationV1,
}

impl AuthenticatedCurrentFinalVerificationNativePreparationV1 {
    #[cfg_attr(
        not(test),
        expect(
            dead_code,
            reason = "schema-v35 launch is deliberately unreachable until native admission supplies the sealed production constructor"
        )
    )]
    fn contract(&self) -> &CurrentFinalVerificationLaunchPreparationV1 {
        &self.preparation
    }

    #[cfg(test)]
    fn from_test(preparation: CurrentFinalVerificationLaunchPreparationV1) -> Self {
        Self { preparation }
    }
}

/// Idempotent input for one exact final-verifier launch commit.
///
/// The plain plan, grant, and policy are canonical persisted values. A fresh
/// commit additionally consumes an authenticated native-plan token plus the
/// unforgeable [`IssuedWorkspaceGrant`] and [`CompiledExecutionPolicy`]
/// wrappers; this DTO alone grants no authority.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CurrentFinalVerificationLaunchRequestV1 {
    /// Contract discriminator.
    pub launch_request_version: u32,
    /// Stable idempotency identity.
    pub launch_request_id: String,
    /// Exact schema-v34 operational attempt.
    pub attempt_id: String,
    /// Digest of the exact schema-v34 operational overlay.
    pub operational_attempt_digest: Digest,
    /// Exact logical/admitted native launch-plan contract.
    pub launch_preparation: CurrentFinalVerificationLaunchPreparationV1,
    /// Exact current sprint workspace grant.
    pub workspace_grant: WorkspaceGrant,
    /// Exact compiler-produced execution policy contract.
    pub execution_policy: ExecutionPolicy,
    /// Exact repository-wide command; no shell string is accepted.
    pub exact_command: CommandSpec,
    /// Exact fixed public sensitive-output detector identity.
    pub detector_policy: SensitiveOutputDetectionPolicyReferenceV1,
    /// Exact aggregate stdout/stderr ceiling.
    pub max_aggregate_output_bytes: u64,
    /// Durable launch-commit timestamp.
    pub committed_at_unix_ms: u64,
}

impl CurrentFinalVerificationLaunchRequestV1 {
    fn validate_intrinsic(&self) -> Result<(), ContractError> {
        require_version(
            "launch_request.launch_request_version",
            self.launch_request_version,
        )?;
        require_identifier("launch_request.launch_request_id", &self.launch_request_id)?;
        require_identifier("launch_request.attempt_id", &self.attempt_id)?;
        self.launch_preparation.validate()?;
        self.workspace_grant.validate()?;
        self.execution_policy
            .validate_against(&self.workspace_grant)?;
        if self.execution_policy.mutation_mode != MutationMode::ReadOnly
            || !self.execution_policy.write_scopes.is_empty()
            || self.execution_policy.network != ExecutionNetwork::None
        {
            return Err(ContractError::new(
                "launch_request.execution_policy",
                "current final-verifier launch requires ReadOnly mutation, no write scopes, and no command network",
            ));
        }
        if self.execution_policy.computed_hash()? != self.execution_policy.policy_hash {
            return Err(ContractError::new(
                "launch_request.execution_policy.policy_hash",
                "does not authenticate the exact execution policy",
            ));
        }
        validate_current_direct_exec_command_v1(&self.exact_command)?;
        self.detector_policy.validate()?;
        let expected_capture_maximum = super::current_command_output_capture_maximum_v1(
            self.execution_policy.resource_limits.max_output_bytes,
        )?;
        if self.max_aggregate_output_bytes != expected_capture_maximum {
            return Err(ContractError::new(
                "launch_request.max_aggregate_output_bytes",
                "must equal the core-derived V1 capture ceiling for the exact execution-policy output limit",
            ));
        }
        if self.launch_preparation.containment_backend
            == CurrentFinalVerificationNativeContainmentBackendV2::MacOsDedicatedIdentitySeatbelt
            && self
                .execution_policy
                .resource_limits
                .max_memory_bytes
                .is_some()
        {
            return Err(ContractError::new(
                "launch_request.execution_policy.resource_limits.max_memory_bytes",
                "macOS dedicated-identity containment cannot claim a finite aggregate memory ceiling",
            ));
        }
        if self.committed_at_unix_ms == 0 {
            return Err(ContractError::new(
                "launch_request.committed_at_unix_ms",
                "must be greater than zero",
            ));
        }
        require_canonical_bound("launch_request", &encode_canonical(self)?)
    }

    fn canonical_bytes(&self) -> Result<Vec<u8>, ContractError> {
        self.validate_intrinsic()?;
        encode_canonical(self)
    }

    fn canonical_digest(&self) -> Result<Digest, ContractError> {
        Ok(domain_digest(
            LAUNCH_REQUEST_DIGEST_DOMAIN_V1,
            &self.canonical_bytes()?,
        ))
    }
}

fn derive_v13_capture_intent(
    sprint_id: &str,
    reservations: &CurrentFinalVerificationLifecycleReservationSetV2,
    request: &CurrentFinalVerificationLaunchRequestV1,
) -> Result<CommandOutputCaptureIntentV1, ContractError> {
    let fields = &reservations.fields;
    CommandOutputCaptureIntentV1::try_new(
        fields.capture_id.clone(),
        CommandOutputArtifactSourceV1 {
            sprint_id: sprint_id.to_owned(),
            runner_launch_id: fields.runner_launch_id.clone(),
            runner_session_id: fields.runner_session_id.clone(),
            effect_id: fields.effect_id.clone(),
            request_digest: current_final_verification_v13_command_request_digest(
                &request.exact_command,
            )?,
        },
        request.launch_preparation.private_state_digest.clone(),
        request.max_aggregate_output_bytes,
        request.committed_at_unix_ms,
    )
}

/// Immutable launch authority reconstructed from schema v35.
///
/// This is exact readback.  It is not itself a process, capture, or dispatch
/// permit.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CurrentFinalVerificationLaunchAuthorityV1 {
    /// Contract discriminator.
    pub launch_version: u32,
    /// Owning current sprint.
    pub sprint_id: String,
    /// Exact current task graph.
    pub task_graph_id: String,
    /// Exact operational attempt.
    pub attempt_id: String,
    /// Exact schema-v32 admission identity bound by the operational overlay.
    pub final_verification_admission_id: String,
    /// Exact current sprint specification digest.
    pub sprint_spec_digest: Digest,
    /// Exact current graph digest.
    pub task_graph_digest: Digest,
    /// Exact reciprocal graph-payload digest.
    pub task_graph_payload_digest: Digest,
    /// Exact immutable repair-slot reserve.
    pub repair_slot_reserve_digest: Digest,
    /// Exact schema-v34 operational-attempt authority digest.
    pub operational_attempt_digest: Digest,
    /// Exact complete current `TaskDone` set.
    pub complete_task_done_set_digest: Digest,
    /// Exact complete current criterion-evidence set.
    pub complete_criterion_evidence_set_digest: Digest,
    /// Exact verification snapshot.
    pub input_snapshot: Digest,
    /// Exact schema-v34 admission event, never the diagnostic v32 ordinal.
    pub authority_admitted_event_id: String,
    /// Exact real schema-v34 admission event sequence.
    pub authority_admitted_event_sequence: u64,
    /// Idempotency identity of the exact launch request.
    pub launch_request_id: String,
    /// Digest of the exact canonical launch request.
    pub launch_request_digest: Digest,
    /// Exact caller-supplied logical launch preparation, authenticated only
    /// after the sealed token and durable joins are validated.
    pub launch_preparation: CurrentFinalVerificationLaunchPreparationV1,
    /// Digest of the exact launch preparation.
    pub launch_preparation_digest: Digest,
    /// Complete core-minted lifecycle reservation set.
    pub reservations: CurrentFinalVerificationLifecycleReservationSetV2,
    /// Exact preallocated output-capture intent.
    pub capture_intent: CommandOutputCaptureIntentV1,
    /// Exact current sprint workspace grant.
    pub workspace_grant: WorkspaceGrant,
    /// Exact compiler-produced execution policy contract.
    pub execution_policy: ExecutionPolicy,
    /// Exact repository-wide command.
    pub exact_command: CommandSpec,
    /// Digest of the exact command under the operational command domain.
    pub verification_command_digest: Digest,
    /// Plain SHA-256 of the exact canonical command required by V13.
    pub v13_command_request_digest: Digest,
    /// Exact fixed public detector identity.
    pub detector_policy: SensitiveOutputDetectionPolicyReferenceV1,
    /// Exact aggregate stdout/stderr ceiling.
    pub max_aggregate_output_bytes: u64,
    /// Real durable `LaunchCommitted` event identity.
    pub launch_event_id: String,
    /// Real contiguous sprint-local launch event sequence.
    pub launch_event_sequence: u64,
    /// Durable launch commit time.
    pub committed_at_unix_ms: u64,
    /// Domain-separated digest of every preceding field.
    pub launch_authority_digest: Digest,
}

#[derive(Serialize)]
struct LaunchAuthorityDigestPreimageV1<'a> {
    launch_version: u32,
    sprint_id: &'a str,
    task_graph_id: &'a str,
    attempt_id: &'a str,
    final_verification_admission_id: &'a str,
    sprint_spec_digest: &'a Digest,
    task_graph_digest: &'a Digest,
    task_graph_payload_digest: &'a Digest,
    repair_slot_reserve_digest: &'a Digest,
    operational_attempt_digest: &'a Digest,
    complete_task_done_set_digest: &'a Digest,
    complete_criterion_evidence_set_digest: &'a Digest,
    input_snapshot: &'a Digest,
    authority_admitted_event_id: &'a str,
    authority_admitted_event_sequence: u64,
    launch_request_id: &'a str,
    launch_request_digest: &'a Digest,
    launch_preparation: &'a CurrentFinalVerificationLaunchPreparationV1,
    launch_preparation_digest: &'a Digest,
    reservations: &'a CurrentFinalVerificationLifecycleReservationSetV2,
    capture_intent: &'a CommandOutputCaptureIntentV1,
    workspace_grant: &'a WorkspaceGrant,
    execution_policy: &'a ExecutionPolicy,
    exact_command: &'a CommandSpec,
    verification_command_digest: &'a Digest,
    v13_command_request_digest: &'a Digest,
    detector_policy: &'a SensitiveOutputDetectionPolicyReferenceV1,
    max_aggregate_output_bytes: u64,
    launch_event_id: &'a str,
    launch_event_sequence: u64,
    committed_at_unix_ms: u64,
}

impl CurrentFinalVerificationLaunchAuthorityV1 {
    #[cfg_attr(
        not(test),
        expect(
            dead_code,
            reason = "schema-v35 launch authority is dormant until the sealed native-admission tranche is connected"
        )
    )]
    fn new(
        operational: &OperationalCurrentFinalVerificationAttemptV1,
        sprint: &SprintSpecV2,
        request: &CurrentFinalVerificationLaunchRequestV1,
        launch_request_digest: Digest,
        reservations: CurrentFinalVerificationLifecycleReservationSetV2,
        event: &CurrentFinalVerificationAuthorityEventV1,
    ) -> Result<Self, ContractError> {
        let overlay = operational;
        let launch_preparation_digest = request.launch_preparation.canonical_digest()?;
        let capture_intent = derive_v13_capture_intent(&overlay.sprint_id, &reservations, request)?;
        let verification_command_digest = operational_command_digest(&request.exact_command)?;
        let v13_command_request_digest =
            current_final_verification_v13_command_request_digest(&request.exact_command)?;
        let mut authority = Self {
            launch_version: LAUNCH_VERSION_V1,
            sprint_id: overlay.sprint_id.clone(),
            task_graph_id: overlay.task_graph_id.clone(),
            attempt_id: overlay.attempt_id.clone(),
            final_verification_admission_id: overlay.final_verification_admission_id.clone(),
            sprint_spec_digest: overlay.sprint_spec_digest.clone(),
            task_graph_digest: overlay.task_graph_digest.clone(),
            task_graph_payload_digest: overlay.task_graph_payload_digest.clone(),
            repair_slot_reserve_digest: overlay.repair_slot_reserve_digest.clone(),
            operational_attempt_digest: overlay.operational_attempt_digest.clone(),
            complete_task_done_set_digest: overlay.complete_task_done_set_digest.clone(),
            complete_criterion_evidence_set_digest: overlay
                .complete_criterion_evidence_set_digest
                .clone(),
            input_snapshot: overlay.input_snapshot.clone(),
            authority_admitted_event_id: overlay.admission_event_id.clone(),
            authority_admitted_event_sequence: overlay.admission_event_sequence,
            launch_request_id: request.launch_request_id.clone(),
            launch_request_digest,
            launch_preparation: request.launch_preparation.clone(),
            launch_preparation_digest,
            reservations,
            capture_intent,
            workspace_grant: request.workspace_grant.clone(),
            execution_policy: request.execution_policy.clone(),
            exact_command: request.exact_command.clone(),
            verification_command_digest,
            v13_command_request_digest,
            detector_policy: request.detector_policy.clone(),
            max_aggregate_output_bytes: request.max_aggregate_output_bytes,
            launch_event_id: event.event_id.clone(),
            launch_event_sequence: event.event_sequence,
            committed_at_unix_ms: request.committed_at_unix_ms,
            launch_authority_digest: Digest::sha256(&[]),
        };
        authority.launch_authority_digest = authority.computed_digest()?;
        authority.validate_for(operational, sprint, request, event)?;
        Ok(authority)
    }

    fn digest_preimage(&self) -> LaunchAuthorityDigestPreimageV1<'_> {
        LaunchAuthorityDigestPreimageV1 {
            launch_version: self.launch_version,
            sprint_id: &self.sprint_id,
            task_graph_id: &self.task_graph_id,
            attempt_id: &self.attempt_id,
            final_verification_admission_id: &self.final_verification_admission_id,
            sprint_spec_digest: &self.sprint_spec_digest,
            task_graph_digest: &self.task_graph_digest,
            task_graph_payload_digest: &self.task_graph_payload_digest,
            repair_slot_reserve_digest: &self.repair_slot_reserve_digest,
            operational_attempt_digest: &self.operational_attempt_digest,
            complete_task_done_set_digest: &self.complete_task_done_set_digest,
            complete_criterion_evidence_set_digest: &self.complete_criterion_evidence_set_digest,
            input_snapshot: &self.input_snapshot,
            authority_admitted_event_id: &self.authority_admitted_event_id,
            authority_admitted_event_sequence: self.authority_admitted_event_sequence,
            launch_request_id: &self.launch_request_id,
            launch_request_digest: &self.launch_request_digest,
            launch_preparation: &self.launch_preparation,
            launch_preparation_digest: &self.launch_preparation_digest,
            reservations: &self.reservations,
            capture_intent: &self.capture_intent,
            workspace_grant: &self.workspace_grant,
            execution_policy: &self.execution_policy,
            exact_command: &self.exact_command,
            verification_command_digest: &self.verification_command_digest,
            v13_command_request_digest: &self.v13_command_request_digest,
            detector_policy: &self.detector_policy,
            max_aggregate_output_bytes: self.max_aggregate_output_bytes,
            launch_event_id: &self.launch_event_id,
            launch_event_sequence: self.launch_event_sequence,
            committed_at_unix_ms: self.committed_at_unix_ms,
        }
    }

    fn computed_digest(&self) -> Result<Digest, ContractError> {
        Ok(domain_digest(
            LAUNCH_AUTHORITY_DIGEST_DOMAIN_V1,
            &encode_canonical(&self.digest_preimage())?,
        ))
    }

    #[allow(
        clippy::too_many_lines,
        reason = "the launch validator crosses every immutable authority edge explicitly"
    )]
    fn validate_for(
        &self,
        operational: &OperationalCurrentFinalVerificationAttemptV1,
        sprint: &SprintSpecV2,
        request: &CurrentFinalVerificationLaunchRequestV1,
        event: &CurrentFinalVerificationAuthorityEventV1,
    ) -> Result<(), ContractError> {
        require_version("launch_authority.launch_version", self.launch_version)?;
        event.validate_integrity()?;
        request.validate_intrinsic()?;
        self.launch_preparation.validate()?;
        self.reservations.validate_integrity().map_err(|error| {
            ContractError::new("launch_authority.reservations", error.to_string())
        })?;
        self.capture_intent.validate()?;
        let overlay = operational;
        let expected_request_digest = request.canonical_digest()?;
        let expected_reservations =
            derive_lifecycle_reservations(&operational.attempt_id, &expected_request_digest)?;
        let expected_command_digest = operational_command_digest(&request.exact_command)?;
        let expected_v13_command_digest =
            current_final_verification_v13_command_request_digest(&request.exact_command)?;
        let expected_capture_intent =
            derive_v13_capture_intent(&overlay.sprint_id, &expected_reservations, request)?;
        let expected_event_sequence =
            overlay
                .admission_event_sequence
                .checked_add(1)
                .ok_or_else(|| {
                    ContractError::new(
                        "launch_authority.launch_event_sequence",
                        "event sequence overflowed",
                    )
                })?;
        if self.sprint_id != overlay.sprint_id
            || self.task_graph_id != overlay.task_graph_id
            || self.attempt_id != overlay.attempt_id
            || self.final_verification_admission_id != overlay.final_verification_admission_id
            || self.sprint_spec_digest != overlay.sprint_spec_digest
            || self.task_graph_digest != overlay.task_graph_digest
            || self.task_graph_payload_digest != overlay.task_graph_payload_digest
            || self.repair_slot_reserve_digest != overlay.repair_slot_reserve_digest
            || self.operational_attempt_digest != overlay.operational_attempt_digest
            || self.complete_task_done_set_digest != overlay.complete_task_done_set_digest
            || self.complete_criterion_evidence_set_digest
                != overlay.complete_criterion_evidence_set_digest
            || self.input_snapshot != overlay.input_snapshot
            || self.authority_admitted_event_id != overlay.admission_event_id
            || self.authority_admitted_event_sequence != overlay.admission_event_sequence
            || self.launch_request_id != request.launch_request_id
            || self.launch_request_id == overlay.request_id
            || self.launch_request_digest != expected_request_digest
            || self.launch_preparation != request.launch_preparation
            || self.launch_preparation_digest != request.launch_preparation.canonical_digest()?
            || self.reservations != expected_reservations
            || self.capture_intent != expected_capture_intent
            || self.workspace_grant != request.workspace_grant
            || self.workspace_grant != sprint.workspace_grant
            || self.workspace_grant.grant_hash != overlay.workspace_grant_hash
            || self.execution_policy != request.execution_policy
            || self.execution_policy.policy_hash != overlay.execution_policy_digest
            || self.exact_command != request.exact_command
            || self.verification_command_digest != expected_command_digest
            || self.verification_command_digest != overlay.verification_command_digest
            || self.v13_command_request_digest != expected_v13_command_digest
            || self.capture_intent.source.request_digest != expected_v13_command_digest
            || self.detector_policy != request.detector_policy
            || self.max_aggregate_output_bytes != request.max_aggregate_output_bytes
            || self.launch_event_id != event.event_id
            || self.launch_event_sequence != event.event_sequence
            || self.launch_event_sequence != expected_event_sequence
            || self.committed_at_unix_ms != request.committed_at_unix_ms
            || request.attempt_id != overlay.attempt_id
            || request.operational_attempt_digest != overlay.operational_attempt_digest
            || request.committed_at_unix_ms < overlay.admitted_at_unix_ms
            || event.event_kind != CurrentFinalVerificationAuthorityEventKindV1::LaunchCommitted
            || event.sprint_id != overlay.sprint_id
            || event.attempt_id != overlay.attempt_id
            || event.request_id != request.launch_request_id
            || event.request_digest != expected_request_digest
            || event.occurred_at_unix_ms != request.committed_at_unix_ms
            || event.event_id == overlay.admission_event_id
            || reservation_ids(&self.reservations.fields).contains(event.event_id.as_str())
            || self.launch_authority_digest != self.computed_digest()?
        {
            return Err(ContractError::new(
                "launch_authority",
                "crosses the exact operational attempt, sprint, request, reservations, or launch event",
            ));
        }
        require_canonical_bound("launch_authority", &encode_canonical(self)?)
    }

    /// Projects the exact store-independent V1 capture intent required by the
    /// V13 runner seam. This derives no new authority and performs no I/O.
    ///
    /// # Errors
    ///
    /// Returns an error if the persisted authority or derived capture contract
    /// is malformed.
    pub fn v13_command_output_capture_intent(
        &self,
    ) -> Result<CommandOutputCaptureIntentV1, ContractError> {
        if self.launch_authority_digest != self.computed_digest()? {
            return Err(ContractError::new(
                "launch_authority.launch_authority_digest",
                "does not authenticate the exact launch authority",
            ));
        }
        self.reservations.validate_integrity().map_err(|error| {
            ContractError::new("launch_authority.reservations", error.to_string())
        })?;
        self.capture_intent.validate()?;
        let expected = CommandOutputCaptureIntentV1::try_new(
            self.reservations.fields.capture_id.clone(),
            CommandOutputArtifactSourceV1 {
                sprint_id: self.sprint_id.clone(),
                runner_launch_id: self.reservations.fields.runner_launch_id.clone(),
                runner_session_id: self.reservations.fields.runner_session_id.clone(),
                effect_id: self.reservations.fields.effect_id.clone(),
                request_digest: self.v13_command_request_digest.clone(),
            },
            self.launch_preparation.private_state_digest.clone(),
            self.max_aggregate_output_bytes,
            self.committed_at_unix_ms,
        )?;
        if self.capture_intent != expected
            || self.capture_intent.source.request_digest
                != current_final_verification_v13_command_request_digest(&self.exact_command)?
        {
            return Err(ContractError::new(
                "launch_authority.v13_command_request_digest",
                "does not bind the exact canonical command",
            ));
        }
        Ok(self.capture_intent.clone())
    }

    #[cfg_attr(
        not(test),
        expect(
            dead_code,
            reason = "schema-v35 launch authority is dormant until the sealed native-admission tranche is connected"
        )
    )]
    fn canonical_bytes(&self) -> Result<Vec<u8>, ContractError> {
        if self.launch_authority_digest != self.computed_digest()? {
            return Err(ContractError::new(
                "launch_authority.launch_authority_digest",
                "does not authenticate the exact launch authority",
            ));
        }
        require_canonical_bound("launch_authority", &encode_canonical(self)?)?;
        encode_canonical(self)
    }
}

/// Exact durable readback of one launch commit.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PersistedCurrentFinalVerificationLaunchV1 {
    /// Exact operational parent; diagnostic schema-v32 outcome is absent.
    pub operational_attempt: PersistedOperationalCurrentFinalVerificationAttemptV1,
    /// Real `LaunchCommitted` event.
    pub launch_event: CurrentFinalVerificationAuthorityEventV1,
    /// Exact immutable launch authority.
    pub launch_authority: CurrentFinalVerificationLaunchAuthorityV1,
}

/// Move-only authority for the next physical capture-acquisition step.
///
/// Only a fresh atomic launch commit can construct this value.  It cannot be
/// cloned, serialized, loaded, or recreated from identifiers.
pub struct FreshCurrentFinalVerificationCaptureAcquisitionPermitV1 {
    attempt_id: String,
    launch_authority_digest: Digest,
    capture_intent_id: String,
    capture_id: String,
    capture_intent_digest: Digest,
    #[cfg_attr(
        not(test),
        expect(
            dead_code,
            reason = "the fresh permit has no consumer until physical capture acquisition is implemented"
        )
    )]
    ledger_instance_id: u64,
}

impl Debug for FreshCurrentFinalVerificationCaptureAcquisitionPermitV1 {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FreshCurrentFinalVerificationCaptureAcquisitionPermitV1")
            .field("authority", &"<redacted move-only permit>")
            .finish()
    }
}

impl FreshCurrentFinalVerificationCaptureAcquisitionPermitV1 {
    #[cfg(test)]
    pub(super) fn duplicate_for_test(&self) -> Self {
        Self {
            attempt_id: self.attempt_id.clone(),
            launch_authority_digest: self.launch_authority_digest.clone(),
            capture_intent_id: self.capture_intent_id.clone(),
            capture_id: self.capture_id.clone(),
            capture_intent_digest: self.capture_intent_digest.clone(),
            ledger_instance_id: self.ledger_instance_id,
        }
    }

    /// Exact operational attempt authorized for capture acquisition.
    #[must_use]
    pub fn attempt_id(&self) -> &str {
        &self.attempt_id
    }

    /// Exact launch authority that must be reopened by the future consumer.
    #[must_use]
    pub const fn launch_authority_digest(&self) -> &Digest {
        &self.launch_authority_digest
    }

    /// Exact preallocated capture intent the future consumer must acquire.
    #[must_use]
    pub fn capture_intent_id(&self) -> &str {
        &self.capture_intent_id
    }

    /// Exact physical V1 capture identity authorized by this fresh cut.
    #[must_use]
    pub fn capture_id(&self) -> &str {
        &self.capture_id
    }

    /// Exact V1 capture-intent digest the acquisition must consume.
    #[must_use]
    pub const fn capture_intent_digest(&self) -> &Digest {
        &self.capture_intent_digest
    }

    /// Consumes this permit only for the exact in-memory ledger instance and
    /// durable launch readback that minted it.
    #[cfg_attr(
        not(test),
        expect(
            dead_code,
            reason = "the fresh permit has no consumer until physical capture acquisition is implemented"
        )
    )]
    pub(super) fn consume_for_ledger_instance(
        self,
        ledger_instance_id: u64,
        launch: &PersistedCurrentFinalVerificationLaunchV1,
    ) -> Result<(), LedgerError> {
        self.validate_for_ledger_instance(ledger_instance_id, launch)
    }

    /// Borrows this move-only permit for an atomic next-stage preflight.
    /// Ownership remains with that stage so a definitely-precommit failure can
    /// return the exact capability instead of silently dropping custody.
    pub(super) fn validate_for_ledger_instance(
        &self,
        ledger_instance_id: u64,
        launch: &PersistedCurrentFinalVerificationLaunchV1,
    ) -> Result<(), LedgerError> {
        let authority = &launch.launch_authority;
        if self.ledger_instance_id != ledger_instance_id
            || self.attempt_id != authority.attempt_id
            || self.launch_authority_digest != authority.launch_authority_digest
            || self.capture_intent_id != authority.reservations.fields.capture_intent_id
            || self.capture_id != authority.capture_intent.capture_id
            || self.capture_intent_digest != authority.capture_intent.intent_digest
        {
            return Err(mismatch(
                "fresh current final-verification capture-acquisition permit",
                "permit crosses its exact ledger instance or persisted V1 capture intent",
            ));
        }
        Ok(())
    }
}

/// Fresh-versus-replay result of one launch-commit request.
pub enum CurrentFinalVerificationLaunchCommitV1 {
    /// One exact fresh commit and its sole move-only next-step permit.
    Fresh {
        /// Exact durable readback.
        persisted: PersistedCurrentFinalVerificationLaunchV1,
        /// Sole in-memory permission to attempt physical capture acquisition.
        capture_acquisition_permit: FreshCurrentFinalVerificationCaptureAcquisitionPermitV1,
    },
    /// Exact idempotent readback; no physical capability is returned.
    Replay {
        /// Exact durable readback.
        persisted: PersistedCurrentFinalVerificationLaunchV1,
    },
}

impl CurrentFinalVerificationLaunchCommitV1 {
    /// Borrows the exact durable launch readback in either disposition.
    #[must_use]
    pub const fn persisted(&self) -> &PersistedCurrentFinalVerificationLaunchV1 {
        match self {
            Self::Fresh { persisted, .. } | Self::Replay { persisted } => persisted,
        }
    }

    /// Returns true only for the one call that committed the launch.
    #[must_use]
    pub const fn is_fresh(&self) -> bool {
        matches!(self, Self::Fresh { .. })
    }
}

impl EventLedger {
    /// Commits one exact current final-verifier launch boundary.
    ///
    /// This crate-private API is deliberately dormant in v35: its sealed
    /// native-preparation token has no production constructor. A fresh commit
    /// returns the sole move-only permit for the future capture-acquisition
    /// tranche. Exact replay returns durable readback only.
    ///
    /// # Errors
    ///
    /// Returns an error for read-only use, stale or crossed authority, an
    /// unauthenticated grant/policy/preparation, noncanonical input, identity
    /// replay, migration corruption, or failed exact readback.
    #[allow(
        clippy::needless_pass_by_value,
        clippy::too_many_arguments,
        clippy::too_many_lines,
        reason = "the dormant launch seam consumes move-only native authority and crosses every independent wrapper explicitly"
    )]
    #[cfg_attr(
        not(test),
        expect(
            dead_code,
            reason = "schema-v35 launch commit is deliberately unreachable until native admission supplies the sealed production constructor"
        )
    )]
    pub(crate) fn commit_current_final_verification_launch_v35(
        &mut self,
        request: &CurrentFinalVerificationLaunchRequestV1,
        native_preparation: AuthenticatedCurrentFinalVerificationNativePreparationV1,
        issued_grant: &IssuedWorkspaceGrant,
        compiled_policy: &CompiledExecutionPolicy,
    ) -> Result<CurrentFinalVerificationLaunchCommitV1, LedgerError> {
        self.require_writable()?;
        request.validate_intrinsic()?;
        let request_bytes = request.canonical_bytes()?;
        let request_digest = request.canonical_digest()?;
        let operational =
            self.load_operational_current_final_verification_attempt_v34(&request.attempt_id)?;
        let current =
            self.load_current_sprint_authority_v32(&operational.operational_attempt.sprint_id)?;

        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;

        if let Some((existing_attempt_id, existing_request_digest, existing_request_bytes)) =
            load_launch_collision_v35(
                &transaction,
                &request.attempt_id,
                &request.launch_request_id,
                &request_digest,
            )?
        {
            if existing_attempt_id != request.attempt_id
                || existing_request_digest != request_digest
                || existing_request_bytes != request_bytes
            {
                return Err(mismatch(
                    "current final-verification launch",
                    "a launch attempt, request identity, or request digest is already bound to different immutable bytes",
                ));
            }
            let transactional = load_launch_v35_from(
                &transaction,
                &operational,
                &current.spec,
                &request.attempt_id,
            )?;
            transaction.commit()?;
            let persisted = self.load_current_final_verification_launch_v35(&request.attempt_id)?;
            if persisted != transactional {
                return Err(corrupt(
                    "current final-verification launch",
                    "replay readback changed across the transaction boundary",
                ));
            }
            return Ok(CurrentFinalVerificationLaunchCommitV1::Replay { persisted });
        }

        issued_grant.validate_integrity()?;
        compiled_policy.validate_integrity(issued_grant)?;
        if native_preparation.contract() != &request.launch_preparation
            || issued_grant.contract() != &request.workspace_grant
            || compiled_policy.contract() != &request.execution_policy
            || request.workspace_grant != current.spec.workspace_grant
            || request.exact_command != operational.attempt.authority.final_verification_check
            || request.operational_attempt_digest
                != operational.operational_attempt.operational_attempt_digest
            || request.launch_request_id == operational.operational_attempt.request_id
        {
            return Err(mismatch(
                "current final-verification launch",
                "fresh launch crosses its sealed native plan, issued grant, compiled policy, exact command, or operational parent",
            ));
        }

        transaction.pragma_update(None, "defer_foreign_keys", true)?;
        let deferred: i64 =
            transaction.pragma_query_value(None, "defer_foreign_keys", |row| row.get(0))?;
        if deferred != 1 {
            return Err(corrupt(
                "current final-verification launch",
                "SQLite did not retain the required deferred foreign-key mode",
            ));
        }

        let reservations = derive_lifecycle_reservations(&request.attempt_id, &request_digest)?;
        let event = launch_event(
            &operational.operational_attempt,
            &request.launch_request_id,
            request_digest.clone(),
            request.committed_at_unix_ms,
        )?;
        let authority = CurrentFinalVerificationLaunchAuthorityV1::new(
            &operational.operational_attempt,
            &current.spec,
            request,
            request_digest,
            reservations,
            &event,
        )?;
        if authority.exact_command != operational.attempt.authority.final_verification_check {
            return Err(mismatch(
                "current final-verification launch",
                "launch command differs from the exact admitted final-verification command",
            ));
        }
        let expected = PersistedCurrentFinalVerificationLaunchV1 {
            operational_attempt: operational.clone(),
            launch_event: event.clone(),
            launch_authority: authority.clone(),
        };
        let guard = LaunchWriteGuardV1 {
            attempt_id: request.attempt_id.clone(),
            event_digest: event.event_digest.clone(),
            launch_authority_digest: authority.launch_authority_digest.clone(),
            reservation_ids: reservation_pairs(&authority.reservations.fields)
                .into_iter()
                .map(|(_, identity)| identity.to_owned())
                .collect(),
        };
        with_launch_write_guard(guard, || {
            insert_launch_v35(&transaction, request, &authority)?;
            insert_lifecycle_reservations_v35(&transaction, &authority)?;
            insert_launch_event_v35(&transaction, &event)
        })?;

        let transactional = load_launch_v35_from(
            &transaction,
            &operational,
            &current.spec,
            &request.attempt_id,
        )?;
        if transactional != expected {
            return Err(corrupt(
                "current final-verification launch",
                "transactional readback differs from the exact derived launch",
            ));
        }
        verify_no_foreign_key_violations_v35(&transaction)?;
        transaction.commit()?;

        let persisted = secure_database_files(&self.database_path)
            .and_then(|()| self.load_current_final_verification_launch_v35(&request.attempt_id))
            .map_err(|error| LedgerError::PostCommitStateUncertain {
                operation: "current final-verification launch commit",
                recovery_id: request.attempt_id.clone(),
                detail: error.to_string(),
            })?;
        if persisted != expected {
            return Err(LedgerError::PostCommitStateUncertain {
                operation: "current final-verification launch commit",
                recovery_id: request.attempt_id.clone(),
                detail: "post-commit readback differs from the exact derived launch".into(),
            });
        }
        let capture_acquisition_permit = FreshCurrentFinalVerificationCaptureAcquisitionPermitV1 {
            attempt_id: persisted.launch_authority.attempt_id.clone(),
            launch_authority_digest: persisted.launch_authority.launch_authority_digest.clone(),
            capture_intent_id: persisted
                .launch_authority
                .reservations
                .fields
                .capture_intent_id
                .clone(),
            capture_id: persisted.launch_authority.capture_intent.capture_id.clone(),
            capture_intent_digest: persisted
                .launch_authority
                .capture_intent
                .intent_digest
                .clone(),
            ledger_instance_id: self.instance_id,
        };
        Ok(CurrentFinalVerificationLaunchCommitV1::Fresh {
            persisted,
            capture_acquisition_permit,
        })
    }

    /// Loads one exact v35 launch without recreating its fresh-only permit.
    ///
    /// # Errors
    ///
    /// Returns an error when the launch is absent or any canonical bytes,
    /// normalized projection, parent join, reservation, event, or V13 seam
    /// identity differs.
    pub fn load_current_final_verification_launch_v35(
        &self,
        attempt_id: &str,
    ) -> Result<PersistedCurrentFinalVerificationLaunchV1, LedgerError> {
        let operational =
            self.load_operational_current_final_verification_attempt_v34(attempt_id)?;
        let current =
            self.load_current_sprint_authority_v32(&operational.operational_attempt.sprint_id)?;
        load_launch_v35_from(&self.connection, &operational, &current.spec, attempt_id)
    }
}

#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "used only by the deliberately dormant schema-v35 atomic launch commit"
    )
)]
fn load_launch_collision_v35(
    connection: &Connection,
    attempt_id: &str,
    launch_request_id: &str,
    launch_request_digest: &Digest,
) -> Result<Option<(String, Digest, Vec<u8>)>, LedgerError> {
    connection
        .query_row(
            "SELECT attempt_id, launch_request_digest, launch_request_json
             FROM current_final_verification_launches_v35
             WHERE attempt_id = ?1 OR launch_request_id = ?2
                OR launch_request_digest = ?3
             LIMIT 1",
            params![
                attempt_id,
                launch_request_id,
                launch_request_digest.as_str()
            ],
            |row| {
                let digest = row.get::<_, String>(1)?;
                Ok((
                    row.get::<_, String>(0)?,
                    Digest::parse(&digest).map_err(|error| {
                        rusqlite::Error::FromSqlConversionFailure(
                            1,
                            rusqlite::types::Type::Text,
                            Box::new(error),
                        )
                    })?,
                    row.get::<_, Vec<u8>>(2)?,
                ))
            },
        )
        .optional()
        .map_err(Into::into)
}

#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "used only by the deliberately dormant schema-v35 atomic launch commit"
    )
)]
fn insert_launch_v35(
    transaction: &Transaction<'_>,
    request: &CurrentFinalVerificationLaunchRequestV1,
    authority: &CurrentFinalVerificationLaunchAuthorityV1,
) -> Result<(), LedgerError> {
    let preparation = &authority.launch_preparation;
    transaction.execute(
        "INSERT INTO current_final_verification_launches_v35 (
            attempt_id, launch_version, sprint_id, operational_attempt_digest,
            launch_request_id, launch_request_digest, launch_request_json,
            preparation_id, launch_preparation_digest, reservation_digest,
            reservations_json, capture_intent_id, capture_intent_digest,
            containment_backend, target_identity_digest, native_policy_digest,
            runner_binary_digest, runner_binary_size_bytes, runner_protocol_version,
            runner_protocol_digest, private_state_id, private_state_digest,
            workspace_grant_hash, execution_policy_digest,
            verification_command_digest, v13_command_request_digest,
            detector_policy_digest, max_aggregate_output_bytes, launch_event_id,
            launch_event_sequence, committed_at_unix_ms,
            launch_authority_digest, launch_authority_json
         ) VALUES (
            ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11,
            ?12, ?13, ?14, ?15, ?16, ?17, ?18, ?19, ?20, ?21,
            ?22, ?23, ?24, ?25, ?26, ?27, ?28, ?29, ?30, ?31,
            ?32, ?33
         )",
        params![
            authority.attempt_id,
            i64::from(authority.launch_version),
            authority.sprint_id,
            authority.operational_attempt_digest.as_str(),
            authority.launch_request_id,
            authority.launch_request_digest.as_str(),
            request.canonical_bytes()?,
            preparation.preparation_id,
            authority.launch_preparation_digest.as_str(),
            authority.reservations.reservation_digest.as_str(),
            encode_canonical(&authority.reservations)?,
            authority.reservations.fields.capture_intent_id,
            authority.capture_intent.intent_digest.as_str(),
            preparation.containment_backend.launch_sql_kind(),
            preparation.target_identity_digest.as_str(),
            preparation.native_policy_digest.as_str(),
            preparation.runner_binary_digest.as_str(),
            super::sqlite_integer(
                "current final-verification runner binary size",
                preparation.runner_binary_size_bytes,
            )?,
            i64::from(preparation.runner_protocol_version),
            preparation.runner_protocol_digest.as_str(),
            preparation.private_state_id,
            preparation.private_state_digest.as_str(),
            authority.workspace_grant.grant_hash.as_str(),
            authority.execution_policy.policy_hash.as_str(),
            authority.verification_command_digest.as_str(),
            authority.v13_command_request_digest.as_str(),
            authority.detector_policy.policy_digest.as_str(),
            super::sqlite_integer(
                "current final-verification maximum aggregate output",
                authority.max_aggregate_output_bytes,
            )?,
            authority.launch_event_id,
            super::sqlite_integer(
                "current final-verification launch event sequence",
                authority.launch_event_sequence,
            )?,
            super::sqlite_integer(
                "current final-verification launch committed_at",
                authority.committed_at_unix_ms,
            )?,
            authority.launch_authority_digest.as_str(),
            authority.canonical_bytes()?,
        ],
    )?;
    Ok(())
}

#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "used only by the deliberately dormant schema-v35 atomic launch commit"
    )
)]
fn insert_lifecycle_reservations_v35(
    transaction: &Transaction<'_>,
    authority: &CurrentFinalVerificationLaunchAuthorityV1,
) -> Result<(), LedgerError> {
    for (role, reserved_id) in reservation_pairs(&authority.reservations.fields) {
        transaction.execute(
            "INSERT INTO current_final_verification_lifecycle_reservations_v35 (
                attempt_id, reservation_role, reserved_id, reservation_digest
             ) VALUES (?1, ?2, ?3, ?4)",
            params![
                authority.attempt_id,
                role,
                reserved_id,
                authority.reservations.reservation_digest.as_str(),
            ],
        )?;
    }
    Ok(())
}

#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "used only by the deliberately dormant schema-v35 atomic launch commit"
    )
)]
fn insert_launch_event_v35(
    transaction: &Transaction<'_>,
    event: &CurrentFinalVerificationAuthorityEventV1,
) -> Result<(), LedgerError> {
    transaction.execute(
        "INSERT INTO current_final_verification_events_v34 (
            sprint_id, event_sequence, event_id, event_version, event_kind,
            attempt_id, request_id, request_digest, occurred_at_unix_ms,
            event_digest, event_json
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
        params![
            event.sprint_id,
            super::sqlite_integer(
                "current final-verification event sequence",
                event.event_sequence,
            )?,
            event.event_id,
            i64::from(event.event_version),
            event_kind_sql(event.event_kind),
            event.attempt_id,
            event.request_id,
            event.request_digest.as_str(),
            super::sqlite_integer(
                "current final-verification event occurred_at",
                event.occurred_at_unix_ms,
            )?,
            event.event_digest.as_str(),
            event.canonical_bytes()?,
        ],
    )?;
    Ok(())
}

fn load_launch_event_v35(
    connection: &Connection,
    event_id: &str,
) -> Result<CurrentFinalVerificationAuthorityEventV1, LedgerError> {
    let bytes = connection
        .query_row(
            "SELECT event_json FROM current_final_verification_events_v34
             WHERE event_id = ?1",
            [event_id],
            |row| row.get::<_, Vec<u8>>(0),
        )
        .optional()?
        .ok_or_else(|| LedgerError::ArtifactNotFound {
            entity: "current final-verification launch event v35",
            id: event_id.to_owned(),
        })?;
    let event: CurrentFinalVerificationAuthorityEventV1 =
        decode_exact("current final-verification launch event", &bytes)
            .map_err(|detail| corrupt("current final-verification launch event", detail))?;
    event.validate_integrity()?;
    let projection_matches = connection.query_row(
        "SELECT EXISTS(
            SELECT 1 FROM current_final_verification_events_v34
            WHERE sprint_id = ?1 AND event_sequence = ?2 AND event_id = ?3
              AND event_version = ?4 AND event_kind = ?5 AND attempt_id = ?6
              AND request_id = ?7 AND request_digest = ?8
              AND occurred_at_unix_ms = ?9 AND event_digest = ?10
              AND event_json = ?11
         )",
        params![
            event.sprint_id,
            super::sqlite_integer(
                "current final-verification event sequence",
                event.event_sequence,
            )?,
            event.event_id,
            i64::from(event.event_version),
            event_kind_sql(event.event_kind),
            event.attempt_id,
            event.request_id,
            event.request_digest.as_str(),
            super::sqlite_integer(
                "current final-verification event occurred_at",
                event.occurred_at_unix_ms,
            )?,
            event.event_digest.as_str(),
            bytes,
        ],
        |row| row.get::<_, bool>(0),
    )?;
    if !projection_matches {
        return Err(corrupt(
            "current final-verification launch event",
            "stored projection differs from exact canonical event bytes",
        ));
    }
    Ok(event)
}

#[allow(clippy::too_many_lines)]
fn load_launch_v35_from(
    connection: &Connection,
    operational: &PersistedOperationalCurrentFinalVerificationAttemptV1,
    sprint: &SprintSpecV2,
    attempt_id: &str,
) -> Result<PersistedCurrentFinalVerificationLaunchV1, LedgerError> {
    let (request_bytes, reservation_bytes, authority_bytes) = connection
        .query_row(
            "SELECT launch_request_json, reservations_json, launch_authority_json
             FROM current_final_verification_launches_v35 WHERE attempt_id = ?1",
            [attempt_id],
            |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, Vec<u8>>(1)?,
                    row.get::<_, Vec<u8>>(2)?,
                ))
            },
        )
        .optional()?
        .ok_or_else(|| LedgerError::ArtifactNotFound {
            entity: "current final-verification launch v35",
            id: attempt_id.to_owned(),
        })?;
    let request: CurrentFinalVerificationLaunchRequestV1 =
        decode_exact("current final-verification launch request", &request_bytes)
            .map_err(|detail| corrupt("current final-verification launch request", detail))?;
    let reservations: CurrentFinalVerificationLifecycleReservationSetV2 = decode_exact(
        "current final-verification lifecycle reservations",
        &reservation_bytes,
    )
    .map_err(|detail| corrupt("current final-verification lifecycle reservations", detail))?;
    let authority: CurrentFinalVerificationLaunchAuthorityV1 = decode_exact(
        "current final-verification launch authority",
        &authority_bytes,
    )
    .map_err(|detail| corrupt("current final-verification launch authority", detail))?;
    request.validate_intrinsic()?;
    reservations.validate_integrity().map_err(|error| {
        corrupt(
            "current final-verification lifecycle reservations",
            error.to_string(),
        )
    })?;
    if authority.reservations != reservations {
        return Err(corrupt(
            "current final-verification launch",
            "authority and standalone reservation bytes differ",
        ));
    }
    let event = load_launch_event_v35(connection, &authority.launch_event_id)?;
    validate_launch_event(
        &event,
        &operational.operational_attempt,
        &request.launch_request_id,
        request.canonical_digest()?,
        request.committed_at_unix_ms,
    )?;
    authority.validate_for(&operational.operational_attempt, sprint, &request, &event)?;
    if request.exact_command != operational.attempt.authority.final_verification_check
        || authority.exact_command != operational.attempt.authority.final_verification_check
    {
        return Err(corrupt(
            "current final-verification launch",
            "exact command differs from the admitted final-verification command",
        ));
    }
    let v13_intent = authority.v13_command_output_capture_intent()?;
    if v13_intent.source.request_digest != authority.v13_command_request_digest
        || authority.reservations.fields.dispatch_id
            != current_final_verification_dispatch_claim_id(
                &authority.reservations.fields.effect_id,
            )?
    {
        return Err(corrupt(
            "current final-verification launch",
            "V13 command/capture seam differs from the exact reserved identities",
        ));
    }

    let preparation = &authority.launch_preparation;
    let projection_matches = connection.query_row(
        "SELECT EXISTS(
            SELECT 1 FROM current_final_verification_launches_v35
            WHERE attempt_id = ?1 AND launch_version = ?2 AND sprint_id = ?3
              AND operational_attempt_digest = ?4 AND launch_request_id = ?5
              AND launch_request_digest = ?6 AND launch_request_json = ?7
              AND preparation_id = ?8 AND launch_preparation_digest = ?9
              AND reservation_digest = ?10 AND reservations_json = ?11
              AND capture_intent_id = ?12 AND capture_intent_digest = ?13
              AND containment_backend = ?14 AND target_identity_digest = ?15
              AND native_policy_digest = ?16 AND runner_binary_digest = ?17
              AND runner_binary_size_bytes = ?18 AND runner_protocol_version = ?19
              AND runner_protocol_digest = ?20 AND private_state_id = ?21
              AND private_state_digest = ?22 AND workspace_grant_hash = ?23
              AND execution_policy_digest = ?24 AND verification_command_digest = ?25
              AND v13_command_request_digest = ?26 AND detector_policy_digest = ?27
              AND max_aggregate_output_bytes = ?28 AND launch_event_id = ?29
              AND launch_event_sequence = ?30 AND committed_at_unix_ms = ?31
              AND launch_authority_digest = ?32 AND launch_authority_json = ?33
         )",
        params![
            authority.attempt_id,
            i64::from(authority.launch_version),
            authority.sprint_id,
            authority.operational_attempt_digest.as_str(),
            authority.launch_request_id,
            authority.launch_request_digest.as_str(),
            request_bytes,
            preparation.preparation_id,
            authority.launch_preparation_digest.as_str(),
            authority.reservations.reservation_digest.as_str(),
            reservation_bytes,
            authority.reservations.fields.capture_intent_id,
            authority.capture_intent.intent_digest.as_str(),
            preparation.containment_backend.launch_sql_kind(),
            preparation.target_identity_digest.as_str(),
            preparation.native_policy_digest.as_str(),
            preparation.runner_binary_digest.as_str(),
            super::sqlite_integer(
                "current final-verification runner binary size",
                preparation.runner_binary_size_bytes,
            )?,
            i64::from(preparation.runner_protocol_version),
            preparation.runner_protocol_digest.as_str(),
            preparation.private_state_id,
            preparation.private_state_digest.as_str(),
            authority.workspace_grant.grant_hash.as_str(),
            authority.execution_policy.policy_hash.as_str(),
            authority.verification_command_digest.as_str(),
            authority.v13_command_request_digest.as_str(),
            authority.detector_policy.policy_digest.as_str(),
            super::sqlite_integer(
                "current final-verification maximum aggregate output",
                authority.max_aggregate_output_bytes,
            )?,
            authority.launch_event_id,
            super::sqlite_integer(
                "current final-verification launch event sequence",
                authority.launch_event_sequence,
            )?,
            super::sqlite_integer(
                "current final-verification launch committed_at",
                authority.committed_at_unix_ms,
            )?,
            authority.launch_authority_digest.as_str(),
            authority_bytes,
        ],
        |row| row.get::<_, bool>(0),
    )?;
    if !projection_matches {
        return Err(corrupt(
            "current final-verification launch",
            "stored normalized projection differs from exact canonical authority bytes",
        ));
    }

    let mut statement = connection.prepare(
        "SELECT reservation_role, reserved_id, reservation_digest
         FROM current_final_verification_lifecycle_reservations_v35
         WHERE attempt_id = ?1 ORDER BY reservation_role",
    )?;
    let actual = statement
        .query_map([attempt_id], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
            ))
        })?
        .collect::<Result<Vec<_>, _>>()?;
    let mut expected = reservation_pairs(&authority.reservations.fields)
        .into_iter()
        .map(|(role, identity)| {
            (
                role.to_owned(),
                identity.to_owned(),
                authority.reservations.reservation_digest.to_string(),
            )
        })
        .collect::<Vec<_>>();
    expected.sort();
    if actual != expected {
        return Err(corrupt(
            "current final-verification lifecycle reservations",
            "stored membership differs from the exact 49-member reservation set",
        ));
    }
    Ok(PersistedCurrentFinalVerificationLaunchV1 {
        operational_attempt: operational.clone(),
        launch_event: event,
        launch_authority: authority,
    })
}

pub(super) fn verify_no_foreign_key_violations_v35(
    connection: &Connection,
) -> Result<(), LedgerError> {
    let mut statement = connection.prepare("PRAGMA foreign_key_check")?;
    let mut rows = statement.query([])?;
    if rows.next()?.is_some() {
        Err(corrupt(
            "current final-verification launch",
            "foreign-key check reported a violation before commit",
        ))
    } else {
        Ok(())
    }
}

const fn event_kind_sql(kind: CurrentFinalVerificationAuthorityEventKindV1) -> &'static str {
    match kind {
        CurrentFinalVerificationAuthorityEventKindV1::AttemptAdmitted => "AttemptAdmitted",
        CurrentFinalVerificationAuthorityEventKindV1::LaunchCommitted => "LaunchCommitted",
        CurrentFinalVerificationAuthorityEventKindV1::CaptureAcquired => "CaptureAcquired",
        CurrentFinalVerificationAuthorityEventKindV1::V13Initialized => "V13Initialized",
        CurrentFinalVerificationAuthorityEventKindV1::CommandDispatched => "CommandDispatched",
        CurrentFinalVerificationAuthorityEventKindV1::ControlIssued => "ControlIssued",
        CurrentFinalVerificationAuthorityEventKindV1::ControlObserved => "ControlObserved",
        CurrentFinalVerificationAuthorityEventKindV1::ControlReconciled => "ControlReconciled",
        CurrentFinalVerificationAuthorityEventKindV1::TerminalObserved => "TerminalObserved",
        CurrentFinalVerificationAuthorityEventKindV1::EffectCutObserved => "EffectCutObserved",
        CurrentFinalVerificationAuthorityEventKindV1::OutputCustodyClosed => "OutputCustodyClosed",
        CurrentFinalVerificationAuthorityEventKindV1::CommandDomainCleanupObserved => {
            "CommandDomainCleanupObserved"
        }
        CurrentFinalVerificationAuthorityEventKindV1::RunnerDirectChildObserved => {
            "RunnerDirectChildObserved"
        }
        CurrentFinalVerificationAuthorityEventKindV1::RunnerDomainObserved => {
            "RunnerDomainObserved"
        }
        CurrentFinalVerificationAuthorityEventKindV1::RunnerCleanupClosed => "RunnerCleanupClosed",
        CurrentFinalVerificationAuthorityEventKindV1::EvidenceClosed => "EvidenceClosed",
        CurrentFinalVerificationAuthorityEventKindV1::OutcomeDerived => "OutcomeDerived",
    }
}

fn launch_event(
    operational: &OperationalCurrentFinalVerificationAttemptV1,
    launch_request_id: &str,
    launch_request_digest: Digest,
    committed_at_unix_ms: u64,
) -> Result<CurrentFinalVerificationAuthorityEventV1, ContractError> {
    CurrentFinalVerificationAuthorityEventV1::try_new_launch(
        operational,
        launch_request_id,
        launch_request_digest,
        committed_at_unix_ms,
    )
}

fn validate_launch_event(
    event: &CurrentFinalVerificationAuthorityEventV1,
    operational: &OperationalCurrentFinalVerificationAttemptV1,
    launch_request_id: &str,
    launch_request_digest: Digest,
    committed_at_unix_ms: u64,
) -> Result<(), ContractError> {
    if event
        != &launch_event(
            operational,
            launch_request_id,
            launch_request_digest,
            committed_at_unix_ms,
        )?
    {
        return Err(ContractError::new(
            "launch_event",
            "does not equal the exact formula-derived LaunchCommitted event",
        ));
    }
    require_canonical_bound("launch_event", &encode_canonical(event)?)
}

fn derive_lifecycle_reservations(
    attempt_id: &str,
    request_digest: &Digest,
) -> Result<CurrentFinalVerificationLifecycleReservationSetV2, ContractError> {
    let identity = |role: &'static str| mint_reservation_identity(role, attempt_id, request_digest);
    let effect_id = identity("effect");
    let dispatch_id = current_final_verification_dispatch_claim_id(&effect_id)?;
    CurrentFinalVerificationLifecycleReservationSetV2::new(
        CurrentFinalVerificationLifecycleReservationFieldsV2 {
            reservation_version: crate::CURRENT_FINAL_VERIFICATION_EVIDENCE_VERSION_V2,
            runner_launch_id: identity("runner-launch"),
            runner_session_id: identity("runner-session"),
            effect_id,
            capture_id: identity("capture"),
            capture_intent_id: identity("capture-intent"),
            dispatch_id,
            command_request_id: identity("command-request"),
            effect_idempotency_key: identity("effect-idempotency-key"),
            native_launch_preparation_attempt_id: identity("native-launch-preparation-attempt"),
            native_launch_journal_id: identity("native-launch-journal"),
            native_launch_cleanup_effect_id: identity("native-launch-cleanup-effect"),
            native_launch_preparation_receipt_id: identity("native-launch-preparation-receipt"),
            native_launch_release_receipt_id: identity("native-launch-release-receipt"),
            native_launch_cleanup_receipt_id: identity("native-launch-cleanup-receipt"),
            capture_acquired_event_id: identity("event-capture-acquired"),
            v13_initialized_event_id: identity("event-v13-initialized"),
            command_dispatched_event_id: identity("event-command-dispatched"),
            control_issued_event_id: identity("event-control-issued"),
            control_observed_event_id: identity("event-control-observed"),
            control_reconciled_event_id: identity("event-control-reconciled"),
            terminal_event_id: identity("event-terminal-observed"),
            effect_cut_event_id: identity("event-effect-cut-observed"),
            output_custody_event_id: identity("event-output-custody-closed"),
            command_cleanup_event_id: identity("event-command-domain-cleanup-observed"),
            runner_direct_child_observed_event_id: identity("event-runner-direct-child-observed"),
            runner_domain_observed_event_id: identity("event-runner-domain-observed"),
            runner_cleanup_event_id: identity("event-runner-cleanup-closed"),
            evidence_closure_event_id: identity("event-evidence-closed"),
            outcome_derived_event_id: identity("event-outcome-derived"),
            initialization_request_id: identity("v13-initialization-request"),
            initialization_receipt_id: identity("v13-initialization-receipt"),
            control_id: identity("control"),
            control_reconciliation_id: identity("control-reconciliation"),
            terminal_observation_id: identity("terminal-observation"),
            effect_cut_observation_id: identity("effect-cut-observation"),
            shutdown_request_id: identity("v13-shutdown-request"),
            shutdown_receipt_id: identity("v13-shutdown-receipt"),
            command_accounting_domain_id: identity("command-accounting-domain"),
            command_cleanup_observation_id: identity("command-cleanup-observation"),
            runner_accounting_domain_id: identity("runner-accounting-domain"),
            runner_direct_child_observer_id: identity("runner-direct-child-observer"),
            runner_direct_child_observation_id: identity("runner-direct-child-observation"),
            runner_domain_observer_id: identity("runner-domain-observer"),
            runner_domain_observation_id: identity("runner-domain-observation"),
            output_custody_closure_receipt_id: identity("output-custody-closure-receipt"),
            runner_cleanup_proof_id: identity("runner-cleanup-proof"),
            evidence_closure_id: identity("evidence-closure"),
            outcome_id: identity("derived-outcome"),
            verification_receipt_id: identity("verification-receipt"),
        },
    )
    .map_err(|error| ContractError::new("launch_reservations", error.to_string()))
}

fn mint_reservation_identity(role: &str, attempt_id: &str, request_digest: &Digest) -> String {
    #[derive(Serialize)]
    struct ReservationIdentityPreimage<'a> {
        reservation_version: u32,
        attempt_id: &'a str,
        launch_request_digest: &'a Digest,
    }

    let canonical = encode_canonical(&ReservationIdentityPreimage {
        reservation_version: crate::CURRENT_FINAL_VERIFICATION_EVIDENCE_VERSION_V2,
        attempt_id,
        launch_request_digest: request_digest,
    })
    .expect("fixed lifecycle reservation preimage is serializable");
    let mut role_domain = Vec::with_capacity(LIFECYCLE_RESERVATION_ID_DOMAIN_V1.len() + role.len());
    role_domain.extend_from_slice(LIFECYCLE_RESERVATION_ID_DOMAIN_V1);
    role_domain.extend_from_slice(role.as_bytes());
    role_domain.push(0);
    mint_identity(&role_domain, &canonical)
}

#[allow(
    clippy::too_many_lines,
    reason = "the exhaustive 49-role reservation projection is deliberately visible and mechanically reviewable"
)]
fn reservation_pairs(
    fields: &CurrentFinalVerificationLifecycleReservationFieldsV2,
) -> [(&'static str, &str); 49] {
    [
        ("runner_launch_id", &fields.runner_launch_id),
        ("runner_session_id", &fields.runner_session_id),
        ("effect_id", &fields.effect_id),
        ("capture_id", &fields.capture_id),
        ("capture_intent_id", &fields.capture_intent_id),
        ("dispatch_id", &fields.dispatch_id),
        ("command_request_id", &fields.command_request_id),
        ("effect_idempotency_key", &fields.effect_idempotency_key),
        (
            "native_launch_preparation_attempt_id",
            &fields.native_launch_preparation_attempt_id,
        ),
        ("native_launch_journal_id", &fields.native_launch_journal_id),
        (
            "native_launch_cleanup_effect_id",
            &fields.native_launch_cleanup_effect_id,
        ),
        (
            "native_launch_preparation_receipt_id",
            &fields.native_launch_preparation_receipt_id,
        ),
        (
            "native_launch_release_receipt_id",
            &fields.native_launch_release_receipt_id,
        ),
        (
            "native_launch_cleanup_receipt_id",
            &fields.native_launch_cleanup_receipt_id,
        ),
        (
            "capture_acquired_event_id",
            &fields.capture_acquired_event_id,
        ),
        ("v13_initialized_event_id", &fields.v13_initialized_event_id),
        (
            "command_dispatched_event_id",
            &fields.command_dispatched_event_id,
        ),
        ("control_issued_event_id", &fields.control_issued_event_id),
        (
            "control_observed_event_id",
            &fields.control_observed_event_id,
        ),
        (
            "control_reconciled_event_id",
            &fields.control_reconciled_event_id,
        ),
        ("terminal_event_id", &fields.terminal_event_id),
        ("effect_cut_event_id", &fields.effect_cut_event_id),
        ("output_custody_event_id", &fields.output_custody_event_id),
        ("command_cleanup_event_id", &fields.command_cleanup_event_id),
        (
            "runner_direct_child_observed_event_id",
            &fields.runner_direct_child_observed_event_id,
        ),
        (
            "runner_domain_observed_event_id",
            &fields.runner_domain_observed_event_id,
        ),
        ("runner_cleanup_event_id", &fields.runner_cleanup_event_id),
        (
            "evidence_closure_event_id",
            &fields.evidence_closure_event_id,
        ),
        ("outcome_derived_event_id", &fields.outcome_derived_event_id),
        (
            "initialization_request_id",
            &fields.initialization_request_id,
        ),
        (
            "initialization_receipt_id",
            &fields.initialization_receipt_id,
        ),
        ("control_id", &fields.control_id),
        (
            "control_reconciliation_id",
            &fields.control_reconciliation_id,
        ),
        ("terminal_observation_id", &fields.terminal_observation_id),
        (
            "effect_cut_observation_id",
            &fields.effect_cut_observation_id,
        ),
        ("shutdown_request_id", &fields.shutdown_request_id),
        ("shutdown_receipt_id", &fields.shutdown_receipt_id),
        (
            "command_accounting_domain_id",
            &fields.command_accounting_domain_id,
        ),
        (
            "command_cleanup_observation_id",
            &fields.command_cleanup_observation_id,
        ),
        (
            "runner_accounting_domain_id",
            &fields.runner_accounting_domain_id,
        ),
        (
            "runner_direct_child_observer_id",
            &fields.runner_direct_child_observer_id,
        ),
        (
            "runner_direct_child_observation_id",
            &fields.runner_direct_child_observation_id,
        ),
        (
            "runner_domain_observer_id",
            &fields.runner_domain_observer_id,
        ),
        (
            "runner_domain_observation_id",
            &fields.runner_domain_observation_id,
        ),
        (
            "output_custody_closure_receipt_id",
            &fields.output_custody_closure_receipt_id,
        ),
        ("runner_cleanup_proof_id", &fields.runner_cleanup_proof_id),
        ("evidence_closure_id", &fields.evidence_closure_id),
        ("outcome_id", &fields.outcome_id),
        ("verification_receipt_id", &fields.verification_receipt_id),
    ]
}

fn reservation_ids(
    fields: &CurrentFinalVerificationLifecycleReservationFieldsV2,
) -> BTreeSet<&str> {
    reservation_pairs(fields)
        .into_iter()
        .map(|(_, identity)| identity)
        .collect()
}

#[derive(Clone)]
struct LaunchWriteGuardV1 {
    attempt_id: String,
    event_digest: Digest,
    launch_authority_digest: Digest,
    reservation_ids: BTreeSet<String>,
}

thread_local! {
    static LAUNCH_WRITE_GUARD_V1: RefCell<Option<LaunchWriteGuardV1>> = const { RefCell::new(None) };
}

#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "used only by the deliberately dormant schema-v35 atomic launch commit"
    )
)]
struct LaunchWriteGuardResetV1;

impl Drop for LaunchWriteGuardResetV1 {
    fn drop(&mut self) {
        LAUNCH_WRITE_GUARD_V1.with(|slot| *slot.borrow_mut() = None);
    }
}

#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "used only by the deliberately dormant schema-v35 atomic launch commit"
    )
)]
fn with_launch_write_guard<T>(
    guard: LaunchWriteGuardV1,
    operation: impl FnOnce() -> Result<T, LedgerError>,
) -> Result<T, LedgerError> {
    let was_empty = LAUNCH_WRITE_GUARD_V1.with(|slot| {
        let mut slot = slot.borrow_mut();
        if slot.is_some() {
            false
        } else {
            *slot = Some(guard);
            true
        }
    });
    if !was_empty {
        return Err(LedgerError::Corrupt {
            entity: "current final-verification launch writer",
            detail: "nested private launch-write admission is forbidden".into(),
        });
    }
    let _reset = LaunchWriteGuardResetV1;
    operation()
}

pub(super) fn sqlite_launch_write_admitted(
    record_kind: &str,
    attempt_id: &str,
    record_identity: &str,
) -> i64 {
    LAUNCH_WRITE_GUARD_V1.with(|slot| {
        i64::from(slot.borrow().as_ref().is_some_and(|guard| {
            guard.attempt_id == attempt_id
                && match record_kind {
                    "event" => guard.event_digest.as_str() == record_identity,
                    "launch" => guard.launch_authority_digest.as_str() == record_identity,
                    "reservation" => guard.reservation_ids.contains(record_identity),
                    _ => false,
                }
        }))
    })
}

pub(super) fn sqlite_launch_request_canonical(bytes: &[u8]) -> Result<i64, String> {
    let request: CurrentFinalVerificationLaunchRequestV1 =
        decode_exact("current final-verification launch request", bytes)?;
    request
        .validate_intrinsic()
        .map(|()| 1)
        .map_err(|error| error.to_string())
}

pub(super) fn sqlite_launch_request_digest(bytes: &[u8]) -> Result<String, String> {
    let request: CurrentFinalVerificationLaunchRequestV1 =
        decode_exact("current final-verification launch request", bytes)?;
    request
        .canonical_digest()
        .map(|digest| digest.to_string())
        .map_err(|error| error.to_string())
}

pub(super) fn sqlite_reservations_canonical(bytes: &[u8]) -> Result<i64, String> {
    let reservations: CurrentFinalVerificationLifecycleReservationSetV2 =
        decode_exact("current final-verification lifecycle reservations", bytes)?;
    reservations
        .validate_integrity()
        .map(|()| 1)
        .map_err(|error| error.to_string())
}

pub(super) fn sqlite_reservations_digest(bytes: &[u8]) -> Result<String, String> {
    let reservations: CurrentFinalVerificationLifecycleReservationSetV2 =
        decode_exact("current final-verification lifecycle reservations", bytes)?;
    reservations
        .validate_integrity()
        .map(|()| reservations.reservation_digest.to_string())
        .map_err(|error| error.to_string())
}

pub(super) fn sqlite_launch_canonical(bytes: &[u8]) -> Result<i64, String> {
    let launch: CurrentFinalVerificationLaunchAuthorityV1 =
        decode_exact("current final-verification launch authority", bytes)?;
    if launch.launch_authority_digest
        != launch
            .computed_digest()
            .map_err(|error| error.to_string())?
    {
        return Err("launch authority digest mismatch".into());
    }
    require_canonical_bound("launch_authority", bytes)
        .map(|()| 1)
        .map_err(|error| error.to_string())
}

pub(super) fn sqlite_launch_digest(bytes: &[u8]) -> Result<String, String> {
    let launch: CurrentFinalVerificationLaunchAuthorityV1 =
        decode_exact("current final-verification launch authority", bytes)?;
    if launch.launch_authority_digest
        != launch
            .computed_digest()
            .map_err(|error| error.to_string())?
    {
        return Err("launch authority digest mismatch".into());
    }
    Ok(launch.launch_authority_digest.to_string())
}

pub(super) fn sqlite_reservation_member(
    reservation_bytes: &[u8],
    role: &str,
    reserved_id: &str,
) -> Result<i64, String> {
    let reservations: CurrentFinalVerificationLifecycleReservationSetV2 = decode_exact(
        "current final-verification lifecycle reservations",
        reservation_bytes,
    )?;
    reservations
        .validate_integrity()
        .map_err(|error| error.to_string())?;
    Ok(i64::from(
        reservation_pairs(&reservations.fields)
            .into_iter()
            .any(|(expected_role, expected_id)| {
                expected_role == role && expected_id == reserved_id
            }),
    ))
}

pub(super) fn sqlite_launch_matches(
    launch_bytes: &[u8],
    request_bytes: &[u8],
    reservation_bytes: &[u8],
    operational_bytes: &[u8],
    sprint_bytes: &[u8],
) -> Result<i64, String> {
    let launch: CurrentFinalVerificationLaunchAuthorityV1 =
        decode_exact("current final-verification launch authority", launch_bytes)?;
    let request: CurrentFinalVerificationLaunchRequestV1 =
        decode_exact("current final-verification launch request", request_bytes)?;
    let reservations: CurrentFinalVerificationLifecycleReservationSetV2 = decode_exact(
        "current final-verification lifecycle reservations",
        reservation_bytes,
    )?;
    let operational: OperationalCurrentFinalVerificationAttemptV1 = decode_exact(
        "current final-verification operational attempt",
        operational_bytes,
    )?;
    let sprint =
        SprintSpecV2::from_canonical_bytes(sprint_bytes).map_err(|error| error.to_string())?;
    let event = launch_event(
        &operational,
        &request.launch_request_id,
        request
            .canonical_digest()
            .map_err(|error| error.to_string())?,
        request.committed_at_unix_ms,
    )
    .map_err(|error| error.to_string())?;
    if launch.reservations != reservations {
        return Ok(0);
    }
    launch
        .validate_for(&operational, &sprint, &request, &event)
        .map(|()| 1)
        .map_err(|error| error.to_string())
}

fn encode_canonical<T: Serialize + ?Sized>(value: &T) -> Result<Vec<u8>, ContractError> {
    serde_json::to_vec(value).map_err(|error| {
        ContractError::new(
            "current_final_verification_launch_v35.canonical_json",
            format!("cannot encode canonical JSON: {error}"),
        )
    })
}

fn decode_exact<T: DeserializeOwned + Serialize>(
    entity: &'static str,
    bytes: &[u8],
) -> Result<T, String> {
    if bytes.is_empty() || bytes.len() > MAX_CURRENT_FINAL_VERIFICATION_CANONICAL_BYTES_V2 {
        return Err(format!(
            "{entity} bytes must contain 1..={MAX_CURRENT_FINAL_VERIFICATION_CANONICAL_BYTES_V2} bytes"
        ));
    }
    let value: T = serde_json::from_slice(bytes)
        .map_err(|error| format!("cannot decode {entity}: {error}"))?;
    let canonical = serde_json::to_vec(&value)
        .map_err(|error| format!("cannot canonicalize {entity}: {error}"))?;
    if canonical != bytes {
        return Err(format!("{entity} is not exact canonical JSON"));
    }
    Ok(value)
}

fn domain_digest(domain: &[u8], canonical: &[u8]) -> Digest {
    let mut preimage = Vec::with_capacity(domain.len() + canonical.len());
    preimage.extend_from_slice(domain);
    preimage.extend_from_slice(canonical);
    Digest::sha256(&preimage)
}

fn mint_identity(domain: &[u8], canonical: &[u8]) -> String {
    domain_digest(domain, canonical).to_string()
}

fn operational_command_digest(command: &CommandSpec) -> Result<Digest, ContractError> {
    super::final_verification_authority_v32::operational_command_digest(command)
}

fn require_version(field: &'static str, version: u32) -> Result<(), ContractError> {
    if version == LAUNCH_VERSION_V1 {
        Ok(())
    } else {
        Err(ContractError::new(field, "must equal version 1"))
    }
}

fn require_identifier(field: &'static str, value: &str) -> Result<(), ContractError> {
    if value.trim().is_empty()
        || value.len() > MAX_CURRENT_FINAL_VERIFICATION_IDENTIFIER_BYTES_V2
        || value.as_bytes().contains(&0)
    {
        Err(ContractError::new(
            field,
            format!(
                "must contain 1..={MAX_CURRENT_FINAL_VERIFICATION_IDENTIFIER_BYTES_V2} non-NUL UTF-8 bytes and not be blank"
            ),
        ))
    } else {
        Ok(())
    }
}

fn require_core_identity(field: &'static str, value: &str) -> Result<(), ContractError> {
    let parsed = Digest::parse(value)
        .map_err(|_| ContractError::new(field, "must be exactly 64 lowercase hexadecimal bytes"))?;
    if parsed.as_str() == value {
        Ok(())
    } else {
        Err(ContractError::new(
            field,
            "must be exactly 64 lowercase hexadecimal bytes",
        ))
    }
}

fn require_canonical_bound(field: &'static str, bytes: &[u8]) -> Result<(), ContractError> {
    if bytes.is_empty() || bytes.len() > MAX_CURRENT_FINAL_VERIFICATION_CANONICAL_BYTES_V2 {
        Err(ContractError::new(
            field,
            format!(
                "canonical bytes must contain 1..={MAX_CURRENT_FINAL_VERIFICATION_CANONICAL_BYTES_V2} bytes"
            ),
        ))
    } else {
        Ok(())
    }
}

#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "used only by the deliberately dormant schema-v35 launch and fresh-permit seams"
    )
)]
fn mismatch(entity: &'static str, detail: impl Into<String>) -> LedgerError {
    LedgerError::ReferenceMismatch {
        entity,
        detail: detail.into(),
    }
}

fn corrupt(entity: &'static str, detail: impl Into<String>) -> LedgerError {
    LedgerError::Corrupt {
        entity,
        detail: detail.into(),
    }
}
#[cfg(test)]
pub(super) mod tests {
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicU64, Ordering};

    use rusqlite::types::{Value, ValueRef};
    use rusqlite::{Connection, OpenFlags, params_from_iter};

    use super::*;
    use crate::ledger::{
        current_criterion_evidence_v32, current_task_done_source_v32,
        next_event_ledger_instance_id, register_schema_functions, verify_exact_schema,
    };
    use crate::{
        AcceptanceCriterion, AcceptanceKind, CompleteCriterionEvidenceSetV1, CompleteTaskDoneSetV1,
        CurrentCriterionEvidenceKindV1, CurrentCriterionEvidenceMemberV1,
        CurrentFinalVerificationAdmissionRequestV1, CurrentTaskDoneIntegrationEvidenceV1,
        CurrentTaskDoneMemberV1, EnvironmentVariable, ExecutionOrigin, ExecutionPolicyCompiler,
        ExecutionPolicyRequest, PathScope, ProviderProfile, ResourceLimits,
        SPRINT_AUTHORITY_CONTRACT_VERSION_V2, SprintBudgetV2, TaskGraphV2, TaskPurposeV2,
        TaskSpecV2, WorkspaceGrantIssuer, WorkspaceGrantRequest, WorkspaceNetworkPolicy,
        WorkspacePermissions,
    };

    static NEXT_TEST: AtomicU64 = AtomicU64::new(1);

    pub(crate) struct TestFiles {
        pub(crate) root: PathBuf,
        pub(crate) database: PathBuf,
    }

    impl TestFiles {
        fn new(label: &str) -> Self {
            let ordinal = NEXT_TEST.fetch_add(1, Ordering::Relaxed);
            let root = std::env::temp_dir().join(format!(
                "grok-build-v35-{label}-{}-{ordinal}",
                std::process::id()
            ));
            fs::create_dir_all(&root).expect("create v35 test workspace");
            let database = root.join("ledger.sqlite3");
            Self { root, database }
        }
    }

    impl Drop for TestFiles {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.root);
        }
    }

    pub(crate) struct LaunchFixture {
        pub(crate) ledger: EventLedger,
        pub(crate) issued_grant: IssuedWorkspaceGrant,
        pub(crate) compiled_policy: CompiledExecutionPolicy,
        pub(crate) operational: PersistedOperationalCurrentFinalVerificationAttemptV1,
        pub(crate) request: CurrentFinalVerificationLaunchRequestV1,
        pub(crate) files: TestFiles,
    }

    fn digest(label: &str) -> Digest {
        Digest::sha256(label.as_bytes())
    }

    fn command() -> CommandSpec {
        CommandSpec {
            program: "cargo".into(),
            arguments: vec!["test".into(), "--workspace".into()],
            working_directory: PathBuf::new(),
        }
    }

    fn current_pair(sprint_id: &str, grant: WorkspaceGrant) -> (SprintSpecV2, TaskGraphV2) {
        let criteria = vec![
            AcceptanceCriterion {
                criterion_id: "automated".into(),
                description: "repository verification succeeds".into(),
                kind: AcceptanceKind::Automated(command()),
            },
            AcceptanceCriterion {
                criterion_id: "human".into(),
                description: "human accepts the exact snapshot".into(),
                kind: AcceptanceKind::HumanJudgment,
            },
        ];
        let mut tasks = vec![TaskSpecV2 {
            sprint_authority_version: SPRINT_AUTHORITY_CONTRACT_VERSION_V2,
            task_id: "ordinary".into(),
            purpose: TaskPurposeV2::Ordinary,
            goal: "finish the exact change".into(),
            dependencies: Vec::new(),
            path_scopes: vec![PathScope::Relative(PathBuf::from("src"))],
            acceptance_checks: vec!["automated".into(), "human".into()],
            base_snapshot: digest("base"),
            required: true,
        }];
        for slot_ordinal in 1..3 {
            let mut dependencies = vec!["ordinary".into()];
            if slot_ordinal > 1 {
                dependencies.push(format!("repair-{}", slot_ordinal - 1));
            }
            tasks.push(TaskSpecV2 {
                sprint_authority_version: SPRINT_AUTHORITY_CONTRACT_VERSION_V2,
                task_id: format!("repair-{slot_ordinal}"),
                purpose: TaskPurposeV2::FinalVerificationRepairSlot { slot_ordinal },
                goal: format!("repair verifier failure {slot_ordinal}"),
                dependencies,
                path_scopes: vec![PathScope::Relative(PathBuf::from("src"))],
                acceptance_checks: vec!["automated".into(), "human".into()],
                base_snapshot: digest("base"),
                required: false,
            });
        }
        let graph_id = format!("graph-{sprint_id}");
        let mut graph = TaskGraphV2 {
            sprint_authority_version: SPRINT_AUTHORITY_CONTRACT_VERSION_V2,
            graph_id: graph_id.clone(),
            sprint_id: sprint_id.into(),
            sprint_spec_digest: digest("placeholder-spec"),
            repair_slot_reserve_digest: digest("placeholder-reserve"),
            tasks,
        };
        graph.repair_slot_reserve_digest = graph
            .computed_repair_slot_reserve_digest()
            .expect("derive repair reserve");
        let mut spec = SprintSpecV2 {
            sprint_authority_version: SPRINT_AUTHORITY_CONTRACT_VERSION_V2,
            sprint_id: sprint_id.into(),
            objective: "prove exact current final verification".into(),
            acceptance_criteria: criteria,
            provider: ProviderProfile {
                backend_id: "fake".into(),
                model_id: "deterministic".into(),
                execution_origin: ExecutionOrigin::HostIsolated,
            },
            budget: SprintBudgetV2 {
                sprint_authority_version: SPRINT_AUTHORITY_CONTRACT_VERSION_V2,
                max_tasks: 5,
                max_attempts_per_task: 2,
                max_final_verification_attempts: 3,
                max_tool_calls: 50,
                max_duration_ms: 60_000,
            },
            max_workers: 1,
            workspace_grant: grant,
            base_snapshot: digest("base"),
            task_graph_id: graph_id,
            task_graph_payload_digest: graph.payload_digest().expect("graph payload"),
            repair_slot_reserve_digest: graph.repair_slot_reserve_digest.clone(),
        };
        graph.sprint_spec_digest = spec.canonical_digest().expect("sprint digest");
        spec.task_graph_payload_digest = graph.payload_digest().expect("stable graph payload");
        graph
            .validate_for_sprint(&spec)
            .expect("valid current sprint/graph pair");
        (spec, graph)
    }

    fn admission_request(
        spec: &SprintSpecV2,
        graph: &TaskGraphV2,
        policy_digest: Digest,
    ) -> CurrentFinalVerificationAdmissionRequestV1 {
        let snapshot = digest("result");
        let mut task_member = CurrentTaskDoneMemberV1 {
            source_ordinal: 0,
            task_id: "ordinary".into(),
            task_done_proof_id: "placeholder-task-done".into(),
            integration_receipt_id: "integration-ordinary".into(),
            integration_evidence: CurrentTaskDoneIntegrationEvidenceV1::Changed,
            input_snapshot: digest("base"),
            result_snapshot: snapshot.clone(),
        };
        task_member.task_done_proof_id =
            current_task_done_source_v32::test_source_for_member(spec, graph, &task_member)
                .expect("derive exact TaskDone source")
                .task_done_proof_id;
        let task_done_set = CompleteTaskDoneSetV1 {
            set_version: 1,
            sprint_id: spec.sprint_id.clone(),
            snapshot_digest: snapshot.clone(),
            members: vec![task_member],
            recorded_at_unix_ms: 20,
        };
        let receipts = current_criterion_evidence_v32::test_criterion_receipts_for_snapshot_v32(
            spec, &snapshot, 21,
        )
        .expect("derive criterion receipts");
        let criterion_evidence_set = CompleteCriterionEvidenceSetV1 {
            set_version: 1,
            sprint_id: spec.sprint_id.clone(),
            snapshot_digest: snapshot.clone(),
            members: vec![
                CurrentCriterionEvidenceMemberV1 {
                    criterion_ordinal: 0,
                    criterion_id: "automated".into(),
                    evidence_receipt_id: receipts[0].receipt_id().to_owned(),
                    evidence_kind: CurrentCriterionEvidenceKindV1::Verified,
                    snapshot_digest: snapshot.clone(),
                },
                CurrentCriterionEvidenceMemberV1 {
                    criterion_ordinal: 1,
                    criterion_id: "human".into(),
                    evidence_receipt_id: receipts[1].receipt_id().to_owned(),
                    evidence_kind: CurrentCriterionEvidenceKindV1::AcceptedByYou,
                    snapshot_digest: snapshot,
                },
            ],
            recorded_at_unix_ms: 21,
        };
        CurrentFinalVerificationAdmissionRequestV1 {
            request_id: format!("admit-{}", spec.sprint_id),
            sprint_id: spec.sprint_id.clone(),
            task_done_set,
            criterion_evidence_set,
            final_verification_check: command(),
            execution_policy_digest: policy_digest,
            coordinator_instance_id: "coordinator-v35".into(),
            admitted_at_unix_ms: 30,
        }
    }

    fn launch_fixture_with_opener(
        label: &str,
        open_ledger: impl FnOnce(&TestFiles) -> EventLedger,
    ) -> LaunchFixture {
        let files = TestFiles::new(label);
        let issued_grant = WorkspaceGrantIssuer::issue(WorkspaceGrantRequest {
            grant_id: format!("grant-{label}"),
            workspace_root: files.root.clone(),
            permissions: WorkspacePermissions::trusted(),
            network: WorkspaceNetworkPolicy::Denied,
            policy_version: 1,
        })
        .expect("issue exact workspace grant");
        let compiled_policy = ExecutionPolicyCompiler::compile(
            &issued_grant,
            ExecutionPolicyRequest {
                policy_id: format!("policy-{label}"),
                read_scopes: vec![PathScope::Workspace],
                write_scopes: Vec::new(),
                environment: Vec::<EnvironmentVariable>::new(),
                network: ExecutionNetwork::None,
                mutation_mode: MutationMode::ReadOnly,
                resource_limits: ResourceLimits {
                    wall_time_ms: 60_000,
                    max_output_bytes: 1_048_576,
                    max_processes: 16,
                    max_memory_bytes: None,
                },
                approval_id: None,
            },
        )
        .expect("compile exact final-verifier policy");
        let sprint_id = format!("sprint-{label}");
        let (spec, graph) = current_pair(&sprint_id, issued_grant.contract().clone());
        let mut ledger = open_ledger(&files);
        ledger
            .create_current_sprint_authority_v32(&spec, &graph, 10)
            .expect("create current sprint authority");
        let admission = admission_request(
            &spec,
            &graph,
            compiled_policy.contract().policy_hash.clone(),
        );
        let operational = ledger
            .admit_operational_current_final_verification_attempt_v34(&admission)
            .expect("admit operational final verifier");
        let preparation = CurrentFinalVerificationLaunchPreparationV1 {
            preparation_version: 1,
            preparation_id: format!("preparation-{label}"),
            containment_backend:
                CurrentFinalVerificationNativeContainmentBackendV2::MacOsDedicatedIdentitySeatbelt,
            target_identity_digest: digest("target-macos-15-arm64"),
            native_policy_digest: digest("seatbelt-policy"),
            runner_binary_digest: digest("runner-binary"),
            runner_binary_size_bytes: 1_024,
            runner_protocol_version: 13,
            runner_protocol_digest: digest("runner-protocol-v13"),
            private_state_id: format!("private-state-{label}"),
            private_state_digest: digest("private-state"),
        };
        let request = CurrentFinalVerificationLaunchRequestV1 {
            launch_request_version: 1,
            launch_request_id: format!("launch-request-{label}"),
            attempt_id: operational.operational_attempt.attempt_id.clone(),
            operational_attempt_digest: operational
                .operational_attempt
                .operational_attempt_digest
                .clone(),
            launch_preparation: preparation,
            workspace_grant: issued_grant.contract().clone(),
            execution_policy: compiled_policy.contract().clone(),
            exact_command: command(),
            detector_policy: SensitiveOutputDetectionPolicyReferenceV1::core_v1(),
            max_aggregate_output_bytes: super::super::current_command_output_capture_maximum_v1(
                compiled_policy.contract().resource_limits.max_output_bytes,
            )
            .expect("derive capture ceiling"),
            committed_at_unix_ms: 40,
        };
        LaunchFixture {
            ledger,
            issued_grant,
            compiled_policy,
            operational,
            request,
            files,
        }
    }

    pub(crate) fn launch_fixture(label: &str) -> LaunchFixture {
        launch_fixture_with_opener(label, |files| {
            EventLedger::open(&files.database).expect("open current launch fixture ledger")
        })
    }

    pub(crate) fn exact_v35_launch_fixture(label: &str) -> LaunchFixture {
        launch_fixture_with_opener(label, |files| {
            create_exact_database(&files.database, 35);
            open_exact_v34_writer(&files.database)
        })
    }

    pub(crate) fn token(
        request: &CurrentFinalVerificationLaunchRequestV1,
    ) -> AuthenticatedCurrentFinalVerificationNativePreparationV1 {
        AuthenticatedCurrentFinalVerificationNativePreparationV1::from_test(
            request.launch_preparation.clone(),
        )
    }

    fn derived_launch(
        fixture: &LaunchFixture,
    ) -> (
        CurrentFinalVerificationAuthorityEventV1,
        CurrentFinalVerificationLaunchAuthorityV1,
        LaunchWriteGuardV1,
    ) {
        let request_digest = fixture.request.canonical_digest().expect("request digest");
        let reservations = derive_lifecycle_reservations(
            &fixture.operational.operational_attempt.attempt_id,
            &request_digest,
        )
        .expect("derive reservations");
        let event = launch_event(
            &fixture.operational.operational_attempt,
            &fixture.request.launch_request_id,
            request_digest.clone(),
            fixture.request.committed_at_unix_ms,
        )
        .expect("derive launch event");
        let sprint = fixture
            .ledger
            .load_current_sprint_authority_v32(&fixture.operational.operational_attempt.sprint_id)
            .expect("load exact current sprint");
        let authority = CurrentFinalVerificationLaunchAuthorityV1::new(
            &fixture.operational.operational_attempt,
            &sprint.spec,
            &fixture.request,
            request_digest,
            reservations,
            &event,
        )
        .expect("derive exact launch authority");
        let guard = LaunchWriteGuardV1 {
            attempt_id: authority.attempt_id.clone(),
            event_digest: event.event_digest.clone(),
            launch_authority_digest: authority.launch_authority_digest.clone(),
            reservation_ids: reservation_pairs(&authority.reservations.fields)
                .into_iter()
                .map(|(_, identity)| identity.to_owned())
                .collect(),
        };
        (event, authority, guard)
    }

    const LAUNCH_INSERT_COLUMNS_V35: [&str; 33] = [
        "attempt_id",
        "launch_version",
        "sprint_id",
        "operational_attempt_digest",
        "launch_request_id",
        "launch_request_digest",
        "launch_request_json",
        "preparation_id",
        "launch_preparation_digest",
        "reservation_digest",
        "reservations_json",
        "capture_intent_id",
        "capture_intent_digest",
        "containment_backend",
        "target_identity_digest",
        "native_policy_digest",
        "runner_binary_digest",
        "runner_binary_size_bytes",
        "runner_protocol_version",
        "runner_protocol_digest",
        "private_state_id",
        "private_state_digest",
        "workspace_grant_hash",
        "execution_policy_digest",
        "verification_command_digest",
        "v13_command_request_digest",
        "detector_policy_digest",
        "max_aggregate_output_bytes",
        "launch_event_id",
        "launch_event_sequence",
        "committed_at_unix_ms",
        "launch_authority_digest",
        "launch_authority_json",
    ];

    fn launch_insert_values(
        request: &CurrentFinalVerificationLaunchRequestV1,
        authority: &CurrentFinalVerificationLaunchAuthorityV1,
    ) -> Vec<Value> {
        let preparation = &authority.launch_preparation;
        vec![
            Value::Text(authority.attempt_id.clone()),
            Value::Integer(i64::from(authority.launch_version)),
            Value::Text(authority.sprint_id.clone()),
            Value::Text(authority.operational_attempt_digest.to_string()),
            Value::Text(authority.launch_request_id.clone()),
            Value::Text(authority.launch_request_digest.to_string()),
            Value::Blob(request.canonical_bytes().expect("canonical launch request")),
            Value::Text(preparation.preparation_id.clone()),
            Value::Text(authority.launch_preparation_digest.to_string()),
            Value::Text(authority.reservations.reservation_digest.to_string()),
            Value::Blob(encode_canonical(&authority.reservations).expect("canonical reservations")),
            Value::Text(authority.reservations.fields.capture_intent_id.clone()),
            Value::Text(authority.capture_intent.intent_digest.to_string()),
            Value::Text(preparation.containment_backend.launch_sql_kind().into()),
            Value::Text(preparation.target_identity_digest.to_string()),
            Value::Text(preparation.native_policy_digest.to_string()),
            Value::Text(preparation.runner_binary_digest.to_string()),
            Value::Integer(
                i64::try_from(preparation.runner_binary_size_bytes)
                    .expect("runner binary size fits SQLite"),
            ),
            Value::Integer(i64::from(preparation.runner_protocol_version)),
            Value::Text(preparation.runner_protocol_digest.to_string()),
            Value::Text(preparation.private_state_id.clone()),
            Value::Text(preparation.private_state_digest.to_string()),
            Value::Text(authority.workspace_grant.grant_hash.to_string()),
            Value::Text(authority.execution_policy.policy_hash.to_string()),
            Value::Text(authority.verification_command_digest.to_string()),
            Value::Text(authority.v13_command_request_digest.to_string()),
            Value::Text(authority.detector_policy.policy_digest.to_string()),
            Value::Integer(
                i64::try_from(authority.max_aggregate_output_bytes)
                    .expect("capture ceiling fits SQLite"),
            ),
            Value::Text(authority.launch_event_id.clone()),
            Value::Integer(
                i64::try_from(authority.launch_event_sequence)
                    .expect("launch event sequence fits SQLite"),
            ),
            Value::Integer(
                i64::try_from(authority.committed_at_unix_ms)
                    .expect("launch commit time fits SQLite"),
            ),
            Value::Text(authority.launch_authority_digest.to_string()),
            Value::Blob(
                authority
                    .canonical_bytes()
                    .expect("canonical launch authority"),
            ),
        ]
    }

    fn execute_launch_insert_values(
        connection: &Connection,
        values: &[Value],
        replace: bool,
    ) -> rusqlite::Result<usize> {
        assert_eq!(values.len(), LAUNCH_INSERT_COLUMNS_V35.len());
        let algorithm = if replace { " OR REPLACE" } else { "" };
        let sql = format!(
            "INSERT{algorithm} INTO current_final_verification_launches_v35 ({}) VALUES ({})",
            LAUNCH_INSERT_COLUMNS_V35.join(", "),
            (1..=LAUNCH_INSERT_COLUMNS_V35.len())
                .map(|index| format!("?{index}"))
                .collect::<Vec<_>>()
                .join(", "),
        );
        connection.execute(&sql, params_from_iter(values))
    }

    #[test]
    fn v35_schema_is_closed_strict_and_names_every_projection() {
        assert_eq!(MIGRATION_V35.matches("CREATE TABLE ").count(), 4);
        assert_eq!(MIGRATION_V35.matches("STRICT, WITHOUT ROWID").count(), 4);
        assert!(MIGRATION_V35.contains("AND 49 = ("));
        assert!(MIGRATION_V35.contains("DEFERRABLE INITIALLY DEFERRED"));
        assert!(MIGRATION_V35.contains("WHEN 'LaunchCommitted' THEN"));
        assert!(MIGRATION_V35.contains("ELSE 1"));
        for (column, json_path) in [
            ("launch_version", "$.launch_version"),
            ("attempt_id", "$.attempt_id"),
            ("launch_request_id", "$.launch_request_id"),
            ("launch_request_digest", "$.launch_request_digest"),
            ("preparation_id", "$.launch_preparation.preparation_id"),
            ("reservation_digest", "$.reservations.reservation_digest"),
            (
                "capture_intent_id",
                "$.reservations.fields.capture_intent_id",
            ),
            ("capture_intent_digest", "$.capture_intent.intent_digest"),
            ("v13_command_request_digest", "$.v13_command_request_digest"),
            ("launch_event_id", "$.launch_event_id"),
            ("launch_authority_digest", "$.launch_authority_digest"),
        ] {
            assert!(MIGRATION_V35.contains(column), "missing column {column}");
            assert!(
                MIGRATION_V35.contains(json_path),
                "missing path {json_path}"
            );
        }
        let fixture = launch_fixture("schema");
        verify_exact_schema(&fixture.ledger.connection).expect("fresh schema extends exact v35");
        let version: i64 = fixture
            .ledger
            .connection
            .pragma_query_value(None, "user_version", |row| row.get(0))
            .expect("read schema version");
        assert_eq!(version, super::super::SCHEMA_VERSION);
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "one adversarial test keeps fresh, replay, restart, and crossed move-only permit behavior in a single lifecycle"
    )]
    fn fresh_commit_replay_restart_and_instance_bound_permit_are_exact() {
        let mut fixture = launch_fixture("fresh-replay");
        let result = fixture
            .ledger
            .commit_current_final_verification_launch_v35(
                &fixture.request,
                token(&fixture.request),
                &fixture.issued_grant,
                &fixture.compiled_policy,
            )
            .expect("commit fresh launch");
        let (persisted, permit) = match result {
            CurrentFinalVerificationLaunchCommitV1::Fresh {
                persisted,
                capture_acquisition_permit,
            } => (persisted, capture_acquisition_permit),
            CurrentFinalVerificationLaunchCommitV1::Replay { .. } => {
                panic!("first launch must be fresh")
            }
        };
        assert_eq!(persisted.launch_event.event_sequence, 2);
        assert_eq!(
            persisted.launch_event.event_kind,
            CurrentFinalVerificationAuthorityEventKindV1::LaunchCommitted,
        );
        assert_eq!(
            persisted.launch_event.request_id,
            fixture.request.launch_request_id
        );
        assert_eq!(
            persisted.launch_event.request_digest,
            fixture.request.canonical_digest().expect("request digest"),
        );
        assert_eq!(
            persisted.launch_event,
            launch_event(
                &fixture.operational.operational_attempt,
                &fixture.request.launch_request_id,
                fixture.request.canonical_digest().expect("request digest"),
                fixture.request.committed_at_unix_ms,
            )
            .expect("formula-derived launch event"),
        );
        assert_eq!(
            persisted.launch_event.event_digest,
            persisted
                .launch_event
                .computed_event_digest()
                .expect("formula-derived event digest"),
        );
        assert_eq!(
            persisted.launch_authority.reservations.fields.dispatch_id,
            current_final_verification_dispatch_claim_id(
                &persisted.launch_authority.reservations.fields.effect_id,
            )
            .expect("derive dispatch claim"),
        );
        assert_eq!(
            persisted.launch_authority.capture_intent,
            persisted
                .launch_authority
                .v13_command_output_capture_intent()
                .expect("project exact V1 capture intent"),
        );
        assert_eq!(
            persisted.launch_authority.verification_command_digest,
            super::super::final_verification_authority_v32::operational_command_digest(
                &fixture.request.exact_command,
            )
            .expect("established operational command digest"),
        );
        assert_ne!(
            persisted.launch_authority.verification_command_digest,
            persisted.launch_authority.v13_command_request_digest,
            "the established operational digest and plain V13 request digest are distinct domains",
        );
        let reservation_count: i64 = fixture
            .ledger
            .connection
            .query_row(
                "SELECT COUNT(*) FROM current_final_verification_lifecycle_reservations_v35",
                [],
                |row| row.get(0),
            )
            .expect("count reservations");
        assert_eq!(reservation_count, 49);

        let reopened = EventLedger::open(&fixture.files.database).expect("reopen same database");
        let reopened_readback = reopened
            .load_current_final_verification_launch_v35(&fixture.request.attempt_id)
            .expect("restart readback");
        assert_eq!(reopened_readback, persisted);
        assert!(
            permit
                .consume_for_ledger_instance(reopened.instance_id, &reopened_readback)
                .is_err(),
            "a fresh permit must not cross a reopened ledger instance"
        );
        drop(reopened);

        let replay = fixture
            .ledger
            .commit_current_final_verification_launch_v35(
                &fixture.request,
                token(&fixture.request),
                &fixture.issued_grant,
                &fixture.compiled_policy,
            )
            .expect("exact replay");
        assert!(matches!(
            replay,
            CurrentFinalVerificationLaunchCommitV1::Replay {
                persisted: ref replayed
            }
                if replayed == &persisted
        ));

        let mut second = launch_fixture("crossed-same-instance-permit");
        let second_result = second
            .ledger
            .commit_current_final_verification_launch_v35(
                &second.request,
                token(&second.request),
                &second.issued_grant,
                &second.compiled_policy,
            )
            .expect("commit second fresh launch");
        if let CurrentFinalVerificationLaunchCommitV1::Fresh {
            persisted: _,
            capture_acquisition_permit,
        } = second_result
        {
            assert!(
                capture_acquisition_permit
                    .consume_for_ledger_instance(second.ledger.instance_id, &persisted)
                    .is_err(),
                "a same-instance permit must reject a different persisted launch/capture",
            );
        } else {
            panic!("second independent launch must be fresh");
        }

        let mut third = launch_fixture("same-instance-permit-control");
        let third_result = third
            .ledger
            .commit_current_final_verification_launch_v35(
                &third.request,
                token(&third.request),
                &third.issued_grant,
                &third.compiled_policy,
            )
            .expect("commit same-instance control launch");
        if let CurrentFinalVerificationLaunchCommitV1::Fresh {
            persisted,
            capture_acquisition_permit,
        } = third_result
        {
            capture_acquisition_permit
                .consume_for_ledger_instance(third.ledger.instance_id, &persisted)
                .expect("exact same-instance permit validates once");
        } else {
            panic!("third independent launch must be fresh");
        }
    }

    #[cfg(unix)]
    #[test]
    fn postcommit_hardening_uncertainty_never_returns_or_remints_a_fresh_permit() {
        let mut fixture = launch_fixture("postcommit-uncertainty");
        let hardlink = fixture
            .files
            .root
            .join("launch-postcommit-hardlink.sqlite3");
        fs::hard_link(&fixture.files.database, &hardlink)
            .expect("install launch post-commit hardening fault");
        assert!(matches!(
            fixture
                .ledger
                .commit_current_final_verification_launch_v35(
                    &fixture.request,
                    token(&fixture.request),
                    &fixture.issued_grant,
                    &fixture.compiled_policy,
                ),
            Err(LedgerError::PostCommitStateUncertain {
                operation: "current final-verification launch commit",
                ref recovery_id,
                ..
            }) if recovery_id == &fixture.request.attempt_id
        ));
        fs::remove_file(&hardlink).expect("remove launch post-commit hardening fault");

        let committed = fixture
            .ledger
            .load_current_final_verification_launch_v35(&fixture.request.attempt_id)
            .expect("recover the exact committed launch without a permit");
        let replay = fixture
            .ledger
            .commit_current_final_verification_launch_v35(
                &fixture.request,
                token(&fixture.request),
                &fixture.issued_grant,
                &fixture.compiled_policy,
            )
            .expect("recover by exact readback-only replay");
        assert!(matches!(
            replay,
            CurrentFinalVerificationLaunchCommitV1::Replay { persisted }
                if persisted == committed
        ));
        let counts: (i64, i64, i64) = fixture
            .ledger
            .connection
            .query_row(
                "SELECT
                    (SELECT COUNT(*) FROM current_final_verification_launches_v35),
                    (SELECT COUNT(*) FROM current_final_verification_lifecycle_reservations_v35),
                    (SELECT COUNT(*) FROM current_final_verification_events_v34)",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .expect("read post-uncertainty authority counts");
        assert_eq!(counts, (1, 49, 2));
    }

    #[test]
    fn launch_request_rejects_unrepresentable_role_and_capture_shapes() {
        let fixture = launch_fixture("negative-shapes");
        let baseline = fixture.request;

        let mut shell = baseline.clone();
        shell.exact_command.program = "BASH".into();
        assert!(shell.validate_intrinsic().is_err());
        assert!(
            current_final_verification_v13_command_request_digest(&shell.exact_command).is_err()
        );

        let mut git = baseline.clone();
        git.exact_command.working_directory = PathBuf::from("src/.GiT/hooks");
        assert!(git.validate_intrinsic().is_err());

        let mut network = baseline.clone();
        network.execution_policy.network = ExecutionNetwork::FullForAction;
        network.execution_policy.policy_hash = network
            .execution_policy
            .computed_hash()
            .expect("rehash crossed policy");
        assert!(network.validate_intrinsic().is_err());

        let mut writes = baseline.clone();
        writes.execution_policy.mutation_mode = MutationMode::ShadowWorkspace;
        writes.execution_policy.write_scopes = vec![PathScope::Relative(PathBuf::from("src"))];
        writes.execution_policy.policy_hash = writes
            .execution_policy
            .computed_hash()
            .expect("rehash crossed write policy");
        assert!(writes.validate_intrinsic().is_err());

        let mut wrong_capture = baseline.clone();
        wrong_capture.max_aggregate_output_bytes = wrong_capture
            .execution_policy
            .resource_limits
            .max_output_bytes;
        assert!(wrong_capture.validate_intrinsic().is_err());

        let mut finite_mac_memory = baseline;
        finite_mac_memory
            .execution_policy
            .resource_limits
            .max_memory_bytes = Some(1_000_000);
        finite_mac_memory.execution_policy.policy_hash = finite_mac_memory
            .execution_policy
            .computed_hash()
            .expect("rehash finite-memory policy");
        assert!(finite_mac_memory.validate_intrinsic().is_err());
    }

    #[test]
    fn reservations_are_deterministic_v13_compatible_and_not_caller_rebindable() {
        let fixture = launch_fixture("reservation-law");
        let request_digest = fixture.request.canonical_digest().expect("request digest");
        let reservations = derive_lifecycle_reservations(
            &fixture.operational.operational_attempt.attempt_id,
            &request_digest,
        )
        .expect("derive reservations");
        assert_eq!(reservation_pairs(&reservations.fields).len(), 49);
        assert_eq!(
            reservations.fields.dispatch_id,
            current_final_verification_dispatch_claim_id(&reservations.fields.effect_id)
                .expect("dispatch formula"),
        );
        assert_ne!(
            reservations.fields.effect_idempotency_key,
            reservations.fields.effect_id
        );
        assert_eq!(
            reservations,
            derive_lifecycle_reservations(
                &fixture.operational.operational_attempt.attempt_id,
                &request_digest,
            )
            .expect("rederive exact reservations")
        );

        let event = launch_event(
            &fixture.operational.operational_attempt,
            &fixture.request.launch_request_id,
            request_digest.clone(),
            fixture.request.committed_at_unix_ms,
        )
        .expect("derive launch event");
        let sprint = fixture
            .ledger
            .load_current_sprint_authority_v32(&fixture.operational.operational_attempt.sprint_id)
            .expect("load sprint");
        let mut authority = CurrentFinalVerificationLaunchAuthorityV1::new(
            &fixture.operational.operational_attempt,
            &sprint.spec,
            &fixture.request,
            request_digest,
            reservations,
            &event,
        )
        .expect("derive authority");
        authority.reservations.fields.effect_idempotency_key = digest("caller-choice").to_string();
        authority.reservations = CurrentFinalVerificationLifecycleReservationSetV2::new(
            authority.reservations.fields.clone(),
        )
        .expect("rebind a shape-valid caller reservation set");
        authority.capture_intent = derive_v13_capture_intent(
            &authority.sprint_id,
            &authority.reservations,
            &fixture.request,
        )
        .expect("rebind dependent capture intent");
        authority.launch_authority_digest = authority.computed_digest().expect("rebind authority");
        assert!(
            authority
                .validate_for(
                    &fixture.operational.operational_attempt,
                    &sprint.spec,
                    &fixture.request,
                    &event,
                )
                .is_err(),
            "shape-valid caller reservations must not replace core derivation"
        );
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "one table-driven authority test proves every crossed wrapper and idempotency collision leaves one shared row set untouched"
    )]
    fn crossed_launch_inputs_and_idempotency_collisions_leave_no_partial_authority() {
        let mut fixture = launch_fixture("crossed-native-plan");
        let counts = |connection: &Connection| -> (i64, i64, i64) {
            connection
                .query_row(
                    "SELECT
                        (SELECT COUNT(*) FROM current_final_verification_launches_v35),
                        (SELECT COUNT(*) FROM current_final_verification_lifecycle_reservations_v35),
                        (SELECT COUNT(*) FROM current_final_verification_events_v34)",
                    [],
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
                )
                .expect("count launch authority rows")
        };
        let assert_untouched = |connection: &Connection, label: &str| {
            assert_eq!(counts(connection), (0, 0, 1), "{label}");
        };

        let mut crossed = fixture.request.launch_preparation.clone();
        crossed.runner_binary_digest = digest("different-runner");
        let result = fixture.ledger.commit_current_final_verification_launch_v35(
            &fixture.request,
            AuthenticatedCurrentFinalVerificationNativePreparationV1::from_test(crossed),
            &fixture.issued_grant,
            &fixture.compiled_policy,
        );
        assert!(result.is_err());
        assert_untouched(&fixture.ledger.connection, "crossed native plan");

        let wrong_issued = WorkspaceGrantIssuer::issue(WorkspaceGrantRequest {
            grant_id: "grant-crossed-wrapper".into(),
            workspace_root: fixture.files.root.clone(),
            permissions: WorkspacePermissions::trusted(),
            network: WorkspaceNetworkPolicy::Denied,
            policy_version: 1,
        })
        .expect("issue crossed grant wrapper");
        assert!(
            fixture
                .ledger
                .commit_current_final_verification_launch_v35(
                    &fixture.request,
                    token(&fixture.request),
                    &wrong_issued,
                    &fixture.compiled_policy,
                )
                .is_err()
        );
        assert_untouched(&fixture.ledger.connection, "crossed issued grant");

        let wrong_policy = ExecutionPolicyCompiler::compile(
            &fixture.issued_grant,
            ExecutionPolicyRequest {
                policy_id: "policy-crossed-wrapper".into(),
                read_scopes: vec![PathScope::Workspace],
                write_scopes: vec![],
                environment: vec![],
                network: ExecutionNetwork::None,
                mutation_mode: MutationMode::ReadOnly,
                resource_limits: ResourceLimits {
                    wall_time_ms: 60_000,
                    max_output_bytes: 1_048_576,
                    max_processes: 16,
                    max_memory_bytes: None,
                },
                approval_id: None,
            },
        )
        .expect("compile crossed policy wrapper");
        assert!(
            fixture
                .ledger
                .commit_current_final_verification_launch_v35(
                    &fixture.request,
                    token(&fixture.request),
                    &fixture.issued_grant,
                    &wrong_policy,
                )
                .is_err()
        );
        assert_untouched(&fixture.ledger.connection, "crossed compiled policy");

        let mut crossed_command = fixture.request.clone();
        crossed_command
            .exact_command
            .arguments
            .push("--all-targets".into());
        assert!(
            fixture
                .ledger
                .commit_current_final_verification_launch_v35(
                    &crossed_command,
                    token(&crossed_command),
                    &fixture.issued_grant,
                    &fixture.compiled_policy,
                )
                .is_err()
        );
        assert_untouched(&fixture.ledger.connection, "crossed exact command");

        let mut crossed_detector = fixture.request.clone();
        crossed_detector.detector_policy.policy_id = "crossed-detector".into();
        assert!(
            fixture
                .ledger
                .commit_current_final_verification_launch_v35(
                    &crossed_detector,
                    token(&crossed_detector),
                    &fixture.issued_grant,
                    &fixture.compiled_policy,
                )
                .is_err()
        );
        assert_untouched(&fixture.ledger.connection, "crossed detector");

        let mut crossed_operational_digest = fixture.request.clone();
        crossed_operational_digest.operational_attempt_digest = digest("crossed-operational");
        assert!(
            fixture
                .ledger
                .commit_current_final_verification_launch_v35(
                    &crossed_operational_digest,
                    token(&crossed_operational_digest),
                    &fixture.issued_grant,
                    &fixture.compiled_policy,
                )
                .is_err()
        );
        assert_untouched(&fixture.ledger.connection, "crossed operational digest");

        let mut crossed_attempt_id = fixture.request.clone();
        crossed_attempt_id.attempt_id = "missing-operational-attempt".into();
        assert!(
            fixture
                .ledger
                .commit_current_final_verification_launch_v35(
                    &crossed_attempt_id,
                    token(&crossed_attempt_id),
                    &fixture.issued_grant,
                    &fixture.compiled_policy,
                )
                .is_err()
        );
        assert_untouched(&fixture.ledger.connection, "crossed operational identity");

        let mut reused_parent_request_id = fixture.request.clone();
        reused_parent_request_id.launch_request_id =
            fixture.operational.operational_attempt.request_id.clone();
        assert!(
            fixture
                .ledger
                .commit_current_final_verification_launch_v35(
                    &reused_parent_request_id,
                    token(&reused_parent_request_id),
                    &fixture.issued_grant,
                    &fixture.compiled_policy,
                )
                .is_err()
        );
        assert_untouched(
            &fixture.ledger.connection,
            "reused admission request identity",
        );

        let fresh = fixture
            .ledger
            .commit_current_final_verification_launch_v35(
                &fixture.request,
                token(&fixture.request),
                &fixture.issued_grant,
                &fixture.compiled_policy,
            )
            .expect("commit exact launch after crossed inputs");
        assert!(fresh.is_fresh());
        let exact = fresh.persisted().clone();
        assert_eq!(counts(&fixture.ledger.connection), (1, 49, 2));

        let mut crossed_launch_request_id = fixture.request.clone();
        crossed_launch_request_id.launch_request_id = "different-launch-request".into();
        assert!(
            fixture
                .ledger
                .commit_current_final_verification_launch_v35(
                    &crossed_launch_request_id,
                    token(&crossed_launch_request_id),
                    &fixture.issued_grant,
                    &fixture.compiled_policy,
                )
                .is_err()
        );
        let mut reused_launch_request_id = fixture.request.clone();
        reused_launch_request_id.committed_at_unix_ms += 1;
        assert!(
            fixture
                .ledger
                .commit_current_final_verification_launch_v35(
                    &reused_launch_request_id,
                    token(&reused_launch_request_id),
                    &fixture.issued_grant,
                    &fixture.compiled_policy,
                )
                .is_err()
        );
        let replay = fixture
            .ledger
            .commit_current_final_verification_launch_v35(
                &fixture.request,
                token(&fixture.request),
                &fixture.issued_grant,
                &fixture.compiled_policy,
            )
            .expect("exact launch replay");
        assert!(matches!(
            replay,
            CurrentFinalVerificationLaunchCommitV1::Replay { persisted }
                if persisted == exact
        ));
        assert_eq!(counts(&fixture.ledger.connection), (1, 49, 2));
    }

    #[test]
    fn direct_sql_and_later_frontier_events_remain_closed() {
        let fixture = launch_fixture("direct-sql");
        let direct_launch = fixture.ledger.connection.execute(
            "INSERT INTO current_final_verification_launches_v35 (
                attempt_id, launch_version, sprint_id, operational_attempt_digest,
                launch_request_id, launch_request_digest, launch_request_json,
                preparation_id, launch_preparation_digest, reservation_digest,
                reservations_json, capture_intent_id, capture_intent_digest,
                containment_backend, target_identity_digest, native_policy_digest,
                runner_binary_digest, runner_binary_size_bytes, runner_protocol_version,
                runner_protocol_digest, private_state_id, private_state_digest,
                workspace_grant_hash, execution_policy_digest,
                verification_command_digest, v13_command_request_digest,
                detector_policy_digest, max_aggregate_output_bytes, launch_event_id,
                launch_event_sequence, committed_at_unix_ms,
                launch_authority_digest, launch_authority_json
             ) SELECT attempt_id, 1, sprint_id, operational_attempt_digest,
                'direct-launch', request_digest, operational_json,
                'direct-prep', request_digest, request_digest, operational_json,
                request_digest, request_digest, 'MacOsDedicatedIdentitySeatbelt',
                request_digest, request_digest, request_digest, 1, 13,
                request_digest, 'direct-private', request_digest,
                workspace_grant_hash, execution_policy_digest,
                verification_command_digest, request_digest, request_digest,
                1, request_digest, admission_event_sequence + 1,
                admitted_at_unix_ms + 1, request_digest, operational_json
             FROM current_final_verification_operational_attempts_v34",
            [],
        );
        assert!(direct_launch.is_err());

        let later_event = CurrentFinalVerificationAuthorityEventV1 {
            event_version: 1,
            event_id: digest("future-event").to_string(),
            sprint_id: fixture.operational.operational_attempt.sprint_id.clone(),
            event_sequence: 2,
            event_kind: CurrentFinalVerificationAuthorityEventKindV1::CaptureAcquired,
            attempt_id: fixture.operational.operational_attempt.attempt_id.clone(),
            request_id: "future-request".into(),
            request_digest: digest("future-request"),
            occurred_at_unix_ms: 40,
            event_digest: digest("placeholder"),
        };
        let mut later_event = later_event;
        later_event.event_digest = later_event
            .computed_event_digest()
            .expect("derive future event digest");
        let direct_event = fixture.ledger.connection.execute(
            "INSERT INTO current_final_verification_events_v34 (
                sprint_id, event_sequence, event_id, event_version, event_kind,
                attempt_id, request_id, request_digest, occurred_at_unix_ms,
                event_digest, event_json
             ) VALUES (?1, ?2, ?3, 1, 'CaptureAcquired', ?4, ?5, ?6, ?7, ?8, ?9)",
            params![
                later_event.sprint_id,
                i64::try_from(later_event.event_sequence).expect("sequence fits"),
                later_event.event_id,
                later_event.attempt_id,
                later_event.request_id,
                later_event.request_digest.as_str(),
                i64::try_from(later_event.occurred_at_unix_ms).expect("time fits"),
                later_event.event_digest.as_str(),
                later_event
                    .canonical_bytes()
                    .expect("canonical later event"),
            ],
        );
        assert!(direct_event.is_err());
    }

    #[test]
    fn every_launch_transaction_crash_cut_rolls_back_to_admission_only() {
        let mut fixture = launch_fixture("launch-crash-cuts");
        let (event, authority, guard) = derived_launch(&fixture);
        for cut in 0..=3 {
            let transaction = fixture
                .ledger
                .connection
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .expect("begin launch crash-cut transaction");
            transaction
                .pragma_update(None, "defer_foreign_keys", true)
                .expect("defer launch event parent");
            with_launch_write_guard(guard.clone(), || {
                insert_launch_v35(&transaction, &fixture.request, &authority)?;
                if cut == 1 {
                    let (role, reserved_id) = reservation_pairs(&authority.reservations.fields)[0];
                    transaction.execute(
                        "INSERT INTO current_final_verification_lifecycle_reservations_v35 (
                            attempt_id, reservation_role, reserved_id, reservation_digest
                         ) VALUES (?1, ?2, ?3, ?4)",
                        params![
                            authority.attempt_id,
                            role,
                            reserved_id,
                            authority.reservations.reservation_digest.as_str(),
                        ],
                    )?;
                } else if cut >= 2 {
                    insert_lifecycle_reservations_v35(&transaction, &authority)?;
                }
                if cut == 3 {
                    insert_launch_event_v35(&transaction, &event)?;
                }
                Ok(())
            })
            .expect("materialize exact crash-cut prefix");
            transaction
                .rollback()
                .expect("simulate process crash rollback");
            let counts: (i64, i64, i64) = fixture
                .ledger
                .connection
                .query_row(
                    "SELECT
                        (SELECT COUNT(*) FROM current_final_verification_launches_v35),
                        (SELECT COUNT(*) FROM current_final_verification_lifecycle_reservations_v35),
                        (SELECT COUNT(*) FROM current_final_verification_events_v34)",
                    [],
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
                )
                .expect("read post-crash-cut counts");
            assert_eq!(counts, (0, 0, 1), "crash cut {cut}");
        }
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "the explicit primary and alternate unique-identity collision inventory is intentionally exhaustive"
    )]
    fn insert_or_replace_cannot_cross_primary_or_alternate_launch_identities() {
        let mut fixture = launch_fixture("replace-collisions");
        let fresh = fixture
            .ledger
            .commit_current_final_verification_launch_v35(
                &fixture.request,
                token(&fixture.request),
                &fixture.issued_grant,
                &fixture.compiled_policy,
            )
            .expect("commit replacement target");
        let persisted = fresh.persisted().clone();
        let baseline = launch_insert_values(&fixture.request, &persisted.launch_authority);
        let collision_columns = [
            "attempt_id",
            "operational_attempt_digest",
            "launch_request_id",
            "launch_request_digest",
            "preparation_id",
            "launch_preparation_digest",
            "reservation_digest",
            "capture_intent_id",
            "capture_intent_digest",
            "private_state_id",
            "private_state_digest",
            "launch_event_id",
            "launch_authority_digest",
        ];
        fixture
            .ledger
            .connection
            .pragma_update(None, "recursive_triggers", false)
            .expect("disable recursive delete-trigger defense for explicit guard proof");
        for target in collision_columns {
            let mut crossed = baseline.clone();
            for column in collision_columns {
                let position = LAUNCH_INSERT_COLUMNS_V35
                    .iter()
                    .position(|candidate| candidate == &column)
                    .expect("collision column exists");
                crossed[position] = match column {
                    "attempt_id" | "launch_request_id" | "preparation_id" | "private_state_id" => {
                        Value::Text(format!("replacement-{target}-{column}"))
                    }
                    _ => Value::Text(digest(&format!("replacement-{target}-{column}")).to_string()),
                };
            }
            let target_position = LAUNCH_INSERT_COLUMNS_V35
                .iter()
                .position(|candidate| candidate == &target)
                .expect("target collision column exists");
            crossed[target_position] = baseline[target_position].clone();
            let attempt_id = match &crossed[0] {
                Value::Text(value) => value.clone(),
                _ => panic!("attempt identity remains text"),
            };
            let launch_authority_digest = match &crossed[31] {
                Value::Text(value) => Digest::parse(value).expect("authority digest shape"),
                _ => panic!("launch authority digest remains text"),
            };
            let guard = LaunchWriteGuardV1 {
                attempt_id,
                event_digest: persisted.launch_event.event_digest.clone(),
                launch_authority_digest,
                reservation_ids: BTreeSet::new(),
            };
            let error = with_launch_write_guard(guard, || {
                execute_launch_insert_values(&fixture.ledger.connection, &crossed, true)?;
                Ok(())
            })
            .expect_err("replacement collision must fail");
            assert!(
                error
                    .to_string()
                    .contains("current final-verification launch identity already exists"),
                "{target} was not rejected by the explicit no-replace guard: {error}",
            );
            assert_eq!(
                fixture
                    .ledger
                    .load_current_final_verification_launch_v35(&fixture.request.attempt_id)
                    .expect("read unchanged launch after replacement collision"),
                persisted,
                "{target}",
            );
        }

        let (reservation_role, reserved_id) =
            reservation_pairs(&persisted.launch_authority.reservations.fields)[0];
        for (label, attempt_id, role) in [
            (
                "reservation primary",
                persisted.launch_authority.attempt_id.clone(),
                reservation_role.to_owned(),
            ),
            (
                "reservation alternate reserved_id",
                "replacement-reservation-attempt".into(),
                reservation_role.to_owned(),
            ),
        ] {
            let guard = LaunchWriteGuardV1 {
                attempt_id: attempt_id.clone(),
                event_digest: persisted.launch_event.event_digest.clone(),
                launch_authority_digest: persisted.launch_authority.launch_authority_digest.clone(),
                reservation_ids: BTreeSet::from([reserved_id.to_owned()]),
            };
            let error =
                with_launch_write_guard(guard, || {
                    fixture.ledger.connection.execute(
                    "INSERT OR REPLACE INTO current_final_verification_lifecycle_reservations_v35 (
                        attempt_id, reservation_role, reserved_id, reservation_digest
                     ) VALUES (?1, ?2, ?3, ?4)",
                    params![
                        attempt_id,
                        role,
                        reserved_id,
                        persisted.launch_authority.reservations.reservation_digest.as_str(),
                    ],
                )?;
                    Ok(())
                })
                .expect_err("reservation replacement collision must fail");
            assert!(
                error.to_string().contains(
                    "current final-verification lifecycle reservation identity already exists"
                ),
                "{label} was not rejected by the explicit no-replace guard: {error}",
            );
        }
        fixture
            .ledger
            .connection
            .pragma_update(None, "recursive_triggers", true)
            .expect("restore required recursive-trigger setting");
        assert_eq!(
            fixture
                .ledger
                .connection
                .query_row(
                    "SELECT COUNT(*) FROM current_final_verification_lifecycle_reservations_v35",
                    [],
                    |row| row.get::<_, i64>(0),
                )
                .expect("count unchanged reservations"),
            49,
        );
    }

    fn create_exact_database(path: &Path, migration_count: usize) {
        crate::ledger::tests::schema_template::install_exact_database_at(
            u8::try_from(migration_count).expect("template version fits u8"),
            path,
        );
    }

    fn open_exact_v34_writer(path: &Path) -> EventLedger {
        let connection = Connection::open(path).expect("open exact v34 writer");
        register_schema_functions(&connection).expect("register v34 writer functions");
        connection
            .execute_batch(
                "PRAGMA foreign_keys = ON;
                 PRAGMA recursive_triggers = ON;
                 PRAGMA synchronous = FULL;
                 PRAGMA temp_store = MEMORY;
                 PRAGMA trusted_schema = OFF;",
            )
            .expect("configure exact v34 writer");
        let _: String = connection
            .query_row("PRAGMA journal_mode = WAL", [], |row| row.get(0))
            .expect("enable source WAL");
        EventLedger {
            connection,
            database_path: path.to_path_buf(),
            read_only: false,
            instance_id: next_event_ledger_instance_id(),
        }
    }

    #[derive(Debug, Eq, PartialEq)]
    enum RawSqliteValue {
        Null,
        Integer(i64),
        RealBits(u64),
        Text(Vec<u8>),
        Blob(Vec<u8>),
    }

    fn raw_table_image(
        connection: &Connection,
        table: &str,
        order_by: &str,
        expected_columns: usize,
    ) -> Vec<Vec<RawSqliteValue>> {
        let sql = format!("SELECT * FROM {table} ORDER BY {order_by}");
        let mut statement = connection.prepare(&sql).expect("prepare raw table image");
        assert_eq!(statement.column_count(), expected_columns, "{table}");
        let mut rows = statement.query([]).expect("query raw table image");
        let mut image = Vec::new();
        while let Some(row) = rows.next().expect("read raw table row") {
            let mut values = Vec::with_capacity(expected_columns);
            for index in 0..expected_columns {
                values.push(match row.get_ref(index).expect("read raw SQLite value") {
                    ValueRef::Null => RawSqliteValue::Null,
                    ValueRef::Integer(value) => RawSqliteValue::Integer(value),
                    ValueRef::Real(value) => RawSqliteValue::RealBits(value.to_bits()),
                    ValueRef::Text(bytes) => RawSqliteValue::Text(bytes.to_vec()),
                    ValueRef::Blob(bytes) => RawSqliteValue::Blob(bytes.to_vec()),
                });
            }
            image.push(values);
        }
        image
    }

    fn raw_v34_row_image(
        connection: &Connection,
    ) -> (Vec<Vec<RawSqliteValue>>, Vec<Vec<RawSqliteValue>>) {
        (
            raw_table_image(
                connection,
                "current_final_verification_events_v34",
                "sprint_id, event_sequence",
                11,
            ),
            raw_table_image(
                connection,
                "current_final_verification_operational_attempts_v34",
                "attempt_id",
                27,
            ),
        )
    }

    #[test]
    fn populated_v34_migrates_without_changing_rows_and_foreign_keys_are_clean() {
        let files = TestFiles::new("populated-upgrade");
        create_exact_database(&files.database, 34);
        let issued = WorkspaceGrantIssuer::issue(WorkspaceGrantRequest {
            grant_id: "grant-populated-upgrade".into(),
            workspace_root: files.root.clone(),
            permissions: WorkspacePermissions::trusted(),
            network: WorkspaceNetworkPolicy::Denied,
            policy_version: 1,
        })
        .expect("issue migration fixture grant");
        let (spec, graph) = current_pair("sprint-populated-upgrade", issued.contract().clone());
        let policy = ExecutionPolicyCompiler::compile(
            &issued,
            ExecutionPolicyRequest {
                policy_id: "policy-populated-upgrade".into(),
                read_scopes: vec![PathScope::Workspace],
                write_scopes: vec![],
                environment: vec![],
                network: ExecutionNetwork::None,
                mutation_mode: MutationMode::ReadOnly,
                resource_limits: ResourceLimits {
                    wall_time_ms: 1_000,
                    max_output_bytes: 1_024,
                    max_processes: 2,
                    max_memory_bytes: None,
                },
                approval_id: None,
            },
        )
        .expect("compile migration policy");
        let mut source = open_exact_v34_writer(&files.database);
        source
            .create_current_sprint_authority_v32(&spec, &graph, 10)
            .expect("create migration sprint");
        let request = admission_request(&spec, &graph, policy.contract().policy_hash.clone());
        let before_loaded = source
            .admit_operational_current_final_verification_attempt_v34(&request)
            .expect("admit populated v34 row");
        let before_raw = raw_v34_row_image(&source.connection);
        drop(source);

        let upgraded = EventLedger::open(&files.database).expect("migrate populated v34 to v35");
        let after_loaded = upgraded
            .load_operational_current_final_verification_attempt_v34(
                &before_loaded.operational_attempt.attempt_id,
            )
            .expect("load preserved v34 authority");
        assert_eq!(after_loaded, before_loaded);
        assert_eq!(raw_v34_row_image(&upgraded.connection), before_raw);
        let no_launch_backfill: (i64, i64, i64) = upgraded
            .connection
            .query_row(
                "SELECT
                    (SELECT COUNT(*) FROM current_final_verification_launches_v35),
                    (SELECT COUNT(*) FROM current_final_verification_lifecycle_reservations_v35),
                    (SELECT COUNT(*) FROM current_final_verification_events_v34
                     WHERE event_kind != 'AttemptAdmitted')",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .expect("read no-backfill projection");
        assert_eq!(no_launch_backfill, (0, 0, 0));
        verify_no_foreign_key_violations_v35(&upgraded.connection)
            .expect("upgraded foreign keys are clean");
        verify_exact_schema(&upgraded.connection).expect("upgraded schema equals fresh v35");
        let fk_parent: String = upgraded
            .connection
            .query_row(
                "SELECT \"table\" FROM pragma_foreign_key_list(
                    'current_final_verification_operational_attempts_v34'
                 ) WHERE \"from\" = 'admission_event_id'",
                [],
                |row| row.get(0),
            )
            .expect("read rebuilt child FK parent");
        assert_eq!(fk_parent, "current_final_verification_events_v34");
    }

    #[test]
    fn divergent_v34_is_rejected_before_v35_mutation() {
        let files = TestFiles::new("divergent-v34");
        create_exact_database(&files.database, 34);
        let divergent = Connection::open(&files.database).expect("open divergent source");
        divergent
            .execute_batch("CREATE TABLE unexpected_v34 (id TEXT PRIMARY KEY) STRICT;")
            .expect("inject divergent object");
        drop(divergent);
        let result = EventLedger::open(&files.database);
        assert!(matches!(
            result,
            Err(LedgerError::Corrupt {
                entity: "ledger schema migration source",
                ref detail,
            }) if detail.contains("exact version 34 source image")
        ));
        let unchanged =
            Connection::open_with_flags(&files.database, OpenFlags::SQLITE_OPEN_READ_ONLY)
                .expect("reopen divergent source");
        let version: i64 = unchanged
            .pragma_query_value(None, "user_version", |row| row.get(0))
            .expect("read unchanged version");
        assert_eq!(version, 34);
        let v35_tables: i64 = unchanged
            .query_row(
                "SELECT COUNT(*) FROM sqlite_schema
                 WHERE name IN (
                    'current_final_verification_launches_v35',
                    'current_final_verification_lifecycle_reservations_v35'
                 )",
                [],
                |row| row.get(0),
            )
            .expect("count premature v35 objects");
        assert_eq!(v35_tables, 0);
    }

    #[test]
    fn read_only_launch_commit_is_rejected_without_rows() {
        let fixture = launch_fixture("read-only");
        let database = fixture.files.database.clone();
        let request = fixture.request.clone();
        let issued = fixture.issued_grant.clone();
        let policy = fixture.compiled_policy.clone();
        drop(fixture.ledger);
        let mut reader = EventLedger::open_read_only(&database).expect("open v35 read-only");
        let result = reader.commit_current_final_verification_launch_v35(
            &request,
            token(&request),
            &issued,
            &policy,
        );
        assert!(matches!(result, Err(LedgerError::ReadOnly)));
    }

    #[test]
    fn request_and_event_canonical_tampering_is_rejected() {
        let fixture = launch_fixture("canonical-tamper");
        let request_bytes = fixture
            .request
            .canonical_bytes()
            .expect("canonical request");
        let mut alternate = request_bytes.clone();
        alternate.insert(1, b' ');
        assert!(sqlite_launch_request_canonical(&alternate).is_err());
        let mut unknown: serde_json::Value =
            serde_json::from_slice(&request_bytes).expect("decode request value");
        unknown
            .as_object_mut()
            .expect("request object")
            .insert("unknown".into(), serde_json::Value::Bool(true));
        assert!(
            sqlite_launch_request_canonical(
                &serde_json::to_vec(&unknown).expect("encode unknown request")
            )
            .is_err()
        );

        let request_digest = fixture.request.canonical_digest().expect("request digest");
        let event = launch_event(
            &fixture.operational.operational_attempt,
            &fixture.request.launch_request_id,
            request_digest,
            fixture.request.committed_at_unix_ms,
        )
        .expect("launch event");
        let mut crossed = event.clone();
        crossed.event_digest = digest("crossed-event-digest");
        assert!(crossed.validate_integrity().is_err());
        let mut crossed_id = event;
        crossed_id.event_id = digest("crossed-event-id").to_string();
        assert!(crossed_id.validate_integrity().is_err());
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "the 30-column normalized projection/path/tamper matrix is intentionally exhaustive"
    )]
    fn normalized_projection_trigger_covers_every_indexed_field() {
        let projections = [
            ("attempt_id", "$.attempt_id"),
            ("launch_version", "$.launch_version"),
            ("sprint_id", "$.sprint_id"),
            ("operational_attempt_digest", "$.operational_attempt_digest"),
            ("launch_request_id", "$.launch_request_id"),
            ("launch_request_digest", "$.launch_request_digest"),
            ("preparation_id", "$.launch_preparation.preparation_id"),
            ("launch_preparation_digest", "$.launch_preparation_digest"),
            ("reservation_digest", "$.reservations.reservation_digest"),
            (
                "capture_intent_id",
                "$.reservations.fields.capture_intent_id",
            ),
            ("capture_intent_digest", "$.capture_intent.intent_digest"),
            (
                "containment_backend",
                "$.launch_preparation.containment_backend",
            ),
            (
                "target_identity_digest",
                "$.launch_preparation.target_identity_digest",
            ),
            (
                "native_policy_digest",
                "$.launch_preparation.native_policy_digest",
            ),
            (
                "runner_binary_digest",
                "$.launch_preparation.runner_binary_digest",
            ),
            (
                "runner_binary_size_bytes",
                "$.launch_preparation.runner_binary_size_bytes",
            ),
            (
                "runner_protocol_version",
                "$.launch_preparation.runner_protocol_version",
            ),
            (
                "runner_protocol_digest",
                "$.launch_preparation.runner_protocol_digest",
            ),
            ("private_state_id", "$.launch_preparation.private_state_id"),
            (
                "private_state_digest",
                "$.launch_preparation.private_state_digest",
            ),
            ("workspace_grant_hash", "$.workspace_grant.grant_hash"),
            ("execution_policy_digest", "$.execution_policy.policy_hash"),
            (
                "verification_command_digest",
                "$.verification_command_digest",
            ),
            ("v13_command_request_digest", "$.v13_command_request_digest"),
            ("detector_policy_digest", "$.detector_policy.policy_digest"),
            ("max_aggregate_output_bytes", "$.max_aggregate_output_bytes"),
            ("launch_event_id", "$.launch_event_id"),
            ("launch_event_sequence", "$.launch_event_sequence"),
            ("committed_at_unix_ms", "$.committed_at_unix_ms"),
            ("launch_authority_digest", "$.launch_authority_digest"),
        ];
        let trigger_start = MIGRATION_V35
            .find("CREATE TRIGGER current_final_verification_launches_v35_validate_insert")
            .expect("launch validation trigger exists");
        let trigger_end = MIGRATION_V35[trigger_start..]
            .find("CREATE TRIGGER current_final_verification_lifecycle_reservations_v35_validate_insert")
            .expect("launch validation trigger ends");
        let trigger = &MIGRATION_V35[trigger_start..trigger_start + trigger_end];
        for (field, path) in projections {
            assert!(
                trigger.contains(&format!("NEW.{field}")),
                "normalized trigger omits {field}"
            );
            assert!(
                trigger.contains(path),
                "normalized trigger crosses {field} to the wrong JSON path"
            );
        }

        let mut fixture = launch_fixture("normalized-runtime");
        let (_event, authority, guard) = derived_launch(&fixture);
        let baseline = launch_insert_values(&fixture.request, &authority);
        let transaction = fixture
            .ledger
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .expect("begin normalized projection matrix");
        transaction
            .pragma_update(None, "defer_foreign_keys", true)
            .expect("defer launch event parent");
        with_launch_write_guard(guard, || {
            for (column, _) in projections {
                let position = LAUNCH_INSERT_COLUMNS_V35
                    .iter()
                    .position(|candidate| candidate == &column)
                    .expect("normalized column exists in insert projection");
                let mut crossed = baseline.clone();
                crossed[position] = match column {
                    "launch_version" => Value::Integer(2),
                    "runner_binary_size_bytes" => Value::Integer(2_048),
                    "runner_protocol_version" => Value::Integer(12),
                    "max_aggregate_output_bytes" => Value::Integer(
                        i64::try_from(authority.max_aggregate_output_bytes)
                            .expect("capture ceiling fits SQLite")
                            + 1,
                    ),
                    "launch_event_sequence" => Value::Integer(
                        i64::try_from(authority.launch_event_sequence)
                            .expect("event sequence fits SQLite")
                            + 1,
                    ),
                    "committed_at_unix_ms" => Value::Integer(
                        i64::try_from(authority.committed_at_unix_ms)
                            .expect("commit time fits SQLite")
                            + 1,
                    ),
                    "containment_backend" => {
                        Value::Text("LinuxBubblewrapLandlockSeccompCgroupV2".into())
                    }
                    "attempt_id" | "sprint_id" | "launch_request_id" | "preparation_id"
                    | "private_state_id" => Value::Text(format!("crossed-{column}")),
                    _ => Value::Text(digest(&format!("crossed-{column}")).to_string()),
                };
                let result = execute_launch_insert_values(&transaction, &crossed, false);
                assert!(
                    result.is_err(),
                    "runtime insert accepted crossed normalized column {column}"
                );
                let count: i64 = transaction.query_row(
                    "SELECT COUNT(*) FROM current_final_verification_launches_v35",
                    [],
                    |row| row.get(0),
                )?;
                assert_eq!(count, 0, "failed {column} insert left a row");
            }
            assert_eq!(
                execute_launch_insert_values(&transaction, &baseline, false)?,
                1,
                "exact unmodified control must pass the same guard and trigger",
            );
            Ok(())
        })
        .expect("run normalized projection matrix");
        transaction
            .rollback()
            .expect("roll back test-only launch without its event parent");
    }
}
