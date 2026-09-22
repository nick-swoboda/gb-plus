//! Schema-v32 current final-verification and bounded-repair authority.
//!
//! This module is deliberately parallel to the historical sprint and final-
//! verification tables. It owns durable current-contract readback and the
//! closed outcome/repair state machine, but it does not mint runner dispatch,
//! composition, application, or completion capability. Production admission
//! remains dormant until genuine current lifecycle writers populate the exact
//! `TaskDone` and criterion source receipts joined by schema v32.

#[cfg(test)]
use std::cell::Cell;
use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet};

use rusqlite::{Connection, OptionalExtension, Transaction, TransactionBehavior, params};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

use crate::{
    AcceptanceKind, CommandSpec, ContractError, Digest, FinalVerificationAttemptAuthorityV1,
    FinalVerificationAttemptExpectedInputsV1, FinalVerificationAttemptPredecessorV1,
    FinalVerificationAttemptProvenanceV1, MAX_CURRENT_FINAL_VERIFICATION_CANONICAL_BYTES_V2,
    MAX_CURRENT_FINAL_VERIFICATION_IDENTIFIER_BYTES_V2, SprintSpecV2, TaskGraphV2, TaskPurposeV2,
    validate_current_direct_exec_command_v1,
};

use super::{EventLedger, LedgerError, secure_database_files};

const CURRENT_SET_VERSION_V1: u32 = 1;
const CURRENT_OUTCOME_VERSION_V1: u32 = 1;
const TASK_DONE_SET_DIGEST_DOMAIN: &[u8] = b"grok-build/current-task-done-set-v1/canonical-json\0";
const CRITERION_EVIDENCE_SET_DIGEST_DOMAIN: &[u8] =
    b"grok-build/current-criterion-evidence-set-v1/canonical-json\0";
const ADMISSION_REQUEST_DIGEST_DOMAIN: &[u8] =
    b"grok-build/current-final-verification-admission-request-v1/canonical-json\0";
const CONTROL_ID_DOMAIN: &[u8] = b"grok-build/current-final-verification-control-v1/id\0";
const OUTCOME_ID_DOMAIN: &[u8] = b"grok-build/current-final-verification-outcome-v1/id\0";
const ATTEMPT_ID_DOMAIN: &[u8] = b"grok-build/current-final-verification-attempt-v1/id\0";
const ADMISSION_ID_DOMAIN: &[u8] = b"grok-build/current-final-verification-admission-v1/id\0";
const ADMISSION_EVENT_ID_DOMAIN: &[u8] =
    b"grok-build/current-final-verification-admission-event-v1/id\0";
const OPERATIONAL_EVENT_ID_DOMAIN_V1: &[u8] =
    b"grok-build/current-final-verification-operational-event-v1/id\0";
const OPERATIONAL_EVENT_DIGEST_DOMAIN_V1: &[u8] =
    b"grok-build/current-final-verification-operational-event-v1/canonical-json\0";
const OPERATIONAL_ATTEMPT_DIGEST_DOMAIN_V1: &[u8] =
    b"grok-build/current-final-verification-operational-attempt-v1/canonical-json\0";
const OPERATIONAL_COMMAND_DIGEST_DOMAIN_V1: &[u8] =
    b"grok-build/current-final-verification-operational-command-v1/canonical-json\0";
const REPAIR_ACTIVATION_ID_DOMAIN: &[u8] =
    b"grok-build/current-final-verification-repair-activation-v1/id\0";
const REPAIR_COMPLETION_REQUEST_DIGEST_DOMAIN: &[u8] =
    b"grok-build/current-final-verification-repair-completion-request-v1/canonical-json\0";
const REPAIR_COMPLETION_ID_DOMAIN: &[u8] =
    b"grok-build/current-final-verification-repair-completion-v1/id\0";

#[derive(Clone)]
struct OperationalAdmissionWriteGuardV1 {
    attempt_id: String,
    event_digest: Digest,
    operational_attempt_digest: Digest,
}

thread_local! {
    static OPERATIONAL_ADMISSION_WRITE_GUARD_V1:
        RefCell<Option<OperationalAdmissionWriteGuardV1>> = const { RefCell::new(None) };
}

#[cfg(test)]
thread_local! {
    static TEST_SOURCE_FIXTURE_SEEDING_ENABLED: Cell<bool> = const { Cell::new(true) };
}

#[cfg(test)]
fn test_source_fixture_seeding_enabled() -> bool {
    TEST_SOURCE_FIXTURE_SEEDING_ENABLED.with(Cell::get)
}

#[cfg(test)]
fn without_test_source_fixture_seeding<T>(operation: impl FnOnce() -> T) -> T {
    struct Restore(bool);
    impl Drop for Restore {
        fn drop(&mut self) {
            TEST_SOURCE_FIXTURE_SEEDING_ENABLED.with(|enabled| enabled.set(self.0));
        }
    }

    let prior = TEST_SOURCE_FIXTURE_SEEDING_ENABLED.with(|enabled| enabled.replace(false));
    let _restore = Restore(prior);
    operation()
}

#[derive(Serialize)]
struct ControlIdentity<'a> {
    sprint_id: &'a str,
    attempt_id: &'a str,
    control_kind: CurrentFinalVerificationControlKindV1,
    before_effect: bool,
    issued_at_unix_ms: u64,
}

#[derive(Serialize)]
struct RepairActivationIdentity<'a> {
    sprint_id: &'a str,
    failed_attempt_id: &'a str,
    failure_outcome_id: &'a str,
    failed_snapshot: &'a Digest,
    slot_ordinal: u8,
    repair_task_id: &'a str,
    activated_at_unix_ms: u64,
}

#[derive(Serialize)]
struct RepairCompletionIdentity<'a> {
    request_digest: &'a Digest,
    sprint_id: &'a str,
    failed_attempt_id: &'a str,
}

/// Closed integration-evidence shape for one current `TaskDone` source.
///
/// Schema v32 joins each member to an exact immutable source receipt. This
/// union also prevents an unchanged snapshot from being confused with an
/// ordinary changed integration while production source derivation remains
/// dormant.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum CurrentTaskDoneIntegrationEvidenceV1 {
    /// A nonempty integration produced a distinct result snapshot.
    Changed,
    /// An explicit empty `ChangeSet` was integrated without changing the
    /// snapshot.
    VerifiedNoOp {
        /// Exact identity of the explicit empty `ChangeSet`.
        empty_change_set_id: String,
    },
}

impl CurrentTaskDoneIntegrationEvidenceV1 {
    fn validate_for_snapshots(
        &self,
        input_snapshot: &Digest,
        result_snapshot: &Digest,
    ) -> Result<(), ContractError> {
        match self {
            Self::Changed if input_snapshot == result_snapshot => Err(ContractError::new(
                "current_task_done_member.result_snapshot",
                "Changed integration evidence requires a distinct result snapshot",
            )),
            Self::VerifiedNoOp {
                empty_change_set_id,
            } => {
                require_nonblank(
                    "current_task_done_member.integration_evidence.empty_change_set_id",
                    empty_change_set_id,
                )?;
                if input_snapshot != result_snapshot {
                    return Err(ContractError::new(
                        "current_task_done_member.result_snapshot",
                        "VerifiedNoOp evidence requires an unchanged snapshot",
                    ));
                }
                Ok(())
            }
            Self::Changed => Ok(()),
        }
    }

    fn sql_kind(&self) -> &'static str {
        match self {
            Self::Changed => "Changed",
            Self::VerifiedNoOp { .. } => "VerifiedNoOp",
        }
    }

    fn empty_change_set_id(&self) -> Option<&str> {
        match self {
            Self::Changed => None,
            Self::VerifiedNoOp {
                empty_change_set_id,
            } => Some(empty_change_set_id),
        }
    }
}

/// One member of the complete current `TaskDone` integration chain.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CurrentTaskDoneMemberV1 {
    /// Zero-based contiguous source ordinal.
    pub source_ordinal: u32,
    /// Exact task identity.
    pub task_id: String,
    /// Exact independently derived `TaskDone` proof identity.
    pub task_done_proof_id: String,
    /// Exact integration receipt identity.
    pub integration_receipt_id: String,
    /// Typed changed or explicit verified-no-op integration evidence.
    pub integration_evidence: CurrentTaskDoneIntegrationEvidenceV1,
    /// Snapshot consumed by this integration source.
    pub input_snapshot: Digest,
    /// Snapshot produced by this integration source.
    pub result_snapshot: Digest,
}

impl CurrentTaskDoneMemberV1 {
    fn validate(&self) -> Result<(), ContractError> {
        for (field, value) in [
            ("current_task_done_member.task_id", self.task_id.as_str()),
            (
                "current_task_done_member.task_done_proof_id",
                self.task_done_proof_id.as_str(),
            ),
            (
                "current_task_done_member.integration_receipt_id",
                self.integration_receipt_id.as_str(),
            ),
        ] {
            require_nonblank(field, value)?;
        }
        self.integration_evidence
            .validate_for_snapshots(&self.input_snapshot, &self.result_snapshot)
    }
}

/// Canonical complete current `TaskDone` set and contiguous integration chain.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CompleteTaskDoneSetV1 {
    /// Contract discriminator.
    pub set_version: u32,
    /// Owning sprint identity.
    pub sprint_id: String,
    /// Result snapshot of the complete chain.
    pub snapshot_digest: Digest,
    /// Every integrated `TaskDone` source in exact ordinal order.
    pub members: Vec<CurrentTaskDoneMemberV1>,
    /// Durable observation time.
    pub recorded_at_unix_ms: u64,
}

impl CompleteTaskDoneSetV1 {
    /// Validates this complete set against the exact current sprint and graph.
    ///
    /// # Errors
    ///
    /// Returns an error for crossed sprint/task identities, missing required
    /// tasks, noncontiguous ordinals or snapshots, or out-of-order repair slots.
    #[allow(clippy::too_many_lines)] // Complete-set validation keeps graph coverage, chain continuity, and dormant-slot order in one closed check.
    pub fn validate_for(
        &self,
        sprint: &SprintSpecV2,
        graph: &TaskGraphV2,
    ) -> Result<(), ContractError> {
        graph.validate_for_sprint(sprint)?;
        require_version("complete_task_done_set.set_version", self.set_version)?;
        require_nonblank("complete_task_done_set.sprint_id", &self.sprint_id)?;
        require_nonzero(
            "complete_task_done_set.recorded_at_unix_ms",
            self.recorded_at_unix_ms,
        )?;
        if self.sprint_id != sprint.sprint_id {
            return Err(ContractError::new(
                "complete_task_done_set.sprint_id",
                "must equal the current sprint identity",
            ));
        }
        if self.members.is_empty() {
            return Err(ContractError::new(
                "complete_task_done_set.members",
                "must contain at least one integrated TaskDone source",
            ));
        }

        let graph_tasks = graph
            .tasks
            .iter()
            .map(|task| (task.task_id.as_str(), task))
            .collect::<BTreeMap<_, _>>();
        let mut task_ids = BTreeSet::new();
        let mut proof_ids = BTreeSet::new();
        let mut integration_ids = BTreeSet::new();
        let mut empty_change_set_ids = BTreeSet::new();
        let mut expected_input = sprint.base_snapshot.clone();
        let mut repair_ordinals = Vec::new();
        for (index, member) in self.members.iter().enumerate() {
            member.validate()?;
            let expected_ordinal = u32::try_from(index).map_err(|_| {
                ContractError::new(
                    "complete_task_done_set.members",
                    "member count exceeds the supported ordinal range",
                )
            })?;
            if member.source_ordinal != expected_ordinal {
                return Err(ContractError::new(
                    "complete_task_done_set.members",
                    "source ordinals must be contiguous from zero",
                ));
            }
            if member.input_snapshot != expected_input {
                return Err(ContractError::new(
                    "complete_task_done_set.members",
                    "integration snapshots must form one contiguous chain from the sprint base",
                ));
            }
            let task = graph_tasks.get(member.task_id.as_str()).ok_or_else(|| {
                ContractError::new(
                    "complete_task_done_set.members",
                    format!("unknown task `{}`", member.task_id),
                )
            })?;
            if let TaskPurposeV2::FinalVerificationRepairSlot { slot_ordinal } = task.purpose {
                if !matches!(
                    &member.integration_evidence,
                    CurrentTaskDoneIntegrationEvidenceV1::Changed
                ) {
                    return Err(ContractError::new(
                        "complete_task_done_set.members",
                        "a final-verification repair slot must integrate a changed, nonempty source",
                    ));
                }
                repair_ordinals.push(slot_ordinal);
            }
            if member
                .integration_evidence
                .empty_change_set_id()
                .is_some_and(|identity| !empty_change_set_ids.insert(identity))
            {
                return Err(ContractError::new(
                    "complete_task_done_set.members",
                    "explicit empty ChangeSet identities must be unique",
                ));
            }
            if !task_ids.insert(member.task_id.as_str())
                || !proof_ids.insert(member.task_done_proof_id.as_str())
                || !integration_ids.insert(member.integration_receipt_id.as_str())
            {
                return Err(ContractError::new(
                    "complete_task_done_set.members",
                    "task, TaskDone proof, and integration identities must each be unique",
                ));
            }
            expected_input.clone_from(&member.result_snapshot);
        }
        if expected_input != self.snapshot_digest {
            return Err(ContractError::new(
                "complete_task_done_set.snapshot_digest",
                "must equal the last result in the contiguous integration chain",
            ));
        }

        for task in graph
            .tasks
            .iter()
            .filter(|task| task.required && task.purpose == TaskPurposeV2::Ordinary)
        {
            if !task_ids.contains(task.task_id.as_str()) {
                return Err(ContractError::new(
                    "complete_task_done_set.members",
                    format!("required ordinary task `{}` is missing", task.task_id),
                ));
            }
        }
        let expected_repairs = (1..=repair_ordinals.len())
            .map(u8::try_from)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| {
                ContractError::new(
                    "complete_task_done_set.members",
                    "repair-slot ordinal exceeds the supported range",
                )
            })?;
        if repair_ordinals != expected_repairs {
            return Err(ContractError::new(
                "complete_task_done_set.members",
                "integrated repair slots must be a contiguous prefix in slot order",
            ));
        }
        Ok(())
    }

    /// Returns exact compact canonical bytes after intrinsic validation.
    ///
    /// # Errors
    ///
    /// Returns an error when the set shape or serialization is invalid.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, ContractError> {
        self.validate_intrinsic()?;
        encode_canonical("complete_task_done_set", self)
    }

    /// Returns the domain-separated canonical set digest.
    ///
    /// # Errors
    ///
    /// Returns an error when canonicalization fails.
    pub fn canonical_digest(&self) -> Result<Digest, ContractError> {
        Ok(domain_digest(
            TASK_DONE_SET_DIGEST_DOMAIN,
            &self.canonical_bytes()?,
        ))
    }

    fn validate_intrinsic(&self) -> Result<(), ContractError> {
        require_version("complete_task_done_set.set_version", self.set_version)?;
        require_nonblank("complete_task_done_set.sprint_id", &self.sprint_id)?;
        require_nonzero(
            "complete_task_done_set.recorded_at_unix_ms",
            self.recorded_at_unix_ms,
        )?;
        if self.members.is_empty() {
            return Err(ContractError::new(
                "complete_task_done_set.members",
                "must not be empty",
            ));
        }
        for (index, member) in self.members.iter().enumerate() {
            member.validate()?;
            if member.source_ordinal
                != u32::try_from(index).map_err(|_| {
                    ContractError::new(
                        "complete_task_done_set.members",
                        "member ordinal exceeds u32",
                    )
                })?
            {
                return Err(ContractError::new(
                    "complete_task_done_set.members",
                    "source ordinals must be contiguous from zero",
                ));
            }
        }
        Ok(())
    }
}

/// Closed evidence-kind vocabulary for one current criterion.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum CurrentCriterionEvidenceKindV1 {
    /// Machine verification evidence.
    Verified,
    /// One-to-one authenticated human acceptance evidence.
    AcceptedByYou,
}

/// One criterion and its exact same-snapshot evidence receipt.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CurrentCriterionEvidenceMemberV1 {
    /// Zero-based criterion declaration ordinal.
    pub criterion_ordinal: u32,
    /// Exact criterion identity.
    pub criterion_id: String,
    /// Exact verification or human-decision receipt identity.
    pub evidence_receipt_id: String,
    /// Typed evidence kind; machine and human claims remain distinct.
    pub evidence_kind: CurrentCriterionEvidenceKindV1,
    /// Exact snapshot judged or verified.
    pub snapshot_digest: Digest,
}

/// Canonical complete same-snapshot criterion-evidence set.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CompleteCriterionEvidenceSetV1 {
    /// Contract discriminator.
    pub set_version: u32,
    /// Owning sprint identity.
    pub sprint_id: String,
    /// Exact snapshot shared by every receipt.
    pub snapshot_digest: Digest,
    /// Exactly one receipt for every declared criterion, in declaration order.
    pub members: Vec<CurrentCriterionEvidenceMemberV1>,
    /// Durable observation time.
    pub recorded_at_unix_ms: u64,
}

impl CompleteCriterionEvidenceSetV1 {
    /// Validates complete, same-snapshot, type-correct criterion coverage.
    ///
    /// # Errors
    ///
    /// Returns an error for missing, extra, reordered, crossed-snapshot, or
    /// machine/human-substituted evidence.
    pub fn validate_for(&self, sprint: &SprintSpecV2) -> Result<(), ContractError> {
        sprint.validate()?;
        self.validate_intrinsic()?;
        if self.sprint_id != sprint.sprint_id {
            return Err(ContractError::new(
                "complete_criterion_evidence_set.sprint_id",
                "must equal the current sprint identity",
            ));
        }
        if self.members.len() != sprint.acceptance_criteria.len() {
            return Err(ContractError::new(
                "complete_criterion_evidence_set.members",
                "must contain exactly one member for every sprint criterion",
            ));
        }
        for (index, (member, criterion)) in self
            .members
            .iter()
            .zip(&sprint.acceptance_criteria)
            .enumerate()
        {
            if member.criterion_ordinal
                != u32::try_from(index).map_err(|_| {
                    ContractError::new(
                        "complete_criterion_evidence_set.members",
                        "criterion ordinal exceeds u32",
                    )
                })?
                || member.criterion_id != criterion.criterion_id
                || member.snapshot_digest != self.snapshot_digest
            {
                return Err(ContractError::new(
                    "complete_criterion_evidence_set.members",
                    "criterion order, identity, or snapshot differs from the current sprint",
                ));
            }
            let expected_kind = match criterion.kind {
                AcceptanceKind::Automated(_) => CurrentCriterionEvidenceKindV1::Verified,
                AcceptanceKind::HumanJudgment => CurrentCriterionEvidenceKindV1::AcceptedByYou,
            };
            if member.evidence_kind != expected_kind {
                return Err(ContractError::new(
                    "complete_criterion_evidence_set.members",
                    "machine Verified and human AcceptedByYou evidence are not substitutable",
                ));
            }
        }
        Ok(())
    }

    /// Returns exact compact canonical bytes.
    ///
    /// # Errors
    ///
    /// Returns an error when intrinsic shape or serialization is invalid.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, ContractError> {
        self.validate_intrinsic()?;
        encode_canonical("complete_criterion_evidence_set", self)
    }

    /// Returns the domain-separated canonical set digest.
    ///
    /// # Errors
    ///
    /// Returns an error when canonicalization fails.
    pub fn canonical_digest(&self) -> Result<Digest, ContractError> {
        Ok(domain_digest(
            CRITERION_EVIDENCE_SET_DIGEST_DOMAIN,
            &self.canonical_bytes()?,
        ))
    }

    fn validate_intrinsic(&self) -> Result<(), ContractError> {
        require_version(
            "complete_criterion_evidence_set.set_version",
            self.set_version,
        )?;
        require_nonblank("complete_criterion_evidence_set.sprint_id", &self.sprint_id)?;
        require_nonzero(
            "complete_criterion_evidence_set.recorded_at_unix_ms",
            self.recorded_at_unix_ms,
        )?;
        if self.members.is_empty() {
            return Err(ContractError::new(
                "complete_criterion_evidence_set.members",
                "must not be empty",
            ));
        }
        let mut criteria = BTreeSet::new();
        let mut receipts = BTreeSet::new();
        for (index, member) in self.members.iter().enumerate() {
            require_nonblank(
                "complete_criterion_evidence_set.member.criterion_id",
                &member.criterion_id,
            )?;
            require_nonblank(
                "complete_criterion_evidence_set.member.evidence_receipt_id",
                &member.evidence_receipt_id,
            )?;
            if member.criterion_ordinal
                != u32::try_from(index).map_err(|_| {
                    ContractError::new(
                        "complete_criterion_evidence_set.members",
                        "criterion ordinal exceeds u32",
                    )
                })?
                || member.snapshot_digest != self.snapshot_digest
                || !criteria.insert(member.criterion_id.as_str())
                || !receipts.insert(member.evidence_receipt_id.as_str())
            {
                return Err(ContractError::new(
                    "complete_criterion_evidence_set.members",
                    "members must be contiguous, same-snapshot, and identity-unique",
                ));
            }
        }
        Ok(())
    }
}

/// Idempotent request whose authority-bearing ordinal and predecessor are
/// derived inside the ledger transaction.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CurrentFinalVerificationAdmissionRequestV1 {
    /// Stable idempotency identity; it is not an attempt ordinal or permit.
    pub request_id: String,
    /// Current sprint to verify.
    pub sprint_id: String,
    /// Complete current `TaskDone` set.
    pub task_done_set: CompleteTaskDoneSetV1,
    /// Complete same-snapshot criterion evidence.
    pub criterion_evidence_set: CompleteCriterionEvidenceSetV1,
    /// Exact repository-wide verification command.
    pub final_verification_check: CommandSpec,
    /// Exact current execution-policy digest.
    pub execution_policy_digest: Digest,
    /// Trusted coordinator process instance holding admission authority.
    pub coordinator_instance_id: String,
    /// Durable admission timestamp.
    pub admitted_at_unix_ms: u64,
}

impl CurrentFinalVerificationAdmissionRequestV1 {
    fn validate_intrinsic(&self) -> Result<(), ContractError> {
        require_nonblank(
            "current_final_verification_request.request_id",
            &self.request_id,
        )?;
        require_nonblank(
            "current_final_verification_request.sprint_id",
            &self.sprint_id,
        )?;
        require_nonblank(
            "current_final_verification_request.coordinator_instance_id",
            &self.coordinator_instance_id,
        )?;
        require_nonzero(
            "current_final_verification_request.admitted_at_unix_ms",
            self.admitted_at_unix_ms,
        )?;
        self.task_done_set.validate_intrinsic()?;
        self.criterion_evidence_set.validate_intrinsic()?;
        if self.task_done_set.sprint_id != self.sprint_id
            || self.criterion_evidence_set.sprint_id != self.sprint_id
        {
            return Err(ContractError::new(
                "current_final_verification_request.sprint_id",
                "request and complete sets must share one sprint identity",
            ));
        }
        if self.task_done_set.snapshot_digest != self.criterion_evidence_set.snapshot_digest {
            return Err(ContractError::new(
                "current_final_verification_request.criterion_evidence_set",
                "TaskDone and criterion evidence must bind the same snapshot",
            ));
        }
        if self.task_done_set.recorded_at_unix_ms > self.admitted_at_unix_ms
            || self.criterion_evidence_set.recorded_at_unix_ms > self.admitted_at_unix_ms
        {
            return Err(ContractError::new(
                "current_final_verification_request.admitted_at_unix_ms",
                "admission cannot predate either complete evidence set",
            ));
        }
        self.final_verification_check.validate()
    }

    fn validate_for(
        &self,
        sprint: &SprintSpecV2,
        graph: &TaskGraphV2,
    ) -> Result<(), ContractError> {
        self.validate_intrinsic()?;
        if self.sprint_id != sprint.sprint_id {
            return Err(ContractError::new(
                "current_final_verification_request.sprint_id",
                "must equal the current sprint identity",
            ));
        }
        self.task_done_set.validate_for(sprint, graph)?;
        self.criterion_evidence_set.validate_for(sprint)?;
        Ok(())
    }

    fn canonical_bytes(&self) -> Result<Vec<u8>, ContractError> {
        self.validate_intrinsic()?;
        encode_canonical("current_final_verification_request", self)
    }

    fn canonical_digest(&self) -> Result<Digest, ContractError> {
        Ok(domain_digest(
            ADMISSION_REQUEST_DIGEST_DOMAIN,
            &self.canonical_bytes()?,
        ))
    }
}

/// Authenticated control cause relevant to one admitted verifier attempt.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum CurrentFinalVerificationControlKindV1 {
    /// Pause requested by the trusted coordinator.
    Pause,
    /// Authenticated steering interruption.
    SteeringInterruption,
    /// Explicit sprint cancellation.
    Cancel,
}

/// Immutable core-minted control record.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CurrentFinalVerificationControlV1 {
    /// Contract discriminator.
    pub control_version: u32,
    /// Deterministic core-minted identity.
    pub control_id: String,
    /// Owning sprint identity.
    pub sprint_id: String,
    /// Exact attempt interrupted or canceled.
    pub attempt_id: String,
    /// Typed authenticated control cause.
    pub control_kind: CurrentFinalVerificationControlKindV1,
    /// Whether control was proven before any command effect.
    pub before_effect: bool,
    /// Durable issue time.
    pub issued_at_unix_ms: u64,
}

impl CurrentFinalVerificationControlV1 {
    fn validate(&self) -> Result<(), ContractError> {
        require_version(
            "current_final_verification_control.control_version",
            self.control_version,
        )?;
        for (field, value) in [
            (
                "current_final_verification_control.control_id",
                self.control_id.as_str(),
            ),
            (
                "current_final_verification_control.sprint_id",
                self.sprint_id.as_str(),
            ),
            (
                "current_final_verification_control.attempt_id",
                self.attempt_id.as_str(),
            ),
        ] {
            require_nonblank(field, value)?;
        }
        require_nonzero(
            "current_final_verification_control.issued_at_unix_ms",
            self.issued_at_unix_ms,
        )
    }
}

/// Exact runner termination observation before core classification.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum CurrentFinalVerificationTerminationV1 {
    /// Process exited with an exact code.
    Exited {
        /// Exact process exit code.
        code: i32,
    },
    /// Process terminated by a positive signal number.
    Signaled {
        /// Positive platform signal number.
        signal: i32,
    },
    /// Unchanged command deadline expired.
    TimedOut,
    /// Unchanged output ceiling was exceeded.
    OutputLimitExceeded,
    /// Launch/effect was exactly proven not to have started.
    FailedBeforeEffect,
    /// Authenticated control interrupted before any effect.
    InterruptedBeforeEffect {
        /// Claimed authenticated control identity.
        control_id: String,
    },
    /// Control occurred after effect and therefore cannot authorize retry.
    InterruptedAfterEffect {
        /// Claimed authenticated control identity.
        control_id: String,
    },
    /// Explicit cancellation claim requiring an authenticated cancel record.
    Canceled {
        /// Claimed authenticated cancel identity.
        control_id: String,
    },
    /// Runner or custody evidence is intrinsically ambiguous.
    Unknown {
        /// Digest of bounded diagnostic ambiguity evidence.
        evidence_digest: Digest,
    },
}

impl CurrentFinalVerificationTerminationV1 {
    fn validate(&self) -> Result<(), ContractError> {
        match self {
            Self::Signaled { signal } if *signal <= 0 => Err(ContractError::new(
                "current_final_verification_capture.termination.signal",
                "must be positive",
            )),
            Self::InterruptedBeforeEffect { control_id }
            | Self::InterruptedAfterEffect { control_id }
            | Self::Canceled { control_id } => require_nonblank(
                "current_final_verification_capture.termination.control_id",
                control_id,
            ),
            _ => Ok(()),
        }
    }

    fn sql_kind(&self) -> &'static str {
        match self {
            Self::Exited { .. } => "Exited",
            Self::Signaled { .. } => "Signaled",
            Self::TimedOut => "TimedOut",
            Self::OutputLimitExceeded => "OutputLimitExceeded",
            Self::FailedBeforeEffect => "FailedBeforeEffect",
            Self::InterruptedBeforeEffect { .. } => "InterruptedBeforeEffect",
            Self::InterruptedAfterEffect { .. } => "InterruptedAfterEffect",
            Self::Canceled { .. } => "Canceled",
            Self::Unknown { .. } => "Unknown",
        }
    }

    fn sql_code(&self) -> Option<i32> {
        match self {
            Self::Exited { code } => Some(*code),
            Self::Signaled { signal } => Some(*signal),
            _ => None,
        }
    }

    fn control_id(&self) -> Option<&str> {
        match self {
            Self::InterruptedBeforeEffect { control_id }
            | Self::InterruptedAfterEffect { control_id }
            | Self::Canceled { control_id } => Some(control_id),
            _ => None,
        }
    }
}

/// Exact command-output custody observation before core classification.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum CurrentFinalVerificationOutputCustodyV1 {
    /// Complete clean stdout/stderr was immutably published.
    PublishedClean {
        /// Exact clean publication receipt identity.
        publication_receipt_id: String,
    },
    /// Sensitive bytes were rejected and exact private staging was removed.
    AbandonedSensitive {
        /// Exact sensitive-output rejection closure identity.
        rejection_closure_id: String,
    },
    /// Capture was exactly closed before effect.
    ClosedBeforeCapture {
        /// Exact pre-capture closure receipt identity.
        closure_receipt_id: String,
    },
    /// Custody cannot be proven.
    Unknown {
        /// Digest of bounded diagnostic custody ambiguity evidence.
        evidence_digest: Digest,
    },
}

impl CurrentFinalVerificationOutputCustodyV1 {
    fn validate(&self) -> Result<(), ContractError> {
        let identity = match self {
            Self::PublishedClean {
                publication_receipt_id,
            } => Some(publication_receipt_id),
            Self::AbandonedSensitive {
                rejection_closure_id,
            } => Some(rejection_closure_id),
            Self::ClosedBeforeCapture { closure_receipt_id } => Some(closure_receipt_id),
            Self::Unknown { .. } => None,
        };
        if let Some(identity) = identity {
            require_nonblank(
                "current_final_verification_capture.custody.receipt_id",
                identity,
            )?;
        }
        Ok(())
    }

    fn sql_kind(&self) -> &'static str {
        match self {
            Self::PublishedClean { .. } => "PublishedClean",
            Self::AbandonedSensitive { .. } => "AbandonedSensitive",
            Self::ClosedBeforeCapture { .. } => "ClosedBeforeCapture",
            Self::Unknown { .. } => "Unknown",
        }
    }

    fn receipt_id(&self) -> Option<&str> {
        match self {
            Self::PublishedClean {
                publication_receipt_id,
            } => Some(publication_receipt_id),
            Self::AbandonedSensitive {
                rejection_closure_id,
            } => Some(rejection_closure_id),
            Self::ClosedBeforeCapture { closure_receipt_id } => Some(closure_receipt_id),
            Self::Unknown { .. } => None,
        }
    }
}

/// Exact terminal capture, custody, and cleanup evidence supplied for core
/// classification.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CurrentFinalVerificationCaptureClosureV1 {
    /// Contract discriminator.
    pub closure_version: u32,
    /// Stable exact capture-closure identity.
    pub closure_id: String,
    /// Owning current sprint.
    pub sprint_id: String,
    /// Exact admitted attempt.
    pub attempt_id: String,
    /// Raw terminal observation.
    pub termination: CurrentFinalVerificationTerminationV1,
    /// Raw output-custody observation.
    pub output_custody: CurrentFinalVerificationOutputCustodyV1,
    /// Exact final-verifier runner cleanup proof, when proven.
    pub runner_cleanup_proof_id: Option<String>,
    /// Exact command-domain cleanup proof, when proven.
    pub command_domain_cleanup_proof_id: Option<String>,
    /// Durable terminal observation time.
    pub terminal_at_unix_ms: u64,
}

impl CurrentFinalVerificationCaptureClosureV1 {
    /// Validates intrinsic identity, termination, custody, and optional-proof shape.
    ///
    /// # Errors
    ///
    /// Returns an error for unsupported versions, blank identities, malformed
    /// termination/custody, or blank optional proof identities.
    pub fn validate(&self) -> Result<(), ContractError> {
        require_version(
            "current_final_verification_capture.closure_version",
            self.closure_version,
        )?;
        for (field, value) in [
            (
                "current_final_verification_capture.closure_id",
                self.closure_id.as_str(),
            ),
            (
                "current_final_verification_capture.sprint_id",
                self.sprint_id.as_str(),
            ),
            (
                "current_final_verification_capture.attempt_id",
                self.attempt_id.as_str(),
            ),
        ] {
            require_nonblank(field, value)?;
        }
        require_nonzero(
            "current_final_verification_capture.terminal_at_unix_ms",
            self.terminal_at_unix_ms,
        )?;
        self.termination.validate()?;
        self.output_custody.validate()?;
        for proof in [
            self.runner_cleanup_proof_id.as_deref(),
            self.command_domain_cleanup_proof_id.as_deref(),
        ]
        .into_iter()
        .flatten()
        {
            require_nonblank("current_final_verification_capture.cleanup_proof_id", proof)?;
        }
        Ok(())
    }
}

/// Closed core-derived terminal classification for one verifier attempt.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum CurrentFinalVerificationOutcomeKindV1 {
    /// Exit zero with clean publication and complete cleanup.
    Verified,
    /// Positive nonzero exit code.
    NonzeroExit {
        /// Positive exact exit code.
        code: i32,
    },
    /// Positive signal termination.
    Signaled {
        /// Positive exact signal number.
        signal: i32,
    },
    /// Unchanged command deadline expired.
    TimedOut,
    /// Unchanged output ceiling was exceeded.
    OutputLimitExceeded,
    /// Sensitive output was exactly abandoned and cleaned.
    SensitiveOutputRejected,
    /// Exact pre-effect closure; same-snapshot continuation may be eligible.
    FailedBeforeEffect,
    /// Authenticated pause/steer interruption before effect.
    ControlInterruptedBeforeEffect {
        /// Exact authenticated pause or steering control identity.
        control_id: String,
    },
    /// Authenticated explicit cancellation.
    Canceled {
        /// Exact authenticated cancel identity.
        control_id: String,
    },
    /// Any ambiguous or crossed effect, custody, cleanup, or control state.
    Unknown,
}

impl CurrentFinalVerificationOutcomeKindV1 {
    fn validate(&self) -> Result<(), ContractError> {
        match self {
            Self::NonzeroExit { code } if *code <= 0 => Err(ContractError::new(
                "current_final_verification_outcome.code",
                "NonzeroExit requires a positive code",
            )),
            Self::Signaled { signal } if *signal <= 0 => Err(ContractError::new(
                "current_final_verification_outcome.signal",
                "Signaled requires a positive signal",
            )),
            Self::ControlInterruptedBeforeEffect { control_id } | Self::Canceled { control_id } => {
                require_nonblank("current_final_verification_outcome.control_id", control_id)
            }
            _ => Ok(()),
        }
    }

    fn sql_kind(&self) -> &'static str {
        match self {
            Self::Verified => "Verified",
            Self::NonzeroExit { .. } => "NonzeroExit",
            Self::Signaled { .. } => "Signaled",
            Self::TimedOut => "TimedOut",
            Self::OutputLimitExceeded => "OutputLimitExceeded",
            Self::SensitiveOutputRejected => "SensitiveOutputRejected",
            Self::FailedBeforeEffect => "FailedBeforeEffect",
            Self::ControlInterruptedBeforeEffect { .. } => "ControlInterruptedBeforeEffect",
            Self::Canceled { .. } => "Canceled",
            Self::Unknown => "Unknown",
        }
    }

    fn sql_code(&self) -> Option<i32> {
        match self {
            Self::NonzeroExit { code } => Some(*code),
            Self::Signaled { signal } => Some(*signal),
            _ => None,
        }
    }

    fn is_known_after_effect_failure(&self) -> bool {
        matches!(
            self,
            Self::NonzeroExit { .. }
                | Self::Signaled { .. }
                | Self::TimedOut
                | Self::OutputLimitExceeded
                | Self::SensitiveOutputRejected
        )
    }
}

/// Immutable typed outcome derived from one exact capture closure.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CurrentFinalVerificationOutcomeV1 {
    /// Contract discriminator.
    pub outcome_version: u32,
    /// Deterministic core-derived outcome identity.
    pub outcome_id: String,
    /// Owning sprint.
    pub sprint_id: String,
    /// Exact attempt.
    pub attempt_id: String,
    /// Exact raw capture closure.
    pub closure_id: String,
    /// Closed typed classification.
    pub outcome: CurrentFinalVerificationOutcomeKindV1,
    /// Durable terminal observation time.
    pub terminal_at_unix_ms: u64,
}

impl CurrentFinalVerificationOutcomeV1 {
    fn validate(&self) -> Result<(), ContractError> {
        require_version(
            "current_final_verification_outcome.outcome_version",
            self.outcome_version,
        )?;
        for (field, value) in [
            (
                "current_final_verification_outcome.outcome_id",
                self.outcome_id.as_str(),
            ),
            (
                "current_final_verification_outcome.sprint_id",
                self.sprint_id.as_str(),
            ),
            (
                "current_final_verification_outcome.attempt_id",
                self.attempt_id.as_str(),
            ),
            (
                "current_final_verification_outcome.closure_id",
                self.closure_id.as_str(),
            ),
        ] {
            require_nonblank(field, value)?;
        }
        require_nonzero(
            "current_final_verification_outcome.terminal_at_unix_ms",
            self.terminal_at_unix_ms,
        )?;
        self.outcome.validate()
    }
}

/// One exact current V2 sprint/graph pair read from the v32 lattice.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CurrentSprintAuthorityV32 {
    /// Exact current sprint specification.
    pub spec: SprintSpecV2,
    /// Exact reciprocally bound current task graph.
    pub graph: TaskGraphV2,
    /// Durable creation timestamp.
    pub created_at_unix_ms: u64,
}

/// Durable attempt authority together with its idempotency identity and typed
/// terminal outcome, when closed.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PersistedCurrentFinalVerificationAttemptV1 {
    /// Non-authority idempotency request identity.
    pub request_id: String,
    /// Exact immutable attempt authority.
    pub authority: FinalVerificationAttemptAuthorityV1,
    /// Typed terminal outcome when closure has completed.
    pub outcome: Option<CurrentFinalVerificationOutcomeV1>,
}

/// Closed schema-v34 event kind. This tranche records admission only; later
/// lifecycle events require their own additive source migration.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CurrentFinalVerificationAuthorityEventKindV1 {
    /// One current final-verification attempt was durably admitted.
    AttemptAdmitted,
    /// Exact launch and preallocated capture intent became durable.
    LaunchCommitted,
    /// The private output capture was physically acquired.
    CaptureAcquired,
    /// One exact V13 runner session initialized.
    V13Initialized,
    /// The sole command dispatch claim committed.
    CommandDispatched,
    /// The coordinator issued one authenticated control.
    ControlIssued,
    /// The runner independently observed the control.
    ControlObserved,
    /// Bounded control reconciliation completed.
    ControlReconciled,
    /// The exact raw runner terminal was recorded.
    TerminalObserved,
    /// The independent command-effect cut was recorded.
    EffectCutObserved,
    /// Output custody reached one typed terminal state.
    OutputCustodyClosed,
    /// The native command accounting domain was observed.
    CommandDomainCleanupObserved,
    /// The runner direct child was independently observed.
    RunnerDirectChildObserved,
    /// The runner native accounting domain was independently observed.
    RunnerDomainObserved,
    /// The complete runner cleanup join closed.
    RunnerCleanupClosed,
    /// All source domains joined into one closure.
    EvidenceClosed,
    /// Core derived the typed attempt outcome.
    OutcomeDerived,
}

impl CurrentFinalVerificationAuthorityEventKindV1 {
    const fn sql_kind(self) -> &'static str {
        match self {
            Self::AttemptAdmitted => "AttemptAdmitted",
            Self::LaunchCommitted => "LaunchCommitted",
            Self::CaptureAcquired => "CaptureAcquired",
            Self::V13Initialized => "V13Initialized",
            Self::CommandDispatched => "CommandDispatched",
            Self::ControlIssued => "ControlIssued",
            Self::ControlObserved => "ControlObserved",
            Self::ControlReconciled => "ControlReconciled",
            Self::TerminalObserved => "TerminalObserved",
            Self::EffectCutObserved => "EffectCutObserved",
            Self::OutputCustodyClosed => "OutputCustodyClosed",
            Self::CommandDomainCleanupObserved => "CommandDomainCleanupObserved",
            Self::RunnerDirectChildObserved => "RunnerDirectChildObserved",
            Self::RunnerDomainObserved => "RunnerDomainObserved",
            Self::RunnerCleanupClosed => "RunnerCleanupClosed",
            Self::EvidenceClosed => "EvidenceClosed",
            Self::OutcomeDerived => "OutcomeDerived",
        }
    }
}

/// Exact sprint-local operational admission event.
///
/// This is integrity data and readback, not launch or dispatch authority.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CurrentFinalVerificationAuthorityEventV1 {
    /// Contract discriminator.
    pub event_version: u32,
    /// Formula-derived identity for admission/launch, or the exact launch-
    /// reserved identity for a later lifecycle event.
    pub event_id: String,
    /// Owning current sprint.
    pub sprint_id: String,
    /// Real contiguous sequence in the current sprint event stream.
    pub event_sequence: u64,
    /// Closed event kind.
    pub event_kind: CurrentFinalVerificationAuthorityEventKindV1,
    /// Exact admitted attempt.
    pub attempt_id: String,
    /// Exact causative idempotency request for this event variant.
    pub request_id: String,
    /// Digest of that exact canonical request.
    pub request_digest: Digest,
    /// Durable admission time.
    pub occurred_at_unix_ms: u64,
    /// Domain-separated digest of every preceding field.
    pub event_digest: Digest,
}

#[derive(Serialize)]
struct OperationalEventIdPreimageV1<'a> {
    event_version: u32,
    sprint_id: &'a str,
    event_sequence: u64,
    event_kind: CurrentFinalVerificationAuthorityEventKindV1,
    attempt_id: &'a str,
    request_id: &'a str,
    request_digest: &'a Digest,
    occurred_at_unix_ms: u64,
}

#[derive(Serialize)]
struct OperationalEventDigestPreimageV1<'a> {
    event_version: u32,
    event_id: &'a str,
    sprint_id: &'a str,
    event_sequence: u64,
    event_kind: CurrentFinalVerificationAuthorityEventKindV1,
    attempt_id: &'a str,
    request_id: &'a str,
    request_digest: &'a Digest,
    occurred_at_unix_ms: u64,
}

impl CurrentFinalVerificationAuthorityEventV1 {
    fn try_new(
        attempt: &PersistedCurrentFinalVerificationAttemptV1,
        request_digest: Digest,
        event_sequence: u64,
    ) -> Result<Self, ContractError> {
        let authority = &attempt.authority;
        let id_preimage = OperationalEventIdPreimageV1 {
            event_version: CURRENT_SET_VERSION_V1,
            sprint_id: &authority.sprint_id,
            event_sequence,
            event_kind: CurrentFinalVerificationAuthorityEventKindV1::AttemptAdmitted,
            attempt_id: &authority.attempt_id,
            request_id: &attempt.request_id,
            request_digest: &request_digest,
            occurred_at_unix_ms: authority.provenance.admitted_at_unix_ms,
        };
        let event_id = mint_identity(
            OPERATIONAL_EVENT_ID_DOMAIN_V1,
            &encode_canonical("current_final_verification_event_v1.id", &id_preimage)?,
        );
        let mut event = Self {
            event_version: CURRENT_SET_VERSION_V1,
            event_id,
            sprint_id: authority.sprint_id.clone(),
            event_sequence,
            event_kind: CurrentFinalVerificationAuthorityEventKindV1::AttemptAdmitted,
            attempt_id: authority.attempt_id.clone(),
            request_id: attempt.request_id.clone(),
            request_digest,
            occurred_at_unix_ms: authority.provenance.admitted_at_unix_ms,
            event_digest: Digest::sha256(&[]),
        };
        event.event_digest = event.computed_event_digest()?;
        event.validate_integrity()?;
        Ok(event)
    }

    /// Constructs the sole formula-derived `LaunchCommitted` event from an
    /// exact operational attempt and exact canonical launch request.
    ///
    /// This helper owns the V1 event hashing rule. It does not grant launch,
    /// capture, spawn, initialization, or dispatch authority.
    pub(super) fn try_new_launch(
        operational: &OperationalCurrentFinalVerificationAttemptV1,
        launch_request_id: &str,
        launch_request_digest: Digest,
        committed_at_unix_ms: u64,
    ) -> Result<Self, ContractError> {
        require_operational_identifier(
            "current_final_verification_event_v1.request_id",
            launch_request_id,
        )?;
        require_nonzero(
            "current_final_verification_event_v1.occurred_at_unix_ms",
            committed_at_unix_ms,
        )?;
        if committed_at_unix_ms < operational.admitted_at_unix_ms {
            return Err(ContractError::new(
                "current_final_verification_event_v1.occurred_at_unix_ms",
                "launch commit cannot predate operational attempt admission",
            ));
        }
        let event_sequence = operational
            .admission_event_sequence
            .checked_add(1)
            .ok_or_else(|| {
                ContractError::new(
                    "current_final_verification_event_v1.event_sequence",
                    "launch event sequence overflowed",
                )
            })?;
        let event_kind = CurrentFinalVerificationAuthorityEventKindV1::LaunchCommitted;
        let id_preimage = OperationalEventIdPreimageV1 {
            event_version: CURRENT_SET_VERSION_V1,
            sprint_id: &operational.sprint_id,
            event_sequence,
            event_kind,
            attempt_id: &operational.attempt_id,
            request_id: launch_request_id,
            request_digest: &launch_request_digest,
            occurred_at_unix_ms: committed_at_unix_ms,
        };
        let event_id = mint_identity(
            OPERATIONAL_EVENT_ID_DOMAIN_V1,
            &encode_canonical("current_final_verification_event_v1.id", &id_preimage)?,
        );
        let mut event = Self {
            event_version: CURRENT_SET_VERSION_V1,
            event_id,
            sprint_id: operational.sprint_id.clone(),
            event_sequence,
            event_kind,
            attempt_id: operational.attempt_id.clone(),
            request_id: launch_request_id.to_owned(),
            request_digest: launch_request_digest,
            occurred_at_unix_ms: committed_at_unix_ms,
            event_digest: Digest::sha256(&[]),
        };
        event.event_digest = event.computed_event_digest()?;
        event.validate_integrity()?;
        Ok(event)
    }

    fn id_preimage(&self) -> OperationalEventIdPreimageV1<'_> {
        OperationalEventIdPreimageV1 {
            event_version: self.event_version,
            sprint_id: &self.sprint_id,
            event_sequence: self.event_sequence,
            event_kind: self.event_kind,
            attempt_id: &self.attempt_id,
            request_id: &self.request_id,
            request_digest: &self.request_digest,
            occurred_at_unix_ms: self.occurred_at_unix_ms,
        }
    }

    fn digest_preimage(&self) -> OperationalEventDigestPreimageV1<'_> {
        OperationalEventDigestPreimageV1 {
            event_version: self.event_version,
            event_id: &self.event_id,
            sprint_id: &self.sprint_id,
            event_sequence: self.event_sequence,
            event_kind: self.event_kind,
            attempt_id: &self.attempt_id,
            request_id: &self.request_id,
            request_digest: &self.request_digest,
            occurred_at_unix_ms: self.occurred_at_unix_ms,
        }
    }

    fn computed_event_id(&self) -> Result<String, ContractError> {
        Ok(mint_identity(
            OPERATIONAL_EVENT_ID_DOMAIN_V1,
            &encode_canonical(
                "current_final_verification_event_v1.id",
                &self.id_preimage(),
            )?,
        ))
    }

    pub(super) fn computed_event_digest(&self) -> Result<Digest, ContractError> {
        Ok(domain_digest(
            OPERATIONAL_EVENT_DIGEST_DOMAIN_V1,
            &encode_canonical(
                "current_final_verification_event_v1.digest",
                &self.digest_preimage(),
            )?,
        ))
    }

    pub(super) fn validate_integrity(&self) -> Result<(), ContractError> {
        require_version(
            "current_final_verification_event_v1.event_version",
            self.event_version,
        )?;
        for (field, value) in [
            (
                "current_final_verification_event_v1.event_id",
                self.event_id.as_str(),
            ),
            (
                "current_final_verification_event_v1.sprint_id",
                self.sprint_id.as_str(),
            ),
            (
                "current_final_verification_event_v1.attempt_id",
                self.attempt_id.as_str(),
            ),
            (
                "current_final_verification_event_v1.request_id",
                self.request_id.as_str(),
            ),
        ] {
            require_operational_identifier(field, value)?;
        }
        require_nonzero(
            "current_final_verification_event_v1.event_sequence",
            self.event_sequence,
        )?;
        require_nonzero(
            "current_final_verification_event_v1.occurred_at_unix_ms",
            self.occurred_at_unix_ms,
        )?;
        match self.event_kind {
            CurrentFinalVerificationAuthorityEventKindV1::AttemptAdmitted
            | CurrentFinalVerificationAuthorityEventKindV1::LaunchCommitted => {
                if self.event_id != self.computed_event_id()? {
                    return Err(ContractError::new(
                        "current_final_verification_event_v1.event_id",
                        "does not identify the exact event fields",
                    ));
                }
            }
            CurrentFinalVerificationAuthorityEventKindV1::CaptureAcquired
            | CurrentFinalVerificationAuthorityEventKindV1::V13Initialized
            | CurrentFinalVerificationAuthorityEventKindV1::CommandDispatched
            | CurrentFinalVerificationAuthorityEventKindV1::ControlIssued
            | CurrentFinalVerificationAuthorityEventKindV1::ControlObserved
            | CurrentFinalVerificationAuthorityEventKindV1::ControlReconciled
            | CurrentFinalVerificationAuthorityEventKindV1::TerminalObserved
            | CurrentFinalVerificationAuthorityEventKindV1::EffectCutObserved
            | CurrentFinalVerificationAuthorityEventKindV1::OutputCustodyClosed
            | CurrentFinalVerificationAuthorityEventKindV1::CommandDomainCleanupObserved
            | CurrentFinalVerificationAuthorityEventKindV1::RunnerDirectChildObserved
            | CurrentFinalVerificationAuthorityEventKindV1::RunnerDomainObserved
            | CurrentFinalVerificationAuthorityEventKindV1::RunnerCleanupClosed
            | CurrentFinalVerificationAuthorityEventKindV1::EvidenceClosed
            | CurrentFinalVerificationAuthorityEventKindV1::OutcomeDerived => {
                Digest::parse(&self.event_id).map_err(|_| {
                    ContractError::new(
                        "current_final_verification_event_v1.event_id",
                        "post-launch event identity must be one exact pre-reserved SHA-256 identity",
                    )
                })?;
            }
        }
        if self.event_digest != self.computed_event_digest()? {
            return Err(ContractError::new(
                "current_final_verification_event_v1.event_digest",
                "does not authenticate the exact event fields",
            ));
        }
        let bytes = encode_canonical("current_final_verification_event_v1", self)?;
        require_operational_canonical_bound("current_final_verification_event_v1", &bytes)
    }

    pub(super) fn canonical_bytes(&self) -> Result<Vec<u8>, ContractError> {
        self.validate_integrity()?;
        encode_canonical("current_final_verification_event_v1", self)
    }
}

/// Current-only operational binding for one exact schema-v32 attempt.
///
/// The diagnostic schema-v32 provenance is retained explicitly, but the
/// separate `admission_event_*` pair is the only operational event identity.
/// This value is readback only and grants no execution capability.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OperationalCurrentFinalVerificationAttemptV1 {
    /// Contract discriminator.
    pub operational_version: u32,
    /// Exact schema-v32 attempt identity.
    pub attempt_id: String,
    /// Owning current sprint.
    pub sprint_id: String,
    /// Bounded schema-v32 attempt ordinal; never used as an event sequence.
    pub attempt_ordinal: u8,
    /// Exact schema-v32 admission identity.
    pub final_verification_admission_id: String,
    /// Digest of the exact schema-v32 authority bytes.
    pub attempt_authority_digest: Digest,
    /// Historical schema-v32 event-shaped identifier retained diagnostically.
    pub diagnostic_v32_admission_event_id: String,
    /// Historical schema-v32 ordinal projection retained diagnostically.
    pub diagnostic_v32_admission_event_sequence: u64,
    /// Exact idempotency request identity.
    pub request_id: String,
    /// Digest of the exact canonical request.
    pub request_digest: Digest,
    /// Actual durable current event identity.
    pub admission_event_id: String,
    /// Actual contiguous current sprint event sequence.
    pub admission_event_sequence: u64,
    /// Exact current sprint specification digest.
    pub sprint_spec_digest: Digest,
    /// Exact current task-graph identity.
    pub task_graph_id: String,
    /// Exact current task-graph digest.
    pub task_graph_digest: Digest,
    /// Exact reciprocal graph-payload digest.
    pub task_graph_payload_digest: Digest,
    /// Exact immutable repair-slot reserve digest.
    pub repair_slot_reserve_digest: Digest,
    /// Exact integration snapshot admitted for verification.
    pub input_snapshot: Digest,
    /// Exact sealed complete `TaskDone` set.
    pub complete_task_done_set_digest: Digest,
    /// Exact sealed complete criterion-evidence set.
    pub complete_criterion_evidence_set_digest: Digest,
    /// Authenticated workspace-grant digest.
    pub workspace_grant_hash: Digest,
    /// Digest of the exact repository-wide command.
    pub verification_command_digest: Digest,
    /// Exact execution-policy digest.
    pub execution_policy_digest: Digest,
    /// Trusted coordinator instance that admitted the attempt.
    pub coordinator_instance_id: String,
    /// Durable admission time.
    pub admitted_at_unix_ms: u64,
    /// Domain-separated digest of every preceding field.
    pub operational_attempt_digest: Digest,
}

#[derive(Serialize)]
struct OperationalAttemptDigestPreimageV1<'a> {
    operational_version: u32,
    attempt_id: &'a str,
    sprint_id: &'a str,
    attempt_ordinal: u8,
    final_verification_admission_id: &'a str,
    attempt_authority_digest: &'a Digest,
    diagnostic_v32_admission_event_id: &'a str,
    diagnostic_v32_admission_event_sequence: u64,
    request_id: &'a str,
    request_digest: &'a Digest,
    admission_event_id: &'a str,
    admission_event_sequence: u64,
    sprint_spec_digest: &'a Digest,
    task_graph_id: &'a str,
    task_graph_digest: &'a Digest,
    task_graph_payload_digest: &'a Digest,
    repair_slot_reserve_digest: &'a Digest,
    input_snapshot: &'a Digest,
    complete_task_done_set_digest: &'a Digest,
    complete_criterion_evidence_set_digest: &'a Digest,
    workspace_grant_hash: &'a Digest,
    verification_command_digest: &'a Digest,
    execution_policy_digest: &'a Digest,
    coordinator_instance_id: &'a str,
    admitted_at_unix_ms: u64,
}

impl OperationalCurrentFinalVerificationAttemptV1 {
    fn try_new(
        request: &CurrentFinalVerificationAdmissionRequestV1,
        current: &CurrentSprintAuthorityV32,
        attempt: &PersistedCurrentFinalVerificationAttemptV1,
        event: &CurrentFinalVerificationAuthorityEventV1,
    ) -> Result<Self, ContractError> {
        let authority = &attempt.authority;
        let mut operational = Self {
            operational_version: CURRENT_SET_VERSION_V1,
            attempt_id: authority.attempt_id.clone(),
            sprint_id: authority.sprint_id.clone(),
            attempt_ordinal: authority.attempt_ordinal,
            final_verification_admission_id: authority.final_verification_admission_id.clone(),
            attempt_authority_digest: authority.canonical_digest()?,
            diagnostic_v32_admission_event_id: authority.provenance.admission_event_id.clone(),
            diagnostic_v32_admission_event_sequence: authority.provenance.admission_event_sequence,
            request_id: request.request_id.clone(),
            request_digest: request.canonical_digest()?,
            admission_event_id: event.event_id.clone(),
            admission_event_sequence: event.event_sequence,
            sprint_spec_digest: current.spec.canonical_digest()?,
            task_graph_id: current.graph.graph_id.clone(),
            task_graph_digest: current.graph.canonical_digest_for_sprint(&current.spec)?,
            task_graph_payload_digest: current.spec.task_graph_payload_digest.clone(),
            repair_slot_reserve_digest: current.graph.repair_slot_reserve_digest.clone(),
            input_snapshot: authority.input_snapshot.clone(),
            complete_task_done_set_digest: authority.complete_task_done_set_digest.clone(),
            complete_criterion_evidence_set_digest: authority
                .complete_criterion_evidence_set_digest
                .clone(),
            workspace_grant_hash: current.spec.workspace_grant.grant_hash.clone(),
            verification_command_digest: operational_command_digest(
                &authority.final_verification_check,
            )?,
            execution_policy_digest: authority.execution_policy_digest.clone(),
            coordinator_instance_id: authority.provenance.coordinator_instance_id.clone(),
            admitted_at_unix_ms: authority.provenance.admitted_at_unix_ms,
            operational_attempt_digest: Digest::sha256(&[]),
        };
        operational.operational_attempt_digest = operational.computed_digest()?;
        operational.validate_for(request, current, attempt, event)?;
        Ok(operational)
    }

    fn digest_preimage(&self) -> OperationalAttemptDigestPreimageV1<'_> {
        OperationalAttemptDigestPreimageV1 {
            operational_version: self.operational_version,
            attempt_id: &self.attempt_id,
            sprint_id: &self.sprint_id,
            attempt_ordinal: self.attempt_ordinal,
            final_verification_admission_id: &self.final_verification_admission_id,
            attempt_authority_digest: &self.attempt_authority_digest,
            diagnostic_v32_admission_event_id: &self.diagnostic_v32_admission_event_id,
            diagnostic_v32_admission_event_sequence: self.diagnostic_v32_admission_event_sequence,
            request_id: &self.request_id,
            request_digest: &self.request_digest,
            admission_event_id: &self.admission_event_id,
            admission_event_sequence: self.admission_event_sequence,
            sprint_spec_digest: &self.sprint_spec_digest,
            task_graph_id: &self.task_graph_id,
            task_graph_digest: &self.task_graph_digest,
            task_graph_payload_digest: &self.task_graph_payload_digest,
            repair_slot_reserve_digest: &self.repair_slot_reserve_digest,
            input_snapshot: &self.input_snapshot,
            complete_task_done_set_digest: &self.complete_task_done_set_digest,
            complete_criterion_evidence_set_digest: &self.complete_criterion_evidence_set_digest,
            workspace_grant_hash: &self.workspace_grant_hash,
            verification_command_digest: &self.verification_command_digest,
            execution_policy_digest: &self.execution_policy_digest,
            coordinator_instance_id: &self.coordinator_instance_id,
            admitted_at_unix_ms: self.admitted_at_unix_ms,
        }
    }

    fn computed_digest(&self) -> Result<Digest, ContractError> {
        Ok(domain_digest(
            OPERATIONAL_ATTEMPT_DIGEST_DOMAIN_V1,
            &encode_canonical(
                "operational_current_final_verification_attempt_v1.digest",
                &self.digest_preimage(),
            )?,
        ))
    }

    fn validate_integrity(&self) -> Result<(), ContractError> {
        require_version(
            "operational_current_final_verification_attempt_v1.operational_version",
            self.operational_version,
        )?;
        for (field, value) in [
            (
                "operational_current_final_verification_attempt_v1.attempt_id",
                self.attempt_id.as_str(),
            ),
            (
                "operational_current_final_verification_attempt_v1.sprint_id",
                self.sprint_id.as_str(),
            ),
            (
                "operational_current_final_verification_attempt_v1.final_verification_admission_id",
                self.final_verification_admission_id.as_str(),
            ),
            (
                "operational_current_final_verification_attempt_v1.diagnostic_v32_admission_event_id",
                self.diagnostic_v32_admission_event_id.as_str(),
            ),
            (
                "operational_current_final_verification_attempt_v1.request_id",
                self.request_id.as_str(),
            ),
            (
                "operational_current_final_verification_attempt_v1.admission_event_id",
                self.admission_event_id.as_str(),
            ),
            (
                "operational_current_final_verification_attempt_v1.task_graph_id",
                self.task_graph_id.as_str(),
            ),
            (
                "operational_current_final_verification_attempt_v1.coordinator_instance_id",
                self.coordinator_instance_id.as_str(),
            ),
        ] {
            require_operational_identifier(field, value)?;
        }
        if !(1..=3).contains(&self.attempt_ordinal) {
            return Err(ContractError::new(
                "operational_current_final_verification_attempt_v1.attempt_ordinal",
                "must be in 1..=3",
            ));
        }
        require_nonzero(
            "operational_current_final_verification_attempt_v1.diagnostic_v32_admission_event_sequence",
            self.diagnostic_v32_admission_event_sequence,
        )?;
        require_nonzero(
            "operational_current_final_verification_attempt_v1.admission_event_sequence",
            self.admission_event_sequence,
        )?;
        require_nonzero(
            "operational_current_final_verification_attempt_v1.admitted_at_unix_ms",
            self.admitted_at_unix_ms,
        )?;
        if self.admission_event_id == self.diagnostic_v32_admission_event_id {
            return Err(ContractError::new(
                "operational_current_final_verification_attempt_v1.admission_event_id",
                "actual event identity must not reuse diagnostic schema-v32 provenance",
            ));
        }
        if self.operational_attempt_digest != self.computed_digest()? {
            return Err(ContractError::new(
                "operational_current_final_verification_attempt_v1.operational_attempt_digest",
                "does not authenticate the exact operational binding",
            ));
        }
        let bytes = encode_canonical("operational_current_final_verification_attempt_v1", self)?;
        require_operational_canonical_bound(
            "operational_current_final_verification_attempt_v1",
            &bytes,
        )
    }

    fn validate_for(
        &self,
        request: &CurrentFinalVerificationAdmissionRequestV1,
        current: &CurrentSprintAuthorityV32,
        attempt: &PersistedCurrentFinalVerificationAttemptV1,
        event: &CurrentFinalVerificationAuthorityEventV1,
    ) -> Result<(), ContractError> {
        self.validate_integrity()?;
        event.validate_integrity()?;
        request.validate_for(&current.spec, &current.graph)?;
        let authority = &attempt.authority;
        validate_current_direct_exec_command_v1(&authority.final_verification_check)?;
        let expected_command_digest =
            operational_command_digest(&authority.final_verification_check)?;
        if self.attempt_id != authority.attempt_id
            || self.sprint_id != authority.sprint_id
            || self.attempt_ordinal != authority.attempt_ordinal
            || self.final_verification_admission_id != authority.final_verification_admission_id
            || self.attempt_authority_digest != authority.canonical_digest()?
            || self.diagnostic_v32_admission_event_id != authority.provenance.admission_event_id
            || self.diagnostic_v32_admission_event_sequence
                != authority.provenance.admission_event_sequence
            || self.request_id != attempt.request_id
            || self.request_id != request.request_id
            || self.request_digest != request.canonical_digest()?
            || self.admission_event_id != event.event_id
            || self.admission_event_sequence != event.event_sequence
            || event.event_kind != CurrentFinalVerificationAuthorityEventKindV1::AttemptAdmitted
            || event.sprint_id != self.sprint_id
            || event.attempt_id != self.attempt_id
            || event.request_id != self.request_id
            || event.request_digest != self.request_digest
            || event.occurred_at_unix_ms != self.admitted_at_unix_ms
            || self.sprint_spec_digest != current.spec.canonical_digest()?
            || self.task_graph_id != current.graph.graph_id
            || self.task_graph_digest != current.graph.canonical_digest_for_sprint(&current.spec)?
            || self.task_graph_payload_digest != current.spec.task_graph_payload_digest
            || self.repair_slot_reserve_digest != current.graph.repair_slot_reserve_digest
            || self.input_snapshot != authority.input_snapshot
            || self.complete_task_done_set_digest != authority.complete_task_done_set_digest
            || self.complete_criterion_evidence_set_digest
                != authority.complete_criterion_evidence_set_digest
            || self.workspace_grant_hash != current.spec.workspace_grant.grant_hash
            || self.verification_command_digest != expected_command_digest
            || self.execution_policy_digest != authority.execution_policy_digest
            || self.coordinator_instance_id != authority.provenance.coordinator_instance_id
            || self.admitted_at_unix_ms != authority.provenance.admitted_at_unix_ms
        {
            return Err(ContractError::new(
                "operational_current_final_verification_attempt_v1",
                "crosses request, current authority, exact attempt, or admission event",
            ));
        }
        Ok(())
    }

    fn canonical_bytes(&self) -> Result<Vec<u8>, ContractError> {
        self.validate_integrity()?;
        encode_canonical("operational_current_final_verification_attempt_v1", self)
    }
}

/// Immutable schema-v32 parent fields admitted into the operational boundary.
///
/// The mutable diagnostic v32 outcome join is structurally absent.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OperationalCurrentFinalVerificationParentV1 {
    /// Non-authority idempotency request identity.
    pub request_id: String,
    /// Exact immutable schema-v32 attempt authority.
    pub authority: FinalVerificationAttemptAuthorityV1,
}

impl From<&PersistedCurrentFinalVerificationAttemptV1>
    for OperationalCurrentFinalVerificationParentV1
{
    fn from(attempt: &PersistedCurrentFinalVerificationAttemptV1) -> Self {
        Self {
            request_id: attempt.request_id.clone(),
            authority: attempt.authority.clone(),
        }
    }
}

/// Exact readback of one atomic schema-v34 T0 admission.
///
/// It deliberately contains no diagnostic outcome, launch, capture, dispatch,
/// or retry permit.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PersistedOperationalCurrentFinalVerificationAttemptV1 {
    /// Exact immutable schema-v32 parent fields.
    pub attempt: OperationalCurrentFinalVerificationParentV1,
    /// Exact actual sprint-local admission event.
    pub admission_event: CurrentFinalVerificationAuthorityEventV1,
    /// Exact operational overlay binding all current inputs.
    pub operational_attempt: OperationalCurrentFinalVerificationAttemptV1,
}

/// Immutable activation of the next predeclared dormant repair slot.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CurrentFinalVerificationRepairActivationV1 {
    /// Contract discriminator.
    pub activation_version: u32,
    /// Deterministic core-minted activation identity.
    pub activation_id: String,
    /// Owning sprint.
    pub sprint_id: String,
    /// Exact failed verifier attempt.
    pub failed_attempt_id: String,
    /// Exact typed known-failure outcome.
    pub failure_outcome_id: String,
    /// Snapshot that failed verification.
    pub failed_snapshot: Digest,
    /// One-based predeclared repair-slot ordinal.
    pub slot_ordinal: u8,
    /// Exact dormant graph task activated by this record.
    pub repair_task_id: String,
    /// Durable activation time.
    pub activated_at_unix_ms: u64,
}

/// Sealed scheduling/transition capability for one currently live repair slot.
///
/// Callers cannot construct or deserialize this value. The ledger issues it
/// only after re-reading the exact immutable activation together with its
/// reciprocally bound V2 sprint and graph. It is deliberately a read-cut
/// capability: every durable readiness, lease, or attempt write must re-check
/// the activation and current terminal/completion state in SQL.
///
/// The permit is intentionally move-only (not `Clone`) but remains
/// `Send + Sync`: moving one read cut between trusted core threads is harmless
/// because every durable consumer rechecks live SQL authority.
#[derive(Debug, Eq, PartialEq)]
pub struct CurrentRepairActivationPermitV1 {
    activation: CurrentFinalVerificationRepairActivationV1,
    sprint_spec_digest: Digest,
    task_graph_digest: Digest,
    repair_slot_reserve_digest: Digest,
}

impl CurrentRepairActivationPermitV1 {
    fn from_persisted(
        activation: CurrentFinalVerificationRepairActivationV1,
        current: &CurrentSprintAuthorityV32,
    ) -> Result<Self, ContractError> {
        current.graph.validate_for_sprint(&current.spec)?;
        let permit = Self {
            sprint_spec_digest: current.spec.canonical_digest()?,
            task_graph_digest: current.graph.canonical_digest_for_sprint(&current.spec)?,
            repair_slot_reserve_digest: current.graph.repair_slot_reserve_digest.clone(),
            activation,
        };
        permit.validate_for(&current.spec, &current.graph)?;
        Ok(permit)
    }

    #[cfg(test)]
    pub(crate) fn from_test_activation(
        activation: CurrentFinalVerificationRepairActivationV1,
        current: &CurrentSprintAuthorityV32,
    ) -> Result<Self, ContractError> {
        Self::from_persisted(activation, current)
    }

    /// Returns the exact durable activation identity.
    #[must_use]
    pub fn activation_id(&self) -> &str {
        &self.activation.activation_id
    }

    /// Returns the owning sprint identity.
    #[must_use]
    pub fn sprint_id(&self) -> &str {
        &self.activation.sprint_id
    }

    /// Returns the exact activated repair task identity.
    #[must_use]
    pub fn repair_task_id(&self) -> &str {
        &self.activation.repair_task_id
    }

    /// Returns the one-based activated slot ordinal.
    #[must_use]
    pub const fn slot_ordinal(&self) -> u8 {
        self.activation.slot_ordinal
    }

    /// Returns the durable activation time represented by this read cut.
    #[must_use]
    pub const fn activated_at_unix_ms(&self) -> u64 {
        self.activation.activated_at_unix_ms
    }

    /// Returns the immutable activation record carried by the permit.
    #[must_use]
    pub const fn activation(&self) -> &CurrentFinalVerificationRepairActivationV1 {
        &self.activation
    }

    /// Validates the permit against one exact reciprocally bound V2 pair.
    ///
    /// This proves structural identity only. Durable writes independently
    /// re-check that the activation has not been completed or terminalized.
    ///
    /// # Errors
    ///
    /// Returns a contract error for a crossed sprint, graph, reserve, task,
    /// slot, or canonical identity.
    pub fn validate_for(
        &self,
        sprint: &SprintSpecV2,
        graph: &TaskGraphV2,
    ) -> Result<(), ContractError> {
        self.activation.validate()?;
        graph.validate_for_sprint(sprint)?;
        if self.activation.sprint_id != sprint.sprint_id
            || self.sprint_spec_digest != sprint.canonical_digest()?
            || self.task_graph_digest != graph.canonical_digest_for_sprint(sprint)?
            || self.repair_slot_reserve_digest != graph.repair_slot_reserve_digest
        {
            return Err(ContractError::new(
                "current_repair_activation_permit.authority",
                "must bind the exact current V2 sprint, graph, and repair reserve",
            ));
        }
        let Some(task) = graph
            .tasks
            .iter()
            .find(|task| task.task_id == self.activation.repair_task_id)
        else {
            return Err(ContractError::new(
                "current_repair_activation_permit.repair_task_id",
                "does not name a task in the bound graph",
            ));
        };
        if task.purpose
            != (TaskPurposeV2::FinalVerificationRepairSlot {
                slot_ordinal: self.activation.slot_ordinal,
            })
        {
            return Err(ContractError::new(
                "current_repair_activation_permit.slot_ordinal",
                "does not match the exact predeclared repair task",
            ));
        }
        Ok(())
    }
}

impl CurrentFinalVerificationRepairActivationV1 {
    fn validate(&self) -> Result<(), ContractError> {
        require_version(
            "current_final_verification_repair_activation.activation_version",
            self.activation_version,
        )?;
        for (field, value) in [
            (
                "current_final_verification_repair_activation.activation_id",
                self.activation_id.as_str(),
            ),
            (
                "current_final_verification_repair_activation.sprint_id",
                self.sprint_id.as_str(),
            ),
            (
                "current_final_verification_repair_activation.failed_attempt_id",
                self.failed_attempt_id.as_str(),
            ),
            (
                "current_final_verification_repair_activation.failure_outcome_id",
                self.failure_outcome_id.as_str(),
            ),
            (
                "current_final_verification_repair_activation.repair_task_id",
                self.repair_task_id.as_str(),
            ),
        ] {
            require_nonblank(field, value)?;
        }
        if !(1..=2).contains(&self.slot_ordinal) {
            return Err(ContractError::new(
                "current_final_verification_repair_activation.slot_ordinal",
                "must be one or two",
            ));
        }
        require_nonzero(
            "current_final_verification_repair_activation.activated_at_unix_ms",
            self.activated_at_unix_ms,
        )
    }
}

/// Idempotent request to close one activated repair slot with a changed
/// snapshot and fully fresh criterion evidence.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CurrentFinalVerificationRepairCompletionRequestV1 {
    /// Stable non-authority idempotency identity.
    pub request_id: String,
    /// Exact activation being completed.
    pub activation_id: String,
    /// Fresh repair-slot `TaskDone` proof.
    pub repair_task_done_proof_id: String,
    /// Exact changed-snapshot integration receipt.
    pub integration_receipt_id: String,
    /// Failed snapshot consumed by the repair.
    pub input_snapshot: Digest,
    /// Distinct repaired snapshot.
    pub result_snapshot: Digest,
    /// Exact nonempty, non-net-zero repair `ChangeSet` identity.
    pub change_set_id: String,
    /// Number of exact operations in that repair source.
    pub operation_count: u32,
    /// Complete changed-snapshot `TaskDone` set.
    pub task_done_set: CompleteTaskDoneSetV1,
    /// Complete fresh changed-snapshot criterion evidence.
    pub criterion_evidence_set: CompleteCriterionEvidenceSetV1,
    /// Durable completion time.
    pub completed_at_unix_ms: u64,
}

impl CurrentFinalVerificationRepairCompletionRequestV1 {
    fn validate_intrinsic(&self) -> Result<(), ContractError> {
        for (field, value) in [
            (
                "repair_completion_request.request_id",
                self.request_id.as_str(),
            ),
            (
                "repair_completion_request.activation_id",
                self.activation_id.as_str(),
            ),
            (
                "repair_completion_request.repair_task_done_proof_id",
                self.repair_task_done_proof_id.as_str(),
            ),
            (
                "repair_completion_request.integration_receipt_id",
                self.integration_receipt_id.as_str(),
            ),
            (
                "repair_completion_request.change_set_id",
                self.change_set_id.as_str(),
            ),
        ] {
            require_nonblank(field, value)?;
        }
        require_nonzero(
            "repair_completion_request.completed_at_unix_ms",
            self.completed_at_unix_ms,
        )?;
        if self.operation_count == 0 || self.input_snapshot == self.result_snapshot {
            return Err(ContractError::new(
                "repair_completion_request.result_snapshot",
                "repair must be nonempty, non-net-zero, and change the failed snapshot",
            ));
        }
        Ok(())
    }

    fn canonical_digest(&self) -> Result<Digest, ContractError> {
        self.validate_intrinsic()?;
        Ok(domain_digest(
            REPAIR_COMPLETION_REQUEST_DIGEST_DOMAIN,
            &encode_canonical("repair_completion_request", self)?,
        ))
    }
}

/// Immutable successfully closed repair-slot authority.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CurrentFinalVerificationRepairCompletionV1 {
    /// Contract discriminator.
    pub completion_version: u32,
    /// Deterministic core-derived completion identity.
    pub completion_id: String,
    /// Owning sprint.
    pub sprint_id: String,
    /// Exact activation.
    pub activation_id: String,
    /// Failed verifier attempt repaired by this slot.
    pub failed_attempt_id: String,
    /// Exact predeclared repair task.
    pub repair_task_id: String,
    /// Fresh repair `TaskDone` proof.
    pub repair_task_done_proof_id: String,
    /// Exact changed-snapshot integration receipt.
    pub integration_receipt_id: String,
    /// Failed snapshot.
    pub input_snapshot: Digest,
    /// Distinct repaired snapshot.
    pub result_snapshot: Digest,
    /// Exact nonempty repair `ChangeSet` identity.
    pub change_set_id: String,
    /// Positive operation count.
    pub operation_count: u32,
    /// Complete changed-snapshot `TaskDone` set digest.
    pub complete_task_done_set_digest: Digest,
    /// Complete fresh changed-snapshot criterion-evidence-set digest.
    pub complete_criterion_evidence_set_digest: Digest,
    /// Durable completion time.
    pub completed_at_unix_ms: u64,
}

impl CurrentFinalVerificationRepairCompletionV1 {
    fn validate(&self) -> Result<(), ContractError> {
        require_version(
            "current_final_verification_repair_completion.completion_version",
            self.completion_version,
        )?;
        for (field, value) in [
            (
                "repair_completion.completion_id",
                self.completion_id.as_str(),
            ),
            ("repair_completion.sprint_id", self.sprint_id.as_str()),
            (
                "repair_completion.activation_id",
                self.activation_id.as_str(),
            ),
            (
                "repair_completion.failed_attempt_id",
                self.failed_attempt_id.as_str(),
            ),
            (
                "repair_completion.repair_task_id",
                self.repair_task_id.as_str(),
            ),
            (
                "repair_completion.repair_task_done_proof_id",
                self.repair_task_done_proof_id.as_str(),
            ),
            (
                "repair_completion.integration_receipt_id",
                self.integration_receipt_id.as_str(),
            ),
            (
                "repair_completion.change_set_id",
                self.change_set_id.as_str(),
            ),
        ] {
            require_nonblank(field, value)?;
        }
        require_nonzero(
            "repair_completion.completed_at_unix_ms",
            self.completed_at_unix_ms,
        )?;
        if self.operation_count == 0 || self.input_snapshot == self.result_snapshot {
            return Err(ContractError::new(
                "repair_completion.result_snapshot",
                "repair must be nonempty and change the failed snapshot",
            ));
        }
        Ok(())
    }
}

/// Closed unsuccessful terminal reason for the current v32 authority branch.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum CurrentSprintTerminalReasonV1 {
    /// The separately bounded final-verification attempt cap was consumed.
    FinalVerificationAttemptsExhausted,
    /// An authenticated explicit cancel closed the sprint.
    ExplicitCancel,
    /// Effect, custody, cleanup, or control evidence was ambiguous.
    AmbiguousFinalVerification,
}

/// Current v32 unsuccessful terminal readback.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CurrentSprintTerminalOutcomeV1 {
    /// Owning sprint.
    pub sprint_id: String,
    /// Exact terminal state (`Failed`, `Canceled`, or `Unknown`).
    pub terminal_state: String,
    /// Attempt whose outcome caused terminalization.
    pub source_attempt_id: String,
    /// Exact typed outcome identity.
    pub source_outcome_id: String,
    /// Closed terminal reason.
    pub terminal_reason: CurrentSprintTerminalReasonV1,
    /// Durable terminal time.
    pub terminal_at_unix_ms: u64,
}

fn require_version(field: &'static str, version: u32) -> Result<(), ContractError> {
    if version == CURRENT_SET_VERSION_V1 {
        Ok(())
    } else {
        Err(ContractError::new(
            field,
            format!("expected version {CURRENT_SET_VERSION_V1}, got {version}"),
        ))
    }
}

fn require_nonblank(field: &'static str, value: &str) -> Result<(), ContractError> {
    if value.trim().is_empty() {
        Err(ContractError::new(field, "must not be blank"))
    } else {
        Ok(())
    }
}

fn require_operational_identifier(field: &'static str, value: &str) -> Result<(), ContractError> {
    require_nonblank(field, value)?;
    if value.len() > MAX_CURRENT_FINAL_VERIFICATION_IDENTIFIER_BYTES_V2 {
        Err(ContractError::new(
            field,
            format!(
                "must contain at most {MAX_CURRENT_FINAL_VERIFICATION_IDENTIFIER_BYTES_V2} UTF-8 bytes"
            ),
        ))
    } else {
        Ok(())
    }
}

fn require_operational_canonical_bound(
    field: &'static str,
    bytes: &[u8],
) -> Result<(), ContractError> {
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

pub(super) fn operational_command_digest(command: &CommandSpec) -> Result<Digest, ContractError> {
    command.validate()?;
    Ok(domain_digest(
        OPERATIONAL_COMMAND_DIGEST_DOMAIN_V1,
        &encode_canonical("operational_final_verification_command_v1", command)?,
    ))
}

fn require_nonzero(field: &'static str, value: u64) -> Result<(), ContractError> {
    if value == 0 {
        Err(ContractError::new(field, "must be greater than zero"))
    } else {
        Ok(())
    }
}

fn encode_canonical<T: Serialize + ?Sized>(
    field: &'static str,
    value: &T,
) -> Result<Vec<u8>, ContractError> {
    serde_json::to_vec(value).map_err(|error| {
        ContractError::new(field, format!("cannot encode canonical JSON: {error}"))
    })
}

fn decode_exact<T: DeserializeOwned + Serialize>(
    field: &'static str,
    bytes: &[u8],
) -> Result<T, String> {
    let value: T = serde_json::from_slice(bytes).map_err(|error| error.to_string())?;
    let canonical = serde_json::to_vec(&value).map_err(|error| error.to_string())?;
    if canonical != bytes {
        return Err(format!("{field} is not exact canonical JSON"));
    }
    Ok(value)
}

fn domain_digest(domain: &[u8], canonical: &[u8]) -> Digest {
    let mut preimage = Vec::with_capacity(domain.len() + 8 + canonical.len());
    preimage.extend_from_slice(domain);
    preimage.extend_from_slice(
        &u64::try_from(canonical.len())
            .expect("supported targets use at most 64-bit usize")
            .to_be_bytes(),
    );
    preimage.extend_from_slice(canonical);
    Digest::sha256(&preimage)
}

pub(super) fn sqlite_sprint_spec_canonical(bytes: &[u8]) -> Result<i64, String> {
    SprintSpecV2::from_canonical_bytes(bytes)
        .map(|_| 1)
        .map_err(|error| error.to_string())
}

pub(super) fn sqlite_sprint_spec_digest(bytes: &[u8]) -> Result<String, String> {
    SprintSpecV2::from_canonical_bytes(bytes)
        .and_then(|value| value.canonical_digest())
        .map(|digest| digest.to_string())
        .map_err(|error| error.to_string())
}

pub(super) fn sqlite_task_graph_pair_canonical(
    graph_bytes: &[u8],
    sprint_bytes: &[u8],
) -> Result<i64, String> {
    let sprint =
        SprintSpecV2::from_canonical_bytes(sprint_bytes).map_err(|error| error.to_string())?;
    TaskGraphV2::from_canonical_bytes_for_sprint(graph_bytes, &sprint)
        .map(|_| 1)
        .map_err(|error| error.to_string())
}

pub(super) fn sqlite_task_graph_digest(
    graph_bytes: &[u8],
    sprint_bytes: &[u8],
) -> Result<String, String> {
    let sprint =
        SprintSpecV2::from_canonical_bytes(sprint_bytes).map_err(|error| error.to_string())?;
    TaskGraphV2::from_canonical_bytes_for_sprint(graph_bytes, &sprint)
        .and_then(|graph| graph.canonical_digest_for_sprint(&sprint))
        .map(|digest| digest.to_string())
        .map_err(|error| error.to_string())
}

pub(super) fn sqlite_task_done_set_canonical(bytes: &[u8]) -> Result<i64, String> {
    let value: CompleteTaskDoneSetV1 = decode_exact("complete TaskDone set", bytes)?;
    value
        .validate_intrinsic()
        .map(|()| 1)
        .map_err(|error| error.to_string())
}

pub(super) fn sqlite_task_done_set_digest(bytes: &[u8]) -> Result<String, String> {
    let value: CompleteTaskDoneSetV1 = decode_exact("complete TaskDone set", bytes)?;
    value
        .canonical_digest()
        .map(|digest| digest.to_string())
        .map_err(|error| error.to_string())
}

pub(super) fn sqlite_task_done_set_matches_authority(
    set_bytes: &[u8],
    sprint_bytes: &[u8],
    graph_bytes: &[u8],
) -> Result<i64, String> {
    let set: CompleteTaskDoneSetV1 =
        serde_json::from_slice(set_bytes).map_err(|error| error.to_string())?;
    if set.canonical_bytes().map_err(|error| error.to_string())? != set_bytes {
        return Ok(0);
    }
    let sprint =
        SprintSpecV2::from_canonical_bytes(sprint_bytes).map_err(|error| error.to_string())?;
    let graph = TaskGraphV2::from_canonical_bytes_for_sprint(graph_bytes, &sprint)
        .map_err(|error| error.to_string())?;
    Ok(i64::from(set.validate_for(&sprint, &graph).is_ok()))
}

pub(super) fn sqlite_criterion_evidence_set_canonical(bytes: &[u8]) -> Result<i64, String> {
    let value: CompleteCriterionEvidenceSetV1 =
        decode_exact("complete criterion-evidence set", bytes)?;
    value
        .validate_intrinsic()
        .map(|()| 1)
        .map_err(|error| error.to_string())
}

pub(super) fn sqlite_criterion_evidence_set_digest(bytes: &[u8]) -> Result<String, String> {
    let value: CompleteCriterionEvidenceSetV1 =
        decode_exact("complete criterion-evidence set", bytes)?;
    value
        .canonical_digest()
        .map(|digest| digest.to_string())
        .map_err(|error| error.to_string())
}

pub(super) fn sqlite_criterion_evidence_set_matches_sprint(
    set_bytes: &[u8],
    sprint_bytes: &[u8],
) -> Result<i64, String> {
    let set: CompleteCriterionEvidenceSetV1 =
        serde_json::from_slice(set_bytes).map_err(|error| error.to_string())?;
    if set.canonical_bytes().map_err(|error| error.to_string())? != set_bytes {
        return Ok(0);
    }
    let sprint =
        SprintSpecV2::from_canonical_bytes(sprint_bytes).map_err(|error| error.to_string())?;
    Ok(i64::from(set.validate_for(&sprint).is_ok()))
}

fn validate_attempt_request_binding(
    request: &CurrentFinalVerificationAdmissionRequestV1,
    authority: &FinalVerificationAttemptAuthorityV1,
) -> Result<(), ContractError> {
    request.validate_intrinsic()?;
    let request_digest = request.canonical_digest()?;
    let task_set_digest = request.task_done_set.canonical_digest()?;
    let criterion_set_digest = request.criterion_evidence_set.canonical_digest()?;
    let expected_attempt_id = mint_identity(ATTEMPT_ID_DOMAIN, request_digest.as_str().as_bytes());
    let expected_admission_id =
        mint_identity(ADMISSION_ID_DOMAIN, request_digest.as_str().as_bytes());
    let expected_event_id = mint_identity(
        ADMISSION_EVENT_ID_DOMAIN,
        request_digest.as_str().as_bytes(),
    );
    if authority.attempt_id != expected_attempt_id
        || authority.sprint_id != request.sprint_id
        || authority.final_verification_admission_id != expected_admission_id
        || authority.input_snapshot != request.task_done_set.snapshot_digest
        || authority.complete_task_done_set_digest != task_set_digest
        || authority.complete_criterion_evidence_set_digest != criterion_set_digest
        || authority.final_verification_check != request.final_verification_check
        || authority.execution_policy_digest != request.execution_policy_digest
        || authority.provenance.coordinator_instance_id != request.coordinator_instance_id
        || authority.provenance.admission_event_id != expected_event_id
        || authority.provenance.admission_event_sequence != u64::from(authority.attempt_ordinal)
        || authority.provenance.admitted_at_unix_ms != request.admitted_at_unix_ms
    {
        return Err(ContractError::new(
            "current_final_verification_request",
            "canonical request bytes do not derive the exact attempt authority",
        ));
    }
    Ok(())
}

pub(super) fn sqlite_admission_request_canonical(bytes: &[u8]) -> Result<i64, String> {
    let value: CurrentFinalVerificationAdmissionRequestV1 =
        decode_exact("current final-verification admission request", bytes)?;
    value
        .validate_intrinsic()
        .map(|()| 1)
        .map_err(|error| error.to_string())
}

pub(super) fn sqlite_admission_request_digest(bytes: &[u8]) -> Result<String, String> {
    let value: CurrentFinalVerificationAdmissionRequestV1 =
        decode_exact("current final-verification admission request", bytes)?;
    value
        .canonical_digest()
        .map(|digest| digest.to_string())
        .map_err(|error| error.to_string())
}

pub(super) fn sqlite_attempt_matches_request(
    request_bytes: &[u8],
    authority_bytes: &[u8],
    request_id: &str,
) -> Result<i64, String> {
    let request: CurrentFinalVerificationAdmissionRequestV1 = decode_exact(
        "current final-verification admission request",
        request_bytes,
    )?;
    let authority = FinalVerificationAttemptAuthorityV1::from_canonical_bytes(authority_bytes)
        .map_err(|error| error.to_string())?;
    if request.request_id != request_id {
        return Err("admission request identity differs from its projected request id".into());
    }
    validate_attempt_request_binding(&request, &authority)
        .map(|()| 1)
        .map_err(|error| error.to_string())
}

pub(super) fn sqlite_attempt_canonical(bytes: &[u8]) -> Result<i64, String> {
    FinalVerificationAttemptAuthorityV1::from_canonical_bytes(bytes)
        .map(|_| 1)
        .map_err(|error| error.to_string())
}

pub(super) fn sqlite_attempt_digest(bytes: &[u8]) -> Result<String, String> {
    FinalVerificationAttemptAuthorityV1::from_canonical_bytes(bytes)
        .and_then(|value| value.canonical_digest())
        .map(|digest| digest.to_string())
        .map_err(|error| error.to_string())
}

pub(super) fn sqlite_control_canonical(bytes: &[u8]) -> Result<i64, String> {
    let value: CurrentFinalVerificationControlV1 =
        decode_exact("current final-verification control", bytes)?;
    value
        .validate()
        .map(|()| 1)
        .map_err(|error| error.to_string())
}

pub(super) fn sqlite_capture_canonical(bytes: &[u8]) -> Result<i64, String> {
    let value: CurrentFinalVerificationCaptureClosureV1 =
        decode_exact("current final-verification capture", bytes)?;
    value
        .validate()
        .map(|()| 1)
        .map_err(|error| error.to_string())
}

pub(super) fn sqlite_outcome_canonical(bytes: &[u8]) -> Result<i64, String> {
    let value: CurrentFinalVerificationOutcomeV1 =
        decode_exact("current final-verification outcome", bytes)?;
    value
        .validate()
        .map(|()| 1)
        .map_err(|error| error.to_string())
}

pub(super) fn sqlite_repair_activation_canonical(bytes: &[u8]) -> Result<i64, String> {
    let value: CurrentFinalVerificationRepairActivationV1 =
        decode_exact("current repair activation", bytes)?;
    value
        .validate()
        .map(|()| 1)
        .map_err(|error| error.to_string())
}

pub(super) fn sqlite_repair_completion_canonical(bytes: &[u8]) -> Result<i64, String> {
    let value: CurrentFinalVerificationRepairCompletionV1 =
        decode_exact("current repair completion", bytes)?;
    value
        .validate()
        .map(|()| 1)
        .map_err(|error| error.to_string())
}

pub(super) fn sqlite_operational_event_canonical(bytes: &[u8]) -> Result<i64, String> {
    let event: CurrentFinalVerificationAuthorityEventV1 =
        decode_exact("current final-verification operational event", bytes)?;
    event
        .validate_integrity()
        .map(|()| 1)
        .map_err(|error| error.to_string())
}

pub(super) fn sqlite_operational_event_digest(bytes: &[u8]) -> Result<String, String> {
    let event: CurrentFinalVerificationAuthorityEventV1 =
        decode_exact("current final-verification operational event", bytes)?;
    event
        .validate_integrity()
        .map(|()| event.event_digest.to_string())
        .map_err(|error| error.to_string())
}

pub(super) fn sqlite_operational_attempt_canonical(bytes: &[u8]) -> Result<i64, String> {
    let attempt: OperationalCurrentFinalVerificationAttemptV1 =
        decode_exact("current final-verification operational attempt", bytes)?;
    attempt
        .validate_integrity()
        .map(|()| 1)
        .map_err(|error| error.to_string())
}

pub(super) fn sqlite_operational_attempt_digest(bytes: &[u8]) -> Result<String, String> {
    let attempt: OperationalCurrentFinalVerificationAttemptV1 =
        decode_exact("current final-verification operational attempt", bytes)?;
    attempt
        .validate_integrity()
        .map(|()| attempt.operational_attempt_digest.to_string())
        .map_err(|error| error.to_string())
}

pub(super) fn sqlite_operational_attempt_matches(
    operational_bytes: &[u8],
    event_bytes: &[u8],
    authority_bytes: &[u8],
    request_bytes: &[u8],
    sprint_bytes: &[u8],
    graph_bytes: &[u8],
) -> Result<i64, String> {
    let operational: OperationalCurrentFinalVerificationAttemptV1 = decode_exact(
        "current final-verification operational attempt",
        operational_bytes,
    )?;
    let event: CurrentFinalVerificationAuthorityEventV1 =
        decode_exact("current final-verification operational event", event_bytes)?;
    let authority = FinalVerificationAttemptAuthorityV1::from_canonical_bytes(authority_bytes)
        .map_err(|error| error.to_string())?;
    let request: CurrentFinalVerificationAdmissionRequestV1 = decode_exact(
        "current final-verification admission request",
        request_bytes,
    )?;
    let spec =
        SprintSpecV2::from_canonical_bytes(sprint_bytes).map_err(|error| error.to_string())?;
    let graph = TaskGraphV2::from_canonical_bytes_for_sprint(graph_bytes, &spec)
        .map_err(|error| error.to_string())?;
    validate_attempt_request_binding(&request, &authority).map_err(|error| error.to_string())?;
    let current = CurrentSprintAuthorityV32 {
        spec,
        graph,
        created_at_unix_ms: 1,
    };
    let attempt = PersistedCurrentFinalVerificationAttemptV1 {
        request_id: request.request_id.clone(),
        authority,
        outcome: None,
    };
    operational
        .validate_for(&request, &current, &attempt, &event)
        .map(|()| 1)
        .map_err(|error| error.to_string())
}

pub(super) fn sqlite_operational_write_admitted(
    record_kind: &str,
    attempt_id: &str,
    record_digest: &str,
) -> i64 {
    OPERATIONAL_ADMISSION_WRITE_GUARD_V1.with(|slot| {
        i64::from(slot.borrow().as_ref().is_some_and(|guard| {
            guard.attempt_id == attempt_id
                && match record_kind {
                    "event" => guard.event_digest.as_str() == record_digest,
                    "operational-attempt" => {
                        guard.operational_attempt_digest.as_str() == record_digest
                    }
                    _ => false,
                }
        }))
    })
}

struct OperationalAdmissionWriteGuardResetV1;

impl Drop for OperationalAdmissionWriteGuardResetV1 {
    fn drop(&mut self) {
        OPERATIONAL_ADMISSION_WRITE_GUARD_V1.with(|slot| *slot.borrow_mut() = None);
    }
}

fn with_operational_admission_write_guard<T>(
    guard: OperationalAdmissionWriteGuardV1,
    operation: impl FnOnce() -> Result<T, LedgerError>,
) -> Result<T, LedgerError> {
    let prior = OPERATIONAL_ADMISSION_WRITE_GUARD_V1.with(|slot| slot.borrow_mut().replace(guard));
    if prior.is_some() {
        OPERATIONAL_ADMISSION_WRITE_GUARD_V1.with(|slot| *slot.borrow_mut() = prior);
        return Err(corrupt(
            "current final-verification operational admission",
            "nested operational write admission is forbidden",
        ));
    }
    let _reset = OperationalAdmissionWriteGuardResetV1;
    operation()
}
impl EventLedger {
    /// Atomically persists one exact current V2 sprint/graph pair.
    ///
    /// Exact replay returns the existing readback. Legacy sprint identifiers
    /// and crossed current bytes are rejected; this method grants no dispatch.
    ///
    /// # Errors
    ///
    /// Returns a ledger error for invalid/crossed contracts, identity reuse,
    /// nonpositive timestamps, read-only handles, or storage/readback failure.
    #[allow(clippy::too_many_lines)] // One transaction persists and reads back the reciprocal sprint, graph, and every exact task node.
    pub fn create_current_sprint_authority_v32(
        &mut self,
        spec: &SprintSpecV2,
        graph: &TaskGraphV2,
        created_at_unix_ms: u64,
    ) -> Result<CurrentSprintAuthorityV32, LedgerError> {
        self.require_writable()?;
        graph.validate_for_sprint(spec)?;
        if created_at_unix_ms == 0 {
            return Err(LedgerError::InvalidTimestamp("created_at_unix_ms"));
        }
        let spec_bytes = spec.canonical_bytes()?;
        let spec_digest = spec.canonical_digest()?;
        let graph_bytes = graph.canonical_bytes_for_sprint(spec)?;
        let graph_digest = graph.canonical_digest_for_sprint(spec)?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        if let Some(existing) =
            load_current_sprint_authority_optional(&transaction, &spec.sprint_id)?
        {
            if existing.spec == *spec
                && existing.graph == *graph
                && existing.created_at_unix_ms == created_at_unix_ms
            {
                super::current_criterion_evidence_v32::project_current_sprint_criteria_v32(
                    &transaction,
                    spec,
                )?;
                transaction.commit()?;
                return Ok(existing);
            }
            return Err(mismatch(
                "current sprint authority v32",
                "an existing sprint identity has different immutable bytes",
            ));
        }
        if transaction.query_row(
            "SELECT EXISTS(SELECT 1 FROM sprints WHERE sprint_id = ?1)",
            [spec.sprint_id.as_str()],
            |row| row.get::<_, bool>(0),
        )? {
            return Err(LedgerError::SprintAlreadyExists(spec.sprint_id.clone()));
        }
        transaction.execute(
            "INSERT INTO current_sprint_authorities_v32 (
                sprint_id, sprint_authority_version, sprint_spec_digest,
                task_graph_id, task_graph_payload_digest,
                repair_slot_reserve_digest, max_final_verification_attempts,
                base_snapshot, workspace_grant_hash, created_at_unix_ms, spec_json
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
            params![
                spec.sprint_id,
                i64::from(spec.sprint_authority_version),
                spec_digest.as_str(),
                spec.task_graph_id,
                spec.task_graph_payload_digest.as_str(),
                spec.repair_slot_reserve_digest.as_str(),
                i64::from(spec.budget.max_final_verification_attempts),
                spec.base_snapshot.as_str(),
                spec.workspace_grant.grant_hash.as_str(),
                super::sqlite_integer("created_at_unix_ms", created_at_unix_ms)?,
                spec_bytes,
            ],
        )?;
        transaction.execute(
            "INSERT INTO current_task_graph_authorities_v32 (
                graph_id, sprint_id, sprint_authority_version, graph_digest,
                sprint_spec_digest, graph_payload_digest,
                repair_slot_reserve_digest, graph_json
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                graph.graph_id,
                graph.sprint_id,
                i64::from(graph.sprint_authority_version),
                graph_digest.as_str(),
                graph.sprint_spec_digest.as_str(),
                graph.payload_digest()?.as_str(),
                graph.repair_slot_reserve_digest.as_str(),
                graph_bytes,
            ],
        )?;
        for (ordinal, task) in graph.tasks.iter().enumerate() {
            let (purpose, repair_slot_ordinal) = match task.purpose {
                TaskPurposeV2::Ordinary => ("Ordinary", None),
                TaskPurposeV2::FinalVerificationRepairSlot { slot_ordinal } => {
                    ("FinalVerificationRepairSlot", Some(i64::from(slot_ordinal)))
                }
            };
            transaction.execute(
                "INSERT INTO current_task_nodes_v32 (
                    sprint_id, task_id, declaration_ordinal, purpose,
                    repair_slot_ordinal, required, task_json
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                params![
                    spec.sprint_id,
                    task.task_id,
                    i64::try_from(ordinal)
                        .map_err(|_| LedgerError::IntegerOutOfRange("task ordinal"))?,
                    purpose,
                    repair_slot_ordinal,
                    i64::from(task.required),
                    encode_ledger("current task v32", task)?,
                ],
            )?;
        }
        super::current_criterion_evidence_v32::project_current_sprint_criteria_v32(
            &transaction,
            spec,
        )?;
        let persisted = load_current_sprint_authority(&transaction, &spec.sprint_id)?;
        if persisted.spec != *spec
            || persisted.graph != *graph
            || persisted.created_at_unix_ms != created_at_unix_ms
        {
            return Err(corrupt(
                "current sprint authority v32",
                "transactional readback differs from supplied canonical authority",
            ));
        }
        transaction.commit()?;
        secure_database_files(&self.database_path)?;
        self.load_current_sprint_authority_v32(&spec.sprint_id)
    }

    /// Loads one exact current V2 sprint/graph pair without minting authority.
    ///
    /// # Errors
    ///
    /// Returns a ledger error when absent or when any stored bytes, digest, or
    /// reciprocal link fail exact readback.
    pub fn load_current_sprint_authority_v32(
        &self,
        sprint_id: &str,
    ) -> Result<CurrentSprintAuthorityV32, LedgerError> {
        self.load_current_sprint_criteria_v32(sprint_id)?;
        load_current_sprint_authority(&self.connection, sprint_id)
    }

    /// Atomically records a source-only schema-v32 final-verification attempt.
    ///
    /// Core derives the one-based ordinal, immutable predecessor, attempt,
    /// admission, and diagnostic event-shaped identities under the write
    /// transaction. This compatibility API does not create a real event or an
    /// operational attempt; calling it makes that request permanently
    /// ineligible for schema-v34 operational backfill. Exact request replay
    /// returns readback only and never a runner permit.
    ///
    /// # Errors
    ///
    /// Returns a ledger error for incomplete/crossed evidence sets, an open or
    /// noncontinuable prior outcome, exhausted cap, missing activated repair,
    /// stale repaired-snapshot evidence, identity replay, or storage failure.
    #[allow(clippy::too_many_lines)] // One transaction derives and crosses every attempt-authority dimension.
    pub fn admit_current_final_verification_attempt_v32(
        &mut self,
        request: &CurrentFinalVerificationAdmissionRequestV1,
    ) -> Result<PersistedCurrentFinalVerificationAttemptV1, LedgerError> {
        self.require_writable()?;
        let current = load_current_sprint_authority(&self.connection, &request.sprint_id)?;
        request.validate_for(&current.spec, &current.graph)?;
        let request_bytes = request.canonical_bytes()?;
        let request_digest = domain_digest(ADMISSION_REQUEST_DIGEST_DOMAIN, &request_bytes);

        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let admitted = admit_current_final_verification_attempt_in_transaction_v32(
            &transaction,
            request,
            &request_bytes,
            &request_digest,
        )?;
        let attempt_id = admitted.persisted.authority.attempt_id.clone();
        transaction.commit()?;
        secure_database_files(&self.database_path)?;
        self.load_current_final_verification_attempt_v32(&attempt_id)
    }

    /// Atomically creates the first operational final-verification admission.
    ///
    /// The one `Immediate` transaction creates the schema-v32 parent attempt,
    /// one real contiguous `AttemptAdmitted` event, and the exact schema-v34
    /// overlay. Exact request replay returns the same readback and no execution
    /// capability. Existing source-only attempts are never backfilled, and
    /// successor admission remains dormant until source-derived schema-v34
    /// outcomes exist.
    ///
    /// # Errors
    ///
    /// Returns a ledger error for a diagnostic gap, any prior attempt when a
    /// new request is presented, crossed or oversized inputs, read-only use,
    /// identity replay, or failure of transactional/post-commit readback.
    #[allow(clippy::too_many_lines)] // One transaction must derive, persist, and read back all three T0 rows atomically.
    pub fn admit_operational_current_final_verification_attempt_v34(
        &mut self,
        request: &CurrentFinalVerificationAdmissionRequestV1,
    ) -> Result<PersistedOperationalCurrentFinalVerificationAttemptV1, LedgerError> {
        self.require_writable()?;
        validate_current_direct_exec_command_v1(&request.final_verification_check)?;
        let current = load_current_sprint_authority(&self.connection, &request.sprint_id)?;
        request.validate_for(&current.spec, &current.graph)?;
        let request_bytes = request.canonical_bytes()?;
        let request_digest = domain_digest(ADMISSION_REQUEST_DIGEST_DOMAIN, &request_bytes);

        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let current = load_current_sprint_authority(&transaction, &request.sprint_id)?;
        request.validate_for(&current.spec, &current.graph)?;

        if let Some(existing_attempt_id) = transaction
            .query_row(
                "SELECT attempt_id FROM current_final_verification_attempts_v32
                 WHERE request_id = ?1",
                [request.request_id.as_str()],
                |row| row.get::<_, String>(0),
            )
            .optional()?
        {
            let admitted = admit_current_final_verification_attempt_in_transaction_v32(
                &transaction,
                request,
                &request_bytes,
                &request_digest,
            )?;
            if admitted.inserted || admitted.persisted.authority.attempt_id != existing_attempt_id {
                return Err(corrupt(
                    "current final-verification operational admission",
                    "exact replay unexpectedly created or crossed its schema-v32 parent",
                ));
            }
            let Some(replayed) =
                load_operational_attempt_optional_v34(&transaction, &existing_attempt_id)?
            else {
                return Err(mismatch(
                    "current final-verification operational admission",
                    "an existing schema-v32 diagnostic attempt cannot be operationally backfilled",
                ));
            };
            if replayed.attempt
                != OperationalCurrentFinalVerificationParentV1::from(&admitted.persisted)
            {
                return Err(corrupt(
                    "current final-verification operational admission",
                    "operational replay crosses its exact schema-v32 parent",
                ));
            }
            transaction.commit()?;
            return self
                .load_operational_current_final_verification_attempt_v34(&existing_attempt_id);
        }

        let prior_attempt_count = transaction.query_row(
            "SELECT COUNT(*) FROM current_final_verification_attempts_v32
             WHERE sprint_id = ?1",
            [request.sprint_id.as_str()],
            |row| row.get::<_, i64>(0),
        )?;
        if prior_attempt_count != 0 {
            return Err(mismatch(
                "current final-verification operational admission",
                "successor admission is dormant until source-derived schema-v34 outcomes exist",
            ));
        }

        let admitted = admit_current_final_verification_attempt_in_transaction_v32(
            &transaction,
            request,
            &request_bytes,
            &request_digest,
        )?;
        if !admitted.inserted || admitted.persisted.authority.attempt_ordinal != 1 {
            return Err(corrupt(
                "current final-verification operational admission",
                "fresh T0 admission must create exactly the first schema-v32 parent",
            ));
        }
        let event_sequence = next_operational_event_sequence_v34(
            &transaction,
            &admitted.persisted.authority.sprint_id,
        )?;
        let event = CurrentFinalVerificationAuthorityEventV1::try_new(
            &admitted.persisted,
            request_digest,
            event_sequence,
        )?;
        let operational = OperationalCurrentFinalVerificationAttemptV1::try_new(
            request,
            &current,
            &admitted.persisted,
            &event,
        )?;
        let guard = OperationalAdmissionWriteGuardV1 {
            attempt_id: admitted.persisted.authority.attempt_id.clone(),
            event_digest: event.event_digest.clone(),
            operational_attempt_digest: operational.operational_attempt_digest.clone(),
        };
        with_operational_admission_write_guard(guard, || {
            insert_operational_event_v34(&transaction, &event)?;
            insert_operational_attempt_v34(&transaction, &operational)
        })?;

        let expected = PersistedOperationalCurrentFinalVerificationAttemptV1 {
            attempt: OperationalCurrentFinalVerificationParentV1::from(&admitted.persisted),
            admission_event: event,
            operational_attempt: operational,
        };
        let transactional =
            load_operational_attempt_v34(&transaction, &expected.attempt.authority.attempt_id)?;
        if transactional != expected {
            return Err(corrupt(
                "current final-verification operational admission",
                "transactional readback differs from the exact derived admission",
            ));
        }
        let attempt_id = expected.attempt.authority.attempt_id.clone();
        transaction.commit()?;
        secure_database_files(&self.database_path)?;
        let persisted =
            self.load_operational_current_final_verification_attempt_v34(&attempt_id)?;
        if persisted == expected {
            Ok(persisted)
        } else {
            Err(corrupt(
                "current final-verification operational admission",
                "post-commit readback differs from the exact derived admission",
            ))
        }
    }

    /// Loads one exact operational schema-v34 admission without granting launch.
    ///
    /// # Errors
    ///
    /// Returns a ledger error when absent or when any stored projection,
    /// canonical byte string, digest, or current-authority join differs.
    pub fn load_operational_current_final_verification_attempt_v34(
        &self,
        attempt_id: &str,
    ) -> Result<PersistedOperationalCurrentFinalVerificationAttemptV1, LedgerError> {
        load_operational_attempt_v34(&self.connection, attempt_id)
    }

    /// Loads one exact current attempt and optional typed outcome.
    ///
    /// # Errors
    ///
    /// Returns a ledger error when absent or when canonical bytes and stored
    /// projection columns disagree.
    pub fn load_current_final_verification_attempt_v32(
        &self,
        attempt_id: &str,
    ) -> Result<PersistedCurrentFinalVerificationAttemptV1, LedgerError> {
        load_current_attempt(&self.connection, attempt_id)
    }

    /// Records one core-minted authenticated pause, steering, or cancel cause.
    ///
    /// The returned record is evidence only. Whether it permits same-snapshot
    /// continuation is derived later from its exact before-effect join.
    ///
    /// # Errors
    ///
    /// Returns a ledger error for an absent/closed/crossed attempt, terminal
    /// sprint, invalid timestamp, read-only handle, or storage failure.
    pub fn record_current_final_verification_control_v32(
        &mut self,
        attempt_id: &str,
        control_kind: CurrentFinalVerificationControlKindV1,
        before_effect: bool,
        issued_at_unix_ms: u64,
    ) -> Result<CurrentFinalVerificationControlV1, LedgerError> {
        self.require_writable()?;
        if issued_at_unix_ms == 0 {
            return Err(LedgerError::InvalidTimestamp("control issued_at_unix_ms"));
        }
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let attempt = load_current_attempt(&transaction, attempt_id)?;
        ensure_no_current_terminal(&transaction, &attempt.authority.sprint_id)?;
        if attempt.outcome.is_some() {
            return Err(mismatch(
                "current final-verification control",
                "a terminal attempt cannot receive new control authority",
            ));
        }
        if issued_at_unix_ms < attempt.authority.provenance.admitted_at_unix_ms {
            return Err(mismatch(
                "current final-verification control",
                "control cannot predate attempt admission",
            ));
        }
        let identity_bytes = encode_ledger(
            "current final-verification control identity",
            &ControlIdentity {
                sprint_id: &attempt.authority.sprint_id,
                attempt_id,
                control_kind,
                before_effect,
                issued_at_unix_ms,
            },
        )?;
        let control = CurrentFinalVerificationControlV1 {
            control_version: CURRENT_OUTCOME_VERSION_V1,
            control_id: mint_identity(CONTROL_ID_DOMAIN, &identity_bytes),
            sprint_id: attempt.authority.sprint_id,
            attempt_id: attempt_id.to_owned(),
            control_kind,
            before_effect,
            issued_at_unix_ms,
        };
        control.validate()?;
        if let Some(existing) = load_current_control_optional(&transaction, &control.control_id)? {
            if existing == control {
                return Ok(existing);
            }
            return Err(mismatch(
                "current final-verification control",
                "deterministic control identity names different canonical bytes",
            ));
        }
        transaction.execute(
            "INSERT INTO current_final_verification_controls_v32 (
                control_id, sprint_id, attempt_id, control_kind,
                before_effect, issued_at_unix_ms, control_json
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                control.control_id,
                control.sprint_id,
                control.attempt_id,
                control_kind_sql(control.control_kind),
                i64::from(control.before_effect),
                super::sqlite_integer("control issued_at", issued_at_unix_ms)?,
                encode_ledger("current final-verification control", &control)?,
            ],
        )?;
        let persisted = load_current_control(&transaction, &control.control_id)?;
        if persisted != control {
            return Err(corrupt(
                "current final-verification control",
                "transactional readback differs from derived control",
            ));
        }
        transaction.commit()?;
        secure_database_files(&self.database_path)?;
        load_current_control(&self.connection, &control.control_id)
    }

    /// Atomically persists exact capture closure and derives its sole typed outcome.
    ///
    /// Missing cleanup/custody/control backing becomes `Unknown`; callers do
    /// not select an outcome class. Exact replay returns immutable readback.
    ///
    /// # Errors
    ///
    /// Returns a ledger error for malformed or crossed capture identity,
    /// replay with different bytes, an already terminal sprint, read-only
    /// handle, or storage/readback failure.
    pub fn close_current_final_verification_attempt_v32(
        &mut self,
        capture: &CurrentFinalVerificationCaptureClosureV1,
    ) -> Result<CurrentFinalVerificationOutcomeV1, LedgerError> {
        self.require_writable()?;
        capture.validate()?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let attempt = load_current_attempt(&transaction, &capture.attempt_id)?;
        if attempt.authority.sprint_id != capture.sprint_id
            || capture.terminal_at_unix_ms < attempt.authority.provenance.admitted_at_unix_ms
        {
            return Err(mismatch(
                "current final-verification capture",
                "capture crosses sprint, attempt, or admission time",
            ));
        }
        if let Some(existing) = attempt.outcome {
            let stored_capture = load_current_capture(&transaction, &capture.attempt_id)?;
            if stored_capture == *capture {
                return Ok(existing);
            }
            return Err(mismatch(
                "current final-verification capture",
                "terminal attempt was replayed with different capture bytes",
            ));
        }
        ensure_no_current_terminal(&transaction, &capture.sprint_id)?;
        insert_current_capture(&transaction, capture)?;
        let outcome_kind = classify_current_capture(&transaction, capture)?;
        let capture_bytes = encode_ledger("current final-verification capture", capture)?;
        let outcome = CurrentFinalVerificationOutcomeV1 {
            outcome_version: CURRENT_OUTCOME_VERSION_V1,
            outcome_id: mint_identity(OUTCOME_ID_DOMAIN, &capture_bytes),
            sprint_id: capture.sprint_id.clone(),
            attempt_id: capture.attempt_id.clone(),
            closure_id: capture.closure_id.clone(),
            outcome: outcome_kind,
            terminal_at_unix_ms: capture.terminal_at_unix_ms,
        };
        outcome.validate()?;
        transaction.execute(
            "INSERT INTO current_final_verification_outcomes_v32 (
                outcome_id, sprint_id, attempt_id, closure_id, outcome_kind,
                outcome_code, terminal_at_unix_ms, outcome_json
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                outcome.outcome_id,
                outcome.sprint_id,
                outcome.attempt_id,
                outcome.closure_id,
                outcome.outcome.sql_kind(),
                outcome.outcome.sql_code().map(i64::from),
                super::sqlite_integer("outcome terminal_at", outcome.terminal_at_unix_ms)?,
                encode_ledger("current final-verification outcome", &outcome)?,
            ],
        )?;
        maybe_insert_current_terminal(&transaction, &attempt.authority, &outcome)?;
        let persisted = load_current_outcome_optional(&transaction, &capture.attempt_id)?
            .ok_or_else(|| corrupt("current final-verification outcome", "readback missing"))?;
        if persisted != outcome {
            return Err(corrupt(
                "current final-verification outcome",
                "transactional readback differs from core-derived classification",
            ));
        }
        transaction.commit()?;
        secure_database_files(&self.database_path)?;
        load_current_outcome_optional(&self.connection, &capture.attempt_id)?.ok_or_else(|| {
            corrupt(
                "current final-verification outcome",
                "post-commit readback missing",
            )
        })
    }

    /// Loads the current unsuccessful terminal marker, when one exists.
    ///
    /// # Errors
    ///
    /// Returns a ledger error when stored terminal columns cross their exact
    /// source attempt/outcome.
    pub fn load_current_sprint_terminal_outcome_v32(
        &self,
        sprint_id: &str,
    ) -> Result<Option<CurrentSprintTerminalOutcomeV1>, LedgerError> {
        load_current_terminal_optional(&self.connection, sprint_id)
    }

    /// Activates the next predeclared dormant repair slot for one exact known
    /// after-effect verifier failure.
    ///
    /// # Errors
    ///
    /// Returns a ledger error unless the failed attempt is latest, its outcome
    /// is a repairable known failure, an attempt remains under the immutable
    /// cap, and the exact next graph slot is still dormant.
    #[allow(clippy::too_many_lines)] // Activation atomically crosses the failed attempt, outcome, cap, graph slot, time, and deterministic identity.
    pub fn activate_current_final_verification_repair_v32(
        &mut self,
        failure_outcome_id: &str,
        activated_at_unix_ms: u64,
    ) -> Result<CurrentFinalVerificationRepairActivationV1, LedgerError> {
        self.require_writable()?;
        if activated_at_unix_ms == 0 {
            return Err(LedgerError::InvalidTimestamp("repair activated_at_unix_ms"));
        }
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        if let Some(existing) =
            load_repair_activation_by_failure_optional(&transaction, failure_outcome_id)?
        {
            if existing.activated_at_unix_ms == activated_at_unix_ms {
                return Ok(existing);
            }
            return Err(mismatch(
                "current repair activation v32",
                "failure was replayed with a different activation timestamp",
            ));
        }
        let attempt_id = transaction
            .query_row(
                "SELECT attempt_id FROM current_final_verification_outcomes_v32
                 WHERE outcome_id = ?1",
                [failure_outcome_id],
                |row| row.get::<_, String>(0),
            )
            .optional()?
            .ok_or_else(|| LedgerError::ArtifactNotFound {
                entity: "current final-verification failure outcome",
                id: failure_outcome_id.to_owned(),
            })?;
        let attempt = load_current_attempt(&transaction, &attempt_id)?;
        ensure_no_current_terminal(&transaction, &attempt.authority.sprint_id)?;
        let outcome = attempt.outcome.as_ref().ok_or_else(|| {
            corrupt(
                "current repair activation v32",
                "indexed failure attempt lacks a typed outcome",
            )
        })?;
        if outcome.outcome_id != failure_outcome_id
            || !outcome.outcome.is_known_after_effect_failure()
            || attempt.authority.attempt_ordinal
                >= attempt.authority.max_final_verification_attempts
            || activated_at_unix_ms < outcome.terminal_at_unix_ms
        {
            return Err(mismatch(
                "current repair activation v32",
                "outcome is not a latest repairable known failure with remaining attempt budget",
            ));
        }
        let latest = load_latest_current_attempt(&transaction, &attempt.authority.sprint_id)?
            .ok_or_else(|| corrupt("current repair activation v32", "latest attempt missing"))?;
        if latest.authority.attempt_id != attempt.authority.attempt_id {
            return Err(mismatch(
                "current repair activation v32",
                "only the latest admitted attempt may activate a repair slot",
            ));
        }
        let current = load_current_sprint_authority(&transaction, &attempt.authority.sprint_id)?;
        let slot_ordinal = attempt.authority.attempt_ordinal;
        let repair_task = current
            .graph
            .tasks
            .iter()
            .find(|task| {
                task.purpose == TaskPurposeV2::FinalVerificationRepairSlot { slot_ordinal }
            })
            .ok_or_else(|| {
                corrupt(
                    "current repair activation v32",
                    "validated graph lacks the exact next predeclared repair slot",
                )
            })?;
        let identity_bytes = encode_ledger(
            "current repair activation identity",
            &RepairActivationIdentity {
                sprint_id: &attempt.authority.sprint_id,
                failed_attempt_id: &attempt.authority.attempt_id,
                failure_outcome_id,
                failed_snapshot: &attempt.authority.input_snapshot,
                slot_ordinal,
                repair_task_id: &repair_task.task_id,
                activated_at_unix_ms,
            },
        )?;
        let activation = CurrentFinalVerificationRepairActivationV1 {
            activation_version: CURRENT_OUTCOME_VERSION_V1,
            activation_id: mint_identity(REPAIR_ACTIVATION_ID_DOMAIN, &identity_bytes),
            sprint_id: attempt.authority.sprint_id,
            failed_attempt_id: attempt.authority.attempt_id,
            failure_outcome_id: failure_outcome_id.to_owned(),
            failed_snapshot: attempt.authority.input_snapshot,
            slot_ordinal,
            repair_task_id: repair_task.task_id.clone(),
            activated_at_unix_ms,
        };
        activation.validate()?;
        transaction.execute(
            "INSERT INTO current_final_verification_repair_activations_v32 (
                activation_id, sprint_id, failed_attempt_id, failure_outcome_id,
                failed_snapshot, slot_ordinal, repair_task_id,
                activated_at_unix_ms, activation_json
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            params![
                activation.activation_id,
                activation.sprint_id,
                activation.failed_attempt_id,
                activation.failure_outcome_id,
                activation.failed_snapshot.as_str(),
                i64::from(activation.slot_ordinal),
                activation.repair_task_id,
                super::sqlite_integer("repair activated_at", activated_at_unix_ms)?,
                encode_ledger("current repair activation", &activation)?,
            ],
        )?;
        let persisted = load_repair_activation(&transaction, &activation.activation_id)?;
        if persisted != activation {
            return Err(corrupt(
                "current repair activation v32",
                "transactional readback differs from derived activation",
            ));
        }
        transaction.commit()?;
        secure_database_files(&self.database_path)?;
        load_repair_activation(&self.connection, &activation.activation_id)
    }

    /// Closes one activated repair slot with a nonempty changed snapshot and
    /// a complete fresh criterion-evidence set.
    ///
    /// # Errors
    ///
    /// Returns a ledger error for an absent/unactivated slot, exact replay
    /// with changed bytes, empty/net-zero repair, crossed `TaskDone` linkage,
    /// stale criterion receipt, terminal sprint, or storage failure.
    #[allow(clippy::too_many_lines)] // The atomic repair closure crosses activation, TaskDone, integration, and every criterion receipt.
    pub fn complete_current_final_verification_repair_v32(
        &mut self,
        request: &CurrentFinalVerificationRepairCompletionRequestV1,
    ) -> Result<CurrentFinalVerificationRepairCompletionV1, LedgerError> {
        self.require_writable()?;
        request.validate_intrinsic()?;
        let request_digest = request.canonical_digest()?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        if let Some((completion_id, stored_digest)) = transaction
            .query_row(
                "SELECT completion_id, request_digest
                 FROM current_final_verification_repair_completions_v32
                 WHERE request_id = ?1",
                [request.request_id.as_str()],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
            )
            .optional()?
        {
            if stored_digest != request_digest.as_str() {
                return Err(mismatch(
                    "current repair completion request v32",
                    "idempotency identity was replayed with different canonical bytes",
                ));
            }
            let persisted = load_repair_completion(&transaction, &completion_id)?;
            transaction.commit()?;
            return Ok(persisted);
        }
        let activation = load_repair_activation(&transaction, &request.activation_id)?;
        ensure_no_current_terminal(&transaction, &activation.sprint_id)?;
        if request.completed_at_unix_ms < activation.activated_at_unix_ms
            || request.task_done_set.recorded_at_unix_ms > request.completed_at_unix_ms
            || request.criterion_evidence_set.recorded_at_unix_ms > request.completed_at_unix_ms
            || request.input_snapshot != activation.failed_snapshot
            || request.result_snapshot == activation.failed_snapshot
            || request.task_done_set.sprint_id != activation.sprint_id
            || request.criterion_evidence_set.sprint_id != activation.sprint_id
            || request.task_done_set.snapshot_digest != request.result_snapshot
            || request.criterion_evidence_set.snapshot_digest != request.result_snapshot
        {
            return Err(mismatch(
                "current repair completion v32",
                "repair crosses activation time, sprint, failed snapshot, or changed result snapshot",
            ));
        }
        let current = load_current_sprint_authority(&transaction, &activation.sprint_id)?;
        request
            .task_done_set
            .validate_for(&current.spec, &current.graph)?;
        request.criterion_evidence_set.validate_for(&current.spec)?;
        let failed = load_current_attempt(&transaction, &activation.failed_attempt_id)?;
        let failed_task_set = load_task_done_set_optional(
            &transaction,
            failed.authority.complete_task_done_set_digest.as_str(),
        )?
        .ok_or_else(|| {
            corrupt(
                "current repair completion v32",
                "failed TaskDone set missing",
            )
        })?;
        require_exact_repair_task_done_extension(
            &failed_task_set,
            &request.task_done_set,
            &activation,
            &request.repair_task_done_proof_id,
            &request.integration_receipt_id,
        )?;
        let stale_set = load_criterion_evidence_set_optional(
            &transaction,
            failed
                .authority
                .complete_criterion_evidence_set_digest
                .as_str(),
        )?
        .ok_or_else(|| {
            corrupt(
                "current repair completion v32",
                "failed evidence set missing",
            )
        })?;
        require_all_criterion_evidence_fresh(&stale_set, &request.criterion_evidence_set)?;
        let task_set_digest = persist_task_done_set(
            &transaction,
            &current.spec,
            &current.graph,
            &request.task_done_set,
        )?;
        let criterion_set_digest = persist_criterion_evidence_set(
            &transaction,
            &current.spec,
            &request.criterion_evidence_set,
        )?;
        if task_set_digest == failed.authority.complete_task_done_set_digest
            || criterion_set_digest == failed.authority.complete_criterion_evidence_set_digest
        {
            return Err(mismatch(
                "current repair completion v32",
                "changed-snapshot repair requires fresh complete TaskDone and criterion sets",
            ));
        }
        let identity_bytes = encode_ledger(
            "current repair completion identity",
            &RepairCompletionIdentity {
                request_digest: &request_digest,
                sprint_id: &activation.sprint_id,
                failed_attempt_id: &activation.failed_attempt_id,
            },
        )?;
        let completion = CurrentFinalVerificationRepairCompletionV1 {
            completion_version: CURRENT_OUTCOME_VERSION_V1,
            completion_id: mint_identity(REPAIR_COMPLETION_ID_DOMAIN, &identity_bytes),
            sprint_id: activation.sprint_id,
            activation_id: activation.activation_id,
            failed_attempt_id: activation.failed_attempt_id,
            repair_task_id: activation.repair_task_id,
            repair_task_done_proof_id: request.repair_task_done_proof_id.clone(),
            integration_receipt_id: request.integration_receipt_id.clone(),
            input_snapshot: request.input_snapshot.clone(),
            result_snapshot: request.result_snapshot.clone(),
            change_set_id: request.change_set_id.clone(),
            operation_count: request.operation_count,
            complete_task_done_set_digest: task_set_digest,
            complete_criterion_evidence_set_digest: criterion_set_digest,
            completed_at_unix_ms: request.completed_at_unix_ms,
        };
        completion.validate()?;
        transaction.execute(
            "INSERT INTO current_final_verification_repair_completions_v32 (
                completion_id, request_id, request_digest, sprint_id,
                activation_id, failed_attempt_id, repair_task_id,
                repair_task_done_proof_id, integration_receipt_id,
                input_snapshot, result_snapshot, change_set_id, operation_count,
                complete_task_done_set_digest,
                complete_criterion_evidence_set_digest,
                completed_at_unix_ms, completion_json
             ) VALUES (
                ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9,
                ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17
             )",
            params![
                completion.completion_id,
                request.request_id,
                request_digest.as_str(),
                completion.sprint_id,
                completion.activation_id,
                completion.failed_attempt_id,
                completion.repair_task_id,
                completion.repair_task_done_proof_id,
                completion.integration_receipt_id,
                completion.input_snapshot.as_str(),
                completion.result_snapshot.as_str(),
                completion.change_set_id,
                i64::from(completion.operation_count),
                completion.complete_task_done_set_digest.as_str(),
                completion.complete_criterion_evidence_set_digest.as_str(),
                super::sqlite_integer("repair completed_at", completion.completed_at_unix_ms)?,
                encode_ledger("current repair completion", &completion)?,
            ],
        )?;
        let persisted = load_repair_completion(&transaction, &completion.completion_id)?;
        if persisted != completion {
            return Err(corrupt(
                "current repair completion v32",
                "transactional readback differs from derived completion",
            ));
        }
        transaction.commit()?;
        secure_database_files(&self.database_path)?;
        load_repair_completion(&self.connection, &completion.completion_id)
    }

    /// Loads one exact repair activation without creating scheduling authority.
    ///
    /// # Errors
    ///
    /// Returns a ledger error when absent or corrupt.
    pub fn load_current_final_verification_repair_activation_v32(
        &self,
        activation_id: &str,
    ) -> Result<CurrentFinalVerificationRepairActivationV1, LedgerError> {
        load_repair_activation(&self.connection, activation_id)
    }

    /// Loads a sealed read-cut permit for one activated, unfinished repair.
    ///
    /// The permit cannot be caller-manufactured. Durable consumers still
    /// re-check the activation within their own transaction because a permit
    /// retained in memory can become stale after repair completion or sprint
    /// terminalization.
    ///
    /// # Errors
    ///
    /// Returns a ledger error when the activation is absent, crossed,
    /// completed, terminalized, or no longer the latest live repair slot.
    pub fn load_current_repair_activation_permit_v32(
        &self,
        activation_id: &str,
    ) -> Result<CurrentRepairActivationPermitV1, LedgerError> {
        let activation = load_repair_activation(&self.connection, activation_id)?;
        let is_live = self.connection.query_row(
            "SELECT EXISTS (
                 SELECT 1
                 FROM current_final_verification_repair_activations_v32 activation
                 WHERE activation.activation_id = ?1
                   AND NOT EXISTS (
                       SELECT 1
                       FROM current_final_verification_repair_completions_v32 completion
                       WHERE completion.activation_id = activation.activation_id
                   )
                   AND NOT EXISTS (
                       SELECT 1 FROM current_sprint_terminal_outcomes_v32 terminal
                       WHERE terminal.sprint_id = activation.sprint_id
                   )
                   AND NOT EXISTS (
                       SELECT 1
                       FROM current_final_verification_attempts_v32 later
                       JOIN current_final_verification_attempts_v32 failed
                         ON failed.attempt_id = activation.failed_attempt_id
                       WHERE later.sprint_id = activation.sprint_id
                         AND later.attempt_ordinal > failed.attempt_ordinal
                   )
             )",
            [activation_id],
            |row| row.get::<_, bool>(0),
        )?;
        if !is_live {
            return Err(mismatch(
                "current repair activation permit v32",
                "activation is completed, terminalized, or superseded",
            ));
        }
        let current = load_current_sprint_authority(&self.connection, &activation.sprint_id)?;
        CurrentRepairActivationPermitV1::from_persisted(activation, &current)
            .map_err(LedgerError::Contract)
    }

    /// Loads one exact completed repair proof.
    ///
    /// # Errors
    ///
    /// Returns a ledger error when absent or corrupt.
    pub fn load_current_final_verification_repair_completion_v32(
        &self,
        completion_id: &str,
    ) -> Result<CurrentFinalVerificationRepairCompletionV1, LedgerError> {
        load_repair_completion(&self.connection, completion_id)
    }
}

struct AttemptPredecessorColumns {
    kind: &'static str,
    prior_attempt_id: Option<String>,
    prior_outcome_id: Option<String>,
    control_id: Option<String>,
    closure_id: Option<String>,
    repair_activation_id: Option<String>,
    repair_task_done_proof_id: Option<String>,
    repair_integration_receipt_id: Option<String>,
}

#[allow(clippy::too_many_lines)] // The closed predecessor union deliberately keeps all continuation classes in one auditable selector.
fn derive_attempt_predecessor(
    connection: &Connection,
    prior: Option<&PersistedCurrentFinalVerificationAttemptV1>,
    task_set: &CompleteTaskDoneSetV1,
    criterion_set: &CompleteCriterionEvidenceSetV1,
    graph: &TaskGraphV2,
    admitted_at_unix_ms: u64,
) -> Result<
    (
        FinalVerificationAttemptPredecessorV1,
        AttemptPredecessorColumns,
    ),
    LedgerError,
> {
    let Some(prior) = prior else {
        let graph_tasks = graph
            .tasks
            .iter()
            .map(|task| (task.task_id.as_str(), task))
            .collect::<BTreeMap<_, _>>();
        if task_set.members.iter().any(|member| {
            graph_tasks
                .get(member.task_id.as_str())
                .is_some_and(|task| {
                    matches!(
                        task.purpose,
                        TaskPurposeV2::FinalVerificationRepairSlot { .. }
                    )
                })
        }) {
            return Err(mismatch(
                "current final-verification predecessor",
                "the initial attempt cannot consume a dormant final-verification repair slot",
            ));
        }
        return Ok((
            FinalVerificationAttemptPredecessorV1::Initial,
            AttemptPredecessorColumns {
                kind: "Initial",
                prior_attempt_id: None,
                prior_outcome_id: None,
                control_id: None,
                closure_id: None,
                repair_activation_id: None,
                repair_task_done_proof_id: None,
                repair_integration_receipt_id: None,
            },
        ));
    };
    let outcome = prior.outcome.as_ref().ok_or_else(|| {
        mismatch(
            "current final-verification predecessor",
            "the immediately prior attempt has no exact typed terminal outcome",
        )
    })?;
    match &outcome.outcome {
        CurrentFinalVerificationOutcomeKindV1::FailedBeforeEffect => {
            require_same_snapshot_sets(prior, task_set, criterion_set)?;
            Ok((
                FinalVerificationAttemptPredecessorV1::SameSnapshotAfterFailedBeforeEffect {
                    prior_attempt_id: prior.authority.attempt_id.clone(),
                    closure_id: outcome.closure_id.clone(),
                },
                AttemptPredecessorColumns {
                    kind: "SameSnapshotAfterFailedBeforeEffect",
                    prior_attempt_id: Some(prior.authority.attempt_id.clone()),
                    prior_outcome_id: Some(outcome.outcome_id.clone()),
                    control_id: None,
                    closure_id: Some(outcome.closure_id.clone()),
                    repair_activation_id: None,
                    repair_task_done_proof_id: None,
                    repair_integration_receipt_id: None,
                },
            ))
        }
        CurrentFinalVerificationOutcomeKindV1::ControlInterruptedBeforeEffect { control_id } => {
            require_same_snapshot_sets(prior, task_set, criterion_set)?;
            Ok((
                FinalVerificationAttemptPredecessorV1::SameSnapshotAfterControlInterruption {
                    prior_attempt_id: prior.authority.attempt_id.clone(),
                    control_id: control_id.clone(),
                    closure_id: outcome.closure_id.clone(),
                },
                AttemptPredecessorColumns {
                    kind: "SameSnapshotAfterControlInterruption",
                    prior_attempt_id: Some(prior.authority.attempt_id.clone()),
                    prior_outcome_id: Some(outcome.outcome_id.clone()),
                    control_id: Some(control_id.clone()),
                    closure_id: Some(outcome.closure_id.clone()),
                    repair_activation_id: None,
                    repair_task_done_proof_id: None,
                    repair_integration_receipt_id: None,
                },
            ))
        }
        known if known.is_known_after_effect_failure() => {
            let completion =
                load_repair_completion_for_failed_attempt(connection, &prior.authority.attempt_id)?
                    .ok_or_else(|| {
                        mismatch(
                            "current final-verification predecessor",
                            "known after-effect failure has no completed activated repair slot",
                        )
                    })?;
            let task_digest = task_set.canonical_digest()?;
            let criterion_digest = criterion_set.canonical_digest()?;
            if completion.result_snapshot != task_set.snapshot_digest
                || completion.result_snapshot != criterion_set.snapshot_digest
                || completion.complete_task_done_set_digest != task_digest
                || completion.complete_criterion_evidence_set_digest != criterion_digest
                || completion.completed_at_unix_ms > admitted_at_unix_ms
            {
                return Err(mismatch(
                    "current final-verification predecessor",
                    "follow-up sets differ from the exact changed-snapshot repair completion",
                ));
            }
            Ok((
                FinalVerificationAttemptPredecessorV1::ChangedSnapshotAfterRepair {
                    prior_failure_id: outcome.outcome_id.clone(),
                    repair_admission_id: completion.activation_id.clone(),
                    repair_task_done_proof_id: completion.repair_task_done_proof_id.clone(),
                    integration_receipt_id: completion.integration_receipt_id.clone(),
                },
                AttemptPredecessorColumns {
                    kind: "ChangedSnapshotAfterRepair",
                    prior_attempt_id: Some(prior.authority.attempt_id.clone()),
                    prior_outcome_id: Some(outcome.outcome_id.clone()),
                    control_id: None,
                    closure_id: Some(outcome.closure_id.clone()),
                    repair_activation_id: Some(completion.activation_id.clone()),
                    repair_task_done_proof_id: Some(completion.repair_task_done_proof_id.clone()),
                    repair_integration_receipt_id: Some(completion.integration_receipt_id.clone()),
                },
            ))
        }
        _ => Err(mismatch(
            "current final-verification predecessor",
            "prior outcome grants no retry or repair continuation authority",
        )),
    }
}

fn require_same_snapshot_sets(
    prior: &PersistedCurrentFinalVerificationAttemptV1,
    task_set: &CompleteTaskDoneSetV1,
    criterion_set: &CompleteCriterionEvidenceSetV1,
) -> Result<(), LedgerError> {
    if prior.authority.input_snapshot != task_set.snapshot_digest
        || prior.authority.input_snapshot != criterion_set.snapshot_digest
        || prior.authority.complete_task_done_set_digest != task_set.canonical_digest()?
        || prior.authority.complete_criterion_evidence_set_digest
            != criterion_set.canonical_digest()?
    {
        return Err(mismatch(
            "current final-verification predecessor",
            "same-snapshot continuation must preserve both complete evidence sets exactly",
        ));
    }
    Ok(())
}

fn persist_task_done_set(
    transaction: &Transaction<'_>,
    sprint: &SprintSpecV2,
    graph: &TaskGraphV2,
    set: &CompleteTaskDoneSetV1,
) -> Result<Digest, LedgerError> {
    #[cfg(test)]
    if test_source_fixture_seeding_enabled() {
        super::current_task_done_source_v32::test_seed_sources_for_set(
            transaction,
            sprint,
            graph,
            set,
        )?;
    }
    persist_task_done_set_from_current_sources(transaction, sprint, graph, set)
}

/// Persists a complete set only from current source receipts already present.
///
/// Production builds reach exactly this body: the fixture source seeder above
/// is removed by `cfg(test)`. Keeping the authority-bearing body separate also
/// lets tests prove that schema v32 remains dormant without genuine lifecycle
/// sources.
fn persist_task_done_set_from_current_sources(
    transaction: &Transaction<'_>,
    sprint: &SprintSpecV2,
    graph: &TaskGraphV2,
    set: &CompleteTaskDoneSetV1,
) -> Result<Digest, LedgerError> {
    set.validate_for(sprint, graph)?;
    let digest = set.canonical_digest()?;
    if let Some(existing) = load_task_done_set_optional(transaction, digest.as_str())? {
        if existing == *set {
            return Ok(digest);
        }
        return Err(mismatch(
            "complete TaskDone set v32",
            "set digest already names different canonical bytes",
        ));
    }
    let bytes = set.canonical_bytes()?;
    transaction.execute(
        "INSERT INTO current_task_done_sets_v32 (
            set_digest, sprint_id, snapshot_digest, member_count,
            recorded_at_unix_ms, set_json
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        params![
            digest.as_str(),
            set.sprint_id,
            set.snapshot_digest.as_str(),
            i64::try_from(set.members.len())
                .map_err(|_| LedgerError::IntegerOutOfRange("TaskDone set member count"))?,
            super::sqlite_integer("TaskDone set recorded_at", set.recorded_at_unix_ms)?,
            bytes,
        ],
    )?;
    for member in &set.members {
        transaction.execute(
            "INSERT INTO current_task_done_members_v32 (
                set_digest, sprint_id, member_ordinal, task_id, task_done_proof_id,
                integration_receipt_id, integration_kind,
                empty_change_set_id, input_snapshot, result_snapshot
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
            params![
                digest.as_str(),
                set.sprint_id,
                i64::from(member.source_ordinal),
                member.task_id,
                member.task_done_proof_id,
                member.integration_receipt_id,
                member.integration_evidence.sql_kind(),
                member.integration_evidence.empty_change_set_id(),
                member.input_snapshot.as_str(),
                member.result_snapshot.as_str(),
            ],
        )?;
    }
    transaction.execute(
        "INSERT INTO current_task_done_set_seals_v32 (
            set_digest, sprint_id, snapshot_digest, sealed_at_unix_ms
         ) VALUES (?1, ?2, ?3, ?4)",
        params![
            digest.as_str(),
            set.sprint_id,
            set.snapshot_digest.as_str(),
            super::sqlite_integer("TaskDone set sealed_at", set.recorded_at_unix_ms)?,
        ],
    )?;
    if load_task_done_set_optional(transaction, digest.as_str())?.as_ref() != Some(set) {
        return Err(corrupt(
            "complete TaskDone set v32",
            "transactional readback differs from canonical set",
        ));
    }
    Ok(digest)
}

fn load_task_done_set_optional(
    connection: &Connection,
    digest: &str,
) -> Result<Option<CompleteTaskDoneSetV1>, LedgerError> {
    let stored = connection
        .query_row(
            "SELECT sprint_id, snapshot_digest, member_count,
                    recorded_at_unix_ms, set_json,
                    EXISTS(SELECT 1 FROM current_task_done_set_seals_v32 seal
                           WHERE seal.set_digest = current_task_done_sets_v32.set_digest)
             FROM current_task_done_sets_v32 WHERE set_digest = ?1",
            [digest],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, Vec<u8>>(4)?,
                    row.get::<_, bool>(5)?,
                ))
            },
        )
        .optional()?;
    let Some(stored) = stored else {
        return Ok(None);
    };
    let set: CompleteTaskDoneSetV1 = decode_ledger("complete TaskDone set v32", &stored.4)?;
    let canonical = set.canonical_bytes()?;
    if canonical != stored.4
        || set.canonical_digest()?.as_str() != digest
        || set.sprint_id != stored.0
        || set.snapshot_digest.as_str() != stored.1
        || i64::try_from(set.members.len()).ok() != Some(stored.2)
        || set.recorded_at_unix_ms != super::unsigned_integer("TaskDone set recorded_at", stored.3)?
        || !stored.5
    {
        return Err(corrupt(
            "complete TaskDone set v32",
            "stored set columns, seal, digest, or canonical bytes differ",
        ));
    }
    let mut statement = connection.prepare(
        "SELECT sprint_id, member_ordinal, task_id, task_done_proof_id,
                integration_receipt_id, integration_kind,
                empty_change_set_id, input_snapshot, result_snapshot
         FROM current_task_done_members_v32 WHERE set_digest = ?1
         ORDER BY member_ordinal",
    )?;
    let rows = statement
        .query_map([digest], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, i64>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, String>(4)?,
                row.get::<_, String>(5)?,
                row.get::<_, Option<String>>(6)?,
                row.get::<_, String>(7)?,
                row.get::<_, String>(8)?,
            ))
        })?
        .collect::<Result<Vec<_>, _>>()?;
    for (member, row) in set.members.iter().zip(&rows) {
        let source = super::current_task_done_source_v32::load_current_task_done_source_from(
            connection,
            &member.task_done_proof_id,
        )?;
        if row.0 != set.sprint_id
            || row.1 != i64::from(member.source_ordinal)
            || row.2 != member.task_id
            || row.3 != member.task_done_proof_id
            || row.4 != member.integration_receipt_id
            || row.5 != member.integration_evidence.sql_kind()
            || row.6.as_deref() != member.integration_evidence.empty_change_set_id()
            || row.7 != member.input_snapshot.as_str()
            || row.8 != member.result_snapshot.as_str()
            || source.sprint_id != set.sprint_id
            || source.task_id != member.task_id
            || source.integration.integration_receipt_id() != member.integration_receipt_id
            || source.integration.sql_kind() != member.integration_evidence.sql_kind()
            || source.integration.empty_change_set_id()
                != member.integration_evidence.empty_change_set_id()
            || source.input_snapshot != member.input_snapshot
            || source.result_snapshot != member.result_snapshot
            || source.derived_at_unix_ms > set.recorded_at_unix_ms
        {
            return Err(corrupt(
                "complete TaskDone set v32",
                "member projection differs from canonical set bytes",
            ));
        }
    }
    if rows.len() != set.members.len() {
        return Err(corrupt(
            "complete TaskDone set v32",
            "member projection count differs from canonical set bytes",
        ));
    }
    Ok(Some(set))
}

fn persist_criterion_evidence_set(
    transaction: &Transaction<'_>,
    sprint: &SprintSpecV2,
    set: &CompleteCriterionEvidenceSetV1,
) -> Result<Digest, LedgerError> {
    #[cfg(test)]
    if test_source_fixture_seeding_enabled() {
        let receipts =
            super::current_criterion_evidence_v32::test_seed_criterion_sources_for_snapshot_v32(
                transaction,
                sprint,
                &set.snapshot_digest,
                set.recorded_at_unix_ms,
            )?;
        if receipts.len() != set.members.len()
            || receipts
                .iter()
                .zip(&set.members)
                .any(|(receipt, member)| receipt.receipt_id() != member.evidence_receipt_id)
        {
            return Err(mismatch(
                "test complete criterion-evidence set v32",
                "member identities differ from exact seeded criterion sources",
            ));
        }
    }
    persist_criterion_evidence_set_from_current_sources(transaction, sprint, set)
}

/// Persists a complete set only from current criterion receipts already present.
///
/// Production builds reach exactly this body; test-only source minting is
/// compiled out before it is called.
fn persist_criterion_evidence_set_from_current_sources(
    transaction: &Transaction<'_>,
    sprint: &SprintSpecV2,
    set: &CompleteCriterionEvidenceSetV1,
) -> Result<Digest, LedgerError> {
    set.validate_for(sprint)?;
    let digest = set.canonical_digest()?;
    if let Some(existing) = load_criterion_evidence_set_optional(transaction, digest.as_str())? {
        if existing == *set {
            return Ok(digest);
        }
        return Err(mismatch(
            "complete criterion-evidence set v32",
            "set digest already names different canonical bytes",
        ));
    }
    transaction.execute(
        "INSERT INTO current_criterion_evidence_sets_v32 (
            set_digest, sprint_id, snapshot_digest, member_count,
            recorded_at_unix_ms, set_json
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        params![
            digest.as_str(),
            set.sprint_id,
            set.snapshot_digest.as_str(),
            i64::try_from(set.members.len()).map_err(|_| {
                LedgerError::IntegerOutOfRange("criterion-evidence set member count")
            })?,
            super::sqlite_integer(
                "criterion-evidence set recorded_at",
                set.recorded_at_unix_ms,
            )?,
            set.canonical_bytes()?,
        ],
    )?;
    for member in &set.members {
        let evidence_kind = match member.evidence_kind {
            CurrentCriterionEvidenceKindV1::Verified => "Verified",
            CurrentCriterionEvidenceKindV1::AcceptedByYou => "AcceptedByYou",
        };
        transaction.execute(
            "INSERT INTO current_criterion_evidence_members_v32 (
                set_digest, sprint_id, member_ordinal, criterion_id, evidence_receipt_id,
                evidence_kind, snapshot_digest
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                digest.as_str(),
                set.sprint_id,
                i64::from(member.criterion_ordinal),
                member.criterion_id,
                member.evidence_receipt_id,
                evidence_kind,
                member.snapshot_digest.as_str(),
            ],
        )?;
    }
    transaction.execute(
        "INSERT INTO current_criterion_evidence_set_seals_v32 (
            set_digest, sprint_id, snapshot_digest, sealed_at_unix_ms
         ) VALUES (?1, ?2, ?3, ?4)",
        params![
            digest.as_str(),
            set.sprint_id,
            set.snapshot_digest.as_str(),
            super::sqlite_integer("criterion-evidence set sealed_at", set.recorded_at_unix_ms,)?,
        ],
    )?;
    if load_criterion_evidence_set_optional(transaction, digest.as_str())?.as_ref() != Some(set) {
        return Err(corrupt(
            "complete criterion-evidence set v32",
            "transactional readback differs from canonical set",
        ));
    }
    Ok(digest)
}

fn load_criterion_evidence_set_optional(
    connection: &Connection,
    digest: &str,
) -> Result<Option<CompleteCriterionEvidenceSetV1>, LedgerError> {
    let stored = connection
        .query_row(
            "SELECT sprint_id, snapshot_digest, member_count,
                    recorded_at_unix_ms, set_json,
                    EXISTS(SELECT 1 FROM current_criterion_evidence_set_seals_v32 seal
                           WHERE seal.set_digest = current_criterion_evidence_sets_v32.set_digest)
             FROM current_criterion_evidence_sets_v32 WHERE set_digest = ?1",
            [digest],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, Vec<u8>>(4)?,
                    row.get::<_, bool>(5)?,
                ))
            },
        )
        .optional()?;
    let Some(stored) = stored else {
        return Ok(None);
    };
    let set: CompleteCriterionEvidenceSetV1 =
        decode_ledger("complete criterion-evidence set v32", &stored.4)?;
    if set.canonical_bytes()? != stored.4
        || set.canonical_digest()?.as_str() != digest
        || set.sprint_id != stored.0
        || set.snapshot_digest.as_str() != stored.1
        || i64::try_from(set.members.len()).ok() != Some(stored.2)
        || set.recorded_at_unix_ms
            != super::unsigned_integer("criterion-evidence set recorded_at", stored.3)?
        || !stored.5
    {
        return Err(corrupt(
            "complete criterion-evidence set v32",
            "stored set columns, seal, digest, or canonical bytes differ",
        ));
    }
    let mut statement = connection.prepare(
        "SELECT sprint_id, member_ordinal, criterion_id, evidence_receipt_id,
                evidence_kind, snapshot_digest
         FROM current_criterion_evidence_members_v32 WHERE set_digest = ?1
         ORDER BY member_ordinal",
    )?;
    let rows = statement
        .query_map([digest], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, i64>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, String>(4)?,
                row.get::<_, String>(5)?,
            ))
        })?
        .collect::<Result<Vec<_>, _>>()?;
    for (member, row) in set.members.iter().zip(&rows) {
        let expected_kind = match member.evidence_kind {
            CurrentCriterionEvidenceKindV1::Verified => "Verified",
            CurrentCriterionEvidenceKindV1::AcceptedByYou => "AcceptedByYou",
        };
        let source = super::current_criterion_evidence_v32::load_current_criterion_receipt_from(
            connection,
            &member.evidence_receipt_id,
        )?;
        if row.0 != set.sprint_id
            || row.1 != i64::from(member.criterion_ordinal)
            || row.2 != member.criterion_id
            || row.3 != member.evidence_receipt_id
            || row.4 != expected_kind
            || row.5 != member.snapshot_digest.as_str()
            || source.sprint_id() != set.sprint_id
            || source.criterion_id() != member.criterion_id
            || source.snapshot_digest() != &member.snapshot_digest
            || source.recorded_at() > set.recorded_at_unix_ms
            || !matches!(
                (&source, member.evidence_kind),
                (
                    crate::CriterionEvidenceReceiptV2::Verified { .. },
                    CurrentCriterionEvidenceKindV1::Verified
                ) | (
                    crate::CriterionEvidenceReceiptV2::AcceptedByYou { .. },
                    CurrentCriterionEvidenceKindV1::AcceptedByYou
                )
            )
        {
            return Err(corrupt(
                "complete criterion-evidence set v32",
                "member projection differs from canonical set bytes",
            ));
        }
    }
    if rows.len() != set.members.len() {
        return Err(corrupt(
            "complete criterion-evidence set v32",
            "member projection count differs from canonical set bytes",
        ));
    }
    Ok(Some(set))
}

fn ensure_no_current_terminal(connection: &Connection, sprint_id: &str) -> Result<(), LedgerError> {
    let terminal = connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM current_sprint_terminal_outcomes_v32
                       WHERE sprint_id = ?1)",
        [sprint_id],
        |row| row.get::<_, bool>(0),
    )?;
    if terminal {
        Err(LedgerError::SprintAlreadyTerminal(sprint_id.to_owned()))
    } else {
        Ok(())
    }
}

fn mint_identity(domain: &[u8], seed: &[u8]) -> String {
    domain_digest(domain, seed).to_string()
}

struct TransactionalCurrentFinalVerificationAttemptAdmissionV32 {
    persisted: PersistedCurrentFinalVerificationAttemptV1,
    inserted: bool,
}

#[allow(clippy::too_many_lines)] // One transaction derives and crosses every attempt-authority dimension.
fn admit_current_final_verification_attempt_in_transaction_v32(
    transaction: &Transaction<'_>,
    request: &CurrentFinalVerificationAdmissionRequestV1,
    request_bytes: &[u8],
    request_digest: &Digest,
) -> Result<TransactionalCurrentFinalVerificationAttemptAdmissionV32, LedgerError> {
    let current = load_current_sprint_authority(transaction, &request.sprint_id)?;
    request.validate_for(&current.spec, &current.graph)?;
    if let Some((attempt_id, stored_request_digest, stored_request_bytes)) = transaction
        .query_row(
            "SELECT attempt_id, request_digest, request_json
             FROM current_final_verification_attempts_v32 WHERE request_id = ?1",
            [request.request_id.as_str()],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, Vec<u8>>(2)?,
                ))
            },
        )
        .optional()?
    {
        if stored_request_digest != request_digest.as_str() || stored_request_bytes != request_bytes
        {
            return Err(mismatch(
                "current final-verification admission request",
                "idempotency identity was replayed with different canonical bytes",
            ));
        }
        return Ok(TransactionalCurrentFinalVerificationAttemptAdmissionV32 {
            persisted: load_current_attempt(transaction, &attempt_id)?,
            inserted: false,
        });
    }
    ensure_no_current_terminal(transaction, &request.sprint_id)?;
    let task_set_digest = persist_task_done_set(
        transaction,
        &current.spec,
        &current.graph,
        &request.task_done_set,
    )?;
    let criterion_set_digest = persist_criterion_evidence_set(
        transaction,
        &current.spec,
        &request.criterion_evidence_set,
    )?;
    let prior = load_latest_current_attempt(transaction, &request.sprint_id)?;
    let attempt_ordinal = prior.as_ref().map_or(1_u8, |prior| {
        prior.authority.attempt_ordinal.saturating_add(1)
    });
    if attempt_ordinal > current.spec.budget.max_final_verification_attempts {
        return Err(mismatch(
            "current final-verification attempt",
            "the immutable sprint final-verification attempt cap is exhausted",
        ));
    }
    let (predecessor, predecessor_columns) = derive_attempt_predecessor(
        transaction,
        prior.as_ref(),
        &request.task_done_set,
        &request.criterion_evidence_set,
        &current.graph,
        request.admitted_at_unix_ms,
    )?;
    let attempt_id = mint_identity(ATTEMPT_ID_DOMAIN, request_digest.as_str().as_bytes());
    let final_verification_admission_id =
        mint_identity(ADMISSION_ID_DOMAIN, request_digest.as_str().as_bytes());
    let admission_event_id = mint_identity(
        ADMISSION_EVENT_ID_DOMAIN,
        request_digest.as_str().as_bytes(),
    );
    let provenance = FinalVerificationAttemptProvenanceV1 {
        coordinator_instance_id: request.coordinator_instance_id.clone(),
        admission_event_id,
        admission_event_sequence: u64::from(attempt_ordinal),
        admitted_at_unix_ms: request.admitted_at_unix_ms,
    };
    let expected = FinalVerificationAttemptExpectedInputsV1 {
        attempt_id: attempt_id.clone(),
        attempt_ordinal,
        final_verification_admission_id: final_verification_admission_id.clone(),
        input_snapshot: request.task_done_set.snapshot_digest.clone(),
        final_verification_check: request.final_verification_check.clone(),
        execution_policy_digest: request.execution_policy_digest.clone(),
        complete_task_done_set_digest: task_set_digest.clone(),
        complete_criterion_evidence_set_digest: criterion_set_digest.clone(),
        provenance: provenance.clone(),
        predecessor: predecessor.clone(),
    };
    let authority = FinalVerificationAttemptAuthorityV1 {
        authority_version: crate::FINAL_VERIFICATION_ATTEMPT_AUTHORITY_VERSION_V1,
        attempt_id: attempt_id.clone(),
        sprint_id: request.sprint_id.clone(),
        attempt_ordinal,
        max_final_verification_attempts: current.spec.budget.max_final_verification_attempts,
        final_verification_admission_id,
        input_snapshot: request.task_done_set.snapshot_digest.clone(),
        complete_task_done_set_digest: task_set_digest,
        complete_criterion_evidence_set_digest: criterion_set_digest,
        final_verification_check: request.final_verification_check.clone(),
        execution_policy_digest: request.execution_policy_digest.clone(),
        provenance,
        predecessor,
    };
    authority.validate_for(&current.spec, &current.graph, &expected)?;
    if let Some(prior) = &prior {
        authority.validate_successor_of(&prior.authority)?;
    }
    let authority_bytes = authority.canonical_bytes()?;
    let authority_digest = authority.canonical_digest()?;
    transaction.execute(
        "INSERT INTO current_final_verification_attempts_v32 (
            attempt_id, request_id, request_digest, request_json, sprint_id,
            attempt_ordinal, max_final_verification_attempts,
            final_verification_admission_id, input_snapshot,
            complete_task_done_set_digest,
            complete_criterion_evidence_set_digest, predecessor_kind,
            predecessor_attempt_id, predecessor_outcome_id,
            predecessor_control_id, predecessor_closure_id,
            repair_activation_id, repair_task_done_proof_id,
            repair_integration_receipt_id, authority_digest,
            admitted_at_unix_ms, authority_json
         ) VALUES (
            ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10,
            ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18, ?19, ?20, ?21, ?22
         )",
        params![
            authority.attempt_id,
            request.request_id,
            request_digest.as_str(),
            request_bytes,
            authority.sprint_id,
            i64::from(authority.attempt_ordinal),
            i64::from(authority.max_final_verification_attempts),
            authority.final_verification_admission_id,
            authority.input_snapshot.as_str(),
            authority.complete_task_done_set_digest.as_str(),
            authority.complete_criterion_evidence_set_digest.as_str(),
            predecessor_columns.kind,
            predecessor_columns.prior_attempt_id,
            predecessor_columns.prior_outcome_id,
            predecessor_columns.control_id,
            predecessor_columns.closure_id,
            predecessor_columns.repair_activation_id,
            predecessor_columns.repair_task_done_proof_id,
            predecessor_columns.repair_integration_receipt_id,
            authority_digest.as_str(),
            super::sqlite_integer(
                "final verification admitted_at",
                request.admitted_at_unix_ms
            )?,
            authority_bytes,
        ],
    )?;
    let persisted = load_current_attempt(transaction, &attempt_id)?;
    if persisted.request_id != request.request_id || persisted.authority != authority {
        return Err(corrupt(
            "current final-verification attempt",
            "transactional readback differs from derived authority",
        ));
    }
    Ok(TransactionalCurrentFinalVerificationAttemptAdmissionV32 {
        persisted,
        inserted: true,
    })
}

fn next_operational_event_sequence_v34(
    connection: &Connection,
    sprint_id: &str,
) -> Result<u64, LedgerError> {
    let next = connection.query_row(
        "SELECT COALESCE(MAX(event_sequence) + 1, 1)
         FROM current_final_verification_events_v34 WHERE sprint_id = ?1",
        [sprint_id],
        |row| row.get::<_, i64>(0),
    )?;
    super::unsigned_integer("current final-verification event sequence", next)
}

fn insert_operational_event_v34(
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
                event.event_sequence
            )?,
            event.event_id,
            i64::from(event.event_version),
            event.event_kind.sql_kind(),
            event.attempt_id,
            event.request_id,
            event.request_digest.as_str(),
            super::sqlite_integer(
                "current final-verification event occurred_at",
                event.occurred_at_unix_ms
            )?,
            event.event_digest.as_str(),
            event.canonical_bytes()?,
        ],
    )?;
    Ok(())
}

fn insert_operational_attempt_v34(
    transaction: &Transaction<'_>,
    operational: &OperationalCurrentFinalVerificationAttemptV1,
) -> Result<(), LedgerError> {
    transaction.execute(
        "INSERT INTO current_final_verification_operational_attempts_v34 (
            attempt_id, operational_version, sprint_id, attempt_ordinal,
            final_verification_admission_id, attempt_authority_digest,
            diagnostic_v32_admission_event_id,
            diagnostic_v32_admission_event_sequence, request_id,
            request_digest, admission_event_id, admission_event_sequence,
            sprint_spec_digest, task_graph_id, task_graph_digest,
            task_graph_payload_digest, repair_slot_reserve_digest,
            input_snapshot, complete_task_done_set_digest,
            complete_criterion_evidence_set_digest, workspace_grant_hash,
            verification_command_digest, execution_policy_digest,
            coordinator_instance_id, admitted_at_unix_ms,
            operational_attempt_digest, operational_json
         ) VALUES (
            ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10,
            ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18, ?19, ?20,
            ?21, ?22, ?23, ?24, ?25, ?26, ?27
         )",
        params![
            operational.attempt_id,
            i64::from(operational.operational_version),
            operational.sprint_id,
            i64::from(operational.attempt_ordinal),
            operational.final_verification_admission_id,
            operational.attempt_authority_digest.as_str(),
            operational.diagnostic_v32_admission_event_id,
            super::sqlite_integer(
                "diagnostic current final-verification event sequence",
                operational.diagnostic_v32_admission_event_sequence
            )?,
            operational.request_id,
            operational.request_digest.as_str(),
            operational.admission_event_id,
            super::sqlite_integer(
                "current final-verification admission event sequence",
                operational.admission_event_sequence
            )?,
            operational.sprint_spec_digest.as_str(),
            operational.task_graph_id,
            operational.task_graph_digest.as_str(),
            operational.task_graph_payload_digest.as_str(),
            operational.repair_slot_reserve_digest.as_str(),
            operational.input_snapshot.as_str(),
            operational.complete_task_done_set_digest.as_str(),
            operational.complete_criterion_evidence_set_digest.as_str(),
            operational.workspace_grant_hash.as_str(),
            operational.verification_command_digest.as_str(),
            operational.execution_policy_digest.as_str(),
            operational.coordinator_instance_id,
            super::sqlite_integer(
                "current final-verification operational admitted_at",
                operational.admitted_at_unix_ms
            )?,
            operational.operational_attempt_digest.as_str(),
            operational.canonical_bytes()?,
        ],
    )?;
    Ok(())
}

fn load_operational_event_v34(
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
            entity: "current final-verification operational event v34",
            id: event_id.to_owned(),
        })?;
    let event: CurrentFinalVerificationAuthorityEventV1 =
        decode_exact("current final-verification operational event", &bytes)
            .map_err(|detail| corrupt("current final-verification operational event", detail))?;
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
                event.event_sequence
            )?,
            event.event_id,
            i64::from(event.event_version),
            event.event_kind.sql_kind(),
            event.attempt_id,
            event.request_id,
            event.request_digest.as_str(),
            super::sqlite_integer(
                "current final-verification event occurred_at",
                event.occurred_at_unix_ms
            )?,
            event.event_digest.as_str(),
            bytes,
        ],
        |row| row.get::<_, bool>(0),
    )?;
    if !projection_matches {
        return Err(corrupt(
            "current final-verification operational event",
            "stored projection differs from exact canonical event bytes",
        ));
    }
    Ok(event)
}

fn load_operational_attempt_optional_v34(
    connection: &Connection,
    attempt_id: &str,
) -> Result<Option<PersistedOperationalCurrentFinalVerificationAttemptV1>, LedgerError> {
    let exists = connection.query_row(
        "SELECT EXISTS(
            SELECT 1 FROM current_final_verification_operational_attempts_v34
            WHERE attempt_id = ?1
         )",
        [attempt_id],
        |row| row.get::<_, bool>(0),
    )?;
    exists
        .then(|| load_operational_attempt_v34(connection, attempt_id))
        .transpose()
}

#[allow(clippy::too_many_lines)] // Exact readback crosses every scalar and canonical parent.
fn load_operational_attempt_v34(
    connection: &Connection,
    attempt_id: &str,
) -> Result<PersistedOperationalCurrentFinalVerificationAttemptV1, LedgerError> {
    let bytes = connection
        .query_row(
            "SELECT operational_json
             FROM current_final_verification_operational_attempts_v34
             WHERE attempt_id = ?1",
            [attempt_id],
            |row| row.get::<_, Vec<u8>>(0),
        )
        .optional()?
        .ok_or_else(|| LedgerError::ArtifactNotFound {
            entity: "current final-verification operational attempt v34",
            id: attempt_id.to_owned(),
        })?;
    let operational: OperationalCurrentFinalVerificationAttemptV1 =
        decode_exact("current final-verification operational attempt", &bytes)
            .map_err(|detail| corrupt("current final-verification operational attempt", detail))?;
    operational.validate_integrity()?;
    let projection_matches = connection.query_row(
        "SELECT EXISTS(
            SELECT 1 FROM current_final_verification_operational_attempts_v34
            WHERE attempt_id = ?1 AND operational_version = ?2
              AND sprint_id = ?3 AND attempt_ordinal = ?4
              AND final_verification_admission_id = ?5
              AND attempt_authority_digest = ?6
              AND diagnostic_v32_admission_event_id = ?7
              AND diagnostic_v32_admission_event_sequence = ?8
              AND request_id = ?9 AND request_digest = ?10
              AND admission_event_id = ?11 AND admission_event_sequence = ?12
              AND sprint_spec_digest = ?13 AND task_graph_id = ?14
              AND task_graph_digest = ?15 AND task_graph_payload_digest = ?16
              AND repair_slot_reserve_digest = ?17 AND input_snapshot = ?18
              AND complete_task_done_set_digest = ?19
              AND complete_criterion_evidence_set_digest = ?20
              AND workspace_grant_hash = ?21 AND verification_command_digest = ?22
              AND execution_policy_digest = ?23 AND coordinator_instance_id = ?24
              AND admitted_at_unix_ms = ?25 AND operational_attempt_digest = ?26
              AND operational_json = ?27
         )",
        params![
            operational.attempt_id,
            i64::from(operational.operational_version),
            operational.sprint_id,
            i64::from(operational.attempt_ordinal),
            operational.final_verification_admission_id,
            operational.attempt_authority_digest.as_str(),
            operational.diagnostic_v32_admission_event_id,
            super::sqlite_integer(
                "diagnostic current final-verification event sequence",
                operational.diagnostic_v32_admission_event_sequence
            )?,
            operational.request_id,
            operational.request_digest.as_str(),
            operational.admission_event_id,
            super::sqlite_integer(
                "current final-verification admission event sequence",
                operational.admission_event_sequence
            )?,
            operational.sprint_spec_digest.as_str(),
            operational.task_graph_id,
            operational.task_graph_digest.as_str(),
            operational.task_graph_payload_digest.as_str(),
            operational.repair_slot_reserve_digest.as_str(),
            operational.input_snapshot.as_str(),
            operational.complete_task_done_set_digest.as_str(),
            operational.complete_criterion_evidence_set_digest.as_str(),
            operational.workspace_grant_hash.as_str(),
            operational.verification_command_digest.as_str(),
            operational.execution_policy_digest.as_str(),
            operational.coordinator_instance_id,
            super::sqlite_integer(
                "current final-verification operational admitted_at",
                operational.admitted_at_unix_ms
            )?,
            operational.operational_attempt_digest.as_str(),
            bytes,
        ],
        |row| row.get::<_, bool>(0),
    )?;
    if !projection_matches {
        return Err(corrupt(
            "current final-verification operational attempt",
            "stored projection differs from exact canonical operational bytes",
        ));
    }
    let attempt = load_current_attempt(connection, attempt_id)?;
    let (request_digest, request_bytes) = connection.query_row(
        "SELECT request_digest, request_json
         FROM current_final_verification_attempts_v32 WHERE attempt_id = ?1",
        [attempt_id],
        |row| Ok((row.get::<_, String>(0)?, row.get::<_, Vec<u8>>(1)?)),
    )?;
    let request: CurrentFinalVerificationAdmissionRequestV1 = decode_exact(
        "current final-verification admission request",
        &request_bytes,
    )
    .map_err(|detail| corrupt("current final-verification admission request", detail))?;
    if request.canonical_digest()?.as_str() != request_digest {
        return Err(corrupt(
            "current final-verification admission request",
            "stored digest differs from exact canonical request bytes",
        ));
    }
    let current = load_current_sprint_authority(connection, &operational.sprint_id)?;
    let event = load_operational_event_v34(connection, &operational.admission_event_id)?;
    operational.validate_for(&request, &current, &attempt, &event)?;
    Ok(PersistedOperationalCurrentFinalVerificationAttemptV1 {
        attempt: OperationalCurrentFinalVerificationParentV1::from(&attempt),
        admission_event: event,
        operational_attempt: operational,
    })
}

fn load_latest_current_attempt(
    connection: &Connection,
    sprint_id: &str,
) -> Result<Option<PersistedCurrentFinalVerificationAttemptV1>, LedgerError> {
    let attempt_id = connection
        .query_row(
            "SELECT attempt_id FROM current_final_verification_attempts_v32
             WHERE sprint_id = ?1 ORDER BY attempt_ordinal DESC LIMIT 1",
            [sprint_id],
            |row| row.get::<_, String>(0),
        )
        .optional()?;
    attempt_id
        .map(|attempt_id| load_current_attempt(connection, &attempt_id))
        .transpose()
}

#[allow(clippy::too_many_lines)] // Exact attempt readback crosses every projection, set, predecessor, and deterministic identity.
fn load_current_attempt(
    connection: &Connection,
    attempt_id: &str,
) -> Result<PersistedCurrentFinalVerificationAttemptV1, LedgerError> {
    let stored = connection
        .query_row(
            "SELECT request_id, sprint_id, attempt_ordinal,
                    max_final_verification_attempts,
                    final_verification_admission_id, input_snapshot,
                    complete_task_done_set_digest,
                    complete_criterion_evidence_set_digest,
                    predecessor_kind, predecessor_attempt_id,
                    predecessor_outcome_id, predecessor_control_id,
                    predecessor_closure_id, repair_activation_id,
                    repair_task_done_proof_id, repair_integration_receipt_id,
                    authority_digest, admitted_at_unix_ms, authority_json,
                    request_digest, request_json
             FROM current_final_verification_attempts_v32 WHERE attempt_id = ?1",
            [attempt_id],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, String>(5)?,
                    row.get::<_, String>(6)?,
                    row.get::<_, String>(7)?,
                    row.get::<_, String>(8)?,
                    row.get::<_, Option<String>>(9)?,
                    row.get::<_, Option<String>>(10)?,
                    row.get::<_, Option<String>>(11)?,
                    row.get::<_, Option<String>>(12)?,
                    row.get::<_, Option<String>>(13)?,
                    row.get::<_, Option<String>>(14)?,
                    row.get::<_, Option<String>>(15)?,
                    row.get::<_, String>(16)?,
                    row.get::<_, i64>(17)?,
                    row.get::<_, Vec<u8>>(18)?,
                    row.get::<_, String>(19)?,
                    row.get::<_, Vec<u8>>(20)?,
                ))
            },
        )
        .optional()?
        .ok_or_else(|| LedgerError::ArtifactNotFound {
            entity: "current final-verification attempt v32",
            id: attempt_id.to_owned(),
        })?;
    let authority = FinalVerificationAttemptAuthorityV1::from_canonical_bytes(&stored.18)?;
    let authority_digest = authority.canonical_digest()?;
    let request: CurrentFinalVerificationAdmissionRequestV1 = decode_ledger(
        "current final-verification admission request v32",
        &stored.20,
    )?;
    let request_digest = Digest::parse(stored.19.clone())?;
    let expected_attempt_id = mint_identity(ATTEMPT_ID_DOMAIN, stored.19.as_bytes());
    let expected_admission_id = mint_identity(ADMISSION_ID_DOMAIN, stored.19.as_bytes());
    let expected_event_id = mint_identity(ADMISSION_EVENT_ID_DOMAIN, stored.19.as_bytes());
    if authority.attempt_id != attempt_id
        || authority.attempt_id != expected_attempt_id
        || authority.sprint_id != stored.1
        || i64::from(authority.attempt_ordinal) != stored.2
        || i64::from(authority.max_final_verification_attempts) != stored.3
        || authority.final_verification_admission_id != stored.4
        || authority.final_verification_admission_id != expected_admission_id
        || authority.input_snapshot.as_str() != stored.5
        || authority.complete_task_done_set_digest.as_str() != stored.6
        || authority.complete_criterion_evidence_set_digest.as_str() != stored.7
        || authority_digest.as_str() != stored.16
        || request.canonical_bytes()? != stored.20
        || request.canonical_digest()? != request_digest
        || request.request_id != stored.0
        || request_digest.as_str() != stored.19
        || authority.provenance.admission_event_id != expected_event_id
        || authority.provenance.admission_event_sequence != u64::from(authority.attempt_ordinal)
        || authority.provenance.admitted_at_unix_ms
            != super::unsigned_integer("attempt admitted_at", stored.17)?
        || !stored_predecessor_matches(&authority.predecessor, &stored)
    {
        return Err(corrupt(
            "current final-verification attempt v32",
            "stored projection differs from exact canonical attempt authority",
        ));
    }
    let current = load_current_sprint_authority(connection, &authority.sprint_id)?;
    request.validate_for(&current.spec, &current.graph)?;
    validate_attempt_request_binding(&request, &authority)?;
    let task_set =
        load_task_done_set_optional(connection, authority.complete_task_done_set_digest.as_str())?
            .ok_or_else(|| {
                corrupt(
                    "current final-verification attempt v32",
                    "TaskDone set missing",
                )
            })?;
    let criterion_set = load_criterion_evidence_set_optional(
        connection,
        authority.complete_criterion_evidence_set_digest.as_str(),
    )?
    .ok_or_else(|| {
        corrupt(
            "current final-verification attempt v32",
            "criterion-evidence set missing",
        )
    })?;
    task_set.validate_for(&current.spec, &current.graph)?;
    criterion_set.validate_for(&current.spec)?;
    if task_set.snapshot_digest != authority.input_snapshot
        || criterion_set.snapshot_digest != authority.input_snapshot
        || task_set != request.task_done_set
        || criterion_set != request.criterion_evidence_set
    {
        return Err(corrupt(
            "current final-verification attempt v32",
            "complete evidence sets cross the attempt snapshot",
        ));
    }
    let outcome = load_current_outcome_optional(connection, attempt_id)?;
    let persisted = PersistedCurrentFinalVerificationAttemptV1 {
        request_id: stored.0,
        outcome,
        authority,
    };
    let prior = if persisted.authority.attempt_ordinal == 1 {
        None
    } else {
        let prior_id = connection
            .query_row(
                "SELECT attempt_id FROM current_final_verification_attempts_v32
                 WHERE sprint_id = ?1 AND attempt_ordinal = ?2",
                params![
                    persisted.authority.sprint_id,
                    i64::from(persisted.authority.attempt_ordinal - 1),
                ],
                |row| row.get::<_, String>(0),
            )
            .optional()?
            .ok_or_else(|| {
                corrupt(
                    "current final-verification attempt v32",
                    "immediately preceding attempt is missing",
                )
            })?;
        Some(load_current_attempt(connection, &prior_id)?)
    };
    let (expected_predecessor, _) = derive_attempt_predecessor(
        connection,
        prior.as_ref(),
        &task_set,
        &criterion_set,
        &current.graph,
        persisted.authority.provenance.admitted_at_unix_ms,
    )?;
    if persisted.authority.predecessor != expected_predecessor {
        return Err(corrupt(
            "current final-verification attempt v32",
            "stored predecessor differs from the exact current prior outcome and repair authority",
        ));
    }
    if let Some(prior) = &prior {
        persisted
            .authority
            .validate_successor_of(&prior.authority)?;
    }
    Ok(persisted)
}

#[allow(clippy::type_complexity)]
fn stored_predecessor_matches(
    predecessor: &FinalVerificationAttemptPredecessorV1,
    stored: &(
        String,
        String,
        i64,
        i64,
        String,
        String,
        String,
        String,
        String,
        Option<String>,
        Option<String>,
        Option<String>,
        Option<String>,
        Option<String>,
        Option<String>,
        Option<String>,
        String,
        i64,
        Vec<u8>,
        String,
        Vec<u8>,
    ),
) -> bool {
    match predecessor {
        FinalVerificationAttemptPredecessorV1::Initial => {
            stored.8 == "Initial"
                && stored.9.is_none()
                && stored.10.is_none()
                && stored.11.is_none()
                && stored.12.is_none()
                && stored.13.is_none()
                && stored.14.is_none()
                && stored.15.is_none()
        }
        FinalVerificationAttemptPredecessorV1::SameSnapshotAfterFailedBeforeEffect {
            prior_attempt_id,
            closure_id,
        } => {
            stored.8 == "SameSnapshotAfterFailedBeforeEffect"
                && stored.9.as_ref() == Some(prior_attempt_id)
                && stored.10.is_some()
                && stored.11.is_none()
                && stored.12.as_ref() == Some(closure_id)
                && stored.13.is_none()
                && stored.14.is_none()
                && stored.15.is_none()
        }
        FinalVerificationAttemptPredecessorV1::SameSnapshotAfterControlInterruption {
            prior_attempt_id,
            control_id,
            closure_id,
        } => {
            stored.8 == "SameSnapshotAfterControlInterruption"
                && stored.9.as_ref() == Some(prior_attempt_id)
                && stored.10.is_some()
                && stored.11.as_ref() == Some(control_id)
                && stored.12.as_ref() == Some(closure_id)
                && stored.13.is_none()
                && stored.14.is_none()
                && stored.15.is_none()
        }
        FinalVerificationAttemptPredecessorV1::ChangedSnapshotAfterRepair {
            prior_failure_id,
            repair_admission_id,
            repair_task_done_proof_id,
            integration_receipt_id,
        } => {
            stored.8 == "ChangedSnapshotAfterRepair"
                && stored.9.is_some()
                && stored.10.as_ref() == Some(prior_failure_id)
                && stored.11.is_none()
                && stored.12.is_some()
                && stored.13.as_ref() == Some(repair_admission_id)
                && stored.14.as_ref() == Some(repair_task_done_proof_id)
                && stored.15.as_ref() == Some(integration_receipt_id)
        }
    }
}

fn load_current_outcome_optional(
    connection: &Connection,
    attempt_id: &str,
) -> Result<Option<CurrentFinalVerificationOutcomeV1>, LedgerError> {
    let stored = connection
        .query_row(
            "SELECT outcome_id, sprint_id, closure_id, outcome_kind,
                    outcome_code, terminal_at_unix_ms, outcome_json
             FROM current_final_verification_outcomes_v32 WHERE attempt_id = ?1",
            [attempt_id],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, Option<i64>>(4)?,
                    row.get::<_, i64>(5)?,
                    row.get::<_, Vec<u8>>(6)?,
                ))
            },
        )
        .optional()?;
    let Some(stored) = stored else {
        return Ok(None);
    };
    let outcome: CurrentFinalVerificationOutcomeV1 =
        decode_ledger("current final-verification outcome v32", &stored.6)?;
    outcome.validate()?;
    let expected_code = outcome.outcome.sql_code().map(i64::from);
    if encode_ledger("current final-verification outcome v32", &outcome)? != stored.6
        || outcome.outcome_id != stored.0
        || outcome.sprint_id != stored.1
        || outcome.attempt_id != attempt_id
        || outcome.closure_id != stored.2
        || outcome.outcome.sql_kind() != stored.3
        || expected_code != stored.4
        || outcome.terminal_at_unix_ms != super::unsigned_integer("outcome terminal_at", stored.5)?
    {
        return Err(corrupt(
            "current final-verification outcome v32",
            "stored projection differs from exact canonical outcome",
        ));
    }
    let capture = load_current_capture(connection, attempt_id)?;
    let expected_outcome_id = mint_identity(
        OUTCOME_ID_DOMAIN,
        &encode_ledger("current final-verification capture", &capture)?,
    );
    let expected_kind = classify_current_capture(connection, &capture)?;
    if outcome.outcome_id != expected_outcome_id
        || outcome.sprint_id != capture.sprint_id
        || outcome.closure_id != capture.closure_id
        || outcome.terminal_at_unix_ms != capture.terminal_at_unix_ms
        || outcome.outcome != expected_kind
    {
        return Err(corrupt(
            "current final-verification outcome v32",
            "outcome is not the exact core-derived classification of its capture",
        ));
    }
    Ok(Some(outcome))
}

const fn control_kind_sql(kind: CurrentFinalVerificationControlKindV1) -> &'static str {
    match kind {
        CurrentFinalVerificationControlKindV1::Pause => "Pause",
        CurrentFinalVerificationControlKindV1::SteeringInterruption => "SteeringInterruption",
        CurrentFinalVerificationControlKindV1::Cancel => "Cancel",
    }
}

fn load_current_control_optional(
    connection: &Connection,
    control_id: &str,
) -> Result<Option<CurrentFinalVerificationControlV1>, LedgerError> {
    let stored = connection
        .query_row(
            "SELECT sprint_id, attempt_id, control_kind, before_effect,
                    issued_at_unix_ms, control_json
             FROM current_final_verification_controls_v32 WHERE control_id = ?1",
            [control_id],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, bool>(3)?,
                    row.get::<_, i64>(4)?,
                    row.get::<_, Vec<u8>>(5)?,
                ))
            },
        )
        .optional()?;
    let Some(stored) = stored else {
        return Ok(None);
    };
    let control: CurrentFinalVerificationControlV1 =
        decode_ledger("current final-verification control", &stored.5)?;
    control.validate()?;
    let expected_control_id = mint_identity(
        CONTROL_ID_DOMAIN,
        &encode_ledger(
            "current final-verification control identity",
            &ControlIdentity {
                sprint_id: &control.sprint_id,
                attempt_id: &control.attempt_id,
                control_kind: control.control_kind,
                before_effect: control.before_effect,
                issued_at_unix_ms: control.issued_at_unix_ms,
            },
        )?,
    );
    if encode_ledger("current final-verification control", &control)? != stored.5
        || control.control_id != control_id
        || control.control_id != expected_control_id
        || control.sprint_id != stored.0
        || control.attempt_id != stored.1
        || control_kind_sql(control.control_kind) != stored.2
        || control.before_effect != stored.3
        || control.issued_at_unix_ms != super::unsigned_integer("control issued_at", stored.4)?
    {
        return Err(corrupt(
            "current final-verification control",
            "stored projection differs from exact canonical control",
        ));
    }
    Ok(Some(control))
}

fn load_current_control(
    connection: &Connection,
    control_id: &str,
) -> Result<CurrentFinalVerificationControlV1, LedgerError> {
    load_current_control_optional(connection, control_id)?.ok_or_else(|| {
        LedgerError::ArtifactNotFound {
            entity: "current final-verification control",
            id: control_id.to_owned(),
        }
    })
}

fn insert_current_capture(
    transaction: &Transaction<'_>,
    capture: &CurrentFinalVerificationCaptureClosureV1,
) -> Result<(), LedgerError> {
    transaction.execute(
        "INSERT INTO current_final_verification_capture_closures_v32 (
            closure_id, sprint_id, attempt_id, termination_kind,
            termination_code, control_id, custody_kind, custody_receipt_id,
            runner_cleanup_proof_id, command_domain_cleanup_proof_id,
            terminal_at_unix_ms, closure_json
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
        params![
            capture.closure_id,
            capture.sprint_id,
            capture.attempt_id,
            capture.termination.sql_kind(),
            capture.termination.sql_code().map(i64::from),
            capture.termination.control_id(),
            capture.output_custody.sql_kind(),
            capture.output_custody.receipt_id(),
            capture.runner_cleanup_proof_id,
            capture.command_domain_cleanup_proof_id,
            super::sqlite_integer("capture terminal_at", capture.terminal_at_unix_ms)?,
            encode_ledger("current final-verification capture", capture)?,
        ],
    )?;
    Ok(())
}

fn load_current_capture(
    connection: &Connection,
    attempt_id: &str,
) -> Result<CurrentFinalVerificationCaptureClosureV1, LedgerError> {
    let stored = connection
        .query_row(
            "SELECT closure_id, sprint_id, termination_kind, termination_code,
                    control_id, custody_kind, custody_receipt_id,
                    runner_cleanup_proof_id, command_domain_cleanup_proof_id,
                    terminal_at_unix_ms, closure_json
             FROM current_final_verification_capture_closures_v32
             WHERE attempt_id = ?1",
            [attempt_id],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, Option<i64>>(3)?,
                    row.get::<_, Option<String>>(4)?,
                    row.get::<_, String>(5)?,
                    row.get::<_, Option<String>>(6)?,
                    row.get::<_, Option<String>>(7)?,
                    row.get::<_, Option<String>>(8)?,
                    row.get::<_, i64>(9)?,
                    row.get::<_, Vec<u8>>(10)?,
                ))
            },
        )
        .optional()?
        .ok_or_else(|| LedgerError::ArtifactNotFound {
            entity: "current final-verification capture",
            id: attempt_id.to_owned(),
        })?;
    let capture: CurrentFinalVerificationCaptureClosureV1 =
        decode_ledger("current final-verification capture", &stored.10)?;
    capture.validate()?;
    if encode_ledger("current final-verification capture", &capture)? != stored.10
        || capture.attempt_id != attempt_id
        || capture.closure_id != stored.0
        || capture.sprint_id != stored.1
        || capture.termination.sql_kind() != stored.2
        || capture.termination.sql_code().map(i64::from) != stored.3
        || capture.termination.control_id() != stored.4.as_deref()
        || capture.output_custody.sql_kind() != stored.5
        || capture.output_custody.receipt_id() != stored.6.as_deref()
        || capture.runner_cleanup_proof_id != stored.7
        || capture.command_domain_cleanup_proof_id != stored.8
        || capture.terminal_at_unix_ms != super::unsigned_integer("capture terminal_at", stored.9)?
    {
        return Err(corrupt(
            "current final-verification capture",
            "stored projection differs from exact canonical capture",
        ));
    }
    Ok(capture)
}

fn classify_current_capture(
    connection: &Connection,
    capture: &CurrentFinalVerificationCaptureClosureV1,
) -> Result<CurrentFinalVerificationOutcomeKindV1, LedgerError> {
    let cleanup_complete = capture.runner_cleanup_proof_id.is_some()
        && capture.command_domain_cleanup_proof_id.is_some();
    if !cleanup_complete
        || matches!(
            capture.termination,
            CurrentFinalVerificationTerminationV1::Unknown { .. }
                | CurrentFinalVerificationTerminationV1::InterruptedAfterEffect { .. }
        )
        || matches!(
            capture.output_custody,
            CurrentFinalVerificationOutputCustodyV1::Unknown { .. }
        )
    {
        return Ok(CurrentFinalVerificationOutcomeKindV1::Unknown);
    }

    let control = capture
        .termination
        .control_id()
        .map(|control_id| load_current_control_optional(connection, control_id))
        .transpose()?
        .flatten()
        .filter(|control| {
            control.sprint_id == capture.sprint_id
                && control.attempt_id == capture.attempt_id
                && control.issued_at_unix_ms <= capture.terminal_at_unix_ms
        });
    match (&capture.termination, &capture.output_custody) {
        (
            CurrentFinalVerificationTerminationV1::InterruptedBeforeEffect { control_id },
            CurrentFinalVerificationOutputCustodyV1::ClosedBeforeCapture { .. },
        ) if control.as_ref().is_some_and(|record| {
            record.control_id == *control_id
                && record.before_effect
                && matches!(
                    record.control_kind,
                    CurrentFinalVerificationControlKindV1::Pause
                        | CurrentFinalVerificationControlKindV1::SteeringInterruption
                )
        }) =>
        {
            Ok(
                CurrentFinalVerificationOutcomeKindV1::ControlInterruptedBeforeEffect {
                    control_id: control_id.clone(),
                },
            )
        }
        (
            CurrentFinalVerificationTerminationV1::Canceled { control_id },
            custody @ (CurrentFinalVerificationOutputCustodyV1::PublishedClean { .. }
            | CurrentFinalVerificationOutputCustodyV1::AbandonedSensitive { .. }
            | CurrentFinalVerificationOutputCustodyV1::ClosedBeforeCapture { .. }),
        ) if control.as_ref().is_some_and(|record| {
            record.control_id == *control_id
                && record.control_kind == CurrentFinalVerificationControlKindV1::Cancel
                && matches!(
                    (record.before_effect, custody),
                    (
                        true,
                        CurrentFinalVerificationOutputCustodyV1::ClosedBeforeCapture { .. }
                    ) | (
                        false,
                        CurrentFinalVerificationOutputCustodyV1::PublishedClean { .. }
                            | CurrentFinalVerificationOutputCustodyV1::AbandonedSensitive { .. }
                    )
                )
        }) =>
        {
            Ok(CurrentFinalVerificationOutcomeKindV1::Canceled {
                control_id: control_id.clone(),
            })
        }
        (
            CurrentFinalVerificationTerminationV1::FailedBeforeEffect,
            CurrentFinalVerificationOutputCustodyV1::ClosedBeforeCapture { .. },
        ) => Ok(CurrentFinalVerificationOutcomeKindV1::FailedBeforeEffect),
        (_, CurrentFinalVerificationOutputCustodyV1::AbandonedSensitive { .. }) => {
            Ok(CurrentFinalVerificationOutcomeKindV1::SensitiveOutputRejected)
        }
        (
            CurrentFinalVerificationTerminationV1::Exited { code: 0 },
            CurrentFinalVerificationOutputCustodyV1::PublishedClean { .. },
        ) => Ok(CurrentFinalVerificationOutcomeKindV1::Verified),
        (
            CurrentFinalVerificationTerminationV1::Exited { code },
            CurrentFinalVerificationOutputCustodyV1::PublishedClean { .. },
        ) if *code > 0 => Ok(CurrentFinalVerificationOutcomeKindV1::NonzeroExit { code: *code }),
        (
            CurrentFinalVerificationTerminationV1::Signaled { signal },
            CurrentFinalVerificationOutputCustodyV1::PublishedClean { .. },
        ) if *signal > 0 => Ok(CurrentFinalVerificationOutcomeKindV1::Signaled { signal: *signal }),
        (
            CurrentFinalVerificationTerminationV1::TimedOut,
            CurrentFinalVerificationOutputCustodyV1::PublishedClean { .. },
        ) => Ok(CurrentFinalVerificationOutcomeKindV1::TimedOut),
        (
            CurrentFinalVerificationTerminationV1::OutputLimitExceeded,
            CurrentFinalVerificationOutputCustodyV1::PublishedClean { .. },
        ) => Ok(CurrentFinalVerificationOutcomeKindV1::OutputLimitExceeded),
        _ => Ok(CurrentFinalVerificationOutcomeKindV1::Unknown),
    }
}

fn maybe_insert_current_terminal(
    transaction: &Transaction<'_>,
    authority: &FinalVerificationAttemptAuthorityV1,
    outcome: &CurrentFinalVerificationOutcomeV1,
) -> Result<(), LedgerError> {
    let terminal = match &outcome.outcome {
        CurrentFinalVerificationOutcomeKindV1::Canceled { .. } => Some((
            "Canceled",
            CurrentSprintTerminalReasonV1::ExplicitCancel,
            "ExplicitCancel",
        )),
        CurrentFinalVerificationOutcomeKindV1::Unknown => Some((
            "Unknown",
            CurrentSprintTerminalReasonV1::AmbiguousFinalVerification,
            "AmbiguousFinalVerification",
        )),
        CurrentFinalVerificationOutcomeKindV1::Verified => None,
        _ if authority.attempt_ordinal == authority.max_final_verification_attempts => Some((
            "Failed",
            CurrentSprintTerminalReasonV1::FinalVerificationAttemptsExhausted,
            "FinalVerificationAttemptsExhausted",
        )),
        _ => None,
    };
    if let Some((terminal_state, _, reason_sql)) = terminal {
        transaction.execute(
            "INSERT INTO current_sprint_terminal_outcomes_v32 (
                sprint_id, terminal_state, source_attempt_id,
                source_outcome_id, terminal_reason, terminal_at_unix_ms
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                authority.sprint_id,
                terminal_state,
                authority.attempt_id,
                outcome.outcome_id,
                reason_sql,
                super::sqlite_integer("current terminal_at", outcome.terminal_at_unix_ms)?,
            ],
        )?;
    }
    Ok(())
}

fn load_current_terminal_optional(
    connection: &Connection,
    sprint_id: &str,
) -> Result<Option<CurrentSprintTerminalOutcomeV1>, LedgerError> {
    let stored = connection
        .query_row(
            "SELECT terminal_state, source_attempt_id, source_outcome_id,
                    terminal_reason, terminal_at_unix_ms
             FROM current_sprint_terminal_outcomes_v32 WHERE sprint_id = ?1",
            [sprint_id],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, i64>(4)?,
                ))
            },
        )
        .optional()?;
    let Some(stored) = stored else {
        return Ok(None);
    };
    let terminal_reason = match stored.3.as_str() {
        "FinalVerificationAttemptsExhausted" => {
            CurrentSprintTerminalReasonV1::FinalVerificationAttemptsExhausted
        }
        "ExplicitCancel" => CurrentSprintTerminalReasonV1::ExplicitCancel,
        "AmbiguousFinalVerification" => CurrentSprintTerminalReasonV1::AmbiguousFinalVerification,
        _ => {
            return Err(corrupt(
                "current sprint terminal v32",
                "unknown terminal reason",
            ));
        }
    };
    let outcome = load_current_outcome_optional(connection, &stored.1)?.ok_or_else(|| {
        corrupt(
            "current sprint terminal v32",
            "source attempt lacks exact outcome",
        )
    })?;
    let (source_ordinal, source_cap) = connection.query_row(
        "SELECT attempt_ordinal, max_final_verification_attempts
         FROM current_final_verification_attempts_v32
         WHERE attempt_id = ?1 AND sprint_id = ?2",
        params![stored.1, sprint_id],
        |row| Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?)),
    )?;
    let exhausted_failure = source_ordinal == source_cap
        && !matches!(
            &outcome.outcome,
            CurrentFinalVerificationOutcomeKindV1::Verified
                | CurrentFinalVerificationOutcomeKindV1::Canceled { .. }
                | CurrentFinalVerificationOutcomeKindV1::Unknown
        );
    let terminal_matches = match (stored.0.as_str(), &outcome.outcome, terminal_reason) {
        ("Failed", _, CurrentSprintTerminalReasonV1::FinalVerificationAttemptsExhausted) => {
            exhausted_failure
        }
        (
            "Canceled",
            CurrentFinalVerificationOutcomeKindV1::Canceled { .. },
            CurrentSprintTerminalReasonV1::ExplicitCancel,
        )
        | (
            "Unknown",
            CurrentFinalVerificationOutcomeKindV1::Unknown,
            CurrentSprintTerminalReasonV1::AmbiguousFinalVerification,
        ) => true,
        _ => false,
    };
    if outcome.sprint_id != sprint_id
        || outcome.outcome_id != stored.2
        || outcome.terminal_at_unix_ms != super::unsigned_integer("current terminal_at", stored.4)?
        || !terminal_matches
    {
        return Err(corrupt(
            "current sprint terminal v32",
            "terminal marker crosses its exact source outcome",
        ));
    }
    Ok(Some(CurrentSprintTerminalOutcomeV1 {
        sprint_id: sprint_id.to_owned(),
        terminal_state: stored.0,
        source_attempt_id: stored.1,
        source_outcome_id: stored.2,
        terminal_reason,
        terminal_at_unix_ms: super::unsigned_integer("current terminal_at", stored.4)?,
    }))
}
fn load_repair_completion_for_failed_attempt(
    connection: &Connection,
    failed_attempt_id: &str,
) -> Result<Option<CurrentFinalVerificationRepairCompletionV1>, LedgerError> {
    let completion_id = connection
        .query_row(
            "SELECT completion_id FROM current_final_verification_repair_completions_v32
             WHERE failed_attempt_id = ?1",
            [failed_attempt_id],
            |row| row.get::<_, String>(0),
        )
        .optional()?;
    completion_id
        .map(|completion_id| load_repair_completion(connection, &completion_id))
        .transpose()
}

fn load_repair_activation_by_failure_optional(
    connection: &Connection,
    failure_outcome_id: &str,
) -> Result<Option<CurrentFinalVerificationRepairActivationV1>, LedgerError> {
    let activation_id = connection
        .query_row(
            "SELECT activation_id FROM current_final_verification_repair_activations_v32
             WHERE failure_outcome_id = ?1",
            [failure_outcome_id],
            |row| row.get::<_, String>(0),
        )
        .optional()?;
    activation_id
        .map(|activation_id| load_repair_activation(connection, &activation_id))
        .transpose()
}

fn load_repair_activation(
    connection: &Connection,
    activation_id: &str,
) -> Result<CurrentFinalVerificationRepairActivationV1, LedgerError> {
    let stored = connection
        .query_row(
            "SELECT sprint_id, failed_attempt_id, failure_outcome_id,
                    failed_snapshot, slot_ordinal, repair_task_id,
                    activated_at_unix_ms, activation_json
             FROM current_final_verification_repair_activations_v32
             WHERE activation_id = ?1",
            [activation_id],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, i64>(4)?,
                    row.get::<_, String>(5)?,
                    row.get::<_, i64>(6)?,
                    row.get::<_, Vec<u8>>(7)?,
                ))
            },
        )
        .optional()?
        .ok_or_else(|| LedgerError::ArtifactNotFound {
            entity: "current repair activation v32",
            id: activation_id.to_owned(),
        })?;
    let activation: CurrentFinalVerificationRepairActivationV1 =
        decode_ledger("current repair activation v32", &stored.7)?;
    activation.validate()?;
    let expected_activation_id = mint_identity(
        REPAIR_ACTIVATION_ID_DOMAIN,
        &encode_ledger(
            "current repair activation identity",
            &RepairActivationIdentity {
                sprint_id: &activation.sprint_id,
                failed_attempt_id: &activation.failed_attempt_id,
                failure_outcome_id: &activation.failure_outcome_id,
                failed_snapshot: &activation.failed_snapshot,
                slot_ordinal: activation.slot_ordinal,
                repair_task_id: &activation.repair_task_id,
                activated_at_unix_ms: activation.activated_at_unix_ms,
            },
        )?,
    );
    if encode_ledger("current repair activation v32", &activation)? != stored.7
        || activation.activation_id != activation_id
        || activation.activation_id != expected_activation_id
        || activation.sprint_id != stored.0
        || activation.failed_attempt_id != stored.1
        || activation.failure_outcome_id != stored.2
        || activation.failed_snapshot.as_str() != stored.3
        || i64::from(activation.slot_ordinal) != stored.4
        || activation.repair_task_id != stored.5
        || activation.activated_at_unix_ms
            != super::unsigned_integer("repair activated_at", stored.6)?
    {
        return Err(corrupt(
            "current repair activation v32",
            "stored projection differs from exact canonical activation",
        ));
    }
    let attempt = load_current_attempt(connection, &activation.failed_attempt_id)?;
    let current = load_current_sprint_authority(connection, &activation.sprint_id)?;
    let graph_slot_matches = current.graph.tasks.iter().any(|task| {
        task.task_id == activation.repair_task_id
            && task.purpose
                == TaskPurposeV2::FinalVerificationRepairSlot {
                    slot_ordinal: activation.slot_ordinal,
                }
    });
    if attempt.authority.sprint_id != activation.sprint_id
        || attempt.authority.input_snapshot != activation.failed_snapshot
        || attempt.authority.attempt_ordinal != activation.slot_ordinal
        || attempt.authority.attempt_ordinal >= attempt.authority.max_final_verification_attempts
        || !graph_slot_matches
        || attempt.outcome.as_ref().is_none_or(|outcome| {
            outcome.outcome_id != activation.failure_outcome_id
                || !outcome.outcome.is_known_after_effect_failure()
                || outcome.terminal_at_unix_ms > activation.activated_at_unix_ms
        })
    {
        return Err(corrupt(
            "current repair activation v32",
            "activation crosses its exact failed attempt or known outcome",
        ));
    }
    Ok(activation)
}

fn require_all_criterion_evidence_fresh(
    stale: &CompleteCriterionEvidenceSetV1,
    fresh: &CompleteCriterionEvidenceSetV1,
) -> Result<(), LedgerError> {
    if stale.sprint_id != fresh.sprint_id
        || stale.snapshot_digest == fresh.snapshot_digest
        || stale.members.len() != fresh.members.len()
    {
        return Err(mismatch(
            "current repair criterion evidence v32",
            "repair evidence must cover the same criteria on a distinct snapshot",
        ));
    }
    for (old, new) in stale.members.iter().zip(&fresh.members) {
        if old.criterion_id != new.criterion_id
            || old.criterion_ordinal != new.criterion_ordinal
            || old.evidence_kind != new.evidence_kind
            || old.evidence_receipt_id == new.evidence_receipt_id
            || new.snapshot_digest != fresh.snapshot_digest
        {
            return Err(mismatch(
                "current repair criterion evidence v32",
                "every machine or human criterion requires one fresh same-snapshot receipt",
            ));
        }
    }
    Ok(())
}

fn require_exact_repair_task_done_extension(
    failed: &CompleteTaskDoneSetV1,
    repaired: &CompleteTaskDoneSetV1,
    activation: &CurrentFinalVerificationRepairActivationV1,
    repair_task_done_proof_id: &str,
    integration_receipt_id: &str,
) -> Result<(), LedgerError> {
    let Some(repair_member) = repaired.members.last() else {
        return Err(mismatch(
            "current repair TaskDone set v32",
            "repaired TaskDone set is empty",
        ));
    };
    let expected_ordinal = u32::try_from(failed.members.len())
        .map_err(|_| LedgerError::IntegerOutOfRange("repair TaskDone source ordinal"))?;
    if repaired.members.len() != failed.members.len().saturating_add(1)
        || repaired.members[..failed.members.len()] != failed.members
        || repair_member.source_ordinal != expected_ordinal
        || repair_member.task_id != activation.repair_task_id
        || repair_member.task_done_proof_id != repair_task_done_proof_id
        || repair_member.integration_receipt_id != integration_receipt_id
        || !matches!(
            &repair_member.integration_evidence,
            CurrentTaskDoneIntegrationEvidenceV1::Changed
        )
        || repair_member.input_snapshot != failed.snapshot_digest
        || repair_member.result_snapshot != repaired.snapshot_digest
    {
        return Err(mismatch(
            "current repair TaskDone set v32",
            "repair must preserve the exact prior integration chain and append only the activated fresh TaskDone source",
        ));
    }
    Ok(())
}

#[allow(clippy::too_many_lines)] // Exact completion readback crosses activation, both complete sets, prior-chain preservation, and fresh evidence.
fn load_repair_completion(
    connection: &Connection,
    completion_id: &str,
) -> Result<CurrentFinalVerificationRepairCompletionV1, LedgerError> {
    let stored = connection
        .query_row(
            "SELECT sprint_id, activation_id, failed_attempt_id, repair_task_id,
                    repair_task_done_proof_id, integration_receipt_id,
                    input_snapshot, result_snapshot, change_set_id,
                    operation_count, complete_task_done_set_digest,
                    complete_criterion_evidence_set_digest,
                    completed_at_unix_ms, completion_json, request_digest
             FROM current_final_verification_repair_completions_v32
             WHERE completion_id = ?1",
            [completion_id],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, String>(5)?,
                    row.get::<_, String>(6)?,
                    row.get::<_, String>(7)?,
                    row.get::<_, String>(8)?,
                    row.get::<_, i64>(9)?,
                    row.get::<_, String>(10)?,
                    row.get::<_, String>(11)?,
                    row.get::<_, i64>(12)?,
                    row.get::<_, Vec<u8>>(13)?,
                    row.get::<_, String>(14)?,
                ))
            },
        )
        .optional()?
        .ok_or_else(|| LedgerError::ArtifactNotFound {
            entity: "current repair completion v32",
            id: completion_id.to_owned(),
        })?;
    let completion: CurrentFinalVerificationRepairCompletionV1 =
        decode_ledger("current repair completion v32", &stored.13)?;
    completion.validate()?;
    let request_digest = Digest::parse(stored.14.clone())?;
    let expected_completion_id = mint_identity(
        REPAIR_COMPLETION_ID_DOMAIN,
        &encode_ledger(
            "current repair completion identity",
            &RepairCompletionIdentity {
                request_digest: &request_digest,
                sprint_id: &completion.sprint_id,
                failed_attempt_id: &completion.failed_attempt_id,
            },
        )?,
    );
    if encode_ledger("current repair completion v32", &completion)? != stored.13
        || completion.completion_id != completion_id
        || completion.completion_id != expected_completion_id
        || completion.sprint_id != stored.0
        || completion.activation_id != stored.1
        || completion.failed_attempt_id != stored.2
        || completion.repair_task_id != stored.3
        || completion.repair_task_done_proof_id != stored.4
        || completion.integration_receipt_id != stored.5
        || completion.input_snapshot.as_str() != stored.6
        || completion.result_snapshot.as_str() != stored.7
        || completion.change_set_id != stored.8
        || i64::from(completion.operation_count) != stored.9
        || completion.complete_task_done_set_digest.as_str() != stored.10
        || completion.complete_criterion_evidence_set_digest.as_str() != stored.11
        || completion.completed_at_unix_ms
            != super::unsigned_integer("repair completed_at", stored.12)?
    {
        return Err(corrupt(
            "current repair completion v32",
            "stored projection differs from exact canonical completion",
        ));
    }
    let activation = load_repair_activation(connection, &completion.activation_id)?;
    if activation.sprint_id != completion.sprint_id
        || activation.failed_attempt_id != completion.failed_attempt_id
        || activation.repair_task_id != completion.repair_task_id
        || activation.failed_snapshot != completion.input_snapshot
        || completion.completed_at_unix_ms < activation.activated_at_unix_ms
    {
        return Err(corrupt(
            "current repair completion v32",
            "completion crosses its exact activation",
        ));
    }
    let current = load_current_sprint_authority(connection, &completion.sprint_id)?;
    let task_set = load_task_done_set_optional(
        connection,
        completion.complete_task_done_set_digest.as_str(),
    )?
    .ok_or_else(|| corrupt("current repair completion v32", "TaskDone set missing"))?;
    let criterion_set = load_criterion_evidence_set_optional(
        connection,
        completion.complete_criterion_evidence_set_digest.as_str(),
    )?
    .ok_or_else(|| {
        corrupt(
            "current repair completion v32",
            "criterion-evidence set missing",
        )
    })?;
    task_set.validate_for(&current.spec, &current.graph)?;
    criterion_set.validate_for(&current.spec)?;
    if task_set.snapshot_digest != completion.result_snapshot
        || criterion_set.snapshot_digest != completion.result_snapshot
        || task_set.recorded_at_unix_ms > completion.completed_at_unix_ms
        || criterion_set.recorded_at_unix_ms > completion.completed_at_unix_ms
    {
        return Err(corrupt(
            "current repair completion v32",
            "complete evidence sets cross the repaired result snapshot or completion time",
        ));
    }
    let failed = load_current_attempt(connection, &completion.failed_attempt_id)?;
    let failed_task_set = load_task_done_set_optional(
        connection,
        failed.authority.complete_task_done_set_digest.as_str(),
    )?
    .ok_or_else(|| {
        corrupt(
            "current repair completion v32",
            "failed TaskDone set missing",
        )
    })?;
    let failed_criterion_set = load_criterion_evidence_set_optional(
        connection,
        failed
            .authority
            .complete_criterion_evidence_set_digest
            .as_str(),
    )?
    .ok_or_else(|| {
        corrupt(
            "current repair completion v32",
            "failed criterion-evidence set missing",
        )
    })?;
    require_exact_repair_task_done_extension(
        &failed_task_set,
        &task_set,
        &activation,
        &completion.repair_task_done_proof_id,
        &completion.integration_receipt_id,
    )?;
    require_all_criterion_evidence_fresh(&failed_criterion_set, &criterion_set)?;
    Ok(completion)
}

#[allow(clippy::too_many_lines)] // Exact current authority readback crosses reciprocal envelopes and every projected task node.
fn load_current_sprint_authority_optional(
    connection: &Connection,
    sprint_id: &str,
) -> Result<Option<CurrentSprintAuthorityV32>, LedgerError> {
    let stored = connection
        .query_row(
            "SELECT sprint.sprint_authority_version, sprint.sprint_spec_digest,
                    sprint.task_graph_id, sprint.task_graph_payload_digest,
                    sprint.repair_slot_reserve_digest,
                    sprint.max_final_verification_attempts, sprint.base_snapshot,
                    sprint.workspace_grant_hash, sprint.created_at_unix_ms,
                    sprint.spec_json, graph.graph_digest,
                    graph.sprint_spec_digest, graph.graph_payload_digest,
                    graph.repair_slot_reserve_digest, graph.graph_json
             FROM current_sprint_authority_capture_v32 capture
             JOIN current_sprint_authorities_v32 sprint
               ON sprint.sprint_id = capture.sprint_id
             JOIN current_task_graph_authorities_v32 graph
               ON graph.sprint_id = sprint.sprint_id
             WHERE sprint.sprint_id = ?1",
            [sprint_id],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, i64>(5)?,
                    row.get::<_, String>(6)?,
                    row.get::<_, String>(7)?,
                    row.get::<_, i64>(8)?,
                    row.get::<_, Vec<u8>>(9)?,
                    row.get::<_, String>(10)?,
                    row.get::<_, String>(11)?,
                    row.get::<_, String>(12)?,
                    row.get::<_, String>(13)?,
                    row.get::<_, Vec<u8>>(14)?,
                ))
            },
        )
        .optional()?;
    let Some(stored) = stored else {
        return Ok(None);
    };
    let spec = SprintSpecV2::from_canonical_bytes(&stored.9)?;
    let graph = TaskGraphV2::from_canonical_bytes_for_sprint(&stored.14, &spec)?;
    let spec_digest = spec.canonical_digest()?;
    let graph_digest = graph.canonical_digest_for_sprint(&spec)?;
    let created_at_unix_ms = super::unsigned_integer("created_at_unix_ms", stored.8)?;
    if stored.0 != i64::from(spec.sprint_authority_version)
        || stored.1 != spec_digest.as_str()
        || stored.2 != spec.task_graph_id
        || stored.3 != spec.task_graph_payload_digest.as_str()
        || stored.4 != spec.repair_slot_reserve_digest.as_str()
        || stored.5 != i64::from(spec.budget.max_final_verification_attempts)
        || stored.6 != spec.base_snapshot.as_str()
        || stored.7 != spec.workspace_grant.grant_hash.as_str()
        || stored.10 != graph_digest.as_str()
        || stored.11 != graph.sprint_spec_digest.as_str()
        || stored.12 != graph.payload_digest()?.as_str()
        || stored.13 != graph.repair_slot_reserve_digest.as_str()
    {
        return Err(corrupt(
            "current sprint authority v32",
            "stored columns differ from exact canonical sprint/graph bytes",
        ));
    }
    let mut statement = connection.prepare(
        "SELECT declaration_ordinal, task_id, purpose, repair_slot_ordinal,
                required, task_json
         FROM current_task_nodes_v32 WHERE sprint_id = ?1
         ORDER BY declaration_ordinal",
    )?;
    let nodes = statement
        .query_map([sprint_id], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, Option<i64>>(3)?,
                row.get::<_, bool>(4)?,
                row.get::<_, Vec<u8>>(5)?,
            ))
        })?
        .collect::<Result<Vec<_>, _>>()?;
    if nodes.len() != graph.tasks.len() {
        return Err(corrupt(
            "current sprint authority v32",
            "task-node projection count differs from the canonical graph",
        ));
    }
    for (ordinal, (task, node)) in graph.tasks.iter().zip(&nodes).enumerate() {
        let (expected_purpose, expected_slot) = match task.purpose {
            TaskPurposeV2::Ordinary => ("Ordinary", None),
            TaskPurposeV2::FinalVerificationRepairSlot { slot_ordinal } => {
                ("FinalVerificationRepairSlot", Some(i64::from(slot_ordinal)))
            }
        };
        if i64::try_from(ordinal).ok() != Some(node.0)
            || task.task_id != node.1
            || expected_purpose != node.2
            || expected_slot != node.3
            || task.required != node.4
            || encode_ledger("current task v32", task)? != node.5
        {
            return Err(corrupt(
                "current sprint authority v32",
                "task-node projection differs from the exact canonical graph task",
            ));
        }
    }
    Ok(Some(CurrentSprintAuthorityV32 {
        spec,
        graph,
        created_at_unix_ms,
    }))
}

fn load_current_sprint_authority(
    connection: &Connection,
    sprint_id: &str,
) -> Result<CurrentSprintAuthorityV32, LedgerError> {
    load_current_sprint_authority_optional(connection, sprint_id)?.ok_or_else(|| {
        LedgerError::ArtifactNotFound {
            entity: "current sprint authority v32",
            id: sprint_id.to_owned(),
        }
    })
}

fn encode_ledger<T: Serialize + ?Sized>(
    entity: &'static str,
    value: &T,
) -> Result<Vec<u8>, LedgerError> {
    serde_json::to_vec(value).map_err(|source| LedgerError::Json { entity, source })
}

fn decode_ledger<T: DeserializeOwned>(
    entity: &'static str,
    bytes: &[u8],
) -> Result<T, LedgerError> {
    serde_json::from_slice(bytes).map_err(|source| LedgerError::Json { entity, source })
}

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
mod tests;
