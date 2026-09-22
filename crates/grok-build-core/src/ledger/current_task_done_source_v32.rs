//! Dormant current-only `TaskDone` source projection for schema v32.
//!
//! No production writer exists because the current V2 lifecycle, effect,
//! output-capture, cleanup, lease, and replay-authority source tables needed to
//! derive this conjunction do not exist yet. A connection-local, crate-private
//! admission guard permits exact fixture seeding only under `cfg(test)`. This
//! assumes the signed desktop is the only same-user writer to its `0600`
//! ledger; arbitrary same-user code could register a same-named innocuous
//! `SQLite` UDF on another connection, so this is not a cryptographic boundary.

use std::cell::RefCell;
use std::collections::BTreeSet;

use rusqlite::functions::FunctionFlags;
use rusqlite::{Connection, OptionalExtension, params};
use serde::{Deserialize, Serialize};

use crate::{AcceptanceKind, ContractError, Digest, SprintSpecV2, TaskSpecV2};

#[cfg(test)]
use super::final_verification_authority_v32::{
    CompleteTaskDoneSetV1, CurrentTaskDoneIntegrationEvidenceV1, CurrentTaskDoneMemberV1,
};
#[cfg(test)]
use super::sqlite_integer;
use super::{EventLedger, LedgerError, decode_stored, encode, unsigned_integer};
#[cfg(test)]
use crate::TaskGraphV2;

pub(super) const MIGRATION_V32: &str = include_str!("current_task_done_source_v32.sql");

const SOURCE_VERSION_V1: u32 = 1;
const WRITE_ADMISSION_FUNCTION: &str = "grok_current_task_done_source_write_admitted_v32";
const PROOF_ID_DOMAIN: &[u8] = b"grok-build/current-task-done-source-v1/proof-id\0";
const SOURCE_DIGEST_DOMAIN: &[u8] = b"grok-build/current-task-done-source-v1/canonical-json\0";
const MAX_ASSIGNED_AUTOMATED_CHECKS: usize = 256;
const MAX_ATTEMPT_CLOSURES: usize = 64;

/// Exact changed integration or explicit verified no-op backing one task.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum CurrentTaskDoneIntegrationSourceV1 {
    /// A nonempty `ChangeSet` produced a distinct result snapshot.
    Changed {
        /// Exact successful integration receipt.
        integration_receipt_id: String,
        /// Exact nonempty `ChangeSet`.
        change_set_id: String,
        /// Positive exact operation count.
        operation_count: u32,
    },
    /// An explicit empty `ChangeSet` preserved the input snapshot.
    VerifiedNoOp {
        /// Exact successful no-op integration receipt.
        integration_receipt_id: String,
        /// Exact explicit empty `ChangeSet` identity.
        empty_change_set_id: String,
    },
}

impl CurrentTaskDoneIntegrationSourceV1 {
    fn validate_for_snapshots(
        &self,
        input_snapshot: &Digest,
        result_snapshot: &Digest,
    ) -> Result<(), ContractError> {
        match self {
            Self::Changed {
                integration_receipt_id,
                change_set_id,
                operation_count,
            } => {
                require_nonblank("integration.integration_receipt_id", integration_receipt_id)?;
                require_nonblank("integration.change_set_id", change_set_id)?;
                if *operation_count == 0 || input_snapshot == result_snapshot {
                    return Err(contract_error(
                        "integration.change_set_id",
                        "changed integration requires positive operations and distinct snapshots",
                    ));
                }
            }
            Self::VerifiedNoOp {
                integration_receipt_id,
                empty_change_set_id,
            } => {
                require_nonblank("integration.integration_receipt_id", integration_receipt_id)?;
                require_nonblank("integration.empty_change_set_id", empty_change_set_id)?;
                if input_snapshot != result_snapshot {
                    return Err(contract_error(
                        "integration.empty_change_set_id",
                        "verified no-op integration requires identical snapshots",
                    ));
                }
            }
        }
        Ok(())
    }

    pub(super) const fn sql_kind(&self) -> &'static str {
        match self {
            Self::Changed { .. } => "Changed",
            Self::VerifiedNoOp { .. } => "VerifiedNoOp",
        }
    }

    pub(super) fn integration_receipt_id(&self) -> &str {
        match self {
            Self::Changed {
                integration_receipt_id,
                ..
            }
            | Self::VerifiedNoOp {
                integration_receipt_id,
                ..
            } => integration_receipt_id,
        }
    }

    pub(super) fn change_set_id(&self) -> Option<&str> {
        match self {
            Self::Changed { change_set_id, .. } => Some(change_set_id),
            Self::VerifiedNoOp { .. } => None,
        }
    }

    pub(super) fn empty_change_set_id(&self) -> Option<&str> {
        match self {
            Self::Changed { .. } => None,
            Self::VerifiedNoOp {
                empty_change_set_id,
                ..
            } => Some(empty_change_set_id),
        }
    }

    pub(super) const fn operation_count(&self) -> u32 {
        match self {
            Self::Changed {
                operation_count, ..
            } => *operation_count,
            Self::VerifiedNoOp { .. } => 0,
        }
    }
}

/// One assigned automated task check proven on the exact result snapshot.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CurrentTaskDoneAutomatedCheckV1 {
    /// Exact criterion identity in task declaration order.
    pub criterion_id: String,
    /// Exact successful task-formal-check receipt.
    pub verification_receipt_id: String,
    /// Exact integrated snapshot checked.
    pub snapshot_digest: Digest,
}

/// Closed disposition of one attempt represented in a `TaskDone` source.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CurrentTaskDoneAttemptDispositionV1 {
    /// The sole integrated winner.
    Integrated,
    /// Known safe retryable nonwinner.
    Retryable,
    /// Known exhausted nonwinner.
    AttemptsExhausted,
    /// Known permanent-failure nonwinner.
    PermanentFailure,
    /// Known blocked nonwinner.
    Blocked,
    /// Known canceled nonwinner.
    Canceled,
}

/// Exact all-domain terminal closure for one admitted task attempt.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CurrentTaskDoneAttemptClosureV1 {
    /// Exact attempt identity.
    pub attempt_id: String,
    /// Positive contiguous task-local ordinal.
    pub attempt_ordinal: u32,
    /// Exact worker lease.
    pub lease_id: String,
    /// Nonzero lease epoch.
    pub lease_epoch: u64,
    /// Exact immutable terminal disposition identity.
    pub disposition_id: String,
    /// Exact terminal disposition class; the winner is `Integrated`.
    pub disposition: CurrentTaskDoneAttemptDispositionV1,
    /// Complete set proving every owned effect terminal and non-Unknown.
    pub terminal_effect_closure_set_id: String,
    /// Complete set proving every owned command capture terminal.
    pub output_capture_closure_set_id: String,
    /// Complete zero-survivor runner-cleanup set.
    pub runner_cleanup_closure_set_id: String,
    /// Complete OS command-domain cleanup set.
    pub command_domain_cleanup_closure_set_id: String,
    /// Exact append-only lease-release record.
    pub lease_release_id: String,
}

/// Immutable, content-addressed current `TaskDone` conjunction projection.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CurrentTaskDoneSourceReceiptV1 {
    /// Closed source-contract version.
    pub source_version: u32,
    /// Deterministic identity derived from every remaining field.
    pub task_done_proof_id: String,
    /// Owning current sprint.
    pub sprint_id: String,
    /// Exact graph task.
    pub task_id: String,
    /// Exact durable task-state transition or observation proving `Integrated`.
    pub durable_integrated_state_event_id: String,
    /// Sole integrated winning attempt.
    pub winning_attempt_id: String,
    /// Positive winning attempt ordinal.
    pub winning_attempt_ordinal: u32,
    /// Winning attempt's exact lease.
    pub winning_lease_id: String,
    /// Winning attempt's nonzero lease epoch.
    pub winning_lease_epoch: u64,
    /// Exact changed integration or explicit verified no-op.
    pub integration: CurrentTaskDoneIntegrationSourceV1,
    /// Snapshot consumed by integration.
    pub input_snapshot: Digest,
    /// Exact integrated result snapshot.
    pub result_snapshot: Digest,
    /// Every assigned automated task check, in declaration order.
    pub assigned_automated_checks: Vec<CurrentTaskDoneAutomatedCheckV1>,
    /// Every attempt's terminal effect, capture, cleanup, disposition, and lease closure.
    pub attempt_closures: Vec<CurrentTaskDoneAttemptClosureV1>,
    /// Exact observation proving zero active task leases.
    pub zero_active_leases_proof_id: String,
    /// Must be zero at the derivation cut.
    pub active_lease_count: u32,
    /// Exact observation proving zero replay or dispatch authority.
    pub zero_replay_dispatch_authority_proof_id: String,
    /// Must be zero at the derivation cut.
    pub replay_dispatch_authority_count: u32,
    /// Time the complete conjunction was derived.
    pub derived_at_unix_ms: u64,
}

impl CurrentTaskDoneSourceReceiptV1 {
    /// Validates intrinsic closure, ordering, and deterministic identity.
    ///
    /// This does not authenticate lifecycle facts; only a future role-sealed
    /// writer may derive those facts from current source tables.
    ///
    /// # Errors
    ///
    /// Returns a contract error for an invalid, incomplete, unbounded, crossed,
    /// or caller-selected source identity.
    #[allow(clippy::too_many_lines)] // One pass validates the complete indivisible TaskDone conjunction.
    pub fn validate(&self) -> Result<(), ContractError> {
        if self.source_version != SOURCE_VERSION_V1 {
            return Err(contract_error("source_version", "must equal one"));
        }
        for (field, value) in [
            ("task_done_proof_id", self.task_done_proof_id.as_str()),
            ("sprint_id", self.sprint_id.as_str()),
            ("task_id", self.task_id.as_str()),
            (
                "durable_integrated_state_event_id",
                self.durable_integrated_state_event_id.as_str(),
            ),
            ("winning_attempt_id", self.winning_attempt_id.as_str()),
            ("winning_lease_id", self.winning_lease_id.as_str()),
            (
                "zero_active_leases_proof_id",
                self.zero_active_leases_proof_id.as_str(),
            ),
            (
                "zero_replay_dispatch_authority_proof_id",
                self.zero_replay_dispatch_authority_proof_id.as_str(),
            ),
        ] {
            require_nonblank(field, value)?;
        }
        if self.winning_attempt_ordinal == 0
            || self.winning_lease_epoch == 0
            || self.derived_at_unix_ms == 0
        {
            return Err(contract_error(
                "winning_attempt",
                "attempt ordinal, lease epoch, and derivation time must be positive",
            ));
        }
        if self.active_lease_count != 0 || self.replay_dispatch_authority_count != 0 {
            return Err(contract_error(
                "zero_authority",
                "TaskDone requires zero active leases and zero replay/dispatch authority",
            ));
        }
        self.integration
            .validate_for_snapshots(&self.input_snapshot, &self.result_snapshot)?;
        if self.assigned_automated_checks.len() > MAX_ASSIGNED_AUTOMATED_CHECKS {
            return Err(contract_error(
                "assigned_automated_checks",
                "assigned automated check count exceeds the closed bound",
            ));
        }
        let mut criterion_ids = BTreeSet::new();
        let mut verification_ids = BTreeSet::new();
        for check in &self.assigned_automated_checks {
            require_nonblank("assigned_check.criterion_id", &check.criterion_id)?;
            require_nonblank(
                "assigned_check.verification_receipt_id",
                &check.verification_receipt_id,
            )?;
            if check.snapshot_digest != self.result_snapshot
                || !criterion_ids.insert(check.criterion_id.as_str())
                || !verification_ids.insert(check.verification_receipt_id.as_str())
            {
                return Err(contract_error(
                    "assigned_automated_checks",
                    "checks must be same-snapshot and identity-unique",
                ));
            }
        }
        if self.attempt_closures.is_empty() || self.attempt_closures.len() > MAX_ATTEMPT_CLOSURES {
            return Err(contract_error(
                "attempt_closures",
                "attempt closure count must be within 1..=64",
            ));
        }
        let mut attempts = BTreeSet::new();
        let mut leases = BTreeSet::new();
        let mut disposition_ids = BTreeSet::new();
        let mut release_ids = BTreeSet::new();
        let mut winner_count = 0_usize;
        for (index, closure) in self.attempt_closures.iter().enumerate() {
            for (field, value) in [
                ("attempt_id", closure.attempt_id.as_str()),
                ("lease_id", closure.lease_id.as_str()),
                ("disposition_id", closure.disposition_id.as_str()),
                (
                    "terminal_effect_closure_set_id",
                    closure.terminal_effect_closure_set_id.as_str(),
                ),
                (
                    "output_capture_closure_set_id",
                    closure.output_capture_closure_set_id.as_str(),
                ),
                (
                    "runner_cleanup_closure_set_id",
                    closure.runner_cleanup_closure_set_id.as_str(),
                ),
                (
                    "command_domain_cleanup_closure_set_id",
                    closure.command_domain_cleanup_closure_set_id.as_str(),
                ),
                ("lease_release_id", closure.lease_release_id.as_str()),
            ] {
                require_nonblank(field, value)?;
            }
            let expected_ordinal = u32::try_from(index + 1)
                .map_err(|_| contract_error("attempt_closures", "ordinal overflow"))?;
            let attempt_unique = attempts.insert(closure.attempt_id.as_str());
            let lease_unique = leases.insert((closure.lease_id.as_str(), closure.lease_epoch));
            let disposition_unique = disposition_ids.insert(closure.disposition_id.as_str());
            let release_unique = release_ids.insert(closure.lease_release_id.as_str());
            if closure.attempt_ordinal != expected_ordinal
                || closure.lease_epoch == 0
                || !attempt_unique
                || !lease_unique
                || !disposition_unique
                || !release_unique
            {
                return Err(contract_error(
                    "attempt_closures",
                    format!(
                        "attempts, leases, dispositions, and releases must be contiguous and identity-unique (expected ordinal {expected_ordinal}, observed {}, lease epoch {}, attempt unique {attempt_unique}, lease unique {lease_unique}, disposition unique {disposition_unique}, release unique {release_unique})",
                        closure.attempt_ordinal, closure.lease_epoch
                    ),
                ));
            }
            if closure.disposition == CurrentTaskDoneAttemptDispositionV1::Integrated {
                winner_count += 1;
                if closure.attempt_id != self.winning_attempt_id
                    || closure.attempt_ordinal != self.winning_attempt_ordinal
                    || closure.lease_id != self.winning_lease_id
                    || closure.lease_epoch != self.winning_lease_epoch
                {
                    return Err(contract_error(
                        "winning_attempt",
                        "integrated closure must equal the exact winning attempt and lease",
                    ));
                }
            }
        }
        if winner_count != 1 {
            return Err(contract_error(
                "attempt_closures",
                "exactly one attempt closure must be Integrated",
            ));
        }
        if self.task_done_proof_id != self.expected_proof_id()? {
            return Err(contract_error(
                "task_done_proof_id",
                "must be derived from the complete exact source body",
            ));
        }
        Ok(())
    }

    /// Returns exact canonical JSON after intrinsic validation.
    ///
    /// # Errors
    ///
    /// Returns a contract error when validation or encoding fails.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, ContractError> {
        self.validate()?;
        serde_json::to_vec(self)
            .map_err(|error| contract_error("source_json", format!("cannot encode: {error}")))
    }

    /// Returns the domain-separated digest of exact canonical source bytes.
    ///
    /// # Errors
    ///
    /// Returns a contract error when validation or encoding fails.
    pub fn canonical_digest(&self) -> Result<Digest, ContractError> {
        let bytes = self.canonical_bytes()?;
        Ok(domain_digest(SOURCE_DIGEST_DOMAIN, &bytes))
    }

    #[cfg(test)]
    fn with_derived_proof_id(mut self) -> Result<Self, ContractError> {
        self.task_done_proof_id = self.expected_proof_id()?;
        self.validate()?;
        Ok(self)
    }

    fn expected_proof_id(&self) -> Result<String, ContractError> {
        #[derive(Serialize)]
        struct Identity<'a> {
            source_version: u32,
            sprint_id: &'a str,
            task_id: &'a str,
            durable_integrated_state_event_id: &'a str,
            winning_attempt_id: &'a str,
            winning_attempt_ordinal: u32,
            winning_lease_id: &'a str,
            winning_lease_epoch: u64,
            integration: &'a CurrentTaskDoneIntegrationSourceV1,
            input_snapshot: &'a Digest,
            result_snapshot: &'a Digest,
            assigned_automated_checks: &'a [CurrentTaskDoneAutomatedCheckV1],
            attempt_closures: &'a [CurrentTaskDoneAttemptClosureV1],
            zero_active_leases_proof_id: &'a str,
            active_lease_count: u32,
            zero_replay_dispatch_authority_proof_id: &'a str,
            replay_dispatch_authority_count: u32,
            derived_at_unix_ms: u64,
        }
        let identity = Identity {
            source_version: self.source_version,
            sprint_id: &self.sprint_id,
            task_id: &self.task_id,
            durable_integrated_state_event_id: &self.durable_integrated_state_event_id,
            winning_attempt_id: &self.winning_attempt_id,
            winning_attempt_ordinal: self.winning_attempt_ordinal,
            winning_lease_id: &self.winning_lease_id,
            winning_lease_epoch: self.winning_lease_epoch,
            integration: &self.integration,
            input_snapshot: &self.input_snapshot,
            result_snapshot: &self.result_snapshot,
            assigned_automated_checks: &self.assigned_automated_checks,
            attempt_closures: &self.attempt_closures,
            zero_active_leases_proof_id: &self.zero_active_leases_proof_id,
            active_lease_count: self.active_lease_count,
            zero_replay_dispatch_authority_proof_id: &self.zero_replay_dispatch_authority_proof_id,
            replay_dispatch_authority_count: self.replay_dispatch_authority_count,
            derived_at_unix_ms: self.derived_at_unix_ms,
        };
        let bytes = serde_json::to_vec(&identity)
            .map_err(|error| contract_error("task_done_proof_id", error.to_string()))?;
        Ok(format!(
            "current-task-done:{}",
            domain_digest(PROOF_ID_DOMAIN, &bytes)
        ))
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct WritePermit {
    sprint_id: String,
    task_id: String,
    proof_id: String,
    source_digest: String,
}

thread_local! {
    static WRITE_PERMIT: RefCell<Option<WritePermit>> = const { RefCell::new(None) };
}

#[cfg(test)]
struct WritePermitGuard;

#[cfg(test)]
impl Drop for WritePermitGuard {
    fn drop(&mut self) {
        WRITE_PERMIT.with(|slot| *slot.borrow_mut() = None);
    }
}

#[cfg(test)]
fn with_write_permit<T>(
    permit: WritePermit,
    operation: impl FnOnce() -> Result<T, LedgerError>,
) -> Result<T, LedgerError> {
    let nested = WRITE_PERMIT.with(|slot| slot.borrow_mut().replace(permit));
    if nested.is_some() {
        WRITE_PERMIT.with(|slot| *slot.borrow_mut() = nested);
        return Err(LedgerError::Corrupt {
            entity: "current TaskDone source write admission",
            detail: "nested source write admission is forbidden".into(),
        });
    }
    let _guard = WritePermitGuard;
    operation()
}

fn write_is_admitted(sprint_id: &str, task_id: &str, proof_id: &str, source_digest: &str) -> i64 {
    WRITE_PERMIT.with(|slot| {
        i64::from(slot.borrow().as_ref().is_some_and(|permit| {
            permit.sprint_id == sprint_id
                && permit.task_id == task_id
                && permit.proof_id == proof_id
                && permit.source_digest == source_digest
        }))
    })
}

/// Registers deterministic source validators and the connection-local writer guard.
///
/// # Errors
///
/// Returns a ledger error when `SQLite` rejects function registration.
#[allow(clippy::too_many_lines)]
pub(super) fn register_schema_functions(connection: &Connection) -> Result<(), LedgerError> {
    connection.create_scalar_function(
        WRITE_ADMISSION_FUNCTION,
        4,
        FunctionFlags::SQLITE_INNOCUOUS,
        |context| {
            Ok(write_is_admitted(
                &context.get::<String>(0)?,
                &context.get::<String>(1)?,
                &context.get::<String>(2)?,
                &context.get::<String>(3)?,
            ))
        },
    )?;
    connection.create_scalar_function(
        "grok_current_task_done_source_canonical_v32",
        21,
        FunctionFlags::SQLITE_DETERMINISTIC | FunctionFlags::SQLITE_INNOCUOUS,
        |context| {
            let bytes = context.get::<Vec<u8>>(0)?;
            let source: CurrentTaskDoneSourceReceiptV1 = serde_json::from_slice(&bytes)
                .map_err(|error| sqlite_user_error(error.to_string()))?;
            source
                .validate()
                .map_err(|error| sqlite_user_error(error.to_string()))?;
            let canonical = serde_json::to_vec(&source)
                .map_err(|error| sqlite_user_error(error.to_string()))?;
            let source_digest = domain_digest(SOURCE_DIGEST_DOMAIN, &canonical);
            let winning_ordinal = u32::try_from(context.get::<i64>(6)?).ok();
            let winning_epoch = u64::try_from(context.get::<i64>(8)?).ok();
            let operation_count = u32::try_from(context.get::<i64>(13)?).ok();
            let active_count = u32::try_from(context.get::<i64>(17)?).ok();
            let replay_count = u32::try_from(context.get::<i64>(19)?).ok();
            let derived_at = u64::try_from(context.get::<i64>(20)?).ok();
            Ok(i64::from(
                canonical == bytes
                    && source_digest.as_str() == context.get::<String>(1)?
                    && source.task_done_proof_id == context.get::<String>(2)?
                    && source.sprint_id == context.get::<String>(3)?
                    && source.task_id == context.get::<String>(4)?
                    && source.winning_attempt_id == context.get::<String>(5)?
                    && Some(source.winning_attempt_ordinal) == winning_ordinal
                    && source.winning_lease_id == context.get::<String>(7)?
                    && Some(source.winning_lease_epoch) == winning_epoch
                    && source.integration.integration_receipt_id() == context.get::<String>(9)?
                    && source.integration.sql_kind() == context.get::<String>(10)?
                    && source.integration.change_set_id()
                        == context.get::<Option<String>>(11)?.as_deref()
                    && source.integration.empty_change_set_id()
                        == context.get::<Option<String>>(12)?.as_deref()
                    && Some(source.integration.operation_count()) == operation_count
                    && source.input_snapshot.as_str() == context.get::<String>(14)?
                    && source.result_snapshot.as_str() == context.get::<String>(15)?
                    && source.zero_active_leases_proof_id == context.get::<String>(16)?
                    && Some(source.active_lease_count) == active_count
                    && source.zero_replay_dispatch_authority_proof_id
                        == context.get::<String>(18)?
                    && Some(source.replay_dispatch_authority_count) == replay_count
                    && Some(source.derived_at_unix_ms) == derived_at,
            ))
        },
    )?;
    connection.create_scalar_function(
        "grok_current_task_done_source_matches_task_v32",
        3,
        FunctionFlags::SQLITE_DETERMINISTIC | FunctionFlags::SQLITE_INNOCUOUS,
        |context| {
            let source_bytes = context.get::<Vec<u8>>(0)?;
            let task_bytes = context.get::<Vec<u8>>(1)?;
            let spec_bytes = context.get::<Vec<u8>>(2)?;
            let source: CurrentTaskDoneSourceReceiptV1 = serde_json::from_slice(&source_bytes)
                .map_err(|error| sqlite_user_error(error.to_string()))?;
            source
                .validate()
                .map_err(|error| sqlite_user_error(error.to_string()))?;
            let task: TaskSpecV2 = serde_json::from_slice(&task_bytes)
                .map_err(|error| sqlite_user_error(error.to_string()))?;
            if serde_json::to_vec(&task).map_err(|error| sqlite_user_error(error.to_string()))?
                != task_bytes
            {
                return Ok(0_i64);
            }
            let spec = SprintSpecV2::from_canonical_bytes(&spec_bytes)
                .map_err(|error| sqlite_user_error(error.to_string()))?;
            Ok(i64::from(
                validate_source_for_task(&source, &spec, &task).is_ok(),
            ))
        },
    )?;
    Ok(())
}

impl EventLedger {
    /// Loads and revalidates one exact dormant current `TaskDone` source.
    ///
    /// This method grants no attempt, integration, dispatch, or completion
    /// authority.
    ///
    /// # Errors
    ///
    /// Returns a ledger error when the source is absent, noncanonical,
    /// non-content-addressed, crossed with its task, or projection-incomplete.
    pub fn load_current_task_done_source_v32(
        &self,
        task_done_proof_id: &str,
    ) -> Result<CurrentTaskDoneSourceReceiptV1, LedgerError> {
        load_current_task_done_source_from(&self.connection, task_done_proof_id)
    }
}

pub(super) fn load_current_task_done_source_from(
    connection: &Connection,
    task_done_proof_id: &str,
) -> Result<CurrentTaskDoneSourceReceiptV1, LedgerError> {
    let stored = connection
        .query_row(
            "SELECT source_digest, sprint_id, task_id, winning_attempt_id,
                    winning_attempt_ordinal, winning_lease_id, winning_lease_epoch,
                    integration_receipt_id, integration_kind, change_set_id,
                    empty_change_set_id, operation_count, input_snapshot,
                    result_snapshot, zero_active_leases_proof_id,
                    active_lease_count, zero_replay_dispatch_authority_proof_id,
                    replay_dispatch_authority_count, derived_at_unix_ms, source_json
             FROM current_task_done_sources_v32 WHERE task_done_proof_id = ?1",
            [task_done_proof_id],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, i64>(4)?,
                    row.get::<_, String>(5)?,
                    row.get::<_, i64>(6)?,
                    row.get::<_, String>(7)?,
                    row.get::<_, String>(8)?,
                    row.get::<_, Option<String>>(9)?,
                    row.get::<_, Option<String>>(10)?,
                    row.get::<_, i64>(11)?,
                    row.get::<_, String>(12)?,
                    row.get::<_, String>(13)?,
                    row.get::<_, String>(14)?,
                    row.get::<_, i64>(15)?,
                    row.get::<_, String>(16)?,
                    row.get::<_, i64>(17)?,
                    row.get::<_, i64>(18)?,
                    row.get::<_, Vec<u8>>(19)?,
                ))
            },
        )
        .optional()?
        .ok_or_else(|| LedgerError::ArtifactNotFound {
            entity: "current TaskDone source v32",
            id: task_done_proof_id.to_owned(),
        })?;
    let source: CurrentTaskDoneSourceReceiptV1 =
        decode_stored("current TaskDone source v32", &stored.19)?;
    source.validate()?;
    if encode("current TaskDone source v32", &source)? != stored.19
        || source.canonical_digest()?.as_str() != stored.0
        || source.task_done_proof_id != task_done_proof_id
        || source.sprint_id != stored.1
        || source.task_id != stored.2
        || source.winning_attempt_id != stored.3
        || i64::from(source.winning_attempt_ordinal) != stored.4
        || source.winning_lease_id != stored.5
        || i64::try_from(source.winning_lease_epoch).ok() != Some(stored.6)
        || source.integration.integration_receipt_id() != stored.7
        || source.integration.sql_kind() != stored.8
        || source.integration.change_set_id() != stored.9.as_deref()
        || source.integration.empty_change_set_id() != stored.10.as_deref()
        || i64::from(source.integration.operation_count()) != stored.11
        || source.input_snapshot.as_str() != stored.12
        || source.result_snapshot.as_str() != stored.13
        || source.zero_active_leases_proof_id != stored.14
        || i64::from(source.active_lease_count) != stored.15
        || source.zero_replay_dispatch_authority_proof_id != stored.16
        || i64::from(source.replay_dispatch_authority_count) != stored.17
        || source.derived_at_unix_ms
            != unsigned_integer("current TaskDone source derived_at", stored.18)?
    {
        return Err(LedgerError::Corrupt {
            entity: "current TaskDone source v32",
            detail: "canonical JSON, digest, or indexed projection differs".into(),
        });
    }
    let (spec_bytes, task_bytes): (Vec<u8>, Vec<u8>) = connection
        .query_row(
            "SELECT sprint.spec_json, task.task_json
             FROM current_sprint_authorities_v32 sprint
             JOIN current_task_nodes_v32 task ON task.sprint_id = sprint.sprint_id
             WHERE sprint.sprint_id = ?1 AND task.task_id = ?2",
            params![source.sprint_id, source.task_id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()?
        .ok_or_else(|| LedgerError::ReferenceMismatch {
            entity: "current TaskDone source v32",
            detail: "source task is absent from its exact current sprint".into(),
        })?;
    let spec = SprintSpecV2::from_canonical_bytes(&spec_bytes)?;
    let task: TaskSpecV2 = decode_stored("current TaskDone source task", &task_bytes)?;
    validate_source_for_task(&source, &spec, &task)?;
    Ok(source)
}

fn validate_source_for_task(
    source: &CurrentTaskDoneSourceReceiptV1,
    spec: &SprintSpecV2,
    task: &TaskSpecV2,
) -> Result<(), ContractError> {
    source.validate()?;
    if source.sprint_id != spec.sprint_id || source.task_id != task.task_id {
        return Err(contract_error(
            "source_task",
            "source must name the exact current sprint and task",
        ));
    }
    let expected = task
        .acceptance_checks
        .iter()
        .filter(|criterion_id| {
            spec.acceptance_criteria.iter().any(|criterion| {
                criterion.criterion_id == criterion_id.as_str()
                    && matches!(criterion.kind, AcceptanceKind::Automated(_))
            })
        })
        .map(String::as_str)
        .collect::<Vec<_>>();
    let actual = source
        .assigned_automated_checks
        .iter()
        .map(|check| check.criterion_id.as_str())
        .collect::<Vec<_>>();
    if actual != expected {
        return Err(contract_error(
            "assigned_automated_checks",
            "must equal every assigned automated criterion in task declaration order",
        ));
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::too_many_lines)] // The fixture explicitly fills every indivisible TaskDone source term for adversarial joins.
pub(super) fn test_source_for_member(
    sprint: &SprintSpecV2,
    graph: &TaskGraphV2,
    member: &CurrentTaskDoneMemberV1,
) -> Result<CurrentTaskDoneSourceReceiptV1, LedgerError> {
    let task = graph
        .tasks
        .iter()
        .find(|task| task.task_id == member.task_id)
        .ok_or_else(|| LedgerError::ReferenceMismatch {
            entity: "test current TaskDone source",
            detail: "member task is absent from graph".into(),
        })?;
    let attempt_ordinal = 1;
    let lease_epoch = u64::from(member.source_ordinal) + 1;
    let attempt_id = format!(
        "test-current-attempt:{}:{}:{}",
        sprint.sprint_id, member.task_id, attempt_ordinal
    );
    let integration = match &member.integration_evidence {
        CurrentTaskDoneIntegrationEvidenceV1::Changed => {
            CurrentTaskDoneIntegrationSourceV1::Changed {
                integration_receipt_id: member.integration_receipt_id.clone(),
                change_set_id: format!("test-change-set:{}", member.integration_receipt_id),
                operation_count: 1,
            }
        }
        CurrentTaskDoneIntegrationEvidenceV1::VerifiedNoOp {
            empty_change_set_id,
        } => CurrentTaskDoneIntegrationSourceV1::VerifiedNoOp {
            integration_receipt_id: member.integration_receipt_id.clone(),
            empty_change_set_id: empty_change_set_id.clone(),
        },
    };
    let assigned_automated_checks = task
        .acceptance_checks
        .iter()
        .filter(|criterion_id| {
            sprint.acceptance_criteria.iter().any(|criterion| {
                criterion.criterion_id == criterion_id.as_str()
                    && matches!(criterion.kind, AcceptanceKind::Automated(_))
            })
        })
        .map(|criterion_id| CurrentTaskDoneAutomatedCheckV1 {
            criterion_id: criterion_id.clone(),
            verification_receipt_id: format!(
                "test-task-check:{}:{}:{}:{}",
                sprint.sprint_id, member.task_id, criterion_id, member.result_snapshot
            ),
            snapshot_digest: member.result_snapshot.clone(),
        })
        .collect();
    let derived_at_unix_ms = if member.task_id.starts_with("repair-") {
        59
    } else {
        19
    };
    CurrentTaskDoneSourceReceiptV1 {
        source_version: SOURCE_VERSION_V1,
        task_done_proof_id: "pending".into(),
        sprint_id: sprint.sprint_id.clone(),
        task_id: member.task_id.clone(),
        durable_integrated_state_event_id: format!(
            "test-task-integrated-state:{}:{}",
            sprint.sprint_id, member.task_id
        ),
        winning_attempt_id: attempt_id.clone(),
        winning_attempt_ordinal: attempt_ordinal,
        winning_lease_id: attempt_id.clone(),
        winning_lease_epoch: lease_epoch,
        integration,
        input_snapshot: member.input_snapshot.clone(),
        result_snapshot: member.result_snapshot.clone(),
        assigned_automated_checks,
        attempt_closures: vec![CurrentTaskDoneAttemptClosureV1 {
            attempt_id: attempt_id.clone(),
            attempt_ordinal,
            lease_id: attempt_id,
            lease_epoch,
            disposition_id: format!(
                "test-disposition:{}:{}:{}",
                sprint.sprint_id, member.task_id, attempt_ordinal
            ),
            disposition: CurrentTaskDoneAttemptDispositionV1::Integrated,
            terminal_effect_closure_set_id: format!(
                "test-terminal-effects:{}:{}:{}",
                sprint.sprint_id, member.task_id, attempt_ordinal
            ),
            output_capture_closure_set_id: format!(
                "test-output-captures:{}:{}:{}",
                sprint.sprint_id, member.task_id, attempt_ordinal
            ),
            runner_cleanup_closure_set_id: format!(
                "test-runner-cleanup:{}:{}:{}",
                sprint.sprint_id, member.task_id, attempt_ordinal
            ),
            command_domain_cleanup_closure_set_id: format!(
                "test-command-cleanup:{}:{}:{}",
                sprint.sprint_id, member.task_id, attempt_ordinal
            ),
            lease_release_id: format!(
                "test-lease-release:{}:{}:{}",
                sprint.sprint_id, member.task_id, attempt_ordinal
            ),
        }],
        zero_active_leases_proof_id: format!(
            "test-zero-leases:{}:{}",
            sprint.sprint_id, member.task_id
        ),
        active_lease_count: 0,
        zero_replay_dispatch_authority_proof_id: format!(
            "test-zero-replay:{}:{}",
            sprint.sprint_id, member.task_id
        ),
        replay_dispatch_authority_count: 0,
        derived_at_unix_ms,
    }
    .with_derived_proof_id()
    .map_err(LedgerError::from)
}

#[cfg(test)]
pub(super) fn test_seed_sources_for_set(
    transaction: &rusqlite::Transaction<'_>,
    sprint: &SprintSpecV2,
    graph: &TaskGraphV2,
    set: &CompleteTaskDoneSetV1,
) -> Result<(), LedgerError> {
    for member in &set.members {
        let source = test_source_for_member(sprint, graph, member)?;
        if source.task_done_proof_id != member.task_done_proof_id {
            return Err(LedgerError::ReferenceMismatch {
                entity: "test current TaskDone source",
                detail: "member proof identity differs from exact seeded source".into(),
            });
        }
        match load_current_task_done_source_from(transaction, &source.task_done_proof_id) {
            Ok(existing) if existing == source => continue,
            Ok(_) => {
                return Err(LedgerError::ReferenceMismatch {
                    entity: "test current TaskDone source",
                    detail: "proof identity already names different source bytes".into(),
                });
            }
            Err(LedgerError::ArtifactNotFound { .. }) => {}
            Err(error) => return Err(error),
        }
        let source_digest = source.canonical_digest()?;
        let permit = WritePermit {
            sprint_id: source.sprint_id.clone(),
            task_id: source.task_id.clone(),
            proof_id: source.task_done_proof_id.clone(),
            source_digest: source_digest.to_string(),
        };
        with_write_permit(permit, || {
            insert_source(transaction, &source, &source_digest)
        })?;
        let readback = load_current_task_done_source_from(transaction, &source.task_done_proof_id)?;
        if readback != source {
            return Err(LedgerError::Corrupt {
                entity: "test current TaskDone source",
                detail: "transactional source readback differs".into(),
            });
        }
    }
    Ok(())
}

#[cfg(test)]
pub(super) fn test_insert_source_without_permit(
    connection: &Connection,
    source: &CurrentTaskDoneSourceReceiptV1,
) -> Result<(), LedgerError> {
    let source_digest = source.canonical_digest()?;
    insert_source(connection, source, &source_digest)
}

#[cfg(test)]
fn insert_source(
    connection: &Connection,
    source: &CurrentTaskDoneSourceReceiptV1,
    source_digest: &Digest,
) -> Result<(), LedgerError> {
    connection.execute(
        "INSERT INTO current_task_done_sources_v32 (
            task_done_proof_id, source_digest, sprint_id, task_id,
            winning_attempt_id, winning_attempt_ordinal, winning_lease_id,
            winning_lease_epoch, integration_receipt_id, integration_kind,
            change_set_id, empty_change_set_id, operation_count,
            input_snapshot, result_snapshot, zero_active_leases_proof_id,
            active_lease_count, zero_replay_dispatch_authority_proof_id,
            replay_dispatch_authority_count, derived_at_unix_ms, source_json
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11,
                   ?12, ?13, ?14, ?15, ?16, ?17, ?18, ?19, ?20, ?21)",
        params![
            source.task_done_proof_id,
            source_digest.as_str(),
            source.sprint_id,
            source.task_id,
            source.winning_attempt_id,
            i64::from(source.winning_attempt_ordinal),
            source.winning_lease_id,
            sqlite_integer(
                "test TaskDone source lease epoch",
                source.winning_lease_epoch
            )?,
            source.integration.integration_receipt_id(),
            source.integration.sql_kind(),
            source.integration.change_set_id(),
            source.integration.empty_change_set_id(),
            i64::from(source.integration.operation_count()),
            source.input_snapshot.as_str(),
            source.result_snapshot.as_str(),
            source.zero_active_leases_proof_id,
            i64::from(source.active_lease_count),
            source.zero_replay_dispatch_authority_proof_id,
            i64::from(source.replay_dispatch_authority_count),
            sqlite_integer("test TaskDone source derived_at", source.derived_at_unix_ms)?,
            source.canonical_bytes()?,
        ],
    )?;
    Ok(())
}

fn domain_digest(domain: &[u8], bytes: &[u8]) -> Digest {
    let mut preimage = Vec::with_capacity(domain.len() + bytes.len());
    preimage.extend_from_slice(domain);
    preimage.extend_from_slice(bytes);
    Digest::sha256(&preimage)
}

fn require_nonblank(field: &'static str, value: &str) -> Result<(), ContractError> {
    if value.trim().is_empty() || value.len() > 4096 {
        Err(contract_error(field, "must contain 1..=4096 UTF-8 bytes"))
    } else {
        Ok(())
    }
}

fn contract_error(field: &'static str, detail: impl Into<String>) -> ContractError {
    ContractError::new(field, detail)
}

fn sqlite_user_error(detail: impl Into<String>) -> rusqlite::Error {
    rusqlite::Error::UserFunctionError(Box::new(std::io::Error::new(
        std::io::ErrorKind::InvalidData,
        detail.into(),
    )))
}
