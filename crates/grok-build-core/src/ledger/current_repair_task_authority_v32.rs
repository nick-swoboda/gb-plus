//! Inert schema-v32 repair-task readiness, lease, and attempt authority.
//!
//! These records close the SQL dormancy fence without connecting V2 tasks to
//! the production coordinator. The first repair-task attempt is the only
//! admitted shape; retries remain closed until current task terminal/cleanup
//! sources can prove that a preceding attempt released all authority.

use rusqlite::Connection;
use rusqlite::functions::FunctionFlags;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

#[cfg(test)]
use crate::CurrentRepairActivationPermitV1;
use crate::{ContractError, Digest, TaskAttempt, TaskState, WorkerLease};

use super::LedgerError;

pub(super) const MIGRATION_V32: &str = include_str!("current_repair_task_authority_v32.sql");

const AUTHORITY_VERSION_V1: u32 = 1;
const READY_ID_DOMAIN: &[u8] = b"grok-build/current-repair-ready-event-v1/id\0";
const LEASE_ID_DOMAIN: &[u8] = b"grok-build/current-repair-lease-admission-v1/id\0";
const ATTEMPT_ID_DOMAIN: &[u8] = b"grok-build/current-repair-attempt-admission-v1/id\0";

#[derive(Serialize)]
struct ReadyIdentity<'a> {
    event_version: u32,
    activation_id: &'a str,
    sprint_id: &'a str,
    task_id: &'a str,
    slot_ordinal: u8,
    from_state: TaskState,
    to_state: TaskState,
    occurred_at_unix_ms: u64,
}

/// Exact `Planned -> Ready` event for one activated repair slot.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct CurrentRepairTaskReadyEventV1 {
    /// Closed contract version.
    pub event_version: u32,
    /// Content-derived event identity.
    pub event_id: String,
    /// Exact durable repair activation.
    pub activation_id: String,
    /// Owning current sprint.
    pub sprint_id: String,
    /// Exact predeclared repair task.
    pub task_id: String,
    /// One-based repair-slot ordinal.
    pub slot_ordinal: u8,
    /// Must be `Planned`.
    pub from_state: TaskState,
    /// Must be `Ready`.
    pub to_state: TaskState,
    /// Durable transition time.
    pub occurred_at_unix_ms: u64,
}

impl CurrentRepairTaskReadyEventV1 {
    #[cfg(test)]
    fn mint(
        permit: &CurrentRepairActivationPermitV1,
        occurred_at_unix_ms: u64,
    ) -> Result<Self, ContractError> {
        let identity = ReadyIdentity {
            event_version: AUTHORITY_VERSION_V1,
            activation_id: permit.activation_id(),
            sprint_id: permit.sprint_id(),
            task_id: permit.repair_task_id(),
            slot_ordinal: permit.slot_ordinal(),
            from_state: TaskState::Planned,
            to_state: TaskState::Ready,
            occurred_at_unix_ms,
        };
        let event = Self {
            event_version: AUTHORITY_VERSION_V1,
            event_id: mint_identity(READY_ID_DOMAIN, &identity)?,
            activation_id: permit.activation_id().to_owned(),
            sprint_id: permit.sprint_id().to_owned(),
            task_id: permit.repair_task_id().to_owned(),
            slot_ordinal: permit.slot_ordinal(),
            from_state: TaskState::Planned,
            to_state: TaskState::Ready,
            occurred_at_unix_ms,
        };
        event.validate()?;
        Ok(event)
    }

    /// Validates the closed transition shape and content-derived identity.
    ///
    /// # Errors
    ///
    /// Returns a contract error for a malformed, unbounded, or caller-chosen
    /// event. Durable activation membership is checked by the ledger/SQL cut.
    pub fn validate(&self) -> Result<(), ContractError> {
        require_version(
            "current_repair_ready_event.event_version",
            self.event_version,
        )?;
        require_identity("current_repair_ready_event.event_id", &self.event_id, true)?;
        require_identity(
            "current_repair_ready_event.activation_id",
            &self.activation_id,
            false,
        )?;
        require_identity(
            "current_repair_ready_event.sprint_id",
            &self.sprint_id,
            false,
        )?;
        require_identity("current_repair_ready_event.task_id", &self.task_id, false)?;
        require_slot(self.slot_ordinal)?;
        if self.from_state != TaskState::Planned || self.to_state != TaskState::Ready {
            return Err(contract_error(
                "current_repair_ready_event.state",
                "must represent exactly Planned -> Ready",
            ));
        }
        require_time(
            "current_repair_ready_event.occurred_at_unix_ms",
            self.occurred_at_unix_ms,
        )?;
        let expected = mint_identity(
            READY_ID_DOMAIN,
            &ReadyIdentity {
                event_version: self.event_version,
                activation_id: &self.activation_id,
                sprint_id: &self.sprint_id,
                task_id: &self.task_id,
                slot_ordinal: self.slot_ordinal,
                from_state: self.from_state,
                to_state: self.to_state,
                occurred_at_unix_ms: self.occurred_at_unix_ms,
            },
        )?;
        if self.event_id != expected {
            return Err(contract_error(
                "current_repair_ready_event.event_id",
                "must equal the content-derived event identity",
            ));
        }
        Ok(())
    }
}

#[derive(Serialize)]
struct LeaseIdentity<'a> {
    admission_version: u32,
    activation_id: &'a str,
    ready_event_id: &'a str,
    sprint_id: &'a str,
    task_id: &'a str,
    slot_ordinal: u8,
    worker_lease: &'a WorkerLease,
}

/// Exact first lease admission for one activated repair slot.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct CurrentRepairTaskLeaseAdmissionV1 {
    /// Closed contract version.
    pub admission_version: u32,
    /// Content-derived admission identity.
    pub lease_admission_id: String,
    /// Exact durable repair activation.
    pub activation_id: String,
    /// Exact preceding repair readiness event.
    pub ready_event_id: String,
    /// Owning sprint.
    pub sprint_id: String,
    /// Exact repair task.
    pub task_id: String,
    /// One-based repair slot.
    pub slot_ordinal: u8,
    /// Complete canonical lease, including exact task scopes.
    pub worker_lease: WorkerLease,
}

impl CurrentRepairTaskLeaseAdmissionV1 {
    #[cfg(test)]
    fn mint(
        permit: &CurrentRepairActivationPermitV1,
        ready: &CurrentRepairTaskReadyEventV1,
        worker_lease: WorkerLease,
    ) -> Result<Self, ContractError> {
        let identity = LeaseIdentity {
            admission_version: AUTHORITY_VERSION_V1,
            activation_id: permit.activation_id(),
            ready_event_id: &ready.event_id,
            sprint_id: permit.sprint_id(),
            task_id: permit.repair_task_id(),
            slot_ordinal: permit.slot_ordinal(),
            worker_lease: &worker_lease,
        };
        let admission = Self {
            admission_version: AUTHORITY_VERSION_V1,
            lease_admission_id: mint_identity(LEASE_ID_DOMAIN, &identity)?,
            activation_id: permit.activation_id().to_owned(),
            ready_event_id: ready.event_id.clone(),
            sprint_id: permit.sprint_id().to_owned(),
            task_id: permit.repair_task_id().to_owned(),
            slot_ordinal: permit.slot_ordinal(),
            worker_lease,
        };
        admission.validate()?;
        Ok(admission)
    }

    /// Validates intrinsic identity and exact lease linkage.
    ///
    /// # Errors
    ///
    /// Returns a contract error for invalid or crossed canonical members.
    pub fn validate(&self) -> Result<(), ContractError> {
        require_version(
            "current_repair_lease_admission.admission_version",
            self.admission_version,
        )?;
        require_identity(
            "current_repair_lease_admission.lease_admission_id",
            &self.lease_admission_id,
            true,
        )?;
        for (field, value) in [
            (
                "current_repair_lease_admission.activation_id",
                self.activation_id.as_str(),
            ),
            (
                "current_repair_lease_admission.ready_event_id",
                self.ready_event_id.as_str(),
            ),
            (
                "current_repair_lease_admission.sprint_id",
                self.sprint_id.as_str(),
            ),
            (
                "current_repair_lease_admission.task_id",
                self.task_id.as_str(),
            ),
        ] {
            require_identity(field, value, false)?;
        }
        require_slot(self.slot_ordinal)?;
        self.worker_lease.validate()?;
        if self.worker_lease.sprint_id != self.sprint_id
            || self.worker_lease.task_id != self.task_id
        {
            return Err(contract_error(
                "current_repair_lease_admission.worker_lease",
                "must belong to the exact repair sprint and task",
            ));
        }
        let expected = mint_identity(
            LEASE_ID_DOMAIN,
            &LeaseIdentity {
                admission_version: self.admission_version,
                activation_id: &self.activation_id,
                ready_event_id: &self.ready_event_id,
                sprint_id: &self.sprint_id,
                task_id: &self.task_id,
                slot_ordinal: self.slot_ordinal,
                worker_lease: &self.worker_lease,
            },
        )?;
        if self.lease_admission_id != expected {
            return Err(contract_error(
                "current_repair_lease_admission.lease_admission_id",
                "must equal the content-derived admission identity",
            ));
        }
        Ok(())
    }
}

#[derive(Serialize)]
struct AttemptIdentity<'a> {
    admission_version: u32,
    activation_id: &'a str,
    ready_event_id: &'a str,
    lease_admission_id: &'a str,
    sprint_id: &'a str,
    task_id: &'a str,
    slot_ordinal: u8,
    task_attempt: &'a TaskAttempt,
}

/// Exact first task-attempt admission for one activated repair slot.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct CurrentRepairTaskAttemptAdmissionV1 {
    /// Closed contract version.
    pub admission_version: u32,
    /// Content-derived admission identity.
    pub attempt_admission_id: String,
    /// Exact durable activation.
    pub activation_id: String,
    /// Exact readiness event.
    pub ready_event_id: String,
    /// Exact lease admission.
    pub lease_admission_id: String,
    /// Owning sprint.
    pub sprint_id: String,
    /// Exact repair task.
    pub task_id: String,
    /// One-based repair slot.
    pub slot_ordinal: u8,
    /// Complete canonical first attempt.
    pub task_attempt: TaskAttempt,
}

impl CurrentRepairTaskAttemptAdmissionV1 {
    #[cfg(test)]
    fn mint(
        permit: &CurrentRepairActivationPermitV1,
        ready: &CurrentRepairTaskReadyEventV1,
        lease: &CurrentRepairTaskLeaseAdmissionV1,
    ) -> Result<Self, ContractError> {
        let task_attempt = TaskAttempt::new(
            lease.worker_lease.clone(),
            1,
            lease.lease_admission_id.clone(),
        )?;
        let identity = AttemptIdentity {
            admission_version: AUTHORITY_VERSION_V1,
            activation_id: permit.activation_id(),
            ready_event_id: &ready.event_id,
            lease_admission_id: &lease.lease_admission_id,
            sprint_id: permit.sprint_id(),
            task_id: permit.repair_task_id(),
            slot_ordinal: permit.slot_ordinal(),
            task_attempt: &task_attempt,
        };
        let admission = Self {
            admission_version: AUTHORITY_VERSION_V1,
            attempt_admission_id: mint_identity(ATTEMPT_ID_DOMAIN, &identity)?,
            activation_id: permit.activation_id().to_owned(),
            ready_event_id: ready.event_id.clone(),
            lease_admission_id: lease.lease_admission_id.clone(),
            sprint_id: permit.sprint_id().to_owned(),
            task_id: permit.repair_task_id().to_owned(),
            slot_ordinal: permit.slot_ordinal(),
            task_attempt,
        };
        admission.validate()?;
        Ok(admission)
    }

    /// Validates intrinsic identity and exact attempt-to-lease linkage.
    ///
    /// # Errors
    ///
    /// Returns a contract error for invalid or crossed canonical members.
    pub fn validate(&self) -> Result<(), ContractError> {
        require_version(
            "current_repair_attempt_admission.admission_version",
            self.admission_version,
        )?;
        require_identity(
            "current_repair_attempt_admission.attempt_admission_id",
            &self.attempt_admission_id,
            true,
        )?;
        for (field, value) in [
            (
                "current_repair_attempt_admission.activation_id",
                self.activation_id.as_str(),
            ),
            (
                "current_repair_attempt_admission.ready_event_id",
                self.ready_event_id.as_str(),
            ),
            (
                "current_repair_attempt_admission.lease_admission_id",
                self.lease_admission_id.as_str(),
            ),
            (
                "current_repair_attempt_admission.sprint_id",
                self.sprint_id.as_str(),
            ),
            (
                "current_repair_attempt_admission.task_id",
                self.task_id.as_str(),
            ),
        ] {
            require_identity(field, value, false)?;
        }
        require_slot(self.slot_ordinal)?;
        self.task_attempt.validate()?;
        if self.task_attempt.attempt_ordinal != 1
            || self.task_attempt.worker_lease.sprint_id != self.sprint_id
            || self.task_attempt.worker_lease.task_id != self.task_id
            || self.task_attempt.opening_event_id != self.lease_admission_id
        {
            return Err(contract_error(
                "current_repair_attempt_admission.task_attempt",
                "must be the exact first attempt opened by the bound repair lease admission",
            ));
        }
        let expected = mint_identity(
            ATTEMPT_ID_DOMAIN,
            &AttemptIdentity {
                admission_version: self.admission_version,
                activation_id: &self.activation_id,
                ready_event_id: &self.ready_event_id,
                lease_admission_id: &self.lease_admission_id,
                sprint_id: &self.sprint_id,
                task_id: &self.task_id,
                slot_ordinal: self.slot_ordinal,
                task_attempt: &self.task_attempt,
            },
        )?;
        if self.attempt_admission_id != expected {
            return Err(contract_error(
                "current_repair_attempt_admission.attempt_admission_id",
                "must equal the content-derived admission identity",
            ));
        }
        Ok(())
    }
}

pub(super) fn register_schema_functions(connection: &Connection) -> Result<(), LedgerError> {
    for (name, validate) in [
        (
            "grok_current_repair_ready_event_v32_canonical",
            sqlite_ready_canonical as fn(&[u8]) -> Result<i64, String>,
        ),
        (
            "grok_current_repair_lease_admission_v32_canonical",
            sqlite_lease_canonical,
        ),
        (
            "grok_current_repair_attempt_admission_v32_canonical",
            sqlite_attempt_canonical,
        ),
    ] {
        connection.create_scalar_function(
            name,
            1,
            FunctionFlags::SQLITE_DETERMINISTIC | FunctionFlags::SQLITE_INNOCUOUS,
            move |context| {
                let bytes = context.get::<Vec<u8>>(0)?;
                validate(&bytes).map_err(|detail| {
                    rusqlite::Error::UserFunctionError(Box::new(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        detail,
                    )))
                })
            },
        )?;
    }
    Ok(())
}

fn sqlite_ready_canonical(bytes: &[u8]) -> Result<i64, String> {
    canonical_sql::<CurrentRepairTaskReadyEventV1>(bytes, CurrentRepairTaskReadyEventV1::validate)
}

fn sqlite_lease_canonical(bytes: &[u8]) -> Result<i64, String> {
    canonical_sql::<CurrentRepairTaskLeaseAdmissionV1>(
        bytes,
        CurrentRepairTaskLeaseAdmissionV1::validate,
    )
}

fn sqlite_attempt_canonical(bytes: &[u8]) -> Result<i64, String> {
    canonical_sql::<CurrentRepairTaskAttemptAdmissionV1>(
        bytes,
        CurrentRepairTaskAttemptAdmissionV1::validate,
    )
}

fn canonical_sql<T>(
    bytes: &[u8],
    validate: impl FnOnce(&T) -> Result<(), ContractError>,
) -> Result<i64, String>
where
    T: DeserializeOwned + Serialize,
{
    let value: T = serde_json::from_slice(bytes).map_err(|error| error.to_string())?;
    validate(&value).map_err(|error| error.to_string())?;
    let canonical = serde_json::to_vec(&value).map_err(|error| error.to_string())?;
    Ok(i64::from(canonical == bytes))
}

fn mint_identity<T: Serialize + ?Sized>(domain: &[u8], value: &T) -> Result<String, ContractError> {
    let bytes = encode_contract("current repair authority identity", value)?;
    let length = u64::try_from(bytes.len()).map_err(|_| {
        contract_error(
            "current_repair_authority.identity",
            "canonical identity bytes exceed the supported u64 range",
        )
    })?;
    let mut preimage = Vec::with_capacity(domain.len() + 8 + bytes.len());
    preimage.extend_from_slice(domain);
    preimage.extend_from_slice(&length.to_be_bytes());
    preimage.extend_from_slice(&bytes);
    Ok(Digest::sha256(&preimage).to_string())
}

fn encode_contract<T: Serialize + ?Sized>(
    field: &'static str,
    value: &T,
) -> Result<Vec<u8>, ContractError> {
    serde_json::to_vec(value)
        .map_err(|error| contract_error(field, format!("cannot encode canonical JSON: {error}")))
}

fn require_version(field: &'static str, value: u32) -> Result<(), ContractError> {
    if value == AUTHORITY_VERSION_V1 {
        Ok(())
    } else {
        Err(contract_error(field, "must equal version one"))
    }
}

fn require_slot(value: u8) -> Result<(), ContractError> {
    if (1..=2).contains(&value) {
        Ok(())
    } else {
        Err(contract_error(
            "current_repair_authority.slot_ordinal",
            "must be one or two",
        ))
    }
}

fn require_time(field: &'static str, value: u64) -> Result<(), ContractError> {
    if value == 0 {
        Err(contract_error(field, "must be greater than zero"))
    } else {
        Ok(())
    }
}

fn require_identity(
    field: &'static str,
    value: &str,
    exact_digest: bool,
) -> Result<(), ContractError> {
    if value.trim().is_empty() || value.len() > 4096 {
        return Err(contract_error(
            field,
            "must be nonblank and at most 4096 bytes",
        ));
    }
    if exact_digest
        && (value.len() != 64
            || !value
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase()))
    {
        return Err(contract_error(
            field,
            "must be exactly 64 lowercase hexadecimal characters",
        ));
    }
    Ok(())
}

fn contract_error(field: &'static str, message: impl Into<String>) -> ContractError {
    ContractError::new(field, message)
}

#[cfg(test)]
pub(super) fn test_mint_ready(
    permit: &CurrentRepairActivationPermitV1,
    occurred_at_unix_ms: u64,
) -> CurrentRepairTaskReadyEventV1 {
    CurrentRepairTaskReadyEventV1::mint(permit, occurred_at_unix_ms)
        .expect("test repair Ready event must be valid")
}

#[cfg(test)]
pub(super) fn test_remint_ready(value: &mut CurrentRepairTaskReadyEventV1) {
    value.event_id = mint_identity(
        READY_ID_DOMAIN,
        &ReadyIdentity {
            event_version: value.event_version,
            activation_id: &value.activation_id,
            sprint_id: &value.sprint_id,
            task_id: &value.task_id,
            slot_ordinal: value.slot_ordinal,
            from_state: value.from_state,
            to_state: value.to_state,
            occurred_at_unix_ms: value.occurred_at_unix_ms,
        },
    )
    .expect("remint test repair Ready identity");
    value.validate().expect("reminted test Ready event");
}

#[cfg(test)]
pub(super) fn test_mint_lease(
    permit: &CurrentRepairActivationPermitV1,
    ready: &CurrentRepairTaskReadyEventV1,
    worker_lease: WorkerLease,
) -> CurrentRepairTaskLeaseAdmissionV1 {
    CurrentRepairTaskLeaseAdmissionV1::mint(permit, ready, worker_lease)
        .expect("test repair lease admission must be valid")
}

#[cfg(test)]
pub(super) fn test_remint_attempt(value: &mut CurrentRepairTaskAttemptAdmissionV1) {
    value.attempt_admission_id = mint_identity(
        ATTEMPT_ID_DOMAIN,
        &AttemptIdentity {
            admission_version: value.admission_version,
            activation_id: &value.activation_id,
            ready_event_id: &value.ready_event_id,
            lease_admission_id: &value.lease_admission_id,
            sprint_id: &value.sprint_id,
            task_id: &value.task_id,
            slot_ordinal: value.slot_ordinal,
            task_attempt: &value.task_attempt,
        },
    )
    .expect("remint test repair attempt identity");
    value.validate().expect("reminted test attempt admission");
}

#[cfg(test)]
pub(super) fn test_mint_attempt(
    permit: &CurrentRepairActivationPermitV1,
    ready: &CurrentRepairTaskReadyEventV1,
    lease: &CurrentRepairTaskLeaseAdmissionV1,
) -> CurrentRepairTaskAttemptAdmissionV1 {
    CurrentRepairTaskAttemptAdmissionV1::mint(permit, ready, lease)
        .expect("test repair attempt admission must be valid")
}
