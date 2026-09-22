//! The contained-command release subject, added by schema v38.
//!
//! This is deliberately *not* the runner-launch family from v13. That family's
//! subject is a launch: its claim authorizes handing a held child its own
//! image, and its preparation outcome is `HeldChildPrepared`. A contained
//! command is an effect inside a sprint that runs inside a runner which has
//! already been released, and there may be many per launch. Minting a
//! runner-launch claim for one would authorize releasing one process on
//! evidence gathered about another.
//!
//! The runner gains no ledger writer from any of this. Everything here runs
//! desktop-side; the only thing that crosses the boundary is the claim's
//! contents, carried over the existing wire.

use rusqlite::{Connection, OptionalExtension as _, TransactionBehavior};
use serde::{Deserialize, Serialize};

use super::{EventLedger, LedgerError, reference_mismatch};

/// Durable admission for releasing exactly one contained command.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContainedCommandReleaseAdmissionRecord {
    /// Contract version the admission was written under.
    pub contract_version: u32,
    /// Sprint owning the command effect.
    pub sprint_id: String,
    /// The command effect being released. This is the subject.
    pub command_effect_id: String,
    /// The launch whose runner performs the release.
    ///
    /// Recorded so a claim minted for one runner can be refused when presented
    /// by another. It is not the subject: two commands in one runner share it.
    pub launch_id: String,
    /// Digest of the exact contained-command request this admits.
    pub request_digest: String,
    /// The desktop's own preparation evidence digest for this command.
    ///
    /// This is the one value in the claim the runner cannot derive for itself.
    /// `native_launch` comes from the domain's own journal, which the runner
    /// wrote, and the held-preparation evidence is a function of that record --
    /// but the outer evidence is the desktop's, and a runner that invented it
    /// would be authorizing its own release. So it is exactly what has to
    /// cross the boundary, and it is the reason the claim exists rather than
    /// the runner simply reading its own journal.
    pub native_evidence_digest: String,
    /// Backend that will host the command.
    pub platform_backend: String,
    /// Wall-clock admission time, milliseconds since the Unix epoch.
    pub admitted_at_unix_ms: i64,
}

/// One durably admitted contained-command release, as read back.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PersistedContainedCommandReleaseAdmission {
    /// The admission record itself.
    pub admission: ContainedCommandReleaseAdmissionRecord,
}

/// Callback-scoped proof that a contained command's release is admitted,
/// unreleased, and exclusively held.
///
/// Like [`super::LiveRunnerLaunchReleaseClaim`] this is expected state rather
/// than a handle, and it deliberately borrows: it cannot outlive the exclusion
/// that made it true. A runner receiving its contents must still enforce its
/// own durable one-shot release journal -- this authorizes a release, it does
/// not perform or remember one.
pub struct LiveContainedCommandReleaseClaim<'a> {
    admission: &'a PersistedContainedCommandReleaseAdmission,
}

impl LiveContainedCommandReleaseClaim<'_> {
    /// The exact revalidated admission this claim was minted from.
    #[must_use]
    pub const fn admission(&self) -> &PersistedContainedCommandReleaseAdmission {
        self.admission
    }

    /// The command effect this claim is about.
    #[must_use]
    pub fn command_effect_id(&self) -> &str {
        &self.admission.admission.command_effect_id
    }

    /// Digest of the request this claim admits, which the runner must require
    /// the plan it is about to release to reproduce.
    #[must_use]
    pub fn request_digest(&self) -> &str {
        &self.admission.admission.request_digest
    }

    /// The desktop's preparation evidence digest for this command.
    #[must_use]
    pub fn native_evidence_digest(&self) -> &str {
        &self.admission.admission.native_evidence_digest
    }
}

/// Terminal disposition reported back after a release attempt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ContainedCommandReleaseDisposition {
    /// The runner observed a same-PID exec under the plan's own containment
    /// artefacts, and the command reached this terminal.
    Released {
        /// Serialized backend termination.
        terminal_json: Vec<u8>,
    },
    /// No release happened, for this reason.
    Refused {
        /// Why the release did not happen.
        reason: String,
    },
}

pub(super) fn load_admission(
    connection: &Connection,
    sprint_id: &str,
    command_effect_id: &str,
) -> Result<Option<PersistedContainedCommandReleaseAdmission>, LedgerError> {
    let row = connection
        .query_row(
            "SELECT admission_json FROM contained_command_release_admissions \
             WHERE sprint_id = ?1 AND command_effect_id = ?2",
            (sprint_id, command_effect_id),
            |row| row.get::<_, Vec<u8>>(0),
        )
        .optional()?;
    let Some(bytes) = row else {
        return Ok(None);
    };
    let admission: ContainedCommandReleaseAdmissionRecord = serde_json::from_slice(&bytes)
        .map_err(|error| LedgerError::Corrupt {
            entity: "contained command release admission",
            detail: error.to_string(),
        })?;
    Ok(Some(PersistedContainedCommandReleaseAdmission {
        admission,
    }))
}

fn outcome_exists(
    connection: &Connection,
    sprint_id: &str,
    command_effect_id: &str,
) -> Result<bool, LedgerError> {
    let found: Option<i64> = connection
        .query_row(
            "SELECT 1 FROM contained_command_release_outcomes \
             WHERE sprint_id = ?1 AND command_effect_id = ?2",
            (sprint_id, command_effect_id),
            |row| row.get(0),
        )
        .optional()?;
    Ok(found.is_some())
}

impl EventLedger {
    /// Durably admits exactly one contained command for release.
    ///
    /// The desktop is the only writer, and this is the only writer at all: the
    /// v38 subject was landed with a reader and an exclusion but no way to
    /// create a row, so the exclusion could never have succeeded in production.
    ///
    /// The insert is deliberately not an upsert. An admission is a decision
    /// about one command effect, and a second decision about the same effect is
    /// a defect rather than an update -- the primary key refuses it, and the
    /// refusal is the point.
    ///
    /// The foreign key onto `effect_intents` means an admission cannot be
    /// written for an effect that does not exist, so an admission can never
    /// name a command the ledger has no record of.
    ///
    /// # Errors
    ///
    /// When the ledger is read-only, when the record does not validate, when no
    /// such effect intent exists, or when this command effect is already
    /// admitted.
    pub fn record_contained_command_release_admission(
        &mut self,
        record: &ContainedCommandReleaseAdmissionRecord,
    ) -> Result<PersistedContainedCommandReleaseAdmission, LedgerError> {
        self.require_writable()?;
        if record.contract_version == 0 {
            return Err(reference_mismatch(
                "contained command release admission",
                "contract version must be positive",
            ));
        }
        if record.admitted_at_unix_ms <= 0 {
            return Err(reference_mismatch(
                "contained command release admission",
                "admission timestamp must be positive",
            ));
        }
        if record.request_digest.len() != 64
            || !record
                .request_digest
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        {
            return Err(reference_mismatch(
                "contained command release admission",
                "request digest must be 64 lowercase hex characters",
            ));
        }
        if record.native_evidence_digest.len() != 64
            || !record
                .native_evidence_digest
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        {
            return Err(reference_mismatch(
                "contained command release admission",
                "native evidence digest must be 64 lowercase hex characters",
            ));
        }
        let admission_json = serde_json::to_vec(record).map_err(|error| LedgerError::Corrupt {
            entity: "contained command release admission",
            detail: error.to_string(),
        })?;

        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        transaction.execute(
            "INSERT INTO contained_command_release_admissions (
                 command_effect_id, sprint_id, launch_id, request_digest,
                 platform_backend, contract_version, admitted_at_unix_ms, admission_json
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            rusqlite::params![
                &record.command_effect_id,
                &record.sprint_id,
                &record.launch_id,
                &record.request_digest,
                &record.platform_backend,
                i64::from(record.contract_version),
                record.admitted_at_unix_ms,
                &admission_json,
            ],
        )?;
        transaction.commit()?;
        Ok(PersistedContainedCommandReleaseAdmission {
            admission: record.clone(),
        })
    }

    /// Records the one terminal disposition for an admitted command.
    ///
    /// Write-once, enforced by the schema's own `BEFORE UPDATE` trigger as well
    /// as by the primary key: the release is one-shot on the runner side and it
    /// is one-shot here.
    ///
    /// # Errors
    ///
    /// When the ledger is read-only, when no admission exists for this command
    /// effect, or when an outcome is already recorded.
    pub fn record_contained_command_release_outcome(
        &mut self,
        sprint_id: &str,
        command_effect_id: &str,
        disposition: &ContainedCommandReleaseDisposition,
        recorded_at_unix_ms: i64,
    ) -> Result<(), LedgerError> {
        self.require_writable()?;
        if recorded_at_unix_ms <= 0 {
            return Err(reference_mismatch(
                "contained command release outcome",
                "outcome timestamp must be positive",
            ));
        }
        let (label, terminal, reason) = match disposition {
            ContainedCommandReleaseDisposition::Released { terminal_json } => {
                ("Released", Some(terminal_json.clone()), None)
            }
            ContainedCommandReleaseDisposition::Refused { reason } => {
                ("Refused", None, Some(reason.clone()))
            }
        };
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        if load_admission(&transaction, sprint_id, command_effect_id)?.is_none() {
            return Err(reference_mismatch(
                "contained command release outcome",
                "no contained-command release admission exists for this command effect",
            ));
        }
        transaction.execute(
            "INSERT INTO contained_command_release_outcomes (
                 command_effect_id, sprint_id, disposition, terminal_json,
                 refusal_reason, recorded_at_unix_ms
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            rusqlite::params![
                command_effect_id,
                sprint_id,
                label,
                terminal,
                reason,
                recorded_at_unix_ms,
            ],
        )?;
        transaction.commit()?;
        Ok(())
    }

    /// Runs `release` under the launch-cleanup exclusion with a live
    /// contained-command release claim, if and only if one is genuinely owed.
    ///
    /// The exclusion is the *same* lock the runner-launch family takes, on
    /// purpose: a contained command runs inside a runner, so releasing one
    /// while that runner's own launch or cleanup is in flight is exactly the
    /// interleaving the lock exists to prevent. Sharing the lock does not share
    /// the subject -- the admission read here is the command's own.
    ///
    /// # Errors
    ///
    /// Returns without invoking `release` when the exclusion cannot be
    /// acquired, when no admission exists for this command effect, when the
    /// stored admission differs from the expected one, or when a release
    /// outcome has already been recorded -- the release is one-shot.
    pub fn with_contained_command_release_exclusion<F, T>(
        &mut self,
        expected: &PersistedContainedCommandReleaseAdmission,
        release: F,
    ) -> Result<T, LedgerError>
    where
        F: FnOnce(&LiveContainedCommandReleaseClaim<'_>) -> T,
    {
        self.require_writable()?;
        let exclusion = self.acquire_launch_cleanup_exclusion()?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let sprint_id = expected.admission.sprint_id.as_str();
        let command_effect_id = expected.admission.command_effect_id.as_str();

        let current =
            load_admission(&transaction, sprint_id, command_effect_id)?.ok_or_else(|| {
                reference_mismatch(
                    "contained command release exclusion",
                    "no contained-command release admission exists for this command effect",
                )
            })?;
        if current != *expected {
            return Err(reference_mismatch(
                "contained command release exclusion",
                "contained-command release admission is stale or crossed",
            ));
        }
        if outcome_exists(&transaction, sprint_id, command_effect_id)? {
            return Err(reference_mismatch(
                "contained command release exclusion",
                "this contained command already has a durable release outcome and the release is one-shot",
            ));
        }

        let live = LiveContainedCommandReleaseClaim {
            admission: &current,
        };
        let result = release(&live);

        // No database mutation represents the release itself; the outcome is
        // recorded separately once the runner reports back. Dropping the
        // readback transaction before the companion lock preserves lock order
        // while keeping the callback's value out of a fallible commit.
        drop(transaction);
        drop(exclusion);
        Ok(result)
    }
}
