//! Current-only criterion-evidence source substrate for schema v32.
//!
//! This module deliberately exposes no production writer for machine
//! verification or human decisions. The current V2 runner/effect source,
//! trusted UI-session source, and current event stream do not exist yet. Until
//! those joins land, a connection-local, crate-private admission guard keeps
//! direct SQL through the trusted desktop connection and public callers from
//! turning labels into evidence. That guard assumes the signed desktop is the
//! only same-user writer to its `0600` ledger. It is not a cryptographic or
//! cross-process boundary: arbitrary same-user code with ledger write access
//! could register a same-named innocuous `SQLite` UDF on another connection.

use std::cell::RefCell;

use rusqlite::functions::FunctionFlags;
use rusqlite::{Connection, OptionalExtension, Transaction, params};
use serde::{Deserialize, Serialize};

use crate::{
    AcceptanceCriterion, AcceptanceKind, CriterionEvidenceReceiptV2, Digest,
    HumanAcceptanceBackingV1, HumanAcceptanceDecisionOutcomeV1, HumanAcceptanceDecisionV1,
    HumanAcceptancePromptV1, SprintSpecV2,
};

#[cfg(test)]
use super::sqlite_integer;
use super::{
    EventLedger, LedgerError, decode_stored, encode, human_acceptance_decision_id, unsigned_integer,
};

pub(super) const MIGRATION_V32: &str = include_str!("current_criterion_evidence_v32.sql");

const AUTOMATED_SOURCE_VERSION_V1: u32 = 1;
const WRITE_ADMISSION_FUNCTION: &str = "grok_current_criterion_write_admitted_v32";

/// Exact immutable projection of one criterion from a canonical V2 sprint.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct CurrentSprintCriterionProjectionV1 {
    /// Owning current sprint.
    pub sprint_id: String,
    /// Zero-based declaration position in `SprintSpecV2.acceptance_criteria`.
    pub criterion_ordinal: usize,
    /// Exact criterion decoded from the canonical sprint bytes.
    pub criterion: AcceptanceCriterion,
    /// SHA-256 of the exact criterion description bytes.
    pub criterion_text_digest: Digest,
    /// SHA-256 of the exact automated command JSON, or `None` for human work.
    pub command_digest: Option<Digest>,
    /// Domain-separated digest of the complete canonical V2 sprint.
    pub sprint_spec_digest: Digest,
}

/// Future current-only source receipt for one successful automated criterion.
///
/// No production method can create this record yet. Its identifiers become
/// authority only after a later implementation derives them from current V2
/// runner/effect, output-publication, and cleanup source rows.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CurrentAutomatedCriterionVerificationSourceV1 {
    /// Closed source-contract version.
    pub source_version: u32,
    /// Deterministic identity of the complete source record.
    pub verification_receipt_id: String,
    /// Owning current sprint.
    pub sprint_id: String,
    /// Exact automated criterion.
    pub criterion_id: String,
    /// Exact verified snapshot.
    pub snapshot_digest: Digest,
    /// Exact declared criterion-command digest.
    pub command_digest: Digest,
    /// Future joined current runner-effect identity.
    pub runner_effect_id: String,
    /// Future joined current runner-session identity.
    pub runner_session_id: String,
    /// Future joined clean output-publication identity.
    pub output_artifact_set_id: String,
    /// Future joined runner-cleanup proof identity.
    pub runner_cleanup_proof_id: String,
    /// Future joined OS command-domain cleanup proof identity.
    pub command_domain_cleanup_proof_id: String,
    /// Time the joined verification became terminal.
    pub verified_at_unix_ms: u64,
}

impl CurrentAutomatedCriterionVerificationSourceV1 {
    fn validate(&self) -> Result<(), String> {
        if self.source_version != AUTOMATED_SOURCE_VERSION_V1 {
            return Err("current automated source version must equal one".into());
        }
        for (field, value) in [
            (
                "verification_receipt_id",
                self.verification_receipt_id.as_str(),
            ),
            ("sprint_id", self.sprint_id.as_str()),
            ("criterion_id", self.criterion_id.as_str()),
            ("runner_effect_id", self.runner_effect_id.as_str()),
            ("runner_session_id", self.runner_session_id.as_str()),
            (
                "output_artifact_set_id",
                self.output_artifact_set_id.as_str(),
            ),
            (
                "runner_cleanup_proof_id",
                self.runner_cleanup_proof_id.as_str(),
            ),
            (
                "command_domain_cleanup_proof_id",
                self.command_domain_cleanup_proof_id.as_str(),
            ),
        ] {
            if value.trim().is_empty() {
                return Err(format!(
                    "current automated source {field} must not be blank"
                ));
            }
        }
        if self.verified_at_unix_ms == 0 {
            return Err("current automated source verified_at_unix_ms must be positive".into());
        }
        let expected = current_automated_verification_source_id(self)?;
        if self.verification_receipt_id != expected {
            return Err(
                "current automated source identity is not derived from its exact body".into(),
            );
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct CurrentWritePermit {
    operation: String,
    sprint_id: String,
    primary_id: String,
    secondary_id: String,
}

thread_local! {
    static CURRENT_WRITE_PERMIT: RefCell<Option<CurrentWritePermit>> = const { RefCell::new(None) };
}

struct CurrentWritePermitGuard;

impl Drop for CurrentWritePermitGuard {
    fn drop(&mut self) {
        CURRENT_WRITE_PERMIT.with(|slot| {
            *slot.borrow_mut() = None;
        });
    }
}

fn with_write_permit<T>(
    permit: CurrentWritePermit,
    write: impl FnOnce() -> Result<T, LedgerError>,
) -> Result<T, LedgerError> {
    let nested = CURRENT_WRITE_PERMIT.with(|slot| slot.borrow_mut().replace(permit));
    if nested.is_some() {
        CURRENT_WRITE_PERMIT.with(|slot| {
            *slot.borrow_mut() = nested;
        });
        return Err(LedgerError::Corrupt {
            entity: "current criterion evidence write admission",
            detail: "nested write admission is forbidden".into(),
        });
    }
    let _guard = CurrentWritePermitGuard;
    write()
}

fn write_is_admitted(
    operation: &str,
    sprint_id: &str,
    primary_id: &str,
    secondary_id: &str,
) -> i64 {
    CURRENT_WRITE_PERMIT.with(|slot| {
        i64::from(slot.borrow().as_ref().is_some_and(|permit| {
            permit.operation == operation
                && permit.sprint_id == sprint_id
                && permit.primary_id == primary_id
                && permit.secondary_id == secondary_id
        }))
    })
}

fn exact_json<T>(
    entity: &str,
    bytes: &[u8],
    validate: impl FnOnce(&T) -> Result<(), String>,
) -> Result<T, String>
where
    T: for<'de> Deserialize<'de> + Serialize,
{
    let value: T = serde_json::from_slice(bytes)
        .map_err(|error| format!("{entity} cannot be decoded: {error}"))?;
    validate(&value)?;
    let canonical = serde_json::to_vec(&value)
        .map_err(|error| format!("{entity} cannot be encoded: {error}"))?;
    if canonical != bytes {
        return Err(format!("{entity} is not exact canonical JSON"));
    }
    Ok(value)
}

fn command_digest(criterion: &AcceptanceCriterion) -> Result<Option<Digest>, LedgerError> {
    match &criterion.kind {
        AcceptanceKind::Automated(command) => Ok(Some(Digest::sha256(&encode(
            "current criterion automated command",
            command,
        )?))),
        AcceptanceKind::HumanJudgment => Ok(None),
    }
}

fn current_prompt_id(prompt: &HumanAcceptancePromptV1) -> Result<String, String> {
    #[derive(Serialize)]
    struct Identity<'a> {
        domain: &'static str,
        ui_session_id: &'a str,
        sprint_id: &'a str,
        criterion_id: &'a str,
        criterion_text_digest: &'a Digest,
        snapshot_digest: &'a Digest,
        workspace_grant_hash: &'a Digest,
        rendered_claim_digest: &'a Digest,
        backing: HumanAcceptanceBackingV1,
        issued_event_sequence: u64,
    }
    let identity = Identity {
        domain: "grok-build.current-human-acceptance-prompt.v1",
        ui_session_id: &prompt.ui_session_id,
        sprint_id: &prompt.sprint_id,
        criterion_id: &prompt.criterion_id,
        criterion_text_digest: &prompt.criterion_text_digest,
        snapshot_digest: &prompt.snapshot_digest,
        workspace_grant_hash: &prompt.workspace_grant_hash,
        rendered_claim_digest: &prompt.rendered_claim_digest,
        backing: prompt.backing,
        issued_event_sequence: prompt.issued_event_sequence,
    };
    let bytes = serde_json::to_vec(&identity)
        .map_err(|error| format!("current prompt identity cannot be encoded: {error}"))?;
    Ok(format!("current-human-prompt:{}", Digest::sha256(&bytes)))
}

fn current_automated_verification_source_id(
    source: &CurrentAutomatedCriterionVerificationSourceV1,
) -> Result<String, String> {
    #[derive(Serialize)]
    struct Identity<'a> {
        domain: &'static str,
        source_version: u32,
        sprint_id: &'a str,
        criterion_id: &'a str,
        snapshot_digest: &'a Digest,
        command_digest: &'a Digest,
        runner_effect_id: &'a str,
        runner_session_id: &'a str,
        output_artifact_set_id: &'a str,
        runner_cleanup_proof_id: &'a str,
        command_domain_cleanup_proof_id: &'a str,
        verified_at_unix_ms: u64,
    }
    let identity = Identity {
        domain: "grok-build.current-automated-criterion-verification.v1",
        source_version: source.source_version,
        sprint_id: &source.sprint_id,
        criterion_id: &source.criterion_id,
        snapshot_digest: &source.snapshot_digest,
        command_digest: &source.command_digest,
        runner_effect_id: &source.runner_effect_id,
        runner_session_id: &source.runner_session_id,
        output_artifact_set_id: &source.output_artifact_set_id,
        runner_cleanup_proof_id: &source.runner_cleanup_proof_id,
        command_domain_cleanup_proof_id: &source.command_domain_cleanup_proof_id,
        verified_at_unix_ms: source.verified_at_unix_ms,
    };
    let bytes = serde_json::to_vec(&identity)
        .map_err(|error| format!("current automated source identity cannot be encoded: {error}"))?;
    Ok(format!("current-verification:{}", Digest::sha256(&bytes)))
}

fn current_criterion_evidence_receipt_id(
    receipt: &CriterionEvidenceReceiptV2,
) -> Result<String, String> {
    #[derive(Serialize)]
    struct Identity<'a> {
        domain: &'static str,
        sprint_id: &'a str,
        criterion_id: &'a str,
        snapshot_digest: &'a Digest,
        evidence_kind: &'static str,
        verification_receipt_id: Option<&'a str>,
        human_decision_id: Option<&'a str>,
        prompt_id: Option<&'a str>,
        backing: Option<HumanAcceptanceBackingV1>,
        recorded_at: u64,
    }
    let identity = match receipt {
        CriterionEvidenceReceiptV2::Verified {
            sprint_id,
            criterion_id,
            snapshot_digest,
            verification_receipt_id,
            recorded_at,
            ..
        } => Identity {
            domain: "grok-build.current-criterion-evidence.v2",
            sprint_id,
            criterion_id,
            snapshot_digest,
            evidence_kind: "verified",
            verification_receipt_id: Some(verification_receipt_id),
            human_decision_id: None,
            prompt_id: None,
            backing: None,
            recorded_at: *recorded_at,
        },
        CriterionEvidenceReceiptV2::AcceptedByYou {
            sprint_id,
            criterion_id,
            snapshot_digest,
            human_decision_id,
            prompt_id,
            backing,
            recorded_at,
            ..
        } => Identity {
            domain: "grok-build.current-criterion-evidence.v2",
            sprint_id,
            criterion_id,
            snapshot_digest,
            evidence_kind: "accepted-by-you",
            verification_receipt_id: None,
            human_decision_id: Some(human_decision_id),
            prompt_id: Some(prompt_id),
            backing: Some(*backing),
            recorded_at: *recorded_at,
        },
    };
    let bytes = serde_json::to_vec(&identity).map_err(|error| {
        format!("current criterion receipt identity cannot be encoded: {error}")
    })?;
    Ok(format!(
        "current-criterion-evidence:{}",
        Digest::sha256(&bytes)
    ))
}

fn sqlite_user_error(detail: impl Into<String>) -> rusqlite::Error {
    rusqlite::Error::UserFunctionError(Box::new(std::io::Error::new(
        std::io::ErrorKind::InvalidData,
        detail.into(),
    )))
}

#[allow(clippy::too_many_lines)] // Keep the closed schema-UDF registry together for one audit boundary.
pub(super) fn register_schema_functions(connection: &Connection) -> Result<(), LedgerError> {
    connection.create_scalar_function(
        WRITE_ADMISSION_FUNCTION,
        4,
        FunctionFlags::SQLITE_INNOCUOUS,
        |context| {
            Ok(write_is_admitted(
                context.get::<String>(0)?.as_str(),
                context.get::<String>(1)?.as_str(),
                context.get::<String>(2)?.as_str(),
                context.get::<String>(3)?.as_str(),
            ))
        },
    )?;
    connection.create_scalar_function(
        "grok_current_criterion_projection_matches_v32",
        7,
        FunctionFlags::SQLITE_DETERMINISTIC | FunctionFlags::SQLITE_INNOCUOUS,
        |context| {
            let spec_bytes = context.get::<Vec<u8>>(0)?;
            let ordinal = usize::try_from(context.get::<i64>(1)?)
                .map_err(|_| sqlite_user_error("criterion ordinal is negative or too large"))?;
            let criterion_id = context.get::<String>(2)?;
            let criterion_kind = context.get::<String>(3)?;
            let text_digest = context.get::<String>(4)?;
            let stored_command_digest = context.get::<String>(5)?;
            let criterion_bytes = context.get::<Vec<u8>>(6)?;
            let spec = SprintSpecV2::from_canonical_bytes(&spec_bytes)
                .map_err(|error| sqlite_user_error(error.to_string()))?;
            let Some(criterion) = spec.acceptance_criteria.get(ordinal) else {
                return Ok(0_i64);
            };
            let expected_bytes = serde_json::to_vec(criterion)
                .map_err(|error| sqlite_user_error(error.to_string()))?;
            let expected_kind = match criterion.kind {
                AcceptanceKind::Automated(_) => "Automated",
                AcceptanceKind::HumanJudgment => "HumanJudgment",
            };
            let expected_command_digest = match &criterion.kind {
                AcceptanceKind::Automated(command) => Digest::sha256(
                    &serde_json::to_vec(command)
                        .map_err(|error| sqlite_user_error(error.to_string()))?,
                )
                .to_string(),
                AcceptanceKind::HumanJudgment => String::new(),
            };
            Ok(i64::from(
                criterion.criterion_id == criterion_id
                    && expected_kind == criterion_kind
                    && Digest::sha256(criterion.description.as_bytes()).as_str() == text_digest
                    && expected_command_digest == stored_command_digest
                    && expected_bytes == criterion_bytes,
            ))
        },
    )?;
    connection.create_scalar_function(
        "grok_current_automated_source_canonical_v32",
        12,
        FunctionFlags::SQLITE_DETERMINISTIC | FunctionFlags::SQLITE_INNOCUOUS,
        |context| {
            let bytes = context.get::<Vec<u8>>(0)?;
            let source = exact_json::<CurrentAutomatedCriterionVerificationSourceV1>(
                "current automated verification source",
                &bytes,
                CurrentAutomatedCriterionVerificationSourceV1::validate,
            )
            .map_err(sqlite_user_error)?;
            let verified_at = u64::try_from(context.get::<i64>(11)?).ok();
            Ok(i64::from(
                source.verification_receipt_id == context.get::<String>(1)?
                    && source.sprint_id == context.get::<String>(2)?
                    && source.criterion_id == context.get::<String>(3)?
                    && source.snapshot_digest.as_str() == context.get::<String>(4)?
                    && source.command_digest.as_str() == context.get::<String>(5)?
                    && source.runner_effect_id == context.get::<String>(6)?
                    && source.runner_session_id == context.get::<String>(7)?
                    && source.output_artifact_set_id == context.get::<String>(8)?
                    && source.runner_cleanup_proof_id == context.get::<String>(9)?
                    && source.command_domain_cleanup_proof_id == context.get::<String>(10)?
                    && Some(source.verified_at_unix_ms) == verified_at,
            ))
        },
    )?;
    connection.create_scalar_function(
        "grok_current_human_prompt_canonical_v32",
        11,
        FunctionFlags::SQLITE_DETERMINISTIC | FunctionFlags::SQLITE_INNOCUOUS,
        |context| {
            let bytes = context.get::<Vec<u8>>(0)?;
            let prompt =
                exact_json::<HumanAcceptancePromptV1>("current human prompt", &bytes, |prompt| {
                    prompt.validate().map_err(|error| error.to_string())?;
                    if prompt.backing != HumanAcceptanceBackingV1::OneToOne
                        || current_prompt_id(prompt)? != prompt.prompt_id
                    {
                        return Err("current human prompt identity or backing is invalid".into());
                    }
                    Ok(())
                })
                .map_err(sqlite_user_error)?;
            let issued_event_sequence = u64::try_from(context.get::<i64>(10)?).ok();
            Ok(i64::from(
                prompt.prompt_id == context.get::<String>(1)?
                    && prompt.ui_session_id == context.get::<String>(2)?
                    && prompt.sprint_id == context.get::<String>(3)?
                    && prompt.criterion_id == context.get::<String>(4)?
                    && prompt.criterion_text_digest.as_str() == context.get::<String>(5)?
                    && prompt.snapshot_digest.as_str() == context.get::<String>(6)?
                    && prompt.workspace_grant_hash.as_str() == context.get::<String>(7)?
                    && prompt.rendered_claim_digest.as_str() == context.get::<String>(8)?
                    && context.get::<String>(9)? == "OneToOne"
                    && Some(prompt.issued_event_sequence) == issued_event_sequence,
            ))
        },
    )?;
    connection.create_scalar_function(
        "grok_current_human_decision_canonical_v32",
        6,
        FunctionFlags::SQLITE_DETERMINISTIC | FunctionFlags::SQLITE_INNOCUOUS,
        |context| {
            let bytes = context.get::<Vec<u8>>(0)?;
            let decision = exact_json::<HumanAcceptanceDecisionV1>(
                "current human decision",
                &bytes,
                |decision| decision.validate().map_err(|error| error.to_string()),
            )
            .map_err(sqlite_user_error)?;
            let expected_outcome = match decision.outcome {
                HumanAcceptanceDecisionOutcomeV1::AcceptedByYou => "AcceptedByYou",
                HumanAcceptanceDecisionOutcomeV1::RejectedByYou => "RejectedByYou",
            };
            let consumed_event_sequence = u64::try_from(context.get::<i64>(4)?).ok();
            let decided_at = u64::try_from(context.get::<i64>(5)?).ok();
            Ok(i64::from(
                decision.decision_id == context.get::<String>(1)?
                    && decision.prompt_id == context.get::<String>(2)?
                    && expected_outcome == context.get::<String>(3)?
                    && Some(decision.consumed_event_sequence) == consumed_event_sequence
                    && Some(decision.decided_at) == decided_at,
            ))
        },
    )?;
    connection.create_scalar_function(
        "grok_current_human_decision_matches_prompt_v32",
        5,
        FunctionFlags::SQLITE_DETERMINISTIC | FunctionFlags::SQLITE_INNOCUOUS,
        |context| {
            let prompt_bytes = context.get::<Vec<u8>>(0)?;
            let decision_bytes = context.get::<Vec<u8>>(1)?;
            let prompt = exact_json::<HumanAcceptancePromptV1>(
                "current human prompt",
                &prompt_bytes,
                |value| {
                    value.validate().map_err(|error| error.to_string())?;
                    if value.backing != HumanAcceptanceBackingV1::OneToOne
                        || current_prompt_id(value)? != value.prompt_id
                    {
                        return Err("current human prompt identity or backing is invalid".into());
                    }
                    Ok(())
                },
            )
            .map_err(sqlite_user_error)?;
            let decision = exact_json::<HumanAcceptanceDecisionV1>(
                "current human decision",
                &decision_bytes,
                |value| value.validate().map_err(|error| error.to_string()),
            )
            .map_err(sqlite_user_error)?;
            let expected = human_acceptance_decision_id(
                &prompt,
                decision.outcome,
                decision.consumed_event_sequence,
                decision.decided_at,
            )
            .map_err(|error| sqlite_user_error(error.to_string()))?;
            Ok(i64::from(
                decision.prompt_id == prompt.prompt_id
                    && decision.consumed_event_sequence == prompt.issued_event_sequence
                    && decision.decision_id == expected
                    && prompt.sprint_id == context.get::<String>(2)?
                    && prompt.criterion_id == context.get::<String>(3)?
                    && prompt.snapshot_digest.as_str() == context.get::<String>(4)?,
            ))
        },
    )?;
    connection.create_scalar_function(
        "grok_current_criterion_receipt_canonical_v32",
        11,
        FunctionFlags::SQLITE_DETERMINISTIC | FunctionFlags::SQLITE_INNOCUOUS,
        |context| {
            let bytes = context.get::<Vec<u8>>(0)?;
            let receipt = exact_json::<CriterionEvidenceReceiptV2>(
                "current criterion evidence receipt",
                &bytes,
                |receipt| {
                    receipt.validate().map_err(|error| error.to_string())?;
                    if current_criterion_evidence_receipt_id(receipt)? != receipt.receipt_id() {
                        return Err("current criterion evidence identity is not derived".into());
                    }
                    Ok(())
                },
            )
            .map_err(sqlite_user_error)?;
            let (evidence_kind, verification_receipt_id, human_decision_id, prompt_id, backing) =
                match &receipt {
                    CriterionEvidenceReceiptV2::Verified {
                        verification_receipt_id,
                        ..
                    } => (
                        "Verified",
                        Some(verification_receipt_id.as_str()),
                        None,
                        None,
                        None,
                    ),
                    CriterionEvidenceReceiptV2::AcceptedByYou {
                        human_decision_id,
                        prompt_id,
                        backing: HumanAcceptanceBackingV1::OneToOne,
                        ..
                    } => (
                        "AcceptedByYou",
                        None,
                        Some(human_decision_id.as_str()),
                        Some(prompt_id.as_str()),
                        Some("OneToOne"),
                    ),
                };
            let recorded_at = u64::try_from(context.get::<i64>(10)?).ok();
            Ok(i64::from(
                receipt.receipt_id() == context.get::<String>(1)?
                    && receipt.sprint_id() == context.get::<String>(2)?
                    && receipt.criterion_id() == context.get::<String>(3)?
                    && receipt.snapshot_digest().as_str() == context.get::<String>(4)?
                    && evidence_kind == context.get::<String>(5)?
                    && verification_receipt_id == context.get::<Option<String>>(6)?.as_deref()
                    && human_decision_id == context.get::<Option<String>>(7)?.as_deref()
                    && prompt_id == context.get::<Option<String>>(8)?.as_deref()
                    && backing == context.get::<Option<String>>(9)?.as_deref()
                    && Some(receipt.recorded_at()) == recorded_at,
            ))
        },
    )?;
    Ok(())
}

/// Projects every exact V2 criterion in the caller's existing transaction.
///
/// The current sprint authority must already be visible in that same
/// transaction. Repeating an identical complete projection is idempotent;
/// partial or crossed state fails closed.
pub(super) fn project_current_sprint_criteria_v32(
    transaction: &Transaction<'_>,
    spec: &SprintSpecV2,
) -> Result<(), LedgerError> {
    let spec_bytes = spec.canonical_bytes()?;
    let spec_digest = spec.canonical_digest()?;
    let stored: Option<(String, Vec<u8>)> = transaction
        .query_row(
            "SELECT sprint_spec_digest, spec_json
             FROM current_sprint_authorities_v32 WHERE sprint_id = ?1",
            [spec.sprint_id.as_str()],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()?;
    let Some((stored_digest, stored_bytes)) = stored else {
        return Err(LedgerError::SprintNotFound(spec.sprint_id.clone()));
    };
    if stored_digest != spec_digest.as_str() || stored_bytes != spec_bytes {
        return Err(LedgerError::ReferenceMismatch {
            entity: "current criterion projection v32",
            detail: "supplied SprintSpecV2 differs from current sprint authority".into(),
        });
    }

    let existing_count: i64 = transaction.query_row(
        "SELECT COUNT(*) FROM current_sprint_criteria_v32 WHERE sprint_id = ?1",
        [spec.sprint_id.as_str()],
        |row| row.get(0),
    )?;
    if existing_count != 0 {
        let existing = load_current_sprint_criteria_from(transaction, &spec.sprint_id)?;
        let expected = derive_projections(spec)?;
        if existing == expected {
            return Ok(());
        }
        return Err(LedgerError::Corrupt {
            entity: "current criterion projection v32",
            detail: "existing projection is partial or differs from canonical SprintSpecV2".into(),
        });
    }

    for (ordinal, criterion) in spec.acceptance_criteria.iter().enumerate() {
        let (kind, command_digest) = match command_digest(criterion)? {
            Some(digest) => ("Automated", digest.to_string()),
            None => ("HumanJudgment", String::new()),
        };
        let ordinal_i64 = i64::try_from(ordinal)
            .map_err(|_| LedgerError::IntegerOutOfRange("criterion ordinal"))?;
        let permit = CurrentWritePermit {
            operation: "criterion".into(),
            sprint_id: spec.sprint_id.clone(),
            primary_id: criterion.criterion_id.clone(),
            secondary_id: ordinal.to_string(),
        };
        with_write_permit(permit, || {
            transaction.execute(
                "INSERT INTO current_sprint_criteria_v32 (
                    sprint_id, criterion_id, criterion_ordinal, criterion_kind,
                    criterion_text_digest, command_digest, sprint_spec_digest,
                    criterion_json
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                params![
                    spec.sprint_id,
                    criterion.criterion_id,
                    ordinal_i64,
                    kind,
                    Digest::sha256(criterion.description.as_bytes()).as_str(),
                    command_digest,
                    spec_digest.as_str(),
                    encode("current criterion projection", criterion)?,
                ],
            )?;
            Ok(())
        })?;
    }
    let persisted = load_current_sprint_criteria_from(transaction, &spec.sprint_id)?;
    if persisted != derive_projections(spec)? {
        return Err(LedgerError::Corrupt {
            entity: "current criterion projection v32",
            detail: "transactional readback differs from canonical SprintSpecV2".into(),
        });
    }
    Ok(())
}

fn derive_projections(
    spec: &SprintSpecV2,
) -> Result<Vec<CurrentSprintCriterionProjectionV1>, LedgerError> {
    let sprint_spec_digest = spec.canonical_digest()?;
    spec.acceptance_criteria
        .iter()
        .enumerate()
        .map(|(criterion_ordinal, criterion)| {
            Ok(CurrentSprintCriterionProjectionV1 {
                sprint_id: spec.sprint_id.clone(),
                criterion_ordinal,
                criterion: criterion.clone(),
                criterion_text_digest: Digest::sha256(criterion.description.as_bytes()),
                command_digest: command_digest(criterion)?,
                sprint_spec_digest: sprint_spec_digest.clone(),
            })
        })
        .collect()
}

fn load_current_sprint_criteria_from(
    connection: &Connection,
    sprint_id: &str,
) -> Result<Vec<CurrentSprintCriterionProjectionV1>, LedgerError> {
    let (spec_digest_text, spec_bytes): (String, Vec<u8>) = connection
        .query_row(
            "SELECT sprint_spec_digest, spec_json
             FROM current_sprint_authorities_v32 WHERE sprint_id = ?1",
            [sprint_id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()?
        .ok_or_else(|| LedgerError::SprintNotFound(sprint_id.to_owned()))?;
    let spec = SprintSpecV2::from_canonical_bytes(&spec_bytes)?;
    let spec_digest = spec.canonical_digest()?;
    if spec.sprint_id != sprint_id || spec_digest.as_str() != spec_digest_text {
        return Err(LedgerError::Corrupt {
            entity: "current criterion projection v32",
            detail: "current sprint authority envelope is inconsistent".into(),
        });
    }
    let mut statement = connection.prepare(
        "SELECT criterion_id, criterion_ordinal, criterion_kind,
                criterion_text_digest, command_digest, sprint_spec_digest,
                criterion_json
         FROM current_sprint_criteria_v32
         WHERE sprint_id = ?1 ORDER BY criterion_ordinal",
    )?;
    let rows = statement.query_map([sprint_id], |row| {
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, i64>(1)?,
            row.get::<_, String>(2)?,
            row.get::<_, String>(3)?,
            row.get::<_, String>(4)?,
            row.get::<_, String>(5)?,
            row.get::<_, Vec<u8>>(6)?,
        ))
    })?;
    let stored = rows.collect::<Result<Vec<_>, _>>()?;
    let expected = derive_projections(&spec)?;
    if stored.len() != expected.len() {
        return Err(LedgerError::Corrupt {
            entity: "current criterion projection v32",
            detail: "projection cardinality differs from canonical SprintSpecV2".into(),
        });
    }
    for (row, projection) in stored.iter().zip(&expected) {
        let ordinal = usize::try_from(row.1)
            .map_err(|_| LedgerError::IntegerOutOfRange("criterion ordinal"))?;
        let criterion: AcceptanceCriterion = decode_stored("current criterion projection", &row.6)?;
        let expected_kind = match projection.criterion.kind {
            AcceptanceKind::Automated(_) => "Automated",
            AcceptanceKind::HumanJudgment => "HumanJudgment",
        };
        let expected_command = projection
            .command_digest
            .as_ref()
            .map_or("", Digest::as_str);
        if row.0 != projection.criterion.criterion_id
            || ordinal != projection.criterion_ordinal
            || row.2 != expected_kind
            || row.3 != projection.criterion_text_digest.as_str()
            || row.4 != expected_command
            || row.5 != projection.sprint_spec_digest.as_str()
            || criterion != projection.criterion
            || encode("current criterion projection", &criterion)? != row.6
        {
            return Err(LedgerError::Corrupt {
                entity: "current criterion projection v32",
                detail: "projection row disagrees with canonical SprintSpecV2".into(),
            });
        }
    }
    Ok(expected)
}

impl EventLedger {
    /// Loads the complete exact criterion projection for one current V2 sprint.
    ///
    /// # Errors
    ///
    /// Returns a ledger error when the sprint or complete projection is absent,
    /// noncanonical, partial, crossed, or corrupt.
    pub(crate) fn load_current_sprint_criteria_v32(
        &self,
        sprint_id: &str,
    ) -> Result<Vec<CurrentSprintCriterionProjectionV1>, LedgerError> {
        load_current_sprint_criteria_from(&self.connection, sprint_id)
    }
}

fn load_current_automated_source_from(
    connection: &Connection,
    verification_receipt_id: &str,
) -> Result<CurrentAutomatedCriterionVerificationSourceV1, LedgerError> {
    let stored = connection
        .query_row(
            "SELECT sprint_id, criterion_id, snapshot_digest, command_digest,
                    runner_effect_id, runner_session_id, output_artifact_set_id,
                    runner_cleanup_proof_id, command_domain_cleanup_proof_id,
                    verified_at_unix_ms, source_json
             FROM current_automated_verification_sources_v32
             WHERE verification_receipt_id = ?1",
            [verification_receipt_id],
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
                    row.get::<_, Vec<u8>>(10)?,
                ))
            },
        )
        .optional()?
        .ok_or_else(|| LedgerError::ArtifactNotFound {
            entity: "current automated verification source",
            id: verification_receipt_id.to_owned(),
        })?;
    let source: CurrentAutomatedCriterionVerificationSourceV1 =
        decode_stored("current automated verification source", &stored.10)?;
    source.validate().map_err(|detail| LedgerError::Corrupt {
        entity: "current automated verification source",
        detail,
    })?;
    let verified_at = unsigned_integer("current automated source verified_at", stored.9)?;
    if encode("current automated verification source", &source)? != stored.10
        || source.verification_receipt_id != verification_receipt_id
        || source.sprint_id != stored.0
        || source.criterion_id != stored.1
        || source.snapshot_digest.as_str() != stored.2
        || source.command_digest.as_str() != stored.3
        || source.runner_effect_id != stored.4
        || source.runner_session_id != stored.5
        || source.output_artifact_set_id != stored.6
        || source.runner_cleanup_proof_id != stored.7
        || source.command_domain_cleanup_proof_id != stored.8
        || source.verified_at_unix_ms != verified_at
    {
        return Err(LedgerError::Corrupt {
            entity: "current automated verification source",
            detail: "source envelope disagrees with indexed columns".into(),
        });
    }
    let projection = load_current_sprint_criteria_from(connection, &source.sprint_id)?
        .into_iter()
        .find(|criterion| criterion.criterion.criterion_id == source.criterion_id)
        .ok_or_else(|| LedgerError::ReferenceMismatch {
            entity: "current automated verification source",
            detail: "criterion is absent from exact SprintSpecV2 projection".into(),
        })?;
    if projection.command_digest.as_ref() != Some(&source.command_digest)
        || !matches!(projection.criterion.kind, AcceptanceKind::Automated(_))
    {
        return Err(LedgerError::ReferenceMismatch {
            entity: "current automated verification source",
            detail: "source command or kind differs from exact automated criterion".into(),
        });
    }
    Ok(source)
}

fn load_current_prompt_from(
    connection: &Connection,
    prompt_id: &str,
) -> Result<HumanAcceptancePromptV1, LedgerError> {
    let stored = connection
        .query_row(
            "SELECT ui_session_id, sprint_id, criterion_id,
                    criterion_text_digest, snapshot_digest, workspace_grant_hash,
                    rendered_claim_digest, backing, issued_event_sequence,
                    prompt_json
             FROM current_human_acceptance_prompts_v32 WHERE prompt_id = ?1",
            [prompt_id],
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
                    row.get::<_, i64>(8)?,
                    row.get::<_, Vec<u8>>(9)?,
                ))
            },
        )
        .optional()?
        .ok_or_else(|| LedgerError::ArtifactNotFound {
            entity: "current human acceptance prompt",
            id: prompt_id.to_owned(),
        })?;
    let prompt: HumanAcceptancePromptV1 =
        decode_stored("current human acceptance prompt", &stored.9)?;
    prompt.validate().map_err(|error| LedgerError::Corrupt {
        entity: "current human acceptance prompt",
        detail: error.to_string(),
    })?;
    let issued = unsigned_integer("current human prompt issued event sequence", stored.8)?;
    if encode("current human acceptance prompt", &prompt)? != stored.9
        || prompt.prompt_id != prompt_id
        || current_prompt_id(&prompt).map_err(|detail| LedgerError::Corrupt {
            entity: "current human acceptance prompt",
            detail,
        })? != prompt.prompt_id
        || prompt.ui_session_id != stored.0
        || prompt.sprint_id != stored.1
        || prompt.criterion_id != stored.2
        || prompt.criterion_text_digest.as_str() != stored.3
        || prompt.snapshot_digest.as_str() != stored.4
        || prompt.workspace_grant_hash.as_str() != stored.5
        || prompt.rendered_claim_digest.as_str() != stored.6
        || stored.7 != "OneToOne"
        || prompt.backing != HumanAcceptanceBackingV1::OneToOne
        || prompt.issued_event_sequence != issued
    {
        return Err(LedgerError::Corrupt {
            entity: "current human acceptance prompt",
            detail: "prompt envelope disagrees with indexed columns".into(),
        });
    }
    let projection = load_current_sprint_criteria_from(connection, &prompt.sprint_id)?
        .into_iter()
        .find(|criterion| criterion.criterion.criterion_id == prompt.criterion_id)
        .ok_or_else(|| LedgerError::ReferenceMismatch {
            entity: "current human acceptance prompt",
            detail: "criterion is absent from exact SprintSpecV2 projection".into(),
        })?;
    let grant_hash: String = connection.query_row(
        "SELECT workspace_grant_hash FROM current_sprint_authorities_v32 WHERE sprint_id = ?1",
        [prompt.sprint_id.as_str()],
        |row| row.get(0),
    )?;
    if !matches!(projection.criterion.kind, AcceptanceKind::HumanJudgment)
        || projection.criterion_text_digest != prompt.criterion_text_digest
        || grant_hash != prompt.workspace_grant_hash.as_str()
    {
        return Err(LedgerError::ReferenceMismatch {
            entity: "current human acceptance prompt",
            detail: "prompt kind, text, or grant differs from exact current authority".into(),
        });
    }
    Ok(prompt)
}

fn load_current_decision_from(
    connection: &Connection,
    decision_id: &str,
) -> Result<HumanAcceptanceDecisionV1, LedgerError> {
    let stored = connection
        .query_row(
            "SELECT prompt_id, sprint_id, criterion_id, snapshot_digest,
                    outcome, consumed_event_sequence, decided_at_unix_ms,
                    decision_json
             FROM current_human_acceptance_decisions_v32 WHERE decision_id = ?1",
            [decision_id],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, i64>(5)?,
                    row.get::<_, i64>(6)?,
                    row.get::<_, Vec<u8>>(7)?,
                ))
            },
        )
        .optional()?
        .ok_or_else(|| LedgerError::ArtifactNotFound {
            entity: "current human acceptance decision",
            id: decision_id.to_owned(),
        })?;
    let decision: HumanAcceptanceDecisionV1 =
        decode_stored("current human acceptance decision", &stored.7)?;
    decision.validate().map_err(|error| LedgerError::Corrupt {
        entity: "current human acceptance decision",
        detail: error.to_string(),
    })?;
    let consumed = unsigned_integer("current decision consumed event sequence", stored.5)?;
    let decided_at = unsigned_integer("current decision decided_at", stored.6)?;
    let expected_outcome = match decision.outcome {
        HumanAcceptanceDecisionOutcomeV1::AcceptedByYou => "AcceptedByYou",
        HumanAcceptanceDecisionOutcomeV1::RejectedByYou => "RejectedByYou",
    };
    if encode("current human acceptance decision", &decision)? != stored.7
        || decision.decision_id != decision_id
        || decision.prompt_id != stored.0
        || expected_outcome != stored.4
        || decision.consumed_event_sequence != consumed
        || decision.decided_at != decided_at
    {
        return Err(LedgerError::Corrupt {
            entity: "current human acceptance decision",
            detail: "decision envelope disagrees with indexed columns".into(),
        });
    }
    let prompt = load_current_prompt_from(connection, &decision.prompt_id)?;
    let expected_id = human_acceptance_decision_id(
        &prompt,
        decision.outcome,
        decision.consumed_event_sequence,
        decision.decided_at,
    )?;
    if expected_id != decision.decision_id
        || prompt.sprint_id != stored.1
        || prompt.criterion_id != stored.2
        || prompt.snapshot_digest.as_str() != stored.3
        || prompt.issued_event_sequence != decision.consumed_event_sequence
    {
        return Err(LedgerError::ReferenceMismatch {
            entity: "current human acceptance decision",
            detail: "decision crossed its immutable one-to-one prompt".into(),
        });
    }
    Ok(decision)
}

#[allow(clippy::too_many_lines)] // One readback validates the envelope and exactly one disjoint backing branch.
pub(super) fn load_current_criterion_receipt_from(
    connection: &Connection,
    receipt_id: &str,
) -> Result<CriterionEvidenceReceiptV2, LedgerError> {
    let stored = connection
        .query_row(
            "SELECT sprint_id, criterion_id, snapshot_digest, evidence_kind,
                    verification_receipt_id, human_decision_id, prompt_id,
                    backing, recorded_at_unix_ms, receipt_json
             FROM current_criterion_evidence_receipts_v32 WHERE receipt_id = ?1",
            [receipt_id],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, Option<String>>(4)?,
                    row.get::<_, Option<String>>(5)?,
                    row.get::<_, Option<String>>(6)?,
                    row.get::<_, Option<String>>(7)?,
                    row.get::<_, i64>(8)?,
                    row.get::<_, Vec<u8>>(9)?,
                ))
            },
        )
        .optional()?
        .ok_or_else(|| LedgerError::ArtifactNotFound {
            entity: "current criterion evidence receipt",
            id: receipt_id.to_owned(),
        })?;
    let receipt: CriterionEvidenceReceiptV2 =
        decode_stored("current criterion evidence receipt", &stored.9)?;
    receipt.validate().map_err(|error| LedgerError::Corrupt {
        entity: "current criterion evidence receipt",
        detail: error.to_string(),
    })?;
    let recorded_at = unsigned_integer("current criterion evidence recorded_at", stored.8)?;
    let expected_id =
        current_criterion_evidence_receipt_id(&receipt).map_err(|detail| LedgerError::Corrupt {
            entity: "current criterion evidence receipt",
            detail,
        })?;
    let (kind, verification_id, decision_id, prompt_id, backing) = match &receipt {
        CriterionEvidenceReceiptV2::Verified {
            verification_receipt_id,
            ..
        } => (
            "Verified",
            Some(verification_receipt_id.as_str()),
            None,
            None,
            None,
        ),
        CriterionEvidenceReceiptV2::AcceptedByYou {
            human_decision_id,
            prompt_id,
            backing: HumanAcceptanceBackingV1::OneToOne,
            ..
        } => (
            "AcceptedByYou",
            None,
            Some(human_decision_id.as_str()),
            Some(prompt_id.as_str()),
            Some("OneToOne"),
        ),
    };
    if encode("current criterion evidence receipt", &receipt)? != stored.9
        || expected_id != receipt_id
        || receipt.receipt_id() != receipt_id
        || receipt.sprint_id() != stored.0
        || receipt.criterion_id() != stored.1
        || receipt.snapshot_digest().as_str() != stored.2
        || kind != stored.3
        || verification_id != stored.4.as_deref()
        || decision_id != stored.5.as_deref()
        || prompt_id != stored.6.as_deref()
        || backing != stored.7.as_deref()
        || receipt.recorded_at() != recorded_at
    {
        return Err(LedgerError::Corrupt {
            entity: "current criterion evidence receipt",
            detail: "receipt envelope disagrees with indexed columns".into(),
        });
    }
    match &receipt {
        CriterionEvidenceReceiptV2::Verified {
            verification_receipt_id,
            ..
        } => {
            let source = load_current_automated_source_from(connection, verification_receipt_id)?;
            if source.sprint_id != receipt.sprint_id()
                || source.criterion_id != receipt.criterion_id()
                || source.snapshot_digest != *receipt.snapshot_digest()
                || source.verified_at_unix_ms > receipt.recorded_at()
            {
                return Err(LedgerError::ReferenceMismatch {
                    entity: "current criterion evidence receipt",
                    detail: "verified receipt crossed or predates its exact machine source".into(),
                });
            }
        }
        CriterionEvidenceReceiptV2::AcceptedByYou {
            human_decision_id,
            prompt_id,
            backing,
            ..
        } => {
            let decision = load_current_decision_from(connection, human_decision_id)?;
            let prompt = load_current_prompt_from(connection, prompt_id)?;
            if decision.prompt_id != *prompt_id
                || decision.outcome != HumanAcceptanceDecisionOutcomeV1::AcceptedByYou
                || decision.decided_at > receipt.recorded_at()
                || prompt.sprint_id != receipt.sprint_id()
                || prompt.criterion_id != receipt.criterion_id()
                || prompt.snapshot_digest != *receipt.snapshot_digest()
                || prompt.backing != *backing
            {
                return Err(LedgerError::ReferenceMismatch {
                    entity: "current criterion evidence receipt",
                    detail: "accepted-by-you receipt crossed its exact decision or prompt".into(),
                });
            }
        }
    }
    Ok(receipt)
}

#[cfg(test)]
struct TestCriterionSourceBundle {
    automated_source: CurrentAutomatedCriterionVerificationSourceV1,
    automated_receipt: CriterionEvidenceReceiptV2,
    prompt: HumanAcceptancePromptV1,
    decision: HumanAcceptanceDecisionV1,
    human_receipt: CriterionEvidenceReceiptV2,
}

#[cfg(test)]
#[allow(clippy::too_many_lines)] // One fixture derives a reciprocally bound source, prompt, decision, and receipts.
fn test_criterion_source_bundle(
    spec: &SprintSpecV2,
    snapshot_digest: &Digest,
    recorded_at: u64,
) -> Result<TestCriterionSourceBundle, LedgerError> {
    if recorded_at < 2 {
        return Err(LedgerError::InvalidTimestamp(
            "test criterion source recorded_at",
        ));
    }
    let automated = spec
        .acceptance_criteria
        .iter()
        .find(|criterion| {
            criterion.criterion_id == "automated"
                && matches!(criterion.kind, AcceptanceKind::Automated(_))
        })
        .ok_or_else(|| LedgerError::ReferenceMismatch {
            entity: "test current criterion source",
            detail: "automated fixture criterion is absent".into(),
        })?;
    let human = spec
        .acceptance_criteria
        .iter()
        .find(|criterion| {
            criterion.criterion_id == "human"
                && matches!(criterion.kind, AcceptanceKind::HumanJudgment)
        })
        .ok_or_else(|| LedgerError::ReferenceMismatch {
            entity: "test current criterion source",
            detail: "human fixture criterion is absent".into(),
        })?;
    let mut automated_source = CurrentAutomatedCriterionVerificationSourceV1 {
        source_version: AUTOMATED_SOURCE_VERSION_V1,
        verification_receipt_id: "pending".into(),
        sprint_id: spec.sprint_id.clone(),
        criterion_id: automated.criterion_id.clone(),
        snapshot_digest: snapshot_digest.clone(),
        command_digest: command_digest(automated)?.ok_or_else(|| {
            LedgerError::ReferenceMismatch {
                entity: "test current criterion source",
                detail: "automated fixture has no command digest".into(),
            }
        })?,
        runner_effect_id: format!("test-criterion-effect:{snapshot_digest}"),
        runner_session_id: format!("test-criterion-session:{snapshot_digest}"),
        output_artifact_set_id: format!("test-criterion-output:{snapshot_digest}"),
        runner_cleanup_proof_id: format!("test-criterion-runner-cleanup:{snapshot_digest}"),
        command_domain_cleanup_proof_id: format!(
            "test-criterion-command-cleanup:{snapshot_digest}"
        ),
        verified_at_unix_ms: recorded_at - 1,
    };
    automated_source.verification_receipt_id =
        current_automated_verification_source_id(&automated_source).map_err(|detail| {
            LedgerError::Corrupt {
                entity: "test current automated source",
                detail,
            }
        })?;
    let mut automated_receipt = CriterionEvidenceReceiptV2::Verified {
        receipt_id: "pending".into(),
        sprint_id: spec.sprint_id.clone(),
        criterion_id: automated.criterion_id.clone(),
        snapshot_digest: snapshot_digest.clone(),
        verification_receipt_id: automated_source.verification_receipt_id.clone(),
        recorded_at,
    };
    let automated_receipt_id =
        current_criterion_evidence_receipt_id(&automated_receipt).map_err(|detail| {
            LedgerError::Corrupt {
                entity: "test current criterion receipt",
                detail,
            }
        })?;
    if let CriterionEvidenceReceiptV2::Verified { receipt_id, .. } = &mut automated_receipt {
        *receipt_id = automated_receipt_id;
    }

    let mut prompt = HumanAcceptancePromptV1 {
        prompt_id: "pending".into(),
        ui_session_id: format!("test-ui-session:{recorded_at}"),
        sprint_id: spec.sprint_id.clone(),
        criterion_id: human.criterion_id.clone(),
        criterion_text_digest: Digest::sha256(human.description.as_bytes()),
        snapshot_digest: snapshot_digest.clone(),
        workspace_grant_hash: spec.workspace_grant.grant_hash.clone(),
        rendered_claim_digest: Digest::sha256(
            format!("{}|{}|backing:1:1", human.description, snapshot_digest).as_bytes(),
        ),
        backing: HumanAcceptanceBackingV1::OneToOne,
        issued_event_sequence: recorded_at,
    };
    prompt.prompt_id = current_prompt_id(&prompt).map_err(|detail| LedgerError::Corrupt {
        entity: "test current human prompt",
        detail,
    })?;
    let decision = HumanAcceptanceDecisionV1 {
        decision_id: human_acceptance_decision_id(
            &prompt,
            HumanAcceptanceDecisionOutcomeV1::AcceptedByYou,
            prompt.issued_event_sequence,
            recorded_at,
        )?,
        prompt_id: prompt.prompt_id.clone(),
        outcome: HumanAcceptanceDecisionOutcomeV1::AcceptedByYou,
        consumed_event_sequence: prompt.issued_event_sequence,
        decided_at: recorded_at,
    };
    let mut human_receipt = CriterionEvidenceReceiptV2::AcceptedByYou {
        receipt_id: "pending".into(),
        sprint_id: spec.sprint_id.clone(),
        criterion_id: human.criterion_id.clone(),
        snapshot_digest: snapshot_digest.clone(),
        human_decision_id: decision.decision_id.clone(),
        prompt_id: prompt.prompt_id.clone(),
        backing: HumanAcceptanceBackingV1::OneToOne,
        recorded_at,
    };
    let human_receipt_id =
        current_criterion_evidence_receipt_id(&human_receipt).map_err(|detail| {
            LedgerError::Corrupt {
                entity: "test current criterion receipt",
                detail,
            }
        })?;
    if let CriterionEvidenceReceiptV2::AcceptedByYou { receipt_id, .. } = &mut human_receipt {
        *receipt_id = human_receipt_id;
    }
    Ok(TestCriterionSourceBundle {
        automated_source,
        automated_receipt,
        prompt,
        decision,
        human_receipt,
    })
}

#[cfg(test)]
pub(super) fn test_criterion_receipts_for_snapshot_v32(
    spec: &SprintSpecV2,
    snapshot_digest: &Digest,
    recorded_at: u64,
) -> Result<Vec<CriterionEvidenceReceiptV2>, LedgerError> {
    let bundle = test_criterion_source_bundle(spec, snapshot_digest, recorded_at)?;
    Ok(vec![bundle.automated_receipt, bundle.human_receipt])
}

#[cfg(test)]
pub(super) fn test_seed_criterion_sources_for_snapshot_v32(
    transaction: &Transaction<'_>,
    spec: &SprintSpecV2,
    snapshot_digest: &Digest,
    recorded_at: u64,
) -> Result<Vec<CriterionEvidenceReceiptV2>, LedgerError> {
    let bundle = test_criterion_source_bundle(spec, snapshot_digest, recorded_at)?;
    let load_optional =
        |receipt_id: &str| match load_current_criterion_receipt_from(transaction, receipt_id) {
            Ok(receipt) => Ok(Some(receipt)),
            Err(LedgerError::ArtifactNotFound { .. }) => Ok(None),
            Err(error) => Err(error),
        };
    let existing_automated = load_optional(bundle.automated_receipt.receipt_id())?;
    let existing_human = load_optional(bundle.human_receipt.receipt_id())?;
    match (existing_automated, existing_human) {
        (Some(automated), Some(human))
            if automated == bundle.automated_receipt && human == bundle.human_receipt =>
        {
            return Ok(vec![bundle.automated_receipt, bundle.human_receipt]);
        }
        (None, None) => {}
        _ => {
            return Err(LedgerError::ReferenceMismatch {
                entity: "test current criterion sources",
                detail: "fixture sources are partial or differ from exact canonical receipts"
                    .into(),
            });
        }
    }
    test_insert_automated_source(transaction, &bundle.automated_source)?;
    test_insert_criterion_receipt(transaction, &bundle.automated_receipt)?;
    test_insert_prompt(transaction, &bundle.prompt)?;
    test_insert_decision(transaction, &bundle.prompt, &bundle.decision)?;
    test_insert_criterion_receipt(transaction, &bundle.human_receipt)?;
    Ok(vec![bundle.automated_receipt, bundle.human_receipt])
}

#[cfg(test)]
fn test_insert_automated_source(
    transaction: &Transaction<'_>,
    source: &CurrentAutomatedCriterionVerificationSourceV1,
) -> Result<(), LedgerError> {
    source.validate().map_err(|detail| LedgerError::Corrupt {
        entity: "test current automated source",
        detail,
    })?;
    let permit = CurrentWritePermit {
        operation: "automated-source".into(),
        sprint_id: source.sprint_id.clone(),
        primary_id: source.verification_receipt_id.clone(),
        secondary_id: source.criterion_id.clone(),
    };
    with_write_permit(permit, || {
        transaction.execute(
            "INSERT INTO current_automated_verification_sources_v32 (
                verification_receipt_id, sprint_id, criterion_id,
                snapshot_digest, command_digest, runner_effect_id,
                runner_session_id, output_artifact_set_id,
                runner_cleanup_proof_id, command_domain_cleanup_proof_id,
                verified_at_unix_ms, source_json
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
            params![
                source.verification_receipt_id,
                source.sprint_id,
                source.criterion_id,
                source.snapshot_digest.as_str(),
                source.command_digest.as_str(),
                source.runner_effect_id,
                source.runner_session_id,
                source.output_artifact_set_id,
                source.runner_cleanup_proof_id,
                source.command_domain_cleanup_proof_id,
                sqlite_integer("test source verified_at", source.verified_at_unix_ms)?,
                encode("test current automated source", source)?,
            ],
        )?;
        Ok(())
    })
}

#[cfg(test)]
fn test_insert_prompt(
    transaction: &Transaction<'_>,
    prompt: &HumanAcceptancePromptV1,
) -> Result<(), LedgerError> {
    let permit = CurrentWritePermit {
        operation: "human-prompt".into(),
        sprint_id: prompt.sprint_id.clone(),
        primary_id: prompt.prompt_id.clone(),
        secondary_id: prompt.criterion_id.clone(),
    };
    with_write_permit(permit, || {
        transaction.execute(
            "INSERT INTO current_human_acceptance_prompts_v32 (
                prompt_id, ui_session_id, sprint_id, criterion_id,
                criterion_text_digest, snapshot_digest, workspace_grant_hash,
                rendered_claim_digest, backing, issued_event_sequence, prompt_json
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, 'OneToOne', ?9, ?10)",
            params![
                prompt.prompt_id,
                prompt.ui_session_id,
                prompt.sprint_id,
                prompt.criterion_id,
                prompt.criterion_text_digest.as_str(),
                prompt.snapshot_digest.as_str(),
                prompt.workspace_grant_hash.as_str(),
                prompt.rendered_claim_digest.as_str(),
                sqlite_integer("test prompt issued sequence", prompt.issued_event_sequence)?,
                encode("test current human prompt", prompt)?,
            ],
        )?;
        Ok(())
    })
}

#[cfg(test)]
fn test_insert_decision(
    transaction: &Transaction<'_>,
    prompt: &HumanAcceptancePromptV1,
    decision: &HumanAcceptanceDecisionV1,
) -> Result<(), LedgerError> {
    let permit = CurrentWritePermit {
        operation: "human-decision".into(),
        sprint_id: prompt.sprint_id.clone(),
        primary_id: decision.decision_id.clone(),
        secondary_id: prompt.prompt_id.clone(),
    };
    let outcome = match decision.outcome {
        HumanAcceptanceDecisionOutcomeV1::AcceptedByYou => "AcceptedByYou",
        HumanAcceptanceDecisionOutcomeV1::RejectedByYou => "RejectedByYou",
    };
    with_write_permit(permit, || {
        transaction.execute(
            "INSERT INTO current_human_acceptance_decisions_v32 (
                decision_id, prompt_id, sprint_id, criterion_id,
                snapshot_digest, outcome, consumed_event_sequence,
                decided_at_unix_ms, decision_json
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            params![
                decision.decision_id,
                decision.prompt_id,
                prompt.sprint_id,
                prompt.criterion_id,
                prompt.snapshot_digest.as_str(),
                outcome,
                sqlite_integer(
                    "test decision consumed sequence",
                    decision.consumed_event_sequence,
                )?,
                sqlite_integer("test decision decided_at", decision.decided_at)?,
                encode("test current human decision", decision)?,
            ],
        )?;
        Ok(())
    })
}

#[cfg(test)]
fn test_insert_criterion_receipt(
    transaction: &Transaction<'_>,
    receipt: &CriterionEvidenceReceiptV2,
) -> Result<(), LedgerError> {
    let permit = CurrentWritePermit {
        operation: "criterion-receipt".into(),
        sprint_id: receipt.sprint_id().to_owned(),
        primary_id: receipt.receipt_id().to_owned(),
        secondary_id: receipt.criterion_id().to_owned(),
    };
    let (kind, verification_id, decision_id, prompt_id, backing) = match receipt {
        CriterionEvidenceReceiptV2::Verified {
            verification_receipt_id,
            ..
        } => (
            "Verified",
            Some(verification_receipt_id.as_str()),
            None,
            None,
            None,
        ),
        CriterionEvidenceReceiptV2::AcceptedByYou {
            human_decision_id,
            prompt_id,
            backing: HumanAcceptanceBackingV1::OneToOne,
            ..
        } => (
            "AcceptedByYou",
            None,
            Some(human_decision_id.as_str()),
            Some(prompt_id.as_str()),
            Some("OneToOne"),
        ),
    };
    with_write_permit(permit, || {
        transaction.execute(
            "INSERT INTO current_criterion_evidence_receipts_v32 (
                receipt_id, sprint_id, criterion_id, snapshot_digest,
                evidence_kind, verification_receipt_id, human_decision_id,
                prompt_id, backing, recorded_at_unix_ms, receipt_json
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
            params![
                receipt.receipt_id(),
                receipt.sprint_id(),
                receipt.criterion_id(),
                receipt.snapshot_digest().as_str(),
                kind,
                verification_id,
                decision_id,
                prompt_id,
                backing,
                sqlite_integer("test criterion receipt recorded_at", receipt.recorded_at())?,
                encode("test current criterion receipt", receipt)?,
            ],
        )?;
        Ok(())
    })
}

#[cfg(test)]
fn test_consume_prompt(
    transaction: &Transaction<'_>,
    prompt_id: &str,
    outcome: HumanAcceptanceDecisionOutcomeV1,
    decided_at: u64,
) -> Result<
    (
        HumanAcceptanceDecisionV1,
        Option<CriterionEvidenceReceiptV2>,
    ),
    LedgerError,
> {
    let prompt = load_current_prompt_from(transaction, prompt_id)?;
    let decision = HumanAcceptanceDecisionV1 {
        decision_id: human_acceptance_decision_id(
            &prompt,
            outcome,
            prompt.issued_event_sequence,
            decided_at,
        )?,
        prompt_id: prompt.prompt_id.clone(),
        outcome,
        consumed_event_sequence: prompt.issued_event_sequence,
        decided_at,
    };
    test_insert_decision(transaction, &prompt, &decision)?;
    let evidence = if outcome == HumanAcceptanceDecisionOutcomeV1::AcceptedByYou {
        let mut receipt = CriterionEvidenceReceiptV2::AcceptedByYou {
            receipt_id: "pending".into(),
            sprint_id: prompt.sprint_id.clone(),
            criterion_id: prompt.criterion_id.clone(),
            snapshot_digest: prompt.snapshot_digest.clone(),
            human_decision_id: decision.decision_id.clone(),
            prompt_id: prompt.prompt_id.clone(),
            backing: HumanAcceptanceBackingV1::OneToOne,
            recorded_at: decided_at,
        };
        let derived = current_criterion_evidence_receipt_id(&receipt).map_err(|detail| {
            LedgerError::Corrupt {
                entity: "test current criterion receipt",
                detail,
            }
        })?;
        if let CriterionEvidenceReceiptV2::AcceptedByYou { receipt_id, .. } = &mut receipt {
            *receipt_id = derived;
        }
        test_insert_criterion_receipt(transaction, &receipt)?;
        Some(receipt)
    } else {
        None
    };
    Ok((decision, evidence))
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    use crate::{
        CommandSpec, ExecutionOrigin, PathScope, ProviderProfile,
        SPRINT_AUTHORITY_CONTRACT_VERSION_V2, SprintBudgetV2, TaskGraphV2, TaskPurposeV2,
        TaskSpecV2, WorkspaceGrant, WorkspaceNetworkPolicy, WorkspacePermissions,
    };

    use super::*;

    static NEXT_DATABASE: AtomicU64 = AtomicU64::new(1);

    struct TestDatabase {
        path: PathBuf,
    }

    impl TestDatabase {
        fn new(label: &str) -> Self {
            let ordinal = NEXT_DATABASE.fetch_add(1, Ordering::Relaxed);
            Self {
                path: std::env::temp_dir().join(format!(
                    "grok-build-current-criterion-{label}-{}-{ordinal}.sqlite3",
                    std::process::id()
                )),
            }
        }
    }

    impl Drop for TestDatabase {
        fn drop(&mut self) {
            for suffix in ["", "-wal", "-shm", "-launch-cleanup.lock"] {
                let _ = fs::remove_file(format!("{}{}", self.path.display(), suffix));
            }
        }
    }

    fn digest(character: char) -> Digest {
        Digest::parse(character.to_string().repeat(64)).expect("valid digest")
    }

    fn current_pair(sprint_id: &str) -> (SprintSpecV2, TaskGraphV2) {
        let criteria = vec![
            AcceptanceCriterion {
                criterion_id: "automated".into(),
                description: "Automated verification succeeds".into(),
                kind: AcceptanceKind::Automated(CommandSpec {
                    program: "cargo".into(),
                    arguments: vec!["test".into(), "--workspace".into()],
                    working_directory: PathBuf::new(),
                }),
            },
            AcceptanceCriterion {
                criterion_id: "human".into(),
                description: "Human accepts the exact rendered result".into(),
                kind: AcceptanceKind::HumanJudgment,
            },
        ];
        let graph_id = format!("graph-{sprint_id}");
        let mut graph = TaskGraphV2 {
            sprint_authority_version: SPRINT_AUTHORITY_CONTRACT_VERSION_V2,
            graph_id: graph_id.clone(),
            sprint_id: sprint_id.into(),
            sprint_spec_digest: digest('0'),
            repair_slot_reserve_digest: digest('0'),
            tasks: vec![TaskSpecV2 {
                sprint_authority_version: SPRINT_AUTHORITY_CONTRACT_VERSION_V2,
                task_id: "ordinary".into(),
                purpose: TaskPurposeV2::Ordinary,
                goal: "Produce a criterion-evidence source".into(),
                dependencies: Vec::new(),
                path_scopes: vec![PathScope::Workspace],
                acceptance_checks: vec!["automated".into(), "human".into()],
                base_snapshot: digest('b'),
                required: true,
            }],
        };
        graph.repair_slot_reserve_digest = graph
            .computed_repair_slot_reserve_digest()
            .expect("repair reserve digest");
        let mut spec = SprintSpecV2 {
            sprint_authority_version: SPRINT_AUTHORITY_CONTRACT_VERSION_V2,
            sprint_id: sprint_id.into(),
            objective: "Exercise exact current criterion evidence".into(),
            acceptance_criteria: criteria,
            provider: ProviderProfile {
                backend_id: "fake".into(),
                model_id: "deterministic".into(),
                execution_origin: ExecutionOrigin::HostIsolated,
            },
            budget: SprintBudgetV2 {
                sprint_authority_version: SPRINT_AUTHORITY_CONTRACT_VERSION_V2,
                max_tasks: 1,
                max_attempts_per_task: 1,
                max_final_verification_attempts: 1,
                max_tool_calls: 10,
                max_duration_ms: 60_000,
            },
            max_workers: 1,
            workspace_grant: WorkspaceGrant {
                grant_id: format!("grant-{sprint_id}"),
                canonical_root: PathBuf::from("/work/project"),
                permissions: WorkspacePermissions::trusted(),
                network: WorkspaceNetworkPolicy::Denied,
                policy_version: 1,
                grant_hash: digest('a'),
            },
            base_snapshot: digest('b'),
            task_graph_id: graph_id,
            task_graph_payload_digest: graph.payload_digest().expect("graph payload digest"),
            repair_slot_reserve_digest: graph.repair_slot_reserve_digest.clone(),
        };
        graph.sprint_spec_digest = spec.canonical_digest().expect("sprint digest");
        spec.task_graph_payload_digest = graph.payload_digest().expect("stable graph payload");
        graph
            .validate_for_sprint(&spec)
            .expect("valid current pair");
        (spec, graph)
    }

    fn create_ledger(label: &str, sprint_id: &str) -> (TestDatabase, EventLedger, SprintSpecV2) {
        let database = TestDatabase::new(label);
        let mut ledger = EventLedger::open(&database.path).expect("open current ledger");
        let (spec, graph) = current_pair(sprint_id);
        ledger
            .create_current_sprint_authority_v32(&spec, &graph, 10)
            .expect("create current sprint authority");
        let transaction = ledger
            .connection
            .transaction()
            .expect("begin criterion projection");
        project_current_sprint_criteria_v32(&transaction, &spec)
            .expect("project exact current criteria");
        project_current_sprint_criteria_v32(&transaction, &spec)
            .expect("identical projection is idempotent");
        transaction.commit().expect("commit criterion projection");
        (database, ledger, spec)
    }

    fn automated_source(
        ledger: &EventLedger,
        sprint_id: &str,
        snapshot: char,
        verified_at_unix_ms: u64,
    ) -> CurrentAutomatedCriterionVerificationSourceV1 {
        let projection = ledger
            .load_current_sprint_criteria_v32(sprint_id)
            .expect("load criteria")
            .into_iter()
            .find(|value| value.criterion.criterion_id == "automated")
            .expect("automated projection");
        let mut source = CurrentAutomatedCriterionVerificationSourceV1 {
            source_version: AUTOMATED_SOURCE_VERSION_V1,
            verification_receipt_id: "pending".into(),
            sprint_id: sprint_id.into(),
            criterion_id: "automated".into(),
            snapshot_digest: digest(snapshot),
            command_digest: projection.command_digest.expect("command digest"),
            runner_effect_id: format!("effect-{snapshot}"),
            runner_session_id: format!("session-{snapshot}"),
            output_artifact_set_id: format!("output-{snapshot}"),
            runner_cleanup_proof_id: format!("runner-cleanup-{snapshot}"),
            command_domain_cleanup_proof_id: format!("domain-cleanup-{snapshot}"),
            verified_at_unix_ms,
        };
        source.verification_receipt_id =
            current_automated_verification_source_id(&source).expect("derive source identity");
        source
    }

    fn verified_receipt(
        source: &CurrentAutomatedCriterionVerificationSourceV1,
        criterion_id: &str,
        snapshot: char,
        recorded_at: u64,
    ) -> CriterionEvidenceReceiptV2 {
        let mut receipt = CriterionEvidenceReceiptV2::Verified {
            receipt_id: "pending".into(),
            sprint_id: source.sprint_id.clone(),
            criterion_id: criterion_id.into(),
            snapshot_digest: digest(snapshot),
            verification_receipt_id: source.verification_receipt_id.clone(),
            recorded_at,
        };
        let identity =
            current_criterion_evidence_receipt_id(&receipt).expect("derive receipt identity");
        if let CriterionEvidenceReceiptV2::Verified { receipt_id, .. } = &mut receipt {
            *receipt_id = identity;
        }
        receipt
    }

    fn human_prompt(
        spec: &SprintSpecV2,
        snapshot: char,
        issued_event_sequence: u64,
    ) -> HumanAcceptancePromptV1 {
        let criterion = spec
            .acceptance_criteria
            .iter()
            .find(|value| value.criterion_id == "human")
            .expect("human criterion");
        let mut prompt = HumanAcceptancePromptV1 {
            prompt_id: "pending".into(),
            ui_session_id: "trusted-ui-session".into(),
            sprint_id: spec.sprint_id.clone(),
            criterion_id: criterion.criterion_id.clone(),
            criterion_text_digest: Digest::sha256(criterion.description.as_bytes()),
            snapshot_digest: digest(snapshot),
            workspace_grant_hash: spec.workspace_grant.grant_hash.clone(),
            rendered_claim_digest: Digest::sha256(
                format!("{}|{}|backing:1:1", criterion.description, digest(snapshot)).as_bytes(),
            ),
            backing: HumanAcceptanceBackingV1::OneToOne,
            issued_event_sequence,
        };
        prompt.prompt_id = current_prompt_id(&prompt).expect("derive prompt identity");
        prompt
    }

    #[test]
    fn current_projection_is_exact_current_only_immutable_and_restart_safe() {
        let (database, ledger, spec) = create_ledger("projection", "sprint-projection");
        let projected = ledger
            .load_current_sprint_criteria_v32(&spec.sprint_id)
            .expect("load exact projection");
        assert_eq!(
            projected,
            derive_projections(&spec).expect("derive projection")
        );
        assert_eq!(projected[0].criterion_ordinal, 0);
        assert!(projected[0].command_digest.is_some());
        assert_eq!(projected[1].criterion_ordinal, 1);
        assert!(projected[1].command_digest.is_none());

        let schema_sql: String = ledger
            .connection
            .query_row(
                "SELECT group_concat(sql, '\n') FROM sqlite_schema
                 WHERE name LIKE 'current_%criterion%v32'
                    OR name LIKE 'current_human_acceptance_%v32'
                    OR name = 'current_automated_verification_sources_v32'",
                [],
                |row| row.get(0),
            )
            .expect("read current-only schema");
        assert!(!schema_sql.contains("REFERENCES sprints("));
        assert!(!schema_sql.contains("human_acceptance_prompts_v1"));
        assert!(!schema_sql.contains("human_acceptance_decisions_v1"));
        assert!(!schema_sql.contains("criterion_evidence_receipts_v2"));

        assert!(
            ledger
                .connection
                .execute(
                    "INSERT INTO current_sprint_criteria_v32 (
                        sprint_id, criterion_id, criterion_ordinal, criterion_kind,
                        criterion_text_digest, command_digest, sprint_spec_digest,
                        criterion_json
                     ) SELECT sprint_id, 'forged', 9, criterion_kind,
                              criterion_text_digest, command_digest,
                              sprint_spec_digest, criterion_json
                       FROM current_sprint_criteria_v32
                       WHERE sprint_id = ?1 AND criterion_id = 'automated'",
                    [spec.sprint_id.as_str()],
                )
                .is_err(),
            "direct SQL must not create a projection"
        );
        assert!(
            ledger
                .connection
                .execute(
                    "UPDATE current_sprint_criteria_v32 SET criterion_ordinal = 9
                     WHERE sprint_id = ?1 AND criterion_id = 'automated'",
                    [spec.sprint_id.as_str()],
                )
                .is_err(),
            "projection must be immutable"
        );

        drop(ledger);
        let reader = EventLedger::open_read_only(&database.path).expect("restart read-only");
        assert_eq!(
            reader
                .load_current_sprint_criteria_v32(&spec.sprint_id)
                .expect("read projection after restart"),
            projected
        );
    }

    #[test]
    fn current_verified_receipt_requires_exact_source_snapshot_kind_time_and_restart_readback() {
        let (database, mut ledger, spec) = create_ledger("verified", "sprint-verified");
        let source_c = automated_source(&ledger, &spec.sprint_id, 'c', 20);
        let receipt_c = verified_receipt(&source_c, "automated", 'c', 21);
        let transaction = ledger.connection.transaction().expect("begin exact source");
        test_insert_automated_source(&transaction, &source_c).expect("insert exact source");
        test_insert_criterion_receipt(&transaction, &receipt_c).expect("insert exact receipt");
        transaction.commit().expect("commit exact machine evidence");
        assert_eq!(
            load_current_automated_source_from(
                &ledger.connection,
                &source_c.verification_receipt_id
            )
            .expect("load source"),
            source_c
        );
        assert_eq!(
            load_current_criterion_receipt_from(&ledger.connection, receipt_c.receipt_id())
                .expect("load verified receipt"),
            receipt_c
        );

        assert!(
            ledger
                .connection
                .execute(
                    "INSERT INTO current_automated_verification_sources_v32
                     SELECT 'direct-forgery', sprint_id, criterion_id,
                            snapshot_digest, command_digest, runner_effect_id,
                            runner_session_id, output_artifact_set_id,
                            runner_cleanup_proof_id, command_domain_cleanup_proof_id,
                            verified_at_unix_ms, source_json
                     FROM current_automated_verification_sources_v32
                     WHERE verification_receipt_id = ?1",
                    [source_c.verification_receipt_id.as_str()],
                )
                .is_err(),
            "direct SQL must not manufacture a machine source"
        );

        let source_d = automated_source(&ledger, &spec.sprint_id, 'd', 30);
        let transaction = ledger
            .connection
            .transaction()
            .expect("begin negative sources");
        test_insert_automated_source(&transaction, &source_d).expect("insert second source");
        let stale = verified_receipt(&source_d, "automated", 'd', 29);
        assert!(
            test_insert_criterion_receipt(&transaction, &stale).is_err(),
            "evidence cannot predate its exact source"
        );
        let crossed_snapshot = verified_receipt(&source_d, "automated", 'e', 31);
        assert!(
            test_insert_criterion_receipt(&transaction, &crossed_snapshot).is_err(),
            "evidence cannot cross the source snapshot"
        );
        let crossed_kind = verified_receipt(&source_d, "human", 'd', 31);
        assert!(
            test_insert_criterion_receipt(&transaction, &crossed_kind).is_err(),
            "machine evidence cannot satisfy a human criterion"
        );
        transaction.rollback().expect("rollback negative sources");

        drop(ledger);
        let reader = EventLedger::open_read_only(&database.path).expect("restart read-only");
        assert_eq!(
            load_current_criterion_receipt_from(&reader.connection, receipt_c.receipt_id())
                .expect("read exact machine evidence after restart"),
            receipt_c
        );
    }

    #[test]
    #[allow(clippy::too_many_lines)] // One table-driven authority cut covers all four immutable record classes.
    fn current_insert_triggers_reject_canonical_json_index_mismatches() {
        let (_database, mut ledger, spec) =
            create_ledger("indexed-envelope", "sprint-indexed-envelope");
        let source = automated_source(&ledger, &spec.sprint_id, 'c', 20);
        let prompt = human_prompt(&spec, 'c', 1);
        let rejected_decision = HumanAcceptanceDecisionV1 {
            decision_id: human_acceptance_decision_id(
                &prompt,
                HumanAcceptanceDecisionOutcomeV1::RejectedByYou,
                prompt.issued_event_sequence,
                21,
            )
            .expect("derive rejected decision"),
            prompt_id: prompt.prompt_id.clone(),
            outcome: HumanAcceptanceDecisionOutcomeV1::RejectedByYou,
            consumed_event_sequence: prompt.issued_event_sequence,
            decided_at: 21,
        };
        let receipt = verified_receipt(&source, "automated", 'c', 21);
        let transaction = ledger
            .connection
            .transaction()
            .expect("begin indexed-envelope mismatch probes");

        let source_result = with_write_permit(
            CurrentWritePermit {
                operation: "automated-source".into(),
                sprint_id: source.sprint_id.clone(),
                primary_id: source.verification_receipt_id.clone(),
                secondary_id: source.criterion_id.clone(),
            },
            || {
                transaction.execute(
                    "INSERT INTO current_automated_verification_sources_v32 (
                        verification_receipt_id, sprint_id, criterion_id,
                        snapshot_digest, command_digest, runner_effect_id,
                        runner_session_id, output_artifact_set_id,
                        runner_cleanup_proof_id, command_domain_cleanup_proof_id,
                        verified_at_unix_ms, source_json
                     ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
                    params![
                        source.verification_receipt_id,
                        source.sprint_id,
                        source.criterion_id,
                        source.snapshot_digest.as_str(),
                        source.command_digest.as_str(),
                        source.runner_effect_id,
                        "crossed-runner-session",
                        source.output_artifact_set_id,
                        source.runner_cleanup_proof_id,
                        source.command_domain_cleanup_proof_id,
                        sqlite_integer(
                            "mismatched source verified_at",
                            source.verified_at_unix_ms
                        )?,
                        encode("mismatched current automated source", &source)?,
                    ],
                )?;
                Ok(())
            },
        );
        assert!(
            source_result.is_err(),
            "canonical source JSON cannot disagree with an indexed source identity"
        );
        test_insert_automated_source(&transaction, &source).expect("insert valid source");

        let prompt_result = with_write_permit(
            CurrentWritePermit {
                operation: "human-prompt".into(),
                sprint_id: prompt.sprint_id.clone(),
                primary_id: prompt.prompt_id.clone(),
                secondary_id: prompt.criterion_id.clone(),
            },
            || {
                transaction.execute(
                    "INSERT INTO current_human_acceptance_prompts_v32 (
                        prompt_id, ui_session_id, sprint_id, criterion_id,
                        criterion_text_digest, snapshot_digest, workspace_grant_hash,
                        rendered_claim_digest, backing, issued_event_sequence, prompt_json
                     ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, 'OneToOne', ?9, ?10)",
                    params![
                        prompt.prompt_id,
                        "crossed-ui-session",
                        prompt.sprint_id,
                        prompt.criterion_id,
                        prompt.criterion_text_digest.as_str(),
                        prompt.snapshot_digest.as_str(),
                        prompt.workspace_grant_hash.as_str(),
                        prompt.rendered_claim_digest.as_str(),
                        sqlite_integer(
                            "mismatched prompt issued sequence",
                            prompt.issued_event_sequence,
                        )?,
                        encode("mismatched current human prompt", &prompt)?,
                    ],
                )?;
                Ok(())
            },
        );
        assert!(
            prompt_result.is_err(),
            "canonical prompt JSON cannot disagree with its indexed UI session"
        );
        test_insert_prompt(&transaction, &prompt).expect("insert valid prompt");

        let decision_result = with_write_permit(
            CurrentWritePermit {
                operation: "human-decision".into(),
                sprint_id: prompt.sprint_id.clone(),
                primary_id: rejected_decision.decision_id.clone(),
                secondary_id: prompt.prompt_id.clone(),
            },
            || {
                transaction.execute(
                    "INSERT INTO current_human_acceptance_decisions_v32 (
                        decision_id, prompt_id, sprint_id, criterion_id,
                        snapshot_digest, outcome, consumed_event_sequence,
                        decided_at_unix_ms, decision_json
                     ) VALUES (?1, ?2, ?3, ?4, ?5, 'AcceptedByYou', ?6, ?7, ?8)",
                    params![
                        rejected_decision.decision_id,
                        rejected_decision.prompt_id,
                        prompt.sprint_id,
                        prompt.criterion_id,
                        prompt.snapshot_digest.as_str(),
                        sqlite_integer(
                            "mismatched decision consumed sequence",
                            rejected_decision.consumed_event_sequence,
                        )?,
                        sqlite_integer(
                            "mismatched decision decided_at",
                            rejected_decision.decided_at,
                        )?,
                        encode("mismatched current human decision", &rejected_decision)?,
                    ],
                )?;
                Ok(())
            },
        );
        assert!(
            decision_result.is_err(),
            "indexed AcceptedByYou cannot wrap canonical RejectedByYou JSON"
        );

        let receipt_result = with_write_permit(
            CurrentWritePermit {
                operation: "criterion-receipt".into(),
                sprint_id: receipt.sprint_id().to_owned(),
                primary_id: receipt.receipt_id().to_owned(),
                secondary_id: receipt.criterion_id().to_owned(),
            },
            || {
                let CriterionEvidenceReceiptV2::Verified {
                    verification_receipt_id,
                    ..
                } = &receipt
                else {
                    unreachable!("fixture is machine verification")
                };
                transaction.execute(
                    "INSERT INTO current_criterion_evidence_receipts_v32 (
                        receipt_id, sprint_id, criterion_id, snapshot_digest,
                        evidence_kind, verification_receipt_id, human_decision_id,
                        prompt_id, backing, recorded_at_unix_ms, receipt_json
                     ) VALUES (?1, ?2, ?3, ?4, 'Verified', ?5, NULL, NULL, NULL, ?6, ?7)",
                    params![
                        receipt.receipt_id(),
                        receipt.sprint_id(),
                        receipt.criterion_id(),
                        receipt.snapshot_digest().as_str(),
                        verification_receipt_id,
                        sqlite_integer(
                            "mismatched criterion receipt recorded_at",
                            receipt.recorded_at() + 1,
                        )?,
                        encode("mismatched current criterion receipt", &receipt)?,
                    ],
                )?;
                Ok(())
            },
        );
        assert!(
            receipt_result.is_err(),
            "canonical receipt JSON cannot disagree with its indexed timestamp"
        );
        transaction
            .rollback()
            .expect("rollback indexed-envelope mismatch probes");
    }

    #[test]
    #[allow(clippy::too_many_lines)] // One lifecycle proves rollback, commit, replay, crossing, rejection, and restart.
    fn current_human_consumption_is_one_to_one_atomic_cross_checked_and_replay_safe() {
        let (database, mut ledger, spec) = create_ledger("human", "sprint-human");
        let prompt = human_prompt(&spec, 'c', 1);
        assert!(
            ledger
                .connection
                .execute(
                    "INSERT INTO current_human_acceptance_prompts_v32 (
                        prompt_id, ui_session_id, sprint_id, criterion_id,
                        criterion_text_digest, snapshot_digest, workspace_grant_hash,
                        rendered_claim_digest, backing, issued_event_sequence, prompt_json
                     ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, 'OneToOne', 1, ?9)",
                    params![
                        prompt.prompt_id,
                        prompt.ui_session_id,
                        prompt.sprint_id,
                        prompt.criterion_id,
                        prompt.criterion_text_digest.as_str(),
                        prompt.snapshot_digest.as_str(),
                        prompt.workspace_grant_hash.as_str(),
                        prompt.rendered_claim_digest.as_str(),
                        encode("direct current prompt", &prompt).expect("encode direct prompt"),
                    ],
                )
                .is_err(),
            "direct SQL must not manufacture a human prompt"
        );
        let transaction = ledger.connection.transaction().expect("begin prompt");
        test_insert_prompt(&transaction, &prompt).expect("insert exact test prompt");
        transaction.commit().expect("commit test prompt");

        let direct_decision = HumanAcceptanceDecisionV1 {
            decision_id: human_acceptance_decision_id(
                &prompt,
                HumanAcceptanceDecisionOutcomeV1::AcceptedByYou,
                prompt.issued_event_sequence,
                20,
            )
            .expect("derive direct decision"),
            prompt_id: prompt.prompt_id.clone(),
            outcome: HumanAcceptanceDecisionOutcomeV1::AcceptedByYou,
            consumed_event_sequence: prompt.issued_event_sequence,
            decided_at: 20,
        };
        assert!(
            ledger
                .connection
                .execute(
                    "INSERT INTO current_human_acceptance_decisions_v32 (
                        decision_id, prompt_id, sprint_id, criterion_id,
                        snapshot_digest, outcome, consumed_event_sequence,
                        decided_at_unix_ms, decision_json
                     ) VALUES (?1, ?2, ?3, 'human', ?4, 'AcceptedByYou', 1, 20, ?5)",
                    params![
                        direct_decision.decision_id,
                        direct_decision.prompt_id,
                        spec.sprint_id,
                        digest('c').as_str(),
                        encode("direct current decision", &direct_decision)
                            .expect("encode direct decision"),
                    ],
                )
                .is_err(),
            "direct SQL must not manufacture a human decision"
        );

        let transaction = ledger
            .connection
            .transaction()
            .expect("begin rolled-back consumption");
        let (rolled_back_decision, rolled_back_evidence) = test_consume_prompt(
            &transaction,
            &prompt.prompt_id,
            HumanAcceptanceDecisionOutcomeV1::AcceptedByYou,
            20,
        )
        .expect("stage atomic consumption");
        assert!(rolled_back_evidence.is_some());
        transaction
            .rollback()
            .expect("rollback complete consumption");
        assert!(matches!(
            load_current_decision_from(&ledger.connection, &rolled_back_decision.decision_id),
            Err(LedgerError::ArtifactNotFound { .. })
        ));

        let transaction = ledger
            .connection
            .transaction()
            .expect("begin committed consumption");
        let (decision, evidence) = test_consume_prompt(
            &transaction,
            &prompt.prompt_id,
            HumanAcceptanceDecisionOutcomeV1::AcceptedByYou,
            20,
        )
        .expect("consume exact prompt once");
        let evidence = evidence.expect("accepted-by-you evidence");
        transaction.commit().expect("commit atomic consumption");
        assert_eq!(
            load_current_decision_from(&ledger.connection, &decision.decision_id)
                .expect("load accepted decision"),
            decision
        );
        assert_eq!(
            load_current_criterion_receipt_from(&ledger.connection, evidence.receipt_id())
                .expect("load accepted-by-you evidence"),
            evidence
        );
        assert!(
            ledger
                .connection
                .execute(
                    "INSERT INTO current_criterion_evidence_receipts_v32
                     SELECT 'direct-forgery', sprint_id, criterion_id,
                            snapshot_digest, evidence_kind, verification_receipt_id,
                            human_decision_id, prompt_id, backing,
                            recorded_at_unix_ms, receipt_json
                     FROM current_criterion_evidence_receipts_v32
                     WHERE receipt_id = ?1",
                    [evidence.receipt_id()],
                )
                .is_err(),
            "direct SQL must not manufacture accepted-by-you evidence"
        );

        let transaction = ledger.connection.transaction().expect("begin replay");
        assert!(
            test_consume_prompt(
                &transaction,
                &prompt.prompt_id,
                HumanAcceptanceDecisionOutcomeV1::AcceptedByYou,
                21,
            )
            .is_err(),
            "one prompt cannot be consumed twice"
        );
        transaction.rollback().expect("rollback replay");

        let prompt_d = human_prompt(&spec, 'd', 2);
        let transaction = ledger
            .connection
            .transaction()
            .expect("begin crossed prompt");
        test_insert_prompt(&transaction, &prompt_d).expect("insert next prompt cut");
        let stale_decision = HumanAcceptanceDecisionV1 {
            decision_id: human_acceptance_decision_id(
                &prompt_d,
                HumanAcceptanceDecisionOutcomeV1::AcceptedByYou,
                3,
                30,
            )
            .expect("derive stale decision"),
            prompt_id: prompt_d.prompt_id.clone(),
            outcome: HumanAcceptanceDecisionOutcomeV1::AcceptedByYou,
            consumed_event_sequence: 3,
            decided_at: 30,
        };
        assert!(
            test_insert_decision(&transaction, &prompt_d, &stale_decision).is_err(),
            "decision cannot move beyond the exact issued event cut"
        );
        let crossed_decision = HumanAcceptanceDecisionV1 {
            decision_id: human_acceptance_decision_id(
                &prompt_d,
                HumanAcceptanceDecisionOutcomeV1::AcceptedByYou,
                2,
                30,
            )
            .expect("derive crossed decision"),
            prompt_id: prompt_d.prompt_id.clone(),
            outcome: HumanAcceptanceDecisionOutcomeV1::AcceptedByYou,
            consumed_event_sequence: 2,
            decided_at: 30,
        };
        test_insert_decision(&transaction, &prompt_d, &crossed_decision)
            .expect("insert second accepted decision");
        let mut crossed_receipt = CriterionEvidenceReceiptV2::AcceptedByYou {
            receipt_id: "pending".into(),
            sprint_id: spec.sprint_id.clone(),
            criterion_id: "human".into(),
            snapshot_digest: digest('e'),
            human_decision_id: crossed_decision.decision_id.clone(),
            prompt_id: prompt_d.prompt_id.clone(),
            backing: HumanAcceptanceBackingV1::OneToOne,
            recorded_at: 30,
        };
        let crossed_id = current_criterion_evidence_receipt_id(&crossed_receipt)
            .expect("derive crossed receipt");
        if let CriterionEvidenceReceiptV2::AcceptedByYou { receipt_id, .. } = &mut crossed_receipt {
            *receipt_id = crossed_id;
        }
        assert!(
            test_insert_criterion_receipt(&transaction, &crossed_receipt).is_err(),
            "accepted-by-you evidence cannot cross its prompt snapshot"
        );
        transaction.rollback().expect("rollback crossed decision");

        let rejected_prompt = human_prompt(&spec, 'e', 3);
        let transaction = ledger.connection.transaction().expect("begin rejection");
        test_insert_prompt(&transaction, &rejected_prompt).expect("insert rejection prompt");
        let (rejected, rejected_evidence) = test_consume_prompt(
            &transaction,
            &rejected_prompt.prompt_id,
            HumanAcceptanceDecisionOutcomeV1::RejectedByYou,
            40,
        )
        .expect("record rejection");
        assert!(rejected_evidence.is_none());
        transaction.commit().expect("commit rejection");
        assert_eq!(
            load_current_decision_from(&ledger.connection, &rejected.decision_id)
                .expect("load rejection")
                .outcome,
            HumanAcceptanceDecisionOutcomeV1::RejectedByYou
        );

        drop(ledger);
        let reader = EventLedger::open_read_only(&database.path).expect("restart read-only");
        assert_eq!(
            load_current_decision_from(&reader.connection, &decision.decision_id)
                .expect("read decision after restart"),
            decision
        );
        assert_eq!(
            load_current_criterion_receipt_from(&reader.connection, evidence.receipt_id())
                .expect("read accepted-by-you evidence after restart"),
            evidence
        );
    }
}
