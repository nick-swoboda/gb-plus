//! Ledger-derived schema-v15 task-attempt recovery projection.
//!
//! Caller facts are comparison inputs only. Every identity is reopened through
//! its canonical durable aggregate before the pure contract projection runs.

use rusqlite::{Connection, OptionalExtension, params};
use serde::Serialize;

use super::{
    EventLedger, LedgerError, PersistedFinishReceipt, PersistedRunnerLaunchPreparation,
    RunnerLaunchPreparationDisposition, RunnerLaunchPreparationOutcome,
    command_output_capture_authority, encode, load_effect_from, load_effect_from_for_recovery,
    load_effect_runner_binding, load_effects_from, load_runner_session_policy_from,
    load_sprint_inputs, load_sprint_inputs_for_recovery, load_task_attempt_history_for_recovery,
    load_task_attempt_history_from, load_task_attempt_unknown_pending_marker, reference_mismatch,
    runner_launch_cleanup_admission, sqlite_integer, task_attempt_authority,
    validate_terminal_effect_admission, worker_lease_authority,
};
use crate::{
    CONTRACT_VERSION, Digest, EffectKind, EffectReconciliation, LegacyTaskAttemptClassification,
    NonSuccessTerminalState, RunnerLaunchIntent, RunnerSessionPolicyRecord, RunnerSessionPurpose,
    SprintUnknownTerminalizationPending, TaskAttempt, TaskAttemptDisposition,
    TaskAttemptHistoryEntry, TaskAttemptKnownCleanupOutcome, TaskAttemptLeaseState,
    TaskAttemptRetryableCause,
};
use crate::{TaskAttemptRecoveryDecision, TaskAttemptRecoveryFacts};

const RECOVERY_MATRIX_DOMAIN: &[u8] = b"grok-build/task-attempt-recovery-matrix/v1\0";
const RECOVERY_MATRIX_PREFIX: &str = "recovery-matrix-";

#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct RecoveryMatrixPreimage {
    contract_version: u32,
    marker: SprintUnknownTerminalizationPending,
    tasks: Vec<RecoveryMatrixTask>,
}

#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct RecoveryMatrixTask {
    task_id: String,
    attempts: Vec<RecoveryMatrixAttempt>,
}

#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct RecoveryMatrixAttempt {
    attempt: TaskAttempt,
    disposition: Option<TaskAttemptDisposition>,
    legacy_classification: Option<LegacyTaskAttemptClassification>,
    lease_state: TaskAttemptLeaseState,
}

struct ExactOpenLaunch {
    launch: RunnerLaunchIntent,
    session: Option<RunnerSessionPolicyRecord>,
    preparation: Option<PersistedRunnerLaunchPreparation>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum UnresolvedAuthorityKind {
    Effect,
    Preparation,
}

/// The one ledger-derived recovery projection for an exact task attempt.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LedgerTaskAttemptRecoveryProjection {
    /// Exact facts reconstructed from durable authority, never caller input.
    pub facts: TaskAttemptRecoveryFacts,
    /// Closed recovery action computed from those exact facts and history.
    pub decision: TaskAttemptRecoveryDecision,
}

impl EventLedger {
    /// Loads the sole recovery action after deriving its facts from one exact
    /// `SQLite` snapshot of durable schema-v15/legacy authority.
    ///
    /// # Errors
    ///
    /// Returns a ledger error for absent, ambiguous, crossed, unsupported, or
    /// corrupt recovery authority.
    pub fn load_task_attempt_recovery_projection(
        &self,
        sprint_id: &str,
        task_id: &str,
        attempt_id: &str,
    ) -> Result<LedgerTaskAttemptRecoveryProjection, LedgerError> {
        let transaction = self.connection.unchecked_transaction()?;
        let facts = derive_recovery_facts(&transaction, sprint_id, task_id, attempt_id)?;
        let decision = validate_and_project_recovery_from(
            &transaction,
            sprint_id,
            task_id,
            attempt_id,
            &facts,
        )?;
        transaction.commit()?;
        Ok(LedgerTaskAttemptRecoveryProjection { facts, decision })
    }

    /// Validation-only hook for internal contract and crossed-authority tests.
    ///
    /// `facts` never authorize execution by themselves. Crossed, stale, or
    /// invented attempt, lease, launch, session, effect, preparation, source,
    /// marker, or matrix identities fail before the pure projection runs.
    ///
    /// # Errors
    ///
    /// Returns a ledger error for absent/corrupt durable authority, a fact that
    /// is not the exact current ledger projection, or a contract-incompatible
    /// recovery decision.
    #[cfg(test)]
    pub(crate) fn project_task_attempt_recovery_decision(
        &self,
        sprint_id: &str,
        task_id: &str,
        attempt_id: &str,
        facts: &TaskAttemptRecoveryFacts,
    ) -> Result<TaskAttemptRecoveryDecision, LedgerError> {
        let transaction = self.connection.unchecked_transaction()?;
        let decision = validate_and_project_recovery_from(
            &transaction,
            sprint_id,
            task_id,
            attempt_id,
            facts,
        )?;
        transaction.commit()?;
        Ok(decision)
    }

    /// Recomputes the current all-domains terminal recovery identity.
    ///
    /// The returned `recovery-matrix-<64hex>` value is domain-separated
    /// comparison state derived from the exact open marker plus the ordered
    /// task-attempt/disposition/lease matrix. It is not persisted authority.
    ///
    /// # Errors
    ///
    /// Returns a ledger error unless an exact marker is open and every attempt
    /// and active lease has the terminal shape required for sprint Unknown.
    pub fn load_task_attempt_recovery_matrix_evidence_id(
        &self,
        sprint_id: &str,
    ) -> Result<String, LedgerError> {
        let transaction = self.connection.unchecked_transaction()?;
        let identity = derive_recovery_matrix_evidence_id(&transaction, sprint_id)?;
        transaction.commit()?;
        Ok(identity)
    }
}

fn validate_and_project_recovery_from(
    connection: &Connection,
    sprint_id: &str,
    task_id: &str,
    attempt_id: &str,
    facts: &TaskAttemptRecoveryFacts,
) -> Result<TaskAttemptRecoveryDecision, LedgerError> {
    facts.validate()?;
    let (spec, graph, _) = load_sprint_inputs_for_recovery(connection, sprint_id)?;
    let task = graph.task(task_id).ok_or_else(|| {
        reference_mismatch(
            "task attempt recovery",
            format!("task `{task_id}` is absent from the durable graph"),
        )
    })?;
    let history = load_task_attempt_history_for_recovery(connection, sprint_id, task_id)?;
    let entry = history
        .attempts
        .iter()
        .find(|entry| entry.attempt.attempt_id == attempt_id)
        .ok_or_else(|| {
            reference_mismatch(
                "task attempt recovery",
                format!("attempt `{attempt_id}` is absent from the exact task history"),
            )
        })?;

    // The history loader has already reopened migrated classifications
    // through their exact schema-v14/v15 compatibility path. Current
    // authority helpers deliberately apply only to non-legacy attempts.
    if entry.legacy_classification.is_none() {
        task_attempt_authority::require_exact_for_recovery(connection, &entry.attempt)?;
        worker_lease_authority::require_exact_for_recovery(
            connection,
            &entry.attempt.worker_lease,
            entry.lease_state.is_active(),
        )?;
    }
    validate_recovery_facts_from_ledger(connection, sprint_id, entry, facts)?;

    history
        .project_recovery_decision(&spec, task, attempt_id, facts)
        .map_err(LedgerError::from)
}

pub(super) fn derive_recovery_facts(
    connection: &Connection,
    sprint_id: &str,
    task_id: &str,
    attempt_id: &str,
) -> Result<TaskAttemptRecoveryFacts, LedgerError> {
    let history = load_task_attempt_history_for_recovery(connection, sprint_id, task_id)?;
    let entry = history
        .attempts
        .iter()
        .find(|entry| entry.attempt.attempt_id == attempt_id)
        .ok_or_else(|| {
            reference_mismatch(
                "task attempt recovery",
                format!("attempt `{attempt_id}` is absent from the exact task history"),
            )
        })?;
    if entry.disposition.is_some() || entry.legacy_classification.is_some() {
        if entry_is_unknown_terminal(entry)
            && let Some(marker) = history.unknown_terminalization_pending.as_ref()
        {
            match derive_recovery_matrix_evidence_id(connection, sprint_id) {
                Ok(evidence_id) => {
                    return Ok(TaskAttemptRecoveryFacts::AllDomainsUnknownTerminalReady {
                        marker_id: marker.marker_id.clone(),
                        evidence_id,
                    });
                }
                Err(LedgerError::ReferenceMismatch { .. }) => {}
                Err(error) => return Err(error),
            }
        }
        return Ok(TaskAttemptRecoveryFacts::DurableHistoryOnly);
    }

    if let Some(evidence_id) = first_unresolved_effect_reference(connection, &entry.attempt)? {
        return Ok(TaskAttemptRecoveryFacts::UncertainAuthority { evidence_id });
    }
    let open = derive_exact_open_launch(connection, &entry.attempt)?;
    if let Some(preferred) =
        task_attempt_authority::preferred_known_cleanup_source(connection, &entry.attempt)?
    {
        let open = open.as_ref().ok_or_else(|| {
            reference_mismatch(
                "task attempt recovery",
                "known cleanup source has no exact open launch cleanup authority",
            )
        })?;
        let outcome = load_known_cleanup_outcome(connection, &entry.attempt, &preferred)?;
        return Ok(TaskAttemptRecoveryFacts::KnownCleanupRequired {
            launch_id: open.launch.launch_id.clone(),
            session_id: open
                .session
                .as_ref()
                .map(|session| session.session_id.clone()),
            outcome,
        });
    }
    if let Some(open) = open {
        if let Some(preparation) = &open.preparation
            && preparation_requires_uncertainty(preparation, open.session.as_ref())
        {
            return Ok(TaskAttemptRecoveryFacts::UncertainAuthority {
                evidence_id: preparation.attempt.native_journal_id.clone(),
            });
        }
        return Ok(TaskAttemptRecoveryFacts::CurrentAuthority {
            launch_id: open.launch.launch_id,
            session_id: open.session.map(|session| session.session_id),
        });
    }
    validate_never_launched(connection, entry)?;
    Ok(TaskAttemptRecoveryFacts::NeverLaunched)
}

fn preparation_requires_uncertainty(
    preparation: &PersistedRunnerLaunchPreparation,
    session: Option<&RunnerSessionPolicyRecord>,
) -> bool {
    match preparation.outcome.as_ref() {
        None
        | Some(RunnerLaunchPreparationOutcome {
            disposition: RunnerLaunchPreparationDisposition::NativeEffectUncertain,
            ..
        }) => true,
        Some(RunnerLaunchPreparationOutcome {
            disposition: RunnerLaunchPreparationDisposition::HeldChildPrepared,
            ..
        }) => session.is_none(),
        Some(RunnerLaunchPreparationOutcome {
            disposition: RunnerLaunchPreparationDisposition::RefusedBeforeNativeEffect,
            ..
        }) => false,
    }
}

fn derive_exact_open_launch(
    connection: &Connection,
    attempt: &TaskAttempt,
) -> Result<Option<ExactOpenLaunch>, LedgerError> {
    let lease = &attempt.worker_lease;
    let open_ids = {
        let mut statement = connection.prepare(
            "SELECT launch.launch_id
               FROM runner_launch_intents launch
               JOIN runner_launch_cleanup_admissions admission
                 ON admission.launch_id = launch.launch_id
               LEFT JOIN effect_observations observation
                 ON observation.effect_id = admission.cleanup_effect_id
              WHERE launch.worker_lease_id = ?1 AND launch.worker_lease_epoch = ?2
                AND observation.effect_id IS NULL
              ORDER BY launch.created_at_unix_ms ASC, launch.launch_id ASC",
        )?;
        statement
            .query_map(
                params![
                    lease.lease_id,
                    sqlite_integer("task_attempt_recovery.lease_epoch", lease.lease_epoch)?,
                ],
                |row| row.get::<_, String>(0),
            )?
            .collect::<Result<Vec<_>, _>>()?
    };
    if open_ids.is_empty() {
        return Ok(None);
    }
    if open_ids.len() != 1 {
        return Err(reference_mismatch(
            "task attempt recovery launch authority",
            format!("attempt has {} simultaneous open launches", open_ids.len()),
        ));
    }
    let launch_id = &open_ids[0];
    let expected_session_id = connection
        .query_row(
            "SELECT session_id FROM runner_session_policies
             WHERE sprint_id = ?1 AND launch_id = ?2",
            params![lease.sprint_id, launch_id],
            |row| row.get::<_, String>(0),
        )
        .optional()?;
    load_exact_open_launch(
        connection,
        attempt,
        launch_id,
        expected_session_id.as_deref(),
    )
    .map(Some)
}

fn first_unresolved_effect_reference(
    connection: &Connection,
    attempt: &TaskAttempt,
) -> Result<Option<String>, LedgerError> {
    let lease = &attempt.worker_lease;
    let effect_ids = {
        let mut statement = connection.prepare(
            "SELECT intent.effect_id FROM effect_intents intent
             WHERE intent.worker_lease_id = ?1 AND intent.worker_lease_epoch = ?2
               AND NOT EXISTS (
                   SELECT 1 FROM runner_launch_cleanup_admissions cleanup
                   WHERE cleanup.cleanup_effect_id = intent.effect_id
               )
             ORDER BY intent.created_at_unix_ms ASC, intent.effect_id ASC",
        )?;
        statement
            .query_map(
                params![
                    lease.lease_id,
                    sqlite_integer("task_attempt_recovery.lease_epoch", lease.lease_epoch)?,
                ],
                |row| row.get::<_, String>(0),
            )?
            .collect::<Result<Vec<_>, _>>()?
    };
    for effect_id in effect_ids {
        let effect = load_effect_from_for_recovery(connection, &effect_id)?;
        if effect.reconciliation() == EffectReconciliation::EvidenceRequired {
            let reference = match effect.observation.as_ref() {
                Some(observation)
                    if matches!(observation.outcome, crate::EffectOutcome::Unknown { .. }) =>
                {
                    observation.observation_id.clone()
                }
                _ => effect_id,
            };
            return Ok(Some(reference));
        }
    }
    Ok(None)
}

#[allow(clippy::too_many_lines)] // Each durable source kind is reconstructed into its closed public contract.
pub(super) fn load_known_cleanup_outcome(
    connection: &Connection,
    attempt: &TaskAttempt,
    preferred: &task_attempt_authority::KnownCleanupSourceKey,
) -> Result<TaskAttemptKnownCleanupOutcome, LedgerError> {
    if preferred.source_kind == task_attempt_authority::KnownCleanupSourceKind::PolicyCause
        && let Some((cause_kind, subject_id, digest, bytes)) = connection
            .query_row(
                "SELECT cause_kind, subject_id, evidence_digest, evidence_bytes
             FROM task_attempt_policy_cause_authorities
             WHERE attempt_id = ?1 AND evidence_id = ?2",
                params![attempt.attempt_id, preferred.source_id],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, Vec<u8>>(3)?,
                    ))
                },
            )
            .optional()?
    {
        let kind = match cause_kind.as_str() {
            "PermanentContractViolation" => {
                crate::TaskAttemptEvidenceKind::PermanentContractViolation
            }
            "CriterionProvenUnsatisfiable" => {
                crate::TaskAttemptEvidenceKind::CriterionProvenUnsatisfiable
            }
            "AuthorityExpansionRequired" => {
                crate::TaskAttemptEvidenceKind::AuthorityExpansionRequired
            }
            "VerifiedDependencyUnavailable" => {
                crate::TaskAttemptEvidenceKind::VerifiedDependencyUnavailable
            }
            "OperatorCanceled" => crate::TaskAttemptEvidenceKind::OperatorCanceled,
            other => {
                return Err(LedgerError::Corrupt {
                    entity: "task attempt recovery policy source",
                    detail: format!("unsupported cause kind `{other}`"),
                });
            }
        };
        let evidence = exact_task_attempt_evidence(&preferred.source_id, kind, bytes, &digest)?;
        return Ok(match cause_kind.as_str() {
            "PermanentContractViolation" => TaskAttemptKnownCleanupOutcome::PermanentFailure(
                crate::TaskAttemptPermanentFailureCause::PermanentContractViolation {
                    violation_id: subject_id,
                    evidence,
                },
            ),
            "CriterionProvenUnsatisfiable" => TaskAttemptKnownCleanupOutcome::PermanentFailure(
                crate::TaskAttemptPermanentFailureCause::CriterionProvenUnsatisfiable {
                    criterion_id: subject_id,
                    evidence,
                },
            ),
            "AuthorityExpansionRequired" => TaskAttemptKnownCleanupOutcome::Blocked(
                crate::TaskAttemptBlockedCause::AuthorityExpansionRequired {
                    authority_request_id: subject_id,
                    evidence,
                },
            ),
            "VerifiedDependencyUnavailable" => TaskAttemptKnownCleanupOutcome::Blocked(
                crate::TaskAttemptBlockedCause::VerifiedDependencyUnavailable {
                    dependency_task_id: subject_id,
                    evidence,
                },
            ),
            "OperatorCanceled" => {
                TaskAttemptKnownCleanupOutcome::Canceled(crate::TaskAttemptCanceledCause {
                    cancellation_id: subject_id,
                    evidence,
                })
            }
            _ => unreachable!("kind checked above"),
        });
    }
    if preferred.source_kind
        == task_attempt_authority::KnownCleanupSourceKind::SensitiveOutputRejection
        && let Some(effect_id) = connection
            .query_row(
                "SELECT anchor.effect_id
                   FROM command_output_sensitive_rejection_exact_finishes_v29 exact
                   JOIN command_output_sensitive_rejection_anchors_v29 anchor
                     ON anchor.effect_id = exact.effect_id
                    AND anchor.rejection_anchor_digest = exact.rejection_anchor_digest
                   JOIN effect_intents intent ON intent.effect_id = anchor.effect_id
                   JOIN task_attempts attempt
                     ON attempt.attempt_id = ?1
                    AND attempt.worker_lease_id = intent.worker_lease_id
                    AND attempt.lease_epoch = intent.worker_lease_epoch
                  WHERE anchor.observation_id = ?2",
                params![attempt.attempt_id, preferred.source_id],
                |row| row.get::<_, String>(0),
            )
            .optional()?
    {
        let rejection = super::sensitive_output_rejection::load_for_effect(connection, &effect_id)?
            .ok_or_else(|| LedgerError::Corrupt {
                entity: "task attempt recovery sensitive-output source",
                detail: "preferred rejection source lacks its exact v29 finish".into(),
            })?;
        let bytes = rejection.anchor.canonical_evidence_bytes()?;
        return Ok(TaskAttemptKnownCleanupOutcome::Retryable(
            TaskAttemptRetryableCause::SensitiveOutputRejected {
                effect_id,
                evidence: exact_task_attempt_evidence(
                    &preferred.source_id,
                    crate::TaskAttemptEvidenceKind::SensitiveOutputRejected,
                    bytes.clone(),
                    Digest::sha256(&bytes).as_str(),
                )?,
            },
        ));
    }
    if preferred.source_kind == task_attempt_authority::KnownCleanupSourceKind::WorkerExit
        && let Some((launch_id, session_id, digest, bytes)) = connection
            .query_row(
                "SELECT launch_id, session_id, evidence_digest, evidence_bytes
             FROM task_attempt_worker_exit_authorities
             WHERE attempt_id = ?1 AND evidence_id = ?2",
                params![attempt.attempt_id, preferred.source_id],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, Vec<u8>>(3)?,
                    ))
                },
            )
            .optional()?
    {
        return Ok(TaskAttemptKnownCleanupOutcome::Retryable(
            TaskAttemptRetryableCause::KnownWorkerExit {
                launch_id,
                session_id,
                evidence: exact_task_attempt_evidence(
                    &preferred.source_id,
                    crate::TaskAttemptEvidenceKind::KnownWorkerExit,
                    bytes,
                    &digest,
                )?,
            },
        ));
    }
    if preferred.source_kind == task_attempt_authority::KnownCleanupSourceKind::CandidateRejection
        && let Some((boundary_id, digest, bytes)) = connection
            .query_row(
                "SELECT candidate_boundary_id, evidence_digest, evidence_bytes
             FROM task_attempt_candidate_rejection_authorities
             WHERE attempt_id = ?1 AND evidence_id = ?2",
                params![attempt.attempt_id, preferred.source_id],
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
        return Ok(TaskAttemptKnownCleanupOutcome::Retryable(
            TaskAttemptRetryableCause::CandidateRejectedKnown {
                candidate_boundary_id: boundary_id,
                evidence: exact_task_attempt_evidence(
                    &preferred.source_id,
                    crate::TaskAttemptEvidenceKind::CandidateRejectedKnown,
                    bytes,
                    &digest,
                )?,
            },
        ));
    }
    if preferred.source_kind
        == task_attempt_authority::KnownCleanupSourceKind::FormalVerificationFailure
        && let Some((formal_check_id, effect_id)) = connection
            .query_row(
                "SELECT formal_check_id, effect_id FROM task_attempt_formal_checks
             WHERE attempt_id = ?1 AND observation_id = ?2 AND passed = 0",
                params![attempt.attempt_id, preferred.source_id],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
            )
            .optional()?
    {
        let effect = load_effect_from(connection, &effect_id)?;
        let bytes = effect.evidence_bytes.ok_or_else(|| LedgerError::Corrupt {
            entity: "task attempt recovery formal source",
            detail: "failed formal effect lacks exact evidence bytes".into(),
        })?;
        let digest = Digest::sha256(&bytes).to_string();
        return Ok(TaskAttemptKnownCleanupOutcome::Retryable(
            TaskAttemptRetryableCause::FormalVerificationFailed {
                formal_check_id,
                evidence: exact_task_attempt_evidence(
                    &preferred.source_id,
                    crate::TaskAttemptEvidenceKind::FormalVerificationFailed,
                    bytes,
                    &digest,
                )?,
            },
        ));
    }
    if preferred.source_kind == task_attempt_authority::KnownCleanupSourceKind::LaunchRefusal
        && let Some(launch_id) = connection
            .query_row(
                "SELECT launch_id FROM runner_launch_preparation_attempts
             WHERE attempt_id = ?1",
                [&preferred.source_id],
                |row| row.get::<_, String>(0),
            )
            .optional()?
    {
        let preparation = runner_launch_cleanup_admission::load_preparation(
            connection,
            &attempt.worker_lease.sprint_id,
            &launch_id,
        )?;
        let outcome = preparation.outcome.ok_or_else(|| LedgerError::Corrupt {
            entity: "task attempt recovery launch-refusal source",
            detail: "preferred refusal preparation lacks its outcome".into(),
        })?;
        let bytes = outcome.native_evidence_bytes;
        let digest = Digest::sha256(&bytes).to_string();
        return Ok(TaskAttemptKnownCleanupOutcome::Retryable(
            TaskAttemptRetryableCause::LaunchRefusedBeforeNativeEffect {
                launch_id,
                evidence: exact_task_attempt_evidence(
                    &preferred.source_id,
                    crate::TaskAttemptEvidenceKind::LaunchRefusedBeforeNativeEffect,
                    bytes,
                    &digest,
                )?,
            },
        ));
    }
    Err(LedgerError::Corrupt {
        entity: "task attempt recovery cleanup source",
        detail: format!(
            "preferred source `{}` has no canonical typed aggregate",
            preferred.source_id
        ),
    })
}

fn exact_task_attempt_evidence(
    evidence_id: &str,
    kind: crate::TaskAttemptEvidenceKind,
    bytes: Vec<u8>,
    expected_digest: &str,
) -> Result<crate::TaskAttemptEvidence, LedgerError> {
    let evidence = crate::TaskAttemptEvidence::new(evidence_id.to_owned(), kind, bytes)?;
    if evidence.digest.as_str() != expected_digest {
        return Err(LedgerError::Corrupt {
            entity: "task attempt recovery source evidence",
            detail: "canonical evidence bytes disagree with the indexed digest".into(),
        });
    }
    Ok(evidence)
}

fn validate_recovery_facts_from_ledger(
    connection: &Connection,
    sprint_id: &str,
    entry: &TaskAttemptHistoryEntry,
    facts: &TaskAttemptRecoveryFacts,
) -> Result<(), LedgerError> {
    if entry.disposition.is_some() || entry.legacy_classification.is_some() {
        return match facts {
            TaskAttemptRecoveryFacts::DurableHistoryOnly => Ok(()),
            TaskAttemptRecoveryFacts::AllDomainsUnknownTerminalReady {
                marker_id,
                evidence_id,
            } if entry_is_unknown_terminal(entry) => {
                require_exact_recovery_matrix(connection, sprint_id, marker_id, evidence_id)
            }
            _ => Err(reference_mismatch(
                "task attempt recovery",
                "disposed or legacy recovery facts do not match exact durable history",
            )),
        };
    }

    if !entry.lease_state.is_active() {
        return Err(reference_mismatch(
            "task attempt recovery",
            "an undisposed attempt must retain exact active lease authority",
        ));
    }

    match facts {
        TaskAttemptRecoveryFacts::CurrentAuthority {
            launch_id,
            session_id,
        } => {
            validate_current_authority(connection, &entry.attempt, launch_id, session_id.as_deref())
        }
        TaskAttemptRecoveryFacts::NeverLaunched => validate_never_launched(connection, entry),
        TaskAttemptRecoveryFacts::KnownCleanupRequired {
            launch_id,
            session_id,
            outcome,
        } => validate_known_cleanup_authority(
            connection,
            entry,
            launch_id,
            session_id.as_deref(),
            outcome,
        ),
        TaskAttemptRecoveryFacts::UncertainAuthority { evidence_id } => {
            let kind = require_exact_unresolved_authority_reference(
                connection,
                &entry.attempt,
                evidence_id,
            )?;
            if kind == UnresolvedAuthorityKind::Preparation
                && task_attempt_authority::preferred_known_cleanup_source(
                    connection,
                    &entry.attempt,
                )?
                .is_some()
            {
                return Err(reference_mismatch(
                    "task attempt recovery precedence",
                    "known cleanup source takes precedence over preparation-only uncertainty",
                ));
            }
            Ok(())
        }
        TaskAttemptRecoveryFacts::DurableHistoryOnly
        | TaskAttemptRecoveryFacts::AllDomainsUnknownTerminalReady { .. } => {
            Err(reference_mismatch(
                "task attempt recovery",
                "open attempt requires exact live, no-launch, cleanup, or uncertainty authority",
            ))
        }
    }
}

fn entry_is_unknown_terminal(entry: &TaskAttemptHistoryEntry) -> bool {
    matches!(
        entry.disposition,
        Some(
            TaskAttemptDisposition::UnknownCleaned(_)
                | TaskAttemptDisposition::UnknownQuarantined(_)
        )
    ) || entry.legacy_classification
        == Some(LegacyTaskAttemptClassification::LegacyUnknownQuarantine)
}

fn validate_current_authority(
    connection: &Connection,
    attempt: &TaskAttempt,
    launch_id: &str,
    session_id: Option<&str>,
) -> Result<(), LedgerError> {
    let exact = load_exact_open_launch(connection, attempt, launch_id, session_id)?;
    require_no_unresolved_attempt_effects(connection, attempt, &exact)?;
    require_no_known_cleanup_source(connection, attempt)?;
    match (&exact.preparation, &exact.session) {
        (None, _)
        | (
            Some(PersistedRunnerLaunchPreparation {
                outcome:
                    Some(RunnerLaunchPreparationOutcome {
                        disposition: RunnerLaunchPreparationDisposition::HeldChildPrepared,
                        ..
                    }),
                ..
            }),
            Some(_),
        ) => Ok(()),
        _ => Err(reference_mismatch(
            "task attempt recovery current authority",
            "preparation is incomplete, refused, uncertain, or lacks its initialized session",
        )),
    }
}

fn validate_known_cleanup_authority(
    connection: &Connection,
    entry: &TaskAttemptHistoryEntry,
    launch_id: &str,
    session_id: Option<&str>,
    outcome: &TaskAttemptKnownCleanupOutcome,
) -> Result<(), LedgerError> {
    let exact = load_exact_open_launch(connection, &entry.attempt, launch_id, session_id)?;
    require_no_unresolved_attempt_effects(connection, &entry.attempt, &exact)?;
    validate_known_cleanup_source_identity(connection, &entry.attempt, &exact, outcome)?;
    task_attempt_authority::require_preferred_current_known_cleanup_outcome_authority(
        connection,
        &entry.attempt,
        outcome,
    )
}

#[allow(clippy::too_many_lines)] // Every typed source is reopened against its independent durable authority.
fn validate_known_cleanup_source_identity(
    connection: &Connection,
    attempt: &TaskAttempt,
    exact: &ExactOpenLaunch,
    outcome: &TaskAttemptKnownCleanupOutcome,
) -> Result<(), LedgerError> {
    match outcome {
        TaskAttemptKnownCleanupOutcome::Retryable(
            TaskAttemptRetryableCause::LaunchRefusedBeforeNativeEffect { evidence, .. },
        ) => {
            let preparation = exact.preparation.as_ref().ok_or_else(|| {
                reference_mismatch(
                    "task attempt recovery launch-refusal source",
                    "exact launch has no durable preparation attempt",
                )
            })?;
            let refused = preparation.outcome.as_ref().ok_or_else(|| {
                reference_mismatch(
                    "task attempt recovery launch-refusal source",
                    "preparation has no durable refusal outcome",
                )
            })?;
            if refused.disposition != RunnerLaunchPreparationDisposition::RefusedBeforeNativeEffect
                || evidence.evidence_id != preparation.attempt.attempt_id
                || evidence.canonical_bytes != refused.native_evidence_bytes
                || evidence.digest != Digest::sha256(&refused.native_evidence_bytes)
            {
                return Err(reference_mismatch(
                    "task attempt recovery launch-refusal source",
                    "evidence must use the exact preparation-attempt identity and native bytes",
                ));
            }
        }
        TaskAttemptKnownCleanupOutcome::Retryable(
            TaskAttemptRetryableCause::FormalVerificationFailed {
                formal_check_id,
                evidence,
            },
        ) => {
            let stored = connection
                .query_row(
                    "SELECT observation_id, effect_id FROM task_attempt_formal_checks
                     WHERE formal_check_id = ?1 AND attempt_id = ?2 AND passed = 0",
                    params![formal_check_id, attempt.attempt_id],
                    |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
                )
                .optional()?
                .ok_or_else(|| LedgerError::ArtifactNotFound {
                    entity: "task attempt recovery formal-failure source",
                    id: formal_check_id.clone(),
                })?;
            let effect = load_effect_from(connection, &stored.1)?;
            if evidence.evidence_id != stored.0
                || effect.evidence_bytes.as_ref() != Some(&evidence.canonical_bytes)
                || effect
                    .observation
                    .as_ref()
                    .map(|value| &value.observation_id)
                    != Some(&stored.0)
            {
                return Err(reference_mismatch(
                    "task attempt recovery formal-failure source",
                    "evidence must use the exact failed observation identity and bytes",
                ));
            }
        }
        TaskAttemptKnownCleanupOutcome::Retryable(
            TaskAttemptRetryableCause::SensitiveOutputRejected {
                effect_id,
                evidence,
            },
        ) => {
            let rejection =
                super::sensitive_output_rejection::load_for_effect(connection, effect_id)?
                    .ok_or_else(|| LedgerError::ArtifactNotFound {
                        entity: "task attempt recovery sensitive-output source",
                        id: effect_id.clone(),
                    })?;
            let bytes = rejection.anchor.canonical_evidence_bytes()?;
            let exact_attempt = connection.query_row(
                "SELECT EXISTS (
                     SELECT 1 FROM effect_intents intent
                     WHERE intent.effect_id = ?1
                       AND intent.worker_lease_id = ?2
                       AND intent.worker_lease_epoch = ?3
                 )",
                params![
                    effect_id,
                    attempt.worker_lease.lease_id,
                    sqlite_integer(
                        "task_attempt_recovery.lease_epoch",
                        attempt.worker_lease.lease_epoch,
                    )?,
                ],
                |row| row.get::<_, bool>(0),
            )?;
            if !exact_attempt
                || rejection.anchor.observation_id != evidence.evidence_id
                || bytes != evidence.canonical_bytes
                || Digest::sha256(&bytes) != evidence.digest
            {
                return Err(reference_mismatch(
                    "task attempt recovery sensitive-output source",
                    "evidence must be the exact secret-free v29 rejection anchor for this attempt lease",
                ));
            }
        }
        _ => {}
    }
    Ok(())
}

fn require_no_known_cleanup_source(
    connection: &Connection,
    attempt: &TaskAttempt,
) -> Result<(), LedgerError> {
    if task_attempt_authority::preferred_known_cleanup_source(connection, attempt)?.is_none() {
        Ok(())
    } else {
        Err(reference_mismatch(
            "task attempt recovery current authority",
            "attempt has durable known-cleanup source authority",
        ))
    }
}

#[allow(clippy::too_many_lines)] // Every launch/session/preparation join is reopened in one snapshot.
fn load_exact_open_launch(
    connection: &Connection,
    attempt: &TaskAttempt,
    expected_launch_id: &str,
    expected_session_id: Option<&str>,
) -> Result<ExactOpenLaunch, LedgerError> {
    let lease = &attempt.worker_lease;
    let launch_ids = {
        let mut statement = connection.prepare(
            "SELECT launch_id FROM runner_launch_intents
             WHERE sprint_id = ?1 AND worker_lease_id = ?2
               AND worker_lease_epoch = ?3
             ORDER BY created_at_unix_ms ASC, launch_id ASC",
        )?;
        statement
            .query_map(
                params![
                    lease.sprint_id,
                    lease.lease_id,
                    sqlite_integer("task_attempt_recovery.lease_epoch", lease.lease_epoch)?,
                ],
                |row| row.get::<_, String>(0),
            )?
            .collect::<Result<Vec<_>, _>>()?
    };
    let mut open = Vec::new();
    for launch_id in launch_ids {
        let admission = runner_launch_cleanup_admission::load_authoritative(
            connection,
            &lease.sprint_id,
            &launch_id,
        )?;
        if admission.launch.purpose != RunnerSessionPurpose::TaskWorker
            || admission.launch.worker_lease.as_ref() != Some(lease)
            || admission.launch.worker_id.as_deref() != Some(lease.worker_id.as_str())
        {
            return Err(LedgerError::Corrupt {
                entity: "task attempt recovery launch authority",
                detail: "launch role, worker, or lease differs from its owning attempt".into(),
            });
        }
        if admission.cleanup_effect.observation.is_none()
            && admission.cleanup_effect.evidence_bytes.is_none()
            && admission.cleanup_effect.terminal_event.is_none()
            && admission.cleanup_effect.finish_receipt == PersistedFinishReceipt::NotRequired
        {
            open.push(admission.launch);
        }
    }
    if open.len() != 1 || open[0].launch_id != expected_launch_id {
        return Err(reference_mismatch(
            "task attempt recovery launch authority",
            format!(
                "expected launch must be the sole exact open attempt-scoped launch; found {}",
                open.len()
            ),
        ));
    }
    let launch = open.pop().expect("length checked");
    runner_launch_cleanup_admission::require_open_authoritative(
        connection,
        &lease.sprint_id,
        expected_launch_id,
    )?;

    let session_exists = connection
        .query_row(
            "SELECT 1 FROM runner_session_policies
             WHERE sprint_id = ?1 AND launch_id = ?2",
            params![lease.sprint_id, expected_launch_id],
            |_| Ok(()),
        )
        .optional()?
        .is_some();
    let session = if session_exists {
        if expected_session_id != Some(launch.session_id.as_str()) {
            return Err(reference_mismatch(
                "task attempt recovery session authority",
                "supplied session does not name the exact initialized launch session",
            ));
        }
        Some(load_runner_session_policy_from(connection, &lease.sprint_id, &launch.session_id)?.0)
    } else {
        if expected_session_id.is_some() {
            return Err(reference_mismatch(
                "task attempt recovery session authority",
                "supplied session is not durably initialized",
            ));
        }
        None
    };

    let preparation_exists = connection
        .query_row(
            "SELECT 1 FROM runner_launch_preparation_attempts
             WHERE sprint_id = ?1 AND launch_id = ?2",
            params![lease.sprint_id, expected_launch_id],
            |_| Ok(()),
        )
        .optional()?
        .is_some();
    let preparation = preparation_exists
        .then(|| {
            runner_launch_cleanup_admission::load_preparation(
                connection,
                &lease.sprint_id,
                expected_launch_id,
            )
        })
        .transpose()?;
    Ok(ExactOpenLaunch {
        launch,
        session,
        preparation,
    })
}

fn require_no_unresolved_attempt_effects(
    connection: &Connection,
    attempt: &TaskAttempt,
    exact: &ExactOpenLaunch,
) -> Result<(), LedgerError> {
    let lease = &attempt.worker_lease;
    let effect_ids = {
        let mut statement = connection.prepare(
            "SELECT intent.effect_id FROM effect_intents intent
             WHERE intent.sprint_id = ?1
               AND intent.worker_lease_id = ?2
               AND intent.worker_lease_epoch = ?3
               AND NOT EXISTS (
                   SELECT 1 FROM runner_launch_cleanup_admissions admission
                   WHERE admission.cleanup_effect_id = intent.effect_id
               )
             ORDER BY intent.created_at_unix_ms ASC, intent.effect_id ASC",
        )?;
        statement
            .query_map(
                params![
                    lease.sprint_id,
                    lease.lease_id,
                    sqlite_integer("task_attempt_recovery.lease_epoch", lease.lease_epoch)?,
                ],
                |row| row.get::<_, String>(0),
            )?
            .collect::<Result<Vec<_>, _>>()?
    };
    for effect_id in effect_ids {
        let effect = load_effect_from(connection, &effect_id)?;
        if effect.intent.worker_lease.as_ref() != Some(lease) {
            return Err(LedgerError::Corrupt {
                entity: "task attempt recovery effect authority",
                detail: format!("effect `{effect_id}` crosses its indexed attempt lease"),
            });
        }
        if effect.reconciliation() == EffectReconciliation::EvidenceRequired {
            return Err(reference_mismatch(
                "task attempt recovery effect authority",
                format!("effect `{effect_id}` remains unresolved and requires UncertainAuthority"),
            ));
        }
        // Provider requests are owned directly by the exact Running attempt
        // lease and deliberately have no runner-session binding. All other
        // attempt effects must still reopen through their exact launch and
        // session authority below.
        if effect.intent.kind == EffectKind::ProviderRequest {
            continue;
        }
        let binding = load_effect_runner_binding(connection, &effect.intent)?;
        if binding.launch.worker_lease.as_ref() != Some(lease) {
            return Err(LedgerError::Corrupt {
                entity: "task attempt recovery effect authority",
                detail: format!("effect `{effect_id}` binds another launch lease"),
            });
        }
        if binding.launch.launch_id != exact.launch.launch_id
            || binding
                .session
                .as_ref()
                .map(|session| session.session_id.as_str())
                != exact
                    .session
                    .as_ref()
                    .map(|session| session.session_id.as_str())
        {
            return Err(reference_mismatch(
                "task attempt recovery effect authority",
                format!("effect `{effect_id}` crosses the supplied current session"),
            ));
        }
    }
    Ok(())
}

fn validate_never_launched(
    connection: &Connection,
    entry: &TaskAttemptHistoryEntry,
) -> Result<(), LedgerError> {
    if entry.running_boundary.is_some()
        || entry.verification_boundary.is_some()
        || !entry.formal_checks.is_empty()
        || entry.candidate_boundary.is_some()
    {
        return Err(reference_mismatch(
            "task attempt recovery NeverLaunched",
            "durable task-attempt phase authority proves work advanced beyond acquisition",
        ));
    }
    let lease = &entry.attempt.worker_lease;
    let count = connection.query_row(
        "SELECT COUNT(*) FROM (
            SELECT launch_id AS authority_id FROM runner_launch_intents
             WHERE worker_lease_id = ?1 AND worker_lease_epoch = ?2
            UNION ALL
            SELECT session_id FROM runner_session_policies
             WHERE worker_lease_id = ?1 AND worker_lease_epoch = ?2
            UNION ALL
            SELECT effect_id FROM effect_intents
             WHERE worker_lease_id = ?1 AND worker_lease_epoch = ?2
            UNION ALL
            SELECT preparation.attempt_id
              FROM runner_launch_preparation_attempts preparation
              JOIN runner_launch_intents launch ON launch.launch_id = preparation.launch_id
             WHERE launch.worker_lease_id = ?1 AND launch.worker_lease_epoch = ?2
            UNION ALL
            SELECT authority_id FROM task_attempt_worker_exit_authorities
             WHERE attempt_id = ?3
            UNION ALL
            SELECT authority_id FROM task_attempt_candidate_rejection_authorities
             WHERE attempt_id = ?3
            UNION ALL
            SELECT authority_id FROM task_attempt_policy_cause_authorities
             WHERE attempt_id = ?3
         )",
        params![
            lease.lease_id,
            sqlite_integer("task_attempt_recovery.lease_epoch", lease.lease_epoch)?,
            entry.attempt.attempt_id,
        ],
        |row| row.get::<_, i64>(0),
    )?;
    if count == 0 {
        Ok(())
    } else {
        Err(reference_mismatch(
            "task attempt recovery NeverLaunched",
            format!("attempt has {count} durable launch/session/effect/preparation authorities"),
        ))
    }
}

fn require_exact_unresolved_authority_reference(
    connection: &Connection,
    attempt: &TaskAttempt,
    authority_reference_id: &str,
) -> Result<UnresolvedAuthorityKind, LedgerError> {
    let lease = &attempt.worker_lease;
    let count = connection.query_row(
        "SELECT COUNT(*) FROM (
            SELECT intent.effect_id
              FROM effect_intents intent
              LEFT JOIN effect_observations observation
                ON observation.effect_id = intent.effect_id
              LEFT JOIN unresolved_mutation_effects mutation
                ON mutation.effect_id = intent.effect_id
              LEFT JOIN legacy_finish_receipt_gaps finish_gap
                ON finish_gap.effect_id = intent.effect_id
             WHERE intent.worker_lease_id = ?1
               AND intent.worker_lease_epoch = ?2
               AND intent.effect_id = ?3
               AND NOT EXISTS (
                   SELECT 1 FROM runner_launch_cleanup_admissions cleanup
                   WHERE cleanup.cleanup_effect_id = intent.effect_id
               )
               AND (
                   observation.effect_id IS NULL OR observation.outcome = 'Unknown'
                   OR mutation.effect_id IS NOT NULL
                   OR finish_gap.effect_id IS NOT NULL
               )
            UNION ALL
            SELECT observation.observation_id
              FROM effect_observations observation
             WHERE observation.worker_lease_id = ?1
               AND observation.worker_lease_epoch = ?2
               AND observation.observation_id = ?3
               AND observation.outcome = 'Unknown'
            UNION ALL
            SELECT preparation.attempt_id
              FROM runner_launch_preparation_attempts preparation
              JOIN runner_launch_intents launch ON launch.launch_id = preparation.launch_id
              LEFT JOIN runner_launch_preparation_outcomes outcome
                ON outcome.attempt_id = preparation.attempt_id
             WHERE launch.worker_lease_id = ?1
               AND launch.worker_lease_epoch = ?2
               AND preparation.attempt_id = ?3
               AND (
                   outcome.attempt_id IS NULL
                   OR outcome.disposition = 'NativeEffectUncertain'
                   OR (
                       outcome.disposition = 'HeldChildPrepared'
                       AND NOT EXISTS (
                           SELECT 1 FROM runner_session_policies session
                           WHERE session.launch_id = launch.launch_id
                       )
                   )
               )
            UNION ALL
            SELECT preparation.native_journal_id
              FROM runner_launch_preparation_attempts preparation
              JOIN runner_launch_intents launch ON launch.launch_id = preparation.launch_id
              LEFT JOIN runner_launch_preparation_outcomes outcome
                ON outcome.attempt_id = preparation.attempt_id
             WHERE launch.worker_lease_id = ?1
               AND launch.worker_lease_epoch = ?2
               AND preparation.native_journal_id = ?3
               AND (
                   outcome.attempt_id IS NULL
                   OR outcome.disposition = 'NativeEffectUncertain'
                   OR (
                       outcome.disposition = 'HeldChildPrepared'
                       AND NOT EXISTS (
                           SELECT 1 FROM runner_session_policies session
                           WHERE session.launch_id = launch.launch_id
                       )
                   )
               )
         )",
        params![
            lease.lease_id,
            sqlite_integer("task_attempt_recovery.lease_epoch", lease.lease_epoch)?,
            authority_reference_id,
        ],
        |row| row.get::<_, i64>(0),
    )?;
    if count == 1 {
        reopen_unresolved_authority_reference(connection, attempt, authority_reference_id)
    } else {
        Err(reference_mismatch(
            "task attempt recovery uncertain authority",
            format!(
                "reference `{authority_reference_id}` must resolve exactly one unresolved attempt-scoped authority; found {count}"
            ),
        ))
    }
}

fn reopen_unresolved_authority_reference(
    connection: &Connection,
    attempt: &TaskAttempt,
    authority_reference_id: &str,
) -> Result<UnresolvedAuthorityKind, LedgerError> {
    let lease = &attempt.worker_lease;
    let effect_id = connection
        .query_row(
            "SELECT effect_id FROM effect_intents WHERE effect_id = ?1
             UNION ALL
             SELECT effect_id FROM effect_observations WHERE observation_id = ?1",
            [authority_reference_id],
            |row| row.get::<_, String>(0),
        )
        .optional()?;
    if let Some(effect_id) = effect_id {
        let effect = load_effect_from_for_recovery(connection, &effect_id)?;
        if effect.intent.worker_lease.as_ref() == Some(lease)
            && effect.reconciliation() == EffectReconciliation::EvidenceRequired
        {
            return Ok(UnresolvedAuthorityKind::Effect);
        }
        return Err(reference_mismatch(
            "task attempt recovery uncertain authority",
            "effect reference is no longer unresolved for the exact attempt",
        ));
    }
    if let Some(launch_id) = connection
        .query_row(
            "SELECT launch_id FROM runner_launch_preparation_attempts
             WHERE attempt_id = ?1 OR native_journal_id = ?1",
            [authority_reference_id],
            |row| row.get::<_, String>(0),
        )
        .optional()?
    {
        let preparation = runner_launch_cleanup_admission::load_preparation(
            connection,
            &lease.sprint_id,
            &launch_id,
        )?;
        let initialized = connection
            .query_row(
                "SELECT 1 FROM runner_session_policies WHERE launch_id = ?1",
                [&launch_id],
                |_| Ok(()),
            )
            .optional()?
            .is_some();
        if preparation.outcome.as_ref().is_none_or(|outcome| {
            outcome.disposition == RunnerLaunchPreparationDisposition::NativeEffectUncertain
                || (outcome.disposition == RunnerLaunchPreparationDisposition::HeldChildPrepared
                    && !initialized)
        }) {
            return Ok(UnresolvedAuthorityKind::Preparation);
        }
    }
    Err(reference_mismatch(
        "task attempt recovery uncertain authority",
        "unresolved reference did not reopen through its canonical aggregate",
    ))
}

fn require_exact_recovery_matrix(
    connection: &Connection,
    sprint_id: &str,
    marker_id: &str,
    evidence_id: &str,
) -> Result<(), LedgerError> {
    let marker = load_task_attempt_unknown_pending_marker(connection, sprint_id)?
        .ok_or_else(|| reference_mismatch("task attempt recovery matrix", "no marker is open"))?;
    if marker.marker_id != marker_id {
        return Err(reference_mismatch(
            "task attempt recovery matrix",
            "supplied marker is not the exact open durable marker",
        ));
    }
    let expected = derive_recovery_matrix_evidence_id(connection, sprint_id)?;
    if evidence_id == expected {
        Ok(())
    } else {
        Err(reference_mismatch(
            "task attempt recovery matrix",
            "supplied evidence identity differs from the current canonical matrix",
        ))
    }
}

fn derive_recovery_matrix_evidence_id(
    connection: &Connection,
    sprint_id: &str,
) -> Result<String, LedgerError> {
    let marker = load_task_attempt_unknown_pending_marker(connection, sprint_id)?
        .ok_or_else(|| reference_mismatch("task attempt recovery matrix", "no marker is open"))?;
    let (spec, graph, _) = load_sprint_inputs(connection, sprint_id)?;
    let first_disposition = task_attempt_authority::load_disposition(
        connection,
        &marker.first_disposition_id,
        spec.budget.max_attempts_per_task,
    )?;
    let first_metadata = first_disposition.metadata();
    if !matches!(
        first_disposition,
        TaskAttemptDisposition::UnknownCleaned(_) | TaskAttemptDisposition::UnknownQuarantined(_)
    ) || first_metadata.attempt.attempt_id != marker.first_attempt_id
        || first_metadata.attempt.worker_lease.sprint_id != marker.sprint_id
        || first_metadata.disposed_at_unix_ms != marker.created_at_unix_ms
    {
        return Err(LedgerError::Corrupt {
            entity: "task attempt recovery matrix marker",
            detail: "open marker does not rejoin its exact first unknown disposition".into(),
        });
    }
    load_effects_from(connection, sprint_id, false)?;
    validate_terminal_effect_admission(connection, sprint_id, NonSuccessTerminalState::Unknown)?;
    require_unknown_terminal_domain_matrix(connection, sprint_id)?;
    let mut task_ids = graph
        .tasks
        .iter()
        .map(|task| task.task_id.clone())
        .collect::<Vec<_>>();
    task_ids.sort();
    let mut tasks = Vec::with_capacity(task_ids.len());
    for task_id in task_ids {
        let history = load_task_attempt_history_from(connection, sprint_id, &task_id)?;
        tasks.push(RecoveryMatrixTask {
            task_id,
            attempts: history
                .attempts
                .into_iter()
                .map(|entry| RecoveryMatrixAttempt {
                    attempt: entry.attempt,
                    disposition: entry.disposition,
                    legacy_classification: entry.legacy_classification,
                    lease_state: entry.lease_state,
                })
                .collect(),
        });
    }
    let canonical = encode(
        "task attempt recovery matrix",
        &RecoveryMatrixPreimage {
            contract_version: CONTRACT_VERSION,
            marker,
            tasks,
        },
    )?;
    let mut preimage = Vec::with_capacity(RECOVERY_MATRIX_DOMAIN.len() + canonical.len());
    preimage.extend_from_slice(RECOVERY_MATRIX_DOMAIN);
    preimage.extend_from_slice(&canonical);
    Ok(format!(
        "{RECOVERY_MATRIX_PREFIX}{}",
        Digest::sha256(&preimage)
    ))
}

fn require_unknown_terminal_domain_matrix(
    connection: &Connection,
    sprint_id: &str,
) -> Result<(), LedgerError> {
    task_attempt_authority::require_unknown_unresolved_authority_coverage(
        connection,
        sprint_id,
        "task attempt recovery matrix",
    )?;
    let unsafe_active = connection
        .query_row(
            "SELECT active.lease_id
             FROM active_worker_leases active
             LEFT JOIN task_attempt_dispositions disposition
               ON disposition.worker_lease_id = active.lease_id
             WHERE active.sprint_id = ?1
               AND (
                   disposition.disposition_kind IS NULL
                   OR disposition.disposition_kind NOT IN ('UnknownQuarantined', 'Integrated')
               )
             ORDER BY active.lease_id ASC LIMIT 1",
            [sprint_id],
            |row| row.get::<_, String>(0),
        )
        .optional()?;
    if let Some(lease_id) = unsafe_active {
        return Err(reference_mismatch(
            "task attempt recovery matrix",
            format!("active lease `{lease_id}` lacks quarantine or Integrated authority"),
        ));
    }
    let undisposed = connection
        .query_row(
            "SELECT attempt.attempt_id
             FROM task_attempts attempt
             LEFT JOIN task_attempt_dispositions disposition
               ON disposition.attempt_id = attempt.attempt_id
             LEFT JOIN task_attempt_legacy_classifications legacy
               ON legacy.attempt_id = attempt.attempt_id
             WHERE attempt.sprint_id = ?1
               AND disposition.attempt_id IS NULL
               AND legacy.attempt_id IS NULL
             ORDER BY attempt.attempt_id ASC LIMIT 1",
            [sprint_id],
            |row| row.get::<_, String>(0),
        )
        .optional()?;
    if let Some(attempt_id) = undisposed {
        return Err(reference_mismatch(
            "task attempt recovery matrix",
            format!("attempt `{attempt_id}` lacks disposition or legacy classification"),
        ));
    }
    command_output_capture_authority::require_closed_reconciliation_obligations_for_sprint(
        connection,
        sprint_id,
        "task attempt recovery matrix",
    )?;
    Ok(())
}
