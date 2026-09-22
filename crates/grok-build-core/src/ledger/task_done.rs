//! Ledger-computed task finish authority.

use std::collections::BTreeSet;

use rusqlite::{Connection, OptionalExtension, params};

use super::command_domain_cleanup::load_task_done_command_domain_cleanup_completeness_from;
use super::{
    CommandDomainBackend, CommandDomainCleanupCompleteness, CompleteCommandDomainCleanupSet,
    EventLedger, LedgerError, load_change_set_from, load_effect_from_with_receipts,
    load_effect_runner_binding, load_runner_launch_intent_from, load_runner_session_policy_from,
    load_sprint_inputs, load_task_attempt_history_from, load_task_integration_receipt_from,
    load_worker_cleanup_evidence_from, load_workspace_snapshot_from, reference_mismatch,
    validate_cleanup_after_launch_activity, worker_lease_authority,
};
use crate::{
    ChangeSet, EffectKind, EffectOutcome, PersistedEffect, RunnerLaunchIntent,
    RunnerSessionPolicyRecord, RunnerSessionPurpose, TaskAttempt, TaskAttemptDisposition,
    TaskAttemptHistoryEntry, TaskAttemptLeaseState, TaskAttemptReleaseProof,
    TaskAttemptTerminalEffect, TaskIntegrationReceipt, TaskState, WorkerCleanupBackend,
    WorkerCleanupEvidence, WorkerLease,
};

/// One independently visible term in the exact `TaskDone` conjunction.
///
/// The enum order is the canonical presentation order used by assessments.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum TaskDoneRequirement {
    /// The current durable task state is exactly `Integrated`.
    DurableTaskStateIntegrated,
    /// Exactly one winning integrated attempt and complete lease are known.
    ExactWinningIntegratedAttemptAndLease,
    /// Every effect owned by every task attempt has known terminal evidence.
    EveryTaskEffectTerminalNonUnknown,
    /// An explicit change-set result and exact integration receipt are durable.
    ExactResultIntegrated,
    /// Candidate, change-set, receipt, and stored result snapshot are identical.
    IntegrationReceiptMatchesResultSnapshot,
    /// Every declared automated task check passed on that result snapshot.
    RequiredTaskChecksPassedOnResultSnapshot,
    /// The winning attempt has the exact typed `Integrated` disposition.
    WinningAttemptDispositionIntegrated,
    /// Every nonwinning attempt has a terminal disposition and complete closure.
    EveryNonWinningAttemptDurablyClosed,
    /// Every admitted attempt runner domain has exact zero-survivor cleanup.
    RunnerDomainCleanupProven,
    /// Every command domain for every attempt runner has exact native cleanup.
    CommandDomainCleanupProven,
    /// Every task-owned command has an exact closed v27 output-capture anchor.
    CommandOutputCaptureTerminalExact,
    /// The originating complete worker lease has an exact cleanup-coupled release.
    OriginatingWorkerLeaseReleased,
    /// No lease for the task remains active.
    NoActiveTaskLeases,
    /// No task attempt retains durable replay or dispatch authority.
    NoTaskReplayOrDispatchAuthority,
}

impl TaskDoneRequirement {
    const ALL: [Self; 14] = [
        Self::DurableTaskStateIntegrated,
        Self::ExactWinningIntegratedAttemptAndLease,
        Self::EveryTaskEffectTerminalNonUnknown,
        Self::ExactResultIntegrated,
        Self::IntegrationReceiptMatchesResultSnapshot,
        Self::RequiredTaskChecksPassedOnResultSnapshot,
        Self::WinningAttemptDispositionIntegrated,
        Self::EveryNonWinningAttemptDurablyClosed,
        Self::RunnerDomainCleanupProven,
        Self::CommandDomainCleanupProven,
        Self::CommandOutputCaptureTerminalExact,
        Self::OriginatingWorkerLeaseReleased,
        Self::NoActiveTaskLeases,
        Self::NoTaskReplayOrDispatchAuthority,
    ];
}

/// Exact universal closure evidence for one nonwinning task attempt.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TaskDoneClosedAttemptProof {
    /// Complete immutable attempt and lease identity.
    pub attempt: TaskAttempt,
    /// Exact terminal non-integrated disposition.
    pub disposition: TaskAttemptDisposition,
    /// Effect-sorted known terminal observations owned by this attempt.
    pub terminal_effects: Vec<TaskAttemptTerminalEffect>,
    /// Exact runner cleanup, absent only for a proven never-launched attempt.
    pub runner_cleanup: Option<WorkerCleanupEvidence>,
    /// Complete command cleanup set, absent only when no runner session existed.
    pub command_domain_cleanup: Option<CompleteCommandDomainCleanupSet>,
    /// Exact released lease projection.
    pub lease_release: TaskAttemptLeaseState,
}

/// Exact evidence returned only when every `TaskDone` term is true.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TaskDoneProof {
    /// Owning sprint.
    pub sprint_id: String,
    /// Finished graph task.
    pub task_id: String,
    /// Exact sole winning integrated attempt and complete lease identity.
    pub attempt: TaskAttempt,
    /// Exact typed integrated disposition identity.
    pub integration_disposition_id: String,
    /// Exact explicit result, including an empty operation vector once the
    /// task-level verified-no-op contract admits that shape.
    pub change_set: ChangeSet,
    /// Exact successful integration receipt.
    pub integration_receipt: TaskIntegrationReceipt,
    /// Canonical effect-sorted terminal observation links across every attempt.
    pub terminal_effects: Vec<TaskAttemptTerminalEffect>,
    /// Formal-check identities in declared criterion order.
    pub formal_check_ids: Vec<String>,
    /// Exact ordinary-runner zero-survivor cleanup.
    pub runner_cleanup: WorkerCleanupEvidence,
    /// Exact effect-sorted cleanup proof set for every command domain.
    pub command_domain_cleanup: CompleteCommandDomainCleanupSet,
    /// Exact cleanup-coupled released projection for the originating lease.
    pub lease_release: TaskAttemptLeaseState,
    /// Attempt-ordinal universal closure proof for every nonwinner.
    pub non_winning_attempts: Vec<TaskDoneClosedAttemptProof>,
}

/// Point-in-time, read-only result of computing the exact task finish standard.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TaskDoneAssessment {
    /// Owning sprint.
    pub sprint_id: String,
    /// Assessed graph task.
    pub task_id: String,
    /// Canonically ordered conjunction terms that are not yet proven.
    pub unmet_requirements: Vec<TaskDoneRequirement>,
    /// Present exactly when `unmet_requirements` is empty.
    pub proof: Option<TaskDoneProof>,
}

impl TaskDoneAssessment {
    /// Returns whether every exact task-finish term is proven.
    #[must_use]
    pub fn is_done(&self) -> bool {
        self.unmet_requirements.is_empty() && self.proof.is_some()
    }
}

impl EventLedger {
    /// Computes `TaskDone` exclusively from canonical durable ledger state.
    ///
    /// Missing lifecycle evidence is reported as an unmet requirement. Crossed,
    /// noncanonical, ambiguous, or corrupt retained evidence is an error and can
    /// never be converted into a false success.
    ///
    /// # Errors
    ///
    /// Returns [`LedgerError`] when the sprint or graph task is absent, or any
    /// retained authority fails exact readback validation.
    pub fn assess_task_done(
        &self,
        sprint_id: &str,
        task_id: &str,
    ) -> Result<TaskDoneAssessment, LedgerError> {
        assess_task_done_from(&self.connection, sprint_id, task_id)
    }
}

#[allow(clippy::too_many_lines)] // Keeps the public finish conjunction auditable in formula order.
pub(super) fn assess_task_done_from(
    connection: &Connection,
    sprint_id: &str,
    task_id: &str,
) -> Result<TaskDoneAssessment, LedgerError> {
    let (_, graph, _) = load_sprint_inputs(connection, sprint_id)?;
    graph.task(task_id).ok_or_else(|| {
        reference_mismatch(
            "task done assessment",
            format!("task `{task_id}` is absent from the durable graph"),
        )
    })?;
    let history = load_task_attempt_history_from(connection, sprint_id, task_id)?;
    let mut unmet = TaskDoneRequirement::ALL
        .into_iter()
        .collect::<BTreeSet<_>>();

    if history.task_state == TaskState::Integrated {
        unmet.remove(&TaskDoneRequirement::DurableTaskStateIntegrated);
    }

    let integrated_attempts = history
        .attempts
        .iter()
        .filter_map(|entry| match entry.disposition.as_ref() {
            Some(TaskAttemptDisposition::Integrated(integrated)) => Some((entry, integrated)),
            _ => None,
        })
        .collect::<Vec<_>>();
    let winning = (integrated_attempts.len() == 1).then(|| integrated_attempts[0]);
    if winning.is_some() {
        unmet.remove(&TaskDoneRequirement::ExactWinningIntegratedAttemptAndLease);
        unmet.remove(&TaskDoneRequirement::WinningAttemptDispositionIntegrated);
    }

    let mut integration_receipt = None;
    let mut change_set = None;
    let mut formal_check_ids = None;
    if let Some((entry, integrated)) = winning {
        let receipt = load_task_integration_receipt_from(
            connection,
            &integrated.integration_receipt.receipt_id,
        )?;
        if receipt != integrated.integration_receipt {
            return Err(LedgerError::Corrupt {
                entity: "task done integration disposition",
                detail: "typed disposition differs from canonical integration receipt".into(),
            });
        }
        let result = load_change_set_from(connection, sprint_id, &receipt.change_set_id)?;
        if result.change_set_id == receipt.change_set_id {
            unmet.remove(&TaskDoneRequirement::ExactResultIntegrated);
            change_set = Some(result.clone());
        }

        let snapshots_match = result.base_snapshot == receipt.input_snapshot
            && result.result_snapshot == receipt.result_snapshot
            && integrated.candidate_boundary.change_set_id == result.change_set_id
            && integrated.candidate_boundary.sealed_snapshot == receipt.result_snapshot
            && entry
                .verification_boundary
                .as_ref()
                .is_some_and(|boundary| {
                    boundary.change_set_id == result.change_set_id
                        && boundary.sealed_snapshot == receipt.result_snapshot
                });
        if snapshots_match {
            load_workspace_snapshot_from(connection, sprint_id, &receipt.input_snapshot)?;
            load_workspace_snapshot_from(connection, sprint_id, &receipt.result_snapshot)?;
            unmet.remove(&TaskDoneRequirement::IntegrationReceiptMatchesResultSnapshot);
        }

        let checks_pass = entry.formal_checks.iter().all(|check| {
            check.verification_receipt.passed()
                && check.sealed_snapshot == receipt.result_snapshot
                && check.verification_receipt.snapshot_id == receipt.result_snapshot
        }) && entry.candidate_boundary.as_ref().is_some_and(|candidate| {
            candidate.verification_receipt_ids == receipt.task_verification_receipt_ids
        });
        if checks_pass {
            unmet.remove(&TaskDoneRequirement::RequiredTaskChecksPassedOnResultSnapshot);
            formal_check_ids = Some(
                entry
                    .formal_checks
                    .iter()
                    .map(|check| check.formal_check_id.clone())
                    .collect(),
            );
        }
        integration_receipt = Some(receipt);
    }

    let all_effects = load_task_owned_effects(connection, sprint_id, task_id, &history.attempts)?;
    let mut effects_by_attempt = (0..history.attempts.len())
        .map(|_| Vec::new())
        .collect::<Vec<Vec<&PersistedEffect>>>();
    for effect in &all_effects {
        let owning_attempt = effect.intent.worker_lease.as_ref().and_then(|lease| {
            history
                .attempts
                .iter()
                .position(|entry| entry.attempt.worker_lease == *lease)
        });
        if effect.intent.task_id.as_deref() == Some(task_id) && owning_attempt.is_none() {
            return Err(LedgerError::Corrupt {
                entity: "task done effect ownership",
                detail: format!(
                    "task effect '{}' is not bound to any exact task attempt lease",
                    effect.intent.effect_id
                ),
            });
        }
        if let Some(index) = owning_attempt {
            let cleanup = effect.intent.kind == EffectKind::CleanupWorkerDomain;
            if (!cleanup && effect.intent.task_id.as_deref() != Some(task_id))
                || (cleanup && effect.intent.task_id.is_some())
            {
                return Err(LedgerError::Corrupt {
                    entity: "task done effect ownership",
                    detail: format!(
                        "effect '{}' crosses its attempt lease and task scope",
                        effect.intent.effect_id
                    ),
                });
            }
            effects_by_attempt[index].push(effect);
        }
    }

    let mut closures = Vec::with_capacity(history.attempts.len());
    for (entry, effects) in history.attempts.iter().zip(&effects_by_attempt) {
        closures.push(assess_attempt_closure(
            connection, sprint_id, entry, effects,
        )?);
    }

    let all_effects_known = closures
        .iter()
        .all(|closure| closure.effects_known.is_proven());
    let all_runner_cleanup = closures
        .iter()
        .all(|closure| closure.runner_cleanup_proven.is_proven());
    let all_command_cleanup = closures
        .iter()
        .all(|closure| closure.command_cleanup_proven.is_proven());
    let mut all_command_captures_terminal = true;
    for effect in all_effects
        .iter()
        .filter(|effect| effect.intent.kind == EffectKind::RunCommand)
    {
        let finish_proven = if let Some(observation) = effect.observation.as_ref() {
            super::command_output_capture_authority::finish_is_proven_for_validated_effect(
                connection,
                effect,
                observation,
            )?
        } else {
            // A pre-v27 command can legitimately have no observation while
            // its immutable migration exemption closes only the later output-
            // capture obligation. The separate effect-terminal requirement
            // remains unmet, so this does not turn an unobserved command into
            // successful task evidence.
            super::command_output_capture_authority::finish_is_proven_for_effect(
                connection,
                &effect.intent.effect_id,
            )?
        };
        if !finish_proven {
            all_command_captures_terminal = false;
        }
    }
    let all_authority_closed = closures
        .iter()
        .all(|closure| closure.no_replay_or_dispatch_authority.is_proven());
    if all_effects_known {
        unmet.remove(&TaskDoneRequirement::EveryTaskEffectTerminalNonUnknown);
    }
    if all_runner_cleanup {
        unmet.remove(&TaskDoneRequirement::RunnerDomainCleanupProven);
    }
    if all_command_cleanup {
        unmet.remove(&TaskDoneRequirement::CommandDomainCleanupProven);
    }
    if all_command_captures_terminal {
        unmet.remove(&TaskDoneRequirement::CommandOutputCaptureTerminalExact);
    }
    if all_authority_closed {
        unmet.remove(&TaskDoneRequirement::NoTaskReplayOrDispatchAuthority);
    }

    let non_winning_closed = history
        .attempts
        .iter()
        .zip(&closures)
        .all(|(entry, closure)| {
            matches!(
                entry.disposition,
                Some(TaskAttemptDisposition::Integrated(_))
            ) || (entry.disposition.is_some()
                && closure.effects_known.is_proven()
                && closure.runner_cleanup_proven.is_proven()
                && closure.command_cleanup_proven.is_proven()
                && closure.lease_released.is_proven()
                && closure.no_replay_or_dispatch_authority.is_proven())
        });
    if non_winning_closed {
        unmet.remove(&TaskDoneRequirement::EveryNonWinningAttemptDurablyClosed);
    }

    let active = worker_lease_authority::load_active(connection, sprint_id)?;
    if active.iter().all(|lease| lease.task_id != task_id) {
        unmet.remove(&TaskDoneRequirement::NoActiveTaskLeases);
    }

    let winning_index = winning.and_then(|(entry, _)| {
        history
            .attempts
            .iter()
            .position(|candidate| candidate.attempt == entry.attempt)
    });
    let mut lease_release = None;
    let mut runner_cleanup = None;
    let mut command_domain_cleanup = None;
    if let Some(index) = winning_index
        && closures[index].lease_released.is_proven()
    {
        unmet.remove(&TaskDoneRequirement::OriginatingWorkerLeaseReleased);
        lease_release = Some(history.attempts[index].lease_state.clone());
        runner_cleanup.clone_from(&closures[index].runner_cleanup);
        command_domain_cleanup.clone_from(&closures[index].command_domain_cleanup);
    }

    let unmet_requirements = unmet.into_iter().collect::<Vec<_>>();
    let proof = if unmet_requirements.is_empty() {
        let Some((entry, integrated)) = winning else {
            return Err(internal_incomplete_proof());
        };
        let Some(winning_index) = winning_index else {
            return Err(internal_incomplete_proof());
        };
        let mut terminal_effects = closures
            .iter()
            .flat_map(|closure| closure.terminal_effects.iter().cloned())
            .collect::<Vec<_>>();
        terminal_effects.sort();
        let non_winning_attempts = history
            .attempts
            .iter()
            .zip(&closures)
            .enumerate()
            .filter(|(index, _)| *index != winning_index)
            .map(|(_, (entry, closure))| {
                Ok(TaskDoneClosedAttemptProof {
                    attempt: entry.attempt.clone(),
                    disposition: entry
                        .disposition
                        .clone()
                        .ok_or_else(internal_incomplete_proof)?,
                    terminal_effects: closure.terminal_effects.clone(),
                    runner_cleanup: closure.runner_cleanup.clone(),
                    command_domain_cleanup: closure.command_domain_cleanup.clone(),
                    lease_release: entry.lease_state.clone(),
                })
            })
            .collect::<Result<Vec<_>, LedgerError>>()?;
        Some(TaskDoneProof {
            sprint_id: sprint_id.to_owned(),
            task_id: task_id.to_owned(),
            attempt: entry.attempt.clone(),
            integration_disposition_id: integrated.metadata.disposition_id.clone(),
            change_set: change_set.ok_or_else(internal_incomplete_proof)?,
            integration_receipt: integration_receipt.ok_or_else(internal_incomplete_proof)?,
            terminal_effects,
            formal_check_ids: formal_check_ids.ok_or_else(internal_incomplete_proof)?,
            runner_cleanup: runner_cleanup.ok_or_else(internal_incomplete_proof)?,
            command_domain_cleanup: command_domain_cleanup.ok_or_else(internal_incomplete_proof)?,
            lease_release: lease_release.ok_or_else(internal_incomplete_proof)?,
            non_winning_attempts,
        })
    } else {
        None
    };

    Ok(TaskDoneAssessment {
        sprint_id: sprint_id.to_owned(),
        task_id: task_id.to_owned(),
        unmet_requirements,
        proof,
    })
}

/// Loads only effects that can belong to the assessed task. Filtering on the
/// immutable indexed task/lease identity before full effect readback prevents
/// unrelated sprint-phase effects from entering `TaskDone`'s dependency graph,
/// while retaining every task-scoped effect and every taskless cleanup bound
/// to one exact attempt lease.
fn load_task_owned_effects(
    connection: &Connection,
    sprint_id: &str,
    task_id: &str,
    attempts: &[TaskAttemptHistoryEntry],
) -> Result<Vec<PersistedEffect>, LedgerError> {
    let exact_leases = attempts
        .iter()
        .map(|entry| {
            Ok((
                entry.attempt.worker_lease.lease_id.clone(),
                i64::try_from(entry.attempt.worker_lease.lease_epoch)
                    .map_err(|_| LedgerError::IntegerOutOfRange("task done lease epoch"))?,
            ))
        })
        .collect::<Result<BTreeSet<_>, LedgerError>>()?;
    let worker_schema = worker_lease_authority::schema_is_installed(connection)?;
    let sql = if worker_schema {
        "SELECT effect_id, task_id, worker_lease_id, worker_lease_epoch
         FROM effect_intents WHERE sprint_id = ?1 ORDER BY effect_id ASC"
    } else {
        "SELECT effect_id, task_id, NULL, NULL
         FROM effect_intents WHERE sprint_id = ?1 ORDER BY effect_id ASC"
    };
    let mut statement = connection.prepare(sql)?;
    let rows = statement
        .query_map([sprint_id], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, Option<String>>(1)?,
                row.get::<_, Option<String>>(2)?,
                row.get::<_, Option<i64>>(3)?,
            ))
        })?
        .collect::<Result<Vec<_>, _>>()?;
    rows.into_iter()
        .filter(|(_, indexed_task_id, lease_id, lease_epoch)| {
            indexed_task_id.as_deref() == Some(task_id)
                || lease_id
                    .as_ref()
                    .zip(*lease_epoch)
                    .is_some_and(|(lease_id, lease_epoch)| {
                        exact_leases.contains(&(lease_id.clone(), lease_epoch))
                    })
        })
        .map(|(effect_id, _, _, _)| load_effect_from_with_receipts(connection, &effect_id, false))
        .collect()
}

#[derive(Debug)]
struct AttemptClosureEvidence {
    terminal_effects: Vec<TaskAttemptTerminalEffect>,
    effects_known: ClosureTerm,
    runner_cleanup: Option<WorkerCleanupEvidence>,
    runner_cleanup_proven: ClosureTerm,
    command_domain_cleanup: Option<CompleteCommandDomainCleanupSet>,
    command_cleanup_proven: ClosureTerm,
    lease_released: ClosureTerm,
    no_replay_or_dispatch_authority: ClosureTerm,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ClosureTerm {
    Missing,
    Proven,
}

impl ClosureTerm {
    const fn from_proven(proven: bool) -> Self {
        if proven { Self::Proven } else { Self::Missing }
    }

    const fn is_proven(self) -> bool {
        matches!(self, Self::Proven)
    }
}

fn assess_attempt_closure(
    connection: &Connection,
    sprint_id: &str,
    entry: &TaskAttemptHistoryEntry,
    effects: &[&PersistedEffect],
) -> Result<AttemptClosureEvidence, LedgerError> {
    let launch = load_attempt_launch(connection, sprint_id, &entry.attempt.worker_lease)?;
    let (mut terminal_effects, effects_known) =
        validate_attempt_effects(connection, entry, launch.as_ref(), effects)?;
    terminal_effects.sort();

    let mut runner_cleanup = None;
    let mut runner_cleanup_proven = false;
    let mut command_domain_cleanup = None;
    let mut command_cleanup_proven = false;
    let mut lease_released = false;

    if let Some(launch) = launch.as_ref() {
        runner_cleanup = load_attempt_runner_cleanup(connection, sprint_id, entry, launch)?;
        if let Some(cleanup) = runner_cleanup.as_ref() {
            runner_cleanup_proven = true;
            let session = load_attempt_session(connection, sprint_id, entry, launch)?;
            if let Some(session) = session {
                let backend = command_backend(cleanup.receipt.platform_backend)?;
                if let CommandDomainCleanupCompleteness::Complete(complete) =
                    load_task_done_command_domain_cleanup_completeness_from(
                        connection,
                        sprint_id,
                        &launch.launch_id,
                        &session.session_id,
                        backend,
                        effects,
                    )?
                {
                    command_cleanup_proven = true;
                    command_domain_cleanup = Some(complete);
                }
            } else {
                command_cleanup_proven = true;
            }
            lease_released = validate_attempt_release(connection, entry, Some(cleanup))?;
        }
    } else if has_exact_never_launched_release(entry) {
        runner_cleanup_proven = true;
        command_cleanup_proven = true;
        lease_released = validate_attempt_release(connection, entry, None)?;
    }

    let no_durable_authority =
        !attempt_has_replay_or_dispatch_authority(connection, &entry.attempt.worker_lease)?;
    let no_replay_or_dispatch_authority =
        entry.disposition.is_some() && effects_known && lease_released && no_durable_authority;

    Ok(AttemptClosureEvidence {
        terminal_effects,
        effects_known: ClosureTerm::from_proven(effects_known),
        runner_cleanup,
        runner_cleanup_proven: ClosureTerm::from_proven(runner_cleanup_proven),
        command_domain_cleanup,
        command_cleanup_proven: ClosureTerm::from_proven(command_cleanup_proven),
        lease_released: ClosureTerm::from_proven(lease_released),
        no_replay_or_dispatch_authority: ClosureTerm::from_proven(no_replay_or_dispatch_authority),
    })
}

fn load_attempt_launch(
    connection: &Connection,
    sprint_id: &str,
    lease: &WorkerLease,
) -> Result<Option<RunnerLaunchIntent>, LedgerError> {
    let launch_id = connection
        .query_row(
            "SELECT launch_id FROM runner_launch_intents
             WHERE sprint_id = ?1 AND worker_lease_id = ?2 AND worker_lease_epoch = ?3",
            params![
                sprint_id,
                lease.lease_id,
                i64::try_from(lease.lease_epoch)
                    .map_err(|_| LedgerError::IntegerOutOfRange("task done lease epoch"))?
            ],
            |row| row.get::<_, String>(0),
        )
        .optional()?;
    launch_id
        .map(|launch_id| {
            let (launch, _) = load_runner_launch_intent_from(connection, sprint_id, &launch_id)?;
            if launch.purpose != RunnerSessionPurpose::TaskWorker
                || launch.worker_lease.as_ref() != Some(lease)
            {
                return Err(LedgerError::Corrupt {
                    entity: "task done attempt launch",
                    detail: "attempt launch role or lease differs from its owning attempt".into(),
                });
            }
            Ok(launch)
        })
        .transpose()
}

fn validate_attempt_effects(
    connection: &Connection,
    entry: &TaskAttemptHistoryEntry,
    launch: Option<&RunnerLaunchIntent>,
    effects: &[&PersistedEffect],
) -> Result<(Vec<TaskAttemptTerminalEffect>, bool), LedgerError> {
    let mut terminal_effects = Vec::new();
    let mut all_known = true;
    for effect in effects {
        if effect.intent.kind == EffectKind::ProviderRequest {
            let unexpectedly_bound = connection.query_row(
                "SELECT EXISTS(
                     SELECT 1 FROM effect_session_bindings WHERE effect_id = ?1
                 )",
                [&effect.intent.effect_id],
                |row| row.get::<_, bool>(0),
            )?;
            if unexpectedly_bound {
                return Err(LedgerError::Corrupt {
                    entity: "task done effect binding",
                    detail: format!(
                        "provider effect '{}' unexpectedly claims runner authority",
                        effect.intent.effect_id
                    ),
                });
            }
        } else {
            let launch = launch.ok_or_else(|| LedgerError::Corrupt {
                entity: "task done effect binding",
                detail: format!(
                    "runner effect '{}' exists for a proven never-launched attempt",
                    effect.intent.effect_id
                ),
            })?;
            let binding = load_effect_runner_binding(connection, &effect.intent)?;
            if binding.launch.launch_id != launch.launch_id
                || binding.launch.worker_lease.as_ref() != Some(&entry.attempt.worker_lease)
            {
                return Err(LedgerError::Corrupt {
                    entity: "task done effect binding",
                    detail: format!(
                        "effect '{}' is crossed away from its exact attempt launch",
                        effect.intent.effect_id
                    ),
                });
            }
            if effect.intent.kind == EffectKind::CleanupWorkerDomain {
                if binding.session.is_some() {
                    return Err(LedgerError::Corrupt {
                        entity: "task done effect binding",
                        detail: format!(
                            "cleanup effect '{}' claims ordinary session authority",
                            effect.intent.effect_id
                        ),
                    });
                }
            } else {
                let running =
                    entry
                        .running_boundary
                        .as_ref()
                        .ok_or_else(|| LedgerError::Corrupt {
                            entity: "task done effect binding",
                            detail: format!(
                                "ordinary runner effect '{}' exists without a Running boundary",
                                effect.intent.effect_id
                            ),
                        })?;
                let session = binding
                    .session
                    .as_ref()
                    .ok_or_else(|| LedgerError::Corrupt {
                        entity: "task done effect binding",
                        detail: format!(
                            "ordinary runner effect '{}' lacks initialized session authority",
                            effect.intent.effect_id
                        ),
                    })?;
                if running.runner_launch_id != launch.launch_id
                    || running.runner_session_id != session.session_id
                    || session.launch_id != launch.launch_id
                {
                    return Err(LedgerError::Corrupt {
                        entity: "task done effect binding",
                        detail: format!(
                            "effect '{}' crosses its attempt Running boundary",
                            effect.intent.effect_id
                        ),
                    });
                }
            }
        }
        let Some(observation) = effect.observation.as_ref() else {
            all_known = false;
            continue;
        };
        if matches!(observation.outcome, EffectOutcome::Unknown { .. }) {
            all_known = false;
            continue;
        }
        terminal_effects.push(TaskAttemptTerminalEffect {
            effect_id: effect.intent.effect_id.clone(),
            observation_id: observation.observation_id.clone(),
        });
    }
    Ok((terminal_effects, all_known))
}

fn load_attempt_runner_cleanup(
    connection: &Connection,
    sprint_id: &str,
    entry: &TaskAttemptHistoryEntry,
    launch: &RunnerLaunchIntent,
) -> Result<Option<WorkerCleanupEvidence>, LedgerError> {
    let cleanup_ids = {
        let mut statement = connection.prepare(
            "SELECT receipt_id FROM worker_cleanup_receipts
             WHERE sprint_id = ?1 AND launch_id = ?2 ORDER BY receipt_id ASC",
        )?;
        statement
            .query_map(params![sprint_id, launch.launch_id], |row| {
                row.get::<_, String>(0)
            })?
            .collect::<Result<Vec<_>, _>>()?
    };
    if cleanup_ids.len() > 1 {
        return Err(LedgerError::Corrupt {
            entity: "task done runner cleanup",
            detail: "multiple cleanup receipts claim one exact attempt launch".into(),
        });
    }
    let Some(cleanup_id) = cleanup_ids.first() else {
        return Ok(None);
    };
    let cleanup = load_worker_cleanup_evidence_from(connection, cleanup_id)?;
    if cleanup.receipt.worker_lease.as_ref() != Some(&entry.attempt.worker_lease)
        || cleanup.receipt.launch_id != launch.launch_id
        || cleanup.receipt.session_id != launch.session_id
        || cleanup.receipt.surviving_processes != 0
        || cleanup.receipt.platform_backend == WorkerCleanupBackend::TrustedApplierDirectChildWait
    {
        return Err(LedgerError::Corrupt {
            entity: "task done runner cleanup",
            detail: "attempt cleanup crosses its lease, launch, session, backend, or survivor set"
                .into(),
        });
    }
    validate_cleanup_after_launch_activity(connection, launch, &cleanup)?;
    Ok(Some(cleanup))
}

fn load_attempt_session(
    connection: &Connection,
    sprint_id: &str,
    entry: &TaskAttemptHistoryEntry,
    launch: &RunnerLaunchIntent,
) -> Result<Option<RunnerSessionPolicyRecord>, LedgerError> {
    let session_ids = {
        let mut statement = connection.prepare(
            "SELECT session_id FROM runner_session_policies
             WHERE sprint_id = ?1 AND launch_id = ?2 ORDER BY session_id ASC",
        )?;
        statement
            .query_map(params![sprint_id, launch.launch_id], |row| {
                row.get::<_, String>(0)
            })?
            .collect::<Result<Vec<_>, _>>()?
    };
    if session_ids.len() > 1 {
        return Err(LedgerError::Corrupt {
            entity: "task done attempt session",
            detail: "one attempt launch has multiple initialized sessions".into(),
        });
    }
    let Some(session_id) = session_ids.first() else {
        let bound_sessions: i64 = connection.query_row(
            "SELECT COUNT(*) FROM effect_session_bindings
             WHERE sprint_id = ?1 AND launch_id = ?2 AND session_id IS NOT NULL",
            params![sprint_id, launch.launch_id],
            |row| row.get(0),
        )?;
        if bound_sessions != 0 {
            return Err(LedgerError::Corrupt {
                entity: "task done attempt session",
                detail: "uninitialized launch retains ordinary effect-session bindings".into(),
            });
        }
        return Ok(None);
    };
    let (session, _) = load_runner_session_policy_from(connection, sprint_id, session_id)?;
    if session.session_id != launch.session_id
        || session.launch_id != launch.launch_id
        || session.purpose != RunnerSessionPurpose::TaskWorker
        || session.worker_lease.as_ref() != Some(&entry.attempt.worker_lease)
    {
        return Err(LedgerError::Corrupt {
            entity: "task done attempt session",
            detail: "initialized session crosses its exact attempt launch or lease".into(),
        });
    }
    Ok(Some(session))
}

fn command_backend(backend: WorkerCleanupBackend) -> Result<CommandDomainBackend, LedgerError> {
    match backend {
        WorkerCleanupBackend::MacOsDedicatedIdentity => {
            Ok(CommandDomainBackend::MacOsDedicatedIdentity)
        }
        WorkerCleanupBackend::LinuxCgroupV2 => Ok(CommandDomainBackend::LinuxCgroupV2),
        WorkerCleanupBackend::TrustedApplierDirectChildWait => Err(LedgerError::Corrupt {
            entity: "task done command cleanup",
            detail: "ordinary task runner cannot use trusted-applier cleanup".into(),
        }),
    }
}

fn has_exact_never_launched_release(entry: &TaskAttemptHistoryEntry) -> bool {
    matches!(
        entry.disposition.as_ref().and_then(TaskAttemptDisposition::release_proof),
        Some(TaskAttemptReleaseProof::NeverLaunched(release))
            if release.attempt == entry.attempt
                && matches!(
                    &entry.lease_state,
                    TaskAttemptLeaseState::Released {
                        release_id,
                        released_at_unix_ms,
                    } if release_id == &release.release_id
                        && *released_at_unix_ms == release.released_at_unix_ms
                )
    )
}

fn validate_attempt_release(
    connection: &Connection,
    entry: &TaskAttemptHistoryEntry,
    cleanup: Option<&WorkerCleanupEvidence>,
) -> Result<bool, LedgerError> {
    let TaskAttemptLeaseState::Released {
        release_id,
        released_at_unix_ms,
    } = &entry.lease_state
    else {
        return Ok(false);
    };
    match cleanup {
        Some(cleanup) => {
            if *released_at_unix_ms != cleanup.receipt.cleaned_at_unix_ms {
                return Ok(false);
            }
            if let Some(release_proof) = entry
                .disposition
                .as_ref()
                .and_then(TaskAttemptDisposition::release_proof)
            {
                let TaskAttemptReleaseProof::Cleanup(release) = release_proof else {
                    return Ok(false);
                };
                if release.release_id != *release_id
                    || release.cleanup_receipt != cleanup.receipt
                    || release.released_at_unix_ms != *released_at_unix_ms
                {
                    return Ok(false);
                }
            }
            worker_lease_authority::require_exact_release(
                connection,
                &entry.attempt.worker_lease,
                &cleanup.receipt.receipt_id,
                &cleanup.receipt.effect_id,
                &cleanup.receipt.observation_id,
                cleanup.receipt.cleaned_at_unix_ms,
            )?;
            Ok(true)
        }
        None => Ok(has_exact_never_launched_release(entry)),
    }
}

fn attempt_has_replay_or_dispatch_authority(
    connection: &Connection,
    lease: &WorkerLease,
) -> Result<bool, LedgerError> {
    connection
        .query_row(
            "SELECT
                EXISTS (
                    SELECT 1
                    FROM worker_lease_acquisitions acquisition
                    LEFT JOIN worker_lease_releases release
                      ON release.lease_id = acquisition.lease_id
                    LEFT JOIN worker_lease_never_launched_releases no_launch
                      ON no_launch.worker_lease_id = acquisition.lease_id
                    WHERE acquisition.lease_id = ?1
                      AND acquisition.lease_epoch = ?2
                      AND release.lease_id IS NULL
                      AND no_launch.release_id IS NULL
                )
                OR EXISTS (
                    SELECT 1
                    FROM effect_intents intent
                    LEFT JOIN effect_observations observation
                      ON observation.effect_id = intent.effect_id
                    WHERE intent.worker_lease_id = ?1
                      AND intent.worker_lease_epoch = ?2
                      AND (observation.effect_id IS NULL OR observation.outcome = 'Unknown')
                )
                OR EXISTS (
                    SELECT 1
                    FROM runner_effect_dispatch_claims claim
                    JOIN effect_intents intent ON intent.effect_id = claim.effect_id
                    LEFT JOIN effect_observations observation
                      ON observation.dispatch_claim_id = claim.dispatch_claim_id
                    WHERE intent.worker_lease_id = ?1
                      AND intent.worker_lease_epoch = ?2
                      AND observation.dispatch_claim_id IS NULL
                )",
            params![
                lease.lease_id,
                i64::try_from(lease.lease_epoch)
                    .map_err(|_| LedgerError::IntegerOutOfRange("task done lease epoch"))?
            ],
            |row| row.get::<_, bool>(0),
        )
        .map_err(Into::into)
}

fn internal_incomplete_proof() -> LedgerError {
    LedgerError::Corrupt {
        entity: "task done assessment",
        detail: "empty unmet set did not produce the complete exact proof tuple".into(),
    }
}
