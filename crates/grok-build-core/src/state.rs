//! Explicit task, worker, and sprint transition tables.

use std::error::Error;
use std::fmt::{self, Display, Formatter};

use serde::{Deserialize, Serialize};

use crate::{
    CompletionApplicationAssessment, CompletionAssessment, ContractError,
    CurrentRepairActivationPermitV1, SprintSpecV2, TaskGraphV2, TaskPurposeV2,
};

/// State of one task in the persisted graph.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum TaskState {
    /// Planned but not yet dependency-ready.
    Planned,
    /// Dependencies are integrated and the task may be leased.
    Ready,
    /// Exclusive write scopes are leased to a worker.
    Leased,
    /// A worker is inspecting or changing its private workspace.
    Running,
    /// Task-specific acceptance checks are running.
    Verifying,
    /// The verified change set is ready for coordinator integration.
    Candidate,
    /// The change set and its checks are integrated.
    Integrated,
    /// Progress requires new user authority or input.
    Blocked,
    /// Bounded repair attempts were exhausted.
    Failed,
    /// The sprint or task was deliberately stopped.
    Canceled,
    /// A crash-time side effect cannot be proven.
    Unknown,
}

impl TaskState {
    /// Returns whether no further transition is permitted.
    #[must_use]
    pub const fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::Integrated | Self::Blocked | Self::Failed | Self::Canceled | Self::Unknown
        )
    }

    /// Returns whether the task successfully integrated.
    #[must_use]
    pub const fn is_success(self) -> bool {
        matches!(self, Self::Integrated)
    }

    /// Applies one legal task transition.
    ///
    /// # Errors
    ///
    /// Returns [`StateTransitionError::InvalidTask`] when the transition is not
    /// present in the task lifecycle.
    pub fn transition(self, next: Self) -> Result<Self, StateTransitionError> {
        let common_terminal = matches!(
            next,
            Self::Blocked | Self::Failed | Self::Canceled | Self::Unknown
        ) && !self.is_terminal();
        let normal = matches!(
            (self, next),
            (Self::Planned, Self::Ready)
                | (Self::Ready, Self::Leased)
                | (Self::Leased, Self::Running)
                | (Self::Running, Self::Verifying)
                | (Self::Verifying, Self::Candidate)
                | (Self::Candidate, Self::Integrated)
        );
        if common_terminal || normal {
            Ok(next)
        } else {
            Err(StateTransitionError::InvalidTask {
                from: self,
                to: next,
            })
        }
    }
}

/// Applies one task transition under exact current-V2 graph context.
///
/// This additive API leaves [`TaskState::transition`] byte-for-byte semantic
/// authority for legacy callers. Ordinary V2 tasks are validated from the
/// paired sprint/graph and never consume repair authority. A repair slot may
/// enter or advance through an execution-bearing state only under its exact
/// sealed core-minted activation permit; terminal closure from `Planned`
/// remains possible without activating work.
///
/// # Errors
///
/// Returns a contract error for an invalid V2 pair, unknown/crossed task,
/// illegal lifecycle edge, caller-supplied repair authority on an ordinary
/// task, or a missing/crossed repair activation permit.
pub fn transition_current_v2_task(
    sprint: &SprintSpecV2,
    graph: &TaskGraphV2,
    task_id: &str,
    current: TaskState,
    next: TaskState,
    repair_activation_permit: Option<&CurrentRepairActivationPermitV1>,
) -> Result<TaskState, ContractError> {
    graph.validate_for_sprint(sprint)?;
    let task = graph
        .tasks
        .iter()
        .find(|task| task.task_id == task_id)
        .ok_or_else(|| {
            ContractError::new(
                "current_v2_task_transition.task_id",
                "does not name a task in the exact bound graph",
            )
        })?;
    task.validate()?;
    let transitioned = current.transition(next).map_err(|_| {
        ContractError::new(
            "current_v2_task_transition.state",
            format!("transition from {current:?} to {next:?} is not permitted"),
        )
    })?;
    match task.purpose {
        TaskPurposeV2::Ordinary => {
            if repair_activation_permit.is_some() {
                return Err(ContractError::new(
                    "current_v2_task_transition.repair_activation_permit",
                    "ordinary tasks cannot consume repair-slot authority",
                ));
            }
        }
        TaskPurposeV2::FinalVerificationRepairSlot { .. } => {
            let enters_or_advances_execution = matches!(
                transitioned,
                TaskState::Ready
                    | TaskState::Leased
                    | TaskState::Running
                    | TaskState::Verifying
                    | TaskState::Candidate
                    | TaskState::Integrated
            );
            if enters_or_advances_execution {
                let permit = repair_activation_permit.ok_or_else(|| {
                    ContractError::new(
                        "current_v2_task_transition.repair_activation_permit",
                        "a repair slot cannot leave dormancy without its exact activation permit",
                    )
                })?;
                permit.validate_for(sprint, graph)?;
                if permit.repair_task_id() != task.task_id {
                    return Err(ContractError::new(
                        "current_v2_task_transition.repair_activation_permit",
                        "activation permit names a different repair task",
                    ));
                }
            }
        }
    }
    Ok(transitioned)
}

/// Lifecycle of a worker slot within one sprint.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum WorkerState {
    /// The worker slot is available for a task.
    Idle,
    /// A task and lease have been assigned.
    Assigned,
    /// The worker is inspecting or changing its private workspace.
    Running,
    /// The worker is running task-specific checks.
    Verifying,
    /// Shutdown and descendant cleanup are underway.
    Stopping,
    /// Cleanup proved that the worker has no survivors.
    Stopped,
    /// The worker failed irrecoverably.
    Failed,
    /// The worker was deliberately canceled and cleaned up.
    Canceled,
    /// Worker side effects or cleanup cannot be proven.
    Unknown,
}

impl WorkerState {
    /// Returns whether this worker instance cannot accept more work.
    #[must_use]
    pub const fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::Stopped | Self::Failed | Self::Canceled | Self::Unknown
        )
    }

    /// Applies one legal worker transition.
    ///
    /// # Errors
    ///
    /// Returns [`StateTransitionError::InvalidWorker`] when the transition is
    /// not present in the worker lifecycle.
    pub fn transition(self, next: Self) -> Result<Self, StateTransitionError> {
        let failed =
            matches!(next, Self::Failed | Self::Canceled | Self::Unknown) && !self.is_terminal();
        let normal = matches!(
            (self, next),
            (Self::Idle, Self::Assigned | Self::Stopping)
                | (Self::Assigned | Self::Verifying, Self::Running | Self::Idle)
                | (Self::Running, Self::Verifying | Self::Stopping)
                | (Self::Verifying, Self::Stopping)
                | (Self::Stopping, Self::Stopped)
        );
        if failed || normal {
            Ok(next)
        } else {
            Err(StateTransitionError::InvalidWorker {
                from: self,
                to: next,
            })
        }
    }
}

/// State of the coordinator-owned sprint lifecycle.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum SprintState {
    /// The user is still defining the objective.
    Draft,
    /// The coordinator is producing and validating the task graph.
    Planning,
    /// At least one task is active or ready.
    Running,
    /// A human-only acceptance criterion is pending.
    AwaitingAcceptance,
    /// Repository-wide checks are running against the integration snapshot.
    FinalVerification,
    /// The verified snapshot is being journaled into the live workspace.
    Applying,
    /// The computed finish contract passed and its receipt was persisted.
    Completed,
    /// Progress requires new user authority or input.
    Blocked,
    /// Bounded repair attempts were exhausted.
    Failed,
    /// The user deliberately stopped the sprint.
    Canceled,
    /// A side effect cannot be proven or safely replayed.
    Unknown,
}

impl SprintState {
    /// Returns whether no further transition is permitted.
    #[must_use]
    pub const fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::Completed | Self::Blocked | Self::Failed | Self::Canceled | Self::Unknown
        )
    }

    /// Returns whether this is the sole successful terminal state.
    #[must_use]
    pub const fn is_success(self) -> bool {
        matches!(self, Self::Completed)
    }

    /// Applies a legal non-completion transition.
    ///
    /// `Completed` is deliberately rejected here. Call [`Self::complete`]
    /// with a computed [`CompletionAssessment`] instead.
    ///
    /// # Errors
    ///
    /// Returns [`StateTransitionError`] when the transition is invalid or tries
    /// to bypass computed completion.
    pub fn transition(self, next: Self) -> Result<Self, StateTransitionError> {
        if next == Self::Completed {
            return Err(StateTransitionError::CompletionEvidenceRequired);
        }
        let alternative_terminal = matches!(
            next,
            Self::Blocked | Self::Failed | Self::Canceled | Self::Unknown
        ) && !self.is_terminal();
        let normal = matches!(
            (self, next),
            (Self::Draft, Self::Planning)
                | (
                    Self::Planning | Self::AwaitingAcceptance | Self::FinalVerification,
                    Self::Running
                )
                | (
                    Self::Planning | Self::Running | Self::FinalVerification,
                    Self::AwaitingAcceptance
                )
                | (
                    Self::Running | Self::AwaitingAcceptance,
                    Self::FinalVerification
                )
                | (Self::FinalVerification, Self::Applying)
        );
        if alternative_terminal || normal {
            Ok(next)
        } else {
            Err(StateTransitionError::InvalidSprint {
                from: self,
                to: next,
            })
        }
    }

    /// Projects a complete branch-typed assessment into the matching terminal state.
    ///
    /// Applied completion can only finish `Applying`; verified no-op completion
    /// can only finish `FinalVerification`. This in-memory transition is not a
    /// durable completion authority; the event ledger owns atomic persistence.
    ///
    /// # Errors
    ///
    /// Returns [`StateTransitionError::InvalidSprint`] unless the current state
    /// matches the assessment branch, or [`StateTransitionError::CompletionIncomplete`]
    /// when any computed completion requirement remains unmet.
    pub fn complete(self, assessment: &CompletionAssessment) -> Result<Self, StateTransitionError> {
        let state_matches_branch = matches!(
            (self, assessment.application()),
            (
                Self::Applying,
                Some(CompletionApplicationAssessment::Applied)
            ) | (
                Self::FinalVerification,
                Some(CompletionApplicationAssessment::VerifiedNoOp)
            )
        );
        if !state_matches_branch {
            return Err(StateTransitionError::InvalidSprint {
                from: self,
                to: Self::Completed,
            });
        }
        if !assessment.is_complete() {
            return Err(StateTransitionError::CompletionIncomplete);
        }
        Ok(Self::Completed)
    }
}

/// A rejected state transition.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum StateTransitionError {
    /// Invalid task transition.
    InvalidTask {
        /// Current state.
        from: TaskState,
        /// Requested state.
        to: TaskState,
    },
    /// Invalid worker transition.
    InvalidWorker {
        /// Current state.
        from: WorkerState,
        /// Requested state.
        to: WorkerState,
    },
    /// Invalid sprint transition.
    InvalidSprint {
        /// Current state.
        from: SprintState,
        /// Requested state.
        to: SprintState,
    },
    /// Ordinary transitions cannot declare a sprint completed.
    CompletionEvidenceRequired,
    /// The coordinator's computed completion requirements are not all met.
    CompletionIncomplete,
}

impl Display for StateTransitionError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidTask { from, to } => {
                write!(formatter, "invalid task transition: {from:?} -> {to:?}")
            }
            Self::InvalidWorker { from, to } => {
                write!(formatter, "invalid worker transition: {from:?} -> {to:?}")
            }
            Self::InvalidSprint { from, to } => {
                write!(formatter, "invalid sprint transition: {from:?} -> {to:?}")
            }
            Self::CompletionEvidenceRequired => {
                formatter.write_str("sprint completion requires a computed assessment")
            }
            Self::CompletionIncomplete => {
                formatter.write_str("sprint completion requirements are not all met")
            }
        }
    }
}

impl Error for StateTransitionError {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::CompletionRequirement;

    #[test]
    fn task_happy_path_and_repair_loop_are_explicit() {
        let state = TaskState::Planned
            .transition(TaskState::Ready)
            .and_then(|state| state.transition(TaskState::Leased))
            .and_then(|state| state.transition(TaskState::Running))
            .and_then(|state| state.transition(TaskState::Verifying))
            .and_then(|state| state.transition(TaskState::Candidate))
            .and_then(|state| state.transition(TaskState::Integrated));
        assert_eq!(state, Ok(TaskState::Integrated));
        assert!(TaskState::Integrated.is_terminal());
        assert!(
            TaskState::Integrated
                .transition(TaskState::Running)
                .is_err()
        );
    }

    #[test]
    fn every_active_task_can_stop_but_terminal_tasks_cannot_restart() {
        for state in [
            TaskState::Planned,
            TaskState::Ready,
            TaskState::Leased,
            TaskState::Running,
            TaskState::Verifying,
            TaskState::Candidate,
        ] {
            assert_eq!(
                state.transition(TaskState::Canceled),
                Ok(TaskState::Canceled)
            );
        }
        assert!(TaskState::Failed.transition(TaskState::Ready).is_err());
        assert!(TaskState::Leased.transition(TaskState::Ready).is_err());
        assert!(TaskState::Verifying.transition(TaskState::Running).is_err());
        assert!(TaskState::Candidate.transition(TaskState::Running).is_err());
    }

    #[test]
    fn worker_slot_can_be_reused_then_cleanly_stopped() {
        let state = WorkerState::Idle
            .transition(WorkerState::Assigned)
            .and_then(|state| state.transition(WorkerState::Running))
            .and_then(|state| state.transition(WorkerState::Verifying))
            .and_then(|state| state.transition(WorkerState::Idle))
            .and_then(|state| state.transition(WorkerState::Stopping))
            .and_then(|state| state.transition(WorkerState::Stopped));
        assert_eq!(state, Ok(WorkerState::Stopped));
        assert!(WorkerState::Stopped.is_terminal());
    }

    #[test]
    fn ordinary_sprint_transition_cannot_claim_completion() {
        assert_eq!(
            SprintState::Applying.transition(SprintState::Completed),
            Err(StateTransitionError::CompletionEvidenceRequired)
        );
        let incomplete = CompletionAssessment::from_unmet(
            CompletionApplicationAssessment::Applied,
            vec![CompletionRequirement::AllCriteriaSatisfiedByTypedBacking],
        );
        assert_eq!(
            SprintState::Applying.complete(&incomplete),
            Err(StateTransitionError::CompletionIncomplete)
        );
    }

    #[test]
    fn completion_branches_only_finish_their_exact_preterminal_state() {
        let applied =
            CompletionAssessment::from_unmet(CompletionApplicationAssessment::Applied, Vec::new());
        let no_op = CompletionAssessment::from_unmet(
            CompletionApplicationAssessment::VerifiedNoOp,
            Vec::new(),
        );
        assert_eq!(
            SprintState::Applying.complete(&applied),
            Ok(SprintState::Completed)
        );
        assert_eq!(
            SprintState::FinalVerification.complete(&no_op),
            Ok(SprintState::Completed)
        );
        assert!(matches!(
            SprintState::FinalVerification.complete(&applied),
            Err(StateTransitionError::InvalidSprint { .. })
        ));
        assert!(matches!(
            SprintState::Applying.complete(&no_op),
            Err(StateTransitionError::InvalidSprint { .. })
        ));
    }
}
