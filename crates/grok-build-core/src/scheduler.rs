//! Pure deterministic planning of worker leases.

use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fmt::{self, Display, Formatter};
use std::path::{Component, Path};

use serde::Serialize;

use crate::{
    AcceptanceKind, CurrentRepairActivationPermitV1, PathScope, SprintSpec, SprintSpecV2,
    TaskAttemptBudgetClassification, TaskAttemptHistory, TaskGraph, TaskGraphV2, TaskPurposeV2,
    TaskSpec, TaskState, WorkerLease,
};

const MAX_WORKER_POOL_SIZE: usize = 3;

/// Complete immutable input to one deterministic scheduling decision.
///
/// The caller owns persistence. This contract only validates current durable
/// state and computes lease proposals; it performs no state transition, I/O,
/// execution, or recovery action.
#[derive(Clone, Copy, Debug)]
pub struct SchedulerInput<'a> {
    /// Exact validated sprint contract that owns all tasks and leases.
    pub sprint: &'a SprintSpec,
    /// Exact validated graph whose vector order defines scheduling priority.
    pub graph: &'a TaskGraph,
    /// Complete durable state for every task in `graph`, with no extra tasks.
    pub task_states: &'a BTreeMap<String, TaskState>,
    /// Complete set of leases that remain active for this sprint.
    pub active_leases: &'a [WorkerLease],
    /// Active leases from other sprints on the same authenticated canonical
    /// workspace, supplied by durable workspace-scope readback.
    pub workspace_blocking_leases: &'a [WorkerLease],
    /// Worker identifiers currently available for assignment.
    pub available_worker_ids: &'a [String],
    /// First unused nonzero durable lease epoch.
    pub next_lease_epoch: u64,
    /// Durable acquisition time to copy into every proposed lease.
    pub acquired_at_unix_ms: u64,
}

/// Complete schema-v15 input to one deterministic attempt proposal pass.
///
/// Same-sprint active authority is derived exclusively from one ordered typed
/// [`TaskAttemptHistory`] per graph task. This deliberately accepts no loose
/// attempt, disposition, or active-lease vector.
#[derive(Clone, Copy, Debug)]
pub struct TaskAttemptSchedulerInput<'a> {
    /// Exact validated sprint contract that owns every history.
    pub sprint: &'a SprintSpec,
    /// Exact validated graph whose vector order defines scheduling priority.
    pub graph: &'a TaskGraph,
    /// Exactly one complete history per graph task, in graph vector order.
    pub task_histories: &'a [TaskAttemptHistory],
    /// Active leases from other sprints on the same authenticated workspace.
    pub workspace_blocking_leases: &'a [WorkerLease],
    /// Worker identifiers currently available for assignment.
    pub available_worker_ids: &'a [String],
    /// First unused nonzero durable lease epoch across all sprint attempts.
    pub next_lease_epoch: u64,
    /// Durable acquisition time to copy into every proposed lease.
    pub acquired_at_unix_ms: u64,
}

/// Complete inert schema-v32 input to one deterministic V2 lease plan.
///
/// This path is intentionally separate from the legacy V1 planners. A repair
/// task can appear in an executable state only when the input carries the
/// exact sealed permit loaded from its durable core-minted activation. This
/// function does not persist readiness, leases, attempts, or execution.
#[derive(Clone, Copy, Debug)]
pub struct CurrentV2SchedulerInput<'a> {
    /// Exact current sprint authority.
    pub sprint: &'a SprintSpecV2,
    /// Exact reciprocally bound current graph.
    pub graph: &'a TaskGraphV2,
    /// Complete current state for every task, with no extra task identities.
    pub task_states: &'a BTreeMap<String, TaskState>,
    /// Sealed permits loaded for currently live repair activations.
    pub repair_activation_permits: &'a [CurrentRepairActivationPermitV1],
    /// Complete active same-sprint leases.
    pub active_leases: &'a [WorkerLease],
    /// Active leases from other sprints on the same canonical workspace.
    pub workspace_blocking_leases: &'a [WorkerLease],
    /// Worker identities currently available for assignment.
    pub available_worker_ids: &'a [String],
    /// First unused positive durable lease epoch.
    pub next_lease_epoch: u64,
    /// Durable acquisition time to use for every proposal.
    pub acquired_at_unix_ms: u64,
}

/// Deterministic lease proposals and the epoch following the last proposal.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct SchedulePlan {
    /// New leases in exact graph scheduling order.
    pub leases: Vec<WorkerLease>,
    /// First unused epoch after all proposed leases are durably committed.
    pub next_lease_epoch: u64,
}

/// A fail-closed scheduler input or invariant error.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SchedulerError {
    field: &'static str,
    message: String,
}

impl SchedulerError {
    fn new(field: &'static str, message: impl Into<String>) -> Self {
        Self {
            field,
            message: message.into(),
        }
    }

    /// Returns the input or invariant field that failed validation.
    #[must_use]
    pub const fn field(&self) -> &'static str {
        self.field
    }

    /// Returns a human-readable explanation of the failed invariant.
    #[must_use]
    pub fn message(&self) -> &str {
        &self.message
    }
}

impl Display for SchedulerError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}: {}", self.field, self.message)
    }
}

impl Error for SchedulerError {}

/// Computes the next worker leases without mutating or persisting any state.
///
/// Ready tasks are considered only in exact graph vector order. A task is
/// eligible only when all dependencies are `Integrated`, and it is skipped
/// when its scopes conflict with an active or earlier proposed lease. Available
/// worker identifiers are assigned in lexical order so caller ordering cannot
/// alter the result.
///
/// # Errors
///
/// Returns [`SchedulerError`] when any contract, state-map, active-lease,
/// worker, capacity, scope-identity, or epoch invariant is inconsistent.
pub fn plan_worker_leases(input: SchedulerInput<'_>) -> Result<SchedulePlan, SchedulerError> {
    input
        .graph
        .validate_for_sprint(input.sprint)
        .map_err(|error| SchedulerError::new(error.field(), error.message()))?;
    validate_scalar_inputs(&input)?;
    validate_complete_task_states(&input)?;
    validate_dependency_state_consistency(&input)?;

    let active_tasks = validate_active_leases(&input)?;
    validate_workspace_blocking_leases(&input)?;
    let available_workers = validate_available_workers(&input)?;
    validate_task_lease_agreement(&input, &active_tasks)?;

    let remaining_capacity = usize::from(input.sprint.max_workers)
        .checked_sub(input.active_leases.len())
        .ok_or_else(|| {
            SchedulerError::new(
                "scheduler.active_leases",
                "active lease count exceeds the sprint worker ceiling",
            )
        })?;
    let capacity = remaining_capacity.min(available_workers.len());
    let mut leases = Vec::with_capacity(capacity);
    let mut epoch = input.next_lease_epoch;

    for task in &input.graph.tasks {
        if leases.len() == capacity {
            break;
        }
        if input.task_states.get(&task.task_id) != Some(&TaskState::Ready) {
            continue;
        }
        if conflicts_with_existing(task, input.active_leases, &leases)
            || conflicts_with_existing(task, input.workspace_blocking_leases, &[])
        {
            continue;
        }

        let worker_id = available_workers[leases.len()];
        let next_epoch = epoch.checked_add(1).ok_or_else(|| {
            SchedulerError::new(
                "scheduler.next_lease_epoch",
                "assigning a lease would overflow the durable epoch",
            )
        })?;
        let lease = WorkerLease::new(
            input.sprint.sprint_id.clone(),
            epoch,
            task.task_id.clone(),
            worker_id.to_owned(),
            task.path_scopes.clone(),
            input.acquired_at_unix_ms,
        )
        .map_err(|error| SchedulerError::new(error.field(), error.message()))?;
        leases.push(lease);
        epoch = next_epoch;
    }

    Ok(SchedulePlan {
        leases,
        next_lease_epoch: epoch,
    })
}

/// Computes schema-v15 worker-lease proposals from typed ordered histories.
///
/// The planner rejects terminal or unknown-terminalization-pending sprints,
/// ordinal gaps, over-budget history, impossible phase/active matrices,
/// legacy history that tries to re-enter `Ready`, and `Ready` at the attempt
/// limit. Persistence must repeat every check while atomically opening the
/// proposed [`crate::TaskAttempt`].
///
/// # Errors
///
/// Returns [`SchedulerError`] when any contract, history, budget, dependency,
/// worker, scope, capacity, or epoch invariant is inconsistent.
pub fn plan_task_attempts(
    input: TaskAttemptSchedulerInput<'_>,
) -> Result<SchedulePlan, SchedulerError> {
    input
        .graph
        .validate_for_sprint(input.sprint)
        .map_err(|error| SchedulerError::new(error.field(), error.message()))?;
    validate_attempt_scheduler_scalars(&input)?;
    let histories = validate_typed_histories(&input)?;
    validate_typed_dependencies(&input, &histories)?;
    let active_leases = typed_active_leases(&input);
    validate_typed_active_set(&input, &active_leases)?;
    validate_external_blockers(
        input.sprint,
        input.workspace_blocking_leases,
        "attempt_scheduler.workspace_blocking_leases",
    )?;
    let available_workers = validate_typed_available_workers(&input, &active_leases)?;

    let remaining_capacity = usize::from(input.sprint.max_workers)
        .checked_sub(active_leases.len())
        .ok_or_else(|| {
            SchedulerError::new(
                "attempt_scheduler.task_histories",
                "active attempt count exceeds the sprint worker ceiling",
            )
        })?;
    let capacity = remaining_capacity.min(available_workers.len());
    let mut leases = Vec::with_capacity(capacity);
    let mut epoch = input.next_lease_epoch;

    for (task, history) in input.graph.tasks.iter().zip(histories) {
        if leases.len() == capacity {
            break;
        }
        if history.task_state != TaskState::Ready {
            continue;
        }
        if history.attempts.len() >= usize::from(input.sprint.budget.max_attempts_per_task) {
            return Err(SchedulerError::new(
                "attempt_scheduler.task_histories",
                format!(
                    "Ready task `{}` is already at the immutable attempt limit",
                    task.task_id
                ),
            ));
        }
        if conflicts_with_existing(task, &active_leases, &leases)
            || conflicts_with_existing(task, input.workspace_blocking_leases, &[])
        {
            continue;
        }
        let worker_id = available_workers[leases.len()];
        let next_epoch = epoch.checked_add(1).ok_or_else(|| {
            SchedulerError::new(
                "attempt_scheduler.next_lease_epoch",
                "assigning an attempt would overflow the durable lease epoch",
            )
        })?;
        let lease = WorkerLease::new(
            input.sprint.sprint_id.clone(),
            epoch,
            task.task_id.clone(),
            worker_id.to_owned(),
            task.path_scopes.clone(),
            input.acquired_at_unix_ms,
        )
        .map_err(|error| SchedulerError::new(error.field(), error.message()))?;
        leases.push(lease);
        epoch = next_epoch;
    }

    Ok(SchedulePlan {
        leases,
        next_lease_epoch: epoch,
    })
}

/// Computes an inert current-V2 lease plan while enforcing repair dormancy.
///
/// Ordinary tasks remain governed by graph dependencies and scope conflicts.
/// A `FinalVerificationRepairSlot` in any execution-bearing state must have
/// its exact sealed activation permit, and only an activated `Ready` slot can
/// receive a proposed lease. Persistence must independently admit the repair
/// readiness, lease, and attempt under the same activation.
///
/// # Errors
///
/// Returns [`SchedulerError`] for an invalid V2 pair, incomplete or impossible
/// state, crossed/stale-shaped permit, active-lease mismatch, worker or epoch
/// violation, or any repair slot that has escaped dormancy without authority.
#[allow(clippy::too_many_lines)] // One fail-closed pass audits every current-only scheduling input before proposing authority-free leases.
pub fn plan_current_v2_worker_leases(
    input: CurrentV2SchedulerInput<'_>,
) -> Result<SchedulePlan, SchedulerError> {
    input
        .graph
        .validate_for_sprint(input.sprint)
        .map_err(|error| SchedulerError::new(error.field(), error.message()))?;
    if input.next_lease_epoch == 0 {
        return Err(SchedulerError::new(
            "current_v2_scheduler.next_lease_epoch",
            "must be greater than zero",
        ));
    }
    if input.acquired_at_unix_ms == 0 {
        return Err(SchedulerError::new(
            "current_v2_scheduler.acquired_at_unix_ms",
            "must be greater than zero",
        ));
    }
    if input.task_states.len() != input.graph.tasks.len()
        || input
            .graph
            .tasks
            .iter()
            .any(|task| !input.task_states.contains_key(&task.task_id))
        || input.task_states.keys().any(|task_id| {
            !input
                .graph
                .tasks
                .iter()
                .any(|task| task.task_id == *task_id)
        })
    {
        return Err(SchedulerError::new(
            "current_v2_scheduler.task_states",
            "must contain exactly one state for every bound V2 graph task",
        ));
    }

    let mut permits_by_task = BTreeMap::new();
    let mut permit_ids = BTreeSet::new();
    let mut permit_ordinals = BTreeSet::new();
    for permit in input.repair_activation_permits {
        permit
            .validate_for(input.sprint, input.graph)
            .map_err(|error| SchedulerError::new(error.field(), error.message()))?;
        if input.acquired_at_unix_ms < permit.activated_at_unix_ms() {
            return Err(SchedulerError::new(
                "current_v2_scheduler.repair_activation_permits",
                "lease planning time must not precede repair activation",
            ));
        }
        if !permit_ids.insert(permit.activation_id())
            || !permit_ordinals.insert(permit.slot_ordinal())
            || permits_by_task
                .insert(permit.repair_task_id(), permit)
                .is_some()
        {
            return Err(SchedulerError::new(
                "current_v2_scheduler.repair_activation_permits",
                "contains duplicate repair activation, task, or slot authority",
            ));
        }
    }

    for task in &input.graph.tasks {
        let state = input.task_states[&task.task_id];
        if let TaskPurposeV2::FinalVerificationRepairSlot { .. } = task.purpose {
            let execution_bearing = matches!(
                state,
                TaskState::Ready
                    | TaskState::Leased
                    | TaskState::Running
                    | TaskState::Verifying
                    | TaskState::Candidate
                    | TaskState::Integrated
            );
            if execution_bearing && !permits_by_task.contains_key(task.task_id.as_str()) {
                return Err(SchedulerError::new(
                    "current_v2_scheduler.repair_activation_permits",
                    format!(
                        "repair task `{}` escaped Planned dormancy without its exact activation permit",
                        task.task_id
                    ),
                ));
            }
        }
        if matches!(
            state,
            TaskState::Ready
                | TaskState::Leased
                | TaskState::Running
                | TaskState::Verifying
                | TaskState::Candidate
                | TaskState::Integrated
        ) {
            for dependency_id in &task.dependencies {
                if input.task_states.get(dependency_id) != Some(&TaskState::Integrated) {
                    return Err(SchedulerError::new(
                        "current_v2_scheduler.task_states",
                        format!(
                            "task `{}` state {state:?} has non-integrated dependency `{dependency_id}`",
                            task.task_id
                        ),
                    ));
                }
            }
        }
    }

    if input.active_leases.len() > usize::from(input.sprint.max_workers) {
        return Err(SchedulerError::new(
            "current_v2_scheduler.active_leases",
            "active lease count exceeds the current sprint worker ceiling",
        ));
    }
    let mut active_workers = BTreeSet::new();
    let mut active_tasks = BTreeSet::new();
    let mut active_epochs = BTreeSet::new();
    for (index, lease) in input.active_leases.iter().enumerate() {
        lease
            .validate()
            .map_err(|error| SchedulerError::new(error.field(), error.message()))?;
        if lease.sprint_id != input.sprint.sprint_id || lease.lease_epoch >= input.next_lease_epoch
        {
            return Err(SchedulerError::new(
                "current_v2_scheduler.active_leases",
                "active lease crosses sprint authority or the first-unused epoch",
            ));
        }
        let task = input
            .graph
            .tasks
            .iter()
            .find(|task| task.task_id == lease.task_id)
            .ok_or_else(|| {
                SchedulerError::new(
                    "current_v2_scheduler.active_leases",
                    "active lease names a task outside the bound V2 graph",
                )
            })?;
        if lease.path_scopes != task.path_scopes
            || !matches!(
                input.task_states[&task.task_id],
                TaskState::Leased
                    | TaskState::Running
                    | TaskState::Verifying
                    | TaskState::Candidate
                    | TaskState::Integrated
            )
            || !active_workers.insert(lease.worker_id.as_str())
            || !active_tasks.insert(lease.task_id.as_str())
            || !active_epochs.insert(lease.lease_epoch)
        {
            return Err(SchedulerError::new(
                "current_v2_scheduler.active_leases",
                "active lease does not exactly match task state, scope, worker, task, or epoch",
            ));
        }
        if matches!(
            task.purpose,
            TaskPurposeV2::FinalVerificationRepairSlot { .. }
        ) && !permits_by_task.contains_key(task.task_id.as_str())
        {
            return Err(SchedulerError::new(
                "current_v2_scheduler.repair_activation_permits",
                "active repair lease lacks its exact activation permit",
            ));
        }
        for prior in &input.active_leases[..index] {
            if scope_sets_conflict(&lease.path_scopes, &prior.path_scopes) {
                return Err(SchedulerError::new(
                    "current_v2_scheduler.active_leases",
                    "active leases contain conflicting path scopes",
                ));
            }
        }
    }
    for task in &input.graph.tasks {
        let active = active_tasks.contains(task.task_id.as_str());
        let state = input.task_states[&task.task_id];
        let active_agrees = match state {
            TaskState::Leased
            | TaskState::Running
            | TaskState::Verifying
            | TaskState::Candidate => active,
            // Integration precedes final cleanup/release, so either an active
            // cleanup-pending lease or a released lease is lawful.
            TaskState::Integrated => true,
            _ => !active,
        };
        if !active_agrees {
            return Err(SchedulerError::new(
                "current_v2_scheduler.active_leases",
                format!(
                    "task `{}` state and active-lease presence disagree",
                    task.task_id
                ),
            ));
        }
    }

    validate_external_blockers_v2(input.sprint, input.workspace_blocking_leases)?;
    if input.available_worker_ids.len() > MAX_WORKER_POOL_SIZE
        || input.active_leases.len() + input.available_worker_ids.len() > MAX_WORKER_POOL_SIZE
    {
        return Err(SchedulerError::new(
            "current_v2_scheduler.available_worker_ids",
            format!("worker pool must not exceed {MAX_WORKER_POOL_SIZE} identities"),
        ));
    }
    let mut available_workers = Vec::with_capacity(input.available_worker_ids.len());
    let mut available_set = BTreeSet::new();
    for worker_id in input.available_worker_ids {
        validate_worker_identifier("current_v2_scheduler.available_worker_ids", worker_id)?;
        if active_workers.contains(worker_id.as_str()) || !available_set.insert(worker_id.as_str())
        {
            return Err(SchedulerError::new(
                "current_v2_scheduler.available_worker_ids",
                "workers must be unique and disjoint from active leases",
            ));
        }
        available_workers.push(worker_id.as_str());
    }
    available_workers.sort_unstable();

    let capacity = usize::from(input.sprint.max_workers)
        .checked_sub(input.active_leases.len())
        .ok_or_else(|| {
            SchedulerError::new(
                "current_v2_scheduler.active_leases",
                "active lease count exceeds the worker ceiling",
            )
        })?
        .min(available_workers.len());
    let mut leases = Vec::with_capacity(capacity);
    let mut epoch = input.next_lease_epoch;
    for task in &input.graph.tasks {
        if leases.len() == capacity {
            break;
        }
        if input.task_states[&task.task_id] != TaskState::Ready {
            continue;
        }
        if matches!(
            task.purpose,
            TaskPurposeV2::FinalVerificationRepairSlot { .. }
        ) && !permits_by_task.contains_key(task.task_id.as_str())
        {
            continue;
        }
        if conflicts_with_existing_v2(task, input.active_leases, &leases)
            || conflicts_with_existing_v2(task, input.workspace_blocking_leases, &[])
        {
            continue;
        }
        let next_epoch = epoch.checked_add(1).ok_or_else(|| {
            SchedulerError::new(
                "current_v2_scheduler.next_lease_epoch",
                "assigning a lease would overflow the durable epoch",
            )
        })?;
        let lease = WorkerLease::new(
            input.sprint.sprint_id.clone(),
            epoch,
            task.task_id.clone(),
            available_workers[leases.len()].to_owned(),
            task.path_scopes.clone(),
            input.acquired_at_unix_ms,
        )
        .map_err(|error| SchedulerError::new(error.field(), error.message()))?;
        leases.push(lease);
        epoch = next_epoch;
    }
    Ok(SchedulePlan {
        leases,
        next_lease_epoch: epoch,
    })
}

fn validate_external_blockers_v2(
    sprint: &SprintSpecV2,
    blockers: &[WorkerLease],
) -> Result<(), SchedulerError> {
    let mut identities = BTreeSet::new();
    for lease in blockers {
        lease
            .validate()
            .map_err(|error| SchedulerError::new(error.field(), error.message()))?;
        if lease.sprint_id == sprint.sprint_id || !identities.insert(lease.lease_id.as_str()) {
            return Err(SchedulerError::new(
                "current_v2_scheduler.workspace_blocking_leases",
                "must contain unique leases from other sprints only",
            ));
        }
    }
    Ok(())
}

fn conflicts_with_existing_v2(
    task: &crate::TaskSpecV2,
    active: &[WorkerLease],
    proposed: &[WorkerLease],
) -> bool {
    active
        .iter()
        .chain(proposed)
        .any(|lease| scope_sets_conflict(&task.path_scopes, &lease.path_scopes))
}

fn validate_attempt_scheduler_scalars(
    input: &TaskAttemptSchedulerInput<'_>,
) -> Result<(), SchedulerError> {
    if input.next_lease_epoch == 0 {
        return Err(SchedulerError::new(
            "attempt_scheduler.next_lease_epoch",
            "must be greater than zero",
        ));
    }
    if input.acquired_at_unix_ms == 0 {
        return Err(SchedulerError::new(
            "attempt_scheduler.acquired_at_unix_ms",
            "must be greater than zero",
        ));
    }
    Ok(())
}

fn validate_typed_histories<'a>(
    input: &'a TaskAttemptSchedulerInput<'_>,
) -> Result<Vec<&'a TaskAttemptHistory>, SchedulerError> {
    if input.task_histories.len() != input.graph.tasks.len() {
        return Err(SchedulerError::new(
            "attempt_scheduler.task_histories",
            "must contain exactly one history per graph task",
        ));
    }
    let mut histories = Vec::with_capacity(input.task_histories.len());
    let mut common_sprint_state = None;
    let mut common_pending = None;
    for (task, history) in input.graph.tasks.iter().zip(input.task_histories) {
        validate_scheduler_formal_order(input.sprint, task, history)?;
        history
            .validate_for_task(input.sprint, task)
            .map_err(|error| SchedulerError::new(error.field(), error.message()))?;
        if history.budget_classification == TaskAttemptBudgetClassification::OverBudget {
            return Err(SchedulerError::new(
                "attempt_scheduler.task_histories",
                format!("task `{}` has immutable over-budget history", task.task_id),
            ));
        }
        if history
            .attempts
            .iter()
            .any(|entry| entry.legacy_classification.is_some())
        {
            return Err(SchedulerError::new(
                "attempt_scheduler.task_histories",
                format!(
                    "legacy-classified task `{}` requires recovery and cannot enter ordinary scheduling",
                    task.task_id
                ),
            ));
        }
        match common_sprint_state {
            None => common_sprint_state = Some(history.sprint_state),
            Some(state) if state == history.sprint_state => {}
            Some(_) => {
                return Err(SchedulerError::new(
                    "attempt_scheduler.task_histories",
                    "all task histories must carry one exact sprint state",
                ));
            }
        }
        match common_pending {
            None => common_pending = Some(&history.unknown_terminalization_pending),
            Some(marker) if marker == &history.unknown_terminalization_pending => {}
            Some(_) => {
                return Err(SchedulerError::new(
                    "attempt_scheduler.task_histories",
                    "all task histories must carry one exact pending marker",
                ));
            }
        }
        histories.push(history);
    }
    let sprint_state = common_sprint_state.ok_or_else(|| {
        SchedulerError::new(
            "attempt_scheduler.task_histories",
            "task graph must contain at least one typed history",
        )
    })?;
    if sprint_state.is_terminal() {
        return Err(SchedulerError::new(
            "attempt_scheduler.sprint_state",
            "terminal sprints cannot produce scheduler proposals",
        ));
    }
    let pending = common_pending.ok_or_else(|| {
        SchedulerError::new(
            "attempt_scheduler.task_histories",
            "task graph must contain at least one pending-marker projection",
        )
    })?;
    if let Some(marker) = pending {
        validate_pending_marker_resolution(marker, &histories)?;
        return Err(SchedulerError::new(
            "attempt_scheduler.unknown_terminalization_pending",
            "pending unknown terminalization freezes every scheduler proposal",
        ));
    }
    Ok(histories)
}

fn validate_scheduler_formal_order(
    sprint: &SprintSpec,
    task: &TaskSpec,
    history: &TaskAttemptHistory,
) -> Result<(), SchedulerError> {
    let referenced = task
        .acceptance_checks
        .iter()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    let declared = sprint
        .acceptance_criteria
        .iter()
        .filter(|criterion| referenced.contains(criterion.criterion_id.as_str()))
        .filter_map(|criterion| match &criterion.kind {
            AcceptanceKind::Automated(command) => Some((criterion.criterion_id.as_str(), command)),
            AcceptanceKind::HumanJudgment => None,
        })
        .collect::<Vec<_>>();
    let canonical = history.attempts.iter().all(|entry| {
        entry.formal_checks.iter().zip(&declared).enumerate().all(
            |(ordinal, (check, (criterion_id, command)))| {
                check.criterion_ordinal == u32::try_from(ordinal).unwrap_or(u32::MAX)
                    && check.criterion_id == *criterion_id
                    && check.verification_receipt.command == **command
            },
        )
    });
    if !canonical {
        return Err(SchedulerError::new(
            "attempt_scheduler.task_histories",
            format!(
                "task `{}` formal checks must follow SprintSpec-declared criterion order; migrated legacy order requires immutable ledger exemption authority",
                task.task_id
            ),
        ));
    }
    Ok(())
}

fn validate_typed_dependencies(
    input: &TaskAttemptSchedulerInput<'_>,
    histories: &[&TaskAttemptHistory],
) -> Result<(), SchedulerError> {
    let states = histories
        .iter()
        .map(|history| (history.task_id.as_str(), history.task_state))
        .collect::<BTreeMap<_, _>>();
    for task in &input.graph.tasks {
        let state = states[task.task_id.as_str()];
        if !matches!(
            state,
            TaskState::Ready
                | TaskState::Leased
                | TaskState::Running
                | TaskState::Verifying
                | TaskState::Candidate
                | TaskState::Integrated
        ) {
            continue;
        }
        for dependency_id in &task.dependencies {
            if states.get(dependency_id.as_str()) != Some(&TaskState::Integrated) {
                return Err(SchedulerError::new(
                    "attempt_scheduler.task_histories",
                    format!(
                        "task `{}` state {state:?} has non-integrated dependency `{dependency_id}`",
                        task.task_id
                    ),
                ));
            }
        }
    }
    Ok(())
}

fn typed_active_leases(input: &TaskAttemptSchedulerInput<'_>) -> Vec<WorkerLease> {
    let mut leases = Vec::new();
    for history in input.task_histories {
        if let Some(entry) = history.active_attempt() {
            leases.push(entry.attempt.worker_lease.clone());
        }
    }
    leases
}

fn validate_typed_active_set(
    input: &TaskAttemptSchedulerInput<'_>,
    active_leases: &[WorkerLease],
) -> Result<(), SchedulerError> {
    if active_leases.len() > usize::from(input.sprint.max_workers) {
        return Err(SchedulerError::new(
            "attempt_scheduler.task_histories",
            "active attempt count exceeds the sprint worker ceiling",
        ));
    }
    let mut workers = BTreeSet::new();
    let mut active_epochs = BTreeSet::new();
    for (index, lease) in active_leases.iter().enumerate() {
        if !workers.insert(lease.worker_id.as_str()) {
            return Err(SchedulerError::new(
                "attempt_scheduler.task_histories",
                format!(
                    "worker `{}` has more than one active attempt",
                    lease.worker_id
                ),
            ));
        }
        if !active_epochs.insert(lease.lease_epoch) {
            return Err(SchedulerError::new(
                "attempt_scheduler.task_histories",
                format!("active lease epoch {} is reused", lease.lease_epoch),
            ));
        }
        for previous in &active_leases[..index] {
            if scope_sets_conflict(&lease.path_scopes, &previous.path_scopes) {
                return Err(SchedulerError::new(
                    "attempt_scheduler.task_histories",
                    format!(
                        "active attempts `{}` and `{}` have conflicting scopes",
                        previous.lease_id, lease.lease_id
                    ),
                ));
            }
        }
    }
    let mut all_epochs = BTreeSet::new();
    for entry in input
        .task_histories
        .iter()
        .flat_map(|history| history.attempts.iter())
    {
        let epoch = entry.attempt.worker_lease.lease_epoch;
        if !all_epochs.insert(epoch) {
            return Err(SchedulerError::new(
                "attempt_scheduler.task_histories",
                format!("lease epoch {epoch} is reused across attempt histories"),
            ));
        }
        if epoch >= input.next_lease_epoch {
            return Err(SchedulerError::new(
                "attempt_scheduler.next_lease_epoch",
                format!(
                    "first unused epoch {} must exceed historical lease epoch {epoch}",
                    input.next_lease_epoch
                ),
            ));
        }
    }
    for (index, epoch) in all_epochs.iter().enumerate() {
        let expected = u64::try_from(index)
            .ok()
            .and_then(|value| value.checked_add(1))
            .ok_or_else(|| {
                SchedulerError::new(
                    "attempt_scheduler.task_histories",
                    "attempt count exceeds canonical u64 epoch range",
                )
            })?;
        if *epoch != expected {
            return Err(SchedulerError::new(
                "attempt_scheduler.task_histories",
                format!(
                    "lease epochs must be globally contiguous; expected {expected}, got {epoch}"
                ),
            ));
        }
    }
    let expected_next = u64::try_from(all_epochs.len())
        .ok()
        .and_then(|value| value.checked_add(1))
        .ok_or_else(|| {
            SchedulerError::new(
                "attempt_scheduler.next_lease_epoch",
                "attempt count exceeds canonical u64 epoch range",
            )
        })?;
    if input.next_lease_epoch != expected_next {
        return Err(SchedulerError::new(
            "attempt_scheduler.next_lease_epoch",
            format!(
                "must be the exact first-unused global epoch {expected_next}, got {}",
                input.next_lease_epoch
            ),
        ));
    }
    Ok(())
}

fn validate_pending_marker_resolution(
    marker: &crate::SprintUnknownTerminalizationPending,
    histories: &[&TaskAttemptHistory],
) -> Result<(), SchedulerError> {
    let resolves = histories
        .iter()
        .flat_map(|history| history.attempts.iter())
        .filter_map(|entry| entry.disposition.as_ref())
        .any(|disposition| {
            matches!(
                disposition,
                crate::TaskAttemptDisposition::UnknownCleaned(_)
                    | crate::TaskAttemptDisposition::UnknownQuarantined(_)
            ) && disposition.metadata().attempt.attempt_id == marker.first_attempt_id
                && disposition.metadata().disposition_id == marker.first_disposition_id
        });
    if !resolves {
        return Err(SchedulerError::new(
            "attempt_scheduler.unknown_terminalization_pending",
            "marker must resolve to its exact first unknown attempt and disposition",
        ));
    }
    Ok(())
}

fn validate_external_blockers(
    sprint: &SprintSpec,
    blockers: &[WorkerLease],
    field: &'static str,
) -> Result<(), SchedulerError> {
    let mut identities = BTreeSet::new();
    for lease in blockers {
        lease
            .validate()
            .map_err(|error| SchedulerError::new(error.field(), error.message()))?;
        if lease.sprint_id == sprint.sprint_id {
            return Err(SchedulerError::new(
                field,
                "same-sprint authority must come from typed task histories",
            ));
        }
        if !identities.insert(lease.lease_id.as_str()) {
            return Err(SchedulerError::new(
                field,
                "contains a duplicate external lease identity",
            ));
        }
    }
    Ok(())
}

fn validate_typed_available_workers<'a>(
    input: &'a TaskAttemptSchedulerInput<'_>,
    active_leases: &[WorkerLease],
) -> Result<Vec<&'a str>, SchedulerError> {
    if input.available_worker_ids.len() > MAX_WORKER_POOL_SIZE {
        return Err(SchedulerError::new(
            "attempt_scheduler.available_worker_ids",
            format!("worker pool must not exceed {MAX_WORKER_POOL_SIZE} available identities"),
        ));
    }
    if active_leases.len() + input.available_worker_ids.len() > MAX_WORKER_POOL_SIZE {
        return Err(SchedulerError::new(
            "attempt_scheduler.available_worker_ids",
            format!(
                "active and available worker pool must not exceed {MAX_WORKER_POOL_SIZE} identities"
            ),
        ));
    }
    let active_workers = active_leases
        .iter()
        .map(|lease| lease.worker_id.as_str())
        .collect::<BTreeSet<_>>();
    let mut unique = BTreeSet::new();
    let mut workers = Vec::with_capacity(input.available_worker_ids.len());
    for worker_id in input.available_worker_ids {
        validate_worker_identifier("attempt_scheduler.available_worker_ids", worker_id)?;
        if !unique.insert(worker_id.as_str()) {
            return Err(SchedulerError::new(
                "attempt_scheduler.available_worker_ids",
                format!("duplicate worker id `{worker_id}`"),
            ));
        }
        if active_workers.contains(worker_id.as_str()) {
            return Err(SchedulerError::new(
                "attempt_scheduler.available_worker_ids",
                format!("active worker `{worker_id}` cannot also be available"),
            ));
        }
        workers.push(worker_id.as_str());
    }
    workers.sort_unstable();
    Ok(workers)
}

/// Returns whether two path scopes must be treated as mutually exclusive.
///
/// Workspace scope conflicts with every scope. Relative scopes conflict when
/// either path is the other path or an ancestor of it under ASCII
/// case-insensitive component comparison. Invalid, non-UTF-8, or non-ASCII
/// relative paths conservatively conflict instead of being treated as
/// disjoint.
#[must_use]
pub fn path_scopes_conflict(left: &PathScope, right: &PathScope) -> bool {
    match (left, right) {
        (PathScope::Workspace, _) | (_, PathScope::Workspace) => true,
        (PathScope::Relative(left), PathScope::Relative(right)) => {
            relative_paths_conflict(left, right)
        }
    }
}

fn validate_scalar_inputs(input: &SchedulerInput<'_>) -> Result<(), SchedulerError> {
    if input.next_lease_epoch == 0 {
        return Err(SchedulerError::new(
            "scheduler.next_lease_epoch",
            "must be greater than zero",
        ));
    }
    if input.acquired_at_unix_ms == 0 {
        return Err(SchedulerError::new(
            "scheduler.acquired_at_unix_ms",
            "must be greater than zero",
        ));
    }
    if input.active_leases.len() > usize::from(input.sprint.max_workers) {
        return Err(SchedulerError::new(
            "scheduler.active_leases",
            "active lease count exceeds the sprint worker ceiling",
        ));
    }
    Ok(())
}

fn validate_complete_task_states(input: &SchedulerInput<'_>) -> Result<(), SchedulerError> {
    for task in &input.graph.tasks {
        if !input.task_states.contains_key(&task.task_id) {
            return Err(SchedulerError::new(
                "scheduler.task_states",
                format!("missing state for task `{}`", task.task_id),
            ));
        }
    }
    for task_id in input.task_states.keys() {
        if input.graph.task(task_id).is_none() {
            return Err(SchedulerError::new(
                "scheduler.task_states",
                format!("contains state for unknown task `{task_id}`"),
            ));
        }
    }
    Ok(())
}

fn validate_dependency_state_consistency(input: &SchedulerInput<'_>) -> Result<(), SchedulerError> {
    for task in &input.graph.tasks {
        let state = input.task_states[&task.task_id];
        if !matches!(
            state,
            TaskState::Ready
                | TaskState::Leased
                | TaskState::Running
                | TaskState::Verifying
                | TaskState::Candidate
                | TaskState::Integrated
        ) {
            continue;
        }
        for dependency_id in &task.dependencies {
            if input.task_states.get(dependency_id) != Some(&TaskState::Integrated) {
                return Err(SchedulerError::new(
                    "scheduler.task_states",
                    format!(
                        "task `{}` state {state:?} has non-integrated dependency `{dependency_id}`",
                        task.task_id,
                    ),
                ));
            }
        }
    }
    Ok(())
}

fn validate_active_leases<'a>(
    input: &'a SchedulerInput<'_>,
) -> Result<BTreeSet<&'a str>, SchedulerError> {
    let mut lease_ids = BTreeSet::new();
    let mut task_ids = BTreeSet::new();
    let mut worker_ids = BTreeSet::new();
    let mut epochs = BTreeSet::new();

    for (lease_index, lease) in input.active_leases.iter().enumerate() {
        lease
            .validate()
            .map_err(|error| SchedulerError::new(error.field(), error.message()))?;
        validate_worker_identifier("scheduler.active_leases", &lease.worker_id)?;
        if lease.sprint_id != input.sprint.sprint_id {
            return Err(SchedulerError::new(
                "scheduler.active_leases",
                format!("lease `{}` belongs to another sprint", lease.lease_id),
            ));
        }
        if lease.lease_epoch >= input.next_lease_epoch {
            return Err(SchedulerError::new(
                "scheduler.next_lease_epoch",
                format!(
                    "first unused epoch {} must exceed active lease epoch {}",
                    input.next_lease_epoch, lease.lease_epoch
                ),
            ));
        }
        let Some(task) = input.graph.task(&lease.task_id) else {
            return Err(SchedulerError::new(
                "scheduler.active_leases",
                format!("lease `{}` names an unknown task", lease.lease_id),
            ));
        };
        if lease.path_scopes != task.path_scopes {
            return Err(SchedulerError::new(
                "scheduler.active_leases",
                format!(
                    "lease `{}` scopes do not exactly match task `{}`",
                    lease.lease_id, task.task_id
                ),
            ));
        }
        if !lease_ids.insert(lease.lease_id.as_str()) {
            return Err(SchedulerError::new(
                "scheduler.active_leases",
                format!("duplicate lease id `{}`", lease.lease_id),
            ));
        }
        if !task_ids.insert(lease.task_id.as_str()) {
            return Err(SchedulerError::new(
                "scheduler.active_leases",
                format!("task `{}` has more than one active lease", lease.task_id),
            ));
        }
        if !worker_ids.insert(lease.worker_id.as_str()) {
            return Err(SchedulerError::new(
                "scheduler.active_leases",
                format!(
                    "worker `{}` has more than one active lease",
                    lease.worker_id
                ),
            ));
        }
        if !epochs.insert(lease.lease_epoch) {
            return Err(SchedulerError::new(
                "scheduler.active_leases",
                format!("lease epoch {} is reused", lease.lease_epoch),
            ));
        }
        for previous in &input.active_leases[..lease_index] {
            if scope_sets_conflict(&lease.path_scopes, &previous.path_scopes) {
                return Err(SchedulerError::new(
                    "scheduler.active_leases",
                    format!(
                        "active leases `{}` and `{}` have conflicting scopes",
                        previous.lease_id, lease.lease_id
                    ),
                ));
            }
        }
    }
    Ok(task_ids)
}

fn validate_workspace_blocking_leases(input: &SchedulerInput<'_>) -> Result<(), SchedulerError> {
    let mut identities = BTreeSet::new();
    for lease in input.workspace_blocking_leases {
        lease
            .validate()
            .map_err(|error| SchedulerError::new(error.field(), error.message()))?;
        if lease.sprint_id == input.sprint.sprint_id {
            return Err(SchedulerError::new(
                "scheduler.workspace_blocking_leases",
                "same-sprint leases belong in active_leases",
            ));
        }
        if !identities.insert(lease.lease_id.as_str()) {
            return Err(SchedulerError::new(
                "scheduler.workspace_blocking_leases",
                "contains a duplicate external lease identity",
            ));
        }
    }
    Ok(())
}

fn validate_available_workers<'a>(
    input: &'a SchedulerInput<'_>,
) -> Result<Vec<&'a str>, SchedulerError> {
    if input.available_worker_ids.len() > MAX_WORKER_POOL_SIZE {
        return Err(SchedulerError::new(
            "scheduler.available_worker_ids",
            format!("worker pool must not exceed {MAX_WORKER_POOL_SIZE} available identities"),
        ));
    }
    let total_worker_slots = input
        .active_leases
        .len()
        .checked_add(input.available_worker_ids.len())
        .ok_or_else(|| {
            SchedulerError::new(
                "scheduler.available_worker_ids",
                "active and available worker count overflowed",
            )
        })?;
    if total_worker_slots > MAX_WORKER_POOL_SIZE {
        return Err(SchedulerError::new(
            "scheduler.available_worker_ids",
            format!(
                "active and available worker pool must not exceed {MAX_WORKER_POOL_SIZE} identities"
            ),
        ));
    }
    let active_workers: BTreeSet<&str> = input
        .active_leases
        .iter()
        .map(|lease| lease.worker_id.as_str())
        .collect();
    let mut available_workers = Vec::with_capacity(input.available_worker_ids.len());
    let mut unique = BTreeSet::new();
    for worker_id in input.available_worker_ids {
        validate_worker_identifier("scheduler.available_worker_ids", worker_id)?;
        if !unique.insert(worker_id.as_str()) {
            return Err(SchedulerError::new(
                "scheduler.available_worker_ids",
                format!("duplicate worker id `{worker_id}`"),
            ));
        }
        if active_workers.contains(worker_id.as_str()) {
            return Err(SchedulerError::new(
                "scheduler.available_worker_ids",
                format!("active worker `{worker_id}` cannot also be available"),
            ));
        }
        available_workers.push(worker_id.as_str());
    }
    available_workers.sort_unstable();
    Ok(available_workers)
}

fn validate_worker_identifier(field: &'static str, worker_id: &str) -> Result<(), SchedulerError> {
    WorkerLease::validate_worker_id(worker_id)
        .map_err(|error| SchedulerError::new(field, error.message()))
}

fn validate_task_lease_agreement(
    input: &SchedulerInput<'_>,
    active_tasks: &BTreeSet<&str>,
) -> Result<(), SchedulerError> {
    for task in &input.graph.tasks {
        let state = input.task_states[&task.task_id];
        let has_active_lease = active_tasks.contains(task.task_id.as_str());
        let lease_agrees = match state {
            TaskState::Leased
            | TaskState::Running
            | TaskState::Verifying
            | TaskState::Candidate => has_active_lease,
            // Integration is durable before native cleanup/release. Both the
            // crash-recovered cleanup-pending state and the released state are
            // valid; an active lease continues consuming capacity and scopes.
            TaskState::Integrated => true,
            _ => !has_active_lease,
        };
        if !lease_agrees {
            return Err(SchedulerError::new(
                "scheduler.task_states",
                format!(
                    "task `{}` state {state:?} and active lease presence disagree",
                    task.task_id
                ),
            ));
        }
    }
    Ok(())
}

fn conflicts_with_existing(
    task: &TaskSpec,
    active_leases: &[WorkerLease],
    proposed_leases: &[WorkerLease],
) -> bool {
    active_leases
        .iter()
        .chain(proposed_leases)
        .any(|lease| scope_sets_conflict(&task.path_scopes, &lease.path_scopes))
}

fn scope_sets_conflict(left: &[PathScope], right: &[PathScope]) -> bool {
    left.iter().any(|left_scope| {
        right
            .iter()
            .any(|right_scope| path_scopes_conflict(left_scope, right_scope))
    })
}

fn relative_paths_conflict(left: &Path, right: &Path) -> bool {
    let Some(left_components) = normalized_utf8_components(left) else {
        return true;
    };
    let Some(right_components) = normalized_utf8_components(right) else {
        return true;
    };
    let shared_length = left_components.len().min(right_components.len());
    left_components[..shared_length]
        .iter()
        .zip(&right_components[..shared_length])
        .all(|(left, right)| left.eq_ignore_ascii_case(right))
}

fn normalized_utf8_components(path: &Path) -> Option<Vec<&str>> {
    let components = path
        .components()
        .map(|component| match component {
            Component::Normal(value) => value.to_str().filter(|value| value.is_ascii()),
            _ => None,
        })
        .collect::<Option<Vec<_>>>()?;
    (!components.is_empty()).then_some(components)
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::*;
    use crate::{
        AcceptanceCriterion, AcceptanceKind, CONTRACT_VERSION,
        CurrentFinalVerificationRepairActivationV1, CurrentSprintAuthorityV32, Digest,
        ExecutionOrigin, MAX_WORKER_ID_BYTES, ProviderProfile,
        SPRINT_AUTHORITY_CONTRACT_VERSION_V2, SprintBudget, SprintBudgetV2, TaskSpec, TaskSpecV2,
        WorkspaceGrant, WorkspaceNetworkPolicy, WorkspacePermissions, transition_current_v2_task,
    };

    const ACQUIRED_AT: u64 = 1_750_000_000_000;

    fn digest(character: char) -> Digest {
        Digest::parse(character.to_string().repeat(64)).expect("valid digest")
    }

    fn sprint(max_workers: u8) -> SprintSpec {
        SprintSpec {
            sprint_id: "sprint-1".into(),
            objective: "finish the deterministic graph".into(),
            acceptance_criteria: vec![AcceptanceCriterion {
                criterion_id: "criterion-1".into(),
                description: "all planned work is integrated".into(),
                kind: AcceptanceKind::HumanJudgment,
            }],
            provider: ProviderProfile {
                backend_id: "fake".into(),
                model_id: "deterministic".into(),
                execution_origin: ExecutionOrigin::ReadOnly,
            },
            budget: SprintBudget {
                max_tasks: 16,
                max_attempts_per_task: 2,
                max_tool_calls: 32,
                max_duration_ms: 60_000,
            },
            max_workers,
            workspace_grant: WorkspaceGrant {
                grant_id: "grant-1".into(),
                canonical_root: std::env::temp_dir().join("grok-build-scheduler-tests"),
                permissions: WorkspacePermissions::trusted(),
                network: WorkspaceNetworkPolicy::Denied,
                policy_version: 1,
                grant_hash: digest('b'),
            },
            base_snapshot: digest('a'),
        }
    }

    fn task(task_id: &str, dependencies: &[&str], path: &str) -> TaskSpec {
        TaskSpec {
            task_id: task_id.into(),
            goal: format!("complete {task_id}"),
            dependencies: dependencies
                .iter()
                .map(|dependency| (*dependency).to_owned())
                .collect(),
            path_scopes: vec![PathScope::Relative(PathBuf::from(path))],
            acceptance_checks: vec!["criterion-1".into()],
            base_snapshot: digest('a'),
            required: true,
        }
    }

    fn graph(tasks: Vec<TaskSpec>) -> TaskGraph {
        TaskGraph {
            graph_id: "graph-1".into(),
            tasks,
        }
    }

    fn current_pair(sprint_id: &str) -> (SprintSpecV2, TaskGraphV2) {
        let graph_id = format!("graph-{sprint_id}");
        let mut graph = TaskGraphV2 {
            sprint_authority_version: SPRINT_AUTHORITY_CONTRACT_VERSION_V2,
            graph_id: graph_id.clone(),
            sprint_id: sprint_id.into(),
            sprint_spec_digest: digest('0'),
            repair_slot_reserve_digest: digest('0'),
            tasks: vec![
                TaskSpecV2 {
                    sprint_authority_version: SPRINT_AUTHORITY_CONTRACT_VERSION_V2,
                    task_id: "ordinary".into(),
                    purpose: TaskPurposeV2::Ordinary,
                    goal: "complete ordinary work".into(),
                    dependencies: Vec::new(),
                    path_scopes: vec![PathScope::Relative(PathBuf::from("src/ordinary"))],
                    acceptance_checks: vec!["criterion-1".into()],
                    base_snapshot: digest('a'),
                    required: true,
                },
                TaskSpecV2 {
                    sprint_authority_version: SPRINT_AUTHORITY_CONTRACT_VERSION_V2,
                    task_id: "repair-1".into(),
                    purpose: TaskPurposeV2::FinalVerificationRepairSlot { slot_ordinal: 1 },
                    goal: "repair the first final-verification failure".into(),
                    dependencies: vec!["ordinary".into()],
                    path_scopes: vec![PathScope::Relative(PathBuf::from("src/repair"))],
                    acceptance_checks: vec!["criterion-1".into()],
                    base_snapshot: digest('a'),
                    required: false,
                },
            ],
        };
        graph.repair_slot_reserve_digest = graph
            .computed_repair_slot_reserve_digest()
            .expect("repair reserve digest");
        let mut sprint = SprintSpecV2 {
            sprint_authority_version: SPRINT_AUTHORITY_CONTRACT_VERSION_V2,
            sprint_id: sprint_id.into(),
            objective: "exercise current repair dormancy".into(),
            acceptance_criteria: vec![AcceptanceCriterion {
                criterion_id: "criterion-1".into(),
                description: "exact result is accepted".into(),
                kind: AcceptanceKind::HumanJudgment,
            }],
            provider: ProviderProfile {
                backend_id: "fake".into(),
                model_id: "deterministic".into(),
                execution_origin: ExecutionOrigin::ReadOnly,
            },
            budget: SprintBudgetV2 {
                sprint_authority_version: SPRINT_AUTHORITY_CONTRACT_VERSION_V2,
                max_tasks: 2,
                max_attempts_per_task: 2,
                max_final_verification_attempts: 2,
                max_tool_calls: 32,
                max_duration_ms: 60_000,
            },
            max_workers: 1,
            workspace_grant: WorkspaceGrant {
                grant_id: format!("grant-{sprint_id}"),
                canonical_root: std::env::temp_dir().join("grok-build-current-v2-scheduler"),
                permissions: WorkspacePermissions::trusted(),
                network: WorkspaceNetworkPolicy::Denied,
                policy_version: 1,
                grant_hash: digest('b'),
            },
            base_snapshot: digest('a'),
            task_graph_id: graph_id,
            task_graph_payload_digest: graph.payload_digest().expect("graph payload"),
            repair_slot_reserve_digest: graph.repair_slot_reserve_digest.clone(),
        };
        graph.sprint_spec_digest = sprint.canonical_digest().expect("sprint digest");
        sprint.task_graph_payload_digest = graph.payload_digest().expect("stable graph payload");
        graph
            .validate_for_sprint(&sprint)
            .expect("valid current V2 pair");
        (sprint, graph)
    }

    fn current_permit(
        sprint: &SprintSpecV2,
        graph: &TaskGraphV2,
    ) -> CurrentRepairActivationPermitV1 {
        CurrentRepairActivationPermitV1::from_test_activation(
            CurrentFinalVerificationRepairActivationV1 {
                activation_version: 1,
                activation_id: "activation-current-v2".into(),
                sprint_id: sprint.sprint_id.clone(),
                failed_attempt_id: "failed-verifier-attempt".into(),
                failure_outcome_id: "failed-verifier-outcome".into(),
                failed_snapshot: digest('c'),
                slot_ordinal: 1,
                repair_task_id: "repair-1".into(),
                activated_at_unix_ms: ACQUIRED_AT - 1,
            },
            &CurrentSprintAuthorityV32 {
                spec: sprint.clone(),
                graph: graph.clone(),
                created_at_unix_ms: 1,
            },
        )
        .expect("sealed test permit")
    }

    fn current_schedule(
        sprint: &SprintSpecV2,
        graph: &TaskGraphV2,
        task_states: &BTreeMap<String, TaskState>,
        permits: &[CurrentRepairActivationPermitV1],
        active_leases: &[WorkerLease],
        available_worker_ids: &[String],
        next_lease_epoch: u64,
    ) -> Result<SchedulePlan, SchedulerError> {
        plan_current_v2_worker_leases(CurrentV2SchedulerInput {
            sprint,
            graph,
            task_states,
            repair_activation_permits: permits,
            active_leases,
            workspace_blocking_leases: &[],
            available_worker_ids,
            next_lease_epoch,
            acquired_at_unix_ms: ACQUIRED_AT,
        })
    }

    fn states(values: &[(&str, TaskState)]) -> BTreeMap<String, TaskState> {
        values
            .iter()
            .map(|(task_id, state)| ((*task_id).to_owned(), *state))
            .collect()
    }

    fn workers(values: &[&str]) -> Vec<String> {
        values.iter().map(|value| (*value).to_owned()).collect()
    }

    fn active_lease(
        sprint_id: &str,
        task: &TaskSpec,
        worker_id: &str,
        lease_epoch: u64,
    ) -> WorkerLease {
        WorkerLease::new(
            sprint_id.into(),
            lease_epoch,
            task.task_id.clone(),
            worker_id.into(),
            task.path_scopes.clone(),
            ACQUIRED_AT,
        )
        .expect("test lease identity")
    }

    fn schedule(
        sprint: &SprintSpec,
        graph: &TaskGraph,
        task_states: &BTreeMap<String, TaskState>,
        active_leases: &[WorkerLease],
        available_worker_ids: &[String],
        next_lease_epoch: u64,
    ) -> Result<SchedulePlan, SchedulerError> {
        plan_worker_leases(SchedulerInput {
            sprint,
            graph,
            task_states,
            active_leases,
            workspace_blocking_leases: &[],
            available_worker_ids,
            next_lease_epoch,
            acquired_at_unix_ms: ACQUIRED_AT,
        })
    }

    fn typed_schedule(
        sprint: &SprintSpec,
        graph: &TaskGraph,
        task_histories: &[TaskAttemptHistory],
        available_worker_ids: &[String],
        next_lease_epoch: u64,
    ) -> Result<SchedulePlan, SchedulerError> {
        plan_task_attempts(TaskAttemptSchedulerInput {
            sprint,
            graph,
            task_histories,
            workspace_blocking_leases: &[],
            available_worker_ids,
            next_lease_epoch,
            acquired_at_unix_ms: ACQUIRED_AT,
        })
    }

    fn empty_attempt_history(task: &TaskSpec, task_state: TaskState) -> TaskAttemptHistory {
        TaskAttemptHistory {
            contract_version: CONTRACT_VERSION,
            sprint_id: "sprint-1".into(),
            task_id: task.task_id.clone(),
            task_state,
            sprint_state: crate::SprintState::Running,
            attempts: Vec::new(),
            budget_classification: TaskAttemptBudgetClassification::WithinBudget,
            unknown_terminalization_pending: None,
        }
    }

    fn typed_attempt(
        task: &TaskSpec,
        ordinal: u32,
        epoch: u64,
        worker_id: &str,
    ) -> crate::TaskAttempt {
        crate::TaskAttempt::new(
            active_lease("sprint-1", task, worker_id, epoch),
            ordinal,
            format!("opening-{epoch}"),
        )
        .expect("attempt")
    }

    fn running_boundary(attempt: &crate::TaskAttempt) -> crate::TaskAttemptRunningBoundary {
        crate::TaskAttemptRunningBoundary {
            contract_version: CONTRACT_VERSION,
            boundary_id: format!("running-boundary-{}", attempt.worker_lease.lease_epoch),
            attempt: attempt.clone(),
            runner_launch_id: "launch-1".into(),
            runner_session_id: "session-1".into(),
            transition_event_id: format!("to-running-{}", attempt.worker_lease.lease_epoch),
            started_at_unix_ms: ACQUIRED_AT + 1,
        }
    }

    fn open_attempt_entry(
        attempt: crate::TaskAttempt,
        is_running: bool,
    ) -> crate::TaskAttemptHistoryEntry {
        let running_boundary = is_running.then(|| running_boundary(&attempt));
        crate::TaskAttemptHistoryEntry {
            attempt,
            running_boundary,
            verification_boundary: None,
            formal_checks: Vec::new(),
            candidate_boundary: None,
            disposition: None,
            legacy_classification: None,
            lease_state: crate::TaskAttemptLeaseState::Active,
        }
    }

    fn legacy_attempt_entry(
        task: &TaskSpec,
        ordinal: u32,
        epoch: u64,
        classification: crate::LegacyTaskAttemptClassification,
        active: bool,
    ) -> crate::TaskAttemptHistoryEntry {
        let attempt = typed_attempt(task, ordinal, epoch, &format!("worker-{epoch}"));
        crate::TaskAttemptHistoryEntry {
            lease_state: if active {
                crate::TaskAttemptLeaseState::Active
            } else {
                crate::TaskAttemptLeaseState::Released {
                    release_id: format!("legacy-release-{epoch}"),
                    released_at_unix_ms: ACQUIRED_AT + 1,
                }
            },
            attempt,
            running_boundary: None,
            verification_boundary: None,
            formal_checks: Vec::new(),
            candidate_boundary: None,
            disposition: None,
            legacy_classification: Some(classification),
        }
    }

    fn retained_evidence(
        kind: crate::TaskAttemptEvidenceKind,
        identity: &str,
    ) -> crate::TaskAttemptEvidence {
        crate::TaskAttemptEvidence::new(identity.into(), kind, identity.as_bytes().to_vec())
            .expect("evidence")
    }

    fn verification_boundary(
        attempt: &crate::TaskAttempt,
        snapshot: Digest,
    ) -> crate::TaskAttemptVerificationBoundary {
        crate::TaskAttemptVerificationBoundary {
            contract_version: CONTRACT_VERSION,
            boundary_id: format!("verification-boundary-{}", attempt.attempt_ordinal),
            attempt: attempt.clone(),
            runner_launch_id: "launch-1".into(),
            runner_session_id: "session-1".into(),
            change_set_id: "changes-1".into(),
            sealed_snapshot: snapshot,
            transition_event_id: "to-verifying-1".into(),
            terminal_non_cleanup_effects: Vec::new(),
            sealed_at_unix_ms: ACQUIRED_AT + 1,
        }
    }

    fn formal_check(
        attempt: &crate::TaskAttempt,
        ordinal: u32,
        criterion: &AcceptanceCriterion,
        snapshot: Digest,
        receipt_id: &str,
    ) -> crate::TaskAttemptFormalCheck {
        let AcceptanceKind::Automated(command) = &criterion.kind else {
            panic!("automated criterion required");
        };
        crate::TaskAttemptFormalCheck {
            contract_version: CONTRACT_VERSION,
            formal_check_id: format!("formal-{receipt_id}"),
            attempt: attempt.clone(),
            criterion_ordinal: ordinal,
            criterion_id: criterion.criterion_id.clone(),
            effect_id: format!("effect-{receipt_id}"),
            observation_id: format!("observation-{receipt_id}"),
            verification_receipt: crate::VerificationReceipt {
                receipt_id: receipt_id.into(),
                sprint_id: "sprint-1".into(),
                task_id: Some(attempt.worker_lease.task_id.clone()),
                snapshot_id: snapshot.clone(),
                command: command.clone(),
                policy_hash: digest('d'),
                exit_status: Some(0),
                termination: Some(crate::CommandTerminationV1::Exited { code: 0 }),
                output_digest: digest('e'),
                duration_ms: 1,
                finished_at_unix_ms: ACQUIRED_AT + 2,
            },
            runner_session_id: "session-1".into(),
            sealed_snapshot: snapshot,
        }
    }

    fn candidate_boundary(
        attempt: &crate::TaskAttempt,
        verification: &crate::TaskAttemptVerificationBoundary,
        checks: &[crate::TaskAttemptFormalCheck],
    ) -> crate::TaskAttemptCandidateBoundary {
        crate::TaskAttemptCandidateBoundary {
            contract_version: CONTRACT_VERSION,
            boundary_id: "candidate-1".into(),
            attempt: attempt.clone(),
            verification_boundary_id: verification.boundary_id.clone(),
            change_set_id: verification.change_set_id.clone(),
            sealed_snapshot: verification.sealed_snapshot.clone(),
            formal_check_ids: checks
                .iter()
                .map(|check| check.formal_check_id.clone())
                .collect(),
            verification_receipt_ids: checks
                .iter()
                .map(|check| check.verification_receipt.receipt_id.clone())
                .collect(),
            transition_event_id: "to-candidate-1".into(),
            admitted_at_unix_ms: ACQUIRED_AT + 3,
        }
    }

    #[test]
    fn typed_history_scheduler_proposes_from_zero_attempt_ready_history() {
        let sprint = sprint(1);
        let task = task("task-1", &[], "src");
        let graph = graph(vec![task.clone()]);
        let histories = vec![empty_attempt_history(&task, TaskState::Ready)];
        let plan = typed_schedule(&sprint, &graph, &histories, &workers(&["worker-1"]), 1)
            .expect("typed proposal");
        assert_eq!(plan.leases.len(), 1);
        assert_eq!(plan.leases[0].task_id, "task-1");
        assert_eq!(plan.leases[0].lease_epoch, 1);
        assert_eq!(plan.next_lease_epoch, 2);
    }

    #[test]
    fn typed_scheduler_derives_active_authority_only_from_attempt_histories() {
        let sprint = sprint(2);
        let running = task("running", &[], "src/running");
        let ready = task("ready", &[], "src/ready");
        let graph = graph(vec![running.clone(), ready.clone()]);
        let mut running_history = empty_attempt_history(&running, TaskState::Running);
        running_history.attempts.push(open_attempt_entry(
            typed_attempt(&running, 1, 1, "worker-1"),
            true,
        ));
        let ready_history = empty_attempt_history(&ready, TaskState::Ready);
        let plan = typed_schedule(
            &sprint,
            &graph,
            &[running_history.clone(), ready_history.clone()],
            &workers(&["worker-2"]),
            2,
        )
        .expect("disjoint active attempt");
        assert_eq!(plan.leases.len(), 1);
        assert_eq!(plan.leases[0].task_id, "ready");

        running_history.attempts[0].lease_state = crate::TaskAttemptLeaseState::Released {
            release_id: "forged-release".into(),
            released_at_unix_ms: ACQUIRED_AT + 1,
        };
        assert!(
            typed_schedule(
                &sprint,
                &graph,
                &[running_history, ready_history],
                &workers(&["worker-2"]),
                2,
            )
            .expect_err("Running without active attempt")
            .message()
            .contains("active undisposed")
        );
    }

    #[test]
    fn typed_scheduler_rejects_ordinal_budget_legacy_and_exact_epoch_gaps() {
        let mut sprint = sprint(1);
        let task = task("task-1", &[], "src");
        let graph = graph(vec![task.clone()]);

        let mut ordinal_gap = empty_attempt_history(&task, TaskState::Leased);
        ordinal_gap.attempts.push(open_attempt_entry(
            typed_attempt(&task, 2, 1, "worker-1"),
            false,
        ));
        assert!(
            typed_schedule(&sprint, &graph, &[ordinal_gap], &[], 2)
                .expect_err("ordinal gap")
                .message()
                .contains("contiguous")
        );

        let empty = empty_attempt_history(&task, TaskState::Ready);
        assert!(
            typed_schedule(
                &sprint,
                &graph,
                std::slice::from_ref(&empty),
                &workers(&["worker-1"]),
                2,
            )
            .expect_err("next epoch must be exact")
            .message()
            .contains("exact first-unused")
        );

        let mut terminal = empty.clone();
        terminal.sprint_state = crate::SprintState::Failed;
        assert!(
            typed_schedule(&sprint, &graph, &[terminal], &workers(&["worker-1"]), 1,)
                .expect_err("terminal sprint")
                .message()
                .contains("terminal sprints")
        );

        let mut legacy_ready = empty_attempt_history(&task, TaskState::Ready);
        legacy_ready.attempts.push(legacy_attempt_entry(
            &task,
            1,
            1,
            crate::LegacyTaskAttemptClassification::LegacyReleased,
            false,
        ));
        assert!(
            typed_schedule(&sprint, &graph, &[legacy_ready], &workers(&["worker-1"]), 2,)
                .expect_err("legacy Ready is not retry authority")
                .message()
                .contains("legacy-classified")
        );

        sprint.budget.max_attempts_per_task = 1;
        let mut over_budget = empty_attempt_history(&task, TaskState::Ready);
        over_budget.attempts = vec![
            legacy_attempt_entry(
                &task,
                1,
                1,
                crate::LegacyTaskAttemptClassification::LegacyReleased,
                false,
            ),
            legacy_attempt_entry(
                &task,
                2,
                2,
                crate::LegacyTaskAttemptClassification::LegacyReleased,
                false,
            ),
        ];
        over_budget.budget_classification = TaskAttemptBudgetClassification::OverBudget;
        assert!(
            typed_schedule(&sprint, &graph, &[over_budget], &[], 3)
                .expect_err("over-budget history")
                .message()
                .contains("over-budget")
        );
    }

    #[test]
    fn typed_scheduler_requires_globally_contiguous_complete_epoch_history() {
        let sprint = sprint(2);
        let first = task("first", &[], "src/first");
        let second = task("second", &[], "src/second");
        let graph = graph(vec![first.clone(), second.clone()]);
        let mut first_history = empty_attempt_history(&first, TaskState::Running);
        first_history.attempts.push(open_attempt_entry(
            typed_attempt(&first, 1, 1, "worker-1"),
            true,
        ));
        let mut second_history = empty_attempt_history(&second, TaskState::Running);
        second_history.attempts.push(open_attempt_entry(
            typed_attempt(&second, 1, 3, "worker-2"),
            true,
        ));
        assert!(
            typed_schedule(&sprint, &graph, &[first_history, second_history], &[], 4)
                .expect_err("omitted epoch")
                .message()
                .contains("globally contiguous")
        );
    }

    #[test]
    fn typed_scheduler_rejects_later_nonready_legacy_before_capacity_selection() {
        let sprint = sprint(1);
        let current = task("current", &[], "src/current");
        let legacy = task("legacy", &[], "src/legacy");
        let graph = graph(vec![current.clone(), legacy.clone()]);
        let current_history = empty_attempt_history(&current, TaskState::Ready);
        let mut legacy_history = empty_attempt_history(&legacy, TaskState::Integrated);
        legacy_history.attempts.push(legacy_attempt_entry(
            &legacy,
            1,
            1,
            crate::LegacyTaskAttemptClassification::LegacyIntegratedReleased,
            false,
        ));
        assert!(
            typed_schedule(
                &sprint,
                &graph,
                &[current_history, legacy_history],
                &workers(&["worker-1"]),
                2,
            )
            .expect_err("legacy recovery is checked before capacity can fill")
            .message()
            .contains("requires recovery")
        );
    }

    #[test]
    fn typed_scheduler_validates_candidate_bijection_in_declared_not_lexical_order() {
        let mut sprint = sprint(1);
        sprint.acceptance_criteria = vec![
            AcceptanceCriterion {
                criterion_id: "z-first".into(),
                description: "first declared check".into(),
                kind: AcceptanceKind::Automated(crate::CommandSpec {
                    program: "check-z".into(),
                    arguments: Vec::new(),
                    working_directory: PathBuf::new(),
                }),
            },
            AcceptanceCriterion {
                criterion_id: "a-second".into(),
                description: "second declared check".into(),
                kind: AcceptanceKind::Automated(crate::CommandSpec {
                    program: "check-a".into(),
                    arguments: Vec::new(),
                    working_directory: PathBuf::new(),
                }),
            },
        ];
        let mut task = task("task-1", &[], "src");
        task.acceptance_checks = vec!["z-first".into(), "a-second".into()];
        let graph = graph(vec![task.clone()]);
        let attempt = typed_attempt(&task, 1, 1, "worker-1");
        let verification = verification_boundary(&attempt, digest('c'));
        let checks = vec![
            formal_check(
                &attempt,
                0,
                &sprint.acceptance_criteria[0],
                digest('c'),
                "receipt-z",
            ),
            formal_check(
                &attempt,
                1,
                &sprint.acceptance_criteria[1],
                digest('c'),
                "receipt-a",
            ),
        ];
        let candidate = candidate_boundary(&attempt, &verification, &checks);
        let history = TaskAttemptHistory {
            contract_version: CONTRACT_VERSION,
            sprint_id: "sprint-1".into(),
            task_id: "task-1".into(),
            task_state: TaskState::Candidate,
            sprint_state: crate::SprintState::Running,
            attempts: vec![crate::TaskAttemptHistoryEntry {
                running_boundary: Some(running_boundary(&attempt)),
                attempt,
                verification_boundary: Some(verification),
                formal_checks: checks,
                candidate_boundary: Some(candidate),
                disposition: None,
                legacy_classification: None,
                lease_state: crate::TaskAttemptLeaseState::Active,
            }],
            budget_classification: TaskAttemptBudgetClassification::WithinBudget,
            unknown_terminalization_pending: None,
        };
        assert_eq!(
            typed_schedule(&sprint, &graph, std::slice::from_ref(&history), &[], 2),
            Ok(SchedulePlan {
                leases: Vec::new(),
                next_lease_epoch: 2,
            })
        );

        let mut crossed = history;
        crossed.attempts[0].formal_checks.swap(0, 1);
        assert!(
            typed_schedule(&sprint, &graph, &[crossed], &[], 2)
                .expect_err("declared check order is authority")
                .message()
                .contains("declared criterion")
        );
    }

    #[test]
    fn typed_scheduler_accepts_human_only_empty_candidate_check_set() {
        let sprint = sprint(1);
        let task = task("task-1", &[], "src");
        let graph = graph(vec![task.clone()]);
        let attempt = typed_attempt(&task, 1, 1, "worker-1");
        let verification = verification_boundary(&attempt, digest('c'));
        let candidate = candidate_boundary(&attempt, &verification, &[]);
        let history = TaskAttemptHistory {
            contract_version: CONTRACT_VERSION,
            sprint_id: "sprint-1".into(),
            task_id: "task-1".into(),
            task_state: TaskState::Candidate,
            sprint_state: crate::SprintState::Running,
            attempts: vec![crate::TaskAttemptHistoryEntry {
                running_boundary: Some(running_boundary(&attempt)),
                attempt,
                verification_boundary: Some(verification),
                formal_checks: Vec::new(),
                candidate_boundary: Some(candidate),
                disposition: None,
                legacy_classification: None,
                lease_state: crate::TaskAttemptLeaseState::Active,
            }],
            budget_classification: TaskAttemptBudgetClassification::WithinBudget,
            unknown_terminalization_pending: None,
        };
        assert!(typed_schedule(&sprint, &graph, &[history], &[], 2).is_ok());
    }

    #[test]
    fn typed_scheduler_resolves_then_freezes_exact_unknown_pending_marker() {
        let mut sprint = sprint(2);
        sprint.max_workers = 2;
        let unknown_task = task("unknown", &[], "src/unknown");
        let ready_task = task("ready", &[], "src/ready");
        let graph = graph(vec![unknown_task.clone(), ready_task.clone()]);
        let attempt = typed_attempt(&unknown_task, 1, 1, "worker-1");
        let metadata = crate::TaskAttemptDispositionMetadata {
            contract_version: CONTRACT_VERSION,
            disposition_id: "unknown-disposition-1".into(),
            attempt: attempt.clone(),
            from_state: TaskState::Running,
            state_transition_event_id: "to-unknown-1".into(),
            disposed_at_unix_ms: ACQUIRED_AT + 1,
        };
        let disposition = crate::TaskAttemptDisposition::UnknownQuarantined(
            crate::TaskAttemptUnknownQuarantinedDisposition {
                metadata,
                uncertain_evidence: crate::TaskAttemptUncertainEvidence {
                    uncertainty_id: "uncertainty-1".into(),
                    authority_reference_ids: vec!["session-1".into()],
                    evidence: retained_evidence(
                        crate::TaskAttemptEvidenceKind::UncertainAuthority,
                        "uncertain-1",
                    ),
                },
            },
        );
        let marker = crate::SprintUnknownTerminalizationPending {
            contract_version: CONTRACT_VERSION,
            marker_id: "pending-1".into(),
            sprint_id: "sprint-1".into(),
            first_attempt_id: attempt.attempt_id.clone(),
            first_disposition_id: "unknown-disposition-1".into(),
            created_at_unix_ms: ACQUIRED_AT + 2,
        };
        let unknown_history = TaskAttemptHistory {
            contract_version: CONTRACT_VERSION,
            sprint_id: "sprint-1".into(),
            task_id: "unknown".into(),
            task_state: TaskState::Unknown,
            sprint_state: crate::SprintState::Running,
            attempts: vec![crate::TaskAttemptHistoryEntry {
                running_boundary: Some(running_boundary(&attempt)),
                attempt,
                verification_boundary: None,
                formal_checks: Vec::new(),
                candidate_boundary: None,
                disposition: Some(disposition),
                legacy_classification: None,
                lease_state: crate::TaskAttemptLeaseState::Active,
            }],
            budget_classification: TaskAttemptBudgetClassification::WithinBudget,
            unknown_terminalization_pending: Some(marker.clone()),
        };
        let mut ready_history = empty_attempt_history(&ready_task, TaskState::Ready);
        ready_history.unknown_terminalization_pending = Some(marker.clone());
        let histories = [unknown_history, ready_history];
        assert!(
            typed_schedule(&sprint, &graph, &histories, &workers(&["worker-2"]), 2,)
                .expect_err("pending freezes unrelated Ready task")
                .message()
                .contains("freezes")
        );

        let mut forged = histories;
        forged[0]
            .unknown_terminalization_pending
            .as_mut()
            .expect("marker")
            .first_disposition_id = "missing".into();
        forged[1].unknown_terminalization_pending =
            forged[0].unknown_terminalization_pending.clone();
        assert!(
            typed_schedule(&sprint, &graph, &forged, &[], 2)
                .expect_err("marker must resolve")
                .message()
                .contains("must resolve")
        );
    }

    #[test]
    fn one_node_max_one_is_stable_strict_and_canonical_ready() {
        let sprint = sprint(1);
        let graph = graph(vec![task("task-1", &[], "src")]);
        let states = states(&[("task-1", TaskState::Ready)]);
        let workers = workers(&["worker-1"]);

        let first = schedule(&sprint, &graph, &states, &[], &workers, 1).expect("schedule");
        let second = schedule(&sprint, &graph, &states, &[], &workers, 1).expect("schedule");
        assert_eq!(first, second);
        assert_eq!(first.leases.len(), 1);
        assert_eq!(first.leases[0].lease_epoch, 1);
        assert_eq!(first.next_lease_epoch, 2);
        assert_eq!(first.leases[0].contract_version, CONTRACT_VERSION);
        assert_eq!(first.leases[0].sprint_id, sprint.sprint_id);

        let canonical = serde_json::to_vec(&first.leases[0]).expect("serialize lease");
        assert_eq!(
            serde_json::from_slice::<WorkerLease>(&canonical).expect("deserialize lease"),
            first.leases[0]
        );
        let mut unknown = serde_json::to_value(&first.leases[0]).expect("lease value");
        unknown
            .as_object_mut()
            .expect("object")
            .insert("unexpected".into(), serde_json::Value::Bool(true));
        assert!(serde_json::from_value::<WorkerLease>(unknown).is_err());

        let encoded_plan = serde_json::to_value(&first).expect("serialize proposal-only plan");
        assert_eq!(encoded_plan["next_lease_epoch"], 2);

        let mut invalid_epoch = first.leases[0].clone();
        invalid_epoch.lease_epoch = 0;
        assert_eq!(
            invalid_epoch.validate().expect_err("zero epoch").field(),
            "worker_lease.lease_epoch"
        );
        let mut invalid_version = first.leases[0].clone();
        invalid_version.contract_version = CONTRACT_VERSION + 1;
        assert_eq!(
            invalid_version
                .validate()
                .expect_err("wrong contract version")
                .field(),
            "worker_lease.contract_version"
        );
    }

    #[test]
    fn dependency_promotion_only_dispatches_ready_after_integration() {
        let sprint = sprint(1);
        let graph = graph(vec![
            task("parent", &[], "src/parent"),
            task("child", &["parent"], "src/child"),
        ]);
        let workers = workers(&["worker-1"]);
        let before = states(&[("parent", TaskState::Ready), ("child", TaskState::Planned)]);
        assert_eq!(
            schedule(&sprint, &graph, &before, &[], &workers, 1)
                .expect("parent schedule")
                .leases[0]
                .task_id,
            "parent"
        );

        let after = states(&[
            ("parent", TaskState::Integrated),
            ("child", TaskState::Ready),
        ]);
        assert_eq!(
            schedule(&sprint, &graph, &after, &[], &workers, 2)
                .expect("child schedule")
                .leases[0]
                .task_id,
            "child"
        );
    }

    #[test]
    fn hard_three_worker_ceiling_is_never_exceeded() {
        let sprint = sprint(3);
        let graph = graph(vec![
            task("task-1", &[], "one"),
            task("task-2", &[], "two"),
            task("task-3", &[], "three"),
            task("task-4", &[], "four"),
        ]);
        let states = states(&[
            ("task-1", TaskState::Ready),
            ("task-2", TaskState::Ready),
            ("task-3", TaskState::Ready),
            ("task-4", TaskState::Ready),
        ]);
        let workers = workers(&["worker-3", "worker-2", "worker-1"]);
        let plan = schedule(&sprint, &graph, &states, &[], &workers, 1).expect("schedule");
        assert_eq!(plan.leases.len(), 3);
        assert_eq!(plan.next_lease_epoch, 4);
    }

    #[test]
    fn graph_order_and_sorted_worker_assignment_are_deterministic() {
        let sprint = sprint(2);
        let graph = graph(vec![
            task("z-task", &[], "src/z"),
            task("a-task", &[], "src/a"),
        ]);
        let states = states(&[("z-task", TaskState::Ready), ("a-task", TaskState::Ready)]);
        let workers = workers(&["worker-z", "worker-a"]);
        let plan = schedule(&sprint, &graph, &states, &[], &workers, 10).expect("schedule");
        assert_eq!(plan.leases[0].task_id, "z-task");
        assert_eq!(plan.leases[0].worker_id, "worker-a");
        assert_eq!(plan.leases[1].task_id, "a-task");
        assert_eq!(plan.leases[1].worker_id, "worker-z");
    }

    #[test]
    fn workspace_case_alias_and_ancestor_scopes_conflict() {
        let workspace = PathScope::Workspace;
        let src = PathScope::Relative(PathBuf::from("src/Foo"));
        let descendant = PathScope::Relative(PathBuf::from("SRC/foo/bar.rs"));
        let sibling = PathScope::Relative(PathBuf::from("src/foobar"));
        assert!(path_scopes_conflict(&workspace, &sibling));
        assert!(path_scopes_conflict(&src, &descendant));
        assert!(path_scopes_conflict(&descendant, &src));
        assert!(!path_scopes_conflict(&src, &sibling));
    }

    #[test]
    fn non_ascii_normalization_aliases_conservatively_conflict() {
        let precomposed = PathScope::Relative(PathBuf::from("src/caf\u{e9}"));
        let decomposed = PathScope::Relative(PathBuf::from("src/cafe\u{301}"));
        let ordinary = PathScope::Relative(PathBuf::from("tests"));
        assert!(path_scopes_conflict(&precomposed, &decomposed));
        assert!(path_scopes_conflict(&decomposed, &precomposed));
        assert!(path_scopes_conflict(&precomposed, &ordinary));
    }

    #[test]
    fn disjoint_tasks_dispatch_in_parallel_while_conflicts_are_skipped() {
        let sprint = sprint(3);
        let graph = graph(vec![
            task("first", &[], "src/shared"),
            task("conflict", &[], "SRC/shared/child"),
            task("disjoint", &[], "tests"),
        ]);
        let states = states(&[
            ("first", TaskState::Ready),
            ("conflict", TaskState::Ready),
            ("disjoint", TaskState::Ready),
        ]);
        let workers = workers(&["worker-1", "worker-2", "worker-3"]);
        let plan = schedule(&sprint, &graph, &states, &[], &workers, 1).expect("schedule");
        assert_eq!(
            plan.leases
                .iter()
                .map(|lease| lease.task_id.as_str())
                .collect::<Vec<_>>(),
            ["first", "disjoint"]
        );
    }

    #[test]
    fn active_lease_reduces_capacity_and_blocks_its_scope() {
        let sprint = sprint(2);
        let active_task = task("active", &[], "src/shared");
        let graph = graph(vec![
            active_task.clone(),
            task("blocked", &[], "src/shared/child"),
            task("next", &[], "tests"),
        ]);
        let states = states(&[
            ("active", TaskState::Running),
            ("blocked", TaskState::Ready),
            ("next", TaskState::Ready),
        ]);
        let active = vec![active_lease("sprint-1", &active_task, "worker-1", 3)];
        let workers = workers(&["worker-2", "worker-3"]);
        let plan = schedule(&sprint, &graph, &states, &active, &workers, 4).expect("schedule");
        assert_eq!(plan.leases.len(), 1);
        assert_eq!(plan.leases[0].task_id, "next");
        assert_eq!(plan.leases[0].lease_epoch, 4);
    }

    #[test]
    fn conflicting_active_lease_scopes_are_rejected_as_corrupt_state() {
        let sprint = sprint(2);
        let first = task("first", &[], "src/shared");
        let second = task("second", &[], "SRC/shared/child");
        let graph = graph(vec![first.clone(), second.clone()]);
        let states = states(&[
            ("first", TaskState::Running),
            ("second", TaskState::Verifying),
        ]);
        let active = vec![
            active_lease("sprint-1", &first, "worker-1", 1),
            active_lease("sprint-1", &second, "worker-2", 2),
        ];
        assert!(
            schedule(&sprint, &graph, &states, &active, &[], 3)
                .expect_err("conflicting active scopes")
                .message()
                .contains("conflicting scopes")
        );
    }

    #[test]
    fn missing_extra_and_impossible_ready_states_are_rejected() {
        let sprint = sprint(1);
        let graph = graph(vec![
            task("parent", &[], "parent"),
            task("child", &["parent"], "child"),
        ]);
        let workers = workers(&["worker-1"]);
        let missing = states(&[("parent", TaskState::Ready)]);
        assert_eq!(
            schedule(&sprint, &graph, &missing, &[], &workers, 1)
                .expect_err("missing state")
                .field(),
            "scheduler.task_states"
        );
        let extra = states(&[
            ("parent", TaskState::Ready),
            ("child", TaskState::Planned),
            ("other", TaskState::Ready),
        ]);
        assert_eq!(
            schedule(&sprint, &graph, &extra, &[], &workers, 1)
                .expect_err("extra state")
                .field(),
            "scheduler.task_states"
        );
        let impossible = states(&[("parent", TaskState::Ready), ("child", TaskState::Ready)]);
        assert!(
            schedule(&sprint, &graph, &impossible, &[], &workers, 1)
                .expect_err("dependency not integrated")
                .message()
                .contains("non-integrated dependency")
        );
        let advanced = states(&[
            ("parent", TaskState::Planned),
            ("child", TaskState::Running),
        ]);
        let child_lease = active_lease("sprint-1", &graph.tasks[1], "worker-2", 1);
        assert!(
            schedule(&sprint, &graph, &advanced, &[child_lease], &[], 2)
                .expect_err("running dependency not integrated")
                .message()
                .contains("state Running has non-integrated dependency")
        );
    }

    #[test]
    fn duplicate_and_active_worker_inputs_are_rejected() {
        let sprint = sprint(2);
        let active_task = task("active", &[], "active");
        let graph = graph(vec![active_task.clone(), task("ready", &[], "ready")]);
        let states = states(&[("active", TaskState::Running), ("ready", TaskState::Ready)]);
        let active = vec![active_lease("sprint-1", &active_task, "worker-1", 1)];
        let duplicate = workers(&["worker-2", "worker-2"]);
        assert!(
            schedule(&sprint, &graph, &states, &active, &duplicate, 2)
                .expect_err("duplicate worker")
                .message()
                .contains("duplicate worker")
        );
        let active_as_available = workers(&["worker-1"]);
        assert!(
            schedule(&sprint, &graph, &states, &active, &active_as_available, 2,)
                .expect_err("active worker")
                .message()
                .contains("cannot also be available")
        );
    }

    #[test]
    fn oversized_identifier_and_excess_worker_pool_are_rejected_before_selection() {
        let sprint = sprint(3);
        let ready_task = task("ready", &[], "ready");
        let graph = graph(vec![ready_task.clone()]);
        let ready = states(&[("ready", TaskState::Ready)]);

        let extra_pool = workers(&["worker-1", "worker-2", "worker-3", "worker-4"]);
        assert!(
            schedule(&sprint, &graph, &ready, &[], &extra_pool, 1)
                .expect_err("extra pool identity")
                .message()
                .contains("must not exceed 3")
        );

        let oversized = vec!["w".repeat(MAX_WORKER_ID_BYTES + 1)];
        assert!(
            schedule(&sprint, &graph, &ready, &[], &oversized, 1)
                .expect_err("oversized worker id")
                .message()
                .contains("1..=256")
        );

        let running = states(&[("ready", TaskState::Running)]);
        let active = vec![active_lease("sprint-1", &ready_task, "worker-1", 1)];
        let three_available = workers(&["worker-2", "worker-3", "worker-4"]);
        assert!(
            schedule(&sprint, &graph, &running, &active, &three_available, 2)
                .expect_err("four implied slots")
                .message()
                .contains("active and available worker pool")
        );
    }

    #[test]
    fn duplicate_active_task_worker_epoch_and_capacity_are_rejected() {
        let sprint = sprint(2);
        let first = task("first", &[], "first");
        let second = task("second", &[], "second");
        let graph = graph(vec![first.clone(), second.clone()]);
        let states = states(&[
            ("first", TaskState::Running),
            ("second", TaskState::Running),
        ]);

        let duplicate_epoch = vec![
            active_lease("sprint-1", &first, "worker-1", 1),
            active_lease("sprint-1", &second, "worker-2", 1),
        ];
        assert!(
            schedule(&sprint, &graph, &states, &duplicate_epoch, &[], 2)
                .expect_err("duplicate epoch")
                .message()
                .contains("epoch 1 is reused")
        );

        let mut duplicate_task = vec![
            active_lease("sprint-1", &first, "worker-1", 1),
            active_lease("sprint-1", &first, "worker-2", 2),
        ];
        assert!(
            schedule(&sprint, &graph, &states, &duplicate_task, &[], 3)
                .expect_err("duplicate task")
                .message()
                .contains("more than one active lease")
        );
        duplicate_task[1] = active_lease("sprint-1", &second, "worker-1", 2);
        assert!(
            schedule(&sprint, &graph, &states, &duplicate_task, &[], 3)
                .expect_err("duplicate worker")
                .message()
                .contains("more than one active lease")
        );

        let mut single_worker_sprint = sprint.clone();
        single_worker_sprint.max_workers = 1;
        let over_capacity = vec![
            active_lease("sprint-1", &first, "worker-1", 1),
            active_lease("sprint-1", &second, "worker-2", 2),
        ];
        assert!(
            schedule(
                &single_worker_sprint,
                &graph,
                &states,
                &over_capacity,
                &[],
                3,
            )
            .expect_err("capacity")
            .message()
            .contains("worker ceiling")
        );
    }

    #[test]
    fn substituted_cross_sprint_and_state_disagreement_leases_are_rejected() {
        let sprint = sprint(1);
        let active_task = task("active", &[], "src");
        let graph = graph(vec![active_task.clone()]);
        let running = states(&[("active", TaskState::Running)]);
        let mut substituted = active_lease("sprint-1", &active_task, "worker-1", 1);
        substituted.path_scopes = vec![PathScope::Relative(PathBuf::from("other"))];
        assert!(
            schedule(&sprint, &graph, &running, &[substituted], &[], 2)
                .expect_err("scope substitution")
                .message()
                .contains("do not exactly match")
        );

        let cross_sprint = active_lease("other-sprint", &active_task, "worker-1", 1);
        assert!(
            schedule(&sprint, &graph, &running, &[cross_sprint], &[], 2)
                .expect_err("cross sprint")
                .message()
                .contains("another sprint")
        );

        let ready = states(&[("active", TaskState::Ready)]);
        let lease = active_lease("sprint-1", &active_task, "worker-1", 1);
        assert!(
            schedule(&sprint, &graph, &ready, &[lease], &[], 2)
                .expect_err("state disagreement")
                .message()
                .contains("disagree")
        );
    }

    #[test]
    fn standalone_lease_contract_rejects_identity_substitution_and_oversize() {
        let sprint = sprint(1);
        let active_task = task("active", &[], "src");
        let lease = active_lease(&sprint.sprint_id, &active_task, "worker-1", 7);

        for substituted in [
            WorkerLease {
                sprint_id: "sprint-2".into(),
                ..lease.clone()
            },
            WorkerLease {
                task_id: "task-2".into(),
                ..lease.clone()
            },
            WorkerLease {
                worker_id: "worker-2".into(),
                ..lease.clone()
            },
            WorkerLease {
                lease_epoch: 8,
                ..lease.clone()
            },
        ] {
            assert_eq!(
                substituted
                    .validate()
                    .expect_err("substituted lease identity")
                    .field(),
                "worker_lease.lease_id"
            );
        }

        let mut oversized_worker = lease.clone();
        oversized_worker.worker_id = "w".repeat(crate::MAX_WORKER_ID_BYTES + 1);
        assert_eq!(
            oversized_worker
                .validate()
                .expect_err("oversized worker")
                .field(),
            "worker_lease.worker_id"
        );

        let mut oversized_lease_id = lease;
        oversized_lease_id.lease_id = "l".repeat(crate::WORKER_LEASE_ID_BYTES + 1);
        assert_eq!(
            oversized_lease_id
                .validate()
                .expect_err("oversized lease id")
                .field(),
            "worker_lease.lease_id"
        );
    }

    #[test]
    fn worker_lease_deserialization_validates_exact_canonical_identity() {
        let lease = active_lease("sprint-1", &task("task-1", &[], "src"), "worker-1", 4);
        assert_eq!(
            lease.lease_id,
            "lease-c675f19f20c05ef22aa76892f2279780d6c9b3936cb1b09254e58d9f9d226848"
        );
        let canonical = serde_json::to_value(&lease).expect("serialize lease");
        assert_eq!(
            serde_json::from_value::<WorkerLease>(canonical.clone()).expect("canonical lease"),
            lease
        );

        for (field, value) in [
            ("sprint_id", serde_json::json!("sprint-2")),
            ("task_id", serde_json::json!("task-2")),
            ("worker_id", serde_json::json!("worker-2")),
            ("lease_epoch", serde_json::json!(5)),
            (
                "lease_id",
                serde_json::json!(format!("lease-{}", "f".repeat(64))),
            ),
        ] {
            let mut substituted = canonical.clone();
            substituted
                .as_object_mut()
                .expect("lease object")
                .insert(field.into(), value);
            let error = serde_json::from_value::<WorkerLease>(substituted)
                .expect_err("deserialization must reject substitution");
            assert!(error.to_string().contains("worker_lease.lease_id"));
        }

        let mut oversized_worker = canonical.clone();
        oversized_worker["worker_id"] =
            serde_json::json!("w".repeat(crate::MAX_WORKER_ID_BYTES + 1));
        assert!(
            serde_json::from_value::<WorkerLease>(oversized_worker)
                .expect_err("oversized worker")
                .to_string()
                .contains("worker_lease.worker_id")
        );

        let mut oversized_lease_id = canonical;
        oversized_lease_id["lease_id"] =
            serde_json::json!("l".repeat(crate::WORKER_LEASE_ID_BYTES + 1));
        assert!(
            serde_json::from_value::<WorkerLease>(oversized_lease_id)
                .expect_err("oversized lease id")
                .to_string()
                .contains("worker_lease.lease_id")
        );
    }

    #[test]
    fn stale_reused_and_overflowing_epochs_fail_closed() {
        let sprint = sprint(1);
        let active_task = task("active", &[], "src");
        let graph = graph(vec![active_task.clone()]);
        let running = states(&[("active", TaskState::Running)]);
        let active = active_lease("sprint-1", &active_task, "worker-1", 7);
        assert!(
            schedule(&sprint, &graph, &running, &[active], &[], 7)
                .expect_err("epoch reuse")
                .message()
                .contains("must exceed active lease epoch")
        );

        let ready = states(&[("active", TaskState::Ready)]);
        let workers = workers(&["worker-1"]);
        assert!(
            schedule(&sprint, &graph, &ready, &[], &workers, u64::MAX)
                .expect_err("epoch overflow")
                .message()
                .contains("overflow")
        );
    }

    #[test]
    fn current_v2_scheduler_keeps_repair_dormant_until_exact_activation() {
        let (sprint, graph) = current_pair("current-sprint");
        let workers = workers(&["worker-1"]);
        let dormant = states(&[
            ("ordinary", TaskState::Integrated),
            ("repair-1", TaskState::Planned),
        ]);
        let plan = current_schedule(&sprint, &graph, &dormant, &[], &[], &workers, 1)
            .expect("dormant slot is a valid inert state");
        assert!(plan.leases.is_empty());

        let forged_ready = states(&[
            ("ordinary", TaskState::Integrated),
            ("repair-1", TaskState::Ready),
        ]);
        let error = current_schedule(&sprint, &graph, &forged_ready, &[], &[], &workers, 1)
            .expect_err("repair Ready without activation must fail closed");
        assert!(error.message().contains("escaped Planned dormancy"));

        let permit = current_permit(&sprint, &graph);
        let plan = current_schedule(
            &sprint,
            &graph,
            &forged_ready,
            std::slice::from_ref(&permit),
            &[],
            &workers,
            1,
        )
        .expect("exact activated repair may be proposed");
        assert_eq!(plan.leases.len(), 1);
        assert_eq!(plan.leases[0].task_id, "repair-1");

        let (crossed_sprint, crossed_graph) = current_pair("crossed-sprint");
        let crossed = current_permit(&crossed_sprint, &crossed_graph);
        assert!(
            current_schedule(&sprint, &graph, &forged_ready, &[crossed], &[], &workers, 1,)
                .is_err()
        );
    }

    #[test]
    fn current_v2_transition_requires_exact_repair_context_but_not_for_ordinary_tasks() {
        let (sprint, graph) = current_pair("transition-sprint");
        let permit = current_permit(&sprint, &graph);
        assert_eq!(
            transition_current_v2_task(
                &sprint,
                &graph,
                "ordinary",
                TaskState::Planned,
                TaskState::Ready,
                None,
            ),
            Ok(TaskState::Ready)
        );
        assert!(
            transition_current_v2_task(
                &sprint,
                &graph,
                "ordinary",
                TaskState::Planned,
                TaskState::Ready,
                Some(&permit),
            )
            .is_err()
        );
        assert!(
            transition_current_v2_task(
                &sprint,
                &graph,
                "repair-1",
                TaskState::Planned,
                TaskState::Ready,
                None,
            )
            .is_err()
        );
        assert_eq!(
            transition_current_v2_task(
                &sprint,
                &graph,
                "repair-1",
                TaskState::Planned,
                TaskState::Ready,
                Some(&permit),
            ),
            Ok(TaskState::Ready)
        );
        // A dormant task may be terminalized without creating execution
        // authority, while the legacy generic transition remains unchanged.
        assert_eq!(
            transition_current_v2_task(
                &sprint,
                &graph,
                "repair-1",
                TaskState::Planned,
                TaskState::Canceled,
                None,
            ),
            Ok(TaskState::Canceled)
        );
        assert_eq!(
            TaskState::Planned.transition(TaskState::Ready),
            Ok(TaskState::Ready)
        );
    }

    #[test]
    fn current_v2_integrated_lease_may_be_cleanup_pending_or_released() {
        let (sprint, graph) = current_pair("integrated-lease-sprint");
        let permit = current_permit(&sprint, &graph);
        let states = states(&[
            ("ordinary", TaskState::Integrated),
            ("repair-1", TaskState::Integrated),
        ]);
        let repair = graph
            .tasks
            .iter()
            .find(|task| task.task_id == "repair-1")
            .expect("repair task");
        let active = WorkerLease::new(
            sprint.sprint_id.clone(),
            1,
            repair.task_id.clone(),
            "worker-1".into(),
            repair.path_scopes.clone(),
            ACQUIRED_AT - 1,
        )
        .expect("cleanup-pending repair lease");
        assert!(
            current_schedule(
                &sprint,
                &graph,
                &states,
                std::slice::from_ref(&permit),
                &[active],
                &[],
                2,
            )
            .is_ok()
        );
        assert!(current_schedule(&sprint, &graph, &states, &[permit], &[], &[], 1,).is_ok());
    }

    #[cfg(unix)]
    #[test]
    fn non_utf8_relative_scope_conservatively_conflicts() {
        use std::ffi::OsString;
        use std::os::unix::ffi::OsStringExt;

        let invalid = PathScope::Relative(PathBuf::from(OsString::from_vec(vec![0xff])));
        let ordinary = PathScope::Relative(PathBuf::from("src"));
        assert!(path_scopes_conflict(&invalid, &ordinary));
        assert!(path_scopes_conflict(&ordinary, &invalid));
    }
}
