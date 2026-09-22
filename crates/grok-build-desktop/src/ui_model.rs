//! Framework-independent desktop presentation contracts.
//!
//! No concrete UI framework is admitted yet. These types keep the terminal
//! result, task queue, worker cards, acceptance evidence, and activity stream
//! behind one internal facade so a future runtime cannot redefine `Completed`.

use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fmt::{self, Display, Formatter};

use grok_build_core::{
    AgentEventKind, ApplicationEvidence, ApplicationValidationMode, CompletionApplication,
    CompletionLiveStateApplicationLink, CompletionLiveStateCaptureLink, Digest,
    NonSuccessTerminalState, PersistedCompletion, PersistedCompletionApplication,
    PersistedCompletionLiveStateAuthority, PersistedTerminalOutcome, PersistedTerminalProof,
    RunnerSessionPurpose, SprintState, TaskState, WorkerState,
};
use serde::Serialize;

use crate::ui_projection::DurableUiProjection;

/// Maximum worker cards displayed by the v0.1 sprint surface.
pub const MAX_VISIBLE_WORKERS: usize = 3;

/// A concrete native UI runtime that consumes only validated presentation data.
///
/// Framework-specific imports and widgets belong in the implementation crate or
/// module, never in coordinator or core code.
pub trait UiRuntime {
    /// Runtime-specific rendering failure.
    type Error: Error;

    /// Presents one complete immutable frame.
    ///
    /// # Errors
    ///
    /// Returns the runtime's rendering error without changing sprint state.
    fn present(&mut self, frame: &SprintFrame) -> Result<(), Self::Error>;

    /// Presents the restart-reconstructible typed activity projection.
    ///
    /// The projection contains no provider-local transient deltas and cannot
    /// claim completion without a validated durable completion chain.
    ///
    /// # Errors
    ///
    /// Returns the runtime's rendering error without changing sprint state.
    fn present_projection(&mut self, projection: &DurableUiProjection) -> Result<(), Self::Error>;
}

/// One task-queue component.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TaskCard {
    /// Production task identifier.
    pub task_id: String,
    /// User-visible task outcome.
    pub goal: String,
    /// Coordinator-owned lifecycle state.
    pub state: TaskState,
}

/// One worker-status component.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WorkerCard {
    /// Stable worker-slot identifier.
    pub worker_id: String,
    /// Coordinator-owned worker state.
    pub state: WorkerState,
    /// Assigned task, when one exists.
    pub task_id: Option<String>,
}

/// User-visible state of one exact acceptance criterion.
///
/// Machine and human evidence use disjoint success and failure words. The
/// aggregate word `Satisfied` belongs to [`CriteriaAggregateStatus`], never to
/// an individual machine or human claim.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(tag = "status", rename_all = "kebab-case")]
pub enum AcceptanceStatus {
    /// No terminal evidence exists yet.
    Pending,
    /// One exact one-to-one prompt awaits an explicit human action.
    AwaitingYourDecision {
        /// Exact coordinator-minted prompt identity.
        prompt_id: String,
    },
    /// An automated criterion has exact passing machine evidence.
    Verified {
        /// Exact typed criterion-evidence receipt.
        criterion_evidence_receipt_id: String,
        /// Exact machine-verification receipt.
        verification_receipt_id: String,
    },
    /// A human accepted one exact rendered criterion claim.
    AcceptedByYou {
        /// Exact typed criterion-evidence receipt.
        criterion_evidence_receipt_id: String,
        /// Exact one-to-one prompt consumed by the action.
        prompt_id: String,
        /// Exact immutable human decision.
        decision_id: String,
    },
    /// Machine verification failed and carries an exact visible reason.
    VerificationFailed {
        /// Exact failed machine-verification receipt.
        verification_receipt_id: String,
        /// Non-empty failure reason.
        reason: String,
    },
    /// A human rejected one exact rendered criterion claim.
    RejectedByYou {
        /// Exact one-to-one prompt consumed by the action.
        prompt_id: String,
        /// Exact immutable human decision.
        decision_id: String,
    },
}

impl AcceptanceStatus {
    /// Exact short label used on visible surfaces.
    #[must_use]
    pub const fn visible_label(&self) -> &'static str {
        match self {
            Self::Pending => "Pending",
            Self::AwaitingYourDecision { .. } => "Awaiting your decision",
            Self::Verified { .. } => "Verified",
            Self::AcceptedByYou { .. } => "Accepted by you",
            Self::VerificationFailed { .. } => "Verification failed",
            Self::RejectedByYou { .. } => "Rejected by you",
        }
    }

    /// Exact short label exposed to assistive technology.
    #[must_use]
    pub const fn accessibility_label(&self) -> &'static str {
        self.visible_label()
    }

    /// Whether this exact criterion has honest successful backing.
    #[must_use]
    pub const fn is_satisfied(&self) -> bool {
        matches!(self, Self::Verified { .. } | Self::AcceptedByYou { .. })
    }
}

/// Aggregate presentation state across the exact criterion set.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum CriteriaAggregateStatus {
    /// No current failure exists, but completion has not established success.
    Pending,
    /// At least one exact human prompt awaits a decision.
    AwaitingYourDecision,
    /// Machine verification failed or a human rejected a criterion.
    Unsatisfied,
    /// Every exact criterion is backed and the sprint is durably `Completed`.
    Satisfied,
}

/// One acceptance-results component.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AcceptanceCard {
    /// Criterion identifier from `SprintSpec`.
    pub criterion_id: String,
    /// Original observable success condition.
    pub description: String,
    /// Current evidence state.
    pub status: AcceptanceStatus,
}

impl AcceptanceCard {
    /// Exact concise accessibility label for this criterion and evidence kind.
    #[must_use]
    pub fn accessibility_label(&self) -> String {
        format!(
            "Criterion: {}. Status: {}.",
            self.description,
            self.status.accessibility_label()
        )
    }
}

/// One normalized row in the unified activity stream.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ActivityRow {
    /// Global sprint event sequence.
    pub sequence: u64,
    /// Short, non-empty user-visible event summary.
    pub summary: String,
}

/// The only terminal banner accepted by the desktop facade.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TerminalBanner {
    state: SprintState,
    title: &'static str,
    detail: String,
    completion_receipt_id: Option<String>,
    completion_live_state: Option<CompletionLiveState>,
    terminal_cause: Option<UiTerminalCause>,
    safe_next_action: Option<UiSafeNextAction>,
}

/// Exact typed reason a non-success terminal needs specialized presentation.
///
/// Generic terminal outcomes intentionally have no value here. A cause is
/// exposed only when it can be re-derived from a closed persisted proof rather
/// than inferred from user-facing reason text.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub enum UiTerminalCause {
    /// The selected descriptor-relative capture observed a workspace snapshot
    /// different from the immutable snapshot selected for completion.
    LiveStateDrift {
        /// Exact successful capture that proved the mismatch.
        capture_receipt_id: String,
        /// Immutable snapshot selected by the finish branch.
        expected_snapshot: Digest,
        /// Snapshot recomputed from the retained live manifest.
        observed_snapshot: Digest,
    },
}

/// Closed safe next actions exposed for typed non-success terminals.
///
/// These are presentation instructions, never continuation or mutation
/// authority. The coordinator must independently authorize any later sprint.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub enum UiSafeNextAction {
    /// Keep the blocked sprint immutable and create a new sprint from a fresh
    /// capture of the currently observed workspace.
    StartNewSprintFromObservedWorkspace,
}

/// Exact live-workspace meaning of a durable successful completion.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CompletionLiveState {
    /// A change set was applied and immutable rollback artifacts were reopened.
    Applied {
        /// Exact base snapshot restored by the retained rollback journal.
        rollback_target: Digest,
        /// Exact durable rollback-reference identity.
        rollback_reference_id: String,
    },
    /// No application intent occurred; the verified live manifest equals the
    /// sprint base snapshot.
    VerifiedNoOp {
        /// Exact verified live/base snapshot.
        live_snapshot: Digest,
    },
}

impl TerminalBanner {
    /// Builds a banner from durable successful completion or an exact
    /// non-success reason.
    ///
    /// `Completed` requires a fully correlated [`PersistedCompletion`]. Every
    /// other terminal state rejects completion evidence and requires a
    /// non-empty reason. Nonterminal states reject both and produce no banner.
    ///
    /// # Errors
    ///
    /// Returns an error for missing, contradictory, or internally mismatched
    /// terminal evidence.
    pub fn from_state(
        state: SprintState,
        completion: Option<&PersistedCompletion>,
        non_completion_reason: Option<&str>,
    ) -> Result<Option<Self>, UiModelError> {
        match state {
            SprintState::Completed => {
                let completion = completion.ok_or(UiModelError::CompletionEvidenceRequired)?;
                if non_completion_reason.is_some() {
                    return Err(UiModelError::ContradictoryTerminalEvidence);
                }
                let completion_live_state = validate_persisted_completion(completion)?;
                let detail = match completion_live_state {
                    CompletionLiveState::Applied { .. } => {
                        "Every criterion is satisfied on the exact applied snapshot; reopened rollback artifacts are available."
                    }
                    CompletionLiveState::VerifiedNoOp { .. } => {
                        "Every criterion is satisfied on the verified live base; no live workspace change was applied."
                    }
                };
                Ok(Some(Self {
                    state,
                    title: "Completed",
                    detail: detail.into(),
                    completion_receipt_id: Some(completion.receipt.receipt_id.clone()),
                    completion_live_state: Some(completion_live_state),
                    terminal_cause: None,
                    safe_next_action: None,
                }))
            }
            SprintState::Blocked
            | SprintState::Failed
            | SprintState::Canceled
            | SprintState::Unknown => {
                if completion.is_some() {
                    return Err(UiModelError::ContradictoryTerminalEvidence);
                }
                let reason = require_visible("terminal reason", non_completion_reason)?;
                let title = match state {
                    SprintState::Blocked => "Blocked — not completed",
                    SprintState::Failed => "Failed — not completed",
                    SprintState::Canceled => "Canceled — not completed",
                    SprintState::Unknown => "Unknown outcome — not completed",
                    _ => unreachable!("terminal-state match is exhaustive"),
                };
                Ok(Some(Self {
                    state,
                    title,
                    detail: reason.to_owned(),
                    completion_receipt_id: None,
                    completion_live_state: None,
                    terminal_cause: None,
                    safe_next_action: None,
                }))
            }
            SprintState::Draft
            | SprintState::Planning
            | SprintState::Running
            | SprintState::AwaitingAcceptance
            | SprintState::FinalVerification
            | SprintState::Applying => {
                if completion.is_some() || non_completion_reason.is_some() {
                    return Err(UiModelError::TerminalEvidenceForActiveSprint);
                }
                Ok(None)
            }
        }
    }

    /// Builds one non-success banner from exact persisted terminal evidence.
    ///
    /// Generic terminal outcomes preserve the existing banner behavior. A
    /// live-state-drift action is exposed only after the complete typed proof,
    /// selected capture, and verifier cleanup cross-correlate exactly.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed terminal evidence, a crossed typed drift
    /// proof, contradictory state, or an invalid normalized terminal event.
    pub fn from_persisted_terminal(
        terminal: &PersistedTerminalOutcome,
    ) -> Result<Self, UiModelError> {
        let (cause, safe_next_action) = validate_persisted_terminal(terminal)?;
        let mut banner = Self::from_state(
            terminal.terminal_state,
            None,
            Some(&terminal.evidence.reason),
        )?
        .ok_or(UiModelError::InvalidPersistedTerminal(
            "persisted terminal outcome produced no terminal banner".into(),
        ))?;
        banner.terminal_cause = cause;
        banner.safe_next_action = safe_next_action;
        Ok(banner)
    }

    /// Coordinator-owned terminal state.
    #[must_use]
    pub const fn state(&self) -> SprintState {
        self.state
    }

    /// Unambiguous terminal heading.
    #[must_use]
    pub const fn title(&self) -> &'static str {
        self.title
    }

    /// Completion summary or exact non-completion reason.
    #[must_use]
    pub fn detail(&self) -> &str {
        &self.detail
    }

    /// Durable successful-completion receipt, absent for every other outcome.
    #[must_use]
    pub fn completion_receipt_id(&self) -> Option<&str> {
        self.completion_receipt_id.as_deref()
    }

    /// Exact live-state branch, exposed only for durable completion.
    #[must_use]
    pub const fn completion_live_state(&self) -> Option<&CompletionLiveState> {
        self.completion_live_state.as_ref()
    }

    /// Typed non-success cause, absent for completion and generic terminals.
    #[must_use]
    pub const fn terminal_cause(&self) -> Option<&UiTerminalCause> {
        self.terminal_cause.as_ref()
    }

    /// Safe presentation-only next action derived from typed terminal proof.
    #[must_use]
    pub const fn safe_next_action(&self) -> Option<UiSafeNextAction> {
        self.safe_next_action
    }

    /// One-click rollback target, exposed only for an applied completion.
    #[must_use]
    pub fn rollback_target(&self) -> Option<&Digest> {
        match self.completion_live_state.as_ref() {
            Some(CompletionLiveState::Applied {
                rollback_target, ..
            }) => Some(rollback_target),
            Some(CompletionLiveState::VerifiedNoOp { .. }) | None => None,
        }
    }

    /// Exact verified live snapshot for a no-op completion.
    #[must_use]
    pub fn verified_no_op_live_snapshot(&self) -> Option<&Digest> {
        match self.completion_live_state.as_ref() {
            Some(CompletionLiveState::VerifiedNoOp { live_snapshot }) => Some(live_snapshot),
            Some(CompletionLiveState::Applied { .. }) | None => None,
        }
    }

    /// Returns true only for the sole successful terminal state.
    #[must_use]
    pub const fn is_done(&self) -> bool {
        self.state.is_success()
    }
}

/// Complete validated input to one native sprint screen render.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SprintFrame {
    sprint_id: String,
    objective: String,
    state: SprintState,
    tasks: Vec<TaskCard>,
    workers: Vec<WorkerCard>,
    acceptance: Vec<AcceptanceCard>,
    activity: Vec<ActivityRow>,
    terminal: Option<TerminalBanner>,
}

impl SprintFrame {
    /// Creates one consistent desktop frame.
    ///
    /// # Errors
    ///
    /// Returns an error for missing identifiers, duplicate component identities,
    /// more than three workers, a gapped activity stream, empty acceptance, or
    /// a terminal banner inconsistent with the lifecycle state.
    #[allow(
        clippy::too_many_arguments,
        clippy::too_many_lines,
        reason = "one frame constructor validates every cross-component lifecycle and typed acceptance relationship before the UI can render it"
    )]
    pub fn new(
        sprint_id: String,
        objective: String,
        state: SprintState,
        tasks: Vec<TaskCard>,
        workers: Vec<WorkerCard>,
        acceptance: Vec<AcceptanceCard>,
        activity: Vec<ActivityRow>,
        terminal: Option<TerminalBanner>,
    ) -> Result<Self, UiModelError> {
        require_visible("sprint id", Some(&sprint_id))?;
        require_visible("objective", Some(&objective))?;
        if workers.len() > MAX_VISIBLE_WORKERS {
            return Err(UiModelError::WorkerLimitExceeded {
                actual: workers.len(),
            });
        }
        if acceptance.is_empty() {
            return Err(UiModelError::MissingAcceptanceCriteria);
        }
        require_unique_nonblank("task", tasks.iter().map(|task| task.task_id.as_str()))?;
        require_unique_nonblank(
            "worker",
            workers.iter().map(|worker| worker.worker_id.as_str()),
        )?;
        require_unique_nonblank(
            "acceptance criterion",
            acceptance.iter().map(|item| item.criterion_id.as_str()),
        )?;
        for task in &tasks {
            require_visible("task goal", Some(&task.goal))?;
        }
        for item in &acceptance {
            require_visible("acceptance description", Some(&item.description))?;
            match &item.status {
                AcceptanceStatus::AwaitingYourDecision { prompt_id } => {
                    require_visible("human acceptance prompt id", Some(prompt_id))?;
                }
                AcceptanceStatus::Verified {
                    criterion_evidence_receipt_id,
                    verification_receipt_id,
                } => {
                    require_visible(
                        "criterion evidence receipt id",
                        Some(criterion_evidence_receipt_id),
                    )?;
                    require_visible("verification receipt id", Some(verification_receipt_id))?;
                }
                AcceptanceStatus::AcceptedByYou {
                    criterion_evidence_receipt_id,
                    prompt_id,
                    decision_id,
                } => {
                    require_visible(
                        "criterion evidence receipt id",
                        Some(criterion_evidence_receipt_id),
                    )?;
                    require_visible("human acceptance prompt id", Some(prompt_id))?;
                    require_visible("human acceptance decision id", Some(decision_id))?;
                }
                AcceptanceStatus::VerificationFailed {
                    verification_receipt_id,
                    reason,
                } => {
                    require_visible("verification receipt id", Some(verification_receipt_id))?;
                    require_visible("verification failure reason", Some(reason))?;
                }
                AcceptanceStatus::RejectedByYou {
                    prompt_id,
                    decision_id,
                } => {
                    require_visible("human acceptance prompt id", Some(prompt_id))?;
                    require_visible("human acceptance decision id", Some(decision_id))?;
                }
                AcceptanceStatus::Pending => {}
            }
        }
        for (index, row) in activity.iter().enumerate() {
            let expected = u64::try_from(index)
                .ok()
                .and_then(|value| value.checked_add(1))
                .ok_or(UiModelError::ActivitySequenceOverflow)?;
            if row.sequence != expected {
                return Err(UiModelError::ActivitySequence {
                    expected,
                    actual: row.sequence,
                });
            }
            require_visible("activity summary", Some(&row.summary))?;
        }
        match (&terminal, state.is_terminal()) {
            (Some(banner), true) if banner.state() == state => {}
            (None, false) => {}
            _ => return Err(UiModelError::TerminalBannerMismatch),
        }
        if state == SprintState::Completed
            && acceptance
                .iter()
                .any(|criterion| !criterion.status.is_satisfied())
        {
            return Err(UiModelError::CompletedCriteriaNotSatisfied);
        }
        Ok(Self {
            sprint_id,
            objective,
            state,
            tasks,
            workers,
            acceptance,
            activity,
            terminal,
        })
    }

    /// Sprint identifier displayed by this frame.
    #[must_use]
    pub fn sprint_id(&self) -> &str {
        &self.sprint_id
    }

    /// Original sprint objective.
    #[must_use]
    pub fn objective(&self) -> &str {
        &self.objective
    }

    /// Coordinator-owned lifecycle state.
    #[must_use]
    pub const fn state(&self) -> SprintState {
        self.state
    }

    /// Task-queue component data.
    #[must_use]
    pub fn tasks(&self) -> &[TaskCard] {
        &self.tasks
    }

    /// Worker-card component data.
    #[must_use]
    pub fn workers(&self) -> &[WorkerCard] {
        &self.workers
    }

    /// Acceptance-results component data.
    #[must_use]
    pub fn acceptance(&self) -> &[AcceptanceCard] {
        &self.acceptance
    }

    /// Honest aggregate criterion status for this exact frame.
    #[must_use]
    pub fn criteria_status(&self) -> CriteriaAggregateStatus {
        if self.acceptance.iter().any(|criterion| {
            matches!(
                criterion.status,
                AcceptanceStatus::VerificationFailed { .. }
                    | AcceptanceStatus::RejectedByYou { .. }
            )
        }) {
            CriteriaAggregateStatus::Unsatisfied
        } else if self.acceptance.iter().any(|criterion| {
            matches!(
                criterion.status,
                AcceptanceStatus::AwaitingYourDecision { .. }
            )
        }) {
            CriteriaAggregateStatus::AwaitingYourDecision
        } else if self.state == SprintState::Completed
            && self
                .acceptance
                .iter()
                .all(|criterion| criterion.status.is_satisfied())
        {
            CriteriaAggregateStatus::Satisfied
        } else {
            CriteriaAggregateStatus::Pending
        }
    }

    /// Unified activity rows.
    #[must_use]
    pub fn activity(&self) -> &[ActivityRow] {
        &self.activity
    }

    /// Terminal result component, absent while work remains active.
    #[must_use]
    pub const fn terminal(&self) -> Option<&TerminalBanner> {
        self.terminal.as_ref()
    }

    /// Returns true only when durable completion evidence produced the banner.
    #[must_use]
    pub fn is_done(&self) -> bool {
        self.terminal.as_ref().is_some_and(TerminalBanner::is_done)
    }
}

/// Rejected desktop presentation data.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum UiModelError {
    /// A visible identity, description, or reason is empty.
    MissingVisibleText(&'static str),
    /// A component identity is repeated.
    DuplicateIdentity {
        /// Component class.
        component: &'static str,
        /// Repeated identifier.
        id: String,
    },
    /// More worker cards were requested than v0.1 permits.
    WorkerLimitExceeded {
        /// Actual worker-card count.
        actual: usize,
    },
    /// A sprint frame omitted all acceptance criteria.
    MissingAcceptanceCriteria,
    /// Activity sequence cannot be represented.
    ActivitySequenceOverflow,
    /// Activity is not the exact contiguous global sequence.
    ActivitySequence {
        /// Required next sequence.
        expected: u64,
        /// Supplied sequence.
        actual: u64,
    },
    /// `Completed` lacked durable completion evidence.
    CompletionEvidenceRequired,
    /// Terminal evidence contradicted the lifecycle state.
    ContradictoryTerminalEvidence,
    /// A nonterminal state was supplied terminal evidence.
    TerminalEvidenceForActiveSprint,
    /// The banner and frame lifecycle states differ.
    TerminalBannerMismatch,
    /// A `Completed` frame contains an unbacked or unsuccessful criterion.
    CompletedCriteriaNotSatisfied,
    /// Durable completion records do not correlate exactly.
    InvalidPersistedCompletion(String),
    /// Durable non-success terminal records do not correlate exactly.
    InvalidPersistedTerminal(String),
}

impl Display for UiModelError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingVisibleText(field) => write!(formatter, "{field} must not be blank"),
            Self::DuplicateIdentity { component, id } => {
                write!(formatter, "duplicate {component} identifier `{id}`")
            }
            Self::WorkerLimitExceeded { actual } => write!(
                formatter,
                "worker card count {actual} exceeds the v0.1 limit {MAX_VISIBLE_WORKERS}"
            ),
            Self::MissingAcceptanceCriteria => {
                formatter.write_str("a sprint frame requires acceptance criteria")
            }
            Self::ActivitySequenceOverflow => formatter.write_str("activity sequence overflow"),
            Self::ActivitySequence { expected, actual } => write!(
                formatter,
                "activity sequence must be contiguous: expected {expected}, got {actual}"
            ),
            Self::CompletionEvidenceRequired => {
                formatter.write_str("Completed requires durable completion evidence")
            }
            Self::ContradictoryTerminalEvidence => {
                formatter.write_str("terminal state and evidence contradict each other")
            }
            Self::TerminalEvidenceForActiveSprint => {
                formatter.write_str("an active sprint cannot display terminal evidence")
            }
            Self::TerminalBannerMismatch => {
                formatter.write_str("terminal banner does not match the sprint lifecycle")
            }
            Self::CompletedCriteriaNotSatisfied => {
                formatter.write_str("Completed requires every criterion to be satisfied")
            }
            Self::InvalidPersistedCompletion(reason) => {
                write!(formatter, "invalid durable completion: {reason}")
            }
            Self::InvalidPersistedTerminal(reason) => {
                write!(formatter, "invalid durable terminal outcome: {reason}")
            }
        }
    }
}

impl Error for UiModelError {}

fn require_visible<'a>(
    field: &'static str,
    value: Option<&'a str>,
) -> Result<&'a str, UiModelError> {
    value
        .filter(|value| !value.trim().is_empty())
        .ok_or(UiModelError::MissingVisibleText(field))
}

fn require_unique_nonblank<'a>(
    component: &'static str,
    values: impl Iterator<Item = &'a str>,
) -> Result<(), UiModelError> {
    let mut seen = BTreeSet::new();
    for value in values {
        require_visible(component, Some(value))?;
        if !seen.insert(value) {
            return Err(UiModelError::DuplicateIdentity {
                component,
                id: value.to_owned(),
            });
        }
    }
    Ok(())
}

type TypedTerminalPresentation = (Option<UiTerminalCause>, Option<UiSafeNextAction>);

#[allow(
    clippy::too_many_lines,
    reason = "one linear presentation validator cross-correlates every independently substitutable terminal, capture, and cleanup field before exposing an action"
)]
fn validate_persisted_terminal(
    terminal: &PersistedTerminalOutcome,
) -> Result<TypedTerminalPresentation, UiModelError> {
    let invalid = |reason: &str| UiModelError::InvalidPersistedTerminal(reason.into());
    terminal
        .evidence
        .validate()
        .map_err(|error| UiModelError::InvalidPersistedTerminal(error.to_string()))?;
    terminal
        .event
        .validate()
        .map_err(|error| UiModelError::InvalidPersistedTerminal(error.to_string()))?;
    let canonical = serde_json::to_vec(&terminal.evidence)
        .map_err(|error| UiModelError::InvalidPersistedTerminal(error.to_string()))?;
    if canonical != terminal.evidence_bytes
        || Digest::sha256(&terminal.evidence_bytes) != terminal.evidence_digest
    {
        return Err(invalid(
            "terminal evidence bytes are noncanonical or have a digest mismatch",
        ));
    }
    let expected_state = match terminal.evidence.state {
        NonSuccessTerminalState::Blocked => SprintState::Blocked,
        NonSuccessTerminalState::Failed => SprintState::Failed,
        NonSuccessTerminalState::Canceled => SprintState::Canceled,
        NonSuccessTerminalState::Unknown => SprintState::Unknown,
    };
    let event_matches = matches!(
        &terminal.event.payload,
        AgentEventKind::SprintTerminalRecorded {
            record_id,
            state,
            evidence_digest,
        } if record_id == &terminal.evidence.record_id
            && *state == terminal.evidence.state
            && evidence_digest == &terminal.evidence_digest
    );
    if terminal.terminal_state != expected_state
        || terminal.event.event_id != terminal.evidence.record_id
        || terminal.event.sprint_id != terminal.evidence.sprint_id
        || terminal.event.occurred_at_unix_ms != terminal.evidence.terminal_at_unix_ms
        || !event_matches
    {
        return Err(invalid(
            "terminal state, normalized event, evidence, or sprint identity differs",
        ));
    }

    let PersistedTerminalProof::LiveStateDriftBlocked {
        proof,
        capture_evidence,
        verifier_cleanup_evidence,
    } = &terminal.proof
    else {
        return Ok((None, None));
    };
    proof
        .validate()
        .map_err(|error| UiModelError::InvalidPersistedTerminal(error.to_string()))?;
    capture_evidence
        .validate()
        .map_err(|error| UiModelError::InvalidPersistedTerminal(error.to_string()))?;
    verifier_cleanup_evidence
        .validate()
        .map_err(|error| UiModelError::InvalidPersistedTerminal(error.to_string()))?;
    let capture = &capture_evidence.receipt;
    let cleanup = &verifier_cleanup_evidence.receipt;
    let capture_bytes = serde_json::to_vec(capture_evidence)
        .map_err(|error| UiModelError::InvalidPersistedTerminal(error.to_string()))?;
    if terminal.evidence.state != NonSuccessTerminalState::Blocked
        || proof.sprint_id != terminal.evidence.sprint_id
        || proof.terminal_record_id != terminal.evidence.record_id
        || proof.terminal_evidence_digest != terminal.evidence_digest
        || proof.blocked_at_unix_ms != terminal.evidence.terminal_at_unix_ms
        || proof.capture_receipt_id != capture.receipt_id
        || proof.capture_admission_id != capture.admission_id
        || proof.capture_plan_id != capture.plan_id
        || proof.capture_plan_digest != capture.plan_digest
        || proof.capture_effect_id != capture.effect_id
        || proof.capture_observation_id != capture.observation_id
        || proof.capture_dispatch_claim_id != capture.dispatch_claim_id
        || proof.runner_launch_id != capture.runner_launch_id
        || proof.runner_session_id != capture.runner_session_id
        || proof.capture_evidence_digest != Digest::sha256(&capture_bytes)
        || proof.branch != capture.branch
        || proof.expected_snapshot != capture.expected_snapshot
        || proof.observed_snapshot != capture.observed_snapshot
        || proof.manifest_digest != capture.manifest_digest
        || proof.grant_hash != capture.grant_hash
        || proof.policy_hash != capture.policy_hash
        || proof.policy_version != capture.policy_version
        || proof.capture_started_at_unix_ms != capture.capture_started_at_unix_ms
        || proof.captured_at_unix_ms != capture.captured_at_unix_ms
        || proof.verifier_cleanup_receipt_id != cleanup.receipt_id
        || proof.sprint_id != cleanup.sprint_id
        || proof.runner_launch_id != cleanup.launch_id
        || proof.runner_session_id != cleanup.session_id
        || proof.policy_hash != cleanup.policy_hash
        || proof.grant_hash != cleanup.grant_hash
        || proof.policy_version != cleanup.policy_version
        || proof.verifier_cleaned_at_unix_ms != cleanup.cleaned_at_unix_ms
        || cleanup.worker_lease.is_some()
        || cleanup.surviving_processes != 0
        || capture_evidence.matches_expected_snapshot()
    {
        return Err(invalid(
            "live-state drift proof crosses terminal, capture, manifest, policy, or verifier cleanup authority",
        ));
    }
    Ok((
        Some(UiTerminalCause::LiveStateDrift {
            capture_receipt_id: proof.capture_receipt_id.clone(),
            expected_snapshot: proof.expected_snapshot.clone(),
            observed_snapshot: proof.observed_snapshot.clone(),
        }),
        Some(UiSafeNextAction::StartNewSprintFromObservedWorkspace),
    ))
}

#[allow(
    clippy::too_many_lines,
    reason = "the desktop success boundary deliberately rechecks the complete typed v9 finish projection"
)]
fn validate_persisted_completion(
    completion: &PersistedCompletion,
) -> Result<CompletionLiveState, UiModelError> {
    let invalid = |reason: &str| UiModelError::InvalidPersistedCompletion(reason.into());
    completion
        .receipt
        .validate()
        .map_err(|error| UiModelError::InvalidPersistedCompletion(error.to_string()))?;
    completion
        .final_report
        .validate()
        .map_err(|error| UiModelError::InvalidPersistedCompletion(error.to_string()))?;
    completion
        .event
        .validate()
        .map_err(|error| UiModelError::InvalidPersistedCompletion(error.to_string()))?;
    let AgentEventKind::CompletionRecorded(event_receipt) = &completion.event.payload else {
        return Err(invalid("terminal event is not CompletionRecorded"));
    };
    if completion.terminal_state != SprintState::Completed
        || completion.receipt.sprint_id != completion.final_report.sprint_id
        || completion.receipt.sprint_id != completion.event.sprint_id
        || completion.receipt.final_snapshot != completion.final_report.final_snapshot
        || completion.receipt.final_report_id != completion.final_report.report_id
        || completion.receipt.receipt_id != *event_receipt
        || completion.receipt.completed_at_unix_ms != completion.event.occurred_at_unix_ms
        || completion.event.task_id.is_some()
        || completion.event.worker_id.is_some()
        || completion.event.policy_hash.is_some()
        || completion.final_report.created_at_unix_ms > completion.receipt.completed_at_unix_ms
    {
        return Err(invalid(
            "receipt, report, event, snapshot, timestamp, scope, or terminal state differs",
        ));
    }

    completion
        .final_verification
        .validate()
        .map_err(|error| UiModelError::InvalidPersistedCompletion(error.to_string()))?;
    if completion.final_verification.receipt_id != completion.receipt.final_verification_receipt_id
        || completion.final_verification.sprint_id != completion.receipt.sprint_id
        || completion.final_verification.task_id.is_some()
        || completion.final_verification.snapshot_id != completion.receipt.final_snapshot
        || !completion.final_verification.passed()
        || completion.final_verification.finished_at_unix_ms
            > completion.receipt.completed_at_unix_ms
    {
        return Err(invalid(
            "final verification is not a passing sprint-wide proof on the final snapshot",
        ));
    }

    let expected_verification_ids = completion
        .receipt
        .verification_receipts
        .iter()
        .map(String::as_str)
        .collect::<Vec<_>>();
    let actual_verification_ids = completion
        .verification_evidence
        .iter()
        .map(|evidence| evidence.verification.receipt_id.as_str())
        .collect::<Vec<_>>();
    if actual_verification_ids != expected_verification_ids {
        return Err(invalid(
            "standalone or missing verification receipts are not effect-bound completion evidence",
        ));
    }

    let mut verification_by_id = BTreeMap::new();
    for evidence in &completion.verification_evidence {
        evidence
            .validate()
            .map_err(|error| UiModelError::InvalidPersistedCompletion(error.to_string()))?;
        let verification = &evidence.verification;
        if verification.sprint_id != completion.receipt.sprint_id
            || !verification.passed()
            || verification.finished_at_unix_ms > completion.receipt.completed_at_unix_ms
            || verification_by_id
                .insert(verification.receipt_id.as_str(), evidence)
                .is_some()
        {
            return Err(invalid(
                "verification evidence has a foreign sprint, failure, late timestamp, or duplicate identity",
            ));
        }
    }
    if verification_by_id
        .get(completion.receipt.final_verification_receipt_id.as_str())
        .is_none_or(|evidence| evidence.verification != completion.final_verification)
    {
        return Err(invalid(
            "final verification is not the exact effect-bound verification evidence",
        ));
    }

    let mut launch_by_id = BTreeMap::new();
    let mut previous_launch_id: Option<&str> = None;
    for launch in &completion.runner_launches {
        launch
            .validate()
            .map_err(|error| UiModelError::InvalidPersistedCompletion(error.to_string()))?;
        if launch.sprint_id != completion.receipt.sprint_id
            || launch.grant_hash != completion.receipt.grant_hash
            || launch.policy_version != completion.receipt.policy_version
            || launch.created_at_unix_ms > completion.receipt.completed_at_unix_ms
            || previous_launch_id.is_some_and(|previous| previous >= launch.launch_id.as_str())
            || launch_by_id
                .insert(launch.launch_id.as_str(), launch)
                .is_some()
        {
            return Err(invalid(
                "runner launches are not the canonical same-sprint grant-bound set",
            ));
        }
        previous_launch_id = Some(&launch.launch_id);
    }
    if launch_by_id.is_empty() {
        return Err(invalid("completion has no durable pre-spawn runner launch"));
    }

    let mut session_by_id = BTreeMap::new();
    let mut previous_session_id: Option<&str> = None;
    for session in &completion.runner_sessions {
        session
            .validate()
            .map_err(|error| UiModelError::InvalidPersistedCompletion(error.to_string()))?;
        let Some(launch) = launch_by_id.get(session.launch_id.as_str()) else {
            return Err(invalid("runner session has no exact pre-spawn launch"));
        };
        if session.sprint_id != completion.receipt.sprint_id
            || session.grant_hash != completion.receipt.grant_hash
            || session.policy_version != completion.receipt.policy_version
            || session.session_id != launch.session_id
            || session.purpose != launch.purpose
            || session.worker_id != launch.worker_id
            || session.policy_hash != launch.policy_hash
            || session.runner_binary_digest != launch.runner_binary_digest
            || session.protocol_digest != launch.protocol_digest
            || session.private_state_digest != launch.private_state_digest
            || session.registered_at_unix_ms < launch.created_at_unix_ms
            || previous_session_id.is_some_and(|previous| previous >= session.session_id.as_str())
            || session_by_id
                .insert(session.session_id.as_str(), session)
                .is_some()
        {
            return Err(invalid(
                "runner session does not exactly authenticate its launch and immutable policy",
            ));
        }
        previous_session_id = Some(&session.session_id);
    }

    for evidence in &completion.verification_evidence {
        let Some(session) = session_by_id.get(evidence.runner_session_id.as_str()) else {
            return Err(invalid("verification has no registered runner session"));
        };
        let expected_purpose = if evidence.verification.task_id.is_some() {
            RunnerSessionPurpose::TaskWorker
        } else {
            RunnerSessionPurpose::FinalVerifier
        };
        if evidence.runner_launch_id != session.launch_id
            || session.purpose != expected_purpose
            || session.policy_hash != evidence.verification.policy_hash
            || session.registered_at_unix_ms > evidence.verification.finished_at_unix_ms
        {
            return Err(invalid(
                "verification is not bound to the exact correctly scoped runner lifecycle",
            ));
        }
    }

    let actual_integration_ids = completion
        .task_integrations
        .iter()
        .map(|integration| integration.receipt_id.as_str())
        .collect::<Vec<_>>();
    let expected_integration_ids = completion
        .receipt
        .task_integration_receipt_ids
        .iter()
        .map(String::as_str)
        .collect::<Vec<_>>();
    if actual_integration_ids != expected_integration_ids {
        return Err(invalid(
            "required task IDs are not backed by the exact typed integration receipt set",
        ));
    }

    let completion_base = match &completion.application {
        PersistedCompletionApplication::Applied {
            application_evidence,
            ..
        } => &application_evidence.receipt.base_snapshot,
        PersistedCompletionApplication::VerifiedNoOp(no_op) => &no_op.base_snapshot,
    };
    let mut expected_input = completion_base;
    let mut integrated_tasks = BTreeSet::new();
    let mut ordered_integrations = completion.task_integrations.iter().collect::<Vec<_>>();
    ordered_integrations.sort_by_key(|integration| integration.integration_ordinal);
    for (ordinal, integration) in ordered_integrations.into_iter().enumerate() {
        integration
            .validate()
            .map_err(|error| UiModelError::InvalidPersistedCompletion(error.to_string()))?;
        let expected_ordinal = u32::try_from(ordinal)
            .map_err(|_| invalid("task integration ordinal does not fit u32"))?;
        let Some(session) = session_by_id.get(integration.worker_session_id.as_str()) else {
            return Err(invalid("task integration has no registered worker session"));
        };
        if integration.sprint_id != completion.receipt.sprint_id
            || integration.integration_ordinal != expected_ordinal
            || &integration.input_snapshot != expected_input
            || integration.integrated_at_unix_ms > completion.final_verification.finished_at_unix_ms
            || !integrated_tasks.insert(integration.task_id.as_str())
            || integration.worker_launch_id != session.launch_id
            || session.purpose != RunnerSessionPurpose::TaskWorker
            || session.worker_id.as_deref() != Some(integration.worker_id.as_str())
            || session.policy_hash != integration.worker_policy_hash
        {
            return Err(invalid(
                "task integration breaks its ordered snapshot, task, worker, or timestamp proof",
            ));
        }
        for verification_id in &integration.task_verification_receipt_ids {
            let Some(evidence) = verification_by_id.get(verification_id.as_str()) else {
                return Err(invalid(
                    "task integration references standalone or missing verification",
                ));
            };
            if evidence.verification.task_id.as_deref() != Some(integration.task_id.as_str())
                || evidence.verification.snapshot_id != integration.result_snapshot
                || evidence.verification.policy_hash != integration.worker_policy_hash
                || evidence.runner_launch_id != integration.worker_launch_id
                || evidence.runner_session_id != integration.worker_session_id
                || evidence.verification.finished_at_unix_ms > integration.integrated_at_unix_ms
            {
                return Err(invalid(
                    "task integration verification is not the exact passing same-session result proof",
                ));
            }
        }
        expected_input = &integration.result_snapshot;
    }
    if !completion.task_integrations.is_empty()
        && expected_input != &completion.receipt.final_snapshot
    {
        return Err(invalid(
            "typed task integration chain does not end at the final verified snapshot",
        ));
    }

    let actual_cleanup_ids = completion
        .worker_cleanup_evidence
        .iter()
        .map(|evidence| evidence.receipt.receipt_id.as_str())
        .collect::<Vec<_>>();
    let expected_cleanup_ids = completion
        .receipt
        .worker_cleanup_receipt_ids
        .iter()
        .map(String::as_str)
        .collect::<Vec<_>>();
    if actual_cleanup_ids != expected_cleanup_ids
        || completion.worker_cleanup_evidence.len() != completion.runner_launches.len()
    {
        return Err(invalid(
            "cleanup receipts are not the canonical exact launch-attempt set",
        ));
    }
    let mut cleanup_by_launch = BTreeMap::new();
    for evidence in &completion.worker_cleanup_evidence {
        evidence
            .validate()
            .map_err(|error| UiModelError::InvalidPersistedCompletion(error.to_string()))?;
        let cleanup = &evidence.receipt;
        let Some(launch) = launch_by_id.get(cleanup.launch_id.as_str()) else {
            return Err(invalid("cleanup receipt has no matching runner launch"));
        };
        let backend_matches = match launch.purpose {
            RunnerSessionPurpose::Applier => matches!(
                cleanup.platform_backend,
                grok_build_core::WorkerCleanupBackend::TrustedApplierDirectChildWait
            ),
            RunnerSessionPurpose::TaskWorker
            | RunnerSessionPurpose::FinalVerifier
            | RunnerSessionPurpose::LiveStateVerifier => matches!(
                cleanup.platform_backend,
                grok_build_core::WorkerCleanupBackend::MacOsDedicatedIdentity
                    | grok_build_core::WorkerCleanupBackend::LinuxCgroupV2
            ),
        };
        if cleanup.sprint_id != completion.receipt.sprint_id
            || cleanup.session_id != launch.session_id
            || cleanup.policy_hash != launch.policy_hash
            || cleanup.grant_hash != launch.grant_hash
            || cleanup.policy_version != launch.policy_version
            || cleanup.cleaned_at_unix_ms < launch.created_at_unix_ms
            || !backend_matches
            || cleanup_by_launch
                .insert(cleanup.launch_id.as_str(), cleanup)
                .is_some()
        {
            return Err(invalid(
                "cleanup evidence does not prove zero descendants for its exact launch",
            ));
        }
    }

    let authority = validate_completion_live_state_authority(
        completion,
        &launch_by_id,
        &session_by_id,
        &cleanup_by_launch,
        &invalid,
    )?;

    validate_completion_application(
        completion,
        &launch_by_id,
        &session_by_id,
        &cleanup_by_launch,
        authority,
        invalid,
    )
}

#[derive(Clone, Copy)]
enum CompletionAuthorityMode<'a> {
    Linked(&'a CompletionLiveStateCaptureLink),
    PreV24MigrationExemption,
}

#[allow(
    clippy::too_many_lines,
    reason = "the desktop independently closes every current live-state authority cross-field"
)]
fn validate_completion_live_state_authority<'a>(
    completion: &'a PersistedCompletion,
    launch_by_id: &BTreeMap<&str, &'a grok_build_core::RunnerLaunchIntent>,
    session_by_id: &BTreeMap<&str, &'a grok_build_core::RunnerSessionPolicyRecord>,
    cleanup_by_launch: &BTreeMap<&str, &'a grok_build_core::WorkerCleanupReceipt>,
    invalid: &impl Fn(&str) -> UiModelError,
) -> Result<CompletionAuthorityMode<'a>, UiModelError> {
    match &completion.live_state_authority {
        PersistedCompletionLiveStateAuthority::PreV24MigrationExemption(exemption) => {
            let receipt_digest = &completion.completion_receipt_wire_digest;
            if exemption.sprint_id != completion.receipt.sprint_id
                || exemption.completion_receipt_id != completion.receipt.receipt_id
                || exemption.completion_event_id != completion.event.event_id
                || &exemption.completion_receipt_digest != receipt_digest
                || exemption.terminal_at_unix_ms != completion.receipt.completed_at_unix_ms
                || exemption.terminal_at_unix_ms != completion.event.occurred_at_unix_ms
                || exemption.contract_version != completion.receipt.contract_version
                || exemption.marked_at_schema_version != 24
            {
                return Err(invalid(
                    "pre-v24 completion exemption does not exactly bind the immutable receipt, event, digest, time, and migration boundary",
                ));
            }
            Ok(CompletionAuthorityMode::PreV24MigrationExemption)
        }
        PersistedCompletionLiveStateAuthority::Linked {
            link,
            capture_evidence,
            verifier_cleanup_evidence,
        } => {
            link.validate()
                .map_err(|error| UiModelError::InvalidPersistedCompletion(error.to_string()))?;
            capture_evidence
                .validate()
                .map_err(|error| UiModelError::InvalidPersistedCompletion(error.to_string()))?;
            verifier_cleanup_evidence
                .validate()
                .map_err(|error| UiModelError::InvalidPersistedCompletion(error.to_string()))?;

            let receipt = &completion.receipt;
            let capture = &capture_evidence.receipt;
            let cleanup = &verifier_cleanup_evidence.receipt;
            let receipt_digest = &completion.completion_receipt_wire_digest;
            let Some(launch) = launch_by_id.get(capture.runner_launch_id.as_str()) else {
                return Err(invalid(
                    "completion capture has no exact live-state-verifier launch",
                ));
            };
            let Some(session) = session_by_id.get(capture.runner_session_id.as_str()) else {
                return Err(invalid(
                    "completion capture has no exact live-state-verifier session",
                ));
            };
            let Some(indexed_cleanup) = cleanup_by_launch.get(capture.runner_launch_id.as_str())
            else {
                return Err(invalid(
                    "completion capture has no exact selected verifier cleanup",
                ));
            };

            let branch_matches = match (&link.application, &capture.branch, &receipt.application) {
                (
                    CompletionLiveStateApplicationLink::Applied {
                        application_receipt_id,
                        rollback_reference_id,
                    },
                    grok_build_core::LiveStateCaptureBranch::Applied {
                        final_verification_receipt_id,
                        application_receipt_id: capture_application_id,
                        rollback_reference_id: capture_rollback_id,
                    },
                    CompletionApplication::Applied {
                        application_receipt_id: receipt_application_id,
                        rollback_reference_id: receipt_rollback_id,
                    },
                ) => {
                    final_verification_receipt_id == &receipt.final_verification_receipt_id
                        && application_receipt_id == capture_application_id
                        && application_receipt_id == receipt_application_id
                        && rollback_reference_id == capture_rollback_id
                        && rollback_reference_id == receipt_rollback_id
                }
                (
                    CompletionLiveStateApplicationLink::VerifiedNoOp {
                        verified_no_op_receipt_id,
                        task_integration_receipt_id,
                    },
                    grok_build_core::LiveStateCaptureBranch::VerifiedNoOp {
                        final_verification_receipt_id,
                        task_integration_receipt_id: capture_integration_id,
                    },
                    CompletionApplication::VerifiedNoOp {
                        verified_no_op_receipt_id: receipt_no_op_id,
                    },
                ) => {
                    final_verification_receipt_id == &receipt.final_verification_receipt_id
                        && verified_no_op_receipt_id == receipt_no_op_id
                        && task_integration_receipt_id == capture_integration_id
                        && receipt
                            .task_integration_receipt_ids
                            .iter()
                            .any(|id| id == task_integration_receipt_id)
                }
                _ => false,
            };

            if link.sprint_id != receipt.sprint_id
                || link.completion_receipt_id != receipt.receipt_id
                || &link.completion_receipt_digest != receipt_digest
                || link.final_snapshot != receipt.final_snapshot
                || link.grant_hash != receipt.grant_hash
                || link.policy_version != receipt.policy_version
                || link.final_verification_receipt_id != receipt.final_verification_receipt_id
                || link.completed_at_unix_ms != receipt.completed_at_unix_ms
                || link.completed_at_unix_ms != completion.event.occurred_at_unix_ms
                || link.verifier_cleaned_at_unix_ms > completion.final_report.created_at_unix_ms
                || link.capture.capture_receipt_id != capture.receipt_id
                || link.capture.admission_id != capture.admission_id
                || link.capture.plan_id != capture.plan_id
                || link.capture.plan_digest != capture.plan_digest
                || link.capture.effect_id != capture.effect_id
                || link.capture.observation_id != capture.observation_id
                || link.capture.dispatch_claim_id != capture.dispatch_claim_id
                || link.capture.runner_launch_id != capture.runner_launch_id
                || link.capture.runner_session_id != capture.runner_session_id
                || link.capture.expected_snapshot != capture.expected_snapshot
                || link.capture.observed_snapshot != capture.observed_snapshot
                || link.capture.manifest_digest != capture.manifest_digest
                || link.capture_started_at_unix_ms != capture.capture_started_at_unix_ms
                || link.captured_at_unix_ms != capture.captured_at_unix_ms
                || link.final_snapshot != capture.expected_snapshot
                || capture.expected_snapshot != capture.observed_snapshot
                || capture.observed_snapshot != capture.manifest_digest
                || capture.manifest_digest != capture_evidence.manifest.manifest_digest
                || link.grant_hash != capture.grant_hash
                || link.policy_hash != capture.policy_hash
                || link.policy_version != capture.policy_version
                || link.verifier_cleanup_receipt_id != cleanup.receipt_id
                || link.verifier_cleaned_at_unix_ms != cleanup.cleaned_at_unix_ms
                || cleanup != *indexed_cleanup
                || cleanup.launch_id != launch.launch_id
                || cleanup.session_id != session.session_id
                || cleanup.policy_hash != link.policy_hash
                || cleanup.grant_hash != link.grant_hash
                || cleanup.policy_version != link.policy_version
                || launch.session_id != session.session_id
                || launch.purpose != RunnerSessionPurpose::LiveStateVerifier
                || session.purpose != RunnerSessionPurpose::LiveStateVerifier
                || launch.policy_hash != link.policy_hash
                || session.policy_hash != link.policy_hash
                || launch.grant_hash != link.grant_hash
                || session.grant_hash != link.grant_hash
                || launch.policy_version != link.policy_version
                || session.policy_version != link.policy_version
                || !branch_matches
            {
                return Err(invalid(
                    "current completion live-state authority crosses its receipt, branch, capture, verifier, cleanup, snapshot, policy, digest, or timestamp",
                ));
            }

            for (launch_id, prior_cleanup) in cleanup_by_launch {
                if *launch_id != capture.runner_launch_id.as_str()
                    && prior_cleanup.cleaned_at_unix_ms > link.capture_started_at_unix_ms
                {
                    return Err(invalid(
                        "plan-prior runner cleanup occurs after the selected capture began",
                    ));
                }
            }
            Ok(CompletionAuthorityMode::Linked(link))
        }
    }
}

fn validate_completion_application<'a>(
    completion: &'a PersistedCompletion,
    launch_by_id: &BTreeMap<&str, &'a grok_build_core::RunnerLaunchIntent>,
    session_by_id: &BTreeMap<&str, &'a grok_build_core::RunnerSessionPolicyRecord>,
    cleanup_by_launch: &BTreeMap<&str, &'a grok_build_core::WorkerCleanupReceipt>,
    authority: CompletionAuthorityMode<'a>,
    invalid: impl Fn(&str) -> UiModelError,
) -> Result<CompletionLiveState, UiModelError> {
    let evidence = CompletionApplicationEvidence {
        completion,
        launch_by_id,
        session_by_id,
        cleanup_by_launch,
    };
    match (&completion.receipt.application, &completion.application) {
        (
            CompletionApplication::Applied {
                application_receipt_id,
                rollback_reference_id,
            },
            PersistedCompletionApplication::Applied {
                application_evidence,
                rollback_reference,
            },
        ) => validate_applied_completion(
            &evidence,
            application_receipt_id,
            rollback_reference_id,
            application_evidence,
            rollback_reference,
            authority,
            &invalid,
        ),
        (
            CompletionApplication::VerifiedNoOp {
                verified_no_op_receipt_id,
            },
            PersistedCompletionApplication::VerifiedNoOp(no_op),
        ) => validate_no_op_completion(
            &evidence,
            verified_no_op_receipt_id,
            no_op,
            authority,
            &invalid,
        ),
        _ => Err(invalid(
            "completion receipt and persisted applied/no-op branches contradict each other",
        )),
    }
}

struct CompletionApplicationEvidence<'completion, 'index> {
    completion: &'completion PersistedCompletion,
    launch_by_id:
        &'index BTreeMap<&'completion str, &'completion grok_build_core::RunnerLaunchIntent>,
    session_by_id:
        &'index BTreeMap<&'completion str, &'completion grok_build_core::RunnerSessionPolicyRecord>,
    cleanup_by_launch:
        &'index BTreeMap<&'completion str, &'completion grok_build_core::WorkerCleanupReceipt>,
}

#[allow(clippy::too_many_lines)] // Audits the complete linked application/capture/cleanup proof in one view.
fn validate_applied_completion(
    evidence: &CompletionApplicationEvidence<'_, '_>,
    application_receipt_id: &str,
    rollback_reference_id: &str,
    application_evidence: &ApplicationEvidence,
    rollback_reference: &grok_build_core::RollbackReferenceEvidence,
    authority: CompletionAuthorityMode<'_>,
    invalid: &impl Fn(&str) -> UiModelError,
) -> Result<CompletionLiveState, UiModelError> {
    application_evidence
        .validate()
        .map_err(|error| UiModelError::InvalidPersistedCompletion(error.to_string()))?;
    rollback_reference
        .validate()
        .map_err(|error| UiModelError::InvalidPersistedCompletion(error.to_string()))?;
    let completion = evidence.completion;
    let application_receipt = &application_evidence.receipt;
    let validation = &application_evidence.validation;
    let reference = &rollback_reference.reference;
    let Some(executor) = evidence
        .session_by_id
        .get(application_receipt.applier_session_id.as_str())
    else {
        return Err(invalid("application has no registered applier session"));
    };
    let Some(validator) = evidence
        .session_by_id
        .get(validation.runner_session_id.as_str())
    else {
        return Err(invalid(
            "application validation has no registered applier session",
        ));
    };
    if application_receipt.receipt_id != application_receipt_id
        || reference.reference_id != rollback_reference_id
        || application_receipt.sprint_id != completion.receipt.sprint_id
        || application_receipt.result_snapshot != completion.receipt.final_snapshot
        || application_receipt.grant_hash != completion.receipt.grant_hash
        || application_receipt.policy_version != completion.receipt.policy_version
        || application_receipt.applied_at_unix_ms
            < completion.final_verification.finished_at_unix_ms
        || reference.sprint_id != completion.receipt.sprint_id
        || reference.application_receipt_id != application_receipt.receipt_id
        || reference.transaction_id != application_receipt.transaction_id
        || reference.base_snapshot != application_receipt.base_snapshot
        || reference.journal_binding_digest
            != application_receipt
                .journal_binding_digest()
                .map_err(|error| UiModelError::InvalidPersistedCompletion(error.to_string()))?
        || reference.validated_at_unix_ms < application_receipt.applied_at_unix_ms
        || reference.validated_at_unix_ms > completion.receipt.completed_at_unix_ms
        || !application_validation_authority_matches(application_evidence, executor, validator)
    {
        return Err(invalid(
            "applied completion does not match its final snapshot, applier, grant, or reopened rollback journal",
        ));
    }

    if let CompletionAuthorityMode::Linked(link) = authority
        && (link.application
            != (CompletionLiveStateApplicationLink::Applied {
                application_receipt_id: application_receipt_id.to_owned(),
                rollback_reference_id: rollback_reference_id.to_owned(),
            })
            || application_receipt.applied_at_unix_ms > link.capture_started_at_unix_ms
            || reference.validated_at_unix_ms > link.capture_started_at_unix_ms)
    {
        return Err(invalid(
            "current applied completion differs from its capture branch or pre-capture application cut",
        ));
    }

    for launch in evidence.launch_by_id.values() {
        let cleanup = evidence
            .cleanup_by_launch
            .get(launch.launch_id.as_str())
            .ok_or_else(|| invalid("application launch has no cleanup proof"))?;
        let ordered = match authority {
            CompletionAuthorityMode::Linked(link) => match launch.purpose {
                RunnerSessionPurpose::LiveStateVerifier
                    if launch.launch_id == link.capture.runner_launch_id =>
                {
                    cleanup.receipt_id == link.verifier_cleanup_receipt_id
                        && link.captured_at_unix_ms <= cleanup.cleaned_at_unix_ms
                        && cleanup.cleaned_at_unix_ms <= completion.receipt.completed_at_unix_ms
                }
                RunnerSessionPurpose::LiveStateVerifier => {
                    application_receipt.applied_at_unix_ms <= cleanup.cleaned_at_unix_ms
                        && cleanup.cleaned_at_unix_ms <= link.capture_started_at_unix_ms
                }
                RunnerSessionPurpose::Applier if launch.launch_id == validator.launch_id => {
                    application_receipt.applied_at_unix_ms <= cleanup.cleaned_at_unix_ms
                        && reference.validated_at_unix_ms <= cleanup.cleaned_at_unix_ms
                        && cleanup.cleaned_at_unix_ms <= link.capture_started_at_unix_ms
                }
                RunnerSessionPurpose::Applier if launch.launch_id == executor.launch_id => {
                    application_receipt.applied_at_unix_ms <= cleanup.cleaned_at_unix_ms
                        && cleanup.cleaned_at_unix_ms <= link.capture_started_at_unix_ms
                }
                RunnerSessionPurpose::TaskWorker
                | RunnerSessionPurpose::FinalVerifier
                | RunnerSessionPurpose::Applier => {
                    cleanup.cleaned_at_unix_ms <= application_receipt.applied_at_unix_ms
                }
            },
            CompletionAuthorityMode::PreV24MigrationExemption => match launch.purpose {
                RunnerSessionPurpose::Applier if launch.launch_id == validator.launch_id => {
                    application_receipt.applied_at_unix_ms <= cleanup.cleaned_at_unix_ms
                        && reference.validated_at_unix_ms <= cleanup.cleaned_at_unix_ms
                        && cleanup.cleaned_at_unix_ms <= completion.receipt.completed_at_unix_ms
                }
                RunnerSessionPurpose::Applier if launch.launch_id == executor.launch_id => {
                    application_receipt.applied_at_unix_ms <= cleanup.cleaned_at_unix_ms
                        && cleanup.cleaned_at_unix_ms <= completion.receipt.completed_at_unix_ms
                }
                RunnerSessionPurpose::TaskWorker
                | RunnerSessionPurpose::FinalVerifier
                | RunnerSessionPurpose::LiveStateVerifier
                | RunnerSessionPurpose::Applier => {
                    cleanup.cleaned_at_unix_ms <= application_receipt.applied_at_unix_ms
                }
            },
        };
        if !ordered {
            return Err(invalid(
                "runner cleanup ordering contradicts application and rollback validation",
            ));
        }
    }
    Ok(CompletionLiveState::Applied {
        rollback_target: reference.base_snapshot.clone(),
        rollback_reference_id: reference.reference_id.clone(),
    })
}

fn application_validation_authority_matches(
    evidence: &ApplicationEvidence,
    executor: &grok_build_core::RunnerSessionPolicyRecord,
    validator: &grok_build_core::RunnerSessionPolicyRecord,
) -> bool {
    let application = &evidence.receipt;
    let validation = &evidence.validation;
    let lifecycle_shape = match validation.mode {
        ApplicationValidationMode::DirectEffectResponse => {
            validator.launch_id == executor.launch_id && validator.session_id == executor.session_id
        }
        ApplicationValidationMode::RecoveryApplierReconciliation => {
            validator.launch_id != executor.launch_id && validator.session_id != executor.session_id
        }
    };
    executor.purpose == RunnerSessionPurpose::Applier
        && executor.policy_hash == application.policy_hash
        && executor.grant_hash == application.grant_hash
        && executor.policy_version == application.policy_version
        && executor.registered_at_unix_ms <= application.applied_at_unix_ms
        && validator.purpose == RunnerSessionPurpose::Applier
        && validator.launch_id == validation.runner_launch_id
        && validator.policy_hash == validation.policy_hash
        && validator.grant_hash == validation.grant_hash
        && validator.policy_version == validation.policy_version
        && validator.private_state_digest == validation.private_state_digest
        && validator.policy_hash == executor.policy_hash
        && validator.grant_hash == executor.grant_hash
        && validator.policy_version == executor.policy_version
        && validator.private_state_digest == executor.private_state_digest
        && validator.runner_binary_digest == executor.runner_binary_digest
        && validator.protocol_digest == executor.protocol_digest
        && validator.registered_at_unix_ms <= application.applied_at_unix_ms
        && lifecycle_shape
}

fn validate_no_op_completion(
    evidence: &CompletionApplicationEvidence<'_, '_>,
    verified_no_op_receipt_id: &str,
    no_op: &grok_build_core::VerifiedNoOpReceipt,
    authority: CompletionAuthorityMode<'_>,
    invalid: &impl Fn(&str) -> UiModelError,
) -> Result<CompletionLiveState, UiModelError> {
    no_op
        .validate()
        .map_err(|error| UiModelError::InvalidPersistedCompletion(error.to_string()))?;
    let completion = evidence.completion;
    if no_op.receipt_id != verified_no_op_receipt_id
        || no_op.sprint_id != completion.receipt.sprint_id
        || no_op.final_verification_receipt_id != completion.receipt.final_verification_receipt_id
        || no_op.base_snapshot != completion.receipt.final_snapshot
        || no_op.grant_hash != completion.receipt.grant_hash
        || no_op.policy_version != completion.receipt.policy_version
        || no_op.observed_at_unix_ms < completion.final_verification.finished_at_unix_ms
        || no_op.observed_at_unix_ms > completion.receipt.completed_at_unix_ms
    {
        return Err(invalid(
            "verified no-op does not prove the exact live base for the completion receipt",
        ));
    }
    match authority {
        CompletionAuthorityMode::Linked(link) => {
            let CompletionLiveStateApplicationLink::VerifiedNoOp {
                verified_no_op_receipt_id: linked_no_op_id,
                task_integration_receipt_id,
            } = &link.application
            else {
                return Err(invalid(
                    "current verified no-op completion has an Applied live-state branch",
                ));
            };
            if linked_no_op_id != verified_no_op_receipt_id
                || !completion
                    .receipt
                    .task_integration_receipt_ids
                    .iter()
                    .any(|id| id == task_integration_receipt_id)
                || no_op.observed_at_unix_ms != link.captured_at_unix_ms
                || no_op.live_manifest_digest != link.capture.manifest_digest
                || no_op.live_manifest_digest != completion.receipt.final_snapshot
                || completion.final_verification.finished_at_unix_ms
                    > link.capture_started_at_unix_ms
                || evidence.cleanup_by_launch.values().any(|cleanup| {
                    if cleanup.receipt_id == link.verifier_cleanup_receipt_id {
                        cleanup.launch_id != link.capture.runner_launch_id
                            || cleanup.session_id != link.capture.runner_session_id
                            || cleanup.cleaned_at_unix_ms < link.captured_at_unix_ms
                    } else {
                        cleanup.cleaned_at_unix_ms > link.capture_started_at_unix_ms
                    }
                })
            {
                return Err(invalid(
                    "current verified no-op does not exactly follow its capture and selected verifier cleanup",
                ));
            }
        }
        CompletionAuthorityMode::PreV24MigrationExemption => {
            if evidence
                .cleanup_by_launch
                .values()
                .any(|cleanup| cleanup.cleaned_at_unix_ms > no_op.observed_at_unix_ms)
            {
                return Err(invalid(
                    "historical verified no-op does not follow every runner cleanup",
                ));
            }
        }
    }
    Ok(CompletionLiveState::VerifiedNoOp {
        live_snapshot: no_op.live_manifest_digest.clone(),
    })
}

#[cfg(test)]
mod tests;
