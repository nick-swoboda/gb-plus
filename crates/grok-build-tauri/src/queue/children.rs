//! Atomic app-issued child identities. Provider fields never supply workspace authority.
use super::{
    Deserialize, MAX_GLOBAL_RUNS, MAX_ID_BYTES, Ordering, ProjectId, QueueBook, QueueCoordinator,
    QueueItemState, RunId, RunRecord, RunState, RuntimeCancelHandle, RuntimeTransport, Serialize,
    SessionId, WorkspaceId, active_project_ids, active_run_count, new_id, unix_time_millis,
};
use grok_build_plus_host::{PlusChildRole, PlusExecutionMember, PlusExecutionState};

const MAX_CHILD_RECORDS: usize = 1_024;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum ChildState {
    Waiting,
    Running,
    StopRequested,
    Done,
    NeedsReview,
    Failed,
    Stopped,
    Interrupted,
}

impl ChildState {
    pub(crate) const fn active(self) -> bool {
        matches!(self, Self::Waiting | Self::Running | Self::StopRequested)
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct ChildRecord {
    pub(crate) id: RunId,
    pub(crate) agent_id: RunId,
    pub(crate) parent: RunId,
    pub(crate) project: ProjectId,
    pub(crate) workspace: WorkspaceId,
    pub(crate) session: SessionId,
    pub(crate) role: PlusChildRole,
    pub(crate) snapshot: String,
    pub(crate) isolated: bool,
    pub(crate) transport: RuntimeTransport,
    /// Digest of the owning provider invocation, never its raw arguments.
    pub(crate) invocation: String,
    pub(crate) predecessor: Option<RunId>,
    /// A parent with ephemeral context cannot turn that data into a durable child journal.
    pub(crate) transient: bool,
    /// A Worker reserves review until its completed result proves there are no changes.
    pub(crate) review_pending: bool,
    pub(crate) state: ChildState,
    pub(crate) created_at_unix_ms: u64,
    pub(crate) ended_at_unix_ms: Option<u64>,
}

/// Issued after the controller has captured and verified its workspace. No IPC deserializer.
pub(crate) struct ChildAdmission {
    pub(crate) workspace: WorkspaceId,
    pub(crate) role: PlusChildRole,
    pub(crate) snapshot: String,
    pub(crate) isolated: bool,
    pub(crate) invocation: String,
    pub(crate) predecessor: Option<RunId>,
    pub(crate) transient: bool,
}

impl QueueCoordinator {
    pub(crate) fn configure_family(
        &self,
        parent: &RunId,
        workflow: Option<String>,
        maximum: u16,
    ) -> Result<(), String> {
        self.mutate(|book| {
            running_parent(book, parent)?;
            book.executions.configure_family(parent, workflow, maximum)
        })
    }

    // Only a runtime tool-continuation boundary may call this operation.
    pub(crate) fn yield_parent(&self, parent: &RunId) -> Result<(), String> {
        self.mutate(|book| {
            running_parent(book, parent)?;
            book.executions.yield_parent(parent)
        })
    }

    pub(crate) fn request_parent_resume(&self, parent: &RunId) -> Result<(), String> {
        self.mutate(|book| {
            running_parent(book, parent)?;
            let ordinal = next_order(book)?;
            book.executions.request_resume(parent, ordinal)
        })
    }

    pub(crate) fn admit_child(
        &self,
        parent: &RunId,
        admission: ChildAdmission,
        cancel: RuntimeCancelHandle,
    ) -> Result<ChildRecord, String> {
        cancel.ensure_not_cancelled()?;
        if self.lifecycle_suspended.load(Ordering::Acquire) {
            return Err("Child scheduling is suspended.".into());
        }
        let mut cancels = self
            .cancels
            .lock()
            .map_err(|_| "Child cancellation registry is unavailable.")?;
        let record = self.mutate(|book| {
            let root = running_parent(book, parent)?.clone();
            if book.children.len() >= MAX_CHILD_RECORDS || !digest(&admission.invocation)
                || book.children.iter().any(|child| child.parent == *parent && child.invocation == admission.invocation) {
                return Err("Child invocation is duplicated, malformed or exceeds retained history.".into());
            }
            let ordinal = next_order(book)?;
            let id = RunId::new(new_id("child", &[parent.as_str(), &ordinal.to_string(), &admission.invocation]));
            let (agent_id, session) = if let Some(previous_id) = &admission.predecessor {
                let previous = book.children.iter().find(|child| &child.id == previous_id).ok_or("Child continuation is unknown.")?;
                if previous.parent != *parent || previous.state.active() || previous.state == ChildState::Interrupted
                    || previous.role != admission.role || previous.workspace != admission.workspace
                    || previous.snapshot != admission.snapshot || previous.isolated != admission.isolated
                    || (previous.transient && !admission.transient)
                    || book.children.iter().any(|child| child.predecessor.as_ref() == Some(previous_id)) {
                    return Err("Child continuation changed its binding or is no longer the latest completed invocation.".into());
                }
                (previous.agent_id.clone(), previous.session.clone())
            } else {
                (id.clone(), SessionId::new(new_id("child-session", &[id.as_str()])))
            };
            let record = ChildRecord {
                id: id.clone(), agent_id, parent: parent.clone(), project: root.project_id.clone(),
                workspace: admission.workspace.clone(), session, role: admission.role,
                snapshot: admission.snapshot.clone(), isolated: admission.isolated, transport: root.transport,
                invocation: admission.invocation, predecessor: admission.predecessor, transient: admission.transient,
                review_pending: admission.role == PlusChildRole::Worker,
                state: ChildState::Waiting, created_at_unix_ms: unix_time_millis(), ended_at_unix_ms: None,
            };
            book.executions.admit_child(parent, PlusExecutionMember {
                run: id, family: parent.clone(), project: root.project_id, workspace: admission.workspace,
                role: Some(admission.role), snapshot: Some(admission.snapshot), isolated: admission.isolated,
                execution: PlusExecutionState::Waiting { ordinal },
            }, ordinal)?;
            book.children.push(record.clone());
            Ok(record)
        })?;
        cancels.insert(record.id.clone(), cancel);
        Ok(record)
    }

    pub(crate) fn try_acquire_execution(&self, run: &RunId) -> Result<bool, String> {
        if self.lifecycle_suspended.load(Ordering::Acquire)
            || crate::bounded_process::model_cleanup_pending()
        {
            return Ok(false);
        }
        let cancels = self
            .cancels
            .lock()
            .map_err(|_| "Execution cancellation registry is unavailable.")?;
        cancels
            .get(run)
            .ok_or("Execution has no app cancellation owner.")?
            .ensure_not_cancelled()?;
        self.mutate(|book| {
            if let Some(child) = book.children.iter().find(|child| &child.id == run) {
                running_parent(book, &child.parent)?;
                if child.state != ChildState::Waiting {
                    return Err("Child is not waiting for execution.".into());
                }
            } else {
                running_parent(book, run)?;
            }
            let earlier = first_admissible_root(book);
            let acquired = book.executions.try_acquire(run, earlier)?;
            if acquired && let Some(child) = book.children.iter_mut().find(|child| &child.id == run)
            {
                child.state = ChildState::Running;
            }
            Ok(acquired)
        })
    }

    pub(crate) fn child_records(&self, parent: &RunId) -> Result<Vec<ChildRecord>, String> {
        self.read(|book| {
            Ok(book
                .children
                .iter()
                .filter(|child| &child.parent == parent)
                .cloned()
                .collect())
        })
    }

    pub(crate) fn child_review_result(
        &self,
        parent: &RunId,
        child_id: &RunId,
        pending: bool,
    ) -> Result<(), String> {
        self.mutate(|book| {
            let child = book
                .children
                .iter_mut()
                .find(|child| &child.id == child_id && &child.parent == parent)
                .ok_or("Child review result has no family binding.")?;
            if pending && child.role != PlusChildRole::Worker {
                return Err("Read-only children cannot stage proposals.".into());
            }
            child.review_pending = pending;
            if pending {
                book.review_blocked_projects.insert(child.project.clone());
            }
            Ok(())
        })
    }

    pub(crate) fn reserve_child_message(
        &self,
        parent: &RunId,
        child_id: &RunId,
        transient: bool,
    ) -> Result<bool, String> {
        self.mutate(|book| {
            running_parent(book, parent)?;
            let child = book
                .children
                .iter_mut()
                .find(|child| {
                    &child.id == child_id
                        && &child.parent == parent
                        && child.state != ChildState::StopRequested
                })
                .ok_or("The child is no longer available for live steering.")?;
            let live = matches!(child.state, ChildState::Waiting | ChildState::Running);
            child.transient |= transient;
            if live {
                book.executions.reserve_child_message(parent, child_id)?;
            }
            Ok(live)
        })
    }

    pub(crate) fn finish_child(
        &self,
        parent: &RunId,
        child_id: &RunId,
        outcome: ChildState,
    ) -> Result<(), String> {
        if outcome.active() || outcome == ChildState::Interrupted {
            return Err("A live child requires a terminal outcome.".into());
        }
        let mut cancels = self
            .cancels
            .lock()
            .map_err(|_| "Child cleanup registry is unavailable.")?;
        if !cancels
            .get(child_id)
            .is_some_and(RuntimeCancelHandle::cleanup_proven)
        {
            return Err(
                "Child transport cleanup is not proven; its reservation is retained.".into(),
            );
        }
        self.mutate(|book| {
            let child = book
                .children
                .iter_mut()
                .find(|child| &child.id == child_id && &child.parent == parent)
                .ok_or("Child does not belong to this family.")?;
            if !child.state.active() {
                return Err("Child already has a terminal outcome.".into());
            }
            if matches!(outcome, ChildState::Done | ChildState::NeedsReview)
                && child.state != ChildState::Running
            {
                return Err("An unexecuted or stopped child cannot report success.".into());
            }
            book.executions.finish(child_id, true)?;
            child.state = outcome;
            child.ended_at_unix_ms = Some(unix_time_millis());
            Ok(())
        })?;
        cancels.remove(child_id);
        Ok(())
    }

    pub(crate) fn stop_child(&self, parent: &RunId, child_id: &RunId) -> Result<(), String> {
        let active = self.mutate(|book| {
            let child = book
                .children
                .iter_mut()
                .find(|child| &child.id == child_id && &child.parent == parent)
                .ok_or("No active child belongs to this family.")?;
            let active = child.state.active();
            if active {
                child.state = ChildState::StopRequested;
            }
            Ok(active)
        })?;
        if active {
            self.cancel_run_ids(std::slice::from_ref(child_id))
        } else {
            Ok(())
        }
    }
}

fn next_order(book: &mut QueueBook) -> Result<u64, String> {
    let ordinal = book.next_ordinal;
    book.next_ordinal = ordinal.checked_add(1).ok_or("Child ordering exhausted.")?;
    Ok(ordinal)
}

fn running_parent<'a>(book: &'a QueueBook, parent: &RunId) -> Result<&'a RunRecord, String> {
    book.runs
        .iter()
        .find(|run| &run.id == parent && run.state == RunState::Running)
        .ok_or("Child family is not an executing top-level run.".into())
}

pub(super) fn first_admissible_root(book: &QueueBook) -> Option<u64> {
    if active_run_count(book) >= MAX_GLOBAL_RUNS {
        return None;
    }
    let active = active_project_ids(book);
    book.items
        .iter()
        .filter(|item| {
            item.state == QueueItemState::Queued
                && item.auto_start
                && item.blocked_reason.is_none()
                && !active.contains(&item.project_id)
                && !book.paused_projects.contains(&item.project_id)
                && !book.review_blocked_projects.contains(&item.project_id)
        })
        .map(|item| item.ordinal)
        .min()
}

pub(super) fn digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

mod validation;
pub(super) use validation::validate;
#[cfg(test)]
mod tests;
