//! Durable execution accounting shared by top-level runs and app-owned children.
//! Callers mutate a transactional clone and commit only after successful validation.
//! This book issues no process, workspace or provider authority by itself.
use crate::{ProjectId, RunId, WorkspaceId};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

/// Maximum simultaneous app-owned model execution leases.
pub const MAX_PLUS_MODEL_EXECUTIONS: usize = 2;
const MAX_FAMILIES: usize = 2;
const MAX_ENTRIES: usize = 2 * (1 + 32);

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
/// Role selected by the app for one depth-one Grok child.
pub enum PlusChildRole {
    /// Workspace reads only.
    Explore,
    /// Workspace reads with planning instructions.
    Plan,
    /// Workspace reads and staged proposals.
    Worker,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "state", rename_all = "snake_case", deny_unknown_fields)]
/// Model lease state, independently of user-visible family activity.
pub enum PlusExecutionState {
    /// One of the two global model leases is held.
    Held,
    /// The parent waits at an app-controlled continuation boundary.
    Yielded,
    /// Waiting in the shared durable order.
    Waiting {
        /// Position in the shared app scheduling order.
        ordinal: u64,
    },
    // A terminal model outcome has not yet proved transport/service cleanup.
    /// Local transport/service teardown still holds its model lease.
    Retiring,
    /// This member has completed within its still-active family.
    Terminal,
}
impl PlusExecutionState {
    fn occupies(self) -> bool {
        matches!(self, Self::Held | Self::Retiring)
    }
    fn active(self) -> bool {
        self != Self::Terminal
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
/// An app-issued member bound to one family, project and workspace.
pub struct PlusExecutionMember {
    /// Exact execution identity.
    pub run: RunId,
    /// Owning top-level run.
    pub family: RunId,
    /// App-resolved project identity.
    pub project: ProjectId,
    /// App-resolved workspace identity.
    pub workspace: WorkspaceId,
    /// None for a top-level owner; a child role otherwise.
    pub role: Option<PlusChildRole>,
    /// SHA-256 commitment to the common captured working files.
    pub snapshot: Option<String>,
    /// Verified separate-worktree admission supplied by the app.
    pub isolated: bool,
    /// Current model lease state.
    pub execution: PlusExecutionState,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
/// Immutable per-family invocation ceiling and consumed calls.
pub struct PlusFamilyBudget {
    /// Owning top-level execution.
    pub parent: RunId,
    /// Explicit workflow identity, absent for ordinary delegation.
    pub workflow: Option<String>,
    /// Invocations already consumed, including continuations.
    pub used: u16,
    /// Fixed ceiling: eight ordinary calls, or an explicit workflow ceiling up to 32.
    pub maximum: u16,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
/// Bounded active execution authority; historical results live in caller journals.
pub struct PlusExecutionBook {
    members: Vec<PlusExecutionMember>,
    budgets: Vec<PlusFamilyBudget>,
}

impl PlusExecutionBook {
    /// Whether no active family authority or retained family budget exists.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.members.is_empty() && self.budgets.is_empty()
    }

    /// Inspect all bounded members without changing their authority.
    pub fn members(&self) -> impl Iterator<Item = &PlusExecutionMember> {
        self.members.iter()
    }

    /// Count held and retiring model leases.
    #[must_use]
    pub fn held(&self) -> usize {
        self.members
            .iter()
            .filter(|entry| entry.execution.occupies())
            .count()
    }

    /// Return top-level families that still retain project serialization.
    #[must_use]
    pub fn roots(&self) -> BTreeSet<RunId> {
        self.members
            .iter()
            .filter(|m| m.role.is_none() && m.execution.active())
            .map(|m| m.run.clone())
            .collect()
    }

    /// Admit a top-level run after app authority and queue checks.
    ///
    /// # Errors
    /// Refuses invalid scope, state, capacity, ordering or unproven admission/cleanup.
    pub fn admit_parent(
        &mut self,
        run: RunId,
        project: ProjectId,
        workspace: WorkspaceId,
    ) -> Result<(), String> {
        if self.held() >= MAX_PLUS_MODEL_EXECUTIONS
            || self.roots().len() >= MAX_FAMILIES
            || self
                .members
                .iter()
                .any(|m| m.run == run || (m.project == project && m.execution.active()))
        {
            return Err("Model or project capacity is occupied.".into());
        }
        self.members.push(PlusExecutionMember {
            family: run.clone(),
            run,
            project,
            workspace,
            role: None,
            snapshot: None,
            isolated: false,
            execution: PlusExecutionState::Held,
        });
        self.validate()
    }

    /// Fix a family budget once before its first child invocation.
    ///
    /// # Errors
    /// Refuses invalid scope, state, capacity, ordering or unproven admission/cleanup.
    pub fn configure_family(
        &mut self,
        parent: &RunId,
        workflow: Option<String>,
        maximum: u16,
    ) -> Result<(), String> {
        let entry = self.member(parent)?;
        if entry.role.is_some()
            || !entry.execution.active()
            || self.budgets.iter().any(|b| &b.parent == parent)
            || (workflow.is_none() && maximum != 8)
            || !(1..=32).contains(&maximum)
            || workflow.as_ref().is_some_and(|id| {
                id.is_empty() || id.len() > 128 || id.chars().any(char::is_control)
            })
        {
            return Err("Family budget must be fixed once by the app before delegation.".into());
        }
        self.budgets.push(PlusFamilyBudget {
            parent: parent.clone(),
            workflow,
            used: 0,
            maximum,
        });
        self.validate()
    }

    // Caller has pinned and verified the common snapshot plus this child's
    // workspace. This book never treats provider-supplied paths as authority.
    /// Admit an app-resolved child after its parent yields.
    ///
    /// # Errors
    /// Refuses invalid scope, state, capacity, ordering or unproven admission/cleanup.
    pub fn admit_child(
        &mut self,
        parent: &RunId,
        mut child: PlusExecutionMember,
        ordinal: u64,
    ) -> Result<(), String> {
        let root = self.member(parent)?;
        let budget = self
            .budgets
            .iter()
            .find(|b| &b.parent == parent)
            .ok_or("Delegation is disabled.")?;
        if root.role.is_some()
            || !root.execution.active()
            || root.execution != PlusExecutionState::Yielded
            || budget.used >= budget.maximum
            || self.members.len() >= MAX_ENTRIES
            || child.run == *parent
            || child.family != *parent
            || child.project != root.project
            || child.role.is_none()
            || child.snapshot.is_none()
            || ordinal == 0
            || self.members.iter().any(|m| m.run == child.run)
            || self
                .members
                .iter()
                .any(|m| m.family == *parent && m.role.is_some() && m.snapshot != child.snapshot)
        {
            return Err("Child admission exceeds its owning family or budget.".into());
        }
        child.execution = PlusExecutionState::Waiting { ordinal };
        self.members.push(child);
        self.budgets
            .iter_mut()
            .find(|b| &b.parent == parent)
            .ok_or("Family disappeared.")?
            .used += 1;
        self.validate()
    }

    /// Reserve a possible provider continuation before steering a live child.
    ///
    /// # Errors
    /// Refuses exhausted budgets and child identities outside the active family.
    pub fn reserve_child_message(&mut self, parent: &RunId, child: &RunId) -> Result<(), String> {
        let member = self.member(child)?;
        if &member.family != parent || member.role.is_none() || !member.execution.active() {
            return Err("Child message does not own an active family invocation.".into());
        }
        let budget = self
            .budgets
            .iter_mut()
            .find(|budget| &budget.parent == parent)
            .ok_or("Child family has no invocation budget.")?;
        if budget.used >= budget.maximum {
            return Err("Child message exceeds the family invocation budget.".into());
        }
        budget.used += 1;
        self.validate()
    }

    // Yield only at a verified provider/tool continuation boundary. The caller
    // withholds the reverse-MCP result until reacquire succeeds.
    /// Yield a parent only at a verified provider/tool continuation boundary.
    ///
    /// # Errors
    /// Refuses invalid scope, state, capacity, ordering or unproven admission/cleanup.
    pub fn yield_parent(&mut self, run: &RunId) -> Result<(), String> {
        let member = self.member_mut(run)?;
        if member.role.is_some() || member.execution != PlusExecutionState::Held {
            return Err("Only an executing parent can yield.".into());
        }
        member.execution = PlusExecutionState::Yielded;
        Ok(())
    }

    /// Place a yielded parent in the shared continuation order.
    ///
    /// # Errors
    /// Refuses invalid scope, state, capacity, ordering or unproven admission/cleanup.
    pub fn request_resume(&mut self, run: &RunId, ordinal: u64) -> Result<(), String> {
        if ordinal == 0 {
            return Err("PlusExecutionState wait requires a durable order.".into());
        }
        let member = self.member_mut(run)?;
        if member.execution != PlusExecutionState::Yielded {
            return Err("Only a yielded parent may request continuation.".into());
        }
        member.execution = PlusExecutionState::Waiting { ordinal };
        self.validate()
    }

    // `earlier_top_level` is the oldest eligible top-level queue item. A parent
    // or child cannot jump over that item when another project is runnable.
    /// Acquire the next eligible model lease without bypassing earlier top-level work.
    ///
    /// # Errors
    /// Refuses invalid scope, state, capacity, ordering or unproven admission/cleanup.
    pub fn try_acquire(
        &mut self,
        run: &RunId,
        earlier_top_level: Option<u64>,
    ) -> Result<bool, String> {
        if self.held() >= MAX_PLUS_MODEL_EXECUTIONS {
            return Ok(false);
        }
        let member = self.member(run)?;
        let PlusExecutionState::Waiting { ordinal } = member.execution else {
            return Err("Model execution has no pending lease request.".into());
        };
        if earlier_top_level.is_some_and(|earlier| earlier < ordinal) {
            return Ok(false);
        }
        let next = self
            .members
            .iter()
            .filter(|m| self.eligible(m))
            .filter_map(|m| match m.execution {
                PlusExecutionState::Waiting { ordinal } => Some((ordinal, &m.run)),
                _ => None,
            })
            .min_by_key(|(n, _)| *n);
        if next.is_none_or(|(_, next)| next != run) {
            return Ok(false);
        }
        self.member_mut(run)?.execution = PlusExecutionState::Held;
        self.validate()?;
        Ok(true)
    }

    fn eligible(&self, candidate: &PlusExecutionMember) -> bool {
        if !matches!(candidate.execution, PlusExecutionState::Waiting { .. }) {
            return false;
        }
        self.members
            .iter()
            .filter(|m| {
                m.family == candidate.family && m.run != candidate.run && m.execution.occupies()
            })
            .all(|other| {
                // Concurrent model executions in one family require both children
                // to have independently verified workspaces from the same snapshot.
                if candidate.role.is_some() && other.role.is_some() {
                    candidate.isolated
                        && other.isolated
                        && candidate.workspace != other.workspace
                        && candidate.snapshot == other.snapshot
                } else {
                    // A parent's machine tools stay app-controlled. Child isolation
                    // is still required when it runs alongside its parent.
                    candidate.role.is_some_and(|_| candidate.isolated)
                        || other.role.is_some_and(|_| other.isolated)
                }
            })
    }

    /// Shared-order position of the first continuation able to acquire a lease.
    #[must_use]
    pub fn first_eligible_ordinal(&self) -> Option<u64> {
        if self.held() >= MAX_PLUS_MODEL_EXECUTIONS {
            return None;
        }
        self.members
            .iter()
            .filter(|member| self.eligible(member))
            .filter_map(|member| match member.execution {
                PlusExecutionState::Waiting { ordinal } => Some(ordinal),
                _ => None,
            })
            .min()
    }

    /// Keep a model lease while its owned transport and services stop.
    ///
    /// # Errors
    /// Refuses invalid scope, state, capacity, ordering or unproven admission/cleanup.
    pub fn retire(&mut self, run: &RunId) -> Result<(), String> {
        let member = self.member_mut(run)?;
        if !member.execution.active() {
            return Err("PlusExecutionState is already terminal.".into());
        }
        // Yielded/waiting parents have no model slot, but a closing CLI could
        // otherwise start a late continuation. Caller must first reacquire or
        // terminate and prove cleanup before invoking finish directly.
        if member.execution != PlusExecutionState::Held {
            return Err("Retirement requires the held execution lease.".into());
        }
        member.execution = PlusExecutionState::Retiring;
        Ok(())
    }

    /// Finish only after local cleanup is proven and, for parents, every child ends.
    ///
    /// # Errors
    /// Refuses invalid scope, state, capacity, ordering or unproven admission/cleanup.
    pub fn finish(&mut self, run: &RunId, cleanup_proven: bool) -> Result<(), String> {
        if !cleanup_proven {
            return Err("PlusExecutionState cleanup is not proven.".into());
        }
        let member = self.member(run)?;
        if member.role.is_none()
            && self
                .members
                .iter()
                .any(|m| m.family == *run && m.run != *run && m.execution.active())
        {
            return Err("Family remains active.".into());
        }
        if member.role.is_none() {
            // Queue and child journals retain history. This book retains only
            // authority for an active family; completed families must not consume
            // capacity forever or reset a still-active family's invocation budget.
            self.members.retain(|m| &m.family != run);
            self.budgets.retain(|b| &b.parent != run);
        } else {
            self.member_mut(run)?.execution = PlusExecutionState::Terminal;
        }
        self.validate()
    }

    /// Clear execution authority after a process restart and return interrupted IDs.
    #[must_use]
    pub fn recover_interrupted(&mut self) -> Vec<RunId> {
        let mut interrupted = Vec::new();
        for member in &mut self.members {
            if member.execution.active() {
                interrupted.push(member.run.clone());
                member.execution = PlusExecutionState::Terminal;
            }
        }
        self.members.clear();
        self.budgets.clear();
        interrupted
    }

    /// Validate capacities, isolation, families, snapshots, order and budgets.
    ///
    /// # Errors
    /// Refuses invalid scope, state, capacity, ordering or unproven admission/cleanup.
    pub fn validate(&self) -> Result<(), String> {
        let mut ids = BTreeSet::new();
        let mut waits = BTreeSet::new();
        let mut projects = std::collections::BTreeMap::new();
        let mut snapshots = std::collections::BTreeMap::new();
        if self.members.len() > MAX_ENTRIES
            || self.held() > MAX_PLUS_MODEL_EXECUTIONS
            || self.roots().len() > MAX_FAMILIES
        {
            return Err("PlusExecutionState capacity invariant failed.".into());
        }
        for m in &self.members {
            if !ids.insert(&m.run)
                || m.run.as_str().is_empty()
                || m.run.as_str().len() > 256
                || m.run.as_str().chars().any(char::is_control)
                || m.project.as_str().is_empty()
                || m.project.as_str().len() > 256
                || m.project.as_str().chars().any(char::is_control)
                || m.workspace.as_str().is_empty()
                || m.workspace.as_str().len() > 256
                || m.workspace.as_str().chars().any(char::is_control)
            {
                return Err("PlusExecutionState identity is invalid or duplicated.".into());
            }
            if m.execution.active()
                && projects
                    .insert(&m.project, &m.family)
                    .is_some_and(|family| family != &m.family)
            {
                return Err("Two unrelated families share an active project.".into());
            }
            if let PlusExecutionState::Waiting { ordinal } = m.execution
                && (ordinal == 0 || !waits.insert(ordinal))
            {
                return Err("PlusExecutionState ordering is invalid.".into());
            }
            if m.role.is_none() {
                if m.run != m.family || m.snapshot.is_some() || m.isolated || !m.execution.active()
                {
                    return Err("Parent execution identity is invalid.".into());
                }
            } else {
                let parent = self.member(&m.family)?;
                if !self.budgets.iter().any(|b| b.parent == m.family)
                    || snapshots
                        .insert(&m.family, &m.snapshot)
                        .is_some_and(|prior| prior != &m.snapshot)
                {
                    return Err("Child snapshot or budget binding changed.".into());
                }
                if parent.role.is_some()
                    || parent.project != m.project
                    || (m.isolated && m.workspace == parent.workspace)
                    || (!parent.execution.active() && m.execution.active())
                    || !m.snapshot.as_ref().is_some_and(|s| {
                        s.len() == 64
                            && s.bytes()
                                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
                    })
                {
                    return Err("Child scope or common snapshot is invalid.".into());
                }
                if m.execution.occupies() && !self.eligible_as_held(m) {
                    return Err("Concurrent family workspaces are not isolated.".into());
                }
            }
        }
        let mut parents = BTreeSet::new();
        for b in &self.budgets {
            if !parents.insert(&b.parent)
                || self.member(&b.parent)?.role.is_some()
                || b.used > b.maximum
                || b.maximum == 0
                || b.maximum > 32
                || (b.workflow.is_none() && b.maximum != 8)
                || b.workflow.as_ref().is_some_and(|id| {
                    id.is_empty() || id.len() > 128 || id.chars().any(char::is_control)
                })
                || usize::from(b.used)
                    < self
                        .members
                        .iter()
                        .filter(|m| m.role.is_some() && m.family == b.parent)
                        .count()
            {
                return Err("Family budget is invalid.".into());
            }
        }
        Ok(())
    }

    fn eligible_as_held(&self, member: &PlusExecutionMember) -> bool {
        let mut candidate = member.clone();
        candidate.execution = PlusExecutionState::Waiting { ordinal: 1 };
        self.eligible(&candidate)
    }
    /// Inspect one exact execution without changing its authority.
    ///
    /// # Errors
    /// Refuses an identity absent from this active book.
    pub fn member(&self, run: &RunId) -> Result<&PlusExecutionMember, String> {
        self.members
            .iter()
            .find(|m| &m.run == run)
            .ok_or_else(|| "Unknown execution identity.".into())
    }
    fn member_mut(&mut self, run: &RunId) -> Result<&mut PlusExecutionMember, String> {
        self.members
            .iter_mut()
            .find(|m| &m.run == run)
            .ok_or_else(|| "Unknown execution identity.".into())
    }
}

#[cfg(test)]
#[path = "plus_execution/tests.rs"]
mod tests;
