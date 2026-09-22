use super::{
    ChildRecord, ChildState, MAX_CHILD_RECORDS, MAX_ID_BYTES, PlusChildRole, PlusExecutionState,
    QueueBook, digest,
};
use std::collections::BTreeSet;

pub(in crate::queue) fn validate(book: &QueueBook) -> Result<(), String> {
    if book.children.len() > MAX_CHILD_RECORDS {
        return Err("Child journal exceeds its record bound.".into());
    }
    let mut ids = BTreeSet::new();
    let mut invocations = BTreeSet::new();
    let mut predecessors = BTreeSet::new();
    let mut active_agents = BTreeSet::new();
    for child in &book.children {
        for id in [
            child.id.as_str(),
            child.agent_id.as_str(),
            child.parent.as_str(),
            child.project.as_str(),
            child.workspace.as_str(),
            child.session.as_str(),
        ] {
            if id.is_empty() || id.len() > MAX_ID_BYTES || id.chars().any(char::is_control) {
                return Err("Invalid child journal identity.".into());
            }
        }
        if !ids.insert(&child.id)
            || book.runs.iter().any(|run| run.id == child.id)
            || !invocations.insert((&child.parent, &child.invocation))
            || !digest(&child.invocation)
            || !digest(&child.snapshot)
            || child.created_at_unix_ms == 0
            || child.state.active() == child.ended_at_unix_ms.is_some()
            || child
                .ended_at_unix_ms
                .is_some_and(|end| end < child.created_at_unix_ms)
            || (child.state == ChildState::NeedsReview && child.role != PlusChildRole::Worker)
            || (child.review_pending && child.role != PlusChildRole::Worker)
        {
            return Err("Child journal identity, result or timestamps are inconsistent.".into());
        }
        let parent = book
            .runs
            .iter()
            .find(|run| run.id == child.parent)
            .ok_or("Child journal has no retained parent.")?;
        if child.project != parent.project_id
            || child.transport != parent.transport
            || (child.isolated && child.workspace == parent.workspace_id)
            || (child.state.active()
                && (!parent.state.active() || !active_agents.insert(&child.agent_id)))
        {
            return Err(
                "Child journal changed its family, project, workspace or transport.".into(),
            );
        }
        if let Some(previous_id) = &child.predecessor {
            let previous = book
                .children
                .iter()
                .find(|previous| &previous.id == previous_id)
                .ok_or("Child continuation lost its predecessor.")?;
            if !ids.contains(previous_id)
                || !predecessors.insert(previous_id)
                || previous.id == child.id
                || previous.state.active()
                || previous.state == ChildState::Interrupted
                || previous.parent != child.parent
                || previous.agent_id != child.agent_id
                || previous.session != child.session
                || previous.role != child.role
                || previous.workspace != child.workspace
                || previous.snapshot != child.snapshot
                || previous.isolated != child.isolated
                || (previous.transient && !child.transient)
                || previous.created_at_unix_ms > child.created_at_unix_ms
                || previous
                    .ended_at_unix_ms
                    .is_none_or(|end| end > child.created_at_unix_ms)
            {
                return Err("Child continuation history changed its exact binding.".into());
            }
        } else if child.agent_id != child.id
            || book.children.iter().any(|other| {
                other.id != child.id
                    && other.predecessor.is_none()
                    && other.session == child.session
            })
        {
            return Err("A new child must own a unique agent and session identity.".into());
        }
        validate_execution(book, child, parent.state.active())?;
    }
    Ok(())
}

fn validate_execution(
    book: &QueueBook,
    child: &ChildRecord,
    parent_active: bool,
) -> Result<(), String> {
    let member = book
        .executions
        .members()
        .find(|member| member.run == child.id);
    if let Some(member) = member {
        if member.family != child.parent
            || member.project != child.project
            || member.workspace != child.workspace
            || member.role != Some(child.role)
            || member.snapshot.as_ref() != Some(&child.snapshot)
            || member.isolated != child.isolated
        {
            return Err("Child execution differs from its exact journal binding.".into());
        }
        let valid_state = match child.state {
            ChildState::Waiting => {
                matches!(member.execution, PlusExecutionState::Waiting { .. })
            }
            ChildState::Running => matches!(
                member.execution,
                PlusExecutionState::Held | PlusExecutionState::Retiring
            ),
            ChildState::StopRequested => matches!(
                member.execution,
                PlusExecutionState::Waiting { .. }
                    | PlusExecutionState::Held
                    | PlusExecutionState::Retiring
            ),
            _ => member.execution == PlusExecutionState::Terminal,
        };
        if !valid_state {
            return Err("Child journal state differs from its execution lease.".into());
        }
    } else if child.state.active() || parent_active {
        return Err("An active child family lost an execution journal binding.".into());
    }
    Ok(())
}
