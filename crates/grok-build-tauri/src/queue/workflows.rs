//! Typed workflow queue identity. Text cannot turn an ordinary chat into a script.
use super::{EnqueueRequest, QueueCoordinator, QueueItem, enqueue_in_book};
use serde::{Deserialize, Serialize};

pub(super) fn require_chat_run(
    book: &super::QueueBook,
    item_id: &crate::contracts::QueueItemId,
) -> Result<(), String> {
    if book
        .items
        .iter()
        .any(|item| item.id == *item_id && item.workflow.is_some())
    {
        return Err(
            "Workflow inputs are fixed. Stop this workflow or queue a separate chat turn.".into(),
        );
    }
    Ok(())
}

#[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct WorkflowTicket {
    pub(crate) job_id: String,
    pub(crate) attempt: u16,
}
impl WorkflowTicket {
    pub(crate) fn validate(&self) -> Result<(), String> {
        if !crate::extensions::valid_digest(&self.job_id) || !(1..=32).contains(&self.attempt) {
            return Err("Workflow ticket identity or explicit attempt limit is invalid.".into());
        }
        Ok(())
    }
}
impl QueueCoordinator {
    pub(crate) fn workflow_attempt_pending(
        &self,
        project: &crate::contracts::ProjectId,
        ticket: &WorkflowTicket,
    ) -> Result<bool, String> {
        ticket.validate()?;
        self.read(|book| {
            Ok(book.items.iter().any(|item| {
                item.project_id == *project
                    && item.workflow.as_ref() == Some(ticket)
                    && matches!(
                        item.state,
                        super::QueueItemState::Queued | super::QueueItemState::Running
                    )
            }))
        })
    }

    pub(crate) fn stop_workflow(
        &self,
        project: &crate::contracts::ProjectId,
        ticket: &WorkflowTicket,
        run: &crate::contracts::RunId,
    ) -> Result<(), String> {
        self.mutate(|book| {
            let record = book
                .runs
                .iter_mut()
                .find(|record| {
                    record.id == *run && record.project_id == *project && record.state.active()
                })
                .ok_or("This exact workflow run is no longer active.")?;
            if !book.items.iter().any(|item| {
                item.id == record.queue_item_id && item.workflow.as_ref() == Some(ticket)
            }) {
                return Err("Workflow stop refused a changed queue binding.".into());
            }
            record.state = super::RunState::StopRequested;
            Ok(())
        })?;
        self.cancel_run_ids(std::slice::from_ref(run))
    }
    pub(crate) fn enqueue_workflow(
        &self,
        request: EnqueueRequest,
        ticket: WorkflowTicket,
    ) -> Result<QueueItem, String> {
        ticket.validate()?;
        self.mutate(|book| {
            if book
                .items
                .iter()
                .any(|item| item.workflow.as_ref() == Some(&ticket))
            {
                return Err("This exact workflow attempt is already queued or retained.".into());
            }
            let mut item = enqueue_in_book(book, request)?;
            item.workflow = Some(ticket);
            *book
                .items
                .last_mut()
                .ok_or("Workflow queue insertion is unavailable.")? = item.clone();
            Ok(item)
        })
    }
}
