//! Reconcile the two durable stores under the caller's scheduler lock.
use super::{Job, JobState};
use crate::queue::{QueueCoordinator, workflows::WorkflowTicket};
use std::path::Path;

impl Job {
    pub(crate) fn reconcile_ready(
        &mut self,
        state: &Path,
        queue: &QueueCoordinator,
    ) -> Result<(), String> {
        if self.state == JobState::Ready
            && !queue.workflow_attempt_pending(
                &self.input.project,
                &WorkflowTicket {
                    job_id: self.id.clone(),
                    attempt: self.attempt,
                },
            )?
        {
            // Covers enqueue failure, queue removal, or preflight failure. An
            // existing exact queued attempt keeps ownership even if the crash
            // preceded writing its item link into the workflow store.
            self.mutate(state, |job| {
                job.state = JobState::Interrupted;
                Ok(())
            })?;
        }
        Ok(())
    }
}
