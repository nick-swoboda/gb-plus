//! Native interaction answers are bound to the still-running durable queue entry.

use super::{ProjectId, QueueCoordinator, RunId, RunState};
use crate::runtime::cli_interactions::{CliAnswer, CliInteraction, CliInteractions};

impl QueueCoordinator {
    fn cli_interactions_for(
        &self,
        project: &ProjectId,
        run: &RunId,
    ) -> Result<CliInteractions, String> {
        let cancels = self
            .cancels
            .lock()
            .map_err(|_| "Run controls are unavailable.")?;
        if !self.view().runs.iter().any(|entry| {
            entry.project_id == project.as_str()
                && entry.id == run.as_str()
                && entry.state == RunState::Running
        }) {
            return Err("The CLI run is no longer active in this project.".into());
        }
        let handle = cancels
            .get(run)
            .ok_or("The CLI run has no active connection.")?;
        handle.ensure_not_cancelled()?;
        Ok(handle.cli_interactions.clone())
    }

    pub(crate) fn pending_cli_interactions(
        &self,
        project: &ProjectId,
        run: &RunId,
    ) -> Result<Vec<CliInteraction>, String> {
        self.cli_interactions_for(project, run)?.snapshot()
    }

    pub(crate) fn answer_cli_interaction(
        &self,
        project: &ProjectId,
        run: &RunId,
        id: u64,
        answer: CliAnswer,
    ) -> Result<(), String> {
        self.cli_interactions_for(project, run)?.answer(id, answer)
    }
}
