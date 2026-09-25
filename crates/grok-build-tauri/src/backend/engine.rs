//! Engine changes are serialized with queue admission.

use super::{Backend, SnapshotSeed};
use crate::queue::QueueItemState;
use crate::runtime::engine::EngineSettings;

impl Backend {
    pub(crate) fn validate_cli_chat_run(&self, project: &str, run: &str) -> Result<(), String> {
        let context = self.operation_context()?;
        if !self.standard_engine()
            || context.project_id.as_str() != project
            || !self.queue.view().runs.iter().any(|entry| {
                entry.id == run
                    && entry.project_id == project
                    && entry.session_id == context.session_id.as_str()
            })
        {
            return Err("The CLI request belongs to another chat or worktree.".into());
        }
        Ok(())
    }

    pub(crate) fn cli_activity_scope(
        &self,
        project: &str,
    ) -> Result<
        (
            crate::runtime::acp::standard::StandardAgentPool,
            std::path::PathBuf,
        ),
        String,
    > {
        if !self.standard_engine() {
            return Err("CLI activity belongs to standard mode.".into());
        }
        let context = self.operation_context()?;
        let binding = self.model_binding(project, context.session_id.as_str())?;
        Ok((
            self.runtime.standard_agent_pool(),
            binding.root().to_owned(),
        ))
    }

    pub(crate) fn standard_engine(&self) -> bool {
        self.runtime.standard_engine()
    }

    pub(crate) fn set_engine(&mut self, settings: EngineSettings) -> Result<SnapshotSeed, String> {
        let view = self.queue.view();
        if !view.available
            || view.active_global_runs != 0
            || view
                .items
                .iter()
                .any(|item| matches!(item.state, QueueItemState::Queued | QueueItemState::Running))
        {
            return Err("Finish or remove queued work before switching engines.".into());
        }
        self.runtime.set_engine(settings)?;
        Ok(self.snapshot_seed())
    }
}

impl Backend {
    pub(crate) fn cli_permission(
        &self,
        project: &str,
        session: &str,
    ) -> Result<crate::runtime::cli_permissions::CliPermissionChoice, String> {
        if !self.standard_engine() {
            return Err("Native permissions belong to Grok CLI standard.".into());
        }
        crate::runtime::cli_permissions::CliPermissionChoice::load(
            self.model_binding(project, session)?.root(),
        )
    }
    pub(crate) fn set_cli_permission(
        &self,
        project: &str,
        session: &str,
        mode: crate::runtime::cli_permissions::CliPermissionMode,
    ) -> Result<crate::runtime::cli_permissions::CliPermissionChoice, String> {
        if !self.standard_engine() {
            return Err("Native permissions belong to Grok CLI standard.".into());
        }
        crate::runtime::cli_permissions::CliPermissionChoice::save(
            self.model_binding(project, session)?.root(),
            mode,
        )
    }
}

impl Backend {
    pub(crate) fn stage_cli_image(
        &self,
        project: &str,
        session: &str,
        bytes: Vec<u8>,
    ) -> Result<String, String> {
        let context = self.operation_context()?;
        if context.project_id.as_str() != project || context.session_id.as_str() != session {
            return Err("The image's project or chat changed.".into());
        }
        self.runtime
            .stage_cli_image(project, context.workspace_id.as_str(), session, bytes)
    }
    pub(crate) fn discard_cli_image(&self, marker: &str) -> Result<(), String> {
        self.runtime.discard_cli_image(marker)
    }
    pub(crate) fn discard_queued_cli_image(
        &self,
        item: &crate::queue::QueueItem,
    ) -> Result<(), String> {
        self.runtime.discard_queued_cli_image(item)
    }
}

#[cfg(test)]
mod tests;
