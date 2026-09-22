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
mod tests {
    use super::*;
    use crate::contracts::SessionId;
    use crate::queue::{EnqueueRequest, RunCompletion};
    use crate::runtime::cancel::RuntimeCancelHandle;
    use crate::runtime::types::RuntimeTransport;
    use grok_build_plus_host::PlusSessionStore;

    #[test]
    fn native_answers_require_the_selected_chat_even_inside_the_same_project() {
        let root = std::env::temp_dir().join(format!(
            "gbplus-cli-chat-scope-{}-{}",
            std::process::id(),
            crate::runtime::types::unix_time_millis()
        ));
        let workspace = root.join("project");
        std::fs::create_dir_all(&workspace).unwrap();
        let mut backend = Backend::new(PlusSessionStore::from_state_root(root.join("state")));
        backend.bind_project(workspace.to_str().unwrap()).unwrap();
        backend
            .set_engine(EngineSettings {
                mode: crate::runtime::engine::EngineMode::GrokCliStandard,
                ..Default::default()
            })
            .unwrap();
        let context = backend.operation_context().unwrap();
        for session in [context.session_id.clone(), SessionId::new("another-chat")] {
            let item = backend
                .queue
                .enqueue(EnqueueRequest {
                    project_id: context.project_id.clone(),
                    workspace_id: context.workspace_id.clone(),
                    workspace_root: context.active_root.to_string_lossy().into(),
                    session_id: session.clone(),
                    transport: RuntimeTransport::GrokCliAcp,
                    prompt: "scope fixture".into(),
                    auto_start: true,
                    retry_of_run_id: None,
                    predecessor_run_id: None,
                })
                .unwrap();
            let run = backend
                .queue
                .begin_run(&item.id, RuntimeCancelHandle::new())
                .unwrap()
                .run;
            assert_eq!(
                backend
                    .validate_cli_chat_run(context.project_id.as_str(), run.id.as_str())
                    .is_ok(),
                session == context.session_id
            );
            assert!(
                backend
                    .validate_cli_chat_run("other-project", run.id.as_str())
                    .is_err()
            );
            backend
                .queue
                .complete_run(&run.id, RunCompletion::Done)
                .unwrap();
        }
        drop(backend);
        std::fs::remove_dir_all(root).unwrap();
    }
}
