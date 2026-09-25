//! Standard engine selection and project-window ownership.

use std::path::{Path, PathBuf};

use super::RuntimeManager;
use crate::runtime::acp::standard::StandardAgentPool;
use crate::runtime::engine::{EngineMode, EngineSettings};

#[derive(Clone, Default)]
pub(super) struct EngineState {
    pub(super) settings: EngineSettings,
    pub(super) workspace: Option<PathBuf>,
    pub(super) pool: StandardAgentPool,
    pub(super) images: crate::runtime::cli_images::CliImages,
    pub(super) issue: Option<String>,
}

impl EngineState {
    pub(super) fn load(root: &Path) -> Self {
        match EngineSettings::load(root) {
            Ok(settings) => Self {
                settings,
                images: crate::runtime::cli_images::CliImages::new(root),
                ..Self::default()
            },
            Err(issue) => Self {
                issue: Some(issue),
                ..Self::default()
            },
        }
    }

    pub(super) fn for_run(&self, role: grok_build_plus_host::PlusRuntimeToolPolicy) -> Self {
        if role != grok_build_plus_host::PlusRuntimeToolPolicy::Parent {
            return Self::default();
        }
        Self {
            workspace: None,
            ..self.clone()
        }
    }
}

impl RuntimeManager {
    pub(crate) fn standard_agent_pool(&self) -> StandardAgentPool {
        self.engine.pool.clone()
    }

    pub(crate) fn standard_engine(&self) -> bool {
        self.engine.settings.mode == EngineMode::GrokCliStandard
    }

    pub(crate) fn engine_settings(&self) -> EngineSettings {
        self.engine.settings.clone()
    }

    pub(crate) fn set_engine(&mut self, settings: EngineSettings) -> Result<(), String> {
        self.disconnect()?;
        settings.save(&self.state_root)?;
        self.engine.settings = settings;
        self.engine.issue = None;
        if self.standard_engine() {
            self.select(super::RuntimeTransport::GrokCliAcp)?;
        }
        Ok(())
    }

    pub(crate) fn bind_cli_workspace(&mut self, workspace: Option<&Path>) -> Result<(), String> {
        let workspace = workspace.map(Path::to_path_buf);
        if self.standard_engine()
            && self.engine.workspace.is_some()
            && self.engine.workspace != workspace
        {
            self.engine.pool.clear()?;
            self.close_adapter()?;
        }
        self.engine.workspace = workspace;
        Ok(())
    }
}

impl RuntimeManager {
    pub(crate) fn stage_cli_image(
        &self,
        project: &str,
        workspace: &str,
        session: &str,
        bytes: Vec<u8>,
    ) -> Result<String, String> {
        if !self.standard_engine()
            || !(self.engine.pool.image_input_supported()
                || self
                    .adapter
                    .as_ref()
                    .is_some_and(|adapter| adapter.image_input_supported()))
        {
            return Err(
                "The connected CLI does not advertise image input. The image was not attached."
                    .into(),
            );
        }
        self.engine.images.stage(project, workspace, session, bytes)
    }
    pub(crate) fn discard_cli_image(&self, marker: &str) -> Result<(), String> {
        self.engine.images.discard(marker)
    }
    pub(crate) fn discard_queued_cli_image(
        &self,
        item: &crate::queue::QueueItem,
    ) -> Result<(), String> {
        self.engine.images.discard_queued(item)
    }
}

#[cfg(test)]
mod tests;
