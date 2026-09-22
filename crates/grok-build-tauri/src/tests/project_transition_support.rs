use grok_build_plus_host::bind_project_folder;

use crate::backend::{Backend, SnapshotSeed};

pub(crate) trait BackendProjectTransitions {
    fn switch_project(&mut self, id: &str) -> Result<SnapshotSeed, String>;
    fn remove_project(&mut self, id: &str) -> Result<SnapshotSeed, String>;
}

impl BackendProjectTransitions for Backend {
    fn switch_project(&mut self, id: &str) -> Result<SnapshotSeed, String> {
        let (projects, bound) = self
            .store
            .activate_known_project(id)
            .map_err(|error| error.to_string())?;
        let status = format!("Active project: {}", bound.folder().display());
        self.load_active_project(projects, Some(bound), status);
        Ok(self.snapshot_seed())
    }

    fn remove_project(&mut self, id: &str) -> Result<SnapshotSeed, String> {
        let projects = self
            .store
            .unlist_known_project(id)
            .map_err(|error| error.to_string())?;
        let bound = projects
            .active_id
            .as_ref()
            .and_then(|active| {
                projects
                    .projects
                    .iter()
                    .find(|project| &project.id == active)
            })
            .map(|project| bind_project_folder(project.active_root()))
            .transpose()
            .map_err(|error| error.to_string())?;
        let status = bound.as_ref().map_or_else(
            || "No active project. Choose a folder to start.".to_owned(),
            |bound| format!("Active project: {}", bound.folder().display()),
        );
        self.load_active_project(projects, bound, status);
        Ok(self.snapshot_seed())
    }
}
