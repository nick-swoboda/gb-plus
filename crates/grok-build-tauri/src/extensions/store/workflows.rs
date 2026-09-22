//! Read enabled immutable workflow text; inventory never evaluates it.
use super::{ComponentKind, ExtensionStore, inspect, validate_project};
use crate::contracts::ProjectId;
use serde::Serialize;

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct FrozenWorkflow {
    pub(crate) extension: String,
    pub(crate) component: String,
    pub(crate) name: String,
    pub(crate) script: String,
}
impl ExtensionStore {
    pub(crate) fn enabled_workflows(
        &self,
        project: &ProjectId,
    ) -> Result<Vec<FrozenWorkflow>, String> {
        validate_project(project)?;
        let record = self.read()?;
        let mut workflows = Vec::new();
        for selection in record
            .projects
            .get(project)
            .into_iter()
            .flat_map(|p| p.values())
        {
            let entry = record
                .entries
                .get(&selection.digest)
                .ok_or("Enabled workflow content is unavailable.")?;
            if !entry.complete || !entry.installed {
                return Err("Enabled workflow content is not installed completely.".into());
            }
            let bundle = self.load_bundle(&selection.digest)?;
            let preview = inspect(&bundle, entry.preview.source.clone())?;
            if !entry.preview.same_inventory(&preview) {
                return Err("Workflow source inventory changed.".into());
            }
            for component in preview.components.iter().filter(|c| {
                selection.components.contains(&c.id)
                    && c.kind == ComponentKind::Automations
                    && std::path::Path::new(&c.path)
                        .extension()
                        .is_some_and(|ext| ext.eq_ignore_ascii_case("rhai"))
            }) {
                if component.quarantine.is_some() {
                    return Err("Enabled workflow remains quarantined.".into());
                }
                workflows.push(FrozenWorkflow {
                    extension: selection.digest.clone(),
                    component: component.id.clone(),
                    name: format!("{} / {}", preview.name, component.name),
                    script: bundle
                        .text(&component.path, grok_build_workflow::MAX_BYTES)?
                        .into(),
                });
                if workflows.len() > 32 {
                    return Err("A project can enable at most 32 workflows.".into());
                }
            }
        }
        Ok(workflows)
    }
    pub(crate) fn workflow(
        &self,
        project: &ProjectId,
        extension: &str,
        component: &str,
    ) -> Result<FrozenWorkflow, String> {
        self.enabled_workflows(project)?
            .into_iter()
            .find(|w| w.extension == extension && w.component == component)
            .ok_or("This exact workflow version is not enabled for the project.".into())
    }
}
