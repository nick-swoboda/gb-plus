//! Explicit per-project opt-in; absence and unknown versions grant no authority.
use crate::contracts::ProjectId;
use crate::owner_state::{OwnerStateFile, OwnerStateRoot};
use serde::{Deserialize, Serialize};
use std::path::Path;

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct AgentSettings {
    version: u16,
    project_id: ProjectId,
    pub(crate) enabled: bool,
}
impl AgentSettings {
    pub(crate) fn load(state: &Path, project: &ProjectId) -> Result<Self, String> {
        let settings = match file(state, project)?.read().map_err(|e| e.to_string())? {
            None => Self {
                version: 1,
                project_id: project.clone(),
                enabled: false,
            },
            Some(bytes) => serde_json::from_slice(&bytes)
                .map_err(|_| "Agent settings remain unreadable and disabled.")?,
        };
        if settings.version != 1 || settings.project_id != *project {
            return Err(
                "Agent settings have an unknown version or changed project identity.".into(),
            );
        }
        Ok(settings)
    }
    pub(crate) fn set(state: &Path, project: &ProjectId, enabled: bool) -> Result<Self, String> {
        let mut settings = Self::load(state, project)?;
        settings.enabled = enabled;
        file(state, project)?
            .replace(&serde_json::to_vec(&settings).map_err(|e| e.to_string())?)
            .map_err(|e| e.to_string())?;
        Ok(settings)
    }
}
fn file(state: &Path, project: &ProjectId) -> Result<OwnerStateFile, String> {
    if project.as_str().is_empty()
        || project.as_str().len() > 256
        || project.as_str().chars().any(char::is_control)
    {
        return Err("Agent project identity is invalid.".into());
    }
    OwnerStateRoot::new(state.join("agent-settings-v1"))
        .file(
            format!(
                "{}.json",
                grok_build_plus_host::worktree_recovery_digest(project.as_str().as_bytes())
            ),
            4 * 1024,
        )
        .map_err(|e| e.to_string())
}
