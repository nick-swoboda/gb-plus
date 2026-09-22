//! Engine preference, separate from existing Account and conversation state.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::owner_state::OwnerStateRoot;

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) enum EngineMode {
    GrokCliStandard,
    #[default]
    GbPlusContained,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct EngineSettings {
    pub(crate) schema_version: u16,
    pub(crate) mode: EngineMode,
    pub(crate) developer_cli: Option<PathBuf>,
}

impl Default for EngineSettings {
    fn default() -> Self {
        Self {
            schema_version: 1,
            mode: EngineMode::default(),
            developer_cli: None,
        }
    }
}

impl EngineSettings {
    pub(crate) fn load(root: &Path) -> Result<Self, String> {
        let file = OwnerStateRoot::new(root)
            .file("engine-v1.json", 16 * 1024)
            .map_err(|e| e.to_string())?;
        let Some(bytes) = file.read().map_err(|e| e.to_string())? else {
            return Ok(Self::default());
        };
        let settings: Self = serde_json::from_slice(&bytes)
            .map_err(|_| "Engine settings could not be read; the original file was retained.")?;
        settings.validate()?;
        Ok(settings)
    }

    pub(crate) fn save(&self, root: &Path) -> Result<(), String> {
        self.validate()?;
        let owner = OwnerStateRoot::new(root);
        let file = owner
            .file("engine-v1.json", 16 * 1024)
            .map_err(|e| e.to_string())?;
        if let Some(bytes) = file.read().map_err(|e| e.to_string())? {
            owner
                .file("engine-before-change.json", 16 * 1024)
                .map_err(|e| e.to_string())?
                .replace(&bytes)
                .map_err(|e| e.to_string())?;
        }
        file.replace(&serde_json::to_vec(self).map_err(|e| e.to_string())?)
            .map_err(|e| e.to_string())
    }

    fn validate(&self) -> Result<(), String> {
        if self.schema_version != 1 {
            return Err(
                "Unknown engine settings version; automatic execution is unavailable.".into(),
            );
        }
        if self.developer_cli.as_ref().is_some_and(|path| {
            !path.is_absolute()
                || path.file_name().is_none_or(|name| name != "xai-grok-pager")
                || path.as_os_str().len() > 4096
        }) {
            return Err(
                "Choose an absolute path to a self-built xai-grok-pager executable.".into(),
            );
        }
        Ok(())
    }
}

pub(crate) fn managed_home() -> Result<PathBuf, String> {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .filter(|home| home.is_absolute())
        .ok_or_else(|| "The user's home directory is unavailable.".into())
}

pub(crate) fn managed_cli() -> Result<PathBuf, String> {
    Ok(managed_home()?.join(".grok/bin/grok"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn contained_remains_default_and_unknown_engines_do_not_execute() {
        assert_eq!(EngineSettings::default().mode, EngineMode::GbPlusContained);
        assert!(EngineSettings::default().developer_cli.is_none());
        assert!(
            serde_json::from_str::<EngineSettings>(
                r#"{"schemaVersion":1,"mode":"futureEngine","developerCli":null}"#
            )
            .is_err()
        );
        assert!(
            EngineSettings {
                schema_version: 2,
                ..EngineSettings::default()
            }
            .validate()
            .is_err()
        );
    }

    #[test]
    fn engine_changes_keep_a_reversible_backup() {
        let root = std::env::temp_dir().join(format!(
            "gbplus-engine-{}-{}",
            std::process::id(),
            super::super::types::unix_time_millis()
        ));
        let original = EngineSettings::default();
        original.save(&root).unwrap();
        let bytes = std::fs::read(root.join("engine-v1.json")).unwrap();
        let changed = EngineSettings {
            mode: EngineMode::GrokCliStandard,
            ..original
        };
        changed.save(&root).unwrap();
        assert_eq!(
            std::fs::read(root.join("engine-before-change.json")).unwrap(),
            bytes
        );
        assert_eq!(EngineSettings::load(&root).unwrap(), changed);
        std::fs::remove_dir_all(root).unwrap();
    }
}
