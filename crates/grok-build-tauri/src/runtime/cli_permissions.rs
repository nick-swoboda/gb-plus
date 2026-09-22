//! Per-chat CLI permission choice, separate from shared Terminal defaults.

use crate::owner_state::OwnerStateRoot;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::path::Path;

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) enum CliPermissionMode {
    #[default]
    Ask,
    AcceptEdits,
    Auto,
    AlwaysApprove,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct CliPermissionChoice {
    schema_version: u16,
    pub(crate) mode: CliPermissionMode,
}

impl Default for CliPermissionChoice {
    fn default() -> Self {
        Self {
            schema_version: 1,
            mode: CliPermissionMode::Ask,
        }
    }
}

impl CliPermissionChoice {
    pub(crate) fn load(root: &Path) -> Result<Self, String> {
        let bytes = OwnerStateRoot::new(root)
            .file("cli-permission-v1.json", 4096)
            .map_err(|e| e.to_string())?
            .read()
            .map_err(|e| e.to_string())?;
        let value: Self = bytes
            .map(|bytes| {
                serde_json::from_slice(&bytes).map_err(|_| {
                    "CLI permission settings are unreadable; retained for recovery.".to_owned()
                })
            })
            .transpose()?
            .unwrap_or_default();
        if value.schema_version != 1 {
            return Err("CLI permission settings version is unsupported.".into());
        }
        Ok(value)
    }

    pub(crate) fn save(root: &Path, mode: CliPermissionMode) -> Result<Self, String> {
        let owner = OwnerStateRoot::new(root);
        let file = owner
            .file("cli-permission-v1.json", 4096)
            .map_err(|e| e.to_string())?;
        if let Some(bytes) = file.read().map_err(|e| e.to_string())? {
            owner
                .file("cli-permission-before-change.json", 4096)
                .map_err(|e| e.to_string())?
                .replace(&bytes)
                .map_err(|e| e.to_string())?;
        }
        let choice = Self {
            mode,
            ..Self::default()
        };
        file.replace(&serde_json::to_vec(&choice).map_err(|e| e.to_string())?)
            .map_err(|e| e.to_string())?;
        Ok(choice)
    }
}

impl CliPermissionMode {
    pub(crate) fn metadata(self, value: &mut Value) {
        value["yoloMode"] = json!(self == Self::AlwaysApprove);
        value["autoMode"] = json!(self == Self::Auto);
    }
}
