//! Freeze only explicitly enabled hook components from immutable capsules.

use super::{ComponentKind, ExtensionStore, inspect, validate_project};
use crate::contracts::ProjectId;
use crate::extensions::hooks::config::{HookSpec, MAX_HOOKS};

impl ExtensionStore {
    pub(in crate::extensions) fn enabled_hooks(
        &self,
        project: &ProjectId,
    ) -> Result<Vec<HookSpec>, String> {
        validate_project(project)?;
        let record = self.read()?;
        let mut hooks = Vec::new();
        for selection in record
            .projects
            .get(project)
            .into_iter()
            .flat_map(|p| p.values())
        {
            let entry = record
                .entries
                .get(&selection.digest)
                .ok_or("Enabled hook content is unavailable.")?;
            if !entry.complete || !entry.installed {
                return Err("Enabled hook content is not completely installed.".into());
            }
            let bundle = self.load_bundle(&selection.digest)?;
            let preview = inspect(&bundle, entry.preview.source.clone())?;
            if !entry.preview.same_inventory(&preview) {
                return Err("Enabled hook inventory changed.".into());
            }
            for component in preview.components.iter().filter(|component| {
                selection.components.contains(&component.id)
                    && component.kind == ComponentKind::Automations
                    && component.name == "hooks"
            }) {
                if component.quarantine.is_some() {
                    return Err("An enabled hook remains quarantined.".into());
                }
                let path = if component.path == "manifest:hooks" {
                    [
                        "plugin.json",
                        ".grok-plugin/plugin.json",
                        ".claude-plugin/plugin.json",
                        ".codex-plugin/plugin.json",
                    ]
                    .into_iter()
                    .find(|path| bundle.files.contains_key(*path))
                    .ok_or("Frozen hook manifest is absent.")?
                } else {
                    &component.path
                };
                let config: serde_json::Value =
                    serde_json::from_str(bundle.text(path, 128 * 1024)?)
                        .map_err(|_| "Frozen hook configuration is malformed.")?;
                hooks.extend(crate::extensions::hooks::config::parse(
                    config
                        .get("hooks")
                        .ok_or("Frozen hook configuration omitted hooks.")?,
                    &selection.digest,
                    &component.id,
                    &bundle,
                )?);
                if hooks.len() > MAX_HOOKS {
                    return Err("A run can enable at most eight command hooks.".into());
                }
            }
        }
        Ok(hooks)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::extensions::content::{Blob, Bundle};
    use std::collections::BTreeMap;

    #[test]
    fn installation_refreshes_support_classification_without_accepting_inventory_drift() {
        let root = std::env::temp_dir().join(format!(
            "gbplus-support-refresh-{}-{}",
            std::process::id(),
            crate::runtime::types::unix_time_millis()
        ));
        let store = ExtensionStore::new(&root);
        let bundle = Bundle {
            files: BTreeMap::from([
                (
                    "plugin.json".into(),
                    Blob {
                        executable: false,
                        bytes: br#"{"name":"fixture","version":"1.0.0","license":"MIT"}"#.to_vec(),
                    },
                ),
                (
                    "LICENSE".into(),
                    Blob {
                        executable: false,
                        bytes: b"Inert license fixture".to_vec(),
                    },
                ),
                (
                    "skills/example/SKILL.md".into(),
                    Blob {
                        executable: false,
                        bytes: b"An inert skill".to_vec(),
                    },
                ),
            ]),
        };
        let preview = store.preview_bundle(&bundle, "fixture".into()).unwrap();
        let mut old = store.read().unwrap();
        old.entries
            .get_mut(&preview.digest)
            .unwrap()
            .preview
            .components[0]
            .quarantine = Some("Unsupported in the previous app".into());
        store.commit(&mut old).unwrap();
        store.install(&preview.digest).unwrap();
        let mut installed = store.read().unwrap();
        let entry = installed.entries.get_mut(&preview.digest).unwrap();
        assert!(entry.installed);
        assert!(entry.preview.components[0].quarantine.is_none());
        assert!(
            installed.projects.is_empty(),
            "A new classification must not enable a component."
        );
        installed
            .entries
            .get_mut(&preview.digest)
            .unwrap()
            .preview
            .version = "changed".into();
        store.commit(&mut installed).unwrap();
        assert!(store.install(&preview.digest).is_err());
        std::fs::remove_dir_all(root).unwrap();
    }
}
