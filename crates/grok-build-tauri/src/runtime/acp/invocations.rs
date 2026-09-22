//! Durable ACP invocation identities. No provider-supplied project authority.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::owner_state::OwnerStateRoot;

#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct ToolInvocationScope {
    provider_session: String,
    connection: String,
    workspace: PathBuf,
    app: crate::runtime::types::RuntimeInvocationScope,
    catalog_digest: String,
}

#[derive(Deserialize, Serialize)]
#[serde(tag = "status", rename_all = "snake_case", deny_unknown_fields)]
enum Entry {
    Intent {
        digest: String,
    },
    Completed {
        digest: String,
        output: Option<Value>,
    },
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct InvocationJournal {
    schema_version: u16,
    scope: ToolInvocationScope,
    entries: BTreeMap<String, Entry>,
    #[serde(skip)]
    root: PathBuf,
}

impl InvocationJournal {
    pub(super) fn new(
        root: &Path,
        provider_session: &str,
        connection: &str,
        workspace: &Path,
        app: &crate::runtime::types::RuntimeInvocationScope,
        catalog: &Value,
    ) -> Result<Self, String> {
        app.validate()?;
        let journal = Self {
            schema_version: 2,
            scope: ToolInvocationScope {
                provider_session: provider_session.into(),
                connection: connection.into(),
                workspace: workspace.into(),
                app: app.clone(),
                catalog_digest: grok_build_plus_host::worktree_recovery_digest(
                    catalog.to_string().as_bytes(),
                ),
            },
            entries: BTreeMap::new(),
            root: root.join("invocations").join(connection),
        };
        for name in ["calls-v1.json", "calls-v2.json"] {
            let file = OwnerStateRoot::new(&journal.root)
                .file(name, 8 * 1024 * 1024)
                .map_err(|e| e.to_string())?;
            if file.read().map_err(|e| e.to_string())?.is_some() {
                return Err(
                    "ACP connection invocation identity was reused; execution refused.".into(),
                );
            }
        }
        journal.persist()?;
        Ok(journal)
    }

    pub(super) fn intent(&mut self, key: &str, digest: &str) -> Result<Option<Value>, String> {
        if let Some(previous) = self.entries.get(key) {
            return match previous {
                Entry::Completed { digest:saved,output:Some(output) } if saved == digest => Ok(Some(output.clone())),
                _ => Err("ACP invocation is uncertain, transient, or changed; its effect cannot be repeated.".into()),
            };
        }
        if self.entries.len() >= 64 {
            return Err("ACP invocation journal exceeded its bounded run budget.".into());
        }
        self.entries.insert(
            key.into(),
            Entry::Intent {
                digest: digest.into(),
            },
        );
        self.persist()?;
        Ok(None)
    }
    pub(super) fn complete(
        &mut self,
        key: &str,
        digest: &str,
        output: &Value,
        transient: bool,
    ) -> Result<(), String> {
        if !matches!(self.entries.get(key),Some(Entry::Intent {digest:saved}) if saved == digest) {
            return Err("ACP tool result has no matching durable invocation intent.".into());
        }
        self.entries.insert(
            key.into(),
            Entry::Completed {
                digest: digest.into(),
                output: (!transient).then(|| output.clone()),
            },
        );
        self.persist()
    }
    fn persist(&self) -> Result<(), String> {
        OwnerStateRoot::new(&self.root)
            .file("calls-v2.json", 8 * 1024 * 1024)
            .map_err(|e| e.to_string())?
            .replace(&serde_json::to_vec(self).map_err(|e| e.to_string())?)
            .map_err(|e| e.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    #[test]
    fn durable_invocation_refuses_uncertain_replay_and_never_saves_transient_output() {
        let root = std::env::temp_dir().join(format!(
            "gbplus-invocations-{}-{}",
            std::process::id(),
            crate::runtime::types::unix_time_millis()
        ));
        let mut journal = InvocationJournal::new(
            &root,
            "provider",
            "connection",
            Path::new("/workspace"),
            &crate::runtime::types::RuntimeInvocationScope::fixture(),
            &json!(["read_file"]),
        )
        .unwrap();
        assert_eq!(journal.intent("call-one", "digest-one").unwrap(), None);
        assert!(journal.intent("call-one", "digest-one").is_err());
        let output = json!({"result":"ordinary result"});
        journal
            .complete("call-one", "digest-one", &output, false)
            .unwrap();
        assert_eq!(
            journal.intent("call-one", "digest-one").unwrap(),
            Some(output)
        );
        assert!(journal.intent("call-one", "changed").is_err());
        journal.intent("high-power", "digest-two").unwrap();
        journal
            .complete(
                "high-power",
                "digest-two",
                &json!({"result":"TRANSIENT PRIVATE DATA"}),
                true,
            )
            .unwrap();
        assert!(journal.intent("high-power", "digest-two").is_err());
        let saved = std::fs::read_to_string(journal.root.join("calls-v2.json")).unwrap();
        assert!(!saved.contains("TRANSIENT PRIVATE DATA"));
        let value: Value = serde_json::from_str(&saved).unwrap();
        assert_eq!(value["scope"]["app"]["projectId"], "fixture-project");
        assert_eq!(value["scope"]["app"]["runId"], "fixture-run");
        assert_eq!(value["scope"]["app"]["sessionId"], "fixture-session");
        assert!(
            InvocationJournal::new(
                &root,
                "other-provider",
                "connection",
                Path::new("/different"),
                &crate::runtime::types::RuntimeInvocationScope::fixture(),
                &json!([])
            )
            .is_err()
        );
        std::fs::remove_dir_all(root).unwrap();
    }
}
