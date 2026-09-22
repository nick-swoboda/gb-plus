//! Durable provider context identity, scoped to one project/workspace/chat/transport.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::contracts::{ProjectId, ProviderSessionId, SessionId, WorkspaceId};
use crate::owner_state::OwnerStateRoot;

use super::types::RuntimeTransport;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct BindingRecord {
    schema_version: u16,
    project_id: ProjectId,
    workspace_id: WorkspaceId,
    session_id: SessionId,
    transport: RuntimeTransport,
    provider_session_id: Option<ProviderSessionId>,
}

#[derive(Clone, Debug)]
pub(crate) struct ConversationBinding {
    root: PathBuf,
    record: BindingRecord,
}

impl ConversationBinding {
    pub(crate) fn open(
        state_root: &Path,
        project_id: &ProjectId,
        workspace_id: &WorkspaceId,
        session_id: &SessionId,
        transport: RuntimeTransport,
    ) -> Result<Self, String> {
        let scope = serde_json::to_vec(&(project_id, workspace_id, session_id, transport))
            .map_err(|error| error.to_string())?;
        let root = state_root
            .join("provider-contexts")
            .join(grok_build_plus_host::worktree_recovery_digest(&scope));
        let expected = BindingRecord {
            schema_version: 1,
            project_id: project_id.clone(),
            workspace_id: workspace_id.clone(),
            session_id: session_id.clone(),
            transport,
            provider_session_id: None,
        };
        let file = OwnerStateRoot::new(&root)
            .file("binding.json", 16 * 1024)
            .map_err(|e| e.to_string())?;
        let record = match file.read().map_err(|e| e.to_string())? {
            None => expected,
            Some(bytes) => {
                let record: BindingRecord = serde_json::from_slice(&bytes)
                    .map_err(|_| "Provider context binding is unreadable; the existing context was retained.")?;
                let mut identity = record.clone();
                identity.provider_session_id = None;
                if identity != expected
                    || record
                        .provider_session_id
                        .as_ref()
                        .is_some_and(|id| !valid_id(id))
                {
                    return Err(
                        "Provider context binding does not match this exact chat and transport."
                            .into(),
                    );
                }
                record
            }
        };
        Ok(Self { root, record })
    }

    pub(crate) fn root(&self) -> &Path {
        &self.root
    }

    pub(crate) fn provider_session_id(&self) -> Option<ProviderSessionId> {
        self.record.provider_session_id.clone()
    }

    pub(crate) fn reset(&mut self) -> Result<(), String> {
        let owner = OwnerStateRoot::new(&self.root);
        let bytes = serde_json::to_vec(&self.record).map_err(|error| error.to_string())?;
        owner
            .file("binding-before-reset.json", 16 * 1024)
            .map_err(|e| e.to_string())?
            .replace(&bytes)
            .map_err(|e| e.to_string())?;
        let mut next = self.record.clone();
        next.provider_session_id = None;
        owner
            .file("binding.json", 16 * 1024)
            .map_err(|e| e.to_string())?
            .replace(&serde_json::to_vec(&next).map_err(|e| e.to_string())?)
            .map_err(|e| e.to_string())?;
        self.record = next;
        Ok(())
    }

    pub(crate) fn remember(&mut self, id: &ProviderSessionId) -> Result<(), String> {
        if !valid_id(id) {
            return Err("Provider returned an invalid context identity.".into());
        }
        if self
            .record
            .provider_session_id
            .as_ref()
            .is_some_and(|existing| existing != id)
        {
            return Err(
                "Provider context changed during this chat; no replacement context was committed."
                    .into(),
            );
        }
        let mut next = self.record.clone();
        next.provider_session_id = Some(id.clone());
        let bytes = serde_json::to_vec(&next).map_err(|e| e.to_string())?;
        OwnerStateRoot::new(&self.root)
            .file("binding.json", 16 * 1024)
            .map_err(|e| e.to_string())?
            .replace(&bytes)
            .map_err(|e| e.to_string())?;
        self.record = next;
        Ok(())
    }
}

fn valid_id(id: &ProviderSessionId) -> bool {
    let value = id.as_str();
    !value.is_empty() && value.len() <= 512 && !value.chars().any(char::is_control)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn provider_identity_survives_runs_but_isolated_contexts_never_share_it() {
        let root = std::env::temp_dir().join(format!(
            "gbplus-conversation-{}-{}",
            std::process::id(),
            super::super::types::unix_time_millis()
        ));
        let project = ProjectId::new("project");
        let workspace = WorkspaceId::new("workspace");
        let session = SessionId::new("chat");
        let mut first = ConversationBinding::open(
            &root,
            &project,
            &workspace,
            &session,
            RuntimeTransport::GrokCliAcp,
        )
        .unwrap();
        let id = ProviderSessionId::new("existing-provider-context");
        first.remember(&id).unwrap();
        let restored = ConversationBinding::open(
            &root,
            &project,
            &workspace,
            &session,
            RuntimeTransport::GrokCliAcp,
        )
        .unwrap();
        assert_eq!(restored.provider_session_id(), Some(id));
        assert!(
            ConversationBinding::open(
                &root,
                &project,
                &workspace,
                &session,
                RuntimeTransport::XaiKeychain
            )
            .unwrap()
            .provider_session_id()
            .is_none()
        );
        assert!(
            ConversationBinding::open(
                &root,
                &project,
                &WorkspaceId::new("other"),
                &session,
                RuntimeTransport::GrokCliAcp
            )
            .unwrap()
            .provider_session_id()
            .is_none()
        );
        assert!(
            first
                .remember(&ProviderSessionId::new("unexpected-replacement"))
                .is_err()
        );
        std::fs::write(first.root().join("binding.json"), b"corrupt").unwrap();
        assert!(
            ConversationBinding::open(
                &root,
                &project,
                &workspace,
                &session,
                RuntimeTransport::GrokCliAcp
            )
            .is_err()
        );
        std::fs::remove_dir_all(root).unwrap();
    }
}
