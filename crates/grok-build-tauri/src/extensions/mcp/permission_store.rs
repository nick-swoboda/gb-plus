//! Persist only project/server/schema policy identities through owner-state I/O.

use std::path::Path;

use grok_build_plus_host::{
    MCP_MAX_PERMISSION_BYTES, McpCatalog, McpPermissionBook, McpPermissionReview,
};

use crate::contracts::ProjectId;
use crate::owner_state::{OwnerStateFile, OwnerStateRoot};

pub(super) struct PermissionStore {
    owner: OwnerStateRoot,
    project: ProjectId,
    key: String,
}

impl PermissionStore {
    pub(super) fn new(root: &Path, project: &ProjectId) -> Self {
        Self {
            owner: OwnerStateRoot::new(root.join("mcp-permissions-v1")),
            project: project.clone(),
            key: grok_build_plus_host::worktree_recovery_digest(project.as_str().as_bytes()),
        }
    }

    pub(super) fn read(&self) -> Result<McpPermissionBook, String> {
        let bytes = self.file()?.read().map_err(|e| e.to_string())?;
        McpPermissionBook::restore(&self.project, bytes.as_deref())
    }

    pub(super) fn change(
        &self,
        catalog: &McpCatalog,
        review: &McpPermissionReview<'_>,
    ) -> Result<McpPermissionBook, String> {
        let lock = self
            .owner
            .file(format!("{}.lock", self.key), 0)
            .map_err(|e| e.to_string())?
            .open_process_file()
            .map_err(|e| e.to_string())?;
        rustix::fs::flock(&lock, rustix::fs::FlockOperation::NonBlockingLockExclusive)
            .map_err(|_| "MCP permissions are being updated. Refresh and try again.")?;
        let file = self.file()?;
        let previous = file.read().map_err(super::super::failure)?;
        let mut book = self.read()?;
        book.change(catalog, review, &mut |bytes| {
            if let Some(previous) = &previous {
                let value: serde_json::Value = serde_json::from_slice(previous).map_err(super::super::failure)?;
                if value["version"] == 1 {
                    let backup = self.owner.file(format!("{}-before-v2.json", self.key), MCP_MAX_PERMISSION_BYTES as u64)
                        .map_err(super::super::failure)?;
                    if let Some(saved) = backup.read().map_err(super::super::failure)? {
                        if &saved != previous { return Err("Legacy MCP permission backup differs; reconcile before changing policy.".into()); }
                    } else {
                        backup.replace(previous).map_err(super::super::failure)?;
                        if backup.read().map_err(super::super::failure)?.as_ref() != Some(previous) {
                            return Err("Legacy MCP permission backup readback failed.".into());
                        }
                    }
                }
            }
            file.replace(bytes).map_err(|e| e.to_string())?;
            if file.read().map_err(|e| e.to_string())?.as_deref() != Some(bytes) {
                return Err("MCP permission readback differed. Reload before continuing.".into());
            }
            Ok(())
        })?;
        Ok(book)
    }

    fn file(&self) -> Result<OwnerStateFile, String> {
        self.owner
            .file(
                format!("{}.json", self.key),
                MCP_MAX_PERMISSION_BYTES as u64,
            )
            .map_err(|e| e.to_string())
    }
}
