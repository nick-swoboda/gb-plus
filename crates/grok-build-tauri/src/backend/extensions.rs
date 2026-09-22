//! Resolve project authority before exposing extension management.
use super::{Backend, OperationContext};
use crate::extensions::ExtensionStore;

impl Backend {
    pub(super) fn bind_queued_runtime_context(
        &self,
        runtime: &mut crate::runtime::manager::RuntimeManager,
        item: &crate::queue::QueueItem,
        bound: &grok_build_plus_host::BoundProject,
    ) -> Result<(), String> {
        runtime.bind_cli_workspace(Some(bound.folder()))?;
        runtime.bind_conversation(
            self.store.state_root(),
            &item.project_id,
            &item.workspace_id,
            &item.session_id,
        )?;
        runtime.bind_service_context(crate::extensions::mcp::service::ServiceContext::new(
            item.project_id.clone(),
            item.id.as_str().into(),
            bound.folder().to_owned(),
            self.store.state_root().to_owned(),
        ))
    }
    pub(crate) fn extension_service_context(
        &self,
        context: &OperationContext,
    ) -> Result<crate::extensions::mcp::service::ServiceContext, String> {
        self.revalidate_operation(context)?;
        Ok(crate::extensions::mcp::service::ServiceContext::new(
            context.project_id.clone(),
            format!("mcp-review-{}", crate::runtime::types::unix_time_millis()),
            context.active_root.clone(),
            self.store.state_root().to_owned(),
        ))
    }
    pub(super) fn enabled_project_context(
        &self,
        project: &crate::contracts::ProjectId,
        prompt: &str,
    ) -> Result<String, String> {
        let mut context = ExtensionStore::new(self.store.state_root()).skill_context(project)?;
        let memory = crate::project_memory::ProjectMemory::new(self.store.state_root(), project)?
            .context(prompt)?;
        if !memory.is_empty() {
            context.push_str("\nProject memory facts:\n");
            context.push_str(&memory);
        }
        if context.len() > 128 * 1024 {
            return Err(
                "Enabled skills and memory exceed the combined 128 KiB context budget.".into(),
            );
        }
        Ok(context)
    }
    pub(crate) fn project_memory(
        &self,
        project_id: &str,
    ) -> Result<crate::project_memory::ProjectMemory, String> {
        let (_, context) = self.extension_operation(project_id)?;
        crate::project_memory::ProjectMemory::new(self.store.state_root(), &context.project_id)
    }
    pub(crate) fn extension_operation(
        &self,
        project_id: &str,
    ) -> Result<(ExtensionStore, OperationContext), String> {
        let context = self.operation_context()?;
        if context.project_id.as_str() != project_id {
            return Err("The active project changed. Refresh Extensions.".into());
        }
        Ok((ExtensionStore::new(self.store.state_root()), context))
    }
}
