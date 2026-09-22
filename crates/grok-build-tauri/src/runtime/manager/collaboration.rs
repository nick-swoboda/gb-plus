use super::{Arc, PathBuf, RuntimeCancelHandle, RuntimeManager};

impl RuntimeManager {
    pub(crate) fn bind_collaboration(
        &mut self,
        controller: Arc<dyn grok_build_plus_host::PlusCollaborationExecutor>,
    ) -> Result<(), String> {
        if self.role != grok_build_plus_host::PlusRuntimeToolPolicy::Parent
            || self.adapter.is_some()
            || self.collaboration.is_some()
        {
            return Err(
                "Collaboration authority must be fixed once before the parent adapter starts."
                    .into(),
            );
        }
        self.collaboration = Some(controller);
        Ok(())
    }

    pub(crate) fn child_runtime_template(&self, state_root: PathBuf) -> Result<Self, String> {
        let mut template = self.fork_connected_transport_for_run(
            state_root,
            grok_build_plus_host::PlusRuntimeToolPolicy::Parent,
        )?;
        template.browser = None;
        template.capture = None;
        template.desktop = None;
        template.mcp = None;
        template.hook_policy.clone_from(&self.hook_policy);
        template.conversation.clone_from(&self.conversation);
        Ok(template)
    }

    pub(crate) fn prepare_child_runtime(
        &self,
        state_root: &std::path::Path,
        child: &crate::queue::children::ChildRecord,
        bound: &grok_build_plus_host::BoundProject,
        cancel: RuntimeCancelHandle,
    ) -> Result<Self, String> {
        use grok_build_plus_host::{PlusChildRole, PlusRuntimeToolPolicy};
        let role = match child.role {
            PlusChildRole::Explore => PlusRuntimeToolPolicy::Explore,
            PlusChildRole::Plan => PlusRuntimeToolPolicy::Plan,
            PlusChildRole::Worker => PlusRuntimeToolPolicy::Worker,
        };
        let mut runtime = self.fork_connected_transport_for_run(
            state_root.join("child-runtime").join(child.id.as_str()),
            role,
        )?;
        runtime.context_transient = child.transient;
        runtime.cancel = cancel;
        runtime.hook_policy.clone_from(&self.hook_policy);
        runtime.service_context = Some(crate::extensions::mcp::service::ServiceContext::new(
            child.project.clone(),
            child.id.as_str().into(),
            bound.folder().to_owned(),
            state_root.to_owned(),
        ));
        runtime.bind_conversation(state_root, &child.project, &child.workspace, &child.session)?;
        if self.selected == super::RuntimeTransport::XaiKeychain
            && let Some(parent) = &self.conversation
        {
            let protocol = super::super::native_protocol::NativeProtocol::load(parent.root())?;
            let child_binding = runtime
                .conversation
                .as_ref()
                .ok_or("Child provider binding is unavailable.")?;
            // The parent choice was verified for the inherited exact model.
            protocol.save_verified(child_binding.root())?;
        }
        if let Some(parent) = &self.conversation
            && let Some(selection) =
                super::super::models::ModelSelection::load(parent.root(), self.selected)?
        {
            let child_binding = runtime
                .conversation
                .as_ref()
                .ok_or("Child provider binding is unavailable.")?;
            selection.save(child_binding.root())?;
        }
        Ok(runtime)
    }
}
