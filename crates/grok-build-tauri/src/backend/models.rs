//! Project-bound model operations; IPC never supplies provider authority.

use super::{Backend, RuntimeManager};
use crate::runtime::conversation::ConversationBinding;
use crate::runtime::models::ModelSelection;

impl Backend {
    pub(crate) fn prepare_model_operation(
        &self,
        project_id: &str,
        session_id: &str,
    ) -> Result<(RuntimeManager, ConversationBinding), String> {
        let binding = self.model_binding(project_id, session_id)?;
        let root = self.store.state_root().join("model-probes").join(format!(
            "{}-{}",
            std::process::id(),
            crate::runtime::types::unix_time_millis()
        ));
        let mut runtime = self.runtime.fork_connected_transport_for_run(
            root,
            grok_build_plus_host::PlusRuntimeToolPolicy::Parent,
        )?;
        runtime.bind_cli_workspace(Some(&self.operation_context()?.active_root))?;
        Ok((runtime, binding))
    }

    pub(crate) fn commit_model_selection(
        &self,
        project_id: &str,
        session_id: &str,
        selection: &ModelSelection,
    ) -> Result<(), String> {
        let binding = self.model_binding(project_id, session_id)?;
        if selection.transport != self.runtime.selected_transport() || selection.verified_at == 0 {
            return Err("Model probe lost its exact authenticated transport binding.".into());
        }
        selection.save(binding.root())
    }

    pub(super) fn model_binding(
        &self,
        project_id: &str,
        session_id: &str,
    ) -> Result<ConversationBinding, String> {
        let context = self.operation_context()?;
        if context.project_id.as_str() != project_id || context.session_id.as_str() != session_id {
            return Err("Model operation refused because the project or session changed.".into());
        }
        let standard_root = self.store.state_root().join("cli-standard");
        ConversationBinding::open(
            if self.runtime.standard_engine() {
                &standard_root
            } else {
                self.store.state_root()
            },
            &context.project_id,
            &context.workspace_id,
            &context.session_id,
            self.runtime.selected_transport(),
        )
    }
}

impl Backend {
    pub(crate) fn native_protocol(
        &self,
        project_id: &str,
        session_id: &str,
    ) -> Result<crate::runtime::native_protocol::NativeProtocol, String> {
        let binding = self.model_binding(project_id, session_id)?;
        if self.runtime.selected_transport() != crate::runtime::types::RuntimeTransport::XaiKeychain
        {
            return Err("Connection mode belongs only to native xAI chats.".into());
        }
        crate::runtime::native_protocol::NativeProtocol::load(binding.root())
    }
    pub(crate) fn commit_native_protocol(
        &self,
        project_id: &str,
        session_id: &str,
        protocol: crate::runtime::native_protocol::NativeProtocol,
        verified: &ModelSelection,
    ) -> Result<(), String> {
        let binding = self.model_binding(project_id, session_id)?;
        if self.runtime.selected_transport() != crate::runtime::types::RuntimeTransport::XaiKeychain
            || verified.transport != self.runtime.selected_transport()
            || verified.verified_at == 0
        {
            return Err(
                "Connection verification lost its native authenticated transport binding.".into(),
            );
        }
        let (model, effort) = crate::runtime::native_protocol::current_model(binding.root())?;
        if verified.model.id != model || verified.reasoning_effort != effort {
            return Err("The selected model changed during connection verification.".into());
        }
        protocol.save_verified(binding.root())
    }
}
