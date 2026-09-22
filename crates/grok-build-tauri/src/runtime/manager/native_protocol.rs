//! Protocol changes verify the current exact model before the caller persists them.
use super::RuntimeManager;
use crate::runtime::{
    models::ModelSelection, native_protocol::NativeProtocol, types::RuntimeTransport,
};
impl RuntimeManager {
    pub(crate) fn verify_native_protocol(
        &self,
        root: &std::path::Path,
        protocol: NativeProtocol,
    ) -> Result<ModelSelection, String> {
        if self.selected_transport() != RuntimeTransport::XaiKeychain {
            return Err("Connection mode belongs only to native xAI chats.".into());
        }
        let (model, effort) = super::super::native_protocol::current_model(root)?;
        self.verify_model_using(&model, effort, Some(protocol))
    }
}
