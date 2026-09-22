//! Catalog and probe operations use a separate connection with no project tools.

use super::{RuntimeManager, RuntimeTransport, unix_time_millis};
use crate::runtime::models::{ModelCatalog, ModelSelection};

impl RuntimeManager {
    pub(crate) fn authenticated_model_catalog(
        &self,
        context_root: &std::path::Path,
    ) -> Result<ModelCatalog, String> {
        let mut adapter = self.build_selected_adapter()?;
        let models = adapter.discover_models().map_err(|error| error.to_string());
        let closed = adapter.close_session();
        let models = models?;
        closed?;
        Ok(ModelCatalog {
            transport: self.selected,
            models,
            selected: ModelSelection::load(context_root, self.selected)?,
        })
    }

    pub(crate) fn verify_model_selection(
        &self,
        root: &std::path::Path,
        model_id: &str,
        reasoning_effort: Option<String>,
    ) -> Result<ModelSelection, String> {
        let protocol = (self.selected == RuntimeTransport::XaiKeychain)
            .then(|| super::super::native_protocol::NativeProtocol::load(root))
            .transpose()?;
        self.verify_model_using(model_id, reasoning_effort, protocol)
    }

    pub(super) fn verify_model_using(
        &self,
        model_id: &str,
        reasoning_effort: Option<String>,
        protocol: Option<super::super::native_protocol::NativeProtocol>,
    ) -> Result<ModelSelection, String> {
        if !crate::runtime::models::identifier(model_id)
            || reasoning_effort
                .as_deref()
                .is_some_and(|value| !crate::runtime::models::effort(value))
        {
            return Err("Model or reasoning effort is invalid.".into());
        }
        let mut adapter = self.build_selected_adapter()?;
        let result: Result<ModelSelection, String> = (|| {
            if let Some(protocol) = protocol {
                adapter
                    .configure_native_protocol(protocol)
                    .map_err(|error| error.to_string())?;
            }
            let model = adapter
                .discover_models()
                .map_err(|error| error.to_string())?
                .into_iter()
                .find(|model| model.id == model_id)
                .ok_or("The authenticated transport does not offer that model.")?;
            if self.selected == RuntimeTransport::GrokCliAcp
                && ((!model.reasoning_efforts.is_empty() && reasoning_effort.is_none())
                    || reasoning_effort
                        .as_ref()
                        .is_some_and(|effort| !model.reasoning_efforts.contains(effort)))
            {
                return Err(
                    "Select an explicit reasoning effort offered by this authenticated CLI.".into(),
                );
            }
            let mut selection = ModelSelection {
                schema_version: 1,
                transport: self.selected,
                model,
                reasoning_effort,
                verified_at: 0,
            };
            adapter
                .configure_model(selection.clone())
                .map_err(|error| error.to_string())?;
            adapter
                .probe_model_tools(&|_| Ok(()))
                .map_err(|error| error.to_string())?;
            selection.verified_at = unix_time_millis();
            Ok(selection)
        })();
        let closed = adapter.close_session();
        let selection = result?;
        closed?;
        Ok(selection)
    }
}
