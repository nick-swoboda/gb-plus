//! Selection probes never dispatch returned tool calls.

use super::{AdapterFailure, AtomicBool, Mutex, RuntimeEventSink, XaiKeychainAdapter};
use grok_build_plus_host::{encode_plus_live_conversation_request, get_plus_live_model_catalog};
use serde_json::{Value, json};

impl XaiKeychainAdapter {
    pub(super) fn authenticated_models(
        &self,
    ) -> Result<Vec<crate::runtime::models::ModelDescriptor>, AdapterFailure> {
        let identity = self.identity()?;
        let cancelled = || self.cancel.cancelled() || !self.credential.is_active();
        let minimal = get_plus_live_model_catalog(&identity, false, cancelled)?;
        let language = get_plus_live_model_catalog(&identity, true, cancelled)?;
        self.credential.ensure_active()?;
        crate::runtime::models::native_catalog(&minimal, &language).map_err(AdapterFailure::from)
    }

    pub(super) fn probe_selected_tools(
        &mut self,
        events: &RuntimeEventSink<'_>,
    ) -> Result<(), AdapterFailure> {
        let selection = self
            .selection
            .as_ref()
            .ok_or_else(|| AdapterFailure::protocol("Select an exact model before probing."))?;
        let identity = self.identity()?;
        let input = [
            json!({"role":"user","content":[{"type":"input_text","text":"GB Plus tool capability check. Emit exactly one read_file function call with path __gbplus_probe_only__. This call will be inspected and will not execute. No prose."}]}),
        ];
        let request = encode_plus_live_conversation_request(
            &input,
            &selection.model.id,
            selection.reasoning_effort.as_deref(),
            &identity,
        )?;
        let output = super::checked_transport(
            &mut self.connection,
            &self.cancel,
            &self.credential,
            &request,
            &super::StreamEvents {
                events,
                saw_assistant_delta: &AtomicBool::new(false),
                latest_usage: &Mutex::new(None),
                event_error: &Mutex::new(None),
            },
        )?;
        let response: Value = serde_json::from_slice(&output)
            .map_err(|_| AdapterFailure::protocol("Model probe is not valid JSON."))?;
        validate_tool_probe(&response).map_err(AdapterFailure::from)
    }
}

fn validate_tool_probe(response: &Value) -> Result<(), String> {
    if response["status"] != "completed" {
        return Err("Model probe did not complete.".into());
    }
    let calls = response["output"]
        .as_array()
        .ok_or("Model probe has no output items.")?
        .iter()
        .filter(|item| item["type"] == "function_call")
        .collect::<Vec<_>>();
    if calls.len() != 1 || calls[0]["name"] != "read_file" {
        return Err("Model did not demonstrate the required native app function call.".into());
    }
    let args: Value = serde_json::from_str(
        calls[0]["arguments"]
            .as_str()
            .ok_or("Model probe has no exact arguments.")?,
    )
    .map_err(|_| "Model probe arguments are malformed.")?;
    if args["path"] != "__gbplus_probe_only__" {
        return Err("Model probe changed its fixed tool fixture.".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn model_probe_requires_completed_native_call_and_does_not_execute_it() {
        let mut value = json!({"status":"completed","output":[{"type":"function_call","name":"read_file","arguments":"{\"path\":\"__gbplus_probe_only__\"}"}]});
        validate_tool_probe(&value).unwrap();
        value["output"][0]["name"] = json!("propose_write");
        assert!(validate_tool_probe(&value).is_err());
    }
}
