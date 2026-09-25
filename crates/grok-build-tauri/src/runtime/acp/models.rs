//! Exact selected model, effort, and app-gateway capability checks.

use super::{AdapterFailure, GrokCliAcpAdapter, RuntimeEventSink, Value, json, process};
use crate::runtime::models::{ModelDescriptor, ModelSelection};

impl GrokCliAcpAdapter {
    pub(super) fn authenticated_models(&mut self) -> Result<Vec<ModelDescriptor>, AdapterFailure> {
        self.ensure_initialized(&|_| Ok(()))?;
        let process = self
            .process
            .as_mut()
            .ok_or_else(|| AdapterFailure::protocol("ACP process is unavailable."))?;
        let value = process.request("_x.ai/models/list", &json!({}), &|_| Ok(()))?;
        crate::runtime::models::acp_catalog_for_engine(&value, process.is_standard())
            .map_err(AdapterFailure::from)
    }

    pub(super) fn probe_selected_tools(
        &mut self,
        events: &RuntimeEventSink<'_>,
    ) -> Result<(), AdapterFailure> {
        if self.selection.is_none() {
            return Err(AdapterFailure::protocol(
                "An exact model selection is required.",
            ));
        }
        self.open_session(None, events)?;
        if self.config.is_standard() {
            return Ok(());
        }
        let process = self
            .process
            .as_mut()
            .ok_or_else(|| AdapterFailure::protocol("ACP process is unavailable."))?;
        process.app_tools.model_probe = Some(false);
        self.prompt("GB Plus tool capability check. Discover the app read_file tool and call it with path __gbplus_probe_only__. This is a fixed capability fixture; no file will be opened. Then acknowledge briefly.", None, events, None)?;
        if self
            .process
            .as_ref()
            .and_then(|process| process.app_tools.model_probe)
            != Some(true)
        {
            return Err(AdapterFailure::protocol(
                "Selected CLI model did not demonstrate its required app gateway call.",
            ));
        }
        Ok(())
    }
}

pub(super) fn apply_selection(
    process: &mut process::AcpProcess,
    session_id: &str,
    selection: &ModelSelection,
    events: &RuntimeEventSink<'_>,
) -> Result<(), String> {
    let current = process.request("_x.ai/models/list", &json!({}), events)?;
    let catalog = crate::runtime::models::acp_catalog_for_engine(&current, process.is_standard())?;
    let offered = catalog
        .iter()
        .find(|model| model.id == selection.model.id)
        .ok_or("The saved model is no longer offered by this authenticated CLI.")?;
    let active_config =
        process.is_standard() && config_option(&process.session_config, "model")?.is_some();
    if (!active_config
        && !offered.reasoning_efforts.is_empty()
        && selection.reasoning_effort.is_none())
        || selection
            .reasoning_effort
            .as_ref()
            .is_some_and(|effort| !offered.reasoning_efforts.contains(effort))
    {
        return Err("The CLI no longer offers the selected reasoning effort.".into());
    }
    if active_config {
        let mut config = process.request(
            "session/set_config_option",
            &json!({"sessionId":session_id,"configId":"model","value":selection.model.id}),
            events,
        )?;
        if let Some(effort) = &selection.reasoning_effort {
            if config_option(&config, "reasoning_effort")?.is_none() {
                return Err("The CLI does not advertise reasoning controls for this model.".into());
            }
            config = process.request(
                "session/set_config_option",
                &json!({"sessionId":session_id,"configId":"reasoning_effort","value":effort}),
                events,
            )?;
        }
        validate_active_selection(&config, selection)?;
        process.session_config["configOptions"] = config["configOptions"].clone();
    } else {
        process.request("session/set_model", &json!({"sessionId":session_id,"modelId":selection.model.id,"_meta":{"reasoningEffort":selection.reasoning_effort}}), events)?;
    }
    let info = process.request(
        "_x.ai/session/info",
        &json!({"sessionId":session_id}),
        events,
    )?;
    if info.get("model").and_then(Value::as_str) != Some(selection.model.id.as_str()) {
        return Err("The CLI did not select the exact requested model; no prompt was sent.".into());
    }
    // Saved history may still describe the initial effort until the next turn.
    if active_config {
        return Ok(());
    }
    let state = process.request(
        "_x.ai/session/state",
        &json!({"sessionId":session_id,"cwd":process.neutral_cwd}),
        events,
    )?;
    if state
        .pointer("/summary/reasoning_effort")
        .and_then(Value::as_str)
        != selection.reasoning_effort.as_deref()
    {
        return Err(
            "The CLI did not persist the exact requested reasoning effort; no prompt was sent."
                .into(),
        );
    }
    // verify_gateway subsequently checks the harness after the model switch.
    Ok(())
}

fn config_option<'a>(config: &'a Value, id: &str) -> Result<Option<&'a Value>, String> {
    let Some(options) = config.get("configOptions") else {
        return Ok(None);
    };
    let options = options
        .as_array()
        .filter(|items| items.len() <= 32)
        .ok_or("CLI session controls are malformed or oversized.")?;
    let mut matches = options.iter().filter(|option| option["id"] == id);
    let option = matches.next();
    if matches.next().is_some() || option.is_some_and(|option| option["type"] != "select") {
        return Err("CLI session control is ambiguous or unsupported.".into());
    }
    Ok(option)
}

fn validate_active_selection(config: &Value, selection: &ModelSelection) -> Result<(), String> {
    for (id, expected) in [
        ("model", Some(selection.model.id.as_str())),
        ("reasoning_effort", selection.reasoning_effort.as_deref()),
    ] {
        if let Some(expected) = expected
            && config_option(config, id)?.and_then(|option| option["currentValue"].as_str())
                != Some(expected)
        {
            return Err("The CLI did not confirm the requested active model and reasoning effort; no prompt was sent.".into());
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests;
