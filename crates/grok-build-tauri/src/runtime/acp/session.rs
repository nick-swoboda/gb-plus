//! The single mutable ACP session owner and runtime-adapter implementation.

use super::process::AcpProcess;
use super::protocol::{acp_prompt_content, bounded_provider_session_id};
use super::tools::{classify_acp_failure, finish_acp_app_tool_turn};
use super::{
    ACP_MAX_ASSISTANT_BYTES, ACP_PROBE_PROMPT, AcpLaunchConfig, AdapterContext, AdapterFailure,
    AdapterImage, AdapterProbe, AdapterSession, AdapterTurn, Arc, LiveRuntimeAdapter, Mutex,
    PlusExternalToolExecutor, ProviderSessionId, RuntimeCancelHandle, RuntimeEvent,
    RuntimeEventSink, RuntimeSteeringSource, RuntimeTransport, Value, json,
};

pub(crate) struct GrokCliAcpAdapter {
    pub(super) config: AcpLaunchConfig,
    pub(super) process: Option<AcpProcess>,
    pub(super) session_id: Option<String>,
    model: Option<String>,
    pub(super) supports_image: bool,
    last_http_status: Option<u16>,
    cancel: RuntimeCancelHandle,
    external: Option<Arc<dyn PlusExternalToolExecutor>>,
    pub(super) selection: Option<crate::runtime::models::ModelSelection>,
    context_transient: bool,
}

impl GrokCliAcpAdapter {
    pub(crate) fn require_transient_context(&mut self, transient: bool) {
        self.context_transient |= transient;
    }
    #[cfg(test)]
    pub(super) fn has_live_process(&self) -> bool {
        self.process.is_some()
    }

    pub(crate) fn new(config: AcpLaunchConfig, cancel: RuntimeCancelHandle) -> Self {
        Self {
            config,
            process: None,
            session_id: None,
            model: None,
            supports_image: false,
            last_http_status: None,
            cancel,
            external: None,
            selection: None,
            context_transient: false,
        }
    }

    pub(crate) fn new_with_external(
        config: AcpLaunchConfig,
        cancel: RuntimeCancelHandle,
        external: Arc<dyn PlusExternalToolExecutor>,
    ) -> Self {
        Self {
            config,
            process: None,
            session_id: None,
            model: None,
            supports_image: false,
            last_http_status: None,
            cancel,
            external: Some(external),
            selection: None,
            context_transient: false,
        }
    }

    pub(super) fn ensure_initialized(
        &mut self,
        events: &RuntimeEventSink<'_>,
    ) -> Result<(), String> {
        if self.process.is_some() {
            return Ok(());
        }
        self.last_http_status = None;
        self.cancel.ensure_not_cancelled()?;
        let parked = self
            .config
            .standard
            .as_ref()
            .and_then(|launch| launch.lease.as_ref())
            .map(super::standard::StandardLease::take)
            .transpose()?
            .flatten();
        let mut process = if let Some(mut process) = parked {
            process.reuse_for_turn(self.cancel.clone())?;
            process.app_tools = super::mcp::ReverseMcpServer::new();
            process
        } else {
            AcpProcess::spawn(&self.config, self.cancel.clone())?
        };
        process.app_tools.standard = self.config.is_standard();
        process.app_tools.transient = self.context_transient;
        process
            .app_tools
            .configure_role(super::super::extension_tools::policy(
                self.external.as_deref(),
            ))?;
        process
            .app_tools
            .configure_catalog(super::super::extension_tools::catalog(
                self.external.as_deref(),
            )?)?;
        process
            .app_tools
            .configure_collaboration(super::super::collaboration_tools::binding(
                self.external.as_deref(),
            )?)?;
        let initialized = if let Some(initialized) = &process.initialized {
            Ok(initialized.clone())
        } else {
            process.request(
                "initialize",
                &json!({
                    "protocolVersion": 1,
                    "clientInfo": {
                        "name": "grok-build-plus",
                        "version": env!("CARGO_PKG_VERSION"),
                    },
                    "clientCapabilities": {
                        "fs": { "readTextFile": false, "writeTextFile": false },
                        "terminal": false,
                        "auth": { "terminal": false },
                    },
                }),
                events,
            )
        };
        self.last_http_status = process.last_http_status;
        let initialized =
            initialized.map_err(|error| format!("Grok CLI ACP initialize failed: {error}"))?;
        self.finish_initialize(process, initialized, events)
    }

    fn finish_initialize(
        &mut self,
        mut process: AcpProcess,
        initialized: Value,
        events: &RuntimeEventSink<'_>,
    ) -> Result<(), String> {
        if initialized.get("protocolVersion").and_then(Value::as_u64) != Some(1) {
            return Err("Grok CLI ACP did not negotiate protocol version 1.".into());
        }
        if !self.config.is_standard()
            && initialized
                .pointer("/_meta/x.ai~1mcp~1sdk")
                .and_then(Value::as_bool)
                != Some(true)
        {
            return Err(
                "Grok CLI does not advertise the required app-owned reverse MCP transport.".into(),
            );
        }
        if !self.config.is_standard()
            && initialized
                .pointer("/_meta/mcpServers")
                .and_then(Value::as_array)
                .is_some_and(|servers| !servers.is_empty())
        {
            return Err("Grok CLI ACP strict profile discovered configured MCP servers.".into());
        }
        let cached_token = initialized
            .get("authMethods")
            .and_then(Value::as_array)
            .is_some_and(|methods| {
                methods
                    .iter()
                    .any(|method| method.get("id").and_then(Value::as_str) == Some("cached_token"))
            });
        if !cached_token {
            return Err(
                "Grok CLI ACP does not advertise its CLI-owned cached_token auth method.".into(),
            );
        }
        self.model = initialized
            .pointer("/_meta/modelState/currentModelId")
            .and_then(Value::as_str)
            .map(str::to_owned);
        self.supports_image = initialized
            .pointer("/agentCapabilities/promptCapabilities/image")
            .and_then(Value::as_bool)
            .unwrap_or(false)
            || process.verified_image_input;
        let authenticated = process.request(
            "authenticate",
            &json!({ "methodId": "cached_token", "_meta": { "headless": true } }),
            events,
        );
        self.last_http_status = process.last_http_status;
        authenticated
            .map_err(|error| format!("Grok CLI ACP cached-token authentication failed: {error}"))?;
        if self.config.is_standard()
            && initialized
                .pointer("/_meta/x.ai~1mcp~1sdk")
                .and_then(Value::as_bool)
                != Some(true)
        {
            events(RuntimeEvent::ToolRefused { name: "GB Plus tools".into(), reason: "This CLI does not advertise the GB Plus tool connection. Native Chat remains available.".into() })?;
        }
        process.initialized = Some(initialized);
        self.process = Some(process);
        Ok(())
    }

    fn structured_http_status(&self) -> Option<u16> {
        self.process
            .as_ref()
            .map_or(self.last_http_status, |process| process.last_http_status)
    }

    pub(super) fn open_session(
        &mut self,
        provider_session_id: Option<&str>,
        events: &RuntimeEventSink<'_>,
    ) -> Result<String, String> {
        self.ensure_initialized(events)?;
        if let Some(existing) = &self.session_id
            && self
                .process
                .as_ref()
                .and_then(|process| process.active_session_id.as_deref())
                == Some(existing.as_str())
        {
            if provider_session_id.is_some_and(|requested| requested != existing) {
                return Err("ACP provider session reuse crossed its bound identity.".into());
            }
            return Ok(existing.clone());
        }
        let provider_session_id = provider_session_id
            .map(str::to_owned)
            .or_else(|| self.session_id.clone());
        let process = self
            .process
            .as_mut()
            .ok_or_else(|| "Grok CLI ACP process is unavailable.".to_owned())?;
        let cwd = process.neutral_cwd.display().to_string();
        let registration = process.app_tools.registration();
        let mut metadata = json!({"x.ai/mcp/servers":[registration]});
        if !self.config.is_standard() {
            metadata["systemPromptOverride"] = json!(super::protocol::strict_acp_system_prompt());
        }
        if let Some(standard) = &self.config.standard {
            standard.permission.metadata(&mut metadata);
        }
        let session_id = if let Some(session_id) = provider_session_id.as_deref() {
            restore_session(
                process,
                session_id,
                &cwd,
                &metadata,
                self.config.standard.as_ref(),
                events,
            )?;
            session_id.to_owned()
        } else {
            if !self.config.is_standard() {
                metadata["yoloMode"] = json!(false);
                metadata["autoMode"] = json!(false);
            }
            let result = process
                .request(
                    "session/new",
                    &json!({
                        "cwd": cwd,
                        "mcpServers": [],
                        "_meta": metadata,
                    }),
                    events,
                )
                .map_err(|error| format!("Grok CLI ACP session/new failed: {error}"))?;
            let session_id = result
                .get("sessionId")
                .and_then(Value::as_str)
                .filter(|id| bounded_provider_session_id(id))
                .ok_or_else(|| "Grok CLI ACP session/new returned no sessionId.".to_owned())?
                .to_owned();
            process.session_config = result;
            process.active_session_id = Some(session_id.clone());
            if !self.config.is_standard() {
                super::capabilities::seed_title_without_inference(process, &session_id, events)?;
            }
            session_id
        };
        if let Some(standard) = &self.config.standard {
            process.applied_permission = Some(standard.permission);
        }
        if let Some(selection) = &self.selection {
            super::models::apply_selection(process, &session_id, selection, events)?;
            self.model = Some(selection.model.id.clone());
        }
        if !self.config.is_standard() {
            super::capabilities::verify_gateway(process, &session_id, events)?;
        }
        if process.mirrors && provider_session_id.is_none() {
            super::mirror::checkpoint(process, &session_id, false)?;
        }
        self.session_id = Some(session_id.clone());
        let stdin = Arc::clone(
            &self
                .process
                .as_ref()
                .ok_or_else(|| "Grok CLI ACP process is unavailable.".to_owned())?
                .stdin,
        );
        self.cancel.register_acp(stdin, session_id.clone())?;
        Ok(session_id)
    }

    pub(super) fn prompt(
        &mut self,
        text: &str,
        image: Option<&AdapterImage<'_>>,
        events: &RuntimeEventSink<'_>,
        steering: Option<&RuntimeSteeringSource<'_>>,
    ) -> Result<(String, String), String> {
        self.cancel.ensure_not_cancelled()?;
        let session_id = self.open_session(None, events)?;
        let prompt = acp_prompt_content(text, image, self.supports_image)?;
        let chunks = Arc::new(Mutex::new(String::new()));
        let captured = Arc::clone(&chunks);
        let forwarding = |event: RuntimeEvent| {
            if let RuntimeEvent::AssistantDelta(text) = &event
                && let Ok(mut combined) = captured.lock()
            {
                if combined.len().saturating_add(text.len()) > ACP_MAX_ASSISTANT_BYTES {
                    return Err(format!(
                        "ACP assistant stream exceeded its {ACP_MAX_ASSISTANT_BYTES}-byte aggregate bound."
                    ));
                }
                combined.push_str(text);
            }
            events(event)
        };
        let result = self
            .process
            .as_mut()
            .ok_or_else(|| "Grok CLI ACP process is unavailable.".to_owned())?
            .request_with_steering(
                "session/prompt",
                &json!({
                    "sessionId": session_id,
                    "prompt": prompt,
                }),
                &forwarding,
                steering,
            )
            .map_err(|error| format!("Grok CLI ACP session/prompt failed: {error}"))?;
        validate_authoritative_prompt_result(&result)?;
        let assistant = chunks
            .lock()
            .map_err(|_| "ACP assistant buffer is unavailable.".to_owned())?
            .clone();
        if !self.config.is_standard() && assistant.trim().is_empty() {
            return Err("Grok CLI ACP returned end_turn but streamed no assistant message.".into());
        }
        Ok((session_id, assistant))
    }
}

fn restore_session(
    process: &mut AcpProcess,
    session_id: &str,
    cwd: &str,
    metadata: &Value,
    standard: Option<&super::standard::StandardLaunch>,
    events: &RuntimeEventSink<'_>,
) -> Result<(), String> {
    if !bounded_provider_session_id(session_id) {
        return Err("Stored Grok CLI ACP session identity is invalid or oversized.".into());
    }
    process.active_session_id = Some(session_id.to_owned());
    if process.mirrors {
        super::mirror::restore(process, session_id)?;
    }
    if let Some(standard) = standard {
        process.prepare_native_permission(session_id, standard.permission)?;
    }
    match process.request(
        "session/load",
        &json!({ "sessionId": session_id, "cwd": cwd, "mcpServers": [], "_meta": metadata }),
        events,
    ) {
        Ok(result) => process.session_config = result,
        Err(error) => {
            process.active_session_id = None;
            return Err(format!("Grok CLI ACP session/load failed: {error}"));
        }
    }
    Ok(())
}

pub(super) fn acp_stop_reason_category(stop_reason: &str) -> &'static str {
    match stop_reason {
        "cancelled" => "cancelled",
        "tool_use" => "tool_use_refused",
        "error" => "provider_error",
        "rate_limit" => "rate_limited",
        "max_tokens" => "incomplete_limit",
        _ => "unsupported",
    }
}

pub(super) fn validate_authoritative_prompt_result(result: &Value) -> Result<(), String> {
    let stop_reason = result
        .get("stopReason")
        .and_then(Value::as_str)
        .ok_or_else(|| "Grok CLI ACP prompt returned no stopReason.".to_owned())?;
    if stop_reason == "end_turn" {
        Ok(())
    } else {
        Err(format!(
            "Grok CLI ACP prompt did not complete normally (stop reason category: {}).",
            acp_stop_reason_category(stop_reason)
        ))
    }
}

impl LiveRuntimeAdapter for GrokCliAcpAdapter {
    fn image_input_supported(&self) -> bool {
        self.supports_image
    }

    fn transport(&self) -> RuntimeTransport {
        RuntimeTransport::GrokCliAcp
    }

    fn discover_models(
        &mut self,
    ) -> Result<Vec<crate::runtime::models::ModelDescriptor>, AdapterFailure> {
        self.authenticated_models()
    }

    fn configure_model(
        &mut self,
        selection: crate::runtime::models::ModelSelection,
    ) -> Result<(), AdapterFailure> {
        if selection.transport != self.transport() || self.session_id.is_some() {
            return Err(AdapterFailure::protocol(
                "Bind the model before opening its exact transport session.",
            ));
        }
        self.selection = Some(selection);
        Ok(())
    }

    fn probe_model_tools(&mut self, events: &RuntimeEventSink<'_>) -> Result<(), AdapterFailure> {
        self.probe_selected_tools(events)
    }

    fn probe(&mut self, events: &RuntimeEventSink<'_>) -> Result<AdapterProbe, AdapterFailure> {
        if self.config.is_standard() {
            self.ensure_initialized(events)
                .map_err(AdapterFailure::from)?;
            return Ok(AdapterProbe {
                model: self.model.clone().unwrap_or_else(|| "unknown".into()),
            });
        }
        let prompt = self.prompt(ACP_PROBE_PROMPT, None, events, None);
        let status = self.structured_http_status();
        let _ = prompt.map_err(|reason| classify_acp_failure(reason, status))?;
        Ok(AdapterProbe {
            model: self.model.clone().unwrap_or_else(|| "unknown".into()),
        })
    }

    fn start_or_restore_session(
        &mut self,
        provider_session_id: Option<&ProviderSessionId>,
    ) -> Result<AdapterSession, AdapterFailure> {
        self.start_or_restore_session_observed(provider_session_id, &|_| Ok(()))
    }

    fn start_or_restore_session_observed(
        &mut self,
        provider_session_id: Option<&ProviderSessionId>,
        events: &RuntimeEventSink<'_>,
    ) -> Result<AdapterSession, AdapterFailure> {
        let opened = self.open_session(provider_session_id.map(ProviderSessionId::as_str), events);
        let status = self.structured_http_status();
        let session_id = opened.map_err(|reason| classify_acp_failure(reason, status))?;
        Ok(AdapterSession {
            provider_session_id: Some(ProviderSessionId::new(session_id)),
        })
    }

    fn send_turn(
        &mut self,
        context: &AdapterContext<'_>,
        prompt: &str,
        image: Option<&AdapterImage<'_>>,
        steering: &RuntimeSteeringSource<'_>,
        events: &RuntimeEventSink<'_>,
    ) -> Result<AdapterTurn, AdapterFailure> {
        self.cancel
            .ensure_not_cancelled()
            .map_err(AdapterFailure::cancellation)?;
        let session_id = self
            .open_session(None, events)
            .map_err(|reason| classify_acp_failure(reason, self.structured_http_status()))?;
        self.process
            .as_mut()
            .ok_or_else(|| AdapterFailure::protocol("ACP process is unavailable."))?
            .app_tools
            .bind(context, self.external.clone())
            .map_err(AdapterFailure::protocol)?;
        // The prefix makes upstream slash commands literal user content. Skills
        // and workflow dispatch are interpreted by the app, never by the CLI.
        let input = if self.config.is_standard() {
            prompt.to_owned()
        } else {
            format!(
                "GB Plus user request:\n{}",
                context.provider_prompt(prompt)?
            )
        };
        acp_prompt_content(&input, image, self.supports_image).map_err(AdapterFailure::protocol)?;
        if let Some(process) = &mut self.process
            && process.mirrors
        {
            let was_transient = super::mirror::begin(&process.runtime_root, &session_id)?;
            process.app_tools.transient |= was_transient || image.is_some();
            process
                .app_tools
                .journal(&process.runtime_root, &session_id)?;
        }
        if self.config.is_standard() {
            self.process
                .as_mut()
                .ok_or_else(|| AdapterFailure::protocol("ACP process is unavailable."))?
                .app_tools
                .journal(&self.config.runtime_root, &session_id)?;
            return self.send_standard_turn(context, &input, image, steering, events, &session_id);
        }
        let prompted = self.prompt(&input, image, events, Some(steering));
        let status = self.structured_http_status();
        let closed = if self.cancel.cancelled() {
            Ok(())
        } else {
            self.process
                .as_mut()
                .ok_or("ACP process disappeared before closing its session.".to_owned())
                .and_then(|process| process.request_close_during_teardown(&session_id))
        };
        let closed = closed.and_then(|()| {
            if prompted.is_ok()
                && let Some(process) = &mut self.process
                && process.mirrors
            {
                super::mirror::checkpoint(process, &session_id, process.app_tools.transient)?;
            }
            Ok(())
        });
        let (steps, pending) = self
            .process
            .as_mut()
            .map(|process| {
                (
                    std::mem::take(&mut process.app_tools.steps),
                    std::mem::take(&mut process.app_tools.pending),
                )
            })
            .unwrap_or_default();
        // A registration never survives its execution. The next run loads the
        // durable provider session on a fresh connection with a fresh server ID.
        let terminated = self
            .process
            .take()
            .map_or(Ok(()), |mut process| process.terminate());
        self.cancel.clear_acp();
        let (_, assistant_text) = prompted
            .and_then(|prompted| closed.map(|()| prompted))
            .and_then(|prompted| terminated.map(|()| prompted))
            .map_err(|reason| classify_acp_failure(reason, status))?;
        let failure = steps.iter().find(|step| !step.ok).map(|step| {
            format!(
                "App-owned tool `{}` was refused or failed.",
                step.name.as_str()
            )
        });
        finish_acp_app_tool_turn(
            context,
            Some(ProviderSessionId::new(session_id)),
            &steps,
            pending,
            Some(assistant_text),
            failure,
            super::super::extension_tools::policy(self.external.as_deref())
                == grok_build_plus_host::PlusRuntimeToolPolicy::Parent,
        )
        .map_err(AdapterFailure::from)
    }

    fn continue_with_tool_results(
        &mut self,
        _context: &AdapterContext<'_>,
        _events: &RuntimeEventSink<'_>,
    ) -> Result<AdapterTurn, AdapterFailure> {
        Err(AdapterFailure::protocol(
            "GrokCliAcp exposes no client tools, so no tool-result continuation exists.",
        ))
    }

    fn cancel_run(&mut self) -> Result<(), String> {
        self.cancel.request_cancel()
    }

    fn close_session(&mut self) -> Result<(), String> {
        if self.config.is_standard() && self.process.is_none() {
            self.session_id = None;
            return Ok(());
        }
        let close_result = if self.cancel.cancelled() {
            if let (Some(process), Some(session_id)) =
                (&mut self.process, self.session_id.as_deref())
            {
                process.request_close_during_teardown(session_id)
            } else {
                Ok(())
            }
        } else if let (Some(process), Some(session_id)) =
            (&mut self.process, self.session_id.as_deref())
        {
            process
                .request(
                    "_x.ai/session/close",
                    &json!({ "sessionId": session_id }),
                    &|_| Ok(()),
                )
                .map(|_| ())
        } else {
            Ok(())
        };
        let terminated = self.process.as_mut().map_or(Ok(()), AcpProcess::terminate);
        self.process = None;
        self.session_id = None;
        self.model = None;
        self.cancel.clear_acp();
        close_result.and(terminated)
    }
}

impl Drop for GrokCliAcpAdapter {
    fn drop(&mut self) {
        let _ = self.close_session();
    }
}
