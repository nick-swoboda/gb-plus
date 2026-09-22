//! The one app-owned MCP server carried by ACP reverse requests.
//!
//! This endpoint is deliberately not a listening HTTP server or a general MCP
//! process launcher. Third-party MCP transports belong to the separate broker.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, Ordering};

use grok_build_plus_host::{
    BoundProject, PLUS_MAX_TOOL_STEPS, PendingFileSet, PlusExternalToolExecutor, PlusHostError,
    PlusSessionMode, PlusSessionStore, PlusToolStep, plus_live_tool_declarations,
    plus_tool_request_from_name_and_args, run_plus_tool_loop_on_store_in_mode_observed_external,
    worktree_recovery_digest,
};
use serde_json::{Value, json};

use super::{AdapterContext, Arc, RuntimeEventSink};

pub(super) const SERVER_NAME: &str = "gbplus";
pub(super) const REVERSE_METHOD: &str = "_x.ai/mcp/sdk_call";
static NEXT_SERVER: AtomicU64 = AtomicU64::new(1);
const MAX_REQUESTS: usize = 256;
const MAX_REQUEST_BYTES: usize = 2 * 1024 * 1024;
const MAX_CACHE_BYTES: usize = 8 * 1024 * 1024;

#[derive(Clone, Copy, Eq, PartialEq)]
enum RegistrationState {
    New,
    Initialized,
    Revoked,
}

pub(super) struct ReverseMcpServer {
    id: String,
    state: RegistrationState,
    binding: Option<(
        BoundProject,
        PlusSessionStore,
        crate::runtime::types::RuntimeInvocationScope,
    )>,
    external: Option<Arc<dyn PlusExternalToolExecutor>>,
    hooks: Option<Arc<dyn crate::extensions::hooks::ToolHookExecutor>>,
    extensions: Vec<grok_build_plus_host::PlusExtensionTool>,
    role: grok_build_plus_host::PlusRuntimeToolPolicy,
    collaboration: Option<String>,
    calls: usize,
    pub(super) standard: bool,
    cache: BTreeMap<String, (String, Value)>,
    cache_bytes: usize,
    persistence_failed: bool,
    pub(super) model_probe: Option<bool>,
    pub(super) transient: bool,
    journal: Option<super::invocations::InvocationJournal>,
    pub(super) pending: PendingFileSet,
    pub(super) steps: Vec<PlusToolStep>,
}

impl ReverseMcpServer {
    pub(super) fn native_preview_bound(&self) -> Option<&BoundProject> {
        self.binding.as_ref().map(|(bound, _, _)| bound)
    }

    pub(super) fn new() -> Self {
        let seed = format!(
            "{}:{}:{}",
            std::process::id(),
            super::super::types::unix_time_millis(),
            NEXT_SERVER.fetch_add(1, Ordering::Relaxed)
        );
        Self {
            id: format!("gbplus-{}", worktree_recovery_digest(seed.as_bytes())),
            state: RegistrationState::New,
            binding: None,
            external: None,
            hooks: None,
            extensions: Vec::new(),
            role: grok_build_plus_host::PlusRuntimeToolPolicy::Parent,
            collaboration: None,
            calls: 0,
            standard: false,
            cache: BTreeMap::new(),
            cache_bytes: 0,
            persistence_failed: false,
            model_probe: None,
            transient: false,
            journal: None,
            pending: PendingFileSet::default(),
            steps: Vec::new(),
        }
    }

    pub(super) fn registration(&self) -> Value {
        json!({"name": SERVER_NAME, "serverId": self.id})
    }

    pub(super) fn configure_role(
        &mut self,
        role: grok_build_plus_host::PlusRuntimeToolPolicy,
    ) -> Result<(), String> {
        if self.state != RegistrationState::New
            || self.binding.is_some()
            || !self.extensions.is_empty()
        {
            return Err("ACP execution role must be fixed before registering tools.".into());
        }
        self.role = role;
        Ok(())
    }

    pub(super) fn configure_catalog(
        &mut self,
        tools: Vec<grok_build_plus_host::PlusExtensionTool>,
    ) -> Result<(), String> {
        if self.state != RegistrationState::New || self.binding.is_some() || tools.len() > 32 {
            return Err("ACP extension catalog cannot change after initialization.".into());
        }
        if self.role != grok_build_plus_host::PlusRuntimeToolPolicy::Parent && !tools.is_empty() {
            return Err("ACP child roles cannot register extension tools.".into());
        }
        let mut names = std::collections::BTreeSet::new();
        for tool in &tools {
            tool.validate().map_err(|e| e.to_string())?;
            if !names.insert(tool.name.clone()) {
                return Err("ACP extension catalog contains duplicates.".into());
            }
        }
        self.extensions = tools;
        Ok(())
    }

    pub(super) fn catalog(&self) -> Result<Vec<Value>, String> {
        let mut tools = tool_catalog()?;
        self.role.restrict_declarations(&mut tools)?;
        if self.collaboration.is_some() {
            tools.extend(grok_build_plus_host::plus_collaboration_declarations().into_iter().map(|tool| json!({"name":tool["name"],"description":tool["description"],"inputSchema":tool["parameters"]})));
        }
        tools.extend(self.extensions.iter().map(|tool| json!({"name":tool.name,"description":tool.description,"inputSchema":tool.parameters})));
        Ok(tools)
    }

    pub(super) fn replacement(&self) -> Result<Self, String> {
        let mut fresh = Self::new();
        fresh.configure_role(self.role)?;
        fresh.configure_catalog(self.extensions.clone())?;
        fresh.configure_collaboration(self.collaboration.clone())?;
        Ok(fresh)
    }

    pub(super) fn configure_collaboration(
        &mut self,
        binding: Option<String>,
    ) -> Result<(), String> {
        if self.state != RegistrationState::New
            || self.binding.is_some()
            || (binding.is_some()
                && self.role != grok_build_plus_host::PlusRuntimeToolPolicy::Parent)
        {
            return Err(
                "ACP collaboration binding must be fixed before parent registration.".into(),
            );
        }
        self.collaboration = binding;
        Ok(())
    }

    pub(super) fn revoke(&mut self) {
        self.state = RegistrationState::Revoked;
        self.binding = None;
        self.external = None;
        self.hooks = None;
    }

    /// A closed actor may finish catalog RPCs while session/close or rename is
    /// awaiting its own response. Refuse those exchanges on the wire without
    /// consulting old result caches or aborting the unrelated control request.
    /// Journal/dispatch failures for an active registration remain fatal.
    pub(super) fn inactive_response(
        &self,
        params: &Value,
        outer_id: &Value,
    ) -> Result<Option<Value>, String> {
        if self.state != RegistrationState::Revoked
            && params.get("serverId").and_then(Value::as_str) == Some(self.id.as_str())
        {
            return Ok(None);
        }
        let message = params
            .get("message")
            .ok_or("Inactive ACP request has no inner message.")?;
        if !valid_rpc_id(outer_id)
            || message.get("jsonrpc").and_then(Value::as_str) != Some("2.0")
            || !message.get("id").is_some_and(valid_rpc_id)
            || serde_json::to_vec(message)
                .map_err(|_| "Cannot bound inactive ACP request.")?
                .len()
                > MAX_REQUEST_BYTES
        {
            return Err(
                "Inactive ACP request has invalid or oversized correlation framing.".into(),
            );
        }
        Ok(Some(json!({"jsonrpc":"2.0","id":message["id"],"error":{
            "code":-32000,"message":"This app tool registration is inactive. No tool executed."
        }})))
    }

    pub(super) fn journal(
        &mut self,
        root: &std::path::Path,
        provider_session: &str,
    ) -> Result<(), String> {
        let (bound, _, scope) = self
            .binding
            .as_ref()
            .ok_or("Invocation journal requires its app-issued workspace binding.")?;
        self.journal = Some(super::invocations::InvocationJournal::new(
            root,
            provider_session,
            &self.id,
            bound.folder(),
            scope,
            &json!(self.catalog()?),
        )?);
        Ok(())
    }

    pub(super) fn bind(
        &mut self,
        context: &AdapterContext<'_>,
        external: Option<Arc<dyn PlusExternalToolExecutor>>,
    ) -> Result<(), String> {
        if self.state == RegistrationState::Revoked {
            return Err("A revoked ACP registration cannot be bound to another execution.".into());
        }
        if self.binding.is_some() {
            return Err("ACP app-tool registration is already bound to an execution.".into());
        }
        if self.model_probe.is_some() {
            return Err(
                "A model-probe registration cannot become an execution registration.".into(),
            );
        }
        context.scope.validate()?;
        if self
            .collaboration
            .as_ref()
            .is_some_and(|parent| parent != context.scope.run_id.as_str())
        {
            return Err("ACP collaboration authority belongs to a different app run.".into());
        }
        if self.role != super::super::extension_tools::policy(external.as_deref()) {
            return Err("ACP role differs from its registered execution owner.".into());
        }
        if self.collaboration != super::super::collaboration_tools::binding(external.as_deref())? {
            return Err("ACP collaboration owner differs from its registered family.".into());
        }
        let declared = super::super::extension_tools::catalog(external.as_deref())?;
        if declared
            .iter()
            .map(|tool| (&tool.name, &tool.fingerprint))
            .collect::<Vec<_>>()
            != self
                .extensions
                .iter()
                .map(|tool| (&tool.name, &tool.fingerprint))
                .collect::<Vec<_>>()
        {
            return Err(
                "ACP invocation executor differs from its verified extension catalog.".into(),
            );
        }
        self.binding = Some((
            context.bound.clone(),
            context.store.clone(),
            context.scope.clone(),
        ));
        self.external = external;
        self.hooks.clone_from(&context.hooks);
        Ok(())
    }

    #[cfg(test)]
    pub(super) fn handle(
        &mut self,
        params: &Value,
        events: &RuntimeEventSink<'_>,
    ) -> Result<Value, String> {
        self.handle_reverse(params, &params["message"]["id"], events)
    }

    pub(super) fn handle_reverse(
        &mut self,
        params: &Value,
        outer_id: &Value,
        events: &RuntimeEventSink<'_>,
    ) -> Result<Value, String> {
        if self.state == RegistrationState::Revoked {
            return Err("ACP app-tool registration has been revoked.".into());
        }
        if !valid_rpc_id(outer_id) {
            return Err("ACP reverse request has no bounded outer correlation identity.".into());
        }
        if self.persistence_failed {
            return Err(
                "ACP tool activity persistence failed; this execution cannot continue.".into(),
            );
        }
        if params.get("serverId").and_then(Value::as_str) != Some(self.id.as_str()) {
            return Err(
                "ACP reverse call did not match this connection's app-tool registration.".into(),
            );
        }
        let message = params
            .get("message")
            .ok_or("ACP reverse call has no MCP message.")?;
        let encoded = serde_json::to_vec(message).map_err(|e| e.to_string())?;
        if encoded.len() > MAX_REQUEST_BYTES
            || message.get("jsonrpc").and_then(Value::as_str) != Some("2.0")
        {
            return Err("ACP MCP request has invalid framing or exceeds its bound.".into());
        }
        let id = message
            .get("id")
            .filter(|id| valid_rpc_id(id))
            .ok_or("ACP MCP request has no bounded correlation ID.")?;
        // rmcp may reuse a completed inner ID (notably after initialize).
        // Each outer ACP reverse request identifies its own inner exchange.
        let key = json!([outer_id, id]).to_string();
        let digest = worktree_recovery_digest(&encoded);
        if let Some((previous, response)) = self.cache.get(&key) {
            return if previous == &digest {
                Ok(response.clone())
            } else {
                Err("ACP MCP request ID was reused with different content.".into())
            };
        }
        if self.cache.len() >= MAX_REQUESTS || self.cache_bytes >= MAX_CACHE_BYTES {
            return Err("ACP MCP invocation cache reached its bound.".into());
        }
        let effectful = message.get("method").and_then(Value::as_str) == Some("tools/call");
        if effectful
            && let Some(journal) = &mut self.journal
            && let Some(output) = journal.intent(&key, &digest)?
        {
            return Ok(output);
        }
        let result = self.dispatch(message, events, &key);
        if self.persistence_failed {
            return Err("ACP tool activity persistence failed; delivery is uncertain and execution was stopped.".into());
        }
        let response = match result {
            Ok(result) => json!({"jsonrpc":"2.0", "id":id, "result":result}),
            Err(reason) => {
                json!({"jsonrpc":"2.0", "id":id, "error":{"code":-32602,"message":reason}})
            }
        };
        if effectful
            && let Some(journal) = &mut self.journal
            && let Err(error) = journal.complete(&key, &digest, &response, self.transient)
        {
            self.persistence_failed = true;
            return Err(error);
        }
        let size = serde_json::to_vec(&response)
            .map_err(|e| e.to_string())?
            .len();
        if self.cache_bytes.saturating_add(size) > MAX_CACHE_BYTES {
            self.persistence_failed = true;
            return Err(
                "ACP result exceeded its aggregate cache bound; execution was stopped.".into(),
            );
        }
        self.cache_bytes = self.cache_bytes.saturating_add(size);
        self.cache.insert(key, (digest, response.clone()));
        Ok(response)
    }

    fn dispatch(
        &mut self,
        message: &Value,
        events: &RuntimeEventSink<'_>,
        invocation: &str,
    ) -> Result<Value, String> {
        match message.get("method").and_then(Value::as_str) {
            Some("initialize") => {
                if self.state != RegistrationState::New {
                    return Err("ACP MCP server was initialized twice.".into());
                }
                if !message
                    .pointer("/params/protocolVersion")
                    .and_then(Value::as_str)
                    .is_some_and(|version| {
                        matches!(
                            version,
                            "2024-11-05"
                                | "2025-03-26"
                                | "2025-06-18"
                                | "2025-11-25"
                                | "2026-07-28"
                        )
                    })
                {
                    return Err("Unsupported or missing MCP protocol version.".into());
                }
                self.state = RegistrationState::Initialized;
                Ok(
                    json!({"protocolVersion":"2025-11-25", "capabilities":{"tools":{}}, "serverInfo":{"name":SERVER_NAME,"version":env!("CARGO_PKG_VERSION")}}),
                )
            }
            Some("ping") => Ok(json!({})),
            Some("tools/list") if self.state == RegistrationState::Initialized => {
                Ok(json!({"tools":self.catalog()?}))
            }
            Some("tools/call") if self.state == RegistrationState::Initialized => {
                self.call(message, events, invocation)
            }
            _ => Err("Unsupported method on the app-owned ACP MCP server.".into()),
        }
    }

    fn call_probe(&mut self, message: &Value) -> Result<Value, String> {
        let observed = self
            .model_probe
            .as_mut()
            .ok_or("ACP model probe is absent.")?;
        if message.pointer("/params/name").and_then(Value::as_str) != Some("read_file")
            || message
                .pointer("/params/arguments/path")
                .and_then(Value::as_str)
                != Some("__gbplus_probe_only__")
        {
            return Err(
                "Model probe accepts only its fixed read_file fixture; nothing executed.".into(),
            );
        }
        *observed = true;
        Ok(
            json!({"content":[{"type":"text","text":"GB Plus capability probe confirmed. No file was opened."}]}),
        )
    }

    fn call(
        &mut self,
        message: &Value,
        events: &RuntimeEventSink<'_>,
        invocation: &str,
    ) -> Result<Value, String> {
        if self.model_probe.is_some() {
            return self.call_probe(message);
        }
        let (bound, store, scope) = self
            .binding
            .as_ref()
            .ok_or("ACP tool call arrived without an active app execution.")?;
        if !self.standard && self.calls >= PLUS_MAX_TOOL_STEPS {
            return Err("ACP app-tool execution reached its step bound.".into());
        }
        self.calls += 1;
        let name = message
            .pointer("/params/name")
            .and_then(Value::as_str)
            .ok_or("ACP tool name is missing.")?;
        let arguments = message
            .pointer("/params/arguments")
            .filter(|v| v.is_object())
            .ok_or("ACP tool arguments must be an object.")?;
        if let Some(reason) = self.role.refusal(name) {
            return super::super::extension_tools::role_refusal(name, reason, events);
        }
        if let Some(hooks) = &self.hooks {
            match hooks.before_tool(scope, name, arguments) {
                Ok(crate::extensions::hooks::HookGateDecision::Proceed) => {}
                Ok(crate::extensions::hooks::HookGateDecision::Refuse(reason)) => {
                    let result = super::super::extension_tools::hook_refusal(name, &reason, events);
                    self.persistence_failed |= result.is_err();
                    return result;
                }
                Err(error) => {
                    self.persistence_failed = true;
                    return Err(error);
                }
            }
        }
        if grok_build_plus_host::PlusCollaborationCommand::recognizes(name) {
            let result = super::super::collaboration_tools::execute(
                self.external.as_deref(),
                &json!([self.id, invocation]).to_string(),
                name,
                arguments,
                self.transient,
                events,
            );
            // Failure may mean the parent could not reacquire its model lease.
            // Never return a tool error that lets the CLI resume without it.
            self.persistence_failed |= result.is_err();
            // The CLI consumes MCP content; arbitrary JSON-RPC result fields
            // do not reach its model. Native Responses retains the plain object.
            return result.map(|result| collaboration_content(&result));
        }
        if name.starts_with("gbext_") {
            self.transient = true;
            let result = super::super::extension_tools::execute(
                self.external.as_deref(),
                &json!([self.id, invocation]).to_string(),
                name,
                arguments,
                events,
            );
            self.persistence_failed |= result.is_err();
            return result;
        }
        let request = plus_tool_request_from_name_and_args(name, &arguments.to_string())
            .map_err(|e| e.to_string())?;
        self.transient |= name.starts_with("browser_") || name.starts_with("desktop_");
        let mut observation_failed = false;
        let mut observer = |event| {
            events(super::tools::acp_tool_runtime_event(event)).map_err(|error| {
                observation_failed = true;
                PlusHostError::Live(error)
            })
        };
        let report = run_plus_tool_loop_on_store_in_mode_observed_external(
            bound,
            Some(store),
            &[request],
            PlusSessionMode::Agent,
            &mut observer,
            self.external.as_deref(),
        );
        self.persistence_failed |= observation_failed;
        let report = report.map_err(|e| e.to_string())?;
        for proposal in report.pending_set.items {
            self.pending.upsert(proposal);
        }
        let step = report
            .steps
            .first()
            .ok_or("App-tool dispatcher returned no authoritative result.")?;
        let output = json!({"content":[{"type":"text", "text":step.result}],"isError":!step.ok});
        self.steps.extend(report.steps);
        Ok(output)
    }
}

fn collaboration_content(result: &Value) -> Value {
    json!({"content":[{"type":"text","text":result.to_string()}],"isError":result["isError"] == true})
}

pub(super) fn valid_rpc_id(value: &Value) -> bool {
    value.as_i64().is_some()
        || value.as_str().is_some_and(|id| {
            !id.is_empty() && id.len() <= 128 && !id.chars().any(char::is_control)
        })
}

pub(super) fn validate_notification(
    message: &Value,
    closing: bool,
    tool_count: usize,
) -> Result<(), String> {
    let params = message
        .get("params")
        .ok_or("MCP lifecycle notification has no parameters.")?;
    let params = params.get("params").unwrap_or(params);
    if serde_json::to_vec(params)
        .map_err(|error| error.to_string())?
        .len()
        > 64 * 1024
    {
        return Err("CLI MCP observation exceeded its metadata bound.".into());
    }
    if params
        .get("name")
        .is_some_and(|name| name.as_str() != Some(SERVER_NAME))
    {
        return Err("CLI reported a server status outside the app-owned namespace.".into());
    }
    if message.get("method").and_then(Value::as_str) == Some("_x.ai/mcp/server_status")
        && !closing
        && !matches!(
            params.get("status").and_then(Value::as_str),
            Some("ready" | "initializing")
        )
    {
        return Err(
            "The CLI app gateway became unavailable; this execution cannot continue.".into(),
        );
    }
    for key in ["mcpToolCount", "toolCount"] {
        if let Some(count) = params.get(key)
            && count.as_u64().is_none_or(|count| count > tool_count as u64)
        {
            return Err("CLI MCP tool count exceeded the app-owned catalog.".into());
        }
    }
    if let Some(servers) = params.get("mcpServers") {
        let servers = servers
            .as_array()
            .ok_or("CLI MCP catalog was not an array.")?;
        if servers.len() > 1
            || servers.iter().any(|server| {
                server
                    .as_str()
                    .or_else(|| server.get("name").and_then(Value::as_str))
                    != Some(SERVER_NAME)
            })
        {
            return Err("CLI reported an MCP server outside the app-owned namespace.".into());
        }
    }
    Ok(())
}

fn tool_catalog() -> Result<Vec<Value>, String> {
    let declarations = plus_live_tool_declarations();
    let declarations = declarations
        .as_array()
        .filter(|items| !items.is_empty())
        .ok_or("App tool catalog is unavailable.")?;
    Ok(declarations.iter().map(|entry| json!({"name":entry["name"],"description":entry["description"],"inputSchema":entry["parameters"]})).collect())
}

#[cfg(test)]
mod tests {
    #[test]
    fn collaboration_refusal_keeps_its_mcp_error_flag_and_exact_content() {
        let value = json!({"isError":true,"error":"This child belongs to another family."});
        let result = collaboration_content(&value);
        assert_eq!(result["isError"], true);
        assert_eq!(
            serde_json::from_str::<Value>(result["content"][0]["text"].as_str().unwrap()).unwrap(),
            value
        );
    }

    #[test]
    fn collaboration_scope_and_failed_parent_reacquisition_cannot_resume_the_cli() {
        use crate::runtime::collaboration_tools::{ParentTools, fixtures::Owner};
        for fail in [false, true] {
            let root = std::env::temp_dir().join(format!(
                "gbplus-collaboration-acp-{}-{}-{fail}",
                std::process::id(),
                crate::runtime::types::unix_time_millis()
            ));
            std::fs::create_dir_all(&root).unwrap();
            let bound = grok_build_plus_host::bind_project_folder(&root).unwrap();
            let store = PlusSessionStore::from_state_root(root.join("store"));
            let mut context = AdapterContext {
                scope: crate::runtime::types::RuntimeInvocationScope::fixture(),
                extension_context: "",
                hooks: None,
                bound: &bound,
                store: &store,
            };
            let owner = Arc::new(Owner {
                fail,
                ..Owner::default()
            });
            let external = Arc::new(ParentTools::new(None, owner.clone()).unwrap());
            let mut server = ReverseMcpServer::new();
            server
                .configure_collaboration(Some("fixture-run".into()))
                .unwrap();
            context.scope.run_id = crate::contracts::RunId::new("foreign-run");
            assert!(server.bind(&context, Some(external.clone())).is_err());
            context.scope.run_id = crate::contracts::RunId::new("fixture-run");
            server.bind(&context, Some(external)).unwrap();
            assert_eq!(
                server
                    .catalog()
                    .unwrap()
                    .iter()
                    .filter(|tool| tool["name"]
                        .as_str()
                        .is_some_and(|name| name.starts_with("app_agent_")))
                    .count(),
                5
            );
            server
                .journal(&root.join("journal"), "fixture-provider")
                .unwrap();
            server
                .handle(
                    &request(
                        &server,
                        1,
                        "initialize",
                        json!({"protocolVersion":"2025-11-25"}),
                    ),
                    &|_| Ok(()),
                )
                .unwrap();
            server.transient = true;
            let call = request(
                &server,
                2,
                "tools/call",
                json!({"name":"app_agent_spawn","arguments":{"role":"explore","prompt":"inspect"}}),
            );
            let result = server.handle(&call, &|_| Ok(()));
            assert_eq!(result.is_err(), fail);
            let repeated = server.handle(&call, &|_| Ok(()));
            assert_eq!(repeated.is_err(), fail);
            assert_eq!(owner.calls.lock().unwrap().len(), 1);
            assert!(owner.calls.lock().unwrap()[0].1);
            if !fail {
                let result = result.unwrap();
                assert_eq!(result, repeated.unwrap());
                let wire_text = result["result"]["content"][0]["text"]
                    .as_str()
                    .expect("The CLI consumes MCP text content, not arbitrary result fields.");
                assert_eq!(
                    serde_json::from_str::<Value>(wire_text).unwrap(),
                    json!({"result":"fixture-child-result"})
                );
                assert_eq!(result["result"]["isError"], false);
            }
            let mut child = ReverseMcpServer::new();
            child
                .configure_role(grok_build_plus_host::PlusRuntimeToolPolicy::Plan)
                .unwrap();
            assert!(
                child
                    .configure_collaboration(Some("fixture-run".into()))
                    .is_err()
            );
            std::fs::remove_dir_all(root).unwrap();
        }
    }

    #[test]
    fn child_role_catalog_and_dispatch_are_frozen_before_hooks() {
        use crate::runtime::extension_tools::fixtures::{Executor, Restricted};
        use grok_build_plus_host::PlusRuntimeToolPolicy;
        let root = std::env::temp_dir().join(format!(
            "gbplus-child-acp-{}-{}",
            std::process::id(),
            crate::runtime::types::unix_time_millis()
        ));
        std::fs::create_dir_all(&root).unwrap();
        std::fs::write(root.join("file.txt"), "before").unwrap();
        let bound = grok_build_plus_host::bind_project_folder(&root).unwrap();
        let store = PlusSessionStore::from_state_root(root.join("state"));
        let hook = Arc::new(crate::extensions::hooks::fixtures::Deny::default());
        let context = AdapterContext {
            scope: crate::runtime::types::RuntimeInvocationScope::fixture(),
            extension_context: "",
            bound: &bound,
            store: &store,
            hooks: Some(hook.clone()),
        };
        let mut server = ReverseMcpServer::new();
        server.configure_role(PlusRuntimeToolPolicy::Plan).unwrap();
        assert!(
            server
                .configure_catalog(vec![Executor::declaration()])
                .is_err()
        );
        server.configure_catalog(vec![]).unwrap();
        assert!(server.bind(&context, None).is_err());
        server
            .bind(
                &context,
                Some(Arc::new(Restricted(PlusRuntimeToolPolicy::Plan))),
            )
            .unwrap();
        assert!(
            server
                .catalog()
                .unwrap()
                .iter()
                .all(|t| PlusRuntimeToolPolicy::Plan.allows(t["name"].as_str().unwrap()))
        );
        server
            .journal(&root.join("journal"), "child-provider")
            .unwrap();
        server
            .handle(
                &request(
                    &server,
                    1,
                    "initialize",
                    json!({"protocolVersion":"2025-11-25"}),
                ),
                &|_| Ok(()),
            )
            .unwrap();
        let call = request(
            &server,
            2,
            "tools/call",
            json!({"name":"propose_write","arguments":{"path":"file.txt","after":"after"}}),
        );
        let result = server.handle(&call, &|_| Ok(())).unwrap();
        assert_eq!(result["result"]["isError"], true);
        assert_eq!(*hook.0.lock().unwrap(), 0);
        assert!(server.pending.items.is_empty());
        assert_eq!(
            std::fs::read_to_string(root.join("file.txt")).unwrap(),
            "before"
        );
        assert!(
            server
                .configure_role(PlusRuntimeToolPolicy::Parent)
                .is_err()
        );
        server.revoke();
        assert_eq!(
            server.replacement().unwrap().catalog().unwrap(),
            server.catalog().unwrap()
        );
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn reverse_extension_calls_bind_catalog_and_cache_exact_ids_without_repeating_effects() {
        use crate::runtime::extension_tools::fixtures::Executor;
        let root = std::env::temp_dir().join(format!(
            "gbplus-acp-extension-{}-{}",
            std::process::id(),
            crate::runtime::types::unix_time_millis()
        ));
        std::fs::create_dir_all(&root).unwrap();
        let bound = grok_build_plus_host::bind_project_folder(&root).unwrap();
        let store = PlusSessionStore::from_state_root(root.join("state"));
        let executor = Arc::new(Executor::default());
        let context = AdapterContext {
            scope: crate::runtime::types::RuntimeInvocationScope::fixture(),
            extension_context: "",
            hooks: None,
            bound: &bound,
            store: &store,
        };
        let mut server = ReverseMcpServer::new();
        assert!(server.bind(&context, Some(executor.clone())).is_err());
        server
            .configure_catalog(vec![Executor::declaration()])
            .unwrap();
        server.bind(&context, Some(executor.clone())).unwrap();
        server.journal(&root.join("journal"), "provider").unwrap();
        server
            .handle(
                &request(
                    &server,
                    1,
                    "initialize",
                    json!({"protocolVersion":"2025-11-25"}),
                ),
                &|_| Ok(()),
            )
            .unwrap();
        assert!(
            server
                .catalog()
                .unwrap()
                .iter()
                .any(|tool| tool["name"] == Executor::name())
        );
        let call = request(
            &server,
            2,
            "tools/call",
            json!({"name":Executor::name(),"arguments":{"value":"TRANSIENT_MCP_ARGUMENT"}}),
        );
        let first = server
            .handle_reverse(&call, &json!(500), &|_| Ok(()))
            .unwrap();
        assert_eq!(
            first["result"]["content"][0]["text"],
            "TRANSIENT_MCP_RESULT"
        );
        assert_eq!(
            server
                .handle_reverse(&call, &json!(500), &|_| Ok(()))
                .unwrap(),
            first
        );
        assert_eq!(executor.calls.lock().unwrap().len(), 1);
        assert!(server.transient);
        let disk = std::fs::read_to_string(
            root.join("journal/invocations")
                .join(&server.id)
                .join("calls-v2.json"),
        )
        .unwrap();
        assert!(!disk.contains("TRANSIENT_MCP_ARGUMENT") && !disk.contains("TRANSIENT_MCP_RESULT"));
        server.revoke();
        let replacement = server.replacement().unwrap();
        assert_eq!(replacement.catalog().unwrap(), server.catalog().unwrap());
        assert!(
            server
                .handle_reverse(&call, &json!(500), &|_| Ok(()))
                .is_err()
        );
        assert_eq!(executor.calls.lock().unwrap().len(), 1);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn inactive_exchanges_are_refused_without_replaying_cached_data_or_granting_authority() {
        let mut server = ReverseMcpServer::new();
        let initialize = request(
            &server,
            4,
            "initialize",
            json!({"protocolVersion":"2025-11-25"}),
        );
        assert!(
            server
                .inactive_response(&initialize, &json!(40))
                .unwrap()
                .is_none()
        );
        server
            .handle_reverse(&initialize, &json!(40), &|_| Ok(()))
            .unwrap();
        let cached = server.cache.len();
        server.revoke();
        let refused = server
            .inactive_response(&initialize, &json!(40))
            .unwrap()
            .unwrap();
        assert_eq!(refused["id"], 4);
        assert_eq!(refused["error"]["code"], -32000);
        assert!(refused.get("result").is_none());
        assert_eq!(server.cache.len(), cached);
        assert!(
            server
                .handle_reverse(&initialize, &json!(40), &|_| Ok(()))
                .is_err()
        );
        let replacement = ReverseMcpServer::new();
        assert!(
            replacement
                .inactive_response(&initialize, &json!(40))
                .unwrap()
                .is_some()
        );
        assert!(
            replacement
                .inactive_response(&initialize, &Value::Null)
                .is_err()
        );
        let mut malformed = initialize;
        malformed["message"]["id"] = json!("x".repeat(129));
        assert!(
            replacement
                .inactive_response(&malformed, &json!(40))
                .is_err()
        );
    }
    use super::*;

    fn request(server: &ReverseMcpServer, id: u64, method: &str, params: Value) -> Value {
        let mut request = json!({"serverId":server.id,"message":{"jsonrpc":"2.0","id":id,"method":method,"params":null}});
        request["message"]["params"] = params;
        request
    }

    #[test]
    fn foreign_registration_unbound_effects_and_changed_request_ids_are_refused() {
        let mut server = ReverseMcpServer::new();
        let init = request(
            &server,
            1,
            "initialize",
            json!({"protocolVersion":"2025-11-25"}),
        );
        let response = server.handle(&init, &|_| Ok(())).unwrap();
        assert_eq!(server.handle(&init, &|_| Ok(())).unwrap(), response);
        assert!(
            server
                .handle(&request(&server, 1, "tools/list", json!({})), &|_| Ok(()))
                .is_err()
        );
        let mut foreign = request(&server, 2, "tools/list", json!({}));
        foreign["serverId"] = Value::String("other-connection".into());
        assert!(server.handle(&foreign, &|_| Ok(())).is_err());
        let call = request(
            &server,
            3,
            "tools/call",
            json!({"name":"propose_write", "arguments":{"path":"x","after":"x"}}),
        );
        assert!(
            server
                .handle(&call, &|_| Ok(()))
                .unwrap()
                .get("error")
                .is_some()
        );
        assert!(server.steps.is_empty());
    }

    #[test]
    fn completed_inner_ids_can_repeat_in_distinct_outer_exchanges() {
        let mut server = ReverseMcpServer::new();
        let initialize = request(
            &server,
            0,
            "initialize",
            json!({"protocolVersion":"2025-11-25"}),
        );
        server
            .handle_reverse(&initialize, &json!(10), &|_| Ok(()))
            .unwrap();
        let list = request(&server, 0, "tools/list", json!({}));
        let response = server
            .handle_reverse(&list, &json!(11), &|_| Ok(()))
            .unwrap();
        assert_eq!(response["id"], 0);
        assert_eq!(
            response["result"]["tools"].as_array().unwrap().len(),
            grok_build_plus_host::PLUS_TOOL_DESCRIPTORS.len()
        );
        assert_eq!(
            server
                .handle_reverse(&list, &json!(11), &|_| Ok(()))
                .unwrap(),
            response
        );
    }

    #[test]
    fn gateway_projects_the_same_app_schemas_without_native_machine_tools() {
        let catalog = tool_catalog().unwrap();
        assert_eq!(
            catalog.len(),
            grok_build_plus_host::PLUS_TOOL_DESCRIPTORS.len()
        );
        for tool in catalog {
            assert!(
                grok_build_plus_host::PlusToolName::from_wire(tool["name"].as_str().unwrap())
                    .is_some()
            );
            assert_eq!(tool["inputSchema"]["type"], "object");
        }
    }

    #[test]
    fn reverse_hook_denial_blocks_proposals_and_external_calls_and_duplicate_ids_reuse_refusal() {
        use crate::runtime::extension_tools::fixtures::Executor;
        let root = std::env::temp_dir().join(format!(
            "gbplus-reverse-hook-{}-{}",
            std::process::id(),
            super::super::super::types::unix_time_millis()
        ));
        std::fs::create_dir_all(&root).unwrap();
        std::fs::write(root.join("file.txt"), "before").unwrap();
        let bound = grok_build_plus_host::bind_project_folder(&root).unwrap();
        let store = PlusSessionStore::from_state_root(root.join("state"));
        let hook = Arc::new(crate::extensions::hooks::fixtures::Deny::default());
        let executor = Arc::new(Executor::default());
        let context = AdapterContext {
            scope: crate::runtime::types::RuntimeInvocationScope::fixture(),
            extension_context: "",
            hooks: Some(hook.clone()),
            bound: &bound,
            store: &store,
        };
        let mut server = ReverseMcpServer::new();
        server
            .configure_catalog(vec![Executor::declaration()])
            .unwrap();
        server.bind(&context, Some(executor.clone())).unwrap();
        server
            .handle(
                &request(
                    &server,
                    1,
                    "initialize",
                    json!({"protocolVersion":"2025-11-25"}),
                ),
                &|_| Ok(()),
            )
            .unwrap();
        for (id, name, arguments) in [
            (
                2,
                "propose_write".into(),
                json!({"path":"file.txt","after":"after"}),
            ),
            (3, Executor::name(), json!({"value":"test"})),
        ] {
            let call = request(
                &server,
                id,
                "tools/call",
                json!({"name":name,"arguments":arguments}),
            );
            let result = server.handle(&call, &|_| Ok(())).unwrap();
            assert_eq!(result["result"]["isError"], true);
            assert_eq!(server.handle(&call, &|_| Ok(())).unwrap(), result);
        }
        assert_eq!(*hook.0.lock().unwrap(), 2);
        assert!(server.pending.items.is_empty());
        assert!(executor.calls.lock().unwrap().is_empty());
        assert_eq!(
            std::fs::read_to_string(root.join("file.txt")).unwrap(),
            "before"
        );
        server.hooks = Some(Arc::new(crate::extensions::hooks::fixtures::Allow));
        let escaped = server.handle(&request(&server, 4, "tools/call", json!({
            "name":"propose_write","arguments":{"path":"../escaped.txt","after":"not admitted"}
        })), &|_| Ok(())).unwrap();
        assert_eq!(escaped["result"]["isError"], true);
        assert!(server.pending.items.is_empty());
        server.hooks = Some(Arc::new(crate::extensions::hooks::fixtures::Interrupt));
        let interrupted = request(
            &server,
            5,
            "tools/call",
            json!({"name":"read_file","arguments":{"path":"file.txt"}}),
        );
        assert!(server.handle(&interrupted, &|_| Ok(())).is_err());
        assert!(server.persistence_failed);
        server.revoke();
        assert!(server.hooks.is_none());
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn reverse_proposals_keep_the_real_accept_boundary_and_duplicate_ids_do_not_repeat_effects() {
        let root = std::env::temp_dir().join(format!(
            "gbplus-mcp-proposal-{}-{}",
            std::process::id(),
            super::super::super::types::unix_time_millis()
        ));
        std::fs::create_dir_all(&root).unwrap();
        let before = "\t before \r\n\n";
        let after = "\t after \r\n\n";
        std::fs::write(root.join("file.txt"), before).unwrap();
        let bound = grok_build_plus_host::bind_project_folder(&root).unwrap();
        let store = PlusSessionStore::from_state_root(root.join("state"));
        let mut server = ReverseMcpServer::new();
        server
            .bind(
                &AdapterContext {
                    scope: crate::runtime::types::RuntimeInvocationScope::fixture(),
                    extension_context: "",
                    hooks: None,
                    bound: &bound,
                    store: &store,
                },
                None,
            )
            .unwrap();
        server
            .handle(
                &request(
                    &server,
                    1,
                    "initialize",
                    json!({"protocolVersion":"2025-11-25"}),
                ),
                &|_| Ok(()),
            )
            .unwrap();
        let call = request(
            &server,
            2,
            "tools/call",
            json!({"name":"propose_write","arguments":{"path":"file.txt","after":after}}),
        );
        let first = server.handle(&call, &|_| Ok(())).unwrap();
        assert_eq!(first["result"]["isError"], false);
        assert_eq!(server.handle(&call, &|_| Ok(())).unwrap(), first);
        assert_eq!(server.steps.len(), 1);
        assert_eq!(server.pending.items.len(), 1);
        assert_eq!(server.pending.items[0].after, after.as_bytes());
        assert_eq!(
            std::fs::read_to_string(root.join("file.txt")).unwrap(),
            before
        );
        let read = server
            .handle(
                &request(
                    &server,
                    3,
                    "tools/call",
                    json!({"name":"read_file","arguments":{"path":"file.txt"}}),
                ),
                &|_| Ok(()),
            )
            .unwrap();
        assert_eq!(read["result"]["content"][0]["text"], before);
        server.revoke();
        // Revocation precedes cache lookup: an identical completed call cannot
        // retrieve old output, and this registration can never acquire a new scope.
        assert!(server.handle(&call, &|_| Ok(())).is_err());
        assert!(
            server
                .bind(
                    &AdapterContext {
                        scope: crate::runtime::types::RuntimeInvocationScope::fixture(),
                        extension_context: "",
                        hooks: None,
                        bound: &bound,
                        store: &store,
                    },
                    None
                )
                .is_err()
        );
        assert_eq!(
            server.pending.items.len(),
            1,
            "teardown retains staged review data"
        );
        std::fs::remove_dir_all(root).unwrap();
    }
}
