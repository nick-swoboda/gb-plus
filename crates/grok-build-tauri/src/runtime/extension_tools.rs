//! The same bounded declarations and dispatch boundary serve both chat transports.

use std::collections::BTreeSet;

use grok_build_plus_host::{PlusExtensionTool, PlusExternalToolExecutor, PlusLiveChatRequest};
use serde_json::{Value, json};

use super::types::{RuntimeEvent, RuntimeEventSink};

pub(super) fn hook_refusal(
    name: &str,
    reason: &str,
    events: &RuntimeEventSink<'_>,
) -> Result<Value, String> {
    events(RuntimeEvent::ToolRequest {
        name: name.into(),
        detail: "App tool intent reached an enabled hook boundary.".into(),
    })?;
    events(RuntimeEvent::ToolRefused {
        name: name.into(),
        reason: reason.into(),
    })?;
    Ok(json!({"isError":true,"content":[{"type":"text","text":reason}]}))
}

pub(super) fn catalog(
    external: Option<&dyn PlusExternalToolExecutor>,
) -> Result<Vec<PlusExtensionTool>, String> {
    let tools = external
        .map_or_else(|| Ok(Vec::new()), PlusExternalToolExecutor::extension_tools)
        .map_err(|e| e.to_string())?;
    if policy(external) != grok_build_plus_host::PlusRuntimeToolPolicy::Parent && !tools.is_empty()
    {
        return Err("Child executions cannot inherit extension tools.".into());
    }
    if tools.len() > 32 {
        return Err("App extension catalog exceeded 32 tools.".into());
    }
    let mut names = BTreeSet::new();
    let mut bytes = 0;
    for tool in &tools {
        tool.validate().map_err(|e| e.to_string())?;
        if !names.insert(&tool.name) {
            return Err("App extension tool name collided.".into());
        }
        bytes += tool.description.len() + tool.parameters.to_string().len();
        if bytes > 1024 * 1024 {
            return Err("App extension catalog exceeded 1 MiB.".into());
        }
    }
    Ok(tools)
}

pub(super) fn append_to_request(
    request: &mut PlusLiveChatRequest,
    external: Option<&dyn PlusExternalToolExecutor>,
) -> Result<(), String> {
    let declarations = catalog(external)?;
    let collaboration = super::collaboration_tools::binding(external)?;
    let role = policy(external);
    if declarations.is_empty()
        && collaboration.is_none()
        && role == grok_build_plus_host::PlusRuntimeToolPolicy::Parent
    {
        return Ok(());
    }
    let mut body: Value =
        serde_json::from_str(&request.body).map_err(|_| "App request is malformed.")?;
    let tools = body
        .get_mut("tools")
        .and_then(Value::as_array_mut)
        .ok_or("App tool declarations are absent.")?;
    role.restrict_declarations(tools)?;
    if collaboration.is_some() {
        for mut declaration in grok_build_plus_host::plus_collaboration_declarations() {
            declaration["type"] = serde_json::json!("function");
            declaration["strict"] = serde_json::json!(false);
            tools.push(declaration);
        }
    }
    for tool in declarations {
        tools.push(
            json!({"type":"function", "name":tool.name, "description":tool.description,
            "parameters":tool.parameters, "strict":false}),
        );
    }
    let encoded =
        serde_json::to_string(&body).map_err(|_| "Cannot encode extension declarations.")?;
    if encoded.len() > 12 * 1024 * 1024 {
        return Err("Native request with extensions exceeds 12 MiB.".into());
    }
    request.body = encoded;
    Ok(())
}

pub(super) fn policy(
    external: Option<&dyn PlusExternalToolExecutor>,
) -> grok_build_plus_host::PlusRuntimeToolPolicy {
    external.map_or(
        grok_build_plus_host::PlusRuntimeToolPolicy::Parent,
        PlusExternalToolExecutor::tool_policy,
    )
}

pub(super) fn role_refusal(
    name: &str,
    reason: &str,
    events: &RuntimeEventSink<'_>,
) -> Result<Value, String> {
    events(RuntimeEvent::ToolRequest {
        name: name.into(),
        detail: "App-issued child role checked before hooks or tool effects.".into(),
    })?;
    events(RuntimeEvent::ToolRefused {
        name: name.into(),
        reason: reason.into(),
    })?;
    Ok(json!({"isError":true,"content":[{"type":"text","text":reason}]}))
}

pub(super) fn execute(
    external: Option<&dyn PlusExternalToolExecutor>,
    invocation: &str,
    name: &str,
    arguments: &Value,
    events: &RuntimeEventSink<'_>,
) -> Result<Value, String> {
    if let Some(reason) = policy(external).refusal(name) {
        return role_refusal(name, reason, events);
    }
    if !catalog(external)?.iter().any(|tool| tool.name == name) || !arguments.is_object() {
        return Err("Extension call is outside the app's frozen run catalog.".into());
    }
    events(RuntimeEvent::ToolRequest {
        name: name.into(),
        detail: "External tool requested; the app broker requires its own bound approval.".into(),
    })?;
    let result = external
        .and_then(|external| external.execute_extension(invocation, name, arguments))
        .ok_or("This run has no owner for the requested extension tool.")?
        .map_err(|e| e.to_string());
    let event = if result
        .as_ref()
        .is_ok_and(|value| value.get("isError") != Some(&Value::Bool(true)))
    {
        RuntimeEvent::ToolCompleted {
            name: name.into(),
            detail: "External tool returned a validated result. Its raw content remains transient."
                .into(),
        }
    } else {
        RuntimeEvent::ToolRefused { name: name.into(), reason: "External call was refused, failed or interrupted. Submitted effects are not automatically repeated.".into() }
    };
    events(event)?;
    result
}

#[cfg(test)]
pub(crate) mod fixtures {
    use super::*;
    use grok_build_plus_host::{PlusHostError, PlusToolRequest};
    use std::sync::Mutex;

    pub(crate) struct Restricted(pub(crate) grok_build_plus_host::PlusRuntimeToolPolicy);
    impl PlusExternalToolExecutor for Restricted {
        fn tool_policy(&self) -> grok_build_plus_host::PlusRuntimeToolPolicy {
            self.0
        }
        fn execute(&self, _: &PlusToolRequest) -> Option<Result<String, PlusHostError>> {
            panic!("child high-power dispatch must be refused before reaching its executor")
        }
        fn execute_extension(
            &self,
            _: &str,
            _: &str,
            _: &Value,
        ) -> Option<Result<Value, PlusHostError>> {
            panic!("child extension dispatch must be refused before reaching its executor")
        }
    }

    #[derive(Default)]
    pub(crate) struct Executor {
        pub(crate) calls: Mutex<Vec<(String, String, Value)>>,
    }

    impl Executor {
        pub(crate) fn name() -> String {
            format!(
                "gbext_{}",
                "a".repeat(grok_build_plus_host::MCP_APP_TOOL_HASH_HEX_LENGTH)
            )
        }
        pub(crate) fn declaration() -> PlusExtensionTool {
            PlusExtensionTool {
                name: Self::name(),
                description: "An app-bound fixture".into(),
                parameters: json!({"type":"object","properties":{"value":{"type":"string"}}}),
                fingerprint: "b".repeat(64),
            }
        }
    }

    impl PlusExternalToolExecutor for Executor {
        fn execute(&self, _: &PlusToolRequest) -> Option<Result<String, PlusHostError>> {
            None
        }
        fn extension_tools(&self) -> Result<Vec<PlusExtensionTool>, PlusHostError> {
            Ok(vec![Self::declaration()])
        }
        fn execute_extension(
            &self,
            invocation: &str,
            name: &str,
            arguments: &Value,
        ) -> Option<Result<Value, PlusHostError>> {
            self.calls
                .lock()
                .unwrap()
                .push((invocation.into(), name.into(), arguments.clone()));
            Some(Ok(
                json!({"content":[{"type":"text","text":"TRANSIENT_MCP_RESULT"}]}),
            ))
        }
    }

    #[test]
    fn external_namespace_cannot_shadow_builtins_or_dispatch_unknown_names() {
        let mut declaration = Executor::declaration();
        declaration.name = "read_file".into();
        assert!(declaration.validate().is_err());
        declaration = Executor::declaration();
        declaration.parameters = json!({"description":"x".repeat(65536)});
        assert!(declaration.validate().is_err());
        let executor = Executor::default();
        assert!(
            execute(
                Some(&executor),
                "call",
                "read_file",
                &json!({}),
                &|_| Ok(())
            )
            .is_err()
        );
        assert!(
            execute(
                Some(&executor),
                "call",
                &format!(
                    "gbext_{}",
                    "c".repeat(grok_build_plus_host::MCP_APP_TOOL_HASH_HEX_LENGTH)
                ),
                &json!({}),
                &|_| Ok(())
            )
            .is_err()
        );
        assert!(executor.calls.lock().unwrap().is_empty());
    }
}
