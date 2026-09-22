//! Effective CLI capability inspection before a production or probe prompt.

use std::collections::BTreeSet;
use std::time::{Duration, Instant};

use serde_json::{Value, json};

use super::{RuntimeEventSink, process::AcpProcess};

pub(super) fn verify_gateway(
    process: &mut AcpProcess,
    session_id: &str,
    events: &RuntimeEventSink<'_>,
) -> Result<(), String> {
    let info = process.request(
        "_x.ai/session/info",
        &json!({"sessionId":session_id}),
        events,
    )?;
    validate_session_capabilities(&info, session_id, &process.neutral_cwd)?;
    let started = Instant::now();
    loop {
        let catalog = process.request(
            "_x.ai/mcp/list",
            &json!({"sessionId":session_id,"cache":true}),
            events,
        )?;
        let expected = process.app_tools.catalog()?;
        if validate_catalog_expected(&catalog, &expected)? {
            return Ok(());
        }
        if started.elapsed() > Duration::from_secs(15) {
            return Err("The app MCP gateway did not become ready; no prompt was sent.".into());
        }
        process.cancel.ensure_not_cancelled()?;
        std::thread::sleep(Duration::from_millis(100));
    }
}

fn validate_session_capabilities(
    info: &Value,
    session_id: &str,
    cwd: &std::path::Path,
) -> Result<(), String> {
    if info.get("sessionId").and_then(Value::as_str) != Some(session_id)
        || info.get("cwd").and_then(Value::as_str) != cwd.to_str()
    {
        return Err("CLI effective session identity differs from its exact app binding; no prompt was sent.".into());
    }
    if info.get("agentName").and_then(Value::as_str) != Some("grok-build-plus-gui") {
        let name = info.get("agentName").and_then(Value::as_str).map_or_else(
            || "missing".into(),
            super::protocol::bounded_event_discriminator,
        );
        return Err(format!(
            "CLI effective agent profile is {name}, rather than the app-owned profile; no prompt was sent."
        ));
    }
    if info
        .pointer("/context/toolDefinitionsCount")
        .and_then(Value::as_u64)
        != Some(2)
    {
        let count = info
            .pointer("/context/toolDefinitionsCount")
            .and_then(Value::as_u64);
        return Err(format!(
            "CLI effective built-in tool count is {count:?}; expected only two app gateway operations. No prompt was sent."
        ));
    }
    if let Some(categories) = info.pointer("/context/usageCategories") {
        let rows = categories
            .as_array()
            .filter(|rows| rows.len() <= 32)
            .ok_or("CLI context categories have invalid bounds.")?;
        for row in rows {
            if matches!(
                row.get("label").and_then(Value::as_str),
                Some("Skills" | "Workflows" | "AGENTS.md")
            ) && row.get("tokens").and_then(Value::as_u64) != Some(0)
            {
                return Err("CLI discovered ambient skill, workflow, or instruction content; no prompt was sent.".into());
            }
        }
    }
    Ok(())
}

#[cfg(test)]
fn validate_catalog(catalog: &Value) -> Result<bool, String> {
    validate_catalog_expected(catalog, &super::mcp::ReverseMcpServer::new().catalog()?)
}

fn validate_catalog_expected(catalog: &Value, expected_tools: &[Value]) -> Result<bool, String> {
    let servers = catalog
        .get("servers")
        .and_then(Value::as_array)
        .filter(|servers| servers.len() <= 128)
        .ok_or("CLI MCP catalog is missing or oversized.")?;
    let mut found = false;
    for server in servers {
        let app_owned = server.get("name").and_then(Value::as_str) == Some(super::mcp::SERVER_NAME);
        let enabled = server.pointer("/session/enabled").and_then(Value::as_bool) == Some(true);
        let ready = server.pointer("/session/status").and_then(Value::as_str) == Some("ready");
        if !app_owned {
            if enabled || ready {
                return Err(
                    "CLI activated an MCP server outside the app gateway; no prompt was sent."
                        .into(),
                );
            }
            continue;
        }
        if found {
            return Err("CLI returned duplicate app gateway identities.".into());
        }
        found = true;
        if !enabled || !ready {
            return Ok(false);
        }
        let tools = server
            .pointer("/session/tools")
            .and_then(Value::as_array)
            .ok_or("CLI app gateway has no effective tool list.")?;
        let expected = expected_tools
            .iter()
            .map(|tool| {
                tool["name"]
                    .as_str()
                    .ok_or("App gateway catalog lost a tool name.")
            })
            .collect::<Result<Vec<_>, _>>()?
            .into_iter()
            .collect::<BTreeSet<_>>();
        let mut actual = BTreeSet::new();
        for tool in tools {
            let name = tool
                .get("name")
                .and_then(Value::as_str)
                .ok_or("CLI gateway tool has no name.")?;
            if tool.get("enabled").and_then(Value::as_bool) != Some(true) || !actual.insert(name) {
                return Err("CLI gateway tool is disabled or duplicated.".into());
            }
        }
        if actual != expected {
            let missing = expected
                .difference(&actual)
                .copied()
                .take(32)
                .collect::<Vec<_>>()
                .join(", ");
            let unexpected = actual
                .difference(&expected)
                .take(32)
                .map(|name| super::protocol::bounded_event_discriminator(name))
                .collect::<Vec<_>>()
                .join(", ");
            return Err(format!(
                "CLI effective app-tool catalog differs from this app version. Missing: [{missing}]. Unexpected: [{unexpected}]."
            ));
        }
    }
    Ok(found)
}

/// Upstream's first-title generator is unconditional on a fresh actor. Close
/// the empty session, assign a fixed title, and load it before any content: the
/// loader marks its title generator done. No hidden title model call can race
/// the app's execution lease. Manual rename on a live actor alone is insufficient.
pub(super) fn seed_title_without_inference(
    process: &mut super::process::AcpProcess,
    session_id: &str,
    events: &super::RuntimeEventSink<'_>,
) -> Result<(), String> {
    process.request_close_during_teardown(session_id)?;
    let renamed = process.request(
        "_x.ai/session/rename",
        &serde_json::json!({"sessionId":session_id,"cwd":process.neutral_cwd,"title":"GB Plus conversation"}),
        events,
    )?;
    if renamed.get("success").and_then(serde_json::Value::as_bool) != Some(true) {
        return Err("Grok CLI did not acknowledge its app-owned session title.".into());
    }
    // Only an unbound catalog exists during bootstrap; replace its opaque
    // registration so the abandoned session actor cannot retain authority.
    process.app_tools = process.app_tools.replacement()?;
    process.request(
        "session/load",
        &serde_json::json!({"sessionId":session_id,"cwd":process.neutral_cwd,"mcpServers":[],"_meta":{
            "x.ai/mcp/servers":[process.app_tools.registration()],
            "systemPromptOverride": super::protocol::strict_acp_system_prompt(),
        }}),
        events,
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn effective_catalog_refuses_foreign_servers_missing_tools_and_ambient_context() {
        let mut catalog: Value = serde_json::from_str(include_str!(
            "../../../tests/fixtures/acp-gateway-catalog.json"
        ))
        .unwrap();
        assert!(validate_catalog(&catalog).unwrap());
        catalog["servers"]
            .as_array_mut()
            .unwrap()
            .push(json!({"name":"foreign","session":{"enabled":true,"status":"ready"}}));
        assert!(validate_catalog(&catalog).is_err());
        catalog["servers"].as_array_mut().unwrap().pop();
        catalog["servers"][0]["session"]["tools"]
            .as_array_mut()
            .unwrap()
            .pop();
        assert!(validate_catalog(&catalog).is_err());
        let cwd = std::path::Path::new("/neutral");
        let mut info = json!({"sessionId":"session","cwd":"/neutral","agentName":"grok-build-plus-gui","context":{"toolDefinitionsCount":2}});
        validate_session_capabilities(&info, "session", cwd).unwrap();
        info["context"]["toolDefinitionsCount"] = json!(22);
        assert!(validate_session_capabilities(&info, "session", cwd).is_err());
        info["context"]["toolDefinitionsCount"] = json!(2);
        info["context"]["usageCategories"] = json!([{"label":"Skills","tokens":100}]);
        assert!(validate_session_capabilities(&info, "session", cwd).is_err());
    }
}
