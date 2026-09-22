//! Read explicitly selected frozen MCP configuration without expanding environment.

use grok_build_plus_host::McpCatalog;
use serde::Serialize;
use serde_json::{Value, json};

use super::super::content::Bundle;
use crate::contracts::ProjectId;

pub(in crate::extensions) mod local;
pub(crate) use local::LocalSpec;

#[derive(Clone)]
pub(crate) struct ServerSpec {
    pub(crate) project: ProjectId,
    pub(crate) identity: String,
    pub(crate) name: String,
    pub(crate) endpoint: String,
    pub(crate) local: Option<LocalSpec>,
    pub(crate) account_identity: Option<String>,
    pub(crate) authorization: Option<std::sync::Arc<grok_build_plus_host::McpBearerAuthorization>>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ServerView {
    pub(crate) name: String,
    pub(crate) endpoint: Option<String>,
    pub(crate) unavailable: Option<String>,
    pub(crate) contained: Option<LocalSpec>,
}

pub(in crate::extensions) fn specs(
    project: &ProjectId,
    content: &str,
    component: &str,
    map: &Value,
    bundle: &Bundle,
) -> Result<super::ServerInventory, String> {
    let servers = map
        .as_object()
        .filter(|map| map.len() <= 16)
        .ok_or("MCP configuration needs at most 16 named servers.")?;
    servers
        .iter()
        .map(|(name, config)| {
            if name.is_empty() || name.len() > 128 || name.chars().any(char::is_control) {
                return Err("MCP configuration has an invalid server name.".into());
            }
            Ok(
                match server(project, content, component, name, config, bundle) {
                    Ok(spec) => (
                        ServerView {
                            name: name.clone(),
                            endpoint: Some(spec.endpoint.clone()),
                            unavailable: None,
                            contained: spec.local.clone(),
                        },
                        Some(spec),
                    ),
                    Err(reason) => (
                        ServerView {
                            name: name.clone(),
                            endpoint: None,
                            unavailable: Some(reason),
                            contained: None,
                        },
                        None,
                    ),
                },
            )
        })
        .collect()
}

fn server(
    project: &ProjectId,
    content: &str,
    component: &str,
    name: &str,
    config: &Value,
    bundle: &Bundle,
) -> Result<ServerSpec, String> {
    if !super::super::valid_digest(content) || !super::super::valid_digest(component) {
        return Err("MCP source does not have a frozen extension binding.".into());
    }
    let local = local::parse(config, content, bundle)?;
    let endpoint = local.as_ref().map_or_else(
        || endpoint(config),
        |spec| Ok(format!("Contained Linux service: {}", spec.command)),
    )?;
    let identity = super::super::digest(
        &serde_json::to_vec(&json!([
            if local.is_some() {
                "GB Plus contained MCP server v1"
            } else {
                "GB Plus HTTPS MCP server v1"
            },
            project.as_str(),
            content,
            component,
            name,
            config,
            "no credential binding"
        ]))
        .map_err(|_| "Cannot encode MCP server binding.")?,
    );
    McpCatalog::new(project.clone(), identity.clone())?;
    Ok(ServerSpec {
        project: project.clone(),
        identity,
        name: name.to_owned(),
        endpoint,
        local,
        account_identity: None,
        authorization: None,
    })
}

/// Configuration support is not a permission or enabled project selection.
pub(in crate::extensions) fn configuration_available(
    map: &Value,
    bundle: &Bundle,
) -> Result<(), String> {
    let servers = map
        .as_object()
        .filter(|servers| !servers.is_empty() && servers.len() <= 16)
        .ok_or("MCP needs one to sixteen named servers.")?;
    for (name, config) in servers {
        if name.is_empty() || name.len() > 128 || name.chars().any(char::is_control) {
            return Err("MCP configuration has an invalid server name.".into());
        }
        if local::parse(config, "preview", bundle)?.is_none() {
            endpoint(config)?;
        }
    }
    Ok(())
}

fn endpoint(config: &Value) -> Result<String, String> {
    let fields = config
        .as_object()
        .ok_or("MCP server configuration must be an object.")?;
    if fields.keys().any(|key| key != "type" && key != "url") {
        return Err("MCP HTTPS configuration accepts only a URL and transport type. Manage account sign-in through the app.".into());
    }
    if config
        .get("type")
        .is_some_and(|kind| !matches!(kind.as_str(), Some("http" | "streamable-http")))
    {
        return Err("This transport is not admitted for HTTPS catalog inspection.".into());
    }
    let text = config
        .get("url")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty() && s.len() <= 4096 && !s.chars().any(char::is_control))
        .ok_or("MCP server requires a bounded HTTPS endpoint.")?;
    let url = tauri::Url::parse(text).map_err(|_| "MCP endpoint is invalid.")?;
    if url.scheme() != "https"
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err(
            "MCP inspection requires HTTPS without embedded credentials, query or fragment.".into(),
        );
    }
    Ok(url.to_string())
}

impl ServerSpec {
    pub(crate) fn catalog_identity(&self) -> &str {
        self.account_identity.as_deref().unwrap_or(&self.identity)
    }
}
