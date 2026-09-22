//! Catalog identity is app-bound; server annotations are descriptive claims only.

use std::collections::{BTreeMap, BTreeSet};

use serde::Serialize;
use serde_json::{Value, json};

use super::super::ProjectId;

const MAX_CATALOG_BYTES: usize = 2 * 1024 * 1024;
const MAX_TOOLS: usize = 256;
const MAX_PAGES: usize = 16;

/// Frozen metadata for one namespaced external tool. This is not permission.
#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct McpTool {
    wire_name: String,
    app_name: String,
    description: String,
    fingerprint: String,
    input_schema: Value,
    metadata: Value,
}

impl std::fmt::Debug for McpTool {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("McpTool")
            .field("app_name", &self.app_name)
            .field("fingerprint", &self.fingerprint)
            .finish_non_exhaustive()
    }
}

impl McpTool {
    /// Exact case-sensitive server tool name.
    #[must_use]
    pub fn wire_name(&self) -> &str {
        &self.wire_name
    }

    /// App-controlled namespace which cannot shadow an existing app tool.
    #[must_use]
    pub fn app_name(&self) -> &str {
        &self.app_name
    }

    /// Fingerprint of the project, server identity, and full tool metadata.
    #[must_use]
    pub fn fingerprint(&self) -> &str {
        &self.fingerprint
    }

    /// Bounded input schema, never used to fetch external references.
    #[must_use]
    pub const fn input_schema(&self) -> &Value {
        &self.input_schema
    }

    /// Untrusted bounded description for the app's review and provider catalog.
    #[must_use]
    pub fn description(&self) -> &str {
        &self.description
    }

    /// An untrusted hint. The broker must classify and authorize independently.
    #[must_use]
    pub fn claimed_read_only(&self) -> bool {
        self.metadata
            .pointer("/annotations/readOnlyHint")
            .and_then(Value::as_bool)
            == Some(true)
    }
}

/// A bounded sequence of tool pages tied to Rust-resolved app identity.
/// Partial catalogs cannot resolve a tool or be used as an approval preview.
pub struct McpCatalog {
    project: ProjectId,
    server_identity: String,
    tools: BTreeMap<String, McpTool>,
    seen_cursors: BTreeSet<String>,
    expected_cursor: Option<String>,
    pages: usize,
    bytes: usize,
    complete: bool,
    invalid: bool,
}

impl McpCatalog {
    /// Rust-resolved project used when this catalog was created.
    #[must_use]
    pub const fn project(&self) -> &ProjectId {
        &self.project
    }

    /// Create an empty catalog from app-owned project and server bindings.
    /// The server identity must commit to enabled content, configuration,
    /// endpoint/contained image, and the credential binding (never its value).
    ///
    /// # Errors
    /// Refuses malformed app identity before accepting any server metadata.
    pub fn new(project: ProjectId, server_identity: String) -> Result<Self, String> {
        if project.as_str().is_empty()
            || project.as_str().len() > 256
            || project.as_str().chars().any(char::is_control)
            || server_identity.len() != 64
            || !server_identity
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err("MCP catalog has no valid app-issued project/server binding.".into());
        }
        Ok(Self {
            project,
            server_identity,
            tools: BTreeMap::new(),
            seen_cursors: BTreeSet::new(),
            expected_cursor: None,
            pages: 0,
            bytes: 0,
            complete: false,
            invalid: false,
        })
    }

    /// Validate a matched tools/list result and return its next cursor, if any.
    ///
    /// # Errors
    /// Refuses repeated/mismatched pages, duplicates, oversized schemas and tool
    /// names, or metadata beyond connection budgets. A failure invalidates the
    /// whole catalog; already accepted pages cannot provide partial authority.
    pub fn push_page(
        &mut self,
        requested_cursor: Option<&str>,
        page: &Value,
    ) -> Result<Option<String>, String> {
        let result = self.push_page_inner(requested_cursor, page);
        if result.is_err() {
            self.invalid = true;
        }
        result
    }

    fn push_page_inner(
        &mut self,
        requested_cursor: Option<&str>,
        page: &Value,
    ) -> Result<Option<String>, String> {
        if self.invalid
            || self.complete
            || self.pages >= MAX_PAGES
            || requested_cursor != self.expected_cursor.as_deref()
        {
            return Err("MCP catalog page is out of order or its budget is exhausted.".into());
        }
        let encoded = serde_json::to_vec(page).map_err(|_| "Cannot inspect MCP tool page.")?;
        if self.bytes.saturating_add(encoded.len()) > MAX_CATALOG_BYTES {
            return Err("MCP catalog exceeded its aggregate byte limit.".into());
        }
        let entries = page
            .get("tools")
            .and_then(Value::as_array)
            .ok_or("MCP catalog has no tool array.")?;
        if self.tools.len().saturating_add(entries.len()) > MAX_TOOLS {
            return Err("MCP catalog exceeded its tool count limit.".into());
        }
        let cursor = match page.get("nextCursor") {
            None => None,
            Some(Value::String(cursor))
                if super::bounded_text(cursor, 4096) && !self.seen_cursors.contains(cursor) =>
            {
                Some(cursor.clone())
            }
            Some(_) => return Err("MCP catalog cursor is repeated, invalid or oversized.".into()),
        };
        for entry in entries {
            let tool = inspect_tool(&self.project, &self.server_identity, entry)?;
            if self
                .tools
                .values()
                .any(|existing| existing.wire_name == tool.wire_name)
                || self.tools.contains_key(tool.app_name())
            {
                return Err("MCP catalog contains a duplicate tool or namespace collision.".into());
            }
            self.tools.insert(tool.app_name.clone(), tool);
        }
        self.bytes += encoded.len();
        self.pages += 1;
        if let Some(cursor) = &cursor {
            self.seen_cursors.insert(cursor.clone());
        }
        self.complete = cursor.is_none();
        self.expected_cursor.clone_from(&cursor);
        Ok(cursor)
    }

    /// Return only a complete catalog suitable for an app approval preview.
    ///
    /// # Errors
    /// Incomplete/invalidated catalogs are unavailable until independently fetched.
    pub fn tools(&self) -> Result<impl Iterator<Item = &McpTool>, String> {
        self.ensure_complete()?;
        Ok(self.tools.values())
    }

    fn ensure_complete(&self) -> Result<(), String> {
        if self.invalid || !self.complete {
            return Err("MCP catalog is incomplete or invalidated.".into());
        }
        Ok(())
    }

    /// Resolve an app tool name against this frozen catalog; never use a
    /// provider-supplied project, endpoint, server ID, or raw tool schema.
    ///
    /// # Errors
    /// Refuses unrecognized names and catalogs needing refresh/reapproval.
    pub fn resolve(&self, app_name: &str) -> Result<&McpTool, String> {
        self.ensure_complete()?;
        self.tools
            .get(app_name)
            .ok_or_else(|| "External tool is not in the bound app catalog.".into())
    }

    /// Stop admission immediately on `tools/list_changed` or a changed binding.
    pub const fn invalidate(&mut self) {
        self.invalid = true;
    }
}

fn inspect_tool(
    project: &ProjectId,
    server_identity: &str,
    entry: &Value,
) -> Result<McpTool, String> {
    let name = entry
        .get("name")
        .and_then(Value::as_str)
        .filter(|name| tool_name(name))
        .ok_or("MCP tool has an unsupported name.")?;
    let description = match entry.get("description") {
        None => "",
        Some(Value::String(text)) if text.is_empty() || super::bounded_text(text, 8192) => text,
        Some(_) => return Err("MCP tool description is invalid or oversized.".into()),
    };
    let schema = entry
        .get("inputSchema")
        .filter(|schema| schema.is_object())
        .ok_or("MCP tool has no object input schema.")?;
    validate_schema(schema)?;
    if let Some(schema) = entry.get("outputSchema") {
        validate_schema(schema)?;
    }
    if serde_json::to_vec(entry)
        .map_err(|_| "Cannot inspect MCP tool metadata.")?
        .len()
        > 128 * 1024
    {
        return Err("MCP tool metadata exceeds its per-tool budget.".into());
    }
    if entry
        .pointer("/execution/taskSupport")
        .and_then(Value::as_str)
        == Some("required")
    {
        return Err("This MCP tool requires unsupported task execution.".into());
    }
    let namespace = super::digest(&json!([
        "GB Plus external tool v1",
        project.as_str(),
        server_identity,
        name
    ]))?;
    let fingerprint = super::digest(&json!([
        "GB Plus MCP authority binding v1",
        project.as_str(),
        server_identity,
        entry
    ]))?;
    Ok(McpTool {
        wire_name: name.to_owned(),
        app_name: format!(
            "gbext_{}",
            &namespace[..super::MCP_APP_TOOL_HASH_HEX_LENGTH]
        ),
        description: description.to_owned(),
        fingerprint,
        input_schema: schema.clone(),
        metadata: entry.clone(),
    })
}

fn validate_schema(schema: &Value) -> Result<(), String> {
    if !schema.is_object()
        || serde_json::to_vec(schema)
            .map_err(|_| "Cannot inspect MCP schema.")?
            .len()
            > 64 * 1024
    {
        return Err("MCP schema must be an object within 64 KiB.".into());
    }
    let mut pending = vec![(schema, 0usize)];
    let mut nodes = 0usize;
    while let Some((value, depth)) = pending.pop() {
        nodes += 1;
        if depth > 24 || nodes > 8192 {
            return Err("MCP schema structure exceeds its bound.".into());
        }
        match value {
            Value::Object(object) => pending.extend(object.values().map(|v| (v, depth + 1))),
            Value::Array(array) => pending.extend(array.iter().map(|v| (v, depth + 1))),
            _ => {}
        }
    }
    Ok(())
}

pub(super) fn tool_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"_-.".contains(&byte))
}
