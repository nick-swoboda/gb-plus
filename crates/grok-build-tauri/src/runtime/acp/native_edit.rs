//! Fill a missing native write preview from the already-bound read-only workspace.

use grok_build_plus_host::BoundProject;
use serde_json::{Value, json};
use std::path::Path;

pub(super) fn preview(bound: Option<&BoundProject>, params: &mut Value) {
    let tool = &params["toolCall"];
    if tool["kind"] != "edit" || tool["content"].as_array().is_some_and(|c| !c.is_empty()) {
        return;
    }
    let input = &tool["rawInput"];
    let path = input
        .get("file_path")
        .or_else(|| input.get("path"))
        .and_then(Value::as_str);
    let Some(path) = path else {
        return;
    };
    if let (Some(old), Some(new)) = (
        input
            .get("old_string")
            .or_else(|| input.get("oldText"))
            .and_then(Value::as_str),
        input
            .get("new_string")
            .or_else(|| input.get("newText"))
            .and_then(Value::as_str),
    ) {
        params["appPreview"] =
            json!({"path":path,"oldText":old,"newText":new,"scope":"replacement"});
        return;
    }
    let Some(new) = input.get("content").and_then(Value::as_str) else {
        return;
    };
    let old = bound.and_then(|bound| {
        let path = Path::new(path);
        let normalized;
        let path = if path.is_absolute() {
            normalized = std::fs::canonicalize(path.parent()?)
                .ok()?
                .join(path.file_name()?);
            normalized.as_path()
        } else {
            path
        };
        let relative = if path.is_absolute() {
            path.strip_prefix(bound.folder()).ok()?
        } else {
            path
        };
        let view = crate::workspace::open_workspace_file(bound, relative.to_str()?).ok()?;
        let encoded = serde_json::to_value(view).ok()?;
        encoded.get("content")?.as_str().map(str::to_owned)
    });
    params["appPreview"] = json!({"path":path,"oldText":old,"newText":new,"scope":"file","previousAvailable":old.is_some()});
}
