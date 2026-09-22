//! Durable turn boundaries and recovery of the first journal generation.

use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};

use serde_json::Value;

use super::{FILE, MAX_JOURNAL_BYTES, OwnerStateRoot, worktree_recovery_digest};

pub(super) fn decode(
    bytes: &[u8],
    source_version: u16,
    root: &Path,
) -> Result<super::Record, String> {
    let mut value: Value = serde_json::from_slice(bytes)
        .map_err(|_| "Responses journal is unreadable; original data was retained.")?;
    if value.get("schemaVersion").and_then(Value::as_u64) != Some(u64::from(source_version))
        || !(1..=super::SCHEMA_VERSION).contains(&source_version)
    {
        return Err(
            "Responses journal version does not match its generation; original retained.".into(),
        );
    }
    if source_version == 1
        && let Some(record) = value.as_object_mut()
    {
        if record.contains_key("turnActive") {
            return Err("Legacy Responses schema contains an unexpected turn-state field; original retained.".into());
        }
        record.insert("turnActive".into(), Value::Bool(false));
    }
    if source_version < 3
        && let Some(record) = value.as_object_mut()
    {
        if record.contains_key("bindingDigest") || record.contains_key("retiredCallIds") {
            return Err("Earlier Responses schema contains unexpected scope or retirement fields; original retained.".into());
        }
        record.insert(
            "bindingDigest".into(),
            Value::String(super::scope_digest(root)),
        );
        record.insert("retiredCallIds".into(), serde_json::json!([]));
        record.insert(
            "schemaVersion".into(),
            serde_json::json!(super::SCHEMA_VERSION),
        );
    }
    serde_json::from_value(value)
        .map_err(|_| "Responses journal is invalid; original data was retained.".into())
}

pub(super) fn validate_record(record: &super::Record) -> Result<(), String> {
    if record.schema_version != super::SCHEMA_VERSION
        || record.items.len() > super::MAX_ITEMS
        || record.effects.len() > super::MAX_ITEMS
        || record.completion_ids.len() > super::MAX_ITEMS
        || record.retired_call_ids.len() > super::MAX_ITEMS
        || record
            .retired_call_ids
            .iter()
            .any(|id| id.len() != 64 || !id.bytes().all(|byte| byte.is_ascii_hexdigit()))
        || !super::valid_identity(&record.context_id)
        || !super::valid_identity(&record.model)
        || record.replay_start > record.items.len()
        || record.measured_items > record.items.len()
        || record
            .compaction_previous_start
            .is_some_and(|index| index > record.replay_start)
        || record
            .tainted_from
            .is_some_and(|index| index >= record.items.len())
    {
        return Err("Responses journal has an unsupported schema or invalid bounds; original data was retained.".into());
    }
    Ok(())
}

pub(super) fn read_existing(root: &Path) -> Result<(Option<Vec<u8>>, u16), String> {
    let owner = OwnerStateRoot::new(root);
    for (name, version) in [
        (FILE, super::SCHEMA_VERSION),
        ("responses-v2.json", 2),
        ("responses-v1.json", 1),
    ] {
        if let Some(bytes) = owner
            .file(name, MAX_JOURNAL_BYTES)
            .map_err(|error| error.to_string())?
            .read()
            .map_err(|error| error.to_string())?
        {
            return Ok((Some(bytes), version));
        }
    }
    Ok((None, 0))
}

pub(super) fn new_context_id(root: &Path) -> String {
    static NEXT: AtomicU64 = AtomicU64::new(1);
    let epoch = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |value| value.as_nanos());
    let mut seed = root.as_os_str().as_encoded_bytes().to_vec();
    seed.extend_from_slice(
        format!(
            ":{}:{epoch}:{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        )
        .as_bytes(),
    );
    format!("native-{}", worktree_recovery_digest(&seed))
}

pub(super) fn has_terminal_output(items: &[Value]) -> bool {
    items.iter().any(|item| {
        item["type"] == "message"
            && item["role"] == "assistant"
            && item
                .get("status")
                .is_none_or(|status| status == "completed")
            && item["content"].as_array().is_some_and(|parts| {
                parts.iter().any(|part| {
                    part["type"] == "output_text"
                        && part["text"]
                            .as_str()
                            .is_some_and(|text| !text.trim().is_empty())
                })
            })
    })
}

pub(super) fn unfinished_prefix(items: &[Value]) -> bool {
    if items.is_empty() {
        return false;
    }
    let mut calls = std::collections::BTreeSet::new();
    let mut terminal = false;
    for item in items {
        match item.get("type").and_then(Value::as_str) {
            Some("function_call") => {
                let Some(id) = item["call_id"].as_str() else {
                    return true;
                };
                if !calls.insert(id) {
                    return true;
                }
                terminal = false;
            }
            Some("function_call_output") => {
                let Some(id) = item["call_id"].as_str() else {
                    return true;
                };
                if !calls.remove(id) {
                    return true;
                }
                terminal = false;
            }
            Some("compaction") => terminal = false,
            _ if item["role"] == "user" => terminal = false,
            _ if has_terminal_output(std::slice::from_ref(item)) => terminal = true,
            _ => {}
        }
    }
    !terminal || !calls.is_empty()
}
