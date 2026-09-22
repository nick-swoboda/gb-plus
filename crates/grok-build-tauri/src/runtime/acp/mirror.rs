//! Bounded app-owned session mirrors; transient CLI context has no disk payload.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use super::process::AcpProcess;
use crate::owner_state::OwnerStateRoot;

const FILE: &str = "acp-context-v1.json";
const MAX_BYTES: u64 = 10 * 1024 * 1024;
const MAX_UPDATES: usize = 4096;

#[derive(Deserialize, Serialize)]
#[serde(tag = "status", rename_all = "snake_case", deny_unknown_fields)]
enum Mirror {
    Ready {
        schema_version: u16,
        session_id: String,
        state: Value,
        updates: Vec<Value>,
        checkpoints: Vec<Checkpoint>,
    },
    Unavailable {
        schema_version: u16,
        session_id: String,
    },
    Interrupted {
        schema_version: u16,
        session_id: String,
    },
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Checkpoint {
    name: String,
    bytes: Vec<u8>,
}

pub(super) fn begin(root: &Path, session_id: &str) -> Result<bool, String> {
    let owner = OwnerStateRoot::new(root);
    let mut transient = false;
    if let Some(bytes) = owner
        .file(FILE, MAX_BYTES)
        .map_err(|e| e.to_string())?
        .read()
        .map_err(|e| e.to_string())?
    {
        match serde_json::from_slice::<Mirror>(&bytes).map_err(|_| "ACP context marker is invalid; retained for recovery.")? {
            Mirror::Interrupted { .. } => return Err("The previous CLI execution was interrupted. Reset its provider context explicitly; uncertain tool effects cannot be repeated.".into()),
            Mirror::Ready { schema_version: 1, session_id: id, .. } if id == session_id => {
                owner.file("acp-context-before-turn.json",MAX_BYTES).map_err(|e| e.to_string())?.replace(&bytes).map_err(|e| e.to_string())?;
            }
            Mirror::Unavailable { schema_version: 1, session_id: id } if id == session_id => { transient = true; }
            _ => return Err("ACP execution marker has an unsupported schema or different session identity.".into()),
        }
    }
    write(
        root,
        &Mirror::Interrupted {
            schema_version: 1,
            session_id: session_id.into(),
        },
    )?;
    Ok(transient)
}

pub(super) fn unavailable(root: &Path, session_id: &str) -> Result<(), String> {
    write(
        root,
        &Mirror::Unavailable {
            schema_version: 1,
            session_id: session_id.into(),
        },
    )
}

pub(super) fn restore(process: &mut AcpProcess, session_id: &str) -> Result<(), String> {
    let existing = process.request(
        "_x.ai/session/state",
        &json!({"sessionId":session_id,"cwd":process.neutral_cwd}),
        &|_| Ok(()),
    );
    if let Ok(state) = existing {
        // Existing context is usable only in the currently validated RAM home.
        if state.pointer("/summary/info/id").and_then(Value::as_str) == Some(session_id) {
            return refuse_interrupted(&process.runtime_root);
        }
        return Err("The CLI RAM session has a different persisted identity.".into());
    }
    let file = OwnerStateRoot::new(&process.runtime_root)
        .file(FILE, MAX_BYTES)
        .map_err(|e| e.to_string())?;
    let bytes = file.read().map_err(|e|e.to_string())?.ok_or("The app-referenced CLI session has no verified mirror. Its original home must be migrated before continuing.")?;
    let Mirror::Ready {
        schema_version: 1,
        session_id: stored_id,
        state,
        updates,
        checkpoints,
    } = serde_json::from_slice::<Mirror>(&bytes)
        .map_err(|_| "ACP mirror is unreadable; original retained.")?
    else {
        return Err("This CLI context was interrupted or used transient data that is no longer in memory. Reset the provider context explicitly or reattach its sources in a new context.".into());
    };
    if stored_id != session_id || updates.len() > MAX_UPDATES || checkpoints.len() > 128 {
        return Err("ACP mirror does not match its app-owned session or bounds.".into());
    }
    process.request(
        "_x.ai/session/import",
        &json!({"sessionId":session_id,"cwd":process.neutral_cwd,"state":state,"updates":updates}),
        &|_| Ok(()),
    )?;
    restore_checkpoints(process, session_id, &checkpoints)?;
    let (read_state, read_updates) = read_snapshot(process, session_id)?;
    if normalize_state(read_state) != normalize_state(state) || read_updates != updates {
        return Err("Imported CLI session differs from its source mirror. No provider reference was switched.".into());
    }
    Ok(())
}

fn refuse_interrupted(root: &Path) -> Result<(), String> {
    if let Some(bytes) = OwnerStateRoot::new(root)
        .file(FILE, MAX_BYTES)
        .map_err(|e| e.to_string())?
        .read()
        .map_err(|e| e.to_string())?
    {
        match serde_json::from_slice::<Mirror>(&bytes)
            .map_err(|_| "ACP execution marker is invalid.")?
        {
            Mirror::Interrupted { .. } => {
                return Err(
                    "Interrupted CLI execution requires an explicit provider-context reset.".into(),
                );
            }
            Mirror::Ready {
                schema_version: 1, ..
            }
            | Mirror::Unavailable {
                schema_version: 1, ..
            } => {}
            _ => return Err("ACP mirror schema is unsupported; original retained.".into()),
        }
    }
    Ok(())
}

pub(super) fn checkpoint(
    process: &mut AcpProcess,
    session_id: &str,
    transient: bool,
) -> Result<(), String> {
    if transient {
        return unavailable(&process.runtime_root, session_id);
    }
    let (state, updates) = read_snapshot(process, session_id)?;
    let checkpoints = read_checkpoints(process, session_id)?;
    write(
        &process.runtime_root,
        &Mirror::Ready {
            schema_version: 1,
            session_id: session_id.into(),
            state,
            updates,
            checkpoints,
        },
    )
}

fn read_snapshot(
    process: &mut AcpProcess,
    session_id: &str,
) -> Result<(Value, Vec<Value>), String> {
    let state = process.request(
        "_x.ai/session/state",
        &json!({"sessionId":session_id,"cwd":process.neutral_cwd}),
        &|_| Ok(()),
    )?;
    if state.pointer("/summary/info/id").and_then(Value::as_str) != Some(session_id) {
        return Err("CLI snapshot identity is invalid.".into());
    }
    if state.pointer("/summary/info/cwd").and_then(Value::as_str) != process.neutral_cwd.to_str() {
        return Err("CLI snapshot escaped its app-owned neutral working directory.".into());
    }
    let mut updates = Vec::new();
    let mut expected_count = None;
    loop {
        let page = process.request("_x.ai/session/updates", &json!({"sessionId":session_id,"cwd":process.neutral_cwd,"offset":updates.len(),"limit":256}), &|_|Ok(()))?;
        let total = page["totalCount"]
            .as_u64()
            .filter(|count| *count <= MAX_UPDATES as u64)
            .ok_or("CLI mirror update count exceeds its bound.")?;
        if expected_count
            .replace(total)
            .is_some_and(|previous| previous != total)
        {
            return Err("CLI history changed during its idle snapshot.".into());
        }
        let rows = page["updates"]
            .as_array()
            .filter(|rows| rows.len() <= 256)
            .ok_or("CLI mirror page is malformed.")?;
        updates.extend(rows.iter().cloned());
        if serde_json::to_vec(&updates)
            .map_err(|e| e.to_string())?
            .len() as u64
            > MAX_BYTES
        {
            return Err("CLI mirror exceeded its byte bound.".into());
        }
        if page["hasMore"] == false {
            if updates.len() as u64 != total {
                return Err("CLI mirror was incomplete.".into());
            }
            return Ok((state, updates));
        }
        if rows.is_empty() || updates.len() >= MAX_UPDATES {
            return Err("CLI mirror pagination made no bounded progress.".into());
        }
    }
}

fn normalize_state(mut state: Value) -> Value {
    // Exact upstream import normalization; all other metadata and every ordered
    // transcript envelope must match unchanged after destination readback.
    if let Some(summary) = state.get_mut("summary").and_then(Value::as_object_mut) {
        for field in [
            "grok_home",
            "sandbox_profile",
            "git_remotes",
            "chat_format_version",
            "prompt_display_cwd",
            "source_workspace_dir",
            "git_root_dir",
            "head_commit",
            "head_branch",
            "worktree_label",
            "request_id",
        ] {
            summary.remove(field);
        }
        if let Some(info) = summary.get_mut("info").and_then(Value::as_object_mut) {
            info.remove("cwd");
        }
    }
    state
}

fn session_dir(process: &AcpProcess, session_id: &str) -> Result<PathBuf, String> {
    if session_id.len() != 36
        || !session_id
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() || byte == b'-')
    {
        return Err("CLI checkpoint identity is not a UUID.".into());
    }
    let sessions = process.home.join("sessions");
    let mut found = None;
    for (index, entry) in std::fs::read_dir(&sessions)
        .map_err(|e| e.to_string())?
        .enumerate()
    {
        if index >= 1024 {
            return Err("CLI session directory lookup exceeded its bound.".into());
        }
        let entry = entry.map_err(|e| e.to_string())?;
        if !entry.file_type().map_err(|e| e.to_string())?.is_dir() {
            continue;
        }
        let path = entry.path().join(session_id);
        if std::fs::symlink_metadata(&path)
            .is_ok_and(|meta| meta.is_dir() && !meta.file_type().is_symlink())
            && found.replace(path).is_some()
        {
            return Err("Duplicate destination CLI session identities were refused.".into());
        }
    }
    found.ok_or("CLI session directory is unavailable.".into())
}

fn checkpoint_name(name: &str) -> bool {
    name.len() <= 128
        && Path::new(name).extension() == Some(std::ffi::OsStr::new("json"))
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"-_.".contains(&byte))
        && !name.starts_with('.')
}
fn read_checkpoints(process: &AcpProcess, session_id: &str) -> Result<Vec<Checkpoint>, String> {
    let root = session_dir(process, session_id)?.join("compaction_checkpoints");
    if !root.exists() {
        return Ok(Vec::new());
    }
    let mut files = Vec::new();
    for entry in std::fs::read_dir(&root).map_err(|e| e.to_string())? {
        let entry = entry.map_err(|e| e.to_string())?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| "Checkpoint name is invalid.")?;
        if files.len() >= 128 || !checkpoint_name(&name) {
            return Err("CLI checkpoint files exceed the admitted inventory.".into());
        }
        let bytes = OwnerStateRoot::new(&root)
            .file(&name, 2 * 1024 * 1024)
            .map_err(|e| e.to_string())?
            .read()
            .map_err(|e| e.to_string())?
            .ok_or("Checkpoint disappeared during snapshot.")?;
        files.push(Checkpoint { name, bytes });
    }
    files.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(files)
}
fn restore_checkpoints(
    process: &AcpProcess,
    session_id: &str,
    files: &[Checkpoint],
) -> Result<(), String> {
    let root = session_dir(process, session_id)?.join("compaction_checkpoints");
    for file in files {
        if !checkpoint_name(&file.name) {
            return Err("CLI mirror checkpoint name is invalid.".into());
        }
        let owner = OwnerStateRoot::new(&root)
            .file(&file.name, 2 * 1024 * 1024)
            .map_err(|e| e.to_string())?;
        if let Some(existing) = owner.read().map_err(|e| e.to_string())? {
            if existing != file.bytes {
                return Err("Duplicate CLI checkpoint differs; original retained.".into());
            }
        } else {
            owner.replace(&file.bytes).map_err(|e| e.to_string())?;
        }
    }
    Ok(())
}
fn write(root: &Path, mirror: &Mirror) -> Result<(), String> {
    OwnerStateRoot::new(root)
        .file(FILE, MAX_BYTES)
        .map_err(|e| e.to_string())?
        .replace(&serde_json::to_vec(mirror).map_err(|e| e.to_string())?)
        .map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn interruption_is_durable_and_unsupported_or_cross_session_mirrors_cannot_start() {
        let root = std::env::temp_dir().join(format!(
            "gbplus-mirror-{}-{}",
            std::process::id(),
            crate::runtime::types::unix_time_millis()
        ));
        write(
            &root,
            &Mirror::Ready {
                schema_version: 1,
                session_id: "one".into(),
                state: json!({}),
                updates: Vec::new(),
                checkpoints: Vec::new(),
            },
        )
        .unwrap();
        assert!(begin(&root, "other").is_err());
        assert!(!begin(&root, "one").unwrap());
        assert!(begin(&root, "one").is_err());
        assert!(root.join("acp-context-before-turn.json").exists());
        unavailable(&root, "one").unwrap();
        assert!(begin(&root, "one").unwrap());
        write(
            &root,
            &Mirror::Unavailable {
                schema_version: 99,
                session_id: "one".into(),
            },
        )
        .unwrap();
        assert!(begin(&root, "one").is_err());
        std::fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn normalization_removes_only_documented_host_metadata() {
        let state = json!({"summary":{"info":{"id":"original","cwd":"old"},"grok_home":"old","generated_title":"KEEP","num_messages":12,"request_id":"old","custom":"KEEP"},"usage":{"tokens":123}});
        let normalized = normalize_state(state);
        assert_eq!(normalized.pointer("/summary/info/id").unwrap(), "original");
        assert_eq!(
            normalized.pointer("/summary/generated_title").unwrap(),
            "KEEP"
        );
        assert_eq!(normalized.pointer("/summary/custom").unwrap(), "KEEP");
        assert_eq!(normalized.pointer("/usage/tokens").unwrap(), 123);
        assert!(normalized.pointer("/summary/grok_home").is_none());
    }
}
