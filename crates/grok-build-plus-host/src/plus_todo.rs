//! In-turn todo list for GB Plus.
//!
//! Persists on the plus desktop state root. This is not a workspace write
//! and not an `EventLedger` event.

use std::collections::HashSet;

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use super::{PlusHostError, PlusSessionStore};

/// Owner-only JSON file under the plus state root.
pub const PLUS_TODOS_FILE: &str = "plus-todos.json";

/// Phrase proving `todo_write` did not write the bound folder.
pub const PLUS_TODO_NOT_WORKSPACE: &str = "not a workspace write";

/// One todo status, matching 1.05 `pending` / `in_progress` / `completed`.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PlusTodoStatus {
    /// Not started.
    Pending,
    /// Current in-turn work.
    InProgress,
    /// Done.
    Completed,
}

impl PlusTodoStatus {
    /// Wire spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::InProgress => "in_progress",
            Self::Completed => "completed",
        }
    }

    /// Parses a status word.
    ///
    /// # Errors
    ///
    /// Returns [`PlusHostError::Proposal`] for an unknown status.
    pub fn parse(text: &str) -> Result<Self, PlusHostError> {
        match text {
            "pending" => Ok(Self::Pending),
            "in_progress" => Ok(Self::InProgress),
            "completed" => Ok(Self::Completed),
            other => Err(PlusHostError::Proposal(format!(
                "todo status is invalid: {other}"
            ))),
        }
    }
}

/// One persisted todo item.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct PlusTodoItem {
    /// Stable id used by merge.
    pub id: String,
    /// User-visible text.
    pub content: String,
    /// Current status.
    pub status: PlusTodoStatus,
}

/// One update from `todo_write`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PlusTodoUpdate {
    /// Stable id.
    pub id: String,
    /// New content. Omitted on merge keeps the previous text.
    pub content: Option<String>,
    /// New status. Omitted defaults to pending on insert.
    pub status: Option<PlusTodoStatus>,
}

/// Desktop-local todo list.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct PlusTodoList {
    /// Items in list order.
    pub items: Vec<PlusTodoItem>,
}

/// Loads the todo list from the plus state root. Missing file is empty.
///
/// # Errors
///
/// Returns [`PlusHostError::Session`] when the file is present but invalid.
pub fn load_plus_todos(store: &PlusSessionStore) -> Result<PlusTodoList, PlusHostError> {
    match store.read_owner_only_text(PLUS_TODOS_FILE)? {
        None => Ok(PlusTodoList::default()),
        Some(text) => serde_json::from_str(&text).map_err(|error| {
            PlusHostError::Session(format!("{PLUS_TODOS_FILE} is not valid JSON: {error}"))
        }),
    }
}

/// Writes `todo_write` merge or replace onto the plus state root.
///
/// # Errors
///
/// Returns [`PlusHostError::Proposal`] for duplicate ids, or session I/O
/// errors when the state root cannot be written.
pub fn plus_todo_write(
    store: &PlusSessionStore,
    updates: &[PlusTodoUpdate],
    merge: bool,
) -> Result<PlusTodoList, PlusHostError> {
    validate_no_duplicate_ids(updates)?;
    let mut list = if merge {
        load_plus_todos(store)?
    } else {
        PlusTodoList::default()
    };
    if merge {
        apply_merge(&mut list, updates);
    } else {
        apply_replace(&mut list, updates);
    }
    let text = serde_json::to_string_pretty(&list)
        .map_err(|error| PlusHostError::Session(format!("cannot encode todos: {error}")))?;
    store.write_owner_only_text(PLUS_TODOS_FILE, &text)?;
    Ok(list)
}

/// Formats the list for the tool trail.
#[must_use]
pub fn present_plus_todos(list: &PlusTodoList) -> String {
    let mut lines: Vec<String> = list
        .items
        .iter()
        .map(|item| {
            format!(
                "todo {} [{}] {}",
                item.id,
                item.status.as_str(),
                item.content
            )
        })
        .collect();
    if lines.is_empty() {
        lines.push("todo list empty".into());
    }
    lines.push(PLUS_TODO_NOT_WORKSPACE.into());
    lines.join("\n")
}

/// Parses `todo_write` JSON arguments into updates plus the merge flag.
///
/// # Errors
///
/// Returns [`PlusHostError::Live`] when `todos` is missing or an item
/// lacks `id`.
pub fn plus_todo_updates_from_args(
    args: &Value,
) -> Result<(Vec<PlusTodoUpdate>, bool), PlusHostError> {
    let todos = args
        .get("todos")
        .and_then(Value::as_array)
        .ok_or_else(|| PlusHostError::Live("todo_write requires todos".into()))?;
    let merge = args.get("merge").and_then(Value::as_bool).unwrap_or(false);
    let mut updates = Vec::new();
    for item in todos {
        let id = item
            .get("id")
            .and_then(Value::as_str)
            .ok_or_else(|| PlusHostError::Live("todo_write item is missing id".into()))?;
        if id.trim().is_empty() {
            return Err(PlusHostError::Live("todo_write item is missing id".into()));
        }
        let content = item
            .get("content")
            .and_then(Value::as_str)
            .map(ToOwned::to_owned);
        let status = match item.get("status").and_then(Value::as_str) {
            None => None,
            Some(text) => Some(
                PlusTodoStatus::parse(text)
                    .map_err(|error| PlusHostError::Live(format!("todo_write {error}")))?,
            ),
        };
        updates.push(PlusTodoUpdate {
            id: id.to_owned(),
            content,
            status,
        });
    }
    Ok((updates, merge))
}

/// Encodes updates as the live `todo_write` arguments object.
#[must_use]
pub fn encode_plus_todo_args(updates: &[PlusTodoUpdate], merge: bool) -> Value {
    json!({
        "merge": merge,
        "todos": updates.iter().map(|item| {
            let mut object = serde_json::Map::new();
            object.insert("id".into(), json!(item.id));
            if let Some(content) = &item.content {
                object.insert("content".into(), json!(content));
            }
            if let Some(status) = item.status {
                object.insert("status".into(), json!(status.as_str()));
            }
            Value::Object(object)
        }).collect::<Vec<_>>()
    })
}

fn validate_no_duplicate_ids(updates: &[PlusTodoUpdate]) -> Result<(), PlusHostError> {
    let mut seen = HashSet::new();
    for update in updates {
        if !seen.insert(update.id.as_str()) {
            return Err(PlusHostError::Proposal(format!(
                "todo_write duplicate id: {}",
                update.id
            )));
        }
    }
    Ok(())
}

fn apply_replace(list: &mut PlusTodoList, updates: &[PlusTodoUpdate]) {
    list.items.clear();
    for update in updates {
        list.items.push(item_from_update(update));
    }
}

fn apply_merge(list: &mut PlusTodoList, updates: &[PlusTodoUpdate]) {
    for update in updates {
        if let Some(existing) = list.items.iter_mut().find(|item| item.id == update.id) {
            if let Some(content) = &update.content {
                existing.content.clone_from(content);
            }
            if let Some(status) = update.status {
                existing.status = status;
            }
        } else {
            list.items.push(item_from_update(update));
        }
    }
}

fn item_from_update(update: &PlusTodoUpdate) -> PlusTodoItem {
    PlusTodoItem {
        id: update.id.clone(),
        content: update
            .content
            .clone()
            .filter(|text| !text.is_empty())
            .unwrap_or_else(|| update.id.clone()),
        status: update.status.unwrap_or(PlusTodoStatus::Pending),
    }
}
