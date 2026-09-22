//! Exact local Responses replay, request intents, and durable effect identities.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};

use grok_build_plus_host::{PendingFileSet, worktree_recovery_digest};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::owner_state::OwnerStateRoot;

const MAX_JOURNAL_BYTES: u64 = 16 * 1024 * 1024;
const MAX_CONTEXT_BYTES: usize = 10 * 1024 * 1024;
const MAX_ITEMS: usize = 4096;
const MAX_MEMORY_BYTES: usize = 64 * 1024 * 1024;
const MAX_MEMORY_CONTEXTS: usize = 64;
const FILE: &str = "responses-v3.json";
const SCHEMA_VERSION: u16 = 3;

// Transient provider items have no disk representation. They may survive runs
// in this process, but a restart or bounded-cache eviction requires context reset.
#[derive(Clone)]
struct CachedContext {
    items: Vec<Value>,
    pending: PendingFileSet,
}
impl CachedContext {
    fn encoded_size(&self) -> usize {
        serde_json::to_vec(&(&self.items, &self.pending))
            .map_or(MAX_MEMORY_BYTES.saturating_add(1), |bytes| bytes.len())
    }
}
static TRANSIENT: OnceLock<Mutex<BTreeMap<PathBuf, CachedContext>>> = OnceLock::new();

mod compaction;
mod lifecycle;
pub(crate) mod turn;

#[cfg(test)]
mod tests;

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum SavedItem {
    Durable { value: Value },
    Unavailable { ordinal: usize },
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(tag = "state", rename_all = "snake_case", deny_unknown_fields)]
enum Effect {
    Intent {
        request_digest: String,
    },
    Completed {
        request_digest: String,
        output_ordinal: usize,
    },
    Retired {
        request_digest: String,
    },
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Record {
    schema_version: u16,
    binding_digest: String,
    context_id: String,
    model: String,
    reasoning_effort: Option<String>,
    sequence: u64,
    interrupted: bool,
    request_pending: bool,
    turn_active: bool,
    tainted_from: Option<usize>,
    items: Vec<SavedItem>,
    completion_ids: Vec<String>,
    effects: BTreeMap<String, Effect>,
    retired_call_ids: std::collections::BTreeSet<String>,
    pending: PendingFileSet,
    #[serde(default)]
    replay_start: usize,
    #[serde(default)]
    compaction_previous_start: Option<usize>,
    #[serde(default)]
    compact_at: Option<u64>,
    #[serde(default)]
    measured_tokens: Option<u64>,
    #[serde(default)]
    measured_items: usize,
}

pub(crate) struct ResponsesJournal {
    root: PathBuf,
    record: Record,
    items: Vec<Value>,
}

impl ResponsesJournal {
    pub(crate) fn reset(root: &Path) -> Result<(), String> {
        let owner = OwnerStateRoot::new(root);
        if let Some(bytes) = lifecycle::read_existing(root)?.0 {
            owner
                .file("responses-before-reset.json", MAX_JOURNAL_BYTES)
                .map_err(|error| error.to_string())?
                .replace(&bytes)
                .map_err(|error| error.to_string())?;
        }
        let mut fresh = Self {
            root: root.into(),
            record: fresh_record(root),
            items: Vec::new(),
        };
        fresh.persist()?;
        TRANSIENT
            .get_or_init(Mutex::default)
            .lock()
            .map_err(|_| "Transient context cache is unavailable.")?
            .remove(root);
        Ok(())
    }
    pub(crate) fn open(root: &Path) -> Result<Self, String> {
        let (existing, source_version) = lifecycle::read_existing(root)?;
        let fresh = existing.is_none();
        let mut record: Record = match existing {
            Some(bytes) => lifecycle::decode(&bytes, source_version, root)?,
            None => fresh_record(root),
        };
        lifecycle::validate_record(&record)?;
        if record.binding_digest != scope_digest(root) {
            return Err("Responses history belongs to another conversation scope; original data was retained.".into());
        }
        let was_interrupted = record.interrupted;
        if record.request_pending
            || record.turn_active
            || record
                .effects
                .values()
                .any(|effect| matches!(effect, Effect::Intent { .. }))
        {
            record.interrupted = true;
        }
        let memory = TRANSIENT
            .get_or_init(Mutex::default)
            .lock()
            .map_err(|_| "Transient context cache is unavailable.")?;
        let cached = memory.get(root);
        let mut items = Vec::with_capacity(record.items.len());
        for (index, saved) in record.items.iter().enumerate() {
            match saved {
                SavedItem::Durable { value }
                    if record.tainted_from.is_none_or(|start| index < start) =>
                {
                    items.push(value.clone());
                }
                SavedItem::Unavailable { ordinal } if *ordinal == index => {
                    let value = cached.and_then(|context| context.items.get(index)).ok_or(
                        "This provider context used transient Capture, Browser, or Desktop data that is no longer available. Reset provider context explicitly or reattach the source in a new context.")?;
                    items.push(value.clone());
                }
                _ => return Err("Responses journal item privacy boundaries are invalid.".into()),
            }
        }
        if record.tainted_from.is_some() {
            // Pending proposal bytes are raw model context too. Only this
            // process's bounded cache may restore them for a temporary context.
            record.pending =
                cached.map_or_else(PendingFileSet::default, |context| context.pending.clone());
        }
        drop(memory);
        if lifecycle::unfinished_prefix(&items) {
            record.interrupted = true;
        }
        record.schema_version = SCHEMA_VERSION;
        let mut journal = Self {
            root: root.into(),
            record,
            items,
        };
        journal.check_size()?;
        if fresh || source_version < SCHEMA_VERSION || journal.record.interrupted != was_interrupted
        {
            // Keep earlier generations untouched; publish the new one atomically.
            journal.persist()?;
        }
        Ok(journal)
    }

    pub(crate) fn context_id(&self) -> &str {
        &self.record.context_id
    }
    pub(crate) fn model(&self) -> &str {
        &self.record.model
    }
    pub(crate) fn select_model(
        &mut self,
        selection: &super::models::ModelSelection,
    ) -> Result<(), String> {
        if self.record.request_pending || self.record.interrupted {
            return Err("Resolve interrupted provider context before changing its model.".into());
        }
        self.record.model.clone_from(&selection.model.id);
        self.record
            .reasoning_effort
            .clone_from(&selection.reasoning_effort);
        self.record.compact_at = selection.model.compact_at();
        self.persist()
    }
    pub(crate) fn reasoning_effort(&self) -> Option<&str> {
        self.record.reasoning_effort.as_deref()
    }
    pub(crate) fn refresh_model_metadata(
        &mut self,
        model: &super::models::ModelDescriptor,
    ) -> Result<(), String> {
        if model.id != self.record.model || self.record.request_pending || self.record.interrupted {
            return Err(
                "Authenticated model metadata does not match this idle provider context.".into(),
            );
        }
        self.record.compact_at = model.compact_at();
        self.persist()
    }
    pub(crate) fn input(&self) -> &[Value] {
        &self.items[self.record.replay_start..]
    }
    pub(crate) fn pending(&self) -> PendingFileSet {
        self.record.pending.clone()
    }

    pub(crate) fn begin_turn(&mut self, prompt: &str, image: Option<&str>) -> Result<(), String> {
        if self.record.interrupted || self.record.request_pending || self.record.turn_active {
            return Err("The previous provider request was interrupted or its effects are uncertain. Explicitly reset provider context before starting another turn; completed app effects will not be repeated.".into());
        }
        if prompt.is_empty() || prompt.len() > 12_000 {
            return Err("Responses user message exceeds its bound.".into());
        }
        let mut content = vec![json!({"type":"input_text","text":prompt})];
        if let Some(image) = image {
            content.insert(0,json!({"type":"input_image","image_url":format!("data:image/png;base64,{image}"),"detail":"high"}));
            self.taint();
        }
        self.record.pending = PendingFileSet::default();
        self.record.turn_active = true;
        self.items.push(json!({"role":"user","content":content}));
        self.persist()
    }

    pub(crate) fn append_steering(&mut self, text: &str) -> Result<(), String> {
        self.items
            .push(json!({"role":"user","content":[{"type":"input_text","text":text}]}));
        self.persist()
    }

    /// Must succeed before opening the network request. A failed response leaves
    /// this intent in place, so restart never retries an uncertain submission.
    pub(crate) fn request_intent(&mut self) -> Result<(), String> {
        if self.record.interrupted || self.record.request_pending || !self.record.turn_active {
            return Err("Responses request is already pending or interrupted.".into());
        }
        self.record.sequence = self
            .record
            .sequence
            .checked_add(1)
            .ok_or("Responses sequence exhausted.")?;
        self.record.request_pending = true;
        self.persist()
    }

    pub(crate) fn rejected_request(&mut self, status: u16) -> Result<(), String> {
        if !self.record.request_pending || !matches!(status, 429 | 503) {
            return Err(
                "Only a definitively rejected eligible HTTP request can clear its pending intent."
                    .into(),
            );
        }
        self.record.request_pending = false;
        self.persist()
    }

    pub(crate) fn interrupt(&mut self) -> Result<(), String> {
        self.record.interrupted = true;
        self.persist()
    }

    pub(crate) fn complete_response(&mut self, response: &Value) -> Result<Vec<Value>, String> {
        if !self.record.request_pending {
            return Err("Responses completion has no durable request intent.".into());
        }
        if response.get("status").and_then(Value::as_str) != Some("completed") {
            return Err("Responses request ended without a validated completed response.".into());
        }
        let id = response
            .get("id")
            .and_then(Value::as_str)
            .filter(|id| valid_identity(id))
            .ok_or("Responses completion has no bounded identity.")?;
        if self
            .record
            .completion_ids
            .iter()
            .any(|previous| previous == id)
        {
            return Err(
                "Provider reused a completed response identity for another request.".into(),
            );
        }
        let output = response
            .get("output")
            .and_then(Value::as_array)
            .filter(|items| !items.is_empty() && items.len() <= 128)
            .ok_or("Responses completion has no bounded output item list.")?;
        let mut call_ids = std::collections::BTreeSet::new();
        let mut high_power = false;
        for item in output {
            match item.get("type").and_then(Value::as_str) {
                Some("message" | "reasoning" | "compaction") => {}
                Some("function_call") => {
                    let call_id = item
                        .get("call_id")
                        .and_then(Value::as_str)
                        .filter(|id| valid_identity(id))
                        .ok_or("Responses function call lacks its invocation identity.")?;
                    if !call_ids.insert(call_id) {
                        return Err(
                            "Responses completion contains duplicate invocation identities.".into(),
                        );
                    }
                    if self
                        .record
                        .retired_call_ids
                        .contains(&worktree_recovery_digest(call_id.as_bytes()))
                        || self.items.iter().any(|previous| {
                            previous.get("type").and_then(Value::as_str) == Some("function_call")
                                && previous.get("call_id").and_then(Value::as_str) == Some(call_id)
                        })
                    {
                        return Err("Provider reused an invocation identity from an earlier completion; no tool effect was repeated.".into());
                    }
                    let name = item
                        .get("name")
                        .and_then(Value::as_str)
                        .ok_or("Responses function call has no name.")?;
                    if name.starts_with("browser_")
                        || name.starts_with("desktop_")
                        || name.starts_with("gbext_")
                    {
                        high_power = true;
                    }
                    if item.get("arguments").and_then(Value::as_str).is_none() {
                        return Err("Responses function arguments are not exact JSON text.".into());
                    }
                }
                _ => return Err("Responses output contains an unsupported effectful item.".into()),
            }
        }
        if high_power {
            self.taint();
        }
        self.items.extend(output.iter().cloned());
        self.record.measured_tokens = response
            .pointer("/usage/input_tokens")
            .and_then(Value::as_u64)
            .zip(
                response
                    .pointer("/usage/output_tokens")
                    .and_then(Value::as_u64),
            )
            .map(|(input, output)| input.saturating_add(output));
        self.record.measured_items = self.items.len();
        let completed_compaction = self.record.compaction_previous_start.take().is_some();
        self.record.completion_ids.push(id.into());
        self.record.request_pending = false;
        self.record.turn_active = !call_ids.is_empty() || !lifecycle::has_terminal_output(output);
        if completed_compaction {
            self.retire_compacted_prefix()?;
        }
        self.persist()?;
        Ok(output.clone())
    }

    /// Returns a recorded output on duplicate dispatch; never repeats its effect.
    pub(crate) fn effect_intent(
        &mut self,
        response_id: &str,
        call: &Value,
    ) -> Result<Option<Value>, String> {
        let key = effect_key(response_id, call)?;
        let digest = worktree_recovery_digest(call.to_string().as_bytes());
        if let Some(previous) = self.record.effects.get(&key) {
            return match previous {
                Effect::Completed {request_digest,output_ordinal} if request_digest == &digest => {
                    self.items.get(*output_ordinal).cloned().map(Some).ok_or("Recorded tool output is unavailable.".into())
                }
                Effect::Retired {request_digest} if request_digest == &digest => Err("This completed invocation belongs to a retired compacted prefix; it cannot be dispatched again.".into()),
                _ => Err("Tool invocation is uncertain or changed its recorded arguments; replay is refused.".into()),
            };
        }
        if self.record.interrupted
            || !self.record.turn_active
            || self.record.request_pending
            || self.record.completion_ids.last().map(String::as_str) != Some(response_id)
            || !self.items.iter().any(|item| item == call)
        {
            return Err(
                "Tool invocation is not part of this active completed provider request.".into(),
            );
        }
        self.record.effects.insert(
            key,
            Effect::Intent {
                request_digest: digest,
            },
        );
        self.persist()?;
        Ok(None)
    }

    pub(crate) fn complete_effect(
        &mut self,
        response_id: &str,
        call: &Value,
        result: &str,
        pending: PendingFileSet,
    ) -> Result<Value, String> {
        let key = effect_key(response_id, call)?;
        let digest = worktree_recovery_digest(call.to_string().as_bytes());
        if !matches!(self.record.effects.get(&key),Some(Effect::Intent {request_digest}) if request_digest == &digest)
        {
            return Err("Tool result has no matching durable invocation intent.".into());
        }
        let output =
            json!({"type":"function_call_output","call_id":call["call_id"],"output":result});
        let ordinal = self.items.len();
        self.items.push(output.clone());
        for proposal in pending.items {
            self.record.pending.upsert(proposal);
        }
        self.record.effects.insert(
            key,
            Effect::Completed {
                request_digest: digest,
                output_ordinal: ordinal,
            },
        );
        self.persist()?;
        Ok(output)
    }

    pub(super) fn context_is_transient(&self) -> bool {
        self.record.tainted_from.is_some()
    }

    pub(crate) fn require_transient_context(&mut self) -> Result<(), String> {
        self.taint();
        self.persist()
    }

    fn taint(&mut self) {
        self.record.tainted_from.get_or_insert(self.items.len());
    }

    fn check_size(&self) -> Result<(), String> {
        if self.items.len() > MAX_ITEMS
            || self.record.retired_call_ids.len() > MAX_ITEMS
            || self.record.effects.len() > MAX_ITEMS
            || self.record.completion_ids.len() > MAX_ITEMS
            || serde_json::to_vec(&self.items)
                .map_err(|error| error.to_string())?
                .len()
                > MAX_CONTEXT_BYTES
        {
            return Err(
                "Responses context reached its local bound; compact or reset explicitly.".into(),
            );
        }
        Ok(())
    }

    fn persist(&mut self) -> Result<(), String> {
        self.check_size()?;
        self.record.items = self
            .items
            .iter()
            .enumerate()
            .map(|(ordinal, value)| {
                if self
                    .record
                    .tainted_from
                    .is_some_and(|start| ordinal >= start)
                {
                    SavedItem::Unavailable { ordinal }
                } else {
                    SavedItem::Durable {
                        value: value.clone(),
                    }
                }
            })
            .collect();
        let mut disk = self.record.clone();
        if disk.tainted_from.is_some() {
            disk.pending = PendingFileSet::default();
        }
        let bytes = serde_json::to_vec(&disk).map_err(|error| error.to_string())?;
        OwnerStateRoot::new(&self.root)
            .file(FILE, MAX_JOURNAL_BYTES)
            .map_err(|error| error.to_string())?
            .replace(&bytes)
            .map_err(|error| error.to_string())?;
        if self.record.tainted_from.is_some() {
            let mut memory = TRANSIENT
                .get_or_init(Mutex::default)
                .lock()
                .map_err(|_| "Transient context cache is unavailable.")?;
            memory.remove(&self.root);
            let cached = CachedContext {
                items: self.items.clone(),
                pending: self.record.pending.clone(),
            };
            let needed = cached.encoded_size();
            if needed > MAX_MEMORY_BYTES {
                return Err(
                    "Transient provider context and proposals exceed the memory budget.".into(),
                );
            }
            while memory.len() >= MAX_MEMORY_CONTEXTS
                || needed
                    + memory
                        .values()
                        .map(CachedContext::encoded_size)
                        .sum::<usize>()
                    > MAX_MEMORY_BYTES
            {
                if memory.pop_first().is_none() {
                    break;
                }
            }
            memory.insert(self.root.clone(), cached);
        }
        Ok(())
    }
}

fn effect_key(response_id: &str, call: &Value) -> Result<String, String> {
    let call_id = call
        .get("call_id")
        .and_then(Value::as_str)
        .filter(|id| valid_identity(id))
        .ok_or("Tool call lacks its invocation identity.")?;
    if !valid_identity(response_id) {
        return Err("Tool call lacks its completion identity.".into());
    }
    Ok(worktree_recovery_digest(
        serde_json::to_string(&(response_id, call_id))
            .map_err(|error| error.to_string())?
            .as_bytes(),
    ))
}

fn valid_identity(id: &str) -> bool {
    !id.is_empty() && id.len() <= 512 && !id.chars().any(char::is_control)
}

fn fresh_record(root: &Path) -> Record {
    Record {
        schema_version: SCHEMA_VERSION,
        binding_digest: scope_digest(root),
        context_id: lifecycle::new_context_id(root),
        model: grok_build_plus_host::PLUS_LIVE_MODEL.into(),
        reasoning_effort: None,
        sequence: 0,
        interrupted: false,
        request_pending: false,
        turn_active: false,
        tainted_from: None,
        items: Vec::new(),
        completion_ids: Vec::new(),
        effects: BTreeMap::new(),
        retired_call_ids: std::collections::BTreeSet::new(),
        pending: PendingFileSet::default(),
        replay_start: 0,
        compaction_previous_start: None,
        compact_at: None,
        measured_tokens: None,
        measured_items: 0,
    }
}

fn scope_digest(root: &Path) -> String {
    let mut framed = b"grok-build/responses-conversation-scope/v1\0".to_vec();
    framed.extend_from_slice(root.as_os_str().as_encoded_bytes());
    worktree_recovery_digest(&framed)
}
