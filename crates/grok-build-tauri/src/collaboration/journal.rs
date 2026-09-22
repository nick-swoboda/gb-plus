//! Child content and operation intents are bounded and separate from queue authority.
use crate::contracts::{ProjectId, RunId};
use crate::owner_state::{OwnerStateFile, OwnerStateRoot};
use grok_build_plus_host::PendingFileSet;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::path::Path;

const MAX_BYTES: u64 = 16 * 1024 * 1024;
mod decisions;
mod messages;
use messages::Message;
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(tag = "status", rename_all = "snake_case", deny_unknown_fields)]
pub(super) enum Payload {
    Available {
        prompt: String,
        assistant: Option<String>,
        pending: PendingFileSet,
    },
    Unavailable,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct Entry {
    pub(super) run: RunId,
    pub(super) transient: bool,
    pub(super) decision: Decision,
    pub(super) payload: Payload,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(super) enum Decision {
    Pending,
    Accepting,
    Accepted,
    Rejected,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Operation {
    identity: String,
    fingerprint: String,
    transient: bool,
    completed: bool,
    result: Option<Value>,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct Journal {
    version: u16,
    project: ProjectId,
    family: RunId,
    operations: Vec<Operation>,
    pub(super) entries: Vec<Entry>,
    #[serde(default)]
    messages: Vec<Message>,
}
impl Journal {
    pub(super) fn load(state: &Path, project: &ProjectId, family: &RunId) -> Result<Self, String> {
        let expected = Self::create(project.clone(), family.clone());
        let bytes = expected
            .file(state)?
            .read()
            .map_err(|e| e.to_string())?
            .ok_or("No child result journal is retained for this family.")?;
        let record: Self = serde_json::from_slice(&bytes).map_err(
            |_| "Child result journal is unreadable; its original bytes remain recoverable.",
        )?;
        if record.version != 1
            || record.project != *project
            || record.family != *family
            || record.entries.len() > 32
            || record.operations.len() > 256
        {
            return Err(
                "Child result journal has an unsupported version, identity or size.".into(),
            );
        }
        let mut ids = std::collections::BTreeSet::new();
        for entry in &record.entries {
            if entry.run.as_str().is_empty()
                || entry.run.as_str().len() > 256
                || !ids.insert(&entry.run)
                || (entry.transient && !matches!(entry.payload, Payload::Unavailable))
            {
                return Err("Child journal payload binding or privacy was changed.".into());
            }
        }
        record.validate_messages()?;
        Ok(record)
    }
    pub(super) fn result(&self, run: &RunId) -> Result<Value, String> {
        let entry = self
            .entries
            .iter()
            .find(|entry| &entry.run == run)
            .ok_or("The selected child result does not belong to this family.")?;
        let mut value = serde_json::to_value(entry).map_err(|e| e.to_string())?;
        value["messages"] = serde_json::to_value(
            self.messages
                .iter()
                .filter(|message| &message.run == run)
                .collect::<Vec<_>>(),
        )
        .map_err(|e| e.to_string())?;
        Ok(value)
    }
    pub(super) fn start(&self, state: &Path) -> Result<(), String> {
        if self
            .file(state)?
            .read()
            .map_err(|e| e.to_string())?
            .is_some()
        {
            return Err("An existing child journal remains recoverable; a new controller cannot replace it.".into());
        }
        self.save(state)
    }
    pub(super) fn create(project: ProjectId, family: RunId) -> Self {
        Self {
            version: 1,
            project,
            family,
            operations: Vec::new(),
            entries: Vec::new(),
            messages: Vec::new(),
        }
    }
    pub(super) fn begin(
        &mut self,
        state: &Path,
        id: String,
        fingerprint: String,
        transient: bool,
    ) -> Result<Option<Value>, String> {
        if let Some(operation) = self
            .operations
            .iter()
            .find(|operation| operation.identity == id)
        {
            if operation.fingerprint != fingerprint || operation.transient != transient {
                return Err(
                    "Collaboration invocation was reused with different content or privacy.".into(),
                );
            }
            return operation.result.clone().map(Some).ok_or("This collaboration operation is incomplete or unavailable; it cannot be replayed automatically.".into());
        }
        if self.operations.len() >= 256 {
            return Err("Family operation journal is full.".into());
        }
        let before = self.clone();
        self.operations.push(Operation {
            identity: id,
            fingerprint,
            transient,
            completed: false,
            result: None,
        });
        self.save_or_restore(state, before)?;
        Ok(None)
    }
    pub(super) fn complete(&mut self, state: &Path, id: &str, result: Value) -> Result<(), String> {
        let before = self.clone();
        let operation = self
            .operations
            .iter_mut()
            .find(|operation| operation.identity == id && !operation.completed)
            .ok_or("Collaboration result has no uncompleted intent.")?;
        operation.completed = true;
        operation.result = Some(result);
        self.save_or_restore(state, before)
    }
    pub(super) fn begin_child(
        &mut self,
        state: &Path,
        run: RunId,
        prompt: String,
        transient: bool,
    ) -> Result<(), String> {
        if self.entries.len() >= 32
            || self.entries.iter().any(|entry| entry.run == run)
            || prompt.len() > 16 * 1024
        {
            return Err("Child content admission exceeded its bound or repeated a run.".into());
        }
        let before = self.clone();
        self.entries.push(Entry {
            run,
            transient,
            decision: Decision::Pending,
            payload: Payload::Available {
                prompt,
                assistant: None,
                pending: PendingFileSet::default(),
            },
        });
        self.save_or_restore(state, before)
    }
    pub(super) fn complete_child(
        &mut self,
        state: &Path,
        run: &RunId,
        assistant: String,
        pending: PendingFileSet,
    ) -> Result<(), String> {
        if assistant.len() > 256 * 1024
            || pending.items.len() > 64
            || pending
                .items
                .iter()
                .map(|p| p.before.len() + p.after.len())
                .sum::<usize>()
                > 2 * 1024 * 1024
        {
            return Err("Child result exceeds its text or proposal bound.".into());
        }
        let before = self.clone();
        let entry = self
            .entries
            .iter_mut()
            .find(|entry| &entry.run == run)
            .ok_or("Child result lost its intent.")?;
        let Payload::Available {
            prompt,
            assistant: prior,
            ..
        } = &entry.payload
        else {
            return Err("Child source context is unavailable.".into());
        };
        if prior.is_some() {
            return Err("Child result was already committed.".into());
        }
        entry.payload = Payload::Available {
            prompt: prompt.clone(),
            assistant: Some(assistant),
            pending,
        };
        self.save_or_restore(state, before)
    }
    fn save_or_restore(&mut self, state: &Path, before: Self) -> Result<(), String> {
        if let Err(error) = self.save(state) {
            *self = before;
            return Err(error);
        }
        Ok(())
    }
    fn file(&self, state: &Path) -> Result<OwnerStateFile, String> {
        OwnerStateRoot::new(state.join("child-results-v1"))
            .file(
                format!(
                    "{}.json",
                    grok_build_plus_host::worktree_recovery_digest(self.family.as_str().as_bytes())
                ),
                MAX_BYTES,
            )
            .map_err(|e| e.to_string())
    }
    fn save(&self, state: &Path) -> Result<(), String> {
        let memory = serde_json::to_vec(self).map_err(|e| e.to_string())?;
        if memory.len() as u64 > MAX_BYTES {
            return Err("Family content journal exceeded 16 MiB.".into());
        }
        let mut durable = self.clone();
        for entry in &mut durable.entries {
            if entry.transient {
                entry.payload = Payload::Unavailable;
            }
        }
        for operation in &mut durable.operations {
            if operation.transient {
                operation.result = None;
            }
        }
        for message in &mut durable.messages {
            if message.transient {
                message.text = None;
            }
        }
        self.file(state)?
            .replace(&serde_json::to_vec(&durable).map_err(|e| e.to_string())?)
            .map_err(|e| e.to_string())
    }
}
