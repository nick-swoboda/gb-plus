//! Tool arguments/results stay in memory; durable identities prevent uncertain replay.

use std::collections::BTreeMap;
use std::path::Path;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::contracts::ProjectId;
use crate::owner_state::{OwnerStateFile, OwnerStateRoot};

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Record {
    version: u16,
    project: ProjectId,
    run: String,
    entries: BTreeMap<String, Entry>,
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Entry {
    binding: String,
    connection: String,
    request: String,
    completed_result_digest: Option<String>,
}

pub(super) struct InvocationJournal {
    file: OwnerStateFile,
    _lock: std::fs::File,
    record: Record,
    results: BTreeMap<String, Value>,
    failed: bool,
}

impl InvocationJournal {
    pub(super) fn open(root: &Path, project: &ProjectId, run: &str) -> Result<Self, String> {
        if project.as_str().is_empty()
            || project.as_str().len() > 256
            || run.is_empty()
            || run.len() > 256
            || run.chars().any(char::is_control)
        {
            return Err("MCP journal has an invalid app scope.".into());
        }
        let scope = super::super::digest(
            &serde_json::to_vec(&(project, run)).map_err(super::super::failure)?,
        );
        let owner = OwnerStateRoot::new(root.join("mcp-invocations-v1").join(scope));
        let lock = owner
            .file("writer.lock", 0)
            .map_err(super::super::failure)?
            .open_process_file()
            .map_err(super::super::failure)?;
        rustix::fs::flock(&lock, rustix::fs::FlockOperation::NonBlockingLockExclusive)
            .map_err(|_| "Another MCP owner holds this run's journal.")?;
        let file = owner
            .file("calls.json", 128 * 1024)
            .map_err(super::super::failure)?;
        let record = match file.read().map_err(super::super::failure)? {
            Some(bytes) => serde_json::from_slice::<Record>(&bytes).map_err(
                |_| "MCP invocation history is unreadable; its original remains recoverable.",
            )?,
            None => Record {
                version: 1,
                project: project.clone(),
                run: run.into(),
                entries: BTreeMap::new(),
            },
        };
        if record.version != 1
            || &record.project != project
            || record.run != run
            || record.entries.len() > 64
            || record.entries.iter().any(|(id, entry)| {
                !super::super::valid_digest(id)
                    || !super::super::valid_digest(&entry.binding)
                    || !super::super::valid_digest(&entry.connection)
                    || entry.request.len() > 128
                    || entry.request.is_empty()
                    || entry
                        .completed_result_digest
                        .as_ref()
                        .is_some_and(|value| !super::super::valid_digest(value))
            })
        {
            return Err("Unknown or inconsistent MCP invocation history cannot execute.".into());
        }
        Ok(Self {
            file,
            _lock: lock,
            record,
            results: BTreeMap::new(),
            failed: false,
        })
    }

    pub(super) fn previous(&self, id: &str, binding: &str) -> Result<Option<Value>, String> {
        if self.failed {
            return Err("MCP invocation persistence requires recovery.".into());
        }
        let Some(entry) = self.record.entries.get(id) else {
            return Ok(None);
        };
        if entry.binding != binding {
            return Err("MCP invocation identity was reused with changed input.".into());
        }
        self.results.get(id).cloned().map(Some)
            .ok_or("MCP invocation was already submitted or lost transient context. Its effect cannot be repeated.".into())
    }

    pub(super) fn intent(
        &mut self,
        id: &str,
        binding: &str,
        connection: &str,
        request: &str,
    ) -> Result<(), String> {
        if self.failed
            || self.record.entries.contains_key(id)
            || self.record.entries.len() >= 64
            || ![id, binding, connection]
                .iter()
                .all(|value| super::super::valid_digest(value))
            || request.is_empty()
            || request.len() > 128
        {
            return Err("MCP invocation intent is stale, malformed or exceeds its budget.".into());
        }
        self.record.entries.insert(
            id.into(),
            Entry {
                binding: binding.into(),
                connection: connection.into(),
                request: request.into(),
                completed_result_digest: None,
            },
        );
        self.persist()
    }

    pub(super) fn complete(&mut self, id: &str, result: &Value) -> Result<(), String> {
        let bytes = serde_json::to_vec(result).map_err(super::super::failure)?;
        if self.failed || bytes.len() > 1024 * 1024 {
            return Err("MCP result cannot be durably acknowledged.".into());
        }
        let entry = self
            .record
            .entries
            .get_mut(id)
            .filter(|entry| entry.completed_result_digest.is_none())
            .ok_or("MCP completion has no outstanding invocation intent.")?;
        entry.completed_result_digest = Some(super::super::digest(&bytes));
        self.persist()?;
        self.results.insert(id.into(), result.clone());
        Ok(())
    }

    fn persist(&mut self) -> Result<(), String> {
        let bytes = serde_json::to_vec(&self.record).map_err(super::super::failure)?;
        let result = self
            .file
            .replace(&bytes)
            .map_err(super::super::failure)
            .and_then(|()| {
                if self.file.read().map_err(super::super::failure)?.as_deref() != Some(&bytes) {
                    return Err(
                        "MCP invocation readback changed; its effect cannot be retried.".into(),
                    );
                }
                Ok(())
            });
        self.failed |= result.is_err();
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn restart_and_uncertain_intents_refuse_reexecution_without_persisting_raw_results() {
        let root = std::env::temp_dir().join(format!(
            "gbplus-mcp-calls-{}-{}",
            std::process::id(),
            crate::runtime::types::unix_time_millis()
        ));
        let project = ProjectId::new("project");
        let id = "a".repeat(64);
        let binding = "b".repeat(64);
        let connection = "c".repeat(64);
        let mut journal = InvocationJournal::open(&root, &project, "run").unwrap();
        assert!(InvocationJournal::open(&root, &project, "run").is_err());
        journal
            .intent(&id, &binding, &connection, "gbplus-1")
            .unwrap();
        assert!(journal.previous(&id, &binding).is_err());
        let result = json!({"content":[{"type":"text","text":"PRIVATE RESULT FIXTURE"}]});
        journal.complete(&id, &result).unwrap();
        assert_eq!(journal.previous(&id, &binding).unwrap(), Some(result));
        assert!(journal.previous(&id, &"d".repeat(64)).is_err());
        assert!(
            !String::from_utf8(journal.file.read().unwrap().unwrap())
                .unwrap()
                .contains("PRIVATE RESULT FIXTURE")
        );
        drop(journal);
        let restored = InvocationJournal::open(&root, &project, "run").unwrap();
        assert!(restored.previous(&id, &binding).is_err());
        drop(restored);
        std::fs::remove_dir_all(root).unwrap();
    }
}
