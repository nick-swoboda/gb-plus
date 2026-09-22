//! Explicit project-only facts. No model or high-power tool writes this store.

use crate::contracts::ProjectId;
use crate::owner_state::{OwnerStateFile, OwnerStateRoot};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::fmt::Write as _;
use std::path::Path;

const MAX_FILE: u64 = 256 * 1024;
const MAX_FACTS: usize = 128;
const MAX_FACT_BYTES: usize = 1024;
const MAX_TOTAL_BYTES: usize = 64 * 1024;

#[derive(Clone)]
pub(crate) struct ProjectMemory {
    owner: OwnerStateRoot,
    project: ProjectId,
    key: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct MemoryFact {
    pub(crate) id: String,
    pub(crate) text: String,
    pub(crate) provenance: Provenance,
    pub(crate) ordinal: u64,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) enum Provenance {
    UserSavedInProject,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct MemoryView {
    version: u16,
    project_id: ProjectId,
    pub(crate) enabled: bool,
    next_ordinal: u64,
    pub(crate) facts: Vec<MemoryFact>,
}

impl ProjectMemory {
    pub(crate) fn new(state_root: &Path, project: &ProjectId) -> Result<Self, String> {
        if project.as_str().is_empty()
            || project.as_str().len() > 256
            || project.as_str().chars().any(char::is_control)
        {
            return Err("Project memory identity is invalid.".into());
        }
        Ok(Self {
            owner: OwnerStateRoot::new(state_root.join("project-memory-v1")),
            project: project.clone(),
            key: digest(project.as_str().as_bytes()),
        })
    }

    pub(crate) fn view(&self) -> Result<MemoryView, String> {
        let record = match self.file()?.read().map_err(failure)? {
            Some(bytes) => serde_json::from_slice(&bytes)
                .map_err(|_| "Project memory is unreadable; its original bytes were retained.")?,
            None => MemoryView {
                version: 1,
                project_id: self.project.clone(),
                enabled: false,
                next_ordinal: 1,
                facts: Vec::new(),
            },
        };
        self.validate(&record)?;
        Ok(record)
    }

    pub(crate) fn set_enabled(&self, enabled: bool) -> Result<MemoryView, String> {
        self.update(false, |record| {
            record.enabled = enabled;
            Ok(())
        })
    }

    pub(crate) fn remember_user_fact(&self, text: &str) -> Result<MemoryView, String> {
        let text = text.trim();
        screen_fact(text)?;
        self.update(false, |record| {
            if !record.enabled {
                return Err("Enable project memory before saving a fact.".into());
            }
            let id = self.fact_id(text);
            if record.facts.iter().any(|fact| fact.id == id) {
                return Ok(());
            }
            if record.facts.len() >= MAX_FACTS
                || record
                    .facts
                    .iter()
                    .map(|f| f.text.len())
                    .sum::<usize>()
                    .saturating_add(text.len())
                    > MAX_TOTAL_BYTES
            {
                return Err("Project memory is full. Forget a fact before saving another.".into());
            }
            let ordinal = record.next_ordinal;
            record.next_ordinal = ordinal
                .checked_add(1)
                .ok_or("Project memory sequence is exhausted.")?;
            record.facts.push(MemoryFact {
                id,
                text: text.to_owned(),
                provenance: Provenance::UserSavedInProject,
                ordinal,
            });
            Ok(())
        })
    }

    pub(crate) fn forget(&self, id: Option<&str>) -> Result<MemoryView, String> {
        self.update(true, |record| {
            if let Some(id) = id {
                if id.len() != 64
                    || !id
                        .bytes()
                        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
                {
                    return Err("Project fact identity is invalid.".into());
                }
                record.facts.retain(|fact| fact.id != id);
            } else {
                record.facts.clear();
            }
            Ok(())
        })
    }

    /// Relevance, recency and identity form a deterministic total ordering.
    pub(crate) fn context(&self, prompt: &str) -> Result<String, String> {
        let record = self.view()?;
        if !record.enabled {
            return Ok(String::new());
        }
        let terms = words(prompt);
        let mut ranked = record
            .facts
            .iter()
            .map(|fact| (words(&fact.text).intersection(&terms).count(), fact))
            .collect::<Vec<_>>();
        ranked.sort_by(|(score_a, a), (score_b, b)| {
            score_b
                .cmp(score_a)
                .then(b.ordinal.cmp(&a.ordinal))
                .then(a.id.cmp(&b.id))
        });
        let mut output = String::new();
        for (_, fact) in ranked.into_iter().take(16) {
            if output
                .len()
                .saturating_add(fact.text.len())
                .saturating_add(160)
                > 8 * 1024
            {
                break;
            }
            writeln!(
                output,
                "Project fact {} (user saved in this project): {}",
                fact.id, fact.text
            )
            .map_err(failure)?;
        }
        Ok(output)
    }

    fn file(&self) -> Result<OwnerStateFile, String> {
        self.owner
            .file(format!("{}.json", self.key), MAX_FILE)
            .map_err(failure)
    }
    fn fact_id(&self, text: &str) -> String {
        digest(format!("GB Plus project fact v1\0{}\0{text}", self.project.as_str()).as_bytes())
    }
    fn validate(&self, record: &MemoryView) -> Result<(), String> {
        if record.version != 1
            || record.project_id != self.project
            || record.next_ordinal == 0
            || record.facts.len() > MAX_FACTS
            || record
                .facts
                .iter()
                .map(|fact| fact.text.len())
                .sum::<usize>()
                > MAX_TOTAL_BYTES
        {
            return Err(
                "Unknown, oversized or cross-project memory was retained without loading it."
                    .into(),
            );
        }
        let mut ids = BTreeSet::new();
        let mut ordinals = BTreeSet::new();
        for fact in &record.facts {
            screen_fact(&fact.text)?;
            if fact.id != self.fact_id(&fact.text)
                || !ids.insert(&fact.id)
                || fact.ordinal == 0
                || fact.ordinal >= record.next_ordinal
                || !ordinals.insert(fact.ordinal)
            {
                return Err(
                    "Project memory fact identity or provenance order is inconsistent.".into(),
                );
            }
        }
        Ok(())
    }

    fn update(
        &self,
        forget: bool,
        operation: impl FnOnce(&mut MemoryView) -> Result<(), String>,
    ) -> Result<MemoryView, String> {
        let lock = self
            .owner
            .file(format!("{}.lock", self.key), 0)
            .map_err(failure)?
            .open_process_file()
            .map_err(failure)?;
        rustix::fs::flock(&lock, rustix::fs::FlockOperation::NonBlockingLockExclusive)
            .map_err(|_| "Project memory is being updated. Try again.")?;
        let mut record = self.view()?;
        operation(&mut record)?;
        self.validate(&record)?;
        // Purge BEFORE publication: a crash either leaves the original fact
        // visible, or publishes its removal after every older temp is gone.
        // A newly interrupted write contains only the already-filtered facts.
        if forget {
            self.file()?
                .remove_abandoned_temporaries_after_lock()
                .map_err(failure)?;
        }
        let bytes = serde_json::to_vec(&record).map_err(failure)?;
        // No history/backup copy retains a fact after Forget. The atomic owner
        // primitive supplies crash consistency; unknown originals are not reset.
        self.file()?.replace(&bytes).map_err(failure)?;
        if self.file()?.read().map_err(failure)?.as_deref() != Some(bytes.as_slice()) {
            return Err("Project memory readback failed; refresh before continuing.".into());
        }
        Ok(record)
    }
}

fn screen_fact(text: &str) -> Result<(), String> {
    if text.is_empty()
        || text.len() > MAX_FACT_BYTES
        || text.chars().any(|c| c.is_control() && c != '\n')
    {
        return Err("Save a plain-text fact between 1 and 1024 bytes.".into());
    }
    let lower = text.to_ascii_lowercase();
    if [
        "-----begin",
        "private key",
        "authorization:",
        "bearer ",
        "access_token",
        "refresh_token",
        "api_key",
        "api-key",
        "apikey",
        "client_secret",
        "password=",
        "password:",
        "password\"",
        "secret=",
        "token=",
        "ghp_",
        "github_pat_",
        "xoxb-",
        "xoxp-",
        "data:image",
        "data:audio",
    ]
    .iter()
    .any(|marker| lower.contains(marker))
        || lower
            .split(|c: char| !(c.is_ascii_alphanumeric() || c == '-'))
            .any(|word| word.len() >= 24 && (word.starts_with("sk-") || word.starts_with("xai-")))
        || text
            .split(|c: char| {
                !(c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '/' | '+' | '='))
            })
            .any(|word| {
                word.len() >= 40
                    && word.bytes().any(|b| b.is_ascii_uppercase())
                    && word.bytes().any(|b| b.is_ascii_lowercase())
                    && word.bytes().any(|b| b.is_ascii_digit())
            })
    {
        return Err("This fact resembles credential or raw media data and was not saved. Store only a non-secret project fact.".into());
    }
    Ok(())
}
fn words(text: &str) -> BTreeSet<String> {
    text.split(|c: char| !c.is_alphanumeric())
        .filter(|word| word.len() >= 3)
        .take(2048)
        .map(str::to_lowercase)
        .collect()
}
fn digest(bytes: &[u8]) -> String {
    grok_build_plus_host::worktree_recovery_digest(bytes)
}
fn failure(error: impl std::fmt::Display) -> String {
    error.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn memory_defaults_off_is_project_bound_deterministic_and_forget_does_not_keep_a_backup() {
        let root = std::env::temp_dir().join(format!(
            "gbplus-memory-{}-{}",
            std::process::id(),
            crate::runtime::types::unix_time_millis()
        ));
        let a = ProjectMemory::new(&root, &ProjectId::new("a")).unwrap();
        let b = ProjectMemory::new(&root, &ProjectId::new("b")).unwrap();
        assert!(!a.view().unwrap().enabled);
        assert!(
            a.remember_user_fact("Use cobalt for the project color.")
                .is_err()
        );
        a.set_enabled(true).unwrap();
        a.remember_user_fact("Use cobalt for the project color.")
            .unwrap();
        a.remember_user_fact("Checks use the managed Linux guest.")
            .unwrap();
        let context = a.context("What project color?").unwrap();
        assert!(context.lines().next().unwrap().contains("cobalt"));
        assert_eq!(a.context("What project color?").unwrap(), context);
        assert!(b.context("What project color?").unwrap().is_empty());
        for secret in [
            "XAI_API_KEY=not-a-real-key",
            "Authorization: Bearer fixture",
            "-----BEGIN PRIVATE KEY-----",
            "data:image/png;base64,fixture",
        ] {
            assert!(a.remember_user_fact(secret).is_err());
        }
        a.set_enabled(false).unwrap();
        assert!(a.context("color").unwrap().is_empty());
        let abandoned = a
            .owner
            .file(format!(".{}.json.123-7.tmp", a.key), MAX_FILE)
            .unwrap();
        abandoned
            .replace(&a.file().unwrap().read().unwrap().unwrap())
            .unwrap();
        a.forget(None).unwrap();
        assert!(abandoned.read().unwrap().is_none());
        assert!(a.view().unwrap().facts.is_empty());
        let bytes = a.file().unwrap().read().unwrap().unwrap();
        assert!(!String::from_utf8(bytes).unwrap().contains("cobalt"));
        for entry in std::fs::read_dir(root.join("project-memory-v1")).unwrap() {
            assert!(
                !entry
                    .unwrap()
                    .file_name()
                    .to_string_lossy()
                    .contains("backup")
            );
        }
        std::fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn copied_or_unknown_memory_is_preserved_without_execution() {
        let root = std::env::temp_dir().join(format!(
            "gbplus-memory-copy-{}-{}",
            std::process::id(),
            crate::runtime::types::unix_time_millis()
        ));
        let a = ProjectMemory::new(&root, &ProjectId::new("a")).unwrap();
        let b = ProjectMemory::new(&root, &ProjectId::new("b")).unwrap();
        a.set_enabled(true).unwrap();
        a.remember_user_fact("Cobalt is the project color.")
            .unwrap();
        let bytes = a.file().unwrap().read().unwrap().unwrap();
        b.file().unwrap().replace(&bytes).unwrap();
        assert!(b.view().is_err());
        assert_eq!(b.file().unwrap().read().unwrap().unwrap(), bytes);
        let mut future: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        future["version"] = serde_json::json!(99);
        a.file()
            .unwrap()
            .replace(&serde_json::to_vec(&future).unwrap())
            .unwrap();
        assert!(a.set_enabled(false).is_err());
        std::fs::remove_dir_all(root).unwrap();
    }
}
