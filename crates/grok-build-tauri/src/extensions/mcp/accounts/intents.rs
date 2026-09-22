//! Non-secret, process-bound sign-in intents precede each remote or Keychain effect.
use super::store::{Binding, owner};
use crate::owner_state::{OwnerStateFile, OwnerStateRoot};
use serde::{Deserialize, Serialize};
use std::path::Path;

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Phase {
    Prepared,
    Registering,
    Authorizing,
    Exchanging,
    Storing,
    Complete,
    Interrupted,
    Cleared,
}
#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Intent {
    version: u16,
    project: String,
    server: String,
    pub(super) id: String,
    owner: String,
    pub(crate) phase: Phase,
    pub(crate) binding: Option<Binding>,
}
pub(crate) struct Journal {
    root: OwnerStateRoot,
    project: String,
    key: String,
}
impl Journal {
    pub(crate) fn new(root: &Path, project: &str) -> Result<Self, String> {
        if project.is_empty() || project.len() > 256 || project.chars().any(char::is_control) {
            return Err("MCP sign-in project is invalid.".into());
        }
        Ok(Self {
            root: OwnerStateRoot::new(root.join("mcp-signin-v1")),
            project: project.into(),
            key: super::store::hash(project.as_bytes()),
        })
    }
    fn file(&self) -> Result<OwnerStateFile, String> {
        self.root
            .file(format!("{}.json", self.key), 32 * 1024)
            .map_err(|e| e.to_string())
    }
    pub(crate) fn read(&self) -> Result<Option<Intent>, String> {
        let Some(bytes) = self.file()?.read().map_err(|e| e.to_string())? else {
            return Ok(None);
        };
        let record: Intent = serde_json::from_slice(&bytes)
            .map_err(|_| "MCP sign-in journal is unsupported; its bytes were preserved.")?;
        self.validate(&record)?;
        Ok(Some(record))
    }
    fn validate(&self, r: &Intent) -> Result<(), String> {
        if r.version != 1
            || r.project != self.project
            || [&r.id, &r.server, &r.owner]
                .iter()
                .any(|s| !super::store::digest(s))
        {
            return Err("MCP sign-in journal identity is invalid.".into());
        }
        if let Some(b) = &r.binding {
            b.validate()?;
            if b.project != r.project || b.server != r.server || b.epoch != r.id {
                return Err("MCP sign-in credential binding changed.".into());
            }
        }
        if matches!(r.phase, Phase::Storing | Phase::Complete) && r.binding.is_none() {
            return Err("MCP sign-in journal omitted its stored credential binding.".into());
        }
        Ok(())
    }
    fn mutate<T>(
        &self,
        f: impl FnOnce(Option<Intent>) -> Result<(Intent, T), String>,
    ) -> Result<T, String> {
        let lock = self
            .root
            .file(format!("{}.lock", self.key), 0)
            .map_err(|e| e.to_string())?
            .open_process_file()
            .map_err(|e| e.to_string())?;
        rustix::fs::flock(&lock, rustix::fs::FlockOperation::NonBlockingLockExclusive)
            .map_err(|_| "Another sign-in transition is in progress.")?;
        let (record, result) = f(self.read()?)?;
        self.validate(&record)?;
        let bytes =
            serde_json::to_vec(&record).map_err(|_| "Cannot encode MCP sign-in journal.")?;
        let file = self.file()?;
        file.replace(&bytes).map_err(|e| e.to_string())?;
        if file.read().map_err(|e| e.to_string())?.as_deref() != Some(bytes.as_slice()) {
            return Err("MCP sign-in journal readback differed.".into());
        }
        Ok(result)
    }
    pub(crate) fn begin(&self, server: &str, id: &str) -> Result<(), String> {
        self.mutate(|old| {
            if old.is_some_and(|r| !matches!(r.phase, Phase::Complete | Phase::Cleared)) {
                return Err(
                    "An interrupted or active MCP sign-in must be cleared explicitly.".into(),
                );
            }
            Ok((
                Intent {
                    version: 1,
                    project: self.project.clone(),
                    server: server.into(),
                    id: id.into(),
                    owner: owner()?,
                    phase: Phase::Prepared,
                    binding: None,
                },
                (),
            ))
        })
    }
    pub(crate) fn advance(
        &self,
        id: &str,
        from: Phase,
        to: Phase,
        binding: Option<Binding>,
    ) -> Result<(), String> {
        let valid = matches!(
            (from, to),
            (Phase::Prepared, Phase::Registering | Phase::Authorizing)
                | (Phase::Registering, Phase::Authorizing)
                | (Phase::Authorizing, Phase::Exchanging)
                | (Phase::Exchanging, Phase::Storing)
                | (Phase::Storing, Phase::Complete)
        );
        if !valid {
            return Err("MCP sign-in transition is not allowed.".into());
        }
        self.mutate(|old| {
            let mut r = old.ok_or("MCP sign-in intent is absent.")?;
            if r.id != id || r.owner != owner()? || r.phase != from {
                return Err(
                    "MCP sign-in intent is stale, interrupted or already submitted.".into(),
                );
            }
            if binding.is_some() {
                if from != Phase::Exchanging {
                    return Err("MCP credential binding arrived outside token validation.".into());
                }
                r.binding = binding;
            }
            r.phase = to;
            Ok((r, ()))
        })
    }
    /// Caller has stopped the owning task and verified cleanup of its exact pending credentials.
    pub(crate) fn clear_after_cleanup(&self, id: &str) -> Result<(), String> {
        self.mutate(|old| {
            let mut r = old.ok_or("MCP sign-in intent is absent.")?;
            if r.id != id || r.phase != Phase::Interrupted {
                return Err("MCP sign-in cleanup is stale or still active.".into());
            }
            r.phase = Phase::Cleared;
            Ok((r, ()))
        })
    }
    pub(crate) fn interrupt(&self, id: &str) -> Result<(), String> {
        self.mutate(|old| {
            let mut r = old.ok_or("MCP sign-in intent is absent.")?;
            if r.id != id || r.phase == Phase::Complete {
                return Err("MCP sign-in interruption is stale.".into());
            }
            r.phase = Phase::Interrupted;
            Ok((r, ()))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn an_effect_intent_cannot_be_resubmitted_or_advanced_after_restart() {
        let root = std::env::temp_dir().join(format!(
            "gbplus-auth-intent-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let journal = Journal::new(&root, "fixture-project").unwrap();
        let id = "a".repeat(64);
        journal.begin(&"b".repeat(64), &id).unwrap();
        journal
            .advance(&id, Phase::Prepared, Phase::Registering, None)
            .unwrap();
        assert!(
            journal
                .advance(&id, Phase::Prepared, Phase::Registering, None)
                .is_err()
        );
        let mut stale = journal.read().unwrap().unwrap();
        stale.owner = "0".repeat(64);
        journal
            .file()
            .unwrap()
            .replace(&serde_json::to_vec(&stale).unwrap())
            .unwrap();
        assert!(
            journal
                .advance(&id, Phase::Registering, Phase::Authorizing, None)
                .is_err()
        );
        assert!(journal.begin(&"b".repeat(64), &"c".repeat(64)).is_err());
        assert!(journal.clear_after_cleanup(&id).is_err());
        journal.interrupt(&id).unwrap();
        assert_eq!(journal.read().unwrap().unwrap().phase, Phase::Interrupted);
        journal.clear_after_cleanup(&id).unwrap();
        journal.begin(&"b".repeat(64), &"c".repeat(64)).unwrap();
        std::fs::remove_dir_all(root).unwrap();
    }
}
