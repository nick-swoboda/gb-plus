//! Account metadata is owner-only and contains no token, code, verifier or callback state.
use super::auth_contract::{Endpoint, validate_scopes};
use crate::owner_state::{OwnerStateFile, OwnerStateRoot};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Binding {
    pub(crate) project: String,
    pub(crate) server: String,
    pub(crate) epoch: String,
    pub(crate) resource: String,
    pub(crate) issuer: String,
    pub(crate) client_id: String,
    pub(crate) metadata_digest: String,
    pub(crate) scopes: Vec<String>,
    pub(crate) key: String,
}
impl Binding {
    pub(crate) fn validate(&self) -> Result<(), String> {
        project_id(&self.project)?;
        if [&self.server, &self.epoch, &self.metadata_digest, &self.key]
            .iter()
            .any(|s| !digest(s))
            || self.client_id.is_empty()
            || self.client_id.len() > 1024
            || self.client_id.chars().any(char::is_control)
        {
            return Err("MCP account binding is invalid.".into());
        }
        Endpoint::parse(&self.resource)?;
        Endpoint::parse(&self.issuer)?;
        if validate_scopes(self.scopes.clone())? != self.scopes {
            return Err("MCP account scopes are not canonical.".into());
        }
        if self.key != self.expected_key()? {
            return Err("MCP credential key does not match its account binding.".into());
        }
        Ok(())
    }
    pub(crate) fn expected_key(&self) -> Result<String, String> {
        let bytes = serde_json::to_vec(&(
            "GB Plus MCP credential v1",
            &self.project,
            &self.server,
            &self.epoch,
            &self.resource,
            &self.issuer,
            &self.client_id,
            &self.metadata_digest,
            &self.scopes,
        ))
        .map_err(|_| "Cannot encode MCP credential binding.")?;
        Ok(hash(&bytes))
    }
    pub(crate) fn server_identity(&self) -> Result<String, String> {
        self.validate()?;
        Ok(hash(
            format!(
                "GB Plus authenticated MCP v1\0{}\0{}",
                self.server, self.key
            )
            .as_bytes(),
        ))
    }
}

#[derive(Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum PendingState {
    Authorizing,
    Storing,
    Interrupted,
}
#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Pending {
    binding: Binding,
    state: PendingState,
    owner: String,
}
#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Record {
    version: u16,
    project: String,
    revision: u64,
    accounts: BTreeMap<String, Binding>,
    account_required: BTreeSet<String>,
    retired: BTreeMap<String, Binding>,
    pending: BTreeMap<String, Pending>,
}
pub(crate) struct Store {
    root: OwnerStateRoot,
    project: String,
    key: String,
}
impl Store {
    pub(crate) fn new(root: &Path, project: &str) -> Result<Self, String> {
        project_id(project)?;
        Ok(Self {
            root: OwnerStateRoot::new(root.join("mcp-accounts-v1")),
            project: project.into(),
            key: hash(project.as_bytes()),
        })
    }
    fn file(&self) -> Result<OwnerStateFile, String> {
        self.root
            .file(format!("{}.json", self.key), 1024 * 1024)
            .map_err(|e| e.to_string())
    }
    fn read(&self) -> Result<Record, String> {
        let Some(bytes) = self.file()?.read().map_err(|e| e.to_string())? else {
            return Ok(Record {
                version: 1,
                project: self.project.clone(),
                revision: 0,
                accounts: BTreeMap::new(),
                account_required: BTreeSet::new(),
                retired: BTreeMap::new(),
                pending: BTreeMap::new(),
            });
        };
        let record: Record = serde_json::from_slice(&bytes)
            .map_err(|_| "MCP account metadata is unsupported; its bytes were preserved.")?;
        self.validate(&record)?;
        Ok(record)
    }
    fn validate(&self, record: &Record) -> Result<(), String> {
        if record.version != 1
            || record.project != self.project
            || record.accounts.len() > 64
            || record.pending.len() > 8
            || record.retired.len() > 128
            || record.account_required.len() > 64
            || record.account_required.iter().any(|server| !digest(server))
        {
            return Err("MCP account metadata version, scope or count is invalid.".into());
        }
        for (server, binding) in &record.accounts {
            binding.validate()?;
            if server != &binding.server
                || binding.project != self.project
                || !record.account_required.contains(server)
            {
                return Err("MCP account crossed its project/server binding.".into());
            }
        }
        for (key, binding) in &record.retired {
            binding.validate()?;
            if key != &binding.key
                || binding.project != self.project
                || record.accounts.values().any(|active| &active.key == key)
            {
                return Err("Retired MCP account binding is invalid.".into());
            }
        }
        for (epoch, pending) in &record.pending {
            pending.binding.validate()?;
            if !digest(&pending.owner)
                || epoch != &pending.binding.epoch
                || pending.binding.project != self.project
            {
                return Err("MCP pending account crossed its project/attempt binding.".into());
            }
        }
        Ok(())
    }
    fn mutate<T>(
        &self,
        operation: impl FnOnce(&mut Record) -> Result<T, String>,
    ) -> Result<T, String> {
        let lock = self
            .root
            .file(format!("{}.lock", self.key), 0)
            .map_err(|e| e.to_string())?
            .open_process_file()
            .map_err(|e| e.to_string())?;
        rustix::fs::flock(&lock, rustix::fs::FlockOperation::NonBlockingLockExclusive)
            .map_err(|_| "MCP account metadata is being changed.")?;
        let mut record = self.read()?;
        let result = operation(&mut record)?;
        record.revision = record
            .revision
            .checked_add(1)
            .ok_or("MCP account revision is exhausted.")?;
        self.validate(&record)?;
        let bytes =
            serde_json::to_vec(&record).map_err(|_| "Cannot encode MCP account metadata.")?;
        let file = self.file()?;
        file.replace(&bytes).map_err(|e| e.to_string())?;
        if file.read().map_err(|e| e.to_string())?.as_deref() != Some(bytes.as_slice()) {
            return Err("MCP account metadata readback differed.".into());
        }
        Ok(result)
    }
    pub(crate) fn active(&self, server: &str) -> Result<Option<Binding>, String> {
        Ok(self.read()?.accounts.get(server).cloned())
    }
    pub(crate) fn begin(&self, binding: Binding) -> Result<(), String> {
        binding.validate()?;
        self.mutate(|r| {
            if binding.project != self.project
                || r.pending.len() >= 8
                || r.pending.contains_key(&binding.epoch)
                || r.accounts.values().any(|a| a.epoch == binding.epoch)
            {
                return Err("MCP sign-in attempt is duplicated or outside its scope.".into());
            }
            r.pending.insert(
                binding.epoch.clone(),
                Pending {
                    binding,
                    state: PendingState::Authorizing,
                    owner: owner()?,
                },
            );
            Ok(())
        })
    }
    pub(crate) fn storing(&self, epoch: &str) -> Result<(), String> {
        self.mutate(|r| {
            let p = r
                .pending
                .get_mut(epoch)
                .ok_or("MCP sign-in attempt is absent.")?;
            if p.state != PendingState::Authorizing || p.owner != owner()? {
                return Err("MCP credentials cannot be automatically replayed.".into());
            }
            p.state = PendingState::Storing;
            Ok(())
        })
    }
    // Called only after exact Keychain readback and authenticated MCP readiness.
    // Replacing a pointer does not erase the old Keychain item; caller cleans it
    // only after commit succeeds and no active run retains that account epoch.
    pub(crate) fn activate_verified(&self, epoch: &str) -> Result<Option<Binding>, String> {
        self.mutate(|r| {
            let p = r
                .pending
                .remove(epoch)
                .ok_or("MCP sign-in attempt is absent.")?;
            if p.state != PendingState::Storing || p.owner != owner()? {
                return Err("MCP account was not staged for verification.".into());
            }
            r.account_required.insert(p.binding.server.clone());
            let old = r.accounts.insert(p.binding.server.clone(), p.binding);
            if let Some(binding) = &old {
                r.retired.insert(binding.key.clone(), binding.clone());
            }
            Ok(old)
        })
    }
    pub(crate) fn interrupt(&self, epoch: &str) -> Result<(), String> {
        self.mutate(|r| {
            r.pending
                .get_mut(epoch)
                .ok_or("MCP sign-in attempt is absent.")?
                .state = PendingState::Interrupted;
            Ok(())
        })
    }
    pub(crate) fn requires_account(&self, server: &str) -> Result<bool, String> {
        Ok(self.read()?.account_required.contains(server))
    }
    pub(crate) fn retired_cleanup(&self) -> Result<Vec<Binding>, String> {
        Ok(self.read()?.retired.into_values().collect())
    }
    pub(crate) fn retire_active(&self, server: &str) -> Result<Binding, String> {
        self.mutate(|r| {
            let old = r
                .accounts
                .remove(server)
                .ok_or("MCP account is not connected.")?;
            r.retired.insert(old.key.clone(), old.clone());
            Ok(old)
        })
    }
    pub(crate) fn forget_retired_after_keychain_absence(&self, key: &str) -> Result<(), String> {
        self.mutate(|r| {
            r.retired
                .remove(key)
                .ok_or("Retired MCP account is absent.")?;
            Ok(())
        })
    }
    pub(crate) fn pending_cleanup(&self) -> Result<Vec<Binding>, String> {
        Ok(self
            .read()?
            .pending
            .into_values()
            .map(|p| p.binding)
            .collect())
    }
    pub(crate) fn forget_pending_after_keychain_absence(&self, epoch: &str) -> Result<(), String> {
        self.mutate(|r| {
            r.pending
                .remove(epoch)
                .ok_or("MCP pending account is absent.")?;
            Ok(())
        })
    }
}

fn project_id(text: &str) -> Result<(), String> {
    if text.is_empty() || text.len() > 256 || text.chars().any(char::is_control) {
        Err("MCP account project is invalid.".into())
    } else {
        Ok(())
    }
}
pub(super) fn digest(text: &str) -> bool {
    text.len() == 64
        && text
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
pub(super) fn hash(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut text = String::with_capacity(64);
    for byte in Sha256::digest(bytes) {
        write!(&mut text, "{byte:02x}").expect("write to String");
    }
    text
}

pub(super) fn owner() -> Result<String, String> {
    use std::io::Read as _;
    static OWNER: std::sync::OnceLock<Result<String, String>> = std::sync::OnceLock::new();
    OWNER
        .get_or_init(|| {
            let mut bytes = [0u8; 32];
            std::fs::File::open("/dev/urandom")
                .and_then(|mut f| f.read_exact(&mut bytes))
                .map_err(|_| "MCP account process identity is unavailable.".to_owned())?;
            Ok(hash(&bytes))
        })
        .clone()
}

#[cfg(test)]
mod tests {
    use super::*;
    fn binding(epoch: &str) -> Binding {
        let mut b = Binding {
            project: "fixture-project".into(),
            server: "a".repeat(64),
            epoch: epoch.repeat(64),
            resource: "https://resource.example/mcp".into(),
            issuer: "https://issuer.example/".into(),
            client_id: "public-client".into(),
            metadata_digest: "b".repeat(64),
            scopes: vec!["read".into()],
            key: String::new(),
        };
        b.key = b.expected_key().unwrap();
        b
    }
    fn root() -> std::path::PathBuf {
        std::env::temp_dir().join(format!(
            "gbplus-oauth-store-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ))
    }
    #[test]
    fn interrupted_sign_in_preserves_the_previous_active_account() {
        let root = root();
        let store = Store::new(&root, "fixture-project").unwrap();
        let first = binding("c");
        store.begin(first.clone()).unwrap();
        assert!(store.activate_verified(&first.epoch).is_err());
        store.storing(&first.epoch).unwrap();
        store.activate_verified(&first.epoch).unwrap();
        let next = binding("d");
        store.begin(next.clone()).unwrap();
        store.storing(&next.epoch).unwrap();
        store.interrupt(&next.epoch).unwrap();
        let reopened = Store::new(&root, "fixture-project").unwrap();
        assert_eq!(
            reopened.active(&first.server).unwrap().unwrap().key,
            first.key
        );
        assert!(reopened.storing(&next.epoch).is_err());
        assert!(reopened.activate_verified(&next.epoch).is_err());
        assert_eq!(reopened.pending_cleanup().unwrap().len(), 1);
        reopened
            .forget_pending_after_keychain_absence(&next.epoch)
            .unwrap();
        assert_ne!(
            first.server_identity().unwrap(),
            next.server_identity().unwrap()
        );
        std::fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn replacement_and_disconnect_retain_exact_cleanup_references_without_anonymous_fallback() {
        let root = root();
        let store = Store::new(&root, "fixture-project").unwrap();
        let first = binding("c");
        let second = binding("d");
        for b in [&first, &second] {
            store.begin(b.clone()).unwrap();
            store.storing(&b.epoch).unwrap();
            store.activate_verified(&b.epoch).unwrap();
        }
        let reopened = Store::new(&root, "fixture-project").unwrap();
        assert_eq!(reopened.retired_cleanup().unwrap()[0].key, first.key);
        assert_eq!(
            reopened.retire_active(&second.server).unwrap().key,
            second.key
        );
        assert!(reopened.active(&second.server).unwrap().is_none());
        assert!(reopened.requires_account(&second.server).unwrap());
        assert_eq!(reopened.retired_cleanup().unwrap().len(), 2);
        reopened
            .forget_retired_after_keychain_absence(&first.key)
            .unwrap();
        assert_eq!(reopened.retired_cleanup().unwrap()[0].key, second.key);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn another_process_cannot_resume_or_activate_an_interrupted_sign_in() {
        let root = root();
        let store = Store::new(&root, "fixture-project").unwrap();
        let pending = binding("c");
        store.begin(pending.clone()).unwrap();
        store.storing(&pending.epoch).unwrap();
        let mut record = store.read().unwrap();
        let stale = "0".repeat(64);
        assert_ne!(stale, owner().unwrap());
        record.pending.get_mut(&pending.epoch).unwrap().owner = stale;
        store
            .file()
            .unwrap()
            .replace(&serde_json::to_vec(&record).unwrap())
            .unwrap();
        let reopened = Store::new(&root, "fixture-project").unwrap();
        assert!(reopened.storing(&pending.epoch).is_err());
        assert!(reopened.activate_verified(&pending.epoch).is_err());
        assert!(reopened.active(&pending.server).unwrap().is_none());
        assert_eq!(reopened.pending_cleanup().unwrap().len(), 1);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn copied_unknown_and_secret_bearing_metadata_refuse_without_rewrite() {
        let root = root();
        let store = Store::new(&root, "fixture-project").unwrap();
        store.begin(binding("c")).unwrap();
        let original = store.file().unwrap().read().unwrap().unwrap();
        for (field, value) in [
            ("version", serde_json::json!(99)),
            ("project", serde_json::json!("another-project")),
            ("accessToken", serde_json::json!("must-not-be-accepted")),
        ] {
            let mut record: serde_json::Value = serde_json::from_slice(&original).unwrap();
            record[field] = value;
            let bytes = serde_json::to_vec(&record).unwrap();
            store.file().unwrap().replace(&bytes).unwrap();
            assert!(store.read().is_err());
            assert_eq!(store.file().unwrap().read().unwrap().unwrap(), bytes);
        }
        std::fs::remove_dir_all(root).unwrap();
    }
}
