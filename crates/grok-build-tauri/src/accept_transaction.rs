//! Crash-recoverable all-or-rollback application for an accepted proposal set.

use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use grok_build_plus_host::{
    BoundProject, PendingFileSet, PlusSessionStore, accept_pending_file_proposal,
    bind_project_folder, preflight_pending_file_set, rollback_accepted_file_proposal,
};
use serde::{Deserialize, Serialize};

const ACCEPT_TRANSACTION_FILE: &str = "plus-accept-transaction.json";
const ACCEPT_TRANSACTION_SCHEMA: u16 = 1;
const MAX_TRANSACTION_BYTES: u64 = 64 * 1024 * 1024;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum TransactionPhase {
    Applying,
    Applied,
    Committed,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct TransactionJournal {
    schema_version: u16,
    phase: TransactionPhase,
    workspace_root: PathBuf,
    session_id: String,
    proposals: PendingFileSet,
    applied_count: usize,
}

pub(crate) struct AcceptTransaction {
    state_root: PathBuf,
    journal: TransactionJournal,
}

impl AcceptTransaction {
    pub(crate) fn begin(
        state_root: &Path,
        bound: &BoundProject,
        session_id: &str,
        proposals: &PendingFileSet,
    ) -> Result<Self, String> {
        if proposals.items.is_empty() {
            return Err("No staged file proposal is waiting for Accept.".into());
        }
        preflight_pending_file_set(bound, proposals).map_err(|error| error.to_string())?;
        ensure_owner_directory(state_root)?;
        let path = state_root.join(ACCEPT_TRANSACTION_FILE);
        if path.exists() {
            return Err(
                "Accept is blocked until the previous change transaction is recovered.".into(),
            );
        }
        let transaction = Self {
            state_root: state_root.to_path_buf(),
            journal: TransactionJournal {
                schema_version: ACCEPT_TRANSACTION_SCHEMA,
                phase: TransactionPhase::Applying,
                workspace_root: bound.folder().to_path_buf(),
                session_id: session_id.to_owned(),
                proposals: proposals.clone(),
                applied_count: 0,
            },
        };
        transaction.save()?;
        Ok(transaction)
    }

    pub(crate) fn apply(&mut self, bound: &BoundProject) -> Result<(), String> {
        self.apply_using(bound, |bound, proposal| {
            accept_pending_file_proposal(bound, proposal).map_err(|error| error.to_string())
        })
    }

    fn apply_using(
        &mut self,
        bound: &BoundProject,
        mut apply: impl FnMut(
            &BoundProject,
            &grok_build_plus_host::PendingFileProposal,
        ) -> Result<(), String>,
    ) -> Result<(), String> {
        for index in 0..self.journal.proposals.items.len() {
            let proposal = &self.journal.proposals.items[index];
            if let Err(error) = apply(bound, proposal) {
                return match self.rollback(bound) {
                    Ok(()) => Err(format!(
                        "Accept failed and every earlier write was rolled back: {error}"
                    )),
                    Err(rollback) => Err(format!(
                        "Accept failed and recovery remains required: {error}; rollback: {rollback}"
                    )),
                };
            }
            self.journal.applied_count = index + 1;
            self.save()?;
        }
        self.journal.phase = TransactionPhase::Applied;
        self.save()
    }

    pub(crate) fn rollback(&mut self, bound: &BoundProject) -> Result<(), String> {
        rollback_journal(bound, &self.journal)?;
        remove_journal(&self.state_root)
    }

    pub(crate) fn commit(mut self) -> Result<(), String> {
        self.journal.phase = TransactionPhase::Committed;
        self.save()?;
        remove_journal(&self.state_root)
    }

    fn save(&self) -> Result<(), String> {
        save_journal(&self.state_root, &self.journal)
    }
}

pub(crate) fn recover_accept_transaction(store: &PlusSessionStore) -> Result<(), String> {
    let Some(journal) = load_journal(store.state_root())? else {
        return Ok(());
    };
    if journal.phase == TransactionPhase::Committed {
        return remove_journal(store.state_root());
    }
    let bound = bind_project_folder(&journal.workspace_root)
        .map_err(|error| format!("Cannot bind the interrupted Accept workspace: {error}"))?;
    if journal.phase == TransactionPhase::Applied {
        let sessions = store
            .load_session_book()
            .map_err(|error| format!("Cannot inspect interrupted Accept session state: {error}"))?;
        let session = sessions
            .sessions
            .iter()
            .find(|session| session.id == journal.session_id)
            .ok_or_else(|| "Interrupted Accept references a missing session.".to_owned())?;
        if session.pending.items.is_empty() {
            return remove_journal(store.state_root());
        }
        if session.pending != journal.proposals {
            return Err(
                "Interrupted Accept has mixed proposal/session state; project effects remain blocked."
                    .into(),
            );
        }
    }
    rollback_journal(&bound, &journal)?;
    remove_journal(store.state_root())
}

fn rollback_journal(bound: &BoundProject, journal: &TransactionJournal) -> Result<(), String> {
    for proposal in journal.proposals.items.iter().rev() {
        let one = PendingFileSet {
            items: vec![proposal.clone()],
        };
        if preflight_pending_file_set(bound, &one).is_ok() {
            continue;
        }
        rollback_accepted_file_proposal(bound, proposal).map_err(|error| error.to_string())?;
    }
    Ok(())
}

fn journal_path(state_root: &Path) -> PathBuf {
    state_root.join(ACCEPT_TRANSACTION_FILE)
}

fn load_journal(state_root: &Path) -> Result<Option<TransactionJournal>, String> {
    let path = journal_path(state_root);
    let metadata = match fs::symlink_metadata(&path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(format!("Cannot inspect Accept transaction: {error}")),
    };
    if !metadata.is_file()
        || metadata.file_type().is_symlink()
        || metadata.len() > MAX_TRANSACTION_BYTES
    {
        return Err("Accept transaction is not a bounded regular owner file.".into());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err("Accept transaction permissions are not owner-only.".into());
        }
    }
    let mut bytes = Vec::with_capacity(usize::try_from(metadata.len()).unwrap_or_default());
    File::open(&path)
        .and_then(|mut file| file.read_to_end(&mut bytes))
        .map_err(|error| format!("Cannot read Accept transaction: {error}"))?;
    let journal: TransactionJournal = serde_json::from_slice(&bytes)
        .map_err(|error| format!("Accept transaction is invalid: {error}"))?;
    validate_journal(&journal)?;
    Ok(Some(journal))
}

fn save_journal(state_root: &Path, journal: &TransactionJournal) -> Result<(), String> {
    validate_journal(journal)?;
    ensure_owner_directory(state_root)?;
    let mut bytes = serde_json::to_vec_pretty(journal)
        .map_err(|error| format!("Cannot encode Accept transaction: {error}"))?;
    bytes.push(b'\n');
    if bytes.len() as u64 > MAX_TRANSACTION_BYTES {
        return Err("Accept transaction exceeds its recovery bound.".into());
    }
    let path = journal_path(state_root);
    let temporary = state_root.join(format!(
        ".{ACCEPT_TRANSACTION_FILE}.{}-{}.tmp",
        std::process::id(),
        unix_time_millis()
    ));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temporary)
        .map_err(|error| format!("Cannot create Accept transaction temp: {error}"))?;
    restrict_owner_file(&file)?;
    if let Err(error) = file
        .write_all(&bytes)
        .and_then(|()| file.flush())
        .and_then(|()| file.sync_all())
        .and_then(|()| fs::rename(&temporary, &path))
        .and_then(|()| sync_directory(state_root))
    {
        let _ = fs::remove_file(&temporary);
        return Err(format!("Cannot durably save Accept transaction: {error}"));
    }
    Ok(())
}

fn remove_journal(state_root: &Path) -> Result<(), String> {
    let path = journal_path(state_root);
    match fs::remove_file(&path) {
        Ok(()) => sync_directory(state_root)
            .map_err(|error| format!("Cannot sync Accept recovery removal: {error}")),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(format!("Cannot remove Accept transaction: {error}")),
    }
}

fn validate_journal(journal: &TransactionJournal) -> Result<(), String> {
    if journal.schema_version != ACCEPT_TRANSACTION_SCHEMA
        || !journal.workspace_root.is_absolute()
        || journal.session_id.is_empty()
        || journal.session_id.len() > 256
        || journal.proposals.items.is_empty()
        || journal.applied_count > journal.proposals.items.len()
    {
        return Err("Accept transaction violates its schema bounds.".into());
    }
    Ok(())
}

fn ensure_owner_directory(path: &Path) -> Result<(), String> {
    fs::create_dir_all(path)
        .map_err(|error| format!("Cannot create Accept state root: {error}"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))
            .map_err(|error| format!("Cannot restrict Accept state root: {error}"))?;
    }
    Ok(())
}

fn restrict_owner_file(file: &File) -> Result<(), String> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        file.set_permissions(fs::Permissions::from_mode(0o600))
            .map_err(|error| format!("Cannot restrict Accept transaction: {error}"))?;
    }
    Ok(())
}

fn sync_directory(path: &Path) -> std::io::Result<()> {
    File::open(path)?.sync_all()
}

fn unix_time_millis() -> u128 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
}

#[cfg(test)]
mod tests {
    use super::*;
    use grok_build_plus_host::{PendingFileProposal, bind_project_folder};

    fn root(label: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "grok-build-accept-transaction-{label}-{}-{}",
            std::process::id(),
            unix_time_millis()
        ))
    }

    fn proposal(path: &str, before: &[u8], after: &[u8]) -> PendingFileProposal {
        PendingFileProposal {
            relative_path: PathBuf::from(path),
            before: before.to_vec(),
            before_existed: Some(true),
            after: after.to_vec(),
            group_decisions: Vec::new(),
        }
    }

    #[test]
    fn batch_accept_rolls_back_every_prior_write_on_failure() {
        let root = root("rollback");
        let workspace = root.join("workspace");
        let state = root.join("state");
        fs::create_dir_all(&workspace).expect("workspace");
        fs::write(workspace.join("one.txt"), b"one-before").expect("one");
        fs::write(workspace.join("three.txt"), b"three-before").expect("three");
        let bound = bind_project_folder(&workspace).expect("bind");
        let mut new_file = proposal("new.txt", b"", b"new-after");
        new_file.before_existed = Some(false);
        let set = PendingFileSet {
            items: vec![
                proposal("one.txt", b"one-before", b"one-after"),
                new_file,
                proposal("three.txt", b"three-before", b"three-after"),
            ],
        };
        let mut transaction =
            AcceptTransaction::begin(&state, &bound, "session", &set).expect("begin");
        let mut count = 0;
        let error = transaction
            .apply_using(&bound, |bound, proposal| {
                count += 1;
                if count == 3 {
                    return Err("injected third-file failure".into());
                }
                accept_pending_file_proposal(bound, proposal).map_err(|error| error.to_string())
            })
            .expect_err("injected failure");
        assert!(error.contains("every earlier write was rolled back"));
        assert_eq!(
            fs::read(workspace.join("one.txt")).expect("one"),
            b"one-before"
        );
        assert!(!workspace.join("new.txt").exists());
        assert_eq!(
            fs::read(workspace.join("three.txt")).expect("three"),
            b"three-before"
        );
        assert!(!journal_path(&state).exists());
        fs::remove_dir_all(root).expect("cleanup");
    }

    #[test]
    fn restart_recovers_an_interrupted_accept_transaction() {
        let root = root("restart");
        let workspace = root.join("workspace");
        let state = root.join("state");
        fs::create_dir_all(&workspace).expect("workspace");
        fs::write(workspace.join("one.txt"), b"before").expect("seed");
        let bound = bind_project_folder(&workspace).expect("bind");
        let set = PendingFileSet {
            items: vec![proposal("one.txt", b"before", b"after")],
        };
        let store = PlusSessionStore::from_state_root(&state);
        let session = store.create_plus_session("Session").expect("session");
        store.remember_pending_set(&set).expect("persist pending");
        let transaction =
            AcceptTransaction::begin(&state, &bound, &session.id, &set).expect("begin");
        accept_pending_file_proposal(&bound, &set.items[0]).expect("simulate applied file");
        drop(transaction);
        recover_accept_transaction(&store).expect("recover");
        assert_eq!(
            fs::read(workspace.join("one.txt")).expect("restored"),
            b"before"
        );
        assert!(!journal_path(&state).exists());
        fs::remove_dir_all(root).expect("cleanup");
    }
}
