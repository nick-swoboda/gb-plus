//! Prototype path-based application and rollback of staged regular-file changes.
//!
//! Replacement writes use a same-directory temporary file and atomic rename on
//! the supported Unix targets. Validation is repeated at each operation, but it
//! is not descriptor-relative and therefore does not claim complete protection
//! from an actively racing same-user process. New production callers must use
//! [`crate::CapabilitySafeApplier`]; this implementation remains for migration
//! compatibility and its historical crash-recovery fixtures.

use std::fmt::{self, Display, Formatter};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};

use grok_build_core::{ChangeSet, ContractError, Digest, FileOperation, IssuedWorkspaceGrant};
use sha2::{Digest as _, Sha256};

use crate::workspace::{WorkspacePipelineError, hash_bytes, read_stable_file};
use crate::{CanonicalRoot, PathValidationError, StagedChangeSet, WorkspaceManifest};

const JOURNAL_VERSION: &str = "grok-build-safe-apply-v1";

/// Evidence returned after a staged change set is fully applied and re-snapshotted.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ApplyOutcome {
    change_set_id: String,
    applied_snapshot: Digest,
}

impl ApplyOutcome {
    /// Returns the applied change-set identifier.
    #[must_use]
    pub fn change_set_id(&self) -> &str {
        &self.change_set_id
    }

    /// Returns the verified post-apply workspace snapshot.
    #[must_use]
    pub const fn applied_snapshot(&self) -> &Digest {
        &self.applied_snapshot
    }
}

/// A report of incomplete transactions restored to their base snapshots.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct RecoveryReport {
    recovered_change_sets: Vec<String>,
}

/// Proven result of reconciling one durable application transaction.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ApplyReconciliation {
    /// The exact result snapshot is still live and the transaction is committed.
    Committed(ApplyOutcome),
    /// The exact base snapshot is live and the transaction is durably rolled back.
    RolledBack {
        /// Change-set identifier whose effects were absent or restored.
        change_set_id: String,
        /// Exact restored base snapshot.
        base_snapshot: Digest,
    },
}

impl RecoveryReport {
    /// Returns transaction identifiers recovered during this pass.
    #[must_use]
    pub fn recovered_change_sets(&self) -> &[String] {
        &self.recovered_change_sets
    }

    /// Returns whether no incomplete transaction required recovery.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.recovered_change_sets.is_empty()
    }
}

/// A path-based prototype retained for migration and regression coverage.
///
/// New production code must use [`crate::CapabilitySafeApplier`].
#[derive(Debug)]
pub struct SafeApplier {
    grant: IssuedWorkspaceGrant,
    root: CanonicalRoot,
    journal_root: PathBuf,
}

impl SafeApplier {
    /// Opens or creates a private transaction-journal directory.
    ///
    /// The journal path must be absolute, outside the workspace, and either an
    /// existing directory or a missing leaf beneath an existing directory. On
    /// Unix its permissions are forced to `0700`.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid/insufficient grant, unsafe path, link,
    /// non-directory entry, containment overlap, or filesystem failure.
    pub fn open(
        grant: IssuedWorkspaceGrant,
        journal_root: impl AsRef<Path>,
    ) -> Result<Self, SafeApplyError> {
        grant
            .validate_integrity()
            .map_err(SafeApplyError::Contract)?;
        let contract = grant.contract();
        if !contract.permissions.apply_verified_changes {
            return Err(SafeApplyError::PermissionDenied);
        }
        let root = CanonicalRoot::open(&contract.canonical_root)
            .map_err(SafeApplyError::PathValidation)?;
        if root.as_path() != contract.canonical_root {
            return Err(SafeApplyError::Journal(
                "grant root is not the exact canonical workspace root".into(),
            ));
        }

        let requested = journal_root.as_ref();
        if !requested.is_absolute() {
            return Err(SafeApplyError::Journal(format!(
                "journal root is not absolute: {}",
                requested.display()
            )));
        }
        match fs::symlink_metadata(requested) {
            Ok(metadata) => {
                if metadata.file_type().is_symlink() || !metadata.file_type().is_dir() {
                    return Err(SafeApplyError::Journal(format!(
                        "journal root is not a real directory: {}",
                        requested.display()
                    )));
                }
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                let parent = requested
                    .parent()
                    .ok_or_else(|| SafeApplyError::Journal("journal root has no parent".into()))?;
                let canonical_parent = fs::canonicalize(parent)
                    .map_err(|error| io_error("canonicalize journal parent", parent, &error))?;
                let leaf = requested.file_name().ok_or_else(|| {
                    SafeApplyError::Journal("journal root has no leaf name".into())
                })?;
                let candidate = canonical_parent.join(leaf);
                if candidate.starts_with(root.as_path()) || root.as_path().starts_with(&candidate) {
                    return Err(SafeApplyError::Journal(
                        "journal root must not overlap the workspace".into(),
                    ));
                }
                fs::create_dir(&candidate)
                    .map_err(|error| io_error("create journal root", &candidate, &error))?;
            }
            Err(error) => return Err(io_error("inspect journal root", requested, &error)),
        }
        let journal_root = fs::canonicalize(requested)
            .map_err(|error| io_error("canonicalize journal root", requested, &error))?;
        if journal_root.starts_with(root.as_path()) || root.as_path().starts_with(&journal_root) {
            return Err(SafeApplyError::Journal(
                "journal root must not overlap the workspace".into(),
            ));
        }
        set_directory_mode(&journal_root, 0o700)?;

        Ok(Self {
            grant,
            root,
            journal_root,
        })
    }

    /// Returns the private journal root.
    #[must_use]
    pub fn journal_root(&self) -> &Path {
        &self.journal_root
    }

    /// Verifies that the entire live regular-file manifest still matches the
    /// staged base snapshot.
    ///
    /// # Errors
    ///
    /// Returns an error for an unsafe live entry, stale content, or filesystem
    /// failure.
    pub fn preflight(&self, staged: &StagedChangeSet) -> Result<(), SafeApplyError> {
        validate_staged(staged)?;
        let current =
            WorkspaceManifest::capture(&self.grant, 1).map_err(SafeApplyError::Workspace)?;
        if current.snapshot().snapshot_id != staged.change_set().base_snapshot {
            return Err(SafeApplyError::StaleBase {
                expected: staged.change_set().base_snapshot.clone(),
                actual: current.snapshot().snapshot_id.clone(),
            });
        }
        Ok(())
    }

    /// Applies a staged change set through a durable transaction journal.
    ///
    /// Any ordinary execution or verification failure triggers an immediate
    /// rollback attempt. Incomplete journals are also recovered at the start of
    /// every call.
    ///
    /// # Errors
    ///
    /// Returns an error for stale content, unsafe paths, invalid blobs, journal
    /// corruption, mutation failure, post-apply mismatch, or failed recovery.
    pub fn apply(&self, staged: &StagedChangeSet) -> Result<ApplyOutcome, SafeApplyError> {
        self.apply_internal(staged, None)
    }

    /// Rolls back a committed transaction when the live workspace still exactly
    /// matches that transaction's result snapshot.
    ///
    /// # Errors
    ///
    /// Returns an error if the transaction is absent/not committed, live content
    /// is stale, journal evidence is invalid, or restoration fails.
    pub fn rollback(&self, change_set_id: &str) -> Result<Digest, SafeApplyError> {
        self.rollback_internal(change_set_id, None)
    }

    fn rollback_internal(
        &self,
        change_set_id: &str,
        fault: Option<FaultInjection>,
    ) -> Result<Digest, SafeApplyError> {
        let transaction = self.transaction_path(change_set_id);
        if !transaction.is_dir() {
            return Err(SafeApplyError::TransactionNotFound(change_set_id.into()));
        }
        let phase = read_phase(&transaction)?;
        if phase == JournalPhase::RolledBack {
            let plan = read_plan(&transaction)?;
            let current =
                WorkspaceManifest::capture(&self.grant, 1).map_err(SafeApplyError::Workspace)?;
            if current.snapshot().snapshot_id != plan.change_set.base_snapshot {
                return Err(SafeApplyError::StaleRollback {
                    expected: plan.change_set.base_snapshot,
                    actual: current.snapshot().snapshot_id.clone(),
                });
            }
            return Ok(plan.change_set.base_snapshot);
        }
        if phase != JournalPhase::Committed {
            return Err(SafeApplyError::InvalidTransactionState {
                change_set_id: change_set_id.into(),
                state: phase.as_str().into(),
            });
        }
        let plan = read_plan(&transaction)?;
        let current =
            WorkspaceManifest::capture(&self.grant, 1).map_err(SafeApplyError::Workspace)?;
        if current.snapshot().snapshot_id != plan.change_set.result_snapshot {
            return Err(SafeApplyError::StaleResult {
                expected: plan.change_set.result_snapshot,
                actual: current.snapshot().snapshot_id.clone(),
            });
        }
        write_phase(&transaction, JournalPhase::RollingBack)?;
        self.restore_transaction(&transaction, &plan, fault)?;
        write_phase(&transaction, JournalPhase::RolledBack)?;
        Ok(plan.change_set.base_snapshot)
    }

    /// Restores every prepared, applying, or interrupted-rollback transaction.
    /// Committed and already-rolled-back transactions are retained for explicit
    /// one-click rollback and audit evidence.
    ///
    /// # Errors
    ///
    /// Returns an error for an unexpected journal entry, corrupt plan/phase,
    /// conflicting live content, unsafe path, or failed restoration.
    pub fn recover_pending(&self) -> Result<RecoveryReport, SafeApplyError> {
        self.grant
            .validate_integrity()
            .map_err(SafeApplyError::Contract)?;
        let mut entries = fs::read_dir(&self.journal_root)
            .map_err(|error| io_error("read journal root", &self.journal_root, &error))?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| io_error("enumerate journal root", &self.journal_root, &error))?;
        entries.sort_by_key(fs::DirEntry::file_name);
        let mut report = RecoveryReport::default();

        for entry in entries {
            let path = entry.path();
            let metadata = fs::symlink_metadata(&path)
                .map_err(|error| io_error("inspect journal entry", &path, &error))?;
            if !metadata.file_type().is_dir() {
                return Err(SafeApplyError::Journal(format!(
                    "unexpected non-directory journal entry: {}",
                    path.display()
                )));
            }
            let phase_path = path.join("phase");
            if !phase_path.exists() {
                fs::remove_dir_all(&path)
                    .map_err(|error| io_error("remove incomplete preparation", &path, &error))?;
                sync_directory(&self.journal_root)?;
                continue;
            }
            let phase = read_phase(&path)?;
            match phase {
                JournalPhase::Prepared | JournalPhase::Applying | JournalPhase::RollingBack => {
                    let plan = read_plan(&path)?;
                    write_phase(&path, JournalPhase::RollingBack)?;
                    self.restore_transaction(&path, &plan, None)?;
                    write_phase(&path, JournalPhase::RolledBack)?;
                    report
                        .recovered_change_sets
                        .push(plan.change_set.change_set_id);
                }
                JournalPhase::Committed | JournalPhase::RolledBack => {}
            }
        }
        Ok(report)
    }

    /// Reconciles one transaction without executing or replaying its change set.
    ///
    /// Pending application or rollback phases are restored to the base through
    /// the recovery protocol. A committed result is accepted only when the live
    /// manifest still exactly matches the journaled result snapshot; a rolled
    /// back result is accepted only when it still matches the base snapshot.
    ///
    /// # Errors
    ///
    /// Returns an error when the transaction is absent, authority is stale,
    /// journal evidence is invalid, recovery is ambiguous, or live content no
    /// longer matches the uniquely proven terminal outcome.
    pub fn reconcile(&self, change_set_id: &str) -> Result<ApplyReconciliation, SafeApplyError> {
        self.grant
            .validate_integrity()
            .map_err(SafeApplyError::Contract)?;
        let transaction = self.transaction_path(change_set_id);
        if !transaction.is_dir() {
            return Err(SafeApplyError::TransactionNotFound(change_set_id.into()));
        }

        let initial_phase = read_phase(&transaction)?;
        if matches!(
            initial_phase,
            JournalPhase::Prepared | JournalPhase::Applying | JournalPhase::RollingBack
        ) {
            self.recover_pending()?;
        }

        let phase = read_phase(&transaction)?;
        let plan = read_plan(&transaction)?;
        let current =
            WorkspaceManifest::capture(&self.grant, 1).map_err(SafeApplyError::Workspace)?;
        match phase {
            JournalPhase::Committed => {
                if current.snapshot().snapshot_id != plan.change_set.result_snapshot {
                    return Err(SafeApplyError::StaleResult {
                        expected: plan.change_set.result_snapshot,
                        actual: current.snapshot().snapshot_id.clone(),
                    });
                }
                Ok(ApplyReconciliation::Committed(ApplyOutcome {
                    change_set_id: plan.change_set.change_set_id,
                    applied_snapshot: current.snapshot().snapshot_id.clone(),
                }))
            }
            JournalPhase::RolledBack => {
                if current.snapshot().snapshot_id != plan.change_set.base_snapshot {
                    return Err(SafeApplyError::StaleRollback {
                        expected: plan.change_set.base_snapshot,
                        actual: current.snapshot().snapshot_id.clone(),
                    });
                }
                Ok(ApplyReconciliation::RolledBack {
                    change_set_id: plan.change_set.change_set_id,
                    base_snapshot: plan.change_set.base_snapshot,
                })
            }
            JournalPhase::Prepared | JournalPhase::Applying | JournalPhase::RollingBack => {
                Err(SafeApplyError::InvalidTransactionState {
                    change_set_id: change_set_id.into(),
                    state: phase.as_str().into(),
                })
            }
        }
    }

    fn apply_internal(
        &self,
        staged: &StagedChangeSet,
        fault: Option<FaultInjection>,
    ) -> Result<ApplyOutcome, SafeApplyError> {
        self.recover_pending()?;
        self.preflight(staged)?;
        let transaction = self.prepare_transaction(staged)?;
        write_phase(&transaction, JournalPhase::Applying)?;
        maybe_inject(fault, 0, FaultPoint::AfterApplyingPhase)?;

        let execution = self.execute_operations(&transaction, staged, fault);
        if let Err(error) = execution {
            if matches!(error, SafeApplyError::InjectedFailure { .. }) {
                return Err(error);
            }
            let plan = read_plan(&transaction)?;
            if let Err(recovery) = self.restore_transaction(&transaction, &plan, None) {
                return Err(SafeApplyError::ApplyAndRecoveryFailed {
                    apply: error.to_string(),
                    recovery: recovery.to_string(),
                });
            }
            write_phase(&transaction, JournalPhase::RolledBack)?;
            return Err(error);
        }

        let current =
            WorkspaceManifest::capture(&self.grant, 1).map_err(SafeApplyError::Workspace)?;
        if current.snapshot().snapshot_id != staged.change_set().result_snapshot {
            let mismatch = SafeApplyError::ResultMismatch {
                expected: staged.change_set().result_snapshot.clone(),
                actual: current.snapshot().snapshot_id.clone(),
            };
            let plan = read_plan(&transaction)?;
            if let Err(recovery) = self.restore_transaction(&transaction, &plan, None) {
                return Err(SafeApplyError::ApplyAndRecoveryFailed {
                    apply: mismatch.to_string(),
                    recovery: recovery.to_string(),
                });
            }
            write_phase(&transaction, JournalPhase::RolledBack)?;
            return Err(mismatch);
        }

        maybe_inject(fault, 0, FaultPoint::BeforeCommit)?;
        write_phase(&transaction, JournalPhase::Committed)?;
        maybe_inject(fault, 0, FaultPoint::AfterCommit)?;
        Ok(ApplyOutcome {
            change_set_id: staged.change_set().change_set_id.clone(),
            applied_snapshot: current.snapshot().snapshot_id.clone(),
        })
    }

    fn prepare_transaction(&self, staged: &StagedChangeSet) -> Result<PathBuf, SafeApplyError> {
        let transaction = self.transaction_path(&staged.change_set().change_set_id);
        if transaction.exists() {
            let phase = read_phase(&transaction)?;
            match phase {
                // Change-set identity is write-once. A rollback requires a new identity
                // before another application attempt.
                JournalPhase::RolledBack => {
                    return Err(SafeApplyError::AlreadyRolledBack(
                        staged.change_set().change_set_id.clone(),
                    ));
                }
                JournalPhase::Committed => {
                    return Err(SafeApplyError::AlreadyCommitted(
                        staged.change_set().change_set_id.clone(),
                    ));
                }
                JournalPhase::Prepared | JournalPhase::Applying | JournalPhase::RollingBack => {
                    return Err(SafeApplyError::InvalidTransactionState {
                        change_set_id: staged.change_set().change_set_id.clone(),
                        state: phase.as_str().into(),
                    });
                }
            }
        }
        fs::create_dir(&transaction)
            .map_err(|error| io_error("create transaction directory", &transaction, &error))?;
        set_directory_mode(&transaction, 0o700)?;
        // Persist the transaction directory entry before any live mutation can
        // occur. Fsyncing the child directory alone does not durably commit its
        // name in the journal root on all supported filesystems.
        sync_directory(&self.journal_root)?;

        let preparation = self.build_plan_and_backups(&transaction, staged);
        let plan = match preparation {
            Ok(plan) => plan,
            Err(error) => {
                let _ = fs::remove_dir_all(&transaction);
                let _ = sync_directory(&self.journal_root);
                return Err(error);
            }
        };
        write_plan(&transaction, &plan)?;
        write_phase(&transaction, JournalPhase::Prepared)?;
        Ok(transaction)
    }

    fn build_plan_and_backups(
        &self,
        transaction: &Path,
        staged: &StagedChangeSet,
    ) -> Result<JournalPlan, SafeApplyError> {
        let mut operations = Vec::with_capacity(staged.change_set().operations.len());
        for (index, operation) in staged.change_set().operations.iter().enumerate() {
            let validated = self
                .root
                .validate_mutation_target(operation.path())
                .map_err(SafeApplyError::PathValidation)?;
            match operation {
                FileOperation::Create { .. } => match fs::symlink_metadata(validated.absolute()) {
                    Err(error) if error.kind() == io::ErrorKind::NotFound => {
                        operations.push(JournalOperation {
                            operation: operation.clone(),
                            original_mode: None,
                        });
                    }
                    Ok(_) => {
                        return Err(SafeApplyError::StalePath(operation.path().to_path_buf()));
                    }
                    Err(error) => {
                        return Err(io_error(
                            "inspect create target",
                            validated.absolute(),
                            &error,
                        ));
                    }
                },
                FileOperation::Modify { base_hash, .. }
                | FileOperation::Delete { base_hash, .. } => {
                    let (bytes, metadata) = read_stable_file(validated.absolute())
                        .map_err(SafeApplyError::Workspace)?;
                    let actual = hash_bytes(&bytes).map_err(SafeApplyError::Workspace)?;
                    if actual != *base_hash {
                        return Err(SafeApplyError::StaleFile {
                            path: operation.path().to_path_buf(),
                            expected: base_hash.clone(),
                            actual,
                        });
                    }
                    let backup = backup_path(transaction, index);
                    write_new_file(&backup, &bytes, 0o600)?;
                    operations.push(JournalOperation {
                        operation: operation.clone(),
                        original_mode: Some(file_mode(&metadata)),
                    });
                }
            }
        }
        Ok(JournalPlan {
            change_set: staged.change_set().clone(),
            operations,
        })
    }

    fn execute_operations(
        &self,
        transaction: &Path,
        staged: &StagedChangeSet,
        fault: Option<FaultInjection>,
    ) -> Result<(), SafeApplyError> {
        let plan = read_plan(transaction)?;
        for (index, journal_operation) in plan.operations.iter().enumerate() {
            let operation = &journal_operation.operation;
            match operation {
                FileOperation::Create { path, result_hash } => {
                    let bytes = staged
                        .blob(result_hash)
                        .ok_or_else(|| SafeApplyError::MissingBlob(result_hash.clone()))?;
                    self.replace_file(
                        transaction,
                        index,
                        path,
                        bytes,
                        staged.create_mode(path).unwrap_or(0o600),
                        None,
                        ReplacementRole::Apply,
                        fault,
                    )?;
                }
                FileOperation::Modify {
                    path,
                    base_hash,
                    result_hash,
                } => {
                    let bytes = staged
                        .blob(result_hash)
                        .ok_or_else(|| SafeApplyError::MissingBlob(result_hash.clone()))?;
                    self.replace_file(
                        transaction,
                        index,
                        path,
                        bytes,
                        journal_operation.original_mode.unwrap_or(0o600),
                        Some(base_hash),
                        ReplacementRole::Apply,
                        fault,
                    )?;
                }
                FileOperation::Delete { path, base_hash } => {
                    self.delete_file(transaction, index, path, base_hash, fault)?;
                }
            }
            if !matches!(operation, FileOperation::Delete { .. }) {
                write_marker(transaction, index)?;
                maybe_inject(fault, index, FaultPoint::AfterMarker)?;
            }
        }
        Ok(())
    }

    #[allow(
        clippy::too_many_arguments,
        reason = "the explicit transaction, path, digest, mode, role, and fault inputs are security-relevant"
    )]
    fn replace_file(
        &self,
        transaction: &Path,
        index: usize,
        relative: &Path,
        bytes: &[u8],
        mode: u32,
        expected_current: Option<&Digest>,
        role: ReplacementRole,
        fault: Option<FaultInjection>,
    ) -> Result<(), SafeApplyError> {
        let validated = self
            .root
            .validate_mutation_target(relative)
            .map_err(SafeApplyError::PathValidation)?;
        let target = validated.absolute();
        let parent = target
            .parent()
            .ok_or_else(|| SafeApplyError::StalePath(relative.to_path_buf()))?;
        fs::create_dir_all(parent)
            .map_err(|error| io_error("create target parent", parent, &error))?;
        let result_hash = hash_bytes(bytes).map_err(SafeApplyError::Workspace)?;
        let temporary = replacement_temporary_path(transaction, parent, index, role)?;
        let intent_path = replacement_intent_path(transaction, index, role);

        let (mut temporary_file, intent) = if intent_path.exists() {
            let intent = read_replacement_intent(&intent_path)?;
            if intent.result_hash != result_hash
                || intent.mode != mode & 0o777
                || intent.temporary != temporary
            {
                return Err(SafeApplyError::Journal(format!(
                    "{} replacement intent {index} does not match requested bytes",
                    role.as_str()
                )));
            }
            if path_has_identity(target, intent.identity)? {
                if temporary.exists() {
                    return Err(SafeApplyError::RecoveryConflict {
                        path: relative.to_path_buf(),
                        expected_one_of: "one owned replacement inode".into(),
                        actual: Some(result_hash),
                    });
                }
                verify_file_digest(target, &intent.result_hash, relative)?;
                return Ok(());
            }
            if !path_has_identity(&temporary, intent.identity)? {
                return Err(SafeApplyError::UnownedTemporary(temporary));
            }
            validate_expected_target(target, relative, expected_current)?;
            let file = OpenOptions::new()
                .write(true)
                .truncate(true)
                .open(&temporary)
                .map_err(|error| {
                    io_error("reopen owned replacement temporary", &temporary, &error)
                })?;
            (file, intent)
        } else {
            if fs::symlink_metadata(&temporary).is_ok() {
                return Err(SafeApplyError::UnownedTemporary(temporary));
            }
            validate_expected_target(target, relative, expected_current)?;
            let file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&temporary)
                .map_err(|error| io_error("create replacement temporary", &temporary, &error))?;
            set_file_mode(&file, mode)?;
            let metadata = file
                .metadata()
                .map_err(|error| io_error("inspect replacement temporary", &temporary, &error))?;
            let intent = ReplacementIntent {
                identity: file_identity(&metadata),
                result_hash,
                mode: mode & 0o777,
                temporary: temporary.clone(),
            };
            write_replacement_intent(&intent_path, &intent)?;
            (file, intent)
        };

        maybe_inject(fault, index, FaultPoint::BeforeTempWrite)?;
        temporary_file
            .write_all(bytes)
            .map_err(|error| io_error("write replacement temporary", &temporary, &error))?;
        temporary_file
            .sync_all()
            .map_err(|error| io_error("sync replacement temporary", &temporary, &error))?;
        let final_metadata = temporary_file
            .metadata()
            .map_err(|error| io_error("reinspect replacement temporary", &temporary, &error))?;
        if file_identity(&final_metadata) != intent.identity {
            return Err(SafeApplyError::UnownedTemporary(temporary));
        }
        drop(temporary_file);
        verify_file_digest(&temporary, &intent.result_hash, relative)?;
        maybe_inject(fault, index, FaultPoint::AfterTempWrite)?;
        validate_expected_target(target, relative, expected_current)?;
        fs::rename(&temporary, target)
            .map_err(|error| io_error("atomically replace target", target, &error))?;
        maybe_inject(fault, index, FaultPoint::AfterRename)?;
        sync_directory(parent)?;
        maybe_inject(fault, index, FaultPoint::AfterDirectorySync)?;
        Ok(())
    }

    fn delete_file(
        &self,
        transaction: &Path,
        index: usize,
        relative: &Path,
        expected: &Digest,
        fault: Option<FaultInjection>,
    ) -> Result<(), SafeApplyError> {
        let validated = self
            .root
            .validate_mutation_target(relative)
            .map_err(SafeApplyError::PathValidation)?;
        let (bytes, metadata) =
            read_stable_file(validated.absolute()).map_err(SafeApplyError::Workspace)?;
        let actual = hash_bytes(&bytes).map_err(SafeApplyError::Workspace)?;
        if &actual != expected {
            return Err(SafeApplyError::StaleFile {
                path: relative.to_path_buf(),
                expected: expected.clone(),
                actual,
            });
        }
        let parent = validated
            .absolute()
            .parent()
            .ok_or_else(|| SafeApplyError::StalePath(relative.to_path_buf()))?;
        let tombstone = delete_tombstone_path(transaction, parent, index)?;
        if fs::symlink_metadata(&tombstone).is_ok() {
            return Err(SafeApplyError::UnownedTemporary(tombstone));
        }
        let intent = DeleteIntent {
            identity: file_identity(&metadata),
            base_hash: expected.clone(),
            tombstone: tombstone.clone(),
        };
        write_delete_intent(&delete_intent_path(transaction, index), &intent)?;
        maybe_inject(fault, index, FaultPoint::BeforeDelete)?;
        fs::rename(validated.absolute(), &tombstone).map_err(|error| {
            io_error(
                "move delete target to tombstone",
                validated.absolute(),
                &error,
            )
        })?;
        maybe_inject(fault, index, FaultPoint::AfterDelete)?;
        sync_directory(parent)?;
        maybe_inject(fault, index, FaultPoint::AfterDirectorySync)?;
        write_marker(transaction, index)?;
        maybe_inject(fault, index, FaultPoint::AfterMarker)?;
        fs::remove_file(&tombstone)
            .map_err(|error| io_error("remove delete tombstone", &tombstone, &error))?;
        sync_directory(parent)?;
        Ok(())
    }

    fn rollback_created_file(
        &self,
        transaction: &Path,
        index: usize,
        relative: &Path,
        result_hash: &Digest,
        fault: Option<FaultInjection>,
    ) -> Result<(), SafeApplyError> {
        let validated = self
            .root
            .validate_mutation_target(relative)
            .map_err(SafeApplyError::PathValidation)?;
        let target = validated.absolute();
        let parent = target
            .parent()
            .ok_or_else(|| SafeApplyError::StalePath(relative.to_path_buf()))?;
        let tombstone = rollback_delete_tombstone_path(transaction, parent, index)?;
        let intent_path = rollback_delete_intent_path(transaction, index);
        let intent = if intent_path.exists() {
            let intent = read_delete_intent(&intent_path)?;
            if intent.base_hash != *result_hash || intent.tombstone != tombstone {
                return Err(SafeApplyError::Journal(format!(
                    "rollback-delete intent {index} does not match the journal plan"
                )));
            }
            intent
        } else {
            if fs::symlink_metadata(&tombstone).is_ok() {
                return Err(SafeApplyError::UnownedTemporary(tombstone));
            }
            let (bytes, metadata) = read_stable_file(target).map_err(SafeApplyError::Workspace)?;
            let actual = hash_bytes(&bytes).map_err(SafeApplyError::Workspace)?;
            if actual != *result_hash {
                return Err(SafeApplyError::RecoveryConflict {
                    path: relative.to_path_buf(),
                    expected_one_of: format!("applied result {result_hash}"),
                    actual: Some(actual),
                });
            }
            let intent = DeleteIntent {
                identity: file_identity(&metadata),
                base_hash: result_hash.clone(),
                tombstone: tombstone.clone(),
            };
            write_delete_intent(&intent_path, &intent)?;
            intent
        };

        let target_owned = path_has_identity(target, intent.identity)?;
        let tombstone_owned = path_has_identity(&tombstone, intent.identity)?;
        if target_owned && tombstone_owned {
            return Err(SafeApplyError::RecoveryConflict {
                path: relative.to_path_buf(),
                expected_one_of: "one transaction-owned rollback inode".into(),
                actual: Some(result_hash.clone()),
            });
        }
        if target_owned {
            if fs::symlink_metadata(&tombstone).is_ok() {
                return Err(SafeApplyError::UnownedTemporary(tombstone));
            }
            maybe_inject(fault, index, FaultPoint::BeforeDelete)?;
            fs::rename(target, &tombstone).map_err(|error| {
                io_error("move created file to rollback tombstone", target, &error)
            })?;
            maybe_inject(fault, index, FaultPoint::AfterDelete)?;
            sync_directory(parent)?;
            maybe_inject(fault, index, FaultPoint::AfterDirectorySync)?;
        } else if !tombstone_owned {
            if has_valid_rollback_marker(transaction, index)?
                && !target.exists()
                && !tombstone.exists()
            {
                return Ok(());
            }
            return Err(SafeApplyError::RecoveryConflict {
                path: relative.to_path_buf(),
                expected_one_of: "owned rollback target/tombstone or durable rollback marker"
                    .into(),
                actual: current_digest(target)?,
            });
        }

        if !has_valid_rollback_marker(transaction, index)? {
            write_rollback_marker(transaction, index)?;
        }
        maybe_inject(fault, index, FaultPoint::AfterMarker)?;
        if path_has_identity(&tombstone, intent.identity)? {
            fs::remove_file(&tombstone)
                .map_err(|error| io_error("remove rollback tombstone", &tombstone, &error))?;
            sync_directory(parent)?;
        } else if tombstone.exists() {
            return Err(SafeApplyError::UnownedTemporary(tombstone));
        }
        Ok(())
    }

    #[allow(
        clippy::too_many_lines,
        reason = "keeping the three operation-specific recovery state machines together makes their fail-closed symmetry auditable"
    )]
    fn restore_transaction(
        &self,
        transaction: &Path,
        plan: &JournalPlan,
        fault: Option<FaultInjection>,
    ) -> Result<(), SafeApplyError> {
        for (index, journal_operation) in plan.operations.iter().enumerate().rev() {
            match &journal_operation.operation {
                FileOperation::Create { path, result_hash } => {
                    let validated = self
                        .root
                        .validate_mutation_target(path)
                        .map_err(SafeApplyError::PathValidation)?;
                    if rollback_delete_intent_path(transaction, index).exists() {
                        self.rollback_created_file(transaction, index, path, result_hash, fault)?;
                        continue;
                    }
                    let evidence = reconcile_replacement_for_recovery(
                        transaction,
                        index,
                        validated.absolute(),
                        path,
                        result_hash,
                    )?;
                    match evidence {
                        OperationEvidence::Applied => {
                            self.rollback_created_file(
                                transaction,
                                index,
                                path,
                                result_hash,
                                fault,
                            )?;
                        }
                        OperationEvidence::NoIntent | OperationEvidence::NotApplied => {
                            if let Some(actual) = current_digest(validated.absolute())? {
                                return Err(SafeApplyError::RecoveryConflict {
                                    path: path.clone(),
                                    expected_one_of: "absent without owned apply evidence".into(),
                                    actual: Some(actual),
                                });
                            }
                        }
                    }
                }
                FileOperation::Modify {
                    path,
                    base_hash,
                    result_hash,
                } => {
                    let validated = self
                        .root
                        .validate_mutation_target(path)
                        .map_err(SafeApplyError::PathValidation)?;
                    if replacement_intent_path(transaction, index, ReplacementRole::Rollback)
                        .exists()
                    {
                        let backup = read_backup(transaction, index, base_hash)?;
                        self.replace_file(
                            transaction,
                            index,
                            path,
                            &backup,
                            journal_operation.original_mode.unwrap_or(0o600),
                            Some(result_hash),
                            ReplacementRole::Rollback,
                            fault,
                        )?;
                        continue;
                    }
                    let evidence = reconcile_replacement_for_recovery(
                        transaction,
                        index,
                        validated.absolute(),
                        path,
                        result_hash,
                    )?;
                    match evidence {
                        OperationEvidence::Applied => {
                            let backup = read_backup(transaction, index, base_hash)?;
                            self.replace_file(
                                transaction,
                                index,
                                path,
                                &backup,
                                journal_operation.original_mode.unwrap_or(0o600),
                                Some(result_hash),
                                ReplacementRole::Rollback,
                                fault,
                            )?;
                        }
                        OperationEvidence::NoIntent | OperationEvidence::NotApplied => {
                            let actual = current_digest(validated.absolute())?;
                            if actual.as_ref() != Some(base_hash) {
                                return Err(SafeApplyError::RecoveryConflict {
                                    path: path.clone(),
                                    expected_one_of: format!(
                                        "base {base_hash} without owned apply evidence"
                                    ),
                                    actual,
                                });
                            }
                        }
                    }
                }
                FileOperation::Delete { path, base_hash } => {
                    let validated = self
                        .root
                        .validate_mutation_target(path)
                        .map_err(SafeApplyError::PathValidation)?;
                    if replacement_intent_path(transaction, index, ReplacementRole::Rollback)
                        .exists()
                    {
                        let backup = read_backup(transaction, index, base_hash)?;
                        self.replace_file(
                            transaction,
                            index,
                            path,
                            &backup,
                            journal_operation.original_mode.unwrap_or(0o600),
                            None,
                            ReplacementRole::Rollback,
                            fault,
                        )?;
                        continue;
                    }
                    match delete_evidence_for_recovery(
                        transaction,
                        index,
                        validated.absolute(),
                        path,
                        base_hash,
                    )? {
                        OperationEvidence::Applied => {
                            let backup = read_backup(transaction, index, base_hash)?;
                            self.replace_file(
                                transaction,
                                index,
                                path,
                                &backup,
                                journal_operation.original_mode.unwrap_or(0o600),
                                None,
                                ReplacementRole::Rollback,
                                fault,
                            )?;
                        }
                        OperationEvidence::NoIntent | OperationEvidence::NotApplied => {}
                    }
                }
            }
        }
        let current =
            WorkspaceManifest::capture(&self.grant, 1).map_err(SafeApplyError::Workspace)?;
        if current.snapshot().snapshot_id != plan.change_set.base_snapshot {
            return Err(SafeApplyError::RecoverySnapshotMismatch {
                expected: plan.change_set.base_snapshot.clone(),
                actual: current.snapshot().snapshot_id.clone(),
            });
        }
        Ok(())
    }

    fn transaction_path(&self, change_set_id: &str) -> PathBuf {
        let mut hasher = Sha256::new();
        hasher.update(b"grok-build.transaction-directory.sha256.v1\0");
        hasher.update(change_set_id.as_bytes());
        let digest = hasher.finalize();
        self.journal_root
            .join(format!("transaction-{}", encode_hex(digest.as_ref())))
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ReplacementRole {
    Apply,
    Rollback,
}

impl ReplacementRole {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Apply => "apply",
            Self::Rollback => "rollback",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum FaultPoint {
    AfterApplyingPhase,
    BeforeTempWrite,
    AfterTempWrite,
    AfterRename,
    BeforeDelete,
    AfterDelete,
    AfterDirectorySync,
    AfterMarker,
    BeforeCommit,
    AfterCommit,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct FaultInjection {
    operation_index: usize,
    point: FaultPoint,
}

fn maybe_inject(
    fault: Option<FaultInjection>,
    operation_index: usize,
    point: FaultPoint,
) -> Result<(), SafeApplyError> {
    if fault
        == Some(FaultInjection {
            operation_index,
            point,
        })
    {
        return Err(SafeApplyError::InjectedFailure {
            applied_operations: operation_index + 1,
        });
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct FileIdentity {
    device: u64,
    inode: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ReplacementIntent {
    identity: FileIdentity,
    result_hash: Digest,
    mode: u32,
    temporary: PathBuf,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct DeleteIntent {
    identity: FileIdentity,
    base_hash: Digest,
    tombstone: PathBuf,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum OperationEvidence {
    NoIntent,
    NotApplied,
    Applied,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum JournalPhase {
    Prepared,
    Applying,
    Committed,
    RollingBack,
    RolledBack,
}

impl JournalPhase {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Prepared => "prepared",
            Self::Applying => "applying",
            Self::Committed => "committed",
            Self::RollingBack => "rolling-back",
            Self::RolledBack => "rolled-back",
        }
    }

    fn parse(value: &str) -> Result<Self, SafeApplyError> {
        match value.trim() {
            "prepared" => Ok(Self::Prepared),
            "applying" => Ok(Self::Applying),
            "committed" => Ok(Self::Committed),
            "rolling-back" => Ok(Self::RollingBack),
            "rolled-back" => Ok(Self::RolledBack),
            other => Err(SafeApplyError::Journal(format!(
                "unknown transaction phase `{other}`"
            ))),
        }
    }
}

#[derive(Clone, Debug)]
struct JournalOperation {
    operation: FileOperation,
    original_mode: Option<u32>,
}

#[derive(Clone, Debug)]
struct JournalPlan {
    change_set: ChangeSet,
    operations: Vec<JournalOperation>,
}

/// A fail-closed application, recovery, or journal error.
#[derive(Debug)]
pub enum SafeApplyError {
    /// A core contract failed validation.
    Contract(ContractError),
    /// Workspace snapshot/diff processing failed.
    Workspace(WorkspacePipelineError),
    /// Runner path validation failed.
    PathValidation(PathValidationError),
    /// The grant does not authorize verified application.
    PermissionDenied,
    /// A verified no-op has no live filesystem mutation to apply.
    EmptyChangeSet,
    /// The complete live manifest no longer matches the staged base.
    StaleBase {
        /// Staged base snapshot.
        expected: Digest,
        /// Current live snapshot.
        actual: Digest,
    },
    /// One base file no longer has its expected content.
    StaleFile {
        /// Stale relative path.
        path: PathBuf,
        /// Expected content digest.
        expected: Digest,
        /// Actual content digest.
        actual: Digest,
    },
    /// A create target appeared or otherwise changed before application.
    StalePath(PathBuf),
    /// A transaction-shaped temporary exists without matching inode evidence.
    UnownedTemporary(PathBuf),
    /// The applied regular-file manifest differs from the staged result.
    ResultMismatch {
        /// Expected result snapshot.
        expected: Digest,
        /// Actual result snapshot.
        actual: Digest,
    },
    /// Explicit rollback would overwrite changes made after application.
    StaleResult {
        /// Committed result snapshot.
        expected: Digest,
        /// Current live snapshot.
        actual: Digest,
    },
    /// A previously completed rollback no longer matches its base snapshot.
    StaleRollback {
        /// Snapshot the rollback originally restored.
        expected: Digest,
        /// Current live snapshot.
        actual: Digest,
    },
    /// Recovery found content that is neither the journaled base nor result.
    RecoveryConflict {
        /// Conflicting relative path.
        path: PathBuf,
        /// Safe states recovery expected.
        expected_one_of: String,
        /// Actual digest, or absence when absence is unsafe.
        actual: Option<Digest>,
    },
    /// Recovery completed its operations but the full base manifest did not match.
    RecoverySnapshotMismatch {
        /// Journaled base snapshot.
        expected: Digest,
        /// Actual live snapshot.
        actual: Digest,
    },
    /// A staged result blob is missing.
    MissingBlob(Digest),
    /// A transaction with this identifier is already committed.
    AlreadyCommitted(String),
    /// A transaction with this identifier already reached durable rollback.
    AlreadyRolledBack(String),
    /// No transaction exists for explicit rollback.
    TransactionNotFound(String),
    /// A transaction is not in the state required by the requested action.
    InvalidTransactionState {
        /// Transaction identifier.
        change_set_id: String,
        /// Actual journal state.
        state: String,
    },
    /// A deterministic test-only interruption was injected after durable mutation.
    InjectedFailure {
        /// Number of completed operations.
        applied_operations: usize,
    },
    /// Both application and its immediate recovery attempt failed.
    ApplyAndRecoveryFailed {
        /// Original application failure.
        apply: String,
        /// Recovery failure.
        recovery: String,
    },
    /// Journal structure or encoding is invalid.
    Journal(String),
    /// A filesystem operation failed.
    Io {
        /// Operation being performed.
        operation: &'static str,
        /// Path involved.
        path: PathBuf,
        /// Operating-system error text.
        message: String,
    },
}

impl Display for SafeApplyError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Contract(error) => write!(formatter, "contract validation failed: {error}"),
            Self::Workspace(error) => write!(formatter, "workspace processing failed: {error}"),
            Self::PathValidation(error) => write!(formatter, "path validation failed: {error}"),
            Self::PermissionDenied => {
                formatter.write_str("workspace grant does not authorize verified application")
            }
            Self::EmptyChangeSet => {
                formatter.write_str("verified no-op change set cannot enter live application")
            }
            Self::StaleBase { expected, actual } => {
                write!(formatter, "stale base: expected {expected}, found {actual}")
            }
            Self::StaleFile {
                path,
                expected,
                actual,
            } => write!(
                formatter,
                "stale file {}: expected {expected}, found {actual}",
                path.display()
            ),
            Self::StalePath(path) => {
                write!(formatter, "target path changed: {}", path.display())
            }
            Self::UnownedTemporary(path) => write!(
                formatter,
                "temporary file lacks matching transaction ownership evidence: {}",
                path.display()
            ),
            Self::ResultMismatch { expected, actual } => write!(
                formatter,
                "applied snapshot mismatch: expected {expected}, found {actual}"
            ),
            Self::StaleResult { expected, actual } => write!(
                formatter,
                "rollback refused: expected live result {expected}, found {actual}"
            ),
            Self::StaleRollback { expected, actual } => write!(
                formatter,
                "rollback is no longer current: expected restored base {expected}, found {actual}"
            ),
            Self::RecoveryConflict {
                path,
                expected_one_of,
                actual,
            } => write!(
                formatter,
                "recovery conflict at {}: expected {expected_one_of}, found {}",
                path.display(),
                actual.as_ref().map_or("absent", Digest::as_str)
            ),
            Self::RecoverySnapshotMismatch { expected, actual } => write!(
                formatter,
                "recovered snapshot mismatch: expected {expected}, found {actual}"
            ),
            Self::MissingBlob(digest) => write!(formatter, "missing staged blob {digest}"),
            Self::AlreadyCommitted(id) => write!(formatter, "transaction `{id}` is committed"),
            Self::AlreadyRolledBack(id) => {
                write!(formatter, "transaction `{id}` is already rolled back")
            }
            Self::TransactionNotFound(id) => write!(formatter, "transaction `{id}` not found"),
            Self::InvalidTransactionState {
                change_set_id,
                state,
            } => write!(
                formatter,
                "transaction `{change_set_id}` has invalid state `{state}`"
            ),
            Self::InjectedFailure { applied_operations } => write!(
                formatter,
                "injected interruption after {applied_operations} operations"
            ),
            Self::ApplyAndRecoveryFailed { apply, recovery } => write!(
                formatter,
                "application failed ({apply}) and recovery failed ({recovery})"
            ),
            Self::Journal(message) => write!(formatter, "invalid transaction journal: {message}"),
            Self::Io {
                operation,
                path,
                message,
            } => write!(
                formatter,
                "{operation} failed for {}: {message}",
                path.display()
            ),
        }
    }
}

impl std::error::Error for SafeApplyError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Contract(error) => Some(error),
            Self::Workspace(error) => Some(error),
            Self::PathValidation(error) => Some(error),
            _ => None,
        }
    }
}

fn validate_staged(staged: &StagedChangeSet) -> Result<(), SafeApplyError> {
    staged
        .change_set()
        .validate()
        .map_err(SafeApplyError::Contract)?;
    if staged.change_set().operations.is_empty() {
        return Err(SafeApplyError::EmptyChangeSet);
    }
    for operation in &staged.change_set().operations {
        if let FileOperation::Create { result_hash, .. }
        | FileOperation::Modify { result_hash, .. } = operation
        {
            let bytes = staged
                .blob(result_hash)
                .ok_or_else(|| SafeApplyError::MissingBlob(result_hash.clone()))?;
            let actual = hash_bytes(bytes).map_err(SafeApplyError::Workspace)?;
            if actual != *result_hash {
                return Err(SafeApplyError::Journal(format!(
                    "staged blob {result_hash} failed digest verification"
                )));
            }
        }
    }
    Ok(())
}

fn validate_expected_target(
    target: &Path,
    relative: &Path,
    expected_current: Option<&Digest>,
) -> Result<(), SafeApplyError> {
    match expected_current {
        Some(expected) => {
            let (current, _) = read_stable_file(target).map_err(SafeApplyError::Workspace)?;
            let actual = hash_bytes(&current).map_err(SafeApplyError::Workspace)?;
            if &actual != expected {
                return Err(SafeApplyError::StaleFile {
                    path: relative.to_path_buf(),
                    expected: expected.clone(),
                    actual,
                });
            }
        }
        None => match fs::symlink_metadata(target) {
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Ok(_) => return Err(SafeApplyError::StalePath(relative.to_path_buf())),
            Err(error) => return Err(io_error("inspect create target", target, &error)),
        },
    }
    Ok(())
}

fn verify_file_digest(
    absolute: &Path,
    expected: &Digest,
    relative: &Path,
) -> Result<(), SafeApplyError> {
    let (bytes, _) = read_stable_file(absolute).map_err(SafeApplyError::Workspace)?;
    let actual = hash_bytes(&bytes).map_err(SafeApplyError::Workspace)?;
    if &actual != expected {
        return Err(SafeApplyError::StaleFile {
            path: relative.to_path_buf(),
            expected: expected.clone(),
            actual,
        });
    }
    Ok(())
}

fn replacement_temporary_path(
    transaction: &Path,
    parent: &Path,
    index: usize,
    role: ReplacementRole,
) -> Result<PathBuf, SafeApplyError> {
    let transaction_name = transaction
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| SafeApplyError::Journal("invalid transaction directory name".into()))?;
    Ok(parent.join(format!(
        ".grok-build-{transaction_name}-{}-{index:06}.tmp",
        role.as_str()
    )))
}

fn replacement_intent_path(transaction: &Path, index: usize, role: ReplacementRole) -> PathBuf {
    transaction.join(format!("{}-intent-{index:06}", role.as_str()))
}

fn delete_intent_path(transaction: &Path, index: usize) -> PathBuf {
    transaction.join(format!("delete-intent-{index:06}"))
}

fn delete_tombstone_path(
    transaction: &Path,
    parent: &Path,
    index: usize,
) -> Result<PathBuf, SafeApplyError> {
    let transaction_name = transaction
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| SafeApplyError::Journal("invalid transaction directory name".into()))?;
    Ok(parent.join(format!(
        ".grok-build-{transaction_name}-delete-{index:06}.tombstone"
    )))
}

fn rollback_delete_intent_path(transaction: &Path, index: usize) -> PathBuf {
    transaction.join(format!("rollback-delete-intent-{index:06}"))
}

fn rollback_delete_tombstone_path(
    transaction: &Path,
    parent: &Path,
    index: usize,
) -> Result<PathBuf, SafeApplyError> {
    let transaction_name = transaction
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| SafeApplyError::Journal("invalid transaction directory name".into()))?;
    Ok(parent.join(format!(
        ".grok-build-{transaction_name}-rollback-delete-{index:06}.tombstone"
    )))
}

fn write_replacement_intent(path: &Path, intent: &ReplacementIntent) -> Result<(), SafeApplyError> {
    let temporary = intent
        .temporary
        .to_str()
        .ok_or_else(|| SafeApplyError::Journal("replacement temporary is not UTF-8".into()))?;
    let encoded = format!(
        "replacement-v1\t{}\t{}\t{}\t{:o}\t{}\n",
        intent.identity.device,
        intent.identity.inode,
        intent.result_hash,
        intent.mode,
        encode_hex(temporary.as_bytes())
    );
    let directory = path
        .parent()
        .ok_or_else(|| SafeApplyError::Journal("replacement intent has no parent".into()))?;
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| SafeApplyError::Journal("invalid replacement intent name".into()))?;
    write_atomic_journal_file(directory, name, encoded.as_bytes())
}

fn read_replacement_intent(path: &Path) -> Result<ReplacementIntent, SafeApplyError> {
    let bytes = read_journal_file(path)?;
    let text = std::str::from_utf8(&bytes)
        .map_err(|_| SafeApplyError::Journal("replacement intent is not UTF-8".into()))?;
    let fields = text.trim_end().split('\t').collect::<Vec<_>>();
    if fields.len() != 6 || fields[0] != "replacement-v1" {
        return Err(SafeApplyError::Journal(
            "invalid replacement intent encoding".into(),
        ));
    }
    let device = fields[1]
        .parse()
        .map_err(|_| SafeApplyError::Journal("invalid replacement device".into()))?;
    let inode = fields[2]
        .parse()
        .map_err(|_| SafeApplyError::Journal("invalid replacement inode".into()))?;
    let result_hash = parse_digest(fields[3])?;
    let mode = u32::from_str_radix(fields[4], 8)
        .map_err(|_| SafeApplyError::Journal("invalid replacement mode".into()))?;
    let temporary = String::from_utf8(decode_hex(fields[5])?)
        .map_err(|_| SafeApplyError::Journal("replacement temporary is not UTF-8".into()))?;
    Ok(ReplacementIntent {
        identity: FileIdentity { device, inode },
        result_hash,
        mode,
        temporary: PathBuf::from(temporary),
    })
}

fn write_delete_intent(path: &Path, intent: &DeleteIntent) -> Result<(), SafeApplyError> {
    let tombstone = intent
        .tombstone
        .to_str()
        .ok_or_else(|| SafeApplyError::Journal("delete tombstone is not UTF-8".into()))?;
    let encoded = format!(
        "delete-v1\t{}\t{}\t{}\t{}\n",
        intent.identity.device,
        intent.identity.inode,
        intent.base_hash,
        encode_hex(tombstone.as_bytes())
    );
    let directory = path
        .parent()
        .ok_or_else(|| SafeApplyError::Journal("delete intent has no parent".into()))?;
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| SafeApplyError::Journal("invalid delete intent name".into()))?;
    write_atomic_journal_file(directory, name, encoded.as_bytes())
}

fn read_delete_intent(path: &Path) -> Result<DeleteIntent, SafeApplyError> {
    let bytes = read_journal_file(path)?;
    let text = std::str::from_utf8(&bytes)
        .map_err(|_| SafeApplyError::Journal("delete intent is not UTF-8".into()))?;
    let fields = text.trim_end().split('\t').collect::<Vec<_>>();
    if fields.len() != 5 || fields[0] != "delete-v1" {
        return Err(SafeApplyError::Journal(
            "invalid delete intent encoding".into(),
        ));
    }
    let device = fields[1]
        .parse()
        .map_err(|_| SafeApplyError::Journal("invalid delete device".into()))?;
    let inode = fields[2]
        .parse()
        .map_err(|_| SafeApplyError::Journal("invalid delete inode".into()))?;
    Ok(DeleteIntent {
        identity: FileIdentity { device, inode },
        base_hash: parse_digest(fields[3])?,
        tombstone: PathBuf::from(
            String::from_utf8(decode_hex(fields[4])?)
                .map_err(|_| SafeApplyError::Journal("delete tombstone is not UTF-8".into()))?,
        ),
    })
}

#[cfg(unix)]
fn file_identity(metadata: &fs::Metadata) -> FileIdentity {
    use std::os::unix::fs::MetadataExt;
    FileIdentity {
        device: metadata.dev(),
        inode: metadata.ino(),
    }
}

#[cfg(not(unix))]
fn file_identity(metadata: &fs::Metadata) -> FileIdentity {
    FileIdentity {
        device: 0,
        inode: metadata.len(),
    }
}

fn path_has_identity(path: &Path, expected: FileIdentity) -> Result<bool, SafeApplyError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_file() => Ok(file_identity(&metadata) == expected),
        Ok(_) => Ok(false),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(io_error("inspect file identity", path, &error)),
    }
}

fn reconcile_replacement_for_recovery(
    transaction: &Path,
    index: usize,
    target: &Path,
    relative: &Path,
    result_hash: &Digest,
) -> Result<OperationEvidence, SafeApplyError> {
    let parent = target
        .parent()
        .ok_or_else(|| SafeApplyError::StalePath(relative.to_path_buf()))?;
    let temporary = replacement_temporary_path(transaction, parent, index, ReplacementRole::Apply)?;
    let intent_path = replacement_intent_path(transaction, index, ReplacementRole::Apply);
    if !intent_path.exists() {
        if fs::symlink_metadata(&temporary).is_ok() {
            return Err(SafeApplyError::UnownedTemporary(temporary));
        }
        return Ok(OperationEvidence::NoIntent);
    }

    let intent = read_replacement_intent(&intent_path)?;
    if intent.result_hash != *result_hash || intent.temporary != temporary {
        return Err(SafeApplyError::Journal(format!(
            "apply intent {index} does not match the journal plan"
        )));
    }
    let temporary_owned = path_has_identity(&temporary, intent.identity)?;
    let target_owned = path_has_identity(target, intent.identity)?;
    if temporary_owned && target_owned {
        return Err(SafeApplyError::RecoveryConflict {
            path: relative.to_path_buf(),
            expected_one_of: "exactly one transaction-owned inode".into(),
            actual: Some(result_hash.clone()),
        });
    }
    if temporary_owned {
        fs::remove_file(&temporary)
            .map_err(|error| io_error("remove owned interrupted temporary", &temporary, &error))?;
        sync_directory(parent)?;
        return Ok(OperationEvidence::NotApplied);
    }
    if target_owned {
        verify_file_digest(target, result_hash, relative)?;
        return Ok(OperationEvidence::Applied);
    }
    if temporary.exists() {
        return Err(SafeApplyError::UnownedTemporary(temporary));
    }
    Err(SafeApplyError::RecoveryConflict {
        path: relative.to_path_buf(),
        expected_one_of: "transaction-owned temporary or target inode".into(),
        actual: current_digest(target)?,
    })
}

fn delete_evidence_for_recovery(
    transaction: &Path,
    index: usize,
    target: &Path,
    relative: &Path,
    base_hash: &Digest,
) -> Result<OperationEvidence, SafeApplyError> {
    let intent_path = delete_intent_path(transaction, index);
    let parent = target
        .parent()
        .ok_or_else(|| SafeApplyError::StalePath(relative.to_path_buf()))?;
    let expected_tombstone = delete_tombstone_path(transaction, parent, index)?;
    if !intent_path.exists() {
        if fs::symlink_metadata(&expected_tombstone).is_ok() {
            return Err(SafeApplyError::UnownedTemporary(expected_tombstone));
        }
        let actual = current_digest(target)?;
        return match actual {
            Some(actual) if actual == *base_hash => Ok(OperationEvidence::NoIntent),
            other => Err(SafeApplyError::RecoveryConflict {
                path: relative.to_path_buf(),
                expected_one_of: format!("existing base {base_hash} without delete intent"),
                actual: other,
            }),
        };
    }
    let intent = read_delete_intent(&intent_path)?;
    if intent.base_hash != *base_hash || intent.tombstone != expected_tombstone {
        return Err(SafeApplyError::Journal(format!(
            "delete intent {index} does not match the journal plan"
        )));
    }
    let marked_applied = has_valid_marker(transaction, index)?;
    let target_owned = path_has_identity(target, intent.identity)?;
    let tombstone_owned = path_has_identity(&intent.tombstone, intent.identity)?;
    if target_owned && tombstone_owned {
        return Err(SafeApplyError::RecoveryConflict {
            path: relative.to_path_buf(),
            expected_one_of: "one original delete-target inode".into(),
            actual: Some(base_hash.clone()),
        });
    }
    if tombstone_owned {
        if fs::symlink_metadata(target).is_ok() {
            return Err(SafeApplyError::RecoveryConflict {
                path: relative.to_path_buf(),
                expected_one_of: "absent target while owned tombstone exists".into(),
                actual: current_digest(target)?,
            });
        }
        verify_file_digest(&intent.tombstone, base_hash, relative)?;
        fs::rename(&intent.tombstone, target)
            .map_err(|error| io_error("restore owned delete tombstone", target, &error))?;
        sync_directory(parent)?;
        write_rollback_marker(transaction, index)?;
        return Ok(OperationEvidence::NotApplied);
    }
    if target_owned {
        if has_valid_rollback_marker(transaction, index)? {
            verify_file_digest(target, base_hash, relative)?;
            return Ok(OperationEvidence::NotApplied);
        }
        if marked_applied {
            return Err(SafeApplyError::RecoveryConflict {
                path: relative.to_path_buf(),
                expected_one_of: "absence or owned tombstone after delete marker".into(),
                actual: Some(base_hash.clone()),
            });
        }
        if fs::symlink_metadata(&intent.tombstone).is_ok() {
            return Err(SafeApplyError::UnownedTemporary(intent.tombstone));
        }
        verify_file_digest(target, base_hash, relative)?;
        return Ok(OperationEvidence::NotApplied);
    }
    if fs::symlink_metadata(&intent.tombstone).is_ok() {
        return Err(SafeApplyError::UnownedTemporary(intent.tombstone));
    }
    if fs::symlink_metadata(target).is_ok() {
        return Err(SafeApplyError::RecoveryConflict {
            path: relative.to_path_buf(),
            expected_one_of: "original target inode or owned tombstone".into(),
            actual: current_digest(target)?,
        });
    }
    if marked_applied {
        Ok(OperationEvidence::Applied)
    } else {
        Err(SafeApplyError::RecoveryConflict {
            path: relative.to_path_buf(),
            expected_one_of: "original inode, owned tombstone, or durable delete marker".into(),
            actual: None,
        })
    }
}

fn has_valid_marker(transaction: &Path, index: usize) -> Result<bool, SafeApplyError> {
    let path = transaction.join(format!("applied-{index:06}"));
    match fs::symlink_metadata(&path) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        Ok(_) => Ok(read_journal_file(&path)? == b"applied\n"),
        Err(error) => Err(io_error("inspect operation marker", &path, &error)),
    }
}

fn has_valid_rollback_marker(transaction: &Path, index: usize) -> Result<bool, SafeApplyError> {
    let path = transaction.join(format!("rollback-applied-{index:06}"));
    match fs::symlink_metadata(&path) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        Ok(_) => Ok(read_journal_file(&path)? == b"rollback-applied\n"),
        Err(error) => Err(io_error("inspect rollback marker", &path, &error)),
    }
}

fn current_digest(path: &Path) -> Result<Option<Digest>, SafeApplyError> {
    match fs::symlink_metadata(path) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Ok(metadata) if metadata.file_type().is_file() => {
            let (bytes, _) = read_stable_file(path).map_err(SafeApplyError::Workspace)?;
            hash_bytes(&bytes)
                .map(Some)
                .map_err(SafeApplyError::Workspace)
        }
        Ok(_) => Ok(None),
        Err(error) => Err(io_error("inspect recovery target", path, &error)),
    }
}

fn write_plan(transaction: &Path, plan: &JournalPlan) -> Result<(), SafeApplyError> {
    let mut encoded = String::new();
    encoded.push_str(JOURNAL_VERSION);
    encoded.push('\n');
    encoded.push_str("id\t");
    encoded.push_str(&encode_hex(plan.change_set.change_set_id.as_bytes()));
    encoded.push('\n');
    encoded.push_str("base\t");
    encoded.push_str(plan.change_set.base_snapshot.as_str());
    encoded.push('\n');
    encoded.push_str("result\t");
    encoded.push_str(plan.change_set.result_snapshot.as_str());
    encoded.push('\n');
    for journal_operation in &plan.operations {
        let (kind, base, result) = match &journal_operation.operation {
            FileOperation::Create { result_hash, .. } => ("C", "-", result_hash.as_str()),
            FileOperation::Modify {
                base_hash,
                result_hash,
                ..
            } => ("M", base_hash.as_str(), result_hash.as_str()),
            FileOperation::Delete { base_hash, .. } => ("D", base_hash.as_str(), "-"),
        };
        let path = journal_operation
            .operation
            .path()
            .to_str()
            .ok_or_else(|| SafeApplyError::Journal("non-UTF-8 operation path".into()))?;
        let mode = journal_operation
            .original_mode
            .map_or_else(|| "-".into(), |value| format!("{value:o}"));
        encoded.push_str(kind);
        encoded.push('\t');
        encoded.push_str(&encode_hex(path.as_bytes()));
        encoded.push('\t');
        encoded.push_str(base);
        encoded.push('\t');
        encoded.push_str(result);
        encoded.push('\t');
        encoded.push_str(&mode);
        encoded.push('\n');
    }
    write_atomic_journal_file(transaction, "plan", encoded.as_bytes())
}

fn read_plan(transaction: &Path) -> Result<JournalPlan, SafeApplyError> {
    let path = transaction.join("plan");
    let bytes = read_journal_file(&path)?;
    let text = std::str::from_utf8(&bytes)
        .map_err(|_| SafeApplyError::Journal("plan is not UTF-8".into()))?;
    let mut lines = text.lines();
    if lines.next() != Some(JOURNAL_VERSION) {
        return Err(SafeApplyError::Journal(
            "unsupported or missing plan version".into(),
        ));
    }
    let change_set_id = parse_named_hex_line(lines.next(), "id")?;
    let change_set_id = String::from_utf8(change_set_id)
        .map_err(|_| SafeApplyError::Journal("change-set id is not UTF-8".into()))?;
    let base_snapshot = parse_named_digest_line(lines.next(), "base")?;
    let result_snapshot = parse_named_digest_line(lines.next(), "result")?;

    let mut operations = Vec::new();
    for line in lines {
        let fields = line.split('\t').collect::<Vec<_>>();
        if fields.len() != 5 {
            return Err(SafeApplyError::Journal(
                "operation line must have five fields".into(),
            ));
        }
        let path_bytes = decode_hex(fields[1])?;
        let path = PathBuf::from(
            String::from_utf8(path_bytes)
                .map_err(|_| SafeApplyError::Journal("operation path is not UTF-8".into()))?,
        );
        let original_mode = if fields[4] == "-" {
            None
        } else {
            Some(
                u32::from_str_radix(fields[4], 8)
                    .map_err(|_| SafeApplyError::Journal("invalid file mode".into()))?,
            )
        };
        let operation = match fields[0] {
            "C" if fields[2] == "-" => FileOperation::Create {
                path,
                result_hash: parse_digest(fields[3])?,
            },
            "M" => FileOperation::Modify {
                path,
                base_hash: parse_digest(fields[2])?,
                result_hash: parse_digest(fields[3])?,
            },
            "D" if fields[3] == "-" => FileOperation::Delete {
                path,
                base_hash: parse_digest(fields[2])?,
            },
            _ => return Err(SafeApplyError::Journal("invalid operation encoding".into())),
        };
        operations.push(JournalOperation {
            operation,
            original_mode,
        });
    }
    let change_set = ChangeSet {
        change_set_id,
        base_snapshot,
        result_snapshot,
        operations: operations
            .iter()
            .map(|operation| operation.operation.clone())
            .collect(),
    };
    change_set.validate().map_err(SafeApplyError::Contract)?;
    Ok(JournalPlan {
        change_set,
        operations,
    })
}

fn parse_named_hex_line(line: Option<&str>, name: &str) -> Result<Vec<u8>, SafeApplyError> {
    let fields = line
        .ok_or_else(|| SafeApplyError::Journal(format!("missing `{name}` line")))?
        .split('\t')
        .collect::<Vec<_>>();
    if fields.len() != 2 || fields[0] != name {
        return Err(SafeApplyError::Journal(format!("invalid `{name}` line")));
    }
    decode_hex(fields[1])
}

fn parse_named_digest_line(line: Option<&str>, name: &str) -> Result<Digest, SafeApplyError> {
    let fields = line
        .ok_or_else(|| SafeApplyError::Journal(format!("missing `{name}` line")))?
        .split('\t')
        .collect::<Vec<_>>();
    if fields.len() != 2 || fields[0] != name {
        return Err(SafeApplyError::Journal(format!("invalid `{name}` line")));
    }
    parse_digest(fields[1])
}

fn parse_digest(value: &str) -> Result<Digest, SafeApplyError> {
    Digest::parse(value).map_err(SafeApplyError::Contract)
}

fn write_phase(transaction: &Path, phase: JournalPhase) -> Result<(), SafeApplyError> {
    write_atomic_journal_file(
        transaction,
        "phase",
        format!("{}\n", phase.as_str()).as_bytes(),
    )
}

fn read_phase(transaction: &Path) -> Result<JournalPhase, SafeApplyError> {
    let bytes = read_journal_file(&transaction.join("phase"))?;
    let text = std::str::from_utf8(&bytes)
        .map_err(|_| SafeApplyError::Journal("phase is not UTF-8".into()))?;
    JournalPhase::parse(text)
}

fn write_marker(transaction: &Path, index: usize) -> Result<(), SafeApplyError> {
    let name = format!("applied-{index:06}");
    write_atomic_journal_file(transaction, &name, b"applied\n")
}

fn write_rollback_marker(transaction: &Path, index: usize) -> Result<(), SafeApplyError> {
    let name = format!("rollback-applied-{index:06}");
    write_atomic_journal_file(transaction, &name, b"rollback-applied\n")
}

fn write_atomic_journal_file(
    directory: &Path,
    name: &str,
    bytes: &[u8],
) -> Result<(), SafeApplyError> {
    let target = directory.join(name);
    let temporary = directory.join(format!(".{name}.next"));
    if let Ok(metadata) = fs::symlink_metadata(&temporary) {
        if !metadata.file_type().is_file() {
            return Err(SafeApplyError::Journal(format!(
                "journal temporary is not a regular file: {}",
                temporary.display()
            )));
        }
        fs::remove_file(&temporary)
            .map_err(|error| io_error("remove stale journal temporary", &temporary, &error))?;
    }
    write_new_file(&temporary, bytes, 0o600)?;
    fs::rename(&temporary, &target)
        .map_err(|error| io_error("commit journal file", &target, &error))?;
    sync_directory(directory)
}

fn read_journal_file(path: &Path) -> Result<Vec<u8>, SafeApplyError> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| io_error("inspect journal file", path, &error))?;
    if !metadata.file_type().is_file() {
        return Err(SafeApplyError::Journal(format!(
            "journal path is not a regular file: {}",
            path.display()
        )));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if metadata.nlink() != 1 {
            return Err(SafeApplyError::Journal(format!(
                "journal file is hard-linked: {}",
                path.display()
            )));
        }
    }
    let mut file = File::open(path).map_err(|error| io_error("open journal file", path, &error))?;
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)
        .map_err(|error| io_error("read journal file", path, &error))?;
    Ok(bytes)
}

fn backup_path(transaction: &Path, index: usize) -> PathBuf {
    transaction.join(format!("backup-{index:06}"))
}

fn read_backup(
    transaction: &Path,
    index: usize,
    expected: &Digest,
) -> Result<Vec<u8>, SafeApplyError> {
    let path = backup_path(transaction, index);
    let bytes = read_journal_file(&path)?;
    let actual = hash_bytes(&bytes).map_err(SafeApplyError::Workspace)?;
    if actual != *expected {
        return Err(SafeApplyError::Journal(format!(
            "backup {index} digest mismatch: expected {expected}, found {actual}"
        )));
    }
    Ok(bytes)
}

fn write_new_file(path: &Path, bytes: &[u8], mode: u32) -> Result<(), SafeApplyError> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|error| io_error("create file", path, &error))?;
    set_file_mode(&file, mode)?;
    file.write_all(bytes)
        .map_err(|error| io_error("write file", path, &error))?;
    file.sync_all()
        .map_err(|error| io_error("sync file", path, &error))
}

#[cfg(unix)]
fn file_mode(metadata: &fs::Metadata) -> u32 {
    use std::os::unix::fs::PermissionsExt;
    metadata.permissions().mode() & 0o777
}

#[cfg(not(unix))]
fn file_mode(_metadata: &fs::Metadata) -> u32 {
    0o600
}

#[cfg(unix)]
fn set_file_mode(file: &File, mode: u32) -> Result<(), SafeApplyError> {
    use std::os::unix::fs::PermissionsExt;
    file.set_permissions(fs::Permissions::from_mode(mode & 0o777))
        .map_err(|error| SafeApplyError::Io {
            operation: "set file permissions",
            path: PathBuf::from("<open-file>"),
            message: error.to_string(),
        })
}

#[cfg(not(unix))]
fn set_file_mode(_file: &File, _mode: u32) -> Result<(), SafeApplyError> {
    Ok(())
}

#[cfg(unix)]
fn set_directory_mode(path: &Path, mode: u32) -> Result<(), SafeApplyError> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(mode & 0o777))
        .map_err(|error| io_error("set directory permissions", path, &error))
}

#[cfg(not(unix))]
fn set_directory_mode(_path: &Path, _mode: u32) -> Result<(), SafeApplyError> {
    Ok(())
}

fn sync_directory(path: &Path) -> Result<(), SafeApplyError> {
    let directory = File::open(path).map_err(|error| io_error("open directory", path, &error))?;
    directory
        .sync_all()
        .map_err(|error| io_error("sync directory", path, &error))
}

fn encode_hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;

    bytes.iter().fold(
        String::with_capacity(bytes.len().saturating_mul(2)),
        |mut encoded, byte| {
            let _ = write!(encoded, "{byte:02x}");
            encoded
        },
    )
}

fn decode_hex(value: &str) -> Result<Vec<u8>, SafeApplyError> {
    if !value.len().is_multiple_of(2) {
        return Err(SafeApplyError::Journal(
            "odd-length hexadecimal field".into(),
        ));
    }
    (0..value.len())
        .step_by(2)
        .map(|index| {
            u8::from_str_radix(&value[index..index + 2], 16)
                .map_err(|_| SafeApplyError::Journal("invalid hexadecimal field".into()))
        })
        .collect()
}

fn io_error(operation: &'static str, path: &Path, error: &io::Error) -> SafeApplyError {
    SafeApplyError::Io {
        operation,
        path: path.to_path_buf(),
        message: error.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ShadowWorkspace;
    use grok_build_core::{
        WorkspaceGrantIssuer, WorkspaceGrantRequest, WorkspaceNetworkPolicy, WorkspacePermissions,
    };
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT_DIRECTORY: AtomicU64 = AtomicU64::new(0);

    struct TestDirectory(PathBuf);

    impl TestDirectory {
        fn new(label: &str) -> Self {
            let number = NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "grok-build-apply-{label}-{}-{number}",
                std::process::id()
            ));
            fs::create_dir_all(&path).unwrap();
            Self(fs::canonicalize(path).unwrap())
        }
    }

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn grant(root: &Path) -> IssuedWorkspaceGrant {
        WorkspaceGrantIssuer::issue(WorkspaceGrantRequest {
            grant_id: "apply-test-grant".into(),
            workspace_root: root.to_path_buf(),
            permissions: WorkspacePermissions::trusted(),
            network: WorkspaceNetworkPolicy::Denied,
            policy_version: 1,
        })
        .unwrap()
    }

    fn staged_three_file_change(
        workspace: &TestDirectory,
        private: &TestDirectory,
    ) -> (IssuedWorkspaceGrant, WorkspaceManifest, StagedChangeSet) {
        fs::write(workspace.0.join("modify"), b"before").unwrap();
        fs::write(workspace.0.join("delete"), b"delete me").unwrap();
        let grant = grant(&workspace.0);
        let base = WorkspaceManifest::capture(&grant, 1).unwrap();
        let shadow = ShadowWorkspace::create(&grant, &base, private.0.join("shadow")).unwrap();
        fs::write(shadow.root().join("modify"), b"after").unwrap();
        fs::remove_file(shadow.root().join("delete")).unwrap();
        fs::write(shadow.root().join("create"), b"created").unwrap();
        let staged = shadow.stage_changes("three-file-change", 2).unwrap();
        (grant, base, staged)
    }

    fn staged_single_create(
        workspace: &TestDirectory,
        private: &TestDirectory,
        change_set_id: &str,
    ) -> (IssuedWorkspaceGrant, WorkspaceManifest, StagedChangeSet) {
        fs::write(workspace.0.join("anchor"), b"base anchor").unwrap();
        let grant = grant(&workspace.0);
        let base = WorkspaceManifest::capture(&grant, 1).unwrap();
        let shadow = ShadowWorkspace::create(&grant, &base, private.0.join("shadow")).unwrap();
        fs::write(shadow.root().join("created"), b"new bytes").unwrap();
        let staged = shadow.stage_changes(change_set_id, 2).unwrap();
        (grant, base, staged)
    }

    fn staged_single_delete(
        workspace: &TestDirectory,
        private: &TestDirectory,
        change_set_id: &str,
    ) -> (IssuedWorkspaceGrant, WorkspaceManifest, StagedChangeSet) {
        fs::write(workspace.0.join("deleted"), b"base bytes").unwrap();
        let grant = grant(&workspace.0);
        let base = WorkspaceManifest::capture(&grant, 1).unwrap();
        let shadow = ShadowWorkspace::create(&grant, &base, private.0.join("shadow")).unwrap();
        fs::remove_file(shadow.root().join("deleted")).unwrap();
        let staged = shadow.stage_changes(change_set_id, 2).unwrap();
        (grant, base, staged)
    }

    fn staged_single_modify(
        workspace: &TestDirectory,
        private: &TestDirectory,
        change_set_id: &str,
    ) -> (IssuedWorkspaceGrant, WorkspaceManifest, StagedChangeSet) {
        fs::write(workspace.0.join("modified"), b"before").unwrap();
        let grant = grant(&workspace.0);
        let base = WorkspaceManifest::capture(&grant, 1).unwrap();
        let shadow = ShadowWorkspace::create(&grant, &base, private.0.join("shadow")).unwrap();
        fs::write(shadow.root().join("modified"), b"after").unwrap();
        let staged = shadow.stage_changes(change_set_id, 2).unwrap();
        (grant, base, staged)
    }

    #[test]
    fn live_application_rejects_a_verified_no_op_before_journaling() {
        let snapshot = Digest::sha256(b"unchanged application snapshot");
        let staged = StagedChangeSet::new(
            ChangeSet {
                change_set_id: "verified-no-op-application".into(),
                base_snapshot: snapshot.clone(),
                result_snapshot: snapshot,
                operations: Vec::new(),
            },
            std::collections::BTreeMap::new(),
        )
        .expect("construct verified no-op");

        assert!(matches!(
            validate_staged(&staged),
            Err(SafeApplyError::EmptyChangeSet)
        ));
    }

    #[test]
    fn apply_succeeds_and_explicit_rollback_restores_base() {
        let workspace = TestDirectory::new("success-workspace");
        let private = TestDirectory::new("success-private");
        let (grant, base, staged) = staged_three_file_change(&workspace, &private);
        let applier = SafeApplier::open(grant.clone(), private.0.join("journal")).unwrap();

        let outcome = applier.apply(&staged).unwrap();

        assert_eq!(
            outcome.applied_snapshot(),
            &staged.change_set().result_snapshot
        );
        assert_eq!(fs::read(workspace.0.join("modify")).unwrap(), b"after");
        assert_eq!(fs::read(workspace.0.join("create")).unwrap(), b"created");
        assert!(!workspace.0.join("delete").exists());

        let restored = applier.rollback("three-file-change").unwrap();

        assert_eq!(restored, base.snapshot().snapshot_id);
        assert_eq!(fs::read(workspace.0.join("modify")).unwrap(), b"before");
        assert_eq!(fs::read(workspace.0.join("delete")).unwrap(), b"delete me");
        assert!(!workspace.0.join("create").exists());
        assert_eq!(
            WorkspaceManifest::capture(&grant, 3)
                .unwrap()
                .snapshot()
                .snapshot_id,
            base.snapshot().snapshot_id
        );
    }

    #[test]
    fn rolled_back_change_set_identity_cannot_be_reused() {
        let workspace = TestDirectory::new("no-reuse-workspace");
        let private = TestDirectory::new("no-reuse-private");
        let (grant, base, staged) =
            staged_single_create(&workspace, &private, "write-once-change-set");
        let applier = SafeApplier::open(grant.clone(), private.0.join("journal")).unwrap();
        applier.apply(&staged).unwrap();
        applier.rollback("write-once-change-set").unwrap();

        assert!(matches!(
            applier.apply(&staged),
            Err(SafeApplyError::AlreadyRolledBack(id)) if id == "write-once-change-set"
        ));
        assert_eq!(
            WorkspaceManifest::capture(&grant, 3)
                .unwrap()
                .snapshot()
                .snapshot_id,
            base.snapshot().snapshot_id
        );
        assert!(!workspace.0.join("created").exists());
    }

    #[test]
    fn repeated_rollback_does_not_claim_success_after_external_edit() {
        let workspace = TestDirectory::new("stale-rolled-back-workspace");
        let private = TestDirectory::new("stale-rolled-back-private");
        let (grant, base, staged) = staged_single_create(&workspace, &private, "stale-rolled-back");
        let applier = SafeApplier::open(grant, private.0.join("journal")).unwrap();
        applier.apply(&staged).unwrap();
        assert_eq!(
            applier.rollback("stale-rolled-back").unwrap(),
            base.snapshot().snapshot_id
        );

        fs::write(workspace.0.join("external-edit"), b"changed after rollback").unwrap();

        assert!(matches!(
            applier.rollback("stale-rolled-back"),
            Err(SafeApplyError::StaleRollback { .. })
        ));
    }

    #[test]
    fn stale_full_manifest_is_rejected_before_journaling() {
        let workspace = TestDirectory::new("stale-workspace");
        let private = TestDirectory::new("stale-private");
        let (grant, _base, staged) = staged_three_file_change(&workspace, &private);
        fs::write(workspace.0.join("unrelated"), b"external change").unwrap();
        let applier = SafeApplier::open(grant, private.0.join("journal")).unwrap();

        let result = applier.apply(&staged);

        assert!(matches!(result, Err(SafeApplyError::StaleBase { .. })));
        assert!(applier.recover_pending().unwrap().is_empty());
    }

    #[test]
    fn injected_interruption_is_recovered_after_reopen() {
        let workspace = TestDirectory::new("recovery-workspace");
        let private = TestDirectory::new("recovery-private");
        let (grant, base, staged) = staged_three_file_change(&workspace, &private);
        let journal = private.0.join("journal");
        let first = SafeApplier::open(grant.clone(), &journal).unwrap();

        let interrupted = first.apply_internal(
            &staged,
            Some(FaultInjection {
                operation_index: 1,
                point: FaultPoint::AfterMarker,
            }),
        );
        assert!(matches!(
            interrupted,
            Err(SafeApplyError::InjectedFailure {
                applied_operations: 2
            })
        ));
        drop(first);

        let reopened = SafeApplier::open(grant.clone(), &journal).unwrap();
        let report = reopened.recover_pending().unwrap();

        assert_eq!(report.recovered_change_sets(), &["three-file-change"]);
        assert_eq!(
            WorkspaceManifest::capture(&grant, 3)
                .unwrap()
                .snapshot()
                .snapshot_id,
            base.snapshot().snapshot_id
        );
        assert_eq!(fs::read(workspace.0.join("modify")).unwrap(), b"before");
        assert_eq!(fs::read(workspace.0.join("delete")).unwrap(), b"delete me");
        assert!(!workspace.0.join("create").exists());
    }

    #[test]
    fn journal_rejects_workspace_overlap() {
        let workspace = TestDirectory::new("overlap-workspace");
        let grant = grant(&workspace.0);

        let result = SafeApplier::open(grant, workspace.0.join("journal"));

        assert!(matches!(result, Err(SafeApplyError::Journal(_))));
    }

    #[test]
    fn recovery_rejects_workspace_replacement_before_journal_processing() {
        let workspace = TestDirectory::new("replaced-recovery-workspace");
        let private = TestDirectory::new("replaced-recovery-private");
        let (grant, _base, staged) =
            staged_single_create(&workspace, &private, "replaced-recovery");
        let applier = SafeApplier::open(grant, private.0.join("journal")).unwrap();
        let interrupted = applier.apply_internal(
            &staged,
            Some(FaultInjection {
                operation_index: 0,
                point: FaultPoint::AfterApplyingPhase,
            }),
        );
        assert!(matches!(
            interrupted,
            Err(SafeApplyError::InjectedFailure { .. })
        ));

        let moved = workspace.0.with_extension("trusted-directory-moved");
        fs::rename(&workspace.0, &moved).unwrap();
        fs::create_dir(&workspace.0).unwrap();
        fs::write(
            workspace.0.join("sentinel"),
            b"replacement must remain untouched",
        )
        .unwrap();

        let recovery = applier.recover_pending();

        assert!(matches!(recovery, Err(SafeApplyError::Contract(_))));
        assert_eq!(
            fs::read(workspace.0.join("sentinel")).unwrap(),
            b"replacement must remain untouched"
        );

        fs::remove_dir_all(&workspace.0).unwrap();
        fs::rename(moved, &workspace.0).unwrap();
    }

    #[test]
    fn replacement_crash_windows_recover_owned_temporary_or_target() {
        let points = [
            FaultPoint::AfterApplyingPhase,
            FaultPoint::BeforeTempWrite,
            FaultPoint::AfterTempWrite,
            FaultPoint::AfterRename,
            FaultPoint::AfterDirectorySync,
            FaultPoint::AfterMarker,
            FaultPoint::BeforeCommit,
        ];
        for (iteration, point) in points.into_iter().enumerate() {
            let workspace = TestDirectory::new(&format!("replace-fault-{iteration}-workspace"));
            let private = TestDirectory::new(&format!("replace-fault-{iteration}-private"));
            let id = format!("replace-fault-{iteration}");
            let (grant, base, staged) = staged_single_create(&workspace, &private, &id);
            let journal = private.0.join("journal");
            let applier = SafeApplier::open(grant.clone(), &journal).unwrap();

            let result = applier.apply_internal(
                &staged,
                Some(FaultInjection {
                    operation_index: 0,
                    point,
                }),
            );
            assert!(matches!(
                result,
                Err(SafeApplyError::InjectedFailure { .. })
            ));
            drop(applier);

            let reopened = SafeApplier::open(grant.clone(), &journal).unwrap();
            let report = reopened.recover_pending().unwrap();
            assert_eq!(report.recovered_change_sets(), &[id]);
            assert_eq!(
                WorkspaceManifest::capture(&grant, 3)
                    .unwrap()
                    .snapshot()
                    .snapshot_id,
                base.snapshot().snapshot_id
            );
            assert!(!workspace.0.join("created").exists());
        }
    }

    #[test]
    fn unowned_lookalike_temporary_is_never_removed() {
        let workspace = TestDirectory::new("unowned-temp-workspace");
        let private = TestDirectory::new("unowned-temp-private");
        let (grant, _base, staged) = staged_single_create(&workspace, &private, "unowned-temp");
        let journal = private.0.join("journal");
        let applier = SafeApplier::open(grant, &journal).unwrap();
        let interrupted = applier.apply_internal(
            &staged,
            Some(FaultInjection {
                operation_index: 0,
                point: FaultPoint::AfterApplyingPhase,
            }),
        );
        assert!(matches!(
            interrupted,
            Err(SafeApplyError::InjectedFailure { .. })
        ));
        let transaction = applier.transaction_path("unowned-temp");
        let temporary =
            replacement_temporary_path(&transaction, &workspace.0, 0, ReplacementRole::Apply)
                .unwrap();
        fs::write(&temporary, b"new bytes").unwrap();

        let recovery = applier.recover_pending();

        assert!(matches!(
            recovery,
            Err(SafeApplyError::UnownedTemporary(path)) if path == temporary
        ));
        assert_eq!(fs::read(&temporary).unwrap(), b"new bytes");
        assert!(!workspace.0.join("created").exists());
    }

    #[test]
    fn delete_tombstone_recovers_before_post_unlink_marker() {
        for (iteration, point) in [FaultPoint::AfterDelete, FaultPoint::AfterDirectorySync]
            .into_iter()
            .enumerate()
        {
            let workspace = TestDirectory::new(&format!("delete-gap-{iteration}-workspace"));
            let private = TestDirectory::new(&format!("delete-gap-{iteration}-private"));
            let id = format!("delete-gap-{iteration}");
            let (grant, base, staged) = staged_single_delete(&workspace, &private, &id);
            let applier = SafeApplier::open(grant.clone(), private.0.join("journal")).unwrap();
            let interrupted = applier.apply_internal(
                &staged,
                Some(FaultInjection {
                    operation_index: 0,
                    point,
                }),
            );
            assert!(matches!(
                interrupted,
                Err(SafeApplyError::InjectedFailure { .. })
            ));
            assert!(!workspace.0.join("deleted").exists());

            if iteration == 0 {
                let transaction = applier.transaction_path(&id);
                let FileOperation::Delete { base_hash, .. } = &staged.change_set().operations[0]
                else {
                    panic!("fixture must contain one delete");
                };
                assert_eq!(
                    delete_evidence_for_recovery(
                        &transaction,
                        0,
                        &workspace.0.join("deleted"),
                        Path::new("deleted"),
                        base_hash,
                    )
                    .unwrap(),
                    OperationEvidence::NotApplied
                );
                assert_eq!(
                    fs::read(workspace.0.join("deleted")).unwrap(),
                    b"base bytes"
                );
            }

            let recovery = applier.recover_pending().unwrap();

            assert_eq!(recovery.recovered_change_sets(), &[id]);
            assert_eq!(
                fs::read(workspace.0.join("deleted")).unwrap(),
                b"base bytes"
            );
            assert_eq!(
                WorkspaceManifest::capture(&grant, 3)
                    .unwrap()
                    .snapshot()
                    .snapshot_id,
                base.snapshot().snapshot_id
            );
        }
    }

    #[test]
    fn delete_with_durable_marker_recovers_and_after_commit_stays_committed() {
        let workspace = TestDirectory::new("delete-marker-workspace");
        let private = TestDirectory::new("delete-marker-private");
        let (grant, base, staged) = staged_single_delete(&workspace, &private, "delete-marker");
        let journal = private.0.join("journal");
        let applier = SafeApplier::open(grant.clone(), &journal).unwrap();
        let interrupted = applier.apply_internal(
            &staged,
            Some(FaultInjection {
                operation_index: 0,
                point: FaultPoint::AfterMarker,
            }),
        );
        assert!(matches!(
            interrupted,
            Err(SafeApplyError::InjectedFailure { .. })
        ));
        assert_eq!(
            applier.recover_pending().unwrap().recovered_change_sets(),
            &["delete-marker"]
        );
        assert_eq!(
            fs::read(workspace.0.join("deleted")).unwrap(),
            b"base bytes"
        );
        assert_eq!(
            WorkspaceManifest::capture(&grant, 3)
                .unwrap()
                .snapshot()
                .snapshot_id,
            base.snapshot().snapshot_id
        );

        let workspace = TestDirectory::new("after-commit-workspace");
        let private = TestDirectory::new("after-commit-private");
        let (grant, base, staged) = staged_single_create(&workspace, &private, "after-commit");
        let applier = SafeApplier::open(grant.clone(), private.0.join("journal")).unwrap();
        let result = applier.apply_internal(
            &staged,
            Some(FaultInjection {
                operation_index: 0,
                point: FaultPoint::AfterCommit,
            }),
        );
        assert!(matches!(
            result,
            Err(SafeApplyError::InjectedFailure { .. })
        ));
        assert!(applier.recover_pending().unwrap().is_empty());
        assert_eq!(
            applier.reconcile("after-commit").unwrap(),
            ApplyReconciliation::Committed(ApplyOutcome {
                change_set_id: "after-commit".into(),
                applied_snapshot: staged.change_set().result_snapshot.clone(),
            })
        );
        assert_eq!(fs::read(workspace.0.join("created")).unwrap(), b"new bytes");
        assert_eq!(
            applier.rollback("after-commit").unwrap(),
            base.snapshot().snapshot_id
        );
        assert!(!workspace.0.join("created").exists());
    }

    #[test]
    fn effect_specific_reconciliation_restores_an_interrupted_apply() {
        let workspace = TestDirectory::new("specific-reconcile-workspace");
        let private = TestDirectory::new("specific-reconcile-private");
        let (grant, base, staged) =
            staged_single_modify(&workspace, &private, "specific-reconcile");
        let applier = SafeApplier::open(grant, private.0.join("journal")).unwrap();
        let interrupted = applier.apply_internal(
            &staged,
            Some(FaultInjection {
                operation_index: 0,
                point: FaultPoint::AfterRename,
            }),
        );
        assert!(matches!(
            interrupted,
            Err(SafeApplyError::InjectedFailure { .. })
        ));

        assert_eq!(
            applier.reconcile("specific-reconcile").unwrap(),
            ApplyReconciliation::RolledBack {
                change_set_id: "specific-reconcile".into(),
                base_snapshot: base.snapshot().snapshot_id.clone(),
            }
        );
        assert_eq!(fs::read(workspace.0.join("modified")).unwrap(), b"before");
    }

    #[test]
    fn interrupted_create_rollback_resumes_from_owned_tombstone() {
        for (iteration, point) in [
            FaultPoint::BeforeDelete,
            FaultPoint::AfterDelete,
            FaultPoint::AfterDirectorySync,
            FaultPoint::AfterMarker,
        ]
        .into_iter()
        .enumerate()
        {
            let workspace = TestDirectory::new(&format!("rollback-create-{iteration}-workspace"));
            let private = TestDirectory::new(&format!("rollback-create-{iteration}-private"));
            let id = format!("rollback-create-{iteration}");
            let (grant, base, staged) = staged_single_create(&workspace, &private, &id);
            let journal = private.0.join("journal");
            let applier = SafeApplier::open(grant.clone(), &journal).unwrap();
            applier.apply(&staged).unwrap();

            let interrupted = applier.rollback_internal(
                &id,
                Some(FaultInjection {
                    operation_index: 0,
                    point,
                }),
            );
            assert!(matches!(
                interrupted,
                Err(SafeApplyError::InjectedFailure { .. })
            ));
            drop(applier);

            let reopened = SafeApplier::open(grant.clone(), &journal).unwrap();
            assert_eq!(
                reopened.recover_pending().unwrap().recovered_change_sets(),
                &[id]
            );
            assert!(!workspace.0.join("created").exists());
            assert_eq!(
                WorkspaceManifest::capture(&grant, 3)
                    .unwrap()
                    .snapshot()
                    .snapshot_id,
                base.snapshot().snapshot_id
            );
        }
    }

    #[test]
    fn interrupted_replacement_rollback_resumes_from_inode_intent() {
        for (iteration, point) in [
            FaultPoint::BeforeTempWrite,
            FaultPoint::AfterTempWrite,
            FaultPoint::AfterRename,
            FaultPoint::AfterDirectorySync,
        ]
        .into_iter()
        .enumerate()
        {
            let workspace = TestDirectory::new(&format!("rollback-modify-{iteration}-workspace"));
            let private = TestDirectory::new(&format!("rollback-modify-{iteration}-private"));
            let id = format!("rollback-modify-{iteration}");
            let (grant, base, staged) = staged_single_modify(&workspace, &private, &id);
            let journal = private.0.join("journal");
            let applier = SafeApplier::open(grant.clone(), &journal).unwrap();
            applier.apply(&staged).unwrap();

            let interrupted = applier.rollback_internal(
                &id,
                Some(FaultInjection {
                    operation_index: 0,
                    point,
                }),
            );
            assert!(matches!(
                interrupted,
                Err(SafeApplyError::InjectedFailure { .. })
            ));
            drop(applier);

            let reopened = SafeApplier::open(grant.clone(), &journal).unwrap();
            assert_eq!(
                reopened.recover_pending().unwrap().recovered_change_sets(),
                &[id]
            );
            assert_eq!(fs::read(workspace.0.join("modified")).unwrap(), b"before");
            assert_eq!(
                WorkspaceManifest::capture(&grant, 3)
                    .unwrap()
                    .snapshot()
                    .snapshot_id,
                base.snapshot().snapshot_id
            );
        }
    }
}
