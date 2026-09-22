//! Durable generation journal for the macOS dedicated-identity helper.
//!
//! This module supplies only persistence and state-machine evidence. It does
//! not authenticate XPC peers, inspect accounts, launch or terminate
//! processes, install a helper, verify signatures, or call Service Management.
//! The privileged host must supply a freshly validated pool observation before
//! every lease acquisition and durable transition.

#![allow(dead_code)] // Activated with the signed Service Management helper.

use std::collections::BTreeSet;
use std::ffi::OsString;
use std::fmt::{self, Display, Formatter};
use std::fs;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::thread;
use std::time::{Duration, Instant};

use cap_fs_ext::{
    DirExt, FollowSymlinks, MetadataExt as PortableMetadataExt, OpenOptionsFollowExt, OsMetadataExt,
};
use cap_std::fs::{
    Dir, DirBuilder, DirBuilderExt, File, Metadata, OpenOptions, OpenOptionsExt, PermissionsExt,
};
use cap_std::{ambient_authority, fs::Permissions};
use grok_build_core::Digest;
use rustix::fs::{FlockOperation, RenameFlags, flock, renameat_with};
use serde::{Deserialize, Serialize};

use crate::capability_apply::DirectoryPathAnchor;
use crate::durable_directory::sync_directory_entries as sync_directory;
use crate::macos_helper_lifecycle::{
    MacosLifecycleTransition, MacosLiveReleasePermit, MacosLiveReleaseTransition,
    MacosPostPersistAction, MacosRecoveryAction, begin_cleaning, intend_cleanup_agent,
    reconstruct_launcher_release_intent, record_cleanup_agent, record_empty_domain,
    record_held_launcher, record_identity_released, record_launcher_released, recovery_action,
};
use crate::macos_helper_protocol::{
    MacosAssignedIdentity, MacosExecutionIdentityRecord, MacosHelperJournalRecord,
    MacosHelperJournalState, MacosHelperLaunchRequest, MacosHelperSession,
    MacosIdentityPoolObservation, MacosProcessObservation,
};

const JOURNAL_FORMAT_VERSION: u32 = 3;
const POOL_MANIFEST_NAME: &str = "pool.json";
const ADMISSION_LOCK_NAME: &str = "admission.lock";
const ADMISSION_INDEX_NAME: &str = "admission-index.jsonl";
const ACCOUNT_PREFIX: &str = "identity-";
const LOCK_NAME: &str = "lease.lock";
const GENERATION_PREFIX: &str = "generation-";
const GENERATION_SUFFIX: &str = ".json";
const GENERATION_DIGITS: usize = 20;
const MAX_POOL_MANIFEST_BYTES: u64 = 256 * 1024;
const MAX_ADMISSION_INDEX_BYTES: u64 = 64 * 1024 * 1024;
const MAX_ADMISSION_ENTRY_BYTES: usize = 1024 * 1024;
const MAX_ADMISSION_ENTRIES: usize = 65_536;
const MAX_JOURNAL_REFERENCE_BYTES: usize = 4 * 1024;
const MAX_GENERATION_BYTES: u64 = 1024 * 1024;
const MAX_IDENTITY_HISTORY_BYTES: u64 = 64 * 1024 * 1024;
const MAX_GENERATIONS_PER_IDENTITY: usize = 65_536;
const MAX_GENERATIONS_PER_IDENTITY_U64: u64 = 65_536;
const GLOBAL_LOCK_WAIT: Duration = Duration::from_secs(2);
const GLOBAL_LOCK_POLL: Duration = Duration::from_millis(1);
const MANIFEST_DOMAIN: &[u8] = b"grok-build.macos-helper-journal-manifest.v3\0";
const GENERATION_DOMAIN: &[u8] = b"grok-build.macos-helper-journal-generation.v3\0";
const ADMISSION_DOMAIN: &[u8] = b"grok-build.macos-helper-admission-index.v1\0";

/// Path-independent identity required to reopen the exact provisioned store.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct MacosHelperJournalReference {
    format_version: u32,
    pool_record_digest: Digest,
    manifest_digest: Digest,
    root_identity: ObjectIdentity,
    manifest_identity: ObjectIdentity,
}

impl MacosHelperJournalReference {
    pub(crate) const fn pool_record_digest(&self) -> &Digest {
        &self.pool_record_digest
    }

    pub(crate) const fn manifest_digest(&self) -> &Digest {
        &self.manifest_digest
    }

    /// Encodes the provisioned identity in one bounded canonical form suitable
    /// for trusted installation-state custody across helper restarts.
    pub(crate) fn canonical_bytes(&self) -> Result<Vec<u8>, MacosHelperJournalError> {
        let bytes = serde_json::to_vec(self).map_err(|error| {
            MacosHelperJournalError::Layout(format!("journal-reference encoding failed: {error}"))
        })?;
        if bytes.len() > MAX_JOURNAL_REFERENCE_BYTES {
            return Err(MacosHelperJournalError::Layout(
                "journal reference exceeds its hard byte bound".into(),
            ));
        }
        Ok(bytes)
    }

    /// Decodes only the unique bounded canonical reference representation.
    pub(crate) fn decode_canonical(bytes: &[u8]) -> Result<Self, MacosHelperJournalError> {
        if bytes.len() > MAX_JOURNAL_REFERENCE_BYTES {
            return Err(MacosHelperJournalError::Layout(
                "journal reference exceeds its hard byte bound".into(),
            ));
        }
        let reference: Self = serde_json::from_slice(bytes).map_err(|error| {
            MacosHelperJournalError::Layout(format!("journal-reference decoding failed: {error}"))
        })?;
        if reference.format_version != JOURNAL_FORMAT_VERSION
            || reference.root_identity.device == 0
            || reference.root_identity.inode == 0
            || reference.manifest_identity.device == 0
            || reference.manifest_identity.inode == 0
            || reference.canonical_bytes()? != bytes
        {
            return Err(MacosHelperJournalError::Layout(
                "journal reference is invalid or noncanonical".into(),
            ));
        }
        Ok(reference)
    }
}

/// Fail-closed durable-journal error.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum MacosHelperJournalError {
    Root(String),
    Pool(String),
    Layout(String),
    Generation(String),
    Lock(String),
    Io {
        operation: &'static str,
        path: PathBuf,
        message: String,
    },
    #[cfg(test)]
    InjectedFault(&'static str),
}

impl Display for MacosHelperJournalError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Root(message) => write!(formatter, "helper-journal root rejected: {message}"),
            Self::Pool(message) => write!(formatter, "helper-journal pool rejected: {message}"),
            Self::Layout(message) => {
                write!(formatter, "helper-journal layout rejected: {message}")
            }
            Self::Generation(message) => {
                write!(formatter, "helper-journal generation rejected: {message}")
            }
            Self::Lock(message) => write!(formatter, "helper-journal lease rejected: {message}"),
            Self::Io {
                operation,
                path,
                message,
            } => write!(
                formatter,
                "{operation} failed for helper-journal path {}: {message}",
                path.display()
            ),
            #[cfg(test)]
            Self::InjectedFault(point) => {
                write!(formatter, "injected helper-journal fault after {point}")
            }
        }
    }
}

impl std::error::Error for MacosHelperJournalError {}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct ObjectIdentity {
    device: u64,
    inode: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct PrivateDirectoryIdentity {
    object: ObjectIdentity,
    uid: u32,
    mode: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct FileFingerprint {
    object: ObjectIdentity,
    links: u64,
    length: u64,
    uid: u32,
    mode: u32,
    modified_seconds: i64,
    modified_nanoseconds: i64,
    changed_seconds: i64,
    changed_nanoseconds: i64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct StoredAccountLayout {
    uid: u32,
    account_record_digest: Digest,
    directory_identity: ObjectIdentity,
    lock_identity: ObjectIdentity,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct StoredPoolManifest {
    format_version: u32,
    root_identity: ObjectIdentity,
    pool_record_digest: Digest,
    records: Vec<MacosExecutionIdentityRecord>,
    accounts: Vec<StoredAccountLayout>,
    admission_lock_identity: ObjectIdentity,
    admission_index_identity: ObjectIdentity,
    manifest_digest: Digest,
}

#[derive(Serialize)]
struct ManifestDigestPreimage<'a> {
    format_version: u32,
    root_identity: ObjectIdentity,
    pool_record_digest: &'a Digest,
    records: &'a [MacosExecutionIdentityRecord],
    accounts: &'a [StoredAccountLayout],
    admission_lock_identity: ObjectIdentity,
    admission_index_identity: ObjectIdentity,
}

impl StoredPoolManifest {
    fn computed_digest(&self) -> Result<Digest, MacosHelperJournalError> {
        let canonical = serde_json::to_vec(&ManifestDigestPreimage {
            format_version: self.format_version,
            root_identity: self.root_identity,
            pool_record_digest: &self.pool_record_digest,
            records: &self.records,
            accounts: &self.accounts,
            admission_lock_identity: self.admission_lock_identity,
            admission_index_identity: self.admission_index_identity,
        })
        .map_err(|error| {
            MacosHelperJournalError::Layout(format!(
                "canonical pool-manifest encoding failed: {error}"
            ))
        })?;
        let mut bytes = Vec::with_capacity(MANIFEST_DOMAIN.len() + canonical.len());
        bytes.extend_from_slice(MANIFEST_DOMAIN);
        bytes.extend_from_slice(&canonical);
        Ok(Digest::sha256(&bytes))
    }

    fn canonical_bytes(&self) -> Result<Vec<u8>, MacosHelperJournalError> {
        serde_json::to_vec(self).map_err(|error| {
            MacosHelperJournalError::Layout(format!("pool-manifest encoding failed: {error}"))
        })
    }
}

/// One pool-global, append-only replay fence. The complete authenticated
/// request is retained so recovery can prove that its generation belongs to
/// exactly one fixed UID, rather than relying on a per-account uniqueness set.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct StoredAdmissionIndexEntry {
    format_version: u32,
    sequence: u64,
    previous_entry_digest: Option<Digest>,
    pool_record_digest: Digest,
    admission_session: MacosHelperSession,
    request: MacosHelperLaunchRequest,
    assigned_identity: MacosAssignedIdentity,
    initial_record: MacosHelperJournalRecord,
    entry_digest: Digest,
}

#[derive(Serialize)]
struct AdmissionIndexDigestPreimage<'a> {
    format_version: u32,
    sequence: u64,
    previous_entry_digest: Option<&'a Digest>,
    pool_record_digest: &'a Digest,
    admission_session: &'a MacosHelperSession,
    request: &'a MacosHelperLaunchRequest,
    assigned_identity: &'a MacosAssignedIdentity,
    initial_record: &'a MacosHelperJournalRecord,
}

impl StoredAdmissionIndexEntry {
    fn computed_digest(&self) -> Result<Digest, MacosHelperJournalError> {
        let canonical = serde_json::to_vec(&AdmissionIndexDigestPreimage {
            format_version: self.format_version,
            sequence: self.sequence,
            previous_entry_digest: self.previous_entry_digest.as_ref(),
            pool_record_digest: &self.pool_record_digest,
            admission_session: &self.admission_session,
            request: &self.request,
            assigned_identity: &self.assigned_identity,
            initial_record: &self.initial_record,
        })
        .map_err(|error| {
            MacosHelperJournalError::Generation(format!(
                "canonical admission-index encoding failed: {error}"
            ))
        })?;
        let mut bytes = Vec::with_capacity(ADMISSION_DOMAIN.len() + canonical.len());
        bytes.extend_from_slice(ADMISSION_DOMAIN);
        bytes.extend_from_slice(&canonical);
        Ok(Digest::sha256(&bytes))
    }

    fn canonical_bytes(&self) -> Result<Vec<u8>, MacosHelperJournalError> {
        serde_json::to_vec(self).map_err(|error| {
            MacosHelperJournalError::Generation(format!(
                "admission-index entry encoding failed: {error}"
            ))
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct StoredGeneration {
    format_version: u32,
    generation: u64,
    previous_generation_digest: Option<Digest>,
    pool_record_digest: Digest,
    assigned_identity: MacosAssignedIdentity,
    record: MacosHelperJournalRecord,
    generation_digest: Digest,
}

#[derive(Serialize)]
struct GenerationDigestPreimage<'a> {
    format_version: u32,
    generation: u64,
    previous_generation_digest: Option<&'a Digest>,
    pool_record_digest: &'a Digest,
    assigned_identity: &'a MacosAssignedIdentity,
    record: &'a MacosHelperJournalRecord,
}

impl StoredGeneration {
    fn computed_digest(&self) -> Result<Digest, MacosHelperJournalError> {
        let canonical = serde_json::to_vec(&GenerationDigestPreimage {
            format_version: self.format_version,
            generation: self.generation,
            previous_generation_digest: self.previous_generation_digest.as_ref(),
            pool_record_digest: &self.pool_record_digest,
            assigned_identity: &self.assigned_identity,
            record: &self.record,
        })
        .map_err(|error| {
            MacosHelperJournalError::Generation(format!(
                "canonical generation encoding failed: {error}"
            ))
        })?;
        let mut bytes = Vec::with_capacity(GENERATION_DOMAIN.len() + canonical.len());
        bytes.extend_from_slice(GENERATION_DOMAIN);
        bytes.extend_from_slice(&canonical);
        Ok(Digest::sha256(&bytes))
    }

    fn canonical_bytes(&self) -> Result<Vec<u8>, MacosHelperJournalError> {
        serde_json::to_vec(self).map_err(|error| {
            MacosHelperJournalError::Generation(format!("generation encoding failed: {error}"))
        })
    }
}

/// Retained capability for one fixed helper journal root.
pub(crate) struct MacosHelperJournalStore {
    root: Dir,
    root_parent: Dir,
    root_leaf: OsString,
    root_path: PathBuf,
    root_identity: PrivateDirectoryIdentity,
    path_anchor: DirectoryPathAnchor,
    manifest: StoredPoolManifest,
    manifest_identity: ObjectIdentity,
    reference: MacosHelperJournalReference,
}

impl MacosHelperJournalStore {
    /// Provisions an empty, already-created owner-private directory.
    ///
    /// Provisioning never repairs residue. Any interruption leaves an
    /// intentionally unusable layout which must be explicitly reconciled by
    /// installation code.
    #[allow(
        clippy::too_many_lines,
        reason = "provisioning keeps every identity capture and durability boundary explicit"
    )]
    pub(crate) fn provision(
        path: impl AsRef<Path>,
        session: &MacosHelperSession,
        pool: &MacosIdentityPoolObservation,
    ) -> Result<(Self, MacosHelperJournalReference), MacosHelperJournalError> {
        validate_pool(session, pool)?;
        let acquired = AcquiredRoot::open(path.as_ref())?;
        if !entry_names(&acquired.root, ".", 1)?.is_empty() {
            return Err(MacosHelperJournalError::Layout(
                "provisioning requires a completely empty private directory".into(),
            ));
        }

        let mut records = pool.records.clone();
        records.sort_by_key(|record| record.uid);
        let mut accounts = Vec::with_capacity(records.len());
        for record in &records {
            let name = account_directory_name(record.uid);
            let mut builder = DirBuilder::new();
            builder.mode(0o700);
            acquired
                .root
                .create_dir_with(&name, &builder)
                .map_err(|error| {
                    io_error("create fixed account journal", Path::new(&name), &error)
                })?;
            let account = acquired.root.open_dir_nofollow(&name).map_err(|error| {
                io_error(
                    "open fixed account journal without links",
                    Path::new(&name),
                    &error,
                )
            })?;
            account
                .set_permissions(Path::new("."), Permissions::from_mode(0o700))
                .map_err(|error| {
                    io_error("set fixed account-journal mode", Path::new(&name), &error)
                })?;
            let directory_identity =
                validate_private_directory(&account, "fixed account journal")?.object;
            let lock = create_private_file(&account, Path::new(LOCK_NAME))?;
            lock.sync_all().map_err(|error| {
                io_error("sync fixed account lease", Path::new(LOCK_NAME), &error)
            })?;
            let lock_metadata = lock.metadata().map_err(|error| {
                io_error("inspect fixed account lease", Path::new(LOCK_NAME), &error)
            })?;
            validate_private_file_metadata(Path::new(LOCK_NAME), &lock_metadata, 0, Some(0))?;
            let lock_identity = object_identity(&lock_metadata);
            sync_directory(&account).map_err(|error| {
                io_error("sync fixed account journal", Path::new(&name), &error)
            })?;
            accounts.push(StoredAccountLayout {
                uid: record.uid,
                account_record_digest: record.record_digest.clone(),
                directory_identity,
                lock_identity,
            });
        }
        let admission_lock = create_private_file(&acquired.root, Path::new(ADMISSION_LOCK_NAME))?;
        admission_lock.sync_all().map_err(|error| {
            io_error(
                "sync pool-global admission lock",
                Path::new(ADMISSION_LOCK_NAME),
                &error,
            )
        })?;
        let admission_lock_metadata = admission_lock.metadata().map_err(|error| {
            io_error(
                "inspect pool-global admission lock",
                Path::new(ADMISSION_LOCK_NAME),
                &error,
            )
        })?;
        validate_private_file_metadata(
            Path::new(ADMISSION_LOCK_NAME),
            &admission_lock_metadata,
            0,
            Some(0),
        )?;
        let admission_lock_identity = object_identity(&admission_lock_metadata);

        let admission_index = create_private_file(&acquired.root, Path::new(ADMISSION_INDEX_NAME))?;
        admission_index.sync_all().map_err(|error| {
            io_error(
                "sync empty pool-global admission index",
                Path::new(ADMISSION_INDEX_NAME),
                &error,
            )
        })?;
        let admission_index_metadata = admission_index.metadata().map_err(|error| {
            io_error(
                "inspect pool-global admission index",
                Path::new(ADMISSION_INDEX_NAME),
                &error,
            )
        })?;
        validate_private_file_metadata(
            Path::new(ADMISSION_INDEX_NAME),
            &admission_index_metadata,
            MAX_ADMISSION_INDEX_BYTES,
            Some(0),
        )?;
        let admission_index_identity = object_identity(&admission_index_metadata);
        sync_directory(&acquired.root)
            .map_err(|error| io_error("sync provisioned account layout", Path::new("."), &error))?;

        let mut manifest = StoredPoolManifest {
            format_version: JOURNAL_FORMAT_VERSION,
            root_identity: acquired.root_identity.object,
            pool_record_digest: pool.pool_record_digest.clone(),
            records,
            accounts,
            admission_lock_identity,
            admission_index_identity,
            manifest_digest: Digest::sha256(&[]),
        };
        manifest.manifest_digest = manifest.computed_digest()?;
        let manifest_bytes = manifest.canonical_bytes()?;
        let manifest_length = u64::try_from(manifest_bytes.len()).map_err(|_| {
            MacosHelperJournalError::Layout("pool-manifest byte count exceeds u64".into())
        })?;
        if manifest_length > MAX_POOL_MANIFEST_BYTES {
            return Err(MacosHelperJournalError::Layout(
                "canonical pool manifest exceeds its hard byte bound".into(),
            ));
        }
        let mut manifest_file = create_private_file(&acquired.root, Path::new(POOL_MANIFEST_NAME))?;
        manifest_file.write_all(&manifest_bytes).map_err(|error| {
            io_error(
                "write immutable pool manifest",
                Path::new(POOL_MANIFEST_NAME),
                &error,
            )
        })?;
        manifest_file.sync_all().map_err(|error| {
            io_error(
                "sync immutable pool manifest",
                Path::new(POOL_MANIFEST_NAME),
                &error,
            )
        })?;
        let manifest_metadata = manifest_file.metadata().map_err(|error| {
            io_error(
                "inspect immutable pool manifest",
                Path::new(POOL_MANIFEST_NAME),
                &error,
            )
        })?;
        validate_private_file_metadata(
            Path::new(POOL_MANIFEST_NAME),
            &manifest_metadata,
            MAX_POOL_MANIFEST_BYTES,
            Some(manifest_length),
        )?;
        let manifest_identity = object_identity(&manifest_metadata);
        sync_directory(&acquired.root)
            .map_err(|error| io_error("sync published pool manifest", Path::new("."), &error))?;

        let reference = MacosHelperJournalReference {
            format_version: JOURNAL_FORMAT_VERSION,
            pool_record_digest: pool.pool_record_digest.clone(),
            manifest_digest: manifest.manifest_digest.clone(),
            root_identity: acquired.root_identity.object,
            manifest_identity,
        };
        drop(manifest_file);
        drop(admission_index);
        drop(admission_lock);
        drop(acquired);
        let store = Self::open(path, &reference, session, pool)?;
        Ok((store, reference))
    }

    /// Reopens the exact provisioned root and immutable pool layout.
    pub(crate) fn open(
        path: impl AsRef<Path>,
        reference: &MacosHelperJournalReference,
        session: &MacosHelperSession,
        pool: &MacosIdentityPoolObservation,
    ) -> Result<Self, MacosHelperJournalError> {
        validate_pool(session, pool)?;
        if reference.format_version != JOURNAL_FORMAT_VERSION
            || reference.pool_record_digest != pool.pool_record_digest
        {
            return Err(MacosHelperJournalError::Pool(
                "journal reference differs from the active fixed pool".into(),
            ));
        }
        let acquired = AcquiredRoot::open(path.as_ref())?;
        if acquired.root_identity.object != reference.root_identity {
            return Err(MacosHelperJournalError::Root(
                "journal root identity differs from the provisioned reference".into(),
            ));
        }
        let (manifest_bytes, manifest_fingerprint) = read_stable_private_file(
            &acquired.root,
            Path::new(POOL_MANIFEST_NAME),
            MAX_POOL_MANIFEST_BYTES,
        )?;
        if manifest_fingerprint.object != reference.manifest_identity {
            return Err(MacosHelperJournalError::Layout(
                "pool manifest name was replaced".into(),
            ));
        }
        let manifest = decode_manifest(&manifest_bytes)?;
        if manifest.manifest_digest != reference.manifest_digest
            || manifest.root_identity != reference.root_identity
            || manifest.pool_record_digest != reference.pool_record_digest
        {
            return Err(MacosHelperJournalError::Layout(
                "pool manifest differs from the provisioned reference".into(),
            ));
        }
        let store = Self {
            root: acquired.root,
            root_parent: acquired.root_parent,
            root_leaf: acquired.root_leaf,
            root_path: acquired.root_path,
            root_identity: acquired.root_identity,
            path_anchor: acquired.path_anchor,
            manifest,
            manifest_identity: reference.manifest_identity,
            reference: reference.clone(),
        };
        store.validate(session, pool)?;
        Ok(store)
    }

    pub(crate) const fn reference(&self) -> &MacosHelperJournalReference {
        &self.reference
    }

    /// Acquires the single-writer lease for one exact fixed-pool identity.
    ///
    /// Once the lock is acquired, every validation failure is returned as a
    /// reconciliation lease so the caller cannot accidentally discard the
    /// account's exclusion while treating uncertain state as retryable.
    pub(crate) fn acquire<'store>(
        &'store self,
        session: &MacosHelperSession,
        pool: &MacosIdentityPoolObservation,
        assigned: MacosAssignedIdentity,
    ) -> Result<MacosJournalAcquireOutcome<'store>, MacosHelperJournalError> {
        self.validate(session, pool)?;
        let layout = self.layout_for_assigned(&assigned)?.clone();
        let account_name = account_directory_name(assigned.uid);
        let account = self
            .root
            .open_dir_nofollow(&account_name)
            .map_err(|error| {
                io_error(
                    "open account journal for lease",
                    Path::new(&account_name),
                    &error,
                )
            })?;
        let account_identity = validate_private_directory(&account, "leased account journal")?;
        if account_identity.object != layout.directory_identity {
            return Err(MacosHelperJournalError::Layout(
                "account journal identity differs from the fixed pool layout".into(),
            ));
        }
        let mut options = OpenOptions::new();
        options.read(true).write(true).follow(FollowSymlinks::No);
        let lock = account
            .open_with(LOCK_NAME, &options)
            .map_err(|error| io_error("open account lease", Path::new(LOCK_NAME), &error))?;
        let lock_metadata = lock.metadata().map_err(|error| {
            io_error(
                "inspect retained account lease",
                Path::new(LOCK_NAME),
                &error,
            )
        })?;
        validate_private_file_metadata(Path::new(LOCK_NAME), &lock_metadata, 0, Some(0))?;
        if object_identity(&lock_metadata) != layout.lock_identity {
            return Err(MacosHelperJournalError::Layout(
                "account lease identity differs from the fixed pool layout".into(),
            ));
        }
        flock(&lock, FlockOperation::NonBlockingLockExclusive).map_err(|error| {
            MacosHelperJournalError::Lock(format!(
                "identity {} is already leased: {error}",
                assigned.uid
            ))
        })?;

        let lease = MacosJournalLease {
            store: self,
            account,
            account_name,
            account_identity,
            lock: AccountLeaseExclusion { file: lock },
            lock_identity: layout.lock_identity,
            assigned,
        };
        Ok(classify_lease(lease, session, pool))
    }

    #[allow(
        clippy::too_many_lines,
        reason = "one store validation pass binds the root, manifest, global replay files, and every fixed account identity"
    )]
    fn validate(
        &self,
        session: &MacosHelperSession,
        pool: &MacosIdentityPoolObservation,
    ) -> Result<(), MacosHelperJournalError> {
        validate_pool(session, pool)?;
        self.path_anchor
            .validate("macOS helper journal")
            .map_err(|error| MacosHelperJournalError::Root(error.to_string()))?;
        let retained = validate_private_directory(&self.root, "retained helper journal root")?;
        if retained != self.root_identity {
            return Err(MacosHelperJournalError::Root(
                "retained helper-journal root identity, owner, or mode drifted".into(),
            ));
        }
        let named = self
            .root_parent
            .open_dir_nofollow(&self.root_leaf)
            .map_err(|error| {
                io_error("reopen named helper-journal root", Path::new("."), &error)
            })?;
        if validate_private_directory(&named, "named helper journal root")? != self.root_identity {
            return Err(MacosHelperJournalError::Root(
                "helper-journal root name was replaced".into(),
            ));
        }

        let (manifest_bytes, manifest_fingerprint) = read_stable_private_file(
            &self.root,
            Path::new(POOL_MANIFEST_NAME),
            MAX_POOL_MANIFEST_BYTES,
        )?;
        if manifest_fingerprint.object != self.manifest_identity
            || decode_manifest(&manifest_bytes)? != self.manifest
            || self.manifest.root_identity != self.reference.root_identity
            || self.manifest.manifest_digest != self.reference.manifest_digest
        {
            return Err(MacosHelperJournalError::Layout(
                "retained pool manifest changed or was replaced".into(),
            ));
        }
        let mut expected_records = pool.records.clone();
        expected_records.sort_by_key(|record| record.uid);
        if self.manifest.records != expected_records
            || self.manifest.pool_record_digest != pool.pool_record_digest
            || self.manifest.accounts.len() != self.manifest.records.len()
        {
            return Err(MacosHelperJournalError::Pool(
                "active pool membership differs from the immutable journal pool".into(),
            ));
        }

        let admission_lock =
            inspect_named_private_file(&self.root, Path::new(ADMISSION_LOCK_NAME), 0, Some(0))?;
        let admission_index = inspect_named_private_file(
            &self.root,
            Path::new(ADMISSION_INDEX_NAME),
            MAX_ADMISSION_INDEX_BYTES,
            None,
        )?;
        if admission_lock.object != self.manifest.admission_lock_identity
            || admission_index.object != self.manifest.admission_index_identity
        {
            return Err(MacosHelperJournalError::Layout(
                "pool-global admission lock or index was replaced".into(),
            ));
        }

        let mut expected_root_entries = BTreeSet::from([
            POOL_MANIFEST_NAME.to_owned(),
            ADMISSION_LOCK_NAME.to_owned(),
            ADMISSION_INDEX_NAME.to_owned(),
        ]);
        for (record, layout) in self.manifest.records.iter().zip(&self.manifest.accounts) {
            if layout.uid != record.uid || layout.account_record_digest != record.record_digest {
                return Err(MacosHelperJournalError::Layout(
                    "account layout is not ordered and bound to the pool records".into(),
                ));
            }
            let name = account_directory_name(record.uid);
            expected_root_entries.insert(name.clone());
            let account = self.root.open_dir_nofollow(&name).map_err(|error| {
                io_error(
                    "open fixed account layout without links",
                    Path::new(&name),
                    &error,
                )
            })?;
            if validate_private_directory(&account, "fixed account layout")?.object
                != layout.directory_identity
            {
                return Err(MacosHelperJournalError::Layout(format!(
                    "account journal for UID {} was replaced",
                    record.uid
                )));
            }
            let lock_fingerprint =
                inspect_named_private_file(&account, Path::new(LOCK_NAME), 0, Some(0))?;
            if lock_fingerprint.object != layout.lock_identity {
                return Err(MacosHelperJournalError::Layout(format!(
                    "account lease for UID {} was replaced",
                    record.uid
                )));
            }
        }
        if entry_names(&self.root, ".", self.manifest.records.len() + 4)? != expected_root_entries {
            return Err(MacosHelperJournalError::Layout(
                "helper-journal root contains a missing, temporary, or unknown entry".into(),
            ));
        }
        Ok(())
    }

    fn layout_for_assigned(
        &self,
        assigned: &MacosAssignedIdentity,
    ) -> Result<&StoredAccountLayout, MacosHelperJournalError> {
        let Some((record, layout)) = self
            .manifest
            .records
            .iter()
            .zip(&self.manifest.accounts)
            .find(|(record, _)| record.uid == assigned.uid)
        else {
            return Err(MacosHelperJournalError::Pool(
                "assigned UID is not a member of the fixed pool".into(),
            ));
        };
        if record.account_name != assigned.account_name
            || record.gid != assigned.gid
            || record.record_digest != assigned.account_record_digest
        {
            return Err(MacosHelperJournalError::Pool(
                "assigned account identity differs from its fixed pool record".into(),
            ));
        }
        Ok(layout)
    }

    fn read_admission_index(
        &self,
        session: &MacosHelperSession,
        pool: &MacosIdentityPoolObservation,
    ) -> Result<Vec<StoredAdmissionIndexEntry>, MacosHelperJournalError> {
        let (bytes, fingerprint) = read_stable_private_file(
            &self.root,
            Path::new(ADMISSION_INDEX_NAME),
            MAX_ADMISSION_INDEX_BYTES,
        )?;
        if fingerprint.object != self.manifest.admission_index_identity {
            return Err(MacosHelperJournalError::Layout(
                "pool-global admission index was replaced".into(),
            ));
        }
        decode_admission_index(&bytes, &self.manifest, session, pool)
    }

    fn indexed_preparation_for_assigned(
        &self,
        session: &MacosHelperSession,
        pool: &MacosIdentityPoolObservation,
        assigned: &MacosAssignedIdentity,
    ) -> Result<Option<StoredAdmissionIndexEntry>, MacosHelperJournalError> {
        let entries = self.read_admission_index(session, pool)?;
        let mut matching = entries
            .into_iter()
            .filter(|entry| entry.assigned_identity == *assigned);
        let first = matching.next();
        if matching.next().is_some() {
            return Err(MacosHelperJournalError::Generation(
                "an empty account prefix has multiple pool-global admission mappings".into(),
            ));
        }
        Ok(first)
    }

    /// Appends the global request-to-UID fence under the one fixed pool lock.
    /// The synchronized mapping is intentionally retained even if subsequent
    /// account-generation persistence fails or the lifecycle is cleaned.
    #[allow(
        clippy::too_many_lines,
        reason = "the single append path keeps lock acquisition, collision checks, fsync, and exact readback adjacent"
    )]
    fn append_admission_fence(
        &self,
        session: &MacosHelperSession,
        pool: &MacosIdentityPoolObservation,
        record: &MacosHelperJournalRecord,
    ) -> Result<(), MacosHelperJournalError> {
        record
            .validate_for_session(session)
            .map_err(|error| MacosHelperJournalError::Generation(error.to_string()))?;
        if record.state != MacosHelperJournalState::Prepared {
            return Err(MacosHelperJournalError::Generation(
                "pool-global admission fence requires the initial Prepared record".into(),
            ));
        }
        let assigned = record.assigned_identity.as_ref().ok_or_else(|| {
            MacosHelperJournalError::Generation(
                "pool-global admission fence requires an assigned identity".into(),
            )
        })?;
        self.layout_for_assigned(assigned)?;

        let admission_lock = self.open_admission_lock()?;
        acquire_bounded_exclusive_lock(&admission_lock)?;
        self.validate(session, pool)?;
        let entries = self.read_admission_index(session, pool)?;
        if entries.iter().any(|entry| {
            entry
                .admission_session
                .same_durable_authority(&record.admission_session)
                && entry.request == record.request
                && entry.assigned_identity == *assigned
                && entry.initial_record == *record
        }) {
            return Err(MacosHelperJournalError::Generation(
                "an existing admission fence can be resumed only through indexed preparation reconciliation"
                    .into(),
            ));
        }
        if entries
            .iter()
            .any(|entry| admission_identity_collides(&entry.request, &record.request))
        {
            return Err(MacosHelperJournalError::Generation(
                "request, attempt, launch, journal, or runner/effect identity was already assigned in the pool-global index"
                    .into(),
            ));
        }
        let sequence = u64::try_from(entries.len())
            .ok()
            .and_then(|value| value.checked_add(1))
            .ok_or_else(|| {
                MacosHelperJournalError::Generation("admission-index sequence overflow".into())
            })?;
        let mut entry = StoredAdmissionIndexEntry {
            format_version: JOURNAL_FORMAT_VERSION,
            sequence,
            previous_entry_digest: entries.last().map(|entry| entry.entry_digest.clone()),
            pool_record_digest: self.manifest.pool_record_digest.clone(),
            admission_session: record.admission_session.clone(),
            request: record.request.clone(),
            assigned_identity: assigned.clone(),
            initial_record: record.clone(),
            entry_digest: Digest::sha256(&[]),
        };
        entry.entry_digest = entry.computed_digest()?;
        let mut encoded = entry.canonical_bytes()?;
        if encoded.len() > MAX_ADMISSION_ENTRY_BYTES {
            return Err(MacosHelperJournalError::Generation(
                "admission-index entry exceeds its hard byte bound".into(),
            ));
        }
        encoded.push(b'\n');
        let current_length = inspect_named_private_file(
            &self.root,
            Path::new(ADMISSION_INDEX_NAME),
            MAX_ADMISSION_INDEX_BYTES,
            None,
        )?
        .length;
        let append_length = u64::try_from(encoded.len()).map_err(|_| {
            MacosHelperJournalError::Generation("admission-index byte count exceeds u64".into())
        })?;
        let final_length = current_length.checked_add(append_length).ok_or_else(|| {
            MacosHelperJournalError::Generation("admission-index length overflow".into())
        })?;
        if final_length > MAX_ADMISSION_INDEX_BYTES {
            return Err(MacosHelperJournalError::Generation(
                "admission-index reached its aggregate hard byte bound".into(),
            ));
        }

        let mut options = OpenOptions::new();
        options.read(true).append(true).follow(FollowSymlinks::No);
        let mut index = self
            .root
            .open_with(ADMISSION_INDEX_NAME, &options)
            .map_err(|error| {
                io_error(
                    "open pool-global admission index for append",
                    Path::new(ADMISSION_INDEX_NAME),
                    &error,
                )
            })?;
        let metadata = index.metadata().map_err(|error| {
            io_error(
                "inspect retained admission index before append",
                Path::new(ADMISSION_INDEX_NAME),
                &error,
            )
        })?;
        validate_private_file_metadata(
            Path::new(ADMISSION_INDEX_NAME),
            &metadata,
            MAX_ADMISSION_INDEX_BYTES,
            Some(current_length),
        )?;
        if object_identity(&metadata) != self.manifest.admission_index_identity {
            return Err(MacosHelperJournalError::Layout(
                "retained admission index differs from the manifest".into(),
            ));
        }
        index.write_all(&encoded).map_err(|error| {
            io_error(
                "append pool-global admission fence",
                Path::new(ADMISSION_INDEX_NAME),
                &error,
            )
        })?;
        index.sync_all().map_err(|error| {
            io_error(
                "sync pool-global admission fence",
                Path::new(ADMISSION_INDEX_NAME),
                &error,
            )
        })?;
        drop(index);
        let readback = self.read_admission_index(session, pool)?;
        if readback.len() != entries.len() + 1 || readback.last() != Some(&entry) {
            return Err(MacosHelperJournalError::Generation(
                "synchronized admission fence differs from exact readback".into(),
            ));
        }
        Ok(())
    }

    fn open_admission_lock(&self) -> Result<File, MacosHelperJournalError> {
        let mut options = OpenOptions::new();
        options.read(true).write(true).follow(FollowSymlinks::No);
        let lock = self
            .root
            .open_with(ADMISSION_LOCK_NAME, &options)
            .map_err(|error| {
                io_error(
                    "open pool-global admission lock",
                    Path::new(ADMISSION_LOCK_NAME),
                    &error,
                )
            })?;
        let metadata = lock.metadata().map_err(|error| {
            io_error(
                "inspect pool-global admission lock",
                Path::new(ADMISSION_LOCK_NAME),
                &error,
            )
        })?;
        validate_private_file_metadata(Path::new(ADMISSION_LOCK_NAME), &metadata, 0, Some(0))?;
        if object_identity(&metadata) != self.manifest.admission_lock_identity {
            return Err(MacosHelperJournalError::Layout(
                "pool-global admission lock differs from the manifest".into(),
            ));
        }
        Ok(lock)
    }
}

struct AcquiredRoot {
    root: Dir,
    root_parent: Dir,
    root_leaf: OsString,
    root_path: PathBuf,
    root_identity: PrivateDirectoryIdentity,
    path_anchor: DirectoryPathAnchor,
}

impl AcquiredRoot {
    fn open(path: &Path) -> Result<Self, MacosHelperJournalError> {
        if !path.is_absolute() {
            return Err(MacosHelperJournalError::Root(
                "helper-journal root must be absolute".into(),
            ));
        }
        let canonical = fs::canonicalize(path).map_err(|error| {
            io_error("canonicalize helper-journal root", Path::new("."), &error)
        })?;
        if canonical != path {
            return Err(MacosHelperJournalError::Root(
                "helper-journal root must use its exact canonical path".into(),
            ));
        }
        let parent_path = canonical.parent().ok_or_else(|| {
            MacosHelperJournalError::Root("helper-journal root has no parent".into())
        })?;
        let root_leaf = canonical
            .file_name()
            .ok_or_else(|| MacosHelperJournalError::Root("helper-journal root has no leaf".into()))?
            .to_os_string();
        let root_parent = Dir::open_ambient_dir(parent_path, ambient_authority())
            .map_err(|error| io_error("open helper-journal parent", Path::new("."), &error))?;
        let root = root_parent.open_dir_nofollow(&root_leaf).map_err(|error| {
            io_error(
                "open helper-journal root without links",
                Path::new("."),
                &error,
            )
        })?;
        let root_identity = validate_private_directory(&root, "helper journal root")?;
        let path_anchor = DirectoryPathAnchor::acquire(&canonical, "macOS helper journal")
            .map_err(|error| MacosHelperJournalError::Root(error.to_string()))?;
        if path_anchor.final_device_inode()
            != (root_identity.object.device, root_identity.object.inode)
        {
            return Err(MacosHelperJournalError::Root(
                "helper-journal path anchor differs from its retained descriptor".into(),
            ));
        }
        Ok(Self {
            root,
            root_parent,
            root_leaf,
            root_path: canonical,
            root_identity,
            path_anchor,
        })
    }
}

/// Lease classification after validating the complete immutable prefix.
#[must_use = "dropping a journal outcome releases the account lease"]
pub(crate) enum MacosJournalAcquireOutcome<'store> {
    Ready(MacosJournalReadyLease<'store>),
    IndexedPreparationRequired(Box<MacosJournalIndexedPreparationLease<'store>>),
    RecoveryRequired(MacosJournalRecoveryLease<'store>),
    ReconciliationRequired(MacosJournalReconciliationLease<'store>),
}

/// Exclusive account lease for a pool-global fence whose initial `Prepared`
/// generation was not published. Recovery uses the exact archived record from
/// the index; it never fabricates a new admission session or silently returns
/// the UID to the ready pool.
#[must_use = "an indexed UID remains quarantined until Prepared is durable or cleanup reconciles it"]
pub(crate) struct MacosJournalIndexedPreparationLease<'store> {
    lease: MacosJournalLease<'store>,
    indexed: StoredAdmissionIndexEntry,
}

impl<'store> MacosJournalIndexedPreparationLease<'store> {
    pub(crate) const fn record(&self) -> &MacosHelperJournalRecord {
        &self.indexed.initial_record
    }

    /// Replaces pre-crash observations with two freshly reconciled empty UID
    /// observations, then publishes `Prepared` while the request is unexpired.
    /// At or after the deadline, or without exact fresh emptiness, the UID stays
    /// reconciliation-only and no actionable durable lease is returned.
    pub(crate) fn persist_prepared_after_fresh_empty_reconciliation(
        self,
        session: &MacosHelperSession,
        pool: &MacosIdentityPoolObservation,
        fresh_observations: [MacosProcessObservation; 2],
        now_unix_ms: u64,
    ) -> MacosJournalAppendOutcome<'store> {
        if now_unix_ms >= self.indexed.request.deadline_unix_ms {
            return MacosJournalAppendOutcome::ReconciliationRequired(
                MacosJournalReconciliationLease {
                    lease: self.lease,
                    cause: MacosHelperJournalError::Generation(
                        "indexed pre-effect request expired before Prepared publication; UID remains quarantined for cleanup reconciliation"
                            .into(),
                    ),
                },
            );
        }
        if fresh_observations[0].observed_at_unix_ms < session.authenticated_at_unix_ms
            || fresh_observations[1].observed_at_unix_ms > now_unix_ms
            || fresh_observations.iter().any(|observation| {
                observation.creation_sealed || !observation.process_ids.is_empty()
            })
        {
            return MacosJournalAppendOutcome::ReconciliationRequired(
                MacosJournalReconciliationLease {
                    lease: self.lease,
                    cause: MacosHelperJournalError::Generation(
                        "indexed Prepared recovery requires two fresh, unsealed, stable-empty UID observations"
                            .into(),
                    ),
                },
            );
        }
        let mut reconciled = self.indexed.initial_record.clone();
        reconciled.observations = fresh_observations.into();
        if let Err(error) = reconciled.validate_for_session(session) {
            return MacosJournalAppendOutcome::ReconciliationRequired(
                MacosJournalReconciliationLease {
                    lease: self.lease,
                    cause: MacosHelperJournalError::Generation(format!(
                        "fresh indexed Prepared reconciliation failed validation: {error}"
                    )),
                },
            );
        }
        match persist_transition_inner(
            &self.lease,
            None,
            &reconciled,
            TransitionPosition::Initial,
            session,
            pool,
            #[cfg(test)]
            None,
        ) {
            Ok(head) => MacosJournalAppendOutcome::Durable(Box::new(MacosJournalDurableLease {
                lease: self.lease,
                head,
                action: MacosPostPersistAction::None,
            })),
            Err(cause) => {
                MacosJournalAppendOutcome::ReconciliationRequired(MacosJournalReconciliationLease {
                    lease: self.lease,
                    cause,
                })
            }
        }
    }
}

/// Exclusive account lease with no unfinished lifecycle record.
#[must_use = "the fixed account remains exclusively leased while this value is held"]
pub(crate) struct MacosJournalReadyLease<'store> {
    lease: MacosJournalLease<'store>,
    head: Option<StoredGeneration>,
}

impl<'store> MacosJournalReadyLease<'store> {
    /// Persists the first `Prepared` generation for a new request lifecycle.
    pub(crate) fn persist_initial(
        self,
        session: &MacosHelperSession,
        pool: &MacosIdentityPoolObservation,
        transition: MacosLifecycleTransition,
    ) -> MacosJournalAppendOutcome<'store> {
        if let Err(cause) =
            self.lease
                .store
                .append_admission_fence(session, pool, transition.record())
        {
            return MacosJournalAppendOutcome::ReconciliationRequired(
                MacosJournalReconciliationLease {
                    lease: self.lease,
                    cause,
                },
            );
        }
        let expected_head = self.head;
        persist_transition(
            self.lease,
            expected_head.as_ref(),
            transition,
            TransitionPosition::Initial,
            session,
            pool,
            #[cfg(test)]
            None,
        )
    }
}

/// Exclusive account lease for a valid, unfinished lifecycle prefix.
#[must_use = "recovery must retain this exclusive account lease"]
pub(crate) struct MacosJournalRecoveryLease<'store> {
    lease: MacosJournalLease<'store>,
    head: StoredGeneration,
    action: MacosRecoveryAction,
}

impl<'store> MacosJournalRecoveryLease<'store> {
    pub(crate) const fn action(&self) -> MacosRecoveryAction {
        self.action
    }

    pub(crate) const fn record(&self) -> &MacosHelperJournalRecord {
        &self.head.record
    }

    /// Persists an exact reconciled successor; it never replays the prior host
    /// action merely because the journal contains intent.
    pub(crate) fn persist_successor(
        self,
        session: &MacosHelperSession,
        pool: &MacosIdentityPoolObservation,
        transition: MacosLifecycleTransition,
    ) -> MacosJournalAppendOutcome<'store> {
        let expected_head = self.head;
        persist_transition(
            self.lease,
            Some(&expected_head),
            transition,
            TransitionPosition::Successor,
            session,
            pool,
            #[cfg(test)]
            None,
        )
    }
}

/// Exclusive lease returned when disk state or durability is uncertain.
#[must_use = "uncertain journal state must retain this exclusive account lease"]
pub(crate) struct MacosJournalReconciliationLease<'store> {
    lease: MacosJournalLease<'store>,
    cause: MacosHelperJournalError,
}

impl<'store> MacosJournalReconciliationLease<'store> {
    pub(crate) const fn cause(&self) -> &MacosHelperJournalError {
        &self.cause
    }

    /// Revalidates under the same continuously-held lock after explicit host
    /// reconciliation. It does not remove residue or replay an effect.
    pub(crate) fn retry_validation(
        self,
        session: &MacosHelperSession,
        pool: &MacosIdentityPoolObservation,
    ) -> MacosJournalAcquireOutcome<'store> {
        classify_lease(self.lease, session, pool)
    }
}

/// Result of publishing one immutable generation.
#[must_use = "the returned value owns the still-exclusive account lease"]
pub(crate) enum MacosJournalAppendOutcome<'store> {
    Durable(Box<MacosJournalDurableLease<'store>>),
    ReconciliationRequired(MacosJournalReconciliationLease<'store>),
}

/// Result of the only production path that can execute the native held-launch
/// release. Both variants retain the account lease; the reconciliation branch
/// never invokes the supplied release callback.
#[must_use = "release completion or reconciliation must retain the account lease"]
pub(crate) enum MacosJournalReleaseOutcome<'store, Released> {
    Executed {
        durable: Box<MacosJournalDurableLease<'store>>,
        released: Released,
    },
    ReconciliationRequired(MacosJournalReconciliationLease<'store>),
}

/// Exclusive lease and exact action authorized after a durable generation.
#[must_use = "perform or reconcile the post-persist action before releasing the lease"]
pub(crate) struct MacosJournalDurableLease<'store> {
    lease: MacosJournalLease<'store>,
    head: StoredGeneration,
    action: MacosPostPersistAction,
}

/// Non-cloneable readback receipt for an exact durable `HeldPrepared`
/// generation in the provisioned helper journal.
///
/// This is binding evidence only. It carries no live core claim, hold-control
/// descriptor, process handle, release authority, or cleanup authority.
#[must_use = "durable held-preparation evidence must be handed off or explicitly dropped"]
pub(crate) struct MacosDurableHeldPreparationReceipt {
    helper_journal_reference_bytes: Vec<u8>,
    record: MacosHelperJournalRecord,
    generation_digest: Digest,
}

impl MacosDurableHeldPreparationReceipt {
    pub(crate) fn helper_journal_reference_bytes(&self) -> &[u8] {
        &self.helper_journal_reference_bytes
    }

    pub(crate) const fn record(&self) -> &MacosHelperJournalRecord {
        &self.record
    }

    pub(crate) const fn generation_digest(&self) -> &Digest {
        &self.generation_digest
    }
}

impl<'store> MacosJournalDurableLease<'store> {
    pub(crate) const fn post_persist_action(&self) -> MacosPostPersistAction {
        self.action
    }

    pub(crate) const fn record(&self) -> &MacosHelperJournalRecord {
        &self.head.record
    }

    /// Captures the exact synchronized generation already read back by the
    /// append path. The returned value is deliberately non-cloneable and does
    /// not authorize the held child to run.
    pub(crate) fn durable_held_preparation_receipt(
        &self,
    ) -> Result<MacosDurableHeldPreparationReceipt, MacosHelperJournalError> {
        self.head
            .record
            .validate()
            .map_err(|error| MacosHelperJournalError::Generation(error.to_string()))?;
        if self.head.record.state != MacosHelperJournalState::HeldPrepared
            || self.head.record.held_preparation_evidence.is_none()
        {
            return Err(MacosHelperJournalError::Generation(
                "held-preparation receipt requires the exact durable HeldPrepared generation"
                    .into(),
            ));
        }
        let helper_journal_reference_bytes = self.store_reference_bytes()?;
        Ok(MacosDurableHeldPreparationReceipt {
            helper_journal_reference_bytes,
            record: self.head.record.clone(),
            generation_digest: self.head.generation_digest.clone(),
        })
    }

    fn store_reference_bytes(&self) -> Result<Vec<u8>, MacosHelperJournalError> {
        self.lease.store.reference.canonical_bytes()
    }

    /// Synchronizes `ReleaseIntended`, rechecks the authenticated deadline,
    /// and invokes the native hold-control callback while core's live release
    /// claim is still borrowed. No owned or copyable release action escapes.
    pub(crate) fn persist_release_intent_and_execute<'claim, 'ledger, Released, Release>(
        self,
        session: &MacosHelperSession,
        pool: &MacosIdentityPoolObservation,
        transition: MacosLiveReleaseTransition<'claim, 'ledger>,
        release_started_at_unix_ms: u64,
        release: Release,
    ) -> MacosJournalReleaseOutcome<'store, Released>
    where
        Release: FnOnce(&MacosLiveReleasePermit<'_, 'claim, 'ledger>) -> Released,
    {
        let (record, authorization) = transition.into_parts();
        let expected_head = self.head;
        match persist_transition_inner(
            &self.lease,
            Some(&expected_head),
            &record,
            TransitionPosition::Successor,
            session,
            pool,
            #[cfg(test)]
            None,
        ) {
            Err(cause) => MacosJournalReleaseOutcome::ReconciliationRequired(
                MacosJournalReconciliationLease {
                    lease: self.lease,
                    cause,
                },
            ),
            Ok(head) => {
                let authorized_at = authorization.record().authorized_at_unix_ms;
                if release_started_at_unix_ms < authorized_at
                    || release_started_at_unix_ms >= record.request.deadline_unix_ms
                {
                    return MacosJournalReleaseOutcome::ReconciliationRequired(
                        MacosJournalReconciliationLease {
                            lease: self.lease,
                            cause: MacosHelperJournalError::Generation(
                                "release deadline crossed after durable ReleaseIntended; native release was not executed"
                                    .into(),
                            ),
                        },
                    );
                }
                let permit =
                    MacosLiveReleasePermit::new(&authorization, release_started_at_unix_ms);
                let released = release(&permit);
                MacosJournalReleaseOutcome::Executed {
                    durable: Box::new(MacosJournalDurableLease {
                        lease: self.lease,
                        head,
                        action: MacosPostPersistAction::None,
                    }),
                    released,
                }
            }
        }
    }

    /// Persists one exact successor after the authorized host action has been
    /// positively reconciled.
    pub(crate) fn persist_successor(
        self,
        session: &MacosHelperSession,
        pool: &MacosIdentityPoolObservation,
        transition: MacosLifecycleTransition,
    ) -> MacosJournalAppendOutcome<'store> {
        let expected_head = self.head;
        persist_transition(
            self.lease,
            Some(&expected_head),
            transition,
            TransitionPosition::Successor,
            session,
            pool,
            #[cfg(test)]
            None,
        )
    }
}

struct MacosJournalLease<'store> {
    store: &'store MacosHelperJournalStore,
    account: Dir,
    account_name: String,
    account_identity: PrivateDirectoryIdentity,
    lock: AccountLeaseExclusion,
    lock_identity: ObjectIdentity,
    assigned: MacosAssignedIdentity,
}

/// Holds the account-lease exclusion for exactly as long as the lease lives.
///
/// `flock` exclusion belongs to the open file description rather than to any
/// one descriptor, so closing a descriptor is not the same as releasing the
/// lock: it stays held while any duplicate of that description survives. Every
/// `fork` behind a process spawn duplicates the whole descriptor table, and
/// close-on-exec only clears those copies at `exec`, so a spawn that merely
/// overlaps a lease can carry the exclusion past the lease that owns it and
/// make the next rightful holder fail its acquisition. Unlocking explicitly
/// bounds the exclusion by this value's lifetime, which is the lifetime the
/// holder was promised. This only narrows exclusion to its intended scope: a
/// lock left held past its owner cannot make a refusal safe, only spurious.
struct AccountLeaseExclusion {
    file: File,
}

impl Drop for AccountLeaseExclusion {
    fn drop(&mut self) {
        let _ = flock(&self.file, FlockOperation::Unlock);
    }
}

impl MacosJournalLease<'_> {
    fn validate(
        &self,
        session: &MacosHelperSession,
        pool: &MacosIdentityPoolObservation,
    ) -> Result<(), MacosHelperJournalError> {
        self.store.validate(session, pool)?;
        self.store.layout_for_assigned(&self.assigned)?;
        if validate_private_directory(&self.account, "retained account journal")?
            != self.account_identity
        {
            return Err(MacosHelperJournalError::Layout(
                "retained account journal identity, owner, or mode drifted".into(),
            ));
        }
        let named_account = self
            .store
            .root
            .open_dir_nofollow(&self.account_name)
            .map_err(|error| {
                io_error(
                    "reopen leased account journal",
                    Path::new(&self.account_name),
                    &error,
                )
            })?;
        if validate_private_directory(&named_account, "named account journal")?
            != self.account_identity
        {
            return Err(MacosHelperJournalError::Layout(
                "leased account journal name was replaced".into(),
            ));
        }
        let retained_lock = self.lock.file.metadata().map_err(|error| {
            io_error(
                "inspect retained account lease",
                Path::new(LOCK_NAME),
                &error,
            )
        })?;
        validate_private_file_metadata(Path::new(LOCK_NAME), &retained_lock, 0, Some(0))?;
        if object_identity(&retained_lock) != self.lock_identity {
            return Err(MacosHelperJournalError::Layout(
                "retained account lease identity drifted".into(),
            ));
        }
        let named_lock =
            inspect_named_private_file(&self.account, Path::new(LOCK_NAME), 0, Some(0))?;
        if named_lock.object != self.lock_identity {
            return Err(MacosHelperJournalError::Layout(
                "account lease name was replaced".into(),
            ));
        }
        Ok(())
    }

    fn read_history(
        &self,
        session: &MacosHelperSession,
        pool: &MacosIdentityPoolObservation,
    ) -> Result<Vec<StoredGeneration>, MacosHelperJournalError> {
        self.validate(session, pool)?;
        let admissions = self.store.read_admission_index(session, pool)?;
        let names = entry_names(
            &self.account,
            Path::new(&self.account_name),
            MAX_GENERATIONS_PER_IDENTITY + 2,
        )?;
        if !names.contains(LOCK_NAME) {
            return Err(MacosHelperJournalError::Layout(
                "account journal is missing its fixed lease".into(),
            ));
        }
        let mut numbered = Vec::new();
        for name in names {
            if name == LOCK_NAME {
                continue;
            }
            let generation = parse_generation_name(&name).ok_or_else(|| {
                MacosHelperJournalError::Layout(format!(
                    "account journal contains temporary or unknown entry {name:?}"
                ))
            })?;
            numbered.push((generation, name));
        }
        if numbered.len() > MAX_GENERATIONS_PER_IDENTITY {
            return Err(MacosHelperJournalError::Layout(
                "account generation count exceeds its hard bound".into(),
            ));
        }
        numbered.sort_by_key(|(generation, _)| *generation);

        let mut generations = Vec::with_capacity(numbered.len());
        let mut total_bytes = 0_u64;
        let mut seen_request_digests = BTreeSet::new();
        let mut seen_effects = BTreeSet::new();
        for (index, (number, name)) in numbered.iter().enumerate() {
            let expected = u64::try_from(index)
                .ok()
                .and_then(|index| index.checked_add(1))
                .ok_or_else(|| {
                    MacosHelperJournalError::Generation("generation index overflow".into())
                })?;
            if *number != expected || *name != generation_name(expected) {
                return Err(MacosHelperJournalError::Generation(format!(
                    "generation prefix has a gap or noncanonical name at {expected}"
                )));
            }
            let (bytes, _) =
                read_stable_private_file(&self.account, Path::new(name), MAX_GENERATION_BYTES)?;
            let byte_count = u64::try_from(bytes.len()).map_err(|_| {
                MacosHelperJournalError::Generation("generation byte count exceeds u64".into())
            })?;
            total_bytes = total_bytes.checked_add(byte_count).ok_or_else(|| {
                MacosHelperJournalError::Generation("history byte count overflow".into())
            })?;
            if total_bytes > MAX_IDENTITY_HISTORY_BYTES {
                return Err(MacosHelperJournalError::Generation(
                    "account history exceeds its aggregate hard byte bound".into(),
                ));
            }
            let generation = decode_generation(&bytes)?;
            validate_generation(
                &generation,
                expected,
                generations.last(),
                &self.assigned,
                &self.store.manifest.pool_record_digest,
                session,
                &admissions,
                &mut seen_request_digests,
                &mut seen_effects,
            )?;
            generations.push(generation);
        }
        Ok(generations)
    }
}

fn classify_lease<'store>(
    lease: MacosJournalLease<'store>,
    session: &MacosHelperSession,
    pool: &MacosIdentityPoolObservation,
) -> MacosJournalAcquireOutcome<'store> {
    match lease.read_history(session, pool) {
        Err(cause) => {
            MacosJournalAcquireOutcome::ReconciliationRequired(MacosJournalReconciliationLease {
                lease,
                cause,
            })
        }
        Ok(history) => match history.last().cloned() {
            None => {
                match lease
                    .store
                    .indexed_preparation_for_assigned(session, pool, &lease.assigned)
                {
                    Ok(Some(indexed)) => MacosJournalAcquireOutcome::IndexedPreparationRequired(
                        Box::new(MacosJournalIndexedPreparationLease { lease, indexed }),
                    ),
                    Ok(None) => MacosJournalAcquireOutcome::Ready(MacosJournalReadyLease {
                        lease,
                        head: None,
                    }),
                    Err(cause) => MacosJournalAcquireOutcome::ReconciliationRequired(
                        MacosJournalReconciliationLease { lease, cause },
                    ),
                }
            }
            Some(head) if head.record.state == MacosHelperJournalState::Cleaned => {
                MacosJournalAcquireOutcome::Ready(MacosJournalReadyLease {
                    lease,
                    head: Some(head),
                })
            }
            Some(head) => match recovery_action(&head.record, session) {
                Ok(action) => {
                    MacosJournalAcquireOutcome::RecoveryRequired(MacosJournalRecoveryLease {
                        lease,
                        head,
                        action,
                    })
                }
                Err(error) => MacosJournalAcquireOutcome::ReconciliationRequired(
                    MacosJournalReconciliationLease {
                        lease,
                        cause: MacosHelperJournalError::Generation(error.to_string()),
                    },
                ),
            },
        },
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum TransitionPosition {
    Initial,
    Successor,
}

#[cfg(test)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PersistFaultPoint {
    TempCreated,
    BytesWritten,
    FileSynced,
    Renamed,
    DirectorySynced,
}

#[allow(
    clippy::too_many_arguments,
    reason = "persistence binds the lease, expected prefix, transition, current pool, and test-only durability boundary"
)]
fn persist_transition<'store>(
    lease: MacosJournalLease<'store>,
    expected_head: Option<&StoredGeneration>,
    transition: MacosLifecycleTransition,
    position: TransitionPosition,
    session: &MacosHelperSession,
    pool: &MacosIdentityPoolObservation,
    #[cfg(test)] fault: Option<PersistFaultPoint>,
) -> MacosJournalAppendOutcome<'store> {
    let action = transition.post_persist_action();
    let record = transition.into_record();
    match persist_transition_inner(
        &lease,
        expected_head,
        &record,
        position,
        session,
        pool,
        #[cfg(test)]
        fault,
    ) {
        Ok(head) => MacosJournalAppendOutcome::Durable(Box::new(MacosJournalDurableLease {
            lease,
            head,
            action,
        })),
        Err(cause) => {
            MacosJournalAppendOutcome::ReconciliationRequired(MacosJournalReconciliationLease {
                lease,
                cause,
            })
        }
    }
}

#[allow(
    clippy::too_many_arguments,
    clippy::too_many_lines,
    reason = "the atomic publication path keeps all authority, expected-prefix, and durability boundaries explicit"
)]
fn persist_transition_inner(
    lease: &MacosJournalLease<'_>,
    expected_head: Option<&StoredGeneration>,
    record: &MacosHelperJournalRecord,
    position: TransitionPosition,
    session: &MacosHelperSession,
    pool: &MacosIdentityPoolObservation,
    #[cfg(test)] fault: Option<PersistFaultPoint>,
) -> Result<StoredGeneration, MacosHelperJournalError> {
    let current = lease.read_history(session, pool)?;
    if !same_head(current.last(), expected_head) {
        return Err(MacosHelperJournalError::Generation(
            "immutable generation head changed while the account lease was held".into(),
        ));
    }
    validate_candidate(position, current.last(), record, &lease.assigned, session)?;
    let generation = u64::try_from(current.len())
        .ok()
        .and_then(|length| length.checked_add(1))
        .ok_or_else(|| MacosHelperJournalError::Generation("generation overflow".into()))?;
    if generation > MAX_GENERATIONS_PER_IDENTITY_U64 {
        return Err(MacosHelperJournalError::Generation(
            "account generation count reached its hard bound".into(),
        ));
    }
    let mut stored = StoredGeneration {
        format_version: JOURNAL_FORMAT_VERSION,
        generation,
        previous_generation_digest: current
            .last()
            .map(|generation| generation.generation_digest.clone()),
        pool_record_digest: lease.store.manifest.pool_record_digest.clone(),
        assigned_identity: lease.assigned.clone(),
        record: record.clone(),
        generation_digest: Digest::sha256(&[]),
    };
    stored.generation_digest = stored.computed_digest()?;
    let bytes = stored.canonical_bytes()?;
    let byte_count = u64::try_from(bytes.len()).map_err(|_| {
        MacosHelperJournalError::Generation("canonical generation byte count exceeds u64".into())
    })?;
    if byte_count > MAX_GENERATION_BYTES {
        return Err(MacosHelperJournalError::Generation(
            "canonical generation exceeds its hard byte bound".into(),
        ));
    }
    let final_name = generation_name(generation);
    let temp_name = format!(".{final_name}.tmp");
    let mut file = create_private_file(&lease.account, Path::new(&temp_name))?;
    #[cfg(test)]
    maybe_fault(fault, PersistFaultPoint::TempCreated)?;
    file.write_all(&bytes).map_err(|error| {
        io_error(
            "write temporary journal generation",
            Path::new(&temp_name),
            &error,
        )
    })?;
    #[cfg(test)]
    maybe_fault(fault, PersistFaultPoint::BytesWritten)?;
    file.sync_all().map_err(|error| {
        io_error(
            "sync temporary journal generation",
            Path::new(&temp_name),
            &error,
        )
    })?;
    let metadata = file.metadata().map_err(|error| {
        io_error(
            "inspect synchronized journal generation",
            Path::new(&temp_name),
            &error,
        )
    })?;
    validate_private_file_metadata(
        Path::new(&temp_name),
        &metadata,
        MAX_GENERATION_BYTES,
        Some(byte_count),
    )?;
    #[cfg(test)]
    maybe_fault(fault, PersistFaultPoint::FileSynced)?;
    renameat_with(
        &lease.account,
        Path::new(&temp_name),
        &lease.account,
        Path::new(&final_name),
        RenameFlags::NOREPLACE,
    )
    .map_err(|error| {
        MacosHelperJournalError::Generation(format!(
            "atomic no-replace generation publication is uncertain: {error}"
        ))
    })?;
    #[cfg(test)]
    maybe_fault(fault, PersistFaultPoint::Renamed)?;
    sync_directory(&lease.account).map_err(|error| {
        io_error(
            "sync published journal generation",
            Path::new(&final_name),
            &error,
        )
    })?;
    #[cfg(test)]
    maybe_fault(fault, PersistFaultPoint::DirectorySynced)?;
    drop(file);
    let verified = lease.read_history(session, pool)?;
    let Some(head) = verified.last() else {
        return Err(MacosHelperJournalError::Generation(
            "published generation disappeared during readback".into(),
        ));
    };
    if verified.len() != current.len() + 1 || head != &stored {
        return Err(MacosHelperJournalError::Generation(
            "published generation differs from its exact synchronized bytes".into(),
        ));
    }
    Ok(stored)
}

fn validate_candidate(
    position: TransitionPosition,
    previous: Option<&StoredGeneration>,
    record: &MacosHelperJournalRecord,
    assigned: &MacosAssignedIdentity,
    session: &MacosHelperSession,
) -> Result<(), MacosHelperJournalError> {
    record
        .validate_for_session(session)
        .map_err(|error| MacosHelperJournalError::Generation(error.to_string()))?;
    if record.assigned_identity.as_ref() != Some(assigned) {
        return Err(MacosHelperJournalError::Generation(
            "candidate record differs from the exclusively leased account".into(),
        ));
    }
    match (position, previous) {
        (
            TransitionPosition::Initial,
            None
            | Some(StoredGeneration {
                record:
                    MacosHelperJournalRecord {
                        state: MacosHelperJournalState::Cleaned,
                        ..
                    },
                ..
            }),
        ) if record.state == MacosHelperJournalState::Prepared => Ok(()),
        (TransitionPosition::Successor, Some(previous)) => {
            validate_exact_successor(&previous.record, record)
        }
        _ => Err(MacosHelperJournalError::Generation(
            "candidate is not in the exact initial or successor position".into(),
        )),
    }
}

#[allow(
    clippy::too_many_arguments,
    reason = "generation validation keeps the chain, assigned identity, active session, and replay sets explicit"
)]
fn validate_generation(
    generation: &StoredGeneration,
    expected_number: u64,
    previous: Option<&StoredGeneration>,
    assigned: &MacosAssignedIdentity,
    pool_record_digest: &Digest,
    session: &MacosHelperSession,
    admissions: &[StoredAdmissionIndexEntry],
    seen_request_digests: &mut BTreeSet<String>,
    seen_effects: &mut BTreeSet<(String, String)>,
) -> Result<(), MacosHelperJournalError> {
    if generation.format_version != JOURNAL_FORMAT_VERSION
        || generation.generation != expected_number
        || &generation.pool_record_digest != pool_record_digest
        || &generation.assigned_identity != assigned
        || generation.record.assigned_identity.as_ref() != Some(assigned)
        || generation.generation_digest != generation.computed_digest()?
        || generation.previous_generation_digest.as_ref()
            != previous.map(|generation| &generation.generation_digest)
    {
        return Err(MacosHelperJournalError::Generation(format!(
            "generation {expected_number} has invalid identity, chain, or digest binding"
        )));
    }
    generation
        .record
        .validate_for_session(session)
        .map_err(|error| MacosHelperJournalError::Generation(error.to_string()))?;
    match previous {
        None => {
            if generation.record.state != MacosHelperJournalState::Prepared {
                return Err(MacosHelperJournalError::Generation(
                    "the immutable prefix must begin with Prepared".into(),
                ));
            }
            require_global_admission(generation, admissions)?;
            insert_new_request(generation, seen_request_digests, seen_effects)?;
        }
        Some(previous) if previous.record.state == MacosHelperJournalState::Cleaned => {
            if generation.record.state != MacosHelperJournalState::Prepared {
                return Err(MacosHelperJournalError::Generation(
                    "a cleaned lifecycle may be followed only by a new Prepared request".into(),
                ));
            }
            require_global_admission(generation, admissions)?;
            insert_new_request(generation, seen_request_digests, seen_effects)?;
        }
        Some(previous) => {
            validate_exact_successor(&previous.record, &generation.record)?;
        }
    }
    Ok(())
}

fn require_global_admission(
    generation: &StoredGeneration,
    admissions: &[StoredAdmissionIndexEntry],
) -> Result<(), MacosHelperJournalError> {
    let mut matching = admissions.iter().filter(|entry| {
        entry.request == generation.record.request
            && entry.admission_session == generation.record.admission_session
    });
    let Some(entry) = matching.next() else {
        return Err(MacosHelperJournalError::Generation(
            "initial account generation has no exact pool-global admission fence".into(),
        ));
    };
    if matching.next().is_some() || entry.assigned_identity != generation.assigned_identity {
        return Err(MacosHelperJournalError::Generation(
            "initial account generation is not mapped to exactly one indexed UID".into(),
        ));
    }
    Ok(())
}

fn insert_new_request(
    generation: &StoredGeneration,
    seen_request_digests: &mut BTreeSet<String>,
    seen_effects: &mut BTreeSet<(String, String)>,
) -> Result<(), MacosHelperJournalError> {
    if !seen_request_digests.insert(generation.record.request_digest().as_str().to_owned())
        || !seen_effects.insert((
            generation.record.runner_session_id().to_owned(),
            generation.record.effect_id().to_owned(),
        ))
    {
        return Err(MacosHelperJournalError::Generation(
            "request digest or runner/effect identity was replayed".into(),
        ));
    }
    Ok(())
}

#[allow(
    clippy::too_many_lines,
    reason = "every lifecycle edge is reconstructed through the effect-free transition engine"
)]
fn validate_exact_successor(
    previous: &MacosHelperJournalRecord,
    next: &MacosHelperJournalRecord,
) -> Result<(), MacosHelperJournalError> {
    if previous.admission_session != next.admission_session
        || previous.request != next.request
        || previous.assigned_identity != next.assigned_identity
    {
        return Err(MacosHelperJournalError::Generation(
            "successor changed immutable request or account identity".into(),
        ));
    }
    let reconstructed = match (previous.state, next.state) {
        (MacosHelperJournalState::Prepared, MacosHelperJournalState::CleanupAgentIntended) => {
            intend_cleanup_agent(previous)
        }
        (
            MacosHelperJournalState::CleanupAgentIntended,
            MacosHelperJournalState::LaunchIntended,
        ) => {
            let digest = next.cleanup_agent_digest.clone().ok_or_else(|| {
                MacosHelperJournalError::Generation(
                    "LaunchIntended successor lacks cleanup-agent digest".into(),
                )
            })?;
            record_cleanup_agent(previous, digest)
        }
        (MacosHelperJournalState::LaunchIntended, MacosHelperJournalState::HeldPrepared) => {
            let evidence = next.held_preparation_evidence.clone().ok_or_else(|| {
                MacosHelperJournalError::Generation(
                    "HeldPrepared successor lacks authenticated held evidence".into(),
                )
            })?;
            let evidence_session = evidence.authenticated_session.clone();
            record_held_launcher(previous, &evidence_session, evidence)
        }
        (MacosHelperJournalState::HeldPrepared, MacosHelperJournalState::ReleaseIntended) => {
            let authorization = next.release_authorization.clone().ok_or_else(|| {
                MacosHelperJournalError::Generation(
                    "ReleaseIntended successor lacks outer release authorization".into(),
                )
            })?;
            reconstruct_launcher_release_intent(previous, authorization)
        }
        (MacosHelperJournalState::ReleaseIntended, MacosHelperJournalState::Released) => {
            let evidence = next.release_evidence.clone().ok_or_else(|| {
                MacosHelperJournalError::Generation(
                    "Released successor lacks authenticated release evidence".into(),
                )
            })?;
            let evidence_session = evidence.authenticated_session.clone();
            record_launcher_released(previous, &evidence_session, evidence)
        }
        (
            MacosHelperJournalState::LaunchIntended
            | MacosHelperJournalState::HeldPrepared
            | MacosHelperJournalState::ReleaseIntended
            | MacosHelperJournalState::Released,
            MacosHelperJournalState::Cleaning,
        ) => {
            let reason = next.termination_reason.ok_or_else(|| {
                MacosHelperJournalError::Generation(
                    "Cleaning successor lacks a termination reason".into(),
                )
            })?;
            begin_cleaning(previous, reason)
        }
        (MacosHelperJournalState::Cleaning, MacosHelperJournalState::EmptyProven) => {
            if next.observations.len() != previous.observations.len() + 2
                || next.observations[..previous.observations.len()] != previous.observations
            {
                return Err(MacosHelperJournalError::Generation(
                    "EmptyProven successor changed the observation prefix".into(),
                ));
            }
            let observations = [
                next.observations[previous.observations.len()].clone(),
                next.observations[previous.observations.len() + 1].clone(),
            ];
            record_empty_domain(previous, observations)
        }
        (MacosHelperJournalState::EmptyProven, MacosHelperJournalState::Cleaned) => {
            record_identity_released(previous)
        }
        _ => {
            return Err(MacosHelperJournalError::Generation(
                "generation skipped, repeated, or followed a terminal lifecycle state".into(),
            ));
        }
    }
    .map_err(|error| MacosHelperJournalError::Generation(error.to_string()))?;
    if reconstructed.record() != next {
        return Err(MacosHelperJournalError::Generation(
            "successor fields differ from the exact lifecycle transition".into(),
        ));
    }
    Ok(())
}

fn same_head(left: Option<&StoredGeneration>, right: Option<&StoredGeneration>) -> bool {
    match (left, right) {
        (None, None) => true,
        (Some(left), Some(right)) => {
            left.generation == right.generation
                && left.generation_digest == right.generation_digest
                && left == right
        }
        _ => false,
    }
}

fn validate_pool(
    session: &MacosHelperSession,
    pool: &MacosIdentityPoolObservation,
) -> Result<(), MacosHelperJournalError> {
    pool.validate_for_session(session)
        .map_err(|error| MacosHelperJournalError::Pool(error.to_string()))
}

fn acquire_bounded_exclusive_lock(lock: &File) -> Result<(), MacosHelperJournalError> {
    let deadline = Instant::now() + GLOBAL_LOCK_WAIT;
    loop {
        match flock(lock, FlockOperation::NonBlockingLockExclusive) {
            Ok(()) => return Ok(()),
            Err(error)
                if (error == rustix::io::Errno::WOULDBLOCK
                    || error == rustix::io::Errno::AGAIN)
                    && Instant::now() < deadline =>
            {
                thread::sleep(GLOBAL_LOCK_POLL);
            }
            Err(error) => {
                return Err(MacosHelperJournalError::Lock(format!(
                    "pool-global admission lock was unavailable within its bounded wait: {error}"
                )));
            }
        }
    }
}

fn admission_identity_collides(
    left: &MacosHelperLaunchRequest,
    right: &MacosHelperLaunchRequest,
) -> bool {
    left.request_digest == right.request_digest
        || left.preparation.attempt_id == right.preparation.attempt_id
        || left.preparation.launch_id == right.preparation.launch_id
        || left.preparation.cleanup_effect_id == right.preparation.cleanup_effect_id
        || left.preparation.native_journal_id == right.preparation.native_journal_id
        || (left.runner_session_id == right.runner_session_id && left.effect_id == right.effect_id)
}

#[allow(
    clippy::too_many_lines,
    reason = "the append-only global replay fence validates every chain and uniqueness dimension in one pass"
)]
fn decode_admission_index(
    bytes: &[u8],
    manifest: &StoredPoolManifest,
    session: &MacosHelperSession,
    pool: &MacosIdentityPoolObservation,
) -> Result<Vec<StoredAdmissionIndexEntry>, MacosHelperJournalError> {
    if bytes.len() > usize::try_from(MAX_ADMISSION_INDEX_BYTES).unwrap_or(usize::MAX) {
        return Err(MacosHelperJournalError::Generation(
            "admission-index exceeds its aggregate hard byte bound".into(),
        ));
    }
    if !bytes.is_empty() && !bytes.ends_with(b"\n") {
        return Err(MacosHelperJournalError::Generation(
            "admission-index has a torn or noncanonical final entry".into(),
        ));
    }
    let mut entries = Vec::new();
    let mut seen_requests = BTreeSet::new();
    let mut seen_attempts = BTreeSet::new();
    let mut seen_launches = BTreeSet::new();
    let mut seen_cleanup_effects = BTreeSet::new();
    let mut seen_native_journals = BTreeSet::new();
    let mut seen_runner_effects = BTreeSet::new();
    let body = bytes.strip_suffix(b"\n").unwrap_or(bytes);
    if body.is_empty() {
        return Ok(entries);
    }
    for line in body.split(|byte| *byte == b'\n') {
        if line.is_empty() || line.len() > MAX_ADMISSION_ENTRY_BYTES {
            return Err(MacosHelperJournalError::Generation(
                "admission-index contains an empty or oversized entry".into(),
            ));
        }
        if entries.len() >= MAX_ADMISSION_ENTRIES {
            return Err(MacosHelperJournalError::Generation(
                "admission-index exceeds its entry bound".into(),
            ));
        }
        let entry: StoredAdmissionIndexEntry = serde_json::from_slice(line).map_err(|error| {
            MacosHelperJournalError::Generation(format!(
                "admission-index entry decoding failed: {error}"
            ))
        })?;
        let sequence = u64::try_from(entries.len())
            .ok()
            .and_then(|value| value.checked_add(1))
            .ok_or_else(|| {
                MacosHelperJournalError::Generation("admission-index sequence overflow".into())
            })?;
        let previous = entries
            .last()
            .map(|entry: &StoredAdmissionIndexEntry| &entry.entry_digest);
        entry.admission_session.validate().map_err(|error| {
            MacosHelperJournalError::Generation(format!(
                "admission-index session failed validation: {error}"
            ))
        })?;
        entry.request.validate_retained().map_err(|error| {
            MacosHelperJournalError::Generation(format!(
                "admission-index request failed validation: {error}"
            ))
        })?;
        entry
            .request
            .validate_archived_session_binding(&entry.admission_session)
            .map_err(|error| MacosHelperJournalError::Generation(error.to_string()))?;
        entry
            .initial_record
            .validate_for_session(session)
            .map_err(|error| MacosHelperJournalError::Generation(error.to_string()))?;
        let matching_identity = manifest.records.iter().any(|record| {
            record.account_name == entry.assigned_identity.account_name
                && record.uid == entry.assigned_identity.uid
                && record.gid == entry.assigned_identity.gid
                && record.record_digest == entry.assigned_identity.account_record_digest
        });
        if entry.format_version != JOURNAL_FORMAT_VERSION
            || entry.sequence != sequence
            || entry.previous_entry_digest.as_ref() != previous
            || entry.pool_record_digest != manifest.pool_record_digest
            || entry.pool_record_digest != pool.pool_record_digest
            || !entry.admission_session.same_durable_authority(session)
            || !matching_identity
            || entry.initial_record.state != MacosHelperJournalState::Prepared
            || entry.initial_record.admission_session != entry.admission_session
            || entry.initial_record.request != entry.request
            || entry.initial_record.assigned_identity.as_ref() != Some(&entry.assigned_identity)
            || entry.entry_digest != entry.computed_digest()?
            || entry.canonical_bytes()? != line
        {
            return Err(MacosHelperJournalError::Generation(format!(
                "admission-index entry {sequence} has invalid authority, chain, account, or canonical bytes"
            )));
        }
        let preparation = &entry.request.preparation;
        if !seen_requests.insert(entry.request.request_digest.as_str().to_owned())
            || !seen_attempts.insert(preparation.attempt_id.clone())
            || !seen_launches.insert(preparation.launch_id.clone())
            || !seen_cleanup_effects.insert(preparation.cleanup_effect_id.clone())
            || !seen_native_journals.insert(preparation.native_journal_id.clone())
            || !seen_runner_effects.insert((
                entry.request.runner_session_id.clone(),
                entry.request.effect_id.clone(),
            ))
        {
            return Err(MacosHelperJournalError::Generation(
                "admission-index reuses a request, attempt, launch, journal, or runner/effect identity"
                    .into(),
            ));
        }
        entries.push(entry);
    }
    Ok(entries)
}

fn decode_manifest(bytes: &[u8]) -> Result<StoredPoolManifest, MacosHelperJournalError> {
    let manifest: StoredPoolManifest = serde_json::from_slice(bytes).map_err(|error| {
        MacosHelperJournalError::Layout(format!("pool manifest decoding failed: {error}"))
    })?;
    if manifest.format_version != JOURNAL_FORMAT_VERSION
        || manifest.manifest_digest != manifest.computed_digest()?
        || manifest.canonical_bytes()? != bytes
    {
        return Err(MacosHelperJournalError::Layout(
            "pool manifest is noncanonical or digest-mismatched".into(),
        ));
    }
    Ok(manifest)
}

fn decode_generation(bytes: &[u8]) -> Result<StoredGeneration, MacosHelperJournalError> {
    let generation: StoredGeneration = serde_json::from_slice(bytes).map_err(|error| {
        MacosHelperJournalError::Generation(format!("generation decoding failed: {error}"))
    })?;
    if generation.canonical_bytes()? != bytes {
        return Err(MacosHelperJournalError::Generation(
            "generation bytes are not the unique canonical encoding".into(),
        ));
    }
    Ok(generation)
}

fn account_directory_name(uid: u32) -> String {
    format!("{ACCOUNT_PREFIX}{uid:010}")
}

fn generation_name(generation: u64) -> String {
    format!("{GENERATION_PREFIX}{generation:0GENERATION_DIGITS$}{GENERATION_SUFFIX}")
}

fn parse_generation_name(name: &str) -> Option<u64> {
    let digits = name
        .strip_prefix(GENERATION_PREFIX)?
        .strip_suffix(GENERATION_SUFFIX)?;
    if digits.len() != GENERATION_DIGITS || !digits.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    digits.parse().ok()
}

fn create_private_file(directory: &Dir, name: &Path) -> Result<File, MacosHelperJournalError> {
    let mut options = OpenOptions::new();
    options
        .read(true)
        .write(true)
        .create_new(true)
        .mode(0o600)
        .follow(FollowSymlinks::No);
    let file = directory
        .open_with(name, &options)
        .map_err(|error| io_error("create owner-private journal file", name, &error))?;
    file.set_permissions(Permissions::from_mode(0o600))
        .map_err(|error| io_error("set owner-private journal-file mode", name, &error))?;
    Ok(file)
}

fn validate_private_directory(
    directory: &Dir,
    label: &str,
) -> Result<PrivateDirectoryIdentity, MacosHelperJournalError> {
    let metadata = directory
        .dir_metadata()
        .map_err(|error| MacosHelperJournalError::Root(format!("inspect {label}: {error}")))?;
    let uid = OsMetadataExt::uid(&metadata);
    let mode = OsMetadataExt::mode(&metadata) & 0o777;
    if !metadata.is_dir() || uid != rustix::process::geteuid().as_raw() || mode != 0o700 {
        return Err(MacosHelperJournalError::Root(format!(
            "{label} must be a real effective-user-owned directory with mode 0700"
        )));
    }
    Ok(PrivateDirectoryIdentity {
        object: object_identity(&metadata),
        uid,
        mode,
    })
}

fn inspect_named_private_file(
    directory: &Dir,
    name: &Path,
    limit: u64,
    exact_length: Option<u64>,
) -> Result<FileFingerprint, MacosHelperJournalError> {
    let named = directory.symlink_metadata(name).map_err(|error| {
        io_error(
            "inspect owner-private journal file without links",
            name,
            &error,
        )
    })?;
    validate_private_file_metadata(name, &named, limit, exact_length)?;
    let mut options = OpenOptions::new();
    options.read(true).follow(FollowSymlinks::No);
    let opened = directory
        .open_with(name, &options)
        .map_err(|error| io_error("open owner-private journal file", name, &error))?;
    let descriptor = opened
        .metadata()
        .map_err(|error| io_error("inspect owner-private file descriptor", name, &error))?;
    validate_private_file_metadata(name, &descriptor, limit, exact_length)?;
    let named_fingerprint = file_fingerprint(&named);
    let descriptor_fingerprint = file_fingerprint(&descriptor);
    if named_fingerprint != descriptor_fingerprint {
        return Err(MacosHelperJournalError::Layout(format!(
            "journal file {} changed while it was opened",
            name.display()
        )));
    }
    Ok(descriptor_fingerprint)
}

fn read_stable_private_file(
    directory: &Dir,
    name: &Path,
    limit: u64,
) -> Result<(Vec<u8>, FileFingerprint), MacosHelperJournalError> {
    let named_before = directory
        .symlink_metadata(name)
        .map_err(|error| io_error("inspect immutable journal file without links", name, &error))?;
    validate_private_file_metadata(name, &named_before, limit, None)?;
    let mut options = OpenOptions::new();
    options.read(true).follow(FollowSymlinks::No);
    let mut file = directory
        .open_with(name, &options)
        .map_err(|error| io_error("open immutable journal file", name, &error))?;
    let descriptor_before = file
        .metadata()
        .map_err(|error| io_error("inspect immutable journal descriptor", name, &error))?;
    validate_private_file_metadata(name, &descriptor_before, limit, None)?;
    let before = file_fingerprint(&descriptor_before);
    if file_fingerprint(&named_before) != before {
        return Err(MacosHelperJournalError::Layout(format!(
            "immutable journal file {} changed during open",
            name.display()
        )));
    }
    let first = read_bounded(&mut file, name, limit)?;
    file.seek(SeekFrom::Start(0))
        .map_err(|error| io_error("rewind immutable journal file", name, &error))?;
    let second = read_bounded(&mut file, name, limit)?;
    let descriptor_after = file
        .metadata()
        .map_err(|error| io_error("reinspect immutable journal descriptor", name, &error))?;
    validate_private_file_metadata(name, &descriptor_after, limit, None)?;
    let named_after = directory.symlink_metadata(name).map_err(|error| {
        io_error(
            "reinspect immutable journal name without links",
            name,
            &error,
        )
    })?;
    validate_private_file_metadata(name, &named_after, limit, None)?;
    let after = file_fingerprint(&descriptor_after);
    if first != second
        || before != after
        || before != file_fingerprint(&named_after)
        || u64::try_from(first.len()) != Ok(before.length)
    {
        return Err(MacosHelperJournalError::Layout(format!(
            "immutable journal file {} changed during stable read",
            name.display()
        )));
    }
    Ok((first, before))
}

fn validate_private_file_metadata(
    name: &Path,
    metadata: &Metadata,
    limit: u64,
    exact_length: Option<u64>,
) -> Result<(), MacosHelperJournalError> {
    let length = metadata.len();
    if !metadata.is_file()
        || PortableMetadataExt::nlink(metadata) != 1
        || OsMetadataExt::uid(metadata) != rustix::process::geteuid().as_raw()
        || OsMetadataExt::mode(metadata) & 0o777 != 0o600
        || length > limit
        || exact_length.is_some_and(|expected| length != expected)
    {
        return Err(MacosHelperJournalError::Layout(format!(
            "{} is not a singly-linked effective-user-owned regular file with mode 0600 and the required bound",
            name.display()
        )));
    }
    Ok(())
}

fn object_identity(metadata: &Metadata) -> ObjectIdentity {
    ObjectIdentity {
        device: PortableMetadataExt::dev(metadata),
        inode: PortableMetadataExt::ino(metadata),
    }
}

fn file_fingerprint(metadata: &Metadata) -> FileFingerprint {
    FileFingerprint {
        object: object_identity(metadata),
        links: PortableMetadataExt::nlink(metadata),
        length: metadata.len(),
        uid: OsMetadataExt::uid(metadata),
        mode: OsMetadataExt::mode(metadata),
        modified_seconds: OsMetadataExt::mtime(metadata),
        modified_nanoseconds: OsMetadataExt::mtime_nsec(metadata),
        changed_seconds: OsMetadataExt::ctime(metadata),
        changed_nanoseconds: OsMetadataExt::ctime_nsec(metadata),
    }
}

fn entry_names(
    directory: &Dir,
    label: impl AsRef<Path>,
    limit: usize,
) -> Result<BTreeSet<String>, MacosHelperJournalError> {
    let label = label.as_ref();
    let mut names = BTreeSet::new();
    for entry in directory
        .entries()
        .map_err(|error| io_error("enumerate helper-journal directory", label, &error))?
    {
        if names.len() >= limit {
            return Err(MacosHelperJournalError::Layout(format!(
                "journal directory {} exceeds its entry bound",
                label.display()
            )));
        }
        let entry = entry
            .map_err(|error| io_error("read helper-journal directory entry", label, &error))?;
        let name = entry.file_name().into_string().map_err(|_| {
            MacosHelperJournalError::Layout(format!(
                "journal directory {} contains a non-UTF-8 entry name",
                label.display()
            ))
        })?;
        if !names.insert(name) {
            return Err(MacosHelperJournalError::Layout(format!(
                "journal directory {} contains duplicate names",
                label.display()
            )));
        }
    }
    Ok(names)
}

fn read_bounded(
    file: &mut File,
    name: &Path,
    limit: u64,
) -> Result<Vec<u8>, MacosHelperJournalError> {
    let mut bytes = Vec::new();
    file.take(limit.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|error| io_error("read immutable journal file", name, &error))?;
    if u64::try_from(bytes.len()).map_or(true, |length| length > limit) {
        return Err(MacosHelperJournalError::Layout(format!(
            "journal file {} exceeds its hard byte bound",
            name.display()
        )));
    }
    Ok(bytes)
}

fn io_error(operation: &'static str, path: &Path, error: &impl Display) -> MacosHelperJournalError {
    MacosHelperJournalError::Io {
        operation,
        path: path.to_path_buf(),
        message: error.to_string(),
    }
}

#[cfg(test)]
fn maybe_fault(
    actual: Option<PersistFaultPoint>,
    expected: PersistFaultPoint,
) -> Result<(), MacosHelperJournalError> {
    if actual == Some(expected) {
        return Err(MacosHelperJournalError::InjectedFault(match expected {
            PersistFaultPoint::TempCreated => "temporary-file creation",
            PersistFaultPoint::BytesWritten => "generation write",
            PersistFaultPoint::FileSynced => "generation file sync",
            PersistFaultPoint::Renamed => "generation rename",
            PersistFaultPoint::DirectorySynced => "account-directory sync",
        }));
    }
    Ok(())
}

#[cfg(test)]
mod tests;
