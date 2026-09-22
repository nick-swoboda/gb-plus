//! Immutable, capability-bound transfer bundles between worker and applier runners.
//!
//! Staged file bytes never cross the bounded runner wire frame. A worker writes
//! one content-addressed bundle below the already-acquired private-state root,
//! and an independently initialized applier reopens that same root and verifies
//! the bundle reference, canonical manifest, directory contents, file identities,
//! modes, lengths, and content digests before constructing a [`StagedChangeSet`].

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsString;
use std::fmt::{self, Display, Formatter};
use std::fs;
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use cap_fs_ext::{
    DirExt, FollowSymlinks, MetadataExt as PortableMetadataExt, OpenOptionsFollowExt, OsMetadataExt,
};
use cap_std::fs::{
    Dir, DirBuilder, DirBuilderExt, File, Metadata, OpenOptions, OpenOptionsExt, PermissionsExt,
};
use cap_std::{ambient_authority, fs::Permissions};
use grok_build_core::{ChangeSet, Digest, FileOperation, TaskIntegrationArtifactReference};
use rustix::fs::{RenameFlags, renameat_with};
use serde::{Deserialize, Serialize};

use crate::StagedChangeSet;
use crate::capability_apply::DirectoryPathAnchor;
use crate::durable_directory::sync_directory_entries as sync_directory;

const BUNDLE_FORMAT_VERSION: u32 = 1;
const BUNDLE_DIGEST_DOMAIN: &[u8] = b"grok-build/stage-bundle/v1\0";
const MANIFEST_FILE: &str = "manifest.json";
const BUNDLE_PREFIX: &str = "stage-";
const TEMP_PREFIX: &str = ".stage-tmp-";
const MAX_MANIFEST_BYTES: u64 = 16 * 1024 * 1024;
const MAX_STAGE_FILE_BYTES: u64 = 16 * 1024 * 1024;
/// v0.1 deliberately keeps the in-memory worker/applier handoff below 64 MiB.
/// A later streaming applier may raise this only with an explicit sprint budget.
const MAX_STAGE_TOTAL_BYTES: u64 = 64 * 1024 * 1024;
const MAX_STAGE_OPERATIONS: usize = 4_096;
const MAX_STAGE_BLOBS: usize = 4_096;
const MAX_CHANGE_SET_ID_BYTES: usize = 256;
const MAX_RELATIVE_PATH_BYTES: usize = 4_096;
const TEMP_ATTEMPTS: usize = 128;

static NEXT_TEMP: AtomicU64 = AtomicU64::new(0);

/// Digest-bound identity for one immutable staged change bundle.
///
/// The reference contains no filesystem path. Both runner roles derive the
/// only admissible bundle location from their fixed private-state capability.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct StageBundleReference {
    /// On-disk bundle format version.
    pub format_version: u32,
    /// SHA-256 over the domain-separated canonical bundle manifest.
    pub bundle_digest: Digest,
    /// Exact change-set identity stored in the bundle.
    pub change_set_id: String,
    /// Exact live snapshot against which the change set was staged.
    pub base_snapshot: Digest,
    /// Exact snapshot produced by the staged operations.
    pub result_snapshot: Digest,
}

impl StageBundleReference {
    pub(crate) fn validate(&self) -> Result<(), StageBundleError> {
        if self.format_version != BUNDLE_FORMAT_VERSION {
            return Err(StageBundleError::Reference(format!(
                "unsupported stage-bundle version {}",
                self.format_version
            )));
        }
        validate_identifier("change_set_id", &self.change_set_id)?;
        Ok(())
    }

    fn directory_name(&self) -> String {
        format!("{BUNDLE_PREFIX}{}", self.bundle_digest)
    }

    /// Converts this exact runner-owned bundle identity into the path-free
    /// core artifact reference persisted with task-integration evidence.
    ///
    /// # Errors
    ///
    /// Returns an error unless this is a valid v1 stage-bundle reference and
    /// the mapped core artifact contract independently validates.
    pub fn to_core_integration_artifact(
        &self,
    ) -> Result<TaskIntegrationArtifactReference, StageBundleError> {
        self.validate()?;
        let artifact = TaskIntegrationArtifactReference {
            format_version: self.format_version,
            artifact_digest: self.bundle_digest.clone(),
            change_set_id: self.change_set_id.clone(),
            base_snapshot: self.base_snapshot.clone(),
            result_snapshot: self.result_snapshot.clone(),
        };
        artifact.validate().map_err(|error| {
            StageBundleError::Reference(format!(
                "mapped core integration artifact is invalid: {error}"
            ))
        })?;
        Ok(artifact)
    }
}

impl TryFrom<&TaskIntegrationArtifactReference> for StageBundleReference {
    type Error = StageBundleError;

    fn try_from(artifact: &TaskIntegrationArtifactReference) -> Result<Self, Self::Error> {
        artifact.validate().map_err(|error| {
            StageBundleError::Reference(format!("core integration artifact is invalid: {error}"))
        })?;
        let reference = Self {
            format_version: artifact.format_version,
            bundle_digest: artifact.artifact_digest.clone(),
            change_set_id: artifact.change_set_id.clone(),
            base_snapshot: artifact.base_snapshot.clone(),
            result_snapshot: artifact.result_snapshot.clone(),
        };
        reference.validate()?;
        Ok(reference)
    }
}

/// Fail-closed stage-bundle persistence or verification error.
#[derive(Debug)]
pub enum StageBundleError {
    /// The private-state root was not exact, owner-private, or identity-stable.
    Root(String),
    /// The typed reference was malformed or did not match stored content.
    Reference(String),
    /// The canonical bundle manifest was malformed, oversized, or corrupt.
    Manifest(String),
    /// A change-set operation or path was outside the supported file model.
    ChangeSet(String),
    /// A required blob was absent, unsafe, oversized, or digest-mismatched.
    Blob(String),
    /// Publication may have taken effect and must be reconciled by reference.
    ReconciliationRequired {
        /// Exact typed bundle identity whose final name may now exist.
        reference: Box<StageBundleReference>,
        /// Failed post-syscall proof.
        reason: String,
    },
    /// A descriptor-relative filesystem operation failed.
    Io {
        /// Failed operation.
        operation: &'static str,
        /// Redacted path relative to the private-state root.
        path: PathBuf,
        /// Operating-system error text.
        message: String,
    },
}

impl Display for StageBundleError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Root(message) => write!(formatter, "stage-bundle root rejected: {message}"),
            Self::Reference(message) => {
                write!(formatter, "stage-bundle reference rejected: {message}")
            }
            Self::Manifest(message) => {
                write!(formatter, "stage-bundle manifest rejected: {message}")
            }
            Self::ChangeSet(message) => write!(formatter, "stage change set rejected: {message}"),
            Self::Blob(message) => write!(formatter, "stage-bundle blob rejected: {message}"),
            Self::ReconciliationRequired { reference, reason } => write!(
                formatter,
                "stage bundle {} requires reconciliation: {reason}",
                reference.bundle_digest
            ),
            Self::Io {
                operation,
                path,
                message,
            } => write!(
                formatter,
                "{operation} failed for private stage path {}: {message}",
                path.display()
            ),
        }
    }
}

impl std::error::Error for StageBundleError {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
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

/// An exact retained capability for the owner-private stage-bundle store.
pub struct CapabilityStageBundleStore {
    root: Dir,
    root_parent: Dir,
    root_leaf: OsString,
    root_identity: PrivateDirectoryIdentity,
    path_anchor: DirectoryPathAnchor,
    root_path: PathBuf,
}

impl CapabilityStageBundleStore {
    /// Opens an existing canonical, owner-owned `0700` private-state root.
    ///
    /// # Errors
    ///
    /// Returns an error for a non-absolute/non-canonical path, a link, wrong
    /// ownership or mode, replacement during acquisition, or I/O failure.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, StageBundleError> {
        let path = path.as_ref();
        if !path.is_absolute() {
            return Err(StageBundleError::Root(
                "private-state root must be absolute".into(),
            ));
        }
        let canonical = fs::canonicalize(path)
            .map_err(|error| io_error("canonicalize private-state root", Path::new("."), &error))?;
        if canonical != path {
            return Err(StageBundleError::Root(
                "private-state root must use its exact canonical path".into(),
            ));
        }
        let parent_path = canonical
            .parent()
            .ok_or_else(|| StageBundleError::Root("private-state root has no parent".into()))?;
        let root_leaf = canonical
            .file_name()
            .ok_or_else(|| StageBundleError::Root("private-state root has no leaf".into()))?
            .to_os_string();
        let root_parent = Dir::open_ambient_dir(parent_path, ambient_authority())
            .map_err(|error| io_error("open private-state parent", Path::new("."), &error))?;
        let root = root_parent.open_dir_nofollow(&root_leaf).map_err(|error| {
            io_error(
                "open private-state root without links",
                Path::new("."),
                &error,
            )
        })?;
        let root_identity = validate_private_directory(&root, "private-state root")?;
        let path_anchor = DirectoryPathAnchor::acquire(&canonical, "stage-bundle store")
            .map_err(|error| StageBundleError::Root(error.to_string()))?;
        if path_anchor.final_device_inode()
            != (root_identity.object.device, root_identity.object.inode)
        {
            return Err(StageBundleError::Root(
                "private-state path anchor differs from the retained store descriptor".into(),
            ));
        }
        let store = Self {
            root,
            root_parent,
            root_leaf,
            root_identity,
            path_anchor,
            root_path: canonical,
        };
        store.validate_root()?;
        Ok(store)
    }

    /// Returns the fixed canonical private-state root.
    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root_path
    }

    /// Clones the already-acquired private-state capability for the dormant
    /// aggregate-composer journal. The clone is returned only after the full
    /// retained and named store authority has been revalidated.
    #[allow(
        dead_code,
        reason = "the aggregate composer remains dormant until schema-v32 core authority can mint its role seal"
    )]
    pub(crate) fn clone_composer_store_capability(&self) -> Result<Dir, StageBundleError> {
        self.validate_root()?;
        self.root.try_clone().map_err(|error| {
            io_error(
                "clone retained aggregate-composer store",
                &self.root_path,
                &error,
            )
        })
    }

    /// Revalidates the retained and fully anchored private-state capability at
    /// the dormant aggregate-composer effect boundary.
    #[allow(
        dead_code,
        reason = "the aggregate composer remains dormant until schema-v32 core authority can mint its role seal"
    )]
    pub(crate) fn validate_composer_store_capability(&self) -> Result<(), StageBundleError> {
        self.validate_root()
    }

    /// Computes the exact immutable reference that [`Self::persist`] will
    /// publish for a validated staged change set, without touching the store.
    ///
    /// The calculation uses the same canonical manifest construction as the
    /// publication path, so a caller can durably authorize one exact bundle
    /// before any publishing syscall is attempted.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid or oversized staged data, unsupported
    /// paths or operations, or canonical manifest serialization failure.
    pub fn preview(staged: &StagedChangeSet) -> Result<StageBundleReference, StageBundleError> {
        prepare_bundle(staged).map(|(_, _, reference)| reference)
    }

    /// Persists an immutable staged change set and returns its path-free reference.
    ///
    /// An existing bundle with the same digest is accepted only after complete
    /// verification. A new bundle becomes visible through one no-replace atomic
    /// directory rename after every file and directory has been synchronized.
    ///
    /// # Errors
    ///
    /// Returns an error for stale root authority, invalid or oversized staged
    /// data, an unsafe existing bundle, ambiguous rename, or failed durability.
    pub fn persist(
        &self,
        staged: &StagedChangeSet,
    ) -> Result<StageBundleReference, StageBundleError> {
        self.persist_with_post_publish_probe(staged, || Ok(()))
    }

    fn persist_with_post_publish_probe(
        &self,
        staged: &StagedChangeSet,
        post_publish_probe: impl FnOnce() -> Result<(), String>,
    ) -> Result<StageBundleReference, StageBundleError> {
        self.validate_root()?;
        let (stored, manifest, reference) = prepare_bundle(staged)?;
        let target_name = reference.directory_name();

        match self.root.open_dir_nofollow(&target_name) {
            Ok(_) => return self.load(&reference).map(|_| reference),
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(io_error(
                    "inspect existing stage bundle",
                    Path::new(&target_name),
                    &error,
                ));
            }
        }

        let (temp_name, temp, temp_identity) = self.create_temp_directory()?;
        let write_result = Self::write_temp_bundle(&temp, &stored, &manifest, staged);
        if let Err(error) = write_result {
            drop(temp);
            let _ = self.remove_owned_temp(&temp_name, temp_identity);
            return Err(error);
        }
        if let Err(error) = sync_directory(&temp) {
            drop(temp);
            let _ = self.remove_owned_temp(&temp_name, temp_identity);
            return Err(io_error(
                "sync staged temporary bundle",
                Path::new(&temp_name),
                &error,
            ));
        }

        match renameat_with(
            &self.root,
            Path::new(&temp_name),
            &self.root,
            Path::new(&target_name),
            RenameFlags::NOREPLACE,
        ) {
            Ok(()) => {
                let proof = sync_directory(&self.root)
                    .map_err(|error| format!("published-name directory sync failed: {error}"))
                    .and_then(|()| {
                        self.root
                            .open_dir_nofollow(&target_name)
                            .map_err(|error| format!("cannot reopen published name: {error}"))
                    })
                    .and_then(|named| {
                        validate_private_directory(&named, "published stage bundle")
                            .map_err(|error| error.to_string())
                    })
                    .and_then(|identity| {
                        if identity == temp_identity {
                            Ok(())
                        } else {
                            Err("published name does not identify the written directory".into())
                        }
                    })
                    .and_then(|()| post_publish_probe());
                if let Err(reason) = proof {
                    return Err(StageBundleError::ReconciliationRequired {
                        reference: Box::new(reference),
                        reason,
                    });
                }
            }
            Err(error) if error == rustix::io::Errno::EXIST => {
                drop(temp);
                self.remove_owned_temp(&temp_name, temp_identity)?;
            }
            Err(error) => {
                return Err(StageBundleError::ReconciliationRequired {
                    reference: Box::new(reference),
                    reason: format!("atomic directory publication could not be proven: {error}"),
                });
            }
        }
        self.validate_root()?;
        self.load(&reference).map(|_| reference)
    }

    /// Reconciles an uncertain publication by reopening and completely
    /// verifying the exact expected immutable bundle.
    ///
    /// This method never creates, renames, or removes an entry. It verifies the
    /// expected bundle, synchronizes the retained namespace to close an
    /// uncertain post-rename durability window, and verifies the bundle again.
    /// Success therefore proves that the expected final name contains the
    /// exact canonical bundle; absence, failed durability, or corruption
    /// remains a typed error and cannot be mistaken for publication.
    ///
    /// # Errors
    ///
    /// Returns an error for a stale store authority, malformed reference,
    /// absent bundle, or any incomplete, unsafe, or corrupt stored content.
    pub fn reconcile(
        &self,
        expected: &StageBundleReference,
    ) -> Result<StageBundleReference, StageBundleError> {
        self.load(expected)?;
        sync_directory(&self.root).map_err(|error| StageBundleError::ReconciliationRequired {
            reference: Box::new(expected.clone()),
            reason: format!("reconciled stage-bundle namespace sync failed: {error}"),
        })?;
        self.load(expected)?;
        Ok(expected.clone())
    }

    /// Reopens and completely verifies a referenced immutable staged bundle.
    ///
    /// # Errors
    ///
    /// Returns an error for a stale root, invalid reference, unsafe bundle
    /// directory, non-canonical manifest, unexpected entry, corrupt blob, or
    /// mismatch between the reference and reconstructed change set.
    pub fn load(
        &self,
        reference: &StageBundleReference,
    ) -> Result<StagedChangeSet, StageBundleError> {
        self.validate_root()?;
        reference.validate()?;
        let directory_name = reference.directory_name();
        let directory = self
            .root
            .open_dir_nofollow(&directory_name)
            .map_err(|error| {
                io_error(
                    "open referenced stage bundle",
                    Path::new(&directory_name),
                    &error,
                )
            })?;
        let identity = validate_private_directory(&directory, "stage bundle")?;
        let manifest = read_private_file(&directory, Path::new(MANIFEST_FILE), MAX_MANIFEST_BYTES)?;
        if bundle_digest(&manifest) != reference.bundle_digest {
            return Err(StageBundleError::Reference(
                "manifest digest does not match the typed bundle reference".into(),
            ));
        }
        let stored: StoredBundle = serde_json::from_slice(&manifest)
            .map_err(|error| StageBundleError::Manifest(error.to_string()))?;
        if canonical_manifest(&stored)? != manifest {
            return Err(StageBundleError::Manifest(
                "manifest is not the exact canonical JSON encoding".into(),
            ));
        }
        stored.validate()?;

        let mut expected_names = BTreeSet::from([MANIFEST_FILE.to_string()]);
        let mut blobs = BTreeMap::new();
        let mut total = 0_u64;
        if stored.blobs.len() > MAX_STAGE_BLOBS {
            return Err(StageBundleError::Blob(format!(
                "blob count exceeds {MAX_STAGE_BLOBS}"
            )));
        }
        for blob in &stored.blobs {
            let name = blob_name(&blob.digest);
            if !expected_names.insert(name.clone()) {
                return Err(StageBundleError::Manifest(
                    "manifest contains duplicate blob digests".into(),
                ));
            }
            let bytes = read_private_file(&directory, Path::new(&name), MAX_STAGE_FILE_BYTES)?;
            let length = u64::try_from(bytes.len()).map_err(|_| {
                StageBundleError::Blob("blob length cannot be represented as u64".into())
            })?;
            if length != blob.length || Digest::sha256(&bytes) != blob.digest {
                return Err(StageBundleError::Blob(format!(
                    "blob {} differs from its length or digest",
                    blob.digest
                )));
            }
            total = total
                .checked_add(length)
                .ok_or_else(|| StageBundleError::Blob("aggregate blob length overflowed".into()))?;
            if total > MAX_STAGE_TOTAL_BYTES {
                return Err(StageBundleError::Blob(format!(
                    "aggregate staged bytes exceed {MAX_STAGE_TOTAL_BYTES}"
                )));
            }
            blobs.insert(blob.digest.clone(), bytes);
        }
        let actual_names = directory_entry_names(&directory, &directory_name)?;
        if actual_names != expected_names {
            return Err(StageBundleError::Manifest(
                "bundle directory contains missing or unexpected entries".into(),
            ));
        }

        let (change_set, create_modes) = stored.into_native()?;
        if change_set.change_set_id != reference.change_set_id
            || change_set.base_snapshot != reference.base_snapshot
            || change_set.result_snapshot != reference.result_snapshot
        {
            return Err(StageBundleError::Reference(
                "typed reference differs from the verified stored change set".into(),
            ));
        }
        let staged = StagedChangeSet::new_with_create_modes(change_set, blobs, create_modes)
            .map_err(|error| StageBundleError::ChangeSet(error.to_string()))?;
        let named = self
            .root
            .open_dir_nofollow(&directory_name)
            .map_err(|error| {
                io_error(
                    "revalidate referenced stage-bundle name",
                    Path::new(&directory_name),
                    &error,
                )
            })?;
        if validate_private_directory(&named, "named stage bundle")? != identity {
            return Err(StageBundleError::Root(
                "stage-bundle name changed during verification".into(),
            ));
        }
        self.validate_root()?;
        Ok(staged)
    }

    fn validate_root(&self) -> Result<(), StageBundleError> {
        self.path_anchor
            .validate("stage-bundle store")
            .map_err(|error| StageBundleError::Root(error.to_string()))?;
        if validate_private_directory(&self.root, "retained private-state root")?
            != self.root_identity
        {
            return Err(StageBundleError::Root(
                "retained private-state identity, owner, or mode changed".into(),
            ));
        }
        let named = self
            .root_parent
            .open_dir_nofollow(&self.root_leaf)
            .map_err(|error| {
                StageBundleError::Root(format!(
                    "private-state root name no longer resolves without a link: {error}"
                ))
            })?;
        if validate_private_directory(&named, "named private-state root")? != self.root_identity {
            return Err(StageBundleError::Root(
                "private-state root name was replaced".into(),
            ));
        }
        Ok(())
    }

    fn create_temp_directory(
        &self,
    ) -> Result<(String, Dir, PrivateDirectoryIdentity), StageBundleError> {
        for _ in 0..TEMP_ATTEMPTS {
            let sequence = NEXT_TEMP.fetch_add(1, Ordering::Relaxed);
            let name = format!("{TEMP_PREFIX}{}-{sequence}", std::process::id());
            let mut builder = DirBuilder::new();
            builder.mode(0o700);
            match self.root.create_dir_with(&name, &builder) {
                Ok(()) => {
                    let directory = self.root.open_dir_nofollow(&name).map_err(|error| {
                        io_error(
                            "open new stage temporary directory",
                            Path::new(&name),
                            &error,
                        )
                    })?;
                    directory
                        .set_permissions(Path::new("."), Permissions::from_mode(0o700))
                        .map_err(|error| {
                            io_error("set stage temporary mode", Path::new(&name), &error)
                        })?;
                    let identity =
                        validate_private_directory(&directory, "stage temporary directory")?;
                    return Ok((name, directory, identity));
                }
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
                Err(error) => {
                    return Err(io_error(
                        "create stage temporary directory",
                        Path::new(&name),
                        &error,
                    ));
                }
            }
        }
        Err(StageBundleError::Root(
            "could not allocate a unique stage temporary directory".into(),
        ))
    }

    fn write_temp_bundle(
        directory: &Dir,
        stored: &StoredBundle,
        manifest: &[u8],
        staged: &StagedChangeSet,
    ) -> Result<(), StageBundleError> {
        write_private_file(directory, Path::new(MANIFEST_FILE), manifest)?;
        for blob in &stored.blobs {
            let bytes = staged_blob(staged, blob)?;
            write_private_file(directory, Path::new(&blob_name(&blob.digest)), bytes)?;
        }
        Ok(())
    }

    fn remove_owned_temp(
        &self,
        name: &str,
        identity: PrivateDirectoryIdentity,
    ) -> Result<(), StageBundleError> {
        let directory = self.root.open_dir_nofollow(name).map_err(|error| {
            io_error(
                "open stage temporary cleanup target",
                Path::new(name),
                &error,
            )
        })?;
        if validate_private_directory(&directory, "stage temporary cleanup target")? != identity {
            return Err(StageBundleError::Root(
                "stage temporary directory changed before cleanup".into(),
            ));
        }
        drop(directory);
        self.root.remove_dir_all(name).map_err(|error| {
            io_error("remove stage temporary directory", Path::new(name), &error)
        })?;
        sync_directory(&self.root).map_err(|error| {
            io_error(
                "sync removed stage temporary directory",
                Path::new(name),
                &error,
            )
        })
    }
}

fn prepare_bundle(
    staged: &StagedChangeSet,
) -> Result<(StoredBundle, Vec<u8>, StageBundleReference), StageBundleError> {
    let stored = StoredBundle::from_staged(staged)?;
    let manifest = canonical_manifest(&stored)?;
    let change_set = staged.change_set();
    let reference = StageBundleReference {
        format_version: BUNDLE_FORMAT_VERSION,
        bundle_digest: bundle_digest(&manifest),
        change_set_id: change_set.change_set_id.clone(),
        base_snapshot: change_set.base_snapshot.clone(),
        result_snapshot: change_set.result_snapshot.clone(),
    };
    reference.validate()?;
    Ok((stored, manifest, reference))
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct StoredBundle {
    format_version: u32,
    change_set: StoredChangeSet,
    blobs: Vec<StoredBlob>,
    create_modes: Vec<StoredCreateMode>,
}

impl StoredBundle {
    fn from_staged(staged: &StagedChangeSet) -> Result<Self, StageBundleError> {
        let change_set = staged.change_set();
        validate_identifier("change_set_id", &change_set.change_set_id)?;
        if change_set.operations.len() > MAX_STAGE_OPERATIONS {
            return Err(StageBundleError::ChangeSet(format!(
                "operation count exceeds {MAX_STAGE_OPERATIONS}"
            )));
        }
        let operations = change_set
            .operations
            .iter()
            .map(StoredOperation::from_native)
            .collect::<Result<Vec<_>, _>>()?;
        if staged.blobs().len() > MAX_STAGE_BLOBS {
            return Err(StageBundleError::Blob(format!(
                "blob count exceeds {MAX_STAGE_BLOBS}"
            )));
        }
        let mut total = 0_u64;
        let mut blobs = Vec::with_capacity(staged.blobs().len());
        for (digest, bytes) in staged.blobs() {
            let length = u64::try_from(bytes.len()).expect("usize fits u64");
            if length > MAX_STAGE_FILE_BYTES {
                return Err(StageBundleError::Blob(format!(
                    "blob {digest} exceeds {MAX_STAGE_FILE_BYTES} bytes"
                )));
            }
            total = total
                .checked_add(length)
                .ok_or_else(|| StageBundleError::Blob("aggregate blob length overflowed".into()))?;
            if total > MAX_STAGE_TOTAL_BYTES {
                return Err(StageBundleError::Blob(format!(
                    "aggregate staged bytes exceed {MAX_STAGE_TOTAL_BYTES}"
                )));
            }
            if Digest::sha256(bytes) != *digest {
                return Err(StageBundleError::Blob(format!(
                    "staged blob {digest} differs from its digest"
                )));
            }
            blobs.push(StoredBlob {
                digest: digest.clone(),
                length,
            });
        }
        let create_modes = change_set
            .operations
            .iter()
            .filter_map(|operation| match operation {
                FileOperation::Create { path, .. } => Some(path),
                FileOperation::Modify { .. } | FileOperation::Delete { .. } => None,
            })
            .map(|path| {
                let mode = staged.create_mode(path).ok_or_else(|| {
                    StageBundleError::ChangeSet(format!(
                        "create mode is absent for {}",
                        path.display()
                    ))
                })?;
                Ok(StoredCreateMode {
                    path: portable_relative_path(path)?,
                    mode,
                })
            })
            .collect::<Result<Vec<_>, StageBundleError>>()?;
        let stored = Self {
            format_version: BUNDLE_FORMAT_VERSION,
            change_set: StoredChangeSet {
                change_set_id: change_set.change_set_id.clone(),
                base_snapshot: change_set.base_snapshot.clone(),
                result_snapshot: change_set.result_snapshot.clone(),
                operations,
            },
            blobs,
            create_modes,
        };
        stored.validate()?;
        Ok(stored)
    }

    fn validate(&self) -> Result<(), StageBundleError> {
        if self.format_version != BUNDLE_FORMAT_VERSION {
            return Err(StageBundleError::Manifest(format!(
                "unsupported stored format version {}",
                self.format_version
            )));
        }
        validate_identifier("change_set_id", &self.change_set.change_set_id)?;
        if self.change_set.operations.len() > MAX_STAGE_OPERATIONS {
            return Err(StageBundleError::ChangeSet(
                "operation count is outside the supported range".into(),
            ));
        }
        let snapshots_are_equal = self.change_set.base_snapshot == self.change_set.result_snapshot;
        let operations_are_empty = self.change_set.operations.is_empty();
        if snapshots_are_equal != operations_are_empty {
            return Err(StageBundleError::ChangeSet(
                "empty operations must exactly match an unchanged snapshot".into(),
            ));
        }
        let mut paths = BTreeSet::new();
        let mut required_blobs = BTreeSet::new();
        let mut create_paths = BTreeSet::new();
        for operation in &self.change_set.operations {
            let (path, result) = operation.validate()?;
            if !paths.insert(path.clone()) {
                return Err(StageBundleError::ChangeSet(format!(
                    "duplicate operation target {path}"
                )));
            }
            if let Some(result) = result {
                required_blobs.insert(result);
            }
            if matches!(operation, StoredOperation::Create { .. }) {
                create_paths.insert(path);
            }
        }
        if self.blobs.len() > MAX_STAGE_BLOBS {
            return Err(StageBundleError::Blob(format!(
                "blob count exceeds {MAX_STAGE_BLOBS}"
            )));
        }
        let mut blob_digests = BTreeSet::new();
        let mut total = 0_u64;
        for blob in &self.blobs {
            if blob.length > MAX_STAGE_FILE_BYTES || !blob_digests.insert(blob.digest.clone()) {
                return Err(StageBundleError::Blob(
                    "blob length is oversized or digest is duplicated".into(),
                ));
            }
            total = total
                .checked_add(blob.length)
                .ok_or_else(|| StageBundleError::Blob("aggregate blob length overflowed".into()))?;
            if total > MAX_STAGE_TOTAL_BYTES {
                return Err(StageBundleError::Blob(format!(
                    "aggregate staged bytes exceed {MAX_STAGE_TOTAL_BYTES}"
                )));
            }
        }
        if blob_digests != required_blobs {
            return Err(StageBundleError::Blob(
                "manifest blobs do not exactly match operation result digests".into(),
            ));
        }
        let mut mode_paths = BTreeSet::new();
        for entry in &self.create_modes {
            validate_relative_path_text(&entry.path)?;
            if entry.mode & !0o777 != 0 || !mode_paths.insert(entry.path.clone()) {
                return Err(StageBundleError::ChangeSet(
                    "create modes are invalid or duplicated".into(),
                ));
            }
        }
        if mode_paths != create_paths {
            return Err(StageBundleError::ChangeSet(
                "create modes do not exactly match create operations".into(),
            ));
        }
        Ok(())
    }

    fn into_native(self) -> Result<(ChangeSet, BTreeMap<PathBuf, u32>), StageBundleError> {
        let operations = self
            .change_set
            .operations
            .into_iter()
            .map(StoredOperation::into_native)
            .collect::<Result<Vec<_>, _>>()?;
        let change_set = ChangeSet {
            change_set_id: self.change_set.change_set_id,
            base_snapshot: self.change_set.base_snapshot,
            result_snapshot: self.change_set.result_snapshot,
            operations,
        };
        change_set
            .validate()
            .map_err(|error| StageBundleError::ChangeSet(error.to_string()))?;
        let create_modes = self
            .create_modes
            .into_iter()
            .map(|entry| Ok((validated_relative_path(&entry.path)?, entry.mode)))
            .collect::<Result<BTreeMap<_, _>, StageBundleError>>()?;
        Ok((change_set, create_modes))
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct StoredChangeSet {
    change_set_id: String,
    base_snapshot: Digest,
    result_snapshot: Digest,
    operations: Vec<StoredOperation>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum StoredOperation {
    Create {
        path: String,
        result_hash: Digest,
    },
    Modify {
        path: String,
        base_hash: Digest,
        result_hash: Digest,
    },
    Delete {
        path: String,
        base_hash: Digest,
    },
}

impl StoredOperation {
    fn from_native(operation: &FileOperation) -> Result<Self, StageBundleError> {
        Ok(match operation {
            FileOperation::Create { path, result_hash } => Self::Create {
                path: portable_relative_path(path)?,
                result_hash: result_hash.clone(),
            },
            FileOperation::Modify {
                path,
                base_hash,
                result_hash,
            } => Self::Modify {
                path: portable_relative_path(path)?,
                base_hash: base_hash.clone(),
                result_hash: result_hash.clone(),
            },
            FileOperation::Delete { path, base_hash } => Self::Delete {
                path: portable_relative_path(path)?,
                base_hash: base_hash.clone(),
            },
        })
    }

    fn validate(&self) -> Result<(String, Option<Digest>), StageBundleError> {
        let (path, result) = match self {
            Self::Create { path, result_hash } => (path, Some(result_hash.clone())),
            Self::Modify {
                path,
                base_hash,
                result_hash,
            } => {
                if base_hash == result_hash {
                    return Err(StageBundleError::ChangeSet(
                        "modify base and result hashes are equal".into(),
                    ));
                }
                (path, Some(result_hash.clone()))
            }
            Self::Delete { path, .. } => (path, None),
        };
        validate_relative_path_text(path)?;
        Ok((path.clone(), result))
    }

    fn into_native(self) -> Result<FileOperation, StageBundleError> {
        Ok(match self {
            Self::Create { path, result_hash } => FileOperation::Create {
                path: validated_relative_path(&path)?,
                result_hash,
            },
            Self::Modify {
                path,
                base_hash,
                result_hash,
            } => FileOperation::Modify {
                path: validated_relative_path(&path)?,
                base_hash,
                result_hash,
            },
            Self::Delete { path, base_hash } => FileOperation::Delete {
                path: validated_relative_path(&path)?,
                base_hash,
            },
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct StoredBlob {
    digest: Digest,
    length: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct StoredCreateMode {
    path: String,
    mode: u32,
}

fn staged_blob<'a>(
    staged: &'a StagedChangeSet,
    blob: &StoredBlob,
) -> Result<&'a [u8], StageBundleError> {
    staged
        .blobs()
        .get(&blob.digest)
        .map(Vec::as_slice)
        .ok_or_else(|| StageBundleError::Blob(format!("bytes missing for {}", blob.digest)))
}

fn canonical_manifest(stored: &StoredBundle) -> Result<Vec<u8>, StageBundleError> {
    let bytes = serde_json::to_vec(stored)
        .map_err(|error| StageBundleError::Manifest(error.to_string()))?;
    if u64::try_from(bytes.len()).expect("usize fits u64") > MAX_MANIFEST_BYTES {
        return Err(StageBundleError::Manifest(format!(
            "canonical manifest exceeds {MAX_MANIFEST_BYTES} bytes"
        )));
    }
    Ok(bytes)
}

fn bundle_digest(manifest: &[u8]) -> Digest {
    let mut preimage = Vec::with_capacity(BUNDLE_DIGEST_DOMAIN.len() + manifest.len());
    preimage.extend_from_slice(BUNDLE_DIGEST_DOMAIN);
    preimage.extend_from_slice(manifest);
    Digest::sha256(&preimage)
}

fn blob_name(digest: &Digest) -> String {
    format!("blob-{digest}")
}

fn validate_identifier(field: &str, value: &str) -> Result<(), StageBundleError> {
    if value.is_empty()
        || value.len() > MAX_CHANGE_SET_ID_BYTES
        || value.trim() != value
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':'))
    {
        return Err(StageBundleError::Reference(format!(
            "{field} is blank, oversized, or contains unsupported bytes"
        )));
    }
    Ok(())
}

fn portable_relative_path(path: &Path) -> Result<String, StageBundleError> {
    let text = path.to_str().ok_or_else(|| {
        StageBundleError::ChangeSet(format!("path {} is not UTF-8", path.display()))
    })?;
    validate_relative_path_text(text)?;
    Ok(text.into())
}

fn validated_relative_path(text: &str) -> Result<PathBuf, StageBundleError> {
    validate_relative_path_text(text)?;
    Ok(PathBuf::from(text))
}

fn validate_relative_path_text(text: &str) -> Result<(), StageBundleError> {
    if text.is_empty() || text.len() > MAX_RELATIVE_PATH_BYTES || text.as_bytes().contains(&0) {
        return Err(StageBundleError::ChangeSet(
            "path is blank, oversized, or contains NUL".into(),
        ));
    }
    let path = Path::new(text);
    if path.is_absolute() {
        return Err(StageBundleError::ChangeSet(
            "stage paths must be relative".into(),
        ));
    }
    for component in path.components() {
        match component {
            Component::Normal(name)
                if !name
                    .to_str()
                    .is_some_and(|text| text.eq_ignore_ascii_case(".git")) => {}
            Component::Normal(_) => {
                return Err(StageBundleError::ChangeSet(
                    "protected .git paths are forbidden case-insensitively".into(),
                ));
            }
            Component::Prefix(_)
            | Component::RootDir
            | Component::CurDir
            | Component::ParentDir => {
                return Err(StageBundleError::ChangeSet(
                    "stage paths must contain only normalized components".into(),
                ));
            }
        }
    }
    Ok(())
}

fn validate_private_directory(
    directory: &Dir,
    label: &str,
) -> Result<PrivateDirectoryIdentity, StageBundleError> {
    let metadata = directory
        .dir_metadata()
        .map_err(|error| StageBundleError::Root(format!("inspect {label}: {error}")))?;
    if !metadata.is_dir() {
        return Err(StageBundleError::Root(format!(
            "{label} is not a directory"
        )));
    }
    let uid = OsMetadataExt::uid(&metadata);
    let mode = OsMetadataExt::mode(&metadata) & 0o777;
    if uid != rustix::process::geteuid().as_raw() || mode != 0o700 {
        return Err(StageBundleError::Root(format!(
            "{label} must be effective-user owned with mode 0700"
        )));
    }
    Ok(PrivateDirectoryIdentity {
        object: object_identity(&metadata),
        uid,
        mode,
    })
}

fn object_identity(metadata: &Metadata) -> ObjectIdentity {
    ObjectIdentity {
        device: PortableMetadataExt::dev(metadata),
        inode: PortableMetadataExt::ino(metadata),
    }
}

fn write_private_file(directory: &Dir, name: &Path, bytes: &[u8]) -> Result<(), StageBundleError> {
    let mut options = OpenOptions::new();
    options
        .write(true)
        .create_new(true)
        .mode(0o600)
        .follow(FollowSymlinks::No);
    let mut file = directory
        .open_with(name, &options)
        .map_err(|error| io_error("create immutable stage file", name, &error))?;
    file.set_permissions(Permissions::from_mode(0o600))
        .map_err(|error| io_error("set immutable stage-file mode", name, &error))?;
    file.write_all(bytes)
        .map_err(|error| io_error("write immutable stage file", name, &error))?;
    file.sync_all()
        .map_err(|error| io_error("sync immutable stage file", name, &error))?;
    validate_private_file(
        &file,
        name,
        u64::try_from(bytes.len()).expect("usize fits u64"),
    )?;
    Ok(())
}

fn read_private_file(
    directory: &Dir,
    name: &Path,
    limit: u64,
) -> Result<Vec<u8>, StageBundleError> {
    let mut options = OpenOptions::new();
    options.read(true).follow(FollowSymlinks::No);
    let mut file = directory
        .open_with(name, &options)
        .map_err(|error| io_error("open immutable stage file", name, &error))?;
    let first = file
        .metadata()
        .map_err(|error| io_error("inspect immutable stage file", name, &error))?;
    validate_private_file_metadata(name, &first, limit)?;
    let expected_length = first.len();
    let first_bytes = read_bounded(&mut file, name, limit)?;
    file.seek(SeekFrom::Start(0))
        .map_err(|error| io_error("rewind immutable stage file", name, &error))?;
    let second_bytes = read_bounded(&mut file, name, limit)?;
    let second = file
        .metadata()
        .map_err(|error| io_error("reinspect immutable stage file", name, &error))?;
    validate_private_file_metadata(name, &second, limit)?;
    if object_identity(&first) != object_identity(&second)
        || first_bytes != second_bytes
        || u64::try_from(first_bytes.len()).expect("usize fits u64") != expected_length
    {
        return Err(StageBundleError::Blob(format!(
            "{} changed during stable read",
            name.display()
        )));
    }
    Ok(first_bytes)
}

fn validate_private_file(file: &File, name: &Path, length: u64) -> Result<(), StageBundleError> {
    let metadata = file
        .metadata()
        .map_err(|error| io_error("inspect written stage file", name, &error))?;
    validate_private_file_metadata(name, &metadata, length)
}

fn validate_private_file_metadata(
    name: &Path,
    metadata: &Metadata,
    limit: u64,
) -> Result<(), StageBundleError> {
    let length = metadata.len();
    if !metadata.is_file()
        || OsMetadataExt::nlink(metadata) != 1
        || OsMetadataExt::uid(metadata) != rustix::process::geteuid().as_raw()
        || OsMetadataExt::mode(metadata) & 0o777 != 0o600
        || length > limit
    {
        return Err(StageBundleError::Blob(format!(
            "{} is not a singly-linked owner-private regular file within {limit} bytes",
            name.display()
        )));
    }
    Ok(())
}

fn directory_entry_names(
    directory: &Dir,
    label: &str,
) -> Result<BTreeSet<String>, StageBundleError> {
    let mut names = BTreeSet::new();
    for entry in directory
        .entries()
        .map_err(|error| io_error("enumerate stage bundle", Path::new(label), &error))?
    {
        if names.len() > MAX_STAGE_BLOBS {
            return Err(StageBundleError::Manifest(format!(
                "bundle entry count exceeds {}",
                MAX_STAGE_BLOBS + 1
            )));
        }
        let entry =
            entry.map_err(|error| io_error("read stage-bundle entry", Path::new(label), &error))?;
        let name = entry.file_name().into_string().map_err(|_| {
            StageBundleError::Manifest("bundle contains a non-UTF-8 entry name".into())
        })?;
        if !names.insert(name) {
            return Err(StageBundleError::Manifest(
                "bundle contains duplicate entry names".into(),
            ));
        }
    }
    Ok(names)
}

fn read_bounded(file: &mut File, name: &Path, limit: u64) -> Result<Vec<u8>, StageBundleError> {
    let mut bytes = Vec::new();
    file.take(limit.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|error| io_error("read immutable stage file", name, &error))?;
    if u64::try_from(bytes.len()).map_or(true, |length| length > limit) {
        return Err(StageBundleError::Blob(format!(
            "{} grew beyond its {limit}-byte bound during read",
            name.display()
        )));
    }
    Ok(bytes)
}

fn io_error(operation: &'static str, path: &Path, error: &impl Display) -> StageBundleError {
    StageBundleError::Io {
        operation,
        path: path.to_path_buf(),
        message: error.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::fs::{self, OpenOptions};
    use std::io::Write as _;
    use std::os::unix::fs::PermissionsExt as _;
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicU64, Ordering};

    use grok_build_core::{ChangeSet, Digest, FileOperation, TaskIntegrationArtifactReference};

    use super::{
        BUNDLE_FORMAT_VERSION, CapabilityStageBundleStore, MAX_STAGE_FILE_BYTES,
        MAX_STAGE_TOTAL_BYTES, StageBundleError, StoredBlob, StoredBundle, StoredChangeSet,
        StoredCreateMode, StoredOperation,
    };
    use crate::StagedChangeSet;

    static NEXT_FIXTURE: AtomicU64 = AtomicU64::new(1);

    struct Fixture {
        parent: PathBuf,
        state: PathBuf,
    }

    impl Fixture {
        fn new() -> Self {
            let requested_parent = std::env::temp_dir().join(format!(
                "grok-build-stage-bundle-{}-{}",
                std::process::id(),
                NEXT_FIXTURE.fetch_add(1, Ordering::Relaxed)
            ));
            let requested_state = requested_parent.join("state");
            fs::create_dir(&requested_parent).expect("create fixture parent");
            fs::create_dir(&requested_state).expect("create private state");
            let parent = fs::canonicalize(&requested_parent).expect("canonicalize fixture parent");
            let state = parent.join("state");
            fs::set_permissions(&state, fs::Permissions::from_mode(0o700))
                .expect("set private-state mode");
            Self { parent, state }
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.parent);
        }
    }

    fn staged(bytes: Vec<u8>) -> StagedChangeSet {
        let result_hash = Digest::sha256(&bytes);
        let change_set = ChangeSet {
            change_set_id: "changeset-stage-fixture".into(),
            base_snapshot: Digest::sha256(b"base"),
            result_snapshot: Digest::sha256(b"result"),
            operations: vec![FileOperation::Create {
                path: PathBuf::from("docs/report.bin"),
                result_hash: result_hash.clone(),
            }],
        };
        StagedChangeSet::new(change_set, BTreeMap::from([(result_hash, bytes)]))
            .expect("construct staged fixture")
    }

    fn staged_verified_no_op() -> StagedChangeSet {
        let snapshot = Digest::sha256(b"unchanged verified snapshot");
        let change_set = ChangeSet {
            change_set_id: "changeset-verified-no-op".into(),
            base_snapshot: snapshot.clone(),
            result_snapshot: snapshot,
            operations: Vec::new(),
        };
        StagedChangeSet::new(change_set, BTreeMap::new()).expect("construct verified no-op fixture")
    }

    fn bundle_path(state: &Path, digest: &Digest) -> PathBuf {
        state.join(format!("stage-{digest}"))
    }

    fn stored_with_lengths(lengths: &[u64]) -> StoredBundle {
        let records = lengths
            .iter()
            .enumerate()
            .map(|(index, &length)| {
                let path = format!("files/{index}.bin");
                let digest = Digest::sha256(&index.to_be_bytes());
                (
                    StoredOperation::Create {
                        path: path.clone(),
                        result_hash: digest.clone(),
                    },
                    StoredBlob { digest, length },
                    StoredCreateMode { path, mode: 0o600 },
                )
            })
            .collect::<Vec<_>>();
        StoredBundle {
            format_version: BUNDLE_FORMAT_VERSION,
            change_set: StoredChangeSet {
                change_set_id: "changeset-boundary".into(),
                base_snapshot: Digest::sha256(b"boundary-base"),
                result_snapshot: Digest::sha256(b"boundary-result"),
                operations: records.iter().map(|record| record.0.clone()).collect(),
            },
            blobs: records.iter().map(|record| record.1.clone()).collect(),
            create_modes: records.into_iter().map(|record| record.2).collect(),
        }
    }

    #[test]
    fn aggregate_memory_budget_accepts_boundary_and_rejects_plus_one() {
        let at_boundary = stored_with_lengths(&[MAX_STAGE_FILE_BYTES; 4]);
        assert_eq!(MAX_STAGE_TOTAL_BYTES, MAX_STAGE_FILE_BYTES * 4);
        at_boundary
            .validate()
            .expect("accept exact aggregate boundary");

        let over_boundary = stored_with_lengths(&[
            MAX_STAGE_FILE_BYTES,
            MAX_STAGE_FILE_BYTES,
            MAX_STAGE_FILE_BYTES,
            MAX_STAGE_FILE_BYTES,
            1,
        ]);
        assert!(matches!(
            over_boundary.validate(),
            Err(StageBundleError::Blob(message))
                if message.contains("aggregate staged bytes exceed")
        ));
    }

    #[test]
    fn core_integration_artifact_mapping_is_exact_and_round_trips() {
        let staged = staged(b"artifact mapping".to_vec());
        let reference = CapabilityStageBundleStore::preview(&staged).expect("preview stage bundle");
        let artifact = reference
            .to_core_integration_artifact()
            .expect("map runner bundle to core artifact");
        assert_eq!(artifact.format_version, reference.format_version);
        assert_eq!(artifact.artifact_digest, reference.bundle_digest);
        assert_eq!(artifact.change_set_id, reference.change_set_id);
        assert_eq!(artifact.base_snapshot, reference.base_snapshot);
        assert_eq!(artifact.result_snapshot, reference.result_snapshot);
        assert_eq!(
            super::StageBundleReference::try_from(&artifact)
                .expect("map core artifact back to runner bundle"),
            reference
        );

        let unsupported = TaskIntegrationArtifactReference {
            format_version: 2,
            ..artifact.clone()
        };
        assert!(matches!(
            super::StageBundleReference::try_from(&unsupported),
            Err(StageBundleError::Reference(message))
                if message.contains("unsupported stage-bundle version")
        ));

        let unchanged_transition = TaskIntegrationArtifactReference {
            result_snapshot: artifact.base_snapshot.clone(),
            ..artifact
        };
        let unchanged_reference = super::StageBundleReference::try_from(&unchanged_transition)
            .expect("an artifact reference may identify an explicit verified no-op bundle");
        assert_eq!(
            unchanged_reference.base_snapshot,
            unchanged_reference.result_snapshot
        );
    }

    #[test]
    fn verified_no_op_bundle_round_trips_but_mismatched_shapes_are_rejected() {
        let fixture = Fixture::new();
        let store = CapabilityStageBundleStore::open(&fixture.state).expect("open bundle store");
        let staged = staged_verified_no_op();
        let preview = CapabilityStageBundleStore::preview(&staged).expect("preview no-op bundle");
        assert_eq!(preview.base_snapshot, preview.result_snapshot);
        let reference = store.persist(&staged).expect("persist no-op bundle");
        assert_eq!(reference, preview);
        assert_eq!(store.load(&reference).expect("load no-op bundle"), staged);

        let snapshot = Digest::sha256(b"empty-base");
        let mut empty = StoredBundle {
            format_version: BUNDLE_FORMAT_VERSION,
            change_set: StoredChangeSet {
                change_set_id: "empty-shape".into(),
                base_snapshot: snapshot.clone(),
                result_snapshot: snapshot,
                operations: Vec::new(),
            },
            blobs: Vec::new(),
            create_modes: Vec::new(),
        };
        empty.validate().expect("accept exact empty no-op shape");
        empty.change_set.result_snapshot = Digest::sha256(b"different-result");
        assert!(matches!(
            empty.validate(),
            Err(StageBundleError::ChangeSet(message))
                if message.contains("empty operations must exactly match")
        ));

        let mut nonempty = stored_with_lengths(&[1]);
        nonempty.change_set.result_snapshot = nonempty.change_set.base_snapshot.clone();
        assert!(matches!(
            nonempty.validate(),
            Err(StageBundleError::ChangeSet(message))
                if message.contains("empty operations must exactly match")
        ));
    }

    #[test]
    fn protected_git_component_is_rejected_case_insensitively() {
        let mut stored = stored_with_lengths(&[1]);
        let StoredOperation::Create { path, .. } = &mut stored.change_set.operations[0] else {
            unreachable!()
        };
        *path = ".GIT/config".into();
        stored.create_modes[0].path = ".GIT/config".into();
        assert!(matches!(
            stored.validate(),
            Err(StageBundleError::ChangeSet(message))
                if message.contains("case-insensitively")
        ));
    }

    #[test]
    fn immutable_bundle_round_trip_exceeds_inline_wire_ceiling() {
        let fixture = Fixture::new();
        let store = CapabilityStageBundleStore::open(&fixture.state).expect("open bundle store");
        let staged = staged(vec![0x5a; 2 * 1024 * 1024]);
        let preview = CapabilityStageBundleStore::preview(&staged).expect("preview stage bundle");
        let reference = store.persist(&staged).expect("persist stage bundle");
        assert_eq!(reference, preview);
        let loaded = store.load(&reference).expect("load stage bundle");
        assert_eq!(loaded, staged);

        let encoded = serde_json::to_vec(&reference).expect("encode path-free reference");
        assert!(encoded.len() < 512);
        assert!(
            !String::from_utf8_lossy(&encoded).contains(fixture.state.to_string_lossy().as_ref())
        );
        assert_eq!(
            store.persist(&staged).expect("deduplicate bundle"),
            reference
        );
    }

    #[test]
    fn uncertain_publication_reconciles_only_the_exact_previewed_bundle() {
        let fixture = Fixture::new();
        let store = CapabilityStageBundleStore::open(&fixture.state).expect("open bundle store");
        let staged = staged(b"uncertain but durably published".to_vec());
        let expected = CapabilityStageBundleStore::preview(&staged).expect("preview stage bundle");

        let error = store
            .persist_with_post_publish_probe(&staged, || {
                Err("injected loss of post-publication proof".into())
            })
            .expect_err("publication must be reported as uncertain");
        assert!(matches!(
            error,
            StageBundleError::ReconciliationRequired { reference, .. }
                if reference.as_ref() == &expected
        ));
        assert_eq!(
            store
                .reconcile(&expected)
                .expect("reopen exact published bundle"),
            expected
        );

        let mut mismatched = expected.clone();
        mismatched.bundle_digest = Digest::sha256(b"different bundle");
        assert!(matches!(
            store.reconcile(&mismatched),
            Err(StageBundleError::Io { .. } | StageBundleError::Reference(_))
        ));
    }

    #[test]
    fn corrupt_blob_and_extra_entry_are_rejected() {
        let fixture = Fixture::new();
        let store = CapabilityStageBundleStore::open(&fixture.state).expect("open bundle store");
        let staged = staged(b"verified bytes".to_vec());
        let reference = store.persist(&staged).expect("persist stage bundle");
        let directory = bundle_path(&fixture.state, &reference.bundle_digest);
        let blob = fs::read_dir(&directory)
            .expect("enumerate bundle")
            .map(|entry| entry.expect("read entry").path())
            .find(|path| {
                path.file_name()
                    .and_then(|name| name.to_str())
                    .is_some_and(|name| name.starts_with("blob-"))
            })
            .expect("find blob");
        let mut file = OpenOptions::new()
            .write(true)
            .truncate(true)
            .open(&blob)
            .expect("open blob for corruption");
        file.write_all(b"corrupt").expect("corrupt blob");
        file.sync_all().expect("sync corrupt blob");
        assert!(matches!(
            store.load(&reference),
            Err(StageBundleError::Blob(_))
        ));

        let second_fixture = Fixture::new();
        let second_store = CapabilityStageBundleStore::open(&second_fixture.state)
            .expect("open second bundle store");
        let second = second_store
            .persist(&staged)
            .expect("persist second bundle");
        let extra = bundle_path(&second_fixture.state, &second.bundle_digest).join("unexpected");
        fs::write(&extra, b"unexpected").expect("write unexpected entry");
        assert!(matches!(
            second_store.load(&second),
            Err(StageBundleError::Manifest(_))
        ));
    }

    #[test]
    fn modified_manifest_is_rejected() {
        let fixture = Fixture::new();
        let store = CapabilityStageBundleStore::open(&fixture.state).expect("open bundle store");
        let staged = staged(b"manifest fixture".to_vec());
        let reference = store.persist(&staged).expect("persist stage bundle");
        let manifest = bundle_path(&fixture.state, &reference.bundle_digest).join("manifest.json");
        let bytes = fs::read(&manifest).expect("read canonical manifest");
        let mut modified = Vec::with_capacity(bytes.len() + 1);
        modified.push(b' ');
        modified.extend_from_slice(&bytes);
        fs::write(&manifest, modified).expect("write noncanonical manifest");
        assert!(matches!(
            store.load(&reference),
            Err(StageBundleError::Reference(_) | StageBundleError::Manifest(_))
        ));
    }

    #[test]
    fn named_private_root_replacement_is_rejected() {
        let fixture = Fixture::new();
        let store = CapabilityStageBundleStore::open(&fixture.state).expect("open bundle store");
        let moved = fixture.parent.join("old-state");
        fs::rename(&fixture.state, &moved).expect("replace named state root");
        fs::create_dir(&fixture.state).expect("create replacement state root");
        fs::set_permissions(&fixture.state, fs::Permissions::from_mode(0o700))
            .expect("set replacement mode");
        assert!(matches!(
            store.persist(&staged(b"replacement".to_vec())),
            Err(StageBundleError::Root(_))
        ));
    }

    #[test]
    fn private_root_ancestor_replacement_is_rejected() {
        let fixture = Fixture::new();
        let store = CapabilityStageBundleStore::open(&fixture.state).expect("open bundle store");
        let leaf = fixture
            .parent
            .file_name()
            .and_then(|name| name.to_str())
            .expect("fixture parent leaf");
        let moved = fixture.parent.with_file_name(format!("{leaf}-moved"));
        fs::rename(&fixture.parent, &moved).expect("move anchored ancestor");
        fs::create_dir(&fixture.parent).expect("create replacement ancestor");
        fs::create_dir(&fixture.state).expect("create replacement state root");
        fs::set_permissions(&fixture.state, fs::Permissions::from_mode(0o700))
            .expect("set replacement state mode");
        assert!(matches!(
            store.persist(&staged(b"ancestor replacement".to_vec())),
            Err(StageBundleError::Root(_))
        ));
        drop(store);
        fs::remove_dir_all(&moved).expect("remove moved original fixture");
    }

    #[test]
    fn linked_or_nonprivate_store_root_is_rejected() {
        let fixture = Fixture::new();
        fs::set_permissions(&fixture.state, fs::Permissions::from_mode(0o755))
            .expect("widen state mode");
        assert!(matches!(
            CapabilityStageBundleStore::open(&fixture.state),
            Err(StageBundleError::Root(_))
        ));

        let second = Fixture::new();
        let link = second.parent.join("state-link");
        std::os::unix::fs::symlink(&second.state, &link).expect("create state symlink");
        assert!(matches!(
            CapabilityStageBundleStore::open(&link),
            Err(StageBundleError::Root(_))
        ));
    }
}
