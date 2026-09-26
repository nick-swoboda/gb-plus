//! Content-addressed workspace snapshots, private shadows, and staged diffs.
//!
//! This module rejects links and non-regular filesystem objects, but its path
//! validation is not descriptor-relative. Callers must not treat these checks as
//! a complete defense against an actively racing same-user process.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::{self, Display, Formatter};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Component, Path, PathBuf};

use grok_build_core::{
    ChangeSet, ContractError, Digest, FileOperation, IssuedWorkspaceGrant, WorkspaceSnapshot,
};
use sha2::{Digest as _, Sha256};

use crate::{CanonicalRoot, PathValidationError};

const MANIFEST_DOMAIN: &[u8] = b"grok-build.workspace-manifest.sha256.v1\0";
const CHANGE_SET_DOMAIN: &[u8] = b"grok-build.change-set.sha256.v1\0";

/// One regular file in a deterministic workspace manifest.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManifestEntry {
    digest: Digest,
    length: u64,
    mode: u32,
}

impl ManifestEntry {
    /// Reconstructs an entry after a durable store has verified its fields.
    pub(crate) const fn from_stored_parts(digest: Digest, length: u64, mode: u32) -> Self {
        Self {
            digest,
            length,
            mode,
        }
    }

    /// Returns the SHA-256 content digest.
    #[must_use]
    pub const fn digest(&self) -> &Digest {
        &self.digest
    }

    /// Returns the file length in bytes.
    #[must_use]
    pub const fn length(&self) -> u64 {
        self.length
    }

    /// Returns normalized Unix-style permission bits included in the manifest.
    #[must_use]
    pub const fn mode(&self) -> u32 {
        self.mode
    }
}

/// An immutable, deterministic manifest of regular workspace files.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WorkspaceManifest {
    root: PathBuf,
    snapshot: WorkspaceSnapshot,
    entries: BTreeMap<PathBuf, ManifestEntry>,
}

impl WorkspaceManifest {
    /// Reconstructs a manifest after a durable store has decoded its fields.
    pub(crate) fn from_stored_parts(
        root: PathBuf,
        snapshot: WorkspaceSnapshot,
        entries: BTreeMap<PathBuf, ManifestEntry>,
    ) -> Result<Self, WorkspacePipelineError> {
        snapshot
            .validate()
            .map_err(WorkspacePipelineError::Contract)?;
        for (path, entry) in &entries {
            validate_manifest_path(path)?;
            if entry.mode & !0o777 != 0 {
                return Err(WorkspacePipelineError::InvalidCreateModes);
            }
        }
        let actual = manifest_digest(&entries)?;
        if actual != snapshot.snapshot_id {
            return Err(WorkspacePipelineError::SnapshotMismatch {
                expected: snapshot.snapshot_id,
                actual,
            });
        }
        Ok(Self {
            root,
            snapshot,
            entries,
        })
    }

    /// Captures the workspace authorized by `grant` through a path-based legacy boundary.
    ///
    /// New production callers must use [`crate::CapabilityWorkspace::capture`].
    /// This constructor remains for migration and regression fixtures.
    ///
    /// `.git` path components are excluded. Every other entry must be a directory
    /// or a singly-linked regular file. Symlinks, hard-linked files, sockets,
    /// FIFOs, devices, and non-UTF-8 paths fail closed.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid grant, root mismatch, unsafe entry,
    /// concurrent file mutation, invalid timestamp, or filesystem failure.
    pub fn capture(
        grant: &IssuedWorkspaceGrant,
        created_at_unix_ms: u64,
    ) -> Result<Self, WorkspacePipelineError> {
        grant
            .validate_integrity()
            .map_err(WorkspacePipelineError::Contract)?;
        let contract = grant.contract();
        let root = CanonicalRoot::open(&contract.canonical_root)
            .map_err(WorkspacePipelineError::PathValidation)?;
        if root.as_path() != contract.canonical_root {
            return Err(WorkspacePipelineError::GrantRootMismatch {
                granted: contract.canonical_root.clone(),
                canonical: root.as_path().to_path_buf(),
            });
        }
        Self::capture_root(
            root.as_path(),
            contract.grant_hash.clone(),
            created_at_unix_ms,
        )
    }

    pub(crate) fn capture_root(
        root: &Path,
        grant_hash: Digest,
        created_at_unix_ms: u64,
    ) -> Result<Self, WorkspacePipelineError> {
        if created_at_unix_ms == 0 {
            return Err(WorkspacePipelineError::InvalidTimestamp);
        }

        let canonical_root = fs::canonicalize(root)
            .map_err(|error| io_error("canonicalize snapshot root", root, &error))?;
        let metadata = fs::symlink_metadata(&canonical_root)
            .map_err(|error| io_error("inspect snapshot root", &canonical_root, &error))?;
        if !metadata.file_type().is_dir() {
            return Err(WorkspacePipelineError::UnsafeEntry {
                path: canonical_root,
                kind: UnsafeEntryKind::Special,
            });
        }

        let mut entries = BTreeMap::new();
        walk_directory(&canonical_root, Path::new(""), &mut entries)?;
        let snapshot_id = manifest_digest(&entries)?;
        let snapshot = WorkspaceSnapshot {
            snapshot_id,
            grant_hash,
            created_at_unix_ms,
        };
        snapshot
            .validate()
            .map_err(WorkspacePipelineError::Contract)?;

        Ok(Self {
            root: canonical_root,
            snapshot,
            entries,
        })
    }

    /// Returns the canonical root represented by this manifest.
    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Returns the public snapshot contract.
    #[must_use]
    pub const fn snapshot(&self) -> &WorkspaceSnapshot {
        &self.snapshot
    }

    /// Returns manifest entries ordered by normalized relative path.
    #[must_use]
    pub const fn entries(&self) -> &BTreeMap<PathBuf, ManifestEntry> {
        &self.entries
    }

    /// Returns one manifest entry by relative path.
    #[must_use]
    pub fn entry(&self, path: impl AsRef<Path>) -> Option<&ManifestEntry> {
        self.entries.get(path.as_ref())
    }
}

/// A path-based private-shadow prototype retained for migration and fixtures.
///
/// New production callers must use [`crate::CapabilityWorkspace`] with
/// [`crate::CapabilityShadowStore`] and [`crate::CapabilityShadowWorkspace`].
/// This type reacquires and traverses filesystem paths and therefore does not
/// carry the production descriptor-chain guarantee.
#[derive(Clone, Debug)]
pub struct ShadowWorkspace {
    root: PathBuf,
    base: WorkspaceManifest,
}

impl ShadowWorkspace {
    /// Reconstructs a writable shadow copied from an already verified store.
    pub(crate) const fn from_stored_parts(root: PathBuf, base: WorkspaceManifest) -> Self {
        Self { root, base }
    }

    /// Creates a new shadow at the exact absolute `destination`.
    ///
    /// The destination must not exist and must be outside the granted workspace.
    /// On Unix it is created with mode `0700`; files are copied from verified
    /// bytes without copying links.
    ///
    /// # Errors
    ///
    /// Returns an error if the live workspace is stale, the destination is
    /// unsafe, copying fails, or the resulting shadow does not match the base.
    pub fn create(
        grant: &IssuedWorkspaceGrant,
        base: &WorkspaceManifest,
        destination: impl AsRef<Path>,
    ) -> Result<Self, WorkspacePipelineError> {
        let destination = destination.as_ref();
        let contract = grant.contract();
        validated_shadow_destination(grant, base, destination)?;

        fs::create_dir(destination)
            .map_err(|error| io_error("create shadow workspace", destination, &error))?;
        set_private_directory_permissions(destination)?;

        let copy_result = copy_manifest_files(base, destination);
        if let Err(error) = copy_result {
            let _ = fs::remove_dir_all(destination);
            return Err(error);
        }

        let shadow = Self {
            root: fs::canonicalize(destination)
                .map_err(|error| io_error("canonicalize shadow workspace", destination, &error))?,
            base: base.clone(),
        };
        let copied = WorkspaceManifest::capture_root(
            &shadow.root,
            contract.grant_hash.clone(),
            base.snapshot.created_at_unix_ms,
        )?;
        if copied.snapshot.snapshot_id != base.snapshot.snapshot_id {
            let _ = fs::remove_dir_all(&shadow.root);
            return Err(WorkspacePipelineError::SnapshotMismatch {
                expected: base.snapshot.snapshot_id.clone(),
                actual: copied.snapshot.snapshot_id,
            });
        }
        Ok(shadow)
    }

    /// Names a private shadow for the worker to create, without mutating storage.
    /// Apply the same pre-mutation checks as [`Self::create`]. The worker must
    /// capture the initialized base before materializing the shadow. Observations
    /// through this handle fail until that creation completes.
    ///
    /// # Errors
    ///
    /// Fails for an invalid grant, mismatched or stale base, relative or existing
    /// destination, unsafe parent, or overlap with the granted workspace.
    pub fn worker_created_destination(
        grant: &IssuedWorkspaceGrant,
        base: &WorkspaceManifest,
        destination: impl AsRef<Path>,
    ) -> Result<Self, WorkspacePipelineError> {
        let canonical = validated_shadow_destination(grant, base, destination.as_ref())?;
        Ok(Self {
            root: canonical,
            base: base.clone(),
        })
    }

    /// Returns the private shadow root.
    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Returns the immutable base manifest.
    #[must_use]
    pub const fn base(&self) -> &WorkspaceManifest {
        &self.base
    }

    /// Computes a contract-valid change set and verified result-content blobs.
    ///
    /// # Errors
    ///
    /// Returns an error for an unsafe shadow entry, a no-op diff, an invalid
    /// identifier, an unstable file, or contract validation failure.
    pub fn stage_changes(
        &self,
        change_set_id: impl Into<String>,
        created_at_unix_ms: u64,
    ) -> Result<StagedChangeSet, WorkspacePipelineError> {
        let result = WorkspaceManifest::capture_root(
            &self.root,
            self.base.snapshot.grant_hash.clone(),
            created_at_unix_ms,
        )?;
        let mut paths = BTreeSet::new();
        paths.extend(self.base.entries.keys().cloned());
        paths.extend(result.entries.keys().cloned());

        let mut operations = Vec::new();
        let mut blobs = BTreeMap::new();
        let mut create_modes = BTreeMap::new();
        for path in paths {
            match (self.base.entries.get(&path), result.entries.get(&path)) {
                (None, Some(created)) => {
                    operations.push(FileOperation::Create {
                        path: path.clone(),
                        result_hash: created.digest.clone(),
                    });
                    insert_verified_blob(&self.root, &path, created, &mut blobs)?;
                    create_modes.insert(path, created.mode);
                }
                (Some(base), Some(changed)) if base.mode != changed.mode => {
                    return Err(WorkspacePipelineError::UnsupportedMetadataChange(path));
                }
                (Some(base), Some(changed)) if base.digest != changed.digest => {
                    operations.push(FileOperation::Modify {
                        path: path.clone(),
                        base_hash: base.digest.clone(),
                        result_hash: changed.digest.clone(),
                    });
                    insert_verified_blob(&self.root, &path, changed, &mut blobs)?;
                }
                (Some(base), None) => operations.push(FileOperation::Delete {
                    path,
                    base_hash: base.digest.clone(),
                }),
                (Some(_), Some(_)) => {}
                (None, None) => unreachable!("the union contains at least one manifest entry"),
            }
        }

        if operations.is_empty() {
            return Err(WorkspacePipelineError::NoChanges);
        }
        let supplied_id = change_set_id.into();
        let change_set_id = if supplied_id.trim().is_empty() {
            deterministic_change_set_id(
                &self.base.snapshot.snapshot_id,
                &result.snapshot.snapshot_id,
                &operations,
            )
        } else {
            supplied_id
        };
        let change_set = ChangeSet {
            change_set_id,
            base_snapshot: self.base.snapshot.snapshot_id.clone(),
            result_snapshot: result.snapshot.snapshot_id,
            operations,
        };
        StagedChangeSet::new_with_create_modes(change_set, blobs, create_modes)
    }

    /// Deletes the private shadow tree.
    ///
    /// # Errors
    ///
    /// Returns an error if the tree cannot be removed.
    pub fn discard(self) -> Result<(), WorkspacePipelineError> {
        fs::remove_dir_all(&self.root)
            .map_err(|error| io_error("remove shadow workspace", &self.root, &error))
    }
}

/// A validated change set plus content-addressed bytes for create/modify operations.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StagedChangeSet {
    change_set: ChangeSet,
    blobs: BTreeMap<Digest, Vec<u8>>,
    create_modes: BTreeMap<PathBuf, u32>,
}

impl StagedChangeSet {
    /// Validates a change set and every required result blob.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid change set, missing blob, unexpected blob,
    /// or digest/content mismatch.
    pub fn new(
        change_set: ChangeSet,
        blobs: BTreeMap<Digest, Vec<u8>>,
    ) -> Result<Self, WorkspacePipelineError> {
        let create_modes = change_set
            .operations
            .iter()
            .filter_map(|operation| match operation {
                FileOperation::Create { path, .. } => Some((path.clone(), 0o600)),
                FileOperation::Modify { .. } | FileOperation::Delete { .. } => None,
            })
            .collect();
        Self::new_with_create_modes(change_set, blobs, create_modes)
    }

    pub(crate) fn new_with_create_modes(
        change_set: ChangeSet,
        blobs: BTreeMap<Digest, Vec<u8>>,
        create_modes: BTreeMap<PathBuf, u32>,
    ) -> Result<Self, WorkspacePipelineError> {
        change_set
            .validate()
            .map_err(WorkspacePipelineError::Contract)?;

        let expected = change_set
            .operations
            .iter()
            .filter_map(|operation| match operation {
                FileOperation::Create { result_hash, .. }
                | FileOperation::Modify { result_hash, .. } => Some(result_hash),
                FileOperation::Delete { .. } => None,
            })
            .collect::<BTreeSet<_>>();
        for digest in &expected {
            let bytes = blobs
                .get(*digest)
                .ok_or_else(|| WorkspacePipelineError::MissingBlob((*digest).clone()))?;
            let actual = hash_bytes(bytes)?;
            if &actual != *digest {
                return Err(WorkspacePipelineError::BlobDigestMismatch {
                    expected: (*digest).clone(),
                    actual,
                });
            }
        }
        if let Some(unexpected) = blobs.keys().find(|digest| !expected.contains(digest)) {
            return Err(WorkspacePipelineError::UnexpectedBlob(unexpected.clone()));
        }

        let expected_create_paths = change_set
            .operations
            .iter()
            .filter_map(|operation| match operation {
                FileOperation::Create { path, .. } => Some(path),
                FileOperation::Modify { .. } | FileOperation::Delete { .. } => None,
            })
            .collect::<BTreeSet<_>>();
        if create_modes.keys().collect::<BTreeSet<_>>() != expected_create_paths
            || create_modes.values().any(|mode| mode & !0o777 != 0)
        {
            return Err(WorkspacePipelineError::InvalidCreateModes);
        }

        Ok(Self {
            change_set,
            blobs,
            create_modes,
        })
    }

    /// Returns the validated public change-set contract.
    #[must_use]
    pub const fn change_set(&self) -> &ChangeSet {
        &self.change_set
    }

    /// Returns all result blobs indexed by SHA-256 digest.
    #[must_use]
    pub const fn blobs(&self) -> &BTreeMap<Digest, Vec<u8>> {
        &self.blobs
    }

    /// Returns a result blob by digest.
    #[must_use]
    pub fn blob(&self, digest: &Digest) -> Option<&[u8]> {
        self.blobs.get(digest).map(Vec::as_slice)
    }

    /// Returns the normalized mode for a created file.
    #[must_use]
    pub fn create_mode(&self, path: &Path) -> Option<u32> {
        self.create_modes.get(path).copied()
    }
}

/// Category of a filesystem entry rejected by snapshot capture.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UnsafeEntryKind {
    /// A symbolic link was encountered.
    Symlink,
    /// A regular file has more than one directory entry.
    HardLink,
    /// A socket, FIFO, device, or other unsupported entry was encountered.
    Special,
}

/// A fail-closed snapshot, shadow, or diff error.
#[derive(Debug)]
pub enum WorkspacePipelineError {
    /// A core contract failed validation.
    Contract(ContractError),
    /// Runner path validation failed.
    PathValidation(PathValidationError),
    /// The canonical root differs from the exact granted root.
    GrantRootMismatch {
        /// Root recorded by the grant.
        granted: PathBuf,
        /// Root resolved by the runner.
        canonical: PathBuf,
    },
    /// Snapshot timestamps must be nonzero.
    InvalidTimestamp,
    /// A path cannot be represented without loss across supported hosts.
    NonUtf8Path(PathBuf),
    /// A filesystem entry is outside the supported regular-file model.
    UnsafeEntry {
        /// Rejected path.
        path: PathBuf,
        /// Rejected entry category.
        kind: UnsafeEntryKind,
    },
    /// A file changed while it was being captured.
    ConcurrentMutation(PathBuf),
    /// A verified file no longer has the captured content digest.
    FileContentMismatch {
        /// File whose bytes changed.
        path: PathBuf,
        /// Captured file digest.
        expected: Digest,
        /// Newly computed file digest.
        actual: Digest,
    },
    /// Shadow destinations must be absolute.
    DestinationNotAbsolute(PathBuf),
    /// The requested shadow destination already exists.
    DestinationExists(PathBuf),
    /// The destination has no safe, existing parent.
    UnsafeDestination(PathBuf),
    /// Shadow workspaces cannot be nested in the granted workspace.
    ShadowInsideWorkspace(PathBuf),
    /// The manifest does not belong to the supplied grant.
    BaseGrantMismatch,
    /// The live workspace no longer matches the immutable base.
    StaleBase {
        /// Expected base snapshot.
        expected: Digest,
        /// Current live snapshot.
        actual: Digest,
    },
    /// A copied or applied snapshot differs from its expected digest.
    SnapshotMismatch {
        /// Expected snapshot.
        expected: Digest,
        /// Actual snapshot.
        actual: Digest,
    },
    /// The base and shadow have identical regular-file content.
    NoChanges,
    /// Existing-file mode changes are not representable in the v1 change contract.
    UnsupportedMetadataChange(PathBuf),
    /// A create/modify operation lacks its result bytes.
    MissingBlob(Digest),
    /// A blob's bytes do not match its declared digest.
    BlobDigestMismatch {
        /// Declared digest.
        expected: Digest,
        /// Computed digest.
        actual: Digest,
    },
    /// A staged blob is not referenced by any operation.
    UnexpectedBlob(Digest),
    /// Created-file mode metadata is missing, unexpected, or unsafe.
    InvalidCreateModes,
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

impl Display for WorkspacePipelineError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Contract(error) => write!(formatter, "contract validation failed: {error}"),
            Self::PathValidation(error) => write!(formatter, "path validation failed: {error}"),
            Self::GrantRootMismatch { granted, canonical } => write!(
                formatter,
                "canonical root {} differs from granted root {}",
                canonical.display(),
                granted.display()
            ),
            Self::InvalidTimestamp => formatter.write_str("snapshot timestamp must be nonzero"),
            Self::NonUtf8Path(path) => {
                write!(formatter, "path is not valid UTF-8: {}", path.display())
            }
            Self::UnsafeEntry { path, kind } => {
                write!(formatter, "unsafe {kind:?} entry: {}", path.display())
            }
            Self::ConcurrentMutation(path) => {
                write!(formatter, "file changed during capture: {}", path.display())
            }
            Self::FileContentMismatch {
                path,
                expected,
                actual,
            } => write!(
                formatter,
                "file content changed at {}: expected {expected}, found {actual}",
                path.display()
            ),
            Self::DestinationNotAbsolute(path) => {
                write!(
                    formatter,
                    "shadow destination is not absolute: {}",
                    path.display()
                )
            }
            Self::DestinationExists(path) => {
                write!(formatter, "shadow destination exists: {}", path.display())
            }
            Self::UnsafeDestination(path) => {
                write!(
                    formatter,
                    "shadow destination is unsafe: {}",
                    path.display()
                )
            }
            Self::ShadowInsideWorkspace(path) => write!(
                formatter,
                "shadow destination is inside the workspace: {}",
                path.display()
            ),
            Self::BaseGrantMismatch => {
                formatter.write_str("base manifest does not match the workspace grant")
            }
            Self::StaleBase { expected, actual } => {
                write!(formatter, "stale base: expected {expected}, found {actual}")
            }
            Self::SnapshotMismatch { expected, actual } => write!(
                formatter,
                "snapshot mismatch: expected {expected}, found {actual}"
            ),
            Self::NoChanges => formatter.write_str("shadow contains no regular-file changes"),
            Self::UnsupportedMetadataChange(path) => write!(
                formatter,
                "existing-file metadata changes are unsupported: {}",
                path.display()
            ),
            Self::MissingBlob(digest) => write!(formatter, "missing result blob {digest}"),
            Self::BlobDigestMismatch { expected, actual } => write!(
                formatter,
                "blob digest mismatch: expected {expected}, found {actual}"
            ),
            Self::UnexpectedBlob(digest) => write!(formatter, "unexpected result blob {digest}"),
            Self::InvalidCreateModes => {
                formatter.write_str("created-file modes do not match create operations")
            }
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

impl std::error::Error for WorkspacePipelineError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Contract(error) => Some(error),
            Self::PathValidation(error) => Some(error),
            _ => None,
        }
    }
}

pub(crate) fn ensure_current(
    grant: &IssuedWorkspaceGrant,
    base: &WorkspaceManifest,
) -> Result<WorkspaceManifest, WorkspacePipelineError> {
    require_matching_base(grant, base)?;
    let current = WorkspaceManifest::capture(grant, 1)?;
    if current.snapshot.snapshot_id != base.snapshot.snapshot_id {
        return Err(WorkspacePipelineError::StaleBase {
            expected: base.snapshot.snapshot_id.clone(),
            actual: current.snapshot.snapshot_id.clone(),
        });
    }
    Ok(current)
}

pub(crate) fn hash_bytes(bytes: &[u8]) -> Result<Digest, WorkspacePipelineError> {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    digest_from_output(hasher.finalize())
}

pub(crate) fn read_stable_file(
    path: &Path,
) -> Result<(Vec<u8>, fs::Metadata), WorkspacePipelineError> {
    let before = fs::symlink_metadata(path)
        .map_err(|error| io_error("inspect file before read", path, &error))?;
    validate_regular_metadata(path, &before)?;
    let mut file = File::open(path).map_err(|error| io_error("open file", path, &error))?;
    let opened = file
        .metadata()
        .map_err(|error| io_error("inspect open file", path, &error))?;
    validate_regular_metadata(path, &opened)?;
    if !same_file_identity(&before, &opened) {
        return Err(WorkspacePipelineError::ConcurrentMutation(
            path.to_path_buf(),
        ));
    }
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)
        .map_err(|error| io_error("read file", path, &error))?;
    let after_open = file
        .metadata()
        .map_err(|error| io_error("reinspect open file", path, &error))?;
    let after_path = fs::symlink_metadata(path)
        .map_err(|error| io_error("reinspect file path", path, &error))?;
    if !same_stable_metadata(&opened, &after_open)
        || !same_file_identity(&after_open, &after_path)
        || after_open.len() != u64::try_from(bytes.len()).unwrap_or(u64::MAX)
    {
        return Err(WorkspacePipelineError::ConcurrentMutation(
            path.to_path_buf(),
        ));
    }
    Ok((bytes, after_open))
}

fn walk_directory(
    root: &Path,
    relative_directory: &Path,
    entries: &mut BTreeMap<PathBuf, ManifestEntry>,
) -> Result<(), WorkspacePipelineError> {
    let directory = root.join(relative_directory);
    let mut children = fs::read_dir(&directory)
        .map_err(|error| io_error("read snapshot directory", &directory, &error))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| io_error("enumerate snapshot directory", &directory, &error))?;
    children.sort_by_key(fs::DirEntry::file_name);

    for child in children {
        let name = child.file_name();
        let name_text = name
            .to_str()
            .ok_or_else(|| WorkspacePipelineError::NonUtf8Path(child.path()))?;
        if name_text.eq_ignore_ascii_case(".git") {
            continue;
        }
        let relative = relative_directory.join(name_text);
        validate_manifest_path(&relative)?;
        let absolute = root.join(&relative);
        let metadata = fs::symlink_metadata(&absolute)
            .map_err(|error| io_error("inspect snapshot entry", &absolute, &error))?;
        let file_type = metadata.file_type();
        if file_type.is_symlink() {
            return Err(WorkspacePipelineError::UnsafeEntry {
                path: relative,
                kind: UnsafeEntryKind::Symlink,
            });
        }
        if file_type.is_dir() {
            walk_directory(root, &relative, entries)?;
        } else if file_type.is_file() {
            validate_regular_metadata(&absolute, &metadata)?;
            let (bytes, stable_metadata) = read_stable_file(&absolute)?;
            let digest = hash_bytes(&bytes)?;
            entries.insert(
                relative,
                ManifestEntry {
                    digest,
                    length: stable_metadata.len(),
                    mode: normalized_mode(&stable_metadata),
                },
            );
        } else {
            return Err(WorkspacePipelineError::UnsafeEntry {
                path: relative,
                kind: UnsafeEntryKind::Special,
            });
        }
    }
    Ok(())
}

fn validate_regular_metadata(
    path: &Path,
    metadata: &fs::Metadata,
) -> Result<(), WorkspacePipelineError> {
    if !metadata.file_type().is_file() {
        return Err(WorkspacePipelineError::UnsafeEntry {
            path: path.to_path_buf(),
            kind: if metadata.file_type().is_symlink() {
                UnsafeEntryKind::Symlink
            } else {
                UnsafeEntryKind::Special
            },
        });
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if metadata.nlink() != 1 {
            return Err(WorkspacePipelineError::UnsafeEntry {
                path: path.to_path_buf(),
                kind: UnsafeEntryKind::HardLink,
            });
        }
    }
    Ok(())
}

#[cfg(unix)]
fn same_file_identity(left: &fs::Metadata, right: &fs::Metadata) -> bool {
    use std::os::unix::fs::MetadataExt;
    left.dev() == right.dev() && left.ino() == right.ino()
}

#[cfg(not(unix))]
fn same_file_identity(left: &fs::Metadata, right: &fs::Metadata) -> bool {
    left.len() == right.len() && left.modified().ok() == right.modified().ok()
}

#[cfg(unix)]
fn same_stable_metadata(left: &fs::Metadata, right: &fs::Metadata) -> bool {
    use std::os::unix::fs::MetadataExt;
    same_file_identity(left, right)
        && left.size() == right.size()
        && left.mtime() == right.mtime()
        && left.mtime_nsec() == right.mtime_nsec()
        && left.ctime() == right.ctime()
        && left.ctime_nsec() == right.ctime_nsec()
}

#[cfg(not(unix))]
fn same_stable_metadata(left: &fs::Metadata, right: &fs::Metadata) -> bool {
    same_file_identity(left, right)
        && left.len() == right.len()
        && left.modified().ok() == right.modified().ok()
}

fn manifest_digest(
    entries: &BTreeMap<PathBuf, ManifestEntry>,
) -> Result<Digest, WorkspacePipelineError> {
    let mut hasher = Sha256::new();
    hasher.update(MANIFEST_DOMAIN);
    hasher.update(
        u64::try_from(entries.len())
            .unwrap_or(u64::MAX)
            .to_be_bytes(),
    );
    for (path, entry) in entries {
        let encoded = portable_path(path)?;
        hasher.update(
            u64::try_from(encoded.len())
                .unwrap_or(u64::MAX)
                .to_be_bytes(),
        );
        hasher.update(encoded.as_bytes());
        hasher.update(entry.length.to_be_bytes());
        hasher.update(entry.digest.as_str().as_bytes());
        hasher.update(entry.mode.to_be_bytes());
    }
    digest_from_output(hasher.finalize())
}

fn deterministic_change_set_id(
    base: &Digest,
    result: &Digest,
    operations: &[FileOperation],
) -> String {
    let mut hasher = Sha256::new();
    hasher.update(CHANGE_SET_DOMAIN);
    hasher.update(base.as_str().as_bytes());
    hasher.update(result.as_str().as_bytes());
    for operation in operations {
        let kind = match operation {
            FileOperation::Create { .. } => b'C',
            FileOperation::Modify { .. } => b'M',
            FileOperation::Delete { .. } => b'D',
        };
        hasher.update([kind]);
        hasher.update(operation.path().to_string_lossy().as_bytes());
    }
    format!("changeset-{}", encode_hex(hasher.finalize().as_ref()))
}

fn digest_from_output(output: impl AsRef<[u8]>) -> Result<Digest, WorkspacePipelineError> {
    let text = encode_hex(output.as_ref());
    Digest::parse(text).map_err(WorkspacePipelineError::Contract)
}

fn portable_path(path: &Path) -> Result<String, WorkspacePipelineError> {
    validate_manifest_path(path)?;
    let mut encoded = String::new();
    for (index, component) in path.components().enumerate() {
        let Component::Normal(component) = component else {
            return Err(WorkspacePipelineError::UnsafeDestination(
                path.to_path_buf(),
            ));
        };
        let text = component
            .to_str()
            .ok_or_else(|| WorkspacePipelineError::NonUtf8Path(path.to_path_buf()))?;
        if index != 0 {
            encoded.push('/');
        }
        encoded.push_str(text);
    }
    Ok(encoded)
}

fn validate_manifest_path(path: &Path) -> Result<(), WorkspacePipelineError> {
    if path.is_absolute() || path.as_os_str().is_empty() {
        return Err(WorkspacePipelineError::UnsafeDestination(
            path.to_path_buf(),
        ));
    }
    for component in path.components() {
        let Component::Normal(component) = component else {
            return Err(WorkspacePipelineError::UnsafeDestination(
                path.to_path_buf(),
            ));
        };
        let text = component
            .to_str()
            .ok_or_else(|| WorkspacePipelineError::NonUtf8Path(path.to_path_buf()))?;
        if text.eq_ignore_ascii_case(".git") {
            return Err(WorkspacePipelineError::UnsafeDestination(
                path.to_path_buf(),
            ));
        }
    }
    Ok(())
}

/// Applies every private-shadow destination rule without mutating anything.
///
/// Shared verbatim by [`ShadowWorkspace::create`] and
/// [`ShadowWorkspace::worker_created_destination`] so the desktop naming a
/// worker-created shadow and the fixture creating one are held to the identical
/// authority, currency, and containment checks. Returns the canonical
/// destination path: the canonicalized parent joined to the destination's own
/// final component.
fn validated_shadow_destination(
    grant: &IssuedWorkspaceGrant,
    base: &WorkspaceManifest,
    destination: &Path,
) -> Result<PathBuf, WorkspacePipelineError> {
    grant
        .validate_integrity()
        .map_err(WorkspacePipelineError::Contract)?;
    let contract = grant.contract();
    require_matching_base(grant, base)?;
    ensure_current(grant, base)?;

    if !destination.is_absolute() {
        return Err(WorkspacePipelineError::DestinationNotAbsolute(
            destination.to_path_buf(),
        ));
    }
    if fs::symlink_metadata(destination).is_ok() {
        return Err(WorkspacePipelineError::DestinationExists(
            destination.to_path_buf(),
        ));
    }
    // `file_name` is `None` for `/`, `.`, and any path ending in `..`, so this
    // one check also rejects every non-ordinary final component.
    let leaf = destination
        .file_name()
        .ok_or_else(|| WorkspacePipelineError::UnsafeDestination(destination.to_path_buf()))?
        .to_owned();
    let parent = destination
        .parent()
        .ok_or_else(|| WorkspacePipelineError::UnsafeDestination(destination.to_path_buf()))?;
    let parent = fs::canonicalize(parent)
        .map_err(|error| io_error("canonicalize shadow parent", parent, &error))?;
    if parent.starts_with(&contract.canonical_root) {
        return Err(WorkspacePipelineError::ShadowInsideWorkspace(
            destination.to_path_buf(),
        ));
    }
    Ok(parent.join(leaf))
}

fn require_matching_base(
    grant: &IssuedWorkspaceGrant,
    base: &WorkspaceManifest,
) -> Result<(), WorkspacePipelineError> {
    let contract = grant.contract();
    if base.root != contract.canonical_root || base.snapshot.grant_hash != contract.grant_hash {
        return Err(WorkspacePipelineError::BaseGrantMismatch);
    }
    Ok(())
}

fn copy_manifest_files(
    base: &WorkspaceManifest,
    destination: &Path,
) -> Result<(), WorkspacePipelineError> {
    for (relative, expected) in &base.entries {
        let source = base.root.join(relative);
        let (bytes, metadata) = read_stable_file(&source)?;
        let actual = hash_bytes(&bytes)?;
        if actual != expected.digest {
            return Err(WorkspacePipelineError::FileContentMismatch {
                path: relative.clone(),
                expected: expected.digest.clone(),
                actual,
            });
        }
        let target = destination.join(relative);
        let parent = target
            .parent()
            .ok_or_else(|| WorkspacePipelineError::UnsafeDestination(target.clone()))?;
        fs::create_dir_all(parent)
            .map_err(|error| io_error("create shadow directory", parent, &error))?;
        set_private_directory_permissions(parent)?;
        let mut output = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&target)
            .map_err(|error| io_error("create shadow file", &target, &error))?;
        set_copied_file_permissions(&output, &metadata, &target)?;
        output
            .write_all(&bytes)
            .map_err(|error| io_error("write shadow file", &target, &error))?;
        output
            .sync_all()
            .map_err(|error| io_error("sync shadow file", &target, &error))?;
    }
    Ok(())
}

fn insert_verified_blob(
    root: &Path,
    path: &Path,
    expected: &ManifestEntry,
    blobs: &mut BTreeMap<Digest, Vec<u8>>,
) -> Result<(), WorkspacePipelineError> {
    let (bytes, _) = read_stable_file(&root.join(path))?;
    let actual = hash_bytes(&bytes)?;
    if actual != expected.digest {
        return Err(WorkspacePipelineError::BlobDigestMismatch {
            expected: expected.digest.clone(),
            actual,
        });
    }
    blobs.entry(expected.digest.clone()).or_insert(bytes);
    Ok(())
}

#[cfg(unix)]
fn normalized_mode(metadata: &fs::Metadata) -> u32 {
    use std::os::unix::fs::PermissionsExt;
    metadata.permissions().mode() & 0o777
}

#[cfg(not(unix))]
fn normalized_mode(metadata: &fs::Metadata) -> u32 {
    if metadata.permissions().readonly() {
        0o444
    } else {
        0o644
    }
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

#[cfg(unix)]
fn set_private_directory_permissions(path: &Path) -> Result<(), WorkspacePipelineError> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))
        .map_err(|error| io_error("set private directory permissions", path, &error))
}

#[cfg(not(unix))]
fn set_private_directory_permissions(_path: &Path) -> Result<(), WorkspacePipelineError> {
    Ok(())
}

#[cfg(unix)]
fn set_copied_file_permissions(
    output: &File,
    source: &fs::Metadata,
    path: &Path,
) -> Result<(), WorkspacePipelineError> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    output
        .set_permissions(fs::Permissions::from_mode(source.mode() & 0o777))
        .map_err(|error| io_error("set shadow file permissions", path, &error))
}

#[cfg(not(unix))]
fn set_copied_file_permissions(
    output: &File,
    source: &fs::Metadata,
    path: &Path,
) -> Result<(), WorkspacePipelineError> {
    output
        .set_permissions(source.permissions())
        .map_err(|error| io_error("set shadow file permissions", path, &error))
}

fn io_error(operation: &'static str, path: &Path, error: &io::Error) -> WorkspacePipelineError {
    WorkspacePipelineError::Io {
        operation,
        path: path.to_path_buf(),
        message: error.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use grok_build_core::{
        WorkspaceGrantIssuer, WorkspaceGrantRequest, WorkspaceNetworkPolicy, WorkspacePermissions,
    };
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT_DIRECTORY: AtomicU64 = AtomicU64::new(0);

    struct TestDirectory(PathBuf);

    impl TestDirectory {
        fn new(label: &str) -> Self {
            let number = NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed);
            #[cfg(unix)]
            let temporary_root = Path::new("/tmp");
            #[cfg(not(unix))]
            let temporary_root = std::env::temp_dir();
            let path = temporary_root.join(format!(
                "grok-build-workspace-{label}-{}-{number}",
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
            grant_id: "test-grant".into(),
            workspace_root: root.to_path_buf(),
            permissions: WorkspacePermissions::trusted(),
            network: WorkspaceNetworkPolicy::Denied,
            policy_version: 1,
        })
        .unwrap()
    }

    #[test]
    fn manifest_is_deterministic_and_excludes_git() {
        let directory = TestDirectory::new("deterministic");
        fs::create_dir_all(directory.0.join("src")).unwrap();
        fs::write(
            directory.0.join("src/lib.rs"),
            b"pub fn value() -> u8 { 1 }\n",
        )
        .unwrap();
        fs::create_dir_all(directory.0.join(".git")).unwrap();
        fs::write(directory.0.join(".git/config"), b"ignored").unwrap();
        fs::create_dir_all(directory.0.join(".GIT")).unwrap();
        fs::write(directory.0.join(".GIT/HEAD"), b"also ignored").unwrap();
        let grant = grant(&directory.0);

        let first = WorkspaceManifest::capture(&grant, 1).unwrap();
        let second = WorkspaceManifest::capture(&grant, 2).unwrap();

        assert_eq!(first.snapshot.snapshot_id, second.snapshot.snapshot_id);
        assert_eq!(first.entries.len(), 1);
        assert!(first.entry("src/lib.rs").is_some());
        assert!(first.entry(".git/config").is_none());
        assert!(first.entry(".GIT/HEAD").is_none());
    }

    #[cfg(unix)]
    #[test]
    fn snapshot_rejects_symlinks_hardlinks_and_special_files() {
        use std::os::unix::fs::symlink;
        use std::os::unix::net::UnixListener;

        let symlink_root = TestDirectory::new("snapshot-symlink");
        fs::write(symlink_root.0.join("target"), b"data").unwrap();
        symlink("target", symlink_root.0.join("link")).unwrap();
        assert!(matches!(
            WorkspaceManifest::capture(&grant(&symlink_root.0), 1),
            Err(WorkspacePipelineError::UnsafeEntry {
                kind: UnsafeEntryKind::Symlink,
                ..
            })
        ));

        let hardlink_root = TestDirectory::new("snapshot-hardlink");
        fs::write(hardlink_root.0.join("first"), b"data").unwrap();
        fs::hard_link(
            hardlink_root.0.join("first"),
            hardlink_root.0.join("second"),
        )
        .unwrap();
        assert!(matches!(
            WorkspaceManifest::capture(&grant(&hardlink_root.0), 1),
            Err(WorkspacePipelineError::UnsafeEntry {
                kind: UnsafeEntryKind::HardLink,
                ..
            })
        ));

        let socket_root = TestDirectory::new("snapshot-socket");
        let _listener = UnixListener::bind(socket_root.0.join("socket")).unwrap();
        assert!(matches!(
            WorkspaceManifest::capture(&grant(&socket_root.0), 1),
            Err(WorkspacePipelineError::UnsafeEntry {
                kind: UnsafeEntryKind::Special,
                ..
            })
        ));
    }

    #[test]
    fn shadow_creation_detects_stale_base() {
        let workspace = TestDirectory::new("shadow-stale");
        let private = TestDirectory::new("shadow-stale-private");
        fs::write(workspace.0.join("file"), b"base").unwrap();
        let grant = grant(&workspace.0);
        let base = WorkspaceManifest::capture(&grant, 1).unwrap();
        fs::write(workspace.0.join("file"), b"changed").unwrap();

        let result = ShadowWorkspace::create(&grant, &base, private.0.join("shadow"));

        assert!(matches!(
            result,
            Err(WorkspacePipelineError::StaleBase { .. })
        ));
    }

    /// Naming a worker-owned shadow creates nothing, while applying the same
    /// pre-mutation checks as `create`.
    #[test]
    fn worker_created_shadow_destination_names_without_creating_and_keeps_every_create_check() {
        let workspace = TestDirectory::new("shadow-named");
        let private = TestDirectory::new("shadow-named-private");
        fs::write(workspace.0.join("file"), b"base").unwrap();
        let grant = grant(&workspace.0);
        let base = WorkspaceManifest::capture(&grant, 1).unwrap();

        // Naming creates nothing, and the root is the exact canonical path the
        // runner's `fixed_shadow_leaf` will compare against its private root.
        let destination = private.0.join("private-shadow");
        let named =
            ShadowWorkspace::worker_created_destination(&grant, &base, &destination).unwrap();
        assert_eq!(named.root(), destination);
        assert!(fs::symlink_metadata(named.root()).is_err());
        assert_eq!(named.base().snapshot.snapshot_id, base.snapshot.snapshot_id);

        // An already-existing destination is refused identically to `create`,
        // which is the same rule the runner enforces at initialization.
        fs::create_dir(&destination).unwrap();
        assert!(matches!(
            ShadowWorkspace::worker_created_destination(&grant, &base, &destination),
            Err(WorkspacePipelineError::DestinationExists(_))
        ));
        fs::remove_dir(&destination).unwrap();

        // Containment, absoluteness, and workspace disjointness all still hold.
        assert!(matches!(
            ShadowWorkspace::worker_created_destination(
                &grant,
                &base,
                workspace.0.join("inside-shadow")
            ),
            Err(WorkspacePipelineError::ShadowInsideWorkspace(_))
        ));
        assert!(matches!(
            ShadowWorkspace::worker_created_destination(&grant, &base, Path::new("relative")),
            Err(WorkspacePipelineError::DestinationNotAbsolute(_))
        ));

        // And a stale live workspace is refused before any name is handed out.
        fs::write(workspace.0.join("file"), b"changed").unwrap();
        assert!(matches!(
            ShadowWorkspace::worker_created_destination(&grant, &base, &destination),
            Err(WorkspacePipelineError::StaleBase { .. })
        ));
    }

    #[test]
    fn shadow_diff_uses_real_change_set_and_verified_blobs() {
        let workspace = TestDirectory::new("shadow-diff");
        let private = TestDirectory::new("shadow-diff-private");
        fs::write(workspace.0.join("modify"), b"before").unwrap();
        fs::write(workspace.0.join("delete"), b"remove").unwrap();
        let grant = grant(&workspace.0);
        let base = WorkspaceManifest::capture(&grant, 1).unwrap();
        let shadow = ShadowWorkspace::create(&grant, &base, private.0.join("shadow")).unwrap();
        fs::write(shadow.root().join("modify"), b"after").unwrap();
        fs::remove_file(shadow.root().join("delete")).unwrap();
        fs::write(shadow.root().join("create"), b"new").unwrap();

        let staged = shadow.stage_changes("test-change", 2).unwrap();

        staged.change_set().validate().unwrap();
        assert_eq!(staged.change_set().operations.len(), 3);
        assert_eq!(staged.blobs().len(), 2);
        assert!(matches!(
            &staged.change_set().operations[0],
            FileOperation::Create { path, .. } if path == Path::new("create")
        ));
        assert!(matches!(
            &staged.change_set().operations[1],
            FileOperation::Delete { path, .. } if path == Path::new("delete")
        ));
        assert!(matches!(
            &staged.change_set().operations[2],
            FileOperation::Modify { path, .. } if path == Path::new("modify")
        ));
    }

    #[cfg(unix)]
    #[test]
    fn existing_file_mode_changes_are_explicitly_rejected() {
        use std::os::unix::fs::PermissionsExt;

        let workspace = TestDirectory::new("mode-workspace");
        let private = TestDirectory::new("mode-private");
        fs::write(workspace.0.join("file"), b"same bytes").unwrap();
        let grant = grant(&workspace.0);
        let base = WorkspaceManifest::capture(&grant, 1).unwrap();
        let shadow = ShadowWorkspace::create(&grant, &base, private.0.join("shadow")).unwrap();
        let original_mode = fs::metadata(shadow.root().join("file"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        let changed_mode = if original_mode == 0o600 { 0o644 } else { 0o600 };
        fs::set_permissions(
            shadow.root().join("file"),
            fs::Permissions::from_mode(changed_mode),
        )
        .unwrap();

        let result = shadow.stage_changes("mode-only", 2);

        assert!(matches!(
            result,
            Err(WorkspacePipelineError::UnsupportedMetadataChange(path))
                if path == Path::new("file")
        ));
    }

    #[test]
    fn copy_mismatch_reports_file_digest_not_snapshot_digest() {
        let workspace = TestDirectory::new("copy-mismatch-workspace");
        let private = TestDirectory::new("copy-mismatch-private");
        fs::write(workspace.0.join("file"), b"captured").unwrap();
        let grant = grant(&workspace.0);
        let base = WorkspaceManifest::capture(&grant, 1).unwrap();
        fs::write(workspace.0.join("file"), b"changed after capture").unwrap();
        let destination = private.0.join("copy");
        fs::create_dir(&destination).unwrap();

        let result = copy_manifest_files(&base, &destination);

        assert!(matches!(
            result,
            Err(WorkspacePipelineError::FileContentMismatch {
                path,
                expected,
                actual,
            }) if path == Path::new("file")
                && expected == base.entry("file").unwrap().digest
                && actual != base.snapshot.snapshot_id
        ));
    }
}
