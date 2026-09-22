//! Retained-capability workspace capture, shadow copy, and staging.
//!
//! Ambient authority is limited to opening the exact live root and creating a
//! disjoint private shadow leaf. Capture, copy, and staging then traverse only
//! retained directories without following links.

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::{OsStr, OsString};
use std::fmt::{self, Display, Formatter};
use std::fs;
use std::io::{self, Read, Write};
use std::path::{Component, Path, PathBuf};

use cap_fs_ext::{
    DirExt, FollowSymlinks, MetadataExt as PortableMetadataExt, OpenOptionsFollowExt, OsMetadataExt,
};
use cap_std::fs::{
    Dir, DirBuilder, DirBuilderExt, Metadata, OpenOptions, OpenOptionsExt, PermissionsExt,
};
use cap_std::{ambient_authority, fs::Permissions};
use grok_build_core::{ChangeSet, Digest, FileOperation, IssuedWorkspaceGrant, WorkspaceSnapshot};
use rustix::fs::{RenameFlags, renameat_with};
use sha2::{Digest as _, Sha256};

use crate::capability_apply::{
    CapabilityApplyError, DirectoryPathAnchor, MAX_APPLY_FILE_BYTES, capture_descriptor_entries,
    normalize_path, read_descriptor_regular, snapshot_digest,
};
use crate::durable_directory::sync_directory_entries as sync_directory;
use crate::{ManifestEntry, StagedChangeSet, WorkspaceManifest};

const CHANGE_SET_DOMAIN: &[u8] = b"grok-build.change-set.sha256.v1\0";
const DISCARD_TREE_DOMAIN: &[u8] = b"grok-build.shadow-discard-tree.sha256.v1\0";
const DISCARD_ID_DOMAIN: &[u8] = b"grok-build.shadow-discard-id.sha256.v1\0";
const DISCARD_INTENT_VERSION: &str = "grok-build-shadow-discard-v1";
const DISCARD_STARTED_VERSION: &str = "grok-build-shadow-discard-started-v1";
const DISCARD_INTENT_PREFIX: &str = ".discard-intent-v1-";
const DISCARD_INTENT_PREPARING_PREFIX: &str = ".discard-intent-preparing-v1-";
const DISCARD_STARTED_PREFIX: &str = ".discard-started-v1-";
const DISCARD_STARTED_PREPARING_PREFIX: &str = ".discard-started-preparing-v1-";
const DISCARD_TOMBSTONE_PREFIX: &str = ".discard-tombstone-v1-";
const MAX_DISCARD_ENTRIES: usize = 100_000;
const MAX_DISCARD_INTENT_BYTES: u64 = 4_096;

/// Fail-closed error from descriptor-relative capture, copy, or staging.
#[derive(Debug)]
pub enum CapabilityWorkspaceError {
    /// The supplied grant is invalid or differs from acquisition authority.
    Authority(String),
    /// The grant does not authorize the requested workspace operation.
    PermissionDenied(&'static str),
    /// A retained or named workspace/shadow root changed identity.
    Root(String),
    /// Descriptor traversal rejected a path or filesystem object.
    Descriptor(CapabilityApplyError),
    /// A shadow destination is not an absolute, disjoint, absent leaf.
    Destination(String),
    /// The supplied base no longer equals the descriptor-captured live root.
    StaleBase {
        /// Required immutable base.
        expected: Digest,
        /// Observed live snapshot.
        actual: Digest,
    },
    /// A reopened read-only verification shadow differs from its exact
    /// preauthorized content-addressed snapshot.
    SnapshotMismatch {
        /// Snapshot authorized by the durable verifier launch.
        expected: Digest,
        /// Descriptor-relatively observed shadow snapshot.
        actual: Digest,
    },
    /// A copied or staged file no longer matches its manifest entry.
    FileMismatch(PathBuf),
    /// A capture, copy, or staged blob exceeds the v1 complete-file ceiling.
    FileTooLarge {
        /// Rejected logical path.
        path: PathBuf,
        /// Maximum accepted complete byte count.
        limit: u64,
    },
    /// Existing-file metadata changes are outside the file-operation contract.
    UnsupportedMetadataChange(PathBuf),
    /// Staging observed no regular-file changes.
    NoChanges,
    /// A durable shadow discard has an unsafe or ambiguous restart state.
    DiscardConflict {
        /// Stable bounded discard identity.
        discard_id: String,
        /// Exact fail-closed reason.
        reason: String,
    },
    /// Deterministic test-only process-crash boundary during discard.
    InjectedDiscardCrash {
        /// Exact durable boundary reached before simulated process death.
        checkpoint: &'static str,
        /// Number of tree nodes already removed.
        removed_nodes: usize,
    },
    /// A manifest or staged contract was invalid.
    Contract(String),
    /// A descriptor-relative filesystem operation failed.
    Io {
        /// Failed operation.
        operation: &'static str,
        /// Logical or acquisition path.
        path: PathBuf,
        /// Operating-system error text.
        message: String,
    },
}

impl Display for CapabilityWorkspaceError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Authority(message) => {
                write!(formatter, "workspace authority rejected: {message}")
            }
            Self::PermissionDenied(permission) => {
                write!(formatter, "workspace grant lacks {permission} permission")
            }
            Self::Root(message) => {
                write!(formatter, "capability workspace root rejected: {message}")
            }
            Self::Descriptor(error) => {
                write!(formatter, "descriptor workspace operation failed: {error}")
            }
            Self::Destination(message) => write!(
                formatter,
                "invalid capability shadow destination: {message}"
            ),
            Self::StaleBase { expected, actual } => {
                write!(
                    formatter,
                    "stale capability base: expected {expected}, found {actual}"
                )
            }
            Self::SnapshotMismatch { expected, actual } => write!(
                formatter,
                "verification shadow mismatch: expected {expected}, found {actual}"
            ),
            Self::FileMismatch(path) => {
                write!(formatter, "manifest file changed at {}", path.display())
            }
            Self::FileTooLarge { path, limit } => write!(
                formatter,
                "{} exceeds the complete {limit}-byte capability workspace ceiling",
                path.display()
            ),
            Self::UnsupportedMetadataChange(path) => write!(
                formatter,
                "existing-file metadata change is unsupported at {}",
                path.display()
            ),
            Self::NoChanges => formatter.write_str("capability shadow contains no file changes"),
            Self::DiscardConflict { discard_id, reason } => {
                write!(
                    formatter,
                    "shadow discard `{discard_id}` is ambiguous: {reason}"
                )
            }
            Self::InjectedDiscardCrash {
                checkpoint,
                removed_nodes,
            } => write!(
                formatter,
                "injected shadow-discard crash at {checkpoint} after {removed_nodes} removals"
            ),
            Self::Contract(message) => write!(formatter, "invalid workspace contract: {message}"),
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

impl std::error::Error for CapabilityWorkspaceError {}

impl From<CapabilityApplyError> for CapabilityWorkspaceError {
    fn from(error: CapabilityApplyError) -> Self {
        Self::Descriptor(error)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ObjectIdentity {
    device: u64,
    inode: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct PrivateRootIdentity {
    object: ObjectIdentity,
    uid: u32,
    mode: u32,
}

/// Bounded durable proof that one exact private shadow root was discarded.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CapabilityShadowDiscardEvidence {
    discard_id: String,
    original_child_digest: Digest,
    grant_hash: Digest,
    root_device: u64,
    root_inode: u64,
    tree_digest: Digest,
    regular_file_count: u64,
    directory_count: u64,
    total_file_bytes: u64,
}

impl CapabilityShadowDiscardEvidence {
    /// Returns the stable content-addressed discard identity.
    #[must_use]
    pub fn discard_id(&self) -> &str {
        &self.discard_id
    }

    /// Returns a digest of the original child name without exposing the path.
    #[must_use]
    pub const fn original_child_digest(&self) -> &Digest {
        &self.original_child_digest
    }

    /// Returns the exact workspace-grant binding captured before discard.
    #[must_use]
    pub const fn grant_hash(&self) -> &Digest {
        &self.grant_hash
    }

    /// Returns the discarded root's filesystem device.
    #[must_use]
    pub const fn root_device(&self) -> u64 {
        self.root_device
    }

    /// Returns the discarded root's filesystem inode.
    #[must_use]
    pub const fn root_inode(&self) -> u64 {
        self.root_inode
    }

    /// Returns the canonical digest of all original regular files/directories.
    #[must_use]
    pub const fn tree_digest(&self) -> &Digest {
        &self.tree_digest
    }

    /// Returns the complete original regular-file count.
    #[must_use]
    pub const fn regular_file_count(&self) -> u64 {
        self.regular_file_count
    }

    /// Returns the complete original directory count, including the root.
    #[must_use]
    pub const fn directory_count(&self) -> u64 {
        self.directory_count
    }

    /// Returns the checked sum of original regular-file lengths.
    #[must_use]
    pub const fn total_file_bytes(&self) -> u64 {
        self.total_file_bytes
    }
}

/// Completed durable shadow discards reconciled after restart.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct CapabilityShadowDiscardRecoveryReport {
    completed: Vec<CapabilityShadowDiscardEvidence>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum DiscardNodeKind {
    Directory,
    Regular { digest: Digest, length: u64 },
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct DiscardNode {
    path: PathBuf,
    identity: ObjectIdentity,
    mode: u32,
    kind: DiscardNodeKind,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct DiscardIntent {
    evidence: CapabilityShadowDiscardEvidence,
    original_child: OsString,
    tombstone: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct DiscardStartedRecord {
    discard_id: String,
    intent_digest: Digest,
    root_device: u64,
    root_inode: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DiscardFaultPoint {
    IntentSynced,
    RenameBeforeSync,
    RenameSynced,
    DeletionStarted,
    RemovedNode(usize),
    RootRemoved,
}

impl CapabilityShadowDiscardRecoveryReport {
    /// Returns completed discard evidence in canonical discard-id order.
    #[must_use]
    pub fn completed(&self) -> &[CapabilityShadowDiscardEvidence] {
        &self.completed
    }

    /// Returns whether no durable discard intent required reconciliation.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.completed.is_empty()
    }
}

/// An exact owner-private directory capability under which shadows may be created.
///
/// Acquisition resolves and verifies one existing canonical `0700` directory.
/// Shadow creation accepts only a single normalized child name and never
/// reacquires an arbitrary destination parent through ambient authority.
pub struct CapabilityShadowStore {
    root: Dir,
    root_parent: Dir,
    root_leaf: OsString,
    root_identity: PrivateRootIdentity,
    path_anchor: DirectoryPathAnchor,
    root_path: PathBuf,
}

impl CapabilityShadowStore {
    /// Acquires an existing canonical, owner-owned `0700` shadow store.
    ///
    /// # Errors
    ///
    /// Returns an error if the path is non-absolute/non-canonical, linked or
    /// replaced during acquisition, or does not name an owner-private directory.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, CapabilityWorkspaceError> {
        let path = path.as_ref();
        if !path.is_absolute() {
            return Err(CapabilityWorkspaceError::Destination(
                "shadow store must be absolute".into(),
            ));
        }
        let canonical = fs::canonicalize(path)
            .map_err(|error| io_error("canonicalize shadow store", path, &error))?;
        if canonical != path {
            return Err(CapabilityWorkspaceError::Destination(
                "shadow store must use its exact canonical path".into(),
            ));
        }
        let parent_path = canonical.parent().ok_or_else(|| {
            CapabilityWorkspaceError::Destination("shadow store has no parent".into())
        })?;
        let root_leaf = canonical
            .file_name()
            .ok_or_else(|| {
                CapabilityWorkspaceError::Destination("shadow store has no leaf".into())
            })?
            .to_os_string();
        let root_parent = Dir::open_ambient_dir(parent_path, ambient_authority())
            .map_err(|error| io_error("open shadow-store parent", &canonical, &error))?;
        let root = root_parent
            .open_dir_nofollow(&root_leaf)
            .map_err(|error| io_error("open shadow store without links", &canonical, &error))?;
        let root_identity = validate_private_root(&root, "shadow store")?;
        let path_anchor =
            DirectoryPathAnchor::acquire(&canonical, "shadow store").map_err(path_anchor_error)?;
        if path_anchor.final_device_inode()
            != (root_identity.object.device, root_identity.object.inode)
        {
            return Err(CapabilityWorkspaceError::Root(
                "shadow-store path anchor differs from its retained descriptor".into(),
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
        store.validate()?;
        let resolved_after = fs::canonicalize(path)
            .map_err(|error| io_error("revalidate shadow-store path", path, &error))?;
        if resolved_after != store.root_path {
            return Err(CapabilityWorkspaceError::Root(
                "shadow-store path changed during acquisition".into(),
            ));
        }
        Ok(store)
    }

    /// Returns the exact canonical store path used only for policy/reporting.
    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root_path
    }

    /// Clones the already-acquired store capability for a session-sealed
    /// command boundary. The clone is returned only after the complete retained
    /// and named store authority has been revalidated.
    pub(crate) fn clone_command_store_capability(&self) -> Result<Dir, CapabilityWorkspaceError> {
        self.validate()?;
        self.root.try_clone().map_err(|error| {
            io_error(
                "clone retained command shadow store",
                &self.root_path,
                &error,
            )
        })
    }

    /// Reconciles every exact durable discard intent beneath this retained store.
    ///
    /// Ordinary shadow children are never inferred to be disposable. Recovery
    /// acts only on a canonical owner-private intent, and requires either its
    /// exact original root identity or its exact identity-bound tombstone.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid store, malformed/orphaned discard state,
    /// ambiguous names, unsafe tree objects, identity races, or durability I/O.
    #[allow(
        clippy::too_many_lines,
        reason = "recovery keeps reserved-name classification, exact intent reconciliation, and orphan cleanup auditable"
    )]
    pub fn recover_discards(
        &self,
    ) -> Result<CapabilityShadowDiscardRecoveryReport, CapabilityWorkspaceError> {
        self.validate()?;
        let mut names = self
            .root
            .entries()
            .map_err(|error| io_error("enumerate shadow store", &self.root_path, &error))?
            .map(|entry| {
                entry
                    .map(|entry| entry.file_name())
                    .map_err(|error| io_error("read shadow-store entry", &self.root_path, &error))
            })
            .collect::<Result<Vec<_>, _>>()?;
        names.sort();
        let mut intent_names = Vec::new();
        let mut preparing_names = Vec::new();
        let mut reserved_names = BTreeSet::new();
        for name in names {
            let text = name
                .to_str()
                .ok_or_else(|| CapabilityWorkspaceError::DiscardConflict {
                    discard_id: "unknown".into(),
                    reason: "non-UTF-8 shadow-store entry".into(),
                })?;
            if text.starts_with(DISCARD_INTENT_PREPARING_PREFIX)
                || text.starts_with(DISCARD_STARTED_PREPARING_PREFIX)
            {
                let prefix = if text.starts_with(DISCARD_INTENT_PREPARING_PREFIX) {
                    DISCARD_INTENT_PREPARING_PREFIX
                } else {
                    DISCARD_STARTED_PREPARING_PREFIX
                };
                if !is_discard_id_suffix(text, prefix) {
                    return Err(discard_conflict(
                        text,
                        "malformed discard-record preparation",
                    ));
                }
                preparing_names.push(text.to_owned());
            } else if text.starts_with(DISCARD_INTENT_PREFIX) {
                if !is_discard_id_suffix(text, DISCARD_INTENT_PREFIX) {
                    return Err(discard_conflict(text, "malformed discard-intent name"));
                }
                intent_names.push(text.to_owned());
                reserved_names.insert(text.to_owned());
            } else if text.starts_with(DISCARD_STARTED_PREFIX)
                || text.starts_with(DISCARD_TOMBSTONE_PREFIX)
                || text.starts_with(".discard-")
            {
                reserved_names.insert(text.to_owned());
            }
        }
        if intent_names.len() > MAX_DISCARD_ENTRIES {
            return Err(discard_conflict(
                "store",
                format!(
                    "discard intent count {} exceeds {MAX_DISCARD_ENTRIES}",
                    intent_names.len()
                ),
            ));
        }
        for preparing in preparing_names {
            let metadata = self.root.symlink_metadata(&preparing).map_err(|error| {
                io_error(
                    "inspect discard-record preparation",
                    Path::new(&preparing),
                    &error,
                )
            })?;
            validate_private_regular(Path::new(&preparing), &metadata)?;
            remove_private_file(&self.root, &preparing)?;
            sync_directory(&self.root).map_err(|error| {
                io_error(
                    "sync discard-record preparation cleanup",
                    Path::new(&preparing),
                    &error,
                )
            })?;
        }

        let mut report = CapabilityShadowDiscardRecoveryReport::default();
        let mut consumed_reserved = BTreeSet::new();
        for intent_name in intent_names {
            let intent = read_discard_intent(&self.root, &intent_name)?;
            if discard_intent_name(&intent.evidence.discard_id) != intent_name {
                return Err(discard_conflict(
                    &intent.evidence.discard_id,
                    "intent filename differs from its canonical content identity",
                ));
            }
            consumed_reserved.insert(intent_name.clone());
            consumed_reserved.insert(discard_started_name(&intent.evidence.discard_id));
            consumed_reserved.insert(intent.tombstone.clone());
            let evidence =
                reconcile_discard(&self.root, &self.root_path, &intent_name, &intent, None)?;
            report.completed.push(evidence);
        }
        for orphan in reserved_names.difference(&consumed_reserved) {
            if is_discard_id_suffix(orphan, DISCARD_STARTED_PREFIX) {
                let _ = read_discard_started(&self.root, orphan)?;
                remove_private_file(&self.root, orphan)?;
                sync_directory(&self.root).map_err(|error| {
                    io_error(
                        "sync orphan discard-started cleanup",
                        Path::new(orphan),
                        &error,
                    )
                })?;
                continue;
            }
            return Err(discard_conflict(
                orphan,
                "reserved discard entry has no exact durable intent",
            ));
        }
        self.validate()?;
        report
            .completed
            .sort_by(|left, right| left.discard_id.cmp(&right.discard_id));
        Ok(report)
    }

    fn validate(&self) -> Result<(), CapabilityWorkspaceError> {
        self.path_anchor
            .validate("shadow store")
            .map_err(path_anchor_error)?;
        if validate_private_root(&self.root, "retained shadow store")? != self.root_identity {
            return Err(CapabilityWorkspaceError::Root(
                "retained shadow-store identity, owner, or mode changed".into(),
            ));
        }
        let named = self
            .root_parent
            .open_dir_nofollow(&self.root_leaf)
            .map_err(|error| {
                CapabilityWorkspaceError::Root(format!(
                    "shadow-store name no longer resolves without a link: {error}"
                ))
            })?;
        if validate_private_root(&named, "named shadow store")? != self.root_identity {
            return Err(CapabilityWorkspaceError::Root(
                "shadow-store name was replaced".into(),
            ));
        }
        Ok(())
    }
}

/// An exact retained capability for one issued live workspace root.
pub struct CapabilityWorkspace {
    grant: IssuedWorkspaceGrant,
    root: Dir,
    root_parent: Dir,
    root_leaf: OsString,
    root_identity: ObjectIdentity,
    path_anchor: DirectoryPathAnchor,
}

impl CapabilityWorkspace {
    /// Acquires the exact root named by an issued grant without following its leaf.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid/read-denied authority, a replaced root, or I/O.
    pub fn open(grant: IssuedWorkspaceGrant) -> Result<Self, CapabilityWorkspaceError> {
        grant
            .validate_integrity()
            .map_err(|error| CapabilityWorkspaceError::Authority(error.to_string()))?;
        if !grant.contract().permissions.read {
            return Err(CapabilityWorkspaceError::PermissionDenied("read"));
        }
        let path = &grant.contract().canonical_root;
        let parent_path = path
            .parent()
            .ok_or_else(|| CapabilityWorkspaceError::Root("live root has no parent".into()))?;
        let root_leaf = path
            .file_name()
            .ok_or_else(|| CapabilityWorkspaceError::Root("live root has no leaf".into()))?
            .to_os_string();
        let root_parent = Dir::open_ambient_dir(parent_path, ambient_authority())
            .map_err(|error| io_error("open live-root parent", path, &error))?;
        let root = root_parent
            .open_dir_nofollow(&root_leaf)
            .map_err(|error| io_error("open live root without following links", path, &error))?;
        let metadata = root
            .dir_metadata()
            .map_err(|error| io_error("inspect live-root descriptor", path, &error))?;
        if !metadata.is_dir() {
            return Err(CapabilityWorkspaceError::Root(
                "live root is not a directory".into(),
            ));
        }
        let root_identity = object_identity(&metadata);
        if root_identity.device != grant.identity().device_id()
            || root_identity.inode != grant.identity().inode()
        {
            return Err(CapabilityWorkspaceError::Root(
                "live descriptor differs from issued root identity".into(),
            ));
        }
        let path_anchor =
            DirectoryPathAnchor::acquire(path, "live workspace root").map_err(path_anchor_error)?;
        if path_anchor.final_device_inode() != (root_identity.device, root_identity.inode) {
            return Err(CapabilityWorkspaceError::Root(
                "live path anchor differs from the issued descriptor".into(),
            ));
        }
        let workspace = Self {
            grant,
            root,
            root_parent,
            root_leaf,
            root_identity,
            path_anchor,
        };
        workspace.validate_roots()?;
        Ok(workspace)
    }

    /// Captures a deterministic manifest through the retained root descriptor.
    ///
    /// # Errors
    ///
    /// Returns an error for authority/root changes, unsafe entries, unstable
    /// files, invalid timestamp, or contract failure.
    pub fn capture(
        &self,
        grant: &IssuedWorkspaceGrant,
        created_at_unix_ms: u64,
    ) -> Result<WorkspaceManifest, CapabilityWorkspaceError> {
        self.validate_capture_authority(grant)?;
        self.capture_after_authority_validation(grant, created_at_unix_ms)
    }

    /// Validates capture authority and retained-root identity before a caller
    /// crosses its descriptor-scan effect boundary.
    ///
    /// Keeping this preflight separate lets the runner report authority/root
    /// refusal as `BeforeEffect` without misclassifying any failure after the
    /// first descriptor scan has been entered.
    pub(crate) fn validate_capture_authority(
        &self,
        grant: &IssuedWorkspaceGrant,
    ) -> Result<(), CapabilityWorkspaceError> {
        self.validate_call(grant, false)
    }

    /// Captures after the caller has validated authority and committed to the
    /// descriptor-scan boundary.
    ///
    /// Every error from this method is post-boundary: it can arise in the
    /// first scan, stability interval, second scan, manifest encoding, or the
    /// final retained/named-root revalidation.
    pub(crate) fn capture_after_authority_validation(
        &self,
        grant: &IssuedWorkspaceGrant,
        created_at_unix_ms: u64,
    ) -> Result<WorkspaceManifest, CapabilityWorkspaceError> {
        let manifest = capture_manifest(
            &self.root,
            grant.contract().canonical_root.clone(),
            grant.contract().grant_hash.clone(),
            created_at_unix_ms,
        )?;
        self.validate_roots()?;
        Ok(manifest)
    }

    /// Copies an exact immutable base into a new disjoint private shadow.
    ///
    /// # Errors
    ///
    /// Returns an error for stale authority/base, an unsafe destination, links,
    /// unstable source files, copy mismatches, or durability failure.
    #[allow(clippy::too_many_lines)] // One ordered authority, copy, cleanup, and durability transaction.
    pub fn create_shadow(
        &self,
        grant: &IssuedWorkspaceGrant,
        base: &WorkspaceManifest,
        store: &CapabilityShadowStore,
        child_name: impl AsRef<Path>,
    ) -> Result<CapabilityShadowWorkspace, CapabilityWorkspaceError> {
        self.validate_call(grant, true)?;
        store.validate()?;
        let live = &grant.contract().canonical_root;
        if store.root_path.starts_with(live)
            || live.starts_with(&store.root_path)
            || store
                .path_anchor
                .contains_device_inode(self.root_identity.device, self.root_identity.inode)
            || self.path_anchor.contains_device_inode(
                store.root_identity.object.device,
                store.root_identity.object.inode,
            )
        {
            return Err(CapabilityWorkspaceError::Destination(
                "shadow store and live root must be disjoint".into(),
            ));
        }
        if base.root() != grant.contract().canonical_root
            || base.snapshot().grant_hash != grant.contract().grant_hash
        {
            return Err(CapabilityWorkspaceError::Authority(
                "base manifest is not bound to this issued root".into(),
            ));
        }
        let current = self.capture(grant, base.snapshot().created_at_unix_ms)?;
        if current.snapshot().snapshot_id != base.snapshot().snapshot_id {
            return Err(CapabilityWorkspaceError::StaleBase {
                expected: base.snapshot().snapshot_id.clone(),
                actual: current.snapshot().snapshot_id.clone(),
            });
        }
        let shadow_leaf = normalize_shadow_child(child_name.as_ref())?;
        let shadow_path = store.root_path.join(&shadow_leaf);
        let shadow_parent = store
            .root
            .try_clone()
            .map_err(|error| io_error("clone retained shadow store", &shadow_path, &error))?;
        match shadow_parent.symlink_metadata(&shadow_leaf) {
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(io_error(
                    "inspect shadow child destination",
                    &shadow_path,
                    &error,
                ));
            }
            Ok(_) => {
                return Err(CapabilityWorkspaceError::Destination(
                    "shadow child already exists".into(),
                ));
            }
        }
        let mut builder = DirBuilder::new();
        builder.mode(0o700);
        shadow_parent
            .create_dir_with(&shadow_leaf, &builder)
            .map_err(|error| io_error("create private shadow root", &shadow_path, &error))?;
        let shadow_root = shadow_parent
            .open_dir_nofollow(&shadow_leaf)
            .map_err(|error| io_error("open private shadow root", &shadow_path, &error))?;
        shadow_root
            .set_permissions(Path::new("."), Permissions::from_mode(0o700))
            .map_err(|error| io_error("set private shadow mode", &shadow_path, &error))?;
        sync_directory(&shadow_root)
            .map_err(|error| io_error("sync private shadow root", &shadow_path, &error))?;
        sync_directory(&shadow_parent)
            .map_err(|error| io_error("sync private shadow parent", &shadow_path, &error))?;
        let shadow_identity = validate_private_root(&shadow_root, "shadow root")?;
        let preparation = (|| {
            let root_path_anchor = store
                .path_anchor
                .extend(&store.root, &shadow_leaf, "shadow root")
                .map_err(path_anchor_error)?;
            if root_path_anchor.final_device_inode()
                != (shadow_identity.object.device, shadow_identity.object.inode)
            {
                return Err(CapabilityWorkspaceError::Root(
                    "shadow path anchor differs from its retained descriptor".into(),
                ));
            }
            copy_manifest(&self.root, &shadow_root, base)?;
            let copied = capture_manifest(
                &shadow_root,
                shadow_path.clone(),
                base.snapshot().grant_hash.clone(),
                base.snapshot().created_at_unix_ms,
            )?;
            if copied.entries() != base.entries() {
                return Err(CapabilityWorkspaceError::FileMismatch(PathBuf::from(".")));
            }
            Ok(root_path_anchor)
        })();
        let root_path_anchor = match preparation {
            Ok(anchor) => anchor,
            Err(error) => {
                drop(shadow_root);
                let _ = remove_owned_shadow(
                    &shadow_parent,
                    &shadow_leaf,
                    shadow_identity.object,
                    &shadow_path,
                );
                return Err(error);
            }
        };
        self.validate_roots()?;
        store.validate()?;
        let shadow = CapabilityShadowWorkspace {
            grant: grant.clone(),
            root: shadow_root,
            root_parent: shadow_parent,
            root_leaf: shadow_leaf,
            root_identity: shadow_identity,
            root_path_anchor,
            live_path_anchor: self.path_anchor.try_clone().map_err(path_anchor_error)?,
            root_path: shadow_path,
            base: base.clone(),
        };
        shadow.validate_call(grant)?;
        Ok(shadow)
    }

    /// Reopens one exact existing private shadow for read-only final
    /// verification.
    ///
    /// The child is resolved only beneath the retained shadow-store
    /// capability. The complete descriptor-captured tree must hash to
    /// `expected_snapshot` during acquisition and on every later capture.
    /// This type exposes no mutation or staging API; a platform command
    /// backend must additionally mount the retained root read-only and prove
    /// the same snapshot before and after execution.
    ///
    /// # Errors
    ///
    /// Returns an error for stale authority, overlapping roots, an invalid or
    /// replaced child, unsafe content, or a snapshot mismatch.
    pub fn open_verifier_shadow(
        &self,
        grant: &IssuedWorkspaceGrant,
        store: &CapabilityShadowStore,
        child_name: impl AsRef<Path>,
        expected_snapshot: Digest,
        observed_at_unix_ms: u64,
    ) -> Result<CapabilityVerifierWorkspace, CapabilityWorkspaceError> {
        self.validate_call(grant, false)?;
        store.validate()?;
        ensure_disjoint_roots(self, store)?;

        let root_leaf = normalize_shadow_child(child_name.as_ref())?;
        let root_path = store.root_path.join(&root_leaf);
        let root_parent = store
            .root
            .try_clone()
            .map_err(|error| io_error("clone retained shadow store", &root_path, &error))?;
        let root = root_parent
            .open_dir_nofollow(&root_leaf)
            .map_err(|error| io_error("open verifier shadow without links", &root_path, &error))?;
        let root_identity = validate_private_root(&root, "verifier shadow root")?;
        let root_path_anchor = store
            .path_anchor
            .extend(&store.root, &root_leaf, "verifier shadow root")
            .map_err(path_anchor_error)?;
        if root_path_anchor.final_device_inode()
            != (root_identity.object.device, root_identity.object.inode)
        {
            return Err(CapabilityWorkspaceError::Root(
                "verifier-shadow path anchor differs from its retained descriptor".into(),
            ));
        }

        let verifier = CapabilityVerifierWorkspace {
            grant: grant.clone(),
            root,
            root_parent,
            root_leaf,
            root_identity,
            root_path_anchor,
            live_path_anchor: self.path_anchor.try_clone().map_err(path_anchor_error)?,
            root_path,
            expected_snapshot,
        };
        verifier.capture(grant, observed_at_unix_ms)?;
        self.validate_roots()?;
        store.validate()?;
        Ok(verifier)
    }

    fn validate_call(
        &self,
        grant: &IssuedWorkspaceGrant,
        integrate: bool,
    ) -> Result<(), CapabilityWorkspaceError> {
        grant
            .validate_integrity()
            .map_err(|error| CapabilityWorkspaceError::Authority(error.to_string()))?;
        if grant != &self.grant {
            return Err(CapabilityWorkspaceError::Authority(
                "caller grant differs from acquisition authority".into(),
            ));
        }
        if !grant.contract().permissions.read {
            return Err(CapabilityWorkspaceError::PermissionDenied("read"));
        }
        if integrate && !grant.contract().permissions.integrate_changes {
            return Err(CapabilityWorkspaceError::PermissionDenied(
                "integrate_changes",
            ));
        }
        self.validate_roots()
    }

    fn validate_roots(&self) -> Result<(), CapabilityWorkspaceError> {
        self.path_anchor
            .validate("live workspace root")
            .map_err(path_anchor_error)?;
        let descriptor = self
            .root
            .dir_metadata()
            .map_err(|error| io_error("inspect retained live root", Path::new("."), &error))?;
        if !descriptor.is_dir() || object_identity(&descriptor) != self.root_identity {
            return Err(CapabilityWorkspaceError::Root(
                "retained live-root identity changed".into(),
            ));
        }
        let named = self
            .root_parent
            .open_dir_nofollow(&self.root_leaf)
            .map_err(|error| {
                CapabilityWorkspaceError::Root(format!(
                    "live-root name no longer resolves without a link: {error}"
                ))
            })?;
        if object_identity(
            &named
                .dir_metadata()
                .map_err(|error| CapabilityWorkspaceError::Root(error.to_string()))?,
        ) != self.root_identity
        {
            return Err(CapabilityWorkspaceError::Root(
                "live-root name was replaced".into(),
            ));
        }
        Ok(())
    }
}

fn ensure_disjoint_roots(
    workspace: &CapabilityWorkspace,
    store: &CapabilityShadowStore,
) -> Result<(), CapabilityWorkspaceError> {
    let live = &workspace.grant.contract().canonical_root;
    if store.root_path.starts_with(live)
        || live.starts_with(&store.root_path)
        || store.path_anchor.contains_device_inode(
            workspace.root_identity.device,
            workspace.root_identity.inode,
        )
        || workspace.path_anchor.contains_device_inode(
            store.root_identity.object.device,
            store.root_identity.object.inode,
        )
    {
        return Err(CapabilityWorkspaceError::Destination(
            "shadow store and live root must be disjoint".into(),
        ));
    }
    Ok(())
}

/// A private shadow whose capture and staging remain descriptor-relative.
pub struct CapabilityShadowWorkspace {
    grant: IssuedWorkspaceGrant,
    root: Dir,
    root_parent: Dir,
    root_leaf: OsString,
    root_identity: PrivateRootIdentity,
    root_path_anchor: DirectoryPathAnchor,
    live_path_anchor: DirectoryPathAnchor,
    root_path: PathBuf,
    base: WorkspaceManifest,
}

/// An exact existing private shadow admitted only for read-only verification.
pub struct CapabilityVerifierWorkspace {
    grant: IssuedWorkspaceGrant,
    root: Dir,
    root_parent: Dir,
    root_leaf: OsString,
    root_identity: PrivateRootIdentity,
    root_path_anchor: DirectoryPathAnchor,
    live_path_anchor: DirectoryPathAnchor,
    root_path: PathBuf,
    expected_snapshot: Digest,
}

impl CapabilityVerifierWorkspace {
    /// Returns the canonical private path for platform-policy reporting only.
    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root_path
    }

    /// Returns the exact immutable snapshot authorized for verification.
    #[must_use]
    pub const fn expected_snapshot(&self) -> &Digest {
        &self.expected_snapshot
    }

    /// Captures and proves the complete currently named verifier shadow.
    ///
    /// # Errors
    ///
    /// Returns an error when authority, either path anchor, root identity,
    /// content safety, or the complete expected snapshot differs.
    pub fn capture(
        &self,
        grant: &IssuedWorkspaceGrant,
        created_at_unix_ms: u64,
    ) -> Result<WorkspaceManifest, CapabilityWorkspaceError> {
        self.validate_call(grant)?;
        let manifest = capture_manifest(
            &self.root,
            self.root_path.clone(),
            grant.contract().grant_hash.clone(),
            created_at_unix_ms,
        )?;
        if manifest.snapshot().snapshot_id != self.expected_snapshot {
            return Err(CapabilityWorkspaceError::SnapshotMismatch {
                expected: self.expected_snapshot.clone(),
                actual: manifest.snapshot().snapshot_id.clone(),
            });
        }
        self.validate_call(grant)?;
        Ok(manifest)
    }

    fn validate_call(&self, grant: &IssuedWorkspaceGrant) -> Result<(), CapabilityWorkspaceError> {
        grant
            .validate_integrity()
            .map_err(|error| CapabilityWorkspaceError::Authority(error.to_string()))?;
        if grant != &self.grant {
            return Err(CapabilityWorkspaceError::Authority(
                "caller grant differs from verifier-shadow acquisition authority".into(),
            ));
        }
        if !grant.contract().permissions.read {
            return Err(CapabilityWorkspaceError::PermissionDenied("read"));
        }
        self.live_path_anchor
            .validate("live workspace root")
            .map_err(path_anchor_error)?;
        if self.live_path_anchor.final_device_inode()
            != (grant.identity().device_id(), grant.identity().inode())
        {
            return Err(CapabilityWorkspaceError::Root(
                "live path anchor differs from issued verifier authority".into(),
            ));
        }
        self.root_path_anchor
            .validate("verifier shadow root")
            .map_err(path_anchor_error)?;
        if validate_private_root(&self.root, "retained verifier shadow")? != self.root_identity {
            return Err(CapabilityWorkspaceError::Root(
                "retained verifier-shadow identity, owner, or mode changed".into(),
            ));
        }
        let named = self
            .root_parent
            .open_dir_nofollow(&self.root_leaf)
            .map_err(|error| {
                CapabilityWorkspaceError::Root(format!(
                    "verifier-shadow name no longer resolves without a link: {error}"
                ))
            })?;
        if validate_private_root(&named, "named verifier shadow")? != self.root_identity {
            return Err(CapabilityWorkspaceError::Root(
                "verifier-shadow name was replaced".into(),
            ));
        }
        Ok(())
    }
}

impl CapabilityShadowWorkspace {
    /// Returns the canonical private shadow path for command/file-tool policy.
    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root_path
    }

    /// Returns the exact immutable base copied into this shadow.
    #[must_use]
    pub const fn base(&self) -> &WorkspaceManifest {
        &self.base
    }

    /// Clones this session's already-acquired shadow-root capability for one
    /// command boundary. No path supplied by the command caller is used to
    /// choose the directory.
    pub(crate) fn clone_command_root_capability(
        &self,
        grant: &IssuedWorkspaceGrant,
    ) -> Result<Dir, CapabilityWorkspaceError> {
        self.validate_call(grant)?;
        self.root.try_clone().map_err(|error| {
            io_error(
                "clone retained command shadow root",
                &self.root_path,
                &error,
            )
        })
    }

    /// Captures the complete current shadow through its retained descriptor.
    ///
    /// The returned manifest is the only authoritative way for a caller to
    /// advance a shadow snapshot after an operation.  In-memory application of
    /// an expected file delta is deliberately insufficient because another
    /// same-user process may race the private path.  Both the live grant anchor
    /// and the shadow's retained/named identities are revalidated before and
    /// after the complete no-follow traversal.
    ///
    /// # Errors
    ///
    /// Returns an error for stale authority, a replaced live or shadow root,
    /// an unsafe or unstable entry, an oversized regular file, or a manifest
    /// contract failure.
    pub fn capture(
        &self,
        grant: &IssuedWorkspaceGrant,
        created_at_unix_ms: u64,
    ) -> Result<WorkspaceManifest, CapabilityWorkspaceError> {
        self.validate_call(grant)?;
        let manifest = capture_manifest(
            &self.root,
            self.root_path.clone(),
            self.base.snapshot().grant_hash.clone(),
            created_at_unix_ms,
        )?;
        self.validate_call(grant)?;
        Ok(manifest)
    }

    /// Consumes and durably discards this exact private shadow.
    ///
    /// A canonical intent is synced in the retained store before the root is
    /// renamed to an identity-bound tombstone. Restart recovery can therefore
    /// distinguish both possible post-crash rename outcomes without inferring
    /// authority from a reserved name alone. Deletion rejects Git metadata,
    /// links, special objects, hard links, and identity changes.
    ///
    /// # Errors
    ///
    /// Returns an error for stale authority, unsafe content, conflicting
    /// durable state, a descriptor identity race, or failed durability proof.
    pub fn discard(
        self,
        grant: &IssuedWorkspaceGrant,
    ) -> Result<CapabilityShadowDiscardEvidence, CapabilityWorkspaceError> {
        self.discard_internal(grant, None)
    }

    fn discard_internal(
        self,
        grant: &IssuedWorkspaceGrant,
        fault: Option<DiscardFaultPoint>,
    ) -> Result<CapabilityShadowDiscardEvidence, CapabilityWorkspaceError> {
        self.validate_call(grant)?;
        let parent_anchor = self
            .root_path_anchor
            .try_parent()
            .map_err(path_anchor_error)?;
        let first = scan_discard_tree(&self.root)?;
        let second = scan_discard_tree(&self.root)?;
        if first != second {
            return Err(discard_conflict(
                "unpublished",
                "shadow tree changed during pre-discard capture",
            ));
        }
        let evidence = discard_evidence(
            &self.root_leaf,
            &self.base.snapshot().grant_hash,
            self.root_identity.object,
            &second,
        )?;
        let tombstone = discard_tombstone_name(&evidence);
        let intent = DiscardIntent {
            evidence: evidence.clone(),
            original_child: self.root_leaf.clone(),
            tombstone,
        };
        let intent_name = discard_intent_name(&evidence.discard_id);
        write_discard_intent_new(&self.root_parent, &intent_name, &intent)?;
        maybe_discard_fault(fault, DiscardFaultPoint::IntentSynced, "intent-sync", 0)?;
        let completed = reconcile_discard(
            &self.root_parent,
            self.root_path.parent().ok_or_else(|| {
                discard_conflict(&evidence.discard_id, "shadow path has no retained parent")
            })?,
            &intent_name,
            &intent,
            fault,
        )?;
        parent_anchor
            .validate("shadow-store parent after discard")
            .map_err(path_anchor_error)?;
        self.live_path_anchor
            .validate("live workspace root after discard")
            .map_err(path_anchor_error)?;
        Ok(completed)
    }

    pub(crate) fn clone_capabilities(
        &self,
        grant: &IssuedWorkspaceGrant,
    ) -> Result<
        (Dir, Dir, OsString, DirectoryPathAnchor, DirectoryPathAnchor),
        CapabilityWorkspaceError,
    > {
        self.validate_call(grant)?;
        let root = self
            .root
            .try_clone()
            .map_err(|error| io_error("clone retained shadow root", &self.root_path, &error))?;
        let parent = self.root_parent.try_clone().map_err(|error| {
            io_error("clone retained shadow-root parent", &self.root_path, &error)
        })?;
        Ok((
            root,
            parent,
            self.root_leaf.clone(),
            self.root_path_anchor
                .try_clone()
                .map_err(path_anchor_error)?,
            self.live_path_anchor
                .try_clone()
                .map_err(path_anchor_error)?,
        ))
    }

    /// Captures the shadow and emits a contract-valid staged file change set.
    ///
    /// # Errors
    ///
    /// Returns an error for authority/root changes, links/special entries,
    /// unstable files, unsupported metadata changes, no-op output, or invalid
    /// staged contracts.
    pub fn stage_changes(
        &mut self,
        grant: &IssuedWorkspaceGrant,
        change_set_id: impl Into<String>,
        created_at_unix_ms: u64,
    ) -> Result<StagedChangeSet, CapabilityWorkspaceError> {
        self.validate_call(grant)?;
        let result = capture_manifest(
            &self.root,
            self.root_path.clone(),
            self.base.snapshot().grant_hash.clone(),
            created_at_unix_ms,
        )?;
        self.validate_call(grant)?;
        let mut paths = BTreeSet::new();
        paths.extend(self.base.entries().keys().cloned());
        paths.extend(result.entries().keys().cloned());

        let mut operations = Vec::new();
        let mut blobs = BTreeMap::new();
        let mut create_modes = BTreeMap::new();
        for path in paths {
            match (self.base.entry(&path), result.entry(&path)) {
                (None, Some(created)) => {
                    operations.push(FileOperation::Create {
                        path: path.clone(),
                        result_hash: created.digest().clone(),
                    });
                    insert_verified_blob(&self.root, &path, created, &mut blobs)?;
                    create_modes.insert(path, created.mode());
                }
                (Some(base), Some(changed)) if base.mode() != changed.mode() => {
                    return Err(CapabilityWorkspaceError::UnsupportedMetadataChange(path));
                }
                (Some(base), Some(changed)) if base.digest() != changed.digest() => {
                    operations.push(FileOperation::Modify {
                        path: path.clone(),
                        base_hash: base.digest().clone(),
                        result_hash: changed.digest().clone(),
                    });
                    insert_verified_blob(&self.root, &path, changed, &mut blobs)?;
                }
                (Some(base), None) => operations.push(FileOperation::Delete {
                    path,
                    base_hash: base.digest().clone(),
                }),
                (Some(_), Some(_)) => {}
                (None, None) => unreachable!("manifest union contains one side"),
            }
        }
        if operations.is_empty() {
            return Err(CapabilityWorkspaceError::NoChanges);
        }
        let supplied_id = change_set_id.into();
        let change_set_id = if supplied_id.trim().is_empty() {
            deterministic_change_set_id(
                &self.base.snapshot().snapshot_id,
                &result.snapshot().snapshot_id,
                &operations,
            )
        } else {
            supplied_id
        };
        let change_set = ChangeSet {
            change_set_id,
            base_snapshot: self.base.snapshot().snapshot_id.clone(),
            result_snapshot: result.snapshot().snapshot_id.clone(),
            operations,
        };
        StagedChangeSet::new_with_create_modes(change_set, blobs, create_modes)
            .map_err(|error| CapabilityWorkspaceError::Contract(error.to_string()))
    }

    /// Captures a normal staged delta or an explicit, descriptor-verified no-op.
    ///
    /// This preserves [`Self::stage_changes`] for callers that treat no changes
    /// as an error. The empty contract is emitted only after that method has
    /// captured the complete shadow and revalidated its retained authority.
    ///
    /// # Errors
    ///
    /// Returns every staging error except [`CapabilityWorkspaceError::NoChanges`],
    /// which becomes the sole contract-valid empty shape with identical base and
    /// result snapshots.
    pub(crate) fn stage_changes_or_verified_noop(
        &mut self,
        grant: &IssuedWorkspaceGrant,
        change_set_id: impl Into<String>,
        created_at_unix_ms: u64,
    ) -> Result<StagedChangeSet, CapabilityWorkspaceError> {
        let change_set_id = change_set_id.into();
        match self.stage_changes(grant, change_set_id.clone(), created_at_unix_ms) {
            Ok(staged) => Ok(staged),
            Err(CapabilityWorkspaceError::NoChanges) => {
                let snapshot = self.base.snapshot().snapshot_id.clone();
                let change_set_id = if change_set_id.trim().is_empty() {
                    deterministic_change_set_id(&snapshot, &snapshot, &[])
                } else {
                    change_set_id
                };
                StagedChangeSet::new(
                    ChangeSet {
                        change_set_id,
                        base_snapshot: snapshot.clone(),
                        result_snapshot: snapshot,
                        operations: Vec::new(),
                    },
                    BTreeMap::new(),
                )
                .map_err(|error| CapabilityWorkspaceError::Contract(error.to_string()))
            }
            Err(error) => Err(error),
        }
    }

    pub(crate) fn validate_call(
        &self,
        grant: &IssuedWorkspaceGrant,
    ) -> Result<(), CapabilityWorkspaceError> {
        grant
            .validate_integrity()
            .map_err(|error| CapabilityWorkspaceError::Authority(error.to_string()))?;
        if grant != &self.grant {
            return Err(CapabilityWorkspaceError::Authority(
                "caller grant differs from shadow acquisition authority".into(),
            ));
        }
        if !grant.contract().permissions.integrate_changes {
            return Err(CapabilityWorkspaceError::PermissionDenied(
                "integrate_changes",
            ));
        }
        self.live_path_anchor
            .validate("live workspace root")
            .map_err(path_anchor_error)?;
        if self.live_path_anchor.final_device_inode()
            != (grant.identity().device_id(), grant.identity().inode())
        {
            return Err(CapabilityWorkspaceError::Root(
                "live path anchor differs from issued authority".into(),
            ));
        }
        self.root_path_anchor
            .validate("shadow root")
            .map_err(path_anchor_error)?;
        let descriptor = validate_private_root(&self.root, "retained shadow root")?;
        if descriptor != self.root_identity {
            return Err(CapabilityWorkspaceError::Root(
                "retained shadow identity, owner, or mode changed".into(),
            ));
        }
        let named = self
            .root_parent
            .open_dir_nofollow(&self.root_leaf)
            .map_err(|error| {
                CapabilityWorkspaceError::Root(format!(
                    "shadow name no longer resolves without a link: {error}"
                ))
            })?;
        if validate_private_root(&named, "named shadow root")? != self.root_identity {
            return Err(CapabilityWorkspaceError::Root(
                "shadow-root name was replaced".into(),
            ));
        }
        Ok(())
    }
}

pub(crate) fn capture_manifest(
    root: &Dir,
    root_path: PathBuf,
    grant_hash: Digest,
    created_at_unix_ms: u64,
) -> Result<WorkspaceManifest, CapabilityWorkspaceError> {
    let entries = capture_descriptor_entries(root)?;
    if let Some((path, _)) = entries
        .iter()
        .find(|(_, entry)| entry.length > MAX_APPLY_FILE_BYTES)
    {
        return Err(CapabilityWorkspaceError::FileTooLarge {
            path: path.clone(),
            limit: MAX_APPLY_FILE_BYTES,
        });
    }
    let snapshot_id = snapshot_digest(&entries)?;
    let manifest_entries = entries
        .into_iter()
        .map(|(path, entry)| {
            (
                path,
                ManifestEntry::from_stored_parts(entry.digest, entry.length, entry.mode),
            )
        })
        .collect();
    WorkspaceManifest::from_stored_parts(
        root_path,
        WorkspaceSnapshot {
            snapshot_id,
            grant_hash,
            created_at_unix_ms,
        },
        manifest_entries,
    )
    .map_err(|error| CapabilityWorkspaceError::Contract(error.to_string()))
}

fn discard_conflict(
    discard_id: impl Into<String>,
    reason: impl Into<String>,
) -> CapabilityWorkspaceError {
    CapabilityWorkspaceError::DiscardConflict {
        discard_id: discard_id.into(),
        reason: reason.into(),
    }
}

fn is_discard_id_suffix(name: &str, prefix: &str) -> bool {
    name.strip_prefix(prefix).is_some_and(|suffix| {
        suffix.len() == 64
            && suffix
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    })
}

fn discard_intent_name(discard_id: &str) -> String {
    format!("{DISCARD_INTENT_PREFIX}{discard_id}")
}

fn discard_started_name(discard_id: &str) -> String {
    format!("{DISCARD_STARTED_PREFIX}{discard_id}")
}

fn discard_tombstone_name(evidence: &CapabilityShadowDiscardEvidence) -> String {
    format!(
        "{DISCARD_TOMBSTONE_PREFIX}{}-{:016x}-{:016x}",
        evidence.discard_id, evidence.root_device, evidence.root_inode
    )
}

fn scan_discard_tree(root: &Dir) -> Result<Vec<DiscardNode>, CapabilityWorkspaceError> {
    let root_identity = validate_private_root(root, "discard shadow root")?;
    let mut nodes = vec![DiscardNode {
        path: PathBuf::new(),
        identity: root_identity.object,
        mode: root_identity.mode,
        kind: DiscardNodeKind::Directory,
    }];
    walk_discard_tree(root, root, Path::new(""), &mut nodes)?;
    if nodes.len() > MAX_DISCARD_ENTRIES {
        return Err(discard_conflict(
            "unpublished",
            format!(
                "shadow tree entry count {} exceeds {MAX_DISCARD_ENTRIES}",
                nodes.len()
            ),
        ));
    }
    Ok(nodes)
}

#[allow(
    clippy::too_many_lines,
    reason = "the recursive no-follow scanner keeps every object-class and identity check adjacent"
)]
fn walk_discard_tree(
    root: &Dir,
    directory: &Dir,
    relative_directory: &Path,
    nodes: &mut Vec<DiscardNode>,
) -> Result<(), CapabilityWorkspaceError> {
    let mut children = directory
        .entries()
        .map_err(|error| io_error("enumerate discard shadow", relative_directory, &error))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| io_error("read discard shadow entry", relative_directory, &error))?;
    children.sort_by_key(cap_std::fs::DirEntry::file_name);
    for child in children {
        if nodes.len() >= MAX_DISCARD_ENTRIES {
            return Err(discard_conflict(
                "unpublished",
                format!("shadow tree exceeds {MAX_DISCARD_ENTRIES} entries"),
            ));
        }
        let name = child.file_name();
        let text = name.to_str().ok_or_else(|| {
            discard_conflict("unpublished", "discard tree contains a non-UTF-8 name")
        })?;
        if text.eq_ignore_ascii_case(".git") {
            return Err(discard_conflict(
                "unpublished",
                format!(
                    "Git administrative entry is not discardable at {}",
                    relative_directory.join(&name).display()
                ),
            ));
        }
        let relative = normalize_path(&relative_directory.join(&name))?;
        let before = directory
            .symlink_metadata(&name)
            .map_err(|error| io_error("inspect discard entry without links", &relative, &error))?;
        let kind = before.file_type();
        if kind.is_symlink() {
            return Err(CapabilityApplyError::UnsafeEntry {
                path: relative,
                kind: crate::UnsafeFileKind::Symlink,
            }
            .into());
        }
        if kind.is_dir() {
            let opened = directory.open_dir_nofollow(&name).map_err(|error| {
                io_error("open discard directory without links", &relative, &error)
            })?;
            let opened_metadata = opened
                .dir_metadata()
                .map_err(|error| io_error("inspect opened discard directory", &relative, &error))?;
            let identity = object_identity(&opened_metadata);
            if identity != object_identity(&before) {
                return Err(discard_conflict(
                    "unpublished",
                    format!(
                        "discard directory {} changed during open",
                        relative.display()
                    ),
                ));
            }
            nodes.push(DiscardNode {
                path: relative.clone(),
                identity,
                mode: OsMetadataExt::mode(&opened_metadata) & 0o777,
                kind: DiscardNodeKind::Directory,
            });
            walk_discard_tree(root, &opened, &relative, nodes)?;
            let after = directory
                .symlink_metadata(&name)
                .map_err(|error| io_error("revalidate discard directory", &relative, &error))?;
            if !after.is_dir() || object_identity(&after) != identity {
                return Err(discard_conflict(
                    "unpublished",
                    format!(
                        "discard directory {} changed during traversal",
                        relative.display()
                    ),
                ));
            }
        } else if kind.is_file() {
            if PortableMetadataExt::nlink(&before) != 1 {
                return Err(CapabilityApplyError::UnsafeEntry {
                    path: relative,
                    kind: crate::UnsafeFileKind::HardLink,
                }
                .into());
            }
            let identity = object_identity(&before);
            let (bytes, mode) = read_descriptor_regular(root, &relative, MAX_APPLY_FILE_BYTES)?;
            let after = directory
                .symlink_metadata(&name)
                .map_err(|error| io_error("revalidate discard file", &relative, &error))?;
            if !after.is_file()
                || PortableMetadataExt::nlink(&after) != 1
                || object_identity(&after) != identity
                || after.len() != u64::try_from(bytes.len()).expect("usize fits u64")
            {
                return Err(discard_conflict(
                    "unpublished",
                    format!("discard file {} changed during capture", relative.display()),
                ));
            }
            nodes.push(DiscardNode {
                path: relative,
                identity,
                mode,
                kind: DiscardNodeKind::Regular {
                    digest: Digest::sha256(&bytes),
                    length: u64::try_from(bytes.len()).expect("usize fits u64"),
                },
            });
        } else {
            return Err(CapabilityApplyError::UnsafeEntry {
                path: relative,
                kind: crate::UnsafeFileKind::Special,
            }
            .into());
        }
    }
    Ok(())
}

fn digest_discard_tree(nodes: &[DiscardNode]) -> Result<Digest, CapabilityWorkspaceError> {
    let mut hasher = Sha256::new();
    hasher.update(DISCARD_TREE_DOMAIN);
    hasher.update(
        u64::try_from(nodes.len())
            .map_err(|_| discard_conflict("unpublished", "discard node count exceeds u64"))?
            .to_be_bytes(),
    );
    for node in nodes {
        let path = node
            .path
            .to_str()
            .ok_or_else(|| discard_conflict("unpublished", "discard evidence path is not UTF-8"))?;
        hasher.update(
            u64::try_from(path.len())
                .map_err(|_| discard_conflict("unpublished", "discard path exceeds u64"))?
                .to_be_bytes(),
        );
        hasher.update(path.as_bytes());
        hasher.update(node.identity.device.to_be_bytes());
        hasher.update(node.identity.inode.to_be_bytes());
        hasher.update(node.mode.to_be_bytes());
        match &node.kind {
            DiscardNodeKind::Directory => hasher.update([0]),
            DiscardNodeKind::Regular { digest, length } => {
                hasher.update([1]);
                hasher.update(length.to_be_bytes());
                hasher.update(digest.as_str().as_bytes());
            }
        }
    }
    digest_from_hasher(hasher)
}

fn discard_evidence(
    child: &OsStr,
    grant_hash: &Digest,
    root_identity: ObjectIdentity,
    nodes: &[DiscardNode],
) -> Result<CapabilityShadowDiscardEvidence, CapabilityWorkspaceError> {
    let child_text = child
        .to_str()
        .ok_or_else(|| discard_conflict("unpublished", "discard child identity is not UTF-8"))?;
    let tree_digest = digest_discard_tree(nodes)?;
    let regular_file_count = u64::try_from(
        nodes
            .iter()
            .filter(|node| matches!(node.kind, DiscardNodeKind::Regular { .. }))
            .count(),
    )
    .map_err(|_| discard_conflict("unpublished", "regular-file count exceeds u64"))?;
    let directory_count = u64::try_from(
        nodes
            .iter()
            .filter(|node| matches!(node.kind, DiscardNodeKind::Directory))
            .count(),
    )
    .map_err(|_| discard_conflict("unpublished", "directory count exceeds u64"))?;
    let total_file_bytes = nodes
        .iter()
        .try_fold(0_u64, |total, node| match node.kind {
            DiscardNodeKind::Regular { length, .. } => total.checked_add(length).ok_or_else(|| {
                discard_conflict("unpublished", "discard regular-file byte sum overflow")
            }),
            DiscardNodeKind::Directory => Ok(total),
        })?;
    let original_child_digest = Digest::sha256(child_text.as_bytes());
    let mut hasher = Sha256::new();
    hasher.update(DISCARD_ID_DOMAIN);
    hasher.update(grant_hash.as_str().as_bytes());
    hasher.update(original_child_digest.as_str().as_bytes());
    hasher.update(root_identity.device.to_be_bytes());
    hasher.update(root_identity.inode.to_be_bytes());
    hasher.update(tree_digest.as_str().as_bytes());
    hasher.update(regular_file_count.to_be_bytes());
    hasher.update(directory_count.to_be_bytes());
    hasher.update(total_file_bytes.to_be_bytes());
    let discard_id = digest_from_hasher(hasher)?.as_str().to_owned();
    Ok(CapabilityShadowDiscardEvidence {
        discard_id,
        original_child_digest,
        grant_hash: grant_hash.clone(),
        root_device: root_identity.device,
        root_inode: root_identity.inode,
        tree_digest,
        regular_file_count,
        directory_count,
        total_file_bytes,
    })
}

fn digest_from_hasher(hasher: Sha256) -> Result<Digest, CapabilityWorkspaceError> {
    Digest::parse(encode_hex(hasher.finalize().as_ref()))
        .map_err(|error| CapabilityWorkspaceError::Contract(error.to_string()))
}

fn encode_discard_intent(intent: &DiscardIntent) -> Vec<u8> {
    format!(
        "{DISCARD_INTENT_VERSION}\nid\t{}\nchild\t{}\nchild-digest\t{}\ngrant\t{}\ndevice\t{}\ninode\t{}\ntree\t{}\nfiles\t{}\ndirectories\t{}\nbytes\t{}\ntombstone\t{}\n",
        intent.evidence.discard_id,
        encode_hex(intent.original_child.as_encoded_bytes()),
        intent.evidence.original_child_digest,
        intent.evidence.grant_hash,
        intent.evidence.root_device,
        intent.evidence.root_inode,
        intent.evidence.tree_digest,
        intent.evidence.regular_file_count,
        intent.evidence.directory_count,
        intent.evidence.total_file_bytes,
        intent.tombstone,
    )
    .into_bytes()
}

fn write_discard_intent_new(
    store: &Dir,
    name: &str,
    intent: &DiscardIntent,
) -> Result<(), CapabilityWorkspaceError> {
    if !is_discard_id_suffix(name, DISCARD_INTENT_PREFIX) {
        return Err(discard_conflict(name, "invalid discard-intent filename"));
    }
    let bytes = encode_discard_intent(intent);
    if u64::try_from(bytes.len()).expect("usize fits u64") > MAX_DISCARD_INTENT_BYTES {
        return Err(discard_conflict(
            &intent.evidence.discard_id,
            "encoded discard intent exceeds its byte ceiling",
        ));
    }
    write_private_file_new(store, name, &bytes)
}

fn write_private_file_new(
    parent: &Dir,
    name: &str,
    bytes: &[u8],
) -> Result<(), CapabilityWorkspaceError> {
    let preparation = discard_record_preparation_name(name)?;
    for candidate in [name, preparation.as_str()] {
        match parent.symlink_metadata(candidate) {
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(io_error(
                    "inspect discard-record destination",
                    Path::new(candidate),
                    &error,
                ));
            }
            Ok(_) => {
                return Err(discard_conflict(
                    name,
                    format!("discard-record name {candidate:?} already exists"),
                ));
            }
        }
    }
    let mut options = OpenOptions::new();
    options
        .read(true)
        .write(true)
        .create_new(true)
        .mode(0o600)
        .follow(FollowSymlinks::No);
    let mut file = parent.open_with(&preparation, &options).map_err(|error| {
        io_error(
            "create private discard-record preparation",
            Path::new(&preparation),
            &error,
        )
    })?;
    file.set_permissions(Permissions::from_mode(0o600))
        .map_err(|error| {
            io_error(
                "set private discard-record preparation mode",
                Path::new(&preparation),
                &error,
            )
        })?;
    file.write_all(bytes).map_err(|error| {
        io_error(
            "write private discard-record preparation",
            Path::new(&preparation),
            &error,
        )
    })?;
    file.sync_all().map_err(|error| {
        io_error(
            "sync private discard-record preparation",
            Path::new(&preparation),
            &error,
        )
    })?;
    let metadata = file.metadata().map_err(|error| {
        io_error(
            "inspect private discard-record preparation",
            Path::new(&preparation),
            &error,
        )
    })?;
    validate_private_regular(Path::new(&preparation), &metadata)?;
    if metadata.len() != u64::try_from(bytes.len()).expect("usize fits u64") {
        return Err(discard_conflict(
            name,
            "discard record length changed after write",
        ));
    }
    sync_directory(parent).map_err(|error| {
        io_error(
            "sync discard-record preparation parent",
            Path::new(&preparation),
            &error,
        )
    })?;
    renameat_with(
        parent,
        Path::new(&preparation),
        parent,
        Path::new(name),
        RenameFlags::NOREPLACE,
    )
    .map_err(|error| io_error("publish private discard record", Path::new(name), &error))?;
    sync_directory(parent)
        .map_err(|error| io_error("sync published discard record", Path::new(name), &error))
}

fn discard_record_preparation_name(name: &str) -> Result<String, CapabilityWorkspaceError> {
    if let Some(id) = name.strip_prefix(DISCARD_INTENT_PREFIX) {
        return Ok(format!("{DISCARD_INTENT_PREPARING_PREFIX}{id}"));
    }
    if let Some(id) = name.strip_prefix(DISCARD_STARTED_PREFIX) {
        return Ok(format!("{DISCARD_STARTED_PREPARING_PREFIX}{id}"));
    }
    Err(discard_conflict(
        name,
        "unsupported discard-record final name",
    ))
}

fn validate_private_regular(
    path: &Path,
    metadata: &Metadata,
) -> Result<ObjectIdentity, CapabilityWorkspaceError> {
    let kind = metadata.file_type();
    if kind.is_symlink() || !kind.is_file() {
        return Err(discard_conflict(
            path.display().to_string(),
            "discard record is not a no-follow regular file",
        ));
    }
    if PortableMetadataExt::nlink(metadata) != 1 {
        return Err(discard_conflict(
            path.display().to_string(),
            "discard record is hard linked",
        ));
    }
    let mode = OsMetadataExt::mode(metadata) & 0o777;
    if mode != 0o600 || OsMetadataExt::uid(metadata) != rustix::process::geteuid().as_raw() {
        return Err(discard_conflict(
            path.display().to_string(),
            format!("discard record must be effective-user-owned 0600, found {mode:04o}"),
        ));
    }
    Ok(object_identity(metadata))
}

fn read_private_file(
    parent: &Dir,
    name: &str,
    limit: u64,
) -> Result<Vec<u8>, CapabilityWorkspaceError> {
    let mut observations = Vec::with_capacity(2);
    for _ in 0..2 {
        let named = parent
            .symlink_metadata(name)
            .map_err(|error| io_error("inspect private discard record", Path::new(name), &error))?;
        let identity = validate_private_regular(Path::new(name), &named)?;
        if named.len() > limit {
            return Err(discard_conflict(
                name,
                format!("discard record exceeds {limit} bytes"),
            ));
        }
        let mut options = OpenOptions::new();
        options.read(true).follow(FollowSymlinks::No);
        let mut file = parent
            .open_with(name, &options)
            .map_err(|error| io_error("open private discard record", Path::new(name), &error))?;
        let opened = file
            .metadata()
            .map_err(|error| io_error("inspect opened discard record", Path::new(name), &error))?;
        if validate_private_regular(Path::new(name), &opened)? != identity {
            return Err(discard_conflict(
                name,
                "discard record changed during no-follow open",
            ));
        }
        let mut bytes = Vec::new();
        Read::by_ref(&mut file)
            .take(limit + 1)
            .read_to_end(&mut bytes)
            .map_err(|error| io_error("read private discard record", Path::new(name), &error))?;
        if u64::try_from(bytes.len()).expect("usize fits u64") > limit
            || u64::try_from(bytes.len()).expect("usize fits u64") != opened.len()
        {
            return Err(discard_conflict(name, "discard record length is unstable"));
        }
        observations.push((identity, bytes));
    }
    if observations[0] != observations[1] {
        return Err(discard_conflict(
            name,
            "discard record changed during stable read",
        ));
    }
    Ok(observations.pop().expect("two observations").1)
}

fn read_discard_intent(store: &Dir, name: &str) -> Result<DiscardIntent, CapabilityWorkspaceError> {
    let bytes = read_private_file(store, name, MAX_DISCARD_INTENT_BYTES)?;
    let text = std::str::from_utf8(&bytes)
        .map_err(|_| discard_conflict(name, "discard intent is not UTF-8"))?;
    let mut lines = text.lines();
    if lines.next() != Some(DISCARD_INTENT_VERSION) {
        return Err(discard_conflict(name, "unsupported discard-intent version"));
    }
    let discard_id = parse_discard_field(lines.next(), "id", name)?.to_owned();
    if discard_id.len() != 64
        || !discard_id
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(discard_conflict(name, "invalid discard identity"));
    }
    let child_bytes = decode_hex(parse_discard_field(lines.next(), "child", name)?)?;
    let original_child =
        OsString::from(String::from_utf8(child_bytes).map_err(|_| {
            discard_conflict(&discard_id, "discard child name is not canonical UTF-8")
        })?);
    normalize_shadow_child(Path::new(&original_child))?;
    let original_child_digest =
        parse_workspace_digest(parse_discard_field(lines.next(), "child-digest", name)?)?;
    let grant_hash = parse_workspace_digest(parse_discard_field(lines.next(), "grant", name)?)?;
    let root_device = parse_discard_u64(lines.next(), "device", name)?;
    let root_inode = parse_discard_u64(lines.next(), "inode", name)?;
    let tree_digest = parse_workspace_digest(parse_discard_field(lines.next(), "tree", name)?)?;
    let regular_file_count = parse_discard_u64(lines.next(), "files", name)?;
    let directory_count = parse_discard_u64(lines.next(), "directories", name)?;
    let total_file_bytes = parse_discard_u64(lines.next(), "bytes", name)?;
    let tombstone = parse_discard_field(lines.next(), "tombstone", name)?.to_owned();
    if lines.next().is_some() {
        return Err(discard_conflict(name, "discard intent has trailing fields"));
    }
    let evidence = CapabilityShadowDiscardEvidence {
        discard_id,
        original_child_digest,
        grant_hash,
        root_device,
        root_inode,
        tree_digest,
        regular_file_count,
        directory_count,
        total_file_bytes,
    };
    if Digest::sha256(original_child.as_encoded_bytes()) != evidence.original_child_digest {
        return Err(discard_conflict(
            &evidence.discard_id,
            "discard child-name digest differs",
        ));
    }
    let expected_id = recompute_discard_id(&evidence)?;
    if expected_id != evidence.discard_id {
        return Err(discard_conflict(
            &evidence.discard_id,
            "discard identity differs from canonical evidence",
        ));
    }
    if tombstone != discard_tombstone_name(&evidence) {
        return Err(discard_conflict(
            &evidence.discard_id,
            "discard tombstone differs from canonical identity binding",
        ));
    }
    Ok(DiscardIntent {
        evidence,
        original_child,
        tombstone,
    })
}

fn parse_discard_field<'a>(
    line: Option<&'a str>,
    field: &str,
    discard_id: &str,
) -> Result<&'a str, CapabilityWorkspaceError> {
    let mut values = line
        .ok_or_else(|| discard_conflict(discard_id, format!("missing {field} field")))?
        .split('\t');
    match (values.next(), values.next(), values.next()) {
        (Some(actual), Some(value), None) if actual == field && !value.is_empty() => Ok(value),
        _ => Err(discard_conflict(
            discard_id,
            format!("invalid {field} field"),
        )),
    }
}

fn parse_discard_u64(
    line: Option<&str>,
    field: &str,
    discard_id: &str,
) -> Result<u64, CapabilityWorkspaceError> {
    parse_discard_field(line, field, discard_id)?
        .parse()
        .map_err(|_| discard_conflict(discard_id, format!("invalid {field} integer")))
}

fn parse_workspace_digest(value: &str) -> Result<Digest, CapabilityWorkspaceError> {
    Digest::parse(value).map_err(|error| CapabilityWorkspaceError::Contract(error.to_string()))
}

fn recompute_discard_id(
    evidence: &CapabilityShadowDiscardEvidence,
) -> Result<String, CapabilityWorkspaceError> {
    let mut hasher = Sha256::new();
    hasher.update(DISCARD_ID_DOMAIN);
    hasher.update(evidence.grant_hash.as_str().as_bytes());
    hasher.update(evidence.original_child_digest.as_str().as_bytes());
    hasher.update(evidence.root_device.to_be_bytes());
    hasher.update(evidence.root_inode.to_be_bytes());
    hasher.update(evidence.tree_digest.as_str().as_bytes());
    hasher.update(evidence.regular_file_count.to_be_bytes());
    hasher.update(evidence.directory_count.to_be_bytes());
    hasher.update(evidence.total_file_bytes.to_be_bytes());
    Ok(digest_from_hasher(hasher)?.as_str().to_owned())
}

#[allow(
    clippy::too_many_lines,
    reason = "discard reconciliation is one explicit old-name/tombstone/started/deletion durability state machine"
)]
fn reconcile_discard(
    store: &Dir,
    store_path: &Path,
    intent_name: &str,
    expected_intent: &DiscardIntent,
    fault: Option<DiscardFaultPoint>,
) -> Result<CapabilityShadowDiscardEvidence, CapabilityWorkspaceError> {
    let durable_intent = read_discard_intent(store, intent_name)?;
    if &durable_intent != expected_intent {
        return Err(discard_conflict(
            &expected_intent.evidence.discard_id,
            "durable discard intent differs from expected exact evidence",
        ));
    }
    let discard_id = &durable_intent.evidence.discard_id;
    let expected_identity = ObjectIdentity {
        device: durable_intent.evidence.root_device,
        inode: durable_intent.evidence.root_inode,
    };
    let started_name = discard_started_name(discard_id);
    let old = optional_discard_root(store, &durable_intent.original_child, discard_id)?;
    let tombstone =
        optional_discard_root(store, OsStr::new(&durable_intent.tombstone), discard_id)?;
    match (old, tombstone) {
        (Some(old_identity), None) if old_identity.object == expected_identity => {
            if discard_started_matches(store, &started_name, &durable_intent)? {
                return Err(discard_conflict(
                    discard_id,
                    "deletion-started proof exists while the original shadow name remains",
                ));
            }
            renameat_with(
                store,
                Path::new(&durable_intent.original_child),
                store,
                Path::new(&durable_intent.tombstone),
                RenameFlags::NOREPLACE,
            )
            .map_err(|error| {
                io_error(
                    "rename shadow to discard tombstone",
                    &store_path.join(&durable_intent.tombstone),
                    &error,
                )
            })?;
            maybe_discard_fault(
                fault,
                DiscardFaultPoint::RenameBeforeSync,
                "rename-before-parent-sync",
                0,
            )?;
            let renamed =
                optional_discard_root(store, OsStr::new(&durable_intent.tombstone), discard_id)?
                    .ok_or_else(|| discard_conflict(discard_id, "renamed tombstone disappeared"))?;
            if renamed.object != expected_identity {
                return Err(discard_conflict(
                    discard_id,
                    "renamed tombstone identity differs from durable intent",
                ));
            }
            sync_directory(store).map_err(|error| {
                io_error(
                    "sync shadow-store discard rename",
                    &store_path.join(&durable_intent.tombstone),
                    &error,
                )
            })?;
            maybe_discard_fault(
                fault,
                DiscardFaultPoint::RenameSynced,
                "rename-parent-sync",
                0,
            )?;
        }
        (None, Some(tombstone_identity)) if tombstone_identity.object == expected_identity => {}
        (None, None) => {
            if !discard_started_matches(store, &started_name, &durable_intent)? {
                return Err(discard_conflict(
                    discard_id,
                    "both shadow names are absent without exact deletion-started proof",
                ));
            }
            cleanup_discard_records(store, intent_name, &started_name, discard_id)?;
            return Ok(durable_intent.evidence);
        }
        (Some(_), Some(_)) => {
            return Err(discard_conflict(
                discard_id,
                "both original and tombstone shadow names exist",
            ));
        }
        (Some(_), None) => {
            return Err(discard_conflict(
                discard_id,
                "original shadow identity differs from durable intent",
            ));
        }
        (None, Some(_)) => {
            return Err(discard_conflict(
                discard_id,
                "tombstone identity differs from durable intent",
            ));
        }
    }

    let tombstone_root = store
        .open_dir_nofollow(&durable_intent.tombstone)
        .map_err(|error| {
            io_error(
                "open exact discard tombstone",
                &store_path.join(&durable_intent.tombstone),
                &error,
            )
        })?;
    let root_identity = validate_private_root(&tombstone_root, "discard tombstone root")?;
    if root_identity.object != expected_identity {
        return Err(discard_conflict(
            discard_id,
            "opened tombstone identity differs from durable intent",
        ));
    }
    let started = discard_started_matches(store, &started_name, &durable_intent)?;
    if !started {
        let first = scan_discard_tree(&tombstone_root)?;
        let second = scan_discard_tree(&tombstone_root)?;
        if first != second {
            return Err(discard_conflict(
                discard_id,
                "tombstone tree changed before deletion was authorized",
            ));
        }
        let observed = discard_evidence(
            &durable_intent.original_child,
            &durable_intent.evidence.grant_hash,
            expected_identity,
            &second,
        )?;
        if observed != durable_intent.evidence {
            return Err(discard_conflict(
                discard_id,
                "complete tombstone tree differs from durable pre-discard evidence",
            ));
        }
        let started_record = discard_started_record(&durable_intent);
        write_private_file_new(
            store,
            &started_name,
            &encode_discard_started(&started_record),
        )?;
        maybe_discard_fault(
            fault,
            DiscardFaultPoint::DeletionStarted,
            "deletion-started",
            0,
        )?;
    }

    let residual = scan_discard_tree(&tombstone_root)?;
    let removed_nodes = remove_discard_tree(&tombstone_root, &residual, fault, discard_id)?;
    let named = optional_discard_root(store, OsStr::new(&durable_intent.tombstone), discard_id)?
        .ok_or_else(|| discard_conflict(discard_id, "tombstone disappeared before root removal"))?;
    if named.object != expected_identity {
        return Err(discard_conflict(
            discard_id,
            "tombstone root changed before final removal",
        ));
    }
    if tombstone_root
        .entries()
        .map_err(|error| {
            io_error(
                "enumerate emptied discard root",
                &store_path.join(&durable_intent.tombstone),
                &error,
            )
        })?
        .next()
        .transpose()
        .map_err(|error| {
            io_error(
                "read emptied discard root",
                &store_path.join(&durable_intent.tombstone),
                &error,
            )
        })?
        .is_some()
    {
        return Err(discard_conflict(
            discard_id,
            "discard tombstone is not empty",
        ));
    }
    store
        .remove_dir(&durable_intent.tombstone)
        .map_err(|error| {
            io_error(
                "remove empty discard tombstone",
                &store_path.join(&durable_intent.tombstone),
                &error,
            )
        })?;
    sync_directory(store).map_err(|error| {
        io_error(
            "sync removed discard tombstone",
            &store_path.join(&durable_intent.tombstone),
            &error,
        )
    })?;
    maybe_discard_fault(
        fault,
        DiscardFaultPoint::RootRemoved,
        "root-removal",
        removed_nodes,
    )?;
    cleanup_discard_records(store, intent_name, &started_name, discard_id)?;
    Ok(durable_intent.evidence)
}

fn optional_discard_root(
    store: &Dir,
    name: &OsStr,
    discard_id: &str,
) -> Result<Option<PrivateRootIdentity>, CapabilityWorkspaceError> {
    let named = match store.symlink_metadata(name) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(io_error(
                "inspect discard root name",
                Path::new(name),
                &error,
            ));
        }
        Ok(metadata) => metadata,
    };
    if named.file_type().is_symlink() || !named.is_dir() {
        return Err(discard_conflict(
            discard_id,
            format!(
                "discard root name {} is not a no-follow directory",
                name.display()
            ),
        ));
    }
    let opened = store
        .open_dir_nofollow(name)
        .map_err(|error| io_error("open discard root without links", Path::new(name), &error))?;
    let identity = validate_private_root(&opened, "named discard root")?;
    if identity.object != object_identity(&named) {
        return Err(discard_conflict(
            discard_id,
            "discard root identity changed during no-follow open",
        ));
    }
    Ok(Some(identity))
}

fn discard_started_record(intent: &DiscardIntent) -> DiscardStartedRecord {
    DiscardStartedRecord {
        discard_id: intent.evidence.discard_id.clone(),
        intent_digest: Digest::sha256(&encode_discard_intent(intent)),
        root_device: intent.evidence.root_device,
        root_inode: intent.evidence.root_inode,
    }
}

fn encode_discard_started(record: &DiscardStartedRecord) -> Vec<u8> {
    format!(
        "{DISCARD_STARTED_VERSION}\nid\t{}\nintent\t{}\ndevice\t{}\ninode\t{}\n",
        record.discard_id, record.intent_digest, record.root_device, record.root_inode,
    )
    .into_bytes()
}

fn read_discard_started(
    store: &Dir,
    name: &str,
) -> Result<DiscardStartedRecord, CapabilityWorkspaceError> {
    if !is_discard_id_suffix(name, DISCARD_STARTED_PREFIX) {
        return Err(discard_conflict(name, "invalid discard-started filename"));
    }
    let filename_id = name
        .strip_prefix(DISCARD_STARTED_PREFIX)
        .ok_or_else(|| discard_conflict(name, "missing discard-started prefix"))?;
    let bytes = read_private_file(store, name, 512)?;
    let text = std::str::from_utf8(&bytes)
        .map_err(|_| discard_conflict(filename_id, "discard-started record is not UTF-8"))?;
    let mut lines = text.lines();
    if lines.next() != Some(DISCARD_STARTED_VERSION) {
        return Err(discard_conflict(
            filename_id,
            "unsupported discard-started version",
        ));
    }
    let discard_id = parse_discard_field(lines.next(), "id", filename_id)?.to_owned();
    let intent_digest =
        parse_workspace_digest(parse_discard_field(lines.next(), "intent", filename_id)?)?;
    let root_device = parse_discard_u64(lines.next(), "device", filename_id)?;
    let root_inode = parse_discard_u64(lines.next(), "inode", filename_id)?;
    if lines.next().is_some() || discard_id != filename_id {
        return Err(discard_conflict(
            filename_id,
            "discard-started record identity or field count differs",
        ));
    }
    Ok(DiscardStartedRecord {
        discard_id,
        intent_digest,
        root_device,
        root_inode,
    })
}

fn discard_started_matches(
    store: &Dir,
    name: &str,
    intent: &DiscardIntent,
) -> Result<bool, CapabilityWorkspaceError> {
    match store.symlink_metadata(name) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(io_error(
            "inspect discard-started record",
            Path::new(name),
            &error,
        )),
        Ok(_) => {
            let actual = read_discard_started(store, name)?;
            let expected = discard_started_record(intent);
            if actual == expected {
                Ok(true)
            } else {
                Err(discard_conflict(
                    &intent.evidence.discard_id,
                    "discard-started record differs from exact durable intent and root identity",
                ))
            }
        }
    }
}

#[allow(
    clippy::too_many_lines,
    reason = "post-order deletion keeps file and directory identity revalidation at each removal boundary"
)]
fn remove_discard_tree(
    root: &Dir,
    residual: &[DiscardNode],
    fault: Option<DiscardFaultPoint>,
    discard_id: &str,
) -> Result<usize, CapabilityWorkspaceError> {
    let mut removable = residual
        .iter()
        .filter(|node| !node.path.as_os_str().is_empty())
        .cloned()
        .collect::<Vec<_>>();
    removable.sort_by(|left, right| {
        right
            .path
            .components()
            .count()
            .cmp(&left.path.components().count())
            .then_with(|| right.path.cmp(&left.path))
            .then_with(|| match (&left.kind, &right.kind) {
                (DiscardNodeKind::Regular { .. }, DiscardNodeKind::Directory) => {
                    std::cmp::Ordering::Less
                }
                (DiscardNodeKind::Directory, DiscardNodeKind::Regular { .. }) => {
                    std::cmp::Ordering::Greater
                }
                _ => std::cmp::Ordering::Equal,
            })
    });
    let mut removed = 0;
    for node in removable {
        let (parent, leaf) = open_discard_parent(root, &node.path)?;
        let named = parent
            .symlink_metadata(&leaf)
            .map_err(|error| io_error("revalidate discard target", &node.path, &error))?;
        if object_identity(&named) != node.identity {
            return Err(discard_conflict(
                discard_id,
                format!(
                    "discard target {} changed identity before removal",
                    node.path.display()
                ),
            ));
        }
        match node.kind {
            DiscardNodeKind::Regular { digest, length } => {
                if !named.is_file() || PortableMetadataExt::nlink(&named) != 1 {
                    return Err(discard_conflict(
                        discard_id,
                        format!(
                            "discard target {} is no longer singly-linked regular content",
                            node.path.display()
                        ),
                    ));
                }
                let (bytes, mode) =
                    read_descriptor_regular(root, &node.path, MAX_APPLY_FILE_BYTES)?;
                if Digest::sha256(&bytes) != digest
                    || u64::try_from(bytes.len()).expect("usize fits u64") != length
                    || mode != node.mode
                {
                    return Err(discard_conflict(
                        discard_id,
                        format!(
                            "discard target {} changed content or mode before removal",
                            node.path.display()
                        ),
                    ));
                }
                let final_named = parent.symlink_metadata(&leaf).map_err(|error| {
                    io_error("final revalidate discard file", &node.path, &error)
                })?;
                if object_identity(&final_named) != node.identity
                    || !final_named.is_file()
                    || PortableMetadataExt::nlink(&final_named) != 1
                {
                    return Err(discard_conflict(
                        discard_id,
                        format!(
                            "discard file {} changed at unlink boundary",
                            node.path.display()
                        ),
                    ));
                }
                parent
                    .remove_file(&leaf)
                    .map_err(|error| io_error("remove exact discard file", &node.path, &error))?;
            }
            DiscardNodeKind::Directory => {
                if named.file_type().is_symlink() || !named.is_dir() {
                    return Err(discard_conflict(
                        discard_id,
                        format!(
                            "discard target {} is no longer a directory",
                            node.path.display()
                        ),
                    ));
                }
                let opened = parent.open_dir_nofollow(&leaf).map_err(|error| {
                    io_error("open exact discard directory", &node.path, &error)
                })?;
                let opened_metadata = opened.dir_metadata().map_err(|error| {
                    io_error("inspect exact discard directory", &node.path, &error)
                })?;
                if object_identity(&opened_metadata) != node.identity
                    || OsMetadataExt::mode(&opened_metadata) & 0o777 != node.mode
                {
                    return Err(discard_conflict(
                        discard_id,
                        format!(
                            "discard directory {} changed identity or mode",
                            node.path.display()
                        ),
                    ));
                }
                if opened
                    .entries()
                    .map_err(|error| io_error("enumerate discard directory", &node.path, &error))?
                    .next()
                    .transpose()
                    .map_err(|error| io_error("read discard directory", &node.path, &error))?
                    .is_some()
                {
                    return Err(discard_conflict(
                        discard_id,
                        format!("discard directory {} is not empty", node.path.display()),
                    ));
                }
                parent.remove_dir(&leaf).map_err(|error| {
                    io_error("remove exact discard directory", &node.path, &error)
                })?;
            }
        }
        sync_directory(&parent)
            .map_err(|error| io_error("sync discard target parent", &node.path, &error))?;
        removed += 1;
        maybe_discard_fault(
            fault,
            DiscardFaultPoint::RemovedNode(removed),
            "tree-node-removal",
            removed,
        )?;
    }
    Ok(removed)
}

fn open_discard_parent(
    root: &Dir,
    path: &Path,
) -> Result<(Dir, OsString), CapabilityWorkspaceError> {
    let path = normalize_path(path)?;
    let mut components = path.components().collect::<Vec<_>>();
    let leaf = match components.pop() {
        Some(Component::Normal(leaf)) => leaf.to_os_string(),
        _ => {
            return Err(discard_conflict(
                "unknown",
                "discard target has no normal leaf",
            ));
        }
    };
    let mut parent = root
        .try_clone()
        .map_err(|error| io_error("clone discard root", &path, &error))?;
    let mut relative = PathBuf::new();
    for component in components {
        let Component::Normal(name) = component else {
            return Err(discard_conflict(
                "unknown",
                "discard target parent is not normalized",
            ));
        };
        relative.push(name);
        parent = parent.open_dir_nofollow(name).map_err(|error| {
            io_error(
                "open discard target parent without links",
                &relative,
                &error,
            )
        })?;
    }
    Ok((parent, leaf))
}

fn cleanup_discard_records(
    store: &Dir,
    intent_name: &str,
    started_name: &str,
    discard_id: &str,
) -> Result<(), CapabilityWorkspaceError> {
    let intent = read_discard_intent(store, intent_name)?;
    if intent.evidence.discard_id != discard_id {
        return Err(discard_conflict(
            discard_id,
            "discard cleanup intent identity differs",
        ));
    }
    let has_started = discard_started_matches(store, started_name, &intent)?;
    remove_private_file(store, intent_name)?;
    sync_directory(store).map_err(|error| {
        io_error(
            "sync removed discard intent",
            Path::new(intent_name),
            &error,
        )
    })?;
    if has_started {
        remove_private_file(store, started_name)?;
        sync_directory(store).map_err(|error| {
            io_error(
                "sync removed discard-started record",
                Path::new(started_name),
                &error,
            )
        })?;
    }
    Ok(())
}

fn remove_private_file(parent: &Dir, name: &str) -> Result<(), CapabilityWorkspaceError> {
    let before = parent
        .symlink_metadata(name)
        .map_err(|error| io_error("inspect private discard cleanup", Path::new(name), &error))?;
    let identity = validate_private_regular(Path::new(name), &before)?;
    let final_named = parent.symlink_metadata(name).map_err(|error| {
        io_error(
            "revalidate private discard cleanup",
            Path::new(name),
            &error,
        )
    })?;
    if validate_private_regular(Path::new(name), &final_named)? != identity {
        return Err(discard_conflict(
            name,
            "private discard record changed before removal",
        ));
    }
    parent
        .remove_file(name)
        .map_err(|error| io_error("remove private discard record", Path::new(name), &error))
}

fn maybe_discard_fault(
    actual: Option<DiscardFaultPoint>,
    expected: DiscardFaultPoint,
    checkpoint: &'static str,
    removed_nodes: usize,
) -> Result<(), CapabilityWorkspaceError> {
    if actual == Some(expected) {
        Err(CapabilityWorkspaceError::InjectedDiscardCrash {
            checkpoint,
            removed_nodes,
        })
    } else {
        Ok(())
    }
}

fn decode_hex(value: &str) -> Result<Vec<u8>, CapabilityWorkspaceError> {
    if !value.len().is_multiple_of(2) {
        return Err(discard_conflict("unknown", "odd-length hexadecimal field"));
    }
    (0..value.len())
        .step_by(2)
        .map(|index| {
            u8::from_str_radix(&value[index..index + 2], 16)
                .map_err(|_| discard_conflict("unknown", "invalid hexadecimal field"))
        })
        .collect()
}

fn normalize_shadow_child(path: &Path) -> Result<OsString, CapabilityWorkspaceError> {
    let mut components = path.components();
    let (Some(Component::Normal(leaf)), None) = (components.next(), components.next()) else {
        return Err(CapabilityWorkspaceError::Destination(
            "shadow child must be one normalized relative component".into(),
        ));
    };
    if leaf.to_str().is_none_or(|text| {
        text.eq_ignore_ascii_case(".git") || text.to_ascii_lowercase().starts_with(".discard-")
    }) {
        return Err(CapabilityWorkspaceError::Destination(
            "shadow child must be UTF-8 and cannot use `.git` or reserved `.discard-` names".into(),
        ));
    }
    Ok(leaf.to_os_string())
}

fn copy_manifest(
    live: &Dir,
    shadow: &Dir,
    base: &WorkspaceManifest,
) -> Result<(), CapabilityWorkspaceError> {
    for (path, entry) in base.entries() {
        let (bytes, mode) = read_descriptor_regular(live, path, MAX_APPLY_FILE_BYTES)?;
        if Digest::sha256(&bytes) != *entry.digest()
            || u64::try_from(bytes.len()).expect("usize fits u64") != entry.length()
            || mode != entry.mode()
        {
            return Err(CapabilityWorkspaceError::FileMismatch(path.clone()));
        }
        let (parent, leaf) = open_or_create_shadow_parent(shadow, path)?;
        let mut options = OpenOptions::new();
        options
            .read(true)
            .write(true)
            .create_new(true)
            .mode(0o600)
            .follow(FollowSymlinks::No);
        let mut file = parent
            .open_with(&leaf, &options)
            .map_err(|error| io_error("create copied shadow file", path, &error))?;
        file.write_all(&bytes)
            .map_err(|error| io_error("write copied shadow file", path, &error))?;
        file.set_permissions(Permissions::from_mode(entry.mode()))
            .map_err(|error| io_error("set copied shadow file mode", path, &error))?;
        file.sync_all()
            .map_err(|error| io_error("sync copied shadow file", path, &error))?;
        sync_directory(&parent)
            .map_err(|error| io_error("sync copied shadow parent", path, &error))?;
        let (copied, copied_mode) = read_descriptor_regular(shadow, path, MAX_APPLY_FILE_BYTES)?;
        if copied != bytes || copied_mode != entry.mode() {
            return Err(CapabilityWorkspaceError::FileMismatch(path.clone()));
        }
    }
    Ok(())
}

fn open_or_create_shadow_parent(
    root: &Dir,
    path: &Path,
) -> Result<(Dir, OsString), CapabilityWorkspaceError> {
    let path = normalize_path(path)?;
    let mut components = path.components().collect::<Vec<_>>();
    let leaf = match components.pop() {
        Some(Component::Normal(leaf)) => leaf.to_os_string(),
        _ => return Err(CapabilityWorkspaceError::FileMismatch(path)),
    };
    let mut directory = root
        .try_clone()
        .map_err(|error| io_error("clone shadow root", &path, &error))?;
    let mut relative = PathBuf::new();
    for component in components {
        let Component::Normal(name) = component else {
            unreachable!("normalized shadow path contains normal components");
        };
        relative.push(name);
        let metadata = match directory.symlink_metadata(name) {
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                let mut builder = DirBuilder::new();
                builder.mode(0o700);
                directory
                    .create_dir_with(name, &builder)
                    .map_err(|error| io_error("create private shadow parent", &relative, &error))?;
                let child = directory.open_dir_nofollow(name).map_err(|error| {
                    io_error("open created private shadow parent", &relative, &error)
                })?;
                child
                    .set_permissions(Path::new("."), Permissions::from_mode(0o700))
                    .map_err(|error| {
                        io_error("set private shadow parent mode", &relative, &error)
                    })?;
                sync_directory(&child)
                    .map_err(|error| io_error("sync private shadow parent", &relative, &error))?;
                sync_directory(&directory)
                    .map_err(|error| io_error("sync private shadow ancestor", &relative, &error))?;
                directory = child;
                continue;
            }
            Err(error) => {
                return Err(io_error("inspect private shadow parent", &relative, &error));
            }
            Ok(metadata) => metadata,
        };
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err(CapabilityWorkspaceError::Root(format!(
                "unsafe private shadow parent {}",
                relative.display()
            )));
        }
        let child = directory.open_dir_nofollow(name).map_err(|error| {
            io_error(
                "open private shadow parent without following links",
                &relative,
                &error,
            )
        })?;
        let opened = child
            .dir_metadata()
            .map_err(|error| io_error("inspect private shadow parent", &relative, &error))?;
        if object_identity(&opened) != object_identity(&metadata) {
            return Err(CapabilityWorkspaceError::Root(format!(
                "private shadow parent {} changed during copy",
                relative.display()
            )));
        }
        directory = child;
    }
    Ok((directory, leaf))
}

fn insert_verified_blob(
    root: &Dir,
    path: &Path,
    entry: &ManifestEntry,
    blobs: &mut BTreeMap<Digest, Vec<u8>>,
) -> Result<(), CapabilityWorkspaceError> {
    let (bytes, mode) = read_descriptor_regular(root, path, MAX_APPLY_FILE_BYTES)?;
    if Digest::sha256(&bytes) != *entry.digest()
        || u64::try_from(bytes.len()).expect("usize fits u64") != entry.length()
        || mode != entry.mode()
    {
        return Err(CapabilityWorkspaceError::FileMismatch(path.to_path_buf()));
    }
    blobs.entry(entry.digest().clone()).or_insert(bytes);
    Ok(())
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

fn validate_private_root(
    directory: &Dir,
    label: &str,
) -> Result<PrivateRootIdentity, CapabilityWorkspaceError> {
    let metadata = directory
        .dir_metadata()
        .map_err(|error| CapabilityWorkspaceError::Root(format!("inspect {label}: {error}")))?;
    if !metadata.is_dir() {
        return Err(CapabilityWorkspaceError::Root(format!(
            "{label} is not a directory"
        )));
    }
    let mode = OsMetadataExt::mode(&metadata) & 0o777;
    if mode != 0o700 {
        return Err(CapabilityWorkspaceError::Root(format!(
            "{label} mode must be 0700, found {mode:04o}"
        )));
    }
    let uid = OsMetadataExt::uid(&metadata);
    if uid != rustix::process::geteuid().as_raw() {
        return Err(CapabilityWorkspaceError::Root(format!(
            "{label} is not owned by the effective user"
        )));
    }
    Ok(PrivateRootIdentity {
        object: object_identity(&metadata),
        uid,
        mode,
    })
}

fn remove_owned_shadow(
    parent: &Dir,
    leaf: &OsStr,
    expected: ObjectIdentity,
    path: &Path,
) -> Result<(), CapabilityWorkspaceError> {
    let metadata = parent
        .symlink_metadata(leaf)
        .map_err(|error| io_error("inspect failed shadow cleanup", path, &error))?;
    if !metadata.is_dir() || object_identity(&metadata) != expected {
        return Err(CapabilityWorkspaceError::Root(
            "failed shadow root changed before cleanup".into(),
        ));
    }
    parent
        .remove_dir_all(leaf)
        .map_err(|error| io_error("remove failed private shadow", path, &error))?;
    sync_directory(parent).map_err(|error| io_error("sync removed private shadow", path, &error))
}

fn object_identity(metadata: &Metadata) -> ObjectIdentity {
    ObjectIdentity {
        device: PortableMetadataExt::dev(metadata),
        inode: PortableMetadataExt::ino(metadata),
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

#[allow(clippy::needless_pass_by_value)] // `Result::map_err` transfers ownership of the source error.
fn path_anchor_error(error: CapabilityApplyError) -> CapabilityWorkspaceError {
    CapabilityWorkspaceError::Root(error.to_string())
}

fn io_error(
    operation: &'static str,
    path: &Path,
    error: &impl Display,
) -> CapabilityWorkspaceError {
    CapabilityWorkspaceError::Io {
        operation,
        path: path.to_path_buf(),
        message: error.to_string(),
    }
}

#[cfg(test)]
mod tests;
