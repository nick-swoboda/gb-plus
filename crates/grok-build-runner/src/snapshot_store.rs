//! Restart-safe physical workspace snapshots.
//!
//! A completed snapshot is one atomically promoted, immutable directory. Its
//! regular-file bytes live under digest-named blob files, while a canonical
//! binary manifest preserves each workspace path, length, content digest, and
//! mode. Loading revalidates the complete object; a `READY` file is never
//! treated as sufficient evidence by itself.
//!
//! This implementation rejects links and non-regular objects and checks paths
//! before and after file reads. It does not use descriptor-relative traversal,
//! so it is not a complete defense against an actively racing same-user process.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as FmtWrite;
use std::fmt::{self, Display, Formatter};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use grok_build_core::{
    ContractError, Digest, FileOperation, IssuedWorkspaceGrant, WorkspaceSnapshot,
};
use sha2::{Digest as _, Sha256};

use crate::workspace::{hash_bytes, read_stable_file};
use crate::{
    ManifestEntry, ShadowWorkspace, StagedChangeSet, UnsafeEntryKind, WorkspaceManifest,
    WorkspacePipelineError,
};

const STORE_MAGIC: &[u8] = b"grok-build.snapshot-store.v1\0";
const MANIFEST_MAGIC: &[u8] = b"grok-build.snapshot-manifest.v1\0";
const READY_MAGIC: &[u8] = b"grok-build.snapshot-ready.v1\0";
const MAX_MANIFEST_BYTES: u64 = 64 * 1024 * 1024;
const MAX_MANIFEST_ENTRIES: u64 = 1_000_000;
const MAX_PATH_BYTES: u64 = 1024 * 1024;
const STORE_FILE: &str = "STORE";
const SNAPSHOTS_DIRECTORY: &str = "snapshots";
const MANIFEST_FILE: &str = "MANIFEST";
const READY_FILE: &str = "READY";
const BLOBS_DIRECTORY: &str = "blobs";

static NEXT_TEMPORARY: AtomicU64 = AtomicU64::new(0);

/// A path-based immutable snapshot store retained for migration and fixtures.
///
/// This store is restart-safe but does not provide descriptor-relative traversal
/// against a racing same-user process. New production Worker/Applier handoff
/// must use the capability-retained staged-bundle boundary.
#[derive(Clone, Debug)]
pub struct SnapshotStore {
    grant: IssuedWorkspaceGrant,
    root: PathBuf,
    snapshots: PathBuf,
}

impl SnapshotStore {
    /// Opens or initializes a private store at an absolute path outside the workspace.
    ///
    /// Existing stores must be bound to the exact grant hash and canonical
    /// workspace root. The store root and its mutable snapshot index use mode
    /// `0700` on Unix. Incomplete ordinary temporary directories are safely
    /// removed during open; unsafe temporary trees fail closed.
    ///
    /// # Errors
    ///
    /// Returns an error if the grant is invalid, the store is not disjoint from
    /// the workspace, permissions or layout are unsafe, or an I/O operation fails.
    pub fn open(
        grant: &IssuedWorkspaceGrant,
        root: impl AsRef<Path>,
    ) -> Result<Self, SnapshotStoreError> {
        validate_grant(grant)?;
        let requested = root.as_ref();
        if !requested.is_absolute() || !is_normalized_absolute(requested) {
            return Err(SnapshotStoreError::RootNotNormalizedAbsolute(
                requested.to_path_buf(),
            ));
        }

        match fs::symlink_metadata(requested) {
            Ok(metadata) => {
                if metadata.file_type().is_symlink() {
                    return Err(SnapshotStoreError::UnsafeEntry {
                        path: requested.to_path_buf(),
                        kind: UnsafeEntryKind::Symlink,
                    });
                }
                if !metadata.file_type().is_dir() {
                    return Err(SnapshotStoreError::UnsafeEntry {
                        path: requested.to_path_buf(),
                        kind: UnsafeEntryKind::Special,
                    });
                }
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                let parent = requested.parent().ok_or_else(|| {
                    SnapshotStoreError::RootNotNormalizedAbsolute(requested.to_path_buf())
                })?;
                let canonical_parent = fs::canonicalize(parent)
                    .map_err(|error| io_error("canonicalize store parent", parent, &error))?;
                let name = requested.file_name().ok_or_else(|| {
                    SnapshotStoreError::RootNotNormalizedAbsolute(requested.to_path_buf())
                })?;
                let candidate = canonical_parent.join(name);
                ensure_disjoint(&candidate, &grant.contract().canonical_root)?;
                fs::create_dir(&candidate)
                    .map_err(|error| io_error("create snapshot store", &candidate, &error))?;
                set_mode(&candidate, 0o700, "set snapshot store permissions")?;
                sync_directory(&canonical_parent)?;
            }
            Err(error) => {
                return Err(io_error("inspect snapshot store", requested, &error));
            }
        }

        let canonical_root = fs::canonicalize(requested)
            .map_err(|error| io_error("canonicalize snapshot store", requested, &error))?;
        ensure_disjoint(&canonical_root, &grant.contract().canonical_root)?;
        require_directory(&canonical_root, Some(0o700))?;

        let snapshots = canonical_root.join(SNAPSHOTS_DIRECTORY);
        initialize_or_verify_store(grant, &canonical_root, &snapshots)?;
        let store = Self {
            grant: grant.clone(),
            root: canonical_root,
            snapshots,
        };
        store.clean_incomplete_and_validate_types()?;
        Ok(store)
    }

    /// Returns the canonical private store root.
    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Persists an exact live manifest and all of its verified regular-file bytes.
    ///
    /// Every file is reread stably and checked against its captured digest,
    /// length, and mode before the snapshot is promoted. Repeating this operation
    /// for the same content is idempotent.
    ///
    /// # Errors
    ///
    /// Returns an error for stale or unsafe live contents, an authority mismatch,
    /// identifier collision, corrupt existing object, or I/O failure.
    pub fn persist_manifest(
        &self,
        manifest: &WorkspaceManifest,
    ) -> Result<WorkspaceManifest, SnapshotStoreError> {
        self.validate_authority()?;
        self.validate_manifest_authority(manifest)?;

        let mut blobs = BTreeMap::new();
        for (relative, expected) in manifest.entries() {
            let absolute = manifest.root().join(relative);
            let (bytes, metadata) = read_stable_file(&absolute)?;
            let actual_digest = hash_bytes(&bytes)?;
            if actual_digest != *expected.digest()
                || u64::try_from(bytes.len()).unwrap_or(u64::MAX) != expected.length()
            {
                return Err(SnapshotStoreError::ContentMismatch {
                    path: relative.clone(),
                    expected: expected.digest().clone(),
                    actual: actual_digest,
                });
            }
            let actual_mode = normalized_mode(&metadata);
            if actual_mode != expected.mode() {
                return Err(SnapshotStoreError::ModeMismatch {
                    path: relative.clone(),
                    expected: expected.mode(),
                    actual: actual_mode,
                });
            }
            if let Some(previous) = blobs.insert(expected.digest().clone(), bytes.clone())
                && previous != bytes
            {
                return Err(SnapshotStoreError::Corrupt {
                    path: absolute,
                    reason: "two different byte strings have the same content digest".into(),
                });
            }
        }
        self.persist_verified(manifest, &blobs)
    }

    /// Persists the exact result snapshot represented by a staged change set.
    ///
    /// The base must already be present in this store. Unchanged bytes are read
    /// only from that stored base, while create/modify bytes and create modes come
    /// from the validated staged change set. This lets a worker persist its result
    /// before its writable shadow is discarded.
    ///
    /// # Errors
    ///
    /// Returns an error if the base is absent or mismatched, an operation does not
    /// apply to the base, the declared result snapshot is wrong, or persistence fails.
    pub fn persist_staged_result(
        &self,
        base: &WorkspaceManifest,
        staged: &StagedChangeSet,
        created_at_unix_ms: u64,
    ) -> Result<WorkspaceManifest, SnapshotStoreError> {
        self.validate_authority()?;
        self.validate_manifest_authority(base)?;
        staged
            .change_set()
            .validate()
            .map_err(SnapshotStoreError::Contract)?;
        if created_at_unix_ms == 0 {
            return Err(SnapshotStoreError::InvalidTimestamp);
        }
        if staged.change_set().base_snapshot != base.snapshot().snapshot_id {
            return Err(SnapshotStoreError::BaseMismatch);
        }

        let stored_base = self.load(&base.snapshot().snapshot_id)?;
        if stored_base.entries() != base.entries()
            || stored_base.snapshot().grant_hash != base.snapshot().grant_hash
        {
            return Err(SnapshotStoreError::BaseMismatch);
        }

        let mut entries = stored_base.entries().clone();
        apply_staged_operations(&mut entries, staged)?;
        ensure_no_path_prefix_conflicts(&entries)?;

        let snapshot = WorkspaceSnapshot {
            snapshot_id: staged.change_set().result_snapshot.clone(),
            grant_hash: self.grant.contract().grant_hash.clone(),
            created_at_unix_ms,
        };
        let result = WorkspaceManifest::from_stored_parts(
            self.grant.contract().canonical_root.clone(),
            snapshot,
            entries,
        )?;

        let mut blobs = BTreeMap::new();
        for entry in result.entries().values() {
            if blobs.contains_key(entry.digest()) {
                continue;
            }
            let bytes = if let Some(bytes) = staged.blob(entry.digest()) {
                bytes.to_vec()
            } else {
                self.read_blob(
                    &stored_base.snapshot().snapshot_id,
                    entry.digest(),
                    entry.length(),
                )?
            };
            blobs.insert(entry.digest().clone(), bytes);
        }
        self.persist_verified(&result, &blobs)
    }

    /// Loads and exhaustively verifies one immutable snapshot.
    ///
    /// The canonical manifest encoding, grant binding, exact snapshot identifier,
    /// directory layout, file modes, link counts, byte lengths, and every blob
    /// digest are checked on each load.
    ///
    /// # Errors
    ///
    /// Returns an error when the identifier is absent or any stored evidence is
    /// malformed, unsafe, corrupt, or no longer bound to this issued grant.
    pub fn load(&self, snapshot_id: &Digest) -> Result<WorkspaceManifest, SnapshotStoreError> {
        self.validate_authority()?;
        let directory = self.snapshot_directory(snapshot_id);
        match fs::symlink_metadata(&directory) {
            Ok(_) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                return Err(SnapshotStoreError::SnapshotNotFound(snapshot_id.clone()));
            }
            Err(error) => return Err(io_error("inspect stored snapshot", &directory, &error)),
        }
        require_directory(&directory, Some(0o500))?;
        require_exact_children(&directory, [MANIFEST_FILE, READY_FILE, BLOBS_DIRECTORY])?;
        let blobs_directory = directory.join(BLOBS_DIRECTORY);
        require_directory(&blobs_directory, Some(0o500))?;

        let manifest_path = directory.join(MANIFEST_FILE);
        let manifest_bytes = read_immutable_file(&manifest_path, Some(MAX_MANIFEST_BYTES))?;
        let parsed = decode_manifest(&manifest_bytes, &manifest_path)?;
        if parsed.snapshot.snapshot_id != *snapshot_id {
            return Err(SnapshotStoreError::SnapshotIdMismatch {
                expected: snapshot_id.clone(),
                actual: parsed.snapshot.snapshot_id,
            });
        }
        if parsed.snapshot.grant_hash != self.grant.contract().grant_hash {
            return Err(SnapshotStoreError::GrantMismatch);
        }
        let canonical = encode_manifest(&parsed.snapshot, &parsed.entries)?;
        if canonical != manifest_bytes {
            return Err(SnapshotStoreError::Corrupt {
                path: manifest_path,
                reason: "manifest is not in canonical encoding".into(),
            });
        }

        let ready_path = directory.join(READY_FILE);
        let ready = read_immutable_file(&ready_path, Some(1024))?;
        let expected_ready = encode_ready(snapshot_id, &digest_bytes(&manifest_bytes)?);
        if ready != expected_ready {
            return Err(SnapshotStoreError::Corrupt {
                path: ready_path,
                reason: "READY does not authenticate the exact manifest".into(),
            });
        }

        let expected_blobs = parsed
            .entries
            .values()
            .map(|entry| entry.digest().as_str().to_owned())
            .collect::<BTreeSet<_>>();
        require_exact_dynamic_children(&blobs_directory, &expected_blobs)?;
        let mut verified = BTreeMap::new();
        for (relative, entry) in &parsed.entries {
            if let Some(previous_length) = verified.get(entry.digest()) {
                if *previous_length != entry.length() {
                    return Err(SnapshotStoreError::Corrupt {
                        path: relative.clone(),
                        reason: "one content digest declares conflicting byte lengths".into(),
                    });
                }
            } else {
                let bytes = self.read_blob(snapshot_id, entry.digest(), entry.length())?;
                let actual = digest_bytes(&bytes)?;
                if actual != *entry.digest() {
                    return Err(SnapshotStoreError::ContentMismatch {
                        path: relative.clone(),
                        expected: entry.digest().clone(),
                        actual,
                    });
                }
                verified.insert(entry.digest().clone(), entry.length());
            }
        }

        WorkspaceManifest::from_stored_parts(
            self.grant.contract().canonical_root.clone(),
            parsed.snapshot,
            parsed.entries,
        )
        .map_err(SnapshotStoreError::Workspace)
    }

    /// Creates a private writable shadow exclusively from a stored snapshot.
    ///
    /// The current live workspace contents are not read. The issued grant's root
    /// identity is still revalidated, then stored blobs are copied into a new
    /// `0700` tree with the original per-file modes.
    ///
    /// # Errors
    ///
    /// Returns an error if the snapshot fails verification, the destination is
    /// unsafe or overlaps the workspace/store, or copying and fsync fail.
    pub fn create_shadow(
        &self,
        snapshot_id: &Digest,
        destination: impl AsRef<Path>,
    ) -> Result<ShadowWorkspace, SnapshotStoreError> {
        let manifest = self.load(snapshot_id)?;
        let destination = destination.as_ref();
        self.validate_shadow_destination(destination)?;
        fs::create_dir(destination)
            .map_err(|error| io_error("create stored-snapshot shadow", destination, &error))?;
        set_mode(destination, 0o700, "set shadow root permissions")?;

        let creation = (|| {
            let mut directories = BTreeSet::new();
            let mut outputs = Vec::new();
            directories.insert(destination.to_path_buf());
            for (relative, entry) in manifest.entries() {
                let target = destination.join(relative);
                let parent = target.parent().ok_or_else(|| SnapshotStoreError::Corrupt {
                    path: relative.clone(),
                    reason: "manifest path has no parent".into(),
                })?;
                create_private_directories(destination, parent, &mut directories)?;
                let bytes = self.read_blob(snapshot_id, entry.digest(), entry.length())?;
                let mut output = OpenOptions::new()
                    .read(true)
                    .write(true)
                    .create_new(true)
                    .open(&target)
                    .map_err(|error| io_error("create shadow file", &target, &error))?;
                output
                    .write_all(&bytes)
                    .map_err(|error| io_error("write shadow file", &target, &error))?;
                output
                    .sync_all()
                    .map_err(|error| io_error("sync shadow file", &target, &error))?;
                set_file_mode(&output, &target, entry.mode())?;
                output
                    .sync_all()
                    .map_err(|error| io_error("sync shadow file mode", &target, &error))?;
                outputs.push((
                    target,
                    output,
                    entry.digest().clone(),
                    entry.length(),
                    entry.mode(),
                ));
            }
            let mut directories = directories.into_iter().collect::<Vec<_>>();
            directories.sort_by_key(|path| std::cmp::Reverse(path.components().count()));
            for directory in directories {
                sync_directory(&directory)?;
            }
            validate_shadow_layout(destination, manifest.entries())?;
            for (path, file, expected_digest, expected_length, expected_mode) in &mut outputs {
                let before = file
                    .metadata()
                    .map_err(|error| io_error("inspect open shadow file", path, &error))?;
                require_regular_metadata(path, &before)?;
                require_mode(path, &before, *expected_mode)?;
                let path_metadata = fs::symlink_metadata(&*path)
                    .map_err(|error| io_error("inspect shadow file path", path, &error))?;
                require_regular_metadata(path, &path_metadata)?;
                if !same_file_identity(&before, &path_metadata) {
                    return Err(SnapshotStoreError::Corrupt {
                        path: path.clone(),
                        reason: "shadow file identity changed before verification".into(),
                    });
                }
                file.seek(SeekFrom::Start(0))
                    .map_err(|error| io_error("seek shadow file", path, &error))?;
                let mut bytes = Vec::new();
                file.read_to_end(&mut bytes)
                    .map_err(|error| io_error("verify shadow file bytes", path, &error))?;
                let after = file
                    .metadata()
                    .map_err(|error| io_error("reinspect shadow file", path, &error))?;
                if !same_stable_metadata(&before, &after)
                    || u64::try_from(bytes.len()).unwrap_or(u64::MAX) != *expected_length
                {
                    return Err(SnapshotStoreError::Corrupt {
                        path: path.clone(),
                        reason: "shadow file changed during verification".into(),
                    });
                }
                let actual = digest_bytes(&bytes)?;
                if actual != *expected_digest {
                    return Err(SnapshotStoreError::ContentMismatch {
                        path: path.clone(),
                        expected: expected_digest.clone(),
                        actual,
                    });
                }
            }
            let canonical = fs::canonicalize(destination)
                .map_err(|error| io_error("canonicalize shadow", destination, &error))?;
            Ok(ShadowWorkspace::from_stored_parts(canonical, manifest))
        })();

        if creation.is_err() {
            let _ = fs::remove_dir_all(destination);
        }
        creation
    }

    fn validate_authority(&self) -> Result<(), SnapshotStoreError> {
        validate_grant(&self.grant)?;
        require_directory(&self.root, Some(0o700))?;
        require_directory(&self.snapshots, Some(0o700))?;
        verify_store_binding(&self.grant, &self.root.join(STORE_FILE))
    }

    fn validate_manifest_authority(
        &self,
        manifest: &WorkspaceManifest,
    ) -> Result<(), SnapshotStoreError> {
        if manifest.root() != self.grant.contract().canonical_root
            || manifest.snapshot().grant_hash != self.grant.contract().grant_hash
        {
            return Err(SnapshotStoreError::GrantMismatch);
        }
        ensure_no_path_prefix_conflicts(manifest.entries())
    }

    fn validate_shadow_destination(&self, destination: &Path) -> Result<(), SnapshotStoreError> {
        if !destination.is_absolute() || !is_normalized_absolute(destination) {
            return Err(SnapshotStoreError::UnsafeDestination(
                destination.to_path_buf(),
            ));
        }
        match fs::symlink_metadata(destination) {
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Ok(_) => {
                return Err(SnapshotStoreError::DestinationExists(
                    destination.to_path_buf(),
                ));
            }
            Err(error) => return Err(io_error("inspect shadow destination", destination, &error)),
        }
        let parent = destination
            .parent()
            .ok_or_else(|| SnapshotStoreError::UnsafeDestination(destination.to_path_buf()))?;
        let canonical_parent = fs::canonicalize(parent)
            .map_err(|error| io_error("canonicalize shadow parent", parent, &error))?;
        require_directory(&canonical_parent, None)?;
        let name = destination
            .file_name()
            .ok_or_else(|| SnapshotStoreError::UnsafeDestination(destination.to_path_buf()))?;
        let canonical_candidate = canonical_parent.join(name);
        if canonical_candidate.starts_with(&self.grant.contract().canonical_root)
            || self
                .grant
                .contract()
                .canonical_root
                .starts_with(&canonical_candidate)
            || canonical_candidate.starts_with(&self.root)
            || self.root.starts_with(&canonical_candidate)
        {
            return Err(SnapshotStoreError::UnsafeDestination(
                destination.to_path_buf(),
            ));
        }
        Ok(())
    }

    fn persist_verified(
        &self,
        manifest: &WorkspaceManifest,
        blobs: &BTreeMap<Digest, Vec<u8>>,
    ) -> Result<WorkspaceManifest, SnapshotStoreError> {
        for entry in manifest.entries().values() {
            let bytes = blobs
                .get(entry.digest())
                .ok_or_else(|| SnapshotStoreError::MissingBlob(entry.digest().clone()))?;
            let actual = digest_bytes(bytes)?;
            if actual != *entry.digest()
                || u64::try_from(bytes.len()).unwrap_or(u64::MAX) != entry.length()
            {
                return Err(SnapshotStoreError::ContentMismatch {
                    path: PathBuf::from(entry.digest().as_str()),
                    expected: entry.digest().clone(),
                    actual,
                });
            }
        }

        let target = self.snapshot_directory(&manifest.snapshot().snapshot_id);
        if fs::symlink_metadata(&target).is_ok() {
            return self.verify_idempotent_existing(manifest);
        }
        let temporary = self.temporary_snapshot_path(&manifest.snapshot().snapshot_id);
        fs::create_dir(&temporary)
            .map_err(|error| io_error("create temporary snapshot", &temporary, &error))?;
        set_mode(&temporary, 0o700, "set temporary snapshot permissions")?;

        let write_result = (|| {
            let blob_directory = temporary.join(BLOBS_DIRECTORY);
            fs::create_dir(&blob_directory)
                .map_err(|error| io_error("create blob directory", &blob_directory, &error))?;
            set_mode(&blob_directory, 0o700, "set blob directory permissions")?;

            let expected_digests = manifest
                .entries()
                .values()
                .map(|entry| entry.digest().clone())
                .collect::<BTreeSet<_>>();
            for digest in expected_digests {
                let bytes = blobs
                    .get(&digest)
                    .ok_or_else(|| SnapshotStoreError::MissingBlob(digest.clone()))?;
                write_immutable_file(&blob_directory.join(digest.as_str()), bytes)?;
            }
            sync_directory(&blob_directory)?;

            let manifest_bytes = encode_manifest(manifest.snapshot(), manifest.entries())?;
            write_immutable_file(&temporary.join(MANIFEST_FILE), &manifest_bytes)?;
            let ready = encode_ready(
                &manifest.snapshot().snapshot_id,
                &digest_bytes(&manifest_bytes)?,
            );
            write_immutable_file(&temporary.join(READY_FILE), &ready)?;
            set_mode(&blob_directory, 0o500, "seal blob directory")?;
            sync_directory(&blob_directory)?;
            sync_directory(&temporary)?;

            match fs::rename(&temporary, &target) {
                Ok(()) => {
                    // macOS requires the moved directory itself to remain owner
                    // writable while its `..` entry is changed. All bytes are
                    // already immutable and durable before promotion; sealing the
                    // directory is the only recoverable post-rename metadata step.
                    set_mode(&target, 0o500, "seal snapshot directory")?;
                    sync_directory(&target)?;
                    sync_directory(&self.snapshots)?;
                    self.verify_idempotent_existing(manifest)
                }
                Err(_error) if fs::symlink_metadata(&target).is_ok() => {
                    let _ = fs::remove_dir_all(&temporary);
                    self.verify_idempotent_existing(manifest)
                }
                Err(error) => Err(io_error("promote immutable snapshot", &target, &error)),
            }
        })();

        if write_result.is_err() && fs::symlink_metadata(&temporary).is_ok() {
            let _ = set_mode(&temporary, 0o700, "unseal failed snapshot");
            let _ = fs::remove_dir_all(&temporary);
        }
        write_result
    }

    fn verify_idempotent_existing(
        &self,
        expected: &WorkspaceManifest,
    ) -> Result<WorkspaceManifest, SnapshotStoreError> {
        let loaded = self
            .load(&expected.snapshot().snapshot_id)
            .map_err(|error| SnapshotStoreError::IdentifierCollision {
                snapshot_id: expected.snapshot().snapshot_id.clone(),
                reason: error.to_string(),
            })?;
        if loaded.entries() != expected.entries()
            || loaded.snapshot().grant_hash != expected.snapshot().grant_hash
        {
            return Err(SnapshotStoreError::IdentifierCollision {
                snapshot_id: expected.snapshot().snapshot_id.clone(),
                reason: "existing object has different manifest content".into(),
            });
        }
        Ok(loaded)
    }

    fn read_blob(
        &self,
        snapshot_id: &Digest,
        digest: &Digest,
        expected_length: u64,
    ) -> Result<Vec<u8>, SnapshotStoreError> {
        let path = self
            .snapshot_directory(snapshot_id)
            .join(BLOBS_DIRECTORY)
            .join(digest.as_str());
        let bytes = read_immutable_file(&path, None)?;
        let actual_length = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
        let actual_digest = digest_bytes(&bytes)?;
        if actual_length != expected_length || actual_digest != *digest {
            return Err(SnapshotStoreError::ContentMismatch {
                path,
                expected: digest.clone(),
                actual: actual_digest,
            });
        }
        Ok(bytes)
    }

    fn snapshot_directory(&self, snapshot_id: &Digest) -> PathBuf {
        self.snapshots.join(snapshot_id.as_str())
    }

    fn temporary_snapshot_path(&self, snapshot_id: &Digest) -> PathBuf {
        let sequence = NEXT_TEMPORARY.fetch_add(1, Ordering::Relaxed);
        self.snapshots.join(format!(
            ".tmp-{}-{}-{sequence}",
            snapshot_id.as_str(),
            std::process::id()
        ))
    }

    fn clean_incomplete_and_validate_types(&self) -> Result<(), SnapshotStoreError> {
        let mut children = read_children(&self.snapshots)?;
        children.sort_by_key(fs::DirEntry::file_name);
        for child in children {
            let name = child
                .file_name()
                .into_string()
                .map_err(|_| SnapshotStoreError::UnsafePath(child.path()))?;
            let path = child.path();
            if name.starts_with(".tmp-") {
                validate_safe_tree_types(&path)?;
                make_tree_owner_writable(&path)?;
                fs::remove_dir_all(&path)
                    .map_err(|error| io_error("remove incomplete snapshot", &path, &error))?;
                sync_directory(&self.snapshots)?;
                continue;
            }
            let digest = Digest::parse(name).map_err(SnapshotStoreError::Contract)?;
            let metadata = fs::symlink_metadata(&path)
                .map_err(|error| io_error("inspect completed snapshot", &path, &error))?;
            require_directory(&path, None)?;
            let mut recovered_seal = false;
            if normalized_mode(&metadata) == 0o700 {
                // Recover the only allowed crash window: atomic promotion
                // completed after all bytes and READY were durable, but the
                // directory-sealing chmod did not.
                set_mode(&path, 0o500, "recover snapshot directory seal")?;
                sync_directory(&path)?;
                sync_directory(&self.snapshots)?;
                recovered_seal = true;
            }
            require_directory(&path, Some(0o500))?;
            validate_safe_tree_types(&path)?;
            if recovered_seal {
                self.load(&digest)?;
            }
        }
        Ok(())
    }
}

/// A fail-closed durable snapshot-store error.
#[derive(Debug)]
pub enum SnapshotStoreError {
    /// The issued authority or a digest contract was invalid.
    Contract(ContractError),
    /// Snapshot/diff pipeline validation failed.
    Workspace(WorkspacePipelineError),
    /// Store roots must be canonical-style normalized absolute paths.
    RootNotNormalizedAbsolute(PathBuf),
    /// Store and workspace paths must not contain one another.
    StoreOverlapsWorkspace(PathBuf),
    /// A store or snapshot has an unexpected entry set.
    UnexpectedLayout(PathBuf),
    /// A directory or immutable file has unsafe permissions.
    UnsafeMode {
        /// Affected path.
        path: PathBuf,
        /// Required permission bits.
        expected: u32,
        /// Observed permission bits.
        actual: u32,
    },
    /// A link or unsupported filesystem object was encountered.
    UnsafeEntry {
        /// Affected path.
        path: PathBuf,
        /// Rejected entry category.
        kind: UnsafeEntryKind,
    },
    /// A path could not be represented safely.
    UnsafePath(PathBuf),
    /// Store metadata is bound to different authority.
    GrantMismatch,
    /// A snapshot identifier was not found.
    SnapshotNotFound(Digest),
    /// A stored snapshot's declared identifier is not the requested identifier.
    SnapshotIdMismatch {
        /// Requested or manifest-computed identifier.
        expected: Digest,
        /// Stored or recomputed identifier.
        actual: Digest,
    },
    /// Existing bytes conflict with a supposedly write-once snapshot identifier.
    IdentifierCollision {
        /// Colliding snapshot identifier.
        snapshot_id: Digest,
        /// Evidence explaining the mismatch.
        reason: String,
    },
    /// Stored or source bytes do not match their declared digest or length.
    ContentMismatch {
        /// Affected path.
        path: PathBuf,
        /// Declared content digest.
        expected: Digest,
        /// Recomputed content digest.
        actual: Digest,
    },
    /// Source file mode changed after manifest capture.
    ModeMismatch {
        /// Affected path.
        path: PathBuf,
        /// Captured mode.
        expected: u32,
        /// Current mode.
        actual: u32,
    },
    /// A stored object failed canonical or integrity validation.
    Corrupt {
        /// Affected path.
        path: PathBuf,
        /// Exact validation failure.
        reason: String,
    },
    /// A staged result timestamp must be nonzero.
    InvalidTimestamp,
    /// The supplied base differs from the stored base or change-set base.
    BaseMismatch,
    /// A staged operation cannot be applied to the stored base.
    OperationDoesNotApply(PathBuf),
    /// A staged result content blob is absent.
    MissingBlob(Digest),
    /// A created file lacks its captured mode.
    MissingCreateMode(PathBuf),
    /// A shadow destination already exists.
    DestinationExists(PathBuf),
    /// A shadow destination is non-normalized or overlaps protected roots.
    UnsafeDestination(PathBuf),
    /// A filesystem operation failed.
    Io {
        /// Operation being performed.
        operation: &'static str,
        /// Affected path.
        path: PathBuf,
        /// Operating-system error text.
        message: String,
    },
}

impl Display for SnapshotStoreError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Contract(error) => write!(formatter, "contract validation failed: {error}"),
            Self::Workspace(error) => write!(formatter, "workspace validation failed: {error}"),
            Self::RootNotNormalizedAbsolute(path) => write!(
                formatter,
                "snapshot store root is not a normalized absolute path: {}",
                path.display()
            ),
            Self::StoreOverlapsWorkspace(path) => write!(
                formatter,
                "snapshot store overlaps the workspace: {}",
                path.display()
            ),
            Self::UnexpectedLayout(path) => {
                write!(
                    formatter,
                    "unexpected snapshot-store layout at {}",
                    path.display()
                )
            }
            Self::UnsafeMode {
                path,
                expected,
                actual,
            } => write!(
                formatter,
                "unsafe mode at {}: expected {expected:04o}, found {actual:04o}",
                path.display()
            ),
            Self::UnsafeEntry { path, kind } => {
                write!(formatter, "unsafe {kind:?} entry at {}", path.display())
            }
            Self::UnsafePath(path) => write!(formatter, "unsafe path: {}", path.display()),
            Self::GrantMismatch => formatter.write_str("snapshot store grant binding mismatch"),
            Self::SnapshotNotFound(id) => write!(formatter, "snapshot {id} was not found"),
            Self::SnapshotIdMismatch { expected, actual } => write!(
                formatter,
                "snapshot identifier mismatch: expected {expected}, found {actual}"
            ),
            Self::IdentifierCollision {
                snapshot_id,
                reason,
            } => write!(
                formatter,
                "snapshot identifier collision for {snapshot_id}: {reason}"
            ),
            Self::ContentMismatch {
                path,
                expected,
                actual,
            } => write!(
                formatter,
                "content mismatch at {}: expected {expected}, found {actual}",
                path.display()
            ),
            Self::ModeMismatch {
                path,
                expected,
                actual,
            } => write!(
                formatter,
                "mode mismatch at {}: expected {expected:04o}, found {actual:04o}",
                path.display()
            ),
            Self::Corrupt { path, reason } => {
                write!(
                    formatter,
                    "corrupt snapshot object at {}: {reason}",
                    path.display()
                )
            }
            Self::InvalidTimestamp => formatter.write_str("snapshot timestamp must be nonzero"),
            Self::BaseMismatch => formatter.write_str("staged snapshot base mismatch"),
            Self::OperationDoesNotApply(path) => write!(
                formatter,
                "staged operation does not apply at {}",
                path.display()
            ),
            Self::MissingBlob(digest) => write!(formatter, "missing staged blob {digest}"),
            Self::MissingCreateMode(path) => {
                write!(formatter, "missing create mode for {}", path.display())
            }
            Self::DestinationExists(path) => {
                write!(formatter, "shadow destination exists: {}", path.display())
            }
            Self::UnsafeDestination(path) => {
                write!(formatter, "unsafe shadow destination: {}", path.display())
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

impl std::error::Error for SnapshotStoreError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Contract(error) => Some(error),
            Self::Workspace(error) => Some(error),
            _ => None,
        }
    }
}

impl From<WorkspacePipelineError> for SnapshotStoreError {
    fn from(error: WorkspacePipelineError) -> Self {
        Self::Workspace(error)
    }
}

struct ParsedManifest {
    snapshot: WorkspaceSnapshot,
    entries: BTreeMap<PathBuf, ManifestEntry>,
}

fn apply_staged_operations(
    entries: &mut BTreeMap<PathBuf, ManifestEntry>,
    staged: &StagedChangeSet,
) -> Result<(), SnapshotStoreError> {
    for operation in &staged.change_set().operations {
        match operation {
            FileOperation::Create { path, result_hash } => {
                if entries.contains_key(path) {
                    return Err(SnapshotStoreError::OperationDoesNotApply(path.clone()));
                }
                let bytes = staged
                    .blob(result_hash)
                    .ok_or_else(|| SnapshotStoreError::MissingBlob(result_hash.clone()))?;
                let mode = staged
                    .create_mode(path)
                    .ok_or_else(|| SnapshotStoreError::MissingCreateMode(path.clone()))?;
                entries.insert(
                    path.clone(),
                    ManifestEntry::from_stored_parts(
                        result_hash.clone(),
                        u64::try_from(bytes.len()).unwrap_or(u64::MAX),
                        mode,
                    ),
                );
            }
            FileOperation::Modify {
                path,
                base_hash,
                result_hash,
            } => {
                let current = entries
                    .get(path)
                    .ok_or_else(|| SnapshotStoreError::OperationDoesNotApply(path.clone()))?;
                if current.digest() != base_hash {
                    return Err(SnapshotStoreError::OperationDoesNotApply(path.clone()));
                }
                let mode = current.mode();
                let bytes = staged
                    .blob(result_hash)
                    .ok_or_else(|| SnapshotStoreError::MissingBlob(result_hash.clone()))?;
                entries.insert(
                    path.clone(),
                    ManifestEntry::from_stored_parts(
                        result_hash.clone(),
                        u64::try_from(bytes.len()).unwrap_or(u64::MAX),
                        mode,
                    ),
                );
            }
            FileOperation::Delete { path, base_hash } => {
                let current = entries
                    .get(path)
                    .ok_or_else(|| SnapshotStoreError::OperationDoesNotApply(path.clone()))?;
                if current.digest() != base_hash {
                    return Err(SnapshotStoreError::OperationDoesNotApply(path.clone()));
                }
                entries.remove(path);
            }
        }
    }
    Ok(())
}

fn validate_grant(grant: &IssuedWorkspaceGrant) -> Result<(), SnapshotStoreError> {
    grant
        .validate_integrity()
        .map_err(SnapshotStoreError::Contract)
}

fn ensure_disjoint(store: &Path, workspace: &Path) -> Result<(), SnapshotStoreError> {
    if store.starts_with(workspace) || workspace.starts_with(store) {
        return Err(SnapshotStoreError::StoreOverlapsWorkspace(
            store.to_path_buf(),
        ));
    }
    Ok(())
}

fn initialize_or_verify_store(
    grant: &IssuedWorkspaceGrant,
    root: &Path,
    snapshots: &Path,
) -> Result<(), SnapshotStoreError> {
    let mut names = read_children(root)?
        .into_iter()
        .map(|entry| {
            entry
                .file_name()
                .into_string()
                .map_err(|_| SnapshotStoreError::UnsafePath(entry.path()))
        })
        .collect::<Result<BTreeSet<_>, _>>()?;

    for name in names
        .iter()
        .filter(|name| name.starts_with(".tmp-store-"))
        .cloned()
        .collect::<Vec<_>>()
    {
        let temporary = root.join(&name);
        let metadata = fs::symlink_metadata(&temporary)
            .map_err(|error| io_error("inspect temporary store file", &temporary, &error))?;
        require_regular_metadata(&temporary, &metadata)?;
        fs::remove_file(&temporary)
            .map_err(|error| io_error("remove temporary store file", &temporary, &error))?;
        names.remove(&name);
    }

    if names.is_empty() {
        fs::create_dir(snapshots)
            .map_err(|error| io_error("create snapshots directory", snapshots, &error))?;
        set_mode(snapshots, 0o700, "set snapshots directory permissions")?;
        write_store_binding(grant, root)?;
        sync_directory(root)?;
    } else if names == BTreeSet::from([SNAPSHOTS_DIRECTORY.to_owned()]) {
        require_directory(snapshots, Some(0o700))?;
        if read_children(snapshots)?.is_empty() {
            write_store_binding(grant, root)?;
            sync_directory(root)?;
        } else {
            return Err(SnapshotStoreError::UnexpectedLayout(root.to_path_buf()));
        }
    } else {
        let expected = BTreeSet::from([STORE_FILE.to_owned(), SNAPSHOTS_DIRECTORY.to_owned()]);
        if names != expected {
            return Err(SnapshotStoreError::UnexpectedLayout(root.to_path_buf()));
        }
    }
    require_directory(snapshots, Some(0o700))?;
    verify_store_binding(grant, &root.join(STORE_FILE))
}

fn write_store_binding(
    grant: &IssuedWorkspaceGrant,
    root: &Path,
) -> Result<(), SnapshotStoreError> {
    let binding = encode_store_binding(grant)?;
    let sequence = NEXT_TEMPORARY.fetch_add(1, Ordering::Relaxed);
    let temporary = root.join(format!(".tmp-store-{}-{sequence}", std::process::id()));
    write_immutable_file(&temporary, &binding)?;
    let destination = root.join(STORE_FILE);
    if fs::symlink_metadata(&destination).is_ok() {
        fs::remove_file(&temporary)
            .map_err(|error| io_error("remove redundant store binding", &temporary, &error))?;
        return verify_store_binding(grant, &destination);
    }
    fs::rename(&temporary, &destination)
        .map_err(|error| io_error("promote store binding", &destination, &error))?;
    sync_directory(root)
}

fn encode_store_binding(grant: &IssuedWorkspaceGrant) -> Result<Vec<u8>, SnapshotStoreError> {
    let root =
        grant.contract().canonical_root.to_str().ok_or_else(|| {
            SnapshotStoreError::UnsafePath(grant.contract().canonical_root.clone())
        })?;
    let root_length = u64::try_from(root.len())
        .map_err(|_| SnapshotStoreError::UnsafePath(grant.contract().canonical_root.clone()))?;
    let mut encoded = Vec::new();
    encoded.extend_from_slice(STORE_MAGIC);
    encoded.extend_from_slice(grant.contract().grant_hash.as_str().as_bytes());
    encoded.extend_from_slice(&root_length.to_be_bytes());
    encoded.extend_from_slice(root.as_bytes());
    Ok(encoded)
}

fn verify_store_binding(
    grant: &IssuedWorkspaceGrant,
    path: &Path,
) -> Result<(), SnapshotStoreError> {
    let stored = read_immutable_file(path, Some(4 * 1024 * 1024))?;
    let expected = encode_store_binding(grant)?;
    if stored != expected {
        return Err(SnapshotStoreError::GrantMismatch);
    }
    Ok(())
}

fn encode_manifest(
    snapshot: &WorkspaceSnapshot,
    entries: &BTreeMap<PathBuf, ManifestEntry>,
) -> Result<Vec<u8>, SnapshotStoreError> {
    snapshot.validate().map_err(SnapshotStoreError::Contract)?;
    ensure_no_path_prefix_conflicts(entries)?;
    let mut encoded = Vec::new();
    encoded.extend_from_slice(MANIFEST_MAGIC);
    encoded.extend_from_slice(snapshot.snapshot_id.as_str().as_bytes());
    encoded.extend_from_slice(snapshot.grant_hash.as_str().as_bytes());
    encoded.extend_from_slice(&snapshot.created_at_unix_ms.to_be_bytes());
    encoded.extend_from_slice(
        &u64::try_from(entries.len())
            .map_err(|_| SnapshotStoreError::Corrupt {
                path: PathBuf::from(MANIFEST_FILE),
                reason: "too many manifest entries".into(),
            })?
            .to_be_bytes(),
    );
    for (path, entry) in entries {
        let portable = portable_relative_path(path)?;
        encoded.extend_from_slice(
            &u64::try_from(portable.len())
                .map_err(|_| SnapshotStoreError::UnsafePath(path.clone()))?
                .to_be_bytes(),
        );
        encoded.extend_from_slice(portable.as_bytes());
        encoded.extend_from_slice(entry.digest().as_str().as_bytes());
        encoded.extend_from_slice(&entry.length().to_be_bytes());
        encoded.extend_from_slice(&entry.mode().to_be_bytes());
    }
    Ok(encoded)
}

fn decode_manifest(bytes: &[u8], path: &Path) -> Result<ParsedManifest, SnapshotStoreError> {
    let mut reader = ByteReader::new(bytes, path);
    reader.expect(MANIFEST_MAGIC, "manifest magic")?;
    let snapshot_id = reader.digest("snapshot identifier")?;
    let grant_hash = reader.digest("grant hash")?;
    let created_at_unix_ms = reader.u64("creation timestamp")?;
    let count = reader.u64("entry count")?;
    if count > MAX_MANIFEST_ENTRIES {
        return Err(reader.corrupt("entry count exceeds the supported bound"));
    }
    let mut entries = BTreeMap::new();
    for _ in 0..count {
        let path_length = reader.u64("path length")?;
        if path_length == 0 || path_length > MAX_PATH_BYTES {
            return Err(reader.corrupt("manifest path length is unsafe"));
        }
        let path_bytes = reader.take(
            usize::try_from(path_length)
                .map_err(|_| reader.corrupt("manifest path length overflows this host"))?,
            "path bytes",
        )?;
        let path_text = std::str::from_utf8(path_bytes)
            .map_err(|_| reader.corrupt("manifest path is not UTF-8"))?;
        let relative = parse_portable_relative_path(path_text)?;
        let digest = reader.digest("entry digest")?;
        let length = reader.u64("entry length")?;
        let mode = reader.u32("entry mode")?;
        if mode & !0o777 != 0 {
            return Err(reader.corrupt("manifest mode contains non-permission bits"));
        }
        if entries
            .insert(
                relative,
                ManifestEntry::from_stored_parts(digest, length, mode),
            )
            .is_some()
        {
            return Err(reader.corrupt("manifest contains a duplicate path"));
        }
    }
    if !reader.is_finished() {
        return Err(reader.corrupt("manifest contains trailing bytes"));
    }
    ensure_no_path_prefix_conflicts(&entries)?;
    let snapshot = WorkspaceSnapshot {
        snapshot_id,
        grant_hash,
        created_at_unix_ms,
    };
    WorkspaceManifest::from_stored_parts(PathBuf::from("/"), snapshot.clone(), entries.clone())?;
    Ok(ParsedManifest { snapshot, entries })
}

fn encode_ready(snapshot_id: &Digest, manifest_digest: &Digest) -> Vec<u8> {
    let mut encoded = Vec::new();
    encoded.extend_from_slice(READY_MAGIC);
    encoded.extend_from_slice(snapshot_id.as_str().as_bytes());
    encoded.extend_from_slice(manifest_digest.as_str().as_bytes());
    encoded
}

struct ByteReader<'a> {
    bytes: &'a [u8],
    offset: usize,
    path: &'a Path,
}

impl<'a> ByteReader<'a> {
    const fn new(bytes: &'a [u8], path: &'a Path) -> Self {
        Self {
            bytes,
            offset: 0,
            path,
        }
    }

    fn take(&mut self, length: usize, field: &str) -> Result<&'a [u8], SnapshotStoreError> {
        let end = self
            .offset
            .checked_add(length)
            .ok_or_else(|| self.corrupt(format!("{field} length overflow")))?;
        let value = self
            .bytes
            .get(self.offset..end)
            .ok_or_else(|| self.corrupt(format!("truncated {field}")))?;
        self.offset = end;
        Ok(value)
    }

    fn expect(&mut self, expected: &[u8], field: &str) -> Result<(), SnapshotStoreError> {
        if self.take(expected.len(), field)? != expected {
            return Err(self.corrupt(format!("invalid {field}")));
        }
        Ok(())
    }

    fn digest(&mut self, field: &str) -> Result<Digest, SnapshotStoreError> {
        let bytes = self.take(64, field)?;
        let text = std::str::from_utf8(bytes)
            .map_err(|_| self.corrupt(format!("{field} is not UTF-8")))?;
        Digest::parse(text.to_owned()).map_err(|_| self.corrupt(format!("invalid {field}")))
    }

    fn u64(&mut self, field: &str) -> Result<u64, SnapshotStoreError> {
        let bytes: [u8; 8] = self
            .take(8, field)?
            .try_into()
            .map_err(|_| self.corrupt(format!("invalid {field}")))?;
        Ok(u64::from_be_bytes(bytes))
    }

    fn u32(&mut self, field: &str) -> Result<u32, SnapshotStoreError> {
        let bytes: [u8; 4] = self
            .take(4, field)?
            .try_into()
            .map_err(|_| self.corrupt(format!("invalid {field}")))?;
        Ok(u32::from_be_bytes(bytes))
    }

    const fn is_finished(&self) -> bool {
        self.offset == self.bytes.len()
    }

    fn corrupt(&self, reason: impl Into<String>) -> SnapshotStoreError {
        SnapshotStoreError::Corrupt {
            path: self.path.to_path_buf(),
            reason: reason.into(),
        }
    }
}

fn ensure_no_path_prefix_conflicts(
    entries: &BTreeMap<PathBuf, ManifestEntry>,
) -> Result<(), SnapshotStoreError> {
    for path in entries.keys() {
        portable_relative_path(path)?;
        let mut parent = path.parent();
        while let Some(candidate) = parent {
            if !candidate.as_os_str().is_empty() && entries.contains_key(candidate) {
                return Err(SnapshotStoreError::Corrupt {
                    path: path.clone(),
                    reason: "a regular-file path is the parent of another file".into(),
                });
            }
            parent = candidate.parent();
        }
    }
    Ok(())
}

fn portable_relative_path(path: &Path) -> Result<String, SnapshotStoreError> {
    if path.is_absolute() || path.as_os_str().is_empty() {
        return Err(SnapshotStoreError::UnsafePath(path.to_path_buf()));
    }
    let mut encoded = String::new();
    for (index, component) in path.components().enumerate() {
        let Component::Normal(component) = component else {
            return Err(SnapshotStoreError::UnsafePath(path.to_path_buf()));
        };
        let text = component
            .to_str()
            .ok_or_else(|| SnapshotStoreError::UnsafePath(path.to_path_buf()))?;
        if text.is_empty() || text.eq_ignore_ascii_case(".git") || text.contains(['/', '\0']) {
            return Err(SnapshotStoreError::UnsafePath(path.to_path_buf()));
        }
        if index != 0 {
            encoded.push('/');
        }
        encoded.push_str(text);
    }
    Ok(encoded)
}

fn parse_portable_relative_path(text: &str) -> Result<PathBuf, SnapshotStoreError> {
    if text.is_empty() || text.starts_with('/') || text.ends_with('/') || text.contains('\0') {
        return Err(SnapshotStoreError::UnsafePath(PathBuf::from(text)));
    }
    let mut path = PathBuf::new();
    for component in text.split('/') {
        if component.is_empty()
            || component == "."
            || component == ".."
            || component.eq_ignore_ascii_case(".git")
        {
            return Err(SnapshotStoreError::UnsafePath(PathBuf::from(text)));
        }
        path.push(component);
    }
    if portable_relative_path(&path)? != text {
        return Err(SnapshotStoreError::UnsafePath(path));
    }
    Ok(path)
}

fn is_normalized_absolute(path: &Path) -> bool {
    if !path.is_absolute() {
        return false;
    }
    path.components()
        .all(|component| matches!(component, Component::RootDir | Component::Normal(_)))
}

fn require_exact_children<const N: usize>(
    directory: &Path,
    expected: [&str; N],
) -> Result<(), SnapshotStoreError> {
    let expected = expected
        .into_iter()
        .map(str::to_owned)
        .collect::<BTreeSet<_>>();
    let actual = read_children(directory)?
        .into_iter()
        .map(|entry| {
            entry
                .file_name()
                .into_string()
                .map_err(|_| SnapshotStoreError::UnsafePath(entry.path()))
        })
        .collect::<Result<BTreeSet<_>, _>>()?;
    if actual != expected {
        return Err(SnapshotStoreError::UnexpectedLayout(
            directory.to_path_buf(),
        ));
    }
    Ok(())
}

fn require_exact_dynamic_children(
    directory: &Path,
    expected: &BTreeSet<String>,
) -> Result<(), SnapshotStoreError> {
    let actual = read_children(directory)?
        .into_iter()
        .map(|entry| {
            entry
                .file_name()
                .into_string()
                .map_err(|_| SnapshotStoreError::UnsafePath(entry.path()))
        })
        .collect::<Result<BTreeSet<_>, _>>()?;
    if &actual != expected {
        return Err(SnapshotStoreError::UnexpectedLayout(
            directory.to_path_buf(),
        ));
    }
    Ok(())
}

fn read_children(directory: &Path) -> Result<Vec<fs::DirEntry>, SnapshotStoreError> {
    fs::read_dir(directory)
        .map_err(|error| io_error("read directory", directory, &error))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| io_error("enumerate directory", directory, &error))
}

fn require_directory(path: &Path, expected_mode: Option<u32>) -> Result<(), SnapshotStoreError> {
    let metadata =
        fs::symlink_metadata(path).map_err(|error| io_error("inspect directory", path, &error))?;
    if metadata.file_type().is_symlink() {
        return Err(SnapshotStoreError::UnsafeEntry {
            path: path.to_path_buf(),
            kind: UnsafeEntryKind::Symlink,
        });
    }
    if !metadata.file_type().is_dir() {
        return Err(SnapshotStoreError::UnsafeEntry {
            path: path.to_path_buf(),
            kind: UnsafeEntryKind::Special,
        });
    }
    if let Some(expected) = expected_mode {
        require_mode(path, &metadata, expected)?;
    }
    Ok(())
}

fn require_regular_metadata(
    path: &Path,
    metadata: &fs::Metadata,
) -> Result<(), SnapshotStoreError> {
    if metadata.file_type().is_symlink() {
        return Err(SnapshotStoreError::UnsafeEntry {
            path: path.to_path_buf(),
            kind: UnsafeEntryKind::Symlink,
        });
    }
    if !metadata.file_type().is_file() {
        return Err(SnapshotStoreError::UnsafeEntry {
            path: path.to_path_buf(),
            kind: UnsafeEntryKind::Special,
        });
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if metadata.nlink() != 1 {
            return Err(SnapshotStoreError::UnsafeEntry {
                path: path.to_path_buf(),
                kind: UnsafeEntryKind::HardLink,
            });
        }
    }
    Ok(())
}

fn read_immutable_file(
    path: &Path,
    maximum_length: Option<u64>,
) -> Result<Vec<u8>, SnapshotStoreError> {
    let before = fs::symlink_metadata(path)
        .map_err(|error| io_error("inspect immutable file", path, &error))?;
    require_regular_metadata(path, &before)?;
    require_mode(path, &before, 0o400)?;
    if maximum_length.is_some_and(|maximum| before.len() > maximum) {
        return Err(SnapshotStoreError::Corrupt {
            path: path.to_path_buf(),
            reason: "immutable file exceeds its supported size bound".into(),
        });
    }
    let mut file =
        File::open(path).map_err(|error| io_error("open immutable file", path, &error))?;
    let opened = file
        .metadata()
        .map_err(|error| io_error("inspect open immutable file", path, &error))?;
    require_regular_metadata(path, &opened)?;
    require_mode(path, &opened, 0o400)?;
    if !same_file_identity(&before, &opened) {
        return Err(SnapshotStoreError::Corrupt {
            path: path.to_path_buf(),
            reason: "immutable file identity changed during open".into(),
        });
    }
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)
        .map_err(|error| io_error("read immutable file", path, &error))?;
    let after_open = file
        .metadata()
        .map_err(|error| io_error("reinspect immutable file", path, &error))?;
    let after_path = fs::symlink_metadata(path)
        .map_err(|error| io_error("reinspect immutable path", path, &error))?;
    require_regular_metadata(path, &after_path)?;
    require_mode(path, &after_path, 0o400)?;
    if !same_stable_metadata(&opened, &after_open)
        || !same_file_identity(&after_open, &after_path)
        || after_open.len() != u64::try_from(bytes.len()).unwrap_or(u64::MAX)
    {
        return Err(SnapshotStoreError::Corrupt {
            path: path.to_path_buf(),
            reason: "immutable file changed during read".into(),
        });
    }
    Ok(bytes)
}

fn write_immutable_file(path: &Path, bytes: &[u8]) -> Result<(), SnapshotStoreError> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|error| io_error("create immutable file", path, &error))?;
    set_file_mode(&file, path, 0o600)?;
    file.write_all(bytes)
        .map_err(|error| io_error("write immutable file", path, &error))?;
    file.sync_all()
        .map_err(|error| io_error("sync immutable file", path, &error))?;
    set_file_mode(&file, path, 0o400)?;
    file.sync_all()
        .map_err(|error| io_error("sync immutable file mode", path, &error))
}

fn validate_safe_tree_types(path: &Path) -> Result<(), SnapshotStoreError> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| io_error("inspect store tree entry", path, &error))?;
    if metadata.file_type().is_symlink() {
        return Err(SnapshotStoreError::UnsafeEntry {
            path: path.to_path_buf(),
            kind: UnsafeEntryKind::Symlink,
        });
    }
    if metadata.file_type().is_file() {
        return require_regular_metadata(path, &metadata);
    }
    if !metadata.file_type().is_dir() {
        return Err(SnapshotStoreError::UnsafeEntry {
            path: path.to_path_buf(),
            kind: UnsafeEntryKind::Special,
        });
    }
    for child in read_children(path)? {
        validate_safe_tree_types(&child.path())?;
    }
    Ok(())
}

fn make_tree_owner_writable(path: &Path) -> Result<(), SnapshotStoreError> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| io_error("inspect incomplete tree", path, &error))?;
    if metadata.file_type().is_dir() {
        set_mode(path, 0o700, "unseal incomplete directory")?;
        for child in read_children(path)? {
            make_tree_owner_writable(&child.path())?;
        }
    } else if metadata.file_type().is_file() {
        set_mode(path, 0o600, "unseal incomplete file")?;
    }
    Ok(())
}

fn create_private_directories(
    root: &Path,
    target: &Path,
    directories: &mut BTreeSet<PathBuf>,
) -> Result<(), SnapshotStoreError> {
    let relative = target
        .strip_prefix(root)
        .map_err(|_| SnapshotStoreError::UnsafeDestination(target.to_path_buf()))?;
    let mut current = root.to_path_buf();
    for component in relative.components() {
        let Component::Normal(component) = component else {
            return Err(SnapshotStoreError::UnsafeDestination(target.to_path_buf()));
        };
        current.push(component);
        match fs::create_dir(&current) {
            Ok(()) => set_mode(&current, 0o700, "set shadow directory permissions")?,
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                require_directory(&current, Some(0o700))?;
            }
            Err(error) => return Err(io_error("create shadow directory", &current, &error)),
        }
        directories.insert(current.clone());
    }
    Ok(())
}

fn validate_shadow_layout(
    root: &Path,
    expected: &BTreeMap<PathBuf, ManifestEntry>,
) -> Result<(), SnapshotStoreError> {
    fn walk(
        root: &Path,
        relative_directory: &Path,
        expected: &BTreeMap<PathBuf, ManifestEntry>,
        found: &mut BTreeSet<PathBuf>,
    ) -> Result<(), SnapshotStoreError> {
        let directory = root.join(relative_directory);
        require_directory(&directory, Some(0o700))?;
        for child in read_children(&directory)? {
            let name = child
                .file_name()
                .into_string()
                .map_err(|_| SnapshotStoreError::UnsafePath(child.path()))?;
            let relative = relative_directory.join(name);
            portable_relative_path(&relative)?;
            let metadata = fs::symlink_metadata(child.path())
                .map_err(|error| io_error("inspect shadow layout", &child.path(), &error))?;
            if metadata.file_type().is_symlink() {
                return Err(SnapshotStoreError::UnsafeEntry {
                    path: relative,
                    kind: UnsafeEntryKind::Symlink,
                });
            }
            if metadata.file_type().is_dir() {
                if !expected.keys().any(|path| path.starts_with(&relative)) {
                    return Err(SnapshotStoreError::UnexpectedLayout(child.path()));
                }
                walk(root, &relative, expected, found)?;
            } else if metadata.file_type().is_file() {
                require_regular_metadata(&child.path(), &metadata)?;
                let entry = expected
                    .get(&relative)
                    .ok_or_else(|| SnapshotStoreError::UnexpectedLayout(child.path()))?;
                require_mode(&child.path(), &metadata, entry.mode())?;
                found.insert(relative);
            } else {
                return Err(SnapshotStoreError::UnsafeEntry {
                    path: relative,
                    kind: UnsafeEntryKind::Special,
                });
            }
        }
        Ok(())
    }

    let mut found = BTreeSet::new();
    walk(root, Path::new(""), expected, &mut found)?;
    if found != expected.keys().cloned().collect() {
        return Err(SnapshotStoreError::UnexpectedLayout(root.to_path_buf()));
    }
    Ok(())
}

fn digest_bytes(bytes: &[u8]) -> Result<Digest, SnapshotStoreError> {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    let output = hasher.finalize();
    let mut text = String::with_capacity(64);
    for byte in output {
        let _ = write!(text, "{byte:02x}");
    }
    Digest::parse(text).map_err(SnapshotStoreError::Contract)
}

fn sync_directory(path: &Path) -> Result<(), SnapshotStoreError> {
    let directory =
        File::open(path).map_err(|error| io_error("open directory for sync", path, &error))?;
    directory
        .sync_all()
        .map_err(|error| io_error("sync directory", path, &error))
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

#[cfg(unix)]
fn require_mode(
    path: &Path,
    metadata: &fs::Metadata,
    expected: u32,
) -> Result<(), SnapshotStoreError> {
    let actual = normalized_mode(metadata);
    if actual != expected {
        return Err(SnapshotStoreError::UnsafeMode {
            path: path.to_path_buf(),
            expected,
            actual,
        });
    }
    Ok(())
}

#[cfg(not(unix))]
fn require_mode(
    _path: &Path,
    _metadata: &fs::Metadata,
    _expected: u32,
) -> Result<(), SnapshotStoreError> {
    Ok(())
}

#[cfg(unix)]
fn set_mode(path: &Path, mode: u32, operation: &'static str) -> Result<(), SnapshotStoreError> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(mode))
        .map_err(|error| io_error(operation, path, &error))
}

#[cfg(not(unix))]
fn set_mode(_path: &Path, _mode: u32, _operation: &'static str) -> Result<(), SnapshotStoreError> {
    Ok(())
}

#[cfg(unix)]
fn set_file_mode(file: &File, path: &Path, mode: u32) -> Result<(), SnapshotStoreError> {
    use std::os::unix::fs::PermissionsExt;
    file.set_permissions(fs::Permissions::from_mode(mode))
        .map_err(|error| io_error("set file permissions", path, &error))
}

#[cfg(not(unix))]
fn set_file_mode(file: &File, path: &Path, mode: u32) -> Result<(), SnapshotStoreError> {
    let mut permissions = file
        .metadata()
        .map_err(|error| io_error("inspect file permissions", path, &error))?
        .permissions();
    permissions.set_readonly(mode & 0o200 == 0);
    file.set_permissions(permissions)
        .map_err(|error| io_error("set file permissions", path, &error))
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

fn io_error(operation: &'static str, path: &Path, error: &io::Error) -> SnapshotStoreError {
    SnapshotStoreError::Io {
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
                "grok-build-snapshot-store-{label}-{}-{number}",
                std::process::id()
            ));
            fs::create_dir_all(&path).unwrap();
            Self(fs::canonicalize(path).unwrap())
        }
    }

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            #[cfg(unix)]
            make_writable_for_test(&self.0);
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn grant(root: &Path) -> IssuedWorkspaceGrant {
        WorkspaceGrantIssuer::issue(WorkspaceGrantRequest {
            grant_id: "snapshot-store-test".into(),
            workspace_root: root.to_path_buf(),
            permissions: WorkspacePermissions::trusted(),
            network: WorkspaceNetworkPolicy::Denied,
            policy_version: 1,
        })
        .unwrap()
    }

    fn setup(
        label: &str,
    ) -> (
        TestDirectory,
        TestDirectory,
        IssuedWorkspaceGrant,
        SnapshotStore,
    ) {
        let workspace = TestDirectory::new(&format!("{label}-workspace"));
        let private = TestDirectory::new(&format!("{label}-private"));
        let grant = grant(&workspace.0);
        let store = SnapshotStore::open(&grant, private.0.join("store")).unwrap();
        (workspace, private, grant, store)
    }

    #[test]
    fn snapshot_survives_store_reopen() {
        let (workspace, private, grant, store) = setup("restart");
        fs::create_dir(workspace.0.join("src")).unwrap();
        fs::write(
            workspace.0.join("src/lib.rs"),
            b"pub fn answer() -> u8 { 42 }\n",
        )
        .unwrap();
        let captured = WorkspaceManifest::capture(&grant, 11).unwrap();
        let stored = store.persist_manifest(&captured).unwrap();
        let snapshot_id = stored.snapshot().snapshot_id.clone();
        drop(store);

        let reopened = SnapshotStore::open(&grant, private.0.join("store")).unwrap();
        let loaded = reopened.load(&snapshot_id).unwrap();

        assert_eq!(loaded.entries(), captured.entries());
        assert_eq!(loaded.snapshot().snapshot_id, snapshot_id);
    }

    #[test]
    fn incomplete_temporary_snapshot_is_cleaned_on_reopen() {
        let (_workspace, private, grant, store) = setup("partial");
        let partial = store.snapshots.join(".tmp-interrupted-writer");
        fs::create_dir(&partial).unwrap();
        fs::write(partial.join("partial"), b"not ready").unwrap();
        drop(store);

        let reopened = SnapshotStore::open(&grant, private.0.join("store")).unwrap();

        assert!(!partial.exists());
        assert!(reopened.root().exists());
    }

    #[cfg(unix)]
    #[test]
    fn promoted_snapshot_with_interrupted_seal_is_recovered() {
        use std::os::unix::fs::PermissionsExt;

        let (workspace, private, grant, store) = setup("promotion-recovery");
        fs::write(workspace.0.join("file"), b"fully durable").unwrap();
        let captured = WorkspaceManifest::capture(&grant, 21).unwrap();
        let snapshot_id = captured.snapshot().snapshot_id.clone();
        store.persist_manifest(&captured).unwrap();
        let snapshot = store.snapshot_directory(&snapshot_id);
        set_mode(&snapshot, 0o700, "simulate interrupted seal").unwrap();
        drop(store);

        let reopened = SnapshotStore::open(&grant, private.0.join("store")).unwrap();

        assert_eq!(
            fs::metadata(&snapshot).unwrap().permissions().mode() & 0o777,
            0o500
        );
        assert_eq!(
            reopened.load(&snapshot_id).unwrap().entries(),
            captured.entries()
        );
    }

    #[test]
    fn corrupt_blob_is_rejected() {
        let (workspace, _private, grant, store) = setup("corrupt");
        fs::write(workspace.0.join("file"), b"trusted bytes").unwrap();
        let captured = WorkspaceManifest::capture(&grant, 12).unwrap();
        let snapshot_id = captured.snapshot().snapshot_id.clone();
        let digest = captured.entry("file").unwrap().digest().clone();
        store.persist_manifest(&captured).unwrap();
        let blob = store
            .snapshot_directory(&snapshot_id)
            .join(BLOBS_DIRECTORY)
            .join(digest.as_str());
        #[cfg(unix)]
        set_mode(&blob, 0o600, "make blob writable for test").unwrap();
        fs::write(&blob, b"corrupt bytes").unwrap();
        #[cfg(unix)]
        set_mode(&blob, 0o400, "reseal corrupt blob for test").unwrap();

        assert!(matches!(
            store.load(&snapshot_id),
            Err(SnapshotStoreError::ContentMismatch { .. })
        ));
    }

    #[cfg(unix)]
    #[test]
    fn symlink_and_external_hardlink_are_rejected() {
        use std::os::unix::fs::symlink;

        let (workspace, private, grant, store) = setup("links");
        fs::write(workspace.0.join("file"), b"bytes").unwrap();
        let captured = WorkspaceManifest::capture(&grant, 13).unwrap();
        let snapshot_id = captured.snapshot().snapshot_id.clone();
        let digest = captured.entry("file").unwrap().digest().clone();
        store.persist_manifest(&captured).unwrap();
        let snapshot = store.snapshot_directory(&snapshot_id);
        let blob = snapshot.join(BLOBS_DIRECTORY).join(digest.as_str());
        fs::hard_link(&blob, private.0.join("external-hardlink")).unwrap();
        assert!(matches!(
            store.load(&snapshot_id),
            Err(SnapshotStoreError::UnsafeEntry {
                kind: UnsafeEntryKind::HardLink,
                ..
            })
        ));
        fs::remove_file(private.0.join("external-hardlink")).unwrap();

        set_mode(&snapshot, 0o700, "unseal snapshot for test").unwrap();
        fs::remove_file(snapshot.join(READY_FILE)).unwrap();
        symlink("MANIFEST", snapshot.join(READY_FILE)).unwrap();
        set_mode(&snapshot, 0o500, "reseal snapshot for test").unwrap();
        assert!(matches!(
            store.load(&snapshot_id),
            Err(SnapshotStoreError::UnsafeEntry {
                kind: UnsafeEntryKind::Symlink,
                ..
            })
        ));
    }

    #[cfg(unix)]
    #[test]
    fn shadow_preserves_original_modes() {
        use std::os::unix::fs::PermissionsExt;

        let (workspace, private, grant, store) = setup("modes");
        let executable = workspace.0.join("run");
        fs::write(&executable, b"#!/bin/sh\nexit 0\n").unwrap();
        fs::set_permissions(&executable, fs::Permissions::from_mode(0o751)).unwrap();
        let captured = WorkspaceManifest::capture(&grant, 14).unwrap();
        let snapshot_id = captured.snapshot().snapshot_id.clone();
        store.persist_manifest(&captured).unwrap();

        let shadow = store
            .create_shadow(&snapshot_id, private.0.join("shadow"))
            .unwrap();
        let mode = fs::metadata(shadow.root().join("run"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;

        assert_eq!(mode, 0o751);
    }

    #[test]
    fn stored_shadow_ignores_later_live_workspace_changes() {
        let (workspace, private, grant, store) = setup("live-change");
        fs::write(workspace.0.join("file"), b"snapshot version").unwrap();
        let captured = WorkspaceManifest::capture(&grant, 15).unwrap();
        let snapshot_id = captured.snapshot().snapshot_id.clone();
        store.persist_manifest(&captured).unwrap();
        fs::write(workspace.0.join("file"), b"later live version").unwrap();
        fs::write(workspace.0.join("new-live-file"), b"must not appear").unwrap();

        let shadow = store
            .create_shadow(&snapshot_id, private.0.join("shadow"))
            .unwrap();

        assert_eq!(
            fs::read(shadow.root().join("file")).unwrap(),
            b"snapshot version"
        );
        assert!(!shadow.root().join("new-live-file").exists());
    }

    #[test]
    fn staged_result_is_durable_before_shadow_cleanup() {
        let (workspace, private, grant, store) = setup("staged");
        fs::write(workspace.0.join("file"), b"before").unwrap();
        let base = WorkspaceManifest::capture(&grant, 16).unwrap();
        store.persist_manifest(&base).unwrap();
        let worker = store
            .create_shadow(&base.snapshot().snapshot_id, private.0.join("worker"))
            .unwrap();
        fs::write(worker.root().join("file"), b"after").unwrap();
        fs::write(worker.root().join("created"), b"durable").unwrap();
        let staged = worker.stage_changes("durable-result", 17).unwrap();
        let result_id = staged.change_set().result_snapshot.clone();
        store.persist_staged_result(&base, &staged, 17).unwrap();
        worker.discard().unwrap();

        let restored = store
            .create_shadow(&result_id, private.0.join("restored"))
            .unwrap();

        assert_eq!(fs::read(restored.root().join("file")).unwrap(), b"after");
        assert_eq!(
            fs::read(restored.root().join("created")).unwrap(),
            b"durable"
        );
    }

    #[test]
    fn repeated_persist_is_idempotent() {
        let (workspace, _private, grant, store) = setup("idempotent");
        fs::write(workspace.0.join("file"), b"same").unwrap();
        let first_capture = WorkspaceManifest::capture(&grant, 18).unwrap();
        let first = store.persist_manifest(&first_capture).unwrap();
        let later_capture = WorkspaceManifest::capture(&grant, 19).unwrap();
        let second = store.persist_manifest(&later_capture).unwrap();

        assert_eq!(first.snapshot().snapshot_id, second.snapshot().snapshot_id);
        assert_eq!(first.snapshot().created_at_unix_ms, 18);
        assert_eq!(second.snapshot().created_at_unix_ms, 18);
    }

    #[cfg(unix)]
    #[test]
    fn existing_invalid_snapshot_identifier_is_never_replaced() {
        let (workspace, _private, grant, store) = setup("collision");
        fs::write(workspace.0.join("file"), b"candidate").unwrap();
        let captured = WorkspaceManifest::capture(&grant, 20).unwrap();
        let target = store.snapshot_directory(&captured.snapshot().snapshot_id);
        fs::create_dir(&target).unwrap();
        fs::write(target.join("foreign"), b"must survive").unwrap();
        set_mode(&target, 0o500, "seal collision fixture").unwrap();

        assert!(matches!(
            store.persist_manifest(&captured),
            Err(SnapshotStoreError::IdentifierCollision { .. })
        ));
        assert_eq!(fs::read(target.join("foreign")).unwrap(), b"must survive");
    }

    #[test]
    fn unsafe_portable_paths_are_rejected() {
        for path in [
            "../escape",
            "dir/../escape",
            ".git/config",
            ".GIT/config",
            "/absolute",
        ] {
            assert!(matches!(
                parse_portable_relative_path(path),
                Err(SnapshotStoreError::UnsafePath(_))
            ));
        }
    }

    #[cfg(unix)]
    #[test]
    fn store_root_symlink_is_rejected() {
        use std::os::unix::fs::symlink;

        let workspace = TestDirectory::new("root-link-workspace");
        let private = TestDirectory::new("root-link-private");
        let grant = grant(&workspace.0);
        let real_store = private.0.join("real-store");
        fs::create_dir(&real_store).unwrap();
        set_mode(&real_store, 0o700, "prepare store target").unwrap();
        let linked_store = private.0.join("linked-store");
        symlink(&real_store, &linked_store).unwrap();

        assert!(matches!(
            SnapshotStore::open(&grant, &linked_store),
            Err(SnapshotStoreError::UnsafeEntry {
                kind: UnsafeEntryKind::Symlink,
                ..
            })
        ));
    }

    #[cfg(unix)]
    fn make_writable_for_test(path: &Path) {
        use std::os::unix::fs::PermissionsExt;
        let Ok(metadata) = fs::symlink_metadata(path) else {
            return;
        };
        if metadata.file_type().is_dir() {
            let _ = fs::set_permissions(path, fs::Permissions::from_mode(0o700));
            if let Ok(children) = fs::read_dir(path) {
                for child in children.flatten() {
                    make_writable_for_test(&child.path());
                }
            }
        } else if metadata.file_type().is_file() {
            let _ = fs::set_permissions(path, fs::Permissions::from_mode(0o600));
        }
    }
}
