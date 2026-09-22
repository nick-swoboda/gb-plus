//! Private captured views for service admission. Capture never launches an image.

use std::io::Write as _;
use std::path::{Path, PathBuf};

use cap_fs_ext::{DirExt as _, OpenOptionsFollowExt as _, OsMetadataExt as _};
use cap_std::fs::{Dir, OpenOptions};
use grok_build_core::Digest;

use crate::service_tree::{identity, read_file, service_path_component_allowed};

mod git_import;
mod inventory;
mod transfer;
mod workspace;
mod worktree;
pub use inventory::ServiceSnapshotFile;
pub use transfer::{
    MAX_SERVICE_VIEW_FRAME_BYTES, ServiceSnapshotFrame, ServiceSnapshotOperation,
    ServiceSnapshotReceiver,
};

/// How unavailable conventional credential and repository-administration paths
/// are handled when the app captures a private view.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ServiceSnapshotPolicy {
    /// Exclude those paths and expose their names in the bounded capture report.
    Workspace,
    /// An immutable extension must match its complete admitted inventory.
    Extension,
}

/// A bounded, owner-private copy of selected source bytes, including uncommitted
/// edits. The original directory is never mounted by this object. A snapshot is
/// not a permission grant; the launch request still binds and revalidates its digest.
pub struct ServiceSnapshot {
    storage: PrivateDirectory,
    digest: Digest,
    exclusions: Vec<String>,
    files: usize,
    bytes: u64,
}

impl ServiceSnapshot {
    /// Capture into a fresh app-issued child of an existing owner-only directory.
    /// Source and parent must be canonical absolute paths. Cancellation is checked
    /// between bounded filesystem operations. No script, filter or manager runs.
    ///
    /// # Errors
    /// Refuses aliases, special files, oversized or changing views, unsafe parent
    /// permissions, an existing destination, or cancellation. Partial copies are
    /// removed through the retained destination parent, never through source paths.
    pub fn capture(
        source: &Path,
        private_parent: &Path,
        name: &str,
        policy: ServiceSnapshotPolicy,
        cancelled: &dyn Fn() -> bool,
    ) -> Result<Self, String> {
        Self::capture_inner(source, private_parent, name, policy, None, cancelled)
    }

    /// Capture the app's bounded working-file view, excluding generated trees and
    /// exact app-resolved authentication/state paths before reading their bytes.
    /// Protected paths are host authority inputs, never server or model arguments.
    /// This does not detect arbitrary credentials embedded in project source.
    ///
    /// # Errors
    /// Refuses invalid protection paths, a protected source root, or any ordinary
    /// snapshot failure. Excluded directories are not traversed.
    pub fn capture_workspace(
        source: &Path,
        private_parent: &Path,
        name: &str,
        protected_paths: &[PathBuf],
        cancelled: &dyn Fn() -> bool,
    ) -> Result<Self, String> {
        let filter = workspace::Filter::new(source, protected_paths)?;
        Self::capture_inner(
            source,
            private_parent,
            name,
            ServiceSnapshotPolicy::Workspace,
            Some(&filter),
            cancelled,
        )
    }

    fn capture_inner(
        source: &Path,
        private_parent: &Path,
        name: &str,
        policy: ServiceSnapshotPolicy,
        filter: Option<&workspace::Filter>,
        cancelled: &dyn Fn() -> bool,
    ) -> Result<Self, String> {
        let source_directory = canonical_directory(source)?;
        if private_parent.starts_with(source) {
            return Err("Service snapshot storage cannot be inside its source.".into());
        }
        let storage = PrivateDirectory::create(private_parent, name)?;
        let mut capture = Capture {
            policy,
            filter,
            cancelled,
            exclusions: Vec::new(),
            exclusion_bytes: 0,
            entries: 0,
            path_bytes: 0,
            files: 0,
            bytes: 0,
            observed: Vec::new(),
        };
        capture.walk(&source_directory, &storage.directory, "")?;
        // Revalidate all included objects after the last copy. The captured bytes
        // define the view; concurrent source edits must not silently alter it.
        for (relative, expected) in &capture.observed {
            capture.check_cancelled()?;
            let live = if relative.is_empty() {
                source_directory.dir_metadata()
            } else {
                source_directory.symlink_metadata(relative)
            }
            .map_err(failure)?;
            if identity(&live) != identity(expected) {
                return Err("Service source changed while its snapshot was captured.".into());
            }
        }
        if identity(
            &canonical_directory(source)?
                .dir_metadata()
                .map_err(failure)?,
        ) != identity(&source_directory.dir_metadata().map_err(failure)?)
        {
            return Err("Service source directory was replaced during capture.".into());
        }
        capture.check_cancelled()?;
        let digest = crate::service_tree::digest_held(&storage.directory)?;
        storage.revalidate()?;
        Ok(Self {
            storage,
            digest,
            exclusions: capture.exclusions,
            files: capture.files,
            bytes: capture.bytes,
        })
    }

    /// Path to the private captured copy. Revalidate before consuming its bytes.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.storage.path
    }

    /// Exact content and executable-bit commitment, independent of original paths.
    #[must_use]
    pub fn digest(&self) -> &Digest {
        &self.digest
    }

    /// Paths deliberately omitted by Workspace policy, without their contents.
    #[must_use]
    pub fn exclusions(&self) -> &[String] {
        &self.exclusions
    }

    /// Number of regular files and total captured file bytes.
    #[must_use]
    pub fn size(&self) -> (usize, u64) {
        (self.files, self.bytes)
    }

    /// Check the exact native guest executable inside this captured extension.
    /// This checks image identity and compatibility, not permission to execute it.
    ///
    /// # Errors
    /// Refuses foreign images, changed bytes, non-executable files and unsafe paths.
    pub fn verify_image(
        &self,
        relative: &Path,
        expected_bytes: u64,
        expected: &Digest,
        architecture: crate::service_contract::ServiceArchitecture,
    ) -> Result<(), String> {
        self.revalidate()?;
        let text = relative
            .to_str()
            .ok_or("Service executable path is not UTF-8.")?;
        if relative.is_absolute()
            || text.len() > 4096
            || text.split('/').count() > 33
            || text
                .split('/')
                .any(|component| !service_path_component_allowed(component))
        {
            return Err("Service executable must be inside its captured extension.".into());
        }
        let mut components = text.split('/').collect::<Vec<_>>();
        let name = components
            .pop()
            .ok_or("Service executable has no file name.")?;
        let mut directory = self.storage.directory.try_clone().map_err(failure)?;
        for component in components {
            directory = directory.open_dir_nofollow(component).map_err(failure)?;
        }
        let metadata = directory.symlink_metadata(name).map_err(failure)?;
        if metadata.len() != expected_bytes || metadata.mode() & 0o111 == 0 {
            return Err(
                "Service executable size or executable status differs from admission.".into(),
            );
        }
        let bytes = read_file(&directory, name, &metadata)?;
        if Digest::sha256(&bytes) != *expected
            || crate::service_contract::service_elf_architecture(&bytes)? != architecture
        {
            return Err(
                "Service executable identity or guest architecture differs from admission.".into(),
            );
        }
        Ok(())
    }

    /// Rehash the held view and verify that the named destination is still ours.
    ///
    /// # Errors
    /// Refuses any replacement or change to captured bytes or executable status.
    pub fn revalidate(&self) -> Result<(), String> {
        self.storage.revalidate()?;
        if crate::service_tree::digest_held(&self.storage.directory)? != self.digest {
            return Err("Private service snapshot differs from its admission.".into());
        }
        self.storage.revalidate()
    }

    /// Remove this copy while preserving the original workspace and installed content.
    ///
    /// # Errors
    /// Refuses cleanup through a replaced destination name or after an I/O failure.
    pub fn remove(mut self) -> Result<(), String> {
        self.storage.remove()
    }
}

fn failure(error: impl std::fmt::Display) -> String {
    error.to_string()
}

fn canonical_directory(path: &Path) -> Result<Dir, String> {
    if !path.is_absolute() || path.canonicalize().map_err(failure)? != path {
        return Err("Service snapshot paths must be absolute canonical directories.".into());
    }
    Dir::open_ambient_dir(path, cap_std::ambient_authority()).map_err(failure)
}

struct PrivateDirectory {
    parent: Dir,
    directory: Dir,
    path: PathBuf,
    name: String,
    removed: bool,
}

impl PrivateDirectory {
    fn create(parent_path: &Path, name: &str) -> Result<Self, String> {
        if name.is_empty()
            || name.len() > 128
            || !name
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"-_".contains(&byte))
        {
            return Err("Service snapshot requires an app-issued single-component name.".into());
        }
        let parent = canonical_directory(parent_path)?;
        let metadata = parent.dir_metadata().map_err(failure)?;
        if metadata.uid() != rustix::process::geteuid().as_raw()
            || metadata.mode() & 0o7777 != 0o700
        {
            return Err(
                "Service snapshot storage must be owned by the app user with mode 0700.".into(),
            );
        }
        rustix::fs::mkdirat(&parent, name, rustix::fs::Mode::RWXU).map_err(failure)?;
        let directory = parent.open_dir_nofollow(name).map_err(failure)?;
        let storage = Self {
            parent,
            directory,
            path: parent_path.join(name),
            name: name.into(),
            removed: false,
        };
        crate::durable_directory::sync_directory_entries(&storage.parent).map_err(failure)?;
        Ok(storage)
    }

    fn revalidate(&self) -> Result<(), String> {
        let parent = self.parent.dir_metadata().map_err(failure)?;
        if parent.uid() != rustix::process::geteuid().as_raw() || parent.mode() & 0o7777 != 0o700 {
            return Err("Private service snapshot parent lost its owner-only boundary.".into());
        }
        let named = self.parent.open_dir_nofollow(&self.name).map_err(failure)?;
        let expected = self.directory.dir_metadata().map_err(failure)?;
        let live = named.dir_metadata().map_err(failure)?;
        let absolute = canonical_directory(&self.path)?
            .dir_metadata()
            .map_err(failure)?;
        if self.removed
            || (live.dev(), live.ino()) != (expected.dev(), expected.ino())
            || (absolute.dev(), absolute.ino()) != (expected.dev(), expected.ino())
        {
            return Err("Private service snapshot directory was replaced.".into());
        }
        Ok(())
    }

    fn remove(&mut self) -> Result<(), String> {
        if self.removed {
            return Ok(());
        }
        self.revalidate()?;
        self.parent.remove_dir_all(&self.name).map_err(failure)?;
        self.removed = true;
        crate::durable_directory::sync_directory_entries(&self.parent).map_err(failure)
    }
}

impl Drop for PrivateDirectory {
    fn drop(&mut self) {
        let _ = self.remove();
    }
}

struct Capture<'a> {
    policy: ServiceSnapshotPolicy,
    filter: Option<&'a workspace::Filter>,
    cancelled: &'a dyn Fn() -> bool,
    exclusions: Vec<String>,
    exclusion_bytes: usize,
    entries: usize,
    path_bytes: usize,
    files: usize,
    bytes: u64,
    observed: Vec<(String, cap_std::fs::Metadata)>,
}

impl Capture<'_> {
    fn check_cancelled(&self) -> Result<(), String> {
        if (self.cancelled)() {
            Err("Service snapshot capture was cancelled.".into())
        } else {
            Ok(())
        }
    }

    fn walk(&mut self, source: &Dir, target: &Dir, prefix: &str) -> Result<(), String> {
        self.check_cancelled()?;
        let before = source.dir_metadata().map_err(failure)?;
        if prefix.len() > 4096 || prefix.matches('/').count() > 32 {
            return Err("Service snapshot path bound exceeded.".into());
        }
        self.observed
            .push((prefix.trim_end_matches('/').into(), before.clone()));
        let mut names = Vec::new();
        for entry in source.entries().map_err(failure)? {
            self.check_cancelled()?;
            self.entries += 1;
            if self.entries > 16_384 {
                return Err("Service snapshot entry limit exceeded.".into());
            }
            names.push(
                entry
                    .map_err(failure)?
                    .file_name()
                    .into_string()
                    .map_err(|_| "Service snapshot contains a non-UTF-8 path.")?,
            );
        }
        names.sort();
        for name in names {
            self.check_cancelled()?;
            let relative = format!("{prefix}{name}");
            self.path_bytes = self.path_bytes.saturating_add(relative.len());
            if relative.len() > 4096 || self.path_bytes > 4 * 1024 * 1024 {
                return Err("Service snapshot path bound exceeded.".into());
            }
            if !service_path_component_allowed(&name)
                || self
                    .filter
                    .is_some_and(|filter| filter.excludes_path(&relative))
            {
                self.exclude(relative)?;
                continue;
            }
            let metadata = source.symlink_metadata(&name).map_err(failure)?;
            if self
                .filter
                .is_some_and(|filter| filter.excludes_object(&metadata))
            {
                self.exclude(relative)?;
                continue;
            }
            if metadata.is_dir() {
                let child = source.open_dir_nofollow(&name).map_err(failure)?;
                if identity(&child.dir_metadata().map_err(failure)?) != identity(&metadata) {
                    return Err("Service source directory changed before traversal.".into());
                }
                rustix::fs::mkdirat(target, &name, rustix::fs::Mode::RWXU).map_err(failure)?;
                self.walk(
                    &child,
                    &target.open_dir_nofollow(&name).map_err(failure)?,
                    &format!("{relative}/"),
                )?;
            } else if metadata.is_file() {
                self.copy_file(source, target, &name, &metadata)?;
                self.observed.push((relative, metadata));
            } else {
                return Err(
                    "Service snapshot refuses symlinks, sockets, devices and special files.".into(),
                );
            }
        }
        if identity(&source.dir_metadata().map_err(failure)?) != identity(&before) {
            return Err("Service source directory changed during traversal.".into());
        }
        crate::durable_directory::sync_directory_entries(target).map_err(failure)
    }

    fn exclude(&mut self, relative: String) -> Result<(), String> {
        if self.policy == ServiceSnapshotPolicy::Extension {
            return Err(
                "Extension content contains a path unavailable to contained services.".into(),
            );
        }
        self.exclusion_bytes = self.exclusion_bytes.saturating_add(relative.len());
        if self.exclusions.len() >= 256
            || self.exclusion_bytes > 16 * 1024
            || relative.chars().any(char::is_control)
        {
            return Err("Service snapshot exclusion report exceeded its bounds or contains an invalid name.".into());
        }
        self.exclusions.push(relative);
        Ok(())
    }

    fn copy_file(
        &mut self,
        source: &Dir,
        target: &Dir,
        name: &str,
        metadata: &cap_std::fs::Metadata,
    ) -> Result<(), String> {
        self.bytes = self
            .bytes
            .checked_add(metadata.len())
            .ok_or("Service snapshot size overflow.")?;
        if self.bytes > 256 * 1024 * 1024 {
            return Err("Service snapshot byte limit exceeded.".into());
        }
        let bytes = read_file(source, name, metadata)?;
        self.check_cancelled()?;
        write_captured_file(
            target,
            name,
            &bytes,
            metadata.mode() & 0o111 != 0,
            self.cancelled,
        )?;
        self.files += 1;
        Ok(())
    }
}

fn write_captured_file(
    target: &Dir,
    name: &str,
    bytes: &[u8],
    executable: bool,
    cancelled: &dyn Fn() -> bool,
) -> Result<(), String> {
    let mut file = target
        .open_with(
            name,
            OpenOptions::new()
                .write(true)
                .create_new(true)
                .follow(cap_fs_ext::FollowSymlinks::No),
        )
        .map_err(failure)?;
    rustix::fs::fchmod(&file, rustix::fs::Mode::RUSR | rustix::fs::Mode::WUSR).map_err(failure)?;
    for chunk in bytes.chunks(64 * 1024) {
        if cancelled() {
            return Err("Service snapshot creation was cancelled.".into());
        }
        file.write_all(chunk).map_err(failure)?;
    }
    let mode = if executable {
        rustix::fs::Mode::RUSR | rustix::fs::Mode::XUSR
    } else {
        rustix::fs::Mode::RUSR
    };
    rustix::fs::fchmod(&file, mode).map_err(failure)?;
    file.sync_all().map_err(failure)
}

#[cfg(test)]
mod tests;
