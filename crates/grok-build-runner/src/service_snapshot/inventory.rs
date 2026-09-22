//! Materialize already-verified immutable capsule bytes without archive programs.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use cap_fs_ext::DirExt as _;

use super::{PrivateDirectory, ServiceSnapshot, failure, write_captured_file};

/// One exact content-inventory entry. The caller separately admits its source.
pub struct ServiceSnapshotFile<'a> {
    /// Bounded relative file path; no directory/link entries or substitutions.
    pub path: &'a str,
    /// Exact bytes already checked against the immutable installation inventory.
    pub bytes: &'a [u8],
    /// Executable status from that same inventory, never inferred from a suffix.
    pub executable: bool,
}

impl ServiceSnapshot {
    /// Copy immutable inventory bytes into one private service view. No file from
    /// the original installation is opened and no installation script is run.
    ///
    /// # Errors
    /// Refuses duplicate/ambiguous/unsafe paths, credential names, oversized views,
    /// changed destination identity or cancellation; incomplete views are removed.
    pub fn from_files(
        files: &[ServiceSnapshotFile<'_>],
        private_parent: &Path,
        name: &str,
        cancelled: &dyn Fn() -> bool,
    ) -> Result<Self, String> {
        if files.len() > 16_384 {
            return Err("Service inventory file bound exceeded.".into());
        }
        let mut names = BTreeSet::new();
        let mut directories = BTreeMap::new();
        let mut bytes = 0_u64;
        let mut paths = 0_usize;
        for file in files {
            if cancelled() {
                return Err("Service inventory creation cancelled.".into());
            }
            if !file.path.is_ascii()
                || file.path.len() > 4096
                || file.path.split('/').count() > 33
                || file
                    .path
                    .split('/')
                    .any(|part| !crate::service_path_component_allowed(part))
                || !names.insert(file.path.to_ascii_lowercase())
                || file.bytes.len() > 128 * 1024 * 1024
            {
                return Err(
                    "Service inventory contains an unsafe, duplicate or oversized file.".into(),
                );
            }
            bytes = bytes
                .checked_add(file.bytes.len() as u64)
                .ok_or("Service inventory byte overflow.")?;
            paths = paths.saturating_add(file.path.len());
            if bytes > 256 * 1024 * 1024 || paths > 4 * 1024 * 1024 {
                return Err("Service inventory aggregate bound exceeded.".into());
            }
            let mut parent = Path::new(file.path).parent();
            while let Some(path) = parent.filter(|path| !path.as_os_str().is_empty()) {
                let spelling = path.to_string_lossy().into_owned();
                if directories
                    .insert(spelling.to_ascii_lowercase(), spelling.clone())
                    .is_some_and(|previous| previous != spelling)
                {
                    return Err("Service inventory contains ambiguous directory spelling.".into());
                }
                parent = path.parent();
            }
            if directories.len() + files.len() > 16_384 {
                return Err("Service inventory entry bound exceeded.".into());
            }
        }
        if directories.keys().any(|path| names.contains(path)) {
            return Err("Service inventory file and directory paths overlap.".into());
        }
        let storage = PrivateDirectory::create(private_parent, name)?;
        for file in files {
            if cancelled() {
                return Err("Service inventory creation cancelled.".into());
            }
            let mut parts = file.path.split('/').collect::<Vec<_>>();
            let basename = parts.pop().ok_or("Service inventory file has no name.")?;
            let mut directory = storage.directory.try_clone().map_err(failure)?;
            for component in parts {
                match rustix::fs::mkdirat(&directory, component, rustix::fs::Mode::RWXU) {
                    Ok(()) => crate::durable_directory::sync_directory_entries(&directory)
                        .map_err(failure)?,
                    Err(rustix::io::Errno::EXIST) => {}
                    Err(error) => return Err(failure(error)),
                }
                directory = directory.open_dir_nofollow(component).map_err(failure)?;
            }
            write_captured_file(&directory, basename, file.bytes, file.executable, cancelled)?;
            crate::durable_directory::sync_directory_entries(&directory).map_err(failure)?;
        }
        if cancelled() {
            return Err("Service inventory creation cancelled.".into());
        }
        let digest = crate::service_tree::digest_held(&storage.directory)?;
        storage.revalidate()?;
        Ok(Self {
            storage,
            digest,
            exclusions: Vec::new(),
            files: files.len(),
            bytes,
        })
    }
}
