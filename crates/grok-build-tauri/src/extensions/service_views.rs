//! Host snapshot ownership survives crashes without reclaiming a live writer's views.
use std::fs::File;
use std::io::{Read as _, Write as _};
use std::os::unix::fs::MetadataExt as _;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use cap_fs_ext::{DirExt as _, OsMetadataExt as _};
use cap_std::fs::Dir;
use rustix::fs::{FlockOperation, Mode, OFlags};

use super::failure;
use crate::owner_state::OwnerStateRoot;

const OWNER: &str = "owner.lock";
const MARKER: &[u8] = b"GB Plus private service views v2\n";
const MAX_LEASES: usize = 16;
static NEXT: AtomicU64 = AtomicU64::new(1);

/// Must be dropped after the two `ServiceSnapshot` fields that use this directory.
pub(crate) struct ServiceViews {
    parent: Dir,
    directory: Dir,
    path: PathBuf,
    name: String,
    writer_root: PathBuf,
    _owner: File,
}

impl ServiceViews {
    pub(crate) fn create(state: &Path, cancelled: &dyn Fn() -> bool) -> Result<Self, String> {
        check_cancelled(cancelled)?;
        let writer_root = state.join("service-views-v2");
        let _writer = writer(&writer_root)?;
        let writer_root = writer_root.canonicalize().map_err(failure)?;
        let parent =
            Dir::open_ambient_dir(&writer_root, cap_std::ambient_authority()).map_err(failure)?;
        private(&parent)?;
        recover(&parent, cancelled)?;
        check_cancelled(cancelled)?;
        let names = names(&parent, MAX_LEASES + 1)?;
        if names.len() > MAX_LEASES {
            return Err("Private service view capacity is occupied by active owners.".into());
        }
        let name = format!(
            "view-{}",
            super::digest(
                format!(
                    "{}:{}:{}",
                    std::process::id(),
                    crate::runtime::types::unix_time_millis(),
                    NEXT.fetch_add(1, Ordering::Relaxed)
                )
                .as_bytes()
            )
        );
        rustix::fs::mkdirat(&parent, name.as_str(), Mode::RWXU).map_err(failure)?;
        let directory = parent.open_dir_nofollow(&name).map_err(failure)?;
        let mut owner = File::from(
            rustix::fs::openat(
                &directory,
                OWNER,
                OFlags::RDWR
                    | OFlags::CREATE
                    | OFlags::EXCL
                    | OFlags::CLOEXEC
                    | OFlags::NOFOLLOW
                    | OFlags::NONBLOCK,
                Mode::RUSR | Mode::WUSR,
            )
            .map_err(failure)?,
        );
        rustix::fs::flock(&owner, FlockOperation::NonBlockingLockExclusive).map_err(failure)?;
        owner.write_all(MARKER).map_err(failure)?;
        owner.sync_all().map_err(failure)?;
        sync(&directory)?;
        sync(&parent)?;
        Ok(Self {
            path: writer_root.join(&name),
            parent,
            directory,
            name,
            writer_root,
            _owner: owner,
        })
    }

    pub(crate) fn path(&self) -> &Path {
        &self.path
    }

    fn finish(&self) -> Result<(), String> {
        let _writer = writer(&self.writer_root)?;
        same(&self.parent, &self.name, &self.directory)?;
        if names(&self.directory, 3)? != [OWNER] {
            return Err(
                "Service snapshots remain; their owner record must remain recoverable.".into(),
            );
        }
        self.directory.remove_file(OWNER).map_err(failure)?;
        self.parent.remove_dir(&self.name).map_err(failure)?;
        sync(&self.parent)
    }
}

impl Drop for ServiceViews {
    fn drop(&mut self) {
        let _ = self.finish();
    }
}

fn writer(root: &Path) -> Result<File, String> {
    let file = OwnerStateRoot::new(root)
        .file("writer.lock", 0)
        .map_err(failure)?
        .open_process_file()
        .map_err(failure)?;
    rustix::fs::flock(&file, FlockOperation::NonBlockingLockExclusive)
        .map_err(|_| "Another service view owner is being updated.")?;
    Ok(file)
}

fn private(directory: &Dir) -> Result<(), String> {
    let metadata = directory.dir_metadata().map_err(failure)?;
    if metadata.uid() != rustix::process::geteuid().as_raw() || metadata.mode() & 0o7777 != 0o700 {
        return Err("Private service views lost their owner-only directory boundary.".into());
    }
    Ok(())
}

fn same(parent: &Dir, name: &str, expected: &Dir) -> Result<(), String> {
    private(parent)?;
    let live = parent.open_dir_nofollow(name).map_err(failure)?;
    private(&live)?;
    let a = live.dir_metadata().map_err(failure)?;
    let b = expected.dir_metadata().map_err(failure)?;
    if (a.dev(), a.ino()) != (b.dev(), b.ino()) {
        return Err("Private service view identity changed.".into());
    }
    Ok(())
}

fn names(directory: &Dir, maximum: usize) -> Result<Vec<String>, String> {
    let mut result = Vec::new();
    for entry in directory.entries().map_err(failure)? {
        if result.len() >= maximum {
            return Err("Private service view inventory exceeded its bound.".into());
        }
        result.push(
            entry
                .map_err(failure)?
                .file_name()
                .into_string()
                .map_err(|_| "Private service view has a non-UTF-8 name.")?,
        );
    }
    result.sort();
    Ok(result)
}

fn recover(parent: &Dir, cancelled: &dyn Fn() -> bool) -> Result<(), String> {
    for name in names(parent, MAX_LEASES + 1)? {
        check_cancelled(cancelled)?;
        if name == "writer.lock" {
            continue;
        }
        if !name.strip_prefix("view-").is_some_and(super::valid_digest) {
            return Err("Unknown private service view format remains recoverable.".into());
        }
        let directory = parent.open_dir_nofollow(&name).map_err(failure)?;
        same(parent, &name, &directory)?;
        let entries = names(&directory, 3)?;
        let descriptor = match rustix::fs::openat(
            &directory,
            OWNER,
            OFlags::RDWR | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK,
            Mode::empty(),
        ) {
            Ok(file) => file,
            Err(rustix::io::Errno::NOENT) if entries.is_empty() => {
                // The global writer lock excludes a live constructor before owner publication.
                parent.remove_dir(&name).map_err(failure)?;
                continue;
            }
            Err(error) => return Err(failure(error)),
        };
        let mut owner = File::from(descriptor);
        let metadata = owner.metadata().map_err(failure)?;
        if !metadata.is_file()
            || metadata.uid() != rustix::process::geteuid().as_raw()
            || metadata.mode() & 0o7777 != 0o600
            || metadata.nlink() != 1
            || metadata.len() > MARKER.len() as u64
        {
            return Err("Private service view owner file was refused.".into());
        }
        match rustix::fs::flock(&owner, FlockOperation::NonBlockingLockExclusive) {
            Ok(()) => {}
            Err(rustix::io::Errno::WOULDBLOCK) => continue,
            Err(error) => return Err(failure(error)),
        }
        let mut marker = Vec::new();
        std::io::Read::by_ref(&mut owner)
            .take(MARKER.len() as u64 + 1)
            .read_to_end(&mut marker)
            .map_err(failure)?;
        if marker != MARKER && !(entries == [OWNER] && MARKER.starts_with(&marker)) {
            return Err(
                "Unknown or incomplete private service view owner remains recoverable.".into(),
            );
        }
        if entries
            .iter()
            .any(|entry| ![OWNER, "workspace", "extension"].contains(&entry.as_str()))
        {
            return Err("Private service view contains unknown recovery data.".into());
        }
        let mut budget = 40_000_usize;
        for child in ["workspace", "extension"] {
            if entries.iter().any(|entry| entry == child) {
                let tree = directory.open_dir_nofollow(child).map_err(failure)?;
                validate_tree(&tree, 0, &mut budget, cancelled)?;
            }
        }
        check_cancelled(cancelled)?;
        same(parent, &name, &directory)?;
        // cap-std removes within this held private tree; it never follows an ambient source path.
        for child in ["workspace", "extension"] {
            if entries.iter().any(|entry| entry == child) {
                directory.remove_dir_all(child).map_err(failure)?;
            }
        }
        directory.remove_file(OWNER).map_err(failure)?;
        parent.remove_dir(&name).map_err(failure)?;
    }
    sync(parent)
}

fn validate_tree(
    directory: &Dir,
    depth: usize,
    remaining: &mut usize,
    cancelled: &dyn Fn() -> bool,
) -> Result<(), String> {
    check_cancelled(cancelled)?;
    private(directory)?;
    if depth > 33 {
        return Err("Private service view recovery depth exceeded.".into());
    }
    let device = directory.dir_metadata().map_err(failure)?.dev();
    for name in names(directory, 16_384)? {
        check_cancelled(cancelled)?;
        *remaining = remaining
            .checked_sub(1)
            .ok_or("Private service view recovery count exceeded.")?;
        let metadata = directory.symlink_metadata(&name).map_err(failure)?;
        if metadata.uid() != rustix::process::geteuid().as_raw() || metadata.dev() != device {
            return Err("Private service view owner or filesystem changed.".into());
        }
        if metadata.is_dir() {
            validate_tree(
                &directory.open_dir_nofollow(name).map_err(failure)?,
                depth + 1,
                remaining,
                cancelled,
            )?;
        } else if !metadata.is_file()
            || metadata.nlink() != 1
            || ![0o400, 0o500, 0o600, 0o700].contains(&(metadata.mode() & 0o7777))
        {
            return Err("Private service view recovery refuses links and special files.".into());
        }
    }
    Ok(())
}

fn check_cancelled(cancelled: &dyn Fn() -> bool) -> Result<(), String> {
    if cancelled() {
        Err("Private service view recovery was cancelled.".into())
    } else {
        Ok(())
    }
}

fn sync(directory: &Dir) -> Result<(), String> {
    directory
        .try_clone()
        .map_err(failure)?
        .into_std_file()
        .sync_all()
        .map_err(failure)
}

#[cfg(test)]
mod tests;
