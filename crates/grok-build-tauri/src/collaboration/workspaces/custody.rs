//! Private family storage has descriptor-bound cleanup and an exclusive owner lock.
use crate::owner_state::OwnerStateRoot;
use cap_fs_ext::{DirExt as _, OsMetadataExt as _};
use cap_std::fs::Dir;
use rustix::fs::{FlockOperation, Mode, OFlags};
use std::fs::File;
use std::io::{Read as _, Write as _};
use std::path::{Path, PathBuf};

const MARKER: &[u8] = b"GB Plus child workspace v1\n";
pub(super) struct FamilyDirectory {
    parent: Dir,
    directory: Dir,
    path: PathBuf,
    name: String,
    _owner: File,
}

impl FamilyDirectory {
    pub(super) fn create(state: &Path, family: &str) -> Result<Self, String> {
        let root = state.join("child-workspaces-v1");
        let writer = OwnerStateRoot::new(&root)
            .file("writer.lock", 0)
            .map_err(failure)?
            .open_process_file()
            .map_err(failure)?;
        rustix::fs::flock(&writer, FlockOperation::NonBlockingLockExclusive).map_err(failure)?;
        let root = root.canonicalize().map_err(failure)?;
        let parent = Dir::open_ambient_dir(&root, cap_std::ambient_authority()).map_err(failure)?;
        private(&parent)?;
        recover(&parent)?;
        let name = format!(
            "family-{}",
            grok_build_plus_host::worktree_recovery_digest(family.as_bytes())
        );
        rustix::fs::mkdirat(&parent, name.as_str(), Mode::RWXU)
            .map_err(|_| "Family workspace already exists or cannot be created.")?;
        let directory = parent.open_dir_nofollow(&name).map_err(failure)?;
        let mut owner = File::from(
            rustix::fs::openat(
                &directory,
                "owner.lock",
                OFlags::RDWR | OFlags::CREATE | OFlags::EXCL | OFlags::CLOEXEC | OFlags::NOFOLLOW,
                Mode::RUSR | Mode::WUSR,
            )
            .map_err(failure)?,
        );
        rustix::fs::flock(&owner, FlockOperation::NonBlockingLockExclusive).map_err(failure)?;
        owner.write_all(MARKER).map_err(failure)?;
        owner.sync_all().map_err(failure)?;
        Ok(Self {
            path: root.join(&name),
            parent,
            directory,
            name,
            _owner: owner,
        })
    }

    pub(super) fn path(&self) -> &Path {
        &self.path
    }
    pub(super) fn mkdir(&self, name: &str) -> Result<(), String> {
        self.revalidate()?;
        rustix::fs::mkdirat(&self.directory, name, Mode::RWXU).map_err(failure)
    }
    pub(super) fn revalidate(&self) -> Result<(), String> {
        same(&self.parent, &self.name, &self.directory)
    }
}

impl Drop for FamilyDirectory {
    fn drop(&mut self) {
        // The helper reaper retains an Arc until group cleanup. A held descriptor
        // confines removal even if an ambient name is replaced concurrently.
        let result = self
            .revalidate()
            .and_then(|()| validate_tree(&self.directory, 0, &mut 600_000))
            .and_then(|()| self.parent.remove_dir_all(&self.name).map_err(failure));
        // A failed validation leaves the owner marker for explicit recovery.
        let _ = result;
    }
}

fn same(parent: &Dir, name: &str, expected: &Dir) -> Result<(), String> {
    private(parent)?;
    let live = parent.open_dir_nofollow(name).map_err(failure)?;
    private(&live)?;
    let a = live.dir_metadata().map_err(failure)?;
    let b = expected.dir_metadata().map_err(failure)?;
    if (a.dev(), a.ino()) != (b.dev(), b.ino()) {
        return Err("Family workspace identity changed.".into());
    }
    Ok(())
}
fn private(directory: &Dir) -> Result<(), String> {
    let metadata = directory.dir_metadata().map_err(failure)?;
    if metadata.uid() != rustix::process::geteuid().as_raw() || metadata.mode() & 0o7777 != 0o700 {
        return Err("Family storage lost its private owner boundary.".into());
    }
    Ok(())
}
fn names(directory: &Dir, maximum: usize) -> Result<Vec<String>, String> {
    let mut names = Vec::new();
    for entry in directory.entries().map_err(failure)? {
        if names.len() >= maximum {
            return Err("Family storage inventory exceeded its bound.".into());
        }
        names.push(
            entry
                .map_err(failure)?
                .file_name()
                .into_string()
                .map_err(|_| "Family storage contains a non-UTF-8 name.")?,
        );
    }
    Ok(names)
}
fn validate_tree(directory: &Dir, depth: usize, left: &mut usize) -> Result<(), String> {
    if depth > 64 {
        return Err("Family cleanup depth exceeded.".into());
    }
    let directory_metadata = directory.dir_metadata().map_err(failure)?;
    if directory_metadata.uid() != rustix::process::geteuid().as_raw()
        || directory_metadata.mode() & 0o022 != 0
    {
        return Err("Family cleanup owner or permissions changed.".into());
    }
    for name in names(directory, 20_000)? {
        *left = left
            .checked_sub(1)
            .ok_or("Family cleanup inventory exceeded.")?;
        let metadata = directory.symlink_metadata(&name).map_err(failure)?;
        if metadata.uid() != directory_metadata.uid()
            || metadata.dev() != directory_metadata.dev()
            || metadata.mode() & 0o022 != 0
        {
            return Err("Family cleanup crossed an owner, mount or write boundary.".into());
        }
        if metadata.is_dir() {
            validate_tree(
                &directory.open_dir_nofollow(&name).map_err(failure)?,
                depth + 1,
                left,
            )?;
        } else if !metadata.is_file() || metadata.nlink() != 1 {
            return Err("Family cleanup refuses links and special files.".into());
        }
    }
    Ok(())
}
fn recover(parent: &Dir) -> Result<(), String> {
    for name in names(parent, 17)? {
        if name == "writer.lock" {
            continue;
        }
        if !name
            .strip_prefix("family-")
            .is_some_and(crate::extensions::valid_digest)
        {
            return Err("Unknown child workspace data remains recoverable.".into());
        }
        let directory = parent.open_dir_nofollow(&name).map_err(failure)?;
        same(parent, &name, &directory)?;
        let owner = rustix::fs::openat(
            &directory,
            "owner.lock",
            OFlags::RDWR | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK,
            Mode::empty(),
        )
        .map_err(failure)?;
        match rustix::fs::flock(&owner, FlockOperation::NonBlockingLockExclusive) {
            Ok(()) => {}
            Err(rustix::io::Errno::WOULDBLOCK) => continue,
            Err(error) => return Err(failure(error)),
        }
        let mut owner = File::from(owner);
        let mut marker = Vec::new();
        std::io::Read::by_ref(&mut owner)
            .take(MARKER.len() as u64 + 1)
            .read_to_end(&mut marker)
            .map_err(failure)?;
        if marker != MARKER {
            return Err("Incomplete child workspace marker remains recoverable.".into());
        }
        validate_tree(&directory, 0, &mut 600_000)?;
        same(parent, &name, &directory)?;
        parent.remove_dir_all(&name).map_err(failure)?;
    }
    Ok(())
}
fn failure(error: impl std::fmt::Display) -> String {
    error.to_string()
}
