//! A root-owned resource ceiling shared by every service helper generation.

use std::os::fd::AsRawFd as _;
use std::path::Path;

use cap_fs_ext::{DirExt as _, OsMetadataExt as _};
use cap_std::fs::Dir;

use super::{domain, failure};

pub(super) fn identity(service_parent: &Dir) -> Result<(u64, u64), String> {
    let generation = std::fs::read_link(format!("/proc/self/fd/{}", service_parent.as_raw_fd()))
        .map_err(failure)?;
    if !generation.is_absolute() || generation.canonicalize().map_err(failure)? != generation {
        return Err("Service generation has no stable canonical cgroup path.".into());
    }
    let root = generation
        .parent()
        .ok_or("Service generation has no resource pool.")?;
    if root.file_name() != Some(std::ffi::OsStr::new("stdio-releases")) {
        return Err("Service generation is outside the admitted shared resource pool.".into());
    }
    let pool = Dir::open_ambient_dir(root, cap_std::ambient_authority()).map_err(failure)?;
    let metadata = pool.dir_metadata().map_err(failure)?;
    if metadata.uid() != 0
        || metadata.mode() & 0o7777 != 0o755
        || u64::try_from(rustix::fs::fstatfs(&pool).map_err(failure)?.f_type).map_err(failure)?
            != crate::linux_containment::CGROUP2_SUPER_MAGIC
    {
        return Err("Service resource pool is not a protected cgroup-v2 directory.".into());
    }
    let named = pool
        .open_dir_nofollow(
            generation
                .file_name()
                .ok_or("Missing service generation name.")?,
        )
        .map_err(failure)?;
    let named_metadata = named.dir_metadata().map_err(failure)?;
    let expected = service_parent.dir_metadata().map_err(failure)?;
    if (named_metadata.dev(), named_metadata.ino()) != (expected.dev(), expected.ino()) {
        return Err("Resource pool does not contain the retained service generation.".into());
    }
    for (name, value) in [
        ("memory.max", "1073741824"),
        ("memory.swap.max", "0"),
        ("pids.max", "128"),
    ] {
        let control = pool.symlink_metadata(Path::new(name)).map_err(failure)?;
        if !control.is_file()
            || control.uid() != 0
            || control.mode() & 0o022 != 0
            || domain::read_control(&pool, name, 128)?.trim() != value
        {
            return Err("Service shared resource limit is missing, writable or changed.".into());
        }
    }
    if domain::read_control(&pool, "cgroup.type", 128)?.trim() != "domain"
        || !domain::read_control(&pool, "cgroup.procs", 4096)?
            .trim()
            .is_empty()
    {
        return Err("Service resource pool must remain a process-free parent domain.".into());
    }
    Ok((metadata.dev(), metadata.ino()))
}
