//! Capability-relative storage for small owner-only application records.

use std::fmt;
use std::fs::{self, File};
use std::io::{Read as _, Write as _};
use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use rustix::fs::{AtFlags, Mode, OFlags, open, openat, renameat, unlinkat};

static NEXT_TEMPORARY: AtomicU64 = AtomicU64::new(1);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum OwnerStateErrorKind {
    Policy,
    Root,
    Open,
    Type,
    Owner,
    Oversized,
    Read,
    Temporary,
    Write,
    Sync,
    Publish,
}

#[derive(Debug)]
pub(crate) struct OwnerStateError {
    pub(crate) kind: OwnerStateErrorKind,
    detail: String,
}

impl fmt::Display for OwnerStateError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.detail)
    }
}

fn failure(kind: OwnerStateErrorKind, detail: impl Into<String>) -> OwnerStateError {
    OwnerStateError {
        kind,
        detail: detail.into(),
    }
}

fn system_failure(
    kind: OwnerStateErrorKind,
    action: &str,
    error: impl fmt::Display,
) -> OwnerStateError {
    failure(kind, format!("{action}: {error}"))
}

#[derive(Clone, Debug)]
pub(crate) struct OwnerStateRoot(PathBuf);

impl OwnerStateRoot {
    pub(crate) fn new(path: impl Into<PathBuf>) -> Self {
        Self(path.into())
    }

    pub(crate) fn file(
        &self,
        name: impl Into<String>,
        max_bytes: u64,
    ) -> Result<OwnerStateFile, OwnerStateError> {
        let name = name.into();
        let path = Path::new(&name);
        if path.components().count() != 1
            || !matches!(path.components().next(), Some(Component::Normal(_)))
        {
            return Err(failure(
                OwnerStateErrorKind::Policy,
                "owner-state file name is not one normal component",
            ));
        }
        Ok(OwnerStateFile {
            root: self.clone(),
            name,
            max_bytes,
        })
    }

    fn open(&self, create: bool) -> Result<Option<File>, OwnerStateError> {
        if create {
            fs::create_dir_all(&self.0)
                .map_err(|error| system_failure(OwnerStateErrorKind::Root, "create root", error))?;
        }
        let named = match fs::symlink_metadata(&self.0) {
            Ok(metadata) => metadata,
            Err(error) if !create && error.kind() == std::io::ErrorKind::NotFound => {
                return Ok(None);
            }
            Err(error) => {
                return Err(system_failure(
                    OwnerStateErrorKind::Root,
                    "inspect root",
                    error,
                ));
            }
        };
        if named.file_type().is_symlink() || !named.is_dir() {
            return Err(failure(
                OwnerStateErrorKind::Type,
                "owner-state root is not an owner directory",
            ));
        }
        if named.uid() != rustix::process::geteuid().as_raw() {
            return Err(failure(
                OwnerStateErrorKind::Owner,
                "owner-state root belongs to another user",
            ));
        }
        fs::set_permissions(&self.0, fs::Permissions::from_mode(0o700))
            .map_err(|error| system_failure(OwnerStateErrorKind::Root, "restrict root", error))?;
        let directory = open(
            &self.0,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map(File::from)
        .map_err(|error| system_failure(OwnerStateErrorKind::Open, "open root", error))?;
        let opened = directory
            .metadata()
            .map_err(|error| system_failure(OwnerStateErrorKind::Open, "identify root", error))?;
        if opened.dev() != named.dev() || opened.ino() != named.ino() {
            return Err(failure(
                OwnerStateErrorKind::Policy,
                "owner-state root changed while opening",
            ));
        }
        Ok(Some(directory))
    }
}

#[derive(Clone, Debug)]
pub(crate) struct OwnerStateFile {
    root: OwnerStateRoot,
    name: String,
    max_bytes: u64,
}

impl OwnerStateFile {
    pub(crate) fn read(&self) -> Result<Option<Vec<u8>>, OwnerStateError> {
        let Some(directory) = self.root.open(false)? else {
            return Ok(None);
        };
        let descriptor = match openat(
            &directory,
            self.name.as_str(),
            OFlags::RDONLY | OFlags::NONBLOCK | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        ) {
            Ok(descriptor) => descriptor,
            Err(rustix::io::Errno::NOENT) => return Ok(None),
            Err(error) => {
                return Err(system_failure(
                    OwnerStateErrorKind::Open,
                    "open file",
                    error,
                ));
            }
        };
        let mut file = File::from(descriptor);
        check_file(&file, self.max_bytes, true)?;
        let mut bytes = Vec::new();
        std::io::Read::by_ref(&mut file)
            .take(self.max_bytes.saturating_add(1))
            .read_to_end(&mut bytes)
            .map_err(|error| system_failure(OwnerStateErrorKind::Read, "read file", error))?;
        if bytes.len() as u64 > self.max_bytes {
            return Err(failure(
                OwnerStateErrorKind::Oversized,
                "owner-state file exceeds its byte bound",
            ));
        }
        Ok(Some(bytes))
    }

    pub(crate) fn append(&self, bytes: &[u8]) -> Result<(), OwnerStateError> {
        let (mut file, directory, created) = self.open_mutable(true)?;
        let length = file
            .metadata()
            .map_err(|error| {
                system_failure(OwnerStateErrorKind::Open, "inspect append target", error)
            })?
            .len();
        if length
            .checked_add(bytes.len() as u64)
            .is_none_or(|total| total > self.max_bytes)
        {
            return Err(failure(
                OwnerStateErrorKind::Oversized,
                "owner-state append exceeds its byte bound",
            ));
        }
        file.write_all(bytes)
            .and_then(|()| file.flush())
            .and_then(|()| file.sync_all())
            .map_err(|error| system_failure(OwnerStateErrorKind::Write, "append record", error))?;
        if created {
            directory.sync_all().map_err(|error| {
                system_failure(OwnerStateErrorKind::Sync, "sync directory", error)
            })?;
        }
        Ok(())
    }

    pub(crate) fn open_process_file(&self) -> Result<File, OwnerStateError> {
        let (file, directory, created) = self.open_mutable(false)?;
        if created {
            file.sync_all().map_err(|error| {
                system_failure(OwnerStateErrorKind::Sync, "sync process file", error)
            })?;
            directory.sync_all().map_err(|error| {
                system_failure(OwnerStateErrorKind::Sync, "sync directory", error)
            })?;
        }
        Ok(file)
    }

    fn open_mutable(&self, append: bool) -> Result<(File, File, bool), OwnerStateError> {
        let directory = self
            .root
            .open(true)?
            .ok_or_else(|| failure(OwnerStateErrorKind::Root, "owner-state root is missing"))?;
        for _ in 0..16 {
            let mut flags = OFlags::RDWR | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK;
            if append {
                flags |= OFlags::APPEND;
            }
            let (descriptor, created) =
                match openat(&directory, self.name.as_str(), flags, Mode::empty()) {
                    Ok(descriptor) => (descriptor, false),
                    Err(rustix::io::Errno::NOENT) => match openat(
                        &directory,
                        self.name.as_str(),
                        flags | OFlags::CREATE | OFlags::EXCL,
                        Mode::from_raw_mode(0o600),
                    ) {
                        Ok(descriptor) => (descriptor, true),
                        Err(rustix::io::Errno::EXIST) => continue,
                        Err(error) => {
                            return Err(system_failure(
                                OwnerStateErrorKind::Open,
                                "create process file",
                                error,
                            ));
                        }
                    },
                    Err(error) => {
                        return Err(system_failure(
                            OwnerStateErrorKind::Open,
                            "open process file",
                            error,
                        ));
                    }
                };
            let file = File::from(descriptor);
            check_file(&file, self.max_bytes, !created)?;
            rustix::fs::fchmod(&file, Mode::from_raw_mode(0o600)).map_err(|error| {
                system_failure(OwnerStateErrorKind::Owner, "restrict process file", error)
            })?;
            return Ok((file, directory, created));
        }
        Err(failure(
            OwnerStateErrorKind::Temporary,
            "owner-state identity kept changing",
        ))
    }

    pub(crate) fn replace(&self, bytes: &[u8]) -> Result<(), OwnerStateError> {
        self.replace_inner(bytes, None)
    }

    /// The caller must hold this record's exclusive writer lock. Used after
    /// explicit Forget so interrupted replacements cannot retain old facts.
    pub(crate) fn remove_abandoned_temporaries_after_lock(&self) -> Result<(), OwnerStateError> {
        let Some(directory) = self.root.open(false)? else {
            return Ok(());
        };
        let held = cap_std::fs::Dir::from_std_file(
            directory
                .try_clone()
                .map_err(|e| system_failure(OwnerStateErrorKind::Open, "retain directory", e))?,
        );
        let prefix = format!(".{}.", self.name);
        let mut count = 0;
        for entry in held
            .entries()
            .map_err(|e| system_failure(OwnerStateErrorKind::Read, "enumerate transactions", e))?
        {
            count += 1;
            if count > 4096 {
                return Err(failure(
                    OwnerStateErrorKind::Oversized,
                    "owner-state transaction inventory exceeded its bound",
                ));
            }
            let name = entry
                .map_err(|e| system_failure(OwnerStateErrorKind::Read, "read transaction name", e))?
                .file_name();
            let Some(name) = name.to_str() else {
                continue;
            };
            let Some(suffix) = name
                .strip_prefix(&prefix)
                .and_then(|s| s.strip_suffix(".tmp"))
            else {
                continue;
            };
            let Some((pid, sequence)) = suffix.split_once('-') else {
                continue;
            };
            if pid.parse::<u32>().ok().is_none_or(|value| value == 0)
                || sequence.parse::<u64>().ok().is_none_or(|value| value == 0)
            {
                continue;
            }
            let descriptor = openat(
                &directory,
                name,
                OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK,
                Mode::empty(),
            )
            .map_err(|e| {
                system_failure(OwnerStateErrorKind::Open, "open abandoned transaction", e)
            })?;
            let file = File::from(descriptor);
            check_file(&file, self.max_bytes, true)?;
            if file
                .metadata()
                .map_err(|e| {
                    system_failure(OwnerStateErrorKind::Type, "inspect transaction links", e)
                })?
                .nlink()
                != 1
            {
                return Err(failure(
                    OwnerStateErrorKind::Type,
                    "abandoned transaction has another link",
                ));
            }
            unlinkat(&directory, name, AtFlags::empty()).map_err(|e| {
                system_failure(
                    OwnerStateErrorKind::Write,
                    "remove abandoned transaction",
                    e,
                )
            })?;
        }
        directory
            .sync_all()
            .map_err(|e| system_failure(OwnerStateErrorKind::Sync, "sync transaction removal", e))
    }

    fn replace_inner(
        &self,
        bytes: &[u8],
        #[cfg_attr(not(test), allow(unused_variables))] cut: Option<ReplaceCut>,
    ) -> Result<(), OwnerStateError> {
        if bytes.len() as u64 > self.max_bytes {
            return Err(failure(
                OwnerStateErrorKind::Oversized,
                "owner-state replacement exceeds its byte bound",
            ));
        }
        let directory = self
            .root
            .open(true)?
            .ok_or_else(|| failure(OwnerStateErrorKind::Root, "owner-state root is missing"))?;
        for _ in 0..16 {
            let sequence = NEXT_TEMPORARY.fetch_add(1, Ordering::Relaxed);
            let temporary = format!(".{}.{}-{sequence}.tmp", self.name, std::process::id());
            let descriptor = match openat(
                &directory,
                temporary.as_str(),
                OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::from_raw_mode(0o600),
            ) {
                Ok(descriptor) => descriptor,
                Err(rustix::io::Errno::EXIST) => continue,
                Err(error) => {
                    return Err(system_failure(
                        OwnerStateErrorKind::Temporary,
                        "create transaction",
                        error,
                    ));
                }
            };
            let mut file = File::from(descriptor);
            let result = (|| {
                rustix::fs::fchmod(&file, Mode::from_raw_mode(0o600)).map_err(|error| {
                    system_failure(OwnerStateErrorKind::Owner, "restrict transaction", error)
                })?;
                #[cfg(test)]
                maybe_cut(cut, ReplaceCut::BeforeWrite)?;
                file.write_all(bytes).map_err(|error| {
                    system_failure(OwnerStateErrorKind::Write, "write transaction", error)
                })?;
                #[cfg(test)]
                maybe_cut(cut, ReplaceCut::AfterWrite)?;
                file.flush()
                    .and_then(|()| file.sync_all())
                    .map_err(|error| {
                        system_failure(OwnerStateErrorKind::Sync, "sync transaction", error)
                    })?;
                #[cfg(test)]
                maybe_cut(cut, ReplaceCut::AfterFileSync)?;
                drop(file);
                renameat(
                    &directory,
                    temporary.as_str(),
                    &directory,
                    self.name.as_str(),
                )
                .map_err(|error| {
                    system_failure(OwnerStateErrorKind::Publish, "publish transaction", error)
                })?;
                #[cfg(test)]
                maybe_cut(cut, ReplaceCut::AfterRename)?;
                directory.sync_all().map_err(|error| {
                    system_failure(OwnerStateErrorKind::Sync, "sync directory", error)
                })?;
                #[cfg(test)]
                maybe_cut(cut, ReplaceCut::AfterDirectorySync)?;
                Ok(())
            })();
            if result.is_err() {
                let _ = unlinkat(&directory, temporary.as_str(), AtFlags::empty());
            }
            return result;
        }
        Err(failure(
            OwnerStateErrorKind::Temporary,
            "cannot allocate owner-state transaction",
        ))
    }
}

fn check_file(
    file: &File,
    max_bytes: u64,
    require_owner_mode: bool,
) -> Result<(), OwnerStateError> {
    let metadata = file
        .metadata()
        .map_err(|error| system_failure(OwnerStateErrorKind::Open, "inspect file", error))?;
    if !metadata.is_file() {
        return Err(failure(
            OwnerStateErrorKind::Type,
            "owner-state entry is not a regular file",
        ));
    }
    if metadata.uid() != rustix::process::geteuid().as_raw()
        || require_owner_mode && metadata.mode() & 0o077 != 0
    {
        return Err(failure(
            OwnerStateErrorKind::Owner,
            "owner-state file is not owner-only",
        ));
    }
    if metadata.len() > max_bytes {
        return Err(failure(
            OwnerStateErrorKind::Oversized,
            "owner-state file exceeds its byte bound",
        ));
    }
    Ok(())
}

#[cfg_attr(not(test), allow(dead_code))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ReplaceCut {
    BeforeWrite,
    AfterWrite,
    AfterFileSync,
    AfterRename,
    AfterDirectorySync,
}

#[cfg(test)]
fn maybe_cut(selected: Option<ReplaceCut>, current: ReplaceCut) -> Result<(), OwnerStateError> {
    if selected == Some(current) {
        Err(failure(
            OwnerStateErrorKind::Sync,
            format!("injected owner-state cut after {current:?}"),
        ))
    } else {
        Ok(())
    }
}

#[cfg(test)]
#[path = "owner_state/tests.rs"]
mod tests;
