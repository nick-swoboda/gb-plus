//! Closed, bounded data transfer for a captured view; no extraction program runs.

use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use super::*;

const CHUNK_BYTES: usize = 64 * 1024;
const MAX_FRAMES: u64 = 65_536;

/// Encoded JSON frame ceiling, including byte-array expansion and metadata.
pub const MAX_SERVICE_VIEW_FRAME_BYTES: usize = 300 * 1024;

/// One strictly ordered frame in one view transfer. The surrounding owning
/// connection decides which workspace or extension admission this transfer serves.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ServiceSnapshotFrame {
    /// Exact supported wire version, currently one.
    pub version: u16,
    /// Starts at zero and cannot repeat or skip.
    pub sequence: u64,
    /// Data-only operation; no operation can start a process.
    pub operation: ServiceSnapshotOperation,
}

/// A closed set of inert filesystem data operations.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ServiceSnapshotOperation {
    /// Create one owner-only directory, after its parent has been declared.
    Directory {
        /// Strict relative path with no links or unavailable components.
        path: String,
    },
    /// Start one regular file. Every byte must arrive before another entry.
    File {
        /// Strict relative path, declared exactly once after its parent.
        path: String,
        /// Whether the captured file had any executable bit.
        executable: bool,
        /// Exact expected size, at most 128 MiB.
        bytes: u64,
        /// Exact SHA-256 of the expected file bytes.
        digest: Digest,
    },
    /// At most 64 KiB of the current file, never an outer control operation.
    Data {
        /// Opaque captured bytes.
        bytes: Vec<u8>,
    },
    /// Seal the complete current file after its size and digest match.
    EndFile,
    /// End exactly one complete view after all bytes have been verified.
    Finish {
        /// Must match the receiver's independently supplied admission digest.
        digest: Digest,
    },
}

impl ServiceSnapshot {
    /// Emit bounded data frames for this private captured copy. The caller owns
    /// transport deadlines and cancellation; returning an error stops transfer.
    /// Only the final frame denotes a validated complete view.
    ///
    /// # Errors
    /// Refuses changed snapshots, cancellation, excess frames, or sink failures.
    /// Partial transfer never grants permission to use or execute its contents.
    pub fn transfer(
        &self,
        sink: &mut dyn FnMut(&ServiceSnapshotFrame) -> Result<(), String>,
        cancelled: &dyn Fn() -> bool,
    ) -> Result<(), String> {
        self.revalidate()?;
        let mut writer = Writer {
            sink,
            cancelled,
            next: 0,
        };
        writer.walk(&self.storage.directory, "")?;
        self.revalidate()?;
        writer.emit(ServiceSnapshotOperation::Finish {
            digest: self.digest.clone(),
        })
    }
}

struct Writer<'a> {
    sink: &'a mut dyn FnMut(&ServiceSnapshotFrame) -> Result<(), String>,
    cancelled: &'a dyn Fn() -> bool,
    next: u64,
}

impl Writer<'_> {
    fn emit(&mut self, operation: ServiceSnapshotOperation) -> Result<(), String> {
        if (self.cancelled)() || self.next >= MAX_FRAMES {
            return Err(
                "Service snapshot transfer was cancelled or exceeded its frame bound.".into(),
            );
        }
        let frame = ServiceSnapshotFrame {
            version: 1,
            sequence: self.next,
            operation,
        };
        self.next += 1; // A possibly partial sink write must never reuse this identity.
        (self.sink)(&frame)
    }

    fn walk(&mut self, directory: &Dir, prefix: &str) -> Result<(), String> {
        if prefix.len() > 4096 || prefix.matches('/').count() > 32 {
            return Err("Service snapshot transfer path bound exceeded.".into());
        }
        let mut names = Vec::new();
        for entry in directory.entries().map_err(failure)? {
            if names.len() >= 16_384 {
                return Err("Service snapshot transfer entry limit exceeded.".into());
            }
            names.push(
                entry
                    .map_err(failure)?
                    .file_name()
                    .into_string()
                    .map_err(|_| "Non-UTF-8 snapshot path.")?,
            );
        }
        names.sort();
        for name in names {
            if !service_path_component_allowed(&name) {
                return Err("Unavailable snapshot transfer path.".into());
            }
            let path = format!("{prefix}{name}");
            let metadata = directory.symlink_metadata(&name).map_err(failure)?;
            if metadata.is_dir() {
                self.emit(ServiceSnapshotOperation::Directory { path: path.clone() })?;
                self.walk(
                    &directory.open_dir_nofollow(&name).map_err(failure)?,
                    &format!("{path}/"),
                )?;
            } else {
                let bytes = read_file(directory, &name, &metadata)?;
                self.emit(ServiceSnapshotOperation::File {
                    path,
                    executable: metadata.mode() & 0o111 != 0,
                    bytes: bytes.len() as u64,
                    digest: Digest::sha256(&bytes),
                })?;
                for chunk in bytes.chunks(CHUNK_BYTES) {
                    self.emit(ServiceSnapshotOperation::Data {
                        bytes: chunk.to_vec(),
                    })?;
                }
                self.emit(ServiceSnapshotOperation::EndFile)?;
            }
        }
        Ok(())
    }
}

struct PendingFile {
    file: cap_std::fs::File,
    executable: bool,
    remaining: u64,
    digest: Digest,
    hash: Sha256,
}

/// A fresh destination for exactly one admitted view. Errors permanently poison
/// the receiver; dropping it removes the partial copy. No received path chooses
/// a source file, executable command, or destination outside its private root.
pub struct ServiceSnapshotReceiver {
    storage: Option<PrivateDirectory>,
    expected: Digest,
    next: u64,
    paths: std::collections::BTreeSet<String>,
    entries: usize,
    path_bytes: usize,
    files: usize,
    bytes: u64,
    pending: Option<PendingFile>,
    poisoned: bool,
}

impl ServiceSnapshotReceiver {
    /// Create a receiver for a digest supplied independently by the owning app.
    ///
    /// # Errors
    /// Refuses a reused or unsafe destination, or a non-private parent.
    pub fn new(private_parent: &Path, name: &str, expected: Digest) -> Result<Self, String> {
        Ok(Self {
            storage: Some(PrivateDirectory::create(private_parent, name)?),
            expected,
            next: 0,
            paths: std::collections::BTreeSet::new(),
            entries: 0,
            path_bytes: 0,
            files: 0,
            bytes: 0,
            pending: None,
            poisoned: false,
        })
    }

    /// Consume one bounded frame. Only Finish can return a verified snapshot.
    ///
    /// # Errors
    /// Unknown versions, sequence errors, invalid paths, size/hash mismatches,
    /// incomplete files and I/O errors refuse the entire transfer permanently.
    pub fn accept(
        &mut self,
        frame: &ServiceSnapshotFrame,
    ) -> Result<Option<ServiceSnapshot>, String> {
        if self.poisoned || self.storage.is_none() {
            return Err("Service snapshot transfer already ended or was refused.".into());
        }
        let result = self.accept_inner(frame);
        if result.is_err() {
            self.poisoned = true;
        }
        result
    }

    fn accept_inner(
        &mut self,
        frame: &ServiceSnapshotFrame,
    ) -> Result<Option<ServiceSnapshot>, String> {
        if frame.version != 1 || frame.sequence != self.next || self.next >= MAX_FRAMES {
            return Err("Service snapshot transfer identity or sequence is invalid.".into());
        }
        self.next += 1;
        match &frame.operation {
            ServiceSnapshotOperation::Directory { path } => {
                let (parent, name) = self.entry(path)?;
                rustix::fs::mkdirat(&parent, &name, rustix::fs::Mode::RWXU).map_err(failure)?;
            }
            ServiceSnapshotOperation::File {
                path,
                executable,
                bytes,
                digest,
            } => {
                if *bytes > 128 * 1024 * 1024
                    || self.bytes.saturating_add(*bytes) > 256 * 1024 * 1024
                {
                    return Err("Service snapshot transfer byte limit exceeded.".into());
                }
                let (parent, name) = self.entry(path)?;
                let file = parent
                    .open_with(
                        &name,
                        OpenOptions::new()
                            .write(true)
                            .create_new(true)
                            .follow(cap_fs_ext::FollowSymlinks::No),
                    )
                    .map_err(failure)?;
                rustix::fs::fchmod(&file, rustix::fs::Mode::RUSR | rustix::fs::Mode::WUSR)
                    .map_err(failure)?;
                self.pending = Some(PendingFile {
                    file,
                    executable: *executable,
                    remaining: *bytes,
                    digest: digest.clone(),
                    hash: Sha256::new(),
                });
                self.bytes += bytes;
                self.files += 1;
            }
            ServiceSnapshotOperation::Data { bytes } => {
                let pending = self
                    .pending
                    .as_mut()
                    .ok_or("Snapshot data has no current file.")?;
                if bytes.is_empty()
                    || bytes.len() > CHUNK_BYTES
                    || bytes.len() as u64 > pending.remaining
                {
                    return Err("Snapshot data exceeds its admitted chunk or file size.".into());
                }
                pending.remaining -= bytes.len() as u64;
                pending.file.write_all(bytes).map_err(failure)?;
                pending.hash.update(bytes);
            }
            ServiceSnapshotOperation::EndFile => {
                let pending = self
                    .pending
                    .take()
                    .ok_or("Snapshot end has no current file.")?;
                if pending.remaining != 0 || !hash_matches(pending.hash, &pending.digest) {
                    return Err("Snapshot file does not match its admitted size or digest.".into());
                }
                let mode = rustix::fs::Mode::RUSR
                    | if pending.executable {
                        rustix::fs::Mode::XUSR
                    } else {
                        rustix::fs::Mode::empty()
                    };
                rustix::fs::fchmod(&pending.file, mode).map_err(failure)?;
                pending.file.sync_all().map_err(failure)?;
            }
            ServiceSnapshotOperation::Finish { digest } => {
                if self.pending.is_some() || digest != &self.expected {
                    return Err(
                        "Snapshot completion is partial or belongs to another admission.".into(),
                    );
                }
                let storage = self.storage.as_ref().ok_or("Snapshot transfer ended.")?;
                storage.revalidate()?;
                if crate::service_tree::digest_held(&storage.directory)? != self.expected {
                    return Err("Received snapshot does not match its complete admission.".into());
                }
                sync_tree(&storage.directory)?;
                return Ok(Some(ServiceSnapshot {
                    storage: self.storage.take().ok_or("Snapshot transfer ended.")?,
                    digest: self.expected.clone(),
                    exclusions: Vec::new(),
                    files: self.files,
                    bytes: self.bytes,
                }));
            }
        }
        Ok(None)
    }

    fn entry(&mut self, path: &str) -> Result<(Dir, String), String> {
        self.entries += 1;
        self.path_bytes = self.path_bytes.saturating_add(path.len());
        if self.pending.is_some()
            || path.len() > 4096
            || path.split('/').count() > 33
            || self.entries > 16_384
            || self.path_bytes > 4 * 1024 * 1024
            || path
                .split('/')
                .any(|part| !service_path_component_allowed(part))
            || !self.paths.insert(path.into())
        {
            return Err("Snapshot entry is unavailable, repeated, premature or oversized.".into());
        }
        let mut components = path.split('/').collect::<Vec<_>>();
        let name = components
            .pop()
            .ok_or("Snapshot entry has no filename.")?
            .to_owned();
        let mut parent = self
            .storage
            .as_ref()
            .ok_or("Snapshot transfer ended.")?
            .directory
            .try_clone()
            .map_err(failure)?;
        for component in components {
            parent = parent.open_dir_nofollow(component).map_err(failure)?;
        }
        Ok((parent, name))
    }
}

fn sync_tree(directory: &Dir) -> Result<(), String> {
    for entry in directory.entries().map_err(failure)? {
        let entry = entry.map_err(failure)?;
        if entry.file_type().map_err(failure)?.is_dir() {
            sync_tree(
                &directory
                    .open_dir_nofollow(entry.file_name())
                    .map_err(failure)?,
            )?;
        }
    }
    crate::durable_directory::sync_directory_entries(directory).map_err(failure)
}

fn hash_matches(hash: Sha256, expected: &Digest) -> bool {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    hash.finalize()
        .iter()
        .zip(expected.as_str().as_bytes().chunks_exact(2))
        .all(|(byte, hex)| hex == [HEX[usize::from(byte >> 4)], HEX[usize::from(byte & 15)]])
}
