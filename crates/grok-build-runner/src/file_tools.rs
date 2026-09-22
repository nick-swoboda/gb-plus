//! Descriptor-relative file tools for one private shadow workspace.
//!
//! The production [`ShadowFileTools::acquire_capability`] constructor clones
//! capabilities retained by the descriptor-relative workspace pipeline and
//! performs no ambient path reacquisition. All traversal, revalidation, reads,
//! and mutations are relative to already-open descriptors. The path-based
//! [`ShadowFileTools::acquire`] constructor remains only for migration and
//! regression fixtures. This protects the live workspace and prevents symlink
//! escapes; it is not an OS sandbox for child processes.

use std::ffi::{OsStr, OsString};
use std::fmt::{self, Display, Formatter};
use std::fs;
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::os::unix::ffi::OsStrExt;
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use cap_fs_ext::{
    DirExt, FollowSymlinks, MetadataExt as PortableMetadataExt, OpenOptionsFollowExt, OsMetadataExt,
};
use cap_std::fs::{Dir, File, Metadata, OpenOptions, PermissionsExt};
use cap_std::{ambient_authority, fs::Permissions};
use grok_build_core::{
    CompiledExecutionPolicy, Digest, IssuedWorkspaceGrant, MutationMode, PathScope,
};
use rustix::fs::{RenameFlags, renameat_with};

use crate::capability_apply::DirectoryPathAnchor;
use crate::durable_directory::sync_directory_entries as sync_directory;
use crate::{CapabilityShadowWorkspace, ShadowWorkspace};

const HARD_MAX_FILE_BYTES: u64 = 16 * 1024 * 1024;
const HARD_MAX_SEARCH_MATCHES: usize = 100_000;
const HARD_MAX_LITERAL_BYTES: usize = 4_096;
const TEMP_ATTEMPTS: usize = 128;
const CREATED_FILE_MODE: u32 = 0o600;

static NEXT_TEMP: AtomicU64 = AtomicU64::new(0);

/// Explicit ceilings applied to one descriptor-relative file-tool boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FileToolLimits {
    read_bytes: u64,
    write_bytes: u64,
    search_matches: usize,
}

impl FileToolLimits {
    /// Creates fail-closed file-tool ceilings.
    ///
    /// # Errors
    ///
    /// Returns an error for a zero limit or a value above the runner's hard
    /// in-memory ceilings.
    pub fn new(
        max_read_bytes: u64,
        max_write_bytes: u64,
        max_search_matches: usize,
    ) -> Result<Self, FileToolError> {
        if max_read_bytes == 0 || max_read_bytes > HARD_MAX_FILE_BYTES {
            return Err(FileToolError::InvalidLimit(format!(
                "max_read_bytes must be between 1 and {HARD_MAX_FILE_BYTES}"
            )));
        }
        if max_write_bytes == 0 || max_write_bytes > HARD_MAX_FILE_BYTES {
            return Err(FileToolError::InvalidLimit(format!(
                "max_write_bytes must be between 1 and {HARD_MAX_FILE_BYTES}"
            )));
        }
        if max_search_matches == 0 || max_search_matches > HARD_MAX_SEARCH_MATCHES {
            return Err(FileToolError::InvalidLimit(format!(
                "max_search_matches must be between 1 and {HARD_MAX_SEARCH_MATCHES}"
            )));
        }
        Ok(Self {
            read_bytes: max_read_bytes,
            write_bytes: max_write_bytes,
            search_matches: max_search_matches,
        })
    }

    /// Returns the largest complete file read accepted by this boundary.
    #[must_use]
    pub const fn max_read_bytes(self) -> u64 {
        self.read_bytes
    }

    /// Returns the largest replacement or creation accepted by this boundary.
    #[must_use]
    pub const fn max_write_bytes(self) -> u64 {
        self.write_bytes
    }

    /// Returns the largest complete literal-match set accepted by this boundary.
    #[must_use]
    pub const fn max_search_matches(self) -> usize {
        self.search_matches
    }
}

/// Complete bytes and identity returned by a stable regular-file read.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FileReadResult {
    /// Normalized workspace-relative path.
    pub path: PathBuf,
    /// Exact complete file bytes.
    pub bytes: Vec<u8>,
    /// SHA-256 of `bytes`.
    pub digest: Digest,
}

/// One exact byte match. Lines and columns are one-based byte coordinates.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LiteralMatch {
    /// Zero-based byte offset from the start of the file.
    pub byte_offset: u64,
    /// One-based line, where byte `\n` starts the next line.
    pub line: u64,
    /// One-based byte column. UTF-8 code points may occupy multiple columns.
    pub column: u64,
}

/// Complete result of an exact, overlapping literal-byte search.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LiteralSearchResult {
    /// Normalized workspace-relative path.
    pub path: PathBuf,
    /// SHA-256 of the complete searched file.
    pub file_digest: Digest,
    /// Total bytes in the complete searched file.
    pub file_length: u64,
    /// Every overlapping match in ascending byte-offset order.
    pub matches: Vec<LiteralMatch>,
}

/// Durable facts returned after an atomic shadow mutation and directory sync.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FileMutationReceipt {
    /// Normalized workspace-relative target.
    pub path: PathBuf,
    /// Exact content before the operation, or `None` for create.
    pub previous_digest: Option<Digest>,
    /// Exact content after the operation, or `None` for delete.
    pub result_digest: Option<Digest>,
}

/// Rejected filesystem object type.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UnsafeFileKind {
    /// A symbolic link appeared in the path.
    Symlink,
    /// The target regular file has another hard link.
    HardLink,
    /// The target is a directory where a regular file is required.
    Directory,
    /// The target is a socket, FIFO, device, or another special object.
    Special,
}

/// Fail-closed descriptor-relative file-tool error.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum FileToolError {
    /// The issued grant or compiled policy failed integrity validation.
    Authority(String),
    /// File tools were asked to operate without shadow-workspace policy.
    ShadowModeRequired,
    /// The private shadow is not bound to the supplied grant/base snapshot.
    ShadowBinding(String),
    /// The root is not private, disjoint, owned by this user, or identity-stable.
    PrivateRoot(String),
    /// A tool path was not a normalized relative non-Git path.
    InvalidPath {
        /// Rejected caller-supplied path.
        path: PathBuf,
        /// Exact fail-closed validation reason.
        reason: String,
    },
    /// The compiled policy does not cover this path and access mode.
    ScopeDenied {
        /// Normalized requested path.
        path: PathBuf,
        /// `true` when write authority was required.
        write: bool,
    },
    /// A caller-supplied ceiling was invalid.
    InvalidLimit(String),
    /// A complete read or write would exceed its declared bound.
    FileTooLarge {
        /// Normalized requested path.
        path: PathBuf,
        /// Maximum complete byte count.
        limit: u64,
    },
    /// A search would exceed the complete-result match bound.
    MatchLimitExceeded {
        /// Normalized searched path.
        path: PathBuf,
        /// Maximum complete match count.
        limit: usize,
    },
    /// The requested target does not exist.
    NotFound(PathBuf),
    /// Create requires the target to be absent.
    AlreadyExists(PathBuf),
    /// A link, directory, or special object was rejected.
    UnsafeFile {
        /// Path containing the rejected object.
        path: PathBuf,
        /// Exact rejected object class.
        kind: UnsafeFileKind,
    },
    /// The same open file did not produce two identical, stable reads.
    UnstableRead(PathBuf),
    /// Replace/delete content did not match the caller's expected SHA-256.
    PreconditionFailed {
        /// Normalized mutation target.
        path: PathBuf,
        /// Caller-supplied required SHA-256.
        expected: Digest,
        /// Runner-computed complete SHA-256.
        actual: Digest,
    },
    /// An atomic effect occurred, but its descriptor-relative postcondition or
    /// durability check failed. Callers must reconcile rather than replay.
    EffectAppliedButUnverified {
        /// Normalized mutation target.
        path: PathBuf,
        /// Failed post-effect proof.
        reason: String,
    },
    /// A descriptor-relative filesystem operation failed.
    Io {
        /// Descriptor-relative operation that failed.
        operation: &'static str,
        /// Redacted logical path, never an expanded external target.
        path: PathBuf,
        /// Operating-system error text.
        message: String,
    },
}

impl Display for FileToolError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Authority(message) => {
                write!(formatter, "file-tool authority rejected: {message}")
            }
            Self::ShadowModeRequired => {
                formatter.write_str("file tools require shadow-workspace mutation mode")
            }
            Self::ShadowBinding(message) => write!(formatter, "shadow binding rejected: {message}"),
            Self::PrivateRoot(message) => write!(formatter, "private root rejected: {message}"),
            Self::InvalidPath { path, reason } => {
                write!(formatter, "invalid tool path {}: {reason}", path.display())
            }
            Self::ScopeDenied { path, write } => write!(
                formatter,
                "{} scope does not cover {}",
                if *write { "write" } else { "read" },
                path.display()
            ),
            Self::InvalidLimit(message) => write!(formatter, "invalid file-tool limit: {message}"),
            Self::FileTooLarge { path, limit } => {
                write!(
                    formatter,
                    "{} exceeds the complete {limit}-byte bound",
                    path.display()
                )
            }
            Self::MatchLimitExceeded { path, limit } => write!(
                formatter,
                "{} exceeds the complete {limit}-match bound",
                path.display()
            ),
            Self::NotFound(path) => write!(formatter, "file does not exist: {}", path.display()),
            Self::AlreadyExists(path) => {
                write!(formatter, "file already exists: {}", path.display())
            }
            Self::UnsafeFile { path, kind } => {
                write!(formatter, "unsafe {kind:?} at {}", path.display())
            }
            Self::UnstableRead(path) => {
                write!(
                    formatter,
                    "file changed during stable read: {}",
                    path.display()
                )
            }
            Self::PreconditionFailed {
                path,
                expected,
                actual,
            } => write!(
                formatter,
                "content precondition failed for {}: expected {expected}, found {actual}",
                path.display()
            ),
            Self::EffectAppliedButUnverified { path, reason } => write!(
                formatter,
                "effect applied but postcondition is unverified for {}: {reason}",
                path.display()
            ),
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

impl std::error::Error for FileToolError {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ObjectIdentity {
    device: u64,
    inode: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct RootIdentity {
    object: ObjectIdentity,
    uid: u32,
    mode: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct FileFingerprint {
    object: ObjectIdentity,
    links: u64,
    length: u64,
    mode: u32,
    modified_seconds: i64,
    modified_nanoseconds: i64,
    changed_seconds: i64,
    changed_nanoseconds: i64,
}

struct ParentHandle {
    directory: Dir,
    relative: PathBuf,
    identity: ObjectIdentity,
    leaf: OsString,
}

/// Authority-bound descriptor-relative file tools for one private shadow.
///
/// This type never opens the live workspace. Its constructor is the only place
/// that uses ambient filesystem authority; methods revalidate the live grant,
/// compiled policy, private-root name, root descriptor, and path scope before
/// each operation.
pub struct ShadowFileTools {
    root: Dir,
    root_parent: Dir,
    root_leaf: OsString,
    root_identity: RootIdentity,
    root_path_anchor: DirectoryPathAnchor,
    live_path_anchor: DirectoryPathAnchor,
    grant_hash: Digest,
    policy_hash: Digest,
    limits: FileToolLimits,
}

impl ShadowFileTools {
    /// Acquires a path-based migration shadow and binds it to exact authority.
    ///
    /// New production callers must use [`Self::acquire_capability`]. This
    /// constructor remains for migration and historical regression fixtures.
    ///
    /// # Errors
    ///
    /// Returns an error if authority is stale, mutation mode is not
    /// `ShadowWorkspace`, the shadow is not based on the grant, the private root
    /// is inside the live workspace, or the root is not a private real directory.
    pub fn acquire(
        grant: &IssuedWorkspaceGrant,
        policy: &CompiledExecutionPolicy,
        shadow: &ShadowWorkspace,
        limits: FileToolLimits,
    ) -> Result<Self, FileToolError> {
        validate_authority(grant, policy)?;
        if policy.contract().mutation_mode != MutationMode::ShadowWorkspace {
            return Err(FileToolError::ShadowModeRequired);
        }
        if shadow.base().snapshot().grant_hash != grant.contract().grant_hash {
            return Err(FileToolError::ShadowBinding(
                "base snapshot grant hash does not match issued authority".into(),
            ));
        }
        if shadow.base().root() != grant.contract().canonical_root {
            return Err(FileToolError::ShadowBinding(
                "base manifest root does not match issued authority".into(),
            ));
        }

        let requested_root = shadow.root();
        if !requested_root.is_absolute() {
            return Err(FileToolError::PrivateRoot(
                "shadow root must be absolute".into(),
            ));
        }
        let canonical_root = fs::canonicalize(requested_root)
            .map_err(|error| io_error("canonicalize private root", requested_root, &error))?;
        if canonical_root != requested_root {
            return Err(FileToolError::PrivateRoot(
                "shadow root must already be canonical".into(),
            ));
        }
        let live_root = &grant.contract().canonical_root;
        if canonical_root.starts_with(live_root) || live_root.starts_with(&canonical_root) {
            return Err(FileToolError::PrivateRoot(
                "shadow and live workspace roots must be disjoint".into(),
            ));
        }

        let parent_path = canonical_root.parent().ok_or_else(|| {
            FileToolError::PrivateRoot("shadow root must have an ambient parent".into())
        })?;
        let root_leaf = canonical_root
            .file_name()
            .ok_or_else(|| FileToolError::PrivateRoot("shadow root must have a leaf name".into()))?
            .to_os_string();

        // This is the single ambient acquisition boundary. Ordinary operations
        // retain and traverse only these already-open capabilities.
        let root_parent = Dir::open_ambient_dir(parent_path, ambient_authority())
            .map_err(|error| io_error("open private-root parent", parent_path, &error))?;
        let root = root_parent.open_dir_nofollow(&root_leaf).map_err(|error| {
            io_error(
                "open private root without following links",
                requested_root,
                &error,
            )
        })?;
        let metadata = root
            .dir_metadata()
            .map_err(|error| io_error("inspect private-root descriptor", requested_root, &error))?;
        let root_identity = validate_private_root_metadata(&metadata)?;
        let root_path_anchor = DirectoryPathAnchor::acquire(&canonical_root, "shadow root")
            .map_err(|error| FileToolError::PrivateRoot(error.to_string()))?;
        if root_path_anchor.final_device_inode()
            != (root_identity.object.device, root_identity.object.inode)
        {
            return Err(FileToolError::PrivateRoot(
                "shadow path anchor differs from its retained descriptor".into(),
            ));
        }
        let live_path_anchor = DirectoryPathAnchor::acquire(live_root, "live workspace root")
            .map_err(|error| FileToolError::PrivateRoot(error.to_string()))?;
        if live_path_anchor.final_device_inode()
            != (grant.identity().device_id(), grant.identity().inode())
            || root_path_anchor
                .contains_device_inode(grant.identity().device_id(), grant.identity().inode())
            || live_path_anchor
                .contains_device_inode(root_identity.object.device, root_identity.object.inode)
        {
            return Err(FileToolError::PrivateRoot(
                "shadow and live roots overlap by directory identity".into(),
            ));
        }

        let tools = Self {
            root,
            root_parent,
            root_leaf,
            root_identity,
            root_path_anchor,
            live_path_anchor,
            grant_hash: grant.contract().grant_hash.clone(),
            policy_hash: policy.contract().policy_hash.clone(),
            limits,
        };
        tools.validate_call(grant, policy, Path::new("."), false, true)?;
        Ok(tools)
    }

    /// Clones already-retained shadow capabilities and binds them to exact authority.
    ///
    /// Unlike [`Self::acquire`], this production constructor performs no ambient
    /// path reacquisition. The supplied capability shadow revalidates both its
    /// retained descriptor and named root before returning descriptor clones.
    ///
    /// # Errors
    ///
    /// Returns an error for stale authority/policy, non-shadow mutation mode,
    /// mismatched base authority, changed shadow identity, or unsafe root mode.
    pub fn acquire_capability(
        grant: &IssuedWorkspaceGrant,
        policy: &CompiledExecutionPolicy,
        shadow: &CapabilityShadowWorkspace,
        limits: FileToolLimits,
    ) -> Result<Self, FileToolError> {
        validate_authority(grant, policy)?;
        if policy.contract().mutation_mode != MutationMode::ShadowWorkspace {
            return Err(FileToolError::ShadowModeRequired);
        }
        if shadow.base().snapshot().grant_hash != grant.contract().grant_hash
            || shadow.base().root() != grant.contract().canonical_root
        {
            return Err(FileToolError::ShadowBinding(
                "capability shadow base differs from issued authority".into(),
            ));
        }
        let (root, root_parent, root_leaf, root_path_anchor, live_path_anchor) = shadow
            .clone_capabilities(grant)
            .map_err(|error| FileToolError::ShadowBinding(error.to_string()))?;
        let metadata = root.dir_metadata().map_err(|error| {
            io_error(
                "inspect retained private-root descriptor",
                shadow.root(),
                &error,
            )
        })?;
        let root_identity = validate_private_root_metadata(&metadata)?;
        let tools = Self {
            root,
            root_parent,
            root_leaf,
            root_identity,
            root_path_anchor,
            live_path_anchor,
            grant_hash: grant.contract().grant_hash.clone(),
            policy_hash: policy.contract().policy_hash.clone(),
            limits,
        };
        tools.validate_call(grant, policy, Path::new("."), false, true)?;
        Ok(tools)
    }

    /// Reads a complete, stable, singly-linked regular file.
    ///
    /// The same open descriptor is read twice and its identity, length, mode,
    /// modification time, and change time must remain equal. The returned digest
    /// is computed by the runner over the complete bytes.
    ///
    /// # Errors
    ///
    /// Returns an error for stale authority/root identity, out-of-scope or unsafe
    /// paths, files above `max_bytes`, links/special files, or concurrent writes.
    pub fn read_regular_file(
        &self,
        grant: &IssuedWorkspaceGrant,
        policy: &CompiledExecutionPolicy,
        path: impl AsRef<Path>,
        max_bytes: u64,
    ) -> Result<FileReadResult, FileToolError> {
        let path = normalize_tool_path(path.as_ref())?;
        self.validate_call(grant, policy, &path, false, false)?;
        let bound = self.read_bound(max_bytes)?;
        let parent = self.open_parent(&path, false)?;
        let (bytes, fingerprint) = stable_read(&parent.directory, &parent.leaf, &path, bound)?;
        Self::verify_leaf_identity(&parent, fingerprint.object, &path)?;
        self.verify_parent(&parent)?;
        self.validate_root_identity()?;
        Ok(FileReadResult {
            path,
            digest: Digest::sha256(&bytes),
            bytes,
        })
    }

    /// Searches complete file bytes for every overlapping exact literal.
    ///
    /// Positions are computed here in the trusted runner. `byte_offset` is
    /// zero-based; line and byte-column are one-based. Empty needles are rejected.
    /// Needles are limited to 4096 bytes and searched with a linear-time prefix
    /// automaton.
    ///
    /// # Errors
    ///
    /// Returns an error rather than a truncated result if either byte or match
    /// bound would be exceeded.
    pub fn search_literal(
        &self,
        grant: &IssuedWorkspaceGrant,
        policy: &CompiledExecutionPolicy,
        path: impl AsRef<Path>,
        needle: &[u8],
        max_bytes: u64,
        max_matches: usize,
    ) -> Result<LiteralSearchResult, FileToolError> {
        if needle.is_empty() {
            return Err(FileToolError::InvalidLimit(
                "literal search needle must not be empty".into(),
            ));
        }
        if needle.len() > HARD_MAX_LITERAL_BYTES {
            return Err(FileToolError::InvalidLimit(format!(
                "literal search needle must not exceed {HARD_MAX_LITERAL_BYTES} bytes"
            )));
        }
        if max_matches == 0 || max_matches > self.limits.search_matches {
            return Err(FileToolError::InvalidLimit(format!(
                "max_matches must be between 1 and {}",
                self.limits.search_matches
            )));
        }
        let read = self.read_regular_file(grant, policy, path, max_bytes)?;
        let matches = literal_matches(&read.path, &read.bytes, needle, max_matches)?;
        let file_length =
            u64::try_from(read.bytes.len()).map_err(|_| FileToolError::FileTooLarge {
                path: read.path.clone(),
                limit: self.limits.read_bytes,
            })?;
        Ok(LiteralSearchResult {
            path: read.path,
            file_length,
            file_digest: read.digest,
            matches,
        })
    }

    /// Atomically creates a new `0600` regular file after an absence precondition.
    /// Missing parent directories are created descriptor-relatively beneath the
    /// shadow. A no-replace rename is the authoritative create check.
    ///
    /// # Errors
    ///
    /// Returns an error for stale authority/root identity, unsafe/out-of-scope
    /// paths, an existing target, oversized content, or failed durability.
    pub fn create_regular_file(
        &self,
        grant: &IssuedWorkspaceGrant,
        policy: &CompiledExecutionPolicy,
        path: impl AsRef<Path>,
        contents: &[u8],
    ) -> Result<FileMutationReceipt, FileToolError> {
        let path = normalize_tool_path(path.as_ref())?;
        self.validate_call(grant, policy, &path, true, false)?;
        self.validate_write_size(&path, contents)?;
        let parent = self.open_parent(&path, true)?;
        match parent.directory.symlink_metadata(&parent.leaf) {
            Ok(metadata) => {
                validate_regular_metadata(&path, &metadata)?;
                return Err(FileToolError::AlreadyExists(path));
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(io_error("inspect create target", &path, &error)),
        }

        let temp = write_temp(&parent.directory, &path, contents, CREATED_FILE_MODE)?;
        let rename_result = renameat_with(
            &parent.directory,
            Path::new(&temp),
            &parent.directory,
            Path::new(&parent.leaf),
            RenameFlags::NOREPLACE,
        );
        if let Err(error) = rename_result {
            if error == rustix::io::Errno::EXIST {
                let _ = parent.directory.remove_file(&temp);
                let _ = sync_directory(&parent.directory);
                return Err(FileToolError::AlreadyExists(path));
            }
            return Err(ambiguous_effect_error(
                &path,
                "atomic no-replace rename",
                &error,
            ));
        }
        self.finish_write_effect(&parent, &path, contents, None)
    }

    /// Atomically replaces a regular file whose complete SHA-256 matches
    /// `expected`. The existing mode is preserved.
    ///
    /// # Errors
    ///
    /// Returns an error for stale authority/root identity, links/special files,
    /// an oversized target or result, a stale digest, or failed durability.
    pub fn replace_regular_file(
        &self,
        grant: &IssuedWorkspaceGrant,
        policy: &CompiledExecutionPolicy,
        path: impl AsRef<Path>,
        expected: &Digest,
        contents: &[u8],
    ) -> Result<FileMutationReceipt, FileToolError> {
        let path = normalize_tool_path(path.as_ref())?;
        self.validate_call(grant, policy, &path, true, false)?;
        self.validate_write_size(&path, contents)?;
        let parent = self.open_parent(&path, false)?;
        let (initial_bytes, initial) = stable_read(
            &parent.directory,
            &parent.leaf,
            &path,
            self.limits.read_bytes,
        )?;
        let actual = Digest::sha256(&initial_bytes);
        if &actual != expected {
            return Err(FileToolError::PreconditionFailed {
                path,
                expected: expected.clone(),
                actual,
            });
        }
        let temp = write_temp(&parent.directory, &path, contents, initial.mode & 0o777)?;
        let final_check = stable_read(
            &parent.directory,
            &parent.leaf,
            &path,
            self.limits.read_bytes,
        );
        let (current_bytes, current) = match final_check {
            Ok(current) => current,
            Err(error) => {
                let _ = parent.directory.remove_file(&temp);
                let _ = sync_directory(&parent.directory);
                return Err(error);
            }
        };
        let current_digest = Digest::sha256(&current_bytes);
        if current_digest != *expected {
            let _ = parent.directory.remove_file(&temp);
            let _ = sync_directory(&parent.directory);
            return Err(FileToolError::PreconditionFailed {
                path,
                expected: expected.clone(),
                actual: current_digest,
            });
        }
        if initial.object != current.object {
            let _ = parent.directory.remove_file(&temp);
            let _ = sync_directory(&parent.directory);
            return Err(FileToolError::UnstableRead(path));
        }
        if let Err(error) = parent
            .directory
            .rename(&temp, &parent.directory, &parent.leaf)
        {
            return Err(ambiguous_effect_error(
                &path,
                "atomic replacement rename",
                &error,
            ));
        }
        self.finish_write_effect(&parent, &path, contents, Some(expected.clone()))
    }

    /// Atomically unlinks a regular file whose complete SHA-256 matches
    /// `expected`.
    ///
    /// # Errors
    ///
    /// Returns an error for stale authority/root identity, links/special files,
    /// an oversized target, a stale digest, or failed durability.
    pub fn delete_regular_file(
        &self,
        grant: &IssuedWorkspaceGrant,
        policy: &CompiledExecutionPolicy,
        path: impl AsRef<Path>,
        expected: &Digest,
    ) -> Result<FileMutationReceipt, FileToolError> {
        let path = normalize_tool_path(path.as_ref())?;
        self.validate_call(grant, policy, &path, true, false)?;
        let parent = self.open_parent(&path, false)?;
        let (bytes, first) = stable_read(
            &parent.directory,
            &parent.leaf,
            &path,
            self.limits.read_bytes,
        )?;
        let actual = Digest::sha256(&bytes);
        if &actual != expected {
            return Err(FileToolError::PreconditionFailed {
                path,
                expected: expected.clone(),
                actual,
            });
        }
        let (second_bytes, second) = stable_read(
            &parent.directory,
            &parent.leaf,
            &path,
            self.limits.read_bytes,
        )?;
        if first.object != second.object || Digest::sha256(&second_bytes) != *expected {
            return Err(FileToolError::UnstableRead(path));
        }
        if let Err(error) = parent.directory.remove_file(&parent.leaf) {
            return Err(ambiguous_effect_error(&path, "atomic unlink", &error));
        }
        if let Err(error) = sync_directory(&parent.directory) {
            return Err(FileToolError::EffectAppliedButUnverified {
                path,
                reason: format!("parent directory sync failed: {error}"),
            });
        }
        match parent.directory.symlink_metadata(&parent.leaf) {
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Ok(_) => {
                return Err(FileToolError::EffectAppliedButUnverified {
                    path,
                    reason: "target name exists after unlink".into(),
                });
            }
            Err(error) => {
                return Err(FileToolError::EffectAppliedButUnverified {
                    path,
                    reason: format!("delete postcondition inspection failed: {error}"),
                });
            }
        }
        if let Err(error) = self
            .verify_parent(&parent)
            .and_then(|()| self.validate_root_identity())
        {
            return Err(FileToolError::EffectAppliedButUnverified {
                path,
                reason: error.to_string(),
            });
        }
        Ok(FileMutationReceipt {
            path,
            previous_digest: Some(expected.clone()),
            result_digest: None,
        })
    }

    fn finish_write_effect(
        &self,
        parent: &ParentHandle,
        path: &Path,
        contents: &[u8],
        previous_digest: Option<Digest>,
    ) -> Result<FileMutationReceipt, FileToolError> {
        if let Err(error) = sync_directory(&parent.directory) {
            return Err(FileToolError::EffectAppliedButUnverified {
                path: path.to_path_buf(),
                reason: format!("parent directory sync failed: {error}"),
            });
        }
        let expected = Digest::sha256(contents);
        let postcondition = stable_read(
            &parent.directory,
            &parent.leaf,
            path,
            self.limits.write_bytes,
        )
        .and_then(|(bytes, fingerprint)| {
            if Digest::sha256(&bytes) != expected {
                return Err(FileToolError::UnstableRead(path.to_path_buf()));
            }
            Self::verify_leaf_identity(parent, fingerprint.object, path)
        })
        .and_then(|()| self.verify_parent(parent))
        .and_then(|()| self.validate_root_identity());
        if let Err(error) = postcondition {
            return Err(FileToolError::EffectAppliedButUnverified {
                path: path.to_path_buf(),
                reason: error.to_string(),
            });
        }
        Ok(FileMutationReceipt {
            path: path.to_path_buf(),
            previous_digest,
            result_digest: Some(expected),
        })
    }

    fn read_bound(&self, requested: u64) -> Result<u64, FileToolError> {
        if requested == 0 || requested > self.limits.read_bytes {
            return Err(FileToolError::InvalidLimit(format!(
                "max_bytes must be between 1 and {}",
                self.limits.read_bytes
            )));
        }
        Ok(requested)
    }

    fn validate_write_size(&self, path: &Path, contents: &[u8]) -> Result<(), FileToolError> {
        if u64::try_from(contents.len()).expect("usize fits u64") > self.limits.write_bytes {
            return Err(FileToolError::FileTooLarge {
                path: path.to_path_buf(),
                limit: self.limits.write_bytes,
            });
        }
        Ok(())
    }

    fn validate_call(
        &self,
        grant: &IssuedWorkspaceGrant,
        policy: &CompiledExecutionPolicy,
        path: &Path,
        write: bool,
        allow_root: bool,
    ) -> Result<(), FileToolError> {
        validate_authority(grant, policy)?;
        if policy.contract().mutation_mode != MutationMode::ShadowWorkspace {
            return Err(FileToolError::ShadowModeRequired);
        }
        if grant.contract().grant_hash != self.grant_hash
            || policy.contract().policy_hash != self.policy_hash
        {
            return Err(FileToolError::Authority(
                "authority differs from the capability acquisition".into(),
            ));
        }
        if write && !grant.contract().permissions.write_regular_files {
            return Err(FileToolError::Authority(
                "grant does not authorize regular-file writes".into(),
            ));
        }
        if !allow_root {
            let scopes = if write {
                &policy.contract().write_scopes
            } else {
                &policy.contract().read_scopes
            };
            if !scopes.iter().any(|scope| scope_covers(scope, path)) {
                return Err(FileToolError::ScopeDenied {
                    path: path.to_path_buf(),
                    write,
                });
            }
        }
        self.validate_root_identity()
    }

    fn validate_root_identity(&self) -> Result<(), FileToolError> {
        self.live_path_anchor
            .validate("live workspace root")
            .map_err(|error| FileToolError::PrivateRoot(error.to_string()))?;
        self.root_path_anchor
            .validate("shadow root")
            .map_err(|error| FileToolError::PrivateRoot(error.to_string()))?;
        let descriptor_metadata = self.root.dir_metadata().map_err(|error| {
            FileToolError::PrivateRoot(format!("inspect retained root descriptor: {error}"))
        })?;
        let descriptor = validate_private_root_metadata(&descriptor_metadata)?;
        if descriptor != self.root_identity {
            return Err(FileToolError::PrivateRoot(
                "retained private-root identity, owner, or mode changed".into(),
            ));
        }
        let named_root = self
            .root_parent
            .open_dir_nofollow(&self.root_leaf)
            .map_err(|error| {
                FileToolError::PrivateRoot(format!(
                    "private-root name no longer resolves without a link: {error}"
                ))
            })?;
        let named_metadata = named_root.dir_metadata().map_err(|error| {
            FileToolError::PrivateRoot(format!("inspect named private root: {error}"))
        })?;
        let named = validate_private_root_metadata(&named_metadata)?;
        if named != self.root_identity {
            return Err(FileToolError::PrivateRoot(
                "private-root path was replaced".into(),
            ));
        }
        Ok(())
    }

    fn open_parent(
        &self,
        path: &Path,
        create_missing: bool,
    ) -> Result<ParentHandle, FileToolError> {
        let mut components = path.components().collect::<Vec<_>>();
        let leaf = match components.pop() {
            Some(Component::Normal(leaf)) => leaf.to_os_string(),
            _ => {
                return Err(FileToolError::InvalidPath {
                    path: path.to_path_buf(),
                    reason: "target must have a normal leaf component".into(),
                });
            }
        };
        let mut directory = self
            .root
            .try_clone()
            .map_err(|error| io_error("clone private-root capability", path, &error))?;
        let mut relative = PathBuf::new();
        let mut created_any = false;
        for component in components {
            let Component::Normal(name) = component else {
                return Err(FileToolError::InvalidPath {
                    path: path.to_path_buf(),
                    reason: "target contains a non-normal parent component".into(),
                });
            };
            relative.push(name);
            let (next, created_here) =
                descend_parent_component(&directory, name, path, create_missing, created_any)?;
            directory = next;
            created_any |= created_here;
            let metadata = directory.dir_metadata().map_err(|error| {
                parent_mutation_error(path, "inspect shadow parent", &error, created_any)
            })?;
            if !metadata.is_dir() {
                let error = FileToolError::UnsafeFile {
                    path: relative.clone(),
                    kind: UnsafeFileKind::Special,
                };
                return Err(if created_any {
                    FileToolError::EffectAppliedButUnverified {
                        path: path.to_path_buf(),
                        reason: error.to_string(),
                    }
                } else {
                    error
                });
            }
        }
        let metadata = directory.dir_metadata().map_err(|error| {
            parent_mutation_error(path, "inspect target parent", &error, created_any)
        })?;
        Ok(ParentHandle {
            identity: object_identity(&metadata),
            directory,
            relative,
            leaf,
        })
    }

    fn verify_parent(&self, expected: &ParentHandle) -> Result<(), FileToolError> {
        let directory = self.reopen_directory(&expected.relative)?;
        let metadata = directory
            .dir_metadata()
            .map_err(|error| io_error("revalidate target parent", &expected.relative, &error))?;
        if object_identity(&metadata) != expected.identity {
            return Err(FileToolError::PrivateRoot(format!(
                "target parent {} was replaced",
                expected.relative.display()
            )));
        }
        Ok(())
    }

    fn reopen_directory(&self, relative: &Path) -> Result<Dir, FileToolError> {
        let mut directory = self
            .root
            .try_clone()
            .map_err(|error| io_error("clone private-root capability", relative, &error))?;
        for component in relative.components() {
            let Component::Normal(name) = component else {
                return Err(FileToolError::InvalidPath {
                    path: relative.to_path_buf(),
                    reason: "parent revalidation saw a non-normal component".into(),
                });
            };
            directory = directory.open_dir_nofollow(name).map_err(|error| {
                io_error("reopen parent without following links", relative, &error)
            })?;
        }
        Ok(directory)
    }

    fn verify_leaf_identity(
        parent: &ParentHandle,
        expected: ObjectIdentity,
        path: &Path,
    ) -> Result<(), FileToolError> {
        let metadata = parent
            .directory
            .symlink_metadata(&parent.leaf)
            .map_err(|error| io_error("revalidate file name", path, &error))?;
        validate_regular_metadata(path, &metadata)?;
        if object_identity(&metadata) != expected {
            return Err(FileToolError::UnstableRead(path.to_path_buf()));
        }
        Ok(())
    }
}

fn descend_parent_component(
    current: &Dir,
    name: &OsStr,
    target: &Path,
    create_missing: bool,
    parent_previously_created: bool,
) -> Result<(Dir, bool), FileToolError> {
    match current.open_dir_nofollow(name) {
        Ok(next) => return Ok((next, false)),
        Err(error) if create_missing && error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => {
            return Err(parent_mutation_error(
                target,
                "open shadow parent without following links",
                &error,
                parent_previously_created,
            ));
        }
    }

    let created_here = match current.create_dir(name) {
        Ok(()) => true,
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => false,
        Err(error) => {
            return Err(parent_mutation_error(
                target,
                "create shadow parent",
                &error,
                parent_previously_created,
            ));
        }
    };
    let any_created = parent_previously_created || created_here;
    if created_here {
        sync_directory(current).map_err(|error| {
            parent_mutation_error(target, "sync new shadow parent", &error, true)
        })?;
    }
    let next = current.open_dir_nofollow(name).map_err(|error| {
        parent_mutation_error(target, "open new shadow parent", &error, any_created)
    })?;
    if created_here {
        next.set_permissions(Path::new("."), Permissions::from_mode(0o700))
            .map_err(|error| {
                parent_mutation_error(target, "make shadow parent private", &error, true)
            })?;
        sync_directory(&next).map_err(|error| {
            parent_mutation_error(target, "sync private shadow parent", &error, true)
        })?;
    }
    Ok((next, created_here))
}

fn validate_authority(
    grant: &IssuedWorkspaceGrant,
    policy: &CompiledExecutionPolicy,
) -> Result<(), FileToolError> {
    grant
        .validate_integrity()
        .map_err(|error| FileToolError::Authority(error.to_string()))?;
    policy
        .validate_integrity(grant)
        .map_err(|error| FileToolError::Authority(error.to_string()))
}

fn normalize_tool_path(path: &Path) -> Result<PathBuf, FileToolError> {
    if path.is_absolute() {
        return Err(FileToolError::InvalidPath {
            path: path.to_path_buf(),
            reason: "absolute paths are forbidden".into(),
        });
    }
    let mut normalized = PathBuf::new();
    for component in path.components() {
        let Component::Normal(name) = component else {
            return Err(FileToolError::InvalidPath {
                path: path.to_path_buf(),
                reason: "`.` and `..` components are forbidden".into(),
            });
        };
        if name
            .to_str()
            .is_some_and(|text| text.eq_ignore_ascii_case(".git"))
        {
            return Err(FileToolError::InvalidPath {
                path: path.to_path_buf(),
                reason: "Git administrative paths are forbidden".into(),
            });
        }
        if name.as_bytes().contains(&0) || name.to_str().is_none() {
            return Err(FileToolError::InvalidPath {
                path: path.to_path_buf(),
                reason: "components must be NUL-free UTF-8".into(),
            });
        }
        normalized.push(name);
    }
    if normalized.as_os_str().is_empty() {
        return Err(FileToolError::InvalidPath {
            path: path.to_path_buf(),
            reason: "a regular-file target is required".into(),
        });
    }
    if normalized.as_os_str().as_bytes() != path.as_os_str().as_bytes() {
        return Err(FileToolError::InvalidPath {
            path: path.to_path_buf(),
            reason: "path must use its exact normalized spelling".into(),
        });
    }
    Ok(normalized)
}

fn scope_covers(scope: &PathScope, path: &Path) -> bool {
    match scope {
        PathScope::Workspace => true,
        PathScope::Relative(relative) => path == relative || path.starts_with(relative),
    }
}

fn validate_private_root_metadata(metadata: &Metadata) -> Result<RootIdentity, FileToolError> {
    if !metadata.is_dir() {
        return Err(FileToolError::PrivateRoot(
            "private-root descriptor is not a directory".into(),
        ));
    }
    let mode = OsMetadataExt::mode(metadata) & 0o777;
    if mode & 0o700 != 0o700 || mode & 0o077 != 0 {
        return Err(FileToolError::PrivateRoot(format!(
            "private root mode must grant owner rwx and deny group/other access, found {mode:04o}"
        )));
    }
    let uid = OsMetadataExt::uid(metadata);
    if uid != rustix::process::geteuid().as_raw() {
        return Err(FileToolError::PrivateRoot(
            "private root is not owned by the effective user".into(),
        ));
    }
    Ok(RootIdentity {
        object: object_identity(metadata),
        uid,
        mode,
    })
}

fn object_identity(metadata: &Metadata) -> ObjectIdentity {
    ObjectIdentity {
        device: PortableMetadataExt::dev(metadata),
        inode: PortableMetadataExt::ino(metadata),
    }
}

fn file_fingerprint(metadata: &Metadata) -> FileFingerprint {
    FileFingerprint {
        object: object_identity(metadata),
        links: PortableMetadataExt::nlink(metadata),
        length: metadata.len(),
        mode: OsMetadataExt::mode(metadata),
        modified_seconds: OsMetadataExt::mtime(metadata),
        modified_nanoseconds: OsMetadataExt::mtime_nsec(metadata),
        changed_seconds: OsMetadataExt::ctime(metadata),
        changed_nanoseconds: OsMetadataExt::ctime_nsec(metadata),
    }
}

fn validate_regular_metadata(path: &Path, metadata: &Metadata) -> Result<(), FileToolError> {
    let file_type = metadata.file_type();
    if file_type.is_symlink() {
        return Err(FileToolError::UnsafeFile {
            path: path.to_path_buf(),
            kind: UnsafeFileKind::Symlink,
        });
    }
    if file_type.is_dir() {
        return Err(FileToolError::UnsafeFile {
            path: path.to_path_buf(),
            kind: UnsafeFileKind::Directory,
        });
    }
    if !file_type.is_file() {
        return Err(FileToolError::UnsafeFile {
            path: path.to_path_buf(),
            kind: UnsafeFileKind::Special,
        });
    }
    if PortableMetadataExt::nlink(metadata) != 1 {
        return Err(FileToolError::UnsafeFile {
            path: path.to_path_buf(),
            kind: UnsafeFileKind::HardLink,
        });
    }
    Ok(())
}

fn stable_read(
    parent: &Dir,
    leaf: &OsStr,
    path: &Path,
    limit: u64,
) -> Result<(Vec<u8>, FileFingerprint), FileToolError> {
    let metadata = parent.symlink_metadata(leaf).map_err(|error| {
        if error.kind() == io::ErrorKind::NotFound {
            FileToolError::NotFound(path.to_path_buf())
        } else {
            io_error("inspect regular file without following links", path, &error)
        }
    })?;
    validate_regular_metadata(path, &metadata)?;
    if metadata.len() > limit {
        return Err(FileToolError::FileTooLarge {
            path: path.to_path_buf(),
            limit,
        });
    }

    let mut options = OpenOptions::new();
    options.read(true).follow(FollowSymlinks::No);
    let mut file = parent
        .open_with(leaf, &options)
        .map_err(|error| io_error("open regular file without following links", path, &error))?;
    let named = file_fingerprint(&metadata);
    let before = checked_file_metadata(&file, path, limit)?;
    if named.object != before.object {
        return Err(FileToolError::UnstableRead(path.to_path_buf()));
    }
    let first = read_bounded(&mut file, path, limit)?;
    let middle = checked_file_metadata(&file, path, limit)?;
    file.seek(SeekFrom::Start(0))
        .map_err(|error| io_error("rewind stable file read", path, &error))?;
    let second = read_bounded(&mut file, path, limit)?;
    let after = checked_file_metadata(&file, path, limit)?;
    if before != middle || middle != after || first != second {
        return Err(FileToolError::UnstableRead(path.to_path_buf()));
    }
    Ok((first, after))
}

fn checked_file_metadata(
    file: &File,
    path: &Path,
    limit: u64,
) -> Result<FileFingerprint, FileToolError> {
    let metadata = file
        .metadata()
        .map_err(|error| io_error("inspect open regular file", path, &error))?;
    validate_regular_metadata(path, &metadata)?;
    if metadata.len() > limit {
        return Err(FileToolError::FileTooLarge {
            path: path.to_path_buf(),
            limit,
        });
    }
    Ok(file_fingerprint(&metadata))
}

fn read_bounded(file: &mut File, path: &Path, limit: u64) -> Result<Vec<u8>, FileToolError> {
    let capacity = usize::try_from(limit.min(64 * 1024)).expect("bounded capacity fits usize");
    let mut bytes = Vec::with_capacity(capacity);
    file.take(limit.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|error| io_error("read complete regular file", path, &error))?;
    if u64::try_from(bytes.len()).expect("usize fits u64") > limit {
        return Err(FileToolError::FileTooLarge {
            path: path.to_path_buf(),
            limit,
        });
    }
    Ok(bytes)
}

fn literal_matches(
    path: &Path,
    bytes: &[u8],
    needle: &[u8],
    limit: usize,
) -> Result<Vec<LiteralMatch>, FileToolError> {
    let mut prefix = vec![0_usize; needle.len()];
    let mut matched_prefix = 0_usize;
    for index in 1..needle.len() {
        while matched_prefix > 0 && needle[index] != needle[matched_prefix] {
            matched_prefix = prefix[matched_prefix - 1];
        }
        if needle[index] == needle[matched_prefix] {
            matched_prefix += 1;
        }
        prefix[index] = matched_prefix;
    }

    let mut offsets = Vec::new();
    matched_prefix = 0;
    for (index, byte) in bytes.iter().copied().enumerate() {
        while matched_prefix > 0 && byte != needle[matched_prefix] {
            matched_prefix = prefix[matched_prefix - 1];
        }
        if byte == needle[matched_prefix] {
            matched_prefix += 1;
        }
        if matched_prefix == needle.len() {
            if offsets.len() == limit {
                return Err(FileToolError::MatchLimitExceeded {
                    path: path.to_path_buf(),
                    limit,
                });
            }
            offsets.push(index + 1 - needle.len());
            matched_prefix = prefix[matched_prefix - 1];
        }
    }

    let mut results = Vec::with_capacity(offsets.len());
    let mut next_match = offsets.into_iter().peekable();
    let mut line = 1_u64;
    let mut column = 1_u64;
    for (offset, byte) in bytes.iter().copied().enumerate() {
        if next_match.peek() == Some(&offset) {
            results.push(LiteralMatch {
                byte_offset: u64::try_from(offset).expect("usize fits u64"),
                line,
                column,
            });
            let _ = next_match.next();
        }
        if byte == b'\n' {
            line = line.saturating_add(1);
            column = 1;
        } else {
            column = column.saturating_add(1);
        }
    }
    Ok(results)
}

fn write_temp(
    parent: &Dir,
    path: &Path,
    contents: &[u8],
    mode: u32,
) -> Result<OsString, FileToolError> {
    for _ in 0..TEMP_ATTEMPTS {
        let number = NEXT_TEMP.fetch_add(1, Ordering::Relaxed);
        let name = OsString::from(format!(".grok-build-tmp-{}-{number}", std::process::id()));
        let mut options = OpenOptions::new();
        options
            .read(true)
            .write(true)
            .create_new(true)
            .follow(FollowSymlinks::No);
        match parent.open_with(&name, &options) {
            Ok(mut file) => {
                let result = (|| {
                    file.set_permissions(Permissions::from_mode(mode & 0o777))
                        .map_err(|error| io_error("set temporary-file mode", path, &error))?;
                    file.write_all(contents)
                        .map_err(|error| io_error("write complete temporary file", path, &error))?;
                    file.sync_all()
                        .map_err(|error| io_error("sync complete temporary file", path, &error))?;
                    file.seek(SeekFrom::Start(0))
                        .map_err(|error| io_error("rewind temporary file", path, &error))?;
                    let verified = read_bounded(
                        &mut file,
                        path,
                        u64::try_from(contents.len()).expect("usize fits u64"),
                    )?;
                    let metadata = checked_file_metadata(
                        &file,
                        path,
                        u64::try_from(contents.len()).expect("usize fits u64"),
                    )?;
                    if verified != contents || metadata.links != 1 {
                        return Err(FileToolError::UnstableRead(path.to_path_buf()));
                    }
                    Ok(())
                })();
                if let Err(error) = result {
                    drop(file);
                    let _ = parent.remove_file(&name);
                    let _ = sync_directory(parent);
                    return Err(error);
                }
                return Ok(name);
            }
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(io_error("create private temporary file", path, &error)),
        }
    }
    Err(FileToolError::Io {
        operation: "allocate private temporary-file name",
        path: path.to_path_buf(),
        message: format!("all {TEMP_ATTEMPTS} create-new attempts collided"),
    })
}

fn parent_mutation_error(
    path: &Path,
    operation: &'static str,
    error: &impl Display,
    parent_created: bool,
) -> FileToolError {
    if parent_created {
        FileToolError::EffectAppliedButUnverified {
            path: path.to_path_buf(),
            reason: format!("{operation} failed after creating a parent directory: {error}"),
        }
    } else {
        io_error(operation, path, error)
    }
}

fn ambiguous_effect_error(
    path: &Path,
    operation: &'static str,
    error: &impl Display,
) -> FileToolError {
    FileToolError::EffectAppliedButUnverified {
        path: path.to_path_buf(),
        reason: format!(
            "{operation} returned an ambiguous error; reconcile target and temporary state before replay: {error}"
        ),
    }
}

fn io_error(operation: &'static str, path: &Path, error: &impl Display) -> FileToolError {
    FileToolError::Io {
        operation,
        path: path.to_path_buf(),
        message: error.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{DirBuilderExt, PermissionsExt as StdPermissionsExt, symlink};
    use std::os::unix::net::UnixListener;

    use grok_build_core::{
        EnvironmentVariable, ExecutionNetwork, ExecutionPolicyCompiler, ExecutionPolicyRequest,
        ResourceLimits, WorkspaceGrantIssuer, WorkspaceGrantRequest, WorkspaceNetworkPolicy,
        WorkspacePermissions,
    };

    use crate::{CapabilityShadowStore, CapabilityWorkspace, WorkspaceManifest};

    static NEXT_DIRECTORY: AtomicU64 = AtomicU64::new(0);

    struct TestDirectory(PathBuf);

    impl TestDirectory {
        fn new(label: &str) -> Self {
            let sequence = NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "grok-build-file-tools-{label}-{}-{sequence}",
                std::process::id()
            ));
            let mut builder = fs::DirBuilder::new();
            builder.mode(0o700);
            builder.create(&path).expect("create private test root");
            Self(fs::canonicalize(path).expect("canonicalize private test root"))
        }
    }

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    struct Fixture {
        top: TestDirectory,
        live: PathBuf,
        shadow_path: PathBuf,
        grant: IssuedWorkspaceGrant,
        policy: CompiledExecutionPolicy,
        shadow: ShadowWorkspace,
    }

    impl Fixture {
        fn new(source: &[u8]) -> Self {
            let top = TestDirectory::new("fixture");
            let live = top.0.join("live");
            fs::create_dir(&live).expect("create live root");
            fs::create_dir(live.join("src")).expect("create live src");
            fs::write(live.join("src/lib.rs"), source).expect("write live source");
            fs::write(live.join("README.md"), b"live readme\n").expect("write live readme");
            let live = fs::canonicalize(live).expect("canonical live root");

            let grant = WorkspaceGrantIssuer::issue(WorkspaceGrantRequest {
                grant_id: "grant-file-tools".into(),
                workspace_root: live.clone(),
                permissions: WorkspacePermissions::trusted(),
                network: WorkspaceNetworkPolicy::Denied,
                policy_version: 1,
            })
            .expect("issue test grant");
            let policy = policy(
                &grant,
                MutationMode::ShadowWorkspace,
                vec![
                    PathScope::Relative(PathBuf::from("src")),
                    PathScope::Relative(PathBuf::from("docs")),
                    PathScope::Relative(PathBuf::from("README.md")),
                    PathScope::Relative(PathBuf::from("final")),
                    PathScope::Relative(PathBuf::from("hard")),
                    PathScope::Relative(PathBuf::from("socket")),
                    PathScope::Relative(PathBuf::from("large.txt")),
                    PathScope::Relative(PathBuf::from("search.txt")),
                    PathScope::Relative(PathBuf::from("created")),
                ],
            );
            let base = WorkspaceManifest::capture(&grant, 1).expect("capture base");
            let shadow_path = top.0.join("shadow");
            let shadow = ShadowWorkspace::create(&grant, &base, &shadow_path)
                .expect("create private shadow");
            Self {
                top,
                live,
                shadow_path,
                grant,
                policy,
                shadow,
            }
        }

        fn tools(&self) -> ShadowFileTools {
            ShadowFileTools::acquire(
                &self.grant,
                &self.policy,
                &self.shadow,
                FileToolLimits::new(1024 * 1024, 1024 * 1024, 1024).expect("valid file limits"),
            )
            .expect("acquire file tools")
        }
    }

    fn policy(
        grant: &IssuedWorkspaceGrant,
        mode: MutationMode,
        write_scopes: Vec<PathScope>,
    ) -> CompiledExecutionPolicy {
        ExecutionPolicyCompiler::compile(
            grant,
            ExecutionPolicyRequest {
                policy_id: format!("policy-file-tools-{mode:?}"),
                read_scopes: vec![PathScope::Workspace],
                write_scopes,
                environment: vec![EnvironmentVariable {
                    name: "PATH".into(),
                    value: "/usr/bin:/bin".into(),
                }],
                network: ExecutionNetwork::None,
                mutation_mode: mode,
                resource_limits: ResourceLimits {
                    wall_time_ms: 1_000,
                    max_output_bytes: 1024 * 1024,
                    max_processes: 1,
                    max_memory_bytes: None,
                },
                approval_id: None,
            },
        )
        .expect("compile file-tool policy")
    }

    #[test]
    fn complete_read_and_literal_positions_are_runner_computed() {
        let fixture = Fixture::new("zero\nalpha α\nalphaalpha\n".as_bytes());
        let tools = fixture.tools();

        let read = tools
            .read_regular_file(&fixture.grant, &fixture.policy, "src/lib.rs", 1024)
            .expect("complete stable read");
        assert_eq!(read.bytes, "zero\nalpha α\nalphaalpha\n".as_bytes());
        assert_eq!(read.digest, Digest::sha256(&read.bytes));

        let search = tools
            .search_literal(
                &fixture.grant,
                &fixture.policy,
                "src/lib.rs",
                b"alpha",
                1024,
                10,
            )
            .expect("complete literal search");
        assert_eq!(
            search.matches,
            vec![
                LiteralMatch {
                    byte_offset: 5,
                    line: 2,
                    column: 1,
                },
                LiteralMatch {
                    byte_offset: 14,
                    line: 3,
                    column: 1,
                },
                LiteralMatch {
                    byte_offset: 19,
                    line: 3,
                    column: 6,
                },
            ]
        );
        let utf8 = tools
            .search_literal(
                &fixture.grant,
                &fixture.policy,
                "src/lib.rs",
                "α".as_bytes(),
                1024,
                10,
            )
            .expect("byte-coordinate UTF-8 search");
        assert_eq!(
            utf8.matches,
            vec![LiteralMatch {
                byte_offset: 11,
                line: 2,
                column: 7,
            }]
        );
    }

    #[test]
    fn create_replace_delete_are_durable_in_shadow_and_never_touch_live() {
        let original_source = b"pub fn status() -> &'static str { \"TODO\" }\n";
        let fixture = Fixture::new(original_source);
        let tools = fixture.tools();
        let replacement = b"pub fn status() -> &'static str { \"ready\" }\n";

        let replaced = tools
            .replace_regular_file(
                &fixture.grant,
                &fixture.policy,
                "src/lib.rs",
                &Digest::sha256(original_source),
                replacement,
            )
            .expect("replace shadow source");
        assert_eq!(
            replaced.previous_digest,
            Some(Digest::sha256(original_source))
        );
        assert_eq!(replaced.result_digest, Some(Digest::sha256(replacement)));

        let created = tools
            .create_regular_file(
                &fixture.grant,
                &fixture.policy,
                "docs/report.txt",
                b"walking skeleton complete\n",
            )
            .expect("create nested shadow report");
        assert_eq!(created.previous_digest, None);
        assert_eq!(
            created.result_digest,
            Some(Digest::sha256(b"walking skeleton complete\n"))
        );

        let deleted = tools
            .delete_regular_file(
                &fixture.grant,
                &fixture.policy,
                "README.md",
                &Digest::sha256(b"live readme\n"),
            )
            .expect("delete shadow readme");
        assert_eq!(deleted.result_digest, None);

        assert_eq!(
            fs::read(fixture.shadow_path.join("src/lib.rs")).unwrap(),
            replacement
        );
        assert_eq!(
            fs::read(fixture.shadow_path.join("docs/report.txt")).unwrap(),
            b"walking skeleton complete\n"
        );
        assert!(!fixture.shadow_path.join("README.md").exists());
        assert_eq!(
            fs::read(fixture.live.join("src/lib.rs")).unwrap(),
            original_source
        );
        assert_eq!(
            fs::read(fixture.live.join("README.md")).unwrap(),
            b"live readme\n"
        );
        assert!(!fixture.live.join("docs/report.txt").exists());

        let report_mode = fs::metadata(fixture.shadow_path.join("docs/report.txt"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(report_mode, 0o600);
        assert!(fs::read_dir(&fixture.shadow_path).unwrap().all(|entry| {
            !entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .starts_with(".grok-build-tmp-")
        }));
    }

    #[test]
    fn stale_hashes_and_create_collisions_leave_existing_bytes_unchanged() {
        let fixture = Fixture::new(b"current\n");
        let tools = fixture.tools();
        let stale = Digest::sha256(b"stale\n");

        assert!(matches!(
            tools.replace_regular_file(
                &fixture.grant,
                &fixture.policy,
                "src/lib.rs",
                &stale,
                b"replacement\n"
            ),
            Err(FileToolError::PreconditionFailed { .. })
        ));
        assert!(matches!(
            tools.delete_regular_file(&fixture.grant, &fixture.policy, "src/lib.rs", &stale),
            Err(FileToolError::PreconditionFailed { .. })
        ));
        assert!(matches!(
            tools.create_regular_file(
                &fixture.grant,
                &fixture.policy,
                "src/lib.rs",
                b"replacement\n"
            ),
            Err(FileToolError::AlreadyExists(_))
        ));
        assert_eq!(
            fs::read(fixture.shadow_path.join("src/lib.rs")).unwrap(),
            b"current\n"
        );
    }

    #[test]
    fn lexical_and_policy_scope_checks_fail_before_filesystem_access() {
        let fixture = Fixture::new(b"current\n");
        let restricted = policy(
            &fixture.grant,
            MutationMode::ShadowWorkspace,
            vec![PathScope::Relative(PathBuf::from("src"))],
        );
        let tools = ShadowFileTools::acquire(
            &fixture.grant,
            &restricted,
            &fixture.shadow,
            FileToolLimits::new(1024, 1024, 16).unwrap(),
        )
        .unwrap();

        for path in [
            "../outside",
            "/tmp/outside",
            ".git/config",
            ".GIT/config",
            "src/../outside",
            "src//lib.rs",
            "src/./lib.rs",
            "src/lib.rs/",
        ] {
            assert!(matches!(
                tools.read_regular_file(&fixture.grant, &restricted, path, 1024),
                Err(FileToolError::InvalidPath { .. })
            ));
        }
        assert!(matches!(
            tools.create_regular_file(&fixture.grant, &restricted, "docs/report.txt", b"no\n"),
            Err(FileToolError::ScopeDenied { write: true, .. })
        ));
        assert!(!fixture.shadow_path.join("docs").exists());
    }

    #[test]
    fn final_and_intermediate_links_hardlinks_and_special_files_fail_closed() {
        let fixture = Fixture::new(b"current\n");
        let tools = fixture.tools();
        let outside = fixture.top.0.join("outside");
        fs::create_dir(&outside).unwrap();
        fs::write(outside.join("secret"), b"outside\n").unwrap();

        symlink(outside.join("secret"), fixture.shadow_path.join("final")).unwrap();
        assert!(matches!(
            tools.read_regular_file(&fixture.grant, &fixture.policy, "final", 1024),
            Err(FileToolError::UnsafeFile {
                kind: UnsafeFileKind::Symlink,
                ..
            })
        ));
        assert!(matches!(
            tools.replace_regular_file(
                &fixture.grant,
                &fixture.policy,
                "final",
                &Digest::sha256(b"outside\n"),
                b"changed\n"
            ),
            Err(FileToolError::UnsafeFile {
                kind: UnsafeFileKind::Symlink,
                ..
            })
        ));
        assert_eq!(fs::read(outside.join("secret")).unwrap(), b"outside\n");

        fs::rename(
            fixture.shadow_path.join("src"),
            fixture.shadow_path.join("src-real"),
        )
        .unwrap();
        symlink(&outside, fixture.shadow_path.join("src")).unwrap();
        assert!(
            tools
                .replace_regular_file(
                    &fixture.grant,
                    &fixture.policy,
                    "src/secret",
                    &Digest::sha256(b"outside\n"),
                    b"changed\n"
                )
                .is_err()
        );
        assert_eq!(fs::read(outside.join("secret")).unwrap(), b"outside\n");

        fs::write(outside.join("hard-source"), b"hard\n").unwrap();
        fs::hard_link(
            outside.join("hard-source"),
            fixture.shadow_path.join("hard"),
        )
        .unwrap();
        assert!(matches!(
            tools.read_regular_file(&fixture.grant, &fixture.policy, "hard", 1024),
            Err(FileToolError::UnsafeFile {
                kind: UnsafeFileKind::HardLink,
                ..
            })
        ));

        let socket_path = std::env::temp_dir().join(format!(
            "gb-ft-sock-{}-{}",
            std::process::id(),
            NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed)
        ));
        let _listener = UnixListener::bind(&socket_path).unwrap();
        fs::rename(&socket_path, fixture.shadow_path.join("socket")).unwrap();
        assert!(matches!(
            tools.read_regular_file(&fixture.grant, &fixture.policy, "socket", 1024),
            Err(FileToolError::UnsafeFile {
                kind: UnsafeFileKind::Special,
                ..
            })
        ));
    }

    #[test]
    fn root_name_replacement_invalidates_retained_capability() {
        let fixture = Fixture::new(b"current\n");
        let tools = fixture.tools();
        let moved = fixture.top.0.join("shadow-moved");
        fs::rename(&fixture.shadow_path, &moved).unwrap();
        let mut builder = fs::DirBuilder::new();
        builder.mode(0o700);
        builder.create(&fixture.shadow_path).unwrap();
        fs::create_dir(fixture.shadow_path.join("src")).unwrap();
        fs::write(
            fixture.shadow_path.join("src/lib.rs"),
            b"replacement-root\n",
        )
        .unwrap();

        assert!(matches!(
            tools.read_regular_file(&fixture.grant, &fixture.policy, "src/lib.rs", 1024),
            Err(FileToolError::PrivateRoot(_))
        ));
        assert_eq!(fs::read(moved.join("src/lib.rs")).unwrap(), b"current\n");
    }

    #[test]
    fn byte_and_match_bounds_never_return_partial_results() {
        let fixture = Fixture::new(b"current\n");
        fs::write(fixture.shadow_path.join("large.txt"), vec![b'x'; 32]).unwrap();
        fs::write(fixture.shadow_path.join("search.txt"), b"aaaa").unwrap();
        let tools = ShadowFileTools::acquire(
            &fixture.grant,
            &fixture.policy,
            &fixture.shadow,
            FileToolLimits::new(64, 8, 8).unwrap(),
        )
        .unwrap();

        assert!(matches!(
            tools.read_regular_file(&fixture.grant, &fixture.policy, "large.txt", 16),
            Err(FileToolError::FileTooLarge { limit: 16, .. })
        ));
        assert!(matches!(
            tools.search_literal(
                &fixture.grant,
                &fixture.policy,
                "search.txt",
                &vec![b'a'; HARD_MAX_LITERAL_BYTES + 1],
                16,
                2
            ),
            Err(FileToolError::InvalidLimit(_))
        ));
        assert!(matches!(
            tools.search_literal(&fixture.grant, &fixture.policy, "search.txt", b"aa", 16, 2),
            Err(FileToolError::MatchLimitExceeded { limit: 2, .. })
        ));
        assert!(matches!(
            tools.create_regular_file(
                &fixture.grant,
                &fixture.policy,
                "docs/report.txt",
                b"123456789"
            ),
            Err(FileToolError::FileTooLarge { limit: 8, .. })
        ));
        assert!(!fixture.shadow_path.join("docs").exists());
    }

    #[test]
    fn created_parent_side_effects_are_never_reported_as_replay_safe() {
        let fixture = Fixture::new(b"current\n");
        let tools = fixture.tools();
        let oversized_component = "x".repeat(256);
        let path = PathBuf::from("created")
            .join(oversized_component)
            .join("report.txt");

        assert!(matches!(
            tools.create_regular_file(&fixture.grant, &fixture.policy, &path, b"report\n"),
            Err(FileToolError::EffectAppliedButUnverified { .. })
        ));
        assert!(fixture.shadow_path.join("created").is_dir());
        assert!(!fixture.live.join("created").exists());
    }

    #[test]
    fn ambiguous_mutation_errors_require_reconciliation_before_replay() {
        let error = ambiguous_effect_error(
            Path::new("src/lib.rs"),
            "atomic replacement rename",
            &io::Error::from(io::ErrorKind::Interrupted),
        );
        assert!(matches!(
            error,
            FileToolError::EffectAppliedButUnverified { ref reason, .. }
                if reason.contains("reconcile target and temporary state before replay")
        ));
    }

    #[test]
    fn read_only_and_different_authority_cannot_use_acquired_boundary() {
        let fixture = Fixture::new(b"current\n");
        let read_only = policy(&fixture.grant, MutationMode::ReadOnly, Vec::new());
        assert!(matches!(
            ShadowFileTools::acquire(
                &fixture.grant,
                &read_only,
                &fixture.shadow,
                FileToolLimits::new(1024, 1024, 16).unwrap()
            ),
            Err(FileToolError::ShadowModeRequired)
        ));

        let tools = fixture.tools();
        let other_grant = WorkspaceGrantIssuer::issue(WorkspaceGrantRequest {
            grant_id: "other-grant".into(),
            workspace_root: fixture.live.clone(),
            permissions: WorkspacePermissions::trusted(),
            network: WorkspaceNetworkPolicy::Denied,
            policy_version: 1,
        })
        .unwrap();
        let other_policy = policy(
            &other_grant,
            MutationMode::ShadowWorkspace,
            vec![PathScope::Relative(PathBuf::from("src"))],
        );
        assert!(matches!(
            tools.read_regular_file(&other_grant, &other_policy, "src/lib.rs", 1024),
            Err(FileToolError::Authority(_))
        ));
    }

    #[test]
    fn non_private_shadow_mode_is_rejected_at_acquisition() {
        let fixture = Fixture::new(b"current\n");
        fs::set_permissions(&fixture.shadow_path, fs::Permissions::from_mode(0o755)).unwrap();
        assert!(matches!(
            ShadowFileTools::acquire(
                &fixture.grant,
                &fixture.policy,
                &fixture.shadow,
                FileToolLimits::new(1024, 1024, 16).unwrap()
            ),
            Err(FileToolError::PrivateRoot(_))
        ));
    }

    #[test]
    fn capability_constructor_drives_tools_and_detects_state_ancestor_moves() {
        let top = TestDirectory::new("capability-constructor");
        let live = top.0.join("live");
        fs::create_dir(&live).unwrap();
        fs::create_dir(live.join("src")).unwrap();
        fs::write(live.join("src/lib.rs"), b"before\n").unwrap();
        let state_parent = top.0.join("state-parent");
        fs::create_dir(&state_parent).unwrap();
        let store_path = state_parent.join("store");
        let mut builder = fs::DirBuilder::new();
        builder.mode(0o700);
        builder.create(&store_path).unwrap();
        fs::set_permissions(&store_path, fs::Permissions::from_mode(0o700)).unwrap();
        let live = fs::canonicalize(live).unwrap();
        let grant = WorkspaceGrantIssuer::issue(WorkspaceGrantRequest {
            grant_id: "capability-file-tools".into(),
            workspace_root: live.clone(),
            permissions: WorkspacePermissions::trusted(),
            network: WorkspaceNetworkPolicy::Denied,
            policy_version: 1,
        })
        .unwrap();
        let policy = policy(
            &grant,
            MutationMode::ShadowWorkspace,
            vec![
                PathScope::Relative(PathBuf::from("src")),
                PathScope::Relative(PathBuf::from("docs")),
            ],
        );
        let workspace = CapabilityWorkspace::open(grant.clone()).unwrap();
        let store = CapabilityShadowStore::open(&store_path).unwrap();
        let base = workspace.capture(&grant, 1).unwrap();
        let mut shadow = workspace
            .create_shadow(&grant, &base, &store, "worker-one")
            .unwrap();
        let tools = ShadowFileTools::acquire_capability(
            &grant,
            &policy,
            &shadow,
            FileToolLimits::new(1024 * 1024, 1024 * 1024, 1024).unwrap(),
        )
        .unwrap();

        let before = tools
            .read_regular_file(&grant, &policy, "src/lib.rs", 1024)
            .unwrap();
        tools
            .replace_regular_file(&grant, &policy, "src/lib.rs", &before.digest, b"after\n")
            .unwrap();
        tools
            .create_regular_file(&grant, &policy, "docs/report.txt", b"report\n")
            .unwrap();
        let staged = shadow
            .stage_changes(&grant, "capability-file-tools-stage", 2)
            .unwrap();
        assert_eq!(staged.change_set().operations.len(), 2);
        assert_eq!(fs::read(live.join("src/lib.rs")).unwrap(), b"before\n");
        assert!(!live.join("docs/report.txt").exists());

        fs::rename(&state_parent, top.0.join("moved-state-parent")).unwrap();
        fs::create_dir(&state_parent).unwrap();
        assert!(matches!(
            tools.read_regular_file(&grant, &policy, "src/lib.rs", 1024),
            Err(FileToolError::PrivateRoot(_))
        ));
    }
}
