//! Capture-ID-bound durable journal for complete command output.
//!
//! This module is a child of `command_output_store` so it can reuse the
//! retained private-root capability and the store's exact metadata checks.
//! Journal records are immutable, canonical JSON files joined by a
//! predecessor digest. The journal directory survives removal of its separate
//! working directory, allowing restart reconciliation by one caller-supplied
//! capture ID without scanning source identities or temporary names.

use std::collections::BTreeSet;
use std::fmt::{self, Display, Formatter};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::Path;

use cap_fs_ext::{DirExt, FollowSymlinks, OpenOptionsFollowExt, OsMetadataExt};
use cap_std::fs::Permissions;
use cap_std::fs::{Dir, DirBuilder, DirBuilderExt, File, OpenOptions, PermissionsExt};
use grok_build_core::{
    CommandOutputArtifactSetReferenceV1, CommandOutputArtifactSourceV1,
    CommandOutputCaptureAcquiredV1, CommandOutputCaptureDirectoryIdentityV1,
    CommandOutputCaptureFileIdentityV1, CommandOutputCaptureIntentV1,
    CommandOutputCaptureLaunchHistoryV1, CommandOutputCapturePendingResolutionV1,
    CommandOutputCapturePhysicalHistoryEntryV1, CommandOutputCapturePhysicalReconciliationV1,
    CommandOutputCapturePhysicalResolutionActionV1, CommandOutputCapturePhysicalTerminalEvidenceV1,
    CommandOutputCaptureReconciliationClaimV1, CommandOutputCaptureRestartLaunchEvidenceV1,
    CommandOutputCaptureRestartStateV1, CommandOutputCaptureStoreHeadV1,
    CommandOutputStreamArtifactV1, Digest,
};
use rustix::fs::{FlockOperation, RenameFlags, flock, renameat_with};
use serde::{Deserialize, Serialize};

use super::{
    CapabilityCommandOutputStore, CommandOutputStoreError, MANIFEST_FILE, MAX_MANIFEST_BYTES,
    ObjectIdentity, PrivateDirectoryIdentity, PrivateFileIdentity, STDERR_FILE, STDOUT_FILE,
    create_private_file, io_error, open_private_file, source_name_digest, sync_directory,
    validate_private_directory, validate_private_file, validate_unlinked_private_directory,
    validate_unlinked_private_file,
};

pub(super) const CAPTURE_JOURNAL_FORMAT_VERSION: u32 = 1;
pub(super) const JOURNAL_PREFIX: &str = "command-output-capture-journal-";
pub(super) const WORKING_PREFIX: &str = ".command-output-capture-";
const LOCK_FILE: &str = "writer.lock";
const RECORD_PREFIX: &str = "record-";
const RECORD_SUFFIX: &str = ".json";
const RECORD_DIGITS: usize = 20;
const FENCE_PREFIX: &str = "recovery-fence-";
const FENCE_SUFFIX: &str = ".json";
const FENCE_DIGEST_DOMAIN: &[u8] = b"grok-build/command-output-capture-recovery-fence/v1\0";
const CLEANUP_PLAN_DIGEST_DOMAIN: &[u8] = b"grok-build/command-output-capture-cleanup-plan/v1\0";
const CLEANUP_ENTRY_SET_DIGEST_DOMAIN: &[u8] =
    b"grok-build/command-output-capture-cleanup-entry-set/v1\0";
const RESTART_ABSENCE_DIGEST_DOMAIN: &[u8] =
    b"grok-build/command-output-capture-restart-absence/v1\0";
const RESTART_COMPLETION_DIGEST_DOMAIN: &[u8] =
    b"grok-build/command-output-capture-restart-completion/v1\0";
const CLEANUP_COMPLETION_PROOF_DIGEST_DOMAIN: &[u8] =
    b"grok-build/command-output-capture-cleanup-completion-proof/v1\0";
const MAX_RECOVERY_FENCES: usize = 4096;
const RECORD_DIGEST_DOMAIN: &[u8] = b"grok-build/command-output-capture-journal/v1\0";
const DISPATCH_CLAIM_ID_DOMAIN: &[u8] = b"grok-build/runner-effect-dispatch-claim/v1\0";
// serde's canonical JSON representation of `Vec<u8>` uses decimal integers.
// The worst case is four bytes per input byte (`255,`) plus delimiters. This
// bound therefore admits the 7-MiB terminal payload with more than 4 MiB of
// fixed-field headroom while remaining finite and checked before allocation.
pub(super) const MAX_RECORD_BYTES: u64 = 32 * 1024 * 1024;
const MAX_RECORDS: usize = 8;
pub(super) const MAX_CAPTURE_TERMINAL_PAYLOAD_BYTES: usize = 7 * 1024 * 1024;
pub(super) const MAX_CAPTURE_BINDING_PAYLOAD_BYTES: usize =
    crate::wire::MAX_CONTAINED_CAPTURE_LAUNCH_BINDING_BYTES;
const MAX_SCHEMA_BYTES: usize = 128;

/// Caller-allocated 256-bit identity for exactly one command-output capture.
#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct CommandOutputCaptureId(String);

impl CommandOutputCaptureId {
    /// Parses the unique canonical 64-character lowercase hexadecimal form.
    ///
    /// # Errors
    ///
    /// Returns a source-contract error unless `value` is one canonical
    /// lowercase SHA-256 digest.
    pub fn parse(value: impl Into<String>) -> Result<Self, CommandOutputStoreError> {
        let value = value.into();
        Digest::parse(value.clone()).map_err(|error| {
            CommandOutputStoreError::Source(format!("capture_id is invalid: {error}"))
        })?;
        Ok(Self(value))
    }

    /// Returns the canonical lowercase hexadecimal value.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Display for CommandOutputCaptureId {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

/// Stable filesystem object identity retained in journal evidence.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct StoredObjectIdentityV1 {
    /// Filesystem device number.
    pub device: u64,
    /// Filesystem inode number.
    pub inode: u64,
    /// Effective-user owner observed at acquisition.
    pub uid: u32,
    /// Exact permission bits observed at acquisition.
    pub mode: u32,
    /// Exact link count observed at acquisition.
    pub link_count: u64,
    /// Exact byte length observed at acquisition.
    pub byte_length: u64,
}

impl StoredObjectIdentityV1 {
    fn from_directory(directory: &Dir) -> Result<Self, CommandOutputStoreError> {
        let metadata = directory.dir_metadata().map_err(|error| {
            CommandOutputStoreError::Root(format!(
                "inspect capture-journal directory identity: {error}"
            ))
        })?;
        Ok(Self {
            device: cap_fs_ext::MetadataExt::dev(&metadata),
            inode: cap_fs_ext::MetadataExt::ino(&metadata),
            uid: OsMetadataExt::uid(&metadata),
            mode: OsMetadataExt::mode(&metadata) & 0o7777,
            link_count: OsMetadataExt::nlink(&metadata),
            byte_length: metadata.len(),
        })
    }

    fn from_file(file: &File) -> Result<Self, CommandOutputStoreError> {
        let metadata = file.metadata().map_err(|error| {
            io_error(
                "inspect capture-journal file identity",
                Path::new("capture-object"),
                &error,
            )
        })?;
        Ok(Self {
            device: cap_fs_ext::MetadataExt::dev(&metadata),
            inode: cap_fs_ext::MetadataExt::ino(&metadata),
            uid: OsMetadataExt::uid(&metadata),
            mode: OsMetadataExt::mode(&metadata) & 0o7777,
            link_count: OsMetadataExt::nlink(&metadata),
            byte_length: metadata.len(),
        })
    }

    fn validate_directory_shape(self) -> Result<(), CommandOutputStoreError> {
        if self.device == 0
            || self.inode == 0
            || self.uid != rustix::process::geteuid().as_raw()
            || self.mode != 0o700
            || self.link_count < 1
        {
            return Err(CommandOutputStoreError::Manifest(
                "journaled directory identity is malformed or not private".into(),
            ));
        }
        Ok(())
    }

    fn is_same_directory_object(self, current: Self) -> bool {
        self.device == current.device
            && self.inode == current.inode
            && self.uid == current.uid
            && self.mode == current.mode
    }

    fn validate_file_shape(self, exact_length: u64) -> Result<(), CommandOutputStoreError> {
        if self.device == 0
            || self.inode == 0
            || self.uid != rustix::process::geteuid().as_raw()
            || self.mode != 0o600
            || self.link_count != 1
            || self.byte_length != exact_length
        {
            return Err(CommandOutputStoreError::Manifest(
                "journaled file identity is malformed or not private".into(),
            ));
        }
        Ok(())
    }

    fn validate_unlinked_directory_shape(self) -> Result<(), CommandOutputStoreError> {
        #[cfg(target_os = "macos")]
        let has_unlinked_shape = matches!(self.link_count, 0 | 2);
        #[cfg(not(target_os = "macos"))]
        let has_unlinked_shape = self.link_count == 0;
        if self.device == 0
            || self.inode == 0
            || self.uid != rustix::process::geteuid().as_raw()
            || self.mode != 0o700
            || !has_unlinked_shape
        {
            return Err(CommandOutputStoreError::Manifest(
                "journaled cleaned directory is not an exact unlinked private object".into(),
            ));
        }
        Ok(())
    }

    fn validate_unlinked_file_shape(self) -> Result<(), CommandOutputStoreError> {
        if self.device == 0
            || self.inode == 0
            || self.uid != rustix::process::geteuid().as_raw()
            || self.mode != 0o600
            || self.link_count != 0
        {
            return Err(CommandOutputStoreError::Manifest(
                "journaled cleaned file is not an exact unlinked private object".into(),
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct StoredWorkingSetIdentityV1 {
    pub(super) directory: CommandOutputCaptureDirectoryIdentityV1,
    pub(super) stdout: CommandOutputCaptureFileIdentityV1,
    pub(super) stderr: CommandOutputCaptureFileIdentityV1,
}

impl StoredWorkingSetIdentityV1 {
    fn validate(&self) -> Result<(), CommandOutputStoreError> {
        self.directory.validate().map_err(core_contract_error)?;
        self.stdout.validate().map_err(core_contract_error)?;
        self.stderr.validate().map_err(core_contract_error)?;
        if self.directory.device_id != self.stdout.device_id
            || self.directory.device_id != self.stderr.device_id
            || (self.stdout.device_id, self.stdout.inode)
                == (self.stderr.device_id, self.stderr.inode)
        {
            return Err(CommandOutputStoreError::Manifest(
                "journaled working set is crossed or spans devices".into(),
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct StoredCleanupProofV1 {
    directory: StoredObjectIdentityV1,
    stdout: StoredObjectIdentityV1,
    stderr: StoredObjectIdentityV1,
    manifest: Option<StoredObjectIdentityV1>,
}

impl StoredCleanupProofV1 {
    fn validate(&self) -> Result<(), CommandOutputStoreError> {
        self.directory.validate_unlinked_directory_shape()?;
        self.stdout.validate_unlinked_file_shape()?;
        self.stderr.validate_unlinked_file_shape()?;
        if let Some(manifest) = self.manifest {
            manifest.validate_unlinked_file_shape()?;
        }
        if (self.stdout.device, self.stdout.inode) == (self.stderr.device, self.stderr.inode)
            || (self.directory.device, self.directory.inode)
                == (self.stdout.device, self.stdout.inode)
            || (self.directory.device, self.directory.inode)
                == (self.stderr.device, self.stderr.inode)
        {
            return Err(CommandOutputStoreError::Manifest(
                "cleaned capture proof contains crossed object identities".into(),
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct StoredCleanupNamespacePlanV1 {
    directory: Option<StoredObjectIdentityV1>,
    stdout: Option<StoredObjectIdentityV1>,
    stderr: Option<StoredObjectIdentityV1>,
    manifest: Option<StoredObjectIdentityV1>,
    entry_names: BTreeSet<String>,
    entry_set_digest: Digest,
    planned_identity_digest: Digest,
}

#[derive(Serialize)]
struct CleanupPlanDigestPreimage<'a> {
    directory: Option<&'a StoredObjectIdentityV1>,
    stdout: Option<&'a StoredObjectIdentityV1>,
    stderr: Option<&'a StoredObjectIdentityV1>,
    manifest: Option<&'a StoredObjectIdentityV1>,
    entry_set_digest: &'a Digest,
}

impl StoredCleanupNamespacePlanV1 {
    fn try_new(
        directory: Option<StoredObjectIdentityV1>,
        stdout: Option<StoredObjectIdentityV1>,
        stderr: Option<StoredObjectIdentityV1>,
        manifest: Option<StoredObjectIdentityV1>,
        entry_names: BTreeSet<String>,
    ) -> Result<Self, CommandOutputStoreError> {
        let entry_set_digest = domain_separated_json_digest(
            CLEANUP_ENTRY_SET_DIGEST_DOMAIN,
            &entry_names,
            "cleanup entry-set",
        )?;
        let planned_identity_digest = domain_separated_json_digest(
            CLEANUP_PLAN_DIGEST_DOMAIN,
            &CleanupPlanDigestPreimage {
                directory: directory.as_ref(),
                stdout: stdout.as_ref(),
                stderr: stderr.as_ref(),
                manifest: manifest.as_ref(),
                entry_set_digest: &entry_set_digest,
            },
            "cleanup identity plan",
        )?;
        let plan = Self {
            directory,
            stdout,
            stderr,
            manifest,
            entry_names,
            entry_set_digest,
            planned_identity_digest,
        };
        plan.validate()?;
        Ok(plan)
    }

    fn validate(&self) -> Result<(), CommandOutputStoreError> {
        let expected_names = [
            self.stdout.as_ref().map(|_| STDOUT_FILE.to_string()),
            self.stderr.as_ref().map(|_| STDERR_FILE.to_string()),
            self.manifest.as_ref().map(|_| MANIFEST_FILE.to_string()),
        ]
        .into_iter()
        .flatten()
        .collect::<BTreeSet<_>>();
        if self.directory.is_none() {
            if self.stdout.is_some()
                || self.stderr.is_some()
                || self.manifest.is_some()
                || !self.entry_names.is_empty()
            {
                return Err(CommandOutputStoreError::Manifest(
                    "absent cleanup directory plan contains file identities".into(),
                ));
            }
        } else if self.entry_names != expected_names {
            return Err(CommandOutputStoreError::Manifest(
                "cleanup plan entry set differs from its exact file identities".into(),
            ));
        }
        if let Some(directory) = self.directory {
            directory.validate_directory_shape()?;
        }
        for file in [self.stdout, self.stderr, self.manifest]
            .into_iter()
            .flatten()
        {
            file.validate_file_shape(file.byte_length)?;
        }
        if self
            .stdout
            .zip(self.stderr)
            .is_some_and(|(stdout, stderr)| {
                (stdout.device, stdout.inode) == (stderr.device, stderr.inode)
            })
        {
            return Err(CommandOutputStoreError::Manifest(
                "cleanup plan crosses stdout and stderr identities".into(),
            ));
        }
        let expected_entry_set_digest = domain_separated_json_digest(
            CLEANUP_ENTRY_SET_DIGEST_DOMAIN,
            &self.entry_names,
            "cleanup entry-set",
        )?;
        let expected_plan_digest = domain_separated_json_digest(
            CLEANUP_PLAN_DIGEST_DOMAIN,
            &CleanupPlanDigestPreimage {
                directory: self.directory.as_ref(),
                stdout: self.stdout.as_ref(),
                stderr: self.stderr.as_ref(),
                manifest: self.manifest.as_ref(),
                entry_set_digest: &self.entry_set_digest,
            },
            "cleanup identity plan",
        )?;
        if self.entry_set_digest != expected_entry_set_digest
            || self.planned_identity_digest != expected_plan_digest
        {
            return Err(CommandOutputStoreError::Manifest(
                "cleanup plan digest differs from its exact identities or entry set".into(),
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "proof_kind", rename_all = "snake_case", deny_unknown_fields)]
enum StoredCleanupCompletionProofV1 {
    HeldDescriptorUnlink {
        planned_identity_digest: Digest,
        directory: Option<StoredObjectIdentityV1>,
        stdout: Option<StoredObjectIdentityV1>,
        stderr: Option<StoredObjectIdentityV1>,
        manifest: Option<StoredObjectIdentityV1>,
    },
    RestartNamespaceCompletion {
        cleanup_intent_digest: Digest,
        planned_identity_digest: Digest,
        exact_absence_digest: Digest,
        completion_digest: Digest,
    },
}

#[derive(Serialize)]
struct RestartAbsenceDigestPreimage<'a> {
    capture_id: &'a CommandOutputCaptureId,
    cleanup_intent_digest: &'a Digest,
    planned_identity_digest: &'a Digest,
    absent_working_name: &'a str,
}

#[derive(Serialize)]
#[allow(
    clippy::struct_field_names,
    reason = "each field is an independently domain-bound digest in the cleanup-completion preimage"
)]
struct RestartCompletionDigestPreimage<'a> {
    cleanup_intent_digest: &'a Digest,
    planned_identity_digest: &'a Digest,
    exact_absence_digest: &'a Digest,
}

fn domain_separated_json_digest(
    domain: &[u8],
    value: &impl Serialize,
    label: &str,
) -> Result<Digest, CommandOutputStoreError> {
    let canonical = serde_json::to_vec(value).map_err(|error| {
        CommandOutputStoreError::Manifest(format!("encode {label} digest preimage: {error}"))
    })?;
    let mut preimage = Vec::with_capacity(domain.len() + canonical.len());
    preimage.extend_from_slice(domain);
    preimage.extend_from_slice(&canonical);
    Ok(Digest::sha256(&preimage))
}

/// Generic exact bytes retained for a launch binding or terminal response.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CommandOutputCaptureCanonicalPayloadV1 {
    /// Versioned schema that uniquely defines the bytes.
    pub schema: String,
    /// Exact canonical bytes, encoded by serde as an integer array.
    pub canonical_bytes: Vec<u8>,
    /// SHA-256 commitment to the exact bytes.
    pub canonical_bytes_digest: Digest,
}

impl CommandOutputCaptureCanonicalPayloadV1 {
    /// Constructs a bounded schema-bound exact payload.
    ///
    /// # Errors
    ///
    /// Returns a manifest error for a malformed schema, empty or oversized
    /// bytes, or a payload whose digest cannot be constructed exactly.
    pub fn try_new(
        schema: impl Into<String>,
        canonical_bytes: Vec<u8>,
        maximum_bytes: usize,
    ) -> Result<Self, CommandOutputStoreError> {
        let payload = Self {
            schema: schema.into(),
            canonical_bytes_digest: Digest::sha256(&canonical_bytes),
            canonical_bytes,
        };
        payload.validate(maximum_bytes)?;
        Ok(payload)
    }

    fn validate(&self, maximum_bytes: usize) -> Result<(), CommandOutputStoreError> {
        if self.schema.is_empty()
            || self.schema.len() > MAX_SCHEMA_BYTES
            || !self.schema.bytes().all(|byte| {
                byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'/' | b'.')
            })
        {
            return Err(CommandOutputStoreError::Manifest(
                "capture payload schema must be a bounded nonempty ASCII token".into(),
            ));
        }
        if self.canonical_bytes.is_empty() || self.canonical_bytes.len() > maximum_bytes {
            return Err(CommandOutputStoreError::Manifest(format!(
                "capture payload must contain 1..={maximum_bytes} bytes"
            )));
        }
        if self.canonical_bytes_digest != Digest::sha256(&self.canonical_bytes) {
            return Err(CommandOutputStoreError::Manifest(
                "capture payload digest differs from its exact bytes".into(),
            ));
        }
        Ok(())
    }
}

/// Durable capture-journal state.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CommandOutputCaptureJournalStateV1 {
    /// Capture authority was durably bound before any working file existed.
    Intent,
    /// Exact empty working objects were durably acquired.
    Acquired,
    /// A runner reopened and took writer custody.
    WriterAttached,
    /// Native launch was durably intended.
    LaunchIntended,
    /// Both complete streams were synchronized and committed.
    Finished,
    /// The immutable artifact was published and exactly reopened.
    Published,
    /// Exact terminal response bytes were retained for reconstruction.
    TerminalPrepared,
    /// Exact cleanup was intended before namespace mutation.
    CleanupIntended,
    /// The original working objects were proven unlinked.
    Cleaned,
}

const fn core_restart_state(
    state: CommandOutputCaptureJournalStateV1,
) -> CommandOutputCaptureRestartStateV1 {
    match state {
        CommandOutputCaptureJournalStateV1::Intent => CommandOutputCaptureRestartStateV1::Intent,
        CommandOutputCaptureJournalStateV1::Acquired => {
            CommandOutputCaptureRestartStateV1::Acquired
        }
        CommandOutputCaptureJournalStateV1::WriterAttached => {
            CommandOutputCaptureRestartStateV1::WriterAttached
        }
        CommandOutputCaptureJournalStateV1::LaunchIntended => {
            CommandOutputCaptureRestartStateV1::LaunchIntended
        }
        CommandOutputCaptureJournalStateV1::Finished => {
            CommandOutputCaptureRestartStateV1::Finished
        }
        CommandOutputCaptureJournalStateV1::Published => {
            CommandOutputCaptureRestartStateV1::Published
        }
        CommandOutputCaptureJournalStateV1::TerminalPrepared => {
            CommandOutputCaptureRestartStateV1::TerminalPrepared
        }
        CommandOutputCaptureJournalStateV1::CleanupIntended => {
            CommandOutputCaptureRestartStateV1::CleanupIntended
        }
        CommandOutputCaptureJournalStateV1::Cleaned => CommandOutputCaptureRestartStateV1::Cleaned,
    }
}

/// Exact classification of one interrupted immutable record publication.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CommandOutputCapturePendingRecordClassV1 {
    /// Complete canonical successor bytes exist under their deterministic
    /// temporary name and may be rolled forward by a fenced recovery owner.
    ValidSuccessor,
    /// A deterministic temporary name exists but its bytes are torn or
    /// noncanonical; only exact held-descriptor cleanup may proceed.
    Torn,
}

/// Path-free description of one interrupted journal-record publication.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CommandOutputCapturePendingRecordV1 {
    sequence: u64,
    name_digest: Digest,
    class: CommandOutputCapturePendingRecordClassV1,
    candidate_state: Option<CommandOutputCaptureJournalStateV1>,
    candidate_digest: Option<Digest>,
}

impl CommandOutputCapturePendingRecordV1 {
    /// One-based candidate sequence parsed from the deterministic name.
    #[must_use]
    pub const fn sequence(&self) -> u64 {
        self.sequence
    }

    /// Digest embedded in the deterministic interrupted-publication name.
    #[must_use]
    pub const fn name_digest(&self) -> &Digest {
        &self.name_digest
    }

    /// Whether the retained bytes are a complete valid successor or torn.
    #[must_use]
    pub const fn class(&self) -> CommandOutputCapturePendingRecordClassV1 {
        self.class
    }

    /// Candidate lifecycle state when the exact bytes validated.
    #[must_use]
    pub const fn candidate_state(&self) -> Option<CommandOutputCaptureJournalStateV1> {
        self.candidate_state
    }

    /// Candidate record digest when the exact bytes validated.
    #[must_use]
    pub const fn candidate_digest(&self) -> Option<&Digest> {
        self.candidate_digest.as_ref()
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "state", rename_all = "snake_case", deny_unknown_fields)]
enum StoredCaptureRecordDataV1 {
    Intent {
        intent: CommandOutputCaptureIntentV1,
        journal_directory: StoredObjectIdentityV1,
        writer_lock: StoredObjectIdentityV1,
    },
    Acquired {
        dispatch_claim_id: String,
        acquired_at_unix_ms: u64,
        working_set: StoredWorkingSetIdentityV1,
    },
    WriterAttached,
    LaunchIntended {
        binding: CommandOutputCaptureCanonicalPayloadV1,
    },
    Finished {
        stdout: CommandOutputStreamArtifactV1,
        stderr: CommandOutputStreamArtifactV1,
    },
    Published {
        reference: CommandOutputArtifactSetReferenceV1,
        artifact_directory: StoredObjectIdentityV1,
    },
    TerminalPrepared {
        terminal: CommandOutputCaptureCanonicalPayloadV1,
    },
    CleanupIntended {
        working_set: Option<StoredWorkingSetIdentityV1>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        namespace_plan: Option<StoredCleanupNamespacePlanV1>,
    },
    Cleaned {
        working_set: Option<StoredWorkingSetIdentityV1>,
        cleanup_proof: Option<StoredCleanupProofV1>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        completion_proof: Option<StoredCleanupCompletionProofV1>,
    },
}

impl StoredCaptureRecordDataV1 {
    const fn state(&self) -> CommandOutputCaptureJournalStateV1 {
        match self {
            Self::Intent { .. } => CommandOutputCaptureJournalStateV1::Intent,
            Self::Acquired { .. } => CommandOutputCaptureJournalStateV1::Acquired,
            Self::WriterAttached => CommandOutputCaptureJournalStateV1::WriterAttached,
            Self::LaunchIntended { .. } => CommandOutputCaptureJournalStateV1::LaunchIntended,
            Self::Finished { .. } => CommandOutputCaptureJournalStateV1::Finished,
            Self::Published { .. } => CommandOutputCaptureJournalStateV1::Published,
            Self::TerminalPrepared { .. } => CommandOutputCaptureJournalStateV1::TerminalPrepared,
            Self::CleanupIntended { .. } => CommandOutputCaptureJournalStateV1::CleanupIntended,
            Self::Cleaned { .. } => CommandOutputCaptureJournalStateV1::Cleaned,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct StoredCaptureRecordV1 {
    format_version: u32,
    sequence: u64,
    capture_id: CommandOutputCaptureId,
    predecessor_digest: Option<Digest>,
    data: StoredCaptureRecordDataV1,
    record_digest: Digest,
}

#[derive(Serialize)]
struct CaptureRecordDigestPreimage<'a> {
    format_version: u32,
    sequence: u64,
    capture_id: &'a CommandOutputCaptureId,
    predecessor_digest: Option<&'a Digest>,
    data: &'a StoredCaptureRecordDataV1,
}

impl StoredCaptureRecordV1 {
    fn computed_digest(&self) -> Result<Digest, CommandOutputStoreError> {
        let canonical = serde_json::to_vec(&CaptureRecordDigestPreimage {
            format_version: self.format_version,
            sequence: self.sequence,
            capture_id: &self.capture_id,
            predecessor_digest: self.predecessor_digest.as_ref(),
            data: &self.data,
        })
        .map_err(|error| {
            CommandOutputStoreError::Manifest(format!(
                "capture record digest encoding failed: {error}"
            ))
        })?;
        let mut preimage = Vec::with_capacity(RECORD_DIGEST_DOMAIN.len() + canonical.len());
        preimage.extend_from_slice(RECORD_DIGEST_DOMAIN);
        preimage.extend_from_slice(&canonical);
        Ok(Digest::sha256(&preimage))
    }

    fn canonical_bytes(&self) -> Result<Vec<u8>, CommandOutputStoreError> {
        serde_json::to_vec(self).map_err(|error| {
            CommandOutputStoreError::Manifest(format!(
                "capture record canonical encoding failed: {error}"
            ))
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct StoredRecoveryFenceV1 {
    format_version: u32,
    capture_id: CommandOutputCaptureId,
    predecessor_fence_digest: Option<Digest>,
    claim: CommandOutputCaptureReconciliationClaimV1,
    fence_digest: Digest,
}

#[derive(Serialize)]
struct RecoveryFenceDigestPreimage<'a> {
    format_version: u32,
    capture_id: &'a CommandOutputCaptureId,
    predecessor_fence_digest: Option<&'a Digest>,
    claim: &'a CommandOutputCaptureReconciliationClaimV1,
}

impl StoredRecoveryFenceV1 {
    fn computed_digest(&self) -> Result<Digest, CommandOutputStoreError> {
        let canonical = serde_json::to_vec(&RecoveryFenceDigestPreimage {
            format_version: self.format_version,
            capture_id: &self.capture_id,
            predecessor_fence_digest: self.predecessor_fence_digest.as_ref(),
            claim: &self.claim,
        })
        .map_err(|error| {
            CommandOutputStoreError::Manifest(format!(
                "recovery fence digest encoding failed: {error}"
            ))
        })?;
        let mut preimage = Vec::with_capacity(FENCE_DIGEST_DOMAIN.len() + canonical.len());
        preimage.extend_from_slice(FENCE_DIGEST_DOMAIN);
        preimage.extend_from_slice(&canonical);
        Ok(Digest::sha256(&preimage))
    }

    fn canonical_bytes(&self) -> Result<Vec<u8>, CommandOutputStoreError> {
        serde_json::to_vec(self).map_err(|error| {
            CommandOutputStoreError::Manifest(format!(
                "recovery fence canonical encoding failed: {error}"
            ))
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct PendingRecordFile {
    name: String,
    identity: PrivateFileIdentity,
    sequence: u64,
    name_digest: Digest,
    record: Option<StoredCaptureRecordV1>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct PendingFenceFile {
    name: String,
    identity: PrivateFileIdentity,
    epoch: u64,
    fence: Option<StoredRecoveryFenceV1>,
}

impl PendingRecordFile {
    fn public_view(&self) -> CommandOutputCapturePendingRecordV1 {
        CommandOutputCapturePendingRecordV1 {
            sequence: self.sequence,
            name_digest: self.name_digest.clone(),
            class: if self.record.is_some() {
                CommandOutputCapturePendingRecordClassV1::ValidSuccessor
            } else {
                CommandOutputCapturePendingRecordClassV1::Torn
            },
            candidate_state: self.record.as_ref().map(|record| record.data.state()),
            candidate_digest: self
                .record
                .as_ref()
                .map(|record| record.record_digest.clone()),
        }
    }
}

/// Exact reconstructed journal head plus any durable terminal material.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CommandOutputCaptureRecovery {
    capture_id: CommandOutputCaptureId,
    source: CommandOutputArtifactSourceV1,
    authenticated_maximum_bytes: u64,
    state: CommandOutputCaptureJournalStateV1,
    store_head: CommandOutputCaptureStoreHeadV1,
    acquired: Option<CommandOutputCaptureAcquiredV1>,
    writer_attached_store_head: Option<CommandOutputCaptureStoreHeadV1>,
    expected_reference: Option<CommandOutputArtifactSetReferenceV1>,
    terminal: Option<CommandOutputCaptureCanonicalPayloadV1>,
    launch_intended: Option<CommandOutputCaptureCanonicalPayloadV1>,
    launch_intended_store_head: Option<CommandOutputCaptureStoreHeadV1>,
    finished_store_head: Option<CommandOutputCaptureStoreHeadV1>,
    published_store_head: Option<CommandOutputCaptureStoreHeadV1>,
    terminal_prepared_store_head: Option<CommandOutputCaptureStoreHeadV1>,
    pending_record: Option<CommandOutputCapturePendingRecordV1>,
    cleanup_intended_store_head: Option<CommandOutputCaptureStoreHeadV1>,
    cleaned_store_head: Option<CommandOutputCaptureStoreHeadV1>,
    physical_reconciliation: Option<PhysicalReconciliationContextV1>,
}

/// One claim-fenced Unknown-resolution transition and the inseparable physical
/// receipt reconstructed while the exact capture lease was held.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CommandOutputCaptureFencedResolution {
    recovery: CommandOutputCaptureRecovery,
    physical_reconciliation: CommandOutputCapturePhysicalReconciliationV1,
}

impl CommandOutputCaptureFencedResolution {
    /// Exact final durable capture cut produced or read back under the claim.
    #[must_use]
    pub const fn recovery(&self) -> &CommandOutputCaptureRecovery {
        &self.recovery
    }

    /// Full core physical receipt bound to the requested Unknown terminal head.
    #[must_use]
    pub const fn physical_reconciliation(&self) -> &CommandOutputCapturePhysicalReconciliationV1 {
        &self.physical_reconciliation
    }

    /// Consumes the joined result without projecting away either half.
    #[must_use]
    pub fn into_parts(
        self,
    ) -> (
        CommandOutputCaptureRecovery,
        CommandOutputCapturePhysicalReconciliationV1,
    ) {
        (self.recovery, self.physical_reconciliation)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct PhysicalReconciliationContextV1 {
    claim: CommandOutputCaptureReconciliationClaimV1,
    predecessor_fence_digest: Option<Digest>,
    physical_fence_chain_length: u64,
    physical_fence_digest: Digest,
    requested_store_head: Option<CommandOutputCaptureStoreHeadV1>,
    initial_state: Option<CommandOutputCaptureRestartStateV1>,
    initial_store_head: Option<CommandOutputCaptureStoreHeadV1>,
    pending_resolution: CommandOutputCapturePendingResolutionV1,
    resolution_action: CommandOutputCapturePhysicalResolutionActionV1,
    lifecycle_history: Vec<CommandOutputCapturePhysicalHistoryEntryV1>,
    cleanup_completion_proof_digest: Option<Digest>,
}

impl CommandOutputCaptureRecovery {
    /// Returns the exact claim retained by a fenced physical recovery.
    ///
    /// A plain diagnostic reopen has no physical reconciliation context and
    /// therefore returns `None`.
    pub(super) fn physical_reconciliation_claim(
        &self,
    ) -> Option<&CommandOutputCaptureReconciliationClaimV1> {
        self.physical_reconciliation
            .as_ref()
            .map(|context| &context.claim)
    }

    /// Exact capture identity used for reopen.
    #[must_use]
    pub const fn capture_id(&self) -> &CommandOutputCaptureId {
        &self.capture_id
    }

    /// Source authority from the immutable intent.
    #[must_use]
    pub const fn source(&self) -> &CommandOutputArtifactSourceV1 {
        &self.source
    }

    /// Authenticated aggregate output ceiling.
    #[must_use]
    pub const fn authenticated_maximum_bytes(&self) -> u64 {
        self.authenticated_maximum_bytes
    }

    /// Exact durable state after physical-state revalidation.
    #[must_use]
    pub const fn state(&self) -> CommandOutputCaptureJournalStateV1 {
        self.state
    }

    /// Exact generation and digest of the last immutable journal record.
    #[must_use]
    pub const fn store_head(&self) -> &CommandOutputCaptureStoreHeadV1 {
        &self.store_head
    }

    /// Digest of the last immutable journal record.
    #[must_use]
    pub const fn head_digest(&self) -> &Digest {
        &self.store_head.record_digest
    }

    /// Exact acquired anchor once acquisition was durably recorded.
    #[must_use]
    pub const fn acquired(&self) -> Option<&CommandOutputCaptureAcquiredV1> {
        self.acquired.as_ref()
    }

    /// Exact immutable `WriterAttached` head, when runner writer custody was
    /// durably established before native launch.
    #[must_use]
    pub const fn writer_attached_store_head(&self) -> Option<&CommandOutputCaptureStoreHeadV1> {
        self.writer_attached_store_head.as_ref()
    }

    /// Complete expected artifact once both streams were finished.
    #[must_use]
    pub const fn expected_reference(&self) -> Option<&CommandOutputArtifactSetReferenceV1> {
        self.expected_reference.as_ref()
    }

    /// Exact terminal response bytes when `TerminalPrepared` was durable.
    #[must_use]
    pub const fn terminal(&self) -> Option<&CommandOutputCaptureCanonicalPayloadV1> {
        self.terminal.as_ref()
    }

    /// Exact native-launch binding retained by the historical
    /// `LaunchIntended` record, including after restart cleanup.
    #[must_use]
    pub const fn launch_intended(&self) -> Option<&CommandOutputCaptureCanonicalPayloadV1> {
        self.launch_intended.as_ref()
    }

    /// Exact immutable `LaunchIntended` head, when launch authority crossed
    /// the durable journal boundary.
    #[must_use]
    pub const fn launch_intended_store_head(&self) -> Option<&CommandOutputCaptureStoreHeadV1> {
        self.launch_intended_store_head.as_ref()
    }

    /// Digest of the exact historical native-launch binding bytes.
    #[must_use]
    pub fn launch_intended_payload_digest(&self) -> Option<&Digest> {
        self.launch_intended
            .as_ref()
            .map(|payload| &payload.canonical_bytes_digest)
    }

    /// Exact immutable `Finished` head, when both stream commitments exist.
    #[must_use]
    pub const fn finished_store_head(&self) -> Option<&CommandOutputCaptureStoreHeadV1> {
        self.finished_store_head.as_ref()
    }

    /// Exact immutable `Published` head, when physical publication validates.
    #[must_use]
    pub const fn published_store_head(&self) -> Option<&CommandOutputCaptureStoreHeadV1> {
        self.published_store_head.as_ref()
    }

    /// Exact immutable `TerminalPrepared` head, when response bytes exist.
    #[must_use]
    pub const fn terminal_prepared_store_head(&self) -> Option<&CommandOutputCaptureStoreHeadV1> {
        self.terminal_prepared_store_head.as_ref()
    }

    /// Digest of the exact terminal reconstruction bytes.
    #[must_use]
    pub fn terminal_payload_digest(&self) -> Option<&Digest> {
        self.terminal
            .as_ref()
            .map(|payload| &payload.canonical_bytes_digest)
    }

    /// Interrupted record publication retained under the exact capture
    /// journal, when present.
    #[must_use]
    pub const fn pending_record(&self) -> Option<&CommandOutputCapturePendingRecordV1> {
        self.pending_record.as_ref()
    }

    /// Exact immutable `CleanupIntended` head, when cleanup began.
    #[must_use]
    pub const fn cleanup_intended_store_head(&self) -> Option<&CommandOutputCaptureStoreHeadV1> {
        self.cleanup_intended_store_head.as_ref()
    }

    /// Exact immutable `Cleaned` head containing unlink proof.
    #[must_use]
    pub const fn cleaned_store_head(&self) -> Option<&CommandOutputCaptureStoreHeadV1> {
        self.cleaned_store_head.as_ref()
    }

    /// Digest of the immutable `Cleaned` record itself, not its predecessor.
    #[must_use]
    pub fn cleaned_record_digest(&self) -> Option<&Digest> {
        self.cleaned_store_head
            .as_ref()
            .map(|head| &head.record_digest)
    }

    /// Digest that authenticates the terminal lifecycle record.
    ///
    /// Successful captures return the `TerminalPrepared` record digest;
    /// failed captures return the `Cleaned` record digest that contains the
    /// exact unlink proof.
    #[must_use]
    pub fn terminal_record_digest(&self) -> Option<&Digest> {
        self.terminal_prepared_store_head
            .as_ref()
            .or(self.cleaned_store_head.as_ref())
            .map(|head| &head.record_digest)
    }

    /// Constructs the canonical core physical-reconciliation envelope from
    /// the exact fenced action that produced this recovery readback.
    ///
    /// # Errors
    ///
    /// Returns a reference error unless this value came from the fenced
    /// restart API and the supplied Intent, claim, timestamp, physical fence,
    /// lifecycle history, pending action, and retained anchors all agree.
    pub fn physical_reconciliation_evidence(
        &self,
        intent: &CommandOutputCaptureIntentV1,
        claim: &CommandOutputCaptureReconciliationClaimV1,
        reconciled_at_unix_ms: u64,
    ) -> Result<CommandOutputCapturePhysicalReconciliationV1, CommandOutputStoreError> {
        let context = self.physical_reconciliation.as_ref().ok_or_else(|| {
            CommandOutputStoreError::Reference(
                "capture readback did not perform a fenced physical reconciliation".into(),
            )
        })?;
        if &context.claim != claim {
            return Err(CommandOutputStoreError::Reference(
                "physical reconciliation claim differs from the durable runner fence".into(),
            ));
        }
        let launch_history = match (
            self.launch_intended.as_ref(),
            self.launch_intended_store_head.as_ref(),
        ) {
            (Some(payload), Some(store_head)) => {
                CommandOutputCaptureLaunchHistoryV1::ExactLaunchEvidence {
                    evidence: CommandOutputCaptureRestartLaunchEvidenceV1::try_new(
                        payload.schema.clone(),
                        payload.canonical_bytes.clone(),
                        store_head.clone(),
                    )
                    .map_err(core_contract_error)?,
                }
            }
            (None, None) => CommandOutputCaptureLaunchHistoryV1::NoneBeforeLaunch,
            _ => {
                return Err(CommandOutputStoreError::Manifest(
                    "launch payload and historical head are not paired".into(),
                ));
            }
        };
        let terminal_prepared = self
            .terminal
            .as_ref()
            .map(|terminal| {
                self.terminal_prepared_store_head
                    .as_ref()
                    .map(
                        |store_head| CommandOutputCapturePhysicalTerminalEvidenceV1 {
                            schema: terminal.schema.clone(),
                            canonical_bytes_digest: terminal.canonical_bytes_digest.clone(),
                            store_head: store_head.clone(),
                        },
                    )
                    .ok_or_else(|| {
                        CommandOutputStoreError::Manifest(
                            "terminal payload lacks its immutable journal head".into(),
                        )
                    })
            })
            .transpose()?;
        // Finished is not Published. Zero-first history must not project identities
        // for artifacts that were never published.
        let published_exists = context
            .lifecycle_history
            .iter()
            .any(|entry| entry.state == CommandOutputCaptureRestartStateV1::Published);
        let artifact_reference = if published_exists {
            self.expected_reference.clone()
        } else {
            None
        };
        let evidence = CommandOutputCapturePhysicalReconciliationV1::try_new(
            intent,
            claim,
            context.predecessor_fence_digest.clone(),
            context.physical_fence_chain_length,
            context.requested_store_head.clone(),
            context.initial_state,
            context.initial_store_head.clone(),
            context.pending_resolution.clone(),
            context.resolution_action,
            context.lifecycle_history.clone(),
            self.acquired.clone(),
            launch_history,
            artifact_reference,
            terminal_prepared,
            context.cleanup_completion_proof_digest.clone(),
            reconciled_at_unix_ms,
        )
        .map_err(core_contract_error)?;
        if evidence.physical_fence_digest != context.physical_fence_digest {
            return Err(CommandOutputStoreError::Manifest(
                "core physical fence digest differs from the exact runner fence record".into(),
            ));
        }
        Ok(evidence)
    }
}

pub(super) struct OpenedWorkingSet {
    pub(super) stdout: File,
    pub(super) stdout_identity: PrivateFileIdentity,
    pub(super) stderr: File,
    pub(super) stderr_identity: PrivateFileIdentity,
    pub(super) directory: Dir,
    pub(super) directory_identity: PrivateDirectoryIdentity,
    pub(super) working_name: String,
    pub(super) source: CommandOutputArtifactSourceV1,
    pub(super) source_digest: Digest,
    pub(super) authenticated_maximum_bytes: u64,
    pub(super) lease: CaptureJournalLease,
}

struct SensitiveWorkingSet {
    stdout: File,
    stderr: File,
    directory: Dir,
    directory_identity: PrivateDirectoryIdentity,
    working_name: String,
    _lease: CaptureJournalLease,
}

/// Reservation custody retained until every descriptor is synchronized and
/// deliberately closed for process handoff.
pub struct CommandOutputCaptureReservation {
    store: CapabilityCommandOutputStore,
    capture_id: CommandOutputCaptureId,
    source: CommandOutputArtifactSourceV1,
    authenticated_maximum_bytes: u64,
    working_name: String,
    working: Dir,
    working_identity: PrivateDirectoryIdentity,
    stdout: File,
    stdout_identity: PrivateFileIdentity,
    stderr: File,
    stderr_identity: PrivateFileIdentity,
    lease: CaptureJournalLease,
    anchor: CommandOutputCaptureAcquiredV1,
}

impl CommandOutputCaptureReservation {
    /// Returns the path-free anchor while reservation descriptors remain held.
    #[must_use]
    pub const fn acquired_anchor(&self) -> &CommandOutputCaptureAcquiredV1 {
        &self.anchor
    }

    /// Synchronizes and revalidates every exact name and object, then consumes
    /// all working and journal descriptors and returns only path-free evidence.
    /// Drop never cleans an acquired reservation because restart needs it.
    ///
    /// # Errors
    ///
    /// Returns reconciliation-required when synchronization, exact identity
    /// revalidation, descriptor-closing handoff, or exact-ID reopen fails.
    pub fn into_acquired_anchor_for_handoff(
        self,
    ) -> Result<CommandOutputCaptureAcquiredV1, CommandOutputStoreError> {
        self.store.validate_root()?;
        self.stdout.sync_all().map_err(|error| {
            io_error(
                "sync reserved stdout before handoff",
                Path::new(STDOUT_FILE),
                &error,
            )
        })?;
        self.stderr.sync_all().map_err(|error| {
            io_error(
                "sync reserved stderr before handoff",
                Path::new(STDERR_FILE),
                &error,
            )
        })?;
        sync_directory(&self.working).map_err(|error| {
            io_error(
                "sync capture working directory before handoff",
                Path::new(&self.working_name),
                &error,
            )
        })?;
        sync_directory(&self.store.inner.root).map_err(|error| {
            io_error(
                "sync capture namespace before handoff",
                Path::new(&self.working_name),
                &error,
            )
        })?;
        validate_exact_working_set(
            &self.store,
            &self.working_name,
            &self.working,
            self.working_identity,
            &self.stdout,
            self.stdout_identity,
            &self.stderr,
            self.stderr_identity,
            0,
        )?;
        let expected_head = self.anchor.store_head.record_digest.clone();
        let capture_id = self.capture_id.clone();
        let source = self.source.clone();
        let maximum = self.authenticated_maximum_bytes;
        let anchor = self.anchor.clone();
        drop(self.stdout);
        drop(self.stderr);
        drop(self.working);
        drop(self.lease);
        let recovery = reopen_capture(&self.store, &capture_id)?;
        if recovery.state != CommandOutputCaptureJournalStateV1::Acquired
            || recovery.head_digest() != &expected_head
            || recovery.source != source
            || recovery.authenticated_maximum_bytes != maximum
            || recovery.acquired.as_ref() != Some(&anchor)
        {
            return Err(CommandOutputStoreError::ReconciliationRequired {
                capture_id: Some(capture_id.to_string()),
                source: Box::new(source),
                expected_reference: None,
                reason: format!(
                    "capture {capture_id} changed while closing acquired handoff custody"
                ),
            });
        }
        Ok(anchor)
    }
}

pub(super) struct CaptureJournalLease {
    store: CapabilityCommandOutputStore,
    capture_id: CommandOutputCaptureId,
    journal_name: String,
    journal: Dir,
    journal_identity: PrivateDirectoryIdentity,
    lock: File,
    lock_identity: PrivateFileIdentity,
    records: Vec<StoredCaptureRecordV1>,
    recovery_fences: Vec<StoredRecoveryFenceV1>,
    admitted_recovery_fence_digest: Option<Digest>,
    pending_record: Option<PendingRecordFile>,
    pending_fence: Option<PendingFenceFile>,
    last_pending_resolution: Option<CommandOutputCapturePendingResolutionV1>,
}

impl Drop for CaptureJournalLease {
    fn drop(&mut self) {
        let _ = flock(&self.lock, FlockOperation::Unlock);
    }
}

impl CaptureJournalLease {
    pub(super) fn capture_id(&self) -> &CommandOutputCaptureId {
        &self.capture_id
    }

    pub(super) fn head_digest(&self) -> &Digest {
        &self
            .records
            .last()
            .expect("a leased capture journal always has Intent")
            .record_digest
    }

    pub(super) fn head(&self) -> CommandOutputCaptureStoreHeadV1 {
        CommandOutputCaptureStoreHeadV1 {
            generation: u64::try_from(self.records.len()).expect("bounded records fit u64"),
            record_digest: self.head_digest().clone(),
        }
    }

    pub(super) fn append_launch_intended(
        &mut self,
        binding: CommandOutputCaptureCanonicalPayloadV1,
    ) -> Result<Digest, CommandOutputStoreError> {
        binding.validate(MAX_CAPTURE_BINDING_PAYLOAD_BYTES)?;
        self.append(StoredCaptureRecordDataV1::LaunchIntended { binding })
            .map(|record| record.record_digest.clone())
    }

    pub(super) fn append_finished(
        &mut self,
        stdout: CommandOutputStreamArtifactV1,
        stderr: CommandOutputStreamArtifactV1,
    ) -> Result<Digest, CommandOutputStoreError> {
        self.append(StoredCaptureRecordDataV1::Finished { stdout, stderr })
            .map(|record| record.record_digest.clone())
    }

    pub(super) fn append_published(
        &mut self,
        reference: CommandOutputArtifactSetReferenceV1,
        artifact_directory: &Dir,
    ) -> Result<Digest, CommandOutputStoreError> {
        self.append(StoredCaptureRecordDataV1::Published {
            reference,
            artifact_directory: StoredObjectIdentityV1::from_directory(artifact_directory)?,
        })
        .map(|record| record.record_digest.clone())
    }

    pub(super) fn append_cleanup_intended(&mut self) -> Result<Digest, CommandOutputStoreError> {
        let working_set = self.acquired_working_set();
        let intent = intent_record(&self.records)?;
        let namespace_plan = inspect_cleanup_namespace_plan(
            &self.store,
            &self.capture_id,
            intent.max_aggregate_output_bytes,
        )?;
        self.append(StoredCaptureRecordDataV1::CleanupIntended {
            working_set,
            namespace_plan: Some(namespace_plan),
        })
        .map(|record| record.record_digest.clone())
    }

    fn append_cleaned_held(
        &mut self,
        directory: Option<&Dir>,
        stdout: Option<&File>,
        stderr: Option<&File>,
        manifest: Option<&File>,
    ) -> Result<Digest, CommandOutputStoreError> {
        let (working_set, namespace_plan, _) = cleanup_intent_material(&self.records)?;
        let completion_proof = StoredCleanupCompletionProofV1::HeldDescriptorUnlink {
            planned_identity_digest: namespace_plan.planned_identity_digest.clone(),
            directory: directory
                .map(StoredObjectIdentityV1::from_directory)
                .transpose()?,
            stdout: stdout.map(StoredObjectIdentityV1::from_file).transpose()?,
            stderr: stderr.map(StoredObjectIdentityV1::from_file).transpose()?,
            manifest: manifest
                .map(StoredObjectIdentityV1::from_file)
                .transpose()?,
        };
        let cleanup_intent_digest = &self
            .records
            .last()
            .expect("cleanup intent exists")
            .record_digest;
        validate_completion_proof(
            &self.capture_id,
            &namespace_plan,
            cleanup_intent_digest,
            &completion_proof,
        )?;
        self.append(StoredCaptureRecordDataV1::Cleaned {
            working_set,
            cleanup_proof: None,
            completion_proof: Some(completion_proof),
        })
        .map(|record| record.record_digest.clone())
    }

    fn acquired_working_set(&self) -> Option<StoredWorkingSetIdentityV1> {
        self.records.iter().find_map(|record| match &record.data {
            StoredCaptureRecordDataV1::Acquired { working_set, .. } => Some(working_set.clone()),
            _ => None,
        })
    }

    pub(super) fn append_cleaned_from_unlinked(
        &mut self,
        directory: &Dir,
        stdout: &File,
        stderr: &File,
        manifest: Option<&File>,
    ) -> Result<Digest, CommandOutputStoreError> {
        self.append_cleaned_held(Some(directory), Some(stdout), Some(stderr), manifest)
    }

    fn append_cleaned_restart_namespace(&mut self) -> Result<Digest, CommandOutputStoreError> {
        let (working_set, namespace_plan, cleanup_intent_digest) =
            cleanup_intent_material(&self.records)?;
        ensure_name_absent(
            &self.store,
            &working_name(&self.capture_id),
            intent_source(&self.records)?,
            &self.capture_id,
        )?;
        let absent_working_name = working_name(&self.capture_id);
        let exact_absence_digest = domain_separated_json_digest(
            RESTART_ABSENCE_DIGEST_DOMAIN,
            &RestartAbsenceDigestPreimage {
                capture_id: &self.capture_id,
                cleanup_intent_digest: &cleanup_intent_digest,
                planned_identity_digest: &namespace_plan.planned_identity_digest,
                absent_working_name: &absent_working_name,
            },
            "restart cleanup absence",
        )?;
        let completion_digest = domain_separated_json_digest(
            RESTART_COMPLETION_DIGEST_DOMAIN,
            &RestartCompletionDigestPreimage {
                cleanup_intent_digest: &cleanup_intent_digest,
                planned_identity_digest: &namespace_plan.planned_identity_digest,
                exact_absence_digest: &exact_absence_digest,
            },
            "restart cleanup completion",
        )?;
        let completion_proof = StoredCleanupCompletionProofV1::RestartNamespaceCompletion {
            cleanup_intent_digest: cleanup_intent_digest.clone(),
            planned_identity_digest: namespace_plan.planned_identity_digest.clone(),
            exact_absence_digest,
            completion_digest,
        };
        validate_completion_proof(
            &self.capture_id,
            &namespace_plan,
            &cleanup_intent_digest,
            &completion_proof,
        )?;
        self.append(StoredCaptureRecordDataV1::Cleaned {
            working_set,
            cleanup_proof: None,
            completion_proof: Some(completion_proof),
        })
        .map(|record| record.record_digest.clone())
    }

    fn append(
        &mut self,
        data: StoredCaptureRecordDataV1,
    ) -> Result<&StoredCaptureRecordV1, CommandOutputStoreError> {
        if self.records.is_empty() {
            validate_lease_names(self)?;
            let mut expected_names = BTreeSet::from([LOCK_FILE.to_string()]);
            expected_names.extend(
                self.recovery_fences
                    .iter()
                    .map(|fence| fence_name(fence.claim.claim_epoch, &fence.fence_digest)),
            );
            let names = exact_entry_names(
                &self.journal,
                &self.journal_name,
                1 + self.recovery_fences.len(),
            )?;
            if names != expected_names {
                return Err(CommandOutputStoreError::Manifest(
                    "new capture journal is not the exact empty locked layout".into(),
                ));
            }
        } else {
            self.revalidate()?;
        }
        match (
            self.recovery_fences.last(),
            self.admitted_recovery_fence_digest.as_ref(),
        ) {
            (None, None) => {}
            (Some(latest), Some(admitted)) if admitted == &latest.fence_digest => {}
            (Some(_), None) => {
                return Err(CommandOutputStoreError::Reference(
                    "ordinary capture mutation is permanently fenced by restart reconciliation"
                        .into(),
                ));
            }
            _ => {
                return Err(CommandOutputStoreError::Manifest(
                    "capture mutation authority differs from the latest durable recovery fence"
                        .into(),
                ));
            }
        }
        if self.pending_record.is_some() || self.pending_fence.is_some() {
            return Err(CommandOutputStoreError::Manifest(
                "capture journal has an interrupted publication requiring fenced recovery".into(),
            ));
        }
        validate_successor(self.records.last(), &data)?;
        let sequence = u64::try_from(self.records.len())
            .ok()
            .and_then(|value| value.checked_add(1))
            .ok_or_else(|| {
                CommandOutputStoreError::Manifest("capture journal sequence overflowed".into())
            })?;
        let mut record = StoredCaptureRecordV1 {
            format_version: CAPTURE_JOURNAL_FORMAT_VERSION,
            sequence,
            capture_id: self.capture_id.clone(),
            predecessor_digest: self
                .records
                .last()
                .map(|record| record.record_digest.clone()),
            data,
            record_digest: Digest::sha256(&[]),
        };
        record.record_digest = record.computed_digest()?;
        persist_record(&self.journal, &record)?;
        let records = read_records(
            &self.journal,
            &self.capture_id,
            self.journal_identity,
            self.lock_identity,
        )?;
        if records.len() != self.records.len() + 1 || records.last() != Some(&record) {
            return Err(CommandOutputStoreError::Manifest(
                "capture journal append did not read back as one exact successor".into(),
            ));
        }
        self.records = records;
        Ok(self.records.last().expect("record was appended"))
    }

    fn revalidate(&mut self) -> Result<(), CommandOutputStoreError> {
        validate_lease_names(self)?;
        let records = read_records(
            &self.journal,
            &self.capture_id,
            self.journal_identity,
            self.lock_identity,
        )?;
        if records != self.records {
            return Err(CommandOutputStoreError::Manifest(
                "capture journal immutable prefix changed while writer lock was held".into(),
            ));
        }
        let recovery_fences = read_recovery_fences(&self.journal, &self.capture_id)?;
        if recovery_fences != self.recovery_fences {
            return Err(CommandOutputStoreError::Manifest(
                "capture recovery-fence chain changed while writer lock was held".into(),
            ));
        }
        let pending_record = read_pending_record(&self.journal, &self.capture_id, &records)?;
        let pending_fence = read_pending_fence(&self.journal, &self.capture_id, &recovery_fences)?;
        if pending_record != self.pending_record || pending_fence != self.pending_fence {
            return Err(CommandOutputStoreError::Manifest(
                "capture journal interrupted-publication set changed while lock was held".into(),
            ));
        }
        Ok(())
    }

    fn admit_recovery_claim(
        &mut self,
        claim: &CommandOutputCaptureReconciliationClaimV1,
    ) -> Result<(), CommandOutputStoreError> {
        claim.validate().map_err(core_contract_error)?;
        if claim.capture_id != self.capture_id.as_str() {
            return Err(CommandOutputStoreError::Reference(
                "recovery claim is crossed with another capture ID".into(),
            ));
        }
        self.revalidate()?;
        self.resolve_pending_fence(claim)?;
        if let Some(latest) = self.recovery_fences.last() {
            if latest.claim == *claim {
                self.admitted_recovery_fence_digest = Some(latest.fence_digest.clone());
                return Ok(());
            }
            if claim.claim_epoch <= latest.claim.claim_epoch {
                return Err(CommandOutputStoreError::Reference(format!(
                    "recovery claim epoch {} is fenced by durable epoch {}",
                    claim.claim_epoch, latest.claim.claim_epoch
                )));
            }
        }
        if self.recovery_fences.len() >= MAX_RECOVERY_FENCES {
            return Err(CommandOutputStoreError::Manifest(
                "capture recovery-fence history reached its hard bound".into(),
            ));
        }
        let fence = self.recovery_fence_for_claim(claim)?;
        persist_recovery_fence(&self.journal, &fence)?;
        let fences = read_recovery_fences(&self.journal, &self.capture_id)?;
        if fences.len() != self.recovery_fences.len() + 1 || fences.last() != Some(&fence) {
            return Err(CommandOutputStoreError::Manifest(
                "recovery fence did not read back as one exact monotonic successor".into(),
            ));
        }
        self.recovery_fences = fences;
        self.admitted_recovery_fence_digest = self
            .recovery_fences
            .last()
            .map(|fence| fence.fence_digest.clone());
        Ok(())
    }

    fn recovery_fence_for_claim(
        &self,
        claim: &CommandOutputCaptureReconciliationClaimV1,
    ) -> Result<StoredRecoveryFenceV1, CommandOutputStoreError> {
        let mut fence = StoredRecoveryFenceV1 {
            format_version: CAPTURE_JOURNAL_FORMAT_VERSION,
            capture_id: self.capture_id.clone(),
            predecessor_fence_digest: self
                .recovery_fences
                .last()
                .map(|fence| fence.fence_digest.clone()),
            claim: claim.clone(),
            fence_digest: Digest::sha256(&[]),
        };
        fence.fence_digest = fence.computed_digest()?;
        Ok(fence)
    }

    fn resolve_pending_fence(
        &mut self,
        incoming: &CommandOutputCaptureReconciliationClaimV1,
    ) -> Result<(), CommandOutputStoreError> {
        let Some(pending) = self.pending_fence.clone() else {
            return Ok(());
        };
        if incoming.claim_epoch < pending.epoch {
            return Err(CommandOutputStoreError::Reference(format!(
                "incoming recovery epoch {} cannot supersede interrupted fence epoch {}",
                incoming.claim_epoch, pending.epoch
            )));
        }
        if incoming.claim_epoch == pending.epoch {
            let expected = self.recovery_fence_for_claim(incoming)?;
            let exact_temporary_name = format!(
                ".{}.tmp",
                fence_name(expected.claim.claim_epoch, &expected.fence_digest)
            );
            match pending.fence.as_ref() {
                Some(fence) if fence == &expected => {
                    finalize_pending_name(
                        &self.journal,
                        &pending.name,
                        &fence_name(fence.claim.claim_epoch, &fence.fence_digest),
                        pending.identity,
                    )?;
                    self.recovery_fences = read_recovery_fences(&self.journal, &self.capture_id)?;
                }
                None if pending.name == exact_temporary_name => {
                    remove_pending_name(&self.journal, &pending.name, pending.identity)?;
                }
                _ => {
                    return Err(CommandOutputStoreError::Reference(
                        "same recovery epoch belongs to a different physical claim fence".into(),
                    ));
                }
            }
            self.pending_fence = None;
            return Ok(());
        }
        if let Some(fence) = pending.fence {
            finalize_pending_name(
                &self.journal,
                &pending.name,
                &fence_name(fence.claim.claim_epoch, &fence.fence_digest),
                pending.identity,
            )?;
            self.recovery_fences = read_recovery_fences(&self.journal, &self.capture_id)?;
        } else {
            remove_pending_name(&self.journal, &pending.name, pending.identity)?;
        }
        self.pending_fence = None;
        Ok(())
    }

    fn resolve_pending_record(&mut self) -> Result<(), CommandOutputStoreError> {
        let Some(pending) = self.pending_record.clone() else {
            return Ok(());
        };
        if let Some(record) = pending.record {
            finalize_pending_name(
                &self.journal,
                &pending.name,
                &record_name(record.sequence, &record.record_digest),
                pending.identity,
            )?;
            self.records = read_records(
                &self.journal,
                &self.capture_id,
                self.journal_identity,
                self.lock_identity,
            )?;
            self.last_pending_resolution =
                Some(CommandOutputCapturePendingResolutionV1::RolledForward {
                    sequence: record.sequence,
                    state: core_restart_state(record.data.state()),
                    record_digest: record.record_digest,
                });
        } else {
            remove_pending_name(&self.journal, &pending.name, pending.identity)?;
            self.last_pending_resolution =
                Some(CommandOutputCapturePendingResolutionV1::RemovedTorn {
                    sequence: pending.sequence,
                    name_digest: pending.name_digest,
                });
        }
        self.pending_record = None;
        Ok(())
    }
}

fn inspect_cleanup_namespace_plan(
    store: &CapabilityCommandOutputStore,
    capture_id: &CommandOutputCaptureId,
    maximum_bytes: u64,
) -> Result<StoredCleanupNamespacePlanV1, CommandOutputStoreError> {
    let name = working_name(capture_id);
    match store.inner.root.symlink_metadata(&name) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return StoredCleanupNamespacePlanV1::try_new(None, None, None, None, BTreeSet::new());
        }
        Err(error) => {
            return Err(io_error(
                "inspect cleanup working name",
                Path::new(&name),
                &error,
            ));
        }
        Ok(_) => {}
    }
    let directory =
        store.inner.root.open_dir_nofollow(&name).map_err(|error| {
            io_error("open cleanup working directory", Path::new(&name), &error)
        })?;
    let directory_identity = validate_private_directory(&directory, "cleanup working directory")?;
    let entry_names = exact_entry_names(&directory, &name, 3)?;
    let allowed = BTreeSet::from([
        MANIFEST_FILE.to_string(),
        STDOUT_FILE.to_string(),
        STDERR_FILE.to_string(),
    ]);
    if !entry_names.is_subset(&allowed) {
        return Err(CommandOutputStoreError::Manifest(
            "cleanup working directory contains an unplanned entry".into(),
        ));
    }
    let inspect_file = |file_name: &'static str,
                        maximum: u64|
     -> Result<Option<StoredObjectIdentityV1>, CommandOutputStoreError> {
        if !entry_names.contains(file_name) {
            return Ok(None);
        }
        let file = open_private_file(&directory, Path::new(file_name))?;
        validate_private_file(&file, Path::new(file_name), None, maximum)?;
        StoredObjectIdentityV1::from_file(&file).map(Some)
    };
    let stdout = inspect_file(STDOUT_FILE, maximum_bytes)?;
    let stderr = inspect_file(STDERR_FILE, maximum_bytes)?;
    let manifest = inspect_file(MANIFEST_FILE, MAX_MANIFEST_BYTES)?;
    store.validate_named_directory(&name, directory_identity)?;
    store.validate_root()?;
    StoredCleanupNamespacePlanV1::try_new(
        Some(StoredObjectIdentityV1::from_directory(&directory)?),
        stdout,
        stderr,
        manifest,
        entry_names,
    )
}

fn cleanup_intent_material(
    records: &[StoredCaptureRecordV1],
) -> Result<
    (
        Option<StoredWorkingSetIdentityV1>,
        StoredCleanupNamespacePlanV1,
        Digest,
    ),
    CommandOutputStoreError,
> {
    records
        .iter()
        .find_map(|record| match &record.data {
            StoredCaptureRecordDataV1::CleanupIntended {
                working_set,
                namespace_plan: Some(namespace_plan),
            } => Some((
                working_set.clone(),
                namespace_plan.clone(),
                record.record_digest.clone(),
            )),
            _ => None,
        })
        .ok_or_else(|| {
            CommandOutputStoreError::Manifest(
                "capture cleanup has no exact namespace plan in CleanupIntended".into(),
            )
        })
}

fn admit_recovery_intent(
    lease: &mut CaptureJournalLease,
    intent: &CommandOutputCaptureIntentV1,
    claim: &CommandOutputCaptureReconciliationClaimV1,
) -> Result<(), CommandOutputStoreError> {
    if let Some(stored_intent) = lease
        .records
        .first()
        .map(|_| intent_record(&lease.records))
        .transpose()?
    {
        if stored_intent != intent {
            return Err(CommandOutputStoreError::Reference(
                "restart Intent differs from the exact immutable journal Intent".into(),
            ));
        }
    } else if let Some(pending) = lease
        .pending_record
        .as_ref()
        .and_then(|pending| pending.record.as_ref())
    {
        let StoredCaptureRecordDataV1::Intent {
            intent: pending_intent,
            ..
        } = &pending.data
        else {
            return Err(CommandOutputStoreError::Manifest(
                "an empty journal has a non-Intent pending initial record".into(),
            ));
        };
        if pending_intent != intent {
            return Err(CommandOutputStoreError::Reference(
                "pending initial journal Intent differs from restart authority".into(),
            ));
        }
    }

    lease.admit_recovery_claim(claim)?;
    if lease.records.is_empty() {
        lease.resolve_pending_record()?;
        if lease.records.is_empty() {
            let intent_record = StoredCaptureRecordDataV1::Intent {
                intent: intent.clone(),
                journal_directory: StoredObjectIdentityV1::from_directory(&lease.journal)?,
                writer_lock: StoredObjectIdentityV1::from_file(&lease.lock)?,
            };
            lease.append(intent_record)?;
        }
    }
    if intent_record(&lease.records)? != intent {
        return Err(CommandOutputStoreError::Reference(
            "recovered initial journal Intent differs from restart authority".into(),
        ));
    }
    Ok(())
}

fn validate_completion_proof(
    capture_id: &CommandOutputCaptureId,
    plan: &StoredCleanupNamespacePlanV1,
    cleanup_intent_digest: &Digest,
    proof: &StoredCleanupCompletionProofV1,
) -> Result<(), CommandOutputStoreError> {
    plan.validate()?;
    match proof {
        StoredCleanupCompletionProofV1::HeldDescriptorUnlink {
            planned_identity_digest,
            directory,
            stdout,
            stderr,
            manifest,
        } => {
            if planned_identity_digest != &plan.planned_identity_digest
                || directory.is_some() != plan.directory.is_some()
                || stdout.is_some() != plan.stdout.is_some()
                || stderr.is_some() != plan.stderr.is_some()
                || manifest.is_some() != plan.manifest.is_some()
            {
                return Err(CommandOutputStoreError::Manifest(
                    "held-descriptor cleanup proof differs from its durable plan".into(),
                ));
            }
            if let Some(identity) = directory {
                identity.validate_unlinked_directory_shape()?;
            }
            for identity in [stdout, stderr, manifest].into_iter().flatten() {
                identity.validate_unlinked_file_shape()?;
            }
            for (planned, unlinked) in [
                (plan.directory.as_ref(), directory.as_ref()),
                (plan.stdout.as_ref(), stdout.as_ref()),
                (plan.stderr.as_ref(), stderr.as_ref()),
                (plan.manifest.as_ref(), manifest.as_ref()),
            ] {
                if planned.zip(unlinked).is_some_and(|(planned, unlinked)| {
                    (planned.device, planned.inode) != (unlinked.device, unlinked.inode)
                }) {
                    return Err(CommandOutputStoreError::Manifest(
                        "held-descriptor cleanup proof crosses a planned object".into(),
                    ));
                }
            }
        }
        StoredCleanupCompletionProofV1::RestartNamespaceCompletion {
            cleanup_intent_digest: proof_cleanup_intent_digest,
            planned_identity_digest,
            exact_absence_digest,
            completion_digest,
        } => {
            let absent_working_name = working_name(capture_id);
            let expected_absence = domain_separated_json_digest(
                RESTART_ABSENCE_DIGEST_DOMAIN,
                &RestartAbsenceDigestPreimage {
                    capture_id,
                    cleanup_intent_digest,
                    planned_identity_digest: &plan.planned_identity_digest,
                    absent_working_name: &absent_working_name,
                },
                "restart cleanup absence",
            )?;
            let expected_completion = domain_separated_json_digest(
                RESTART_COMPLETION_DIGEST_DOMAIN,
                &RestartCompletionDigestPreimage {
                    cleanup_intent_digest,
                    planned_identity_digest: &plan.planned_identity_digest,
                    exact_absence_digest: &expected_absence,
                },
                "restart cleanup completion",
            )?;
            if proof_cleanup_intent_digest != cleanup_intent_digest
                || planned_identity_digest != &plan.planned_identity_digest
                || exact_absence_digest != &expected_absence
                || completion_digest != &expected_completion
            {
                return Err(CommandOutputStoreError::Manifest(
                    "restart namespace completion proof is crossed or digest-invalid".into(),
                ));
            }
        }
    }
    Ok(())
}

fn cleanup_completion_proof_digest(
    records: &[StoredCaptureRecordV1],
) -> Result<Option<Digest>, CommandOutputStoreError> {
    let Some(record) = records
        .iter()
        .find(|record| matches!(record.data, StoredCaptureRecordDataV1::Cleaned { .. }))
    else {
        return Ok(None);
    };
    let StoredCaptureRecordDataV1::Cleaned {
        cleanup_proof,
        completion_proof,
        ..
    } = &record.data
    else {
        unreachable!("matched Cleaned")
    };
    match (cleanup_proof, completion_proof) {
        (Some(proof), None) => domain_separated_json_digest(
            CLEANUP_COMPLETION_PROOF_DIGEST_DOMAIN,
            proof,
            "legacy held cleanup proof",
        )
        .map(Some),
        (None, Some(proof)) => domain_separated_json_digest(
            CLEANUP_COMPLETION_PROOF_DIGEST_DOMAIN,
            proof,
            "cleanup completion proof",
        )
        .map(Some),
        _ => Err(CommandOutputStoreError::Manifest(
            "Cleaned record has an ambiguous or missing completion proof".into(),
        )),
    }
}

fn attach_physical_reconciliation_context(
    recovery: &mut CommandOutputCaptureRecovery,
    lease: &CaptureJournalLease,
    claim: &CommandOutputCaptureReconciliationClaimV1,
    requested_store_head: Option<CommandOutputCaptureStoreHeadV1>,
    initial_state: Option<CommandOutputCaptureRestartStateV1>,
    initial_store_head: Option<CommandOutputCaptureStoreHeadV1>,
    journal_was_created: bool,
) -> Result<(), CommandOutputStoreError> {
    let physical_fence = lease.recovery_fences.last().ok_or_else(|| {
        CommandOutputStoreError::Manifest(
            "physical reconciliation has no durable recovery fence".into(),
        )
    })?;
    if &physical_fence.claim != claim {
        return Err(CommandOutputStoreError::Reference(
            "final physical recovery fence belongs to another claim".into(),
        ));
    }
    let lifecycle_history = lease
        .records
        .iter()
        .map(|record| CommandOutputCapturePhysicalHistoryEntryV1 {
            state: core_restart_state(record.data.state()),
            store_head: CommandOutputCaptureStoreHeadV1 {
                generation: record.sequence,
                record_digest: record.record_digest.clone(),
            },
        })
        .collect::<Vec<_>>();
    let pending_resolution = lease
        .last_pending_resolution
        .clone()
        .unwrap_or(CommandOutputCapturePendingResolutionV1::None);
    let final_state = recovery.state;
    let rolled_forward_state = match &pending_resolution {
        CommandOutputCapturePendingResolutionV1::RolledForward { state, .. } => Some(*state),
        _ => None,
    };
    let pending_is_none_or_torn = matches!(
        pending_resolution,
        CommandOutputCapturePendingResolutionV1::None
            | CommandOutputCapturePendingResolutionV1::RemovedTorn { .. }
    );
    let resolution_action = if journal_was_created {
        CommandOutputCapturePhysicalResolutionActionV1::IntentTombstoned
    } else if final_state == CommandOutputCaptureJournalStateV1::TerminalPrepared
        && initial_state == Some(CommandOutputCaptureRestartStateV1::Published)
        && rolled_forward_state == Some(CommandOutputCaptureRestartStateV1::TerminalPrepared)
    {
        CommandOutputCapturePhysicalResolutionActionV1::TerminalPreparedRecovered
    } else if (initial_state == Some(CommandOutputCaptureRestartStateV1::Finished)
        || rolled_forward_state == Some(CommandOutputCaptureRestartStateV1::Finished))
        && final_state == CommandOutputCaptureJournalStateV1::Published
    {
        CommandOutputCapturePhysicalResolutionActionV1::FinishedPublicationRecovered
    } else if initial_state == Some(core_restart_state(final_state))
        && matches!(
            final_state,
            CommandOutputCaptureJournalStateV1::Published
                | CommandOutputCaptureJournalStateV1::TerminalPrepared
                | CommandOutputCaptureJournalStateV1::Cleaned
        )
        && pending_is_none_or_torn
    {
        CommandOutputCapturePhysicalResolutionActionV1::TerminalReadback
    } else if final_state == CommandOutputCaptureJournalStateV1::Cleaned
        && recovery.acquired.is_some()
    {
        CommandOutputCapturePhysicalResolutionActionV1::WorkingSetCleaned
    } else if final_state == CommandOutputCaptureJournalStateV1::Cleaned {
        CommandOutputCapturePhysicalResolutionActionV1::PreAcquisitionCleaned
    } else {
        return Err(CommandOutputStoreError::Manifest(
            "physical reconciliation final state has no exact core action classification".into(),
        ));
    };
    recovery.physical_reconciliation = Some(PhysicalReconciliationContextV1 {
        claim: claim.clone(),
        predecessor_fence_digest: physical_fence.predecessor_fence_digest.clone(),
        physical_fence_chain_length: u64::try_from(lease.recovery_fences.len()).map_err(|_| {
            CommandOutputStoreError::Manifest("physical fence-chain length overflowed".into())
        })?,
        physical_fence_digest: physical_fence.fence_digest.clone(),
        requested_store_head,
        initial_state,
        initial_store_head,
        pending_resolution,
        resolution_action,
        lifecycle_history,
        cleanup_completion_proof_digest: cleanup_completion_proof_digest(&lease.records)?,
    });
    Ok(())
}

enum CaptureJournalAdmission {
    Fresh(Box<CaptureJournalLease>),
    Existing,
}

fn admit_capture_journal(
    store: &CapabilityCommandOutputStore,
    intent: &CommandOutputCaptureIntentV1,
    capture_id: &CommandOutputCaptureId,
) -> Result<CaptureJournalAdmission, CommandOutputStoreError> {
    let journal_name = journal_name(capture_id);
    let Some(journal) = try_create_private_directory(&store.inner.root, &journal_name)? else {
        return Ok(CaptureJournalAdmission::Existing);
    };
    let journal_identity = validate_private_directory(&journal, "new capture journal")?;
    let lock = create_private_file(&journal, Path::new(LOCK_FILE))?;
    let lock_identity = validate_private_file(&lock, Path::new(LOCK_FILE), Some(0), 0)?;
    flock(&lock, FlockOperation::NonBlockingLockExclusive).map_err(|error| {
        CommandOutputStoreError::Manifest(format!(
            "new capture journal writer lock could not be acquired: {error}"
        ))
    })?;
    sync_directory(&journal).map_err(|error| {
        io_error(
            "sync new capture journal layout",
            Path::new(&journal_name),
            &error,
        )
    })?;
    sync_directory(&store.inner.root).map_err(|error| {
        io_error(
            "sync new capture journal namespace",
            Path::new(&journal_name),
            &error,
        )
    })?;
    let intent_record = StoredCaptureRecordDataV1::Intent {
        intent: intent.clone(),
        journal_directory: StoredObjectIdentityV1::from_directory(&journal)?,
        writer_lock: StoredObjectIdentityV1::from_file(&lock)?,
    };
    let mut lease = CaptureJournalLease {
        store: store.clone(),
        capture_id: capture_id.clone(),
        journal_name,
        journal,
        journal_identity,
        lock,
        lock_identity,
        records: Vec::new(),
        recovery_fences: Vec::new(),
        admitted_recovery_fence_digest: None,
        pending_record: None,
        pending_fence: None,
        last_pending_resolution: None,
    };
    lease
        .append(intent_record)
        .map_err(|error| capture_reconciliation(&intent.source, capture_id, error))?;
    Ok(CaptureJournalAdmission::Fresh(Box::new(lease)))
}

#[allow(
    clippy::too_many_lines,
    reason = "capture reservation keeps every durable cut, retained identity check, and acquired-anchor construction in one auditable custody transition"
)]
pub(super) fn reserve_capture(
    store: &CapabilityCommandOutputStore,
    intent: &CommandOutputCaptureIntentV1,
    dispatch_claim_id: &str,
    acquired_at_unix_ms: u64,
) -> Result<CommandOutputCaptureReservation, CommandOutputStoreError> {
    store.validate_root()?;
    intent.validate().map_err(core_contract_error)?;
    Digest::parse(dispatch_claim_id.to_string()).map_err(core_contract_error)?;
    if dispatch_claim_id != expected_dispatch_claim_id(&intent.source.effect_id) {
        return Err(CommandOutputStoreError::Source(
            "dispatch claim ID is not the deterministic claim for the capture effect".into(),
        ));
    }
    if acquired_at_unix_ms < intent.created_at_unix_ms {
        return Err(CommandOutputStoreError::Source(
            "capture acquisition time precedes its durable Intent".into(),
        ));
    }
    let capture_id = CommandOutputCaptureId::parse(intent.capture_id.clone())?;
    let source = intent.source.clone();
    let authenticated_maximum_bytes = intent.max_aggregate_output_bytes;
    let observed_private_state_digest = crate::service::inspect_private_state_digest(store.root())
        .map_err(|error| {
            CommandOutputStoreError::Root(format!(
                "cannot authenticate capture Intent private-state digest: {error}"
            ))
        })?;
    if observed_private_state_digest != intent.private_state_digest {
        return Err(CommandOutputStoreError::Source(
            "capture Intent private-state digest differs from the retained store root".into(),
        ));
    }
    let mut lease = match admit_capture_journal(store, intent, &capture_id)? {
        CaptureJournalAdmission::Fresh(lease) => *lease,
        CaptureJournalAdmission::Existing => {
            return Err(CommandOutputStoreError::Io {
                operation: "create capture-ID-derived private directory",
                path: Path::new(&journal_name(&capture_id)).to_path_buf(),
                message: "capture journal already exists".into(),
            });
        }
    };

    let working_name = working_name(&capture_id);
    let working = create_private_directory(&store.inner.root, &working_name)
        .map_err(|error| capture_reconciliation(&source, &capture_id, error))?;
    let working_identity = validate_private_directory(&working, "capture working directory")?;
    let stdout = create_private_file(&working, Path::new(STDOUT_FILE))?;
    let stdout_identity = validate_private_file(&stdout, Path::new(STDOUT_FILE), Some(0), 0)?;
    let stderr = create_private_file(&working, Path::new(STDERR_FILE))?;
    let stderr_identity = validate_private_file(&stderr, Path::new(STDERR_FILE), Some(0), 0)?;
    if stdout_identity.object == stderr_identity.object {
        return Err(capture_reconciliation(
            &source,
            &capture_id,
            CommandOutputStoreError::Artifact(
                "reserved stdout and stderr identify the same object".into(),
            ),
        ));
    }
    stdout.sync_all().map_err(|error| {
        capture_reconciliation(
            &source,
            &capture_id,
            io_error("sync reserved stdout", Path::new(STDOUT_FILE), &error),
        )
    })?;
    stderr.sync_all().map_err(|error| {
        capture_reconciliation(
            &source,
            &capture_id,
            io_error("sync reserved stderr", Path::new(STDERR_FILE), &error),
        )
    })?;
    sync_directory(&working).map_err(|error| {
        capture_reconciliation(
            &source,
            &capture_id,
            io_error(
                "sync reserved working directory",
                Path::new(&working_name),
                &error,
            ),
        )
    })?;
    sync_directory(&store.inner.root).map_err(|error| {
        capture_reconciliation(
            &source,
            &capture_id,
            io_error(
                "sync reserved working namespace",
                Path::new(&working_name),
                &error,
            ),
        )
    })?;
    let working_set = StoredWorkingSetIdentityV1 {
        directory: core_directory_identity(&working)?,
        stdout: core_file_identity(&stdout)?,
        stderr: core_file_identity(&stderr)?,
    };
    working_set.validate()?;
    let acquired_record_digest = lease
        .append(StoredCaptureRecordDataV1::Acquired {
            dispatch_claim_id: dispatch_claim_id.to_string(),
            acquired_at_unix_ms,
            working_set: working_set.clone(),
        })
        .map_err(|error| capture_reconciliation(&source, &capture_id, error))?
        .record_digest
        .clone();
    let anchor = CommandOutputCaptureAcquiredV1::try_new(
        intent,
        dispatch_claim_id,
        CommandOutputCaptureStoreHeadV1 {
            generation: 2,
            record_digest: acquired_record_digest,
        },
        working_set.directory.clone(),
        working_set.stdout.clone(),
        working_set.stderr.clone(),
        acquired_at_unix_ms,
    )
    .map_err(core_contract_error)?;
    Ok(CommandOutputCaptureReservation {
        store: store.clone(),
        capture_id,
        source,
        authenticated_maximum_bytes,
        working_name,
        working,
        working_identity,
        stdout,
        stdout_identity,
        stderr,
        stderr_identity,
        lease,
        anchor,
    })
}

pub(super) fn expected_dispatch_claim_id(effect_id: &str) -> String {
    let mut preimage = Vec::with_capacity(DISPATCH_CLAIM_ID_DOMAIN.len() + effect_id.len());
    preimage.extend_from_slice(DISPATCH_CLAIM_ID_DOMAIN);
    preimage.extend_from_slice(effect_id.as_bytes());
    Digest::sha256(&preimage).to_string()
}

pub(super) fn reopen_working(
    store: &CapabilityCommandOutputStore,
    anchor: &CommandOutputCaptureAcquiredV1,
) -> Result<OpenedWorkingSet, CommandOutputStoreError> {
    let capture_id = CommandOutputCaptureId::parse(anchor.capture_id.clone())?;
    let mut lease = acquire_lease(store, &capture_id)?;
    let recovery = recovery_from_records(store, &capture_id, &lease.records)?;
    if recovery.state != CommandOutputCaptureJournalStateV1::Acquired
        || recovery.head_digest() != &anchor.store_head.record_digest
        || recovery.acquired.as_ref() != Some(anchor)
    {
        return Err(capture_reconciliation(
            &anchor.source,
            &capture_id,
            CommandOutputStoreError::Reference(
                "capture anchor differs from the exact durable Acquired head".into(),
            ),
        ));
    }
    let working_name = working_name(&capture_id);
    let working = store
        .inner
        .root
        .open_dir_nofollow(&working_name)
        .map_err(|error| {
            capture_reconciliation(
                &anchor.source,
                &capture_id,
                io_error(
                    "open exact capture working directory",
                    Path::new(&working_name),
                    &error,
                ),
            )
        })?;
    let working_identity =
        validate_private_directory(&working, "reopened capture working directory")?;
    let stdout = open_private_output_file(&working, Path::new(STDOUT_FILE))?;
    let stdout_identity = validate_private_file(&stdout, Path::new(STDOUT_FILE), Some(0), 0)?;
    let stderr = open_private_output_file(&working, Path::new(STDERR_FILE))?;
    let stderr_identity = validate_private_file(&stderr, Path::new(STDERR_FILE), Some(0), 0)?;
    validate_exact_working_set(
        store,
        &working_name,
        &working,
        working_identity,
        &stdout,
        stdout_identity,
        &stderr,
        stderr_identity,
        0,
    )?;
    if working_identity != private_directory_identity(&anchor.working_directory)
        || stdout_identity != private_file_identity(&anchor.stdout)
        || stderr_identity != private_file_identity(&anchor.stderr)
    {
        return Err(capture_reconciliation(
            &anchor.source,
            &capture_id,
            CommandOutputStoreError::Artifact(
                "reopened working objects differ from acquired identities".into(),
            ),
        ));
    }
    lease
        .append(StoredCaptureRecordDataV1::WriterAttached)
        .map_err(|error| capture_reconciliation(&anchor.source, &capture_id, error))?;
    Ok(OpenedWorkingSet {
        stdout,
        stdout_identity,
        stderr,
        stderr_identity,
        directory: working,
        directory_identity: working_identity,
        working_name,
        source: anchor.source.clone(),
        source_digest: source_name_digest(&anchor.source)?,
        authenticated_maximum_bytes: anchor.max_aggregate_output_bytes,
        lease,
    })
}

/// Reopens the exact v1 `LaunchIntended` working set and idempotently replaces
/// both rejected stream contents with synchronized zero-length objects. No
/// observed pre-neutralization length or content commitment is returned.
pub(super) fn neutralize_sensitive_working(
    store: &CapabilityCommandOutputStore,
    anchor: &CommandOutputCaptureAcquiredV1,
    launch_intended_store_head: &CommandOutputCaptureStoreHeadV1,
) -> Result<(), CommandOutputStoreError> {
    neutralize_sensitive_working_with_probe(store, anchor, launch_intended_store_head, &mut |_| {
        Ok(())
    })
}

/// Reconstructs the exact clean `Finished -> Published` v1 lifecycle under a
/// durable core recovery fence.
///
/// The only transition this function may manufacture is `Finished`, and only
/// after the two acquired objects are synchronized and read twice against the
/// exact observation-backed artifact reference. `Published` is then recovered
/// through the ordinary no-replace publication path. Existing `Finished`,
/// `Published`, or `TerminalPrepared` state is accepted only when its retained
/// reference is byte-for-byte identical.
pub(super) fn resume_sensitive_clean_publication_under_claim(
    store: &CapabilityCommandOutputStore,
    intent: &CommandOutputCaptureIntentV1,
    claim: &CommandOutputCaptureReconciliationClaimV1,
    acquired: &CommandOutputCaptureAcquiredV1,
    launch_intended_store_head: &CommandOutputCaptureStoreHeadV1,
    reference: &CommandOutputArtifactSetReferenceV1,
) -> Result<CommandOutputCaptureRecovery, CommandOutputStoreError> {
    intent.validate().map_err(core_contract_error)?;
    claim.validate().map_err(core_contract_error)?;
    acquired
        .validate_against(intent)
        .map_err(core_contract_error)?;
    launch_intended_store_head
        .validate()
        .map_err(core_contract_error)?;
    reference.validate().map_err(core_contract_error)?;
    if claim.capture_id != intent.capture_id
        || acquired.capture_id != intent.capture_id
        || reference.source != acquired.source
        || reference
            .stdout
            .byte_length
            .checked_add(reference.stderr.byte_length)
            .is_none_or(|length| length > acquired.max_aggregate_output_bytes)
    {
        return Err(CommandOutputStoreError::Reference(
            "clean restart publication crossed its intent, acquisition, claim, or output bound"
                .into(),
        ));
    }

    let capture_id = CommandOutputCaptureId::parse(intent.capture_id.clone())?;
    let mut lease = acquire_recovery_lease(store, &capture_id)?;
    admit_recovery_intent(&mut lease, intent, claim)?;
    lease.resolve_pending_record()?;
    let before = recovery_from_records(store, &capture_id, &lease.records)?;
    if before.acquired.as_ref() != Some(acquired)
        || before.launch_intended_store_head.as_ref() != Some(launch_intended_store_head)
    {
        return Err(capture_reconciliation(
            &acquired.source,
            &capture_id,
            CommandOutputStoreError::Reference(
                "clean restart publication crossed exact launch custody".into(),
            ),
        ));
    }
    match before.state {
        CommandOutputCaptureJournalStateV1::LaunchIntended => {
            validate_sensitive_clean_working_reference(store, &lease, acquired, reference)?;
            lease.append_finished(reference.stdout.clone(), reference.stderr.clone())?;
        }
        CommandOutputCaptureJournalStateV1::Finished
        | CommandOutputCaptureJournalStateV1::Published
        | CommandOutputCaptureJournalStateV1::TerminalPrepared => {
            if before.expected_reference.as_ref() != Some(reference) {
                return Err(capture_reconciliation(
                    &acquired.source,
                    &capture_id,
                    CommandOutputStoreError::Reference(
                        "clean restart publication crossed the retained artifact reference".into(),
                    ),
                ));
            }
        }
        state => {
            return Err(capture_reconciliation(
                &acquired.source,
                &capture_id,
                CommandOutputStoreError::Reference(format!(
                    "clean restart publication cannot continue from v1 state {state:?}"
                )),
            ));
        }
    }
    drop(lease);

    let recovered = reconcile_capture_restart(store, intent, claim, Some(&acquired.store_head))?;
    if !matches!(
        recovered.state,
        CommandOutputCaptureJournalStateV1::Published
            | CommandOutputCaptureJournalStateV1::TerminalPrepared
    ) || recovered.acquired.as_ref() != Some(acquired)
        || recovered.launch_intended_store_head.as_ref() != Some(launch_intended_store_head)
        || recovered.expected_reference.as_ref() != Some(reference)
        || recovered.finished_store_head.is_none()
        || recovered.published_store_head.is_none()
        || recovered.physical_reconciliation_claim() != Some(claim)
    {
        return Err(capture_reconciliation(
            &acquired.source,
            &capture_id,
            CommandOutputStoreError::Reference(
                "clean restart publication did not produce exact fenced immutable readback".into(),
            ),
        ));
    }
    Ok(recovered)
}

/// Appends or reads back the exact clean `TerminalPrepared` successor while
/// retaining the recovery fence that already owns the published capture.
///
/// The incoming claim must be the publication claim itself or a higher claim
/// that names it as predecessor. The helper resolves only an interrupted copy
/// of the same terminal record, appends only `TerminalPrepared`, and finishes
/// with a second claim-fenced terminal readback. No generic post-recovery
/// mutation authority is recreated.
#[allow(
    clippy::too_many_arguments,
    clippy::too_many_lines,
    reason = "the terminal seam keeps claim lineage, publication custody, pending-record repair, one exact append, and fenced readback adjacent"
)]
pub(super) fn prepare_sensitive_clean_terminal_under_claim(
    store: &CapabilityCommandOutputStore,
    intent: &CommandOutputCaptureIntentV1,
    claim: &CommandOutputCaptureReconciliationClaimV1,
    publication_claim: &CommandOutputCaptureReconciliationClaimV1,
    acquired: &CommandOutputCaptureAcquiredV1,
    launch_intended_store_head: &CommandOutputCaptureStoreHeadV1,
    reference: &CommandOutputArtifactSetReferenceV1,
    expected_published_head: &CommandOutputCaptureStoreHeadV1,
    terminal: &CommandOutputCaptureCanonicalPayloadV1,
) -> Result<CommandOutputCaptureRecovery, CommandOutputStoreError> {
    intent.validate().map_err(core_contract_error)?;
    claim.validate().map_err(core_contract_error)?;
    publication_claim.validate().map_err(core_contract_error)?;
    acquired
        .validate_against(intent)
        .map_err(core_contract_error)?;
    launch_intended_store_head
        .validate()
        .map_err(core_contract_error)?;
    reference.validate().map_err(core_contract_error)?;
    expected_published_head
        .validate()
        .map_err(core_contract_error)?;
    terminal.validate(MAX_CAPTURE_TERMINAL_PAYLOAD_BYTES)?;
    let claim_is_same = claim == publication_claim;
    let claim_is_higher_successor = claim.claim_epoch > publication_claim.claim_epoch
        && claim.previous_claim_id.as_deref() == Some(publication_claim.claim_id.as_str());
    if claim.capture_id != intent.capture_id
        || publication_claim.capture_id != intent.capture_id
        || acquired.capture_id != intent.capture_id
        || reference.source != acquired.source
        || (!claim_is_same && !claim_is_higher_successor)
    {
        return Err(CommandOutputStoreError::Reference(
            "clean terminal preparation crossed intent, acquisition, publication claim, successor claim, or artifact"
                .into(),
        ));
    }

    let capture_id = CommandOutputCaptureId::parse(intent.capture_id.clone())?;
    let mut lease = acquire_recovery_lease(store, &capture_id)?;
    admit_recovery_intent(&mut lease, intent, claim)?;
    lease.resolve_pending_record()?;
    let before = recovery_from_records(store, &capture_id, &lease.records)?;
    if before.acquired.as_ref() != Some(acquired)
        || before.launch_intended_store_head.as_ref() != Some(launch_intended_store_head)
        || before.expected_reference.as_ref() != Some(reference)
        || before.published_store_head.as_ref() != Some(expected_published_head)
    {
        return Err(capture_reconciliation(
            &acquired.source,
            &capture_id,
            CommandOutputStoreError::Reference(
                "clean terminal preparation crossed exact published custody".into(),
            ),
        ));
    }
    match before.state {
        CommandOutputCaptureJournalStateV1::Published => {
            lease.append(StoredCaptureRecordDataV1::TerminalPrepared {
                terminal: terminal.clone(),
            })?;
        }
        CommandOutputCaptureJournalStateV1::TerminalPrepared => {
            if before.terminal.as_ref() != Some(terminal) {
                return Err(capture_reconciliation(
                    &acquired.source,
                    &capture_id,
                    CommandOutputStoreError::Reference(
                        "idempotent clean terminal preparation crossed exact terminal bytes".into(),
                    ),
                ));
            }
        }
        state => {
            return Err(capture_reconciliation(
                &acquired.source,
                &capture_id,
                CommandOutputStoreError::Reference(format!(
                    "clean terminal preparation cannot continue from v1 state {state:?}"
                )),
            ));
        }
    }
    let prepared = recovery_from_records(store, &capture_id, &lease.records)?;
    if prepared.state != CommandOutputCaptureJournalStateV1::TerminalPrepared
        || prepared.acquired.as_ref() != Some(acquired)
        || prepared.launch_intended_store_head.as_ref() != Some(launch_intended_store_head)
        || prepared.expected_reference.as_ref() != Some(reference)
        || prepared.published_store_head.as_ref() != Some(expected_published_head)
        || prepared.terminal.as_ref() != Some(terminal)
        || prepared.terminal_prepared_store_head.is_none()
    {
        return Err(capture_reconciliation(
            &acquired.source,
            &capture_id,
            CommandOutputStoreError::Reference(
                "clean terminal preparation did not read back its exact immutable successor".into(),
            ),
        ));
    }
    drop(lease);

    let fenced = reconcile_capture_restart(store, intent, claim, Some(&acquired.store_head))?;
    if fenced.state != CommandOutputCaptureJournalStateV1::TerminalPrepared
        || fenced.acquired.as_ref() != Some(acquired)
        || fenced.launch_intended_store_head.as_ref() != Some(launch_intended_store_head)
        || fenced.expected_reference.as_ref() != Some(reference)
        || fenced.published_store_head.as_ref() != Some(expected_published_head)
        || fenced.terminal.as_ref() != Some(terminal)
        || fenced.terminal_prepared_store_head != prepared.terminal_prepared_store_head
        || fenced.physical_reconciliation_claim() != Some(claim)
    {
        return Err(capture_reconciliation(
            &acquired.source,
            &capture_id,
            CommandOutputStoreError::Reference(
                "clean terminal preparation lost exact claim-fenced terminal readback".into(),
            ),
        ));
    }
    Ok(fenced)
}

#[allow(
    clippy::too_many_lines,
    reason = "the descriptor-relative clean rejoin keeps identity, synchronization, stable hashing, and namespace checks adjacent"
)]
fn validate_sensitive_clean_working_reference(
    store: &CapabilityCommandOutputStore,
    lease: &CaptureJournalLease,
    acquired: &CommandOutputCaptureAcquiredV1,
    reference: &CommandOutputArtifactSetReferenceV1,
) -> Result<(), CommandOutputStoreError> {
    validate_lease_names(lease)?;
    let capture_id = CommandOutputCaptureId::parse(acquired.capture_id.clone())?;
    let name = working_name(&capture_id);
    let directory = store.inner.root.open_dir_nofollow(&name).map_err(|error| {
        capture_reconciliation(
            &acquired.source,
            &capture_id,
            io_error(
                "open clean restart working directory",
                Path::new(&name),
                &error,
            ),
        )
    })?;
    let directory_identity =
        validate_private_directory(&directory, "clean restart working directory")?;
    if directory_identity != private_directory_identity(&acquired.working_directory)
        || exact_entry_names(&directory, &name, 2)?
            != BTreeSet::from([STDOUT_FILE.to_owned(), STDERR_FILE.to_owned()])
    {
        return Err(capture_reconciliation(
            &acquired.source,
            &capture_id,
            CommandOutputStoreError::Artifact(
                "clean restart working directory identity or entries changed".into(),
            ),
        ));
    }
    let mut stdout = open_private_file(&directory, Path::new(STDOUT_FILE))?;
    let mut stderr = open_private_file(&directory, Path::new(STDERR_FILE))?;
    let stdout_identity = validate_private_file(
        &stdout,
        Path::new(STDOUT_FILE),
        Some(reference.stdout.byte_length),
        reference.stdout.byte_length,
    )?;
    let stderr_identity = validate_private_file(
        &stderr,
        Path::new(STDERR_FILE),
        Some(reference.stderr.byte_length),
        reference.stderr.byte_length,
    )?;
    if stdout_identity.object != private_file_identity(&acquired.stdout).object
        || stderr_identity.object != private_file_identity(&acquired.stderr).object
        || stdout_identity.object == stderr_identity.object
    {
        return Err(capture_reconciliation(
            &acquired.source,
            &capture_id,
            CommandOutputStoreError::Artifact(
                "clean restart streams differ from their acquired identities".into(),
            ),
        ));
    }
    stdout.sync_all().map_err(|error| {
        io_error(
            "synchronize clean restart stdout",
            Path::new(STDOUT_FILE),
            &error,
        )
    })?;
    stderr.sync_all().map_err(|error| {
        io_error(
            "synchronize clean restart stderr",
            Path::new(STDERR_FILE),
            &error,
        )
    })?;
    super::verify_stream_file(&mut stdout, Path::new(STDOUT_FILE), &reference.stdout)?;
    super::verify_stream_file(&mut stderr, Path::new(STDERR_FILE), &reference.stderr)?;
    store.validate_named_directory(&name, directory_identity)
}

/// Conservatively closes a generation-five-through-seven partial branch as
/// terminal `Unknown` under one exact core fence.
///
/// Active `LaunchIntended` or `Finished` objects are zeroed before a cleanup
/// plan is persisted. Immutable `Published`/`TerminalPrepared` artifacts are
/// never deleted or rewritten; they remain retained but receive no success or
/// replay authority. The returned recovery always carries the durable claim
/// context needed by the typed outer disposition.
pub(super) fn quarantine_sensitive_partial_terminal_unknown_under_claim(
    store: &CapabilityCommandOutputStore,
    intent: &CommandOutputCaptureIntentV1,
    claim: &CommandOutputCaptureReconciliationClaimV1,
    acquired: &CommandOutputCaptureAcquiredV1,
    launch_intended_store_head: &CommandOutputCaptureStoreHeadV1,
) -> Result<CommandOutputCaptureRecovery, CommandOutputStoreError> {
    intent.validate().map_err(core_contract_error)?;
    claim.validate().map_err(core_contract_error)?;
    acquired
        .validate_against(intent)
        .map_err(core_contract_error)?;
    launch_intended_store_head
        .validate()
        .map_err(core_contract_error)?;
    if claim.capture_id != intent.capture_id || acquired.capture_id != intent.capture_id {
        return Err(CommandOutputStoreError::Reference(
            "partial-terminal Unknown claim crossed its intent or acquisition".into(),
        ));
    }

    let capture_id = CommandOutputCaptureId::parse(intent.capture_id.clone())?;
    let mut lease = acquire_recovery_lease(store, &capture_id)?;
    admit_recovery_intent(&mut lease, intent, claim)?;
    lease.resolve_pending_record()?;
    let before = recovery_from_records(store, &capture_id, &lease.records)?;
    if before.acquired.as_ref() != Some(acquired)
        || before.launch_intended_store_head.as_ref() != Some(launch_intended_store_head)
    {
        return Err(capture_reconciliation(
            &acquired.source,
            &capture_id,
            CommandOutputStoreError::Reference(
                "partial-terminal Unknown crossed exact launch custody".into(),
            ),
        ));
    }

    match before.state {
        CommandOutputCaptureJournalStateV1::LaunchIntended
        | CommandOutputCaptureJournalStateV1::Finished => {
            neutralize_partial_terminal_working_under_lease(store, &lease, acquired, before.state)?;
            lease.append_cleanup_intended()?;
            complete_durable_cleanup_plan(store, &mut lease, &mut |_| Ok(()))?;
        }
        CommandOutputCaptureJournalStateV1::CleanupIntended => {
            validate_partial_terminal_zero_cleanup_plan(&lease, acquired)?;
            complete_durable_cleanup_plan(store, &mut lease, &mut |_| Ok(()))?;
        }
        CommandOutputCaptureJournalStateV1::Cleaned
        | CommandOutputCaptureJournalStateV1::Published
        | CommandOutputCaptureJournalStateV1::TerminalPrepared => {}
        state => {
            return Err(capture_reconciliation(
                &acquired.source,
                &capture_id,
                CommandOutputStoreError::Reference(format!(
                    "partial-terminal Unknown cannot close v1 state {state:?}"
                )),
            ));
        }
    }
    drop(lease);

    let recovered = reconcile_capture_restart(store, intent, claim, Some(&acquired.store_head))?;
    if !matches!(
        recovered.state,
        CommandOutputCaptureJournalStateV1::Cleaned
            | CommandOutputCaptureJournalStateV1::Published
            | CommandOutputCaptureJournalStateV1::TerminalPrepared
    ) || recovered.acquired.as_ref() != Some(acquired)
        || recovered.launch_intended_store_head.as_ref() != Some(launch_intended_store_head)
        || recovered.physical_reconciliation_claim() != Some(claim)
    {
        return Err(capture_reconciliation(
            &acquired.source,
            &capture_id,
            CommandOutputStoreError::Reference(
                "partial-terminal Unknown did not produce exact fenced closed readback".into(),
            ),
        ));
    }
    Ok(recovered)
}

#[allow(
    clippy::too_many_lines,
    reason = "zero-first partial-terminal cleanup keeps exact descriptors, identity, synchronization, and final zero readback together"
)]
fn neutralize_partial_terminal_working_under_lease(
    store: &CapabilityCommandOutputStore,
    lease: &CaptureJournalLease,
    acquired: &CommandOutputCaptureAcquiredV1,
    state: CommandOutputCaptureJournalStateV1,
) -> Result<(), CommandOutputStoreError> {
    validate_lease_names(lease)?;
    let capture_id = CommandOutputCaptureId::parse(acquired.capture_id.clone())?;
    let name = working_name(&capture_id);
    let directory = store.inner.root.open_dir_nofollow(&name).map_err(|error| {
        capture_reconciliation(
            &acquired.source,
            &capture_id,
            io_error(
                "open partial-terminal working directory",
                Path::new(&name),
                &error,
            ),
        )
    })?;
    let directory_identity =
        validate_private_directory(&directory, "partial-terminal working directory")?;
    let names = exact_entry_names(&directory, &name, 3)?;
    let streams = BTreeSet::from([STDOUT_FILE.to_owned(), STDERR_FILE.to_owned()]);
    let streams_and_manifest = BTreeSet::from([
        MANIFEST_FILE.to_owned(),
        STDOUT_FILE.to_owned(),
        STDERR_FILE.to_owned(),
    ]);
    if directory_identity != private_directory_identity(&acquired.working_directory)
        || (names != streams
            && !(state == CommandOutputCaptureJournalStateV1::Finished
                && names == streams_and_manifest))
    {
        return Err(capture_reconciliation(
            &acquired.source,
            &capture_id,
            CommandOutputStoreError::Artifact(
                "partial-terminal working directory identity or entries changed".into(),
            ),
        ));
    }
    let stdout = open_private_output_file(&directory, Path::new(STDOUT_FILE))?;
    let stderr = open_private_output_file(&directory, Path::new(STDERR_FILE))?;
    for (file, path, expected) in [
        (
            &stdout,
            Path::new(STDOUT_FILE),
            private_file_identity(&acquired.stdout),
        ),
        (
            &stderr,
            Path::new(STDERR_FILE),
            private_file_identity(&acquired.stderr),
        ),
    ] {
        let observed =
            validate_private_file(file, path, None, acquired.max_aggregate_output_bytes)?;
        if observed.object != expected.object {
            return Err(capture_reconciliation(
                &acquired.source,
                &capture_id,
                CommandOutputStoreError::Artifact(format!(
                    "partial-terminal {} identity changed",
                    path.display()
                )),
            ));
        }
        file.set_len(0)
            .map_err(|error| io_error("truncate partial-terminal stream", path, &error))?;
        file.sync_all()
            .map_err(|error| io_error("synchronize partial-terminal zero state", path, &error))?;
        validate_zero_sensitive_stream(file, path, expected)?;
    }
    sync_directory(&directory).map_err(|error| {
        io_error(
            "synchronize partial-terminal working directory",
            Path::new(&name),
            &error,
        )
    })?;
    store.validate_named_directory(&name, directory_identity)
}

fn validate_partial_terminal_zero_cleanup_plan(
    lease: &CaptureJournalLease,
    acquired: &CommandOutputCaptureAcquiredV1,
) -> Result<(), CommandOutputStoreError> {
    let (_, plan, _) = cleanup_intent_material(&lease.records)?;
    let stdout = plan.stdout.as_ref().ok_or_else(|| {
        CommandOutputStoreError::Manifest(
            "partial-terminal cleanup plan lost stdout identity".into(),
        )
    })?;
    let stderr = plan.stderr.as_ref().ok_or_else(|| {
        CommandOutputStoreError::Manifest(
            "partial-terminal cleanup plan lost stderr identity".into(),
        )
    })?;
    if stdout.byte_length != 0
        || stderr.byte_length != 0
        || (stdout.device, stdout.inode) != (acquired.stdout.device_id, acquired.stdout.inode)
        || (stderr.device, stderr.inode) != (acquired.stderr.device_id, acquired.stderr.inode)
    {
        return Err(CommandOutputStoreError::Manifest(
            "partial-terminal cleanup plan is not exact zeroed acquired custody".into(),
        ));
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum SensitiveNeutralizationCheckpoint {
    StdoutTruncated,
    StdoutSynchronized,
    StdoutZeroReadBack,
    StderrTruncated,
    StderrSynchronized,
    StderrZeroReadBack,
}

#[cfg(test)]
pub(super) fn inject_sensitive_neutralization_cut(
    store: &CapabilityCommandOutputStore,
    anchor: &CommandOutputCaptureAcquiredV1,
    launch_intended_store_head: &CommandOutputCaptureStoreHeadV1,
    cut: SensitiveNeutralizationCheckpoint,
) -> Result<(), CommandOutputStoreError> {
    let mut injected = false;
    neutralize_sensitive_working_with_probe(
        store,
        anchor,
        launch_intended_store_head,
        &mut |checkpoint| {
            if checkpoint == cut && !injected {
                injected = true;
                Err(format!("injected {cut:?}"))
            } else {
                Ok(())
            }
        },
    )
}

fn neutralize_sensitive_working_with_probe(
    store: &CapabilityCommandOutputStore,
    anchor: &CommandOutputCaptureAcquiredV1,
    launch_intended_store_head: &CommandOutputCaptureStoreHeadV1,
    probe: &mut impl FnMut(SensitiveNeutralizationCheckpoint) -> Result<(), String>,
) -> Result<(), CommandOutputStoreError> {
    let capture_id = CommandOutputCaptureId::parse(anchor.capture_id.clone())?;
    let working = open_sensitive_working(store, anchor, launch_intended_store_head)?;
    working.stdout.set_len(0).map_err(|error| {
        capture_reconciliation(
            &anchor.source,
            &capture_id,
            io_error(
                "truncate rejected stdout staging",
                Path::new(STDOUT_FILE),
                &error,
            ),
        )
    })?;
    probe(SensitiveNeutralizationCheckpoint::StdoutTruncated).map_err(|reason| {
        capture_reconciliation(
            &anchor.source,
            &capture_id,
            CommandOutputStoreError::Artifact(reason),
        )
    })?;
    working.stdout.sync_all().map_err(|error| {
        io_error(
            "synchronize rejected stdout zero state",
            Path::new(STDOUT_FILE),
            &error,
        )
    })?;
    probe(SensitiveNeutralizationCheckpoint::StdoutSynchronized).map_err(|reason| {
        capture_reconciliation(
            &anchor.source,
            &capture_id,
            CommandOutputStoreError::Artifact(reason),
        )
    })?;
    validate_zero_sensitive_stream(
        &working.stdout,
        Path::new(STDOUT_FILE),
        private_file_identity(&anchor.stdout),
    )?;
    probe(SensitiveNeutralizationCheckpoint::StdoutZeroReadBack).map_err(|reason| {
        capture_reconciliation(
            &anchor.source,
            &capture_id,
            CommandOutputStoreError::Artifact(reason),
        )
    })?;
    working.stderr.set_len(0).map_err(|error| {
        io_error(
            "truncate rejected stderr staging",
            Path::new(STDERR_FILE),
            &error,
        )
    })?;
    probe(SensitiveNeutralizationCheckpoint::StderrTruncated).map_err(|reason| {
        capture_reconciliation(
            &anchor.source,
            &capture_id,
            CommandOutputStoreError::Artifact(reason),
        )
    })?;
    working.stderr.sync_all().map_err(|error| {
        io_error(
            "synchronize rejected stderr zero state",
            Path::new(STDERR_FILE),
            &error,
        )
    })?;
    probe(SensitiveNeutralizationCheckpoint::StderrSynchronized).map_err(|reason| {
        capture_reconciliation(
            &anchor.source,
            &capture_id,
            CommandOutputStoreError::Artifact(reason),
        )
    })?;
    validate_zero_sensitive_stream(
        &working.stderr,
        Path::new(STDERR_FILE),
        private_file_identity(&anchor.stderr),
    )?;
    probe(SensitiveNeutralizationCheckpoint::StderrZeroReadBack).map_err(|reason| {
        capture_reconciliation(
            &anchor.source,
            &capture_id,
            CommandOutputStoreError::Artifact(reason),
        )
    })?;
    validate_zero_sensitive_working(store, anchor, &working)
}

fn validate_zero_sensitive_stream(
    file: &File,
    name: &Path,
    mut expected: PrivateFileIdentity,
) -> Result<(), CommandOutputStoreError> {
    expected.length = 0;
    if validate_private_file(file, name, Some(0), 0)? != expected {
        return Err(CommandOutputStoreError::Artifact(format!(
            "neutralized {} changed identity",
            name.display()
        )));
    }
    Ok(())
}

/// Proves that both exact `LaunchIntended` staging objects remain at zero
/// length before a frozen-v1 cleanup plan is allowed to inspect them.
pub(super) fn validate_sensitive_working_neutralized(
    store: &CapabilityCommandOutputStore,
    anchor: &CommandOutputCaptureAcquiredV1,
    launch_intended_store_head: &CommandOutputCaptureStoreHeadV1,
) -> Result<(), CommandOutputStoreError> {
    let working = open_sensitive_working(store, anchor, launch_intended_store_head)?;
    validate_zero_sensitive_working(store, anchor, &working)
}

/// Revalidates a restart cleanup plan that was already frozen after v2
/// neutralization. The plan must identify the acquired objects at zero length
/// and must not contain a manifest or any additional entry.
pub(super) fn validate_sensitive_cleanup_plan_zero(
    store: &CapabilityCommandOutputStore,
    anchor: &CommandOutputCaptureAcquiredV1,
    launch_intended_store_head: &CommandOutputCaptureStoreHeadV1,
) -> Result<(), CommandOutputStoreError> {
    let capture_id = CommandOutputCaptureId::parse(anchor.capture_id.clone())?;
    let lease = acquire_lease(store, &capture_id)?;
    let recovery = recovery_from_records(store, &capture_id, &lease.records)?;
    if !matches!(
        recovery.state,
        CommandOutputCaptureJournalStateV1::CleanupIntended
            | CommandOutputCaptureJournalStateV1::Cleaned
    ) || recovery.acquired.as_ref() != Some(anchor)
        || recovery.launch_intended_store_head.as_ref() != Some(launch_intended_store_head)
    {
        return Err(capture_reconciliation(
            &anchor.source,
            &capture_id,
            CommandOutputStoreError::Reference(
                "sensitive-output cleanup plan crossed v1 LaunchIntended custody".into(),
            ),
        ));
    }
    let (_, plan, _) = cleanup_intent_material(&lease.records)?;
    let stdout = plan.stdout.as_ref().ok_or_else(|| {
        CommandOutputStoreError::Manifest(
            "sensitive-output cleanup plan lost stdout identity".into(),
        )
    })?;
    let stderr = plan.stderr.as_ref().ok_or_else(|| {
        CommandOutputStoreError::Manifest(
            "sensitive-output cleanup plan lost stderr identity".into(),
        )
    })?;
    if plan.manifest.is_some()
        || plan.entry_names != BTreeSet::from([STDOUT_FILE.to_owned(), STDERR_FILE.to_owned()])
        || stdout.byte_length != 0
        || stderr.byte_length != 0
        || (stdout.device, stdout.inode) != (anchor.stdout.device_id, anchor.stdout.inode)
        || (stderr.device, stderr.inode) != (anchor.stderr.device_id, anchor.stderr.inode)
    {
        return Err(CommandOutputStoreError::Manifest(
            "sensitive-output cleanup plan is not exact acquired zero-length custody".into(),
        ));
    }
    Ok(())
}

fn open_sensitive_working(
    store: &CapabilityCommandOutputStore,
    anchor: &CommandOutputCaptureAcquiredV1,
    launch_intended_store_head: &CommandOutputCaptureStoreHeadV1,
) -> Result<SensitiveWorkingSet, CommandOutputStoreError> {
    anchor.validate().map_err(core_contract_error)?;
    launch_intended_store_head
        .validate()
        .map_err(core_contract_error)?;
    let capture_id = CommandOutputCaptureId::parse(anchor.capture_id.clone())?;
    let lease = acquire_lease(store, &capture_id)?;
    let recovery = recovery_from_records(store, &capture_id, &lease.records)?;
    if recovery.state != CommandOutputCaptureJournalStateV1::LaunchIntended
        || recovery.acquired.as_ref() != Some(anchor)
        || recovery.launch_intended_store_head.as_ref() != Some(launch_intended_store_head)
    {
        return Err(capture_reconciliation(
            &anchor.source,
            &capture_id,
            CommandOutputStoreError::Reference(
                "sensitive-output restart differs from exact v1 LaunchIntended custody".into(),
            ),
        ));
    }
    let working_name = working_name(&capture_id);
    let directory = store
        .inner
        .root
        .open_dir_nofollow(&working_name)
        .map_err(|error| {
            capture_reconciliation(
                &anchor.source,
                &capture_id,
                io_error(
                    "open sensitive-output working directory",
                    Path::new(&working_name),
                    &error,
                ),
            )
        })?;
    let directory_identity =
        validate_private_directory(&directory, "sensitive-output working directory")?;
    if directory_identity != private_directory_identity(&anchor.working_directory)
        || exact_entry_names(&directory, &working_name, 2)?
            != BTreeSet::from([STDOUT_FILE.to_owned(), STDERR_FILE.to_owned()])
    {
        return Err(capture_reconciliation(
            &anchor.source,
            &capture_id,
            CommandOutputStoreError::Artifact(
                "sensitive-output working directory identity or entries changed".into(),
            ),
        ));
    }
    let stdout = open_private_output_file(&directory, Path::new(STDOUT_FILE))?;
    let stderr = open_private_output_file(&directory, Path::new(STDERR_FILE))?;
    let stdout_identity = validate_private_file(
        &stdout,
        Path::new(STDOUT_FILE),
        None,
        anchor.max_aggregate_output_bytes,
    )?;
    let stderr_identity = validate_private_file(
        &stderr,
        Path::new(STDERR_FILE),
        None,
        anchor.max_aggregate_output_bytes,
    )?;
    if stdout_identity.object != private_file_identity(&anchor.stdout).object
        || stderr_identity.object != private_file_identity(&anchor.stderr).object
        || stdout_identity
            .length
            .checked_add(stderr_identity.length)
            .is_none_or(|length| length > anchor.max_aggregate_output_bytes)
    {
        return Err(capture_reconciliation(
            &anchor.source,
            &capture_id,
            CommandOutputStoreError::Artifact(
                "sensitive-output stream identity or aggregate bound changed".into(),
            ),
        ));
    }
    store.validate_named_directory(&working_name, directory_identity)?;
    Ok(SensitiveWorkingSet {
        stdout,
        stderr,
        directory,
        directory_identity,
        working_name,
        _lease: lease,
    })
}

fn validate_zero_sensitive_working(
    store: &CapabilityCommandOutputStore,
    anchor: &CommandOutputCaptureAcquiredV1,
    working: &SensitiveWorkingSet,
) -> Result<(), CommandOutputStoreError> {
    let stdout = validate_private_file(&working.stdout, Path::new(STDOUT_FILE), Some(0), 0)?;
    let stderr = validate_private_file(&working.stderr, Path::new(STDERR_FILE), Some(0), 0)?;
    if stdout.object != private_file_identity(&anchor.stdout).object
        || stderr.object != private_file_identity(&anchor.stderr).object
        || validate_private_directory(
            &working.directory,
            "neutralized sensitive-output working directory",
        )? != working.directory_identity
    {
        return Err(CommandOutputStoreError::Artifact(
            "neutralized sensitive-output objects changed identity".into(),
        ));
    }
    store.validate_named_directory(&working.working_name, working.directory_identity)
}

pub(super) fn reopen_capture(
    store: &CapabilityCommandOutputStore,
    capture_id: &CommandOutputCaptureId,
) -> Result<CommandOutputCaptureRecovery, CommandOutputStoreError> {
    let lease = acquire_lease(store, capture_id)?;
    let mut recovery = recovery_from_records(store, capture_id, &lease.records)?;
    recovery.pending_record = lease
        .pending_record
        .as_ref()
        .map(PendingRecordFile::public_view);
    drop(lease);
    Ok(recovery)
}

pub(super) fn prepare_terminal(
    store: &CapabilityCommandOutputStore,
    capture_id: &CommandOutputCaptureId,
    expected_head: &CommandOutputCaptureStoreHeadV1,
    terminal: CommandOutputCaptureCanonicalPayloadV1,
) -> Result<CommandOutputCaptureRecovery, CommandOutputStoreError> {
    terminal.validate(MAX_CAPTURE_TERMINAL_PAYLOAD_BYTES)?;
    let mut lease = acquire_lease(store, capture_id)?;
    let actual_generation = u64::try_from(lease.records.len()).expect("bounded records fit u64");
    if lease.head_digest() != &expected_head.record_digest
        || actual_generation != expected_head.generation
    {
        let source = intent_source(&lease.records)?.clone();
        return Err(capture_reconciliation(
            &source,
            capture_id,
            CommandOutputStoreError::Reference(
                "terminal preparation expected a different journal head".into(),
            ),
        ));
    }
    let before = recovery_from_records(store, capture_id, &lease.records)?;
    if before.state != CommandOutputCaptureJournalStateV1::Published {
        return Err(capture_reconciliation(
            &before.source,
            capture_id,
            CommandOutputStoreError::Reference(
                "terminal preparation requires a physically verified Published head".into(),
            ),
        ));
    }
    lease.append(StoredCaptureRecordDataV1::TerminalPrepared { terminal })?;
    recovery_from_records(store, capture_id, &lease.records)
}

/// Reconciles one exact physical capture under a durable core fencing claim.
///
/// The capture-ID-derived journal directory is the atomic admission point. A
/// recovery owner that creates it writes an intent-only cleanup tombstone; a
/// recovery owner that loses that `mkdir` race opens and classifies the exact
/// winner. No branch creates working stream files or execution authority.
pub(super) fn reconcile_capture_restart(
    store: &CapabilityCommandOutputStore,
    intent: &CommandOutputCaptureIntentV1,
    claim: &CommandOutputCaptureReconciliationClaimV1,
    expected_head: Option<&CommandOutputCaptureStoreHeadV1>,
) -> Result<CommandOutputCaptureRecovery, CommandOutputStoreError> {
    reconcile_capture_restart_with_probe(store, intent, claim, expected_head, &mut |_| Ok(()))
}

fn reconcile_capture_restart_with_probe(
    store: &CapabilityCommandOutputStore,
    intent: &CommandOutputCaptureIntentV1,
    claim: &CommandOutputCaptureReconciliationClaimV1,
    expected_head: Option<&CommandOutputCaptureStoreHeadV1>,
    cleanup_probe: &mut impl FnMut(CleanupCheckpoint) -> Result<(), String>,
) -> Result<CommandOutputCaptureRecovery, CommandOutputStoreError> {
    store.validate_root()?;
    intent.validate().map_err(core_contract_error)?;
    claim.validate().map_err(core_contract_error)?;
    if claim.capture_id != intent.capture_id {
        return Err(CommandOutputStoreError::Reference(
            "restart claim is crossed with another capture Intent".into(),
        ));
    }
    if let Some(head) = expected_head {
        head.validate().map_err(core_contract_error)?;
    }
    let observed_private_state_digest = crate::service::inspect_private_state_digest(store.root())
        .map_err(|error| {
            CommandOutputStoreError::Root(format!(
                "cannot authenticate restart capture private-state digest: {error}"
            ))
        })?;
    if observed_private_state_digest != intent.private_state_digest {
        return Err(CommandOutputStoreError::Source(
            "restart capture Intent private-state digest differs from the retained store root"
                .into(),
        ));
    }

    let capture_id = CommandOutputCaptureId::parse(intent.capture_id.clone())?;
    let (mut lease, journal_was_created) = match admit_capture_journal(store, intent, &capture_id)?
    {
        CaptureJournalAdmission::Fresh(lease) => (*lease, true),
        CaptureJournalAdmission::Existing => (acquire_recovery_lease(store, &capture_id)?, false),
    };
    let initial_record = (!journal_was_created)
        .then(|| lease.records.last())
        .flatten();
    let initial_state = initial_record.map(|record| core_restart_state(record.data.state()));
    let initial_store_head = initial_record.map(|record| CommandOutputCaptureStoreHeadV1 {
        generation: record.sequence,
        record_digest: record.record_digest.clone(),
    });
    admit_recovery_intent(&mut lease, intent, claim)
        .map_err(|error| capture_reconciliation(&intent.source, &capture_id, error))?;

    let stable_head = lease.head();
    let stable_state = lease
        .records
        .last()
        .expect("capture journal always has Intent")
        .data
        .state();
    let exact_expected_head = match expected_head {
        Some(expected) => expected,
        None if journal_was_created
            || stable_state == CommandOutputCaptureJournalStateV1::Intent
            || (stable_state == CommandOutputCaptureJournalStateV1::Acquired
                && lease.pending_record.is_none())
            || matches!(
                stable_state,
                CommandOutputCaptureJournalStateV1::CleanupIntended
                    | CommandOutputCaptureJournalStateV1::Cleaned
            ) =>
        {
            &stable_head
        }
        None => {
            return Err(capture_reconciliation(
                &intent.source,
                &capture_id,
                CommandOutputStoreError::Reference(
                    "restart reconciliation requires the exact existing lifecycle head".into(),
                ),
            ));
        }
    };
    let mut recovery = cleanup_leased_capture_with_probe(
        store,
        &mut lease,
        exact_expected_head,
        true,
        RequestedHeadPolicy::AcquiredHistorical,
        cleanup_probe,
    )?;
    attach_physical_reconciliation_context(
        &mut recovery,
        &lease,
        claim,
        expected_head.cloned(),
        initial_state,
        initial_store_head,
        journal_was_created,
    )?;
    Ok(recovery)
}

/// Resolves one exact immutable Unknown terminal under a fresh physical fence
/// and returns the final readback joined to its full core receipt.
#[allow(
    clippy::too_many_arguments,
    clippy::too_many_lines,
    reason = "the transition keeps independent intent, acquisition, Unknown-terminal, claim, observed-head, lease-held mutation, and joined-receipt checks in one auditable boundary"
)]
pub(super) fn resolve_unknown_capture<F>(
    store: &CapabilityCommandOutputStore,
    intent: &CommandOutputCaptureIntentV1,
    acquired: &CommandOutputCaptureAcquiredV1,
    terminal_store_head: &CommandOutputCaptureStoreHeadV1,
    claim: &CommandOutputCaptureReconciliationClaimV1,
    observed_store_head: &CommandOutputCaptureStoreHeadV1,
    reconciled_at: F,
) -> Result<CommandOutputCaptureFencedResolution, CommandOutputStoreError>
where
    F: FnOnce() -> Result<u64, CommandOutputStoreError>,
{
    resolve_unknown_capture_with_requested_head(
        store,
        intent,
        acquired,
        terminal_store_head,
        terminal_store_head,
        claim,
        observed_store_head,
        RequestedHeadPolicy::AnyExactHistorical,
        reconciled_at,
    )
}

/// Performs only the initial core-acquired restart readback for one exact
/// current terminal capture.
///
/// The core-requested head remains the immutable `Acquired` head. The distinct
/// `terminal_store_head` must still equal the freshly observed current head and
/// is independently fenced before the terminal readback is admitted. This is
/// deliberately separate from later generic Unknown-terminal resolution,
/// whose requested head is the Unknown terminal itself.
#[allow(
    clippy::too_many_arguments,
    reason = "the specialized restart boundary keeps core acquisition, current terminal observation, claim, and timestamp authority explicit"
)]
pub(super) fn resolve_core_acquired_terminal_restart<F>(
    store: &CapabilityCommandOutputStore,
    intent: &CommandOutputCaptureIntentV1,
    acquired: &CommandOutputCaptureAcquiredV1,
    terminal_store_head: &CommandOutputCaptureStoreHeadV1,
    claim: &CommandOutputCaptureReconciliationClaimV1,
    observed_store_head: &CommandOutputCaptureStoreHeadV1,
    reconciled_at: F,
) -> Result<CommandOutputCaptureFencedResolution, CommandOutputStoreError>
where
    F: FnOnce() -> Result<u64, CommandOutputStoreError>,
{
    if terminal_store_head != observed_store_head {
        return Err(CommandOutputStoreError::Reference(
            "core-acquired terminal restart requires the exact current terminal observation".into(),
        ));
    }
    resolve_unknown_capture_with_requested_head(
        store,
        intent,
        acquired,
        &acquired.store_head,
        terminal_store_head,
        claim,
        observed_store_head,
        RequestedHeadPolicy::AcquiredHistorical,
        reconciled_at,
    )
}

#[allow(
    clippy::too_many_arguments,
    clippy::too_many_lines,
    reason = "the transition keeps separate requested and observed heads, exact acquisition, claim, lease-held readback, and joined receipt checks in one auditable boundary"
)]
fn resolve_unknown_capture_with_requested_head<F>(
    store: &CapabilityCommandOutputStore,
    intent: &CommandOutputCaptureIntentV1,
    acquired: &CommandOutputCaptureAcquiredV1,
    requested_store_head: &CommandOutputCaptureStoreHeadV1,
    terminal_store_head: &CommandOutputCaptureStoreHeadV1,
    claim: &CommandOutputCaptureReconciliationClaimV1,
    observed_store_head: &CommandOutputCaptureStoreHeadV1,
    requested_head_policy: RequestedHeadPolicy,
    reconciled_at: F,
) -> Result<CommandOutputCaptureFencedResolution, CommandOutputStoreError>
where
    F: FnOnce() -> Result<u64, CommandOutputStoreError>,
{
    store.validate_root()?;
    intent.validate().map_err(core_contract_error)?;
    acquired
        .validate_against(intent)
        .map_err(core_contract_error)?;
    claim.validate().map_err(core_contract_error)?;
    terminal_store_head
        .validate()
        .map_err(core_contract_error)?;
    requested_store_head
        .validate()
        .map_err(core_contract_error)?;
    observed_store_head
        .validate()
        .map_err(core_contract_error)?;
    if claim.capture_id != intent.capture_id || acquired.capture_id != intent.capture_id {
        return Err(CommandOutputStoreError::Reference(
            "Unknown-resolution claim or acquisition is crossed with the capture Intent".into(),
        ));
    }
    let observed_private_state_digest = crate::service::inspect_private_state_digest(store.root())
        .map_err(|error| {
            CommandOutputStoreError::Root(format!(
                "cannot authenticate Unknown-resolution private-state digest: {error}"
            ))
        })?;
    if observed_private_state_digest != intent.private_state_digest {
        return Err(CommandOutputStoreError::Source(
            "Unknown-resolution Intent private-state digest differs from the retained store root"
                .into(),
        ));
    }

    let capture_id = CommandOutputCaptureId::parse(intent.capture_id.clone())?;
    let mut lease = acquire_recovery_lease(store, &capture_id)?;
    if intent_record(&lease.records)? != intent {
        return Err(capture_reconciliation(
            &intent.source,
            &capture_id,
            CommandOutputStoreError::Reference(
                "Unknown-resolution journal Intent differs from core authority".into(),
            ),
        ));
    }
    let initial_record = lease.records.last().ok_or_else(|| {
        CommandOutputStoreError::Manifest(
            "Unknown-resolution capture journal has no immutable Intent".into(),
        )
    })?;
    let initial_state = core_restart_state(initial_record.data.state());
    let initial_store_head = CommandOutputCaptureStoreHeadV1 {
        generation: initial_record.sequence,
        record_digest: initial_record.record_digest.clone(),
    };
    if &initial_store_head != observed_store_head {
        return Err(capture_reconciliation(
            &intent.source,
            &capture_id,
            CommandOutputStoreError::Reference(
                "Unknown-resolution observed head changed before the fenced transition".into(),
            ),
        ));
    }
    let terminal_record = lease
        .records
        .iter()
        .find(|record| {
            record.sequence == terminal_store_head.generation
                && record.record_digest == terminal_store_head.record_digest
        })
        .ok_or_else(|| {
            capture_reconciliation(
                &intent.source,
                &capture_id,
                CommandOutputStoreError::Reference(
                    "Unknown terminal head is not an exact immutable physical lifecycle record"
                        .into(),
                ),
            )
        })?;
    if terminal_record.sequence < acquired.store_head.generation
        || acquired_anchor(&lease.records)?.as_ref() != Some(acquired)
    {
        return Err(capture_reconciliation(
            &intent.source,
            &capture_id,
            CommandOutputStoreError::Reference(
                "Unknown terminal head or physical acquisition differs from core authority".into(),
            ),
        ));
    }
    if !lease.records.iter().any(|record| {
        record.sequence == requested_store_head.generation
            && record.record_digest == requested_store_head.record_digest
    }) {
        return Err(capture_reconciliation(
            &intent.source,
            &capture_id,
            CommandOutputStoreError::Reference(
                "core-requested restart head is not an exact immutable physical lifecycle record"
                    .into(),
            ),
        ));
    }

    lease
        .admit_recovery_claim(claim)
        .map_err(|error| capture_reconciliation(&intent.source, &capture_id, error))?;
    let mut recovery = cleanup_leased_capture_with_probe(
        store,
        &mut lease,
        requested_store_head,
        true,
        requested_head_policy,
        &mut |_| Ok(()),
    )?;
    attach_physical_reconciliation_context(
        &mut recovery,
        &lease,
        claim,
        Some(requested_store_head.clone()),
        Some(initial_state),
        Some(initial_store_head.clone()),
        false,
    )?;
    let reconciled_at_unix_ms = reconciled_at()?;
    let physical_reconciliation =
        recovery.physical_reconciliation_evidence(intent, claim, reconciled_at_unix_ms)?;
    if physical_reconciliation.requested_store_head.as_ref() != Some(requested_store_head)
        || physical_reconciliation.initial_store_head.as_ref() != Some(&initial_store_head)
        || physical_reconciliation.final_store_head != *recovery.store_head()
        || physical_reconciliation.physical_acquired.as_ref() != Some(acquired)
        || physical_reconciliation.artifact_reference.as_ref() != recovery.expected_reference()
        || physical_reconciliation.reconciled_at_unix_ms != reconciled_at_unix_ms
    {
        return Err(capture_reconciliation(
            &intent.source,
            &capture_id,
            CommandOutputStoreError::Manifest(
                "Unknown-resolution receipt differs from the lease-held final readback".into(),
            ),
        ));
    }
    Ok(CommandOutputCaptureFencedResolution {
        recovery,
        physical_reconciliation,
    })
}

#[cfg(test)]
pub(super) fn inject_restart_cleanup_cut(
    store: &CapabilityCommandOutputStore,
    intent: &CommandOutputCaptureIntentV1,
    claim: &CommandOutputCaptureReconciliationClaimV1,
    expected_head: Option<&CommandOutputCaptureStoreHeadV1>,
    cut: CleanupCheckpoint,
) -> Result<CommandOutputCaptureRecovery, CommandOutputStoreError> {
    let mut injected = false;
    reconcile_capture_restart_with_probe(store, intent, claim, expected_head, &mut |checkpoint| {
        if checkpoint == cut && !injected {
            injected = true;
            Err(format!("injected {cut:?}"))
        } else {
            Ok(())
        }
    })
}

#[allow(
    clippy::too_many_lines,
    reason = "restart cleanup keeps the durable fence, exact lifecycle head, held object identities, unlink proofs, and terminal record in one auditable sequence"
)]
pub(super) fn cleanup_capture(
    store: &CapabilityCommandOutputStore,
    claim: &CommandOutputCaptureReconciliationClaimV1,
    expected_head: &CommandOutputCaptureStoreHeadV1,
) -> Result<CommandOutputCaptureRecovery, CommandOutputStoreError> {
    claim.validate().map_err(core_contract_error)?;
    expected_head.validate().map_err(core_contract_error)?;
    let capture_id = CommandOutputCaptureId::parse(claim.capture_id.clone())?;
    let mut lease = acquire_lease(store, &capture_id)?;
    lease.admit_recovery_claim(claim)?;
    cleanup_leased_capture(store, &mut lease, expected_head, false)
}

#[allow(
    clippy::too_many_lines,
    reason = "the shared fenced cleanup transition keeps exact head comparison, pending-record resolution, terminal classification, and descriptor-held unlink proof adjacent"
)]
fn cleanup_leased_capture(
    store: &CapabilityCommandOutputStore,
    lease: &mut CaptureJournalLease,
    expected_head: &CommandOutputCaptureStoreHeadV1,
    terminal_readback_is_idempotent: bool,
) -> Result<CommandOutputCaptureRecovery, CommandOutputStoreError> {
    cleanup_leased_capture_with_probe(
        store,
        lease,
        expected_head,
        terminal_readback_is_idempotent,
        RequestedHeadPolicy::CurrentOnly,
        &mut |_| Ok(()),
    )
}

#[derive(Clone, Copy)]
enum RequestedHeadPolicy {
    CurrentOnly,
    AcquiredHistorical,
    AnyExactHistorical,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum CleanupCheckpoint {
    CleanupIntended,
    ManifestUnlinked,
    StdoutUnlinked,
    StderrUnlinked,
    DirectoryUnlinked,
}

#[allow(
    clippy::too_many_lines,
    reason = "the restart cleanup state machine keeps exact head comparison, pending publication, terminal roll-forward, durable plan creation, and resumable unlink completion adjacent"
)]
fn cleanup_leased_capture_with_probe(
    store: &CapabilityCommandOutputStore,
    lease: &mut CaptureJournalLease,
    expected_head: &CommandOutputCaptureStoreHeadV1,
    terminal_readback_is_idempotent: bool,
    requested_head_policy: RequestedHeadPolicy,
    probe: &mut impl FnMut(CleanupCheckpoint) -> Result<(), String>,
) -> Result<CommandOutputCaptureRecovery, CommandOutputStoreError> {
    let capture_id = lease.capture_id.clone();
    let generation = u64::try_from(lease.records.len()).expect("bounded records fit u64");
    let source = intent_source(&lease.records)?.clone();
    let current_matches = generation == expected_head.generation
        && lease.head_digest() == &expected_head.record_digest;
    let historical_requested_state = lease.records.iter().find_map(|record| {
        (record.sequence == expected_head.generation
            && record.record_digest == expected_head.record_digest)
            .then(|| record.data.state())
    });
    let historical_request_matches = historical_requested_state.is_some();
    let historical_acquired_request_matches =
        historical_requested_state == Some(CommandOutputCaptureJournalStateV1::Acquired);
    let historical_request_is_admitted = match requested_head_policy {
        RequestedHeadPolicy::CurrentOnly => false,
        RequestedHeadPolicy::AcquiredHistorical => historical_acquired_request_matches,
        RequestedHeadPolicy::AnyExactHistorical => historical_request_matches,
    };
    let cleanup_resume_matches = lease.records.last().is_some_and(|record| {
        matches!(
            record.data.state(),
            CommandOutputCaptureJournalStateV1::CleanupIntended
                | CommandOutputCaptureJournalStateV1::Cleaned
        )
    }) && historical_request_matches
        && match requested_head_policy {
            RequestedHeadPolicy::CurrentOnly | RequestedHeadPolicy::AnyExactHistorical => true,
            RequestedHeadPolicy::AcquiredHistorical => historical_acquired_request_matches,
        };
    if !(current_matches || cleanup_resume_matches || historical_request_is_admitted) {
        return Err(capture_reconciliation(
            &source,
            &capture_id,
            CommandOutputStoreError::Reference(
                "cleanup claim expected a different immutable lifecycle head".into(),
            ),
        ));
    }
    let rolled_forward_valid_successor = lease
        .pending_record
        .as_ref()
        .is_some_and(|pending| pending.record.is_some());
    lease.resolve_pending_record()?;
    let state = lease
        .records
        .last()
        .expect("capture journal has Intent")
        .data
        .state();
    if matches!(
        state,
        CommandOutputCaptureJournalStateV1::Published
            | CommandOutputCaptureJournalStateV1::TerminalPrepared
            | CommandOutputCaptureJournalStateV1::Cleaned
    ) {
        if terminal_readback_is_idempotent || rolled_forward_valid_successor {
            return recovery_from_records(store, &capture_id, &lease.records);
        }
        return Err(capture_reconciliation(
            &source,
            &capture_id,
            CommandOutputStoreError::Reference(format!(
                "cleanup cannot mutate terminal capture state {state:?}"
            )),
        ));
    }
    if state == CommandOutputCaptureJournalStateV1::Finished {
        let anchor = acquired_anchor(&lease.records)?.ok_or_else(|| {
            CommandOutputStoreError::Manifest("Finished cleanup has no acquired anchor".into())
        })?;
        let reference = finished_reference(&lease.records, &source)?;
        let artifact_directory =
            recover_finished_publication(store, &capture_id, &anchor, &reference)?;
        lease.append(StoredCaptureRecordDataV1::Published {
            reference,
            artifact_directory,
        })?;
        return recovery_from_records(store, &capture_id, &lease.records);
    }
    if state != CommandOutputCaptureJournalStateV1::CleanupIntended {
        lease.append_cleanup_intended()?;
        probe(CleanupCheckpoint::CleanupIntended).map_err(|reason| {
            capture_reconciliation(
                &source,
                &capture_id,
                CommandOutputStoreError::Artifact(format!(
                    "injected cleanup cut after CleanupIntended: {reason}"
                )),
            )
        })?;
    }
    complete_durable_cleanup_plan(store, lease, probe)?;
    recovery_from_records(store, &capture_id, &lease.records)
}

#[allow(
    clippy::too_many_lines,
    reason = "durable cleanup deliberately keeps the persisted namespace plan, held identities, ordered unlinks, and completion proof in one auditable transition"
)]
fn complete_durable_cleanup_plan(
    store: &CapabilityCommandOutputStore,
    lease: &mut CaptureJournalLease,
    probe: &mut impl FnMut(CleanupCheckpoint) -> Result<(), String>,
) -> Result<(), CommandOutputStoreError> {
    let (_, plan, _) = cleanup_intent_material(&lease.records)?;
    let capture_id = lease.capture_id.clone();
    let source = intent_source(&lease.records)?.clone();
    let name = working_name(&capture_id);
    let Some(planned_directory) = plan.directory else {
        ensure_name_absent(store, &name, &source, &capture_id)?;
        lease.append_cleaned_restart_namespace()?;
        return Ok(());
    };
    let directory = match store.inner.root.open_dir_nofollow(&name) {
        Ok(directory) => directory,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            lease.append_cleaned_restart_namespace()?;
            return Ok(());
        }
        Err(error) => {
            return Err(capture_reconciliation(
                &source,
                &capture_id,
                io_error("open planned cleanup directory", Path::new(&name), &error),
            ));
        }
    };
    let directory_identity = validate_private_directory(&directory, "planned cleanup directory")?;
    let observed_directory = StoredObjectIdentityV1::from_directory(&directory)?;
    if !planned_directory.is_same_directory_object(observed_directory) {
        return Err(capture_reconciliation(
            &source,
            &capture_id,
            CommandOutputStoreError::Root(
                "planned cleanup directory name identifies another object".into(),
            ),
        ));
    }
    let present_names = exact_entry_names(&directory, &name, 3)?;
    if !present_names.is_subset(&plan.entry_names) {
        return Err(capture_reconciliation(
            &source,
            &capture_id,
            CommandOutputStoreError::Manifest(
                "planned cleanup directory contains an unplanned entry".into(),
            ),
        ));
    }
    let all_planned_entries_are_present = present_names == plan.entry_names;
    let open_planned =
        |file_name: &'static str,
         planned: Option<StoredObjectIdentityV1>|
         -> Result<Option<(File, PrivateFileIdentity)>, CommandOutputStoreError> {
            let Some(planned) = planned else {
                return Ok(None);
            };
            if !present_names.contains(file_name) {
                return Ok(None);
            }
            let file = open_private_file(&directory, Path::new(file_name))?;
            let maximum = if file_name == MANIFEST_FILE {
                MAX_MANIFEST_BYTES
            } else {
                intent_record(&lease.records)?.max_aggregate_output_bytes
            };
            let identity = validate_private_file(
                &file,
                Path::new(file_name),
                Some(planned.byte_length),
                maximum,
            )?;
            if StoredObjectIdentityV1::from_file(&file)? != planned {
                return Err(CommandOutputStoreError::Artifact(format!(
                    "planned cleanup name {file_name} identifies another object"
                )));
            }
            Ok(Some((file, identity)))
        };
    let manifest = open_planned(MANIFEST_FILE, plan.manifest)?;
    let stdout = open_planned(STDOUT_FILE, plan.stdout)?;
    let stderr = open_planned(STDERR_FILE, plan.stderr)?;
    store.validate_named_directory(&name, directory_identity)?;

    for (file_name, opened, checkpoint) in [
        (
            MANIFEST_FILE,
            manifest.as_ref(),
            CleanupCheckpoint::ManifestUnlinked,
        ),
        (
            STDOUT_FILE,
            stdout.as_ref(),
            CleanupCheckpoint::StdoutUnlinked,
        ),
        (
            STDERR_FILE,
            stderr.as_ref(),
            CleanupCheckpoint::StderrUnlinked,
        ),
    ] {
        let Some((file, identity)) = opened else {
            continue;
        };
        directory.remove_file(file_name).map_err(|error| {
            io_error("unlink planned cleanup file", Path::new(file_name), &error)
        })?;
        validate_unlinked_private_file(file, Path::new(file_name), *identity)?;
        sync_directory(&directory).map_err(|error| {
            io_error(
                "sync planned cleanup file unlink",
                Path::new(file_name),
                &error,
            )
        })?;
        probe(checkpoint).map_err(|reason| {
            capture_reconciliation(
                &source,
                &capture_id,
                CommandOutputStoreError::Artifact(format!(
                    "injected cleanup cut after {file_name} unlink: {reason}"
                )),
            )
        })?;
    }
    if !exact_entry_names(&directory, &name, 0)?.is_empty() {
        return Err(CommandOutputStoreError::Manifest(
            "planned cleanup directory is not empty after exact file unlink".into(),
        ));
    }
    store.validate_named_directory(&name, directory_identity)?;
    store
        .inner
        .root
        .remove_dir(&name)
        .map_err(|error| io_error("remove planned cleanup directory", Path::new(&name), &error))?;
    sync_directory(&store.inner.root)
        .map_err(|error| io_error("sync planned cleanup namespace", Path::new(&name), &error))?;
    validate_unlinked_private_directory(
        &directory,
        directory_identity,
        &store.inner.root,
        Path::new(&name),
        "planned cleanup directory",
    )?;
    store.validate_root()?;
    probe(CleanupCheckpoint::DirectoryUnlinked).map_err(|reason| {
        capture_reconciliation(
            &source,
            &capture_id,
            CommandOutputStoreError::Artifact(format!(
                "injected cleanup cut after directory unlink: {reason}"
            )),
        )
    })?;

    if all_planned_entries_are_present {
        lease.append_cleaned_held(
            Some(&directory),
            stdout.as_ref().map(|(file, _)| file),
            stderr.as_ref().map(|(file, _)| file),
            manifest.as_ref().map(|(file, _)| file),
        )?;
    } else {
        lease.append_cleaned_restart_namespace()?;
    }
    Ok(())
}

fn validate_cleanup_plan_physical_state(
    store: &CapabilityCommandOutputStore,
    capture_id: &CommandOutputCaptureId,
    records: &[StoredCaptureRecordV1],
    source: &CommandOutputArtifactSourceV1,
) -> Result<(), CommandOutputStoreError> {
    let (_, plan, _) = cleanup_intent_material(records)?;
    let name = working_name(capture_id);
    let Some(planned_directory) = plan.directory else {
        return ensure_name_absent(store, &name, source, capture_id);
    };
    let directory = match store.inner.root.open_dir_nofollow(&name) {
        Ok(directory) => directory,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => {
            return Err(capture_reconciliation(
                source,
                capture_id,
                io_error("open cleanup-intended directory", Path::new(&name), &error),
            ));
        }
    };
    let directory_identity = validate_private_directory(&directory, "cleanup-intended directory")?;
    if !planned_directory
        .is_same_directory_object(StoredObjectIdentityV1::from_directory(&directory)?)
    {
        return Err(CommandOutputStoreError::Root(
            "cleanup-intended directory differs from its durable plan".into(),
        ));
    }
    let present_names = exact_entry_names(&directory, &name, 3)?;
    if !present_names.is_subset(&plan.entry_names) {
        return Err(CommandOutputStoreError::Manifest(
            "cleanup-intended directory contains an unplanned entry".into(),
        ));
    }
    for (file_name, planned, maximum) in [
        (MANIFEST_FILE, plan.manifest, MAX_MANIFEST_BYTES),
        (
            STDOUT_FILE,
            plan.stdout,
            intent_record(records)?.max_aggregate_output_bytes,
        ),
        (
            STDERR_FILE,
            plan.stderr,
            intent_record(records)?.max_aggregate_output_bytes,
        ),
    ] {
        if !present_names.contains(file_name) {
            continue;
        }
        let planned = planned.ok_or_else(|| {
            CommandOutputStoreError::Manifest(format!(
                "cleanup-intended name {file_name} was not in the durable plan"
            ))
        })?;
        let file = open_private_file(&directory, Path::new(file_name))?;
        validate_private_file(
            &file,
            Path::new(file_name),
            Some(planned.byte_length),
            maximum,
        )?;
        if StoredObjectIdentityV1::from_file(&file)? != planned {
            return Err(CommandOutputStoreError::Artifact(format!(
                "cleanup-intended name {file_name} differs from its planned identity"
            )));
        }
    }
    store.validate_named_directory(&name, directory_identity)
}

fn acquire_lease(
    store: &CapabilityCommandOutputStore,
    capture_id: &CommandOutputCaptureId,
) -> Result<CaptureJournalLease, CommandOutputStoreError> {
    acquire_lease_inner(store, capture_id, false)
}

fn acquire_recovery_lease(
    store: &CapabilityCommandOutputStore,
    capture_id: &CommandOutputCaptureId,
) -> Result<CaptureJournalLease, CommandOutputStoreError> {
    acquire_lease_inner(store, capture_id, true)
}

fn acquire_lease_inner(
    store: &CapabilityCommandOutputStore,
    capture_id: &CommandOutputCaptureId,
    may_create_missing_lock: bool,
) -> Result<CaptureJournalLease, CommandOutputStoreError> {
    store.validate_root()?;
    let journal_name = journal_name(capture_id);
    let journal = store
        .inner
        .root
        .open_dir_nofollow(&journal_name)
        .map_err(|error| {
            io_error(
                "open exact capture journal",
                Path::new(&journal_name),
                &error,
            )
        })?;
    let journal_identity = validate_private_directory(&journal, "exact capture journal")?;
    let mut options = OpenOptions::new();
    options.read(true).write(true).follow(FollowSymlinks::No);
    let lock = match journal.open_with(LOCK_FILE, &options) {
        Ok(lock) => lock,
        Err(error) if may_create_missing_lock && error.kind() == std::io::ErrorKind::NotFound => {
            if !exact_entry_names(&journal, &journal_name, 1)?.is_empty() {
                return Err(CommandOutputStoreError::Manifest(
                    "lockless capture journal contains state that recovery cannot own".into(),
                ));
            }
            match create_private_file(&journal, Path::new(LOCK_FILE)) {
                Ok(lock) => {
                    sync_directory(&journal).map_err(|error| {
                        io_error(
                            "sync recovery-created capture lock",
                            Path::new(LOCK_FILE),
                            &error,
                        )
                    })?;
                    sync_directory(&store.inner.root).map_err(|error| {
                        io_error(
                            "sync recovery-created capture-lock namespace",
                            Path::new(&journal_name),
                            &error,
                        )
                    })?;
                    lock
                }
                Err(create_error) => journal
                    .open_with(LOCK_FILE, &options)
                    .map_err(|_| create_error)?,
            }
        }
        Err(error) => {
            return Err(io_error(
                "open capture journal writer lock",
                Path::new(LOCK_FILE),
                &error,
            ));
        }
    };
    let lock_identity = validate_private_file(&lock, Path::new(LOCK_FILE), Some(0), 0)?;
    flock(&lock, FlockOperation::NonBlockingLockExclusive).map_err(|error| {
        CommandOutputStoreError::ReconciliationRequired {
            capture_id: Some(capture_id.to_string()),
            source: Box::new(CommandOutputArtifactSourceV1 {
                sprint_id: "capture-journal-reopen".into(),
                runner_launch_id: "capture-journal-reopen".into(),
                runner_session_id: "capture-journal-reopen".into(),
                effect_id: capture_id.to_string(),
                request_digest: Digest::sha256(capture_id.as_str().as_bytes()),
            }),
            expected_reference: None,
            reason: format!("capture {capture_id} is already writer-leased: {error}"),
        }
    })?;
    let records = read_records(&journal, capture_id, journal_identity, lock_identity)?;
    let recovery_fences = read_recovery_fences(&journal, capture_id)?;
    let pending_record = read_pending_record(&journal, capture_id, &records)?;
    let pending_fence = read_pending_fence(&journal, capture_id, &recovery_fences)?;
    let lease = CaptureJournalLease {
        store: store.clone(),
        capture_id: capture_id.clone(),
        journal_name,
        journal,
        journal_identity,
        lock,
        lock_identity,
        records,
        recovery_fences,
        admitted_recovery_fence_digest: None,
        pending_record,
        pending_fence,
        last_pending_resolution: None,
    };
    validate_lease_names(&lease)?;
    Ok(lease)
}

fn validate_lease_names(lease: &CaptureJournalLease) -> Result<(), CommandOutputStoreError> {
    lease.store.validate_root()?;
    lease
        .store
        .validate_named_directory(&lease.journal_name, lease.journal_identity)?;
    let named_lock = open_private_file(&lease.journal, Path::new(LOCK_FILE))?;
    if validate_private_file(&named_lock, Path::new(LOCK_FILE), Some(0), 0)? != lease.lock_identity
    {
        return Err(CommandOutputStoreError::Manifest(
            "capture journal writer-lock name was replaced".into(),
        ));
    }
    if validate_private_file(&lease.lock, Path::new(LOCK_FILE), Some(0), 0)? != lease.lock_identity
    {
        return Err(CommandOutputStoreError::Manifest(
            "retained capture journal writer lock changed".into(),
        ));
    }
    Ok(())
}

#[allow(
    clippy::too_many_lines,
    reason = "recovery reconstructs all bounded journal heads and validates each state-dependent namespace invariant in one exhaustive match"
)]
fn recovery_from_records(
    store: &CapabilityCommandOutputStore,
    capture_id: &CommandOutputCaptureId,
    records: &[StoredCaptureRecordV1],
) -> Result<CommandOutputCaptureRecovery, CommandOutputStoreError> {
    validate_record_chain(capture_id, records)?;
    let intent = intent_record(records)?.clone();
    let source = intent.source.clone();
    let authenticated_maximum_bytes = intent.max_aggregate_output_bytes;
    let observed_private_state_digest = crate::service::inspect_private_state_digest(store.root())
        .map_err(|error| {
            CommandOutputStoreError::Root(format!(
                "cannot reauthenticate capture private-state digest: {error}"
            ))
        })?;
    if observed_private_state_digest != intent.private_state_digest {
        return Err(capture_reconciliation(
            &source,
            capture_id,
            CommandOutputStoreError::Root(
                "capture Intent private-state digest no longer matches the store root".into(),
            ),
        ));
    }
    let acquired = acquired_anchor(records)?;
    let mut writer_attached_store_head = None;
    let mut expected_reference = None;
    let mut terminal = None;
    let mut launch_intended = None;
    let mut launch_intended_store_head = None;
    let mut finished_store_head = None;
    let mut published_store_head = None;
    let mut terminal_prepared_store_head = None;
    let mut cleanup_intended_store_head = None;
    let mut cleaned_store_head = None;
    for record in records {
        match &record.data {
            StoredCaptureRecordDataV1::WriterAttached => {
                writer_attached_store_head = Some(CommandOutputCaptureStoreHeadV1 {
                    generation: record.sequence,
                    record_digest: record.record_digest.clone(),
                });
            }
            StoredCaptureRecordDataV1::LaunchIntended { binding } => {
                launch_intended = Some(binding.clone());
                launch_intended_store_head = Some(CommandOutputCaptureStoreHeadV1 {
                    generation: record.sequence,
                    record_digest: record.record_digest.clone(),
                });
            }
            StoredCaptureRecordDataV1::Finished { stdout, stderr } => {
                expected_reference = Some(
                    CommandOutputArtifactSetReferenceV1::try_new(
                        source.clone(),
                        stdout.clone(),
                        stderr.clone(),
                    )
                    .map_err(|error| {
                        CommandOutputStoreError::Manifest(format!(
                            "journal Finished commitments are invalid: {error}"
                        ))
                    })?,
                );
                finished_store_head = Some(CommandOutputCaptureStoreHeadV1 {
                    generation: record.sequence,
                    record_digest: record.record_digest.clone(),
                });
            }
            StoredCaptureRecordDataV1::Published {
                reference,
                artifact_directory,
            } => {
                if expected_reference.as_ref() != Some(reference) {
                    return Err(CommandOutputStoreError::Manifest(
                        "Published reference differs from Finished commitments".into(),
                    ));
                }
                let validated = store.reopen(reference)?;
                let observed = StoredObjectIdentityV1::from_directory(&validated.directory)?;
                if &observed != artifact_directory {
                    return Err(CommandOutputStoreError::ReconciliationRequired {
                        capture_id: Some(capture_id.to_string()),
                        source: Box::new(source.clone()),
                        expected_reference: Some(Box::new(reference.clone())),
                        reason: format!(
                            "capture {capture_id} Published name no longer identifies its journaled directory"
                        ),
                    });
                }
                published_store_head = Some(CommandOutputCaptureStoreHeadV1 {
                    generation: record.sequence,
                    record_digest: record.record_digest.clone(),
                });
            }
            StoredCaptureRecordDataV1::TerminalPrepared { terminal: value } => {
                value.validate(MAX_CAPTURE_TERMINAL_PAYLOAD_BYTES)?;
                terminal = Some(value.clone());
                terminal_prepared_store_head = Some(CommandOutputCaptureStoreHeadV1 {
                    generation: record.sequence,
                    record_digest: record.record_digest.clone(),
                });
            }
            StoredCaptureRecordDataV1::CleanupIntended { .. } => {
                cleanup_intended_store_head = Some(CommandOutputCaptureStoreHeadV1 {
                    generation: record.sequence,
                    record_digest: record.record_digest.clone(),
                });
            }
            StoredCaptureRecordDataV1::Cleaned { .. } => {
                cleaned_store_head = Some(CommandOutputCaptureStoreHeadV1 {
                    generation: record.sequence,
                    record_digest: record.record_digest.clone(),
                });
            }
            _ => {}
        }
    }
    let head = records.last().ok_or_else(|| {
        CommandOutputStoreError::Manifest("capture journal has no Intent record".into())
    })?;
    let state = head.data.state();
    match state {
        CommandOutputCaptureJournalStateV1::Intent => {
            validate_working_name_absent_or_untrusted(store, capture_id, &source)?;
        }
        CommandOutputCaptureJournalStateV1::Acquired
        | CommandOutputCaptureJournalStateV1::WriterAttached
        | CommandOutputCaptureJournalStateV1::LaunchIntended => {
            let anchor = acquired.as_ref().ok_or_else(|| {
                CommandOutputStoreError::Manifest(
                    "active capture state has no Acquired identity".into(),
                )
            })?;
            validate_working_from_anchor(store, anchor, state)?;
        }
        CommandOutputCaptureJournalStateV1::CleanupIntended => {
            validate_cleanup_plan_physical_state(store, capture_id, records, &source)?;
        }
        CommandOutputCaptureJournalStateV1::Finished => {
            let anchor = acquired.as_ref().ok_or_else(|| {
                CommandOutputStoreError::Manifest(
                    "Finished capture state has no Acquired identity".into(),
                )
            })?;
            let reference = expected_reference.as_ref().ok_or_else(|| {
                CommandOutputStoreError::Manifest(
                    "Finished capture state has no complete artifact reference".into(),
                )
            })?;
            validate_finished_physical_state(store, capture_id, anchor, reference)?;
        }
        CommandOutputCaptureJournalStateV1::Published
        | CommandOutputCaptureJournalStateV1::TerminalPrepared
        | CommandOutputCaptureJournalStateV1::Cleaned => {
            ensure_name_absent(store, &working_name(capture_id), &source, capture_id)?;
        }
    }
    Ok(CommandOutputCaptureRecovery {
        capture_id: capture_id.clone(),
        source,
        authenticated_maximum_bytes,
        state,
        store_head: CommandOutputCaptureStoreHeadV1 {
            generation: head.sequence,
            record_digest: head.record_digest.clone(),
        },
        acquired,
        writer_attached_store_head,
        expected_reference,
        terminal,
        launch_intended,
        launch_intended_store_head,
        finished_store_head,
        published_store_head,
        terminal_prepared_store_head,
        pending_record: None,
        cleanup_intended_store_head,
        cleaned_store_head,
        physical_reconciliation: None,
    })
}

fn validate_finished_physical_state(
    store: &CapabilityCommandOutputStore,
    capture_id: &CommandOutputCaptureId,
    anchor: &CommandOutputCaptureAcquiredV1,
    reference: &CommandOutputArtifactSetReferenceV1,
) -> Result<Option<StoredObjectIdentityV1>, CommandOutputStoreError> {
    let name = working_name(capture_id);
    match store.inner.root.symlink_metadata(&name) {
        Ok(_) => {
            validate_working_from_anchor(
                store,
                anchor,
                CommandOutputCaptureJournalStateV1::Finished,
            )?;
            Ok(None)
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            let validated = store.reopen(reference).map_err(|error| {
                capture_reconciliation(
                    &anchor.source,
                    capture_id,
                    CommandOutputStoreError::Artifact(format!(
                        "Finished capture has no working name and its exact publication is invalid: {error}"
                    )),
                )
            })?;
            if validated.directory_identity != private_directory_identity(&anchor.working_directory)
            {
                return Err(capture_reconciliation(
                    &anchor.source,
                    capture_id,
                    CommandOutputStoreError::Artifact(
                        "Finished capture publication does not identify its acquired directory"
                            .into(),
                    ),
                ));
            }
            StoredObjectIdentityV1::from_directory(&validated.directory).map(Some)
        }
        Err(error) => Err(capture_reconciliation(
            &anchor.source,
            capture_id,
            io_error(
                "classify Finished capture working name",
                Path::new(&name),
                &error,
            ),
        )),
    }
}

#[allow(
    clippy::too_many_lines,
    reason = "fenced Finished recovery verifies exact stream commitments, canonical manifest, no-replace publication, directory identity, and immutable readback in one custody transition"
)]
fn recover_finished_publication(
    store: &CapabilityCommandOutputStore,
    capture_id: &CommandOutputCaptureId,
    anchor: &CommandOutputCaptureAcquiredV1,
    reference: &CommandOutputArtifactSetReferenceV1,
) -> Result<StoredObjectIdentityV1, CommandOutputStoreError> {
    if let Some(artifact_directory) =
        validate_finished_physical_state(store, capture_id, anchor, reference)?
    {
        return Ok(artifact_directory);
    }
    let name = working_name(capture_id);
    let directory = store.inner.root.open_dir_nofollow(&name).map_err(|error| {
        capture_reconciliation(
            &anchor.source,
            capture_id,
            io_error("open Finished recovery directory", Path::new(&name), &error),
        )
    })?;
    let directory_identity = validate_private_directory(&directory, "Finished recovery directory")?;
    if directory_identity != private_directory_identity(&anchor.working_directory) {
        return Err(capture_reconciliation(
            &anchor.source,
            capture_id,
            CommandOutputStoreError::Root(
                "Finished recovery directory differs from Acquired identity".into(),
            ),
        ));
    }
    let mut stdout = open_private_file(&directory, Path::new(STDOUT_FILE))?;
    let mut stderr = open_private_file(&directory, Path::new(STDERR_FILE))?;
    let stdout_identity = validate_private_file(
        &stdout,
        Path::new(STDOUT_FILE),
        Some(reference.stdout.byte_length),
        reference.stdout.byte_length,
    )?;
    let stderr_identity = validate_private_file(
        &stderr,
        Path::new(STDERR_FILE),
        Some(reference.stderr.byte_length),
        reference.stderr.byte_length,
    )?;
    if stdout_identity.object != private_file_identity(&anchor.stdout).object
        || stderr_identity.object != private_file_identity(&anchor.stderr).object
        || stdout_identity.object == stderr_identity.object
    {
        return Err(CommandOutputStoreError::Artifact(
            "Finished recovery stream identities differ from Acquired".into(),
        ));
    }
    super::verify_stream_file(&mut stdout, Path::new(STDOUT_FILE), &reference.stdout)?;
    super::verify_stream_file(&mut stderr, Path::new(STDERR_FILE), &reference.stderr)?;
    let stored = super::StoredCommandOutputManifestV1::from_reference(reference);
    let manifest = super::canonical_manifest(&stored)?;
    if super::manifest_digest(&manifest) != reference.manifest_digest {
        return Err(CommandOutputStoreError::Manifest(
            "Finished recovery canonical manifest differs from core reference".into(),
        ));
    }
    let names = exact_entry_names(&directory, &name, 3)?;
    let streams = BTreeSet::from([STDOUT_FILE.to_string(), STDERR_FILE.to_string()]);
    let with_manifest = BTreeSet::from([
        MANIFEST_FILE.to_string(),
        STDOUT_FILE.to_string(),
        STDERR_FILE.to_string(),
    ]);
    if names == streams {
        super::write_private_file(&directory, Path::new(MANIFEST_FILE), &manifest)?;
    } else if names == with_manifest {
        let mut existing = open_private_file(&directory, Path::new(MANIFEST_FILE))?;
        if super::read_file_twice_stable(
            &mut existing,
            Path::new(MANIFEST_FILE),
            MAX_MANIFEST_BYTES,
        )? != manifest
        {
            return Err(CommandOutputStoreError::Manifest(
                "Finished recovery manifest differs from the canonical reference".into(),
            ));
        }
    } else {
        return Err(CommandOutputStoreError::Manifest(
            "Finished recovery directory has missing or unexpected entries".into(),
        ));
    }
    sync_directory(&directory)
        .map_err(|error| io_error("sync Finished recovery directory", Path::new(&name), &error))?;
    store.validate_named_directory(&name, directory_identity)?;
    let target_name = super::final_directory_name(&source_name_digest(&anchor.source)?);
    renameat_with(
        &store.inner.root,
        Path::new(&name),
        &store.inner.root,
        Path::new(&target_name),
        RenameFlags::NOREPLACE,
    )
    .map_err(|error| {
        capture_reconciliation(
            &anchor.source,
            capture_id,
            io_error(
                "publish Finished recovery without replacement",
                Path::new(&target_name),
                &error,
            ),
        )
    })?;
    sync_directory(&store.inner.root).map_err(|error| {
        io_error(
            "sync Finished recovery publication",
            Path::new(&target_name),
            &error,
        )
    })?;
    let validated = store.reopen(reference)?;
    if validated.directory_identity != directory_identity {
        return Err(CommandOutputStoreError::Artifact(
            "Finished recovery publication identifies another directory".into(),
        ));
    }
    StoredObjectIdentityV1::from_directory(&validated.directory)
}

fn validate_working_from_anchor(
    store: &CapabilityCommandOutputStore,
    anchor: &CommandOutputCaptureAcquiredV1,
    state: CommandOutputCaptureJournalStateV1,
) -> Result<(), CommandOutputStoreError> {
    let capture_id = CommandOutputCaptureId::parse(anchor.capture_id.clone())?;
    let name = working_name(&capture_id);
    let directory = store.inner.root.open_dir_nofollow(&name).map_err(|error| {
        capture_reconciliation(
            &anchor.source,
            &capture_id,
            io_error(
                "reopen active capture working name",
                Path::new(&name),
                &error,
            ),
        )
    })?;
    let directory_identity =
        validate_private_directory(&directory, "active capture working directory")?;
    let stdout = open_private_file(&directory, Path::new(STDOUT_FILE))?;
    let stderr = open_private_file(&directory, Path::new(STDERR_FILE))?;
    let maximum = anchor.max_aggregate_output_bytes;
    let stdout_identity = validate_private_file(
        &stdout,
        Path::new(STDOUT_FILE),
        (state == CommandOutputCaptureJournalStateV1::Acquired).then_some(0),
        maximum,
    )?;
    let stderr_identity = validate_private_file(
        &stderr,
        Path::new(STDERR_FILE),
        (state == CommandOutputCaptureJournalStateV1::Acquired).then_some(0),
        maximum,
    )?;
    if directory_identity != private_directory_identity(&anchor.working_directory)
        || stdout_identity.object != private_file_identity(&anchor.stdout).object
        || stderr_identity.object != private_file_identity(&anchor.stderr).object
    {
        return Err(capture_reconciliation(
            &anchor.source,
            &capture_id,
            CommandOutputStoreError::Artifact(
                "active working names differ from acquired object identities".into(),
            ),
        ));
    }
    let names = exact_entry_names(&directory, &name, 3)?;
    let allowed = if matches!(
        state,
        CommandOutputCaptureJournalStateV1::Finished
            | CommandOutputCaptureJournalStateV1::CleanupIntended
    ) {
        BTreeSet::from([
            super::MANIFEST_FILE.to_string(),
            STDOUT_FILE.to_string(),
            STDERR_FILE.to_string(),
        ])
    } else {
        BTreeSet::from([STDOUT_FILE.to_string(), STDERR_FILE.to_string()])
    };
    if names != allowed
        && !(matches!(
            state,
            CommandOutputCaptureJournalStateV1::Finished
                | CommandOutputCaptureJournalStateV1::CleanupIntended
        ) && names == BTreeSet::from([STDOUT_FILE.to_string(), STDERR_FILE.to_string()]))
    {
        return Err(capture_reconciliation(
            &anchor.source,
            &capture_id,
            CommandOutputStoreError::Manifest(
                "active capture working directory has missing or unexpected entries".into(),
            ),
        ));
    }
    store.validate_named_directory(&name, directory_identity)
}

#[allow(
    clippy::too_many_lines,
    reason = "the finite lifecycle-chain validator intentionally keeps predecessor, digest, state, and payload invariants adjacent for auditability"
)]
fn validate_record_chain(
    capture_id: &CommandOutputCaptureId,
    records: &[StoredCaptureRecordV1],
) -> Result<(), CommandOutputStoreError> {
    if records.is_empty() || records.len() > MAX_RECORDS {
        return Err(CommandOutputStoreError::Manifest(
            "capture journal must contain one bounded immutable chain".into(),
        ));
    }
    for (index, record) in records.iter().enumerate() {
        let sequence = u64::try_from(index + 1).expect("bounded record count fits u64");
        if record.format_version != CAPTURE_JOURNAL_FORMAT_VERSION
            || record.sequence != sequence
            || &record.capture_id != capture_id
            || record.predecessor_digest.as_ref()
                != index
                    .checked_sub(1)
                    .and_then(|previous| records.get(previous))
                    .map(|previous| &previous.record_digest)
            || record.record_digest != record.computed_digest()?
        {
            return Err(CommandOutputStoreError::Manifest(format!(
                "capture journal record {sequence} has invalid version, identity, chain, or digest"
            )));
        }
        if index == 0 {
            if !matches!(record.data, StoredCaptureRecordDataV1::Intent { .. }) {
                return Err(CommandOutputStoreError::Manifest(
                    "capture journal must begin with Intent".into(),
                ));
            }
        } else {
            validate_successor(records.get(index - 1), &record.data)?;
        }
    }
    let acquired_working = records.iter().find_map(|record| match &record.data {
        StoredCaptureRecordDataV1::Acquired { working_set, .. } => Some(working_set),
        _ => None,
    });
    for record in records {
        match &record.data {
            StoredCaptureRecordDataV1::Intent { intent, .. } => {
                intent.validate().map_err(core_contract_error)?;
            }
            StoredCaptureRecordDataV1::Acquired { working_set, .. } => working_set.validate()?,
            StoredCaptureRecordDataV1::LaunchIntended { binding } => {
                binding.validate(MAX_CAPTURE_BINDING_PAYLOAD_BYTES)?;
            }
            StoredCaptureRecordDataV1::Finished { stdout, stderr } => {
                let source = intent_source(records)?.clone();
                CommandOutputArtifactSetReferenceV1::try_new(
                    source,
                    stdout.clone(),
                    stderr.clone(),
                )
                .map_err(core_contract_error)?;
            }
            StoredCaptureRecordDataV1::Published {
                reference,
                artifact_directory,
            } => {
                reference.validate().map_err(core_contract_error)?;
                artifact_directory.validate_directory_shape()?;
            }
            StoredCaptureRecordDataV1::TerminalPrepared { terminal } => {
                terminal.validate(MAX_CAPTURE_TERMINAL_PAYLOAD_BYTES)?;
            }
            StoredCaptureRecordDataV1::CleanupIntended {
                working_set,
                namespace_plan,
            } => {
                if working_set.as_ref() != acquired_working {
                    return Err(CommandOutputStoreError::Manifest(
                        "CleanupIntended working identity differs from Acquired".into(),
                    ));
                }
                let plan = namespace_plan.as_ref().ok_or_else(|| {
                    CommandOutputStoreError::Manifest(
                        "CleanupIntended lacks its exact pre-unlink namespace plan".into(),
                    )
                })?;
                plan.validate()?;
                if let Some(acquired) = acquired_working
                    && (plan.directory.is_none_or(|identity| {
                        (identity.device, identity.inode)
                            != (acquired.directory.device_id, acquired.directory.inode)
                    }) || plan.stdout.is_none_or(|identity| {
                        (identity.device, identity.inode)
                            != (acquired.stdout.device_id, acquired.stdout.inode)
                    }) || plan.stderr.is_none_or(|identity| {
                        (identity.device, identity.inode)
                            != (acquired.stderr.device_id, acquired.stderr.inode)
                    }))
                {
                    return Err(CommandOutputStoreError::Manifest(
                        "CleanupIntended plan differs from Acquired object identities".into(),
                    ));
                }
            }
            StoredCaptureRecordDataV1::Cleaned {
                working_set,
                cleanup_proof,
                completion_proof,
            } => {
                if working_set.as_ref() != acquired_working {
                    return Err(CommandOutputStoreError::Manifest(
                        "Cleaned identity/proof differs from its acquired branch".into(),
                    ));
                }
                if let Some(proof) = cleanup_proof {
                    if completion_proof.is_some() || working_set.is_none() {
                        return Err(CommandOutputStoreError::Manifest(
                            "legacy held cleanup proof is missing acquisition or crosses a current completion proof".into(),
                        ));
                    }
                    proof.validate()?;
                    let acquired = acquired_working.expect("paired cleanup proof has acquisition");
                    if (proof.directory.device, proof.directory.inode)
                        != (acquired.directory.device_id, acquired.directory.inode)
                        || (proof.stdout.device, proof.stdout.inode)
                            != (acquired.stdout.device_id, acquired.stdout.inode)
                        || (proof.stderr.device, proof.stderr.inode)
                            != (acquired.stderr.device_id, acquired.stderr.inode)
                    {
                        return Err(CommandOutputStoreError::Manifest(
                            "Cleaned unlink proof is crossed with Acquired objects".into(),
                        ));
                    }
                }
                if let Some(proof) = completion_proof {
                    if cleanup_proof.is_some() {
                        return Err(CommandOutputStoreError::Manifest(
                            "Cleaned contains two competing completion proof kinds".into(),
                        ));
                    }
                    let (_, plan, cleanup_intent_digest) = cleanup_intent_material(records)?;
                    validate_completion_proof(capture_id, &plan, &cleanup_intent_digest, proof)?;
                } else if cleanup_proof.is_none() {
                    return Err(CommandOutputStoreError::Manifest(
                        "Cleaned lacks a held-descriptor or restart-namespace proof".into(),
                    ));
                }
            }
            StoredCaptureRecordDataV1::WriterAttached => {}
        }
    }
    Ok(())
}

fn validate_successor(
    previous: Option<&StoredCaptureRecordV1>,
    candidate: &StoredCaptureRecordDataV1,
) -> Result<(), CommandOutputStoreError> {
    use CommandOutputCaptureJournalStateV1 as State;
    let next = candidate.state();
    let Some(previous) = previous else {
        return if next == State::Intent {
            Ok(())
        } else {
            Err(CommandOutputStoreError::Manifest(
                "the first capture record must be Intent".into(),
            ))
        };
    };
    let current = previous.data.state();
    let success = matches!(
        (current, next),
        (State::Intent, State::Acquired)
            | (State::Acquired, State::WriterAttached)
            | (State::WriterAttached, State::LaunchIntended)
            | (State::LaunchIntended, State::Finished)
            | (State::Finished, State::Published)
            | (State::Published, State::TerminalPrepared)
            | (
                State::Intent
                    | State::Acquired
                    | State::WriterAttached
                    | State::LaunchIntended
                    | State::Finished,
                State::CleanupIntended
            )
            | (State::CleanupIntended, State::Cleaned)
    );
    if !success {
        return Err(CommandOutputStoreError::Manifest(format!(
            "capture journal transition {current:?} -> {next:?} is forbidden"
        )));
    }
    Ok(())
}

fn intent_record(
    records: &[StoredCaptureRecordV1],
) -> Result<&CommandOutputCaptureIntentV1, CommandOutputStoreError> {
    let Some(StoredCaptureRecordV1 {
        data:
            StoredCaptureRecordDataV1::Intent {
                intent,
                journal_directory,
                writer_lock,
            },
        ..
    }) = records.first()
    else {
        return Err(CommandOutputStoreError::Manifest(
            "capture journal has no exact Intent head".into(),
        ));
    };
    intent.validate().map_err(core_contract_error)?;
    journal_directory.validate_directory_shape()?;
    writer_lock.validate_file_shape(0)?;
    Ok(intent)
}

fn intent_source(
    records: &[StoredCaptureRecordV1],
) -> Result<&CommandOutputArtifactSourceV1, CommandOutputStoreError> {
    match &records
        .first()
        .ok_or_else(|| CommandOutputStoreError::Manifest("capture journal is empty".into()))?
        .data
    {
        StoredCaptureRecordDataV1::Intent { intent, .. } => Ok(&intent.source),
        _ => Err(CommandOutputStoreError::Manifest(
            "capture journal does not begin with Intent".into(),
        )),
    }
}

fn finished_reference(
    records: &[StoredCaptureRecordV1],
    source: &CommandOutputArtifactSourceV1,
) -> Result<CommandOutputArtifactSetReferenceV1, CommandOutputStoreError> {
    let (stdout, stderr) = records
        .iter()
        .find_map(|record| match &record.data {
            StoredCaptureRecordDataV1::Finished { stdout, stderr } => {
                Some((stdout.clone(), stderr.clone()))
            }
            _ => None,
        })
        .ok_or_else(|| {
            CommandOutputStoreError::Manifest(
                "capture state requires missing Finished commitments".into(),
            )
        })?;
    CommandOutputArtifactSetReferenceV1::try_new(source.clone(), stdout, stderr).map_err(|error| {
        CommandOutputStoreError::Manifest(format!(
            "journal Finished commitments are invalid: {error}"
        ))
    })
}

fn acquired_anchor(
    records: &[StoredCaptureRecordV1],
) -> Result<Option<CommandOutputCaptureAcquiredV1>, CommandOutputStoreError> {
    let intent = intent_record(records)?;
    let Some(record) = records
        .iter()
        .find(|record| matches!(record.data, StoredCaptureRecordDataV1::Acquired { .. }))
    else {
        return Ok(None);
    };
    let StoredCaptureRecordDataV1::Acquired {
        dispatch_claim_id,
        acquired_at_unix_ms,
        working_set,
    } = &record.data
    else {
        unreachable!("find matched Acquired")
    };
    working_set.validate()?;
    let anchor = CommandOutputCaptureAcquiredV1::try_new(
        intent,
        dispatch_claim_id,
        CommandOutputCaptureStoreHeadV1 {
            generation: record.sequence,
            record_digest: record.record_digest.clone(),
        },
        working_set.directory.clone(),
        working_set.stdout.clone(),
        working_set.stderr.clone(),
        *acquired_at_unix_ms,
    )
    .map_err(core_contract_error)?;
    Ok(Some(anchor))
}

fn persist_record(
    journal: &Dir,
    record: &StoredCaptureRecordV1,
) -> Result<(), CommandOutputStoreError> {
    let bytes = record.canonical_bytes()?;
    if bytes.is_empty() || u64::try_from(bytes.len()).map_or(true, |len| len > MAX_RECORD_BYTES) {
        return Err(CommandOutputStoreError::Manifest(format!(
            "capture journal record exceeds its {MAX_RECORD_BYTES}-byte bound"
        )));
    }
    let final_name = record_name(record.sequence, &record.record_digest);
    let temp_name = format!(".{final_name}.tmp");
    let mut file = create_private_file(journal, Path::new(&temp_name))?;
    file.write_all(&bytes).map_err(|error| {
        io_error(
            "write capture journal record",
            Path::new(&temp_name),
            &error,
        )
    })?;
    file.sync_all()
        .map_err(|error| io_error("sync capture journal record", Path::new(&temp_name), &error))?;
    validate_private_file(
        &file,
        Path::new(&temp_name),
        Some(u64::try_from(bytes.len()).expect("record byte length fits u64")),
        MAX_RECORD_BYTES,
    )?;
    renameat_with(
        journal,
        Path::new(&temp_name),
        journal,
        Path::new(&final_name),
        RenameFlags::NOREPLACE,
    )
    .map_err(|error| {
        io_error(
            "publish capture journal record without replacement",
            Path::new(&final_name),
            &error,
        )
    })?;
    sync_directory(journal).map_err(|error| {
        io_error(
            "sync capture journal record namespace",
            Path::new(&final_name),
            &error,
        )
    })
}

#[cfg(test)]
#[derive(Clone, Copy)]
pub(super) enum InjectedRecordCut {
    TempCreated,
    BytesWritten,
    BytesSynced,
}

#[cfg(test)]
#[derive(Clone, Copy, Debug)]
pub(super) enum InjectedRecordPublicationCut {
    TempTorn,
    TempValid,
    TempSynced,
    Final,
}

#[cfg(test)]
fn inject_record_publication_cut(
    lease: &mut CaptureJournalLease,
    data: StoredCaptureRecordDataV1,
    cut: InjectedRecordPublicationCut,
) -> Result<(), CommandOutputStoreError> {
    let sequence = u64::try_from(lease.records.len())
        .expect("bounded record count fits u64")
        .checked_add(1)
        .expect("bounded next record sequence");
    let mut record = StoredCaptureRecordV1 {
        format_version: CAPTURE_JOURNAL_FORMAT_VERSION,
        sequence,
        capture_id: lease.capture_id.clone(),
        predecessor_digest: lease
            .records
            .last()
            .map(|record| record.record_digest.clone()),
        data,
        record_digest: Digest::sha256(&[]),
    };
    record.record_digest = record.computed_digest()?;
    match cut {
        InjectedRecordPublicationCut::Final => {
            lease.append(record.data)?;
            Ok(())
        }
        InjectedRecordPublicationCut::TempTorn => persist_injected_record_temporary(
            &lease.journal,
            &record,
            InjectedRecordCut::TempCreated,
        ),
        InjectedRecordPublicationCut::TempValid => persist_injected_record_temporary(
            &lease.journal,
            &record,
            InjectedRecordCut::BytesWritten,
        ),
        InjectedRecordPublicationCut::TempSynced => persist_injected_record_temporary(
            &lease.journal,
            &record,
            InjectedRecordCut::BytesSynced,
        ),
    }
}

#[cfg(test)]
pub(super) fn inject_launch_intended_record_cut(
    store: &CapabilityCommandOutputStore,
    capture_id: &str,
    schema: &str,
    canonical_bytes: Vec<u8>,
    cut: InjectedRecordPublicationCut,
) -> Result<(), CommandOutputStoreError> {
    let capture_id = CommandOutputCaptureId::parse(capture_id.to_string())?;
    let mut lease = acquire_lease(store, &capture_id)?;
    if lease.records.last().map(|record| record.data.state())
        != Some(CommandOutputCaptureJournalStateV1::WriterAttached)
    {
        return Err(CommandOutputStoreError::Manifest(
            "LaunchIntended injection requires WriterAttached".into(),
        ));
    }
    let binding = CommandOutputCaptureCanonicalPayloadV1::try_new(
        schema,
        canonical_bytes,
        MAX_CAPTURE_BINDING_PAYLOAD_BYTES,
    )?;
    inject_record_publication_cut(
        &mut lease,
        StoredCaptureRecordDataV1::LaunchIntended { binding },
        cut,
    )
}

#[cfg(test)]
pub(super) fn inject_cleanup_intended_record_cut(
    store: &CapabilityCommandOutputStore,
    capture_id: &str,
    cut: InjectedRecordPublicationCut,
) -> Result<(), CommandOutputStoreError> {
    let capture_id = CommandOutputCaptureId::parse(capture_id.to_string())?;
    let mut lease = acquire_lease(store, &capture_id)?;
    let state = lease.records.last().map(|record| record.data.state());
    if !matches!(
        state,
        Some(
            CommandOutputCaptureJournalStateV1::Intent
                | CommandOutputCaptureJournalStateV1::Acquired
                | CommandOutputCaptureJournalStateV1::WriterAttached
                | CommandOutputCaptureJournalStateV1::LaunchIntended
        )
    ) {
        return Err(CommandOutputStoreError::Manifest(
            "CleanupIntended injection requires a nonterminal pre-publication state".into(),
        ));
    }
    let working_set = lease.acquired_working_set();
    let maximum = intent_record(&lease.records)?.max_aggregate_output_bytes;
    let namespace_plan = inspect_cleanup_namespace_plan(store, &capture_id, maximum)?;
    inject_record_publication_cut(
        &mut lease,
        StoredCaptureRecordDataV1::CleanupIntended {
            working_set,
            namespace_plan: Some(namespace_plan),
        },
        cut,
    )
}

#[cfg(test)]
pub(super) fn inject_published_record_cut(
    store: &CapabilityCommandOutputStore,
    capture_id: &str,
    cut: InjectedRecordPublicationCut,
) -> Result<CommandOutputArtifactSetReferenceV1, CommandOutputStoreError> {
    let capture_id = CommandOutputCaptureId::parse(capture_id.to_string())?;
    let mut lease = acquire_lease(store, &capture_id)?;
    if lease.records.last().map(|record| record.data.state())
        != Some(CommandOutputCaptureJournalStateV1::Finished)
    {
        return Err(CommandOutputStoreError::Manifest(
            "Published injection requires Finished".into(),
        ));
    }
    let source = intent_source(&lease.records)?.clone();
    let reference = finished_reference(&lease.records, &source)?;
    let validated = store.reopen(&reference)?;
    let artifact_directory = StoredObjectIdentityV1::from_directory(&validated.directory)?;
    inject_record_publication_cut(
        &mut lease,
        StoredCaptureRecordDataV1::Published {
            reference: reference.clone(),
            artifact_directory,
        },
        cut,
    )?;
    Ok(reference)
}

#[cfg(test)]
pub(super) fn inject_finished_record_cut(
    store: &CapabilityCommandOutputStore,
    capture_id: &str,
    stdout: CommandOutputStreamArtifactV1,
    stderr: CommandOutputStreamArtifactV1,
    cut: InjectedRecordPublicationCut,
) -> Result<(), CommandOutputStoreError> {
    let capture_id = CommandOutputCaptureId::parse(capture_id.to_string())?;
    let mut lease = acquire_lease(store, &capture_id)?;
    if lease.records.last().map(|record| record.data.state())
        != Some(CommandOutputCaptureJournalStateV1::LaunchIntended)
    {
        return Err(CommandOutputStoreError::Manifest(
            "Finished injection requires LaunchIntended".into(),
        ));
    }
    inject_record_publication_cut(
        &mut lease,
        StoredCaptureRecordDataV1::Finished { stdout, stderr },
        cut,
    )
}

#[cfg(test)]
pub(super) fn inject_terminal_prepared_record_cut(
    store: &CapabilityCommandOutputStore,
    capture_id: &str,
    schema: &str,
    canonical_bytes: Vec<u8>,
    cut: InjectedRecordPublicationCut,
) -> Result<(), CommandOutputStoreError> {
    let capture_id = CommandOutputCaptureId::parse(capture_id.to_string())?;
    let mut lease = acquire_lease(store, &capture_id)?;
    if lease.records.last().map(|record| record.data.state())
        != Some(CommandOutputCaptureJournalStateV1::Published)
    {
        return Err(CommandOutputStoreError::Manifest(
            "TerminalPrepared injection requires Published".into(),
        ));
    }
    let terminal = CommandOutputCaptureCanonicalPayloadV1::try_new(
        schema,
        canonical_bytes,
        MAX_CAPTURE_TERMINAL_PAYLOAD_BYTES,
    )?;
    inject_record_publication_cut(
        &mut lease,
        StoredCaptureRecordDataV1::TerminalPrepared { terminal },
        cut,
    )
}

#[cfg(all(test, feature = "test-support"))]
pub(super) fn inject_sensitive_clean_terminal_prepared_record_cut_under_claim(
    store: &CapabilityCommandOutputStore,
    intent: &CommandOutputCaptureIntentV1,
    claim: &CommandOutputCaptureReconciliationClaimV1,
    expected_published_head: &CommandOutputCaptureStoreHeadV1,
    schema: &str,
    canonical_bytes: Vec<u8>,
    cut: InjectedRecordPublicationCut,
) -> Result<(), CommandOutputStoreError> {
    intent.validate().map_err(core_contract_error)?;
    claim.validate().map_err(core_contract_error)?;
    expected_published_head
        .validate()
        .map_err(core_contract_error)?;
    let capture_id = CommandOutputCaptureId::parse(intent.capture_id.clone())?;
    let mut lease = acquire_recovery_lease(store, &capture_id)?;
    admit_recovery_intent(&mut lease, intent, claim)?;
    lease.resolve_pending_record()?;
    let recovery = recovery_from_records(store, &capture_id, &lease.records)?;
    if recovery.state != CommandOutputCaptureJournalStateV1::Published
        || recovery.published_store_head.as_ref() != Some(expected_published_head)
    {
        return Err(CommandOutputStoreError::Manifest(
            "claim-fenced TerminalPrepared injection requires exact Published custody".into(),
        ));
    }
    let terminal = CommandOutputCaptureCanonicalPayloadV1::try_new(
        schema,
        canonical_bytes,
        MAX_CAPTURE_TERMINAL_PAYLOAD_BYTES,
    )?;
    inject_record_publication_cut(
        &mut lease,
        StoredCaptureRecordDataV1::TerminalPrepared { terminal },
        cut,
    )
}

#[cfg(test)]
pub(super) fn inject_cleaned_record_cut(
    store: &CapabilityCommandOutputStore,
    capture_id: &str,
    claim: &CommandOutputCaptureReconciliationClaimV1,
    cut: InjectedRecordPublicationCut,
) -> Result<(), CommandOutputStoreError> {
    let capture_id = CommandOutputCaptureId::parse(capture_id.to_string())?;
    let mut lease = acquire_lease(store, &capture_id)?;
    lease.admit_recovery_claim(claim)?;
    if lease.records.last().map(|record| record.data.state())
        != Some(CommandOutputCaptureJournalStateV1::CleanupIntended)
    {
        return Err(CommandOutputStoreError::Manifest(
            "Cleaned injection requires CleanupIntended".into(),
        ));
    }
    let (working_set, namespace_plan, cleanup_intent_digest) =
        cleanup_intent_material(&lease.records)?;
    ensure_name_absent(
        store,
        &working_name(&capture_id),
        intent_source(&lease.records)?,
        &capture_id,
    )?;
    let absent_working_name = working_name(&capture_id);
    let exact_absence_digest = domain_separated_json_digest(
        RESTART_ABSENCE_DIGEST_DOMAIN,
        &RestartAbsenceDigestPreimage {
            capture_id: &capture_id,
            cleanup_intent_digest: &cleanup_intent_digest,
            planned_identity_digest: &namespace_plan.planned_identity_digest,
            absent_working_name: &absent_working_name,
        },
        "injected restart cleanup absence",
    )?;
    let completion_digest = domain_separated_json_digest(
        RESTART_COMPLETION_DIGEST_DOMAIN,
        &RestartCompletionDigestPreimage {
            cleanup_intent_digest: &cleanup_intent_digest,
            planned_identity_digest: &namespace_plan.planned_identity_digest,
            exact_absence_digest: &exact_absence_digest,
        },
        "injected restart cleanup completion",
    )?;
    let completion_proof = StoredCleanupCompletionProofV1::RestartNamespaceCompletion {
        cleanup_intent_digest,
        planned_identity_digest: namespace_plan.planned_identity_digest,
        exact_absence_digest,
        completion_digest,
    };
    inject_record_publication_cut(
        &mut lease,
        StoredCaptureRecordDataV1::Cleaned {
            working_set,
            cleanup_proof: None,
            completion_proof: Some(completion_proof),
        },
        cut,
    )
}

#[cfg(test)]
#[derive(Clone, Copy, Debug)]
pub(super) enum InjectedFenceCut {
    TempTorn,
    TempSynced,
    PostRename,
}

#[cfg(test)]
pub(super) fn inject_recovery_fence_cut(
    store: &CapabilityCommandOutputStore,
    capture_id: &str,
    claim: &CommandOutputCaptureReconciliationClaimV1,
    cut: InjectedFenceCut,
) -> Result<(), CommandOutputStoreError> {
    let capture_id = CommandOutputCaptureId::parse(capture_id.to_string())?;
    let lease = acquire_lease(store, &capture_id)?;
    let fence = lease.recovery_fence_for_claim(claim)?;
    if matches!(cut, InjectedFenceCut::PostRename) {
        return persist_recovery_fence(&lease.journal, &fence);
    }
    let bytes = fence.canonical_bytes()?;
    let final_name = fence_name(fence.claim.claim_epoch, &fence.fence_digest);
    let temp_name = format!(".{final_name}.tmp");
    let mut file = create_private_file(&lease.journal, Path::new(&temp_name))?;
    if matches!(cut, InjectedFenceCut::TempSynced) {
        file.write_all(&bytes).map_err(|error| {
            io_error(
                "write injected complete recovery fence",
                Path::new(&temp_name),
                &error,
            )
        })?;
    } else {
        let prefix_length = bytes.len().min(7);
        file.write_all(&bytes[..prefix_length]).map_err(|error| {
            io_error(
                "write injected torn recovery fence",
                Path::new(&temp_name),
                &error,
            )
        })?;
    }
    file.sync_all().map_err(|error| {
        io_error(
            "sync injected recovery-fence temporary",
            Path::new(&temp_name),
            &error,
        )
    })?;
    sync_directory(&lease.journal).map_err(|error| {
        io_error(
            "sync injected recovery-fence namespace",
            Path::new(&temp_name),
            &error,
        )
    })
}

#[cfg(test)]
#[derive(Clone, Copy, Debug)]
pub(super) enum InjectedJournalAdmissionCut {
    DirectoryCreated,
    LockCreated,
    IntentTempTorn,
    IntentTempSynced,
    IntentFinal,
}

#[cfg(test)]
#[derive(Clone, Copy, Debug)]
pub(super) enum InjectedPreAcquisitionCut {
    WorkingDirectoryCreated,
    StdoutCreated,
    StderrCreated,
    AcquiredTempTorn,
    AcquiredTempSynced,
    AcquiredFinal,
}

#[cfg(test)]
pub(super) fn inject_preacquisition_cut(
    store: &CapabilityCommandOutputStore,
    intent: &CommandOutputCaptureIntentV1,
    cut: InjectedPreAcquisitionCut,
) -> Result<(), CommandOutputStoreError> {
    let capture_id = CommandOutputCaptureId::parse(intent.capture_id.clone())?;
    let mut lease = match admit_capture_journal(store, intent, &capture_id)? {
        CaptureJournalAdmission::Fresh(lease) => *lease,
        CaptureJournalAdmission::Existing => {
            return Err(CommandOutputStoreError::Manifest(
                "pre-acquisition injection requires an absent journal".into(),
            ));
        }
    };
    let name = working_name(&capture_id);
    let directory = create_private_directory(&store.inner.root, &name)?;
    sync_directory(&store.inner.root).map_err(|error| {
        io_error(
            "sync injected pre-acquisition directory",
            Path::new(&name),
            &error,
        )
    })?;
    if matches!(cut, InjectedPreAcquisitionCut::WorkingDirectoryCreated) {
        return Ok(());
    }
    let stdout = create_private_file(&directory, Path::new(STDOUT_FILE))?;
    stdout.sync_all().map_err(|error| {
        io_error(
            "sync injected pre-acquisition stdout",
            Path::new(STDOUT_FILE),
            &error,
        )
    })?;
    sync_directory(&directory).map_err(|error| {
        io_error(
            "sync injected pre-acquisition stdout namespace",
            Path::new(&name),
            &error,
        )
    })?;
    if matches!(cut, InjectedPreAcquisitionCut::StdoutCreated) {
        return Ok(());
    }
    let stderr = create_private_file(&directory, Path::new(STDERR_FILE))?;
    stderr.sync_all().map_err(|error| {
        io_error(
            "sync injected pre-acquisition stderr",
            Path::new(STDERR_FILE),
            &error,
        )
    })?;
    sync_directory(&directory).map_err(|error| {
        io_error(
            "sync injected pre-acquisition stderr namespace",
            Path::new(&name),
            &error,
        )
    })?;
    if matches!(cut, InjectedPreAcquisitionCut::StderrCreated) {
        return Ok(());
    }
    let working_set = StoredWorkingSetIdentityV1 {
        directory: core_directory_identity(&directory)?,
        stdout: core_file_identity(&stdout)?,
        stderr: core_file_identity(&stderr)?,
    };
    let data = StoredCaptureRecordDataV1::Acquired {
        dispatch_claim_id: expected_dispatch_claim_id(&intent.source.effect_id),
        acquired_at_unix_ms: intent.created_at_unix_ms + 1,
        working_set,
    };
    if matches!(cut, InjectedPreAcquisitionCut::AcquiredFinal) {
        lease.append(data)?;
        return Ok(());
    }
    let mut record = StoredCaptureRecordV1 {
        format_version: CAPTURE_JOURNAL_FORMAT_VERSION,
        sequence: 2,
        capture_id,
        predecessor_digest: Some(lease.head_digest().clone()),
        data,
        record_digest: Digest::sha256(&[]),
    };
    record.record_digest = record.computed_digest()?;
    persist_injected_record_temporary(
        &lease.journal,
        &record,
        if matches!(cut, InjectedPreAcquisitionCut::AcquiredTempSynced) {
            InjectedRecordCut::BytesSynced
        } else {
            InjectedRecordCut::TempCreated
        },
    )
}

#[cfg(test)]
pub(super) fn inject_initial_journal_admission_cut(
    store: &CapabilityCommandOutputStore,
    intent: &CommandOutputCaptureIntentV1,
    cut: InjectedJournalAdmissionCut,
) -> Result<(), CommandOutputStoreError> {
    store.validate_root()?;
    intent.validate().map_err(core_contract_error)?;
    let capture_id = CommandOutputCaptureId::parse(intent.capture_id.clone())?;
    let journal_name = journal_name(&capture_id);
    let journal = create_private_directory(&store.inner.root, &journal_name)?;
    sync_directory(&store.inner.root).map_err(|error| {
        io_error(
            "sync injected journal-directory admission cut",
            Path::new(&journal_name),
            &error,
        )
    })?;
    if matches!(cut, InjectedJournalAdmissionCut::DirectoryCreated) {
        return Ok(());
    }
    let lock = create_private_file(&journal, Path::new(LOCK_FILE))?;
    lock.sync_all().map_err(|error| {
        io_error(
            "sync injected journal lock admission cut",
            Path::new(LOCK_FILE),
            &error,
        )
    })?;
    sync_directory(&journal).map_err(|error| {
        io_error(
            "sync injected journal-lock namespace",
            Path::new(&journal_name),
            &error,
        )
    })?;
    if matches!(cut, InjectedJournalAdmissionCut::LockCreated) {
        return Ok(());
    }
    let data = StoredCaptureRecordDataV1::Intent {
        intent: intent.clone(),
        journal_directory: StoredObjectIdentityV1::from_directory(&journal)?,
        writer_lock: StoredObjectIdentityV1::from_file(&lock)?,
    };
    let mut record = StoredCaptureRecordV1 {
        format_version: CAPTURE_JOURNAL_FORMAT_VERSION,
        sequence: 1,
        capture_id,
        predecessor_digest: None,
        data,
        record_digest: Digest::sha256(&[]),
    };
    record.record_digest = record.computed_digest()?;
    if matches!(cut, InjectedJournalAdmissionCut::IntentFinal) {
        return persist_record(&journal, &record);
    }
    persist_injected_record_temporary(
        &journal,
        &record,
        if matches!(cut, InjectedJournalAdmissionCut::IntentTempSynced) {
            InjectedRecordCut::BytesSynced
        } else {
            InjectedRecordCut::TempCreated
        },
    )
}

#[cfg(test)]
pub(super) fn inject_writer_attached_record_cut(
    store: &CapabilityCommandOutputStore,
    capture_id: &str,
    cut: InjectedRecordCut,
) -> Result<(), CommandOutputStoreError> {
    let capture_id = CommandOutputCaptureId::parse(capture_id.to_string())?;
    let lease = acquire_lease(store, &capture_id)?;
    if lease.records.last().map(|record| record.data.state())
        != Some(CommandOutputCaptureJournalStateV1::Acquired)
        || lease.pending_record.is_some()
    {
        return Err(CommandOutputStoreError::Manifest(
            "test cut requires one exact Acquired head".into(),
        ));
    }
    let sequence = u64::try_from(lease.records.len())
        .expect("bounded records fit u64")
        .checked_add(1)
        .expect("bounded record sequence");
    let mut record = StoredCaptureRecordV1 {
        format_version: CAPTURE_JOURNAL_FORMAT_VERSION,
        sequence,
        capture_id: capture_id.clone(),
        predecessor_digest: Some(lease.head_digest().clone()),
        data: StoredCaptureRecordDataV1::WriterAttached,
        record_digest: Digest::sha256(&[]),
    };
    record.record_digest = record.computed_digest()?;
    persist_injected_record_temporary(&lease.journal, &record, cut)?;
    drop(lease);
    Ok(())
}

#[cfg(test)]
fn persist_injected_record_temporary(
    journal: &Dir,
    record: &StoredCaptureRecordV1,
    cut: InjectedRecordCut,
) -> Result<(), CommandOutputStoreError> {
    let bytes = record.canonical_bytes()?;
    let final_name = record_name(record.sequence, &record.record_digest);
    let temp_name = format!(".{final_name}.tmp");
    let mut file = create_private_file(journal, Path::new(&temp_name))?;
    if matches!(
        cut,
        InjectedRecordCut::BytesWritten | InjectedRecordCut::BytesSynced
    ) {
        file.write_all(&bytes).map_err(|error| {
            io_error(
                "write injected complete record",
                Path::new(&temp_name),
                &error,
            )
        })?;
    } else {
        let prefix_length = bytes.len().min(7);
        file.write_all(&bytes[..prefix_length]).map_err(|error| {
            io_error("write injected torn record", Path::new(&temp_name), &error)
        })?;
    }
    if matches!(cut, InjectedRecordCut::BytesWritten) {
        return Ok(());
    }
    file.sync_all().map_err(|error| {
        io_error(
            "sync injected pending record",
            Path::new(&temp_name),
            &error,
        )
    })?;
    sync_directory(journal).map_err(|error| {
        io_error(
            "sync injected pending record namespace",
            Path::new(&temp_name),
            &error,
        )
    })
}

fn persist_recovery_fence(
    journal: &Dir,
    fence: &StoredRecoveryFenceV1,
) -> Result<(), CommandOutputStoreError> {
    let bytes = fence.canonical_bytes()?;
    if bytes.is_empty() || u64::try_from(bytes.len()).map_or(true, |len| len > MAX_RECORD_BYTES) {
        return Err(CommandOutputStoreError::Manifest(
            "capture recovery fence exceeds its bounded record size".into(),
        ));
    }
    let final_name = fence_name(fence.claim.claim_epoch, &fence.fence_digest);
    let temp_name = format!(".{final_name}.tmp");
    let mut file = create_private_file(journal, Path::new(&temp_name))?;
    file.write_all(&bytes).map_err(|error| {
        io_error(
            "write capture recovery fence",
            Path::new(&temp_name),
            &error,
        )
    })?;
    file.sync_all()
        .map_err(|error| io_error("sync capture recovery fence", Path::new(&temp_name), &error))?;
    validate_private_file(
        &file,
        Path::new(&temp_name),
        Some(u64::try_from(bytes.len()).expect("fence byte length fits u64")),
        MAX_RECORD_BYTES,
    )?;
    renameat_with(
        journal,
        Path::new(&temp_name),
        journal,
        Path::new(&final_name),
        RenameFlags::NOREPLACE,
    )
    .map_err(|error| {
        io_error(
            "publish capture recovery fence without replacement",
            Path::new(&final_name),
            &error,
        )
    })?;
    sync_directory(journal).map_err(|error| {
        io_error(
            "sync capture recovery-fence namespace",
            Path::new(&final_name),
            &error,
        )
    })
}

fn read_recovery_fences(
    journal: &Dir,
    capture_id: &CommandOutputCaptureId,
) -> Result<Vec<StoredRecoveryFenceV1>, CommandOutputStoreError> {
    let all_names = exact_entry_names(
        journal,
        &journal_name(capture_id),
        MAX_RECORDS + MAX_RECOVERY_FENCES + 3,
    )?;
    let names = all_names
        .iter()
        .filter(|name| name.starts_with(FENCE_PREFIX) && name.ends_with(FENCE_SUFFIX))
        .cloned()
        .collect::<Vec<_>>();
    if names.len() > MAX_RECOVERY_FENCES {
        return Err(CommandOutputStoreError::Manifest(
            "capture recovery-fence count exceeds its hard bound".into(),
        ));
    }
    let mut fences = Vec::with_capacity(names.len());
    for name in names {
        let mut file = open_private_file(journal, Path::new(&name))?;
        let identity = validate_private_file(&file, Path::new(&name), None, MAX_RECORD_BYTES)?;
        let bytes = read_stable_bounded(&mut file, Path::new(&name), MAX_RECORD_BYTES)?;
        let fence: StoredRecoveryFenceV1 = serde_json::from_slice(&bytes).map_err(|error| {
            CommandOutputStoreError::Manifest(format!(
                "capture recovery fence is malformed: {error}"
            ))
        })?;
        if fence.canonical_bytes()? != bytes
            || name != fence_name(fence.claim.claim_epoch, &fence.fence_digest)
        {
            return Err(CommandOutputStoreError::Manifest(
                "capture recovery fence is noncanonical or misnamed".into(),
            ));
        }
        let reopened_fence = open_private_file(journal, Path::new(&name))?;
        if validate_private_file(
            &reopened_fence,
            Path::new(&name),
            Some(identity.length),
            MAX_RECORD_BYTES,
        )? != identity
        {
            return Err(CommandOutputStoreError::Manifest(
                "capture recovery-fence name was replaced during read".into(),
            ));
        }
        fences.push(fence);
    }
    fences.sort_by_key(|fence| fence.claim.claim_epoch);
    for (index, fence) in fences.iter().enumerate() {
        fence.claim.validate().map_err(core_contract_error)?;
        let previous = index
            .checked_sub(1)
            .and_then(|previous| fences.get(previous));
        if fence.format_version != CAPTURE_JOURNAL_FORMAT_VERSION
            || &fence.capture_id != capture_id
            || fence.claim.capture_id != capture_id.as_str()
            || fence.fence_digest != fence.computed_digest()?
            || fence.predecessor_fence_digest.as_ref()
                != previous.map(|previous| &previous.fence_digest)
            || previous
                .is_some_and(|previous| previous.claim.claim_epoch >= fence.claim.claim_epoch)
        {
            return Err(CommandOutputStoreError::Manifest(
                "capture recovery-fence chain is crossed, stale, or digest-invalid".into(),
            ));
        }
    }
    Ok(fences)
}

fn read_pending_record(
    journal: &Dir,
    capture_id: &CommandOutputCaptureId,
    records: &[StoredCaptureRecordV1],
) -> Result<Option<PendingRecordFile>, CommandOutputStoreError> {
    let names = exact_entry_names(
        journal,
        &journal_name(capture_id),
        MAX_RECORDS + MAX_RECOVERY_FENCES + 3,
    )?
    .into_iter()
    .filter(|name| is_record_temp_name(name))
    .collect::<Vec<_>>();
    if names.len() > 1 {
        return Err(CommandOutputStoreError::Manifest(
            "capture journal has more than one interrupted lifecycle record".into(),
        ));
    }
    let Some(name) = names.into_iter().next() else {
        return Ok(None);
    };
    let (sequence, name_digest) = parse_record_temp_name(&name)?;
    let expected_sequence = u64::try_from(records.len())
        .ok()
        .and_then(|value| value.checked_add(1))
        .ok_or_else(|| CommandOutputStoreError::Manifest("record sequence overflow".into()))?;
    if sequence != expected_sequence {
        return Err(CommandOutputStoreError::Manifest(
            "interrupted lifecycle record is not the exact next sequence".into(),
        ));
    }
    let mut file = open_private_file(journal, Path::new(&name))?;
    let identity = validate_private_file(&file, Path::new(&name), None, MAX_RECORD_BYTES)?;
    let bytes = read_stable_bounded(&mut file, Path::new(&name), MAX_RECORD_BYTES)?;
    let record = serde_json::from_slice::<StoredCaptureRecordV1>(&bytes)
        .ok()
        .filter(|record| {
            record.canonical_bytes().ok().as_deref() == Some(bytes.as_slice())
                && record.sequence == sequence
                && record.record_digest == name_digest
                && record.record_digest
                    == record
                        .computed_digest()
                        .unwrap_or_else(|_| Digest::sha256(&[]))
                && record.capture_id == *capture_id
                && record.predecessor_digest.as_ref()
                    == records.last().map(|previous| &previous.record_digest)
                && validate_successor(records.last(), &record.data).is_ok()
        });
    Ok(Some(PendingRecordFile {
        name,
        identity,
        sequence,
        name_digest,
        record,
    }))
}

fn read_pending_fence(
    journal: &Dir,
    capture_id: &CommandOutputCaptureId,
    fences: &[StoredRecoveryFenceV1],
) -> Result<Option<PendingFenceFile>, CommandOutputStoreError> {
    let names = exact_entry_names(
        journal,
        &journal_name(capture_id),
        MAX_RECORDS + MAX_RECOVERY_FENCES + 3,
    )?
    .into_iter()
    .filter(|name| is_fence_temp_name(name))
    .collect::<Vec<_>>();
    if names.len() > 1 {
        return Err(CommandOutputStoreError::Manifest(
            "capture journal has more than one interrupted recovery fence".into(),
        ));
    }
    let Some(name) = names.into_iter().next() else {
        return Ok(None);
    };
    let (epoch, name_digest) = parse_fence_temp_name(&name)?;
    if fences
        .last()
        .is_some_and(|previous| epoch <= previous.claim.claim_epoch)
    {
        return Err(CommandOutputStoreError::Manifest(
            "interrupted recovery fence does not advance the durable epoch".into(),
        ));
    }
    let mut file = open_private_file(journal, Path::new(&name))?;
    let identity = validate_private_file(&file, Path::new(&name), None, MAX_RECORD_BYTES)?;
    let bytes = read_stable_bounded(&mut file, Path::new(&name), MAX_RECORD_BYTES)?;
    let fence = serde_json::from_slice::<StoredRecoveryFenceV1>(&bytes)
        .ok()
        .filter(|fence| {
            fence.canonical_bytes().ok().as_deref() == Some(bytes.as_slice())
                && fence.claim.validate().is_ok()
                && fence.claim.claim_epoch == epoch
                && fence.fence_digest == name_digest
                && fence.fence_digest
                    == fence
                        .computed_digest()
                        .unwrap_or_else(|_| Digest::sha256(&[]))
                && fence.capture_id == *capture_id
                && fence.claim.capture_id == capture_id.as_str()
                && fence.predecessor_fence_digest.as_ref()
                    == fences.last().map(|previous| &previous.fence_digest)
        });
    Ok(Some(PendingFenceFile {
        name,
        identity,
        epoch,
        fence,
    }))
}

fn finalize_pending_name(
    journal: &Dir,
    temporary_name: &str,
    final_name: &str,
    expected: PrivateFileIdentity,
) -> Result<(), CommandOutputStoreError> {
    let retained = open_private_file(journal, Path::new(temporary_name))?;
    if validate_private_file(
        &retained,
        Path::new(temporary_name),
        Some(expected.length),
        MAX_RECORD_BYTES,
    )? != expected
    {
        return Err(CommandOutputStoreError::Manifest(
            "interrupted journal file was replaced before roll-forward".into(),
        ));
    }
    renameat_with(
        journal,
        Path::new(temporary_name),
        journal,
        Path::new(final_name),
        RenameFlags::NOREPLACE,
    )
    .map_err(|error| {
        io_error(
            "roll forward interrupted journal publication",
            Path::new(final_name),
            &error,
        )
    })?;
    sync_directory(journal).map_err(|error| {
        io_error(
            "sync rolled-forward journal publication",
            Path::new(final_name),
            &error,
        )
    })?;
    let named = open_private_file(journal, Path::new(final_name))?;
    if validate_private_file(
        &named,
        Path::new(final_name),
        Some(expected.length),
        MAX_RECORD_BYTES,
    )? != expected
        || validate_private_file(
            &retained,
            Path::new(final_name),
            Some(expected.length),
            MAX_RECORD_BYTES,
        )? != expected
    {
        return Err(CommandOutputStoreError::Manifest(
            "rolled-forward journal name differs from retained exact object".into(),
        ));
    }
    Ok(())
}

fn remove_pending_name(
    journal: &Dir,
    name: &str,
    expected: PrivateFileIdentity,
) -> Result<(), CommandOutputStoreError> {
    let retained = open_private_file(journal, Path::new(name))?;
    if validate_private_file(
        &retained,
        Path::new(name),
        Some(expected.length),
        MAX_RECORD_BYTES,
    )? != expected
    {
        return Err(CommandOutputStoreError::Manifest(
            "torn journal file was replaced before cleanup".into(),
        ));
    }
    journal
        .remove_file(name)
        .map_err(|error| io_error("remove exact torn journal file", Path::new(name), &error))?;
    validate_unlinked_private_file(&retained, Path::new(name), expected)?;
    sync_directory(journal)
        .map_err(|error| io_error("sync torn journal-file cleanup", Path::new(name), &error))
}

#[allow(
    clippy::too_many_lines,
    reason = "journal readback keeps bounded enumeration, no-follow identity checks, sequence validation, canonical decode, and chain verification adjacent"
)]
fn read_records(
    journal: &Dir,
    capture_id: &CommandOutputCaptureId,
    journal_identity: PrivateDirectoryIdentity,
    lock_identity: PrivateFileIdentity,
) -> Result<Vec<StoredCaptureRecordV1>, CommandOutputStoreError> {
    if validate_private_directory(journal, "retained capture journal")? != journal_identity {
        return Err(CommandOutputStoreError::Root(
            "retained capture journal identity changed".into(),
        ));
    }
    let mut all_names = exact_entry_names(
        journal,
        &journal_name(capture_id),
        MAX_RECORDS + MAX_RECOVERY_FENCES + 3,
    )?;
    if !all_names.remove(LOCK_FILE) {
        return Err(CommandOutputStoreError::Manifest(
            "capture journal has a missing lock or invalid record count".into(),
        ));
    }
    let names = all_names
        .iter()
        .filter(|name| name.starts_with(RECORD_PREFIX) && name.ends_with(RECORD_SUFFIX))
        .cloned()
        .collect::<BTreeSet<_>>();
    let recognized = all_names.iter().all(|name| {
        (name.starts_with(RECORD_PREFIX) && name.ends_with(RECORD_SUFFIX))
            || (name.starts_with(FENCE_PREFIX) && name.ends_with(FENCE_SUFFIX))
            || is_record_temp_name(name)
            || is_fence_temp_name(name)
    });
    if !recognized || names.len() > MAX_RECORDS {
        return Err(CommandOutputStoreError::Manifest(format!(
            "capture journal has an unknown entry or invalid record count: {all_names:?}"
        )));
    }
    let named_lock = open_private_file(journal, Path::new(LOCK_FILE))?;
    if validate_private_file(&named_lock, Path::new(LOCK_FILE), Some(0), 0)? != lock_identity {
        return Err(CommandOutputStoreError::Manifest(
            "capture journal lock name changed".into(),
        ));
    }
    let mut records = Vec::with_capacity(names.len());
    for expected_sequence in 1..=names.len() {
        let prefix = format!("{RECORD_PREFIX}{expected_sequence:0RECORD_DIGITS$}-");
        let matching = names
            .iter()
            .filter(|name| name.starts_with(&prefix) && name.ends_with(RECORD_SUFFIX))
            .collect::<Vec<_>>();
        if matching.len() != 1 {
            return Err(CommandOutputStoreError::Manifest(format!(
                "capture journal sequence {expected_sequence} is missing or ambiguous"
            )));
        }
        let name = matching[0];
        let mut file = open_private_file(journal, Path::new(name))?;
        let identity = validate_private_file(&file, Path::new(name), None, MAX_RECORD_BYTES)?;
        let bytes = read_stable_bounded(&mut file, Path::new(name), MAX_RECORD_BYTES)?;
        let record: StoredCaptureRecordV1 = serde_json::from_slice(&bytes).map_err(|error| {
            CommandOutputStoreError::Manifest(format!(
                "capture journal record {expected_sequence} is malformed: {error}"
            ))
        })?;
        if record.canonical_bytes()? != bytes
            || record.sequence != u64::try_from(expected_sequence).expect("record count fits u64")
            || *name != record_name(record.sequence, &record.record_digest)
        {
            return Err(CommandOutputStoreError::Manifest(format!(
                "capture journal record {expected_sequence} is noncanonical or misnamed"
            )));
        }
        let reopened_record = open_private_file(journal, Path::new(name))?;
        if validate_private_file(
            &reopened_record,
            Path::new(name),
            Some(identity.length),
            MAX_RECORD_BYTES,
        )? != identity
        {
            return Err(CommandOutputStoreError::Manifest(format!(
                "capture journal record {expected_sequence} name was replaced during read"
            )));
        }
        records.push(record);
    }
    if records.is_empty() {
        return Ok(records);
    }
    validate_record_chain(capture_id, &records)?;
    let StoredCaptureRecordDataV1::Intent {
        intent,
        journal_directory,
        writer_lock,
    } = &records[0].data
    else {
        unreachable!("validated capture journal begins with Intent")
    };
    let current_journal_directory = StoredObjectIdentityV1::from_directory(journal)?;
    let current_writer_lock = StoredObjectIdentityV1::from_file(&named_lock)?;
    if intent.capture_id != capture_id.as_str()
        || !journal_directory.is_same_directory_object(current_journal_directory)
        || *writer_lock != current_writer_lock
    {
        return Err(CommandOutputStoreError::Manifest(
            "capture Intent differs from the retained journal or writer-lock identity".into(),
        ));
    }
    Ok(records)
}

fn read_stable_bounded(
    file: &mut File,
    name: &Path,
    maximum: u64,
) -> Result<Vec<u8>, CommandOutputStoreError> {
    let before = validate_private_file(file, name, None, maximum)?;
    file.seek(SeekFrom::Start(0))
        .map_err(|error| io_error("rewind capture journal record", name, &error))?;
    let mut first = Vec::new();
    file.take(maximum.saturating_add(1))
        .read_to_end(&mut first)
        .map_err(|error| io_error("read capture journal record", name, &error))?;
    file.seek(SeekFrom::Start(0))
        .map_err(|error| io_error("rewind capture journal record", name, &error))?;
    let mut second = Vec::new();
    file.take(maximum.saturating_add(1))
        .read_to_end(&mut second)
        .map_err(|error| io_error("reread capture journal record", name, &error))?;
    let after = validate_private_file(file, name, Some(before.length), maximum)?;
    if before != after || first != second || u64::try_from(first.len()) != Ok(before.length) {
        return Err(CommandOutputStoreError::Manifest(format!(
            "{} changed during stable journal read",
            name.display()
        )));
    }
    Ok(first)
}

fn open_private_output_file(directory: &Dir, name: &Path) -> Result<File, CommandOutputStoreError> {
    let mut options = OpenOptions::new();
    options.read(true).write(true).follow(FollowSymlinks::No);
    directory
        .open_with(name, &options)
        .map_err(|error| io_error("open exact capture output file", name, &error))
}

#[allow(clippy::too_many_arguments)]
fn validate_exact_working_set(
    store: &CapabilityCommandOutputStore,
    name: &str,
    working: &Dir,
    working_identity: PrivateDirectoryIdentity,
    stdout: &File,
    stdout_identity: PrivateFileIdentity,
    stderr: &File,
    stderr_identity: PrivateFileIdentity,
    exact_length: u64,
) -> Result<(), CommandOutputStoreError> {
    if validate_private_directory(working, "retained capture working directory")?
        != working_identity
        || validate_private_file(
            stdout,
            Path::new(STDOUT_FILE),
            Some(exact_length),
            exact_length,
        )? != stdout_identity
        || validate_private_file(
            stderr,
            Path::new(STDERR_FILE),
            Some(exact_length),
            exact_length,
        )? != stderr_identity
    {
        return Err(CommandOutputStoreError::Artifact(
            "retained capture working set changed".into(),
        ));
    }
    let named = store.inner.root.open_dir_nofollow(name).map_err(|error| {
        io_error(
            "reopen named capture working directory",
            Path::new(name),
            &error,
        )
    })?;
    if validate_private_directory(&named, "named capture working directory")? != working_identity {
        return Err(CommandOutputStoreError::Root(
            "capture working directory name was replaced".into(),
        ));
    }
    let named_stdout = open_private_file(&named, Path::new(STDOUT_FILE))?;
    let named_stderr = open_private_file(&named, Path::new(STDERR_FILE))?;
    if validate_private_file(
        &named_stdout,
        Path::new(STDOUT_FILE),
        Some(exact_length),
        exact_length,
    )? != stdout_identity
        || validate_private_file(
            &named_stderr,
            Path::new(STDERR_FILE),
            Some(exact_length),
            exact_length,
        )? != stderr_identity
    {
        return Err(CommandOutputStoreError::Artifact(
            "capture working file name was replaced".into(),
        ));
    }
    if exact_entry_names(&named, name, 2)?
        != BTreeSet::from([STDOUT_FILE.to_string(), STDERR_FILE.to_string()])
    {
        return Err(CommandOutputStoreError::Manifest(
            "capture working directory has missing or unexpected entries".into(),
        ));
    }
    store.validate_root()
}

fn create_private_directory(parent: &Dir, name: &str) -> Result<Dir, CommandOutputStoreError> {
    try_create_private_directory(parent, name)?.ok_or_else(|| CommandOutputStoreError::Io {
        operation: "create capture-ID-derived private directory",
        path: Path::new(name).to_path_buf(),
        message: "capture-ID-derived private directory already exists".into(),
    })
}

fn try_create_private_directory(
    parent: &Dir,
    name: &str,
) -> Result<Option<Dir>, CommandOutputStoreError> {
    let mut builder = DirBuilder::new();
    builder.mode(0o700);
    match parent.create_dir_with(name, &builder) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => return Ok(None),
        Err(error) => {
            return Err(io_error(
                "create capture-ID-derived private directory",
                Path::new(name),
                &error,
            ));
        }
    }
    let directory = parent.open_dir_nofollow(name).map_err(|error| {
        io_error(
            "open capture-ID-derived private directory",
            Path::new(name),
            &error,
        )
    })?;
    directory
        .set_permissions(Path::new("."), Permissions::from_mode(0o700))
        .map_err(|error| {
            io_error(
                "set capture-ID-derived directory mode",
                Path::new(name),
                &error,
            )
        })?;
    validate_private_directory(&directory, "capture-ID-derived private directory")?;
    Ok(Some(directory))
}

fn core_directory_identity(
    directory: &Dir,
) -> Result<CommandOutputCaptureDirectoryIdentityV1, CommandOutputStoreError> {
    let identity = StoredObjectIdentityV1::from_directory(directory)?;
    let core = CommandOutputCaptureDirectoryIdentityV1 {
        device_id: identity.device,
        inode: identity.inode,
        owner_uid: identity.uid,
        mode: identity.mode,
        link_count: identity.link_count,
    };
    core.validate().map_err(core_contract_error)?;
    Ok(core)
}

fn core_file_identity(
    file: &File,
) -> Result<CommandOutputCaptureFileIdentityV1, CommandOutputStoreError> {
    let identity = StoredObjectIdentityV1::from_file(file)?;
    let core = CommandOutputCaptureFileIdentityV1 {
        device_id: identity.device,
        inode: identity.inode,
        owner_uid: identity.uid,
        mode: identity.mode,
        link_count: identity.link_count,
        byte_length: identity.byte_length,
    };
    core.validate().map_err(core_contract_error)?;
    Ok(core)
}

fn private_directory_identity(
    identity: &CommandOutputCaptureDirectoryIdentityV1,
) -> PrivateDirectoryIdentity {
    PrivateDirectoryIdentity {
        object: ObjectIdentity {
            device: identity.device_id,
            inode: identity.inode,
        },
        uid: identity.owner_uid,
        mode: identity.mode,
    }
}

fn private_file_identity(identity: &CommandOutputCaptureFileIdentityV1) -> PrivateFileIdentity {
    PrivateFileIdentity {
        object: ObjectIdentity {
            device: identity.device_id,
            inode: identity.inode,
        },
        uid: identity.owner_uid,
        mode: identity.mode,
        length: identity.byte_length,
    }
}

fn exact_entry_names(
    directory: &Dir,
    label: &str,
    maximum: usize,
) -> Result<BTreeSet<String>, CommandOutputStoreError> {
    let mut names = BTreeSet::new();
    for entry in directory.entries().map_err(|error| {
        io_error(
            "enumerate capture journal directory",
            Path::new(label),
            &error,
        )
    })? {
        if names.len() >= maximum {
            return Err(CommandOutputStoreError::Manifest(format!(
                "capture directory {label} exceeds its {maximum}-entry bound"
            )));
        }
        let entry = entry.map_err(|error| {
            io_error(
                "read capture journal directory entry",
                Path::new(label),
                &error,
            )
        })?;
        let name = entry.file_name().into_string().map_err(|_| {
            CommandOutputStoreError::Manifest(format!(
                "capture directory {label} contains a non-UTF-8 entry"
            ))
        })?;
        if !names.insert(name) {
            return Err(CommandOutputStoreError::Manifest(format!(
                "capture directory {label} contains a duplicate entry"
            )));
        }
    }
    Ok(names)
}

fn ensure_name_absent(
    store: &CapabilityCommandOutputStore,
    name: &str,
    source: &CommandOutputArtifactSourceV1,
    capture_id: &CommandOutputCaptureId,
) -> Result<(), CommandOutputStoreError> {
    match store.inner.root.symlink_metadata(name) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Ok(_) => Err(capture_reconciliation(
            source,
            capture_id,
            CommandOutputStoreError::Artifact(format!(
                "working name {name} still exists after terminal namespace state"
            )),
        )),
        Err(error) => Err(capture_reconciliation(
            source,
            capture_id,
            io_error(
                "inspect capture working-name absence",
                Path::new(name),
                &error,
            ),
        )),
    }
}

fn validate_working_name_absent_or_untrusted(
    store: &CapabilityCommandOutputStore,
    capture_id: &CommandOutputCaptureId,
    source: &CommandOutputArtifactSourceV1,
) -> Result<(), CommandOutputStoreError> {
    let name = working_name(capture_id);
    match store.inner.root.symlink_metadata(&name) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Ok(_) => Err(capture_reconciliation(
            source,
            capture_id,
            CommandOutputStoreError::Artifact(
                "Intent-only capture has an unanchored working name".into(),
            ),
        )),
        Err(error) => Err(capture_reconciliation(
            source,
            capture_id,
            io_error(
                "inspect Intent-only capture working name",
                Path::new(&name),
                &error,
            ),
        )),
    }
}

fn journal_name(capture_id: &CommandOutputCaptureId) -> String {
    format!("{JOURNAL_PREFIX}{capture_id}")
}

pub(super) fn capture_journal_exists(
    store: &CapabilityCommandOutputStore,
    capture_id: &CommandOutputCaptureId,
) -> Result<bool, CommandOutputStoreError> {
    store.validate_root()?;
    let name = journal_name(capture_id);
    match store.inner.root.symlink_metadata(&name) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Ok(_) => Ok(true),
        Err(error) => Err(io_error(
            "inspect optional capture journal",
            Path::new(&name),
            &error,
        )),
    }
}

pub(super) fn working_name(capture_id: &CommandOutputCaptureId) -> String {
    format!("{WORKING_PREFIX}{capture_id}")
}

fn record_name(sequence: u64, digest: &Digest) -> String {
    format!("{RECORD_PREFIX}{sequence:0RECORD_DIGITS$}-{digest}{RECORD_SUFFIX}")
}

fn fence_name(epoch: u64, digest: &Digest) -> String {
    format!("{FENCE_PREFIX}{epoch:0RECORD_DIGITS$}-{digest}{FENCE_SUFFIX}")
}

fn is_record_temp_name(name: &str) -> bool {
    name.starts_with(&format!(".{RECORD_PREFIX}"))
        && name.ends_with(&format!("{RECORD_SUFFIX}.tmp"))
}

fn is_fence_temp_name(name: &str) -> bool {
    name.starts_with(&format!(".{FENCE_PREFIX}")) && name.ends_with(&format!("{FENCE_SUFFIX}.tmp"))
}

fn parse_record_temp_name(name: &str) -> Result<(u64, Digest), CommandOutputStoreError> {
    parse_pending_name(
        name,
        &format!(".{RECORD_PREFIX}"),
        &format!("{RECORD_SUFFIX}.tmp"),
        "lifecycle record",
    )
}

fn parse_fence_temp_name(name: &str) -> Result<(u64, Digest), CommandOutputStoreError> {
    parse_pending_name(
        name,
        &format!(".{FENCE_PREFIX}"),
        &format!("{FENCE_SUFFIX}.tmp"),
        "recovery fence",
    )
}

fn parse_pending_name(
    name: &str,
    prefix: &str,
    suffix: &str,
    label: &str,
) -> Result<(u64, Digest), CommandOutputStoreError> {
    let body = name
        .strip_prefix(prefix)
        .and_then(|name| name.strip_suffix(suffix))
        .ok_or_else(|| {
            CommandOutputStoreError::Manifest(format!("interrupted {label} name is not canonical"))
        })?;
    let (number, digest) = body.split_once('-').ok_or_else(|| {
        CommandOutputStoreError::Manifest(format!(
            "interrupted {label} name has no digest separator"
        ))
    })?;
    if number.len() != RECORD_DIGITS || !number.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(CommandOutputStoreError::Manifest(format!(
            "interrupted {label} number is not canonical"
        )));
    }
    let number = number.parse::<u64>().map_err(|error| {
        CommandOutputStoreError::Manifest(format!("interrupted {label} number is invalid: {error}"))
    })?;
    let digest = Digest::parse(digest.to_string()).map_err(core_contract_error)?;
    Ok((number, digest))
}

fn capture_reconciliation(
    source: &CommandOutputArtifactSourceV1,
    capture_id: &CommandOutputCaptureId,
    error: impl Display,
) -> CommandOutputStoreError {
    CommandOutputStoreError::ReconciliationRequired {
        capture_id: Some(capture_id.to_string()),
        source: Box::new(source.clone()),
        expected_reference: None,
        reason: format!("capture {capture_id} requires exact-ID reconciliation: {error}"),
    }
}

fn core_contract_error(error: impl Display) -> CommandOutputStoreError {
    CommandOutputStoreError::Reference(format!("core capture contract rejected: {error}"))
}
