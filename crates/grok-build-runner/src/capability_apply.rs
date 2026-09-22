//! Descriptor-relative application and recovery for the live workspace.
//!
//! [`CapabilitySafeApplier`] retains capabilities for the exact granted root,
//! its named parent entry, and a disjoint private journal. Every public call
//! revalidates caller authority plus both retained/named roots. Live traversal
//! is no-follow and descriptor-relative; mutations use same-directory atomic
//! rename or unlink and require durable intent before the syscall.
//!
//! This boundary prevents pathname escape, but it is not a process sandbox. A
//! hostile process running as the same user can still race names inside the
//! granted workspace. Post-mutation identity or durability uncertainty is
//! therefore reported as reconciliation-required and is never ordinary retry
//! authority.

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::{OsStr, OsString};
use std::fmt::{self, Display, Formatter};
use std::fs;
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::os::unix::ffi::OsStrExt;
use std::path::{Component, Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use cap_fs_ext::{
    DirExt, FollowSymlinks, MetadataExt as PortableMetadataExt, OpenOptionsFollowExt, OsMetadataExt,
};
use cap_std::fs::{
    Dir, DirBuilder, DirBuilderExt, File, Metadata, OpenOptions, OpenOptionsExt, PermissionsExt,
};
use cap_std::{ambient_authority, fs::Permissions};
use grok_build_core::{ChangeSet, Digest, FileOperation, IssuedWorkspaceGrant};
use rustix::fs::{FlockOperation, RenameFlags, flock, renameat_with};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use crate::durable_directory::sync_directory_entries as sync_directory;
use crate::{StageBundleReference, StagedChangeSet, UnsafeFileKind};

const JOURNAL_VERSION: &str = "grok-build-capability-apply-v2";
const MANIFEST_DOMAIN: &[u8] = b"grok-build.workspace-manifest.sha256.v1\0";
const ROLLBACK_ARTIFACT_VERSION: &str = "grok-build-capability-rollback-artifacts-v2";
const ROLLBACK_PRECONDITION_VERSION: u32 = 1;
const ROLLBACK_PRECONDITION_NAME: &str = "rollback-precondition.json";
const MAX_ROLLBACK_PRECONDITION_BYTES: u64 = 4 * 1_048_576;
const MAX_ROLLBACK_EVIDENCE_TARGETS: usize = 4_096;
const MAX_ROLLBACK_EVIDENCE_PATH_BYTES: usize = 4_096;
const EXPECTED_ENDPOINTS_DOMAIN: &[u8] = b"grok-build.rollback.expected-application-endpoints.v1\0";
const TARGET_CONTRACT_DOMAIN: &[u8] = b"grok-build.rollback.target-contract.v1\0";
const OBSERVED_ENDPOINTS_DOMAIN: &[u8] = b"grok-build.rollback.observed-endpoints.v1\0";
const ABSENT_ENDPOINT_DOMAIN: &[u8] = b"grok-build.post-completion-rollback.endpoint.absent.v1\0";
const MAX_PLAN_BYTES: u64 = 1024 * 1024;
pub(crate) const MAX_APPLY_FILE_BYTES: u64 = 16 * 1024 * 1024;
const MAX_ROLLBACK_ARTIFACT_ENTRIES: usize = 8_192;
const MAX_ROLLBACK_REFERENCE_BYTES: usize = 8 * 1_048_576;
const MAX_PREPARATION_ENTRIES: usize = 16_386;
const WRITER_LOCK_NAME: &str = ".writer-lock";
const PREPARATION_PREFIX: &str = ".preparing-";

/// One exact endpoint required by the staged rollback contract.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum CapabilityRollbackExpectedEndpoint {
    /// The path must not exist.
    Absent,
    /// The path must be a regular file with these exact content and mode bits.
    Regular {
        /// Complete SHA-256 content digest.
        digest: Digest,
        /// Normalized Unix permission bits.
        mode: u32,
    },
}

impl CapabilityRollbackExpectedEndpoint {
    /// Returns the content digest, or the canonical absent-endpoint sentinel.
    #[must_use]
    pub fn endpoint_digest(&self) -> Digest {
        match self {
            Self::Absent => Digest::sha256(ABSENT_ENDPOINT_DOMAIN),
            Self::Regular { digest, .. } => digest.clone(),
        }
    }
}

/// One safely observed live endpoint.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum CapabilityRollbackObservedEndpoint {
    /// The path was descriptor-relatively proven absent.
    Absent,
    /// The path was a stably read, singly-linked regular file.
    Regular {
        /// Complete SHA-256 content digest.
        digest: Digest,
        /// Complete byte length.
        length: u64,
        /// Normalized Unix permission bits.
        mode: u32,
    },
}

impl CapabilityRollbackObservedEndpoint {
    /// Returns the content digest, or the canonical absent-endpoint sentinel.
    #[must_use]
    pub fn endpoint_digest(&self) -> Digest {
        match self {
            Self::Absent => Digest::sha256(ABSENT_ENDPOINT_DOMAIN),
            Self::Regular { digest, .. } => digest.clone(),
        }
    }

    fn matches_expected(&self, expected: &CapabilityRollbackExpectedEndpoint) -> bool {
        match (self, expected) {
            (Self::Absent, CapabilityRollbackExpectedEndpoint::Absent) => true,
            (
                Self::Regular { digest, mode, .. },
                CapabilityRollbackExpectedEndpoint::Regular {
                    digest: expected_digest,
                    mode: expected_mode,
                },
            ) => digest == expected_digest && mode == expected_mode,
            (Self::Absent, CapabilityRollbackExpectedEndpoint::Regular { .. })
            | (Self::Regular { .. }, CapabilityRollbackExpectedEndpoint::Absent) => false,
        }
    }
}

/// Expected application and restored-base endpoints for one ordered target.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CapabilityRollbackTargetContract {
    path: PathBuf,
    application: CapabilityRollbackExpectedEndpoint,
    restored_base: CapabilityRollbackExpectedEndpoint,
}

impl CapabilityRollbackTargetContract {
    /// Returns the exact workspace-relative path.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Returns the endpoint produced by the staged application.
    #[must_use]
    pub const fn application(&self) -> &CapabilityRollbackExpectedEndpoint {
        &self.application
    }

    /// Returns the endpoint a successful rollback must restore.
    #[must_use]
    pub const fn restored_base(&self) -> &CapabilityRollbackExpectedEndpoint {
        &self.restored_base
    }
}

/// One descriptor-relative endpoint observation in exact operation order.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CapabilityRollbackPathObservation {
    path: PathBuf,
    endpoint: CapabilityRollbackObservedEndpoint,
}

impl CapabilityRollbackPathObservation {
    /// Returns the observed workspace-relative path.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Returns the exact safe endpoint observation.
    #[must_use]
    pub const fn endpoint(&self) -> &CapabilityRollbackObservedEndpoint {
        &self.endpoint
    }
}

/// One exact stale-target mismatch, using core-compatible endpoint digests.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CapabilityRollbackPathConflict {
    path: PathBuf,
    expected_endpoint_digest: Digest,
    observed_endpoint_digest: Digest,
}

impl CapabilityRollbackPathConflict {
    /// Returns the conflicting target.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Returns the required result-content digest or absent sentinel.
    #[must_use]
    pub const fn expected_endpoint_digest(&self) -> &Digest {
        &self.expected_endpoint_digest
    }

    /// Returns the safely observed content digest or absent sentinel.
    #[must_use]
    pub const fn observed_endpoint_digest(&self) -> &Digest {
        &self.observed_endpoint_digest
    }
}

/// Exact successful explicit-rollback evidence, including its immediate
/// pre-effect and stable post-restore target observations.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CapabilityRollbackSuccessEvidence {
    bundle: StageBundleReference,
    rollback: CapabilityRollbackArtifactReference,
    target_contract: Vec<CapabilityRollbackTargetContract>,
    expected_application_endpoints_digest: Digest,
    restored_base_endpoints_digest: Digest,
    touched_target_set_digest: Digest,
    pre_effect_observations: Vec<CapabilityRollbackPathObservation>,
    pre_effect_observations_digest: Digest,
    effect_started_at_unix_ms: u64,
    post_restore_observations: Vec<CapabilityRollbackPathObservation>,
    post_restore_observations_digest: Digest,
    final_live_manifest_digest: Digest,
    final_live_manifest_observed_at_unix_ms: u64,
}

/// Exact no-live-effect stale-target evidence.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CapabilityRollbackLiveConflict {
    bundle: StageBundleReference,
    rollback: CapabilityRollbackArtifactReference,
    target_contract: Vec<CapabilityRollbackTargetContract>,
    expected_application_endpoints_digest: Digest,
    touched_target_set_digest: Digest,
    observations: Vec<CapabilityRollbackPathObservation>,
    observed_endpoints_digest: Digest,
    conflicts: Vec<CapabilityRollbackPathConflict>,
    live_manifest_digest: Digest,
    manifest_observed_at_unix_ms: u64,
    observed_at_unix_ms: u64,
    rollback_mutation_started: bool,
}

/// Closed outcome of one evidence-bearing explicit rollback attempt.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", content = "evidence", rename_all = "snake_case")]
pub enum CapabilityRollbackAttempt {
    /// Every target was restored and stably revalidated.
    Completed(CapabilityRollbackSuccessEvidence),
    /// A complete stable pre-effect observation found exact stale targets.
    LiveConflict(CapabilityRollbackLiveConflict),
}

impl CapabilityRollbackSuccessEvidence {
    /// Returns the exact authorized stage bundle.
    #[must_use]
    pub const fn bundle(&self) -> &StageBundleReference {
        &self.bundle
    }

    /// Returns the exact reopened rollback-artifact reference.
    #[must_use]
    pub const fn rollback(&self) -> &CapabilityRollbackArtifactReference {
        &self.rollback
    }

    /// Returns every target contract in exact change-set operation order.
    #[must_use]
    pub fn target_contract(&self) -> &[CapabilityRollbackTargetContract] {
        &self.target_contract
    }

    /// Returns the canonical digest of the ordered application endpoints.
    #[must_use]
    pub const fn expected_application_endpoints_digest(&self) -> &Digest {
        &self.expected_application_endpoints_digest
    }

    /// Returns the canonical core digest of the ordered restored endpoints.
    #[must_use]
    pub const fn restored_base_endpoints_digest(&self) -> &Digest {
        &self.restored_base_endpoints_digest
    }

    /// Returns the canonical core digest of the ordered target paths.
    #[must_use]
    pub const fn touched_target_set_digest(&self) -> &Digest {
        &self.touched_target_set_digest
    }

    /// Returns every immediate pre-effect target observation.
    #[must_use]
    pub fn pre_effect_observations(&self) -> &[CapabilityRollbackPathObservation] {
        &self.pre_effect_observations
    }

    /// Returns the canonical digest of the pre-effect observations.
    #[must_use]
    pub const fn pre_effect_observations_digest(&self) -> &Digest {
        &self.pre_effect_observations_digest
    }

    /// Returns the exact captured time retained before rollback began.
    #[must_use]
    pub const fn effect_started_at_unix_ms(&self) -> u64 {
        self.effect_started_at_unix_ms
    }

    /// Returns every stable post-restore target observation.
    #[must_use]
    pub fn post_restore_observations(&self) -> &[CapabilityRollbackPathObservation] {
        &self.post_restore_observations
    }

    /// Returns the canonical digest of the post-restore observations.
    #[must_use]
    pub const fn post_restore_observations_digest(&self) -> &Digest {
        &self.post_restore_observations_digest
    }

    /// Returns the complete descriptor-relative final live-manifest digest.
    #[must_use]
    pub const fn final_live_manifest_digest(&self) -> &Digest {
        &self.final_live_manifest_digest
    }

    /// Returns the time of the final complete live-manifest observation.
    ///
    /// This timestamps the internally stable two-pass manifest capture, not
    /// the later target sweep that closes the restoration bracket.
    #[must_use]
    pub const fn final_live_manifest_observed_at_unix_ms(&self) -> u64 {
        self.final_live_manifest_observed_at_unix_ms
    }
}

impl CapabilityRollbackLiveConflict {
    /// Returns the exact authorized stage bundle.
    #[must_use]
    pub const fn bundle(&self) -> &StageBundleReference {
        &self.bundle
    }

    /// Returns the exact reopened rollback-artifact reference.
    #[must_use]
    pub const fn rollback(&self) -> &CapabilityRollbackArtifactReference {
        &self.rollback
    }

    /// Returns every target contract in exact change-set operation order.
    #[must_use]
    pub fn target_contract(&self) -> &[CapabilityRollbackTargetContract] {
        &self.target_contract
    }

    /// Returns the canonical digest of the ordered application endpoints.
    #[must_use]
    pub const fn expected_application_endpoints_digest(&self) -> &Digest {
        &self.expected_application_endpoints_digest
    }

    /// Returns the canonical core digest of the ordered target paths.
    #[must_use]
    pub const fn touched_target_set_digest(&self) -> &Digest {
        &self.touched_target_set_digest
    }

    /// Returns all safely observed targets, including non-conflicting targets.
    #[must_use]
    pub fn observations(&self) -> &[CapabilityRollbackPathObservation] {
        &self.observations
    }

    /// Returns the canonical digest of every ordered observation.
    #[must_use]
    pub const fn observed_endpoints_digest(&self) -> &Digest {
        &self.observed_endpoints_digest
    }

    /// Returns exactly the mismatching subset in operation order.
    #[must_use]
    pub fn conflicts(&self) -> &[CapabilityRollbackPathConflict] {
        &self.conflicts
    }

    /// Returns the complete descriptor-relative live-manifest digest.
    #[must_use]
    pub const fn live_manifest_digest(&self) -> &Digest {
        &self.live_manifest_digest
    }

    /// Returns the time of the bracketed complete manifest capture.
    ///
    /// The later [`Self::observed_at_unix_ms`] timestamps only the closing
    /// target sweep and does not make the manifest current at that later time.
    #[must_use]
    pub const fn manifest_observed_at_unix_ms(&self) -> u64 {
        self.manifest_observed_at_unix_ms
    }

    /// Returns the time of the final stable target sweep.
    #[must_use]
    pub const fn observed_at_unix_ms(&self) -> u64 {
        self.observed_at_unix_ms
    }

    /// Always returns false: typed conflict precedes every live rollback effect.
    #[must_use]
    pub const fn rollback_mutation_started(&self) -> bool {
        self.rollback_mutation_started
    }
}

/// A fully applied change set whose exact targets and complete live manifest
/// were descriptor-relatively verified.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CapabilityApplyOutcome {
    transaction_id: String,
    change_set_id: String,
    verified_result_snapshot: Digest,
    live_manifest_digest: Digest,
    applied_operations_digest: Digest,
    touched_path_endpoints_digest: Digest,
    touched_target_set_digest: Digest,
}

impl CapabilityApplyOutcome {
    /// Returns the immutable capability-journal transaction identity.
    #[must_use]
    pub fn transaction_id(&self) -> &str {
        &self.transaction_id
    }

    /// Returns the committed change-set identifier.
    #[must_use]
    pub fn change_set_id(&self) -> &str {
        &self.change_set_id
    }

    /// Returns the exact private candidate snapshot whose targets were applied.
    ///
    /// The complete live manifest may differ when unrelated external edits are
    /// preserved; use [`Self::live_manifest_digest`] for that observation.
    #[must_use]
    pub const fn applied_snapshot(&self) -> &Digest {
        &self.verified_result_snapshot
    }

    /// Returns the complete live manifest observed after target application.
    #[must_use]
    pub const fn live_manifest_digest(&self) -> &Digest {
        &self.live_manifest_digest
    }

    /// Returns the canonical digest of all ordered applied operations.
    #[must_use]
    pub const fn applied_operations_digest(&self) -> &Digest {
        &self.applied_operations_digest
    }

    /// Returns the canonical digest of every ordered result endpoint.
    #[must_use]
    pub const fn touched_path_endpoints_digest(&self) -> &Digest {
        &self.touched_path_endpoints_digest
    }

    /// Returns the canonical digest of the exact touched path set.
    #[must_use]
    pub const fn touched_target_set_digest(&self) -> &Digest {
        &self.touched_target_set_digest
    }
}

/// Exact target restoration performed without touching unrelated live files.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CapabilityRollbackOutcome {
    transaction_id: String,
    change_set_id: String,
    base_snapshot: Digest,
    restored_paths: Vec<PathBuf>,
    live_manifest_digest: Digest,
    restored_base_endpoints_digest: Digest,
    touched_target_set_digest: Digest,
}

impl CapabilityRollbackOutcome {
    /// Returns the immutable capability-journal transaction identity.
    #[must_use]
    pub fn transaction_id(&self) -> &str {
        &self.transaction_id
    }

    /// Returns the rolled-back change-set identifier.
    #[must_use]
    pub fn change_set_id(&self) -> &str {
        &self.change_set_id
    }

    /// Returns the staged base snapshot that defined the restored target states.
    ///
    /// Unrelated live files are deliberately preserved, so the current complete
    /// workspace snapshot may differ after an unrelated edit.
    #[must_use]
    pub const fn base_snapshot(&self) -> &Digest {
        &self.base_snapshot
    }

    /// Returns every operation target restored to its staged base state.
    #[must_use]
    pub fn restored_paths(&self) -> &[PathBuf] {
        &self.restored_paths
    }

    /// Returns the complete descriptor-captured live manifest after rollback.
    #[must_use]
    pub const fn live_manifest_digest(&self) -> &Digest {
        &self.live_manifest_digest
    }

    /// Returns the canonical digest of every ordered restored base endpoint.
    #[must_use]
    pub const fn restored_base_endpoints_digest(&self) -> &Digest {
        &self.restored_base_endpoints_digest
    }

    /// Returns the canonical digest of the exact restored target path set.
    #[must_use]
    pub const fn touched_target_set_digest(&self) -> &Digest {
        &self.touched_target_set_digest
    }
}

/// Immutable file role in a reopened rollback-artifact manifest.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum CapabilityRollbackArtifactKind {
    /// The canonical transaction plan.
    Plan,
    /// A base-content blob for the ordered operation index.
    BaseBlob {
        /// Zero-based operation index in the canonical plan.
        operation_index: u32,
    },
}

/// Bounded metadata and digest for one reopened rollback artifact.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CapabilityRollbackArtifact {
    kind: CapabilityRollbackArtifactKind,
    name: String,
    length: u64,
    mode: u32,
    digest: Digest,
    device: u64,
    inode: u64,
    owner_uid: u32,
    modified_seconds: i64,
    modified_nanoseconds: i64,
    changed_seconds: i64,
    changed_nanoseconds: i64,
}

impl CapabilityRollbackArtifact {
    /// Returns the artifact's semantic role.
    #[must_use]
    pub const fn kind(&self) -> &CapabilityRollbackArtifactKind {
        &self.kind
    }

    /// Returns its exact descriptor-relative journal name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns the complete artifact byte length; bytes are never inlined.
    #[must_use]
    pub const fn length(&self) -> u64 {
        self.length
    }

    /// Returns exact normalized permission bits.
    #[must_use]
    pub const fn mode(&self) -> u32 {
        self.mode
    }

    /// Returns the complete SHA-256 content digest.
    #[must_use]
    pub const fn digest(&self) -> &Digest {
        &self.digest
    }

    /// Returns the filesystem device observed through the reopened descriptor.
    #[must_use]
    pub const fn device(&self) -> u64 {
        self.device
    }

    /// Returns the filesystem inode observed through the reopened descriptor.
    #[must_use]
    pub const fn inode(&self) -> u64 {
        self.inode
    }

    /// Returns the exact effective-user ownership recorded at reopen.
    #[must_use]
    pub const fn owner_uid(&self) -> u32 {
        self.owner_uid
    }

    /// Returns the artifact modification timestamp seconds.
    #[must_use]
    pub const fn modified_seconds(&self) -> i64 {
        self.modified_seconds
    }

    /// Returns the artifact modification timestamp nanoseconds.
    #[must_use]
    pub const fn modified_nanoseconds(&self) -> i64 {
        self.modified_nanoseconds
    }

    /// Returns the artifact metadata-change timestamp seconds.
    #[must_use]
    pub const fn changed_seconds(&self) -> i64 {
        self.changed_seconds
    }

    /// Returns the artifact metadata-change timestamp nanoseconds.
    #[must_use]
    pub const fn changed_nanoseconds(&self) -> i64 {
        self.changed_nanoseconds
    }
}

/// Canonical bounded proof that exact rollback artifacts were reopened.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CapabilityRollbackArtifactReference {
    transaction_id: String,
    change_set_id: String,
    base_snapshot: Digest,
    touched_target_set_digest: Digest,
    target_contract_digest: Digest,
    transaction_device: u64,
    transaction_inode: u64,
    transaction_mode: u32,
    transaction_owner_uid: u32,
    artifacts_digest: Digest,
    reopened_artifacts_bytes: Vec<u8>,
    artifacts: Vec<CapabilityRollbackArtifact>,
}

impl CapabilityRollbackArtifactReference {
    /// Returns the immutable journal transaction identity.
    #[must_use]
    pub fn transaction_id(&self) -> &str {
        &self.transaction_id
    }

    /// Returns the exact change-set identity parsed from the plan.
    #[must_use]
    pub fn change_set_id(&self) -> &str {
        &self.change_set_id
    }

    /// Returns the exact staged base snapshot.
    #[must_use]
    pub const fn base_snapshot(&self) -> &Digest {
        &self.base_snapshot
    }

    /// Returns the canonical digest of the exact touched target set.
    #[must_use]
    pub const fn touched_target_set_digest(&self) -> &Digest {
        &self.touched_target_set_digest
    }

    /// Returns the canonical commitment to ordered application/base endpoints,
    /// including every normalized mode claim.
    #[must_use]
    pub const fn target_contract_digest(&self) -> &Digest {
        &self.target_contract_digest
    }

    /// Returns the reopened transaction directory device.
    #[must_use]
    pub const fn transaction_device(&self) -> u64 {
        self.transaction_device
    }

    /// Returns the reopened transaction directory inode.
    #[must_use]
    pub const fn transaction_inode(&self) -> u64 {
        self.transaction_inode
    }

    /// Returns normalized transaction directory permission bits.
    #[must_use]
    pub const fn transaction_mode(&self) -> u32 {
        self.transaction_mode
    }

    /// Returns the effective-user ownership observed on the transaction root.
    #[must_use]
    pub const fn transaction_owner_uid(&self) -> u32 {
        self.transaction_owner_uid
    }

    /// Returns the domain-separated digest of all binding fields and artifacts.
    #[must_use]
    pub const fn artifacts_digest(&self) -> &Digest {
        &self.artifacts_digest
    }

    /// Returns the exact canonical bounded evidence bytes retained by core.
    #[must_use]
    pub fn reopened_artifacts_bytes(&self) -> &[u8] {
        &self.reopened_artifacts_bytes
    }

    /// Returns the bounded canonical plan/base-blob artifact list.
    #[must_use]
    pub fn artifacts(&self) -> &[CapabilityRollbackArtifact] {
        &self.artifacts
    }
}

/// Pending transactions restored during startup recovery.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct CapabilityRecoveryReport {
    recovered_change_sets: Vec<String>,
    abandoned_preparations: Vec<String>,
}

impl CapabilityRecoveryReport {
    /// Returns recovered transaction identifiers in journal order.
    #[must_use]
    pub fn recovered_change_sets(&self) -> &[String] {
        &self.recovered_change_sets
    }

    /// Returns whether no pending transaction required restoration.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.recovered_change_sets.is_empty() && self.abandoned_preparations.is_empty()
    }

    /// Returns preparation identifiers proven to precede all live effects and
    /// durably removed during startup recovery.
    #[must_use]
    pub fn abandoned_preparations(&self) -> &[String] {
        &self.abandoned_preparations
    }
}

/// Proven state of one durable capability-applier transaction.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CapabilityApplyReconciliation {
    /// The transaction committed after a complete result-snapshot proof.
    Committed(CapabilityApplyOutcome),
    /// Every operation target is in its staged base state.
    TargetsRestored(CapabilityRollbackOutcome),
}

/// Fail-closed capability-application error.
#[derive(Debug)]
pub enum CapabilityApplyError {
    /// Issued authority was stale or differed from acquisition authority.
    Authority(String),
    /// The grant does not authorize verified application.
    PermissionDenied,
    /// A verified no-op has no live filesystem mutation to apply.
    EmptyChangeSet,
    /// A retained or named root failed identity validation.
    Root(String),
    /// A journal path, record, or state was invalid.
    Journal(String),
    /// A caller path was not an exact normalized relative non-Git path.
    InvalidPath {
        /// Rejected logical path.
        path: PathBuf,
        /// Fail-closed reason.
        reason: String,
    },
    /// A no-follow traversal encountered an unsafe object.
    UnsafeEntry {
        /// Logical path containing the object.
        path: PathBuf,
        /// Rejected object class.
        kind: UnsafeFileKind,
    },
    /// The operation's parent directory does not already exist.
    MissingParent(PathBuf),
    /// The complete live workspace did not match the staged base snapshot.
    StaleBase {
        /// Required staged base.
        expected: Digest,
        /// Descriptor-relatively observed live snapshot.
        actual: Digest,
    },
    /// A target did not match its operation-specific content precondition.
    PreconditionFailed {
        /// Stale logical target.
        path: PathBuf,
        /// Required digest, or absence for create.
        expected: Option<Digest>,
        /// Observed digest, or absence.
        actual: Option<Digest>,
    },
    /// A staged or journaled content blob was missing or corrupt.
    Blob(String),
    /// Complete post-application snapshot differed from the staged result.
    ResultMismatch {
        /// Required result snapshot.
        expected: Digest,
        /// Observed complete live snapshot.
        actual: Digest,
    },
    /// A transaction with this write-once identity already exists.
    TransactionExists(String),
    /// No transaction exists with the requested identity.
    TransactionNotFound(String),
    /// The transaction phase does not authorize the requested action.
    InvalidTransactionState {
        /// Transaction identity.
        change_set_id: String,
        /// Observed durable phase.
        phase: String,
    },
    /// Recovery found neither a journal-owned state nor an exact safe endpoint.
    RecoveryConflict {
        /// Conflicting logical path.
        path: PathBuf,
        /// Required safe states.
        expected: String,
        /// Observed digest, or absence.
        actual: Option<Digest>,
    },
    /// A live syscall may have taken effect; only reconciliation may continue.
    ReconciliationRequired {
        /// Owning change-set identity.
        change_set_id: String,
        /// Logical target, when one live target was involved.
        path: Option<PathBuf>,
        /// Ambiguous operation.
        operation: &'static str,
        /// Exact failed proof.
        reason: String,
    },
    /// Deterministic test-only crash injection after a durable intent/effect.
    InjectedCrash {
        /// Number of operations whose mutation syscall was reached.
        affected_operations: usize,
    },
    /// Deterministic test-only process-crash boundary during preparation.
    InjectedPreparationCrash {
        /// Exact durable boundary reached before simulated process death.
        checkpoint: &'static str,
        /// Number of complete content blobs already durable.
        completed_blobs: usize,
    },
    /// A no-live-effect preparation remnant could not be safely removed.
    PreparationCleanupRequired {
        /// Reserved preparation directory identity.
        preparation_id: String,
        /// Exact validation or durability failure.
        reason: String,
    },
    /// A descriptor-relative filesystem operation failed before a live effect.
    Io {
        /// Failed operation.
        operation: &'static str,
        /// Redacted logical path.
        path: PathBuf,
        /// Operating-system error.
        message: String,
    },
}

impl Display for CapabilityApplyError {
    #[allow(
        clippy::too_many_lines,
        reason = "each fail-closed lifecycle error keeps an explicit stable diagnostic"
    )]
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Authority(message) => write!(formatter, "apply authority rejected: {message}"),
            Self::PermissionDenied => {
                formatter.write_str("grant does not authorize verified apply")
            }
            Self::EmptyChangeSet => {
                formatter.write_str("verified no-op change set cannot enter live application")
            }
            Self::Root(message) => write!(formatter, "capability root rejected: {message}"),
            Self::Journal(message) => write!(formatter, "invalid capability journal: {message}"),
            Self::InvalidPath { path, reason } => {
                write!(formatter, "invalid apply path {}: {reason}", path.display())
            }
            Self::UnsafeEntry { path, kind } => {
                write!(formatter, "unsafe {kind:?} at {}", path.display())
            }
            Self::MissingParent(path) => {
                write!(
                    formatter,
                    "operation parent does not exist: {}",
                    path.display()
                )
            }
            Self::StaleBase { expected, actual } => {
                write!(
                    formatter,
                    "stale live base: expected {expected}, found {actual}"
                )
            }
            Self::PreconditionFailed {
                path,
                expected,
                actual,
            } => write!(
                formatter,
                "target precondition failed for {}: expected {}, found {}",
                path.display(),
                display_optional_digest(expected.as_ref()),
                display_optional_digest(actual.as_ref())
            ),
            Self::Blob(message) => write!(formatter, "invalid staged blob: {message}"),
            Self::ResultMismatch { expected, actual } => {
                write!(
                    formatter,
                    "result snapshot mismatch: expected {expected}, found {actual}"
                )
            }
            Self::TransactionExists(id) => write!(formatter, "transaction `{id}` already exists"),
            Self::TransactionNotFound(id) => write!(formatter, "transaction `{id}` not found"),
            Self::InvalidTransactionState {
                change_set_id,
                phase,
            } => write!(
                formatter,
                "transaction `{change_set_id}` has invalid phase `{phase}`"
            ),
            Self::RecoveryConflict {
                path,
                expected,
                actual,
            } => write!(
                formatter,
                "recovery conflict at {}: expected {expected}, found {}",
                path.display(),
                display_optional_digest(actual.as_ref())
            ),
            Self::ReconciliationRequired {
                change_set_id,
                path,
                operation,
                reason,
            } => write!(
                formatter,
                "transaction `{change_set_id}` requires reconciliation after {operation}{}: {reason}",
                path.as_ref()
                    .map(|path| format!(" at {}", path.display()))
                    .unwrap_or_default()
            ),
            Self::InjectedCrash {
                affected_operations,
            } => write!(
                formatter,
                "injected crash after {affected_operations} mutation operations"
            ),
            Self::InjectedPreparationCrash {
                checkpoint,
                completed_blobs,
            } => write!(
                formatter,
                "injected preparation crash at {checkpoint} after {completed_blobs} blobs"
            ),
            Self::PreparationCleanupRequired {
                preparation_id,
                reason,
            } => write!(
                formatter,
                "preparation `{preparation_id}` requires safe cleanup: {reason}"
            ),
            Self::Io {
                operation,
                path,
                message,
            } => {
                write!(
                    formatter,
                    "{operation} failed for {}: {message}",
                    path.display()
                )
            }
        }
    }
}

impl std::error::Error for CapabilityApplyError {}

fn display_optional_digest(value: Option<&Digest>) -> &str {
    value.map_or("absent", Digest::as_str)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ObjectIdentity {
    device: u64,
    inode: u64,
}

struct DirectoryPathLink {
    parent: Dir,
    leaf: OsString,
    identity: ObjectIdentity,
    absolute_path: PathBuf,
}

/// A retained no-follow descriptor chain proving one exact absolute directory path.
///
/// Retaining only a directory and its immediate parent is insufficient: that
/// parent can itself be renamed or replaced, leaving an otherwise valid
/// capability detached from the path used for trust and disjointness checks.
/// This anchor retains every parent/name edge from `/` to the target and
/// revalidates the complete chain before effects.
pub(crate) struct DirectoryPathAnchor {
    links: Vec<DirectoryPathLink>,
}

impl DirectoryPathAnchor {
    pub(crate) fn acquire(path: &Path, label: &'static str) -> Result<Self, CapabilityApplyError> {
        if !path.is_absolute() {
            return Err(CapabilityApplyError::Root(format!(
                "{label} path must be absolute"
            )));
        }
        let canonical = fs::canonicalize(path)
            .map_err(|error| io_error("canonicalize directory path anchor", path, &error))?;
        if canonical != path {
            return Err(CapabilityApplyError::Root(format!(
                "{label} must use its exact canonical path"
            )));
        }

        let mut directory = Dir::open_ambient_dir(Path::new("/"), ambient_authority())
            .map_err(|error| io_error("open filesystem-root anchor", Path::new("/"), &error))?;
        let mut absolute_path = PathBuf::from("/");
        let mut links = Vec::new();
        for component in canonical.components() {
            match component {
                Component::RootDir => {}
                Component::Normal(name) => {
                    absolute_path.push(name);
                    let named = directory.symlink_metadata(name).map_err(|error| {
                        io_error(
                            "inspect anchored directory without following links",
                            &absolute_path,
                            &error,
                        )
                    })?;
                    if named.file_type().is_symlink() || !named.is_dir() {
                        return Err(CapabilityApplyError::Root(format!(
                            "{label} component {} is not a real directory",
                            absolute_path.display()
                        )));
                    }
                    let opened = directory.open_dir_nofollow(name).map_err(|error| {
                        io_error(
                            "open anchored directory without following links",
                            &absolute_path,
                            &error,
                        )
                    })?;
                    let opened_metadata = opened.dir_metadata().map_err(|error| {
                        io_error(
                            "inspect anchored directory descriptor",
                            &absolute_path,
                            &error,
                        )
                    })?;
                    let identity = object_identity(&opened_metadata);
                    if identity != object_identity(&named) {
                        return Err(CapabilityApplyError::Root(format!(
                            "{label} component {} changed during acquisition",
                            absolute_path.display()
                        )));
                    }
                    links.push(DirectoryPathLink {
                        parent: directory.try_clone().map_err(|error| {
                            io_error("retain directory-path parent", &absolute_path, &error)
                        })?,
                        leaf: name.to_os_string(),
                        identity,
                        absolute_path: absolute_path.clone(),
                    });
                    directory = opened;
                }
                _ => {
                    return Err(CapabilityApplyError::Root(format!(
                        "{label} contains a non-canonical path component"
                    )));
                }
            }
        }
        if links.is_empty() {
            return Err(CapabilityApplyError::Root(format!(
                "{label} cannot be the filesystem root"
            )));
        }
        let anchor = Self { links };
        anchor.validate(label)?;
        Ok(anchor)
    }

    pub(crate) fn extend(
        &self,
        parent: &Dir,
        leaf: &OsStr,
        label: &'static str,
    ) -> Result<Self, CapabilityApplyError> {
        self.validate(label)?;
        let parent_metadata = parent.dir_metadata().map_err(|error| {
            io_error(
                "inspect path-anchor extension parent",
                Path::new(label),
                &error,
            )
        })?;
        if object_identity(&parent_metadata) != self.final_identity() {
            return Err(CapabilityApplyError::Root(format!(
                "{label} extension parent differs from the anchored path"
            )));
        }
        let named = parent.symlink_metadata(leaf).map_err(|error| {
            io_error(
                "inspect path-anchor extension without following links",
                Path::new(label),
                &error,
            )
        })?;
        if named.file_type().is_symlink() || !named.is_dir() {
            return Err(CapabilityApplyError::Root(format!(
                "{label} extension is not a real directory"
            )));
        }
        let opened = parent.open_dir_nofollow(leaf).map_err(|error| {
            io_error(
                "open path-anchor extension without following links",
                Path::new(label),
                &error,
            )
        })?;
        let opened_metadata = opened.dir_metadata().map_err(|error| {
            io_error(
                "inspect path-anchor extension descriptor",
                Path::new(label),
                &error,
            )
        })?;
        let identity = object_identity(&opened_metadata);
        if identity != object_identity(&named) {
            return Err(CapabilityApplyError::Root(format!(
                "{label} extension changed during acquisition"
            )));
        }
        let mut cloned = self.try_clone()?;
        let absolute_path = cloned
            .links
            .last()
            .expect("directory path anchors are nonempty")
            .absolute_path
            .join(leaf);
        cloned.links.push(DirectoryPathLink {
            parent: parent.try_clone().map_err(|error| {
                io_error(
                    "retain path-anchor extension parent",
                    &absolute_path,
                    &error,
                )
            })?,
            leaf: leaf.to_os_string(),
            identity,
            absolute_path,
        });
        cloned.validate(label)?;
        Ok(cloned)
    }

    pub(crate) fn try_clone(&self) -> Result<Self, CapabilityApplyError> {
        let links = self
            .links
            .iter()
            .map(|link| {
                Ok(DirectoryPathLink {
                    parent: link.parent.try_clone().map_err(|error| {
                        io_error(
                            "clone retained directory-path parent",
                            &link.absolute_path,
                            &error,
                        )
                    })?,
                    leaf: link.leaf.clone(),
                    identity: link.identity,
                    absolute_path: link.absolute_path.clone(),
                })
            })
            .collect::<Result<Vec<_>, CapabilityApplyError>>()?;
        Ok(Self { links })
    }

    pub(crate) fn try_parent(&self) -> Result<Self, CapabilityApplyError> {
        if self.links.len() < 2 {
            return Err(CapabilityApplyError::Root(
                "directory path anchor has no retainable parent".into(),
            ));
        }
        let mut parent = self.try_clone()?;
        parent.links.pop();
        Ok(parent)
    }

    pub(crate) fn validate(&self, label: &'static str) -> Result<(), CapabilityApplyError> {
        for link in &self.links {
            let named = link.parent.symlink_metadata(&link.leaf).map_err(|error| {
                CapabilityApplyError::Root(format!(
                    "{label} path component {} no longer resolves: {error}",
                    link.absolute_path.display()
                ))
            })?;
            if named.file_type().is_symlink()
                || !named.is_dir()
                || object_identity(&named) != link.identity
            {
                return Err(CapabilityApplyError::Root(format!(
                    "{label} path component {} was replaced",
                    link.absolute_path.display()
                )));
            }
            let opened = link.parent.open_dir_nofollow(&link.leaf).map_err(|error| {
                CapabilityApplyError::Root(format!(
                    "{label} path component {} no longer opens without links: {error}",
                    link.absolute_path.display()
                ))
            })?;
            let opened_metadata = opened.dir_metadata().map_err(|error| {
                CapabilityApplyError::Root(format!(
                    "inspect {label} path component {}: {error}",
                    link.absolute_path.display()
                ))
            })?;
            if object_identity(&opened_metadata) != link.identity {
                return Err(CapabilityApplyError::Root(format!(
                    "{label} path component {} changed during validation",
                    link.absolute_path.display()
                )));
            }
        }
        Ok(())
    }

    pub(crate) fn final_device_inode(&self) -> (u64, u64) {
        let identity = self.final_identity();
        (identity.device, identity.inode)
    }

    pub(crate) fn contains_device_inode(&self, device: u64, inode: u64) -> bool {
        self.links
            .iter()
            .any(|link| link.identity.device == device && link.identity.inode == inode)
    }

    fn final_identity(&self) -> ObjectIdentity {
        self.links
            .last()
            .expect("directory path anchors are nonempty")
            .identity
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct PrivateRootIdentity {
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

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct SnapshotEntry {
    pub(crate) digest: Digest,
    pub(crate) length: u64,
    pub(crate) mode: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum JournalPhase {
    Prepared,
    Applying,
    Committed,
    RollingBack,
    RolledBack,
}

impl JournalPhase {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Prepared => "prepared",
            Self::Applying => "applying",
            Self::Committed => "committed",
            Self::RollingBack => "rolling-back",
            Self::RolledBack => "rolled-back",
        }
    }

    fn parse(value: &str) -> Result<Self, CapabilityApplyError> {
        match value.trim() {
            "prepared" => Ok(Self::Prepared),
            "applying" => Ok(Self::Applying),
            "committed" => Ok(Self::Committed),
            "rolling-back" => Ok(Self::RollingBack),
            "rolled-back" => Ok(Self::RolledBack),
            other => Err(CapabilityApplyError::Journal(format!(
                "unknown phase {other:?}"
            ))),
        }
    }
}

#[derive(Clone, Debug)]
struct PlanOperation {
    operation: FileOperation,
    mode: u32,
    base_identity: Option<ObjectIdentity>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct PlannedDirectory {
    path: PathBuf,
    mode: u32,
}

#[derive(Clone, Debug)]
struct JournalPlan {
    change_set: ChangeSet,
    directories: Vec<PlannedDirectory>,
    operations: Vec<PlanOperation>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct PersistedRollbackPrecondition {
    version: u32,
    bundle: StageBundleReference,
    transaction_id: String,
    change_set_id: String,
    rollback_artifacts_digest: Digest,
    target_contract: Vec<CapabilityRollbackTargetContract>,
    expected_application_endpoints_digest: Digest,
    touched_target_set_digest: Digest,
    observations: Vec<CapabilityRollbackPathObservation>,
    observations_digest: Digest,
    captured_at_unix_ms: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct MutationIntent {
    identity: ObjectIdentity,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum FaultPoint {
    AfterPreparationCreate,
    AfterPreparationMode,
    AfterPreparationDirectorySync,
    AfterPreparationParentSync,
    AfterPreparationBlob(usize),
    AfterPreparationPlan,
    AfterPreparationPhase,
    AfterPreparationRename,
    AfterPreparationPublishSync,
    AfterDirectoryMutation(usize),
    AfterApplyTempIntent(usize),
    #[cfg(test)]
    BeforeCreateNoReplacePublish(usize),
    AfterMutation(usize),
    #[cfg(test)]
    InjectUnsafeEntryBeforeManifest,
    BeforeCommit,
}

/// Descriptor-relative, journal-backed live workspace applier.
pub struct CapabilitySafeApplier {
    grant: IssuedWorkspaceGrant,
    root: Dir,
    root_parent: Dir,
    root_leaf: OsString,
    root_identity: ObjectIdentity,
    root_path_anchor: DirectoryPathAnchor,
    journal: Dir,
    journal_parent: Dir,
    journal_leaf: OsString,
    journal_identity: PrivateRootIdentity,
    journal_path_anchor: DirectoryPathAnchor,
    writer_lock: File,
    writer_lock_identity: ObjectIdentity,
    journal_path: PathBuf,
}

impl Drop for CapabilitySafeApplier {
    fn drop(&mut self) {
        // `flock` belongs to the open file description, which forked children may
        // retain. Explicitly unlock before closing the owner's descriptor.
        let _ = flock(&self.writer_lock, FlockOperation::Unlock);
    }
}

impl CapabilitySafeApplier {
    /// Acquires the exact live root and a disjoint private journal capability.
    ///
    /// Ambient authority is used only during this acquisition. The journal
    /// parent must already exist; the journal leaf is created when absent and is
    /// forced to owner-only `0700`.
    ///
    /// # Errors
    ///
    /// Returns an error for stale/insufficient authority, root replacement,
    /// unsafe journal paths, overlap, links, ownership/mode failure, or I/O.
    #[allow(
        clippy::too_many_lines,
        reason = "capability acquisition keeps the root, journal, and lock validation sequence explicit"
    )]
    pub fn open(
        grant: IssuedWorkspaceGrant,
        journal_path: impl AsRef<Path>,
    ) -> Result<Self, CapabilityApplyError> {
        grant
            .validate_integrity()
            .map_err(|error| CapabilityApplyError::Authority(error.to_string()))?;
        if !grant.contract().permissions.apply_verified_changes {
            return Err(CapabilityApplyError::PermissionDenied);
        }
        let live_path = &grant.contract().canonical_root;
        let live_parent_path = live_path
            .parent()
            .ok_or_else(|| CapabilityApplyError::Root("workspace root has no parent".into()))?;
        let live_leaf = live_path
            .file_name()
            .ok_or_else(|| CapabilityApplyError::Root("workspace root has no leaf".into()))?
            .to_os_string();
        let root_parent = Dir::open_ambient_dir(live_parent_path, ambient_authority())
            .map_err(|error| io_error("open workspace parent capability", live_path, &error))?;
        let root = root_parent.open_dir_nofollow(&live_leaf).map_err(|error| {
            io_error(
                "open workspace root without following links",
                live_path,
                &error,
            )
        })?;
        let root_metadata = root
            .dir_metadata()
            .map_err(|error| io_error("inspect workspace root descriptor", live_path, &error))?;
        if !root_metadata.is_dir() {
            return Err(CapabilityApplyError::Root(
                "workspace root capability is not a directory".into(),
            ));
        }
        let root_identity = object_identity(&root_metadata);
        if root_identity.device != grant.identity().device_id()
            || root_identity.inode != grant.identity().inode()
        {
            return Err(CapabilityApplyError::Root(
                "workspace descriptor does not match issued identity".into(),
            ));
        }
        let root_path_anchor = DirectoryPathAnchor::acquire(live_path, "workspace root")?;
        if root_path_anchor.final_device_inode() != (root_identity.device, root_identity.inode) {
            return Err(CapabilityApplyError::Root(
                "workspace path anchor differs from the issued descriptor".into(),
            ));
        }

        let requested = journal_path.as_ref();
        if !requested.is_absolute() {
            return Err(CapabilityApplyError::Journal(
                "journal root must be absolute".into(),
            ));
        }
        let requested_parent = requested
            .parent()
            .ok_or_else(|| CapabilityApplyError::Journal("journal root has no parent".into()))?;
        let canonical_parent = fs::canonicalize(requested_parent)
            .map_err(|error| io_error("canonicalize journal parent", requested_parent, &error))?;
        let journal_leaf = requested
            .file_name()
            .ok_or_else(|| CapabilityApplyError::Journal("journal root has no leaf".into()))?
            .to_os_string();
        let journal_path = canonical_parent.join(&journal_leaf);
        if requested != journal_path {
            return Err(CapabilityApplyError::Journal(
                "journal root must use its exact canonical parent and normalized leaf".into(),
            ));
        }
        if journal_path.starts_with(live_path) || live_path.starts_with(&journal_path) {
            return Err(CapabilityApplyError::Journal(
                "journal root must be disjoint from the workspace".into(),
            ));
        }
        let journal_parent_anchor =
            DirectoryPathAnchor::acquire(&canonical_parent, "journal parent")?;
        if journal_parent_anchor.contains_device_inode(root_identity.device, root_identity.inode) {
            return Err(CapabilityApplyError::Journal(
                "journal parent resolves inside the workspace through an aliased path".into(),
            ));
        }
        let journal_parent = Dir::open_ambient_dir(&canonical_parent, ambient_authority())
            .map_err(|error| io_error("open journal parent capability", requested, &error))?;
        let journal = match journal_parent.open_dir_nofollow(&journal_leaf) {
            Ok(directory) => {
                validate_private_root(&directory, "existing journal root")?;
                directory
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                let mut builder = DirBuilder::new();
                builder.mode(0o700);
                journal_parent
                    .create_dir_with(&journal_leaf, &builder)
                    .map_err(|error| io_error("create journal root", requested, &error))?;
                let directory = journal_parent
                    .open_dir_nofollow(&journal_leaf)
                    .map_err(|error| io_error("open new journal root", requested, &error))?;
                directory
                    .set_permissions(Path::new("."), Permissions::from_mode(0o700))
                    .map_err(|error| io_error("set new journal root mode", requested, &error))?;
                sync_directory(&directory)
                    .map_err(|error| io_error("sync new journal root", requested, &error))?;
                sync_directory(&journal_parent)
                    .map_err(|error| io_error("sync journal parent", requested, &error))?;
                directory
            }
            Err(error) => {
                return Err(io_error(
                    "open journal root without following links",
                    requested,
                    &error,
                ));
            }
        };
        let journal_identity = validate_private_root(&journal, "journal root")?;
        let journal_path_anchor =
            journal_parent_anchor.extend(&journal_parent, &journal_leaf, "journal root")?;
        if journal_path_anchor.final_device_inode()
            != (
                journal_identity.object.device,
                journal_identity.object.inode,
            )
            || root_path_anchor.contains_device_inode(
                journal_identity.object.device,
                journal_identity.object.inode,
            )
            || journal_path_anchor.contains_device_inode(root_identity.device, root_identity.inode)
        {
            return Err(CapabilityApplyError::Journal(
                "journal and workspace resolve to overlapping directory identities".into(),
            ));
        }
        let existing_lock_identity = match journal.symlink_metadata(WRITER_LOCK_NAME) {
            Err(error) if error.kind() == io::ErrorKind::NotFound => None,
            Err(error) => {
                return Err(io_error(
                    "inspect journal writer lock",
                    Path::new(WRITER_LOCK_NAME),
                    &error,
                ));
            }
            Ok(metadata) => {
                validate_private_file_metadata(Path::new(WRITER_LOCK_NAME), &metadata)?;
                Some(object_identity(&metadata))
            }
        };
        let mut lock_options = OpenOptions::new();
        lock_options
            .read(true)
            .write(true)
            .follow(FollowSymlinks::No);
        if existing_lock_identity.is_none() {
            lock_options.create_new(true).mode(0o600);
        }
        let writer_lock = journal
            .open_with(WRITER_LOCK_NAME, &lock_options)
            .map_err(|error| io_error("open journal writer lock", requested, &error))?;
        if existing_lock_identity.is_none() {
            writer_lock
                .set_permissions(Permissions::from_mode(0o600))
                .map_err(|error| io_error("set new journal writer-lock mode", requested, &error))?;
            writer_lock
                .sync_all()
                .map_err(|error| io_error("sync new journal writer lock", requested, &error))?;
            sync_directory(&journal).map_err(|error| {
                io_error(
                    "sync journal root after writer-lock creation",
                    requested,
                    &error,
                )
            })?;
        }
        let lock_metadata = writer_lock
            .metadata()
            .map_err(|error| io_error("inspect journal writer lock", requested, &error))?;
        validate_private_file_metadata(Path::new(WRITER_LOCK_NAME), &lock_metadata)?;
        let writer_lock_identity = object_identity(&lock_metadata);
        if existing_lock_identity.is_some_and(|identity| identity != writer_lock_identity) {
            return Err(CapabilityApplyError::Journal(
                "journal writer-lock name changed during open".into(),
            ));
        }
        flock(&writer_lock, FlockOperation::NonBlockingLockExclusive).map_err(|error| {
            CapabilityApplyError::Journal(format!(
                "another capability applier owns the journal writer lock: {error}"
            ))
        })?;

        let applier = Self {
            grant,
            root,
            root_parent,
            root_leaf: live_leaf,
            root_identity,
            root_path_anchor,
            journal,
            journal_parent,
            journal_leaf,
            journal_identity,
            journal_path_anchor,
            writer_lock,
            writer_lock_identity,
            journal_path,
        };
        applier.validate_roots()?;
        Ok(applier)
    }

    /// Returns the disjoint private journal root used for diagnostics.
    #[must_use]
    pub fn journal_path(&self) -> &Path {
        &self.journal_path
    }

    /// Applies one staged change set and verifies its complete result snapshot.
    ///
    /// # Errors
    ///
    /// Returns [`CapabilityApplyError`] for stale authority/base/targets,
    /// unsafe objects, corrupt durable data, recovery conflicts, I/O, or any
    /// post-syscall state that requires explicit reconciliation.
    pub fn apply(
        &mut self,
        grant: &IssuedWorkspaceGrant,
        staged: &StagedChangeSet,
    ) -> Result<CapabilityApplyOutcome, CapabilityApplyError> {
        self.apply_internal(grant, staged, None)
    }

    /// Restores a committed transaction's targets while preserving unrelated files.
    ///
    /// # Errors
    ///
    /// Returns an error for stale authority, absent/non-committed transaction,
    /// target conflicts, journal corruption, or reconciliation-required effects.
    pub fn rollback(
        &mut self,
        grant: &IssuedWorkspaceGrant,
        change_set_id: &str,
    ) -> Result<CapabilityRollbackOutcome, CapabilityApplyError> {
        self.rollback_internal(grant, change_set_id, || Ok(()))
    }

    fn rollback_internal(
        &mut self,
        grant: &IssuedWorkspaceGrant,
        change_set_id: &str,
        after_phase_rename: impl FnOnce() -> Result<(), CapabilityApplyError>,
    ) -> Result<CapabilityRollbackOutcome, CapabilityApplyError> {
        self.validate_call(grant)?;
        let name = transaction_name(change_set_id);
        let transaction = self.open_transaction(&name, change_set_id)?;
        let plan = read_plan(&transaction)?;
        if plan.change_set.change_set_id != change_set_id {
            return Err(CapabilityApplyError::Journal(
                "transaction name and plan identity differ".into(),
            ));
        }
        let phase = read_phase(&transaction)?;
        if phase == JournalPhase::RolledBack {
            return rollback_outcome(self, &name, &plan);
        }
        if phase != JournalPhase::Committed {
            return Err(CapabilityApplyError::InvalidTransactionState {
                change_set_id: change_set_id.into(),
                phase: phase.as_str().into(),
            });
        }
        verify_result_targets(self, &plan)?;
        write_phase_after_effect_with_post_rename_hook(
            &transaction,
            JournalPhase::RollingBack,
            change_set_id,
            "durably transition rollback to rolling_back",
            after_phase_rename,
        )?;
        self.restore_plan(&name, &transaction, &plan)?;
        write_phase_after_effect(
            &transaction,
            JournalPhase::RolledBack,
            change_set_id,
            "record rollback completion",
        )?;
        rollback_outcome(self, &name, &plan)
    }

    /// Attempts one explicit rollback with exact immediate endpoint evidence.
    ///
    /// A typed [`CapabilityRollbackAttempt::LiveConflict`] is returned only
    /// while the durable transaction is still committed and before the
    /// rollback phase or any live-workspace mutation begins. Unsafe entries,
    /// observation races, incomplete captures, and any error after the phase
    /// transition remain ordinary errors or reconciliation-required outcomes.
    ///
    /// # Errors
    ///
    /// Returns an error for stale authority, bundle/artifact substitution,
    /// malformed or excessive targets, unsafe observations, observation races,
    /// journal corruption, or an uncertain post-transition effect.
    pub fn rollback_with_evidence(
        &mut self,
        grant: &IssuedWorkspaceGrant,
        bundle: &StageBundleReference,
        rollback: &CapabilityRollbackArtifactReference,
    ) -> Result<CapabilityRollbackAttempt, CapabilityApplyError> {
        self.rollback_with_evidence_internal(
            grant,
            bundle,
            rollback,
            || Ok(()),
            || Ok(()),
            || Ok(()),
        )
    }

    #[allow(
        clippy::too_many_lines,
        reason = "the rollback proof keeps pre-effect authority, the phase fence, restoration, and restart readback in one auditable state machine"
    )]
    fn rollback_with_evidence_internal(
        &mut self,
        grant: &IssuedWorkspaceGrant,
        bundle: &StageBundleReference,
        rollback: &CapabilityRollbackArtifactReference,
        between_observation_sweeps: impl FnOnce() -> Result<(), CapabilityApplyError>,
        after_phase_rename: impl FnOnce() -> Result<(), CapabilityApplyError>,
        after_phase_transition: impl FnOnce() -> Result<(), CapabilityApplyError>,
    ) -> Result<CapabilityRollbackAttempt, CapabilityApplyError> {
        self.validate_call(grant)?;
        bundle
            .validate()
            .map_err(|error| CapabilityApplyError::Journal(error.to_string()))?;
        let name = transaction_name(&bundle.change_set_id);
        let transaction = self.open_transaction(&name, &bundle.change_set_id)?;
        let plan = read_plan(&transaction)?;
        validate_bundle_plan(bundle, &plan)?;
        let target_contract = rollback_target_contract(&plan)?;
        let target_contract_digest = rollback_target_contract_digest(&target_contract)?;
        let expected_application_endpoints_digest =
            expected_application_endpoints_digest(&target_contract)?;
        let touched_target_set_digest = plan
            .change_set
            .touched_target_set_digest()
            .map_err(|error| CapabilityApplyError::Blob(error.to_string()))?;
        if rollback.transaction_id() != name
            || rollback.change_set_id() != plan.change_set.change_set_id
            || rollback.base_snapshot() != &plan.change_set.base_snapshot
            || rollback.touched_target_set_digest() != &touched_target_set_digest
            || rollback.target_contract_digest() != &target_contract_digest
        {
            return Err(CapabilityApplyError::Journal(
                "rollback bundle, transaction, artifact, or target binding differs".into(),
            ));
        }
        let phase = read_phase(&transaction)?;
        let reopened = rollback_artifact_reference(&name, &transaction, &plan)?;
        if &reopened != rollback {
            return Err(CapabilityApplyError::Journal(
                "supplied rollback artifacts differ from exact reopened journal evidence".into(),
            ));
        }
        self.validate_roots()?;
        if phase == JournalPhase::RolledBack {
            let evidence = (|| {
                let retained = read_rollback_precondition(&transaction)?.ok_or_else(|| {
                    CapabilityApplyError::Journal(
                        "rolled-back transaction lacks retained pre-effect observations".into(),
                    )
                })?;
                validate_retained_precondition(
                    &retained,
                    bundle,
                    rollback,
                    &target_contract,
                    &expected_application_endpoints_digest,
                    &touched_target_set_digest,
                )?;
                rollback_success_evidence(self, &plan, bundle, rollback, &retained)
            })();
            return evidence
                .map(CapabilityRollbackAttempt::Completed)
                .map_err(|error| {
                    reconciliation_required(
                        &plan.change_set.change_set_id,
                        "revalidate completed rollback evidence",
                        error,
                    )
                });
        }

        if phase == JournalPhase::RollingBack {
            let evidence = (|| {
                let retained = read_rollback_precondition(&transaction)?.ok_or_else(|| {
                    CapabilityApplyError::Journal(
                        "rolling-back transaction lacks retained pre-effect observations".into(),
                    )
                })?;
                validate_retained_precondition(
                    &retained,
                    bundle,
                    rollback,
                    &target_contract,
                    &expected_application_endpoints_digest,
                    &touched_target_set_digest,
                )?;
                self.restore_plan(&name, &transaction, &plan)?;
                write_phase_after_effect(
                    &transaction,
                    JournalPhase::RolledBack,
                    &plan.change_set.change_set_id,
                    "record resumed rollback completion",
                )?;
                rollback_success_evidence(self, &plan, bundle, rollback, &retained)
            })();
            return evidence
                .map(CapabilityRollbackAttempt::Completed)
                .map_err(|error| {
                    reconciliation_required(
                        &plan.change_set.change_set_id,
                        "construct resumed rollback evidence",
                        error,
                    )
                });
        }

        if phase != JournalPhase::Committed {
            return Err(CapabilityApplyError::InvalidTransactionState {
                change_set_id: bundle.change_set_id.clone(),
                phase: phase.as_str().into(),
            });
        }

        let first = capture_rollback_observations(self, &target_contract)?;
        between_observation_sweeps()?;
        let live_manifest_digest = self.capture_snapshot()?;
        let manifest_observed_at_unix_ms = rollback_observed_at_unix_ms()?;
        let second = capture_rollback_observations(self, &target_contract)?;
        let observed_at_unix_ms = rollback_observed_at_unix_ms()?;
        if first != second {
            return Err(CapabilityApplyError::Root(
                "rollback target observations changed across complete manifest capture".into(),
            ));
        }
        let conflicts = rollback_conflicts(&target_contract, &second)?;
        let observed_endpoints_digest = observed_endpoints_digest(&second)?;
        if !conflicts.is_empty() {
            return Ok(CapabilityRollbackAttempt::LiveConflict(
                CapabilityRollbackLiveConflict {
                    bundle: bundle.clone(),
                    rollback: rollback.clone(),
                    target_contract,
                    expected_application_endpoints_digest,
                    touched_target_set_digest,
                    observations: second,
                    observed_endpoints_digest,
                    conflicts,
                    live_manifest_digest,
                    manifest_observed_at_unix_ms,
                    observed_at_unix_ms,
                    rollback_mutation_started: false,
                },
            ));
        }

        let proposed = PersistedRollbackPrecondition {
            version: ROLLBACK_PRECONDITION_VERSION,
            bundle: bundle.clone(),
            transaction_id: name.clone(),
            change_set_id: plan.change_set.change_set_id.clone(),
            rollback_artifacts_digest: rollback.artifacts_digest().clone(),
            target_contract,
            expected_application_endpoints_digest,
            touched_target_set_digest,
            observations: second,
            observations_digest: observed_endpoints_digest,
            captured_at_unix_ms: observed_at_unix_ms,
        };
        let retained = if let Some(existing) = read_rollback_precondition(&transaction)? {
            validate_retained_precondition(
                &existing,
                bundle,
                rollback,
                &proposed.target_contract,
                &proposed.expected_application_endpoints_digest,
                &proposed.touched_target_set_digest,
            )?;
            if existing.observations != proposed.observations {
                return Err(CapabilityApplyError::Root(
                    "retained rollback precondition differs from the current stable endpoint observation"
                        .into(),
                ));
            }
            existing
        } else {
            write_rollback_precondition(&transaction, &proposed)?;
            proposed
        };

        write_phase_after_effect_with_post_rename_hook(
            &transaction,
            JournalPhase::RollingBack,
            &plan.change_set.change_set_id,
            "durably transition evidence-bearing rollback to rolling_back",
            after_phase_rename,
        )?;
        after_phase_transition().map_err(|error| {
            reconciliation_required(
                &plan.change_set.change_set_id,
                "continue after retained rollback precondition",
                error,
            )
        })?;
        self.restore_plan(&name, &transaction, &plan)
            .map_err(|error| {
                reconciliation_required(
                    &plan.change_set.change_set_id,
                    "execute evidence-bearing rollback",
                    error,
                )
            })?;
        write_phase_after_effect(
            &transaction,
            JournalPhase::RolledBack,
            &plan.change_set.change_set_id,
            "record evidence-bearing rollback completion",
        )?;
        rollback_success_evidence(self, &plan, bundle, rollback, &retained)
            .map(CapabilityRollbackAttempt::Completed)
            .map_err(|error| {
                reconciliation_required(
                    &plan.change_set.change_set_id,
                    "construct evidence-bearing rollback result",
                    error,
                )
            })
    }

    /// Reopens and canonically binds the immutable plan and base blobs needed
    /// to roll back a committed or already-rolled-back transaction.
    ///
    /// Artifact contents are hashed in full but never embedded in the returned
    /// value. The manifest is capped at `MAX_ROLLBACK_ARTIFACT_ENTRIES`.
    ///
    /// # Errors
    ///
    /// Returns an error for stale authority, an in-progress transaction,
    /// corrupt/replaced artifacts, an excessive artifact count, or root I/O.
    pub fn reopen_rollback_artifacts(
        &self,
        grant: &IssuedWorkspaceGrant,
        change_set_id: &str,
    ) -> Result<CapabilityRollbackArtifactReference, CapabilityApplyError> {
        self.validate_call(grant)?;
        let name = transaction_name(change_set_id);
        let transaction = self.open_transaction(&name, change_set_id)?;
        let plan = read_plan(&transaction)?;
        if plan.change_set.change_set_id != change_set_id {
            return Err(CapabilityApplyError::Journal(
                "transaction name and rollback plan identity differ".into(),
            ));
        }
        match read_phase(&transaction)? {
            JournalPhase::Committed | JournalPhase::RolledBack => {}
            phase => {
                return Err(CapabilityApplyError::InvalidTransactionState {
                    change_set_id: change_set_id.into(),
                    phase: phase.as_str().into(),
                });
            }
        }
        let reference = rollback_artifact_reference(&name, &transaction, &plan)?;
        self.validate_roots()?;
        Ok(reference)
    }

    /// Reopens every artifact and proves it still equals a prior reference.
    ///
    /// # Errors
    ///
    /// Returns an error if authority, transaction state, identity, metadata,
    /// content, target binding, or the canonical artifact digest differs.
    pub fn validate_rollback_artifacts(
        &self,
        grant: &IssuedWorkspaceGrant,
        reference: &CapabilityRollbackArtifactReference,
    ) -> Result<(), CapabilityApplyError> {
        let reopened = self.reopen_rollback_artifacts(grant, reference.change_set_id())?;
        if &reopened != reference {
            return Err(CapabilityApplyError::Journal(
                "reopened rollback artifacts differ from the supplied exact reference".into(),
            ));
        }
        Ok(())
    }

    /// Restores all prepared, applying, or rolling-back transactions.
    ///
    /// # Errors
    ///
    /// Returns an error for stale authority/root identity, unexpected journal
    /// entries, corrupt plans, target conflicts, or ambiguous live effects.
    pub fn recover_pending(
        &mut self,
        grant: &IssuedWorkspaceGrant,
    ) -> Result<CapabilityRecoveryReport, CapabilityApplyError> {
        self.validate_call(grant)?;
        let mut names = self
            .journal
            .entries()
            .map_err(|error| io_error("enumerate journal root", &self.journal_path, &error))?
            .map(|entry| {
                entry
                    .map(|entry| entry.file_name())
                    .map_err(|error| io_error("read journal entry", &self.journal_path, &error))
            })
            .collect::<Result<Vec<_>, _>>()?;
        names.sort();
        let mut report = CapabilityRecoveryReport::default();
        for name in names {
            let text = name
                .to_str()
                .ok_or_else(|| CapabilityApplyError::Journal("non-UTF-8 journal entry".into()))?;
            if text == WRITER_LOCK_NAME {
                self.validate_writer_lock()?;
                continue;
            }
            if is_preparation_name(text) {
                self.cleanup_preparation(text).map_err(|error| {
                    CapabilityApplyError::PreparationCleanupRequired {
                        preparation_id: text.to_owned(),
                        reason: error.to_string(),
                    }
                })?;
                report.abandoned_preparations.push(text.to_owned());
                continue;
            }
            if !is_transaction_name(text) {
                return Err(CapabilityApplyError::Journal(format!(
                    "unexpected journal entry {text:?}"
                )));
            }
            let transaction = self
                .journal
                .open_dir_nofollow(&name)
                .map_err(|error| io_error("open transaction directory", Path::new(text), &error))?;
            validate_private_root(&transaction, "transaction directory")?;
            let plan = read_plan(&transaction)?;
            if transaction_name(&plan.change_set.change_set_id) != text {
                return Err(CapabilityApplyError::Journal(
                    "transaction directory does not match plan identity".into(),
                ));
            }
            match read_phase(&transaction)? {
                JournalPhase::Prepared => {
                    validate_prepared_state(&transaction, &plan)?;
                    let preparation = preparation_name(text);
                    publish_no_replace(
                        &self.journal,
                        text,
                        &preparation,
                        "quarantine prepared no-effect transaction",
                    )?;
                    sync_directory(&self.journal).map_err(|error| {
                        io_error(
                            "sync quarantined prepared transaction",
                            Path::new(&preparation),
                            &error,
                        )
                    })?;
                    self.cleanup_preparation(&preparation).map_err(|error| {
                        CapabilityApplyError::PreparationCleanupRequired {
                            preparation_id: preparation.clone(),
                            reason: error.to_string(),
                        }
                    })?;
                    report
                        .abandoned_preparations
                        .push(plan.change_set.change_set_id);
                }
                JournalPhase::Applying | JournalPhase::RollingBack => {
                    write_phase_after_effect(
                        &transaction,
                        JournalPhase::RollingBack,
                        &plan.change_set.change_set_id,
                        "record recovery rollback intent",
                    )?;
                    self.restore_plan(text, &transaction, &plan)?;
                    write_phase_after_effect(
                        &transaction,
                        JournalPhase::RolledBack,
                        &plan.change_set.change_set_id,
                        "record recovered rollback",
                    )?;
                    report
                        .recovered_change_sets
                        .push(plan.change_set.change_set_id);
                }
                JournalPhase::Committed | JournalPhase::RolledBack => {}
            }
        }
        Ok(report)
    }

    /// Reconciles one transaction without replaying its requested change set.
    ///
    /// # Errors
    ///
    /// Returns an error for stale authority, missing/corrupt evidence, target
    /// conflicts, or an effect whose endpoint still cannot be proven.
    pub fn reconcile(
        &mut self,
        grant: &IssuedWorkspaceGrant,
        change_set_id: &str,
    ) -> Result<CapabilityApplyReconciliation, CapabilityApplyError> {
        self.validate_call(grant)?;
        let name = transaction_name(change_set_id);
        let transaction = self.open_transaction(&name, change_set_id)?;
        let plan = read_plan(&transaction)?;
        if plan.change_set.change_set_id != change_set_id {
            return Err(CapabilityApplyError::Journal(
                "transaction and requested identity differ".into(),
            ));
        }
        match read_phase(&transaction)? {
            JournalPhase::Committed => {
                verify_result_targets(self, &plan)?;
                let live_manifest_digest = self.capture_snapshot()?;
                verify_result_targets(self, &plan)?;
                Ok(CapabilityApplyReconciliation::Committed(committed_outcome(
                    &name,
                    &plan,
                    live_manifest_digest,
                )?))
            }
            JournalPhase::RolledBack => Ok(CapabilityApplyReconciliation::TargetsRestored(
                rollback_outcome(self, &name, &plan)?,
            )),
            JournalPhase::Prepared => {
                validate_prepared_state(&transaction, &plan)?;
                let restored = rollback_outcome(self, &name, &plan)?;
                let preparation = preparation_name(&name);
                publish_no_replace(
                    &self.journal,
                    &name,
                    &preparation,
                    "quarantine reconciled prepared transaction",
                )?;
                sync_directory(&self.journal).map_err(|error| {
                    io_error(
                        "sync reconciled preparation quarantine",
                        Path::new(&preparation),
                        &error,
                    )
                })?;
                self.cleanup_preparation(&preparation)?;
                Ok(CapabilityApplyReconciliation::TargetsRestored(restored))
            }
            JournalPhase::Applying | JournalPhase::RollingBack => {
                write_phase_after_effect(
                    &transaction,
                    JournalPhase::RollingBack,
                    change_set_id,
                    "record reconciliation rollback intent",
                )?;
                self.restore_plan(&name, &transaction, &plan)?;
                write_phase_after_effect(
                    &transaction,
                    JournalPhase::RolledBack,
                    change_set_id,
                    "record reconciled rollback",
                )?;
                Ok(CapabilityApplyReconciliation::TargetsRestored(
                    rollback_outcome(self, &name, &plan)?,
                ))
            }
        }
    }

    fn validate_call(&self, grant: &IssuedWorkspaceGrant) -> Result<(), CapabilityApplyError> {
        grant
            .validate_integrity()
            .map_err(|error| CapabilityApplyError::Authority(error.to_string()))?;
        if grant != &self.grant {
            return Err(CapabilityApplyError::Authority(
                "caller grant differs from acquisition authority".into(),
            ));
        }
        if !grant.contract().permissions.apply_verified_changes {
            return Err(CapabilityApplyError::PermissionDenied);
        }
        self.validate_roots()
    }

    fn validate_roots(&self) -> Result<(), CapabilityApplyError> {
        self.root_path_anchor.validate("workspace root")?;
        let descriptor = self
            .root
            .dir_metadata()
            .map_err(|error| io_error("inspect retained workspace root", Path::new("."), &error))?;
        if !descriptor.is_dir() || object_identity(&descriptor) != self.root_identity {
            return Err(CapabilityApplyError::Root(
                "retained workspace root identity changed".into(),
            ));
        }
        let named = self
            .root_parent
            .open_dir_nofollow(&self.root_leaf)
            .map_err(|error| {
                CapabilityApplyError::Root(format!(
                    "workspace root name no longer resolves without a link: {error}"
                ))
            })?;
        let named_metadata = named.dir_metadata().map_err(|error| {
            CapabilityApplyError::Root(format!("inspect named workspace root: {error}"))
        })?;
        if object_identity(&named_metadata) != self.root_identity {
            return Err(CapabilityApplyError::Root(
                "workspace root name was replaced".into(),
            ));
        }
        self.journal_path_anchor.validate("journal root")?;
        let journal_descriptor = validate_private_root(&self.journal, "retained journal root")?;
        if journal_descriptor != self.journal_identity {
            return Err(CapabilityApplyError::Root(
                "retained journal identity, owner, or mode changed".into(),
            ));
        }
        let named_journal = self
            .journal_parent
            .open_dir_nofollow(&self.journal_leaf)
            .map_err(|error| {
                CapabilityApplyError::Root(format!(
                    "journal name no longer resolves without a link: {error}"
                ))
            })?;
        if validate_private_root(&named_journal, "named journal root")? != self.journal_identity {
            return Err(CapabilityApplyError::Root(
                "journal root name was replaced".into(),
            ));
        }
        self.validate_writer_lock()?;
        Ok(())
    }

    fn validate_writer_lock(&self) -> Result<(), CapabilityApplyError> {
        let descriptor = self.writer_lock.metadata().map_err(|error| {
            io_error(
                "inspect retained journal writer lock",
                Path::new(WRITER_LOCK_NAME),
                &error,
            )
        })?;
        validate_private_file_metadata(Path::new(WRITER_LOCK_NAME), &descriptor)?;
        if object_identity(&descriptor) != self.writer_lock_identity {
            return Err(CapabilityApplyError::Root(
                "retained journal writer-lock identity changed".into(),
            ));
        }
        let named = self
            .journal
            .symlink_metadata(WRITER_LOCK_NAME)
            .map_err(|error| {
                io_error(
                    "inspect named journal writer lock",
                    Path::new(WRITER_LOCK_NAME),
                    &error,
                )
            })?;
        validate_private_file_metadata(Path::new(WRITER_LOCK_NAME), &named)?;
        if object_identity(&named) != self.writer_lock_identity {
            return Err(CapabilityApplyError::Root(
                "journal writer-lock name was replaced".into(),
            ));
        }
        Ok(())
    }

    fn open_parent(&self, path: &Path) -> Result<ParentHandle, CapabilityApplyError> {
        let path = normalize_path(path)?;
        let mut components = path.components().collect::<Vec<_>>();
        let leaf = match components.pop() {
            Some(Component::Normal(leaf)) => leaf.to_os_string(),
            _ => {
                return Err(CapabilityApplyError::InvalidPath {
                    path,
                    reason: "target must have a normal leaf".into(),
                });
            }
        };
        let mut directory = self
            .root
            .try_clone()
            .map_err(|error| io_error("clone workspace capability", &path, &error))?;
        let mut relative = PathBuf::new();
        for component in components {
            let Component::Normal(name) = component else {
                return Err(CapabilityApplyError::InvalidPath {
                    path,
                    reason: "parent contains a non-normal component".into(),
                });
            };
            relative.push(name);
            directory = directory.open_dir_nofollow(name).map_err(|error| {
                if error.kind() == io::ErrorKind::NotFound {
                    CapabilityApplyError::MissingParent(relative.clone())
                } else {
                    io_error(
                        "open target parent without following links",
                        &relative,
                        &error,
                    )
                }
            })?;
            let metadata = directory
                .dir_metadata()
                .map_err(|error| io_error("inspect target parent descriptor", &relative, &error))?;
            if !metadata.is_dir() {
                return Err(CapabilityApplyError::UnsafeEntry {
                    path: relative.clone(),
                    kind: UnsafeFileKind::Directory,
                });
            }
        }
        let metadata = directory
            .dir_metadata()
            .map_err(|error| io_error("inspect final target parent", &path, &error))?;
        Ok(ParentHandle {
            directory,
            relative,
            identity: object_identity(&metadata),
            leaf,
        })
    }

    fn verify_parent(&self, expected: &ParentHandle) -> Result<(), CapabilityApplyError> {
        let reopened = self.reopen_directory(&expected.relative)?;
        let metadata = reopened
            .dir_metadata()
            .map_err(|error| io_error("revalidate target parent", &expected.relative, &error))?;
        if object_identity(&metadata) != expected.identity {
            return Err(CapabilityApplyError::Root(format!(
                "target parent {} was replaced",
                expected.relative.display()
            )));
        }
        Ok(())
    }

    fn reopen_directory(&self, relative: &Path) -> Result<Dir, CapabilityApplyError> {
        let mut directory = self
            .root
            .try_clone()
            .map_err(|error| io_error("clone workspace root", relative, &error))?;
        for component in relative.components() {
            let Component::Normal(name) = component else {
                return Err(CapabilityApplyError::InvalidPath {
                    path: relative.to_path_buf(),
                    reason: "revalidation path is not normalized".into(),
                });
            };
            directory = directory.open_dir_nofollow(name).map_err(|error| {
                io_error(
                    "reopen target parent without following links",
                    relative,
                    &error,
                )
            })?;
        }
        Ok(directory)
    }

    fn open_transaction(
        &self,
        name: &str,
        change_set_id: &str,
    ) -> Result<Dir, CapabilityApplyError> {
        self.journal.open_dir_nofollow(name).map_err(|error| {
            if error.kind() == io::ErrorKind::NotFound {
                CapabilityApplyError::TransactionNotFound(change_set_id.into())
            } else {
                io_error("open transaction", Path::new(name), &error)
            }
        })
    }

    fn cleanup_preparation(&self, name: &str) -> Result<(), CapabilityApplyError> {
        if !is_preparation_name(name) {
            return Err(CapabilityApplyError::Journal(format!(
                "invalid preparation directory name {name:?}"
            )));
        }
        let preparation = self.journal.open_dir_nofollow(name).map_err(|error| {
            io_error(
                "open no-effect preparation for cleanup",
                Path::new(name),
                &error,
            )
        })?;
        let identity = validate_private_root(&preparation, "preparation cleanup root")?;
        let entries = validate_preparation_entries(&preparation)?;
        for (entry, expected) in entries {
            remove_owned_regular_file(&preparation, &entry, expected, Path::new(&entry))?;
        }
        sync_directory(&preparation).map_err(|error| {
            io_error(
                "sync emptied preparation directory",
                Path::new(name),
                &error,
            )
        })?;
        let named = self
            .journal
            .symlink_metadata(name)
            .map_err(|error| io_error("revalidate preparation root", Path::new(name), &error))?;
        if !named.is_dir() || object_identity(&named) != identity.object {
            return Err(CapabilityApplyError::Journal(format!(
                "preparation root {name:?} changed before removal"
            )));
        }
        self.journal
            .remove_dir(name)
            .map_err(|error| io_error("remove empty preparation root", Path::new(name), &error))?;
        sync_directory(&self.journal)
            .map_err(|error| io_error("sync removed preparation root", Path::new(name), &error))
    }
}

impl CapabilitySafeApplier {
    #[allow(
        clippy::too_many_lines,
        reason = "application keeps preparation, ordered effects, endpoint bracketing, recovery, and commit adjacent"
    )]
    fn apply_internal(
        &mut self,
        grant: &IssuedWorkspaceGrant,
        staged: &StagedChangeSet,
        fault: Option<FaultPoint>,
    ) -> Result<CapabilityApplyOutcome, CapabilityApplyError> {
        self.validate_call(grant)?;
        staged
            .change_set()
            .validate()
            .map_err(|error| CapabilityApplyError::Blob(error.to_string()))?;
        if staged.change_set().operations.is_empty() {
            return Err(CapabilityApplyError::EmptyChangeSet);
        }
        for operation in &staged.change_set().operations {
            normalize_path(operation.path())?;
        }
        let _ = self.recover_pending(grant)?;
        let (name, transaction, plan) = self.prepare_transaction(staged, fault)?;
        write_phase_after_effect(
            &transaction,
            JournalPhase::Applying,
            &plan.change_set.change_set_id,
            "durably transition application to applying",
        )?;

        for (index, directory) in plan.directories.iter().enumerate() {
            if let Err(error) =
                self.apply_directory(&name, &transaction, &plan, index, directory, fault)
            {
                return Err(self.recover_failed_apply(&name, &transaction, &plan, error));
            }
        }
        for (index, operation) in plan.operations.iter().enumerate() {
            if let Err(error) =
                self.apply_operation(&name, &transaction, &plan, index, operation, fault)
            {
                return Err(self.recover_failed_apply(&name, &transaction, &plan, error));
            }
        }

        if let Err(mismatch) = verify_result_targets(self, &plan) {
            let recovery = (|| {
                write_phase_after_effect(
                    &transaction,
                    JournalPhase::RollingBack,
                    &plan.change_set.change_set_id,
                    "record result-mismatch rollback intent",
                )?;
                self.restore_plan(&name, &transaction, &plan)?;
                write_phase_after_effect(
                    &transaction,
                    JournalPhase::RolledBack,
                    &plan.change_set.change_set_id,
                    "record rollback after result mismatch",
                )
            })();
            if let Err(recovery) = recovery {
                return Err(CapabilityApplyError::ReconciliationRequired {
                    change_set_id: plan.change_set.change_set_id.clone(),
                    path: None,
                    operation: "recover result mismatch",
                    reason: format!("snapshot mismatch ({mismatch}); recovery failed ({recovery})"),
                });
            }
            return Err(mismatch);
        }
        #[cfg(test)]
        if fault == Some(FaultPoint::InjectUnsafeEntryBeforeManifest) {
            std::os::unix::fs::symlink(
                "manifest-capture-target",
                self.grant
                    .contract()
                    .canonical_root
                    .join("manifest-capture-unsafe-link"),
            )
            .map_err(|error| {
                io_error(
                    "inject unsafe manifest entry",
                    Path::new("manifest-capture-unsafe-link"),
                    &error,
                )
            })?;
        }
        let live_manifest_digest = match self.capture_snapshot() {
            Ok(digest) => digest,
            Err(observation_error) => {
                let recovery = (|| {
                    write_phase_after_effect(
                        &transaction,
                        JournalPhase::RollingBack,
                        &plan.change_set.change_set_id,
                        "record manifest-failure rollback intent",
                    )?;
                    self.restore_plan(&name, &transaction, &plan)?;
                    write_phase_after_effect(
                        &transaction,
                        JournalPhase::RolledBack,
                        &plan.change_set.change_set_id,
                        "record rollback after live-manifest capture failure",
                    )
                })();
                if let Err(recovery_error) = recovery {
                    return Err(CapabilityApplyError::ReconciliationRequired {
                        change_set_id: plan.change_set.change_set_id.clone(),
                        path: None,
                        operation: "recover live-manifest capture failure",
                        reason: format!(
                            "manifest capture failed ({observation_error}); recovery failed ({recovery_error})"
                        ),
                    });
                }
                return Err(observation_error);
            }
        };
        if let Err(mismatch) = verify_result_targets(self, &plan) {
            let recovery = (|| {
                write_phase_after_effect(
                    &transaction,
                    JournalPhase::RollingBack,
                    &plan.change_set.change_set_id,
                    "record post-manifest-mismatch rollback intent",
                )?;
                self.restore_plan(&name, &transaction, &plan)?;
                write_phase_after_effect(
                    &transaction,
                    JournalPhase::RolledBack,
                    &plan.change_set.change_set_id,
                    "record rollback after post-manifest target mismatch",
                )
            })();
            if let Err(recovery) = recovery {
                return Err(CapabilityApplyError::ReconciliationRequired {
                    change_set_id: plan.change_set.change_set_id.clone(),
                    path: None,
                    operation: "recover post-manifest target mismatch",
                    reason: format!("target mismatch ({mismatch}); recovery failed ({recovery})"),
                });
            }
            return Err(mismatch);
        }
        maybe_fault(fault, FaultPoint::BeforeCommit, plan.operations.len())?;
        write_phase_after_effect(
            &transaction,
            JournalPhase::Committed,
            &plan.change_set.change_set_id,
            "commit applied transaction",
        )?;
        committed_outcome(&name, &plan, live_manifest_digest)
    }

    fn recover_failed_apply(
        &self,
        transaction_name: &str,
        transaction: &Dir,
        plan: &JournalPlan,
        error: CapabilityApplyError,
    ) -> CapabilityApplyError {
        if matches!(
            error,
            CapabilityApplyError::ReconciliationRequired { .. }
                | CapabilityApplyError::InjectedCrash { .. }
        ) {
            return error;
        }
        let recovery = (|| {
            write_phase_after_effect(
                transaction,
                JournalPhase::RollingBack,
                &plan.change_set.change_set_id,
                "record failed-application rollback intent",
            )?;
            self.restore_plan(transaction_name, transaction, plan)?;
            write_phase_after_effect(
                transaction,
                JournalPhase::RolledBack,
                &plan.change_set.change_set_id,
                "record rollback after apply failure",
            )
        })();
        match recovery {
            Ok(()) => error,
            Err(recovery) => CapabilityApplyError::ReconciliationRequired {
                change_set_id: plan.change_set.change_set_id.clone(),
                path: None,
                operation: "recover failed application",
                reason: format!("apply failed ({error}); recovery failed ({recovery})"),
            },
        }
    }

    #[allow(
        clippy::too_many_lines,
        reason = "preparation is one auditable create-sync-populate-publish crash state machine"
    )]
    fn prepare_transaction(
        &self,
        staged: &StagedChangeSet,
        fault: Option<FaultPoint>,
    ) -> Result<(String, Dir, JournalPlan), CapabilityApplyError> {
        let name = transaction_name(&staged.change_set().change_set_id);
        let prep_name = preparation_name(&name);
        match self.journal.symlink_metadata(&name) {
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Ok(_) => {
                return Err(CapabilityApplyError::TransactionExists(
                    staged.change_set().change_set_id.clone(),
                ));
            }
            Err(error) => {
                return Err(io_error(
                    "inspect transaction name",
                    Path::new(&name),
                    &error,
                ));
            }
        }
        match self.journal.symlink_metadata(&prep_name) {
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Ok(_) => {
                return Err(CapabilityApplyError::PreparationCleanupRequired {
                    preparation_id: prep_name,
                    reason: "reserved preparation name already exists".into(),
                });
            }
            Err(error) => {
                return Err(io_error(
                    "inspect preparation name",
                    Path::new(&prep_name),
                    &error,
                ));
            }
        }
        let mut builder = DirBuilder::new();
        builder.mode(0o700);
        self.journal
            .create_dir_with(&prep_name, &builder)
            .map_err(|error| {
                io_error(
                    "create preparation directory",
                    Path::new(&prep_name),
                    &error,
                )
            })?;
        let transaction = self
            .journal
            .open_dir_nofollow(&prep_name)
            .map_err(|error| {
                io_error("open preparation directory", Path::new(&prep_name), &error)
            })?;
        maybe_preparation_fault(fault, FaultPoint::AfterPreparationCreate, 0, "create")?;
        transaction
            .set_permissions(Path::new("."), Permissions::from_mode(0o700))
            .map_err(|error| io_error("set preparation mode", Path::new(&prep_name), &error))?;
        validate_private_root(&transaction, "preparation directory")?;
        maybe_preparation_fault(fault, FaultPoint::AfterPreparationMode, 0, "mode")?;
        sync_directory(&transaction).map_err(|error| {
            io_error("sync preparation directory", Path::new(&prep_name), &error)
        })?;
        maybe_preparation_fault(
            fault,
            FaultPoint::AfterPreparationDirectorySync,
            0,
            "directory-sync",
        )?;
        sync_directory(&self.journal)
            .map_err(|error| io_error("sync journal root", &self.journal_path, &error))?;
        maybe_preparation_fault(
            fault,
            FaultPoint::AfterPreparationParentSync,
            0,
            "parent-sync",
        )?;

        let preparation_result = (|| {
            let mut completed_blobs = 0;
            let plan = self.build_plan(&transaction, staged, fault, &mut completed_blobs)?;
            write_plan_new(&transaction, &plan)?;
            maybe_preparation_fault(
                fault,
                FaultPoint::AfterPreparationPlan,
                completed_blobs,
                "plan",
            )?;
            write_new_journal_file(
                &transaction,
                "phase",
                format!("{}\n", JournalPhase::Prepared.as_str()).as_bytes(),
            )?;
            maybe_preparation_fault(
                fault,
                FaultPoint::AfterPreparationPhase,
                completed_blobs,
                "phase",
            )?;
            validate_transaction_entries(&transaction, &plan)?;
            validate_prepared_state(&transaction, &plan)?;
            sync_directory(&transaction).map_err(|error| {
                io_error("sync complete preparation", Path::new(&prep_name), &error)
            })?;
            Ok(plan)
        })();
        let plan = match preparation_result {
            Ok(plan) => plan,
            Err(error @ CapabilityApplyError::InjectedPreparationCrash { .. }) => {
                return Err(error);
            }
            Err(error) => {
                return match self.cleanup_preparation(&prep_name) {
                    Ok(()) => Err(error),
                    Err(cleanup) => Err(CapabilityApplyError::PreparationCleanupRequired {
                        preparation_id: prep_name,
                        reason: format!("preparation failed ({error}); cleanup failed ({cleanup})"),
                    }),
                };
            }
        };
        publish_no_replace(
            &self.journal,
            &prep_name,
            &name,
            "publish complete prepared transaction",
        )?;
        maybe_preparation_fault(
            fault,
            FaultPoint::AfterPreparationRename,
            plan_blob_count(&plan),
            "publish-rename",
        )?;
        sync_directory(&self.journal).map_err(|error| {
            io_error(
                "sync published prepared transaction",
                Path::new(&name),
                &error,
            )
        })?;
        maybe_preparation_fault(
            fault,
            FaultPoint::AfterPreparationPublishSync,
            plan_blob_count(&plan),
            "publish-parent-sync",
        )?;
        Ok((name, transaction, plan))
    }

    fn build_plan(
        &self,
        transaction: &Dir,
        staged: &StagedChangeSet,
        fault: Option<FaultPoint>,
        completed_blobs: &mut usize,
    ) -> Result<JournalPlan, CapabilityApplyError> {
        let directories = self.plan_missing_directories(staged.change_set())?;
        let directory_paths = directories
            .iter()
            .map(|directory| directory.path.clone())
            .collect::<BTreeSet<_>>();
        let mut operations = Vec::with_capacity(staged.change_set().operations.len());
        for (index, operation) in staged.change_set().operations.iter().enumerate() {
            let path = normalize_path(operation.path())?;
            match operation {
                FileOperation::Create { result_hash, .. } => {
                    match self.open_parent(&path) {
                        Ok(parent) => require_absent(&parent, &path)?,
                        Err(CapabilityApplyError::MissingParent(missing))
                            if directory_paths.contains(&missing) => {}
                        Err(error) => return Err(error),
                    }
                    let result = verified_staged_blob(staged, result_hash)?;
                    let mode = staged.create_mode(&path).ok_or_else(|| {
                        CapabilityApplyError::Blob(format!(
                            "create mode missing for {}",
                            path.display()
                        ))
                    })?;
                    write_new_journal_file(transaction, &result_blob_name(index), result)?;
                    *completed_blobs += 1;
                    maybe_preparation_blob_fault(fault, *completed_blobs)?;
                    operations.push(PlanOperation {
                        operation: operation.clone(),
                        mode: mode & 0o777,
                        base_identity: None,
                    });
                }
                FileOperation::Modify {
                    base_hash,
                    result_hash,
                    ..
                } => {
                    let parent = self.open_parent(&path)?;
                    let (base, fingerprint) =
                        stable_read(&parent.directory, &parent.leaf, &path, MAX_APPLY_FILE_BYTES)?;
                    require_digest(&path, Some(base_hash), Some(Digest::sha256(&base)))?;
                    let result = verified_staged_blob(staged, result_hash)?;
                    write_new_journal_file(transaction, &base_blob_name(index), &base)?;
                    *completed_blobs += 1;
                    maybe_preparation_blob_fault(fault, *completed_blobs)?;
                    write_new_journal_file(transaction, &result_blob_name(index), result)?;
                    *completed_blobs += 1;
                    maybe_preparation_blob_fault(fault, *completed_blobs)?;
                    operations.push(PlanOperation {
                        operation: operation.clone(),
                        mode: fingerprint.mode & 0o777,
                        base_identity: Some(fingerprint.object),
                    });
                }
                FileOperation::Delete { base_hash, .. } => {
                    let parent = self.open_parent(&path)?;
                    let (base, fingerprint) =
                        stable_read(&parent.directory, &parent.leaf, &path, MAX_APPLY_FILE_BYTES)?;
                    require_digest(&path, Some(base_hash), Some(Digest::sha256(&base)))?;
                    write_new_journal_file(transaction, &base_blob_name(index), &base)?;
                    *completed_blobs += 1;
                    maybe_preparation_blob_fault(fault, *completed_blobs)?;
                    operations.push(PlanOperation {
                        operation: operation.clone(),
                        mode: fingerprint.mode & 0o777,
                        base_identity: Some(fingerprint.object),
                    });
                }
            }
        }
        Ok(JournalPlan {
            change_set: staged.change_set().clone(),
            directories,
            operations,
        })
    }

    #[allow(
        clippy::too_many_lines,
        reason = "directory discovery keeps each no-follow identity check and fail-closed branch explicit"
    )]
    fn plan_missing_directories(
        &self,
        change_set: &ChangeSet,
    ) -> Result<Vec<PlannedDirectory>, CapabilityApplyError> {
        let operation_paths = change_set
            .operations
            .iter()
            .map(|operation| normalize_path(operation.path()))
            .collect::<Result<BTreeSet<_>, _>>()?;
        let mut missing = BTreeSet::new();
        for operation in &change_set.operations {
            let path = normalize_path(operation.path())?;
            let parent_path = path.parent().unwrap_or_else(|| Path::new(""));
            let mut directory = self
                .root
                .try_clone()
                .map_err(|error| io_error("clone workspace root", &path, &error))?;
            let mut relative = PathBuf::new();
            let mut ancestor_missing = false;
            for component in parent_path.components() {
                let Component::Normal(name) = component else {
                    return Err(CapabilityApplyError::InvalidPath {
                        path: path.clone(),
                        reason: "parent path is not normalized".into(),
                    });
                };
                relative.push(name);
                if operation_paths.contains(&relative) {
                    return Err(CapabilityApplyError::InvalidPath {
                        path: path.clone(),
                        reason: format!(
                            "file operation target {} is also required as a directory",
                            relative.display()
                        ),
                    });
                }
                if ancestor_missing || missing.contains(&relative) {
                    ancestor_missing = true;
                    missing.insert(relative.clone());
                    continue;
                }
                match directory.symlink_metadata(name) {
                    Err(error) if error.kind() == io::ErrorKind::NotFound => {
                        ancestor_missing = true;
                        missing.insert(relative.clone());
                    }
                    Err(error) => {
                        return Err(io_error(
                            "inspect prospective operation parent",
                            &relative,
                            &error,
                        ));
                    }
                    Ok(metadata) if metadata.file_type().is_symlink() => {
                        return Err(CapabilityApplyError::UnsafeEntry {
                            path: relative.clone(),
                            kind: UnsafeFileKind::Symlink,
                        });
                    }
                    Ok(metadata) if !metadata.is_dir() => {
                        return Err(CapabilityApplyError::InvalidPath {
                            path: path.clone(),
                            reason: format!(
                                "parent component {} is not a directory",
                                relative.display()
                            ),
                        });
                    }
                    Ok(metadata) => {
                        let opened = directory.open_dir_nofollow(name).map_err(|error| {
                            io_error(
                                "open prospective operation parent without following links",
                                &relative,
                                &error,
                            )
                        })?;
                        let opened_metadata = opened.dir_metadata().map_err(|error| {
                            io_error(
                                "inspect prospective operation parent descriptor",
                                &relative,
                                &error,
                            )
                        })?;
                        if object_identity(&opened_metadata) != object_identity(&metadata) {
                            return Err(CapabilityApplyError::Root(format!(
                                "operation parent {} changed during planning",
                                relative.display()
                            )));
                        }
                        directory = opened;
                    }
                }
            }
        }
        let mut paths = missing.into_iter().collect::<Vec<_>>();
        paths.sort_by(|left, right| {
            left.components()
                .count()
                .cmp(&right.components().count())
                .then_with(|| left.cmp(right))
        });
        Ok(paths
            .into_iter()
            .map(|path| PlannedDirectory { path, mode: 0o755 })
            .collect())
    }

    #[allow(
        clippy::too_many_lines,
        reason = "the durable directory protocol keeps intent, publish, proof, and sync order explicit"
    )]
    fn apply_directory(
        &self,
        transaction_name: &str,
        transaction: &Dir,
        plan: &JournalPlan,
        index: usize,
        planned: &PlannedDirectory,
        fault: Option<FaultPoint>,
    ) -> Result<(), CapabilityApplyError> {
        let path = normalize_path(&planned.path)?;
        let parent = self.open_parent(&path)?;
        if optional_directory_state(&parent.directory, &parent.leaf, &path)?.is_some() {
            return Err(recovery_conflict(
                &path,
                "absent planned live directory",
                None,
            ));
        }
        let temporary = live_artifact_name(transaction_name, index, "directory");
        if optional_directory_state(&parent.directory, OsStr::new(&temporary), &path)?.is_some() {
            return Err(recovery_conflict(
                &path,
                "absent unowned directory temporary",
                None,
            ));
        }

        let mut builder = DirBuilder::new();
        builder.mode(planned.mode & 0o777);
        if let Err(error) = parent.directory.create_dir_with(&temporary, &builder) {
            return Err(uncertain(
                &plan.change_set.change_set_id,
                Some(path),
                "create same-parent directory temporary",
                error,
            ));
        }
        let temporary_directory =
            parent
                .directory
                .open_dir_nofollow(&temporary)
                .map_err(|error| {
                    uncertain(
                        &plan.change_set.change_set_id,
                        Some(path.clone()),
                        "open created directory temporary",
                        error,
                    )
                })?;
        temporary_directory
            .set_permissions(Path::new("."), Permissions::from_mode(planned.mode & 0o777))
            .map_err(|error| {
                uncertain(
                    &plan.change_set.change_set_id,
                    Some(path.clone()),
                    "set created directory mode",
                    error,
                )
            })?;
        sync_directory(&temporary_directory).map_err(|error| {
            uncertain(
                &plan.change_set.change_set_id,
                Some(path.clone()),
                "sync created directory temporary",
                error,
            )
        })?;
        sync_directory(&parent.directory).map_err(|error| {
            uncertain(
                &plan.change_set.change_set_id,
                Some(path.clone()),
                "sync directory temporary parent",
                error,
            )
        })?;
        let temporary_state =
            optional_directory_state(&parent.directory, OsStr::new(&temporary), &path)?
                .ok_or_else(|| CapabilityApplyError::ReconciliationRequired {
                    change_set_id: plan.change_set.change_set_id.clone(),
                    path: Some(path.clone()),
                    operation: "capture directory temporary identity",
                    reason: "created temporary disappeared".into(),
                })?;
        if temporary_state.mode != planned.mode & 0o777 {
            return Err(CapabilityApplyError::ReconciliationRequired {
                change_set_id: plan.change_set.change_set_id.clone(),
                path: Some(path),
                operation: "capture directory temporary mode",
                reason: format!(
                    "expected {:04o}, found {:04o}",
                    planned.mode & 0o777,
                    temporary_state.mode
                ),
            });
        }
        write_intent_new(
            transaction,
            &directory_owned_name(index),
            temporary_state.object,
        )
        .map_err(|error| {
            uncertain(
                &plan.change_set.change_set_id,
                Some(path.clone()),
                "record created directory inode",
                error,
            )
        })?;

        self.validate_roots()?;
        self.verify_parent(&parent)?;
        require_named_absent(&parent.directory, &parent.leaf, &path)?;
        let before_rename =
            optional_directory_state(&parent.directory, OsStr::new(&temporary), &path)?;
        if before_rename != Some(temporary_state) {
            return Err(recovery_conflict(
                &path,
                "exact journal-owned directory temporary",
                None,
            ));
        }
        if let Err(error) = renameat_with(
            &parent.directory,
            Path::new(&temporary),
            &parent.directory,
            Path::new(&parent.leaf),
            RenameFlags::NOREPLACE,
        ) {
            return Err(uncertain(
                &plan.change_set.change_set_id,
                Some(path),
                "publish directory with no-replace rename",
                error,
            ));
        }
        maybe_fault(fault, FaultPoint::AfterDirectoryMutation(index), index + 1)?;
        finish_directory_effect(
            self,
            &parent,
            &path,
            planned.mode,
            temporary_state.object,
            &plan.change_set.change_set_id,
            "verify published directory",
        )?;
        write_marker_after_effect(
            transaction,
            &directory_created_marker_name(index),
            b"directory-created\n",
            &plan.change_set.change_set_id,
            &path,
            "record published directory",
        )
    }

    fn apply_operation(
        &self,
        transaction_name: &str,
        transaction: &Dir,
        plan: &JournalPlan,
        index: usize,
        planned: &PlanOperation,
        fault: Option<FaultPoint>,
    ) -> Result<(), CapabilityApplyError> {
        self.validate_roots()?;
        match &planned.operation {
            FileOperation::Create { path, result_hash } => {
                let result =
                    read_verified_blob(transaction, &result_blob_name(index), result_hash)?;
                self.apply_replacement(
                    transaction_name,
                    transaction,
                    &plan.change_set.change_set_id,
                    index,
                    path,
                    &result,
                    planned.mode,
                    None,
                    None,
                    fault,
                )?;
            }
            FileOperation::Modify {
                path,
                base_hash,
                result_hash,
            } => {
                let result =
                    read_verified_blob(transaction, &result_blob_name(index), result_hash)?;
                self.apply_replacement(
                    transaction_name,
                    transaction,
                    &plan.change_set.change_set_id,
                    index,
                    path,
                    &result,
                    planned.mode,
                    Some(base_hash),
                    planned.base_identity,
                    fault,
                )?;
            }
            FileOperation::Delete { path, base_hash } => self.apply_delete(
                transaction_name,
                transaction,
                &plan.change_set.change_set_id,
                index,
                path,
                base_hash,
                planned.mode,
                planned.base_identity.ok_or_else(|| {
                    CapabilityApplyError::Journal("delete lacks base identity".into())
                })?,
                fault,
            )?,
        }
        Ok(())
    }

    #[allow(
        clippy::too_many_arguments,
        reason = "transaction, identity, content, mode, and fault inputs are security-relevant"
    )]
    fn apply_replacement(
        &self,
        transaction_name: &str,
        transaction: &Dir,
        change_set_id: &str,
        index: usize,
        path: &Path,
        contents: &[u8],
        mode: u32,
        expected: Option<&Digest>,
        expected_identity: Option<ObjectIdentity>,
        fault: Option<FaultPoint>,
    ) -> Result<(), CapabilityApplyError> {
        let path = normalize_path(path)?;
        let parent = self.open_parent(&path)?;
        verify_target_precondition(&parent, &path, expected, expected_identity)?;
        let temp_name = live_artifact_name(transaction_name, index, "apply");
        if optional_artifact_identity(&parent.directory, &temp_name, &path)?.is_some() {
            return Err(CapabilityApplyError::RecoveryConflict {
                path,
                expected: "absent unowned apply temporary".into(),
                actual: None,
            });
        }
        let fingerprint = write_live_temp(&parent.directory, &temp_name, contents, mode, &path)?;
        write_intent_new(transaction, &apply_intent_name(index), fingerprint.object)?;
        maybe_fault(fault, FaultPoint::AfterApplyTempIntent(index), index + 1)?;
        self.validate_roots()?;
        self.verify_parent(&parent)?;
        verify_target_precondition(&parent, &path, expected, expected_identity)?;
        verify_owned_regular_artifact(
            &parent.directory,
            &temp_name,
            &path,
            fingerprint.object,
            &Digest::sha256(contents),
            mode,
        )?;
        #[cfg(test)]
        if expected.is_none() && fault == Some(FaultPoint::BeforeCreateNoReplacePublish(index)) {
            inject_no_replace_file_race(&parent.directory, &parent.leaf, &path)?;
        }
        let rename = if expected.is_none() {
            renameat_with(
                &parent.directory,
                Path::new(&temp_name),
                &parent.directory,
                Path::new(&parent.leaf),
                RenameFlags::NOREPLACE,
            )
            .map_err(io::Error::from)
        } else {
            parent
                .directory
                .rename(&temp_name, &parent.directory, &parent.leaf)
        };
        if let Err(error) = rename {
            return Err(uncertain(
                change_set_id,
                Some(path),
                "atomic apply rename",
                error,
            ));
        }
        maybe_fault(fault, FaultPoint::AfterMutation(index), index + 1)?;
        finish_live_effect(
            self,
            &parent,
            &path,
            &Digest::sha256(contents),
            mode,
            Some(fingerprint.object),
            change_set_id,
            "verify replacement",
        )?;
        write_marker_after_effect(
            transaction,
            &applied_marker_name(index),
            b"applied\n",
            change_set_id,
            &path,
            "record applied replacement",
        )
    }

    #[allow(
        clippy::too_many_arguments,
        clippy::too_many_lines,
        reason = "the durable delete sequence keeps each security-relevant proof adjacent to its effect"
    )]
    fn apply_delete(
        &self,
        transaction_name: &str,
        transaction: &Dir,
        change_set_id: &str,
        index: usize,
        path: &Path,
        expected: &Digest,
        expected_mode: u32,
        expected_identity: ObjectIdentity,
        fault: Option<FaultPoint>,
    ) -> Result<(), CapabilityApplyError> {
        let path = normalize_path(path)?;
        let parent = self.open_parent(&path)?;
        verify_target_precondition(&parent, &path, Some(expected), Some(expected_identity))?;
        let tombstone = live_artifact_name(transaction_name, index, "delete");
        if optional_artifact_identity(&parent.directory, &tombstone, &path)?.is_some() {
            return Err(CapabilityApplyError::RecoveryConflict {
                path,
                expected: "absent unowned delete tombstone".into(),
                actual: None,
            });
        }
        write_intent_new(transaction, &apply_intent_name(index), expected_identity)?;
        self.validate_roots()?;
        self.verify_parent(&parent)?;
        verify_target_precondition(&parent, &path, Some(expected), Some(expected_identity))?;
        if let Err(error) = parent
            .directory
            .rename(&parent.leaf, &parent.directory, &tombstone)
        {
            return Err(uncertain(
                change_set_id,
                Some(path),
                "atomic delete tombstone rename",
                error,
            ));
        }
        maybe_fault(fault, FaultPoint::AfterMutation(index), index + 1)?;
        if let Err(error) = sync_directory(&parent.directory) {
            return Err(uncertain(
                change_set_id,
                Some(path.clone()),
                "sync delete parent after rename",
                error,
            ));
        }
        let (tombstone_bytes, tombstone_fingerprint) = stable_read(
            &parent.directory,
            OsStr::new(&tombstone),
            &path,
            MAX_APPLY_FILE_BYTES,
        )
        .map_err(|error| {
            uncertain(
                change_set_id,
                Some(path.clone()),
                "verify delete tombstone",
                error,
            )
        })?;
        let tombstone_digest = Digest::sha256(&tombstone_bytes);
        if tombstone_fingerprint.object != expected_identity
            || tombstone_fingerprint.mode & 0o777 != expected_mode & 0o777
            || tombstone_digest != *expected
        {
            return Err(CapabilityApplyError::ReconciliationRequired {
                change_set_id: change_set_id.into(),
                path: Some(path.clone()),
                operation: "verify delete tombstone state",
                reason: "tombstone does not retain the authorized inode, mode, and base digest"
                    .into(),
            });
        }
        if let Err(error) = parent.directory.remove_file(&tombstone) {
            return Err(uncertain(
                change_set_id,
                Some(path.clone()),
                "unlink owned delete tombstone",
                error,
            ));
        }
        if let Err(error) = sync_directory(&parent.directory) {
            return Err(uncertain(
                change_set_id,
                Some(path.clone()),
                "sync delete parent after unlink",
                error,
            ));
        }
        let endpoint = require_named_absent(&parent.directory, &parent.leaf, &path)
            .and_then(|()| require_named_absent(&parent.directory, OsStr::new(&tombstone), &path));
        if let Err(error) = endpoint {
            return Err(CapabilityApplyError::ReconciliationRequired {
                change_set_id: change_set_id.into(),
                path: Some(path.clone()),
                operation: "verify delete endpoint",
                reason: error.to_string(),
            });
        }
        self.validate_roots()
            .map_err(|error| CapabilityApplyError::ReconciliationRequired {
                change_set_id: change_set_id.into(),
                path: Some(path.clone()),
                operation: "revalidate roots after delete",
                reason: error.to_string(),
            })?;
        self.verify_parent(&parent).map_err(|error| {
            CapabilityApplyError::ReconciliationRequired {
                change_set_id: change_set_id.into(),
                path: Some(path.clone()),
                operation: "revalidate parent after delete",
                reason: error.to_string(),
            }
        })?;
        write_marker_after_effect(
            transaction,
            &applied_marker_name(index),
            b"applied\n",
            change_set_id,
            &path,
            "record applied delete",
        )
    }
}

impl CapabilitySafeApplier {
    fn restore_plan(
        &self,
        transaction_name: &str,
        transaction: &Dir,
        plan: &JournalPlan,
    ) -> Result<(), CapabilityApplyError> {
        for (index, operation) in plan.operations.iter().enumerate().rev() {
            self.validate_roots()?;
            self.restore_operation(transaction_name, transaction, plan, index, operation)?;
            write_marker_after_effect(
                transaction,
                &restored_marker_name(index),
                b"restored\n",
                &plan.change_set.change_set_id,
                operation.operation.path(),
                "record restored operation",
            )?;
        }
        for (index, directory) in plan.directories.iter().enumerate().rev() {
            self.validate_roots()?;
            self.restore_directory(transaction_name, transaction, plan, index, directory)?;
            write_marker_after_effect(
                transaction,
                &directory_restored_marker_name(index),
                b"directory-restored\n",
                &plan.change_set.change_set_id,
                &directory.path,
                "record restored directory",
            )?;
        }
        verify_base_targets(self, plan)
    }

    #[allow(
        clippy::too_many_lines,
        reason = "directory rollback keeps every exact-inode, mode, emptiness, and durability proof explicit"
    )]
    fn restore_directory(
        &self,
        transaction_name: &str,
        transaction: &Dir,
        plan: &JournalPlan,
        index: usize,
        planned: &PlannedDirectory,
    ) -> Result<(), CapabilityApplyError> {
        let path = normalize_path(&planned.path)?;
        let intent = read_intent_optional(transaction, &directory_owned_name(index))?;
        let parent = match self.open_parent(&path) {
            Ok(parent) => parent,
            Err(CapabilityApplyError::MissingParent(_)) if intent.is_none() => return Ok(()),
            Err(CapabilityApplyError::MissingParent(_)) => {
                return Err(recovery_conflict(
                    &path,
                    "parent of journal-owned directory",
                    None,
                ));
            }
            Err(error) => return Err(error),
        };
        let temporary = live_artifact_name(transaction_name, index, "directory");
        let temporary_state =
            optional_directory_state(&parent.directory, OsStr::new(&temporary), &path)?;
        let target_state = optional_directory_state(&parent.directory, &parent.leaf, &path)?;
        let Some(intent) = intent else {
            return match (temporary_state, target_state) {
                (None, None) => Ok(()),
                _ => Err(recovery_conflict(
                    &path,
                    "absence without directory inode evidence",
                    None,
                )),
            };
        };
        let expected = DirectoryState {
            object: intent.identity,
            mode: planned.mode & 0o777,
        };
        let removal_name = match (temporary_state, target_state) {
            (None, None) => return Ok(()),
            (Some(state), None) if state == expected => temporary.as_str(),
            (None, Some(state)) if state == expected => {
                parent
                    .leaf
                    .to_str()
                    .ok_or_else(|| CapabilityApplyError::InvalidPath {
                        path: path.clone(),
                        reason: "directory leaf is not UTF-8".into(),
                    })?
            }
            _ => {
                return Err(recovery_conflict(
                    &path,
                    &format!(
                        "one journal-owned empty directory with mode {:04o}",
                        planned.mode & 0o777
                    ),
                    None,
                ));
            }
        };
        let opened = parent
            .directory
            .open_dir_nofollow(removal_name)
            .map_err(|error| io_error("open owned directory for rollback", &path, &error))?;
        let opened_metadata = opened
            .dir_metadata()
            .map_err(|error| io_error("inspect owned directory for rollback", &path, &error))?;
        if object_identity(&opened_metadata) != intent.identity
            || OsMetadataExt::mode(&opened_metadata) & 0o777 != planned.mode & 0o777
        {
            return Err(recovery_conflict(
                &path,
                "exact directory inode and mode before rollback",
                None,
            ));
        }
        if !directory_is_empty(&opened, &path)? {
            return Err(recovery_conflict(
                &path,
                "empty journal-owned directory",
                None,
            ));
        }
        self.validate_roots()?;
        self.verify_parent(&parent)?;
        let revalidated =
            optional_directory_state(&parent.directory, OsStr::new(removal_name), &path)?;
        if revalidated != Some(expected) {
            return Err(recovery_conflict(
                &path,
                "revalidated journal-owned empty directory",
                None,
            ));
        }
        if let Err(error) = parent.directory.remove_dir(removal_name) {
            return Err(uncertain(
                &plan.change_set.change_set_id,
                Some(path.clone()),
                "remove journal-owned empty directory",
                error,
            ));
        }
        finish_directory_absence_effect(
            self,
            &parent,
            &path,
            OsStr::new(removal_name),
            &plan.change_set.change_set_id,
            "verify directory rollback",
        )
    }

    #[allow(
        clippy::too_many_lines,
        reason = "the operation variants intentionally expose complete recovery state machines"
    )]
    fn restore_operation(
        &self,
        transaction_name: &str,
        transaction: &Dir,
        plan: &JournalPlan,
        index: usize,
        planned: &PlanOperation,
    ) -> Result<(), CapabilityApplyError> {
        let path = normalize_path(planned.operation.path())?;
        let apply_intent = read_intent_optional(transaction, &apply_intent_name(index))?;
        let parent = match self.open_parent(&path) {
            Ok(parent) => parent,
            Err(CapabilityApplyError::MissingParent(_))
                if matches!(&planned.operation, FileOperation::Create { .. })
                    && apply_intent.is_none() =>
            {
                return Ok(());
            }
            Err(CapabilityApplyError::MissingParent(_)) => {
                return Err(recovery_conflict(
                    &path,
                    "parent containing journal-owned file state",
                    None,
                ));
            }
            Err(error) => return Err(error),
        };
        match &planned.operation {
            FileOperation::Create { result_hash, .. } => {
                Self::cleanup_owned_artifact(
                    transaction_name,
                    &parent,
                    &path,
                    index,
                    "apply",
                    apply_intent,
                    result_hash,
                    planned.mode,
                    &plan.change_set.change_set_id,
                )?;
                match optional_state(&parent, &path)? {
                    None => Ok(()),
                    Some(state)
                        if state.digest == *result_hash
                            && state.mode & 0o777 == planned.mode & 0o777
                            && apply_intent.is_some_and(|intent| {
                                intent.identity == state.fingerprint.object
                            }) =>
                    {
                        ensure_intent(
                            transaction,
                            &rollback_intent_name(index),
                            state.fingerprint.object,
                        )?;
                        self.validate_roots()?;
                        self.verify_parent(&parent)?;
                        let current = optional_state(&parent, &path)?;
                        if !current.as_ref().is_some_and(|current| {
                            current.fingerprint.object == state.fingerprint.object
                                && current.digest == *result_hash
                                && current.mode & 0o777 == planned.mode & 0o777
                        }) {
                            return Err(recovery_conflict(
                                &path,
                                "journal-owned created inode, result digest, and mode",
                                current.map(|state| state.digest),
                            ));
                        }
                        if let Err(error) = parent.directory.remove_file(&parent.leaf) {
                            return Err(uncertain(
                                &plan.change_set.change_set_id,
                                Some(path.clone()),
                                "unlink created file during rollback",
                                error,
                            ));
                        }
                        finish_absence_effect(
                            self,
                            &parent,
                            &path,
                            &plan.change_set.change_set_id,
                            "verify created-file rollback",
                        )
                    }
                    Some(state) => Err(recovery_conflict(
                        &path,
                        &format!("absent or owned result {result_hash}"),
                        Some(state.digest),
                    )),
                }
            }
            FileOperation::Modify {
                base_hash,
                result_hash,
                ..
            } => {
                Self::cleanup_owned_artifact(
                    transaction_name,
                    &parent,
                    &path,
                    index,
                    "apply",
                    apply_intent,
                    result_hash,
                    planned.mode,
                    &plan.change_set.change_set_id,
                )?;
                match optional_state(&parent, &path)? {
                    Some(state)
                        if state.digest == *base_hash
                            && state.mode & 0o777 == planned.mode & 0o777 =>
                    {
                        Ok(())
                    }
                    Some(state)
                        if state.digest == *result_hash
                            && state.mode & 0o777 == planned.mode & 0o777
                            && apply_intent.is_some_and(|intent| {
                                intent.identity == state.fingerprint.object
                            }) =>
                    {
                        let backup =
                            read_verified_blob(transaction, &base_blob_name(index), base_hash)?;
                        self.restore_file(
                            transaction_name,
                            transaction,
                            &plan.change_set.change_set_id,
                            index,
                            &parent,
                            &path,
                            &backup,
                            planned.mode,
                            Some(result_hash),
                            apply_intent.map(|intent| intent.identity),
                        )
                    }
                    state => Err(recovery_conflict(
                        &path,
                        &format!("base {base_hash} or result {result_hash}"),
                        state.map(|state| state.digest),
                    )),
                }
            }
            FileOperation::Delete { base_hash, .. } => {
                let tombstone = live_artifact_name(transaction_name, index, "delete");
                if let Some(intent) = apply_intent {
                    if let Some(tombstone_identity) =
                        optional_artifact_identity(&parent.directory, &tombstone, &path)?
                    {
                        if tombstone_identity != intent.identity {
                            return Err(recovery_conflict(
                                &path,
                                "journal-owned delete tombstone",
                                None,
                            ));
                        }
                        let (tombstone_bytes, tombstone_fingerprint) = stable_read(
                            &parent.directory,
                            OsStr::new(&tombstone),
                            &path,
                            MAX_APPLY_FILE_BYTES,
                        )?;
                        if Digest::sha256(&tombstone_bytes) != *base_hash
                            || tombstone_fingerprint.object != intent.identity
                            || tombstone_fingerprint.mode & 0o777 != planned.mode & 0o777
                        {
                            return Err(recovery_conflict(
                                &path,
                                &format!(
                                    "journal-owned base {base_hash} with mode {:04o}",
                                    planned.mode & 0o777
                                ),
                                Some(Digest::sha256(&tombstone_bytes)),
                            ));
                        }
                        if optional_state(&parent, &path)?.is_some() {
                            return Err(recovery_conflict(
                                &path,
                                "exactly one target or delete tombstone",
                                optional_state(&parent, &path)?.map(|state| state.digest),
                            ));
                        }
                        self.validate_roots()?;
                        self.verify_parent(&parent)?;
                        if let Err(error) =
                            parent
                                .directory
                                .rename(&tombstone, &parent.directory, &parent.leaf)
                        {
                            return Err(uncertain(
                                &plan.change_set.change_set_id,
                                Some(path.clone()),
                                "restore delete tombstone",
                                error,
                            ));
                        }
                        finish_live_effect(
                            self,
                            &parent,
                            &path,
                            base_hash,
                            planned.mode,
                            Some(intent.identity),
                            &plan.change_set.change_set_id,
                            "verify tombstone restoration",
                        )?;
                    }
                } else if optional_artifact_identity(&parent.directory, &tombstone, &path)?
                    .is_some()
                {
                    return Err(recovery_conflict(
                        &path,
                        "no unowned delete tombstone",
                        None,
                    ));
                }
                match optional_state(&parent, &path)? {
                    Some(state)
                        if state.digest == *base_hash
                            && state.mode & 0o777 == planned.mode & 0o777 =>
                    {
                        Ok(())
                    }
                    None => {
                        let backup =
                            read_verified_blob(transaction, &base_blob_name(index), base_hash)?;
                        self.restore_file(
                            transaction_name,
                            transaction,
                            &plan.change_set.change_set_id,
                            index,
                            &parent,
                            &path,
                            &backup,
                            planned.mode,
                            None,
                            None,
                        )
                    }
                    Some(state) => Err(recovery_conflict(
                        &path,
                        &format!("base {base_hash} or absence"),
                        Some(state.digest),
                    )),
                }
            }
        }
    }

    #[allow(
        clippy::too_many_arguments,
        reason = "transaction, parent, content, mode, and expected state are security-relevant"
    )]
    fn restore_file(
        &self,
        transaction_name: &str,
        transaction: &Dir,
        change_set_id: &str,
        index: usize,
        parent: &ParentHandle,
        path: &Path,
        contents: &[u8],
        mode: u32,
        expected_current: Option<&Digest>,
        expected_current_identity: Option<ObjectIdentity>,
    ) -> Result<(), CapabilityApplyError> {
        let temp_name = live_artifact_name(transaction_name, index, "rollback");
        let intent_name = rollback_intent_name(index);
        let intent = read_intent_optional(transaction, &intent_name)?;
        let temp_identity = optional_artifact_identity(&parent.directory, &temp_name, path)?;
        let expected_identity = match (intent, temp_identity) {
            (Some(intent), Some(identity)) if intent.identity == identity => {
                verify_owned_regular_artifact(
                    &parent.directory,
                    &temp_name,
                    path,
                    identity,
                    &Digest::sha256(contents),
                    mode,
                )?;
                identity
            }
            (Some(_), Some(_)) => {
                return Err(recovery_conflict(
                    path,
                    "journal-owned rollback temporary",
                    None,
                ));
            }
            (Some(intent), None) => {
                if optional_state(parent, path)?.as_ref().is_some_and(|state| {
                    state.digest == Digest::sha256(contents)
                        && state.mode & 0o777 == mode & 0o777
                        && state.fingerprint.object == intent.identity
                }) {
                    return Ok(());
                }
                return Err(recovery_conflict(
                    path,
                    "rollback temporary or restored base",
                    optional_state(parent, path)?.map(|state| state.digest),
                ));
            }
            (None, Some(_)) => {
                return Err(recovery_conflict(
                    path,
                    "absent unowned rollback temporary",
                    None,
                ));
            }
            (None, None) => {
                let fingerprint =
                    write_live_temp(&parent.directory, &temp_name, contents, mode, path)?;
                write_intent_new(transaction, &intent_name, fingerprint.object)?;
                fingerprint.object
            }
        };
        self.validate_roots()?;
        self.verify_parent(parent)?;
        verify_target_precondition(parent, path, expected_current, expected_current_identity)?;
        verify_owned_regular_artifact(
            &parent.directory,
            &temp_name,
            path,
            expected_identity,
            &Digest::sha256(contents),
            mode,
        )?;
        let rename = if expected_current.is_none() {
            renameat_with(
                &parent.directory,
                Path::new(&temp_name),
                &parent.directory,
                Path::new(&parent.leaf),
                RenameFlags::NOREPLACE,
            )
            .map_err(io::Error::from)
        } else {
            parent
                .directory
                .rename(&temp_name, &parent.directory, &parent.leaf)
        };
        if let Err(error) = rename {
            return Err(uncertain(
                change_set_id,
                Some(path.to_path_buf()),
                "atomic rollback rename",
                error,
            ));
        }
        finish_live_effect(
            self,
            parent,
            path,
            &Digest::sha256(contents),
            mode,
            Some(expected_identity),
            change_set_id,
            "verify rollback replacement",
        )
    }

    #[allow(
        clippy::too_many_arguments,
        reason = "artifact ownership and transaction identity are security-relevant"
    )]
    fn cleanup_owned_artifact(
        transaction_name: &str,
        parent: &ParentHandle,
        path: &Path,
        index: usize,
        role: &str,
        intent: Option<MutationIntent>,
        expected_digest: &Digest,
        expected_mode: u32,
        change_set_id: &str,
    ) -> Result<(), CapabilityApplyError> {
        let name = live_artifact_name(transaction_name, index, role);
        let identity = optional_artifact_identity(&parent.directory, &name, path)?;
        match (intent, identity) {
            (None | Some(_), None) => Ok(()),
            (None, Some(_)) => Err(recovery_conflict(
                path,
                "absent unowned live temporary",
                None,
            )),
            (Some(intent), Some(identity)) if intent.identity == identity => {
                verify_owned_regular_artifact(
                    &parent.directory,
                    &name,
                    path,
                    identity,
                    expected_digest,
                    expected_mode,
                )?;
                if let Err(error) =
                    remove_owned_regular_file(&parent.directory, &name, identity, path)
                {
                    return Err(uncertain(
                        change_set_id,
                        Some(path.to_path_buf()),
                        "remove journal-owned temporary",
                        error,
                    ));
                }
                if let Err(error) = sync_directory(&parent.directory) {
                    return Err(uncertain(
                        change_set_id,
                        Some(path.to_path_buf()),
                        "sync removed temporary",
                        error,
                    ));
                }
                Ok(())
            }
            (Some(_), Some(_)) => Err(recovery_conflict(
                path,
                "journal-owned live temporary",
                None,
            )),
        }
    }

    fn capture_snapshot(&self) -> Result<Digest, CapabilityApplyError> {
        self.validate_roots()?;
        let entries = capture_descriptor_entries(&self.root)?;
        self.validate_roots()?;
        snapshot_digest(&entries)
    }
}

#[derive(Clone, Debug)]
struct FileState {
    digest: Digest,
    mode: u32,
    fingerprint: FileFingerprint,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct DirectoryState {
    object: ObjectIdentity,
    mode: u32,
}

fn verify_result_targets(
    applier: &CapabilitySafeApplier,
    plan: &JournalPlan,
) -> Result<(), CapabilityApplyError> {
    applier.validate_roots()?;
    for planned in &plan.operations {
        let path = normalize_path(planned.operation.path())?;
        let parent = applier.open_parent(&path)?;
        match &planned.operation {
            FileOperation::Create { result_hash, .. }
            | FileOperation::Modify { result_hash, .. } => {
                let state = optional_state(&parent, &path)?;
                if !state.as_ref().is_some_and(|state| {
                    state.digest == *result_hash && state.mode & 0o777 == planned.mode & 0o777
                }) {
                    return Err(recovery_conflict(
                        &path,
                        &format!("committed result {result_hash}"),
                        state.map(|state| state.digest),
                    ));
                }
            }
            FileOperation::Delete { .. } => {
                if let Some(state) = optional_state(&parent, &path)? {
                    return Err(recovery_conflict(
                        &path,
                        "committed absence",
                        Some(state.digest),
                    ));
                }
            }
        }
    }
    Ok(())
}

fn verify_base_targets(
    applier: &CapabilitySafeApplier,
    plan: &JournalPlan,
) -> Result<(), CapabilityApplyError> {
    applier.validate_roots()?;
    for planned in &plan.operations {
        let path = normalize_path(planned.operation.path())?;
        match &planned.operation {
            FileOperation::Create { .. } => {
                let parent = match applier.open_parent(&path) {
                    Ok(parent) => parent,
                    Err(CapabilityApplyError::MissingParent(_)) => continue,
                    Err(error) => return Err(error),
                };
                if let Some(state) = optional_state(&parent, &path)? {
                    return Err(recovery_conflict(
                        &path,
                        "restored absence",
                        Some(state.digest),
                    ));
                }
            }
            FileOperation::Modify { base_hash, .. } | FileOperation::Delete { base_hash, .. } => {
                let parent = applier.open_parent(&path)?;
                let state = optional_state(&parent, &path)?;
                if !state.as_ref().is_some_and(|state| {
                    state.digest == *base_hash && state.mode & 0o777 == planned.mode & 0o777
                }) {
                    return Err(recovery_conflict(
                        &path,
                        &format!("restored base {base_hash}"),
                        state.map(|state| state.digest),
                    ));
                }
            }
        }
    }
    Ok(())
}

fn rollback_outcome(
    applier: &CapabilitySafeApplier,
    transaction_id: &str,
    plan: &JournalPlan,
) -> Result<CapabilityRollbackOutcome, CapabilityApplyError> {
    verify_base_targets(applier, plan)?;
    let live_manifest_digest = applier.capture_snapshot()?;
    verify_base_targets(applier, plan)?;
    Ok(CapabilityRollbackOutcome {
        transaction_id: transaction_id.to_owned(),
        change_set_id: plan.change_set.change_set_id.clone(),
        base_snapshot: plan.change_set.base_snapshot.clone(),
        restored_paths: plan
            .operations
            .iter()
            .map(|operation| operation.operation.path().to_path_buf())
            .collect(),
        live_manifest_digest,
        restored_base_endpoints_digest: plan
            .change_set
            .restored_base_endpoints_digest()
            .map_err(|error| CapabilityApplyError::Blob(error.to_string()))?,
        touched_target_set_digest: plan
            .change_set
            .touched_target_set_digest()
            .map_err(|error| CapabilityApplyError::Blob(error.to_string()))?,
    })
}

fn validate_bundle_plan(
    bundle: &StageBundleReference,
    plan: &JournalPlan,
) -> Result<(), CapabilityApplyError> {
    plan.change_set
        .validate()
        .map_err(|error| CapabilityApplyError::Blob(error.to_string()))?;
    if bundle.change_set_id != plan.change_set.change_set_id
        || bundle.base_snapshot != plan.change_set.base_snapshot
        || bundle.result_snapshot != plan.change_set.result_snapshot
    {
        return Err(CapabilityApplyError::Journal(
            "stage bundle differs from the exact journaled change set".into(),
        ));
    }
    Ok(())
}

fn rollback_target_contract(
    plan: &JournalPlan,
) -> Result<Vec<CapabilityRollbackTargetContract>, CapabilityApplyError> {
    if plan.operations.is_empty() || plan.operations.len() > MAX_ROLLBACK_EVIDENCE_TARGETS {
        return Err(CapabilityApplyError::Journal(format!(
            "rollback target count must be within 1..={MAX_ROLLBACK_EVIDENCE_TARGETS}"
        )));
    }
    plan.operations
        .iter()
        .map(|planned| {
            let path = normalize_path(planned.operation.path())?;
            if portable_path(&path)?.len() > MAX_ROLLBACK_EVIDENCE_PATH_BYTES {
                return Err(CapabilityApplyError::InvalidPath {
                    path,
                    reason: "rollback evidence path exceeds 4096 UTF-8 bytes".into(),
                });
            }
            let (application, restored_base) = match &planned.operation {
                FileOperation::Create { result_hash, .. } => (
                    CapabilityRollbackExpectedEndpoint::Regular {
                        digest: result_hash.clone(),
                        mode: planned.mode & 0o777,
                    },
                    CapabilityRollbackExpectedEndpoint::Absent,
                ),
                FileOperation::Modify {
                    base_hash,
                    result_hash,
                    ..
                } => (
                    CapabilityRollbackExpectedEndpoint::Regular {
                        digest: result_hash.clone(),
                        mode: planned.mode & 0o777,
                    },
                    CapabilityRollbackExpectedEndpoint::Regular {
                        digest: base_hash.clone(),
                        mode: planned.mode & 0o777,
                    },
                ),
                FileOperation::Delete { base_hash, .. } => (
                    CapabilityRollbackExpectedEndpoint::Absent,
                    CapabilityRollbackExpectedEndpoint::Regular {
                        digest: base_hash.clone(),
                        mode: planned.mode & 0o777,
                    },
                ),
            };
            Ok(CapabilityRollbackTargetContract {
                path,
                application,
                restored_base,
            })
        })
        .collect()
}

fn capture_rollback_observations(
    applier: &CapabilitySafeApplier,
    targets: &[CapabilityRollbackTargetContract],
) -> Result<Vec<CapabilityRollbackPathObservation>, CapabilityApplyError> {
    applier.validate_roots()?;
    let observations = targets
        .iter()
        .map(|target| {
            let endpoint = match applier.open_parent(&target.path) {
                Ok(parent) => optional_state(&parent, &target.path)?.map_or(
                    CapabilityRollbackObservedEndpoint::Absent,
                    |state| CapabilityRollbackObservedEndpoint::Regular {
                        digest: state.digest,
                        length: state.fingerprint.length,
                        mode: state.mode & 0o777,
                    },
                ),
                Err(CapabilityApplyError::MissingParent(_)) => {
                    CapabilityRollbackObservedEndpoint::Absent
                }
                Err(error) => return Err(error),
            };
            Ok(CapabilityRollbackPathObservation {
                path: target.path.clone(),
                endpoint,
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    applier.validate_roots()?;
    Ok(observations)
}

fn rollback_conflicts(
    targets: &[CapabilityRollbackTargetContract],
    observations: &[CapabilityRollbackPathObservation],
) -> Result<Vec<CapabilityRollbackPathConflict>, CapabilityApplyError> {
    if targets.len() != observations.len() {
        return Err(CapabilityApplyError::Journal(
            "rollback target and observation counts differ".into(),
        ));
    }
    let mut conflicts = Vec::new();
    for (target, observation) in targets.iter().zip(observations) {
        if target.path != observation.path {
            return Err(CapabilityApplyError::Journal(
                "rollback target and observation path order differs".into(),
            ));
        }
        if observation.endpoint.matches_expected(&target.application) {
            continue;
        }
        let expected_endpoint_digest = target.application.endpoint_digest();
        let observed_endpoint_digest = observation.endpoint.endpoint_digest();
        if expected_endpoint_digest == observed_endpoint_digest {
            return Err(CapabilityApplyError::Root(format!(
                "rollback target {} retained content but changed mode",
                target.path.display()
            )));
        }
        conflicts.push(CapabilityRollbackPathConflict {
            path: target.path.clone(),
            expected_endpoint_digest,
            observed_endpoint_digest,
        });
    }
    Ok(conflicts)
}

fn require_restored_targets(
    targets: &[CapabilityRollbackTargetContract],
    observations: &[CapabilityRollbackPathObservation],
) -> Result<(), CapabilityApplyError> {
    if targets.len() != observations.len()
        || targets
            .iter()
            .zip(observations)
            .any(|(target, observation)| {
                target.path != observation.path
                    || !observation.endpoint.matches_expected(&target.restored_base)
            })
    {
        return Err(CapabilityApplyError::Root(
            "post-rollback target observations differ from exact restored base endpoints".into(),
        ));
    }
    Ok(())
}

#[derive(Serialize)]
struct ExpectedApplicationEndpointDigestEntry<'a> {
    path: &'a Path,
    endpoint: &'a CapabilityRollbackExpectedEndpoint,
}

fn expected_application_endpoints_digest(
    targets: &[CapabilityRollbackTargetContract],
) -> Result<Digest, CapabilityApplyError> {
    let entries = targets
        .iter()
        .map(|target| ExpectedApplicationEndpointDigestEntry {
            path: &target.path,
            endpoint: &target.application,
        })
        .collect::<Vec<_>>();
    digest_rollback_evidence(EXPECTED_ENDPOINTS_DOMAIN, &entries)
}

#[derive(Serialize)]
struct RollbackTargetContractDigestEntry<'a> {
    path: String,
    application: &'a CapabilityRollbackExpectedEndpoint,
    restored_base: &'a CapabilityRollbackExpectedEndpoint,
}

fn rollback_target_contract_digest(
    targets: &[CapabilityRollbackTargetContract],
) -> Result<Digest, CapabilityApplyError> {
    let entries = targets
        .iter()
        .map(|target| {
            Ok(RollbackTargetContractDigestEntry {
                path: portable_path(&target.path)?,
                application: &target.application,
                restored_base: &target.restored_base,
            })
        })
        .collect::<Result<Vec<_>, CapabilityApplyError>>()?;
    digest_rollback_evidence(TARGET_CONTRACT_DOMAIN, &entries)
}

fn observed_endpoints_digest(
    observations: &[CapabilityRollbackPathObservation],
) -> Result<Digest, CapabilityApplyError> {
    digest_rollback_evidence(OBSERVED_ENDPOINTS_DOMAIN, observations)
}

fn digest_rollback_evidence(
    domain: &[u8],
    value: &(impl Serialize + ?Sized),
) -> Result<Digest, CapabilityApplyError> {
    let encoded = serde_json::to_vec(value)
        .map_err(|error| CapabilityApplyError::Journal(error.to_string()))?;
    let mut preimage = Vec::with_capacity(domain.len() + encoded.len());
    preimage.extend_from_slice(domain);
    preimage.extend_from_slice(&encoded);
    Ok(Digest::sha256(&preimage))
}

fn write_rollback_precondition(
    transaction: &Dir,
    record: &PersistedRollbackPrecondition,
) -> Result<(), CapabilityApplyError> {
    let encoded = serde_json::to_vec(record)
        .map_err(|error| CapabilityApplyError::Journal(error.to_string()))?;
    if encoded.is_empty()
        || u64::try_from(encoded.len()).expect("usize fits u64") > MAX_ROLLBACK_PRECONDITION_BYTES
    {
        return Err(CapabilityApplyError::Journal(
            "rollback precondition record exceeds its hard bound".into(),
        ));
    }
    write_new_journal_file(transaction, ROLLBACK_PRECONDITION_NAME, &encoded)
}

fn read_rollback_precondition(
    transaction: &Dir,
) -> Result<Option<PersistedRollbackPrecondition>, CapabilityApplyError> {
    match transaction.symlink_metadata(ROLLBACK_PRECONDITION_NAME) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(io_error(
            "inspect rollback precondition record",
            Path::new(ROLLBACK_PRECONDITION_NAME),
            &error,
        )),
        Ok(_) => {
            let bytes = read_journal_file(
                transaction,
                ROLLBACK_PRECONDITION_NAME,
                MAX_ROLLBACK_PRECONDITION_BYTES,
            )?;
            let record: PersistedRollbackPrecondition = serde_json::from_slice(&bytes)
                .map_err(|error| CapabilityApplyError::Journal(error.to_string()))?;
            let canonical = serde_json::to_vec(&record)
                .map_err(|error| CapabilityApplyError::Journal(error.to_string()))?;
            if canonical != bytes {
                return Err(CapabilityApplyError::Journal(
                    "rollback precondition record is not canonical".into(),
                ));
            }
            Ok(Some(record))
        }
    }
}

fn validate_retained_precondition(
    retained: &PersistedRollbackPrecondition,
    bundle: &StageBundleReference,
    rollback: &CapabilityRollbackArtifactReference,
    target_contract: &[CapabilityRollbackTargetContract],
    expected_application_digest: &Digest,
    touched_target_set_digest: &Digest,
) -> Result<(), CapabilityApplyError> {
    let observations_digest = observed_endpoints_digest(&retained.observations)?;
    if retained.version != ROLLBACK_PRECONDITION_VERSION
        || &retained.bundle != bundle
        || retained.transaction_id != rollback.transaction_id()
        || retained.change_set_id != rollback.change_set_id()
        || &retained.rollback_artifacts_digest != rollback.artifacts_digest()
        || retained.target_contract != target_contract
        || &retained.expected_application_endpoints_digest != expected_application_digest
        || &retained.touched_target_set_digest != touched_target_set_digest
        || retained.observations_digest != observations_digest
        || retained.captured_at_unix_ms == 0
        || !rollback_conflicts(target_contract, &retained.observations)?.is_empty()
    {
        return Err(CapabilityApplyError::Journal(
            "retained rollback precondition differs from its exact transaction contract".into(),
        ));
    }
    Ok(())
}

fn rollback_success_evidence(
    applier: &CapabilitySafeApplier,
    plan: &JournalPlan,
    bundle: &StageBundleReference,
    rollback: &CapabilityRollbackArtifactReference,
    retained: &PersistedRollbackPrecondition,
) -> Result<CapabilityRollbackSuccessEvidence, CapabilityApplyError> {
    let target_contract = rollback_target_contract(plan)?;
    validate_retained_precondition(
        retained,
        bundle,
        rollback,
        &target_contract,
        &retained.expected_application_endpoints_digest,
        &retained.touched_target_set_digest,
    )?;
    let first = capture_rollback_observations(applier, &target_contract)?;
    require_restored_targets(&target_contract, &first)?;
    let final_live_manifest_digest = applier.capture_snapshot()?;
    let final_live_manifest_observed_at_unix_ms = rollback_observed_at_unix_ms()?;
    let second = capture_rollback_observations(applier, &target_contract)?;
    if first != second {
        return Err(CapabilityApplyError::Root(
            "restored rollback targets changed across final manifest capture".into(),
        ));
    }
    require_restored_targets(&target_contract, &second)?;
    let post_restore_observations_digest = observed_endpoints_digest(&second)?;
    Ok(CapabilityRollbackSuccessEvidence {
        bundle: bundle.clone(),
        rollback: rollback.clone(),
        target_contract,
        expected_application_endpoints_digest: retained
            .expected_application_endpoints_digest
            .clone(),
        restored_base_endpoints_digest: plan
            .change_set
            .restored_base_endpoints_digest()
            .map_err(|error| CapabilityApplyError::Blob(error.to_string()))?,
        touched_target_set_digest: retained.touched_target_set_digest.clone(),
        pre_effect_observations: retained.observations.clone(),
        pre_effect_observations_digest: retained.observations_digest.clone(),
        effect_started_at_unix_ms: retained.captured_at_unix_ms,
        post_restore_observations: second,
        post_restore_observations_digest,
        final_live_manifest_digest,
        final_live_manifest_observed_at_unix_ms,
    })
}

fn rollback_observed_at_unix_ms() -> Result<u64, CapabilityApplyError> {
    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| {
            CapabilityApplyError::Journal(format!("system clock rejected: {error}"))
        })?;
    u64::try_from(duration.as_millis())
        .ok()
        .filter(|timestamp| *timestamp > 0)
        .ok_or_else(|| CapabilityApplyError::Journal("rollback timestamp is invalid".into()))
}

fn reconciliation_required(
    change_set_id: &str,
    operation: &'static str,
    error: CapabilityApplyError,
) -> CapabilityApplyError {
    match error {
        CapabilityApplyError::ReconciliationRequired { .. }
        | CapabilityApplyError::InjectedCrash { .. } => error,
        other => CapabilityApplyError::ReconciliationRequired {
            change_set_id: change_set_id.to_owned(),
            path: None,
            operation,
            reason: other.to_string(),
        },
    }
}

fn rollback_artifact_reference(
    transaction_id: &str,
    transaction: &Dir,
    plan: &JournalPlan,
) -> Result<CapabilityRollbackArtifactReference, CapabilityApplyError> {
    let transaction_identity = validate_private_root(transaction, "rollback transaction")?;
    let base_blob_count = plan
        .operations
        .iter()
        .filter(|planned| !matches!(planned.operation, FileOperation::Create { .. }))
        .count();
    let artifact_count = base_blob_count
        .checked_add(1)
        .ok_or_else(|| CapabilityApplyError::Journal("rollback artifact count overflow".into()))?;
    if artifact_count > MAX_ROLLBACK_ARTIFACT_ENTRIES {
        return Err(CapabilityApplyError::Journal(format!(
            "rollback artifact count {artifact_count} exceeds {MAX_ROLLBACK_ARTIFACT_ENTRIES}"
        )));
    }

    let mut artifacts = Vec::with_capacity(artifact_count);
    artifacts.push(capture_rollback_artifact(
        transaction,
        "plan",
        MAX_PLAN_BYTES,
        CapabilityRollbackArtifactKind::Plan,
    )?);
    for (index, planned) in plan.operations.iter().enumerate() {
        let expected = match &planned.operation {
            FileOperation::Create { .. } => continue,
            FileOperation::Modify { base_hash, .. } | FileOperation::Delete { base_hash, .. } => {
                base_hash
            }
        };
        let operation_index = u32::try_from(index).map_err(|_| {
            CapabilityApplyError::Journal("rollback operation index exceeds u32".into())
        })?;
        let artifact = capture_rollback_artifact(
            transaction,
            &base_blob_name(index),
            MAX_APPLY_FILE_BYTES,
            CapabilityRollbackArtifactKind::BaseBlob { operation_index },
        )?;
        if artifact.digest != *expected {
            return Err(CapabilityApplyError::Blob(format!(
                "rollback base blob {} differs from plan digest {expected}",
                artifact.name
            )));
        }
        artifacts.push(artifact);
    }
    let touched_target_set_digest = plan
        .change_set
        .touched_target_set_digest()
        .map_err(|error| CapabilityApplyError::Journal(error.to_string()))?;
    let target_contract_digest = rollback_target_contract_digest(&rollback_target_contract(plan)?)?;
    let mut reference = CapabilityRollbackArtifactReference {
        transaction_id: transaction_id.to_owned(),
        change_set_id: plan.change_set.change_set_id.clone(),
        base_snapshot: plan.change_set.base_snapshot.clone(),
        touched_target_set_digest,
        target_contract_digest,
        transaction_device: transaction_identity.object.device,
        transaction_inode: transaction_identity.object.inode,
        transaction_mode: transaction_identity.mode,
        transaction_owner_uid: transaction_identity.uid,
        artifacts_digest: Digest::sha256(b"uninitialized"),
        reopened_artifacts_bytes: Vec::new(),
        artifacts,
    };
    reference.reopened_artifacts_bytes = encode_rollback_artifact_reference(&reference);
    if reference.reopened_artifacts_bytes.len() > MAX_ROLLBACK_REFERENCE_BYTES {
        return Err(CapabilityApplyError::Journal(format!(
            "rollback artifact evidence exceeds {MAX_ROLLBACK_REFERENCE_BYTES} bytes"
        )));
    }
    reference.artifacts_digest = Digest::sha256(&reference.reopened_artifacts_bytes);
    Ok(reference)
}

fn capture_rollback_artifact(
    transaction: &Dir,
    name: &str,
    limit: u64,
    kind: CapabilityRollbackArtifactKind,
) -> Result<CapabilityRollbackArtifact, CapabilityApplyError> {
    let named_before = transaction
        .symlink_metadata(name)
        .map_err(|error| io_error("inspect rollback artifact", Path::new(name), &error))?;
    validate_private_file_metadata(Path::new(name), &named_before)?;
    if named_before.len() > limit {
        return Err(CapabilityApplyError::Journal(format!(
            "rollback artifact {name:?} exceeds {limit} bytes"
        )));
    }
    let expected_identity = object_identity(&named_before);
    let (digest, length, fingerprint) =
        stable_digest(transaction, OsStr::new(name), Path::new(name))?;
    if fingerprint.object != expected_identity
        || fingerprint.links != 1
        || fingerprint.mode & 0o777 != 0o600
        || length != named_before.len()
    {
        return Err(CapabilityApplyError::Journal(format!(
            "rollback artifact {name:?} identity or private metadata changed"
        )));
    }
    let named_after = transaction
        .symlink_metadata(name)
        .map_err(|error| io_error("revalidate rollback artifact", Path::new(name), &error))?;
    validate_private_file_metadata(Path::new(name), &named_after)?;
    if object_identity(&named_after) != expected_identity || named_after.len() != length {
        return Err(CapabilityApplyError::Journal(format!(
            "rollback artifact {name:?} changed after hashing"
        )));
    }
    Ok(CapabilityRollbackArtifact {
        kind,
        name: name.to_owned(),
        length,
        mode: fingerprint.mode & 0o777,
        digest,
        device: fingerprint.object.device,
        inode: fingerprint.object.inode,
        owner_uid: OsMetadataExt::uid(&named_after),
        modified_seconds: fingerprint.modified_seconds,
        modified_nanoseconds: fingerprint.modified_nanoseconds,
        changed_seconds: fingerprint.changed_seconds,
        changed_nanoseconds: fingerprint.changed_nanoseconds,
    })
}

fn encode_rollback_artifact_reference(reference: &CapabilityRollbackArtifactReference) -> Vec<u8> {
    use std::fmt::Write as _;

    let mut encoded = String::new();
    encoded.push_str(ROLLBACK_ARTIFACT_VERSION);
    encoded.push('\n');
    let _ = writeln!(
        encoded,
        "transaction\t{}",
        encode_hex(reference.transaction_id.as_bytes())
    );
    let _ = writeln!(
        encoded,
        "change-set\t{}",
        encode_hex(reference.change_set_id.as_bytes())
    );
    let _ = writeln!(encoded, "base\t{}", reference.base_snapshot);
    let _ = writeln!(encoded, "targets\t{}", reference.touched_target_set_digest);
    let _ = writeln!(
        encoded,
        "target-contract\t{}",
        reference.target_contract_digest
    );
    let _ = writeln!(
        encoded,
        "transaction-identity\t{}\t{}\t{:o}\t{}",
        reference.transaction_device,
        reference.transaction_inode,
        reference.transaction_mode,
        reference.transaction_owner_uid
    );
    let _ = writeln!(encoded, "artifacts\t{}", reference.artifacts.len());
    for artifact in &reference.artifacts {
        let (kind, index) = match artifact.kind {
            CapabilityRollbackArtifactKind::Plan => ("plan", "-".to_owned()),
            CapabilityRollbackArtifactKind::BaseBlob { operation_index } => {
                ("base", operation_index.to_string())
            }
        };
        let _ = writeln!(
            encoded,
            "artifact\t{kind}\t{index}\t{}\t{}\t{:o}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}",
            encode_hex(artifact.name.as_bytes()),
            artifact.length,
            artifact.mode,
            artifact.digest,
            artifact.device,
            artifact.inode,
            artifact.owner_uid,
            artifact.modified_seconds,
            artifact.modified_nanoseconds,
            artifact.changed_seconds,
            artifact.changed_nanoseconds,
        );
    }
    encoded.into_bytes()
}

fn committed_outcome(
    transaction_id: &str,
    plan: &JournalPlan,
    live_manifest_digest: Digest,
) -> Result<CapabilityApplyOutcome, CapabilityApplyError> {
    Ok(CapabilityApplyOutcome {
        transaction_id: transaction_id.to_owned(),
        change_set_id: plan.change_set.change_set_id.clone(),
        verified_result_snapshot: plan.change_set.result_snapshot.clone(),
        live_manifest_digest,
        applied_operations_digest: plan
            .change_set
            .applied_operations_digest()
            .map_err(|error| CapabilityApplyError::Blob(error.to_string()))?,
        touched_path_endpoints_digest: plan
            .change_set
            .touched_path_endpoints_digest()
            .map_err(|error| CapabilityApplyError::Blob(error.to_string()))?,
        touched_target_set_digest: plan
            .change_set
            .touched_target_set_digest()
            .map_err(|error| CapabilityApplyError::Blob(error.to_string()))?,
    })
}

pub(crate) fn normalize_path(path: &Path) -> Result<PathBuf, CapabilityApplyError> {
    if path.is_absolute() {
        return Err(CapabilityApplyError::InvalidPath {
            path: path.to_path_buf(),
            reason: "absolute paths are forbidden".into(),
        });
    }
    let mut normalized = PathBuf::new();
    for component in path.components() {
        let Component::Normal(name) = component else {
            return Err(CapabilityApplyError::InvalidPath {
                path: path.to_path_buf(),
                reason: "`.` and `..` components are forbidden".into(),
            });
        };
        if name
            .to_str()
            .is_some_and(|text| text.eq_ignore_ascii_case(".git"))
        {
            return Err(CapabilityApplyError::InvalidPath {
                path: path.to_path_buf(),
                reason: "Git administrative paths are forbidden".into(),
            });
        }
        if name.as_bytes().contains(&0) || name.to_str().is_none() {
            return Err(CapabilityApplyError::InvalidPath {
                path: path.to_path_buf(),
                reason: "components must be NUL-free UTF-8".into(),
            });
        }
        normalized.push(name);
    }
    if normalized.as_os_str().is_empty() {
        return Err(CapabilityApplyError::InvalidPath {
            path: path.to_path_buf(),
            reason: "a regular-file target is required".into(),
        });
    }
    if normalized.as_os_str().as_bytes() != path.as_os_str().as_bytes() {
        return Err(CapabilityApplyError::InvalidPath {
            path: path.to_path_buf(),
            reason: "path must use its exact normalized spelling".into(),
        });
    }
    Ok(normalized)
}

pub(crate) fn read_descriptor_regular(
    root: &Dir,
    path: &Path,
    limit: u64,
) -> Result<(Vec<u8>, u32), CapabilityApplyError> {
    let path = normalize_path(path)?;
    let mut components = path.components().collect::<Vec<_>>();
    let leaf = match components.pop() {
        Some(Component::Normal(leaf)) => leaf.to_os_string(),
        _ => {
            return Err(CapabilityApplyError::InvalidPath {
                path,
                reason: "regular file must have a normal leaf".into(),
            });
        }
    };
    let mut directory = root
        .try_clone()
        .map_err(|error| io_error("clone descriptor root for read", &path, &error))?;
    let mut relative = PathBuf::new();
    for component in components {
        let Component::Normal(name) = component else {
            unreachable!("normalized paths contain only normal components");
        };
        relative.push(name);
        directory = directory.open_dir_nofollow(name).map_err(|error| {
            io_error(
                "open descriptor-relative read parent without following links",
                &relative,
                &error,
            )
        })?;
    }
    let (bytes, fingerprint) = stable_read(&directory, &leaf, &path, limit)?;
    Ok((bytes, fingerprint.mode & 0o777))
}

fn validate_private_root(
    directory: &Dir,
    label: &str,
) -> Result<PrivateRootIdentity, CapabilityApplyError> {
    let metadata = directory
        .dir_metadata()
        .map_err(|error| CapabilityApplyError::Root(format!("inspect {label}: {error}")))?;
    if !metadata.is_dir() {
        return Err(CapabilityApplyError::Root(format!(
            "{label} is not a directory"
        )));
    }
    let mode = OsMetadataExt::mode(&metadata) & 0o777;
    if mode & 0o700 != 0o700 || mode & 0o077 != 0 {
        return Err(CapabilityApplyError::Root(format!(
            "{label} mode must be owner rwx only, found {mode:04o}"
        )));
    }
    let uid = OsMetadataExt::uid(&metadata);
    if uid != rustix::process::geteuid().as_raw() {
        return Err(CapabilityApplyError::Root(format!(
            "{label} is not owned by the effective user"
        )));
    }
    Ok(PrivateRootIdentity {
        object: object_identity(&metadata),
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

fn validate_regular_metadata(path: &Path, metadata: &Metadata) -> Result<(), CapabilityApplyError> {
    let kind = metadata.file_type();
    if kind.is_symlink() {
        return Err(CapabilityApplyError::UnsafeEntry {
            path: path.to_path_buf(),
            kind: UnsafeFileKind::Symlink,
        });
    }
    if kind.is_dir() {
        return Err(CapabilityApplyError::UnsafeEntry {
            path: path.to_path_buf(),
            kind: UnsafeFileKind::Directory,
        });
    }
    if !kind.is_file() {
        return Err(CapabilityApplyError::UnsafeEntry {
            path: path.to_path_buf(),
            kind: UnsafeFileKind::Special,
        });
    }
    if PortableMetadataExt::nlink(metadata) != 1 {
        return Err(CapabilityApplyError::UnsafeEntry {
            path: path.to_path_buf(),
            kind: UnsafeFileKind::HardLink,
        });
    }
    Ok(())
}

fn walk_snapshot(
    directory: &Dir,
    relative_directory: &Path,
    entries: &mut BTreeMap<PathBuf, SnapshotEntry>,
) -> Result<(), CapabilityApplyError> {
    let mut children = directory
        .entries()
        .map_err(|error| io_error("enumerate workspace directory", relative_directory, &error))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| io_error("read workspace directory entry", relative_directory, &error))?;
    children.sort_by_key(cap_std::fs::DirEntry::file_name);
    for child in children {
        let name = child.file_name();
        let text = name
            .to_str()
            .ok_or_else(|| CapabilityApplyError::InvalidPath {
                path: relative_directory.join(&name),
                reason: "workspace entries must be UTF-8".into(),
            })?;
        if text.eq_ignore_ascii_case(".git") {
            continue;
        }
        let relative = normalize_path(&relative_directory.join(&name))?;
        let metadata = directory.symlink_metadata(&name).map_err(|error| {
            io_error(
                "inspect workspace entry without following links",
                &relative,
                &error,
            )
        })?;
        let kind = metadata.file_type();
        if kind.is_symlink() {
            return Err(CapabilityApplyError::UnsafeEntry {
                path: relative,
                kind: UnsafeFileKind::Symlink,
            });
        }
        if kind.is_dir() {
            let child_directory = directory.open_dir_nofollow(&name).map_err(|error| {
                io_error(
                    "open workspace directory without following links",
                    &relative,
                    &error,
                )
            })?;
            let opened = child_directory.dir_metadata().map_err(|error| {
                io_error("inspect opened workspace directory", &relative, &error)
            })?;
            if object_identity(&opened) != object_identity(&metadata) {
                return Err(CapabilityApplyError::Root(format!(
                    "directory {} changed during traversal",
                    relative.display()
                )));
            }
            walk_snapshot(&child_directory, &relative, entries)?;
            let named_after = directory.symlink_metadata(&name).map_err(|error| {
                io_error("revalidate workspace directory name", &relative, &error)
            })?;
            if !named_after.is_dir() || object_identity(&named_after) != object_identity(&opened) {
                return Err(CapabilityApplyError::Root(format!(
                    "directory {} was replaced during traversal",
                    relative.display()
                )));
            }
        } else if kind.is_file() {
            let (digest, length, fingerprint) = stable_digest(directory, &name, &relative)?;
            entries.insert(
                relative,
                SnapshotEntry {
                    digest,
                    length,
                    mode: fingerprint.mode & 0o777,
                },
            );
        } else {
            return Err(CapabilityApplyError::UnsafeEntry {
                path: relative,
                kind: UnsafeFileKind::Special,
            });
        }
    }
    Ok(())
}

pub(crate) fn capture_descriptor_entries(
    root: &Dir,
) -> Result<BTreeMap<PathBuf, SnapshotEntry>, CapabilityApplyError> {
    let first_root = root
        .try_clone()
        .map_err(|error| io_error("clone root for snapshot", Path::new("."), &error))?;
    let mut first = BTreeMap::new();
    walk_snapshot(&first_root, Path::new(""), &mut first)?;
    let second_root = root.try_clone().map_err(|error| {
        io_error(
            "clone root for stable snapshot verification",
            Path::new("."),
            &error,
        )
    })?;
    let mut second = BTreeMap::new();
    walk_snapshot(&second_root, Path::new(""), &mut second)?;
    if first != second {
        return Err(CapabilityApplyError::Root(
            "workspace changed during descriptor-relative snapshot".into(),
        ));
    }
    Ok(second)
}

pub(crate) fn snapshot_digest(
    entries: &BTreeMap<PathBuf, SnapshotEntry>,
) -> Result<Digest, CapabilityApplyError> {
    let mut hasher = Sha256::new();
    hasher.update(MANIFEST_DOMAIN);
    hasher.update(
        u64::try_from(entries.len())
            .unwrap_or(u64::MAX)
            .to_be_bytes(),
    );
    for (path, entry) in entries {
        let text = portable_path(path)?;
        hasher.update(u64::try_from(text.len()).unwrap_or(u64::MAX).to_be_bytes());
        hasher.update(text.as_bytes());
        hasher.update(entry.length.to_be_bytes());
        hasher.update(entry.digest.as_str().as_bytes());
        hasher.update(entry.mode.to_be_bytes());
    }
    digest_from_output(hasher.finalize().as_ref())
}

fn portable_path(path: &Path) -> Result<String, CapabilityApplyError> {
    let path = normalize_path(path)?;
    let mut encoded = String::new();
    for (index, component) in path.components().enumerate() {
        let Component::Normal(component) = component else {
            unreachable!("normalized paths contain only normal components");
        };
        if index != 0 {
            encoded.push('/');
        }
        encoded.push_str(
            component
                .to_str()
                .ok_or_else(|| CapabilityApplyError::InvalidPath {
                    path: path.clone(),
                    reason: "portable paths must be UTF-8".into(),
                })?,
        );
    }
    Ok(encoded)
}

fn stable_digest(
    parent: &Dir,
    leaf: &OsStr,
    path: &Path,
) -> Result<(Digest, u64, FileFingerprint), CapabilityApplyError> {
    let metadata = parent
        .symlink_metadata(leaf)
        .map_err(|error| io_error("inspect file without following links", path, &error))?;
    validate_regular_metadata(path, &metadata)?;
    let mut options = OpenOptions::new();
    options.read(true).follow(FollowSymlinks::No);
    let mut file = parent
        .open_with(leaf, &options)
        .map_err(|error| io_error("open file without following links", path, &error))?;
    let before = checked_file_metadata(&file, path)?;
    if before != file_fingerprint(&metadata) {
        return Err(CapabilityApplyError::Root(format!(
            "file {} changed before open",
            path.display()
        )));
    }
    let (first, first_length) = hash_open_file(&mut file, path)?;
    let middle = checked_file_metadata(&file, path)?;
    file.seek(SeekFrom::Start(0))
        .map_err(|error| io_error("rewind file for stable hash", path, &error))?;
    let (second, second_length) = hash_open_file(&mut file, path)?;
    let after = checked_file_metadata(&file, path)?;
    if before != middle || middle != after || first != second || first_length != second_length {
        return Err(CapabilityApplyError::Root(format!(
            "file {} changed during stable hash",
            path.display()
        )));
    }
    let named_after = parent
        .symlink_metadata(leaf)
        .map_err(|error| io_error("revalidate hashed file name", path, &error))?;
    validate_regular_metadata(path, &named_after)?;
    if file_fingerprint(&named_after) != after {
        return Err(CapabilityApplyError::Root(format!(
            "file {} name changed during stable hash",
            path.display()
        )));
    }
    Ok((first, first_length, after))
}

fn hash_open_file(file: &mut File, path: &Path) -> Result<(Digest, u64), CapabilityApplyError> {
    let mut hasher = Sha256::new();
    let mut length = 0_u64;
    let mut buffer = vec![0_u8; 64 * 1024].into_boxed_slice();
    loop {
        let read = file
            .read(&mut buffer)
            .map_err(|error| io_error("hash complete file", path, &error))?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
        length = length.saturating_add(u64::try_from(read).expect("usize fits u64"));
    }
    Ok((digest_from_output(hasher.finalize().as_ref())?, length))
}

fn stable_read(
    parent: &Dir,
    leaf: &OsStr,
    path: &Path,
    limit: u64,
) -> Result<(Vec<u8>, FileFingerprint), CapabilityApplyError> {
    let metadata = parent
        .symlink_metadata(leaf)
        .map_err(|error| io_error("inspect regular file without following links", path, &error))?;
    validate_regular_metadata(path, &metadata)?;
    if metadata.len() > limit {
        return Err(CapabilityApplyError::Blob(format!(
            "{} exceeds the {limit}-byte apply ceiling",
            path.display()
        )));
    }
    let mut options = OpenOptions::new();
    options.read(true).follow(FollowSymlinks::No);
    let mut file = parent
        .open_with(leaf, &options)
        .map_err(|error| io_error("open regular file without following links", path, &error))?;
    let before = checked_file_metadata(&file, path)?;
    if before != file_fingerprint(&metadata) {
        return Err(CapabilityApplyError::Root(format!(
            "file {} changed before stable read",
            path.display()
        )));
    }
    let first = read_bounded(&mut file, path, limit)?;
    let middle = checked_file_metadata(&file, path)?;
    file.seek(SeekFrom::Start(0))
        .map_err(|error| io_error("rewind stable file read", path, &error))?;
    let second = read_bounded(&mut file, path, limit)?;
    let after = checked_file_metadata(&file, path)?;
    if before != middle || middle != after || first != second {
        return Err(CapabilityApplyError::Root(format!(
            "file {} changed during stable read",
            path.display()
        )));
    }
    let named_after = parent
        .symlink_metadata(leaf)
        .map_err(|error| io_error("revalidate stable-read file name", path, &error))?;
    validate_regular_metadata(path, &named_after)?;
    if file_fingerprint(&named_after) != after {
        return Err(CapabilityApplyError::Root(format!(
            "file {} name changed during stable read",
            path.display()
        )));
    }
    Ok((first, after))
}

fn checked_file_metadata(
    file: &File,
    path: &Path,
) -> Result<FileFingerprint, CapabilityApplyError> {
    let metadata = file
        .metadata()
        .map_err(|error| io_error("inspect open regular file", path, &error))?;
    validate_regular_metadata(path, &metadata)?;
    Ok(file_fingerprint(&metadata))
}

fn read_bounded(file: &mut File, path: &Path, limit: u64) -> Result<Vec<u8>, CapabilityApplyError> {
    let mut bytes = Vec::with_capacity(
        usize::try_from(limit.min(64 * 1024)).expect("bounded capacity fits usize"),
    );
    file.take(limit.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|error| io_error("read complete file", path, &error))?;
    if u64::try_from(bytes.len()).expect("usize fits u64") > limit {
        return Err(CapabilityApplyError::Blob(format!(
            "{} exceeds the {limit}-byte bound",
            path.display()
        )));
    }
    Ok(bytes)
}

fn optional_state(
    parent: &ParentHandle,
    path: &Path,
) -> Result<Option<FileState>, CapabilityApplyError> {
    match parent.directory.symlink_metadata(&parent.leaf) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(io_error("inspect optional target", path, &error)),
        Ok(_) => {
            let (bytes, fingerprint) =
                stable_read(&parent.directory, &parent.leaf, path, MAX_APPLY_FILE_BYTES)?;
            Ok(Some(FileState {
                digest: Digest::sha256(&bytes),
                mode: fingerprint.mode & 0o777,
                fingerprint,
            }))
        }
    }
}

fn require_absent(parent: &ParentHandle, path: &Path) -> Result<(), CapabilityApplyError> {
    match parent.directory.symlink_metadata(&parent.leaf) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(io_error("inspect create target", path, &error)),
        Ok(metadata) => {
            validate_regular_metadata(path, &metadata)?;
            let state = optional_state(parent, path)?;
            Err(CapabilityApplyError::PreconditionFailed {
                path: path.to_path_buf(),
                expected: None,
                actual: state.map(|state| state.digest),
            })
        }
    }
}

fn verify_target_precondition(
    parent: &ParentHandle,
    path: &Path,
    expected: Option<&Digest>,
    expected_identity: Option<ObjectIdentity>,
) -> Result<(), CapabilityApplyError> {
    let state = optional_state(parent, path)?;
    require_digest(
        path,
        expected,
        state.as_ref().map(|state| &state.digest).cloned(),
    )?;
    if let Some(identity) = expected_identity
        && state.as_ref().map(|state| state.fingerprint.object) != Some(identity)
    {
        return Err(CapabilityApplyError::PreconditionFailed {
            path: path.to_path_buf(),
            expected: expected.cloned(),
            actual: state.map(|state| state.digest),
        });
    }
    Ok(())
}

fn require_digest(
    path: &Path,
    expected: Option<&Digest>,
    actual: Option<Digest>,
) -> Result<(), CapabilityApplyError> {
    if expected == actual.as_ref() {
        Ok(())
    } else {
        Err(CapabilityApplyError::PreconditionFailed {
            path: path.to_path_buf(),
            expected: expected.cloned(),
            actual,
        })
    }
}

fn verified_staged_blob<'a>(
    staged: &'a StagedChangeSet,
    expected: &Digest,
) -> Result<&'a [u8], CapabilityApplyError> {
    let bytes = staged
        .blob(expected)
        .ok_or_else(|| CapabilityApplyError::Blob(format!("missing blob {expected}")))?;
    if u64::try_from(bytes.len()).expect("usize fits u64") > MAX_APPLY_FILE_BYTES {
        return Err(CapabilityApplyError::Blob(format!(
            "blob {expected} exceeds the {MAX_APPLY_FILE_BYTES}-byte apply ceiling"
        )));
    }
    let actual = Digest::sha256(bytes);
    if actual != *expected {
        return Err(CapabilityApplyError::Blob(format!(
            "blob digest mismatch: expected {expected}, found {actual}"
        )));
    }
    Ok(bytes)
}

fn transaction_name(change_set_id: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"grok-build.capability-apply.transaction.v1\0");
    hasher.update(change_set_id.as_bytes());
    format!("transaction-{}", encode_hex(hasher.finalize().as_ref()))
}

fn is_transaction_name(name: &str) -> bool {
    name.strip_prefix("transaction-").is_some_and(|suffix| {
        suffix.len() == 64
            && suffix
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    })
}

fn preparation_name(transaction: &str) -> String {
    format!("{PREPARATION_PREFIX}{transaction}")
}

fn is_preparation_name(name: &str) -> bool {
    name.strip_prefix(PREPARATION_PREFIX)
        .is_some_and(is_transaction_name)
}

fn indexed_preparation_artifact(name: &str, prefix: &str) -> bool {
    name.strip_prefix(prefix)
        .is_some_and(|suffix| suffix.len() == 6 && suffix.bytes().all(|byte| byte.is_ascii_digit()))
}

fn validate_preparation_entries(
    preparation: &Dir,
) -> Result<Vec<(String, ObjectIdentity)>, CapabilityApplyError> {
    validate_private_root(preparation, "preparation directory")?;
    let mut entries = preparation
        .entries()
        .map_err(|error| io_error("enumerate preparation directory", Path::new("."), &error))?
        .map(|entry| {
            entry.map_err(|error| io_error("read preparation entry", Path::new("."), &error))
        })
        .collect::<Result<Vec<_>, _>>()?;
    entries.sort_by_key(cap_std::fs::DirEntry::file_name);
    if entries.len() > MAX_PREPARATION_ENTRIES {
        return Err(CapabilityApplyError::Journal(format!(
            "preparation entry count {} exceeds {MAX_PREPARATION_ENTRIES}",
            entries.len()
        )));
    }
    let mut validated = Vec::with_capacity(entries.len());
    let mut has_plan = false;
    let mut has_phase = false;
    for entry in entries {
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| CapabilityApplyError::Journal("non-UTF-8 preparation entry".into()))?;
        let known = match name.as_str() {
            "plan" => {
                has_plan = true;
                true
            }
            "phase" => {
                has_phase = true;
                true
            }
            _ => {
                indexed_preparation_artifact(&name, "base-")
                    || indexed_preparation_artifact(&name, "result-")
            }
        };
        if !known || name.eq_ignore_ascii_case(".git") {
            return Err(CapabilityApplyError::Journal(format!(
                "unexpected preparation entry {name:?}"
            )));
        }
        let metadata = preparation.symlink_metadata(&name).map_err(|error| {
            io_error(
                "inspect preparation entry without links",
                Path::new(&name),
                &error,
            )
        })?;
        validate_private_file_metadata(Path::new(&name), &metadata)?;
        let limit = if name == "plan" {
            MAX_PLAN_BYTES
        } else if name == "phase" {
            64
        } else {
            MAX_APPLY_FILE_BYTES
        };
        if metadata.len() > limit {
            return Err(CapabilityApplyError::Journal(format!(
                "preparation entry {name:?} exceeds {limit} bytes"
            )));
        }
        validated.push((name, object_identity(&metadata)));
    }
    if has_phase {
        if !has_plan {
            return Err(CapabilityApplyError::Journal(
                "preparation phase exists without a plan".into(),
            ));
        }
        if read_phase(preparation)? != JournalPhase::Prepared {
            return Err(CapabilityApplyError::Journal(
                "preparation namespace may contain only the prepared phase".into(),
            ));
        }
    }
    Ok(validated)
}

fn validate_prepared_state(
    transaction: &Dir,
    plan: &JournalPlan,
) -> Result<(), CapabilityApplyError> {
    if read_phase(transaction)? != JournalPhase::Prepared {
        return Err(CapabilityApplyError::Journal(
            "prepared-state validation requires the prepared phase".into(),
        ));
    }
    let mut expected = BTreeSet::from(["plan".to_owned(), "phase".to_owned()]);
    for (index, planned) in plan.operations.iter().enumerate() {
        match planned.operation {
            FileOperation::Create { .. } => {
                expected.insert(result_blob_name(index));
            }
            FileOperation::Modify { .. } => {
                expected.insert(base_blob_name(index));
                expected.insert(result_blob_name(index));
            }
            FileOperation::Delete { .. } => {
                expected.insert(base_blob_name(index));
            }
        }
    }
    let mut actual = transaction
        .entries()
        .map_err(|error| io_error("enumerate prepared transaction", Path::new("."), &error))?
        .map(|entry| {
            entry
                .map_err(|error| io_error("read prepared transaction", Path::new("."), &error))?
                .file_name()
                .into_string()
                .map_err(|_| CapabilityApplyError::Journal("non-UTF-8 prepared entry".into()))
        })
        .collect::<Result<BTreeSet<_>, _>>()?;
    if actual.remove(".phase.next") {
        let next = read_journal_file(transaction, ".phase.next", 64)?;
        if next != format!("{}\n", JournalPhase::Applying.as_str()).as_bytes() {
            return Err(CapabilityApplyError::Journal(
                "prepared phase temporary is not the exact applying transition".into(),
            ));
        }
    }
    if actual != expected {
        return Err(CapabilityApplyError::Journal(
            "prepared transaction contains missing or effect-capable entries".into(),
        ));
    }
    Ok(())
}

fn publish_no_replace(
    parent: &Dir,
    source: &str,
    destination: &str,
    operation: &'static str,
) -> Result<(), CapabilityApplyError> {
    renameat_with(
        parent,
        Path::new(source),
        parent,
        Path::new(destination),
        RenameFlags::NOREPLACE,
    )
    .map_err(|error| io_error(operation, Path::new(destination), &error))
}

fn plan_blob_count(plan: &JournalPlan) -> usize {
    plan.operations
        .iter()
        .map(|planned| match planned.operation {
            FileOperation::Create { .. } | FileOperation::Delete { .. } => 1,
            FileOperation::Modify { .. } => 2,
        })
        .sum()
}

fn maybe_preparation_fault(
    actual: Option<FaultPoint>,
    expected: FaultPoint,
    completed_blobs: usize,
    checkpoint: &'static str,
) -> Result<(), CapabilityApplyError> {
    if actual == Some(expected) {
        Err(CapabilityApplyError::InjectedPreparationCrash {
            checkpoint,
            completed_blobs,
        })
    } else {
        Ok(())
    }
}

fn maybe_preparation_blob_fault(
    fault: Option<FaultPoint>,
    completed_blobs: usize,
) -> Result<(), CapabilityApplyError> {
    maybe_preparation_fault(
        fault,
        FaultPoint::AfterPreparationBlob(completed_blobs),
        completed_blobs,
        "blob",
    )
}

fn base_blob_name(index: usize) -> String {
    format!("base-{index:06}")
}

fn result_blob_name(index: usize) -> String {
    format!("result-{index:06}")
}

fn apply_intent_name(index: usize) -> String {
    format!("apply-intent-{index:06}")
}

fn rollback_intent_name(index: usize) -> String {
    format!("rollback-intent-{index:06}")
}

fn applied_marker_name(index: usize) -> String {
    format!("applied-{index:06}")
}

fn restored_marker_name(index: usize) -> String {
    format!("restored-{index:06}")
}

fn directory_owned_name(index: usize) -> String {
    format!("directory-owned-{index:06}")
}

fn directory_created_marker_name(index: usize) -> String {
    format!("directory-created-{index:06}")
}

fn directory_restored_marker_name(index: usize) -> String {
    format!("directory-restored-{index:06}")
}

fn live_artifact_name(transaction: &str, index: usize, role: &str) -> String {
    format!(".grok-build-{transaction}-{index:06}-{role}")
}

fn write_plan_new(transaction: &Dir, plan: &JournalPlan) -> Result<(), CapabilityApplyError> {
    use std::fmt::Write as _;

    let mut encoded = String::new();
    encoded.push_str(JOURNAL_VERSION);
    encoded.push('\n');
    encoded.push_str("id\t");
    encoded.push_str(&encode_hex(plan.change_set.change_set_id.as_bytes()));
    encoded.push('\n');
    encoded.push_str("base\t");
    encoded.push_str(plan.change_set.base_snapshot.as_str());
    encoded.push('\n');
    encoded.push_str("result\t");
    encoded.push_str(plan.change_set.result_snapshot.as_str());
    encoded.push('\n');
    for directory in &plan.directories {
        encoded.push_str("P\t");
        encoded.push_str(&encode_hex(portable_path(&directory.path)?.as_bytes()));
        encoded.push('\t');
        let _ = write!(encoded, "{:o}", directory.mode & 0o777);
        encoded.push('\n');
    }
    for planned in &plan.operations {
        let (kind, base, result) = match &planned.operation {
            FileOperation::Create { result_hash, .. } => ("C", "-", result_hash.as_str()),
            FileOperation::Modify {
                base_hash,
                result_hash,
                ..
            } => ("M", base_hash.as_str(), result_hash.as_str()),
            FileOperation::Delete { base_hash, .. } => ("D", base_hash.as_str(), "-"),
        };
        let path = portable_path(planned.operation.path())?;
        let (device, inode) = planned.base_identity.map_or_else(
            || ("-".to_owned(), "-".to_owned()),
            |identity| (identity.device.to_string(), identity.inode.to_string()),
        );
        encoded.push_str(kind);
        encoded.push('\t');
        encoded.push_str(&encode_hex(path.as_bytes()));
        encoded.push('\t');
        encoded.push_str(base);
        encoded.push('\t');
        encoded.push_str(result);
        encoded.push('\t');
        let _ = write!(encoded, "{:o}", planned.mode & 0o777);
        encoded.push('\t');
        encoded.push_str(&device);
        encoded.push('\t');
        encoded.push_str(&inode);
        encoded.push('\n');
    }
    if u64::try_from(encoded.len()).expect("usize fits u64") > MAX_PLAN_BYTES {
        return Err(CapabilityApplyError::Journal(format!(
            "encoded plan exceeds {MAX_PLAN_BYTES} bytes"
        )));
    }
    write_new_journal_file(transaction, "plan", encoded.as_bytes())
}

#[allow(
    clippy::too_many_lines,
    reason = "journal parsing and canonical validation remain adjacent so no decoded field bypasses validation"
)]
fn read_plan(transaction: &Dir) -> Result<JournalPlan, CapabilityApplyError> {
    let bytes = read_journal_file(transaction, "plan", MAX_PLAN_BYTES)?;
    let text = std::str::from_utf8(&bytes)
        .map_err(|_| CapabilityApplyError::Journal("plan is not UTF-8".into()))?;
    let mut lines = text.lines();
    if lines.next() != Some(JOURNAL_VERSION) {
        return Err(CapabilityApplyError::Journal(
            "unsupported or missing plan version".into(),
        ));
    }
    let change_set_id = String::from_utf8(parse_named_hex_line(lines.next(), "id")?)
        .map_err(|_| CapabilityApplyError::Journal("change-set id is not UTF-8".into()))?;
    let base_snapshot = parse_named_digest_line(lines.next(), "base")?;
    let result_snapshot = parse_named_digest_line(lines.next(), "result")?;
    let mut directories = Vec::new();
    let mut operations = Vec::new();
    let mut saw_operation = false;
    for line in lines {
        let fields = line.split('\t').collect::<Vec<_>>();
        if fields.first() == Some(&"P") {
            if saw_operation || fields.len() != 3 {
                return Err(CapabilityApplyError::Journal(
                    "directory lines must precede operations and have three fields".into(),
                ));
            }
            let path_text = String::from_utf8(decode_hex(fields[1])?)
                .map_err(|_| CapabilityApplyError::Journal("directory path is not UTF-8".into()))?;
            let path = normalize_path(Path::new(&path_text))?;
            let mode = u32::from_str_radix(fields[2], 8)
                .map_err(|_| CapabilityApplyError::Journal("invalid directory mode".into()))?;
            if mode != 0o755 {
                return Err(CapabilityApplyError::Journal(
                    "created live directory mode must be 0755".into(),
                ));
            }
            directories.push(PlannedDirectory { path, mode });
            continue;
        }
        saw_operation = true;
        if fields.len() != 7 {
            return Err(CapabilityApplyError::Journal(
                "operation line must have seven fields".into(),
            ));
        }
        let path_text = String::from_utf8(decode_hex(fields[1])?)
            .map_err(|_| CapabilityApplyError::Journal("operation path is not UTF-8".into()))?;
        let path = normalize_path(Path::new(&path_text))?;
        let mode = u32::from_str_radix(fields[4], 8)
            .map_err(|_| CapabilityApplyError::Journal("invalid file mode".into()))?;
        if mode & !0o777 != 0 {
            return Err(CapabilityApplyError::Journal(
                "file mode contains non-permission bits".into(),
            ));
        }
        let base_identity = match (fields[5], fields[6]) {
            ("-", "-") => None,
            ("-", _) | (_, "-") => {
                return Err(CapabilityApplyError::Journal(
                    "partial base identity".into(),
                ));
            }
            (device, inode) => Some(ObjectIdentity {
                device: device
                    .parse()
                    .map_err(|_| CapabilityApplyError::Journal("invalid device id".into()))?,
                inode: inode
                    .parse()
                    .map_err(|_| CapabilityApplyError::Journal("invalid inode".into()))?,
            }),
        };
        let operation = match fields[0] {
            "C" if fields[2] == "-" && base_identity.is_none() => FileOperation::Create {
                path,
                result_hash: parse_digest(fields[3])?,
            },
            "M" if base_identity.is_some() => FileOperation::Modify {
                path,
                base_hash: parse_digest(fields[2])?,
                result_hash: parse_digest(fields[3])?,
            },
            "D" if fields[3] == "-" && base_identity.is_some() => FileOperation::Delete {
                path,
                base_hash: parse_digest(fields[2])?,
            },
            _ => {
                return Err(CapabilityApplyError::Journal(
                    "invalid operation encoding".into(),
                ));
            }
        };
        operations.push(PlanOperation {
            operation,
            mode,
            base_identity,
        });
    }
    let change_set = ChangeSet {
        change_set_id,
        base_snapshot,
        result_snapshot,
        operations: operations
            .iter()
            .map(|planned| planned.operation.clone())
            .collect(),
    };
    change_set
        .validate()
        .map_err(|error| CapabilityApplyError::Journal(error.to_string()))?;
    let mut expected_directories = directories.clone();
    expected_directories.sort_by(|left, right| {
        left.path
            .components()
            .count()
            .cmp(&right.path.components().count())
            .then_with(|| left.path.cmp(&right.path))
    });
    if directories != expected_directories
        || directories
            .windows(2)
            .any(|pair| pair[0].path == pair[1].path)
    {
        return Err(CapabilityApplyError::Journal(
            "directory plan is duplicated or out of canonical order".into(),
        ));
    }
    for directory in &directories {
        if !operations.iter().any(|planned| {
            matches!(&planned.operation, FileOperation::Create { .. })
                && planned.operation.path().starts_with(&directory.path)
                && planned.operation.path() != directory.path
        }) {
            return Err(CapabilityApplyError::Journal(format!(
                "planned directory {} is not a strict create-target ancestor",
                directory.path.display()
            )));
        }
    }
    let plan = JournalPlan {
        change_set,
        directories,
        operations,
    };
    validate_transaction_entries(transaction, &plan)?;
    validate_plan_evidence(transaction, &plan)?;
    Ok(plan)
}

fn validate_plan_evidence(
    transaction: &Dir,
    plan: &JournalPlan,
) -> Result<(), CapabilityApplyError> {
    for (index, _) in plan.directories.iter().enumerate() {
        let _ = read_intent_optional(transaction, &directory_owned_name(index))?;
        validate_optional_marker(
            transaction,
            &directory_created_marker_name(index),
            b"directory-created\n",
        )?;
        validate_optional_marker(
            transaction,
            &directory_restored_marker_name(index),
            b"directory-restored\n",
        )?;
    }
    for (index, planned) in plan.operations.iter().enumerate() {
        match &planned.operation {
            FileOperation::Create { result_hash, .. } => {
                let _ = read_verified_blob(transaction, &result_blob_name(index), result_hash)?;
            }
            FileOperation::Modify {
                base_hash,
                result_hash,
                ..
            } => {
                let _ = read_verified_blob(transaction, &base_blob_name(index), base_hash)?;
                let _ = read_verified_blob(transaction, &result_blob_name(index), result_hash)?;
            }
            FileOperation::Delete { base_hash, .. } => {
                let _ = read_verified_blob(transaction, &base_blob_name(index), base_hash)?;
            }
        }
        let _ = read_intent_optional(transaction, &apply_intent_name(index))?;
        let _ = read_intent_optional(transaction, &rollback_intent_name(index))?;
        validate_optional_marker(transaction, &applied_marker_name(index), b"applied\n")?;
        validate_optional_marker(transaction, &restored_marker_name(index), b"restored\n")?;
    }
    Ok(())
}

fn validate_optional_marker(
    transaction: &Dir,
    name: &str,
    expected: &[u8],
) -> Result<(), CapabilityApplyError> {
    match transaction.symlink_metadata(name) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(io_error(
            "inspect optional effect marker",
            Path::new(name),
            &error,
        )),
        Ok(_) => {
            let actual = read_journal_file(transaction, name, 64)?;
            if actual == expected {
                Ok(())
            } else {
                Err(CapabilityApplyError::Journal(format!(
                    "effect marker {name:?} has invalid content"
                )))
            }
        }
    }
}

fn parse_named_hex_line(line: Option<&str>, name: &str) -> Result<Vec<u8>, CapabilityApplyError> {
    let fields = line
        .ok_or_else(|| CapabilityApplyError::Journal(format!("missing `{name}` line")))?
        .split('\t')
        .collect::<Vec<_>>();
    if fields.len() != 2 || fields[0] != name {
        return Err(CapabilityApplyError::Journal(format!(
            "invalid `{name}` line"
        )));
    }
    decode_hex(fields[1])
}

fn parse_named_digest_line(line: Option<&str>, name: &str) -> Result<Digest, CapabilityApplyError> {
    let fields = line
        .ok_or_else(|| CapabilityApplyError::Journal(format!("missing `{name}` line")))?
        .split('\t')
        .collect::<Vec<_>>();
    if fields.len() != 2 || fields[0] != name {
        return Err(CapabilityApplyError::Journal(format!(
            "invalid `{name}` line"
        )));
    }
    parse_digest(fields[1])
}

fn parse_digest(value: &str) -> Result<Digest, CapabilityApplyError> {
    Digest::parse(value).map_err(|error| CapabilityApplyError::Journal(error.to_string()))
}

fn write_phase(transaction: &Dir, phase: JournalPhase) -> Result<(), CapabilityApplyError> {
    write_atomic_journal_file(
        transaction,
        "phase",
        format!("{}\n", phase.as_str()).as_bytes(),
    )
}

fn write_phase_with_post_rename_hook(
    transaction: &Dir,
    phase: JournalPhase,
    after_rename: impl FnOnce() -> Result<(), CapabilityApplyError>,
) -> Result<(), CapabilityApplyError> {
    write_atomic_journal_file_with_post_rename_hook(
        transaction,
        "phase",
        format!("{}\n", phase.as_str()).as_bytes(),
        after_rename,
    )
}

fn write_phase_after_effect(
    transaction: &Dir,
    phase: JournalPhase,
    change_set_id: &str,
    operation: &'static str,
) -> Result<(), CapabilityApplyError> {
    write_phase(transaction, phase)
        .map_err(|error| uncertain(change_set_id, None, operation, error))
}

fn write_phase_after_effect_with_post_rename_hook(
    transaction: &Dir,
    phase: JournalPhase,
    change_set_id: &str,
    operation: &'static str,
    after_rename: impl FnOnce() -> Result<(), CapabilityApplyError>,
) -> Result<(), CapabilityApplyError> {
    write_phase_with_post_rename_hook(transaction, phase, after_rename)
        .map_err(|error| uncertain(change_set_id, None, operation, error))
}

fn read_phase(transaction: &Dir) -> Result<JournalPhase, CapabilityApplyError> {
    let bytes = read_journal_file(transaction, "phase", 64)?;
    let text = std::str::from_utf8(&bytes)
        .map_err(|_| CapabilityApplyError::Journal("phase is not UTF-8".into()))?;
    JournalPhase::parse(text)
}

fn write_new_journal_file(
    directory: &Dir,
    name: &str,
    bytes: &[u8],
) -> Result<(), CapabilityApplyError> {
    let mut options = OpenOptions::new();
    options
        .read(true)
        .write(true)
        .create_new(true)
        .mode(0o600)
        .follow(FollowSymlinks::No);
    let mut file = directory
        .open_with(name, &options)
        .map_err(|error| io_error("create private journal file", Path::new(name), &error))?;
    let created_metadata = file
        .metadata()
        .map_err(|error| io_error("inspect new private journal file", Path::new(name), &error))?;
    validate_private_file_metadata(Path::new(name), &created_metadata)?;
    let created_identity = object_identity(&created_metadata);
    let result = (|| {
        file.write_all(bytes)
            .map_err(|error| io_error("write private journal file", Path::new(name), &error))?;
        file.sync_all()
            .map_err(|error| io_error("sync private journal file", Path::new(name), &error))?;
        let metadata = file
            .metadata()
            .map_err(|error| io_error("inspect private journal file", Path::new(name), &error))?;
        validate_private_file_metadata(Path::new(name), &metadata)?;
        sync_directory(directory)
            .map_err(|error| io_error("sync private journal directory", Path::new(name), &error))
    })();
    if result.is_err() {
        drop(file);
        let _ = remove_owned_regular_file(directory, name, created_identity, Path::new(name));
        let _ = sync_directory(directory);
    }
    result
}

fn write_atomic_journal_file(
    directory: &Dir,
    name: &str,
    bytes: &[u8],
) -> Result<(), CapabilityApplyError> {
    write_atomic_journal_file_with_post_rename_hook(directory, name, bytes, || Ok(()))
}

fn write_atomic_journal_file_with_post_rename_hook(
    directory: &Dir,
    name: &str,
    bytes: &[u8],
    after_rename: impl FnOnce() -> Result<(), CapabilityApplyError>,
) -> Result<(), CapabilityApplyError> {
    if let Ok(metadata) = directory.symlink_metadata(name) {
        validate_private_file_metadata(Path::new(name), &metadata)?;
    }
    let temporary = format!(".{name}.next");
    match directory.symlink_metadata(&temporary) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => {
            return Err(io_error(
                "inspect journal update temporary",
                Path::new(&temporary),
                &error,
            ));
        }
        Ok(metadata) => {
            validate_private_file_metadata(Path::new(&temporary), &metadata)?;
            remove_owned_regular_file(
                directory,
                &temporary,
                object_identity(&metadata),
                Path::new(&temporary),
            )?;
            sync_directory(directory).map_err(|error| {
                io_error(
                    "sync removed journal update temporary",
                    Path::new(&temporary),
                    &error,
                )
            })?;
        }
    }
    write_new_journal_file(directory, &temporary, bytes)?;
    directory
        .rename(&temporary, directory, name)
        .map_err(|error| io_error("commit atomic journal update", Path::new(name), &error))?;
    after_rename()?;
    sync_directory(directory)
        .map_err(|error| io_error("sync atomic journal update", Path::new(name), &error))
}

fn read_journal_file(
    directory: &Dir,
    name: &str,
    limit: u64,
) -> Result<Vec<u8>, CapabilityApplyError> {
    let metadata = directory
        .symlink_metadata(name)
        .map_err(|error| io_error("inspect private journal file", Path::new(name), &error))?;
    validate_private_file_metadata(Path::new(name), &metadata)?;
    stable_read(directory, OsStr::new(name), Path::new(name), limit).map(|(bytes, _)| bytes)
}

fn validate_private_file_metadata(
    path: &Path,
    metadata: &Metadata,
) -> Result<(), CapabilityApplyError> {
    validate_regular_metadata(path, metadata)?;
    let mode = OsMetadataExt::mode(metadata) & 0o777;
    if mode != 0o600 {
        return Err(CapabilityApplyError::Journal(format!(
            "private file {} has mode {mode:04o}, expected 0600",
            path.display()
        )));
    }
    if OsMetadataExt::uid(metadata) != rustix::process::geteuid().as_raw() {
        return Err(CapabilityApplyError::Journal(format!(
            "private file {} is not owned by the effective user",
            path.display()
        )));
    }
    Ok(())
}

fn validate_transaction_entries(
    transaction: &Dir,
    plan: &JournalPlan,
) -> Result<(), CapabilityApplyError> {
    validate_private_root(transaction, "transaction directory")?;
    let mut required = BTreeSet::from(["plan".to_owned(), "phase".to_owned()]);
    let mut allowed = required.clone();
    allowed.insert(".phase.next".to_owned());
    allowed.insert(ROLLBACK_PRECONDITION_NAME.to_owned());
    for (index, _) in plan.directories.iter().enumerate() {
        allowed.insert(directory_owned_name(index));
        allowed.insert(directory_created_marker_name(index));
        allowed.insert(directory_restored_marker_name(index));
    }
    for (index, planned) in plan.operations.iter().enumerate() {
        match planned.operation {
            FileOperation::Create { .. } => {
                required.insert(result_blob_name(index));
            }
            FileOperation::Modify { .. } => {
                required.insert(base_blob_name(index));
                required.insert(result_blob_name(index));
            }
            FileOperation::Delete { .. } => {
                required.insert(base_blob_name(index));
            }
        }
        allowed.insert(apply_intent_name(index));
        allowed.insert(rollback_intent_name(index));
        allowed.insert(applied_marker_name(index));
        allowed.insert(restored_marker_name(index));
    }
    allowed.extend(required.iter().cloned());
    let mut actual = BTreeSet::new();
    let entries = transaction
        .entries()
        .map_err(|error| io_error("enumerate transaction journal", Path::new("."), &error))?;
    for entry in entries {
        let entry = entry
            .map_err(|error| io_error("read transaction journal entry", Path::new("."), &error))?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| CapabilityApplyError::Journal("non-UTF-8 transaction entry".into()))?;
        if !allowed.contains(&name) {
            return Err(CapabilityApplyError::Journal(format!(
                "unexpected transaction entry {name:?}"
            )));
        }
        let metadata = transaction.symlink_metadata(&name).map_err(|error| {
            io_error(
                "inspect transaction journal entry",
                Path::new(&name),
                &error,
            )
        })?;
        validate_private_file_metadata(Path::new(&name), &metadata)?;
        if name == ROLLBACK_PRECONDITION_NAME && metadata.len() > MAX_ROLLBACK_PRECONDITION_BYTES {
            return Err(CapabilityApplyError::Journal(
                "rollback precondition record exceeds its hard bound".into(),
            ));
        }
        actual.insert(name);
    }
    if let Some(missing) = required.difference(&actual).next() {
        return Err(CapabilityApplyError::Journal(format!(
            "missing required transaction entry {missing:?}"
        )));
    }
    Ok(())
}

fn read_verified_blob(
    transaction: &Dir,
    name: &str,
    expected: &Digest,
) -> Result<Vec<u8>, CapabilityApplyError> {
    let bytes = read_journal_file(transaction, name, MAX_APPLY_FILE_BYTES)?;
    let actual = Digest::sha256(&bytes);
    if actual != *expected {
        return Err(CapabilityApplyError::Blob(format!(
            "journal blob {name:?} digest mismatch: expected {expected}, found {actual}"
        )));
    }
    Ok(bytes)
}

fn encode_intent(identity: ObjectIdentity) -> Vec<u8> {
    format!("intent-v1\t{}\t{}\n", identity.device, identity.inode).into_bytes()
}

fn write_intent_new(
    transaction: &Dir,
    name: &str,
    identity: ObjectIdentity,
) -> Result<(), CapabilityApplyError> {
    write_new_journal_file(transaction, name, &encode_intent(identity))
}

fn ensure_intent(
    transaction: &Dir,
    name: &str,
    identity: ObjectIdentity,
) -> Result<(), CapabilityApplyError> {
    match read_intent_optional(transaction, name)? {
        None => write_intent_new(transaction, name, identity),
        Some(existing) if existing.identity == identity => Ok(()),
        Some(_) => Err(CapabilityApplyError::Journal(format!(
            "intent {name:?} identity differs"
        ))),
    }
}

fn read_intent_optional(
    transaction: &Dir,
    name: &str,
) -> Result<Option<MutationIntent>, CapabilityApplyError> {
    match transaction.symlink_metadata(name) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(io_error("inspect mutation intent", Path::new(name), &error)),
        Ok(_) => {
            let bytes = read_journal_file(transaction, name, 128)?;
            let text = std::str::from_utf8(&bytes)
                .map_err(|_| CapabilityApplyError::Journal("intent is not UTF-8".into()))?;
            let fields = text
                .strip_suffix('\n')
                .ok_or_else(|| CapabilityApplyError::Journal("intent lacks newline".into()))?
                .split('\t')
                .collect::<Vec<_>>();
            if fields.len() != 3 || fields[0] != "intent-v1" {
                return Err(CapabilityApplyError::Journal(
                    "invalid mutation intent".into(),
                ));
            }
            Ok(Some(MutationIntent {
                identity: ObjectIdentity {
                    device: fields[1].parse().map_err(|_| {
                        CapabilityApplyError::Journal("invalid intent device".into())
                    })?,
                    inode: fields[2].parse().map_err(|_| {
                        CapabilityApplyError::Journal("invalid intent inode".into())
                    })?,
                },
            }))
        }
    }
}

fn write_marker_after_effect(
    transaction: &Dir,
    name: &str,
    bytes: &[u8],
    change_set_id: &str,
    path: &Path,
    operation: &'static str,
) -> Result<(), CapabilityApplyError> {
    let write = match transaction.symlink_metadata(name) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            write_new_journal_file(transaction, name, bytes)
        }
        Err(error) => Err(io_error(
            "inspect durable effect marker",
            Path::new(name),
            &error,
        )),
        Ok(_) => {
            let actual = read_journal_file(transaction, name, 64)?;
            if actual == bytes {
                Ok(())
            } else {
                Err(CapabilityApplyError::Journal(format!(
                    "effect marker {name:?} has invalid content"
                )))
            }
        }
    };
    write.map_err(|error| uncertain(change_set_id, Some(path.to_path_buf()), operation, error))
}

fn optional_artifact_identity(
    parent: &Dir,
    name: &str,
    logical_path: &Path,
) -> Result<Option<ObjectIdentity>, CapabilityApplyError> {
    match parent.symlink_metadata(name) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(io_error(
            "inspect live transaction artifact",
            logical_path,
            &error,
        )),
        Ok(metadata) => {
            validate_regular_metadata(logical_path, &metadata)?;
            Ok(Some(object_identity(&metadata)))
        }
    }
}

fn verify_owned_regular_artifact(
    parent: &Dir,
    name: &str,
    logical_path: &Path,
    expected_identity: ObjectIdentity,
    expected_digest: &Digest,
    expected_mode: u32,
) -> Result<(), CapabilityApplyError> {
    let (bytes, fingerprint) =
        stable_read(parent, OsStr::new(name), logical_path, MAX_APPLY_FILE_BYTES)?;
    let actual = Digest::sha256(&bytes);
    if fingerprint.object != expected_identity
        || actual != *expected_digest
        || fingerprint.mode & 0o777 != expected_mode & 0o777
    {
        return Err(recovery_conflict(
            logical_path,
            &format!(
                "journal-owned inode, digest {expected_digest}, and mode {:04o}",
                expected_mode & 0o777
            ),
            Some(actual),
        ));
    }
    Ok(())
}

fn optional_directory_state(
    parent: &Dir,
    name: &OsStr,
    logical_path: &Path,
) -> Result<Option<DirectoryState>, CapabilityApplyError> {
    let metadata = match parent.symlink_metadata(name) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(io_error(
                "inspect optional directory without following links",
                logical_path,
                &error,
            ));
        }
        Ok(metadata) => metadata,
    };
    if metadata.file_type().is_symlink() {
        return Err(CapabilityApplyError::UnsafeEntry {
            path: logical_path.to_path_buf(),
            kind: UnsafeFileKind::Symlink,
        });
    }
    if !metadata.is_dir() {
        return Err(recovery_conflict(
            logical_path,
            "directory or absence",
            None,
        ));
    }
    let opened = parent.open_dir_nofollow(name).map_err(|error| {
        io_error(
            "open optional directory without following links",
            logical_path,
            &error,
        )
    })?;
    let opened_metadata = opened
        .dir_metadata()
        .map_err(|error| io_error("inspect optional directory", logical_path, &error))?;
    if object_identity(&metadata) != object_identity(&opened_metadata) {
        return Err(CapabilityApplyError::Root(format!(
            "directory {} changed during no-follow open",
            logical_path.display()
        )));
    }
    Ok(Some(DirectoryState {
        object: object_identity(&opened_metadata),
        mode: OsMetadataExt::mode(&opened_metadata) & 0o777,
    }))
}

fn directory_is_empty(directory: &Dir, logical_path: &Path) -> Result<bool, CapabilityApplyError> {
    let mut entries = directory
        .entries()
        .map_err(|error| io_error("enumerate rollback directory", logical_path, &error))?;
    match entries.next() {
        None => Ok(true),
        Some(Ok(_)) => Ok(false),
        Some(Err(error)) => Err(io_error(
            "read rollback directory entry",
            logical_path,
            &error,
        )),
    }
}

fn require_named_absent(
    parent: &Dir,
    name: &OsStr,
    logical_path: &Path,
) -> Result<(), CapabilityApplyError> {
    match parent.symlink_metadata(name) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(io_error("prove named entry absent", logical_path, &error)),
        Ok(metadata) => {
            validate_regular_metadata(logical_path, &metadata)?;
            Err(recovery_conflict(logical_path, "absent named entry", None))
        }
    }
}

fn remove_owned_regular_file(
    parent: &Dir,
    name: &str,
    expected_identity: ObjectIdentity,
    logical_path: &Path,
) -> Result<(), CapabilityApplyError> {
    let metadata = parent
        .symlink_metadata(name)
        .map_err(|error| io_error("revalidate owned cleanup file", logical_path, &error))?;
    validate_regular_metadata(logical_path, &metadata)?;
    if object_identity(&metadata) != expected_identity {
        return Err(recovery_conflict(
            logical_path,
            "journal-owned cleanup inode",
            None,
        ));
    }
    parent
        .remove_file(name)
        .map_err(|error| io_error("remove owned cleanup file", logical_path, &error))
}

fn write_live_temp(
    parent: &Dir,
    name: &str,
    contents: &[u8],
    mode: u32,
    logical_path: &Path,
) -> Result<FileFingerprint, CapabilityApplyError> {
    if u64::try_from(contents.len()).expect("usize fits u64") > MAX_APPLY_FILE_BYTES {
        return Err(CapabilityApplyError::Blob(format!(
            "{} exceeds the apply-file ceiling",
            logical_path.display()
        )));
    }
    match parent.symlink_metadata(name) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(io_error("inspect live temporary", logical_path, &error)),
        Ok(metadata) => {
            validate_regular_metadata(logical_path, &metadata)?;
            return Err(recovery_conflict(
                logical_path,
                "absent unowned live temporary",
                None,
            ));
        }
    }
    let mut options = OpenOptions::new();
    options
        .read(true)
        .write(true)
        .create_new(true)
        .mode(0o600)
        .follow(FollowSymlinks::No);
    let mut file = parent
        .open_with(name, &options)
        .map_err(|error| io_error("create same-directory live temporary", logical_path, &error))?;
    let created_metadata = file
        .metadata()
        .map_err(|error| io_error("inspect new live temporary", logical_path, &error))?;
    validate_regular_metadata(logical_path, &created_metadata)?;
    let created_identity = object_identity(&created_metadata);
    let result = (|| {
        file.write_all(contents)
            .map_err(|error| io_error("write live temporary", logical_path, &error))?;
        file.sync_all()
            .map_err(|error| io_error("sync live temporary content", logical_path, &error))?;
        file.seek(SeekFrom::Start(0))
            .map_err(|error| io_error("rewind live temporary", logical_path, &error))?;
        let observed = read_bounded(&mut file, logical_path, MAX_APPLY_FILE_BYTES)?;
        if observed != contents {
            return Err(CapabilityApplyError::Blob(format!(
                "live temporary for {} failed readback",
                logical_path.display()
            )));
        }
        file.set_permissions(Permissions::from_mode(mode & 0o777))
            .map_err(|error| io_error("set live temporary mode", logical_path, &error))?;
        file.sync_all()
            .map_err(|error| io_error("sync live temporary metadata", logical_path, &error))?;
        let metadata = file
            .metadata()
            .map_err(|error| io_error("inspect live temporary", logical_path, &error))?;
        validate_regular_metadata(logical_path, &metadata)?;
        let fingerprint = file_fingerprint(&metadata);
        if fingerprint.mode & 0o777 != mode & 0o777 {
            return Err(CapabilityApplyError::Blob(format!(
                "live temporary mode mismatch for {}",
                logical_path.display()
            )));
        }
        sync_directory(parent)
            .map_err(|error| io_error("sync live temporary parent", logical_path, &error))?;
        Ok(fingerprint)
    })();
    if result.is_err() {
        drop(file);
        let _ = remove_owned_regular_file(parent, name, created_identity, logical_path);
        let _ = sync_directory(parent);
    }
    result
}

#[allow(
    clippy::too_many_arguments,
    reason = "post-syscall proof binds authority, parent, content, mode, inode, and durable context"
)]
fn finish_live_effect(
    applier: &CapabilitySafeApplier,
    parent: &ParentHandle,
    path: &Path,
    expected_digest: &Digest,
    expected_mode: u32,
    expected_identity: Option<ObjectIdentity>,
    change_set_id: &str,
    operation: &'static str,
) -> Result<(), CapabilityApplyError> {
    let proof = (|| {
        sync_directory(&parent.directory)
            .map_err(|error| io_error("sync live target parent", path, &error))?;
        let state = optional_state(parent, path)?;
        let Some(state) = state else {
            return Err(recovery_conflict(
                path,
                &format!("live result {expected_digest}"),
                None,
            ));
        };
        if state.digest != *expected_digest
            || state.mode & 0o777 != expected_mode & 0o777
            || expected_identity.is_some_and(|identity| state.fingerprint.object != identity)
        {
            return Err(recovery_conflict(
                path,
                &format!("live result {expected_digest} with owned identity"),
                Some(state.digest),
            ));
        }
        applier.validate_roots()?;
        applier.verify_parent(parent)
    })();
    proof.map_err(|error| uncertain(change_set_id, Some(path.to_path_buf()), operation, error))
}

fn finish_directory_effect(
    applier: &CapabilitySafeApplier,
    parent: &ParentHandle,
    path: &Path,
    expected_mode: u32,
    expected_identity: ObjectIdentity,
    change_set_id: &str,
    operation: &'static str,
) -> Result<(), CapabilityApplyError> {
    let proof = (|| {
        sync_directory(&parent.directory)
            .map_err(|error| io_error("sync live directory parent", path, &error))?;
        let state = optional_directory_state(&parent.directory, &parent.leaf, path)?;
        if state
            != Some(DirectoryState {
                object: expected_identity,
                mode: expected_mode & 0o777,
            })
        {
            return Err(recovery_conflict(
                path,
                &format!(
                    "owned directory inode with mode {:04o}",
                    expected_mode & 0o777
                ),
                None,
            ));
        }
        applier.validate_roots()?;
        applier.verify_parent(parent)
    })();
    proof.map_err(|error| uncertain(change_set_id, Some(path.to_path_buf()), operation, error))
}

fn finish_directory_absence_effect(
    applier: &CapabilitySafeApplier,
    parent: &ParentHandle,
    path: &Path,
    removed_name: &OsStr,
    change_set_id: &str,
    operation: &'static str,
) -> Result<(), CapabilityApplyError> {
    let proof = (|| {
        sync_directory(&parent.directory)
            .map_err(|error| io_error("sync removed directory parent", path, &error))?;
        if optional_directory_state(&parent.directory, removed_name, path)?.is_some() {
            return Err(recovery_conflict(path, "removed directory absence", None));
        }
        applier.validate_roots()?;
        applier.verify_parent(parent)
    })();
    proof.map_err(|error| uncertain(change_set_id, Some(path.to_path_buf()), operation, error))
}

fn finish_absence_effect(
    applier: &CapabilitySafeApplier,
    parent: &ParentHandle,
    path: &Path,
    change_set_id: &str,
    operation: &'static str,
) -> Result<(), CapabilityApplyError> {
    let proof = (|| {
        sync_directory(&parent.directory)
            .map_err(|error| io_error("sync absent target parent", path, &error))?;
        if let Some(state) = optional_state(parent, path)? {
            return Err(recovery_conflict(path, "absent target", Some(state.digest)));
        }
        applier.validate_roots()?;
        applier.verify_parent(parent)
    })();
    proof.map_err(|error| uncertain(change_set_id, Some(path.to_path_buf()), operation, error))
}

fn maybe_fault(
    requested: Option<FaultPoint>,
    point: FaultPoint,
    affected_operations: usize,
) -> Result<(), CapabilityApplyError> {
    if requested == Some(point) {
        Err(CapabilityApplyError::InjectedCrash {
            affected_operations,
        })
    } else {
        Ok(())
    }
}

#[cfg(test)]
fn inject_no_replace_file_race(
    parent: &Dir,
    leaf: &OsStr,
    path: &Path,
) -> Result<(), CapabilityApplyError> {
    let mut options = OpenOptions::new();
    options
        .read(true)
        .write(true)
        .create_new(true)
        .mode(0o600)
        .follow(FollowSymlinks::No);
    let mut file = parent
        .open_with(leaf, &options)
        .map_err(|error| io_error("inject no-replace race target", path, &error))?;
    file.write_all(b"racing writer")
        .map_err(|error| io_error("write no-replace race target", path, &error))?;
    file.sync_all()
        .map_err(|error| io_error("sync no-replace race target", path, &error))?;
    sync_directory(parent).map_err(|error| io_error("sync no-replace race parent", path, &error))
}

fn recovery_conflict(path: &Path, expected: &str, actual: Option<Digest>) -> CapabilityApplyError {
    CapabilityApplyError::RecoveryConflict {
        path: path.to_path_buf(),
        expected: expected.into(),
        actual,
    }
}

fn uncertain(
    change_set_id: &str,
    path: Option<PathBuf>,
    operation: &'static str,
    error: impl Display,
) -> CapabilityApplyError {
    CapabilityApplyError::ReconciliationRequired {
        change_set_id: change_set_id.into(),
        path,
        operation,
        reason: error.to_string(),
    }
}

fn digest_from_output(output: &[u8]) -> Result<Digest, CapabilityApplyError> {
    Digest::parse(encode_hex(output)).map_err(|error| CapabilityApplyError::Blob(error.to_string()))
}

fn encode_hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;

    bytes.iter().fold(
        String::with_capacity(bytes.len().saturating_mul(2)),
        |mut encoded, byte| {
            let _ = write!(encoded, "{byte:02x}");
            encoded
        },
    )
}

fn decode_hex(value: &str) -> Result<Vec<u8>, CapabilityApplyError> {
    if !value.len().is_multiple_of(2) {
        return Err(CapabilityApplyError::Journal(
            "odd-length hexadecimal field".into(),
        ));
    }
    (0..value.len())
        .step_by(2)
        .map(|index| {
            u8::from_str_radix(&value[index..index + 2], 16)
                .map_err(|_| CapabilityApplyError::Journal("invalid hexadecimal field".into()))
        })
        .collect()
}

fn io_error(operation: &'static str, path: &Path, error: &impl Display) -> CapabilityApplyError {
    CapabilityApplyError::Io {
        operation,
        path: path.to_path_buf(),
        message: error.to_string(),
    }
}

#[cfg(test)]
mod tests;
