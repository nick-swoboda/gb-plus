//! Pure, deterministic, and deliberately non-authorizing application composition.
//!
//! This module derives a candidate base-to-final aggregate from already admitted
//! source projections. It owns no artifact bytes, runner handle, ledger permit,
//! publication effect, application authority, or completion authority. Every
//! public value in this module is forgeable input or an integrity-checkable plan.
//! A future role-sealed composer must reopen the exact immutable source bundles,
//! and the ledger must cross those observations with durable source authority,
//! before an `ApplicationArtifactCompositionReceiptV2` may gain authority.

use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fmt::{self, Display, Formatter};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::live_state::compute_workspace_manifest_digest;
use crate::{
    ChangeSet, DescriptorRelativeManifestEntry, Digest, FileOperation,
    MAX_DESCRIPTOR_RELATIVE_MANIFEST_ENTRIES, MAX_DESCRIPTOR_RELATIVE_MANIFEST_PATH_BYTES,
    TaskIntegrationArtifactReference,
};

/// Exact deterministic composer algorithm version used by the current additive generation.
pub const APPLICATION_ARTIFACT_COMPOSER_VERSION_V2: u32 = 2;
/// Exact stage-bundle format admitted by the v0.1 composition projection.
pub const COMPOSITION_SOURCE_BUNDLE_FORMAT_VERSION_V2: u32 = 1;
/// Maximum source projections in one v0.1 composition.
pub const MAX_COMPOSITION_SOURCES_V2: usize = 4_096;
/// Maximum source or aggregate operations/blobs in one v0.1 composition.
pub const MAX_COMPOSITION_OPERATIONS_V2: usize = 4_096;
/// Maximum exact bytes represented by one result blob.
pub const MAX_COMPOSITION_FILE_BYTES_V2: u64 = 16 * 1_048_576;
/// Maximum distinct result bytes in each source bundle or derived aggregate.
pub const MAX_COMPOSITION_TOTAL_BYTES_V2: u64 = 64 * 1_048_576;
/// Maximum cumulative result-blob bytes retained while reopening all sources.
///
/// The aggregate may require one additional copy of these bytes, so this caps
/// the composition publisher's trusted result-byte working set at roughly
/// 128 MiB plus bounded metadata.
pub const MAX_COMPOSITION_REOPENED_SOURCE_BYTES_V2: u64 = 64 * 1_048_576;
/// Maximum operations retained across all reopened source projections.
pub const MAX_COMPOSITION_REOPENED_SOURCE_OPERATIONS_V2: usize = 16_384;
/// Maximum canonical metadata retained across all reopened source projections.
pub const MAX_COMPOSITION_REOPENED_SOURCE_METADATA_BYTES_V2: usize = 8 * 1_048_576;
/// Maximum canonical metadata bytes admitted by the pure composition boundary.
pub const MAX_COMPOSITION_CANONICAL_INPUT_BYTES_V2: usize = 16 * 1_048_576;
/// Maximum UTF-8 bytes in one stable composition identifier.
pub const MAX_COMPOSITION_IDENTIFIER_BYTES_V2: usize = 256;

const BASE_PROJECTION_DIGEST_DOMAIN: &[u8] =
    b"grok-build/application-composition-base-projection/v2\0";
const SOURCE_IDENTITY_DOMAIN: &[u8] = b"grok-build/application-composition-source/v2\0";
const SOURCE_SET_DIGEST_DOMAIN: &[u8] = b"grok-build/application-composition-source-set/v2\0";
const CHANGE_SET_ID_DOMAIN: &[u8] = b"grok-build/application-composition-change-set/v2\0";
const RESULT_MATERIAL_DIGEST_DOMAIN: &[u8] =
    b"grok-build/application-composition-result-material/v2\0";
const DIRECTORY_STATE_DIGEST_DOMAIN: &[u8] =
    b"grok-build/application-composition-directory-state/v2\0";
const DERIVATION_RECORD_DOMAIN: &[u8] =
    b"grok-build/application-composition-derivation-record/v2\0";
const SOURCE_AUTHORITY_DIGEST_DOMAIN: &[u8] =
    b"grok-build/application-composition-source-authority/v2\0";
const SOURCE_AUTHORITY_SET_DIGEST_DOMAIN: &[u8] =
    b"grok-build/application-composition-source-authority-set/v2\0";
const PUBLICATION_CLAIM_DIGEST_DOMAIN: &[u8] =
    b"grok-build/application-composition-publication-claim/v2\0";
const SOURCE_READBACK_DIGEST_DOMAIN: &[u8] =
    b"grok-build/application-composition-source-readback/v2\0";
const AGGREGATE_READBACK_DIGEST_DOMAIN: &[u8] =
    b"grok-build/application-composition-aggregate-readback/v2\0";
const PUBLICATION_CLOSURE_OBSERVATION_DIGEST_DOMAIN: &[u8] =
    b"grok-build/application-composition-publication-closure/v2\0";
const COMPOSITION_RECEIPT_DIGEST_DOMAIN: &[u8] =
    b"grok-build/application-artifact-composition-receipt/v2\0";

/// Closed reason that a path cannot participate in portable composition.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PortablePathConflictKind {
    /// The path cannot be represented as exact UTF-8.
    NonUtf8,
    /// The path is empty or absolute.
    EmptyOrAbsolute,
    /// The path uses a backslash or contains a NUL byte.
    NonPortableSeparatorOrNul,
    /// One component is empty, dot, parent, or protected `.git`.
    InvalidComponent,
    /// The UTF-8 path exceeds the repository portable-manifest bound.
    TooLong,
}

/// Closed source digest whose substitution was detected.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CompositionSourceDigestKind {
    /// Digest of exact ordered source operations.
    OrderedOperations,
    /// Digest of ordered touched base/result endpoints.
    TouchedEndpoints,
    /// Digest of the complete non-authorizing source projection.
    SourceIdentity,
}

/// Closed invalid source-`ChangeSet` shape.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CompositionSourceShapeConflict {
    /// The source change-set identity is blank.
    BlankChangeSetId,
    /// Empty operations and equal snapshots do not agree exactly.
    SnapshotOperationDisagreement,
    /// A `Modify` carries identical base and result hashes.
    NoOpModify,
    /// The source does not carry the one admitted stage-bundle version.
    InvalidArtifactVersion,
}

/// Closed filesystem endpoint class used by typed topology failures.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CompositionEndpointKindV2 {
    /// A regular-file endpoint.
    RegularFile,
    /// A directory endpoint, including an empty directory.
    Directory,
}

/// Typed deterministic composition failure.
#[derive(Clone, Debug, Eq, PartialEq)]
#[allow(
    missing_docs,
    reason = "closed conflict variants document their complete field tuple at the variant"
)]
pub enum CompositionConflict {
    /// A required stable identity is blank.
    InvalidIdentifier { field: &'static str },
    /// A contract carries a composer version other than the admitted version.
    UnsupportedComposerVersion { field: &'static str, observed: u32 },
    /// A bounded collection contains too many members.
    LimitExceeded {
        field: &'static str,
        maximum: usize,
        observed: usize,
    },
    /// A bounded byte total is too large.
    ByteLimitExceeded {
        field: &'static str,
        maximum: u64,
        observed: u64,
    },
    /// Checked accounting overflowed before a limit comparison.
    AccountingOverflow { field: &'static str },
    /// A base-tree or operation path is not portable.
    InvalidPortablePath {
        source_ordinal: Option<u32>,
        path: String,
        kind: PortablePathConflictKind,
    },
    /// A canonical path vector is duplicated or out of byte order.
    NonCanonicalPathOrder {
        field: &'static str,
        previous: String,
        current: String,
    },
    /// A stable source member identity is duplicated.
    DuplicateSourceMember { field: &'static str, value: String },
    /// A directory projection omits one required ancestor.
    IncompleteDirectoryProjection {
        path: String,
        missing_ancestor: String,
    },
    /// A directory and regular file claim the same endpoint or a file ancestor.
    BaseTopologyConflict {
        path: String,
        conflicting_path: String,
    },
    /// The base regular-file entries do not produce the claimed snapshot.
    BaseSnapshotDigestMismatch { claimed: Digest, computed: Digest },
    /// The base projection digest differs from its complete exact projection.
    BaseProjectionDigestMismatch { claimed: Digest, computed: Digest },
    /// The base projection belongs to another snapshot.
    BaseProjectionSnapshotMismatch { expected: Digest, observed: Digest },
    /// The admitted source-set digest differs from its complete ordered IDs.
    SourceSetDigestMismatch { claimed: Digest, computed: Digest },
    /// Reopened source projections are missing or extra.
    SourceCoverageCountMismatch { expected: usize, observed: usize },
    /// A reopened source differs from the admitted identity at its ordinal.
    SourceCoverageIdentityMismatch {
        ordinal: u32,
        expected: Digest,
        observed: Digest,
    },
    /// Source ordinals are not contiguous from zero.
    SourceOrdinalMismatch { expected: u32, observed: u32 },
    /// A source input or terminal snapshot breaks the ordered chain.
    SnapshotChainMismatch {
        source_ordinal: Option<u32>,
        expected: Digest,
        observed: Digest,
    },
    /// Exact replay does not produce a source's claimed result snapshot.
    SourceResultSnapshotDigestMismatch {
        ordinal: u32,
        claimed: Digest,
        computed: Digest,
    },
    /// Exact final replay does not produce the admitted final snapshot.
    FinalSnapshotDigestMismatch { claimed: Digest, computed: Digest },
    /// A source `ChangeSet` or artifact crosses its outer source fields.
    SourceBindingMismatch { ordinal: u32, field: &'static str },
    /// A source contains an invalid immutable `ChangeSet` shape.
    InvalidSourceShape {
        ordinal: u32,
        kind: CompositionSourceShapeConflict,
    },
    /// A source digest differs from exact canonical source material.
    SourceDigestMismatch {
        ordinal: u32,
        kind: CompositionSourceDigestKind,
        claimed: Digest,
        computed: Digest,
    },
    /// One source addresses the same exact path more than once.
    DuplicateOperation { ordinal: u32, path: String },
    /// Result material is missing, extra, crossed, or malformed.
    ResultMaterialMismatch {
        source_ordinal: Option<u32>,
        operation_index: Option<u32>,
        field: &'static str,
    },
    /// The same digest is paired with incompatible byte lengths.
    ResultBlobLengthConflict {
        digest: Digest,
        first: u64,
        second: u64,
    },
    /// `Create` targets an occupied endpoint.
    CreateOverPresent {
        ordinal: Option<u32>,
        path: String,
        kind: CompositionEndpointKindV2,
    },
    /// `Modify` targets an absent or non-regular endpoint.
    ModifyOverInvalidEndpoint {
        ordinal: Option<u32>,
        path: String,
        observed: Option<CompositionEndpointKindV2>,
    },
    /// `Delete` targets an absent or non-regular endpoint.
    DeleteOverInvalidEndpoint {
        ordinal: Option<u32>,
        path: String,
        observed: Option<CompositionEndpointKindV2>,
    },
    /// A modify/delete base hash differs from the replayed endpoint.
    BaseHashMismatch {
        ordinal: Option<u32>,
        path: String,
        expected: Digest,
        observed: Digest,
    },
    /// A regular file conflicts with a path that must be a directory.
    FileAncestorCollision {
        source_ordinal: Option<u32>,
        path: String,
        conflicting_path: String,
    },
    /// Base-to-final mode drift cannot be represented by ordinary `Modify`.
    UnrepresentableModeTransition {
        path: String,
        base_mode: u32,
        result_mode: u32,
    },
    /// Equal content digests with unequal lengths cannot be represented safely.
    UnrepresentableLengthTransition {
        path: String,
        digest: Digest,
        base_length: u64,
        result_length: u64,
    },
    /// Canonical aggregate replay does not reproduce sequential topology/state.
    UnrepresentableAggregateTopology {
        path: Option<String>,
        reason: &'static str,
    },
    /// Derived operation emptiness disagrees with base/final snapshot identity.
    AggregateSnapshotMismatch {
        base_snapshot: Digest,
        result_snapshot: Digest,
        operations_empty: bool,
    },
    /// An integrity-only plan record or relationship was substituted.
    DerivationRecordMismatch { field: &'static str },
    /// A caller-manufacturable publication claim crossed one of its bindings.
    PublicationClaimMismatch { field: &'static str },
    /// A source or aggregate readback claim crossed its publication claim.
    PublicationReadbackMismatch { field: &'static str },
    /// An integrity-checkable composition receipt crossed its exact backing.
    CompositionReceiptMismatch { field: &'static str },
    /// Canonical JSON encoding unexpectedly failed.
    CanonicalEncoding { field: &'static str, reason: String },
    /// Exact workspace-manifest-v1 computation failed.
    WorkspaceManifest { field: &'static str, reason: String },
}

impl Display for CompositionConflict {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        write!(formatter, "application composition conflict: {self:?}")
    }
}

impl Error for CompositionConflict {}

/// One complete regular-file endpoint in the non-authorizing base projection.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CompositionBaseFileV2 {
    /// Normalized portable UTF-8 slash path relative to the workspace root.
    pub path: String,
    /// Exact complete regular-file content digest.
    pub content_digest: Digest,
    /// Exact regular-file byte length committed by workspace-manifest-v1.
    pub byte_length: u64,
    /// Exact normalized Unix permission bits committed by workspace-manifest-v1.
    pub unix_mode: u32,
}

/// One directory occupancy entry in the complete base projection.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CompositionBaseDirectoryV2 {
    /// Normalized portable UTF-8 slash path, excluding the workspace root.
    pub path: String,
}

/// Complete integrity-checkable base projection for pure derivation.
///
/// This value is not evidence that a runner captured these entries. The future
/// composition authority path must join it to a role-sealed descriptor capture.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NonAuthorizingCompositionBaseProjectionV2 {
    /// Required deterministic composer version.
    pub composer_version: u32,
    /// Workspace-manifest-v1 snapshot represented by `files`.
    pub snapshot: Digest,
    /// Complete regular files in strict portable-path byte order.
    pub files: Vec<CompositionBaseFileV2>,
    /// Complete directory occupancy, excluding root, in strict byte order.
    pub directories: Vec<CompositionBaseDirectoryV2>,
    /// Domain-separated digest of snapshot, files, and directory occupancy.
    pub projection_digest: Digest,
}

impl NonAuthorizingCompositionBaseProjectionV2 {
    /// Constructs an integrity-checkable, explicitly non-authorizing projection.
    ///
    /// # Errors
    ///
    /// Returns a typed [`CompositionConflict`] when the projection is not a
    /// complete canonical workspace shape or its bounded encoding cannot be
    /// derived.
    pub fn try_new_non_authorizing(
        snapshot: Digest,
        files: Vec<CompositionBaseFileV2>,
        directories: Vec<CompositionBaseDirectoryV2>,
    ) -> Result<Self, CompositionConflict> {
        validate_base_projection_shape(&snapshot, &files, &directories)?;
        let projection_digest = compute_base_projection_digest(&snapshot, &files, &directories)?;
        let projection = Self {
            composer_version: APPLICATION_ARTIFACT_COMPOSER_VERSION_V2,
            snapshot,
            files,
            directories,
            projection_digest,
        };
        projection.validate_integrity()?;
        Ok(projection)
    }

    /// Recomputes structural, snapshot, and projection digests only.
    ///
    /// Success is not proof that a runner observed this projection.
    ///
    /// # Errors
    ///
    /// Returns a typed [`CompositionConflict`] when any shape, snapshot,
    /// digest, version, or canonical-size invariant is violated.
    pub fn validate_integrity(&self) -> Result<(), CompositionConflict> {
        require_composer_version("base_projection.composer_version", self.composer_version)?;
        validate_base_projection_shape(&self.snapshot, &self.files, &self.directories)?;
        let computed =
            compute_base_projection_digest(&self.snapshot, &self.files, &self.directories)?;
        if self.projection_digest != computed {
            return Err(CompositionConflict::BaseProjectionDigestMismatch {
                claimed: self.projection_digest.clone(),
                computed,
            });
        }
        require_canonical_size(
            "base_projection",
            self,
            MAX_COMPOSITION_CANONICAL_INPUT_BYTES_V2,
        )
    }
}

/// Latest passing final-verification identity projected into pure composition.
///
/// This is data, not proof that the ledger admitted or passed the attempt.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CompositionFinalVerificationBindingV2 {
    /// Exact final-verification attempt identity.
    pub attempt_id: String,
    /// Digest of the complete immutable attempt authority and terminal proof.
    pub attempt_authority_digest: Digest,
    /// Exact snapshot passed by the attempt.
    pub snapshot: Digest,
    /// Complete same-snapshot criterion-evidence-set digest.
    pub complete_criterion_evidence_set_digest: Digest,
}

impl CompositionFinalVerificationBindingV2 {
    fn validate_integrity(&self) -> Result<(), CompositionConflict> {
        require_identifier(
            "composition_inputs.final_verification.attempt_id",
            &self.attempt_id,
        )
    }
}

/// Complete non-authorizing inputs against which pure composition is derived.
///
/// Only a ledger query over durable current-generation rows may turn equivalent
/// data into a private composition permit. This public projection cannot do so.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NonAuthorizingApplicationCompositionInputsV2 {
    /// Required deterministic composer version.
    pub composer_version: u32,
    /// Owning sprint identity.
    pub sprint_id: String,
    /// Exact original sprint snapshot.
    pub base_snapshot: Digest,
    /// Exact latest passing final-verification snapshot.
    pub result_snapshot: Digest,
    /// Digest of the complete current `TaskDone` set.
    pub complete_task_done_set_digest: Digest,
    /// Projected final-verification binding.
    pub final_verification: CompositionFinalVerificationBindingV2,
    /// Exact complete source identities in integration order.
    pub expected_source_identities: Vec<Digest>,
    /// Digest of ordered identities plus the complete `TaskDone` set.
    pub source_set_digest: Digest,
}

impl NonAuthorizingApplicationCompositionInputsV2 {
    /// Constructs integrity-checkable inputs without minting ledger authority.
    ///
    /// # Errors
    ///
    /// Returns a typed [`CompositionConflict`] when source coverage is empty,
    /// duplicated, non-canonical, or the resulting input projection is invalid.
    pub fn try_new_non_authorizing(
        sprint_id: impl Into<String>,
        base_snapshot: Digest,
        result_snapshot: Digest,
        complete_task_done_set_digest: Digest,
        final_verification: CompositionFinalVerificationBindingV2,
        expected_source_identities: Vec<Digest>,
    ) -> Result<Self, CompositionConflict> {
        let sprint_id = sprint_id.into();
        validate_source_identity_set(&expected_source_identities)?;
        let source_set_digest = compute_source_set_digest(
            &sprint_id,
            &complete_task_done_set_digest,
            &expected_source_identities,
        )?;
        let inputs = Self {
            composer_version: APPLICATION_ARTIFACT_COMPOSER_VERSION_V2,
            sprint_id,
            base_snapshot,
            result_snapshot,
            complete_task_done_set_digest,
            final_verification,
            expected_source_identities,
            source_set_digest,
        };
        inputs.validate_integrity()?;
        Ok(inputs)
    }

    /// Revalidates only the internal shape and digest relationships.
    ///
    /// # Errors
    ///
    /// Returns a typed [`CompositionConflict`] when identity, version,
    /// snapshot-chain, source-set, or canonical-size checks fail.
    pub fn validate_integrity(&self) -> Result<(), CompositionConflict> {
        require_composer_version("composition_inputs.composer_version", self.composer_version)?;
        require_identifier("composition_inputs.sprint_id", &self.sprint_id)?;
        self.final_verification.validate_integrity()?;
        if self.final_verification.snapshot != self.result_snapshot {
            return Err(CompositionConflict::SnapshotChainMismatch {
                source_ordinal: None,
                expected: self.result_snapshot.clone(),
                observed: self.final_verification.snapshot.clone(),
            });
        }
        validate_source_identity_set(&self.expected_source_identities)?;
        let computed = compute_source_set_digest(
            &self.sprint_id,
            &self.complete_task_done_set_digest,
            &self.expected_source_identities,
        )?;
        if self.source_set_digest != computed {
            return Err(CompositionConflict::SourceSetDigestMismatch {
                claimed: self.source_set_digest.clone(),
                computed,
            });
        }
        require_canonical_size(
            "composition_inputs",
            self,
            MAX_COMPOSITION_CANONICAL_INPUT_BYTES_V2,
        )
    }
}

/// Operation kind and the only metadata lawful for reopened result material.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum CompositionResultMaterialKindV2 {
    /// A newly created file carries its exact normalized mode.
    Create {
        /// Exact normalized Unix permission bits for the new file.
        unix_mode: u32,
    },
    /// A modification inherits the exact replayed base mode.
    Modify,
}

/// Exact metadata projected from one reopened source result blob.
///
/// This value contains no bytes and is not proof of reopening. Its source
/// artifact link allows a role-sealed publisher to reopen and verify those bytes.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CompositionResultMaterialV2 {
    /// Index of the matching Create/Modify operation in exact source order.
    pub operation_index: u32,
    /// Exact portable operation target.
    pub path: String,
    /// Exact SHA-256 digest of reopened result bytes.
    pub result_digest: Digest,
    /// Exact reopened byte length.
    pub byte_length: u64,
    /// Create/modify metadata shape corresponding to the operation.
    pub operation_kind: CompositionResultMaterialKindV2,
    /// Exact source artifact whose reopened blob supplies the result bytes.
    pub source_artifact_digest: Digest,
}

/// One non-authorizing projection of an exact reopened task-integration source.
///
/// The type deliberately does not claim that reopening occurred. A future
/// role-sealed runner observation and durable ledger join are mandatory.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NonAuthorizingApplicationCompositionSourceV2 {
    /// Required deterministic composer version.
    pub composer_version: u32,
    /// Domain-separated digest of every remaining source field.
    pub source_identity: Digest,
    /// Contiguous integration ordinal beginning at zero.
    pub ordinal: u32,
    /// Exact graph task identity.
    pub task_id: String,
    /// Exact winning task-attempt identity.
    pub attempt_id: String,
    /// Exact current `TaskDone` proof identity.
    pub task_done_proof_id: String,
    /// Digest of the complete `TaskDone` proof.
    pub task_done_proof_digest: Digest,
    /// Exact successful integration-receipt identity.
    pub integration_receipt_id: String,
    /// Digest of the complete integration receipt.
    pub integration_receipt_digest: Digest,
    /// Source input snapshot.
    pub input_snapshot: Digest,
    /// Source result snapshot.
    pub result_snapshot: Digest,
    /// Exact source change set with ordered operations.
    pub change_set: ChangeSet,
    /// Path-free artifact reference projected for later role-sealed reopening.
    pub artifact: TaskIntegrationArtifactReference,
    /// Exact metadata for every Create/Modify operation in operation order.
    pub result_material: Vec<CompositionResultMaterialV2>,
    /// Digest of exact ordered operations.
    pub ordered_operations_digest: Digest,
    /// Digest of exact ordered touched endpoints.
    pub touched_endpoints_digest: Digest,
}

impl NonAuthorizingApplicationCompositionSourceV2 {
    /// Constructs a digest-bound projection without claiming artifact reopening.
    ///
    /// # Errors
    ///
    /// Returns a typed [`CompositionConflict`] when source identifiers,
    /// operations, material locators, bounds, or derived digests are invalid.
    #[allow(
        clippy::too_many_arguments,
        reason = "each independent immutable-source identity remains explicit"
    )]
    pub fn try_new_non_authorizing(
        ordinal: u32,
        task_id: impl Into<String>,
        attempt_id: impl Into<String>,
        task_done_proof_id: impl Into<String>,
        task_done_proof_digest: Digest,
        integration_receipt_id: impl Into<String>,
        integration_receipt_digest: Digest,
        change_set: ChangeSet,
        artifact: TaskIntegrationArtifactReference,
        result_material: Vec<CompositionResultMaterialV2>,
    ) -> Result<Self, CompositionConflict> {
        let mut source = Self {
            composer_version: APPLICATION_ARTIFACT_COMPOSER_VERSION_V2,
            source_identity: Digest::sha256(&[]),
            ordinal,
            task_id: task_id.into(),
            attempt_id: attempt_id.into(),
            task_done_proof_id: task_done_proof_id.into(),
            task_done_proof_digest,
            integration_receipt_id: integration_receipt_id.into(),
            integration_receipt_digest,
            input_snapshot: change_set.base_snapshot.clone(),
            result_snapshot: change_set.result_snapshot.clone(),
            change_set,
            artifact,
            result_material,
            ordered_operations_digest: Digest::sha256(&[]),
            touched_endpoints_digest: Digest::sha256(&[]),
        };
        validate_source_shape(&source)?;
        source.ordered_operations_digest = source
            .change_set
            .applied_operations_digest()
            .map_err(|error| canonical_contract_error("composition_source.operations", error))?;
        source.touched_endpoints_digest = source
            .change_set
            .touched_path_endpoints_digest()
            .map_err(|error| canonical_contract_error("composition_source.endpoints", error))?;
        source.source_identity = compute_source_identity(&source)?;
        source.validate_integrity()?;
        Ok(source)
    }

    /// Recomputes only shape and digest relationships; it does not reopen bytes.
    ///
    /// # Errors
    ///
    /// Returns a typed [`CompositionConflict`] when shape, digest, version, or
    /// canonical-size checks fail.
    pub fn validate_integrity(&self) -> Result<(), CompositionConflict> {
        validate_source_without_identity(self)?;
        let computed = compute_source_identity(self)?;
        if self.source_identity != computed {
            return Err(CompositionConflict::SourceDigestMismatch {
                ordinal: self.ordinal,
                kind: CompositionSourceDigestKind::SourceIdentity,
                claimed: self.source_identity.clone(),
                computed,
            });
        }
        require_canonical_size(
            "composition_source",
            self,
            MAX_COMPOSITION_CANONICAL_INPUT_BYTES_V2,
        )
    }
}

/// Exact material locator required to assemble one aggregate result blob.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AggregateCompositionResultMaterialV2 {
    /// Index of the matching Create/Modify operation in canonical aggregate order.
    pub operation_index: u32,
    /// Exact portable operation target.
    pub path: String,
    /// Exact result-content digest.
    pub result_digest: Digest,
    /// Exact result-content byte length.
    pub byte_length: u64,
    /// Present exactly for an aggregate `Create`; absent for `Modify`.
    pub create_mode: Option<u32>,
    /// Source ordinal from which the publisher must reopen result bytes.
    pub source_ordinal: u32,
    /// Exact source artifact from which the publisher must reopen result bytes.
    pub source_artifact_digest: Digest,
}

/// Integrity-only derivation record; never an application composition receipt.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NonAuthorizingCompositionDerivationRecordV2 {
    /// Required deterministic composer version.
    pub composer_version: u32,
    /// Owning sprint identity.
    pub sprint_id: String,
    /// Exact authenticated base snapshot identifier.
    pub base_snapshot: Digest,
    /// Exact derived result snapshot identifier.
    pub result_snapshot: Digest,
    /// Complete base file-and-directory projection digest.
    pub base_projection_digest: Digest,
    /// Complete ordered source-set digest.
    pub source_set_digest: Digest,
    /// Complete current `TaskDone` set digest.
    pub complete_task_done_set_digest: Digest,
    /// Latest passing final-verification projection.
    pub final_verification: CompositionFinalVerificationBindingV2,
    /// Deterministic aggregate change-set identity.
    pub aggregate_change_set_id: String,
    /// Digest of canonical aggregate operations.
    pub aggregate_operations_digest: Digest,
    /// Digest of aggregate touched endpoints.
    pub aggregate_touched_endpoints_digest: Digest,
    /// Digest of exact aggregate result-material locators and modes.
    pub aggregate_result_material_digest: Digest,
    /// Digest of canonical aggregate-replay directory occupancy.
    pub final_directory_state_digest: Digest,
    /// True exactly when the aggregate operation vector is empty.
    pub aggregate_no_op: bool,
    /// Integrity checksum of every preceding field.
    pub record_digest: Digest,
}

impl NonAuthorizingCompositionDerivationRecordV2 {
    /// Recomputes this record's own checksum only; it proves no source authority.
    ///
    /// # Errors
    ///
    /// Returns a typed [`CompositionConflict`] when the record version,
    /// identifiers, snapshot relationships, no-op claim, or checksum differ.
    pub fn validate_integrity(&self) -> Result<(), CompositionConflict> {
        require_composer_version("derivation_record.composer_version", self.composer_version)?;
        require_identifier("derivation_record.sprint_id", &self.sprint_id)?;
        require_identifier(
            "derivation_record.aggregate_change_set_id",
            &self.aggregate_change_set_id,
        )?;
        self.final_verification.validate_integrity()?;
        if self.final_verification.snapshot != self.result_snapshot {
            return Err(CompositionConflict::DerivationRecordMismatch {
                field: "final_verification.snapshot",
            });
        }
        if self.aggregate_no_op != (self.base_snapshot == self.result_snapshot) {
            return Err(CompositionConflict::DerivationRecordMismatch {
                field: "aggregate_no_op",
            });
        }
        let computed = compute_derivation_record_digest(self)?;
        if self.record_digest != computed {
            return Err(CompositionConflict::DerivationRecordMismatch {
                field: "record_digest",
            });
        }
        Ok(())
    }
}

/// Pure integrity-checkable plan. It carries no publication or application permit.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NonAuthorizingApplicationCompositionPlanV2 {
    /// Canonical base-to-final aggregate change set.
    pub change_set: ChangeSet,
    /// Exact result-byte source and create-mode plan for aggregate assembly.
    pub result_material: Vec<AggregateCompositionResultMaterialV2>,
    /// Exact logical directory occupancy produced by canonical aggregate replay.
    pub final_directories: Vec<String>,
    /// Integrity-only derivation record, never publication authority.
    pub derivation_record: NonAuthorizingCompositionDerivationRecordV2,
}

impl NonAuthorizingApplicationCompositionPlanV2 {
    /// Validates internal plan relationships only. This is not source readback.
    ///
    /// # Errors
    ///
    /// Returns a typed [`CompositionConflict`] when aggregate operations,
    /// material, directories, or their derivation-record bindings differ.
    pub fn validate_integrity(&self) -> Result<(), CompositionConflict> {
        self.change_set
            .validate()
            .map_err(|_| CompositionConflict::DerivationRecordMismatch {
                field: "change_set",
            })?;
        validate_aggregate_operation_order(&self.change_set.operations)?;
        validate_aggregate_result_material(&self.change_set.operations, &self.result_material)?;
        validate_aggregate_bounds(&self.change_set.operations, &self.result_material)?;
        validate_directory_state(&self.final_directories)?;
        self.derivation_record.validate_integrity()?;
        if self.change_set.change_set_id != self.derivation_record.aggregate_change_set_id
            || self.change_set.base_snapshot != self.derivation_record.base_snapshot
            || self.change_set.result_snapshot != self.derivation_record.result_snapshot
            || self.change_set.operations.is_empty() != self.derivation_record.aggregate_no_op
        {
            return Err(CompositionConflict::DerivationRecordMismatch {
                field: "change_set_relationship",
            });
        }
        let operations_digest = self
            .change_set
            .applied_operations_digest()
            .map_err(|error| canonical_contract_error("composition.operations", error))?;
        let endpoints_digest = self
            .change_set
            .touched_path_endpoints_digest()
            .map_err(|error| canonical_contract_error("composition.endpoints", error))?;
        let material_digest = compute_result_material_digest(&self.result_material)?;
        let directory_digest = compute_directory_state_digest(&self.final_directories)?;
        if operations_digest != self.derivation_record.aggregate_operations_digest {
            return Err(CompositionConflict::DerivationRecordMismatch {
                field: "aggregate_operations_digest",
            });
        }
        if endpoints_digest != self.derivation_record.aggregate_touched_endpoints_digest {
            return Err(CompositionConflict::DerivationRecordMismatch {
                field: "aggregate_touched_endpoints_digest",
            });
        }
        if material_digest != self.derivation_record.aggregate_result_material_digest {
            return Err(CompositionConflict::DerivationRecordMismatch {
                field: "aggregate_result_material_digest",
            });
        }
        if directory_digest != self.derivation_record.final_directory_state_digest {
            return Err(CompositionConflict::DerivationRecordMismatch {
                field: "final_directory_state_digest",
            });
        }
        let change_set_id = compute_aggregate_change_set_id_from_fields(
            self.derivation_record.composer_version,
            &self.derivation_record.sprint_id,
            &self.derivation_record.base_snapshot,
            &self.derivation_record.result_snapshot,
            &self.derivation_record.source_set_digest,
            &self.change_set.operations,
        )?
        .to_string();
        if change_set_id != self.change_set.change_set_id {
            return Err(CompositionConflict::DerivationRecordMismatch {
                field: "aggregate_change_set_id",
            });
        }
        Ok(())
    }
}

/// Caller-manufacturable projection of one durable source authority.
///
/// This DTO identifies what a future ledger admission must authenticate. Its
/// constructor and digest prove only internal consistency; neither asserts that
/// the source exists, is current, was integrated, or may be published.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NonAuthorizingApplicationCompositionSourceAuthorityV2 {
    /// Required deterministic composer version.
    pub composer_version: u32,
    /// Contiguous source ordinal expected by the publication claim.
    pub ordinal: u32,
    /// Exact graph task identity.
    pub task_id: String,
    /// Exact winning task-attempt identity.
    pub attempt_id: String,
    /// Exact current `TaskDone` proof identity.
    pub task_done_proof_id: String,
    /// Digest of the complete `TaskDone` proof.
    pub task_done_proof_digest: Digest,
    /// Exact successful integration receipt identity.
    pub integration_receipt_id: String,
    /// Digest of the complete integration receipt.
    pub integration_receipt_digest: Digest,
    /// Immutable path-free stage-bundle identity to reopen.
    pub artifact: TaskIntegrationArtifactReference,
    /// Exact sum of unique result-blob bytes expected when reopening this bundle.
    pub reopened_result_blob_bytes: u64,
    /// Exact operation count expected in the reopened source projection.
    pub source_operation_count: u32,
    /// Domain-separated digest over every preceding field.
    pub source_authority_digest: Digest,
}

impl NonAuthorizingApplicationCompositionSourceAuthorityV2 {
    /// Constructs an integrity-checkable source-authority projection.
    ///
    /// # Errors
    ///
    /// Returns a typed conflict for invalid identifiers, artifact shape,
    /// composer version, digest relationship, or canonical-size bounds.
    #[allow(
        clippy::too_many_arguments,
        reason = "each independent durable source identity remains explicit"
    )]
    pub fn try_new_non_authorizing(
        ordinal: u32,
        task_id: impl Into<String>,
        attempt_id: impl Into<String>,
        task_done_proof_id: impl Into<String>,
        task_done_proof_digest: Digest,
        integration_receipt_id: impl Into<String>,
        integration_receipt_digest: Digest,
        artifact: TaskIntegrationArtifactReference,
        reopened_result_blob_bytes: u64,
        source_operation_count: u32,
    ) -> Result<Self, CompositionConflict> {
        let mut source = Self {
            composer_version: APPLICATION_ARTIFACT_COMPOSER_VERSION_V2,
            ordinal,
            task_id: task_id.into(),
            attempt_id: attempt_id.into(),
            task_done_proof_id: task_done_proof_id.into(),
            task_done_proof_digest,
            integration_receipt_id: integration_receipt_id.into(),
            integration_receipt_digest,
            artifact,
            reopened_result_blob_bytes,
            source_operation_count,
            source_authority_digest: Digest::sha256(&[]),
        };
        validate_source_authority_without_digest(&source)?;
        source.source_authority_digest = compute_source_authority_digest(&source)?;
        source.validate_integrity()?;
        Ok(source)
    }

    /// Recomputes shape, size, and digest relationships only.
    ///
    /// # Errors
    ///
    /// Returns a typed conflict for any malformed or substituted field.
    pub fn validate_integrity(&self) -> Result<(), CompositionConflict> {
        validate_source_authority_without_digest(self)?;
        if self.source_authority_digest != compute_source_authority_digest(self)? {
            return Err(CompositionConflict::PublicationClaimMismatch {
                field: "source_authority_digest",
            });
        }
        require_canonical_size(
            "composition_source_authority",
            self,
            MAX_COMPOSITION_CANONICAL_INPUT_BYTES_V2,
        )
    }
}

/// Complete caller-manufacturable claim for current-generation additive composition.
///
/// The nested inputs bind sprint, complete current `TaskDone` set, expected
/// source identities, and the projected latest final-verification attempt with
/// its same-snapshot criterion set. The base projection and ordered source
/// authorities complete the claim. No constructor or validation result proves
/// ledger admission, attempt latestness, source reopening, or publication
/// permission; a future role-sealed ledger permit must establish those facts.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NonAuthorizingApplicationCompositionPublicationClaimV2 {
    /// Required deterministic composer version.
    pub composer_version: u32,
    /// Stable publication identity selected before any publication effect.
    pub publication_id: String,
    /// Complete non-authorizing sprint/final-verification/source-set inputs.
    pub inputs: NonAuthorizingApplicationCompositionInputsV2,
    /// Complete non-authorizing authenticated-base projection.
    pub base: NonAuthorizingCompositionBaseProjectionV2,
    /// Complete source authorities in contiguous integration order.
    pub sources: Vec<NonAuthorizingApplicationCompositionSourceAuthorityV2>,
    /// Digest of exact ordered source-authority digests and admitted source IDs.
    pub source_authority_set_digest: Digest,
    /// Domain-separated digest over every preceding field.
    pub publication_claim_digest: Digest,
}

impl NonAuthorizingApplicationCompositionPublicationClaimV2 {
    /// Constructs a complete integrity-checkable publication claim.
    ///
    /// # Errors
    ///
    /// Returns a typed conflict for crossed base/result snapshots, source
    /// ordinals or identities, duplicates, bounds, or digest relationships.
    pub fn try_new_non_authorizing(
        publication_id: impl Into<String>,
        inputs: NonAuthorizingApplicationCompositionInputsV2,
        base: NonAuthorizingCompositionBaseProjectionV2,
        sources: Vec<NonAuthorizingApplicationCompositionSourceAuthorityV2>,
    ) -> Result<Self, CompositionConflict> {
        let mut claim = Self {
            composer_version: APPLICATION_ARTIFACT_COMPOSER_VERSION_V2,
            publication_id: publication_id.into(),
            inputs,
            base,
            sources,
            source_authority_set_digest: Digest::sha256(&[]),
            publication_claim_digest: Digest::sha256(&[]),
        };
        validate_publication_claim_without_digests(&claim)?;
        claim.source_authority_set_digest = compute_source_authority_set_digest(&claim)?;
        claim.publication_claim_digest = compute_publication_claim_digest(&claim)?;
        claim.validate_integrity()?;
        Ok(claim)
    }

    /// Recomputes the complete claim without granting publication authority.
    ///
    /// # Errors
    ///
    /// Returns a typed conflict for any malformed, crossed, oversized, or
    /// digest-inconsistent field.
    pub fn validate_integrity(&self) -> Result<(), CompositionConflict> {
        validate_publication_claim_without_digests(self)?;
        if self.source_authority_set_digest != compute_source_authority_set_digest(self)? {
            return Err(CompositionConflict::PublicationClaimMismatch {
                field: "source_authority_set_digest",
            });
        }
        if self.publication_claim_digest != compute_publication_claim_digest(self)? {
            return Err(CompositionConflict::PublicationClaimMismatch {
                field: "publication_claim_digest",
            });
        }
        require_canonical_size(
            "composition_publication_claim",
            self,
            MAX_COMPOSITION_CANONICAL_INPUT_BYTES_V2,
        )
    }
}

/// Canonical claim that exact source bundles were reopened into full source
/// projections. This value is still caller-manufacturable and non-authorizing.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NonAuthorizingApplicationCompositionSourceReadbackV2 {
    /// Required deterministic composer version.
    pub composer_version: u32,
    /// Exact publication claim against which reopening was performed.
    pub publication_claim_digest: Digest,
    /// Complete reopened source projections in contiguous order.
    pub sources: Vec<NonAuthorizingApplicationCompositionSourceV2>,
    /// Domain-separated digest over every preceding field.
    pub source_readback_digest: Digest,
}

impl NonAuthorizingApplicationCompositionSourceReadbackV2 {
    /// Constructs a source-readback claim and crosses it with a publication claim.
    ///
    /// # Errors
    ///
    /// Returns a typed conflict for missing, extra, reordered, crossed,
    /// malformed, or oversized sources.
    pub fn try_new_non_authorizing(
        claim: &NonAuthorizingApplicationCompositionPublicationClaimV2,
        sources: Vec<NonAuthorizingApplicationCompositionSourceV2>,
    ) -> Result<Self, CompositionConflict> {
        claim.validate_integrity()?;
        let mut readback = Self {
            composer_version: APPLICATION_ARTIFACT_COMPOSER_VERSION_V2,
            publication_claim_digest: claim.publication_claim_digest.clone(),
            sources,
            source_readback_digest: Digest::sha256(&[]),
        };
        validate_source_readback_against_claim_without_digest(&readback, claim)?;
        readback.source_readback_digest = compute_source_readback_digest(&readback)?;
        readback.validate_against_non_authorizing(claim)?;
        Ok(readback)
    }

    /// Recomputes this readback's own shape and digest only.
    ///
    /// # Errors
    ///
    /// Returns a typed conflict for invalid sources, bounds, or checksum.
    pub fn validate_integrity(&self) -> Result<(), CompositionConflict> {
        require_composer_version("source_readback.composer_version", self.composer_version)?;
        if self.sources.is_empty() || self.sources.len() > MAX_COMPOSITION_SOURCES_V2 {
            return Err(CompositionConflict::LimitExceeded {
                field: "source_readback.sources",
                maximum: MAX_COMPOSITION_SOURCES_V2,
                observed: self.sources.len(),
            });
        }
        for source in &self.sources {
            source.validate_integrity()?;
        }
        if self.source_readback_digest != compute_source_readback_digest(self)? {
            return Err(CompositionConflict::PublicationReadbackMismatch {
                field: "source_readback_digest",
            });
        }
        require_canonical_size(
            "composition_source_readback",
            self,
            MAX_COMPOSITION_CANONICAL_INPUT_BYTES_V2,
        )
    }

    /// Crosses this caller-manufacturable readback with its complete claim.
    ///
    /// # Errors
    ///
    /// Returns a typed conflict for any claim, ordinal, authority, artifact, or
    /// expected-source-identity crossing.
    pub fn validate_against_non_authorizing(
        &self,
        claim: &NonAuthorizingApplicationCompositionPublicationClaimV2,
    ) -> Result<(), CompositionConflict> {
        self.validate_integrity()?;
        validate_source_readback_against_claim_without_digest(self, claim)
    }
}

/// One canonical aggregate result blob observed by a role-sealed publisher.
/// No bytes are carried; only the publisher can establish the digest-to-bytes
/// relationship before a future ledger admission.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CompositionAggregateBlobReadbackV2 {
    /// Exact result-content digest.
    pub digest: Digest,
    /// Exact observed byte length.
    pub byte_length: u64,
}

/// Exact normalized mode for one canonical aggregate `Create` operation.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CompositionAggregateCreateModeReadbackV2 {
    /// Canonical portable create path.
    pub path: String,
    /// Exact normalized Unix permission bits.
    pub unix_mode: u32,
}

/// Canonical aggregate bundle readback claim.
///
/// This DTO binds the artifact, complete aggregate `ChangeSet`, exact sorted
/// blob digest/length inventory, and exact create modes. Validation does not
/// prove that bytes were observed or that publication occurred.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NonAuthorizingApplicationCompositionAggregateReadbackV2 {
    /// Required deterministic composer version.
    pub composer_version: u32,
    /// Exact publication claim against which the aggregate was prepared.
    pub publication_claim_digest: Digest,
    /// Exact path-free published aggregate artifact identity.
    pub aggregate_artifact: TaskIntegrationArtifactReference,
    /// Complete canonical base-to-final aggregate change set.
    pub change_set: ChangeSet,
    /// Unique blob inventory in strict digest byte order.
    pub blobs: Vec<CompositionAggregateBlobReadbackV2>,
    /// Create modes in strict portable-path byte order.
    pub create_modes: Vec<CompositionAggregateCreateModeReadbackV2>,
    /// Domain-separated digest over every preceding field.
    pub aggregate_readback_digest: Digest,
}

impl NonAuthorizingApplicationCompositionAggregateReadbackV2 {
    /// Constructs an aggregate-readback claim without asserting publication.
    ///
    /// # Errors
    ///
    /// Returns a typed conflict for artifact, change-set, blob, mode, claim,
    /// order, relationship, digest, or size errors.
    pub fn try_new_non_authorizing(
        claim: &NonAuthorizingApplicationCompositionPublicationClaimV2,
        aggregate_artifact: TaskIntegrationArtifactReference,
        change_set: ChangeSet,
        blobs: Vec<CompositionAggregateBlobReadbackV2>,
        create_modes: Vec<CompositionAggregateCreateModeReadbackV2>,
    ) -> Result<Self, CompositionConflict> {
        claim.validate_integrity()?;
        let mut readback = Self {
            composer_version: APPLICATION_ARTIFACT_COMPOSER_VERSION_V2,
            publication_claim_digest: claim.publication_claim_digest.clone(),
            aggregate_artifact,
            change_set,
            blobs,
            create_modes,
            aggregate_readback_digest: Digest::sha256(&[]),
        };
        validate_aggregate_readback_against_claim_without_digest(&readback, claim)?;
        readback.aggregate_readback_digest = compute_aggregate_readback_digest(&readback)?;
        readback.validate_against_non_authorizing(claim)?;
        Ok(readback)
    }

    /// Recomputes this aggregate readback's shape and checksum only.
    ///
    /// # Errors
    ///
    /// Returns a typed conflict for any malformed, crossed, or oversized field.
    pub fn validate_integrity(&self) -> Result<(), CompositionConflict> {
        validate_aggregate_readback_without_digest(self)?;
        if self.aggregate_readback_digest != compute_aggregate_readback_digest(self)? {
            return Err(CompositionConflict::PublicationReadbackMismatch {
                field: "aggregate_readback_digest",
            });
        }
        require_canonical_size(
            "composition_aggregate_readback",
            self,
            MAX_COMPOSITION_CANONICAL_INPUT_BYTES_V2,
        )
    }

    /// Crosses this aggregate readback with its publication claim.
    ///
    /// # Errors
    ///
    /// Returns a typed conflict for a claim, base, result, or digest crossing.
    pub fn validate_against_non_authorizing(
        &self,
        claim: &NonAuthorizingApplicationCompositionPublicationClaimV2,
    ) -> Result<(), CompositionConflict> {
        self.validate_integrity()?;
        validate_aggregate_readback_against_claim_without_digest(self, claim)
    }
}

/// Caller-manufacturable observation that an exact publication journal closed.
///
/// The journal identity and exact `Published` head are carried explicitly and
/// crossed with the publication claim and aggregate readback. This contract is
/// not proof that the journal exists or that its head is durable; a future
/// ledger admission must authenticate the role-sealed publisher observation.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NonAuthorizingApplicationCompositionPublicationClosureV2 {
    /// Required deterministic composer version.
    pub composer_version: u32,
    /// Exact publication identity.
    pub publication_id: String,
    /// Digest of the complete publication claim.
    pub publication_claim_digest: Digest,
    /// Exact identity of the append-only publisher journal.
    pub publication_journal_id: Digest,
    /// Exact digest of that journal's terminal `Published` record.
    pub published_journal_head_digest: Digest,
    /// Exact path-free aggregate artifact named by the terminal record.
    pub aggregate_artifact: TaskIntegrationArtifactReference,
    /// Exact aggregate readback named by the terminal record.
    pub aggregate_readback_digest: Digest,
    /// Domain-separated digest over every preceding field.
    pub publication_closure_observation_digest: Digest,
}

impl NonAuthorizingApplicationCompositionPublicationClosureV2 {
    /// Constructs an integrity-checkable, non-authorizing closure observation.
    ///
    /// # Errors
    ///
    /// Returns a typed conflict for any crossed claim, aggregate, journal,
    /// artifact, checksum, or canonical-size relationship.
    pub fn try_new_non_authorizing(
        claim: &NonAuthorizingApplicationCompositionPublicationClaimV2,
        aggregate_readback: &NonAuthorizingApplicationCompositionAggregateReadbackV2,
        publication_journal_id: Digest,
        published_journal_head_digest: Digest,
    ) -> Result<Self, CompositionConflict> {
        claim.validate_integrity()?;
        aggregate_readback.validate_against_non_authorizing(claim)?;
        let mut closure = Self {
            composer_version: APPLICATION_ARTIFACT_COMPOSER_VERSION_V2,
            publication_id: claim.publication_id.clone(),
            publication_claim_digest: claim.publication_claim_digest.clone(),
            publication_journal_id,
            published_journal_head_digest,
            aggregate_artifact: aggregate_readback.aggregate_artifact.clone(),
            aggregate_readback_digest: aggregate_readback.aggregate_readback_digest.clone(),
            publication_closure_observation_digest: Digest::sha256(&[]),
        };
        validate_publication_closure_against_backing_without_digest(
            &closure,
            claim,
            aggregate_readback,
        )?;
        closure.publication_closure_observation_digest =
            compute_publication_closure_observation_digest(&closure)?;
        closure.validate_against_non_authorizing(claim, aggregate_readback)?;
        Ok(closure)
    }

    /// Recomputes this observation's shape and checksum only.
    ///
    /// # Errors
    ///
    /// Returns a typed conflict for any malformed, crossed, or oversized field.
    pub fn validate_integrity(&self) -> Result<(), CompositionConflict> {
        require_composer_version(
            "publication_closure.composer_version",
            self.composer_version,
        )?;
        require_identifier("publication_closure.publication_id", &self.publication_id)?;
        self.aggregate_artifact.validate().map_err(|_| {
            CompositionConflict::CompositionReceiptMismatch {
                field: "publication_closure.aggregate_artifact",
            }
        })?;
        if self.aggregate_artifact.format_version != COMPOSITION_SOURCE_BUNDLE_FORMAT_VERSION_V2 {
            return Err(CompositionConflict::CompositionReceiptMismatch {
                field: "publication_closure.aggregate_artifact.format_version",
            });
        }
        if self.publication_closure_observation_digest
            != compute_publication_closure_observation_digest(self)?
        {
            return Err(CompositionConflict::CompositionReceiptMismatch {
                field: "publication_closure_observation_digest",
            });
        }
        require_canonical_size(
            "composition_publication_closure",
            self,
            MAX_COMPOSITION_CANONICAL_INPUT_BYTES_V2,
        )
    }

    /// Crosses this observation with the exact claim and aggregate readback.
    ///
    /// # Errors
    ///
    /// Returns a typed conflict for any substituted backing. Success grants no
    /// ledger or publication authority.
    pub fn validate_against_non_authorizing(
        &self,
        claim: &NonAuthorizingApplicationCompositionPublicationClaimV2,
        aggregate_readback: &NonAuthorizingApplicationCompositionAggregateReadbackV2,
    ) -> Result<(), CompositionConflict> {
        self.validate_integrity()?;
        validate_publication_closure_against_backing_without_digest(self, claim, aggregate_readback)
    }
}

/// Canonical current-generation additive composition receipt contract.
///
/// This serialized value remains caller-manufacturable. Its digest and
/// validation prove exact internal backing only. It gains authority solely
/// when a future core ledger admission authenticates the publication claim,
/// role-sealed source/aggregate readbacks, journal closure, and current rows.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ApplicationArtifactCompositionReceiptV2 {
    /// Required deterministic composer version.
    pub composer_version: u32,
    /// Exact publication identity.
    pub publication_id: String,
    /// Digest of the complete publication claim.
    pub publication_claim_digest: Digest,
    /// Owning sprint identity.
    pub sprint_id: String,
    /// Complete current `TaskDone` set digest.
    pub complete_task_done_set_digest: Digest,
    /// Projected latest passing final-verification attempt and criterion set.
    pub final_verification: CompositionFinalVerificationBindingV2,
    /// Exact original sprint snapshot.
    pub base_snapshot: Digest,
    /// Exact final-verification result snapshot.
    pub result_snapshot: Digest,
    /// Digest of the complete base projection.
    pub base_projection_digest: Digest,
    /// Digest of the complete ordered source-authority set.
    pub source_authority_set_digest: Digest,
    /// Digest of the complete ordered reopened source set.
    pub source_set_digest: Digest,
    /// Digest of the complete canonical source readback.
    pub source_readback_digest: Digest,
    /// Canonical base-to-final aggregate change set.
    pub aggregate_change_set: ChangeSet,
    /// Exact path-free published aggregate bundle identity.
    pub aggregate_artifact: TaskIntegrationArtifactReference,
    /// Digest of the exact aggregate artifact readback inventory.
    pub aggregate_readback_digest: Digest,
    /// Exact append-only publication journal identity.
    pub publication_journal_id: Digest,
    /// Exact digest of the journal's terminal `Published` record.
    pub published_journal_head_digest: Digest,
    /// Digest of the complete publication-closure observation.
    pub publication_closure_observation_digest: Digest,
    /// Pure derivation record crossed with every aggregate identity.
    pub derivation_record: NonAuthorizingCompositionDerivationRecordV2,
    /// Domain-separated digest over every preceding field.
    pub receipt_digest: Digest,
}

impl ApplicationArtifactCompositionReceiptV2 {
    /// Constructs a fully crossed but still non-authorizing receipt contract.
    ///
    /// # Errors
    ///
    /// Returns a typed conflict unless source readback, pure rederivation,
    /// aggregate readback, artifact, and every claim identity match exactly.
    pub fn try_new_non_authorizing(
        claim: &NonAuthorizingApplicationCompositionPublicationClaimV2,
        source_readback: &NonAuthorizingApplicationCompositionSourceReadbackV2,
        plan: &NonAuthorizingApplicationCompositionPlanV2,
        aggregate_readback: &NonAuthorizingApplicationCompositionAggregateReadbackV2,
        publication_closure: &NonAuthorizingApplicationCompositionPublicationClosureV2,
    ) -> Result<Self, CompositionConflict> {
        claim.validate_integrity()?;
        source_readback.validate_against_non_authorizing(claim)?;
        source_readback.validate_integrity()?;
        aggregate_readback.validate_against_non_authorizing(claim)?;
        aggregate_readback.validate_integrity()?;
        publication_closure.validate_against_non_authorizing(claim, aggregate_readback)?;
        plan.validate_integrity()?;
        let rederived = derive_non_authorizing_application_composition_v2(
            &claim.inputs,
            &claim.base,
            &source_readback.sources,
        )?;
        if &rederived != plan
            || aggregate_readback.change_set != plan.change_set
            || aggregate_readback.aggregate_artifact.change_set_id != plan.change_set.change_set_id
        {
            return Err(CompositionConflict::CompositionReceiptMismatch {
                field: "rederived_plan_or_aggregate",
            });
        }
        let mut receipt = Self {
            composer_version: APPLICATION_ARTIFACT_COMPOSER_VERSION_V2,
            publication_id: claim.publication_id.clone(),
            publication_claim_digest: claim.publication_claim_digest.clone(),
            sprint_id: claim.inputs.sprint_id.clone(),
            complete_task_done_set_digest: claim.inputs.complete_task_done_set_digest.clone(),
            final_verification: claim.inputs.final_verification.clone(),
            base_snapshot: claim.inputs.base_snapshot.clone(),
            result_snapshot: claim.inputs.result_snapshot.clone(),
            base_projection_digest: claim.base.projection_digest.clone(),
            source_authority_set_digest: claim.source_authority_set_digest.clone(),
            source_set_digest: claim.inputs.source_set_digest.clone(),
            source_readback_digest: source_readback.source_readback_digest.clone(),
            aggregate_change_set: plan.change_set.clone(),
            aggregate_artifact: aggregate_readback.aggregate_artifact.clone(),
            aggregate_readback_digest: aggregate_readback.aggregate_readback_digest.clone(),
            publication_journal_id: publication_closure.publication_journal_id.clone(),
            published_journal_head_digest: publication_closure
                .published_journal_head_digest
                .clone(),
            publication_closure_observation_digest: publication_closure
                .publication_closure_observation_digest
                .clone(),
            derivation_record: plan.derivation_record.clone(),
            receipt_digest: Digest::sha256(&[]),
        };
        receipt.receipt_digest = compute_composition_receipt_digest(&receipt)?;
        receipt.validate_against_non_authorizing(
            claim,
            source_readback,
            plan,
            aggregate_readback,
            publication_closure,
        )?;
        Ok(receipt)
    }

    /// Recomputes this receipt's internal relationships and checksum only.
    ///
    /// # Errors
    ///
    /// Returns a typed conflict for any malformed, crossed, or oversized field.
    pub fn validate_integrity(&self) -> Result<(), CompositionConflict> {
        require_composer_version(
            "composition_receipt.composer_version",
            self.composer_version,
        )?;
        require_identifier("composition_receipt.publication_id", &self.publication_id)?;
        require_identifier("composition_receipt.sprint_id", &self.sprint_id)?;
        self.final_verification.validate_integrity()?;
        self.aggregate_change_set.validate().map_err(|_| {
            CompositionConflict::CompositionReceiptMismatch {
                field: "aggregate_change_set",
            }
        })?;
        self.aggregate_artifact.validate().map_err(|_| {
            CompositionConflict::CompositionReceiptMismatch {
                field: "aggregate_artifact",
            }
        })?;
        self.derivation_record.validate_integrity()?;
        if self.final_verification.snapshot != self.result_snapshot
            || self.aggregate_change_set.base_snapshot != self.base_snapshot
            || self.aggregate_change_set.result_snapshot != self.result_snapshot
            || self.aggregate_artifact.format_version != COMPOSITION_SOURCE_BUNDLE_FORMAT_VERSION_V2
            || self.aggregate_artifact.change_set_id != self.aggregate_change_set.change_set_id
            || self.aggregate_artifact.base_snapshot != self.base_snapshot
            || self.aggregate_artifact.result_snapshot != self.result_snapshot
            || self.derivation_record.sprint_id != self.sprint_id
            || self.derivation_record.base_snapshot != self.base_snapshot
            || self.derivation_record.result_snapshot != self.result_snapshot
            || self.derivation_record.base_projection_digest != self.base_projection_digest
            || self.derivation_record.source_set_digest != self.source_set_digest
            || self.derivation_record.complete_task_done_set_digest
                != self.complete_task_done_set_digest
            || self.derivation_record.final_verification != self.final_verification
            || self.derivation_record.aggregate_change_set_id
                != self.aggregate_change_set.change_set_id
            || self.publication_closure_observation_digest
                != compute_publication_closure_observation_digest_from_fields(
                    self.composer_version,
                    &self.publication_id,
                    &self.publication_claim_digest,
                    &self.publication_journal_id,
                    &self.published_journal_head_digest,
                    &self.aggregate_artifact,
                    &self.aggregate_readback_digest,
                )?
        {
            return Err(CompositionConflict::CompositionReceiptMismatch {
                field: "receipt_relationship",
            });
        }
        if self.receipt_digest != compute_composition_receipt_digest(self)? {
            return Err(CompositionConflict::CompositionReceiptMismatch {
                field: "receipt_digest",
            });
        }
        require_canonical_size(
            "application_artifact_composition_receipt",
            self,
            MAX_COMPOSITION_CANONICAL_INPUT_BYTES_V2,
        )
    }

    /// Crosses this receipt with every non-authorizing backing contract.
    ///
    /// # Errors
    ///
    /// Returns a typed conflict for any claim, readback, plan, artifact, or
    /// digest substitution. Success still grants no ledger authority.
    pub fn validate_against_non_authorizing(
        &self,
        claim: &NonAuthorizingApplicationCompositionPublicationClaimV2,
        source_readback: &NonAuthorizingApplicationCompositionSourceReadbackV2,
        plan: &NonAuthorizingApplicationCompositionPlanV2,
        aggregate_readback: &NonAuthorizingApplicationCompositionAggregateReadbackV2,
        publication_closure: &NonAuthorizingApplicationCompositionPublicationClosureV2,
    ) -> Result<(), CompositionConflict> {
        self.validate_integrity()?;
        claim.validate_integrity()?;
        source_readback.validate_against_non_authorizing(claim)?;
        source_readback.validate_integrity()?;
        aggregate_readback.validate_against_non_authorizing(claim)?;
        aggregate_readback.validate_integrity()?;
        publication_closure.validate_against_non_authorizing(claim, aggregate_readback)?;
        plan.validate_integrity()?;
        let rederived = derive_non_authorizing_application_composition_v2(
            &claim.inputs,
            &claim.base,
            &source_readback.sources,
        )?;
        if &rederived != plan
            || self.publication_id != claim.publication_id
            || self.publication_claim_digest != claim.publication_claim_digest
            || self.sprint_id != claim.inputs.sprint_id
            || self.complete_task_done_set_digest != claim.inputs.complete_task_done_set_digest
            || self.final_verification != claim.inputs.final_verification
            || self.base_snapshot != claim.inputs.base_snapshot
            || self.result_snapshot != claim.inputs.result_snapshot
            || self.base_projection_digest != claim.base.projection_digest
            || self.source_authority_set_digest != claim.source_authority_set_digest
            || self.source_set_digest != claim.inputs.source_set_digest
            || self.source_readback_digest != source_readback.source_readback_digest
            || self.aggregate_change_set != plan.change_set
            || self.aggregate_artifact != aggregate_readback.aggregate_artifact
            || self.aggregate_readback_digest != aggregate_readback.aggregate_readback_digest
            || self.publication_journal_id != publication_closure.publication_journal_id
            || self.published_journal_head_digest
                != publication_closure.published_journal_head_digest
            || self.publication_closure_observation_digest
                != publication_closure.publication_closure_observation_digest
            || self.derivation_record != plan.derivation_record
        {
            return Err(CompositionConflict::CompositionReceiptMismatch {
                field: "receipt_backing",
            });
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ResultOrigin {
    source_ordinal: u32,
    source_artifact_digest: Digest,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ReplayFileEndpoint {
    content_digest: Digest,
    byte_length: u64,
    unix_mode: u32,
    origin: Option<ResultOrigin>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ReplayState {
    files: BTreeMap<String, ReplayFileEndpoint>,
    directories: BTreeSet<String>,
}

/// Derives a candidate aggregate without minting any authority or receipt.
///
/// # Errors
///
/// Returns a typed [`CompositionConflict`] when any source-coverage, identity,
/// ordering, replay, topology, mode, bound, snapshot, or integrity invariant
/// fails closed.
#[allow(
    clippy::too_many_lines,
    reason = "the pure audit boundary keeps coverage, ordered replay, snapshot re-derivation, bounds, topology, net-zero derivation, and integrity-record construction adjacent"
)]
pub fn derive_non_authorizing_application_composition_v2(
    inputs: &NonAuthorizingApplicationCompositionInputsV2,
    base: &NonAuthorizingCompositionBaseProjectionV2,
    sources: &[NonAuthorizingApplicationCompositionSourceV2],
) -> Result<NonAuthorizingApplicationCompositionPlanV2, CompositionConflict> {
    inputs.validate_integrity()?;
    base.validate_integrity()?;
    if base.snapshot != inputs.base_snapshot {
        return Err(CompositionConflict::BaseProjectionSnapshotMismatch {
            expected: inputs.base_snapshot.clone(),
            observed: base.snapshot.clone(),
        });
    }
    if sources.len() != inputs.expected_source_identities.len() {
        return Err(CompositionConflict::SourceCoverageCountMismatch {
            expected: inputs.expected_source_identities.len(),
            observed: sources.len(),
        });
    }
    validate_complete_input_bounds(inputs, base, sources)?;

    let base_state = replay_state_from_base(base);
    let mut current = base_state.clone();
    let mut expected_snapshot = inputs.base_snapshot.clone();
    let mut unique_task_ids = BTreeSet::new();
    let mut unique_attempt_ids = BTreeSet::new();
    let mut unique_task_done_ids = BTreeSet::new();
    let mut unique_integration_receipt_ids = BTreeSet::new();

    for (index, source) in sources.iter().enumerate() {
        let ordinal = u32::try_from(index).map_err(|_| CompositionConflict::LimitExceeded {
            field: "composition.sources",
            maximum: MAX_COMPOSITION_SOURCES_V2,
            observed: sources.len(),
        })?;
        if source.ordinal != ordinal {
            return Err(CompositionConflict::SourceOrdinalMismatch {
                expected: ordinal,
                observed: source.ordinal,
            });
        }
        source.validate_integrity()?;
        let admitted = &inputs.expected_source_identities[index];
        if &source.source_identity != admitted {
            return Err(CompositionConflict::SourceCoverageIdentityMismatch {
                ordinal,
                expected: admitted.clone(),
                observed: source.source_identity.clone(),
            });
        }
        require_unique_source_member(&mut unique_task_ids, "task_id", &source.task_id)?;
        require_unique_source_member(&mut unique_attempt_ids, "attempt_id", &source.attempt_id)?;
        require_unique_source_member(
            &mut unique_task_done_ids,
            "task_done_proof_id",
            &source.task_done_proof_id,
        )?;
        require_unique_source_member(
            &mut unique_integration_receipt_ids,
            "integration_receipt_id",
            &source.integration_receipt_id,
        )?;
        if source.input_snapshot != expected_snapshot {
            return Err(CompositionConflict::SnapshotChainMismatch {
                source_ordinal: Some(ordinal),
                expected: expected_snapshot,
                observed: source.input_snapshot.clone(),
            });
        }
        replay_source(source, &mut current)?;
        let computed = replay_state_snapshot(&current)?;
        if computed != source.result_snapshot {
            return Err(CompositionConflict::SourceResultSnapshotDigestMismatch {
                ordinal,
                claimed: source.result_snapshot.clone(),
                computed,
            });
        }
        expected_snapshot = source.result_snapshot.clone();
    }

    if expected_snapshot != inputs.result_snapshot {
        return Err(CompositionConflict::SnapshotChainMismatch {
            source_ordinal: None,
            expected: inputs.result_snapshot.clone(),
            observed: expected_snapshot,
        });
    }
    let computed_final = replay_state_snapshot(&current)?;
    if computed_final != inputs.result_snapshot {
        return Err(CompositionConflict::FinalSnapshotDigestMismatch {
            claimed: inputs.result_snapshot.clone(),
            computed: computed_final,
        });
    }

    let (operations, result_material) = derive_aggregate(&base_state, &current)?;
    validate_aggregate_bounds(&operations, &result_material)?;
    let operations_empty = operations.is_empty();
    if operations_empty != (inputs.base_snapshot == inputs.result_snapshot) {
        return Err(CompositionConflict::AggregateSnapshotMismatch {
            base_snapshot: inputs.base_snapshot.clone(),
            result_snapshot: inputs.result_snapshot.clone(),
            operations_empty,
        });
    }

    let aggregate_replayed = replay_aggregate(&base_state, &operations, &result_material)?;
    if !same_file_endpoints(&aggregate_replayed.files, &current.files) {
        return Err(CompositionConflict::UnrepresentableAggregateTopology {
            path: first_file_state_difference(&aggregate_replayed.files, &current.files),
            reason: "canonical aggregate replay differs from sequential regular-file state",
        });
    }

    let change_set_id = compute_aggregate_change_set_id(inputs, &operations)?.to_string();
    let change_set = ChangeSet {
        change_set_id,
        base_snapshot: inputs.base_snapshot.clone(),
        result_snapshot: inputs.result_snapshot.clone(),
        operations,
    };
    change_set
        .validate()
        .map_err(|_| CompositionConflict::DerivationRecordMismatch {
            field: "derived_change_set",
        })?;
    let aggregate_operations_digest = change_set
        .applied_operations_digest()
        .map_err(|error| canonical_contract_error("composition.operations", error))?;
    let aggregate_touched_endpoints_digest = change_set
        .touched_path_endpoints_digest()
        .map_err(|error| canonical_contract_error("composition.endpoints", error))?;
    let aggregate_result_material_digest = compute_result_material_digest(&result_material)?;
    // The manifest excludes directories; the aggregate retains only directory
    // occupancy required by its canonical replay.
    let final_directories = aggregate_replayed
        .directories
        .iter()
        .cloned()
        .collect::<Vec<_>>();
    let final_directory_state_digest = compute_directory_state_digest(&final_directories)?;
    let mut derivation_record = NonAuthorizingCompositionDerivationRecordV2 {
        composer_version: APPLICATION_ARTIFACT_COMPOSER_VERSION_V2,
        sprint_id: inputs.sprint_id.clone(),
        base_snapshot: inputs.base_snapshot.clone(),
        result_snapshot: inputs.result_snapshot.clone(),
        base_projection_digest: base.projection_digest.clone(),
        source_set_digest: inputs.source_set_digest.clone(),
        complete_task_done_set_digest: inputs.complete_task_done_set_digest.clone(),
        final_verification: inputs.final_verification.clone(),
        aggregate_change_set_id: change_set.change_set_id.clone(),
        aggregate_operations_digest,
        aggregate_touched_endpoints_digest,
        aggregate_result_material_digest,
        final_directory_state_digest,
        aggregate_no_op: operations_empty,
        record_digest: Digest::sha256(&[]),
    };
    derivation_record.record_digest = compute_derivation_record_digest(&derivation_record)?;
    let plan = NonAuthorizingApplicationCompositionPlanV2 {
        change_set,
        result_material,
        final_directories,
        derivation_record,
    };
    plan.validate_integrity()?;
    Ok(plan)
}

fn validate_complete_input_bounds(
    inputs: &NonAuthorizingApplicationCompositionInputsV2,
    base: &NonAuthorizingCompositionBaseProjectionV2,
    sources: &[NonAuthorizingApplicationCompositionSourceV2],
) -> Result<(), CompositionConflict> {
    if sources.len() > MAX_COMPOSITION_SOURCES_V2 {
        return Err(CompositionConflict::LimitExceeded {
            field: "composition.sources",
            maximum: MAX_COMPOSITION_SOURCES_V2,
            observed: sources.len(),
        });
    }
    let mut canonical_bytes = canonical_len("composition_inputs", inputs)?;
    canonical_bytes = checked_add_usize(
        "composition.canonical_input_bytes",
        canonical_bytes,
        canonical_len("base_projection", base)?,
    )?;
    for source in sources {
        canonical_bytes = checked_add_usize(
            "composition.canonical_input_bytes",
            canonical_bytes,
            canonical_len("composition_source", source)?,
        )?;
    }
    if canonical_bytes > MAX_COMPOSITION_CANONICAL_INPUT_BYTES_V2 {
        return Err(CompositionConflict::LimitExceeded {
            field: "composition.canonical_input_bytes",
            maximum: MAX_COMPOSITION_CANONICAL_INPUT_BYTES_V2,
            observed: canonical_bytes,
        });
    }
    Ok(())
}

fn validate_source_without_identity(
    source: &NonAuthorizingApplicationCompositionSourceV2,
) -> Result<(), CompositionConflict> {
    validate_source_shape(source)?;
    let operations_digest = source
        .change_set
        .applied_operations_digest()
        .map_err(|error| canonical_contract_error("composition_source.operations", error))?;
    if source.ordered_operations_digest != operations_digest {
        return Err(CompositionConflict::SourceDigestMismatch {
            ordinal: source.ordinal,
            kind: CompositionSourceDigestKind::OrderedOperations,
            claimed: source.ordered_operations_digest.clone(),
            computed: operations_digest,
        });
    }
    let endpoints_digest = source
        .change_set
        .touched_path_endpoints_digest()
        .map_err(|error| canonical_contract_error("composition_source.endpoints", error))?;
    if source.touched_endpoints_digest != endpoints_digest {
        return Err(CompositionConflict::SourceDigestMismatch {
            ordinal: source.ordinal,
            kind: CompositionSourceDigestKind::TouchedEndpoints,
            claimed: source.touched_endpoints_digest.clone(),
            computed: endpoints_digest,
        });
    }
    Ok(())
}

fn validate_source_shape(
    source: &NonAuthorizingApplicationCompositionSourceV2,
) -> Result<(), CompositionConflict> {
    require_composer_version(
        "composition_source.composer_version",
        source.composer_version,
    )?;
    for (field, value) in [
        ("composition_source.task_id", &source.task_id),
        ("composition_source.attempt_id", &source.attempt_id),
        (
            "composition_source.task_done_proof_id",
            &source.task_done_proof_id,
        ),
        (
            "composition_source.integration_receipt_id",
            &source.integration_receipt_id,
        ),
    ] {
        require_identifier(field, value)?;
    }
    if source.change_set.change_set_id.trim().is_empty() {
        return Err(CompositionConflict::InvalidSourceShape {
            ordinal: source.ordinal,
            kind: CompositionSourceShapeConflict::BlankChangeSetId,
        });
    }
    if source.change_set.operations.is_empty()
        != (source.change_set.base_snapshot == source.change_set.result_snapshot)
    {
        return Err(CompositionConflict::InvalidSourceShape {
            ordinal: source.ordinal,
            kind: CompositionSourceShapeConflict::SnapshotOperationDisagreement,
        });
    }
    if source.input_snapshot != source.change_set.base_snapshot
        || source.result_snapshot != source.change_set.result_snapshot
    {
        return Err(CompositionConflict::SourceBindingMismatch {
            ordinal: source.ordinal,
            field: "change_set.snapshots",
        });
    }
    if source.artifact.format_version != COMPOSITION_SOURCE_BUNDLE_FORMAT_VERSION_V2 {
        return Err(CompositionConflict::InvalidSourceShape {
            ordinal: source.ordinal,
            kind: CompositionSourceShapeConflict::InvalidArtifactVersion,
        });
    }
    if source.artifact.change_set_id != source.change_set.change_set_id
        || source.artifact.base_snapshot != source.input_snapshot
        || source.artifact.result_snapshot != source.result_snapshot
    {
        return Err(CompositionConflict::SourceBindingMismatch {
            ordinal: source.ordinal,
            field: "artifact",
        });
    }
    if source.change_set.operations.len() > MAX_COMPOSITION_OPERATIONS_V2 {
        return Err(CompositionConflict::LimitExceeded {
            field: "composition_source.operations",
            maximum: MAX_COMPOSITION_OPERATIONS_V2,
            observed: source.change_set.operations.len(),
        });
    }
    validate_source_operations(source)?;
    validate_source_result_material(source)?;
    Ok(())
}

fn validate_source_operations(
    source: &NonAuthorizingApplicationCompositionSourceV2,
) -> Result<(), CompositionConflict> {
    let mut paths = BTreeSet::new();
    for operation in &source.change_set.operations {
        let path = portable_operation_path(source.ordinal, operation.path())?;
        if !paths.insert(path.clone()) {
            return Err(CompositionConflict::DuplicateOperation {
                ordinal: source.ordinal,
                path,
            });
        }
        if let FileOperation::Modify {
            base_hash,
            result_hash,
            ..
        } = operation
            && base_hash == result_hash
        {
            return Err(CompositionConflict::InvalidSourceShape {
                ordinal: source.ordinal,
                kind: CompositionSourceShapeConflict::NoOpModify,
            });
        }
    }
    Ok(())
}

#[allow(
    clippy::too_many_lines,
    reason = "one pass validates the exact operation-to-material bijection and its independent source-bundle bounds"
)]
fn validate_source_result_material(
    source: &NonAuthorizingApplicationCompositionSourceV2,
) -> Result<(), CompositionConflict> {
    if source.result_material.len() > MAX_COMPOSITION_OPERATIONS_V2 {
        return Err(CompositionConflict::LimitExceeded {
            field: "composition_source.result_material",
            maximum: MAX_COMPOSITION_OPERATIONS_V2,
            observed: source.result_material.len(),
        });
    }
    let mut material_index = 0_usize;
    let mut blobs = BTreeMap::<Digest, u64>::new();
    for (operation_index, operation) in source.change_set.operations.iter().enumerate() {
        let needs_material = matches!(
            operation,
            FileOperation::Create { .. } | FileOperation::Modify { .. }
        );
        if !needs_material {
            continue;
        }
        let material = source.result_material.get(material_index).ok_or(
            CompositionConflict::ResultMaterialMismatch {
                source_ordinal: Some(source.ordinal),
                operation_index: u32::try_from(operation_index).ok(),
                field: "missing",
            },
        )?;
        let expected_index =
            u32::try_from(operation_index).map_err(|_| CompositionConflict::LimitExceeded {
                field: "composition_source.operations",
                maximum: MAX_COMPOSITION_OPERATIONS_V2,
                observed: source.change_set.operations.len(),
            })?;
        if material.operation_index != expected_index {
            return Err(CompositionConflict::ResultMaterialMismatch {
                source_ordinal: Some(source.ordinal),
                operation_index: Some(expected_index),
                field: "operation_index",
            });
        }
        let path = portable_operation_path(source.ordinal, operation.path())?;
        if material.path != path {
            return Err(CompositionConflict::ResultMaterialMismatch {
                source_ordinal: Some(source.ordinal),
                operation_index: Some(expected_index),
                field: "path",
            });
        }
        let expected_digest = match operation {
            FileOperation::Create { result_hash, .. }
            | FileOperation::Modify { result_hash, .. } => result_hash,
            FileOperation::Delete { .. } => unreachable!("delete does not need material"),
        };
        if &material.result_digest != expected_digest {
            return Err(CompositionConflict::ResultMaterialMismatch {
                source_ordinal: Some(source.ordinal),
                operation_index: Some(expected_index),
                field: "result_digest",
            });
        }
        if material.source_artifact_digest != source.artifact.artifact_digest {
            return Err(CompositionConflict::ResultMaterialMismatch {
                source_ordinal: Some(source.ordinal),
                operation_index: Some(expected_index),
                field: "source_artifact_digest",
            });
        }
        let kind_matches = matches!(
            (operation, &material.operation_kind),
            (
                FileOperation::Create { .. },
                CompositionResultMaterialKindV2::Create { .. }
            ) | (
                FileOperation::Modify { .. },
                CompositionResultMaterialKindV2::Modify
            )
        );
        if !kind_matches {
            return Err(CompositionConflict::ResultMaterialMismatch {
                source_ordinal: Some(source.ordinal),
                operation_index: Some(expected_index),
                field: "operation_kind",
            });
        }
        if let CompositionResultMaterialKindV2::Create { unix_mode } = material.operation_kind
            && unix_mode & !0o777 != 0
        {
            return Err(CompositionConflict::ResultMaterialMismatch {
                source_ordinal: Some(source.ordinal),
                operation_index: Some(expected_index),
                field: "create_mode",
            });
        }
        if material.byte_length > MAX_COMPOSITION_FILE_BYTES_V2 {
            return Err(CompositionConflict::ByteLimitExceeded {
                field: "composition_source.result_material.byte_length",
                maximum: MAX_COMPOSITION_FILE_BYTES_V2,
                observed: material.byte_length,
            });
        }
        insert_blob_length(&mut blobs, &material.result_digest, material.byte_length)?;
        material_index += 1;
    }
    if material_index != source.result_material.len() {
        return Err(CompositionConflict::ResultMaterialMismatch {
            source_ordinal: Some(source.ordinal),
            operation_index: None,
            field: "unexpected",
        });
    }
    let total = checked_blob_total("composition_source.result_blob_bytes", &blobs)?;
    if total > MAX_COMPOSITION_TOTAL_BYTES_V2 {
        return Err(CompositionConflict::ByteLimitExceeded {
            field: "composition_source.result_blob_bytes",
            maximum: MAX_COMPOSITION_TOTAL_BYTES_V2,
            observed: total,
        });
    }
    Ok(())
}

fn replay_source(
    source: &NonAuthorizingApplicationCompositionSourceV2,
    state: &mut ReplayState,
) -> Result<(), CompositionConflict> {
    let mut material_index = 0_usize;
    for operation in &source.change_set.operations {
        let material = if matches!(
            operation,
            FileOperation::Create { .. } | FileOperation::Modify { .. }
        ) {
            let value = &source.result_material[material_index];
            material_index += 1;
            Some(value)
        } else {
            None
        };
        replay_source_operation(source.ordinal, operation, material, state)?;
    }
    Ok(())
}

fn replay_source_operation(
    ordinal: u32,
    operation: &FileOperation,
    material: Option<&CompositionResultMaterialV2>,
    state: &mut ReplayState,
) -> Result<(), CompositionConflict> {
    let path = portable_operation_path(ordinal, operation.path())?;
    match operation {
        FileOperation::Create { result_hash, .. } => {
            require_create_absent(Some(ordinal), &path, state)?;
            ensure_parent_directories(Some(ordinal), &path, state)?;
            let material = material.expect("validated create material exists");
            let CompositionResultMaterialKindV2::Create { unix_mode } = material.operation_kind
            else {
                unreachable!("validated create material kind")
            };
            state.files.insert(
                path,
                ReplayFileEndpoint {
                    content_digest: result_hash.clone(),
                    byte_length: material.byte_length,
                    unix_mode,
                    origin: Some(ResultOrigin {
                        source_ordinal: ordinal,
                        source_artifact_digest: source_artifact(material),
                    }),
                },
            );
        }
        FileOperation::Modify {
            base_hash,
            result_hash,
            ..
        } => {
            if state.directories.contains(&path) {
                return Err(CompositionConflict::ModifyOverInvalidEndpoint {
                    ordinal: Some(ordinal),
                    path,
                    observed: Some(CompositionEndpointKindV2::Directory),
                });
            }
            let endpoint = state.files.get_mut(&path).ok_or_else(|| {
                CompositionConflict::ModifyOverInvalidEndpoint {
                    ordinal: Some(ordinal),
                    path: path.clone(),
                    observed: None,
                }
            })?;
            if endpoint.content_digest != *base_hash {
                return Err(CompositionConflict::BaseHashMismatch {
                    ordinal: Some(ordinal),
                    path,
                    expected: base_hash.clone(),
                    observed: endpoint.content_digest.clone(),
                });
            }
            let material = material.expect("validated modify material exists");
            endpoint.content_digest = result_hash.clone();
            endpoint.byte_length = material.byte_length;
            endpoint.origin = Some(ResultOrigin {
                source_ordinal: ordinal,
                source_artifact_digest: source_artifact(material),
            });
        }
        FileOperation::Delete { base_hash, .. } => {
            if state.directories.contains(&path) {
                return Err(CompositionConflict::DeleteOverInvalidEndpoint {
                    ordinal: Some(ordinal),
                    path,
                    observed: Some(CompositionEndpointKindV2::Directory),
                });
            }
            let endpoint = state.files.get(&path).ok_or_else(|| {
                CompositionConflict::DeleteOverInvalidEndpoint {
                    ordinal: Some(ordinal),
                    path: path.clone(),
                    observed: None,
                }
            })?;
            if endpoint.content_digest != *base_hash {
                return Err(CompositionConflict::BaseHashMismatch {
                    ordinal: Some(ordinal),
                    path,
                    expected: base_hash.clone(),
                    observed: endpoint.content_digest.clone(),
                });
            }
            state.files.remove(&path);
        }
    }
    Ok(())
}

fn derive_aggregate(
    base: &ReplayState,
    result: &ReplayState,
) -> Result<
    (
        Vec<FileOperation>,
        Vec<AggregateCompositionResultMaterialV2>,
    ),
    CompositionConflict,
> {
    let paths = base
        .files
        .keys()
        .chain(result.files.keys())
        .cloned()
        .collect::<BTreeSet<_>>();
    let mut operations = Vec::new();
    let mut material = Vec::new();
    for path in paths {
        match (base.files.get(&path), result.files.get(&path)) {
            (None, Some(result_endpoint)) => {
                let operation_index = u32::try_from(operations.len()).map_err(|_| {
                    CompositionConflict::LimitExceeded {
                        field: "composition.aggregate_operations",
                        maximum: MAX_COMPOSITION_OPERATIONS_V2,
                        observed: operations.len(),
                    }
                })?;
                let origin = result_endpoint.origin.as_ref().ok_or(
                    CompositionConflict::ResultMaterialMismatch {
                        source_ordinal: None,
                        operation_index: Some(operation_index),
                        field: "aggregate_origin",
                    },
                )?;
                operations.push(FileOperation::Create {
                    path: PathBuf::from(&path),
                    result_hash: result_endpoint.content_digest.clone(),
                });
                material.push(AggregateCompositionResultMaterialV2 {
                    operation_index,
                    path,
                    result_digest: result_endpoint.content_digest.clone(),
                    byte_length: result_endpoint.byte_length,
                    create_mode: Some(result_endpoint.unix_mode),
                    source_ordinal: origin.source_ordinal,
                    source_artifact_digest: origin.source_artifact_digest.clone(),
                });
            }
            (Some(base_endpoint), Some(result_endpoint)) => {
                if base_endpoint.unix_mode != result_endpoint.unix_mode {
                    return Err(CompositionConflict::UnrepresentableModeTransition {
                        path,
                        base_mode: base_endpoint.unix_mode,
                        result_mode: result_endpoint.unix_mode,
                    });
                }
                if base_endpoint.content_digest == result_endpoint.content_digest {
                    if base_endpoint.byte_length != result_endpoint.byte_length {
                        return Err(CompositionConflict::UnrepresentableLengthTransition {
                            path,
                            digest: base_endpoint.content_digest.clone(),
                            base_length: base_endpoint.byte_length,
                            result_length: result_endpoint.byte_length,
                        });
                    }
                    continue;
                }
                let operation_index = u32::try_from(operations.len()).map_err(|_| {
                    CompositionConflict::LimitExceeded {
                        field: "composition.aggregate_operations",
                        maximum: MAX_COMPOSITION_OPERATIONS_V2,
                        observed: operations.len(),
                    }
                })?;
                let origin = result_endpoint.origin.as_ref().ok_or(
                    CompositionConflict::ResultMaterialMismatch {
                        source_ordinal: None,
                        operation_index: Some(operation_index),
                        field: "aggregate_origin",
                    },
                )?;
                operations.push(FileOperation::Modify {
                    path: PathBuf::from(&path),
                    base_hash: base_endpoint.content_digest.clone(),
                    result_hash: result_endpoint.content_digest.clone(),
                });
                material.push(AggregateCompositionResultMaterialV2 {
                    operation_index,
                    path,
                    result_digest: result_endpoint.content_digest.clone(),
                    byte_length: result_endpoint.byte_length,
                    create_mode: None,
                    source_ordinal: origin.source_ordinal,
                    source_artifact_digest: origin.source_artifact_digest.clone(),
                });
            }
            (Some(base_endpoint), None) => operations.push(FileOperation::Delete {
                path: PathBuf::from(path),
                base_hash: base_endpoint.content_digest.clone(),
            }),
            (None, None) => unreachable!("path union contains an endpoint"),
        }
    }
    Ok((operations, material))
}

fn replay_aggregate(
    base: &ReplayState,
    operations: &[FileOperation],
    materials: &[AggregateCompositionResultMaterialV2],
) -> Result<ReplayState, CompositionConflict> {
    let mut state = base.clone();
    let mut material_index = 0_usize;
    for operation in operations {
        let path = portable_operation_path_for_aggregate(operation.path())?;
        match operation {
            FileOperation::Create { result_hash, .. } => {
                require_create_absent(None, &path, &state)?;
                ensure_parent_directories(None, &path, &mut state)?;
                let material = &materials[material_index];
                material_index += 1;
                state.files.insert(
                    path,
                    ReplayFileEndpoint {
                        content_digest: result_hash.clone(),
                        byte_length: material.byte_length,
                        unix_mode: material.create_mode.expect("validated create mode"),
                        origin: Some(ResultOrigin {
                            source_ordinal: material.source_ordinal,
                            source_artifact_digest: material.source_artifact_digest.clone(),
                        }),
                    },
                );
            }
            FileOperation::Modify {
                base_hash,
                result_hash,
                ..
            } => {
                if state.directories.contains(&path) {
                    return Err(CompositionConflict::ModifyOverInvalidEndpoint {
                        ordinal: None,
                        path,
                        observed: Some(CompositionEndpointKindV2::Directory),
                    });
                }
                let endpoint = state.files.get_mut(&path).ok_or_else(|| {
                    CompositionConflict::ModifyOverInvalidEndpoint {
                        ordinal: None,
                        path: path.clone(),
                        observed: None,
                    }
                })?;
                if endpoint.content_digest != *base_hash {
                    return Err(CompositionConflict::BaseHashMismatch {
                        ordinal: None,
                        path,
                        expected: base_hash.clone(),
                        observed: endpoint.content_digest.clone(),
                    });
                }
                let material = &materials[material_index];
                material_index += 1;
                endpoint.content_digest = result_hash.clone();
                endpoint.byte_length = material.byte_length;
                endpoint.origin = Some(ResultOrigin {
                    source_ordinal: material.source_ordinal,
                    source_artifact_digest: material.source_artifact_digest.clone(),
                });
            }
            FileOperation::Delete { base_hash, .. } => {
                if state.directories.contains(&path) {
                    return Err(CompositionConflict::DeleteOverInvalidEndpoint {
                        ordinal: None,
                        path,
                        observed: Some(CompositionEndpointKindV2::Directory),
                    });
                }
                let endpoint = state.files.get(&path).ok_or_else(|| {
                    CompositionConflict::DeleteOverInvalidEndpoint {
                        ordinal: None,
                        path: path.clone(),
                        observed: None,
                    }
                })?;
                if endpoint.content_digest != *base_hash {
                    return Err(CompositionConflict::BaseHashMismatch {
                        ordinal: None,
                        path,
                        expected: base_hash.clone(),
                        observed: endpoint.content_digest.clone(),
                    });
                }
                state.files.remove(&path);
            }
        }
    }
    Ok(state)
}

fn require_create_absent(
    ordinal: Option<u32>,
    path: &str,
    state: &ReplayState,
) -> Result<(), CompositionConflict> {
    if state.files.contains_key(path) {
        return Err(CompositionConflict::CreateOverPresent {
            ordinal,
            path: path.to_owned(),
            kind: CompositionEndpointKindV2::RegularFile,
        });
    }
    if state.directories.contains(path) {
        return Err(CompositionConflict::CreateOverPresent {
            ordinal,
            path: path.to_owned(),
            kind: CompositionEndpointKindV2::Directory,
        });
    }
    if let Some(conflicting_path) = present_file_collision(&state.files, path) {
        return Err(CompositionConflict::FileAncestorCollision {
            source_ordinal: ordinal,
            path: path.to_owned(),
            conflicting_path,
        });
    }
    Ok(())
}

fn ensure_parent_directories(
    ordinal: Option<u32>,
    path: &str,
    state: &mut ReplayState,
) -> Result<(), CompositionConflict> {
    for (separator, _) in path.match_indices('/') {
        let ancestor = &path[..separator];
        if state.files.contains_key(ancestor) {
            return Err(CompositionConflict::FileAncestorCollision {
                source_ordinal: ordinal,
                path: path.to_owned(),
                conflicting_path: ancestor.to_owned(),
            });
        }
        state.directories.insert(ancestor.to_owned());
        if state.directories.len() > MAX_DESCRIPTOR_RELATIVE_MANIFEST_ENTRIES {
            return Err(CompositionConflict::LimitExceeded {
                field: "composition.directory_state",
                maximum: MAX_DESCRIPTOR_RELATIVE_MANIFEST_ENTRIES,
                observed: state.directories.len(),
            });
        }
    }
    Ok(())
}

fn replay_state_from_base(base: &NonAuthorizingCompositionBaseProjectionV2) -> ReplayState {
    ReplayState {
        files: base
            .files
            .iter()
            .map(|entry| {
                (
                    entry.path.clone(),
                    ReplayFileEndpoint {
                        content_digest: entry.content_digest.clone(),
                        byte_length: entry.byte_length,
                        unix_mode: entry.unix_mode,
                        origin: None,
                    },
                )
            })
            .collect(),
        directories: base
            .directories
            .iter()
            .map(|entry| entry.path.clone())
            .collect(),
    }
}

fn replay_state_snapshot(state: &ReplayState) -> Result<Digest, CompositionConflict> {
    let entries = state
        .files
        .iter()
        .map(|(path, endpoint)| DescriptorRelativeManifestEntry {
            path: path.clone(),
            content_digest: endpoint.content_digest.clone(),
            byte_length: endpoint.byte_length,
            unix_mode: endpoint.unix_mode,
        })
        .collect::<Vec<_>>();
    compute_workspace_manifest_digest(&entries).map_err(|error| {
        CompositionConflict::WorkspaceManifest {
            field: "composition.replayed_workspace_manifest",
            reason: error.to_string(),
        }
    })
}

fn validate_base_projection_shape(
    snapshot: &Digest,
    files: &[CompositionBaseFileV2],
    directories: &[CompositionBaseDirectoryV2],
) -> Result<(), CompositionConflict> {
    let node_count = checked_add_usize("base_projection.nodes", files.len(), directories.len())?;
    if node_count > MAX_DESCRIPTOR_RELATIVE_MANIFEST_ENTRIES {
        return Err(CompositionConflict::LimitExceeded {
            field: "base_projection.nodes",
            maximum: MAX_DESCRIPTOR_RELATIVE_MANIFEST_ENTRIES,
            observed: node_count,
        });
    }
    validate_canonical_base_files(files)?;
    validate_canonical_base_directories(directories)?;
    let directory_set = directories
        .iter()
        .map(|entry| entry.path.as_str())
        .collect::<BTreeSet<_>>();
    let file_set = files
        .iter()
        .map(|entry| entry.path.as_str())
        .collect::<BTreeSet<_>>();
    for directory in directories {
        if file_set.contains(directory.path.as_str()) {
            return Err(CompositionConflict::BaseTopologyConflict {
                path: directory.path.clone(),
                conflicting_path: directory.path.clone(),
            });
        }
        for ancestor in path_ancestors(&directory.path) {
            if file_set.contains(ancestor) {
                return Err(CompositionConflict::BaseTopologyConflict {
                    path: directory.path.clone(),
                    conflicting_path: ancestor.to_owned(),
                });
            }
            if !directory_set.contains(ancestor) {
                return Err(CompositionConflict::IncompleteDirectoryProjection {
                    path: directory.path.clone(),
                    missing_ancestor: ancestor.to_owned(),
                });
            }
        }
    }
    for file in files {
        for ancestor in path_ancestors(&file.path) {
            if file_set.contains(ancestor) {
                return Err(CompositionConflict::BaseTopologyConflict {
                    path: file.path.clone(),
                    conflicting_path: ancestor.to_owned(),
                });
            }
            if !directory_set.contains(ancestor) {
                return Err(CompositionConflict::IncompleteDirectoryProjection {
                    path: file.path.clone(),
                    missing_ancestor: ancestor.to_owned(),
                });
            }
        }
    }
    let manifest_entries = files
        .iter()
        .map(|entry| DescriptorRelativeManifestEntry {
            path: entry.path.clone(),
            content_digest: entry.content_digest.clone(),
            byte_length: entry.byte_length,
            unix_mode: entry.unix_mode,
        })
        .collect::<Vec<_>>();
    let computed = compute_workspace_manifest_digest(&manifest_entries).map_err(|error| {
        CompositionConflict::WorkspaceManifest {
            field: "base_projection.files",
            reason: error.to_string(),
        }
    })?;
    if &computed != snapshot {
        return Err(CompositionConflict::BaseSnapshotDigestMismatch {
            claimed: snapshot.clone(),
            computed,
        });
    }
    Ok(())
}

fn validate_canonical_base_files(
    files: &[CompositionBaseFileV2],
) -> Result<(), CompositionConflict> {
    let mut previous: Option<&str> = None;
    for file in files {
        validate_portable_path(None, &file.path)?;
        if file.byte_length > i64::MAX as u64 || file.unix_mode & !0o777 != 0 {
            return Err(CompositionConflict::ResultMaterialMismatch {
                source_ordinal: None,
                operation_index: None,
                field: "base_file_metadata",
            });
        }
        if let Some(prior) = previous
            && prior.as_bytes() >= file.path.as_bytes()
        {
            return Err(CompositionConflict::NonCanonicalPathOrder {
                field: "base_projection.files",
                previous: prior.to_owned(),
                current: file.path.clone(),
            });
        }
        previous = Some(&file.path);
    }
    Ok(())
}

fn validate_canonical_base_directories(
    directories: &[CompositionBaseDirectoryV2],
) -> Result<(), CompositionConflict> {
    let mut previous: Option<&str> = None;
    for directory in directories {
        validate_portable_path(None, &directory.path)?;
        if let Some(prior) = previous
            && prior.as_bytes() >= directory.path.as_bytes()
        {
            return Err(CompositionConflict::NonCanonicalPathOrder {
                field: "base_projection.directories",
                previous: prior.to_owned(),
                current: directory.path.clone(),
            });
        }
        previous = Some(&directory.path);
    }
    Ok(())
}

fn validate_aggregate_operation_order(
    operations: &[FileOperation],
) -> Result<(), CompositionConflict> {
    let mut previous: Option<String> = None;
    for operation in operations {
        let path = portable_operation_path_for_aggregate(operation.path())?;
        if let Some(prior) = &previous
            && prior.as_bytes() >= path.as_bytes()
        {
            return Err(CompositionConflict::NonCanonicalPathOrder {
                field: "composition.aggregate_operations",
                previous: prior.clone(),
                current: path,
            });
        }
        previous = Some(path);
    }
    Ok(())
}

fn validate_aggregate_result_material(
    operations: &[FileOperation],
    materials: &[AggregateCompositionResultMaterialV2],
) -> Result<(), CompositionConflict> {
    let mut material_index = 0_usize;
    for (operation_index, operation) in operations.iter().enumerate() {
        if matches!(operation, FileOperation::Delete { .. }) {
            continue;
        }
        let expected_index =
            u32::try_from(operation_index).map_err(|_| CompositionConflict::LimitExceeded {
                field: "composition.aggregate_operations",
                maximum: MAX_COMPOSITION_OPERATIONS_V2,
                observed: operations.len(),
            })?;
        let material =
            materials
                .get(material_index)
                .ok_or(CompositionConflict::ResultMaterialMismatch {
                    source_ordinal: None,
                    operation_index: Some(expected_index),
                    field: "missing_aggregate_material",
                })?;
        let path = portable_operation_path_for_aggregate(operation.path())?;
        let result_digest = match operation {
            FileOperation::Create { result_hash, .. }
            | FileOperation::Modify { result_hash, .. } => result_hash,
            FileOperation::Delete { .. } => unreachable!(),
        };
        let mode_shape = match operation {
            FileOperation::Create { .. } => {
                material.create_mode.is_some_and(|mode| mode & !0o777 == 0)
            }
            FileOperation::Modify { .. } => material.create_mode.is_none(),
            FileOperation::Delete { .. } => false,
        };
        if material.operation_index != expected_index
            || material.path != path
            || &material.result_digest != result_digest
            || !mode_shape
        {
            return Err(CompositionConflict::ResultMaterialMismatch {
                source_ordinal: None,
                operation_index: Some(expected_index),
                field: "aggregate_material_relationship",
            });
        }
        if material.byte_length > MAX_COMPOSITION_FILE_BYTES_V2 {
            return Err(CompositionConflict::ByteLimitExceeded {
                field: "composition.aggregate_material.byte_length",
                maximum: MAX_COMPOSITION_FILE_BYTES_V2,
                observed: material.byte_length,
            });
        }
        material_index += 1;
    }
    if material_index != materials.len() {
        return Err(CompositionConflict::ResultMaterialMismatch {
            source_ordinal: None,
            operation_index: None,
            field: "unexpected_aggregate_material",
        });
    }
    Ok(())
}

fn validate_aggregate_bounds(
    operations: &[FileOperation],
    materials: &[AggregateCompositionResultMaterialV2],
) -> Result<(), CompositionConflict> {
    if operations.len() > MAX_COMPOSITION_OPERATIONS_V2 {
        return Err(CompositionConflict::LimitExceeded {
            field: "composition.aggregate_operations",
            maximum: MAX_COMPOSITION_OPERATIONS_V2,
            observed: operations.len(),
        });
    }
    if materials.len() > MAX_COMPOSITION_OPERATIONS_V2 {
        return Err(CompositionConflict::LimitExceeded {
            field: "composition.aggregate_blobs",
            maximum: MAX_COMPOSITION_OPERATIONS_V2,
            observed: materials.len(),
        });
    }
    let mut blobs = BTreeMap::new();
    for material in materials {
        insert_blob_length(&mut blobs, &material.result_digest, material.byte_length)?;
    }
    let total = checked_blob_total("composition.aggregate_blob_bytes", &blobs)?;
    if total > MAX_COMPOSITION_TOTAL_BYTES_V2 {
        return Err(CompositionConflict::ByteLimitExceeded {
            field: "composition.aggregate_blob_bytes",
            maximum: MAX_COMPOSITION_TOTAL_BYTES_V2,
            observed: total,
        });
    }
    Ok(())
}

fn validate_directory_state(directories: &[String]) -> Result<(), CompositionConflict> {
    if directories.len() > MAX_DESCRIPTOR_RELATIVE_MANIFEST_ENTRIES {
        return Err(CompositionConflict::LimitExceeded {
            field: "composition.final_directories",
            maximum: MAX_DESCRIPTOR_RELATIVE_MANIFEST_ENTRIES,
            observed: directories.len(),
        });
    }
    let mut previous: Option<&str> = None;
    let set = directories
        .iter()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    if set.len() != directories.len() {
        return Err(CompositionConflict::NonCanonicalPathOrder {
            field: "composition.final_directories",
            previous: "<duplicate>".into(),
            current: "<duplicate>".into(),
        });
    }
    for directory in directories {
        validate_portable_path(None, directory)?;
        if let Some(prior) = previous
            && prior.as_bytes() >= directory.as_bytes()
        {
            return Err(CompositionConflict::NonCanonicalPathOrder {
                field: "composition.final_directories",
                previous: prior.to_owned(),
                current: directory.clone(),
            });
        }
        for ancestor in path_ancestors(directory) {
            if !set.contains(ancestor) {
                return Err(CompositionConflict::IncompleteDirectoryProjection {
                    path: directory.clone(),
                    missing_ancestor: ancestor.to_owned(),
                });
            }
        }
        previous = Some(directory);
    }
    Ok(())
}

fn validate_source_identity_set(identities: &[Digest]) -> Result<(), CompositionConflict> {
    if identities.is_empty() || identities.len() > MAX_COMPOSITION_SOURCES_V2 {
        return Err(CompositionConflict::LimitExceeded {
            field: "composition_inputs.expected_source_identities",
            maximum: MAX_COMPOSITION_SOURCES_V2,
            observed: identities.len(),
        });
    }
    let mut unique = BTreeSet::new();
    for identity in identities {
        if !unique.insert(identity) {
            return Err(CompositionConflict::DuplicateSourceMember {
                field: "source_identity",
                value: identity.to_string(),
            });
        }
    }
    Ok(())
}
fn require_unique_source_member<'a>(
    values: &mut BTreeSet<&'a str>,
    field: &'static str,
    value: &'a str,
) -> Result<(), CompositionConflict> {
    if !values.insert(value) {
        return Err(CompositionConflict::DuplicateSourceMember {
            field,
            value: value.to_owned(),
        });
    }
    Ok(())
}

fn present_file_collision(
    files: &BTreeMap<String, ReplayFileEndpoint>,
    path: &str,
) -> Option<String> {
    for ancestor in path_ancestors(path) {
        if files.contains_key(ancestor) {
            return Some(ancestor.to_owned());
        }
    }
    let descendant_prefix = format!("{path}/");
    files
        .range(descendant_prefix.clone()..)
        .next()
        .filter(|(candidate, _)| candidate.starts_with(&descendant_prefix))
        .map(|(candidate, _)| candidate.clone())
}

fn path_ancestors(path: &str) -> impl Iterator<Item = &str> {
    path.match_indices('/')
        .map(|(separator, _)| &path[..separator])
}

fn portable_operation_path(ordinal: u32, path: &Path) -> Result<String, CompositionConflict> {
    let Some(path) = path.to_str() else {
        return Err(CompositionConflict::InvalidPortablePath {
            source_ordinal: Some(ordinal),
            path: "<non-utf8>".into(),
            kind: PortablePathConflictKind::NonUtf8,
        });
    };
    validate_portable_path(Some(ordinal), path)?;
    Ok(path.to_owned())
}

fn portable_operation_path_for_aggregate(path: &Path) -> Result<String, CompositionConflict> {
    let Some(path) = path.to_str() else {
        return Err(CompositionConflict::InvalidPortablePath {
            source_ordinal: None,
            path: "<non-utf8>".into(),
            kind: PortablePathConflictKind::NonUtf8,
        });
    };
    validate_portable_path(None, path)?;
    Ok(path.to_owned())
}

fn validate_portable_path(
    source_ordinal: Option<u32>,
    path: &str,
) -> Result<(), CompositionConflict> {
    if path.is_empty() || path.starts_with('/') {
        return Err(CompositionConflict::InvalidPortablePath {
            source_ordinal,
            path: path.to_owned(),
            kind: PortablePathConflictKind::EmptyOrAbsolute,
        });
    }
    if path.len() > MAX_DESCRIPTOR_RELATIVE_MANIFEST_PATH_BYTES {
        return Err(CompositionConflict::InvalidPortablePath {
            source_ordinal,
            path: path.to_owned(),
            kind: PortablePathConflictKind::TooLong,
        });
    }
    if path.contains('\\') || path.as_bytes().contains(&0) {
        return Err(CompositionConflict::InvalidPortablePath {
            source_ordinal,
            path: path.to_owned(),
            kind: PortablePathConflictKind::NonPortableSeparatorOrNul,
        });
    }
    if path.split('/').any(|component| {
        component.is_empty()
            || component == "."
            || component == ".."
            || component.eq_ignore_ascii_case(".git")
    }) {
        return Err(CompositionConflict::InvalidPortablePath {
            source_ordinal,
            path: path.to_owned(),
            kind: PortablePathConflictKind::InvalidComponent,
        });
    }
    Ok(())
}

fn require_identifier(field: &'static str, value: &str) -> Result<(), CompositionConflict> {
    if value.trim().is_empty() {
        Err(CompositionConflict::InvalidIdentifier { field })
    } else if value.len() > MAX_COMPOSITION_IDENTIFIER_BYTES_V2 {
        Err(CompositionConflict::LimitExceeded {
            field,
            maximum: MAX_COMPOSITION_IDENTIFIER_BYTES_V2,
            observed: value.len(),
        })
    } else {
        Ok(())
    }
}

fn require_composer_version(field: &'static str, version: u32) -> Result<(), CompositionConflict> {
    if version == APPLICATION_ARTIFACT_COMPOSER_VERSION_V2 {
        Ok(())
    } else {
        Err(CompositionConflict::UnsupportedComposerVersion {
            field,
            observed: version,
        })
    }
}

fn source_artifact(material: &CompositionResultMaterialV2) -> Digest {
    material.source_artifact_digest.clone()
}

fn checked_add_usize(
    field: &'static str,
    left: usize,
    right: usize,
) -> Result<usize, CompositionConflict> {
    left.checked_add(right)
        .ok_or(CompositionConflict::AccountingOverflow { field })
}

fn insert_blob_length(
    blobs: &mut BTreeMap<Digest, u64>,
    digest: &Digest,
    length: u64,
) -> Result<(), CompositionConflict> {
    if length > MAX_COMPOSITION_FILE_BYTES_V2 {
        return Err(CompositionConflict::ByteLimitExceeded {
            field: "composition.result_blob.byte_length",
            maximum: MAX_COMPOSITION_FILE_BYTES_V2,
            observed: length,
        });
    }
    if let Some(existing) = blobs.insert(digest.clone(), length)
        && existing != length
    {
        return Err(CompositionConflict::ResultBlobLengthConflict {
            digest: digest.clone(),
            first: existing,
            second: length,
        });
    }
    Ok(())
}

fn checked_blob_total(
    field: &'static str,
    blobs: &BTreeMap<Digest, u64>,
) -> Result<u64, CompositionConflict> {
    blobs.values().try_fold(0_u64, |total, length| {
        total
            .checked_add(*length)
            .ok_or(CompositionConflict::AccountingOverflow { field })
    })
}

fn first_file_state_difference(
    left: &BTreeMap<String, ReplayFileEndpoint>,
    right: &BTreeMap<String, ReplayFileEndpoint>,
) -> Option<String> {
    left.keys()
        .chain(right.keys())
        .find(|path| !same_optional_file_endpoint(left.get(*path), right.get(*path)))
        .cloned()
}

fn same_file_endpoints(
    left: &BTreeMap<String, ReplayFileEndpoint>,
    right: &BTreeMap<String, ReplayFileEndpoint>,
) -> bool {
    left.len() == right.len()
        && left
            .iter()
            .all(|(path, endpoint)| same_optional_file_endpoint(Some(endpoint), right.get(path)))
}

fn same_optional_file_endpoint(
    left: Option<&ReplayFileEndpoint>,
    right: Option<&ReplayFileEndpoint>,
) -> bool {
    match (left, right) {
        (Some(left), Some(right)) => {
            left.content_digest == right.content_digest
                && left.byte_length == right.byte_length
                && left.unix_mode == right.unix_mode
        }
        (None, None) => true,
        (Some(_), None) | (None, Some(_)) => false,
    }
}

fn validate_source_authority_without_digest(
    source: &NonAuthorizingApplicationCompositionSourceAuthorityV2,
) -> Result<(), CompositionConflict> {
    require_composer_version("source_authority.composer_version", source.composer_version)?;
    for (field, value) in [
        ("source_authority.task_id", source.task_id.as_str()),
        ("source_authority.attempt_id", source.attempt_id.as_str()),
        (
            "source_authority.task_done_proof_id",
            source.task_done_proof_id.as_str(),
        ),
        (
            "source_authority.integration_receipt_id",
            source.integration_receipt_id.as_str(),
        ),
    ] {
        require_identifier(field, value)?;
    }
    source
        .artifact
        .validate()
        .map_err(|error| canonical_contract_error("source_authority.artifact", error))?;
    if source.artifact.format_version != COMPOSITION_SOURCE_BUNDLE_FORMAT_VERSION_V2 {
        return Err(CompositionConflict::PublicationClaimMismatch {
            field: "source_authority.artifact.format_version",
        });
    }
    if source.reopened_result_blob_bytes > MAX_COMPOSITION_REOPENED_SOURCE_BYTES_V2 {
        return Err(CompositionConflict::ByteLimitExceeded {
            field: "source_authority.reopened_result_blob_bytes",
            maximum: MAX_COMPOSITION_REOPENED_SOURCE_BYTES_V2,
            observed: source.reopened_result_blob_bytes,
        });
    }
    let source_operation_count = usize::try_from(source.source_operation_count).map_err(|_| {
        CompositionConflict::AccountingOverflow {
            field: "source_authority.source_operation_count",
        }
    })?;
    if source_operation_count > MAX_COMPOSITION_OPERATIONS_V2 {
        return Err(CompositionConflict::LimitExceeded {
            field: "source_authority.source_operation_count",
            maximum: MAX_COMPOSITION_OPERATIONS_V2,
            observed: source_operation_count,
        });
    }
    Ok(())
}

fn validate_publication_claim_without_digests(
    claim: &NonAuthorizingApplicationCompositionPublicationClaimV2,
) -> Result<(), CompositionConflict> {
    require_composer_version("publication_claim.composer_version", claim.composer_version)?;
    require_identifier("publication_claim.publication_id", &claim.publication_id)?;
    claim.inputs.validate_integrity()?;
    claim.base.validate_integrity()?;
    if claim.base.snapshot != claim.inputs.base_snapshot
        || claim.sources.is_empty()
        || claim.sources.len() > MAX_COMPOSITION_SOURCES_V2
        || claim.sources.len() != claim.inputs.expected_source_identities.len()
    {
        return Err(CompositionConflict::PublicationClaimMismatch {
            field: "publication_claim.base_or_source_count",
        });
    }
    let mut task_ids = BTreeSet::new();
    let mut attempt_ids = BTreeSet::new();
    let mut task_done_ids = BTreeSet::new();
    let mut integration_ids = BTreeSet::new();
    let mut authority_digests = BTreeSet::new();
    let mut expected_snapshot = claim.inputs.base_snapshot.clone();
    let mut cumulative_reopened_bytes = 0_u64;
    let mut cumulative_source_operations = 0_usize;
    for (index, source) in claim.sources.iter().enumerate() {
        source.validate_integrity()?;
        let ordinal =
            u32::try_from(index).map_err(|_| CompositionConflict::AccountingOverflow {
                field: "publication_claim.sources",
            })?;
        if source.ordinal != ordinal
            || source.artifact.base_snapshot != expected_snapshot
            || !task_ids.insert(&source.task_id)
            || !attempt_ids.insert(&source.attempt_id)
            || !task_done_ids.insert(&source.task_done_proof_id)
            || !integration_ids.insert(&source.integration_receipt_id)
            || !authority_digests.insert(&source.source_authority_digest)
        {
            return Err(CompositionConflict::PublicationClaimMismatch {
                field: "publication_claim.source_order_or_identity",
            });
        }
        cumulative_reopened_bytes = cumulative_reopened_bytes
            .checked_add(source.reopened_result_blob_bytes)
            .ok_or(CompositionConflict::AccountingOverflow {
                field: "publication_claim.reopened_source_bytes",
            })?;
        if cumulative_reopened_bytes > MAX_COMPOSITION_REOPENED_SOURCE_BYTES_V2 {
            return Err(CompositionConflict::ByteLimitExceeded {
                field: "publication_claim.reopened_source_bytes",
                maximum: MAX_COMPOSITION_REOPENED_SOURCE_BYTES_V2,
                observed: cumulative_reopened_bytes,
            });
        }
        cumulative_source_operations = checked_add_usize(
            "publication_claim.reopened_source_operations",
            cumulative_source_operations,
            usize::try_from(source.source_operation_count).map_err(|_| {
                CompositionConflict::AccountingOverflow {
                    field: "publication_claim.reopened_source_operations",
                }
            })?,
        )?;
        if cumulative_source_operations > MAX_COMPOSITION_REOPENED_SOURCE_OPERATIONS_V2 {
            return Err(CompositionConflict::LimitExceeded {
                field: "publication_claim.reopened_source_operations",
                maximum: MAX_COMPOSITION_REOPENED_SOURCE_OPERATIONS_V2,
                observed: cumulative_source_operations,
            });
        }
        expected_snapshot = source.artifact.result_snapshot.clone();
    }
    if expected_snapshot != claim.inputs.result_snapshot {
        return Err(CompositionConflict::PublicationClaimMismatch {
            field: "publication_claim.result_snapshot",
        });
    }
    Ok(())
}

fn validate_source_readback_against_claim_without_digest(
    readback: &NonAuthorizingApplicationCompositionSourceReadbackV2,
    claim: &NonAuthorizingApplicationCompositionPublicationClaimV2,
) -> Result<(), CompositionConflict> {
    claim.validate_integrity()?;
    require_composer_version(
        "source_readback.composer_version",
        readback.composer_version,
    )?;
    if readback.publication_claim_digest != claim.publication_claim_digest
        || readback.sources.len() != claim.sources.len()
        || readback.sources.len() != claim.inputs.expected_source_identities.len()
    {
        return Err(CompositionConflict::PublicationReadbackMismatch {
            field: "source_readback_claim_or_count",
        });
    }
    let mut cumulative_reopened_bytes = 0_u64;
    let mut cumulative_source_operations = 0_usize;
    let mut cumulative_source_metadata_bytes = 0_usize;
    for (index, source) in readback.sources.iter().enumerate() {
        source.validate_integrity()?;
        let authority = &claim.sources[index];
        let expected_ordinal =
            u32::try_from(index).map_err(|_| CompositionConflict::AccountingOverflow {
                field: "source_readback.ordinal",
            })?;
        let reopened_result_blob_bytes = source_result_blob_bytes(source)?;
        cumulative_reopened_bytes = cumulative_reopened_bytes
            .checked_add(reopened_result_blob_bytes)
            .ok_or(CompositionConflict::AccountingOverflow {
                field: "source_readback.reopened_source_bytes",
            })?;
        if cumulative_reopened_bytes > MAX_COMPOSITION_REOPENED_SOURCE_BYTES_V2 {
            return Err(CompositionConflict::ByteLimitExceeded {
                field: "source_readback.reopened_source_bytes",
                maximum: MAX_COMPOSITION_REOPENED_SOURCE_BYTES_V2,
                observed: cumulative_reopened_bytes,
            });
        }
        cumulative_source_operations = checked_add_usize(
            "source_readback.reopened_source_operations",
            cumulative_source_operations,
            source.change_set.operations.len(),
        )?;
        if cumulative_source_operations > MAX_COMPOSITION_REOPENED_SOURCE_OPERATIONS_V2 {
            return Err(CompositionConflict::LimitExceeded {
                field: "source_readback.reopened_source_operations",
                maximum: MAX_COMPOSITION_REOPENED_SOURCE_OPERATIONS_V2,
                observed: cumulative_source_operations,
            });
        }
        cumulative_source_metadata_bytes = checked_add_usize(
            "source_readback.reopened_source_metadata_bytes",
            cumulative_source_metadata_bytes,
            canonical_len("composition_source", source)?,
        )?;
        if cumulative_source_metadata_bytes > MAX_COMPOSITION_REOPENED_SOURCE_METADATA_BYTES_V2 {
            return Err(CompositionConflict::LimitExceeded {
                field: "source_readback.reopened_source_metadata_bytes",
                maximum: MAX_COMPOSITION_REOPENED_SOURCE_METADATA_BYTES_V2,
                observed: cumulative_source_metadata_bytes,
            });
        }
        if source.ordinal != expected_ordinal
            || source.ordinal != authority.ordinal
            || source.task_id != authority.task_id
            || source.attempt_id != authority.attempt_id
            || source.task_done_proof_id != authority.task_done_proof_id
            || source.task_done_proof_digest != authority.task_done_proof_digest
            || source.integration_receipt_id != authority.integration_receipt_id
            || source.integration_receipt_digest != authority.integration_receipt_digest
            || source.artifact != authority.artifact
            || reopened_result_blob_bytes != authority.reopened_result_blob_bytes
            || source.change_set.operations.len()
                != usize::try_from(authority.source_operation_count).map_err(|_| {
                    CompositionConflict::AccountingOverflow {
                        field: "source_readback.source_operation_count",
                    }
                })?
            || source.source_identity != claim.inputs.expected_source_identities[index]
        {
            return Err(CompositionConflict::PublicationReadbackMismatch {
                field: "source_readback_authority",
            });
        }
    }
    require_canonical_size(
        "composition_source_readback",
        readback,
        MAX_COMPOSITION_CANONICAL_INPUT_BYTES_V2,
    )
}

fn source_result_blob_bytes(
    source: &NonAuthorizingApplicationCompositionSourceV2,
) -> Result<u64, CompositionConflict> {
    let mut blobs = BTreeMap::new();
    for material in &source.result_material {
        insert_blob_length(&mut blobs, &material.result_digest, material.byte_length)?;
    }
    checked_blob_total("source_readback.source_result_blob_bytes", &blobs)
}

fn validate_aggregate_readback_without_digest(
    readback: &NonAuthorizingApplicationCompositionAggregateReadbackV2,
) -> Result<(), CompositionConflict> {
    require_composer_version(
        "aggregate_readback.composer_version",
        readback.composer_version,
    )?;
    readback
        .change_set
        .validate()
        .map_err(|error| canonical_contract_error("aggregate_readback.change_set", error))?;
    validate_aggregate_operation_order(&readback.change_set.operations)?;
    readback.aggregate_artifact.validate().map_err(|error| {
        canonical_contract_error("aggregate_readback.aggregate_artifact", error)
    })?;
    if readback.aggregate_artifact.format_version != COMPOSITION_SOURCE_BUNDLE_FORMAT_VERSION_V2
        || readback.aggregate_artifact.change_set_id != readback.change_set.change_set_id
        || readback.aggregate_artifact.base_snapshot != readback.change_set.base_snapshot
        || readback.aggregate_artifact.result_snapshot != readback.change_set.result_snapshot
    {
        return Err(CompositionConflict::PublicationReadbackMismatch {
            field: "aggregate_readback.artifact",
        });
    }
    if readback.blobs.len() > MAX_COMPOSITION_OPERATIONS_V2
        || readback.create_modes.len() > MAX_COMPOSITION_OPERATIONS_V2
    {
        return Err(CompositionConflict::LimitExceeded {
            field: "aggregate_readback.entries",
            maximum: MAX_COMPOSITION_OPERATIONS_V2,
            observed: readback.blobs.len().max(readback.create_modes.len()),
        });
    }

    let expected_blob_digests = readback
        .change_set
        .operations
        .iter()
        .filter_map(|operation| match operation {
            FileOperation::Create { result_hash, .. }
            | FileOperation::Modify { result_hash, .. } => Some(result_hash.clone()),
            FileOperation::Delete { .. } => None,
        })
        .collect::<BTreeSet<_>>();
    let mut expected_create_paths = BTreeSet::new();
    for operation in &readback.change_set.operations {
        if let FileOperation::Create { path, .. } = operation {
            expected_create_paths.insert(portable_operation_path_for_aggregate(path)?);
        }
    }

    let mut observed_blob_digests = BTreeSet::new();
    let mut previous_digest: Option<&Digest> = None;
    let mut total = 0_u64;
    for blob in &readback.blobs {
        if previous_digest.is_some_and(|previous| previous >= &blob.digest)
            || !observed_blob_digests.insert(blob.digest.clone())
        {
            return Err(CompositionConflict::PublicationReadbackMismatch {
                field: "aggregate_readback.blob_order",
            });
        }
        if blob.byte_length > MAX_COMPOSITION_FILE_BYTES_V2 {
            return Err(CompositionConflict::ByteLimitExceeded {
                field: "aggregate_readback.blob.byte_length",
                maximum: MAX_COMPOSITION_FILE_BYTES_V2,
                observed: blob.byte_length,
            });
        }
        total =
            total
                .checked_add(blob.byte_length)
                .ok_or(CompositionConflict::AccountingOverflow {
                    field: "aggregate_readback.blob_bytes",
                })?;
        previous_digest = Some(&blob.digest);
    }
    if observed_blob_digests != expected_blob_digests || total > MAX_COMPOSITION_TOTAL_BYTES_V2 {
        return Err(CompositionConflict::PublicationReadbackMismatch {
            field: "aggregate_readback.blob_inventory",
        });
    }

    let mut observed_create_paths = BTreeSet::new();
    let mut previous_path: Option<&str> = None;
    for mode in &readback.create_modes {
        validate_portable_path(None, &mode.path)?;
        if mode.unix_mode & !0o777 != 0
            || previous_path.is_some_and(|previous| previous.as_bytes() >= mode.path.as_bytes())
            || !observed_create_paths.insert(mode.path.clone())
        {
            return Err(CompositionConflict::PublicationReadbackMismatch {
                field: "aggregate_readback.create_modes",
            });
        }
        previous_path = Some(&mode.path);
    }
    if observed_create_paths != expected_create_paths {
        return Err(CompositionConflict::PublicationReadbackMismatch {
            field: "aggregate_readback.create_mode_coverage",
        });
    }
    Ok(())
}

fn validate_aggregate_readback_against_claim_without_digest(
    readback: &NonAuthorizingApplicationCompositionAggregateReadbackV2,
    claim: &NonAuthorizingApplicationCompositionPublicationClaimV2,
) -> Result<(), CompositionConflict> {
    claim.validate_integrity()?;
    validate_aggregate_readback_without_digest(readback)?;
    if readback.publication_claim_digest != claim.publication_claim_digest
        || readback.change_set.base_snapshot != claim.inputs.base_snapshot
        || readback.change_set.result_snapshot != claim.inputs.result_snapshot
    {
        return Err(CompositionConflict::PublicationReadbackMismatch {
            field: "aggregate_readback_claim_or_snapshot",
        });
    }
    require_canonical_size(
        "composition_aggregate_readback",
        readback,
        MAX_COMPOSITION_CANONICAL_INPUT_BYTES_V2,
    )
}

fn validate_publication_closure_against_backing_without_digest(
    closure: &NonAuthorizingApplicationCompositionPublicationClosureV2,
    claim: &NonAuthorizingApplicationCompositionPublicationClaimV2,
    aggregate_readback: &NonAuthorizingApplicationCompositionAggregateReadbackV2,
) -> Result<(), CompositionConflict> {
    claim.validate_integrity()?;
    aggregate_readback.validate_against_non_authorizing(claim)?;
    if closure.composer_version != APPLICATION_ARTIFACT_COMPOSER_VERSION_V2
        || closure.publication_id != claim.publication_id
        || closure.publication_claim_digest != claim.publication_claim_digest
        || closure.aggregate_artifact != aggregate_readback.aggregate_artifact
        || closure.aggregate_readback_digest != aggregate_readback.aggregate_readback_digest
    {
        return Err(CompositionConflict::CompositionReceiptMismatch {
            field: "publication_closure_backing",
        });
    }
    require_identifier(
        "publication_closure.publication_id",
        &closure.publication_id,
    )?;
    require_canonical_size(
        "composition_publication_closure",
        closure,
        MAX_COMPOSITION_CANONICAL_INPUT_BYTES_V2,
    )
}

#[derive(Serialize)]
struct SourceAuthorityDigestPreimage<'a> {
    composer_version: u32,
    ordinal: u32,
    task_id: &'a str,
    attempt_id: &'a str,
    task_done_proof_id: &'a str,
    task_done_proof_digest: &'a Digest,
    integration_receipt_id: &'a str,
    integration_receipt_digest: &'a Digest,
    artifact: &'a TaskIntegrationArtifactReference,
    reopened_result_blob_bytes: u64,
    source_operation_count: u32,
}

fn compute_source_authority_digest(
    source: &NonAuthorizingApplicationCompositionSourceAuthorityV2,
) -> Result<Digest, CompositionConflict> {
    canonical_digest(
        "composition_source_authority",
        SOURCE_AUTHORITY_DIGEST_DOMAIN,
        &SourceAuthorityDigestPreimage {
            composer_version: source.composer_version,
            ordinal: source.ordinal,
            task_id: &source.task_id,
            attempt_id: &source.attempt_id,
            task_done_proof_id: &source.task_done_proof_id,
            task_done_proof_digest: &source.task_done_proof_digest,
            integration_receipt_id: &source.integration_receipt_id,
            integration_receipt_digest: &source.integration_receipt_digest,
            artifact: &source.artifact,
            reopened_result_blob_bytes: source.reopened_result_blob_bytes,
            source_operation_count: source.source_operation_count,
        },
    )
}

#[derive(Serialize)]
struct SourceAuthoritySetDigestPreimage<'a> {
    composer_version: u32,
    publication_id: &'a str,
    sprint_id: &'a str,
    complete_task_done_set_digest: &'a Digest,
    expected_source_identities: &'a [Digest],
    ordered_source_authority_digests: Vec<&'a Digest>,
}

fn compute_source_authority_set_digest(
    claim: &NonAuthorizingApplicationCompositionPublicationClaimV2,
) -> Result<Digest, CompositionConflict> {
    canonical_digest(
        "composition_source_authority_set",
        SOURCE_AUTHORITY_SET_DIGEST_DOMAIN,
        &SourceAuthoritySetDigestPreimage {
            composer_version: claim.composer_version,
            publication_id: &claim.publication_id,
            sprint_id: &claim.inputs.sprint_id,
            complete_task_done_set_digest: &claim.inputs.complete_task_done_set_digest,
            expected_source_identities: &claim.inputs.expected_source_identities,
            ordered_source_authority_digests: claim
                .sources
                .iter()
                .map(|source| &source.source_authority_digest)
                .collect(),
        },
    )
}

#[derive(Serialize)]
struct PublicationClaimDigestPreimage<'a> {
    composer_version: u32,
    publication_id: &'a str,
    inputs: &'a NonAuthorizingApplicationCompositionInputsV2,
    base: &'a NonAuthorizingCompositionBaseProjectionV2,
    sources: &'a [NonAuthorizingApplicationCompositionSourceAuthorityV2],
    source_authority_set_digest: &'a Digest,
}

fn compute_publication_claim_digest(
    claim: &NonAuthorizingApplicationCompositionPublicationClaimV2,
) -> Result<Digest, CompositionConflict> {
    canonical_digest(
        "composition_publication_claim",
        PUBLICATION_CLAIM_DIGEST_DOMAIN,
        &PublicationClaimDigestPreimage {
            composer_version: claim.composer_version,
            publication_id: &claim.publication_id,
            inputs: &claim.inputs,
            base: &claim.base,
            sources: &claim.sources,
            source_authority_set_digest: &claim.source_authority_set_digest,
        },
    )
}

#[derive(Serialize)]
struct SourceReadbackDigestPreimage<'a> {
    composer_version: u32,
    publication_claim_digest: &'a Digest,
    sources: &'a [NonAuthorizingApplicationCompositionSourceV2],
}

fn compute_source_readback_digest(
    readback: &NonAuthorizingApplicationCompositionSourceReadbackV2,
) -> Result<Digest, CompositionConflict> {
    canonical_digest(
        "composition_source_readback",
        SOURCE_READBACK_DIGEST_DOMAIN,
        &SourceReadbackDigestPreimage {
            composer_version: readback.composer_version,
            publication_claim_digest: &readback.publication_claim_digest,
            sources: &readback.sources,
        },
    )
}

#[derive(Serialize)]
struct AggregateReadbackDigestPreimage<'a> {
    composer_version: u32,
    publication_claim_digest: &'a Digest,
    aggregate_artifact: &'a TaskIntegrationArtifactReference,
    change_set: &'a ChangeSet,
    blobs: &'a [CompositionAggregateBlobReadbackV2],
    create_modes: &'a [CompositionAggregateCreateModeReadbackV2],
}

#[derive(Serialize)]
struct PublicationClosureObservationDigestPreimage<'a> {
    composer_version: u32,
    publication_id: &'a str,
    publication_claim_digest: &'a Digest,
    publication_journal_id: &'a Digest,
    published_journal_head_digest: &'a Digest,
    aggregate_artifact: &'a TaskIntegrationArtifactReference,
    aggregate_readback_digest: &'a Digest,
}

fn compute_publication_closure_observation_digest(
    closure: &NonAuthorizingApplicationCompositionPublicationClosureV2,
) -> Result<Digest, CompositionConflict> {
    compute_publication_closure_observation_digest_from_fields(
        closure.composer_version,
        &closure.publication_id,
        &closure.publication_claim_digest,
        &closure.publication_journal_id,
        &closure.published_journal_head_digest,
        &closure.aggregate_artifact,
        &closure.aggregate_readback_digest,
    )
}

#[allow(
    clippy::too_many_arguments,
    reason = "the publication-closure digest keeps every independent custody identity explicit"
)]
fn compute_publication_closure_observation_digest_from_fields(
    composer_version: u32,
    publication_id: &str,
    publication_claim_digest: &Digest,
    publication_journal_id: &Digest,
    published_journal_head_digest: &Digest,
    aggregate_artifact: &TaskIntegrationArtifactReference,
    aggregate_readback_digest: &Digest,
) -> Result<Digest, CompositionConflict> {
    canonical_digest(
        "composition_publication_closure",
        PUBLICATION_CLOSURE_OBSERVATION_DIGEST_DOMAIN,
        &PublicationClosureObservationDigestPreimage {
            composer_version,
            publication_id,
            publication_claim_digest,
            publication_journal_id,
            published_journal_head_digest,
            aggregate_artifact,
            aggregate_readback_digest,
        },
    )
}

fn compute_aggregate_readback_digest(
    readback: &NonAuthorizingApplicationCompositionAggregateReadbackV2,
) -> Result<Digest, CompositionConflict> {
    canonical_digest(
        "composition_aggregate_readback",
        AGGREGATE_READBACK_DIGEST_DOMAIN,
        &AggregateReadbackDigestPreimage {
            composer_version: readback.composer_version,
            publication_claim_digest: &readback.publication_claim_digest,
            aggregate_artifact: &readback.aggregate_artifact,
            change_set: &readback.change_set,
            blobs: &readback.blobs,
            create_modes: &readback.create_modes,
        },
    )
}

#[derive(Serialize)]
struct CompositionReceiptDigestPreimage<'a> {
    composer_version: u32,
    publication_id: &'a str,
    publication_claim_digest: &'a Digest,
    sprint_id: &'a str,
    complete_task_done_set_digest: &'a Digest,
    final_verification: &'a CompositionFinalVerificationBindingV2,
    base_snapshot: &'a Digest,
    result_snapshot: &'a Digest,
    base_projection_digest: &'a Digest,
    source_authority_set_digest: &'a Digest,
    source_set_digest: &'a Digest,
    source_readback_digest: &'a Digest,
    aggregate_change_set: &'a ChangeSet,
    aggregate_artifact: &'a TaskIntegrationArtifactReference,
    aggregate_readback_digest: &'a Digest,
    publication_journal_id: &'a Digest,
    published_journal_head_digest: &'a Digest,
    publication_closure_observation_digest: &'a Digest,
    derivation_record: &'a NonAuthorizingCompositionDerivationRecordV2,
}

fn compute_composition_receipt_digest(
    receipt: &ApplicationArtifactCompositionReceiptV2,
) -> Result<Digest, CompositionConflict> {
    canonical_digest(
        "application_artifact_composition_receipt",
        COMPOSITION_RECEIPT_DIGEST_DOMAIN,
        &CompositionReceiptDigestPreimage {
            composer_version: receipt.composer_version,
            publication_id: &receipt.publication_id,
            publication_claim_digest: &receipt.publication_claim_digest,
            sprint_id: &receipt.sprint_id,
            complete_task_done_set_digest: &receipt.complete_task_done_set_digest,
            final_verification: &receipt.final_verification,
            base_snapshot: &receipt.base_snapshot,
            result_snapshot: &receipt.result_snapshot,
            base_projection_digest: &receipt.base_projection_digest,
            source_authority_set_digest: &receipt.source_authority_set_digest,
            source_set_digest: &receipt.source_set_digest,
            source_readback_digest: &receipt.source_readback_digest,
            aggregate_change_set: &receipt.aggregate_change_set,
            aggregate_artifact: &receipt.aggregate_artifact,
            aggregate_readback_digest: &receipt.aggregate_readback_digest,
            publication_journal_id: &receipt.publication_journal_id,
            published_journal_head_digest: &receipt.published_journal_head_digest,
            publication_closure_observation_digest: &receipt.publication_closure_observation_digest,
            derivation_record: &receipt.derivation_record,
        },
    )
}

#[derive(Serialize)]
struct BaseProjectionDigestPreimage<'a> {
    composer_version: u32,
    snapshot: &'a Digest,
    files: &'a [CompositionBaseFileV2],
    directories: &'a [CompositionBaseDirectoryV2],
}

fn compute_base_projection_digest(
    snapshot: &Digest,
    files: &[CompositionBaseFileV2],
    directories: &[CompositionBaseDirectoryV2],
) -> Result<Digest, CompositionConflict> {
    canonical_digest(
        "base_projection",
        BASE_PROJECTION_DIGEST_DOMAIN,
        &BaseProjectionDigestPreimage {
            composer_version: APPLICATION_ARTIFACT_COMPOSER_VERSION_V2,
            snapshot,
            files,
            directories,
        },
    )
}

#[derive(Serialize)]
struct SourceIdentityPreimage<'a> {
    composer_version: u32,
    ordinal: u32,
    task_id: &'a str,
    attempt_id: &'a str,
    task_done_proof_id: &'a str,
    task_done_proof_digest: &'a Digest,
    integration_receipt_id: &'a str,
    integration_receipt_digest: &'a Digest,
    input_snapshot: &'a Digest,
    result_snapshot: &'a Digest,
    change_set: &'a ChangeSet,
    artifact: &'a TaskIntegrationArtifactReference,
    result_material: &'a [CompositionResultMaterialV2],
    ordered_operations_digest: &'a Digest,
    touched_endpoints_digest: &'a Digest,
}

fn compute_source_identity(
    source: &NonAuthorizingApplicationCompositionSourceV2,
) -> Result<Digest, CompositionConflict> {
    canonical_digest(
        "composition_source",
        SOURCE_IDENTITY_DOMAIN,
        &SourceIdentityPreimage {
            composer_version: source.composer_version,
            ordinal: source.ordinal,
            task_id: &source.task_id,
            attempt_id: &source.attempt_id,
            task_done_proof_id: &source.task_done_proof_id,
            task_done_proof_digest: &source.task_done_proof_digest,
            integration_receipt_id: &source.integration_receipt_id,
            integration_receipt_digest: &source.integration_receipt_digest,
            input_snapshot: &source.input_snapshot,
            result_snapshot: &source.result_snapshot,
            change_set: &source.change_set,
            artifact: &source.artifact,
            result_material: &source.result_material,
            ordered_operations_digest: &source.ordered_operations_digest,
            touched_endpoints_digest: &source.touched_endpoints_digest,
        },
    )
}

#[derive(Serialize)]
struct SourceSetDigestPreimage<'a> {
    composer_version: u32,
    sprint_id: &'a str,
    complete_task_done_set_digest: &'a Digest,
    ordered_source_identities: &'a [Digest],
}

fn compute_source_set_digest(
    sprint_id: &str,
    complete_task_done_set_digest: &Digest,
    ordered_source_identities: &[Digest],
) -> Result<Digest, CompositionConflict> {
    canonical_digest(
        "composition_source_set",
        SOURCE_SET_DIGEST_DOMAIN,
        &SourceSetDigestPreimage {
            composer_version: APPLICATION_ARTIFACT_COMPOSER_VERSION_V2,
            sprint_id,
            complete_task_done_set_digest,
            ordered_source_identities,
        },
    )
}

#[derive(Serialize)]
struct AggregateChangeSetIdPreimage<'a> {
    composer_version: u32,
    sprint_id: &'a str,
    base_snapshot: &'a Digest,
    result_snapshot: &'a Digest,
    source_set_digest: &'a Digest,
    operations: &'a [FileOperation],
}

fn compute_aggregate_change_set_id(
    inputs: &NonAuthorizingApplicationCompositionInputsV2,
    operations: &[FileOperation],
) -> Result<Digest, CompositionConflict> {
    compute_aggregate_change_set_id_from_fields(
        inputs.composer_version,
        &inputs.sprint_id,
        &inputs.base_snapshot,
        &inputs.result_snapshot,
        &inputs.source_set_digest,
        operations,
    )
}

fn compute_aggregate_change_set_id_from_fields(
    composer_version: u32,
    sprint_id: &str,
    base_snapshot: &Digest,
    result_snapshot: &Digest,
    source_set_digest: &Digest,
    operations: &[FileOperation],
) -> Result<Digest, CompositionConflict> {
    canonical_digest(
        "composition_change_set_id",
        CHANGE_SET_ID_DOMAIN,
        &AggregateChangeSetIdPreimage {
            composer_version,
            sprint_id,
            base_snapshot,
            result_snapshot,
            source_set_digest,
            operations,
        },
    )
}

fn compute_result_material_digest<T: Serialize + ?Sized>(
    material: &T,
) -> Result<Digest, CompositionConflict> {
    canonical_digest(
        "composition_result_material",
        RESULT_MATERIAL_DIGEST_DOMAIN,
        material,
    )
}

fn compute_directory_state_digest(directories: &[String]) -> Result<Digest, CompositionConflict> {
    canonical_digest(
        "composition_directory_state",
        DIRECTORY_STATE_DIGEST_DOMAIN,
        directories,
    )
}

#[derive(Serialize)]
struct DerivationRecordDigestPreimage<'a> {
    composer_version: u32,
    sprint_id: &'a str,
    base_snapshot: &'a Digest,
    result_snapshot: &'a Digest,
    base_projection_digest: &'a Digest,
    source_set_digest: &'a Digest,
    complete_task_done_set_digest: &'a Digest,
    final_verification: &'a CompositionFinalVerificationBindingV2,
    aggregate_change_set_id: &'a str,
    aggregate_operations_digest: &'a Digest,
    aggregate_touched_endpoints_digest: &'a Digest,
    aggregate_result_material_digest: &'a Digest,
    final_directory_state_digest: &'a Digest,
    aggregate_no_op: bool,
}

fn compute_derivation_record_digest(
    record: &NonAuthorizingCompositionDerivationRecordV2,
) -> Result<Digest, CompositionConflict> {
    canonical_digest(
        "composition_derivation_record",
        DERIVATION_RECORD_DOMAIN,
        &DerivationRecordDigestPreimage {
            composer_version: record.composer_version,
            sprint_id: &record.sprint_id,
            base_snapshot: &record.base_snapshot,
            result_snapshot: &record.result_snapshot,
            base_projection_digest: &record.base_projection_digest,
            source_set_digest: &record.source_set_digest,
            complete_task_done_set_digest: &record.complete_task_done_set_digest,
            final_verification: &record.final_verification,
            aggregate_change_set_id: &record.aggregate_change_set_id,
            aggregate_operations_digest: &record.aggregate_operations_digest,
            aggregate_touched_endpoints_digest: &record.aggregate_touched_endpoints_digest,
            aggregate_result_material_digest: &record.aggregate_result_material_digest,
            final_directory_state_digest: &record.final_directory_state_digest,
            aggregate_no_op: record.aggregate_no_op,
        },
    )
}

fn canonical_len<T: Serialize + ?Sized>(
    field: &'static str,
    value: &T,
) -> Result<usize, CompositionConflict> {
    serde_json::to_vec(value)
        .map(|bytes| bytes.len())
        .map_err(|error| CompositionConflict::CanonicalEncoding {
            field,
            reason: error.to_string(),
        })
}

fn require_canonical_size<T: Serialize + ?Sized>(
    field: &'static str,
    value: &T,
    maximum: usize,
) -> Result<(), CompositionConflict> {
    let observed = canonical_len(field, value)?;
    if observed > maximum {
        Err(CompositionConflict::LimitExceeded {
            field,
            maximum,
            observed,
        })
    } else {
        Ok(())
    }
}

fn canonical_digest<T: Serialize + ?Sized>(
    field: &'static str,
    domain: &[u8],
    value: &T,
) -> Result<Digest, CompositionConflict> {
    let canonical =
        serde_json::to_vec(value).map_err(|error| CompositionConflict::CanonicalEncoding {
            field,
            reason: error.to_string(),
        })?;
    let mut preimage = Vec::with_capacity(domain.len() + 8 + canonical.len());
    preimage.extend_from_slice(domain);
    preimage.extend_from_slice(
        &u64::try_from(canonical.len())
            .expect("supported targets use at most 64-bit usize")
            .to_be_bytes(),
    );
    preimage.extend_from_slice(&canonical);
    Ok(Digest::sha256(&preimage))
}

fn canonical_contract_error(field: &'static str, error: impl Display) -> CompositionConflict {
    CompositionConflict::CanonicalEncoding {
        field,
        reason: error.to_string(),
    }
}

#[cfg(test)]
mod tests;
