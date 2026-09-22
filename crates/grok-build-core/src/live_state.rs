//! Canonical contracts for descriptor-relative live-workspace finalization.
//!
//! These contracts describe the immutable plan that precedes a live capture
//! and the complete manifest evidence returned by the runner. They do not
//! grant launch, dispatch, observation, or completion authority; the ledger
//! joins these values to the corresponding move-only authorities.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};
use sha2::{Digest as Sha2Digest, Sha256};

use crate::{
    ApplicationEvidence, CONTRACT_VERSION, CompiledExecutionPolicy, ContractError, Digest,
    ExecutionNetwork, MutationMode, PathScope, RollbackReferenceEvidence, SprintSpec,
    TaskDoneProof, VerificationEffectEvidence, WorkerCleanupEvidence, WorkerCleanupReceipt,
};

/// Exact manifest format shared with the descriptor-relative runner capture.
pub const DESCRIPTOR_RELATIVE_WORKSPACE_MANIFEST_FORMAT_VERSION: u32 = 1;
/// Maximum UTF-8 bytes in one portable descriptor-relative manifest path.
pub const MAX_DESCRIPTOR_RELATIVE_MANIFEST_PATH_BYTES: usize = 4 * 1_024;
/// Maximum number of regular files in one live-state manifest.
pub const MAX_DESCRIPTOR_RELATIVE_MANIFEST_ENTRIES: usize = 65_536;
/// Maximum canonical JSON bytes in one complete manifest contract.
pub const MAX_DESCRIPTOR_RELATIVE_MANIFEST_BYTES: usize = 6 * 1_048_576;
/// Maximum UTF-8 bytes in one live-state authority identity.
pub const MAX_LIVE_STATE_CAPTURE_ID_BYTES: usize = 4 * 1_024;
/// Maximum prior cleanup receipts bound into one capture plan.
pub const MAX_LIVE_STATE_REQUIRED_CLEANUP_RECEIPTS: usize = 65_536;
/// Maximum canonical JSON bytes in one live-state capture request.
pub const MAX_LIVE_STATE_CAPTURE_REQUEST_BYTES: usize = 1_048_576;
/// Maximum canonical JSON bytes retained for one successful capture evidence.
pub const MAX_LIVE_STATE_CAPTURE_EVIDENCE_BYTES: usize = (8 * 1_048_576) - (64 * 1_024);
/// Maximum canonical JSON bytes retained for one completion/capture link.
pub const MAX_COMPLETION_LIVE_STATE_CAPTURE_LINK_BYTES: usize = 1_048_576;
/// Maximum canonical JSON bytes retained for one drift-blocked terminal proof.
pub const MAX_LIVE_STATE_DRIFT_BLOCKED_PROOF_BYTES: usize = 1_048_576;

const WORKSPACE_MANIFEST_DOMAIN: &[u8] = b"grok-build.workspace-manifest.sha256.v1\0";
const REQUIRED_CLEANUP_SET_DOMAIN: &[u8] =
    b"grok-build.live-state-required-cleanup-set.sha256.v1\0";
const CAPTURE_PLAN_DOMAIN: &[u8] = b"grok-build.sprint-live-state-capture-plan.sha256.v1\0";

/// One singly linked regular file in a canonical descriptor-relative manifest.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DescriptorRelativeManifestEntry {
    /// Normalized, nonempty, portable UTF-8 path relative to the workspace root.
    pub path: String,
    /// SHA-256 digest of the complete regular-file contents.
    pub content_digest: Digest,
    /// Complete file length in bytes.
    pub byte_length: u64,
    /// Normalized Unix permission bits included by the existing manifest V1 format.
    pub unix_mode: u32,
}

impl DescriptorRelativeManifestEntry {
    /// Validates the portable path, signed-storage length, and normalized mode.
    ///
    /// # Errors
    ///
    /// Returns [`ContractError`] for a nonportable or oversized path, a length
    /// outside `SQLite`'s exact integer range, or mode bits outside `0o777`.
    pub fn validate(&self) -> Result<(), ContractError> {
        validate_manifest_path(&self.path)?;
        if self.byte_length > i64::MAX as u64 {
            return Err(ContractError::new(
                "descriptor_relative_manifest_entry.byte_length",
                "must fit exactly in a signed 64-bit durable integer",
            ));
        }
        if self.unix_mode & !0o777 != 0 {
            return Err(ContractError::new(
                "descriptor_relative_manifest_entry.unix_mode",
                "must contain only normalized Unix permission bits 0o000..=0o777",
            ));
        }
        Ok(())
    }
}

/// Complete descriptor-relative live-workspace manifest.
///
/// The digest deliberately excludes capture metadata and exactly reproduces
/// the runner's existing `grok-build.workspace-manifest.sha256.v1` algorithm.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DescriptorRelativeWorkspaceManifest {
    /// Exact manifest encoding version; currently one.
    pub format_version: u32,
    /// Authenticated workspace grant under which the descriptor root was opened.
    pub grant_hash: Digest,
    /// Runner-supplied time immediately before the stable descriptor scan began.
    pub capture_started_at_unix_ms: u64,
    /// Runner-supplied time after the complete stable descriptor scan finished.
    ///
    /// This is an evidence-finalization time, not a claim that an arbitrary
    /// external editor was frozen at one wall-clock instant.
    pub captured_at_unix_ms: u64,
    /// Entries in strict portable-path UTF-8 byte order.
    pub entries: Vec<DescriptorRelativeManifestEntry>,
    /// Exact existing manifest V1 digest of `entries`.
    pub manifest_digest: Digest,
}

impl DescriptorRelativeWorkspaceManifest {
    /// Constructs and authenticates a manifest from already descriptor-captured entries.
    ///
    /// The caller supplies the capture interval because only the runner owns
    /// the descriptor-relative stable scan. These timestamps describe the
    /// observation interval; they do not claim an operating-system snapshot or
    /// exclusion of arbitrary external editors. This constructor is not
    /// exposed in a request contract.
    ///
    /// # Errors
    ///
    /// Returns [`ContractError`] when an entry, ordering relationship, prefix
    /// relationship, count, timestamp, or encoded-size bound is invalid.
    pub fn from_captured_entries(
        grant_hash: Digest,
        capture_started_at_unix_ms: u64,
        captured_at_unix_ms: u64,
        entries: Vec<DescriptorRelativeManifestEntry>,
    ) -> Result<Self, ContractError> {
        let manifest_digest = compute_workspace_manifest_digest(&entries)?;
        let manifest = Self {
            format_version: DESCRIPTOR_RELATIVE_WORKSPACE_MANIFEST_FORMAT_VERSION,
            grant_hash,
            capture_started_at_unix_ms,
            captured_at_unix_ms,
            entries,
            manifest_digest,
        };
        manifest.validate()?;
        Ok(manifest)
    }

    /// Validates every manifest field and recomputes the exact manifest V1 digest.
    ///
    /// # Errors
    ///
    /// Returns [`ContractError`] for an unsupported format, invalid capture interval,
    /// invalid entry, noncanonical order, duplicate or file-prefix path,
    /// digest mismatch, or count/encoded-size bound violation.
    pub fn validate(&self) -> Result<(), ContractError> {
        if self.format_version != DESCRIPTOR_RELATIVE_WORKSPACE_MANIFEST_FORMAT_VERSION {
            return Err(ContractError::new(
                "descriptor_relative_workspace_manifest.format_version",
                format!(
                    "expected version {DESCRIPTOR_RELATIVE_WORKSPACE_MANIFEST_FORMAT_VERSION}, got {}",
                    self.format_version
                ),
            ));
        }
        if self.capture_started_at_unix_ms == 0 {
            return Err(ContractError::new(
                "descriptor_relative_workspace_manifest.capture_started_at_unix_ms",
                "must be greater than zero",
            ));
        }
        if self.captured_at_unix_ms < self.capture_started_at_unix_ms {
            return Err(ContractError::new(
                "descriptor_relative_workspace_manifest.captured_at_unix_ms",
                "must not precede the descriptor capture start",
            ));
        }
        validate_manifest_entries(&self.entries)?;
        let expected = compute_workspace_manifest_digest(&self.entries)?;
        if self.manifest_digest != expected {
            return Err(ContractError::new(
                "descriptor_relative_workspace_manifest.manifest_digest",
                "does not match the exact canonical manifest V1 preimage",
            ));
        }
        require_canonical_size(
            "descriptor_relative_workspace_manifest",
            self,
            MAX_DESCRIPTOR_RELATIVE_MANIFEST_BYTES,
        )
    }

    /// Recomputes the exact manifest V1 digest after validating every entry.
    ///
    /// # Errors
    ///
    /// Returns [`ContractError`] for an invalid entry, ordering, duplicate,
    /// prefix collision, or entry-count bound.
    pub fn computed_digest(&self) -> Result<Digest, ContractError> {
        validate_manifest_entries(&self.entries)?;
        compute_workspace_manifest_digest(&self.entries)
    }
}

/// Closed source branch for one sprint live-state capture.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub enum LiveStateCaptureBranch {
    /// Capture after a nonempty aggregate application and rollback validation.
    Applied {
        /// Exact passing sprint-wide verification receipt.
        final_verification_receipt_id: String,
        /// Exact successful live-workspace application receipt.
        application_receipt_id: String,
        /// Exact reopened rollback-reference receipt.
        rollback_reference_id: String,
    },
    /// Capture after the exact explicit-empty integrated `TaskDone` source.
    VerifiedNoOp {
        /// Exact passing sprint-wide verification receipt.
        final_verification_receipt_id: String,
        /// Exact successful integration receipt from the explicit-empty `TaskDone` proof.
        task_integration_receipt_id: String,
    },
    /// Reserved schema shape for a later known pre-application terminal tranche.
    KnownPreApplicationTerminal {
        /// Exact unsuccessful terminal record, once that tranche exists.
        terminal_record_id: String,
    },
}

impl LiveStateCaptureBranch {
    fn validate_shape(&self) -> Result<(), ContractError> {
        match self {
            Self::Applied {
                final_verification_receipt_id,
                application_receipt_id,
                rollback_reference_id,
            } => {
                require_live_state_id(
                    "live_state_capture_branch.final_verification_receipt_id",
                    final_verification_receipt_id,
                )?;
                require_live_state_id(
                    "live_state_capture_branch.application_receipt_id",
                    application_receipt_id,
                )?;
                require_live_state_id(
                    "live_state_capture_branch.rollback_reference_id",
                    rollback_reference_id,
                )
            }
            Self::VerifiedNoOp {
                final_verification_receipt_id,
                task_integration_receipt_id,
            } => {
                require_live_state_id(
                    "live_state_capture_branch.final_verification_receipt_id",
                    final_verification_receipt_id,
                )?;
                require_live_state_id(
                    "live_state_capture_branch.task_integration_receipt_id",
                    task_integration_receipt_id,
                )
            }
            Self::KnownPreApplicationTerminal { terminal_record_id } => require_live_state_id(
                "live_state_capture_branch.terminal_record_id",
                terminal_record_id,
            ),
        }
    }

    fn validate_current(&self) -> Result<(), ContractError> {
        self.validate_shape()?;
        if matches!(self, Self::KnownPreApplicationTerminal { .. }) {
            return Err(ContractError::new(
                "live_state_capture_branch",
                "KnownPreApplicationTerminal is reserved and has no schema-v23 runtime authority",
            ));
        }
        Ok(())
    }
}

/// Exact durable high-water cut from which core derives a capture plan.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SprintLiveStateCapturePlanCut {
    /// Stable capture-plan identity.
    pub plan_id: String,
    /// Exact latest agent event visible when the plan was derived.
    pub source_event_id: String,
    /// Nonzero sequence of `source_event_id` in the sprint event stream.
    pub source_event_sequence: u64,
    /// Durable plan-derivation time; never the later runner capture time.
    pub planned_at_unix_ms: u64,
}

/// Serializable, non-executable core derivation for one live-state capture.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SprintLiveStateCapturePlan {
    /// Wire-contract version.
    pub contract_version: u32,
    /// Stable capture-plan identity.
    pub plan_id: String,
    /// Owning sprint.
    pub sprint_id: String,
    /// Exact applied or verified-no-op finish source.
    pub branch: LiveStateCaptureBranch,
    /// Snapshot the complete captured manifest is expected to reproduce.
    pub expected_snapshot: Digest,
    /// Exact workspace grant authorizing the descriptor root.
    pub grant_hash: Digest,
    /// Exact compiler-produced read-only live-state-verifier policy.
    pub policy_hash: Digest,
    /// Exact workspace-grant policy version.
    pub policy_version: u32,
    /// Latest durable event visible at plan derivation.
    pub source_event_id: String,
    /// Exact nonzero sequence of `source_event_id`.
    pub source_event_sequence: u64,
    /// Canonically sorted exact cleanup receipts required before capture launch.
    pub required_cleanup_receipt_ids: Vec<String>,
    /// Domain-separated digest of the exact ordered cleanup receipt set.
    pub required_cleanup_set_digest: Digest,
    /// Core plan-derivation time, before runner launch and capture.
    pub planned_at_unix_ms: u64,
}

impl SprintLiveStateCapturePlan {
    /// Derives the applied-branch plan from exact successful source contracts.
    ///
    /// # Errors
    ///
    /// Returns [`ContractError`] unless the final verification, application,
    /// rollback reference, sprint, read-only policy, prior cleanup set,
    /// snapshots, grant, policy version, and causal times agree exactly.
    #[allow(clippy::too_many_arguments)]
    pub fn derive_applied(
        cut: SprintLiveStateCapturePlanCut,
        sprint: &SprintSpec,
        verifier_policy: &CompiledExecutionPolicy,
        final_verification_evidence: &VerificationEffectEvidence,
        application_evidence: &ApplicationEvidence,
        rollback_reference_evidence: &RollbackReferenceEvidence,
        required_cleanup_evidence: &[WorkerCleanupEvidence],
    ) -> Result<Self, ContractError> {
        validate_common_plan_sources(&cut, sprint, verifier_policy, required_cleanup_evidence)?;
        final_verification_evidence.validate()?;
        application_evidence.validate()?;
        rollback_reference_evidence.validate()?;
        let final_verification = &final_verification_evidence.verification;
        let application = &application_evidence.receipt;
        let rollback_reference = &rollback_reference_evidence.reference;
        if final_verification.sprint_id != sprint.sprint_id
            || final_verification.task_id.is_some()
            || !final_verification.passed()
            || final_verification.snapshot_id != application.result_snapshot
        {
            return Err(ContractError::new(
                "sprint_live_state_capture_plan.final_verification",
                "must be the passing sprint-wide verification of the exact applied result snapshot",
            ));
        }
        if application.sprint_id != sprint.sprint_id
            || application.base_snapshot != sprint.base_snapshot
            || application.grant_hash != sprint.workspace_grant.grant_hash
            || application.policy_version != sprint.workspace_grant.policy_version
        {
            return Err(ContractError::new(
                "sprint_live_state_capture_plan.application",
                "must be the same-sprint application from the exact base grant and policy version",
            ));
        }
        if rollback_reference.sprint_id != sprint.sprint_id
            || rollback_reference.application_receipt_id != application.receipt_id
            || rollback_reference.transaction_id != application.transaction_id
            || rollback_reference.base_snapshot != sprint.base_snapshot
            || rollback_reference.journal_binding_digest != application.journal_binding_digest()?
        {
            return Err(ContractError::new(
                "sprint_live_state_capture_plan.rollback_reference",
                "must reopen the exact same-sprint application transaction and sprint base",
            ));
        }
        if final_verification.finished_at_unix_ms > application.applied_at_unix_ms
            || application.applied_at_unix_ms > rollback_reference.validated_at_unix_ms
            || rollback_reference.validated_at_unix_ms > cut.planned_at_unix_ms
        {
            return Err(ContractError::new(
                "sprint_live_state_capture_plan.source_order",
                "requires final verification <= application <= rollback validation <= plan derivation",
            ));
        }
        let branch = LiveStateCaptureBranch::Applied {
            final_verification_receipt_id: final_verification.receipt_id.clone(),
            application_receipt_id: application.receipt_id.clone(),
            rollback_reference_id: rollback_reference.reference_id.clone(),
        };
        Self::from_validated_sources(
            cut,
            sprint,
            verifier_policy,
            branch,
            application.result_snapshot.clone(),
            required_cleanup_evidence,
        )
    }

    /// Derives the verified-no-op plan from one exact explicit-empty `TaskDone` source.
    ///
    /// # Errors
    ///
    /// Returns [`ContractError`] unless the `TaskDone` proof contains the exact
    /// empty integrated change set at the sprint base, final verification passes
    /// that same base, and all grant, policy, cleanup, identity, and time fields
    /// agree.
    pub fn derive_verified_no_op(
        cut: SprintLiveStateCapturePlanCut,
        sprint: &SprintSpec,
        verifier_policy: &CompiledExecutionPolicy,
        final_verification_evidence: &VerificationEffectEvidence,
        task_done_source: &TaskDoneProof,
        required_cleanup_evidence: &[WorkerCleanupEvidence],
    ) -> Result<Self, ContractError> {
        validate_common_plan_sources(&cut, sprint, verifier_policy, required_cleanup_evidence)?;
        final_verification_evidence.validate()?;
        let final_verification = &final_verification_evidence.verification;
        task_done_source.change_set.validate()?;
        task_done_source.integration_receipt.validate()?;
        let integration = &task_done_source.integration_receipt;
        let change_set = &task_done_source.change_set;
        if task_done_source.sprint_id != sprint.sprint_id
            || integration.sprint_id != sprint.sprint_id
            || integration.task_id != task_done_source.task_id
            || integration.change_set_id != change_set.change_set_id
            || integration.input_snapshot != change_set.base_snapshot
            || integration.result_snapshot != change_set.result_snapshot
            || !change_set.operations.is_empty()
            || change_set.base_snapshot != sprint.base_snapshot
            || change_set.result_snapshot != sprint.base_snapshot
        {
            return Err(ContractError::new(
                "sprint_live_state_capture_plan.task_done_source",
                "must be the exact explicit-empty integrated TaskDone result at the sprint base snapshot",
            ));
        }
        if final_verification.sprint_id != sprint.sprint_id
            || final_verification.task_id.is_some()
            || !final_verification.passed()
            || final_verification.snapshot_id != sprint.base_snapshot
        {
            return Err(ContractError::new(
                "sprint_live_state_capture_plan.final_verification",
                "must be the passing sprint-wide verification of the exact no-op base snapshot",
            ));
        }
        if integration.integrated_at_unix_ms > final_verification.finished_at_unix_ms
            || final_verification.finished_at_unix_ms > cut.planned_at_unix_ms
        {
            return Err(ContractError::new(
                "sprint_live_state_capture_plan.source_order",
                "requires TaskDone integration <= final verification <= plan derivation",
            ));
        }
        let branch = LiveStateCaptureBranch::VerifiedNoOp {
            final_verification_receipt_id: final_verification.receipt_id.clone(),
            task_integration_receipt_id: integration.receipt_id.clone(),
        };
        Self::from_validated_sources(
            cut,
            sprint,
            verifier_policy,
            branch,
            sprint.base_snapshot.clone(),
            required_cleanup_evidence,
        )
    }

    fn from_validated_sources(
        cut: SprintLiveStateCapturePlanCut,
        sprint: &SprintSpec,
        verifier_policy: &CompiledExecutionPolicy,
        branch: LiveStateCaptureBranch,
        expected_snapshot: Digest,
        required_cleanup_evidence: &[WorkerCleanupEvidence],
    ) -> Result<Self, ContractError> {
        let mut required_cleanup_receipt_ids = required_cleanup_evidence
            .iter()
            .map(|evidence| evidence.receipt.receipt_id.clone())
            .collect::<Vec<_>>();
        required_cleanup_receipt_ids.sort();
        let required_cleanup_set_digest =
            compute_required_cleanup_set_digest(&required_cleanup_receipt_ids)?;
        let policy = verifier_policy.contract();
        let plan = Self {
            contract_version: CONTRACT_VERSION,
            plan_id: cut.plan_id,
            sprint_id: sprint.sprint_id.clone(),
            branch,
            expected_snapshot,
            grant_hash: sprint.workspace_grant.grant_hash.clone(),
            policy_hash: policy.policy_hash.clone(),
            policy_version: sprint.workspace_grant.policy_version,
            source_event_id: cut.source_event_id,
            source_event_sequence: cut.source_event_sequence,
            required_cleanup_receipt_ids,
            required_cleanup_set_digest,
            planned_at_unix_ms: cut.planned_at_unix_ms,
        };
        plan.validate()?;
        Ok(plan)
    }

    /// Validates the current-schema structural plan and its canonical cleanup digest.
    ///
    /// This does not replace the ledger's joins to branch source rows, the
    /// high-water event cut, or the complete prior cleanup set.
    ///
    /// # Errors
    ///
    /// Returns [`ContractError`] for an unsupported version, reserved branch,
    /// invalid identity, zero sequence/version/time, noncanonical cleanup set,
    /// digest mismatch, or oversized canonical plan.
    pub fn validate(&self) -> Result<(), ContractError> {
        require_contract_version(
            "sprint_live_state_capture_plan.contract_version",
            self.contract_version,
        )?;
        require_live_state_id("sprint_live_state_capture_plan.plan_id", &self.plan_id)?;
        require_live_state_id("sprint_live_state_capture_plan.sprint_id", &self.sprint_id)?;
        self.branch.validate_current()?;
        if self.policy_version == 0 {
            return Err(ContractError::new(
                "sprint_live_state_capture_plan.policy_version",
                "must be greater than zero",
            ));
        }
        require_live_state_id(
            "sprint_live_state_capture_plan.source_event_id",
            &self.source_event_id,
        )?;
        if self.source_event_sequence == 0 {
            return Err(ContractError::new(
                "sprint_live_state_capture_plan.source_event_sequence",
                "must be greater than zero",
            ));
        }
        if self.planned_at_unix_ms == 0 {
            return Err(ContractError::new(
                "sprint_live_state_capture_plan.planned_at_unix_ms",
                "must be greater than zero",
            ));
        }
        validate_cleanup_ids(&self.required_cleanup_receipt_ids)?;
        let expected_cleanup_digest =
            compute_required_cleanup_set_digest(&self.required_cleanup_receipt_ids)?;
        if self.required_cleanup_set_digest != expected_cleanup_digest {
            return Err(ContractError::new(
                "sprint_live_state_capture_plan.required_cleanup_set_digest",
                "does not authenticate the exact ordered cleanup receipt set",
            ));
        }
        require_canonical_size(
            "sprint_live_state_capture_plan",
            self,
            MAX_LIVE_STATE_CAPTURE_REQUEST_BYTES,
        )
    }

    /// Computes a domain-separated digest of the exact canonical plan bytes.
    ///
    /// # Errors
    ///
    /// Returns [`ContractError`] when the current plan is invalid or cannot be encoded.
    pub fn plan_digest(&self) -> Result<Digest, ContractError> {
        self.validate()?;
        digest_canonical(CAPTURE_PLAN_DOMAIN, self, "sprint_live_state_capture_plan")
    }
}

/// Exact canonical request committed before live-state capture dispatch.
///
/// This request intentionally contains no capture timestamp. The runner alone
/// observes and reports the bounded stable descriptor-scan interval.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SprintLiveStateCaptureRequest {
    /// Wire-contract version.
    pub contract_version: u32,
    /// Exact core-derived plan and pre-capture high-water cut.
    pub plan: SprintLiveStateCapturePlan,
}

impl SprintLiveStateCaptureRequest {
    /// Constructs a request from a validated current-schema plan.
    ///
    /// # Errors
    ///
    /// Returns [`ContractError`] when the plan or encoded request is invalid.
    pub fn from_plan(plan: SprintLiveStateCapturePlan) -> Result<Self, ContractError> {
        let request = Self {
            contract_version: CONTRACT_VERSION,
            plan,
        };
        request.validate()?;
        Ok(request)
    }

    /// Validates the exact plan and canonical request-size bound.
    ///
    /// # Errors
    ///
    /// Returns [`ContractError`] for an unsupported version, invalid plan, or
    /// oversized canonical request.
    pub fn validate(&self) -> Result<(), ContractError> {
        require_contract_version(
            "sprint_live_state_capture_request.contract_version",
            self.contract_version,
        )?;
        self.plan.validate()?;
        require_canonical_size(
            "sprint_live_state_capture_request",
            self,
            MAX_LIVE_STATE_CAPTURE_REQUEST_BYTES,
        )
    }

    /// Returns the SHA-256 digest of the exact canonical request bytes.
    ///
    /// This deliberately matches the existing effect-intent convention: the
    /// digest is over the request bytes themselves, without an added domain.
    ///
    /// # Errors
    ///
    /// Returns [`ContractError`] when the request is invalid or cannot be encoded.
    pub fn request_digest(&self) -> Result<Digest, ContractError> {
        self.validate()?;
        let encoded = canonical_bytes("sprint_live_state_capture_request", self)?;
        Ok(Digest::sha256(&encoded))
    }
}

/// Effect-bound receipt for one complete live-workspace capture.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LiveStateCaptureReceipt {
    /// Wire-contract version.
    pub contract_version: u32,
    /// Globally unique capture receipt.
    pub receipt_id: String,
    /// Exact ledger admission that joined plan, session, and effect.
    pub admission_id: String,
    /// Exact successful capture effect.
    pub effect_id: String,
    /// Exact successful effect observation.
    pub observation_id: String,
    /// Exact one-use durable dispatch claim.
    pub dispatch_claim_id: String,
    /// Owning sprint.
    pub sprint_id: String,
    /// Exact core-derived plan identity copied from the request.
    pub plan_id: String,
    /// Domain-separated digest of the exact core-derived plan.
    pub plan_digest: Digest,
    /// SHA-256 digest of the exact canonical request bytes.
    pub request_digest: Digest,
    /// Exact finish branch copied from the request plan.
    pub branch: LiveStateCaptureBranch,
    /// Snapshot expected by the plan.
    pub expected_snapshot: Digest,
    /// Snapshot actually recomputed from descriptor-relative capture.
    pub observed_snapshot: Digest,
    /// Exact pre-spawn live-state-verifier launch.
    pub runner_launch_id: String,
    /// Exact initialized live-state-verifier session.
    pub runner_session_id: String,
    /// Exact compiler-produced read-only verifier policy.
    pub policy_hash: Digest,
    /// Exact authenticated workspace grant.
    pub grant_hash: Digest,
    /// Exact workspace-grant policy version.
    pub policy_version: u32,
    /// Exact digest of the retained complete manifest.
    pub manifest_digest: Digest,
    /// Runner-supplied time immediately before the stable descriptor scan began.
    pub capture_started_at_unix_ms: u64,
    /// Runner-supplied evidence-finalization time after the stable scan completed.
    pub captured_at_unix_ms: u64,
}

impl LiveStateCaptureReceipt {
    /// Validates the closed receipt envelope without claiming snapshot equality.
    ///
    /// A valid capture may truthfully observe drift, so `observed_snapshot`
    /// need not equal `expected_snapshot`; only exact matching capture evidence
    /// may later authorize successful completion.
    ///
    /// # Errors
    ///
    /// Returns [`ContractError`] for an invalid version, identity, branch,
    /// policy version, timestamp, or observed/manifest digest mismatch.
    pub fn validate(&self) -> Result<(), ContractError> {
        require_contract_version(
            "live_state_capture_receipt.contract_version",
            self.contract_version,
        )?;
        for (field, value) in [
            ("live_state_capture_receipt.receipt_id", &self.receipt_id),
            (
                "live_state_capture_receipt.admission_id",
                &self.admission_id,
            ),
            ("live_state_capture_receipt.effect_id", &self.effect_id),
            (
                "live_state_capture_receipt.observation_id",
                &self.observation_id,
            ),
            (
                "live_state_capture_receipt.dispatch_claim_id",
                &self.dispatch_claim_id,
            ),
            ("live_state_capture_receipt.sprint_id", &self.sprint_id),
            ("live_state_capture_receipt.plan_id", &self.plan_id),
            (
                "live_state_capture_receipt.runner_launch_id",
                &self.runner_launch_id,
            ),
            (
                "live_state_capture_receipt.runner_session_id",
                &self.runner_session_id,
            ),
        ] {
            require_live_state_id(field, value)?;
        }
        self.branch.validate_current()?;
        if self.policy_version == 0 {
            return Err(ContractError::new(
                "live_state_capture_receipt.policy_version",
                "must be greater than zero",
            ));
        }
        if self.capture_started_at_unix_ms == 0 {
            return Err(ContractError::new(
                "live_state_capture_receipt.capture_started_at_unix_ms",
                "must be greater than zero",
            ));
        }
        if self.captured_at_unix_ms < self.capture_started_at_unix_ms {
            return Err(ContractError::new(
                "live_state_capture_receipt.captured_at_unix_ms",
                "must not precede the descriptor capture start",
            ));
        }
        if self.observed_snapshot != self.manifest_digest {
            return Err(ContractError::new(
                "live_state_capture_receipt.observed_snapshot",
                "must equal the exact retained manifest digest",
            ));
        }
        Ok(())
    }
}

/// Complete typed evidence preimage for one successful capture effect.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LiveStateCaptureEvidence {
    /// Wire-contract version.
    pub contract_version: u32,
    /// Exact effect-bound indexed capture receipt.
    pub receipt: LiveStateCaptureReceipt,
    /// Complete descriptor-relative manifest authenticated by the receipt.
    pub manifest: DescriptorRelativeWorkspaceManifest,
}

impl LiveStateCaptureEvidence {
    /// Validates the evidence, retained manifest, and exact cross-fields.
    ///
    /// # Errors
    ///
    /// Returns [`ContractError`] for an invalid child, crossed grant/time/digest,
    /// or oversized canonical evidence.
    pub fn validate(&self) -> Result<(), ContractError> {
        require_contract_version(
            "live_state_capture_evidence.contract_version",
            self.contract_version,
        )?;
        self.receipt.validate()?;
        self.manifest.validate()?;
        if self.manifest.grant_hash != self.receipt.grant_hash
            || self.manifest.capture_started_at_unix_ms != self.receipt.capture_started_at_unix_ms
            || self.manifest.captured_at_unix_ms != self.receipt.captured_at_unix_ms
            || self.manifest.manifest_digest != self.receipt.manifest_digest
        {
            return Err(ContractError::new(
                "live_state_capture_evidence.manifest",
                "must exactly match the receipt grant, capture interval, and manifest digest",
            ));
        }
        require_canonical_size(
            "live_state_capture_evidence",
            self,
            MAX_LIVE_STATE_CAPTURE_EVIDENCE_BYTES,
        )
    }

    /// Validates this evidence against the exact pre-capture request.
    ///
    /// The capture interval is accepted only from evidence and must begin
    /// after plan derivation. A mismatched observed snapshot remains valid capture
    /// evidence but cannot satisfy the later completion equality predicate.
    ///
    /// # Errors
    ///
    /// Returns [`ContractError`] for a crossed sprint, branch, expected
    /// snapshot, grant, policy, policy version, or pre-plan capture time.
    pub fn validate_against_request(
        &self,
        request: &SprintLiveStateCaptureRequest,
    ) -> Result<(), ContractError> {
        self.validate()?;
        request.validate()?;
        let plan = &request.plan;
        let receipt = &self.receipt;
        if receipt.sprint_id != plan.sprint_id
            || receipt.plan_id != plan.plan_id
            || receipt.plan_digest != plan.plan_digest()?
            || receipt.request_digest != request.request_digest()?
            || receipt.branch != plan.branch
            || receipt.expected_snapshot != plan.expected_snapshot
            || receipt.grant_hash != plan.grant_hash
            || receipt.policy_hash != plan.policy_hash
            || receipt.policy_version != plan.policy_version
        {
            return Err(ContractError::new(
                "live_state_capture_evidence.request",
                "must retain the request's exact sprint, branch, expected snapshot, grant, and policy",
            ));
        }
        if receipt.capture_started_at_unix_ms < plan.planned_at_unix_ms {
            return Err(ContractError::new(
                "live_state_capture_receipt.capture_started_at_unix_ms",
                "capture must not begin before core plan derivation",
            ));
        }
        Ok(())
    }

    /// Returns whether the captured live state exactly satisfies the planned snapshot.
    #[must_use]
    pub fn matches_expected_snapshot(&self) -> bool {
        self.receipt.observed_snapshot == self.receipt.expected_snapshot
    }
}

/// Exact completion branch retained by the additive live-state link.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub enum CompletionLiveStateApplicationLink {
    /// A successful application and its usable rollback reference.
    Applied {
        /// Exact application receipt selected by completion and capture.
        application_receipt_id: String,
        /// Exact reopened rollback reference selected by completion and capture.
        rollback_reference_id: String,
    },
    /// The verified sprint base already satisfies the objective.
    VerifiedNoOp {
        /// Exact no-op receipt derived from the selected capture.
        verified_no_op_receipt_id: String,
        /// Exact explicit-empty `TaskDone` integration selected by the capture plan.
        task_integration_receipt_id: String,
    },
}

impl CompletionLiveStateApplicationLink {
    fn validate(&self) -> Result<(), ContractError> {
        match self {
            Self::Applied {
                application_receipt_id,
                rollback_reference_id,
            } => {
                require_live_state_id(
                    "completion_live_state_application_link.application_receipt_id",
                    application_receipt_id,
                )?;
                require_live_state_id(
                    "completion_live_state_application_link.rollback_reference_id",
                    rollback_reference_id,
                )
            }
            Self::VerifiedNoOp {
                verified_no_op_receipt_id,
                task_integration_receipt_id,
            } => {
                require_live_state_id(
                    "completion_live_state_application_link.verified_no_op_receipt_id",
                    verified_no_op_receipt_id,
                )?;
                require_live_state_id(
                    "completion_live_state_application_link.task_integration_receipt_id",
                    task_integration_receipt_id,
                )
            }
        }
    }
}

/// Exact successful capture lifecycle copied into completion authority.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CompletionLiveStateCaptureAuthority {
    /// Successful capture receipt.
    pub capture_receipt_id: String,
    /// Exact capture admission.
    pub admission_id: String,
    /// Exact core-derived capture plan.
    pub plan_id: String,
    /// Domain-separated digest of the canonical capture plan.
    pub plan_digest: Digest,
    /// Exact successful capture effect.
    pub effect_id: String,
    /// Exact successful capture observation.
    pub observation_id: String,
    /// Exact one-use runner dispatch claim.
    pub dispatch_claim_id: String,
    /// Selected live-state-verifier launch.
    pub runner_launch_id: String,
    /// Selected live-state-verifier session.
    pub runner_session_id: String,
    /// Snapshot expected at plan derivation.
    pub expected_snapshot: Digest,
    /// Snapshot observed by descriptor-relative capture.
    pub observed_snapshot: Digest,
    /// Digest of the exact retained manifest.
    pub manifest_digest: Digest,
}

impl CompletionLiveStateCaptureAuthority {
    fn validate(&self) -> Result<(), ContractError> {
        for (field, value) in [
            (
                "completion_live_state_capture_authority.capture_receipt_id",
                &self.capture_receipt_id,
            ),
            (
                "completion_live_state_capture_authority.admission_id",
                &self.admission_id,
            ),
            (
                "completion_live_state_capture_authority.plan_id",
                &self.plan_id,
            ),
            (
                "completion_live_state_capture_authority.effect_id",
                &self.effect_id,
            ),
            (
                "completion_live_state_capture_authority.observation_id",
                &self.observation_id,
            ),
            (
                "completion_live_state_capture_authority.dispatch_claim_id",
                &self.dispatch_claim_id,
            ),
            (
                "completion_live_state_capture_authority.runner_launch_id",
                &self.runner_launch_id,
            ),
            (
                "completion_live_state_capture_authority.runner_session_id",
                &self.runner_session_id,
            ),
        ] {
            require_live_state_id(field, value)?;
        }
        if self.expected_snapshot != self.observed_snapshot
            || self.observed_snapshot != self.manifest_digest
        {
            return Err(ContractError::new(
                "completion_live_state_capture_authority.observed_snapshot",
                "expected, observed, and manifest digests must be identical",
            ));
        }
        Ok(())
    }
}

/// Immutable additive authority joining an unchanged v1 completion receipt to
/// one exact successful descriptor-relative capture.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CompletionLiveStateCaptureLink {
    /// Wire-contract version.
    pub contract_version: u32,
    /// Owning sprint.
    pub sprint_id: String,
    /// Unchanged v1 completion receipt identity.
    pub completion_receipt_id: String,
    /// SHA-256 of the exact canonical v1 completion receipt bytes.
    pub completion_receipt_digest: Digest,
    /// Exact completed workspace snapshot.
    pub final_snapshot: Digest,
    /// Authenticated workspace grant.
    pub grant_hash: Digest,
    /// Exact compiler-produced live-state-verifier policy.
    pub policy_hash: Digest,
    /// Workspace-grant policy version.
    pub policy_version: u32,
    /// Exact sprint-wide passing verification.
    pub final_verification_receipt_id: String,
    /// Exact applied or verified-no-op branch.
    pub application: CompletionLiveStateApplicationLink,
    /// Complete selected capture lifecycle.
    pub capture: CompletionLiveStateCaptureAuthority,
    /// Exact zero-survivor cleanup of the selected verifier.
    pub verifier_cleanup_receipt_id: String,
    /// Start of the descriptor-relative stable scan.
    pub capture_started_at_unix_ms: u64,
    /// End of the descriptor-relative stable scan.
    pub captured_at_unix_ms: u64,
    /// Completion time of selected verifier cleanup.
    pub verifier_cleaned_at_unix_ms: u64,
    /// Completion/event/proof time.
    pub completed_at_unix_ms: u64,
}

impl CompletionLiveStateCaptureLink {
    /// Validates the closed link envelope and completion-time ordering.
    ///
    /// # Errors
    ///
    /// Returns [`ContractError`] for an unsupported version, invalid identity,
    /// crossed snapshot, invalid branch, reversed timestamp, or oversized
    /// canonical envelope.
    pub fn validate(&self) -> Result<(), ContractError> {
        require_contract_version(
            "completion_live_state_capture_link.contract_version",
            self.contract_version,
        )?;
        for (field, value) in [
            (
                "completion_live_state_capture_link.sprint_id",
                &self.sprint_id,
            ),
            (
                "completion_live_state_capture_link.completion_receipt_id",
                &self.completion_receipt_id,
            ),
            (
                "completion_live_state_capture_link.final_verification_receipt_id",
                &self.final_verification_receipt_id,
            ),
            (
                "completion_live_state_capture_link.verifier_cleanup_receipt_id",
                &self.verifier_cleanup_receipt_id,
            ),
        ] {
            require_live_state_id(field, value)?;
        }
        if self.policy_version == 0 {
            return Err(ContractError::new(
                "completion_live_state_capture_link.policy_version",
                "must be greater than zero",
            ));
        }
        self.application.validate()?;
        self.capture.validate()?;
        if self.final_snapshot != self.capture.expected_snapshot {
            return Err(ContractError::new(
                "completion_live_state_capture_link.final_snapshot",
                "must equal the selected capture expected, observed, and manifest digest",
            ));
        }
        if self.capture_started_at_unix_ms == 0
            || self.captured_at_unix_ms < self.capture_started_at_unix_ms
            || self.verifier_cleaned_at_unix_ms < self.captured_at_unix_ms
            || self.completed_at_unix_ms < self.verifier_cleaned_at_unix_ms
        {
            return Err(ContractError::new(
                "completion_live_state_capture_link.timestamps",
                "must order capture start, capture end, verifier cleanup, and completion",
            ));
        }
        require_canonical_size(
            "completion_live_state_capture_link",
            self,
            MAX_COMPLETION_LIVE_STATE_CAPTURE_LINK_BYTES,
        )
    }
}

/// Immutable terminal authority proving that one exact successful live-state
/// capture observed bytes different from its selected finish snapshot.
///
/// This proof does not claim that the live workspace is unchanged, rolled
/// back, or conflicted at an application endpoint. Its identity deliberately
/// reuses the normalized terminal record/event identity, avoiding a second
/// unconstrained proof namespace. The ledger derives every lifecycle field
/// from already-durable capture, branch, and verifier-cleanup evidence.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LiveStateDriftBlockedProof {
    /// Wire-contract version.
    pub contract_version: u32,
    /// Owning sprint.
    pub sprint_id: String,
    /// Exact normalized `Blocked` terminal evidence and event identity.
    pub terminal_record_id: String,
    /// SHA-256 of the exact canonical terminal-evidence bytes.
    pub terminal_evidence_digest: Digest,
    /// Exact applied or verified-no-op branch selected before capture.
    pub branch: LiveStateCaptureBranch,
    /// Exact successful live-state capture receipt.
    pub capture_receipt_id: String,
    /// Exact admission joining the capture plan, effect, launch, and session.
    pub capture_admission_id: String,
    /// Exact core-derived capture plan.
    pub capture_plan_id: String,
    /// Domain-separated digest of the exact canonical capture plan.
    pub capture_plan_digest: Digest,
    /// Exact successful capture effect.
    pub capture_effect_id: String,
    /// Exact successful capture observation.
    pub capture_observation_id: String,
    /// Exact one-use runner dispatch claim.
    pub capture_dispatch_claim_id: String,
    /// Exact live-state-verifier launch.
    pub runner_launch_id: String,
    /// Exact live-state-verifier session.
    pub runner_session_id: String,
    /// SHA-256 of the complete canonical capture-evidence bytes.
    pub capture_evidence_digest: Digest,
    /// Snapshot selected by the durable finish branch.
    pub expected_snapshot: Digest,
    /// Snapshot recomputed from the descriptor-relative manifest.
    pub observed_snapshot: Digest,
    /// Digest of the complete retained descriptor-relative manifest.
    pub manifest_digest: Digest,
    /// Authenticated workspace grant used by capture and cleanup.
    pub grant_hash: Digest,
    /// Exact compiler-produced read-only verifier policy.
    pub policy_hash: Digest,
    /// Workspace-grant policy version.
    pub policy_version: u32,
    /// Exact zero-survivor cleanup of the selected verifier.
    pub verifier_cleanup_receipt_id: String,
    /// Digest authenticating the plan's complete prior-cleanup set.
    pub required_cleanup_set_digest: Digest,
    /// Start of the stable descriptor-relative scan.
    pub capture_started_at_unix_ms: u64,
    /// End of the stable descriptor-relative scan.
    pub captured_at_unix_ms: u64,
    /// Completion time of the selected verifier cleanup.
    pub verifier_cleaned_at_unix_ms: u64,
    /// Time of the normalized `Blocked` evidence and event.
    pub blocked_at_unix_ms: u64,
}

impl LiveStateDriftBlockedProof {
    /// Validates the closed drift envelope without granting ledger authority.
    ///
    /// # Errors
    ///
    /// Returns [`ContractError`] for an unsupported version, reserved branch,
    /// invalid identity, matching expected/observed snapshots, a manifest
    /// mismatch, reversed lifecycle time, zero policy version, or oversized
    /// canonical envelope.
    pub fn validate(&self) -> Result<(), ContractError> {
        require_contract_version(
            "live_state_drift_blocked_proof.contract_version",
            self.contract_version,
        )?;
        self.branch.validate_current()?;
        for (field, value) in [
            ("live_state_drift_blocked_proof.sprint_id", &self.sprint_id),
            (
                "live_state_drift_blocked_proof.terminal_record_id",
                &self.terminal_record_id,
            ),
            (
                "live_state_drift_blocked_proof.capture_receipt_id",
                &self.capture_receipt_id,
            ),
            (
                "live_state_drift_blocked_proof.capture_admission_id",
                &self.capture_admission_id,
            ),
            (
                "live_state_drift_blocked_proof.capture_plan_id",
                &self.capture_plan_id,
            ),
            (
                "live_state_drift_blocked_proof.capture_effect_id",
                &self.capture_effect_id,
            ),
            (
                "live_state_drift_blocked_proof.capture_observation_id",
                &self.capture_observation_id,
            ),
            (
                "live_state_drift_blocked_proof.capture_dispatch_claim_id",
                &self.capture_dispatch_claim_id,
            ),
            (
                "live_state_drift_blocked_proof.runner_launch_id",
                &self.runner_launch_id,
            ),
            (
                "live_state_drift_blocked_proof.runner_session_id",
                &self.runner_session_id,
            ),
            (
                "live_state_drift_blocked_proof.verifier_cleanup_receipt_id",
                &self.verifier_cleanup_receipt_id,
            ),
        ] {
            require_live_state_id(field, value)?;
        }
        if self.policy_version == 0 {
            return Err(ContractError::new(
                "live_state_drift_blocked_proof.policy_version",
                "must be greater than zero",
            ));
        }
        if self.observed_snapshot != self.manifest_digest {
            return Err(ContractError::new(
                "live_state_drift_blocked_proof.manifest_digest",
                "must equal the snapshot recomputed from the retained manifest",
            ));
        }
        if self.expected_snapshot == self.observed_snapshot {
            return Err(ContractError::new(
                "live_state_drift_blocked_proof.observed_snapshot",
                "must differ from the selected finish snapshot",
            ));
        }
        if self.capture_started_at_unix_ms == 0
            || self.captured_at_unix_ms < self.capture_started_at_unix_ms
            || self.verifier_cleaned_at_unix_ms < self.captured_at_unix_ms
            || self.blocked_at_unix_ms < self.verifier_cleaned_at_unix_ms
        {
            return Err(ContractError::new(
                "live_state_drift_blocked_proof.timestamps",
                "must order capture start, capture end, verifier cleanup, and Blocked terminalization",
            ));
        }
        require_canonical_size(
            "live_state_drift_blocked_proof",
            self,
            MAX_LIVE_STATE_DRIFT_BLOCKED_PROOF_BYTES,
        )
    }
}

fn validate_manifest_entries(
    entries: &[DescriptorRelativeManifestEntry],
) -> Result<(), ContractError> {
    if entries.len() > MAX_DESCRIPTOR_RELATIVE_MANIFEST_ENTRIES {
        return Err(ContractError::new(
            "descriptor_relative_workspace_manifest.entries",
            format!("must not exceed {MAX_DESCRIPTOR_RELATIVE_MANIFEST_ENTRIES} entries"),
        ));
    }
    let mut prior_paths = BTreeSet::new();
    let mut previous: Option<&str> = None;
    for entry in entries {
        entry.validate()?;
        if previous.is_some_and(|prior| prior.as_bytes() >= entry.path.as_bytes()) {
            return Err(ContractError::new(
                "descriptor_relative_workspace_manifest.entries",
                "paths must be unique and in strict portable UTF-8 byte order",
            ));
        }
        for (separator, _) in entry.path.match_indices('/') {
            if prior_paths.contains(&entry.path[..separator]) {
                return Err(ContractError::new(
                    "descriptor_relative_workspace_manifest.entries",
                    format!(
                        "regular-file path `{}` is a prefix of `{}`",
                        &entry.path[..separator],
                        entry.path
                    ),
                ));
            }
        }
        prior_paths.insert(entry.path.as_str());
        previous = Some(&entry.path);
    }
    Ok(())
}

fn validate_manifest_path(path: &str) -> Result<(), ContractError> {
    if path.is_empty() {
        return Err(ContractError::new(
            "descriptor_relative_manifest_entry.path",
            "must be nonempty",
        ));
    }
    if path.len() > MAX_DESCRIPTOR_RELATIVE_MANIFEST_PATH_BYTES {
        return Err(ContractError::new(
            "descriptor_relative_manifest_entry.path",
            format!("must not exceed {MAX_DESCRIPTOR_RELATIVE_MANIFEST_PATH_BYTES} UTF-8 bytes"),
        ));
    }
    if path.starts_with('/') || path.contains('\\') || path.as_bytes().contains(&0) {
        return Err(ContractError::new(
            "descriptor_relative_manifest_entry.path",
            "must use normalized relative UTF-8 slash form without backslash or NUL",
        ));
    }
    for component in path.split('/') {
        if component.is_empty()
            || component == "."
            || component == ".."
            || component.eq_ignore_ascii_case(".git")
        {
            return Err(ContractError::new(
                "descriptor_relative_manifest_entry.path",
                "must not contain empty, dot, parent, or protected .git components",
            ));
        }
    }
    Ok(())
}

pub(crate) fn compute_workspace_manifest_digest(
    entries: &[DescriptorRelativeManifestEntry],
) -> Result<Digest, ContractError> {
    validate_manifest_entries(entries)?;
    let entry_count = u64::try_from(entries.len()).map_err(|_| {
        ContractError::new(
            "descriptor_relative_workspace_manifest.entries",
            "entry count does not fit in the manifest V1 u64 field",
        )
    })?;
    let mut hasher = Sha256::new();
    hasher.update(WORKSPACE_MANIFEST_DOMAIN);
    hasher.update(entry_count.to_be_bytes());
    for entry in entries {
        let path_length = u64::try_from(entry.path.len()).map_err(|_| {
            ContractError::new(
                "descriptor_relative_manifest_entry.path",
                "path length does not fit in the manifest V1 u64 field",
            )
        })?;
        hasher.update(path_length.to_be_bytes());
        hasher.update(entry.path.as_bytes());
        hasher.update(entry.byte_length.to_be_bytes());
        hasher.update(entry.content_digest.as_str().as_bytes());
        hasher.update(entry.unix_mode.to_be_bytes());
    }
    digest_from_sha256_output(
        hasher.finalize().as_ref(),
        "descriptor_relative_workspace_manifest.manifest_digest",
    )
}

fn validate_common_plan_sources(
    cut: &SprintLiveStateCapturePlanCut,
    sprint: &SprintSpec,
    verifier_policy: &CompiledExecutionPolicy,
    required_cleanup_evidence: &[WorkerCleanupEvidence],
) -> Result<(), ContractError> {
    sprint.validate()?;
    require_live_state_id("sprint_live_state_capture_plan.plan_id", &cut.plan_id)?;
    require_live_state_id(
        "sprint_live_state_capture_plan.source_event_id",
        &cut.source_event_id,
    )?;
    if cut.source_event_sequence == 0 || cut.planned_at_unix_ms == 0 {
        return Err(ContractError::new(
            "sprint_live_state_capture_plan.cut",
            "source event sequence and plan time must be greater than zero",
        ));
    }
    validate_live_state_verifier_policy(sprint, verifier_policy)?;
    let required_cleanup_receipts = validated_cleanup_receipts(required_cleanup_evidence)?;
    let mut ids = BTreeSet::new();
    for cleanup in required_cleanup_receipts {
        require_live_state_id(
            "sprint_live_state_capture_plan.required_cleanup_receipt_ids",
            &cleanup.receipt_id,
        )?;
        if cleanup.sprint_id != sprint.sprint_id
            || cleanup.grant_hash != sprint.workspace_grant.grant_hash
            || cleanup.policy_version != sprint.workspace_grant.policy_version
            || cleanup.cleaned_at_unix_ms > cut.planned_at_unix_ms
        {
            return Err(ContractError::new(
                "sprint_live_state_capture_plan.required_cleanup_receipts",
                "every cleanup must be same-sprint, same-grant, same-policy-version, and no later than plan derivation",
            ));
        }
        if !ids.insert(cleanup.receipt_id.as_str()) {
            return Err(ContractError::new(
                "sprint_live_state_capture_plan.required_cleanup_receipt_ids",
                "must not contain duplicate receipt identities",
            ));
        }
    }
    Ok(())
}

fn validated_cleanup_receipts(
    evidence: &[WorkerCleanupEvidence],
) -> Result<Vec<&WorkerCleanupReceipt>, ContractError> {
    if evidence.is_empty() || evidence.len() > MAX_LIVE_STATE_REQUIRED_CLEANUP_RECEIPTS {
        return Err(ContractError::new(
            "sprint_live_state_capture_plan.required_cleanup_receipt_ids",
            format!(
                "must contain 1..={MAX_LIVE_STATE_REQUIRED_CLEANUP_RECEIPTS} prior cleanup evidence envelopes"
            ),
        ));
    }
    evidence
        .iter()
        .map(|item| {
            item.validate()?;
            Ok(&item.receipt)
        })
        .collect()
}

fn validate_live_state_verifier_policy(
    sprint: &SprintSpec,
    verifier_policy: &CompiledExecutionPolicy,
) -> Result<(), ContractError> {
    let policy = verifier_policy.contract();
    policy.validate_against(&sprint.workspace_grant)?;
    if policy.computed_hash()? != policy.policy_hash {
        return Err(ContractError::new(
            "sprint_live_state_capture_plan.policy_hash",
            "must be the canonical compiler-produced policy hash",
        ));
    }
    if policy.grant_hash != sprint.workspace_grant.grant_hash
        || policy.workspace_root != sprint.workspace_grant.canonical_root
        || policy.read_scopes != [PathScope::Workspace]
        || !policy.write_scopes.is_empty()
        || policy.mutation_mode != MutationMode::ReadOnly
        || policy.network != ExecutionNetwork::None
        || policy.approval_id.is_some()
    {
        return Err(ContractError::new(
            "sprint_live_state_capture_plan.verifier_policy",
            "must be an exact whole-workspace, read-only, offline, no-approval policy for the sprint grant",
        ));
    }
    Ok(())
}

fn validate_cleanup_ids(ids: &[String]) -> Result<(), ContractError> {
    if ids.is_empty() || ids.len() > MAX_LIVE_STATE_REQUIRED_CLEANUP_RECEIPTS {
        return Err(ContractError::new(
            "sprint_live_state_capture_plan.required_cleanup_receipt_ids",
            format!("must contain 1..={MAX_LIVE_STATE_REQUIRED_CLEANUP_RECEIPTS} identities"),
        ));
    }
    for id in ids {
        require_live_state_id(
            "sprint_live_state_capture_plan.required_cleanup_receipt_ids",
            id,
        )?;
    }
    if !ids.windows(2).all(|pair| pair[0] < pair[1]) {
        return Err(ContractError::new(
            "sprint_live_state_capture_plan.required_cleanup_receipt_ids",
            "must be unique and in strict canonical lexical order",
        ));
    }
    Ok(())
}

fn compute_required_cleanup_set_digest(ids: &[String]) -> Result<Digest, ContractError> {
    validate_cleanup_ids(ids)?;
    let count = u64::try_from(ids.len()).map_err(|_| {
        ContractError::new(
            "sprint_live_state_capture_plan.required_cleanup_receipt_ids",
            "cleanup count does not fit in the canonical u64 field",
        )
    })?;
    let mut hasher = Sha256::new();
    hasher.update(REQUIRED_CLEANUP_SET_DOMAIN);
    hasher.update(count.to_be_bytes());
    for id in ids {
        let length = u64::try_from(id.len()).map_err(|_| {
            ContractError::new(
                "sprint_live_state_capture_plan.required_cleanup_receipt_ids",
                "cleanup identity length does not fit in the canonical u64 field",
            )
        })?;
        hasher.update(length.to_be_bytes());
        hasher.update(id.as_bytes());
    }
    digest_from_sha256_output(
        hasher.finalize().as_ref(),
        "sprint_live_state_capture_plan.required_cleanup_set_digest",
    )
}

fn digest_from_sha256_output(output: &[u8], field: &'static str) -> Result<Digest, ContractError> {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(output.len() * 2);
    for byte in output {
        encoded.push(char::from(HEX[usize::from(byte >> 4)]));
        encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    Digest::parse(encoded).map_err(|error| {
        ContractError::new(field, format!("cannot encode SHA-256 output: {error}"))
    })
}

fn require_contract_version(field: &'static str, version: u32) -> Result<(), ContractError> {
    if version != CONTRACT_VERSION {
        return Err(ContractError::new(
            field,
            format!("expected version {CONTRACT_VERSION}, got {version}"),
        ));
    }
    Ok(())
}

fn require_live_state_id(field: &'static str, value: &str) -> Result<(), ContractError> {
    if value.trim().is_empty() {
        return Err(ContractError::new(field, "must not be blank"));
    }
    if value.len() > MAX_LIVE_STATE_CAPTURE_ID_BYTES {
        return Err(ContractError::new(
            field,
            format!("must not exceed {MAX_LIVE_STATE_CAPTURE_ID_BYTES} UTF-8 bytes"),
        ));
    }
    Ok(())
}

fn canonical_bytes<T: Serialize + ?Sized>(
    field: &'static str,
    value: &T,
) -> Result<Vec<u8>, ContractError> {
    serde_json::to_vec(value)
        .map_err(|error| ContractError::new(field, format!("cannot encode canonically: {error}")))
}

fn require_canonical_size<T: Serialize + ?Sized>(
    field: &'static str,
    value: &T,
    maximum: usize,
) -> Result<(), ContractError> {
    let encoded = canonical_bytes(field, value)?;
    if encoded.len() > maximum {
        return Err(ContractError::new(
            field,
            format!("canonical encoding exceeds {maximum} bytes"),
        ));
    }
    Ok(())
}

fn digest_canonical<T: Serialize + ?Sized>(
    domain: &[u8],
    value: &T,
    field: &'static str,
) -> Result<Digest, ContractError> {
    let encoded = canonical_bytes(field, value)?;
    let mut preimage = Vec::with_capacity(domain.len() + encoded.len());
    preimage.extend_from_slice(domain);
    preimage.extend_from_slice(&encoded);
    Ok(Digest::sha256(&preimage))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn digest(byte: u8) -> Digest {
        Digest::sha256(&[byte])
    }

    fn entry(path: &str, bytes: &[u8], unix_mode: u32) -> DescriptorRelativeManifestEntry {
        DescriptorRelativeManifestEntry {
            path: path.to_owned(),
            content_digest: Digest::sha256(bytes),
            byte_length: u64::try_from(bytes.len()).expect("fixture length"),
            unix_mode,
        }
    }

    fn branch() -> LiveStateCaptureBranch {
        LiveStateCaptureBranch::VerifiedNoOp {
            final_verification_receipt_id: "verification-1".into(),
            task_integration_receipt_id: "integration-1".into(),
        }
    }

    fn plan() -> SprintLiveStateCapturePlan {
        let cleanup_ids = vec!["cleanup-1".to_owned(), "cleanup-2".to_owned()];
        SprintLiveStateCapturePlan {
            contract_version: CONTRACT_VERSION,
            plan_id: "capture-plan-1".into(),
            sprint_id: "sprint-1".into(),
            branch: branch(),
            expected_snapshot: digest(1),
            grant_hash: digest(2),
            policy_hash: digest(3),
            policy_version: 1,
            source_event_id: "event-17".into(),
            source_event_sequence: 17,
            required_cleanup_set_digest: compute_required_cleanup_set_digest(&cleanup_ids)
                .expect("cleanup digest"),
            required_cleanup_receipt_ids: cleanup_ids,
            planned_at_unix_ms: 100,
        }
    }

    fn evidence(
        request: &SprintLiveStateCaptureRequest,
        observed: Digest,
    ) -> LiveStateCaptureEvidence {
        let manifest = DescriptorRelativeWorkspaceManifest {
            format_version: DESCRIPTOR_RELATIVE_WORKSPACE_MANIFEST_FORMAT_VERSION,
            grant_hash: request.plan.grant_hash.clone(),
            capture_started_at_unix_ms: 101,
            captured_at_unix_ms: 102,
            entries: Vec::new(),
            manifest_digest: observed.clone(),
        };
        LiveStateCaptureEvidence {
            contract_version: CONTRACT_VERSION,
            receipt: LiveStateCaptureReceipt {
                contract_version: CONTRACT_VERSION,
                receipt_id: "capture-receipt-1".into(),
                admission_id: "capture-admission-1".into(),
                effect_id: "capture-effect-1".into(),
                observation_id: "capture-observation-1".into(),
                dispatch_claim_id: "capture-claim-1".into(),
                sprint_id: request.plan.sprint_id.clone(),
                plan_id: request.plan.plan_id.clone(),
                plan_digest: request.plan.plan_digest().expect("plan digest"),
                request_digest: request.request_digest().expect("request digest"),
                branch: request.plan.branch.clone(),
                expected_snapshot: request.plan.expected_snapshot.clone(),
                observed_snapshot: observed.clone(),
                runner_launch_id: "capture-launch-1".into(),
                runner_session_id: "capture-session-1".into(),
                policy_hash: request.plan.policy_hash.clone(),
                grant_hash: request.plan.grant_hash.clone(),
                policy_version: request.plan.policy_version,
                manifest_digest: observed,
                capture_started_at_unix_ms: 101,
                captured_at_unix_ms: 102,
            },
            manifest,
        }
    }

    fn drift_blocked_proof() -> LiveStateDriftBlockedProof {
        LiveStateDriftBlockedProof {
            contract_version: CONTRACT_VERSION,
            sprint_id: "sprint-1".into(),
            terminal_record_id: "terminal-drift-1".into(),
            terminal_evidence_digest: digest(4),
            branch: branch(),
            capture_receipt_id: "capture-receipt-1".into(),
            capture_admission_id: "capture-admission-1".into(),
            capture_plan_id: "capture-plan-1".into(),
            capture_plan_digest: digest(5),
            capture_effect_id: "capture-effect-1".into(),
            capture_observation_id: "capture-observation-1".into(),
            capture_dispatch_claim_id: "capture-claim-1".into(),
            runner_launch_id: "capture-launch-1".into(),
            runner_session_id: "capture-session-1".into(),
            capture_evidence_digest: digest(6),
            expected_snapshot: digest(1),
            observed_snapshot: digest(7),
            manifest_digest: digest(7),
            grant_hash: digest(2),
            policy_hash: digest(3),
            policy_version: 1,
            verifier_cleanup_receipt_id: "capture-cleanup-1".into(),
            required_cleanup_set_digest: digest(8),
            capture_started_at_unix_ms: 101,
            captured_at_unix_ms: 102,
            verifier_cleaned_at_unix_ms: 103,
            blocked_at_unix_ms: 104,
        }
    }

    #[test]
    fn drift_blocked_proof_accepts_exact_applied_and_verified_no_op_branches() {
        let no_op = drift_blocked_proof();
        no_op.validate().expect("verified-no-op drift proof");
        assert!(
            serde_json::to_vec(&no_op).expect("canonical proof").len()
                <= MAX_LIVE_STATE_DRIFT_BLOCKED_PROOF_BYTES
        );

        let mut applied = no_op;
        applied.branch = LiveStateCaptureBranch::Applied {
            final_verification_receipt_id: "verification-1".into(),
            application_receipt_id: "application-1".into(),
            rollback_reference_id: "rollback-reference-1".into(),
        };
        applied.validate().expect("applied drift proof");
    }

    #[test]
    fn drift_blocked_proof_requires_truthful_mismatch_and_manifest_digest() {
        let valid = drift_blocked_proof();

        let mut matching = valid.clone();
        matching.observed_snapshot = matching.expected_snapshot.clone();
        matching.manifest_digest = matching.expected_snapshot.clone();
        assert!(matching.validate().is_err());

        let mut crossed_manifest = valid;
        crossed_manifest.manifest_digest = digest(9);
        assert!(crossed_manifest.validate().is_err());
    }

    #[test]
    fn drift_blocked_proof_rejects_reserved_branch_invalid_identity_and_policy() {
        let valid = drift_blocked_proof();

        let mut wrong_version = valid.clone();
        wrong_version.contract_version = CONTRACT_VERSION + 1;
        assert!(wrong_version.validate().is_err());

        let mut reserved = valid.clone();
        reserved.branch = LiveStateCaptureBranch::KnownPreApplicationTerminal {
            terminal_record_id: "other-terminal".into(),
        };
        assert!(reserved.validate().is_err());

        let mut blank = valid.clone();
        blank.capture_dispatch_claim_id = "  ".into();
        assert!(blank.validate().is_err());

        let mut oversized = valid.clone();
        oversized.terminal_record_id = "x".repeat(MAX_LIVE_STATE_CAPTURE_ID_BYTES + 1);
        assert!(oversized.validate().is_err());

        let mut zero_policy = valid;
        zero_policy.policy_version = 0;
        assert!(zero_policy.validate().is_err());
    }

    #[test]
    fn drift_blocked_proof_rejects_reversed_lifecycle_and_unknown_fields() {
        let valid = drift_blocked_proof();
        for mutation in [
            |proof: &mut LiveStateDriftBlockedProof| proof.capture_started_at_unix_ms = 0,
            |proof: &mut LiveStateDriftBlockedProof| proof.captured_at_unix_ms = 100,
            |proof: &mut LiveStateDriftBlockedProof| proof.verifier_cleaned_at_unix_ms = 101,
            |proof: &mut LiveStateDriftBlockedProof| proof.blocked_at_unix_ms = 102,
        ] {
            let mut crossed = valid.clone();
            mutation(&mut crossed);
            assert!(crossed.validate().is_err());
        }

        let mut json = serde_json::to_value(valid).expect("proof JSON");
        json.as_object_mut()
            .expect("proof object")
            .insert("unexpected".into(), serde_json::Value::Bool(true));
        assert!(serde_json::from_value::<LiveStateDriftBlockedProof>(json).is_err());
    }

    #[test]
    fn manifest_v1_empty_golden_vector_matches_existing_runner_algorithm() {
        let manifest =
            DescriptorRelativeWorkspaceManifest::from_captured_entries(digest(7), 1, 2, Vec::new())
                .expect("empty manifest");
        assert_eq!(
            manifest.manifest_digest.as_str(),
            "014ef20ce39b5f44bdcded20c0c6278a273e5741a9234f7d985196e0620302fb"
        );
    }

    #[test]
    fn manifest_v1_nested_golden_vector_matches_existing_runner_field_order() {
        let manifest = DescriptorRelativeWorkspaceManifest::from_captured_entries(
            digest(7),
            2,
            3,
            vec![
                entry("Cargo.toml", b"[workspace]\n", 0o644),
                entry("src/lib.rs", b"pub fn answer() -> u8 { 42 }\n", 0o755),
            ],
        )
        .expect("nested manifest");
        assert_eq!(
            manifest.manifest_digest.as_str(),
            "7082363f546edb9c67c9bd86060bd43955c06e55610dfd1a48005fda27456e02"
        );
    }

    #[test]
    fn manifest_rejects_nonportable_paths_order_duplicates_prefixes_modes_and_lengths() {
        for path in [
            "",
            "/absolute",
            "a//b",
            "./a",
            "a/../b",
            "a\\b",
            ".git/config",
            "a/.GIT/config",
            "nul\0byte",
        ] {
            assert!(entry(path, b"x", 0o644).validate().is_err(), "{path:?}");
        }

        let unordered = vec![entry("b", b"b", 0o644), entry("a", b"a", 0o644)];
        assert!(compute_workspace_manifest_digest(&unordered).is_err());
        let duplicate = vec![entry("a", b"a", 0o644), entry("a", b"b", 0o644)];
        assert!(compute_workspace_manifest_digest(&duplicate).is_err());
        let prefix = vec![
            entry("a", b"a", 0o644),
            entry("a-x", b"x", 0o644),
            entry("a/b", b"b", 0o644),
        ];
        assert!(compute_workspace_manifest_digest(&prefix).is_err());

        let mut invalid_mode = entry("a", b"a", 0o644);
        invalid_mode.unix_mode = 0o1_000;
        assert!(invalid_mode.validate().is_err());
        let mut invalid_length = entry("a", b"a", 0o644);
        invalid_length.byte_length = (i64::MAX as u64) + 1;
        assert!(invalid_length.validate().is_err());

        let oversized_path = entry(
            &"x".repeat(MAX_DESCRIPTOR_RELATIVE_MANIFEST_PATH_BYTES + 1),
            b"x",
            0o644,
        );
        assert!(oversized_path.validate().is_err());

        let excessive_count =
            vec![entry("a", b"a", 0o644); MAX_DESCRIPTOR_RELATIVE_MANIFEST_ENTRIES + 1];
        assert!(compute_workspace_manifest_digest(&excessive_count).is_err());
    }

    #[test]
    fn manifest_rejects_a_validly_shaped_manifest_above_the_canonical_size_bound() {
        let suffix = "x".repeat(MAX_DESCRIPTOR_RELATIVE_MANIFEST_PATH_BYTES - 6);
        let entries = (0..1_600)
            .map(|index| DescriptorRelativeManifestEntry {
                path: format!("{index:05}-{suffix}"),
                content_digest: digest(1),
                byte_length: 0,
                unix_mode: 0o644,
            })
            .collect::<Vec<_>>();
        assert_eq!(
            entries[0].path.len(),
            MAX_DESCRIPTOR_RELATIVE_MANIFEST_PATH_BYTES
        );
        assert!(
            DescriptorRelativeWorkspaceManifest::from_captured_entries(digest(2), 1, 2, entries)
                .is_err()
        );
    }

    #[test]
    fn manifest_digest_changes_for_every_existing_v1_field() {
        let original = vec![entry("src/lib.rs", b"content", 0o644)];
        let expected = compute_workspace_manifest_digest(&original).expect("digest");
        for changed in [
            vec![entry("src/main.rs", b"content", 0o644)],
            vec![DescriptorRelativeManifestEntry {
                byte_length: 8,
                ..original[0].clone()
            }],
            vec![entry("src/lib.rs", b"changed", 0o644)],
            vec![entry("src/lib.rs", b"content", 0o600)],
        ] {
            assert_ne!(
                compute_workspace_manifest_digest(&changed).expect("changed digest"),
                expected
            );
        }
    }

    #[test]
    fn reserved_terminal_branch_is_deserializable_but_has_no_current_authority() {
        let encoded = br#"{"KnownPreApplicationTerminal":{"terminal_record_id":"terminal-1"}}"#;
        let decoded: LiveStateCaptureBranch = serde_json::from_slice(encoded).expect("decode");
        assert!(decoded.validate_shape().is_ok());
        assert!(decoded.validate_current().is_err());

        let mut current = plan();
        current.branch = decoded;
        assert!(current.validate().is_err());
    }

    #[test]
    fn plan_rejects_crossed_cleanup_order_digest_and_unbounded_identity() {
        let valid = plan();
        valid.validate().expect("valid plan");
        valid.plan_digest().expect("plan digest");

        let mut unordered = valid.clone();
        unordered.required_cleanup_receipt_ids.reverse();
        assert!(unordered.validate().is_err());

        let mut crossed = valid.clone();
        crossed.required_cleanup_set_digest = digest(9);
        assert!(crossed.validate().is_err());

        let mut oversized = valid;
        oversized.source_event_id = "x".repeat(MAX_LIVE_STATE_CAPTURE_ID_BYTES + 1);
        assert!(oversized.validate().is_err());
    }

    #[test]
    fn plan_cleanup_sources_require_exact_retained_os_evidence() {
        let os_evidence_bytes = b"zero descendants".to_vec();
        let mut cleanup = WorkerCleanupEvidence {
            receipt: WorkerCleanupReceipt {
                contract_version: CONTRACT_VERSION,
                receipt_id: "cleanup-1".into(),
                sprint_id: "sprint-1".into(),
                launch_id: "launch-1".into(),
                effect_id: "cleanup-effect-1".into(),
                observation_id: "cleanup-observation-1".into(),
                session_id: "session-1".into(),
                worker_lease: None,
                policy_hash: digest(1),
                grant_hash: digest(2),
                policy_version: 1,
                platform_backend: crate::WorkerCleanupBackend::LinuxCgroupV2,
                os_evidence_digest: Digest::sha256(&os_evidence_bytes),
                surviving_processes: 0,
                cleaned_at_unix_ms: 99,
            },
            os_evidence_bytes,
        };
        validated_cleanup_receipts(std::slice::from_ref(&cleanup)).expect("exact cleanup evidence");
        cleanup.os_evidence_bytes.push(b'!');
        assert!(validated_cleanup_receipts(&[cleanup]).is_err());
    }

    #[test]
    fn request_has_no_capture_timestamp_and_digest_is_exact_canonical_bytes() {
        let request = SprintLiveStateCaptureRequest::from_plan(plan()).expect("request");
        let encoded = serde_json::to_vec(&request).expect("encode");
        assert!(
            !String::from_utf8(encoded.clone())
                .expect("utf8")
                .contains("captured_at_unix_ms")
        );
        assert!(
            !String::from_utf8(encoded.clone())
                .expect("utf8")
                .contains("capture_started_at_unix_ms")
        );
        assert_eq!(
            request.request_digest().expect("digest"),
            Digest::sha256(&encoded)
        );
    }

    #[test]
    fn evidence_accepts_truthful_drift_but_exactly_binds_request_and_runner_capture_time() {
        let request = SprintLiveStateCaptureRequest::from_plan(plan()).expect("request");
        let empty_digest = compute_workspace_manifest_digest(&[]).expect("empty digest");
        let captured = evidence(&request, empty_digest);
        captured
            .validate_against_request(&request)
            .expect("truthful capture");
        assert!(!captured.matches_expected_snapshot());

        let mut crossed = captured.clone();
        crossed.receipt.policy_hash = digest(8);
        assert!(crossed.validate_against_request(&request).is_err());

        let mut caller_time = captured;
        caller_time.receipt.capture_started_at_unix_ms = request.plan.planned_at_unix_ms - 1;
        caller_time.manifest.capture_started_at_unix_ms = request.plan.planned_at_unix_ms - 1;
        assert!(caller_time.validate_against_request(&request).is_err());

        let mut reversed_interval = evidence(
            &request,
            compute_workspace_manifest_digest(&[]).expect("empty digest"),
        );
        reversed_interval.receipt.captured_at_unix_ms =
            reversed_interval.receipt.capture_started_at_unix_ms - 1;
        reversed_interval.manifest.captured_at_unix_ms =
            reversed_interval.manifest.capture_started_at_unix_ms - 1;
        assert!(
            reversed_interval
                .validate_against_request(&request)
                .is_err()
        );
    }

    #[test]
    fn evidence_rejects_crossed_high_water_cut_and_cleanup_set_even_when_branch_matches() {
        let request = SprintLiveStateCaptureRequest::from_plan(plan()).expect("request");
        let captured = evidence(
            &request,
            compute_workspace_manifest_digest(&[]).expect("empty digest"),
        );

        let mut crossed_cut_plan = request.plan.clone();
        crossed_cut_plan.source_event_id = "event-18".into();
        crossed_cut_plan.source_event_sequence = 18;
        let crossed_cut =
            SprintLiveStateCaptureRequest::from_plan(crossed_cut_plan).expect("crossed cut");
        assert!(captured.validate_against_request(&crossed_cut).is_err());

        let mut crossed_cleanup_plan = request.plan.clone();
        crossed_cleanup_plan.required_cleanup_receipt_ids = vec!["cleanup-3".into()];
        crossed_cleanup_plan.required_cleanup_set_digest =
            compute_required_cleanup_set_digest(&crossed_cleanup_plan.required_cleanup_receipt_ids)
                .expect("crossed cleanup digest");
        let crossed_cleanup = SprintLiveStateCaptureRequest::from_plan(crossed_cleanup_plan)
            .expect("crossed cleanup");
        assert!(captured.validate_against_request(&crossed_cleanup).is_err());
    }

    #[test]
    fn manifest_serde_rejects_unknown_fields_and_noncanonical_digest() {
        let digest = compute_workspace_manifest_digest(&[]).expect("empty digest");
        let encoded = format!(
            "{{\"format_version\":1,\"grant_hash\":\"{}\",\"capture_started_at_unix_ms\":1,\"captured_at_unix_ms\":2,\"entries\":[],\"manifest_digest\":\"{}\",\"extra\":true}}",
            super::tests::digest(1),
            digest
        );
        assert!(serde_json::from_str::<DescriptorRelativeWorkspaceManifest>(&encoded).is_err());

        let mut manifest = DescriptorRelativeWorkspaceManifest::from_captured_entries(
            super::tests::digest(2),
            1,
            2,
            Vec::new(),
        )
        .expect("manifest");
        manifest.manifest_digest = super::tests::digest(3);
        assert!(manifest.validate().is_err());
    }
}
