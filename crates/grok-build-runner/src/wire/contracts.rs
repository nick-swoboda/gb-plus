//! Wire request/response contracts and canonical authority records.

use super::{
    COMMAND_OUTPUT_CAPTURE_DRAIN_ALLOWANCE_BYTES_V1, CONTRACT_VERSION, CapabilityApplyOutcome,
    CapabilityRecoveryReport, CapabilityRollbackArtifact, CapabilityRollbackArtifactKind,
    CapabilityRollbackArtifactReference, CapabilityRollbackExpectedEndpoint,
    CapabilityRollbackLiveConflict, CapabilityRollbackObservedEndpoint, CapabilityRollbackOutcome,
    CapabilityRollbackPathConflict, CapabilityRollbackPathObservation,
    CapabilityRollbackSuccessEvidence, CapabilityRollbackTargetContract, CapturedOutput, ChangeSet,
    CommandDomainCleanupBackend, CommandDomainCleanupBinding, CommandDomainCleanupDisposition,
    CommandDomainCleanupProofError, CommandOutputAbandonmentReasonV2,
    CommandOutputArtifactSetReferenceV1, CommandOutputCaptureAcquiredV1,
    CommandOutputCaptureStoreHeadV1, CommandTermination, CommandTerminationV1,
    ContainedExecutionEvidence, ContainedSensitiveOutputRejectionEvidence, Cursor,
    DescriptorRelativeManifestEntry, DescriptorRelativeWorkspaceManifest, Deserialize, Digest,
    Display, EffectIntent, EffectKind, EnvironmentVariable, ExecutionNetwork, ExecutionOrigin,
    ExecutionPolicyRequest, FileMutationReceipt, FileOperation, FileReadResult, Formatter,
    LiteralSearchResult, MAX_COMMAND_DOMAIN_CLEANUP_EVIDENCE_BYTES, MutationMode, PathScope,
    PersistedRunnerEffectDispatchClaim, PostCompletionRollbackApplicationArtifactAuthority, Read,
    ResourceLimits, RunnerEffectRequestAuthority, RunnerSessionPolicyRecord, RunnerSessionPurpose,
    SensitiveOutputCleanJournalReceiptV2, SensitiveOutputDetectionPolicyReferenceV1,
    SensitiveOutputRejectionJournalReceiptV2, SensitiveOutputRejectionNativeProofRejoinV1,
    Serialize, SessionValidatedCommandEnvelope, SessionValidatedCommandEnvelopeV12,
    SprintLiveStateCapturePlan, SprintLiveStateCaptureRequest, SprintSpec, StageBundleReference,
    TaskIntegrationRequest, ValidatedCommandDomainCleanupProof, WorkerLease, WorkspaceGrant,
    WorkspaceManifest, WorkspaceNetworkPolicy, WorkspacePermissions, Write, bounded_error_message,
    change_set_endpoints_digest, change_set_operations_digest,
    change_set_restored_endpoints_digest, change_set_target_digest, classify_request_frame_version,
    command_terminal_record_bytes_unchecked, encode_hex, fmt, invalid, io, portable_path,
    require_nonzero, validate_absolute_path_text, validate_bundle_change_set, validate_capture_id,
    validate_command_effect_request, validate_command_terminal_bound,
    validate_command_terminal_capture_bound, validate_command_terminal_shape,
    validate_command_terminal_shape_without_record_digest, validate_failure_reference_correlation,
    validate_identifier, validate_inline_file_bound, validate_legacy_runner_command_v11_v12,
    validate_reconciliation_reference, validate_relative_path_text, validate_response,
    validated_absolute_path, validated_relative_path,
};
#[cfg(test)]
use super::{
    CommandOutputArtifactSourceV1, CommandOutputCaptureDirectoryIdentityV1,
    CommandOutputCaptureFileIdentityV1, CommandOutputCaptureIntentV1,
};

/// Runner protocol version, independent of provider and database schemas.
pub const RUNNER_WIRE_PROTOCOL_VERSION: u32 = 11;
/// Additive command-only protocol carrying fixed sensitive-output policy.
pub const RUNNER_WIRE_PROTOCOL_VERSION_V12: u32 = 12;
/// Largest accepted JSON payload, excluding the four-byte length prefix.
pub const MAX_WIRE_FRAME_BYTES: usize = 8 * 1024 * 1024;
/// Largest complete file bytes accepted inline in a request or response.
pub const MAX_INLINE_FILE_BYTES: usize = 1024 * 1024;
/// Largest aggregate stdout/stderr prefix retained by one command response.
pub const MAX_INLINE_COMMAND_RETAINED_BYTES: usize = 128 * 1024;
/// Maximum additional bytes that the contained supervisor can observe while
/// crossing and draining its bounded cleanup window: two 64-KiB streams over
/// one crossing observation plus 400 cleanup observations.
pub const COMMAND_OUTPUT_CAPTURE_DRAIN_ALLOWANCE_BYTES: u64 =
    COMMAND_OUTPUT_CAPTURE_DRAIN_ALLOWANCE_BYTES_V1;
/// Schema token stored beside the exact canonical v11 terminal response bytes.
pub const COMMAND_TERMINAL_CAPTURE_SCHEMA: &str = "runner-wire-command-terminal/v11";
/// Schema token stored beside the exact canonical contained-launch binding.
pub const CONTAINED_CAPTURE_LAUNCH_SCHEMA: &str = "runner-contained-capture-launch/v1";
/// Maximum retained canonical contained-launch binding accepted on restart.
pub const MAX_CONTAINED_CAPTURE_LAUNCH_BINDING_BYTES: usize = 256 * 1024;
/// Largest exact literal accepted by the search request.
pub const MAX_WIRE_LITERAL_BYTES: usize = 4_096;
/// Largest complete literal-match set accepted by the wire contract.
pub const MAX_WIRE_SEARCH_MATCHES: usize = 10_000;

pub(super) const MAX_ID_BYTES: usize = 256;
pub(super) const MAX_PATH_BYTES: usize = 4_096;
pub(super) const MAX_ENVIRONMENT_ENTRIES: usize = 128;
pub(super) const MAX_SCOPE_ENTRIES: usize = 256;
pub(super) const MAX_COMMAND_ARGUMENTS: usize = 256;
pub(super) const MAX_COMMAND_TEXT_BYTES: usize = 4_096;
pub(crate) const MAX_ERROR_MESSAGE_BYTES: usize = 4_096;
pub(super) const MAX_RECOVERY_IDENTITIES: usize = 100_000;
pub(super) const MAX_CHANGE_SET_OPERATIONS: usize = 4_096;
pub(super) const MAX_ROLLBACK_ARTIFACTS: usize = 8_192;
pub(super) const MAX_ROLLBACK_EVIDENCE_TARGETS: usize = 4_096;
pub(super) const MAX_ROLLBACK_WIRE_ENCODED_BYTES: usize = 6 * 1024 * 1024;
pub(super) const ROLLBACK_ARTIFACT_VERSION: &str = "grok-build-capability-rollback-artifacts-v2";
pub(super) const WORKSPACE_CAPTURE_DOMAIN: &[u8] = b"grok-build/workspace-capture/v1\0";
pub(super) const REQUEST_COMMITMENT_DOMAIN: &[u8] = b"grok-build/runner-request-commitment/v1\0";
pub(super) const REQUEST_COMMITMENT_V12_DOMAIN: &[u8] =
    b"grok-build/runner-request-commitment/v12\0";
#[cfg(test)]
pub(super) const RUNNER_EFFECT_DISPATCH_CLAIM_ID_DOMAIN: &[u8] =
    b"grok-build/runner-effect-dispatch-claim/v1\0";
pub(super) const SPRINT_SPEC_DIGEST_DOMAIN: &[u8] = b"grok-build/sprint-spec/v1\0";
pub(super) const SHUTDOWN_ACK_DOMAIN: &[u8] = b"grok-build/runner-shutdown-prepared/v2\0";
pub(super) const COMMAND_STREAM_OUTPUT_DIGEST_DOMAIN: &[u8] = b"grok-build/command-output/v1";
pub(super) const COMMAND_TERMINAL_DIGEST_DOMAIN: &[u8] = b"grok-build/runner-command-terminal/v1\0";
pub(super) const COMMAND_TERMINAL_RECORD_DIGEST_DOMAIN: &[u8] =
    b"grok-build/runner-command-terminal-record/v11\0";
pub(super) const MAX_COMMAND_OUTPUT_CAPTURE_ANCHOR_BYTES: usize = 64 * 1024;
pub(super) const EXPECTED_ROLLBACK_ENDPOINTS_DOMAIN: &[u8] =
    b"grok-build.rollback.expected-application-endpoints.v1\0";
pub(super) const ROLLBACK_TARGET_CONTRACT_DOMAIN: &[u8] =
    b"grok-build.rollback.target-contract.v1\0";
pub(super) const OBSERVED_ROLLBACK_ENDPOINTS_DOMAIN: &[u8] =
    b"grok-build.rollback.observed-endpoints.v1\0";
pub(super) const ABSENT_ROLLBACK_ENDPOINT_DOMAIN: &[u8] =
    b"grok-build.post-completion-rollback.endpoint.absent.v1\0";
pub(super) const LEGACY_SHELL_PROGRAMS_V11_V12: &[&str] = &[
    "sh",
    "bash",
    "zsh",
    "dash",
    "ksh",
    "fish",
    "csh",
    "tcsh",
    "pwsh",
    "powershell",
    "powershell.exe",
    "cmd",
    "cmd.exe",
    "env",
];
/// Immutable role assigned to one runner process.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RunnerRole {
    /// Reads the live root and mutates only one fixed private shadow.
    Worker,
    /// Reopens one exact preauthorized private snapshot without mutation APIs.
    FinalVerifier,
    /// Owns journaled application, reconciliation, and rollback only.
    Applier,
    /// Captures one complete descriptor-relative live-workspace manifest under
    /// an exact core-derived sprint-finalization plan.
    LiveStateVerifier,
}

/// Closed durable authority that selected the initialized role input snapshot.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum RunnerRoleInputAuthority {
    /// The immutable planning/application base from the exact `SprintSpec`.
    PlanningBase,
    /// The exact contiguous durable task-integration head, which may equal the
    /// planning base before the first integration.
    IntegrationHead,
    /// The result snapshot of the exact durable applied artifact authorizing a
    /// post-completion rollback operation.
    PostCompletionAppliedResult {
        /// Complete operation-local authority derived from the exact original
        /// successful application request.
        authority: Box<PostCompletionRollbackApplicationArtifactAuthority>,
        /// SHA-256 of the exact canonical authority bytes, exact-compared with
        /// the durable ledger commitment by the desktop.
        authority_digest: Digest,
    },
    /// Exact core-derived finalization plan retained before the dedicated
    /// live-state-verifier runner is launched.
    LiveStateFinalization {
        /// Complete serializable capture plan. This value grants no dispatch
        /// authority by itself.
        plan: Box<SprintLiveStateCapturePlan>,
        /// Domain-separated digest recomputed from `plan` by the runner.
        plan_digest: Digest,
    },
}

pub(crate) fn validate_live_state_finalization_plan(
    plan: &SprintLiveStateCapturePlan,
    plan_digest: &Digest,
    sprint_id: &str,
    sprint_spec: &SprintSpec,
    expected_policy_hash: &Digest,
    expected_input_snapshot: &Digest,
) -> Result<(), WireProtocolError> {
    plan.validate()
        .map_err(|error| invalid(error.to_string()))?;
    let actual_plan_digest = plan
        .plan_digest()
        .map_err(|error| invalid(error.to_string()))?;
    if actual_plan_digest != *plan_digest
        || plan.sprint_id != sprint_id
        || plan.sprint_id != sprint_spec.sprint_id
        || plan.expected_snapshot != *expected_input_snapshot
        || plan.grant_hash != sprint_spec.workspace_grant.grant_hash
        || plan.policy_hash != *expected_policy_hash
        || plan.policy_version != sprint_spec.workspace_grant.policy_version
    {
        return Err(invalid(
            "live-state finalization plan differs from its digest, sprint, snapshot, grant, or policy",
        ));
    }
    Ok(())
}

/// Stable filesystem identity authenticated by the launcher before runner exec.
#[allow(
    missing_docs,
    reason = "public fields are the exact binary identity schema"
)]
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WireBinaryIdentity {
    pub device_id: u64,
    pub inode: u64,
    pub byte_length: u64,
    pub mode: u32,
    pub owner_uid: u32,
    pub link_count: u64,
}

/// Durable ledger identity and authority commitment for one non-init request.
#[allow(
    missing_docs,
    reason = "public fields are the exact durable effect binding schema"
)]
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WireEffectContext {
    pub contract_version: u32,
    pub launch_id: String,
    pub effect_id: String,
    pub idempotency_key: String,
    pub sprint_id: String,
    pub task_id: Option<String>,
    pub worker_id: Option<String>,
    /// Exact durable assignment for worker-scoped effects. Sprint-scoped
    /// final-verifier and applier effects must carry `None`.
    pub worker_lease: Option<WorkerLease>,
    pub policy_hash: Digest,
    pub input_snapshot: Digest,
    /// Plain SHA-256 of the exact core effect-request preimage durably persisted
    /// in the ledger. For `WorkerStageChanges`, that preimage is the canonical
    /// [`TaskIntegrationRequest`], which includes the expected artifact before
    /// publication; it is intentionally not a hash of the wire enum encoding.
    pub request_digest: Digest,
    /// Domain-separated commitment to nonce, ordering, context, and wire DTO.
    pub transport_commitment_digest: Digest,
}

impl WireEffectContext {
    pub(super) fn validate_shape(&self) -> Result<(), WireProtocolError> {
        if self.contract_version != CONTRACT_VERSION {
            return Err(invalid(format!(
                "effect.contract_version expected {CONTRACT_VERSION}, got {}",
                self.contract_version
            )));
        }
        validate_identifier("effect.launch_id", &self.launch_id)?;
        validate_identifier("effect.effect_id", &self.effect_id)?;
        validate_identifier("effect.idempotency_key", &self.idempotency_key)?;
        validate_identifier("effect.sprint_id", &self.sprint_id)?;
        if let Some(task_id) = &self.task_id {
            validate_identifier("effect.task_id", task_id)?;
        }
        if let Some(worker_id) = &self.worker_id {
            validate_identifier("effect.worker_id", worker_id)?;
        }
        match (
            self.task_id.as_deref(),
            self.worker_id.as_deref(),
            self.worker_lease.as_ref(),
        ) {
            (Some(task_id), Some(worker_id), Some(lease)) => {
                lease
                    .validate_assignment(&self.sprint_id, task_id, worker_id)
                    .map_err(|error| invalid(error.to_string()))?;
            }
            (None, None, None) => {}
            _ => {
                return Err(invalid(
                    "worker effects require one exact task, worker, and lease; non-worker effects forbid all three",
                ));
            }
        }
        Ok(())
    }
}

#[derive(Serialize)]
pub(super) struct RequestCommitment<'a> {
    pub(super) protocol_version: u32,
    pub(super) contract_version: u32,
    pub(super) session_id: &'a str,
    pub(super) runner_nonce: &'a Digest,
    pub(super) sequence: u64,
    pub(super) request_id: &'a str,
    pub(super) launch_id: &'a str,
    pub(super) effect_id: &'a str,
    pub(super) idempotency_key: &'a str,
    pub(super) sprint_id: &'a str,
    pub(super) task_id: &'a Option<String>,
    pub(super) worker_id: &'a Option<String>,
    pub(super) worker_lease: &'a Option<WorkerLease>,
    pub(super) policy_hash: &'a Digest,
    pub(super) input_snapshot: &'a Digest,
    pub(super) request_digest: &'a Digest,
    pub(super) request: &'a RunnerRequest,
}

#[derive(Serialize)]
pub(super) struct RequestCommitmentV12<'a> {
    pub(super) protocol_version: u32,
    pub(super) contract_version: u32,
    pub(super) session_id: &'a str,
    pub(super) runner_nonce: &'a Digest,
    pub(super) sequence: u64,
    pub(super) request_id: &'a str,
    pub(super) launch_id: &'a str,
    pub(super) effect_id: &'a str,
    pub(super) idempotency_key: &'a str,
    pub(super) sprint_id: &'a str,
    pub(super) task_id: &'a Option<String>,
    pub(super) worker_id: &'a Option<String>,
    pub(super) worker_lease: &'a Option<WorkerLease>,
    pub(super) policy_hash: &'a Digest,
    pub(super) input_snapshot: &'a Digest,
    pub(super) request_digest: &'a Digest,
    pub(super) request: &'a RunnerRequestV12,
}

/// Strict persisted-workspace permission mirror.
#[allow(
    missing_docs,
    reason = "public fields exactly mirror the named wire capabilities"
)]
#[allow(
    clippy::struct_excessive_bools,
    reason = "the wire mirror must preserve the five independent WorkspacePermissions bits exactly"
)]
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WireWorkspacePermissions {
    pub read: bool,
    pub write_regular_files: bool,
    pub execute_commands: bool,
    pub integrate_changes: bool,
    pub apply_verified_changes: bool,
}

/// Strict persisted-workspace command-network mirror.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WireWorkspaceNetworkPolicy {
    /// Commands receive no network authority.
    Denied,
    /// An explicitly compiled action may receive host networking.
    Allowed,
}

/// Strict wire mirror of [`WorkspaceGrant`].
#[allow(
    missing_docs,
    reason = "public fields exactly mirror the named workspace-grant contract"
)]
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WireWorkspaceGrant {
    pub grant_id: String,
    pub canonical_root: String,
    pub permissions: WireWorkspacePermissions,
    pub network: WireWorkspaceNetworkPolicy,
    pub policy_version: u32,
    pub grant_hash: Digest,
}

impl TryFrom<&WorkspaceGrant> for WireWorkspaceGrant {
    type Error = WireProtocolError;

    fn try_from(grant: &WorkspaceGrant) -> Result<Self, Self::Error> {
        let canonical_root = grant
            .canonical_root
            .to_str()
            .ok_or_else(|| invalid("workspace grant canonical root is not UTF-8"))?;
        validate_identifier("workspace_grant.grant_id", &grant.grant_id)?;
        validate_absolute_path_text("workspace_grant.canonical_root", canonical_root)?;
        Ok(Self {
            grant_id: grant.grant_id.clone(),
            canonical_root: canonical_root.to_owned(),
            permissions: WireWorkspacePermissions {
                read: grant.permissions.read,
                write_regular_files: grant.permissions.write_regular_files,
                execute_commands: grant.permissions.execute_commands,
                integrate_changes: grant.permissions.integrate_changes,
                apply_verified_changes: grant.permissions.apply_verified_changes,
            },
            network: match grant.network {
                WorkspaceNetworkPolicy::Denied => WireWorkspaceNetworkPolicy::Denied,
                WorkspaceNetworkPolicy::Allowed => WireWorkspaceNetworkPolicy::Allowed,
            },
            policy_version: grant.policy_version,
            grant_hash: grant.grant_hash.clone(),
        })
    }
}

impl WireWorkspaceGrant {
    pub(crate) fn into_native(self) -> Result<WorkspaceGrant, WireProtocolError> {
        validate_identifier("workspace_grant.grant_id", &self.grant_id)?;
        let root = validated_absolute_path("workspace_grant.canonical_root", &self.canonical_root)?;
        Ok(WorkspaceGrant {
            grant_id: self.grant_id,
            canonical_root: root,
            permissions: WorkspacePermissions {
                read: self.permissions.read,
                write_regular_files: self.permissions.write_regular_files,
                execute_commands: self.permissions.execute_commands,
                integrate_changes: self.permissions.integrate_changes,
                apply_verified_changes: self.permissions.apply_verified_changes,
            },
            network: match self.network {
                WireWorkspaceNetworkPolicy::Denied => WorkspaceNetworkPolicy::Denied,
                WireWorkspaceNetworkPolicy::Allowed => WorkspaceNetworkPolicy::Allowed,
            },
            policy_version: self.policy_version,
            grant_hash: self.grant_hash,
        })
    }
}

/// Strict execution path-scope mirror.
#[allow(missing_docs, reason = "variant fields are the normative wire schema")]
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum WirePathScope {
    Workspace,
    Relative { path: String },
}

/// One explicit non-secret environment value.
#[allow(
    missing_docs,
    reason = "public fields exactly mirror the named policy contract"
)]
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WireEnvironmentVariable {
    pub name: String,
    pub value: String,
}

/// Command-network mode requested before policy compilation.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WireExecutionNetwork {
    /// No command network.
    None,
    /// Host network for this exact action.
    FullForAction,
}

/// Workspace mutation mode requested before policy compilation.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WireMutationMode {
    /// Read-only workspace view.
    ReadOnly,
    /// Writes are confined to the fixed private shadow.
    ShadowWorkspace,
}

/// Strict resource-limit mirror.
#[allow(
    missing_docs,
    reason = "public fields exactly mirror the named resource ceilings"
)]
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WireResourceLimits {
    pub wall_time_ms: u64,
    pub max_output_bytes: u64,
    pub max_processes: u32,
    pub max_memory_bytes: Option<u64>,
}

/// Strict wire mirror compiled independently into an execution policy.
#[allow(
    missing_docs,
    reason = "public fields exactly mirror the named policy request"
)]
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WireExecutionPolicyRequest {
    pub policy_id: String,
    pub read_scopes: Vec<WirePathScope>,
    pub write_scopes: Vec<WirePathScope>,
    pub environment: Vec<WireEnvironmentVariable>,
    pub network: WireExecutionNetwork,
    pub mutation_mode: WireMutationMode,
    pub resource_limits: WireResourceLimits,
    pub approval_id: Option<String>,
}

impl WireExecutionPolicyRequest {
    pub(crate) fn into_native(self) -> Result<ExecutionPolicyRequest, WireProtocolError> {
        validate_identifier("execution_policy_request.policy_id", &self.policy_id)?;
        if self.read_scopes.is_empty() || self.read_scopes.len() > MAX_SCOPE_ENTRIES {
            return Err(invalid(
                "execution policy read-scope count is outside bounds",
            ));
        }
        if self.write_scopes.len() > MAX_SCOPE_ENTRIES {
            return Err(invalid(
                "execution policy write-scope count exceeds the bound",
            ));
        }
        if self.environment.len() > MAX_ENVIRONMENT_ENTRIES {
            return Err(invalid(
                "execution policy environment exceeds the entry bound",
            ));
        }
        let read_scopes = self
            .read_scopes
            .into_iter()
            .map(WirePathScope::into_native)
            .collect::<Result<Vec<_>, _>>()?;
        let write_scopes = self
            .write_scopes
            .into_iter()
            .map(WirePathScope::into_native)
            .collect::<Result<Vec<_>, _>>()?;
        let environment = self
            .environment
            .into_iter()
            .map(|entry| {
                if entry.name.is_empty()
                    || entry.name.len() > 256
                    || entry.value.len() > MAX_COMMAND_TEXT_BYTES
                    || entry.name.as_bytes().contains(&0)
                    || entry.value.as_bytes().contains(&0)
                {
                    return Err(invalid("environment name or value is outside wire bounds"));
                }
                Ok(EnvironmentVariable {
                    name: entry.name,
                    value: entry.value,
                })
            })
            .collect::<Result<Vec<_>, _>>()?;
        if let Some(approval) = &self.approval_id {
            validate_identifier("execution_policy_request.approval_id", approval)?;
        }
        if self.resource_limits.wall_time_ms == 0
            || self.resource_limits.wall_time_ms > 86_400_000
            || self.resource_limits.max_output_bytes == 0
            || self.resource_limits.max_output_bytes > 1024 * 1024 * 1024
            || self.resource_limits.max_processes == 0
            || self.resource_limits.max_processes > 4_096
            || self.resource_limits.max_memory_bytes == Some(0)
        {
            return Err(invalid("execution resource limits are outside wire bounds"));
        }
        Ok(ExecutionPolicyRequest {
            policy_id: self.policy_id,
            read_scopes,
            write_scopes,
            environment,
            network: match self.network {
                WireExecutionNetwork::None => ExecutionNetwork::None,
                WireExecutionNetwork::FullForAction => ExecutionNetwork::FullForAction,
            },
            mutation_mode: match self.mutation_mode {
                WireMutationMode::ReadOnly => MutationMode::ReadOnly,
                WireMutationMode::ShadowWorkspace => MutationMode::ShadowWorkspace,
            },
            resource_limits: ResourceLimits {
                wall_time_ms: self.resource_limits.wall_time_ms,
                max_output_bytes: self.resource_limits.max_output_bytes,
                max_processes: self.resource_limits.max_processes,
                max_memory_bytes: self.resource_limits.max_memory_bytes,
            },
            approval_id: self.approval_id,
        })
    }
}

impl WirePathScope {
    fn into_native(self) -> Result<PathScope, WireProtocolError> {
        Ok(match self {
            Self::Workspace => PathScope::Workspace,
            Self::Relative { path } => PathScope::Relative(validated_relative_path(&path)?),
        })
    }
}

/// One exact direct-exec command; it is never interpreted by a shell.
#[allow(
    missing_docs,
    reason = "public fields are the complete no-shell command schema"
)]
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WireCommandSpec {
    pub program: String,
    pub arguments: Vec<String>,
    pub working_directory: String,
}

/// Path-free, canonically authenticated custody acquired before one command
/// request may cross the runner transport boundary.
///
/// The transparent core value is deliberately independent of the runner's
/// concrete artifact-store implementation. It binds the capture layout,
/// deterministic dispatch claim, complete artifact source, private-state root
/// digest, aggregate byte ceiling, intent/acquisition/store heads, and exact
/// directory/stdout/stderr object identities.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(transparent)]
pub struct WireCommandOutputCaptureAnchorV1(CommandOutputCaptureAcquiredV1);

impl WireCommandOutputCaptureAnchorV1 {
    /// Adapts an independently validated durable acquisition into the wire
    /// contract without projecting away any authority or identity field.
    ///
    /// # Errors
    ///
    /// Returns an error when the acquisition is malformed, noncanonical,
    /// oversized, or contains a non-canonical capture identifier.
    pub fn try_new(acquired: CommandOutputCaptureAcquiredV1) -> Result<Self, WireProtocolError> {
        let anchor = Self(acquired);
        anchor.validate()?;
        Ok(anchor)
    }

    /// Returns the complete store-independent acquisition contract.
    #[must_use]
    pub const fn acquired(&self) -> &CommandOutputCaptureAcquiredV1 {
        &self.0
    }

    /// Returns the complete acquired contract without projection.
    #[must_use]
    pub fn into_acquired(self) -> CommandOutputCaptureAcquiredV1 {
        self.0
    }

    /// Validates the canonical acquisition, digest, identities, and wire-size
    /// bound without consulting a concrete output store.
    ///
    /// # Errors
    ///
    /// Returns an error for any malformed or noncanonical field.
    pub fn validate(&self) -> Result<(), WireProtocolError> {
        self.0
            .validate()
            .map_err(|error| invalid(error.to_string()))?;
        validate_capture_id(&self.0.capture_id)?;
        let canonical = serde_json::to_vec(&self.0)
            .map_err(|error| WireProtocolError::Encode(error.to_string()))?;
        if canonical.len() > MAX_COMMAND_OUTPUT_CAPTURE_ANCHOR_BYTES {
            return Err(invalid(
                "command-output capture anchor exceeds its canonical wire bound",
            ));
        }
        Ok(())
    }

    /// Binds the acquisition source to one exact runner session and durable
    /// command effect.
    ///
    /// # Errors
    ///
    /// Returns an error for any sprint, launch, session, effect, or canonical
    /// core request-digest mismatch.
    pub fn validate_request_binding(
        &self,
        session_id: &str,
        effect: &WireEffectContext,
    ) -> Result<(), WireProtocolError> {
        self.validate()?;
        let source = &self.0.source;
        if source.sprint_id != effect.sprint_id
            || source.runner_launch_id != effect.launch_id
            || source.runner_session_id != session_id
            || source.effect_id != effect.effect_id
            || source.request_digest != effect.request_digest
        {
            return Err(invalid(
                "command-output capture source differs from the exact sprint, launch, session, effect, or canonical core request digest",
            ));
        }
        Ok(())
    }

    /// Binds the acquisition to independently restored session-root evidence
    /// and the exact aggregate command-output ceiling.
    ///
    /// # Errors
    ///
    /// Returns an error when either value differs from the durable anchor.
    pub fn validate_session_binding(
        &self,
        expected_private_state_digest: &Digest,
        expected_max_aggregate_output_bytes: u64,
    ) -> Result<(), WireProtocolError> {
        self.validate()?;
        if self.0.private_state_digest != *expected_private_state_digest
            || self.0.max_aggregate_output_bytes != expected_max_aggregate_output_bytes
        {
            return Err(invalid(
                "command-output capture differs from the exact private-state root digest or aggregate output ceiling",
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
pub(crate) fn test_command_output_capture_anchor(
    source: CommandOutputArtifactSourceV1,
    private_state_digest: Digest,
    max_aggregate_output_bytes: u64,
    identity_seed: u64,
) -> WireCommandOutputCaptureAnchorV1 {
    let source_bytes = serde_json::to_vec(&source).expect("encode test capture source");
    let mut capture_preimage = source_bytes;
    capture_preimage.extend_from_slice(&identity_seed.to_be_bytes());
    let capture_id = Digest::sha256(&capture_preimage).as_str().to_owned();
    let effect_id = source.effect_id.clone();
    let intent = CommandOutputCaptureIntentV1::try_new(
        capture_id,
        source,
        private_state_digest,
        max_aggregate_output_bytes,
        1,
    )
    .expect("construct test capture intent");
    let mut claim_preimage =
        Vec::with_capacity(RUNNER_EFFECT_DISPATCH_CLAIM_ID_DOMAIN.len() + effect_id.len());
    claim_preimage.extend_from_slice(RUNNER_EFFECT_DISPATCH_CLAIM_ID_DOMAIN);
    claim_preimage.extend_from_slice(effect_id.as_bytes());
    let acquired = CommandOutputCaptureAcquiredV1::try_new(
        &intent,
        Digest::sha256(&claim_preimage).as_str(),
        CommandOutputCaptureStoreHeadV1 {
            generation: 2,
            record_digest: Digest::sha256(
                format!("test-capture-acquired-{identity_seed}").as_bytes(),
            ),
        },
        CommandOutputCaptureDirectoryIdentityV1 {
            device_id: 1,
            inode: 1_000 + identity_seed.saturating_mul(3),
            owner_uid: 501,
            mode: 0o700,
            link_count: 1,
        },
        CommandOutputCaptureFileIdentityV1 {
            device_id: 1,
            inode: 1_001 + identity_seed.saturating_mul(3),
            owner_uid: 501,
            mode: 0o600,
            link_count: 1,
            byte_length: 0,
        },
        CommandOutputCaptureFileIdentityV1 {
            device_id: 1,
            inode: 1_002 + identity_seed.saturating_mul(3),
            owner_uid: 501,
            mode: 0o600,
            link_count: 1,
            byte_length: 0,
        },
        2,
    )
    .expect("construct test acquired capture");
    WireCommandOutputCaptureAnchorV1::try_new(acquired).expect("construct test wire capture anchor")
}

/// Expected endpoint used to reconcile an uncertain file mutation without replay.
#[allow(
    missing_docs,
    reason = "variant fields are the normative endpoint schema"
)]
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum WireFileExpectation {
    Absent,
    Present { digest: Digest },
}

/// Closed request set admitted by the runner.
#[allow(
    missing_docs,
    reason = "variant fields are the normative runner request schema"
)]
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum RunnerRequest {
    InitializeSession {
        launch_id: String,
        sprint_id: String,
        sprint_spec: Box<SprintSpec>,
        expected_sprint_spec_digest: Digest,
        logical_worker_id: Option<String>,
        worker_lease: Option<WorkerLease>,
        role: RunnerRole,
        role_input_authority: RunnerRoleInputAuthority,
        workspace_grant: Box<WireWorkspaceGrant>,
        execution_policy_request: Box<WireExecutionPolicyRequest>,
        expected_policy_hash: Digest,
        expected_base_snapshot: Digest,
        expected_private_state_digest: Digest,
        expected_binary_digest: Digest,
        expected_binary_identity: WireBinaryIdentity,
        private_state_root: String,
        shadow_root: Option<String>,
    },
    WorkerCaptureLive {
        created_at_unix_ms: u64,
    },
    WorkerCreateShadow {
        base_snapshot: Digest,
    },
    WorkerReadFile {
        path: String,
        max_bytes: u64,
    },
    WorkerSearchLiteral {
        path: String,
        needle: Vec<u8>,
        max_bytes: u64,
        max_matches: usize,
    },
    WorkerCreateFile {
        path: String,
        contents: Vec<u8>,
    },
    WorkerReplaceFile {
        path: String,
        expected_digest: Digest,
        contents: Vec<u8>,
    },
    WorkerDeleteFile {
        path: String,
        expected_digest: Digest,
    },
    WorkerReconcileFile {
        path: String,
        expected: WireFileExpectation,
        max_bytes: u64,
    },
    WorkerPrepareStage {
        change_set_id: String,
        created_at_unix_ms: u64,
    },
    WorkerStageChanges {
        change_set: Box<ChangeSet>,
        expected_bundle: StageBundleReference,
    },
    WorkerReconcileStage {
        expected_bundle: StageBundleReference,
    },
    WorkerRunCommand {
        command: WireCommandSpec,
        output_capture: WireCommandOutputCaptureAnchorV1,
    },
    WorkerCancel,
    FinalVerifierCapture {
        created_at_unix_ms: u64,
    },
    FinalVerifierRunCommand {
        command: WireCommandSpec,
        output_capture: WireCommandOutputCaptureAnchorV1,
    },
    LiveStateVerifierCapture {
        request: Box<SprintLiveStateCaptureRequest>,
    },
    ApplierRecoverPending,
    ApplierReconcileStageBundle {
        expected_bundle: StageBundleReference,
    },
    ApplierApplyBundle {
        bundle: StageBundleReference,
    },
    ApplierReconcile {
        bundle: StageBundleReference,
    },
    ApplierRollback {
        bundle: StageBundleReference,
        rollback: WireRollbackArtifactReference,
    },
    ApplierCaptureLive {
        created_at_unix_ms: u64,
    },
    Shutdown,
}

impl RunnerRequest {
    #[allow(
        clippy::too_many_lines,
        reason = "the closed request validator keeps every variant's bounds in one audit boundary"
    )]
    pub(crate) fn validate(&self) -> Result<(), WireProtocolError> {
        match self {
            Self::InitializeSession {
                launch_id,
                sprint_id,
                sprint_spec,
                expected_sprint_spec_digest,
                logical_worker_id,
                worker_lease,
                role,
                role_input_authority,
                workspace_grant,
                execution_policy_request,
                expected_policy_hash,
                expected_base_snapshot,
                private_state_root,
                shadow_root,
                ..
            } => {
                validate_identifier("launch_id", launch_id)?;
                validate_identifier("sprint_id", sprint_id)?;
                let actual_sprint_spec_digest = sprint_spec_digest(sprint_spec)?;
                let sprint_workspace_grant =
                    WireWorkspaceGrant::try_from(&sprint_spec.workspace_grant)?;
                if sprint_spec.sprint_id != *sprint_id
                    || sprint_workspace_grant != **workspace_grant
                    || actual_sprint_spec_digest != *expected_sprint_spec_digest
                {
                    return Err(invalid(
                        "sprint specification differs from the initialized sprint, grant, base snapshot, or digest",
                    ));
                }
                match (role, role_input_authority) {
                    (
                        RunnerRole::Worker | RunnerRole::FinalVerifier,
                        RunnerRoleInputAuthority::IntegrationHead,
                    ) => {}
                    (RunnerRole::Applier, RunnerRoleInputAuthority::PlanningBase)
                        if sprint_spec.base_snapshot == *expected_base_snapshot => {}
                    (
                        RunnerRole::Applier,
                        RunnerRoleInputAuthority::PostCompletionAppliedResult {
                            authority,
                            authority_digest,
                        },
                    ) => {
                        authority
                            .validate()
                            .map_err(|error| invalid(error.to_string()))?;
                        let canonical = serde_json::to_vec(authority).map_err(|error| {
                            invalid(format!(
                                "cannot encode post-completion role-input authority: {error}"
                            ))
                        })?;
                        if Digest::sha256(&canonical) != *authority_digest
                            || authority.sprint_id != *sprint_id
                            || authority.artifact.base_snapshot != sprint_spec.base_snapshot
                            || authority.artifact.result_snapshot != *expected_base_snapshot
                        {
                            return Err(invalid(
                                "post-completion role-input authority differs from its sprint, artifact, digest, or result snapshot",
                            ));
                        }
                    }
                    (
                        RunnerRole::LiveStateVerifier,
                        RunnerRoleInputAuthority::LiveStateFinalization { plan, plan_digest },
                    ) => validate_live_state_finalization_plan(
                        plan,
                        plan_digest,
                        sprint_id,
                        sprint_spec,
                        expected_policy_hash,
                        expected_base_snapshot,
                    )?,
                    _ => {
                        return Err(invalid(
                            "runner role input authority is incompatible with the role or snapshot",
                        ));
                    }
                }
                if sprint_spec.provider.execution_origin != ExecutionOrigin::HostIsolated {
                    return Err(invalid(
                        "runner initialization requires a host-isolated sprint provider",
                    ));
                }
                if execution_policy_request.resource_limits.wall_time_ms
                    > sprint_spec.budget.max_duration_ms
                {
                    return Err(invalid(
                        "execution-policy wall time exceeds the sprint duration budget",
                    ));
                }
                if let Some(worker_id) = logical_worker_id {
                    validate_identifier("logical_worker_id", worker_id)?;
                }
                match (role, logical_worker_id.as_deref(), worker_lease.as_ref()) {
                    (RunnerRole::Worker, Some(worker_id), Some(lease)) => {
                        validate_identifier("worker_lease.task_id", &lease.task_id)?;
                        lease
                            .validate_assignment(sprint_id, &lease.task_id, worker_id)
                            .map_err(|error| invalid(error.to_string()))?;
                    }
                    (
                        RunnerRole::FinalVerifier
                        | RunnerRole::Applier
                        | RunnerRole::LiveStateVerifier,
                        None,
                        None,
                    ) => {}
                    _ => {
                        return Err(invalid(
                            "worker initialization requires one exact logical worker and lease; non-worker initialization forbids both",
                        ));
                    }
                }
                validate_absolute_path_text("private_state_root", private_state_root)?;
                if let Some(root) = shadow_root {
                    validate_absolute_path_text("shadow_root", root)?;
                }
            }
            Self::WorkerCaptureLive { created_at_unix_ms }
            | Self::FinalVerifierCapture { created_at_unix_ms }
            | Self::ApplierCaptureLive { created_at_unix_ms } => {
                require_nonzero(*created_at_unix_ms, "capture timestamp")?;
            }
            Self::WorkerCreateShadow { .. }
            | Self::WorkerCancel
            | Self::ApplierRecoverPending
            | Self::Shutdown => {}
            Self::LiveStateVerifierCapture { request } => request
                .validate()
                .map_err(|error| invalid(error.to_string()))?,
            Self::WorkerReadFile { path, max_bytes } => {
                validate_relative_path_text(path)?;
                validate_inline_file_bound(*max_bytes)?;
            }
            Self::WorkerSearchLiteral {
                path,
                needle,
                max_bytes,
                max_matches,
            } => {
                validate_relative_path_text(path)?;
                validate_inline_file_bound(*max_bytes)?;
                if needle.is_empty() || needle.len() > MAX_WIRE_LITERAL_BYTES {
                    return Err(invalid("literal bytes are outside the wire bound"));
                }
                if *max_matches == 0 || *max_matches > MAX_WIRE_SEARCH_MATCHES {
                    return Err(invalid("literal match count is outside the wire bound"));
                }
            }
            Self::WorkerCreateFile { path, contents }
            | Self::WorkerReplaceFile { path, contents, .. } => {
                validate_relative_path_text(path)?;
                if contents.len() > MAX_INLINE_FILE_BYTES {
                    return Err(invalid("inline mutation bytes exceed the wire bound"));
                }
                if let Self::WorkerReplaceFile {
                    expected_digest, ..
                } = self
                    && *expected_digest == Digest::sha256(contents)
                {
                    return Err(invalid("replacement must change the exact endpoint digest"));
                }
            }
            Self::WorkerDeleteFile { path, .. } | Self::WorkerReconcileFile { path, .. } => {
                validate_relative_path_text(path)?;
                if let Self::WorkerReconcileFile { max_bytes, .. } = self {
                    validate_inline_file_bound(*max_bytes)?;
                }
            }
            Self::WorkerPrepareStage {
                change_set_id,
                created_at_unix_ms,
            } => {
                validate_identifier("change_set_id", change_set_id)?;
                require_nonzero(*created_at_unix_ms, "stage timestamp")?;
            }
            Self::WorkerStageChanges {
                change_set,
                expected_bundle,
            } => validate_bundle_change_set(expected_bundle, change_set)?,
            Self::WorkerReconcileStage { expected_bundle } => expected_bundle
                .validate()
                .map_err(|error| invalid(error.to_string()))?,
            Self::WorkerRunCommand {
                command,
                output_capture,
            }
            | Self::FinalVerifierRunCommand {
                command,
                output_capture,
            } => {
                validate_legacy_runner_command_v11_v12(command)?;
                output_capture.validate()?;
            }
            Self::ApplierReconcileStageBundle { expected_bundle } => expected_bundle
                .validate()
                .map_err(|error| invalid(error.to_string()))?,
            Self::ApplierApplyBundle { bundle } | Self::ApplierReconcile { bundle } => bundle
                .validate()
                .map_err(|error| invalid(error.to_string()))?,
            Self::ApplierRollback { bundle, rollback } => {
                bundle
                    .validate()
                    .map_err(|error| invalid(error.to_string()))?;
                rollback.validate()?;
                if rollback.change_set_id != bundle.change_set_id
                    || rollback.base_snapshot != bundle.base_snapshot
                {
                    return Err(invalid(
                        "rollback artifact reference and exact stage-bundle reference disagree",
                    ));
                }
            }
        }
        Ok(())
    }

    pub(crate) const fn required_role(&self) -> Option<RunnerRole> {
        match self {
            Self::InitializeSession { .. } | Self::Shutdown => None,
            Self::WorkerCaptureLive { .. }
            | Self::WorkerCreateShadow { .. }
            | Self::WorkerReadFile { .. }
            | Self::WorkerSearchLiteral { .. }
            | Self::WorkerCreateFile { .. }
            | Self::WorkerReplaceFile { .. }
            | Self::WorkerDeleteFile { .. }
            | Self::WorkerReconcileFile { .. }
            | Self::WorkerPrepareStage { .. }
            | Self::WorkerStageChanges { .. }
            | Self::WorkerReconcileStage { .. }
            | Self::WorkerRunCommand { .. }
            | Self::WorkerCancel => Some(RunnerRole::Worker),
            Self::FinalVerifierCapture { .. } | Self::FinalVerifierRunCommand { .. } => {
                Some(RunnerRole::FinalVerifier)
            }
            Self::LiveStateVerifierCapture { .. } => Some(RunnerRole::LiveStateVerifier),
            Self::ApplierRecoverPending
            | Self::ApplierReconcileStageBundle { .. }
            | Self::ApplierApplyBundle { .. }
            | Self::ApplierReconcile { .. }
            | Self::ApplierRollback { .. }
            | Self::ApplierCaptureLive { .. } => Some(RunnerRole::Applier),
        }
    }

    /// Builds the exact core request preimage that must be persisted before a
    /// `WorkerStageChanges` publication effect is dispatched.
    ///
    /// # Errors
    ///
    /// Returns an error for any other request variant, an invalid stage-bundle
    /// reference, or disagreement between the exact change set and artifact.
    pub fn to_core_task_integration_request(
        &self,
    ) -> Result<TaskIntegrationRequest, WireProtocolError> {
        let Self::WorkerStageChanges {
            change_set,
            expected_bundle,
        } = self
        else {
            return Err(invalid(
                "only WorkerStageChanges has a core task-integration request preimage",
            ));
        };
        validate_bundle_change_set(expected_bundle, change_set)?;
        let request = TaskIntegrationRequest {
            contract_version: CONTRACT_VERSION,
            change_set: change_set.as_ref().clone(),
            artifact: expected_bundle
                .to_core_integration_artifact()
                .map_err(|error| invalid(error.to_string()))?,
        };
        request
            .validate()
            .map_err(|error| invalid(error.to_string()))?;
        Ok(request)
    }

    /// Returns whether this request is bounded session preparation, capture,
    /// recovery, or process control rather than a core-ledger effect.
    ///
    /// This is deliberately a closed positive list: every future request
    /// variant defaults to effect-required until it is explicitly audited.
    #[must_use]
    pub const fn is_session_control(&self) -> bool {
        matches!(
            self,
            Self::WorkerCaptureLive { .. }
                | Self::WorkerCreateShadow { .. }
                | Self::WorkerReconcileFile { .. }
                | Self::WorkerPrepareStage { .. }
                | Self::WorkerReconcileStage { .. }
                | Self::WorkerCancel
                | Self::FinalVerifierCapture { .. }
                | Self::ApplierRecoverPending
                | Self::ApplierReconcileStageBundle { .. }
                | Self::ApplierReconcile { .. }
                | Self::ApplierCaptureLive { .. }
                | Self::Shutdown
        )
    }
}

impl TryFrom<&TaskIntegrationRequest> for RunnerRequest {
    type Error = WireProtocolError;

    fn try_from(request: &TaskIntegrationRequest) -> Result<Self, Self::Error> {
        request
            .validate()
            .map_err(|error| invalid(error.to_string()))?;
        let expected_bundle = StageBundleReference::try_from(&request.artifact)
            .map_err(|error| invalid(error.to_string()))?;
        let wire = Self::WorkerStageChanges {
            change_set: Box::new(request.change_set.clone()),
            expected_bundle,
        };
        wire.validate()?;
        Ok(wire)
    }
}

/// Common version/session/request envelope for every client request.
#[allow(
    missing_docs,
    reason = "public fields are the mandatory correlation envelope"
)]
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RunnerRequestEnvelope {
    pub protocol_version: u32,
    pub session_id: String,
    pub runner_nonce: Option<Digest>,
    pub sequence: u64,
    pub request_id: String,
    pub effect: Option<WireEffectContext>,
    pub request: RunnerRequest,
}

/// Closed v12 request set. Only command effects use the additive policy-bound
/// protocol; every non-command operation remains on frozen v11.
#[allow(
    missing_docs,
    reason = "variant fields are the normative v12 command request schema"
)]
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum RunnerRequestV12 {
    RunCommand {
        request: RunnerRequest,
        detector_policy: SensitiveOutputDetectionPolicyReferenceV1,
    },
}

impl RunnerRequestV12 {
    pub(super) fn validate(&self) -> Result<(), WireProtocolError> {
        let Self::RunCommand {
            request,
            detector_policy,
        } = self;
        if !matches!(
            request,
            RunnerRequest::WorkerRunCommand { .. } | RunnerRequest::FinalVerifierRunCommand { .. }
        ) {
            return Err(invalid("v12 admits only an exact RunCommand request"));
        }
        request.validate()?;
        detector_policy
            .validate()
            .map_err(|error| invalid(error.to_string()))?;
        crate::sensitive_output::validate_matcher_policy_v1(detector_policy)
            .map_err(|_| invalid("v12 detector policy differs from the compiled matcher"))
    }

    /// Returns the exact fixed policy admitted before command launch.
    #[must_use]
    pub const fn detector_policy(&self) -> &SensitiveOutputDetectionPolicyReferenceV1 {
        match self {
            Self::RunCommand {
                detector_policy, ..
            } => detector_policy,
        }
    }

    /// Returns the unchanged role-exact v11 command DTO nested by v12.
    #[must_use]
    pub const fn command_request(&self) -> &RunnerRequest {
        match self {
            Self::RunCommand { request, .. } => request,
        }
    }
}

/// Correlation envelope for one additive v12 command exchange.
#[allow(
    missing_docs,
    reason = "public fields are the mandatory v12 correlation envelope"
)]
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RunnerRequestEnvelopeV12 {
    pub protocol_version: u32,
    pub session_id: String,
    pub runner_nonce: Digest,
    pub sequence: u64,
    pub request_id: String,
    pub effect: WireEffectContext,
    pub request: RunnerRequestV12,
}

impl RunnerRequestEnvelopeV12 {
    pub(super) fn validate(&self) -> Result<(), WireProtocolError> {
        if self.protocol_version != RUNNER_WIRE_PROTOCOL_VERSION_V12 {
            return Err(WireProtocolError::Version {
                expected: RUNNER_WIRE_PROTOCOL_VERSION_V12,
                actual: self.protocol_version,
            });
        }
        if self.sequence == 0 || self.sequence == u64::MAX {
            return Err(invalid("v12 command sequence must be positive and finite"));
        }
        validate_identifier("session_id", &self.session_id)?;
        validate_identifier("request_id", &self.request_id)?;
        self.request.validate()?;
        self.effect.validate_shape()?;
        if self.effect.transport_commitment_digest != self.computed_transport_commitment_digest()? {
            return Err(invalid(
                "v12 transport commitment digest differs from the full policy-bound request",
            ));
        }
        let mut legacy = self.as_v11_envelope();
        legacy.bind_transport_commitment_digest()?;
        legacy.validate()
    }

    /// Projects only the unchanged command/effect fields for existing command
    /// authority validation. The v12 policy remains separately mandatory.
    #[must_use]
    pub fn as_v11_envelope(&self) -> RunnerRequestEnvelope {
        RunnerRequestEnvelope {
            protocol_version: RUNNER_WIRE_PROTOCOL_VERSION,
            session_id: self.session_id.clone(),
            runner_nonce: Some(self.runner_nonce.clone()),
            sequence: self.sequence,
            request_id: self.request_id.clone(),
            effect: Some(self.effect.clone()),
            request: self.request.command_request().clone(),
        }
    }

    /// Returns the exact pre-effect policy reference carried by v12.
    #[must_use]
    pub const fn detector_policy(&self) -> &SensitiveOutputDetectionPolicyReferenceV1 {
        self.request.detector_policy()
    }

    /// Computes the domain-separated digest over the complete v12 command
    /// envelope except the digest field itself, including detector policy.
    ///
    /// # Errors
    ///
    /// Returns an error if the canonical commitment cannot be encoded or its
    /// length cannot be represented by the fixed framing contract.
    pub fn computed_transport_commitment_digest(&self) -> Result<Digest, WireProtocolError> {
        let effect = &self.effect;
        let commitment = RequestCommitmentV12 {
            protocol_version: self.protocol_version,
            contract_version: effect.contract_version,
            session_id: &self.session_id,
            runner_nonce: &self.runner_nonce,
            sequence: self.sequence,
            request_id: &self.request_id,
            launch_id: &effect.launch_id,
            effect_id: &effect.effect_id,
            idempotency_key: &effect.idempotency_key,
            sprint_id: &effect.sprint_id,
            task_id: &effect.task_id,
            worker_id: &effect.worker_id,
            worker_lease: &effect.worker_lease,
            policy_hash: &effect.policy_hash,
            input_snapshot: &effect.input_snapshot,
            request_digest: &effect.request_digest,
            request: &self.request,
        };
        let canonical = serde_json::to_vec(&commitment)
            .map_err(|error| WireProtocolError::Encode(error.to_string()))?;
        let canonical_length = u64::try_from(canonical.len())
            .map_err(|_| invalid("canonical v12 request length exceeds u64"))?;
        let mut preimage = Vec::with_capacity(
            REQUEST_COMMITMENT_V12_DOMAIN.len() + std::mem::size_of::<u64>() + canonical.len(),
        );
        preimage.extend_from_slice(REQUEST_COMMITMENT_V12_DOMAIN);
        preimage.extend_from_slice(&canonical_length.to_be_bytes());
        preimage.extend_from_slice(&canonical);
        Ok(Digest::sha256(&preimage))
    }

    /// Installs the full v12 transport commitment, including detector policy.
    ///
    /// # Errors
    ///
    /// Returns the canonical commitment encoding errors from
    /// [`Self::computed_transport_commitment_digest`].
    pub fn bind_transport_commitment_digest(&mut self) -> Result<(), WireProtocolError> {
        self.effect.transport_commitment_digest = self.computed_transport_commitment_digest()?;
        Ok(())
    }
}

/// Version of the complete command-effect authority preimage retained between
/// the role-sealed runner service and a future native containment backend.
pub(crate) const COMMAND_EFFECT_AUTHORITY_SCHEMA_VERSION: u32 = 1;
/// Version of the complete policy-bound v12 command-effect authority.
pub(crate) const COMMAND_EFFECT_AUTHORITY_V2_SCHEMA_VERSION: u32 = 2;

/// Complete immutable command-effect binding at the runner/platform boundary.
///
/// The exact validated wire envelope is retained instead of projecting a
/// smaller collection of hashes. `grant_hash` adds the independently restored
/// workspace authority that is not carried by each wire request. This object
/// is necessary input to a native platform transition, but it is deliberately
/// not a release permit: a backend must still join it to a live, non-cloneable
/// native preparation claim and its crash-safe platform journal.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CommandEffectAuthorityV1 {
    pub(super) schema_version: u32,
    pub(super) contract_version: u32,
    pub(super) grant_hash: Digest,
    pub(super) role: RunnerRole,
    pub(super) envelope: RunnerRequestEnvelope,
}

impl CommandEffectAuthorityV1 {
    /// Retains a command envelope only from a proof minted after live service
    /// session validation, then independently revalidates transport and the
    /// exact canonical core `CommandSpec` digest.
    #[allow(
        dead_code,
        reason = "v11 command authority remains only for historical codec and refusal-path compatibility; production commands require v12"
    )]
    pub(crate) fn from_session_validated(
        proof: SessionValidatedCommandEnvelope,
    ) -> Result<Option<Self>, WireProtocolError> {
        let (envelope, grant_hash) = proof.into_parts();
        envelope.validate()?;
        let role = match &envelope.request {
            RunnerRequest::WorkerRunCommand { .. } => RunnerRole::Worker,
            RunnerRequest::FinalVerifierRunCommand { .. } => RunnerRole::FinalVerifier,
            _ => return Ok(None),
        };
        let authority = Self {
            schema_version: COMMAND_EFFECT_AUTHORITY_SCHEMA_VERSION,
            contract_version: CONTRACT_VERSION,
            grant_hash,
            role,
            envelope,
        };
        authority.validate_integrity()?;
        Ok(Some(authority))
    }

    pub(crate) fn validate_integrity(&self) -> Result<(), WireProtocolError> {
        if self.schema_version != COMMAND_EFFECT_AUTHORITY_SCHEMA_VERSION {
            return Err(invalid("command-effect authority schema version differs"));
        }
        if self.contract_version != CONTRACT_VERSION {
            return Err(invalid("command-effect authority contract version differs"));
        }
        self.envelope.validate()?;
        let (expected_role, command, output_capture) = match &self.envelope.request {
            RunnerRequest::WorkerRunCommand {
                command,
                output_capture,
            } => (RunnerRole::Worker, command, output_capture),
            RunnerRequest::FinalVerifierRunCommand {
                command,
                output_capture,
            } => (RunnerRole::FinalVerifier, command, output_capture),
            _ => {
                return Err(invalid(
                    "command-effect authority requires one role-exact command request",
                ));
            }
        };
        if self.role != expected_role {
            return Err(invalid(
                "command-effect authority role differs from request",
            ));
        }
        let effect =
            self.envelope.effect.as_ref().ok_or_else(|| {
                invalid("command-effect authority requires durable effect context")
            })?;
        validate_command_effect_request(
            effect,
            self.role,
            command,
            output_capture,
            &self.envelope.session_id,
        )
    }

    pub(crate) const fn role(&self) -> RunnerRole {
        self.role
    }

    pub(crate) fn grant_hash(&self) -> &Digest {
        &self.grant_hash
    }

    pub(crate) fn envelope(&self) -> &RunnerRequestEnvelope {
        &self.envelope
    }
}

/// Complete immutable policy-bound v12 command-effect authority.
///
/// This type retains the exact service-validated v12 envelope. It is never
/// reconstructed from a v11 projection, so detector policy and the v12
/// transport commitment remain launch authority through containment.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CommandEffectAuthorityV2 {
    pub(super) schema_version: u32,
    pub(super) contract_version: u32,
    pub(super) grant_hash: Digest,
    pub(super) role: RunnerRole,
    pub(super) envelope: RunnerRequestEnvelopeV12,
}

impl CommandEffectAuthorityV2 {
    /// Consumes the non-cloneable proof minted only by the live mixed-protocol
    /// service after session, grant, role, sequence, and effect validation.
    pub(crate) fn from_session_validated(
        proof: SessionValidatedCommandEnvelopeV12,
    ) -> Result<Self, WireProtocolError> {
        let (envelope, grant_hash) = proof.into_parts();
        envelope.validate()?;
        let role = match envelope.request.command_request() {
            RunnerRequest::WorkerRunCommand { .. } => RunnerRole::Worker,
            RunnerRequest::FinalVerifierRunCommand { .. } => RunnerRole::FinalVerifier,
            _ => {
                return Err(invalid(
                    "v12 authority requires a role-exact command request",
                ));
            }
        };
        let authority = Self {
            schema_version: COMMAND_EFFECT_AUTHORITY_V2_SCHEMA_VERSION,
            contract_version: CONTRACT_VERSION,
            grant_hash,
            role,
            envelope,
        };
        authority.validate_integrity()?;
        Ok(authority)
    }

    pub(crate) fn validate_integrity(&self) -> Result<(), WireProtocolError> {
        if self.schema_version != COMMAND_EFFECT_AUTHORITY_V2_SCHEMA_VERSION
            || self.contract_version != CONTRACT_VERSION
        {
            return Err(invalid("v12 command-effect authority version differs"));
        }
        self.envelope.validate()?;
        let (expected_role, command, output_capture) = match self.envelope.request.command_request()
        {
            RunnerRequest::WorkerRunCommand {
                command,
                output_capture,
            } => (RunnerRole::Worker, command, output_capture),
            RunnerRequest::FinalVerifierRunCommand {
                command,
                output_capture,
            } => (RunnerRole::FinalVerifier, command, output_capture),
            _ => {
                return Err(invalid(
                    "v12 command-effect authority requires one role-exact command request",
                ));
            }
        };
        if self.role != expected_role {
            return Err(invalid(
                "v12 command-effect authority role differs from request",
            ));
        }
        validate_command_effect_request(
            &self.envelope.effect,
            self.role,
            command,
            output_capture,
            &self.envelope.session_id,
        )
    }

    pub(crate) const fn role(&self) -> RunnerRole {
        self.role
    }

    pub(crate) const fn grant_hash(&self) -> &Digest {
        &self.grant_hash
    }

    pub(crate) const fn envelope(&self) -> &RunnerRequestEnvelopeV12 {
        &self.envelope
    }

    pub(crate) const fn detector_policy(&self) -> &SensitiveOutputDetectionPolicyReferenceV1 {
        self.envelope.detector_policy()
    }

    /// Returns the legacy execution projection only after full v12 integrity
    /// has been retained. Its transport digest is rebound to the v11 domain;
    /// callers must continue carrying this v2 authority as the source of truth.
    pub(crate) fn v11_execution_projection(
        &self,
    ) -> Result<CommandEffectAuthorityV1, WireProtocolError> {
        self.validate_integrity()?;
        let mut envelope = self.envelope.as_v11_envelope();
        envelope.bind_transport_commitment_digest()?;
        envelope.validate()?;
        let projection = CommandEffectAuthorityV1 {
            schema_version: COMMAND_EFFECT_AUTHORITY_SCHEMA_VERSION,
            contract_version: CONTRACT_VERSION,
            grant_hash: self.grant_hash.clone(),
            role: self.role,
            envelope,
        };
        projection.validate_integrity()?;
        Ok(projection)
    }
}

impl RunnerRequestEnvelope {
    pub(super) fn validate(&self) -> Result<(), WireProtocolError> {
        if self.protocol_version != RUNNER_WIRE_PROTOCOL_VERSION {
            return Err(WireProtocolError::Version {
                expected: RUNNER_WIRE_PROTOCOL_VERSION,
                actual: self.protocol_version,
            });
        }
        validate_identifier("session_id", &self.session_id)?;
        validate_identifier("request_id", &self.request_id)?;
        self.request.validate()?;
        match (&self.request, &self.runner_nonce, &self.effect) {
            (RunnerRequest::InitializeSession { .. }, None, None) if self.sequence == 0 => Ok(()),
            (RunnerRequest::InitializeSession { .. }, _, _) => Err(invalid(
                "initialization requires sequence zero and forbids runner nonce/effect context",
            )),
            (request, Some(_), None)
                if request.is_session_control()
                    && self.sequence > 0
                    && self.sequence < u64::MAX =>
            {
                Ok(())
            }
            (request, Some(_), Some(_)) if request.is_session_control() => Err(invalid(
                "session-control requests forbid fabricated core effect context",
            )),
            (request, Some(_), Some(effect))
                if !request.is_session_control()
                    && self.sequence > 0
                    && self.sequence < u64::MAX =>
            {
                effect.validate_shape()?;
                if effect.transport_commitment_digest
                    != self.computed_transport_commitment_digest()?
                {
                    return Err(invalid(
                        "transport commitment digest differs from the exact wire request commitment",
                    ));
                }
                if let RunnerRequest::LiveStateVerifierCapture { request } = request {
                    let expected_request_digest = request
                        .request_digest()
                        .map_err(|error| invalid(error.to_string()))?;
                    if effect.request_digest != expected_request_digest
                        || effect.task_id.is_some()
                        || effect.worker_id.is_some()
                        || effect.worker_lease.is_some()
                    {
                        return Err(invalid(
                            "live-state capture effect differs from the exact core request or sprint scope",
                        ));
                    }
                }
                match request {
                    RunnerRequest::WorkerRunCommand {
                        command,
                        output_capture,
                    } => {
                        validate_command_effect_request(
                            effect,
                            RunnerRole::Worker,
                            command,
                            output_capture,
                            &self.session_id,
                        )?;
                    }
                    RunnerRequest::FinalVerifierRunCommand {
                        command,
                        output_capture,
                    } => {
                        validate_command_effect_request(
                            effect,
                            RunnerRole::FinalVerifier,
                            command,
                            output_capture,
                            &self.session_id,
                        )?;
                    }
                    _ => {}
                }
                Ok(())
            }
            _ => Err(invalid(
                "every non-initialization request requires a nonce and positive sequence; non-controls also require effect context",
            )),
        }
    }

    /// Computes the domain-separated digest of every transport request field
    /// except `effect.transport_commitment_digest` itself. The distinct core
    /// `request_digest` remains the plain digest of ledger-persisted bytes.
    ///
    /// # Errors
    ///
    /// Returns an error for an initialization envelope, a missing nonce/effect,
    /// or canonical serialization failure.
    pub fn computed_transport_commitment_digest(&self) -> Result<Digest, WireProtocolError> {
        let nonce = self
            .runner_nonce
            .as_ref()
            .ok_or_else(|| invalid("effect commitment requires the initialized runner nonce"))?;
        let effect = self
            .effect
            .as_ref()
            .ok_or_else(|| invalid("effect commitment requires effect context"))?;
        if matches!(self.request, RunnerRequest::InitializeSession { .. }) {
            return Err(invalid("initialization has no durable effect commitment"));
        }
        let commitment = RequestCommitment {
            protocol_version: self.protocol_version,
            contract_version: effect.contract_version,
            session_id: &self.session_id,
            runner_nonce: nonce,
            sequence: self.sequence,
            request_id: &self.request_id,
            launch_id: &effect.launch_id,
            effect_id: &effect.effect_id,
            idempotency_key: &effect.idempotency_key,
            sprint_id: &effect.sprint_id,
            task_id: &effect.task_id,
            worker_id: &effect.worker_id,
            worker_lease: &effect.worker_lease,
            policy_hash: &effect.policy_hash,
            input_snapshot: &effect.input_snapshot,
            request_digest: &effect.request_digest,
            request: &self.request,
        };
        let canonical = serde_json::to_vec(&commitment)
            .map_err(|error| WireProtocolError::Encode(error.to_string()))?;
        let mut preimage = Vec::with_capacity(
            REQUEST_COMMITMENT_DOMAIN.len() + std::mem::size_of::<u64>() + canonical.len(),
        );
        preimage.extend_from_slice(REQUEST_COMMITMENT_DOMAIN);
        let canonical_length = u64::try_from(canonical.len())
            .map_err(|_| invalid("canonical request length exceeds u64"))?;
        preimage.extend_from_slice(&canonical_length.to_be_bytes());
        preimage.extend_from_slice(&canonical);
        Ok(Digest::sha256(&preimage))
    }

    /// Replaces the placeholder transport digest with the exact commitment.
    ///
    /// # Errors
    ///
    /// Returns an error when the envelope is not a non-initialization effect
    /// request or canonical serialization fails.
    pub fn bind_transport_commitment_digest(&mut self) -> Result<(), WireProtocolError> {
        let digest = self.computed_transport_commitment_digest()?;
        self.effect
            .as_mut()
            .ok_or_else(|| invalid("effect context is absent"))?
            .transport_commitment_digest = digest;
        Ok(())
    }
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct DecodedContainedCaptureLaunchBinding {
    pub(super) schema_version: u32,
    pub(super) command_effect_authority_digest: Digest,
    pub(super) role: RunnerRole,
    pub(super) grant_hash: Digest,
    pub(super) runner_session_id: String,
    pub(super) runner_nonce: Option<Digest>,
    pub(super) request_sequence: u64,
    pub(super) request_id: String,
    pub(super) effect_contract_version: u32,
    pub(super) runner_launch_id: String,
    pub(super) effect_id: String,
    pub(super) idempotency_key: String,
    pub(super) sprint_id: String,
    pub(super) task_id: Option<String>,
    pub(super) worker_id: Option<String>,
    pub(super) policy_hash: Digest,
    pub(super) input_snapshot: Digest,
    pub(super) command_request_digest: Digest,
    pub(super) transport_commitment_digest: Digest,
    pub(super) capture_id: String,
    pub(super) capture_intent_digest: Digest,
    pub(super) capture_acquired_anchor_digest: Digest,
    pub(super) capture_acquired_store_head: CommandOutputCaptureStoreHeadV1,
    pub(super) capture_dispatch_claim_id: String,
    pub(super) capture_private_state_digest: Digest,
    pub(super) capture_max_aggregate_output_bytes: u64,
    pub(super) launch_digest: Digest,
    pub(super) preflight_digest: Digest,
    pub(super) command_domain_backend: CommandDomainCleanupBackend,
    pub(super) backend_id: String,
    pub(super) backend_implementation_digest: Digest,
    pub(super) closed_exec_descriptors: [i32; 3],
}

#[cfg(feature = "test-support")]
pub(crate) fn encode_contained_capture_launch_binding_v12_for_test_support(
    request: &RunnerRequestEnvelopeV12,
    grant_hash: &Digest,
    acquired: &CommandOutputCaptureAcquiredV1,
    launch_digest: &Digest,
    preflight_digest: &Digest,
    backend: &WireCommandBackendIdentity,
) -> Result<Vec<u8>, WireProtocolError> {
    request.validate()?;
    acquired
        .validate()
        .map_err(|error| invalid(error.to_string()))?;
    let (role, output_capture) = match request.request.command_request() {
        RunnerRequest::WorkerRunCommand { output_capture, .. } => {
            (RunnerRole::Worker, output_capture)
        }
        RunnerRequest::FinalVerifierRunCommand { output_capture, .. } => {
            (RunnerRole::FinalVerifier, output_capture)
        }
        _ => {
            return Err(invalid(
                "test-support v12 launch binding requires one role-exact command request",
            ));
        }
    };
    if output_capture.acquired() != acquired {
        return Err(invalid(
            "test-support v12 launch binding crossed its acquired capture",
        ));
    }
    if backend.backend_id.trim().is_empty()
        || backend.backend_id.len() > 128
        || backend.backend_id.chars().any(char::is_control)
    {
        return Err(invalid(
            "test-support v12 launch binding backend identity is malformed",
        ));
    }
    let authority = CommandEffectAuthorityV2 {
        schema_version: COMMAND_EFFECT_AUTHORITY_V2_SCHEMA_VERSION,
        contract_version: CONTRACT_VERSION,
        grant_hash: grant_hash.clone(),
        role,
        envelope: request.clone(),
    };
    authority.validate_integrity()?;
    let authority_bytes = serde_json::to_vec(&authority)
        .map_err(|error| WireProtocolError::Encode(error.to_string()))?;
    let effect = &request.effect;
    let binding = DecodedContainedCaptureLaunchBinding {
        schema_version: 1,
        command_effect_authority_digest: Digest::sha256(&authority_bytes),
        role,
        grant_hash: grant_hash.clone(),
        runner_session_id: request.session_id.clone(),
        runner_nonce: Some(request.runner_nonce.clone()),
        request_sequence: request.sequence,
        request_id: request.request_id.clone(),
        effect_contract_version: effect.contract_version,
        runner_launch_id: effect.launch_id.clone(),
        effect_id: effect.effect_id.clone(),
        idempotency_key: effect.idempotency_key.clone(),
        sprint_id: effect.sprint_id.clone(),
        task_id: effect.task_id.clone(),
        worker_id: effect.worker_id.clone(),
        policy_hash: effect.policy_hash.clone(),
        input_snapshot: effect.input_snapshot.clone(),
        command_request_digest: effect.request_digest.clone(),
        transport_commitment_digest: effect.transport_commitment_digest.clone(),
        capture_id: acquired.capture_id.clone(),
        capture_intent_digest: acquired.intent_digest.clone(),
        capture_acquired_anchor_digest: acquired.acquired_anchor_digest.clone(),
        capture_acquired_store_head: acquired.store_head.clone(),
        capture_dispatch_claim_id: acquired.dispatch_claim_id.clone(),
        capture_private_state_digest: acquired.private_state_digest.clone(),
        capture_max_aggregate_output_bytes: acquired.max_aggregate_output_bytes,
        launch_digest: launch_digest.clone(),
        preflight_digest: preflight_digest.clone(),
        command_domain_backend: backend.command_domain_backend,
        backend_id: backend.backend_id.clone(),
        backend_implementation_digest: backend.implementation_digest.clone(),
        closed_exec_descriptors: [0, 1, 2],
    };
    serde_json::to_vec(&binding).map_err(|error| WireProtocolError::Encode(error.to_string()))
}

/// Strictly reconstructs and validates one retained contained-command launch
/// binding without asking the caller to synthesize the original wire envelope.
///
/// Sequence, request ID, nonce, and transport commitment come from the
/// immutable launch record. All execution authority comes independently from
/// the exact core effect, dispatch claim, registered session, command, acquired
/// capture, and grant supplied by the caller. The reconstructed canonical wire
/// frame must hash to the dispatch claim's opaque request digest, and the full
/// private command-effect authority must hash to the digest retained in the
/// launch binding.
///
/// # Errors
///
/// Returns an error for oversized, truncated, unknown-field, non-canonical,
/// substituted, non-worker, crossed-head, crossed-request, crossed-acquisition,
/// crossed-authority, malformed backend, or descriptor-closure evidence.
#[allow(
    clippy::too_many_arguments,
    clippy::too_many_lines,
    reason = "restart launch reconstruction intentionally joins independent core, session, command, capture, grant, and physical-journal authorities in one auditable validator"
)]
pub fn decode_contained_capture_launch_binding(
    bytes: &[u8],
    launch_intended_store_head: &CommandOutputCaptureStoreHeadV1,
    effect: &EffectIntent,
    dispatch_claim: &PersistedRunnerEffectDispatchClaim,
    session: &RunnerSessionPolicyRecord,
    command: &WireCommandSpec,
    output_capture: &WireCommandOutputCaptureAnchorV1,
    expected_grant_hash: &Digest,
) -> Result<ValidatedCommandCaptureLaunchBinding, WireProtocolError> {
    if bytes.is_empty() || bytes.len() > MAX_CONTAINED_CAPTURE_LAUNCH_BINDING_BYTES {
        return Err(invalid(
            "contained capture launch binding length is outside the restart bound",
        ));
    }
    let decoded: DecodedContainedCaptureLaunchBinding = serde_json::from_slice(bytes)
        .map_err(|error| WireProtocolError::InvalidJson(error.to_string()))?;
    let canonical = serde_json::to_vec(&decoded)
        .map_err(|error| WireProtocolError::Encode(error.to_string()))?;
    if canonical != bytes {
        return Err(WireProtocolError::NonCanonical);
    }
    if decoded.schema_version != 1 {
        return Err(invalid(
            "contained capture launch binding schema version differs",
        ));
    }
    effect
        .validate()
        .map_err(|error| invalid(error.to_string()))?;
    session
        .validate()
        .map_err(|error| invalid(error.to_string()))?;
    output_capture.validate()?;
    launch_intended_store_head
        .validate()
        .map_err(|error| invalid(error.to_string()))?;
    let acquired = output_capture.acquired();
    let expected_launch_generation = acquired
        .store_head
        .generation
        .checked_add(2)
        .ok_or_else(|| invalid("LaunchIntended generation overflowed u64"))?;
    if launch_intended_store_head.generation != expected_launch_generation
        || launch_intended_store_head.record_digest == acquired.store_head.record_digest
    {
        return Err(invalid(
            "LaunchIntended head is not the exact distinct Acquired-plus-two successor",
        ));
    }
    if effect.kind != EffectKind::RunCommand
        || session.purpose != RunnerSessionPurpose::TaskWorker
        || session.worker_id != effect.worker_id
        || session.worker_lease != effect.worker_lease
        || session.sprint_id != effect.sprint_id
        || session.policy_hash != effect.policy_hash
        || session.grant_hash != *expected_grant_hash
    {
        return Err(invalid(
            "worker effect, registered session, policy, lease, or grant authority is crossed",
        ));
    }
    let claim_running_boundary = dispatch_claim.running_boundary_id.as_deref();
    match (&dispatch_claim.authority, claim_running_boundary) {
        (
            RunnerEffectRequestAuthority::TaskRunning {
                running_boundary_id,
            },
            Some(claim_running_boundary),
        ) if running_boundary_id == claim_running_boundary => {}
        _ => {
            return Err(invalid(
                "worker command dispatch claim lacks exact TaskRunning authority",
            ));
        }
    }
    if dispatch_claim.contract_version != CONTRACT_VERSION
        || dispatch_claim.effect_id != effect.effect_id
        || dispatch_claim.sprint_id != effect.sprint_id
        || dispatch_claim.launch_id != session.launch_id
        || dispatch_claim.session_id != session.session_id
        || dispatch_claim.request_digest != effect.request_digest
        || dispatch_claim.policy_hash != effect.policy_hash
        || dispatch_claim.input_snapshot != effect.input_snapshot
        || dispatch_claim.dispatch_claim_id != acquired.dispatch_claim_id
    {
        return Err(invalid(
            "persisted dispatch claim differs from effect, session, policy, snapshot, or capture acquisition",
        ));
    }
    let mut request = RunnerRequestEnvelope {
        protocol_version: RUNNER_WIRE_PROTOCOL_VERSION,
        session_id: session.session_id.clone(),
        runner_nonce: Some(session.session_nonce.clone()),
        sequence: decoded.request_sequence,
        request_id: decoded.request_id.clone(),
        effect: Some(WireEffectContext {
            contract_version: effect.contract_version,
            launch_id: dispatch_claim.launch_id.clone(),
            effect_id: effect.effect_id.clone(),
            idempotency_key: effect.idempotency_key.clone(),
            sprint_id: effect.sprint_id.clone(),
            task_id: effect.task_id.clone(),
            worker_id: effect.worker_id.clone(),
            worker_lease: effect.worker_lease.clone(),
            policy_hash: effect.policy_hash.clone(),
            input_snapshot: effect.input_snapshot.clone(),
            request_digest: effect.request_digest.clone(),
            transport_commitment_digest: Digest::sha256(
                b"grok-build/reconstructed-command-transport-placeholder/v1",
            ),
        }),
        request: RunnerRequest::WorkerRunCommand {
            command: command.clone(),
            output_capture: output_capture.clone(),
        },
    };
    request.bind_transport_commitment_digest()?;
    request.validate()?;
    if Digest::sha256(&encode_request_frame(&request)?)
        != dispatch_claim.opaque_transport_request_digest
    {
        return Err(invalid(
            "reconstructed canonical worker request frame differs from the dispatch claim",
        ));
    }
    let authority = CommandEffectAuthorityV1 {
        schema_version: COMMAND_EFFECT_AUTHORITY_SCHEMA_VERSION,
        contract_version: CONTRACT_VERSION,
        grant_hash: expected_grant_hash.clone(),
        role: RunnerRole::Worker,
        envelope: request.clone(),
    };
    authority.validate_integrity()?;
    let authority_bytes = serde_json::to_vec(&authority)
        .map_err(|error| WireProtocolError::Encode(error.to_string()))?;
    let authority_digest = Digest::sha256(&authority_bytes);
    let request_effect = request
        .effect
        .as_ref()
        .ok_or_else(|| invalid("validated worker request lost its effect context"))?;
    if decoded.command_effect_authority_digest != authority_digest
        || decoded.role != RunnerRole::Worker
        || decoded.grant_hash != *expected_grant_hash
        || decoded.runner_session_id != request.session_id
        || decoded.runner_nonce.as_ref() != request.runner_nonce.as_ref()
        || decoded.effect_contract_version != request_effect.contract_version
        || decoded.runner_launch_id != request_effect.launch_id
        || decoded.effect_id != request_effect.effect_id
        || decoded.idempotency_key != request_effect.idempotency_key
        || decoded.sprint_id != request_effect.sprint_id
        || decoded.task_id != request_effect.task_id
        || decoded.worker_id != request_effect.worker_id
        || decoded.policy_hash != request_effect.policy_hash
        || decoded.input_snapshot != request_effect.input_snapshot
        || decoded.command_request_digest != request_effect.request_digest
        || decoded.transport_commitment_digest != request_effect.transport_commitment_digest
        || decoded.capture_id != acquired.capture_id
        || decoded.capture_intent_digest != acquired.intent_digest
        || decoded.capture_acquired_anchor_digest != acquired.acquired_anchor_digest
        || decoded.capture_acquired_store_head != acquired.store_head
        || decoded.capture_dispatch_claim_id != acquired.dispatch_claim_id
        || decoded.capture_private_state_digest != acquired.private_state_digest
        || decoded.capture_max_aggregate_output_bytes != acquired.max_aggregate_output_bytes
    {
        return Err(invalid(
            "contained launch binding differs from exact request, effect, grant, or acquired capture authority",
        ));
    }
    if decoded.backend_id.trim().is_empty()
        || decoded.backend_id.len() > 128
        || decoded.backend_id.chars().any(char::is_control)
        || decoded.closed_exec_descriptors != [0, 1, 2]
    {
        return Err(invalid(
            "contained launch backend identity or child descriptor closure is malformed",
        ));
    }
    let command_domain_binding = CommandDomainCleanupBinding::try_new(
        request.session_id.clone(),
        effect.effect_id.clone(),
        effect.request_digest.clone(),
    )
    .map_err(|error| invalid(error.to_string()))?;
    Ok(ValidatedCommandCaptureLaunchBinding {
        request,
        launch_intended_store_head: launch_intended_store_head.clone(),
        canonical_bytes_digest: Digest::sha256(bytes),
        launch_digest: decoded.launch_digest,
        preflight_digest: decoded.preflight_digest,
        backend: WireCommandBackendIdentity {
            command_domain_backend: decoded.command_domain_backend,
            backend_id: decoded.backend_id,
            implementation_digest: decoded.backend_implementation_digest,
        },
        command_domain_binding,
        closed_exec_descriptors: decoded.closed_exec_descriptors,
    })
}

/// Strictly reconstructs one additive-v12 contained-command launch binding
/// from the exact detector policy persisted before dispatch.
///
/// This is intentionally separate from
/// [`decode_contained_capture_launch_binding`]. A v12 claim is never retried as
/// v11, and the detector policy is never defaulted from runner configuration
/// during restart. The reconstructed canonical v12 frame and complete v2
/// command authority must independently match the durable dispatch claim and
/// retained launch binding.
///
/// # Errors
///
/// Returns an error for any crossed policy, frame, authority, effect, session,
/// grant, acquisition, launch head, backend, or descriptor-closure evidence.
#[allow(
    clippy::too_many_arguments,
    clippy::too_many_lines,
    reason = "v12 restart reconstruction keeps every independently persisted authority join visible in one fail-closed validator"
)]
pub fn decode_contained_capture_launch_binding_v12(
    bytes: &[u8],
    launch_intended_store_head: &CommandOutputCaptureStoreHeadV1,
    effect: &EffectIntent,
    dispatch_claim: &PersistedRunnerEffectDispatchClaim,
    session: &RunnerSessionPolicyRecord,
    command: &WireCommandSpec,
    output_capture: &WireCommandOutputCaptureAnchorV1,
    detector_policy: &SensitiveOutputDetectionPolicyReferenceV1,
    expected_grant_hash: &Digest,
) -> Result<ValidatedCommandCaptureLaunchBindingV12, WireProtocolError> {
    if bytes.is_empty() || bytes.len() > MAX_CONTAINED_CAPTURE_LAUNCH_BINDING_BYTES {
        return Err(invalid(
            "contained v12 capture launch binding length is outside the restart bound",
        ));
    }
    let decoded: DecodedContainedCaptureLaunchBinding = serde_json::from_slice(bytes)
        .map_err(|error| WireProtocolError::InvalidJson(error.to_string()))?;
    let canonical = serde_json::to_vec(&decoded)
        .map_err(|error| WireProtocolError::Encode(error.to_string()))?;
    if canonical != bytes {
        return Err(WireProtocolError::NonCanonical);
    }
    if decoded.schema_version != 1 {
        return Err(invalid(
            "contained v12 capture launch binding schema version differs",
        ));
    }
    effect
        .validate()
        .map_err(|error| invalid(error.to_string()))?;
    session
        .validate()
        .map_err(|error| invalid(error.to_string()))?;
    detector_policy
        .validate()
        .map_err(|error| invalid(error.to_string()))?;
    crate::sensitive_output::validate_matcher_policy_v1(detector_policy)
        .map_err(|_| invalid("persisted v12 detector policy differs from the compiled matcher"))?;
    output_capture.validate()?;
    launch_intended_store_head
        .validate()
        .map_err(|error| invalid(error.to_string()))?;
    let acquired = output_capture.acquired();
    let expected_launch_generation = acquired
        .store_head
        .generation
        .checked_add(2)
        .ok_or_else(|| invalid("v12 LaunchIntended generation overflowed u64"))?;
    if launch_intended_store_head.generation != expected_launch_generation
        || launch_intended_store_head.record_digest == acquired.store_head.record_digest
    {
        return Err(invalid(
            "v12 LaunchIntended head is not the exact distinct Acquired-plus-two successor",
        ));
    }
    if effect.kind != EffectKind::RunCommand
        || session.purpose != RunnerSessionPurpose::TaskWorker
        || session.worker_id != effect.worker_id
        || session.worker_lease != effect.worker_lease
        || session.sprint_id != effect.sprint_id
        || session.policy_hash != effect.policy_hash
        || session.grant_hash != *expected_grant_hash
    {
        return Err(invalid(
            "v12 worker effect, registered session, policy, lease, or grant authority is crossed",
        ));
    }
    let claim_running_boundary = dispatch_claim.running_boundary_id.as_deref();
    match (&dispatch_claim.authority, claim_running_boundary) {
        (
            RunnerEffectRequestAuthority::TaskRunning {
                running_boundary_id,
            },
            Some(claim_running_boundary),
        ) if running_boundary_id == claim_running_boundary => {}
        _ => {
            return Err(invalid(
                "v12 worker command dispatch claim lacks exact TaskRunning authority",
            ));
        }
    }
    if dispatch_claim.contract_version != CONTRACT_VERSION
        || dispatch_claim.effect_id != effect.effect_id
        || dispatch_claim.sprint_id != effect.sprint_id
        || dispatch_claim.launch_id != session.launch_id
        || dispatch_claim.session_id != session.session_id
        || dispatch_claim.request_digest != effect.request_digest
        || dispatch_claim.policy_hash != effect.policy_hash
        || dispatch_claim.input_snapshot != effect.input_snapshot
        || dispatch_claim.dispatch_claim_id != acquired.dispatch_claim_id
    {
        return Err(invalid(
            "persisted v12 dispatch claim differs from effect, session, policy, snapshot, or capture acquisition",
        ));
    }
    let mut request = RunnerRequestEnvelopeV12 {
        protocol_version: RUNNER_WIRE_PROTOCOL_VERSION_V12,
        session_id: session.session_id.clone(),
        runner_nonce: session.session_nonce.clone(),
        sequence: decoded.request_sequence,
        request_id: decoded.request_id.clone(),
        effect: WireEffectContext {
            contract_version: effect.contract_version,
            launch_id: dispatch_claim.launch_id.clone(),
            effect_id: effect.effect_id.clone(),
            idempotency_key: effect.idempotency_key.clone(),
            sprint_id: effect.sprint_id.clone(),
            task_id: effect.task_id.clone(),
            worker_id: effect.worker_id.clone(),
            worker_lease: effect.worker_lease.clone(),
            policy_hash: effect.policy_hash.clone(),
            input_snapshot: effect.input_snapshot.clone(),
            request_digest: effect.request_digest.clone(),
            transport_commitment_digest: Digest::sha256(
                b"grok-build/reconstructed-command-transport-placeholder/v12",
            ),
        },
        request: RunnerRequestV12::RunCommand {
            request: RunnerRequest::WorkerRunCommand {
                command: command.clone(),
                output_capture: output_capture.clone(),
            },
            detector_policy: detector_policy.clone(),
        },
    };
    request.bind_transport_commitment_digest()?;
    request.validate()?;
    if Digest::sha256(&encode_request_frame_v12(&request)?)
        != dispatch_claim.opaque_transport_request_digest
    {
        return Err(invalid(
            "reconstructed canonical v12 worker request frame differs from the dispatch claim",
        ));
    }
    let authority = CommandEffectAuthorityV2 {
        schema_version: COMMAND_EFFECT_AUTHORITY_V2_SCHEMA_VERSION,
        contract_version: CONTRACT_VERSION,
        grant_hash: expected_grant_hash.clone(),
        role: RunnerRole::Worker,
        envelope: request.clone(),
    };
    authority.validate_integrity()?;
    let authority_bytes = serde_json::to_vec(&authority)
        .map_err(|error| WireProtocolError::Encode(error.to_string()))?;
    let authority_digest = Digest::sha256(&authority_bytes);
    let request_effect = &request.effect;
    if decoded.command_effect_authority_digest != authority_digest
        || decoded.role != RunnerRole::Worker
        || decoded.grant_hash != *expected_grant_hash
        || decoded.runner_session_id != request.session_id
        || decoded.runner_nonce.as_ref() != Some(&request.runner_nonce)
        || decoded.effect_contract_version != request_effect.contract_version
        || decoded.runner_launch_id != request_effect.launch_id
        || decoded.effect_id != request_effect.effect_id
        || decoded.idempotency_key != request_effect.idempotency_key
        || decoded.sprint_id != request_effect.sprint_id
        || decoded.task_id != request_effect.task_id
        || decoded.worker_id != request_effect.worker_id
        || decoded.policy_hash != request_effect.policy_hash
        || decoded.input_snapshot != request_effect.input_snapshot
        || decoded.command_request_digest != request_effect.request_digest
        || decoded.transport_commitment_digest != request_effect.transport_commitment_digest
        || decoded.capture_id != acquired.capture_id
        || decoded.capture_intent_digest != acquired.intent_digest
        || decoded.capture_acquired_anchor_digest != acquired.acquired_anchor_digest
        || decoded.capture_acquired_store_head != acquired.store_head
        || decoded.capture_dispatch_claim_id != acquired.dispatch_claim_id
        || decoded.capture_private_state_digest != acquired.private_state_digest
        || decoded.capture_max_aggregate_output_bytes != acquired.max_aggregate_output_bytes
    {
        return Err(invalid(
            "contained v12 launch binding differs from exact request, effect, policy, grant, or acquired capture authority",
        ));
    }
    if decoded.backend_id.trim().is_empty()
        || decoded.backend_id.len() > 128
        || decoded.backend_id.chars().any(char::is_control)
        || decoded.closed_exec_descriptors != [0, 1, 2]
    {
        return Err(invalid(
            "contained v12 launch backend identity or child descriptor closure is malformed",
        ));
    }
    let command_domain_binding = CommandDomainCleanupBinding::try_new(
        request.session_id.clone(),
        effect.effect_id.clone(),
        effect.request_digest.clone(),
    )
    .map_err(|error| invalid(error.to_string()))?;
    Ok(ValidatedCommandCaptureLaunchBindingV12 {
        request,
        launch_intended_store_head: launch_intended_store_head.clone(),
        canonical_bytes_digest: Digest::sha256(bytes),
        launch_digest: decoded.launch_digest,
        preflight_digest: decoded.preflight_digest,
        backend: WireCommandBackendIdentity {
            command_domain_backend: decoded.command_domain_backend,
            backend_id: decoded.backend_id,
            implementation_digest: decoded.backend_implementation_digest,
        },
        command_domain_binding,
        closed_exec_descriptors: decoded.closed_exec_descriptors,
    })
}

include!("contracts/evidence.rs");
include!("contracts/responses.rs");
