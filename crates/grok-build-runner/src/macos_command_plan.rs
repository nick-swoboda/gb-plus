//! Canonical, non-admissible production command plan for the future macOS helper.
//!
//! This module closes the lossy handoff between the role-sealed runner command
//! envelope and the dedicated-identity helper contracts. It intentionally has
//! no XPC transport, service-authority mint, process creation, held-child
//! release, credential operation, Seatbelt call, signal operation, or cleanup
//! effect. A validated plan is complete binding data and nothing more.

#![allow(
    dead_code,
    missing_docs,
    reason = "Gate-1 command-plan contract is intentionally unwired until the signed native helper exists"
)]

use std::collections::BTreeMap;
use std::fmt::{self, Display, Formatter};

use grok_build_core::{
    CONTRACT_VERSION, CompiledExecutionPolicy, Digest, ExecutionNetwork, ExecutionOrigin,
    ExecutionPolicy, IssuedWorkspaceGrant, SPRINT_AUTHORITY_CONTRACT_VERSION_V2, SprintSpec,
    SprintSpecV2, TaskGraphV2, WorkspaceGrant,
};
use serde::{Deserialize, Serialize};

use crate::macos_helper_journal::MacosHelperJournalReference;
use crate::macos_helper_protocol::{
    MACOS_EXECUTION_IDENTITY_COUNT, MACOS_HELPER_PROTOCOL_VERSION, MacosAssignedIdentity,
    MacosExecutionIdentityRecord, MacosHelperLaunchRequest, MacosHelperNetwork, MacosHelperSession,
    MacosIdentityPoolObservation,
};
use crate::wire::{CommandEffectAuthorityV1, RunnerRequest, RunnerRole, sprint_spec_digest};
use crate::wire_v13::{CommandEffectAuthorityV13, sprint_spec_digest_v2};

pub(crate) const MACOS_PRODUCTION_COMMAND_PLAN_SCHEMA_VERSION: u32 = 1;
pub(crate) const MACOS_PRODUCTION_COMMAND_PLAN_SCHEMA_VERSION_V2: u32 = 2;
pub(crate) const MACOS_SERVICE_COMMAND_JOURNAL_AUTHORITY_VERSION: u32 = 1;
pub(crate) const MACOS_SERVICE_COMMAND_JOURNAL_FORMAT_VERSION: u32 = 1;
pub(crate) const MAX_MACOS_PRODUCTION_COMMAND_PLAN_BYTES: usize = 512 * 1024;

const COMMAND_PLAN_DOMAIN: &[u8] = b"grok-build/macos-production-command-plan/v1\0";
const COMMAND_PLAN_DOMAIN_V2: &[u8] = b"grok-build/macos-production-command-plan/v2\0";
const HELPER_JOURNAL_REFERENCE_DOMAIN: &[u8] = b"grok-build/macos-helper-journal-reference/v1\0";
const MAX_HELPER_JOURNAL_REFERENCE_BYTES: usize = 4 * 1024;
const PRIVATE_DIRECTORY_MODE: u32 = 0o700;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum MacosProductionCommandPlanError {
    Invalid(String),
    Encode(String),
    Decode(String),
    NonCanonical,
    TooLarge { actual: usize },
}

impl Display for MacosProductionCommandPlanError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Invalid(message) => formatter.write_str(message),
            Self::Encode(message) => {
                write!(formatter, "cannot encode macOS command plan: {message}")
            }
            Self::Decode(message) => {
                write!(formatter, "cannot decode macOS command plan: {message}")
            }
            Self::NonCanonical => formatter.write_str("macOS command plan is not canonical"),
            Self::TooLarge { actual } => write!(
                formatter,
                "macOS command plan is {actual} bytes; limit is {MAX_MACOS_PRODUCTION_COMMAND_PLAN_BYTES}"
            ),
        }
    }
}

impl std::error::Error for MacosProductionCommandPlanError {}

fn invalid(message: impl Into<String>) -> MacosProductionCommandPlanError {
    MacosProductionCommandPlanError::Invalid(message.into())
}

/// Path-independent identity for one retained service object.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct MacosJournalObjectIdentityV1 {
    pub(crate) device_id: u64,
    pub(crate) inode: u64,
}

impl MacosJournalObjectIdentityV1 {
    pub(crate) fn validate(self, field: &str) -> Result<(), MacosProductionCommandPlanError> {
        if self.device_id == 0 || self.inode == 0 {
            return Err(invalid(format!("{field} identity is zero")));
        }
        Ok(())
    }
}

/// Cloneable identity data expected by the non-cloneable native-service mint.
///
/// Constructing this value never opens a store and grants no journal, launch,
/// release, or cleanup authority. The service journal module independently
/// compares every field to retained descriptors before it can commit a plan.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct MacosProductionServiceJournalBindingV1 {
    authority_version: u32,
    journal_format_version: u32,
    helper_protocol_version: u32,
    helper_policy_version: u32,
    authenticated_helper_binary_digest: Digest,
    helper_requirement_digest: Digest,
    authenticated_client_binary_digest: Digest,
    client_requirement_digest: Digest,
    pool_record_digest: Digest,
    service_state_root_identity: MacosJournalObjectIdentityV1,
    singleton_journal_root_identity: MacosJournalObjectIdentityV1,
    helper_journal_reference_digest: Digest,
    service_owner_uid: u32,
    service_state_mode: u32,
    singleton_journal_mode: u32,
}

#[allow(
    clippy::too_many_arguments,
    reason = "service identity binding intentionally lists every independently authenticated field"
)]
impl MacosProductionServiceJournalBindingV1 {
    pub(crate) fn try_new(
        session: &MacosHelperSession,
        service_state_root_identity: MacosJournalObjectIdentityV1,
        singleton_journal_root_identity: MacosJournalObjectIdentityV1,
        helper_journal_reference_digest: Digest,
        service_owner_uid: u32,
        service_state_mode: u32,
        singleton_journal_mode: u32,
    ) -> Result<Self, MacosProductionCommandPlanError> {
        session
            .validate()
            .map_err(|error| invalid(format!("helper session failed: {error}")))?;
        let binding = Self {
            authority_version: MACOS_SERVICE_COMMAND_JOURNAL_AUTHORITY_VERSION,
            journal_format_version: MACOS_SERVICE_COMMAND_JOURNAL_FORMAT_VERSION,
            helper_protocol_version: session.protocol_version,
            helper_policy_version: session.policy_version,
            authenticated_helper_binary_digest: session.helper_binary_digest.clone(),
            helper_requirement_digest: session.helper_requirement_digest.clone(),
            authenticated_client_binary_digest: session.client_binary_digest.clone(),
            client_requirement_digest: session.client_requirement_digest.clone(),
            pool_record_digest: session.pool_record_digest.clone(),
            service_state_root_identity,
            singleton_journal_root_identity,
            helper_journal_reference_digest,
            service_owner_uid,
            service_state_mode,
            singleton_journal_mode,
        };
        binding.validate()?;
        Ok(binding)
    }

    pub(crate) fn validate(&self) -> Result<(), MacosProductionCommandPlanError> {
        self.service_state_root_identity
            .validate("service-state root")?;
        self.singleton_journal_root_identity
            .validate("singleton command-journal root")?;
        if self.authority_version != MACOS_SERVICE_COMMAND_JOURNAL_AUTHORITY_VERSION
            || self.journal_format_version != MACOS_SERVICE_COMMAND_JOURNAL_FORMAT_VERSION
            || self.helper_protocol_version != MACOS_HELPER_PROTOCOL_VERSION
            || self.helper_policy_version == 0
            || self.service_state_root_identity == self.singleton_journal_root_identity
            || self.service_state_mode != PRIVATE_DIRECTORY_MODE
            || self.singleton_journal_mode != PRIVATE_DIRECTORY_MODE
        {
            return Err(invalid(
                "macOS service authority version, helper version, retained roots, or private modes differ",
            ));
        }
        Ok(())
    }

    pub(crate) const fn service_state_root_identity(&self) -> MacosJournalObjectIdentityV1 {
        self.service_state_root_identity
    }

    pub(crate) const fn singleton_journal_root_identity(&self) -> MacosJournalObjectIdentityV1 {
        self.singleton_journal_root_identity
    }

    pub(crate) const fn service_owner_uid(&self) -> u32 {
        self.service_owner_uid
    }

    pub(crate) const fn service_state_mode(&self) -> u32 {
        self.service_state_mode
    }

    pub(crate) const fn singleton_journal_mode(&self) -> u32 {
        self.singleton_journal_mode
    }

    pub(crate) const fn helper_journal_reference_digest(&self) -> &Digest {
        &self.helper_journal_reference_digest
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct MacosWorkspaceIdentityV1 {
    canonical_root: String,
    device_id: u64,
    inode: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct MacosTrustedSprintAuthorityV1 {
    sprint_spec: SprintSpec,
    sprint_spec_digest: Digest,
    workspace_grant: WorkspaceGrant,
    workspace_identity: MacosWorkspaceIdentityV1,
    execution_policy: ExecutionPolicy,
}

impl MacosTrustedSprintAuthorityV1 {
    fn from_trusted(
        sprint: &SprintSpec,
        grant: &IssuedWorkspaceGrant,
        policy: &CompiledExecutionPolicy,
    ) -> Result<Self, MacosProductionCommandPlanError> {
        sprint
            .validate()
            .map_err(|error| invalid(format!("sprint contract failed: {error}")))?;
        grant
            .validate_integrity()
            .map_err(|error| invalid(format!("workspace grant integrity failed: {error}")))?;
        policy
            .validate_integrity(grant)
            .map_err(|error| invalid(format!("compiled policy integrity failed: {error}")))?;
        if sprint.workspace_grant != *grant.contract() {
            return Err(invalid(
                "sprint workspace grant differs from the independently restored grant",
            ));
        }
        if sprint.provider.execution_origin != ExecutionOrigin::HostIsolated {
            return Err(invalid(
                "native macOS command plan requires a host-isolated provider profile",
            ));
        }
        let canonical_root = grant
            .identity()
            .canonical_root()
            .to_str()
            .ok_or_else(|| invalid("workspace root is not normalized UTF-8"))?
            .to_owned();
        let sprint_spec_digest = shared_sprint_digest(sprint)?;
        let value = Self {
            sprint_spec: sprint.clone(),
            sprint_spec_digest,
            workspace_grant: grant.contract().clone(),
            workspace_identity: MacosWorkspaceIdentityV1 {
                canonical_root,
                device_id: grant.identity().device_id(),
                inode: grant.identity().inode(),
            },
            execution_policy: policy.contract().clone(),
        };
        value.validate_retained()?;
        Ok(value)
    }

    fn validate_retained(&self) -> Result<(), MacosProductionCommandPlanError> {
        self.sprint_spec
            .validate()
            .map_err(|error| invalid(format!("retained sprint failed: {error}")))?;
        self.workspace_grant
            .validate()
            .map_err(|error| invalid(format!("retained grant failed: {error}")))?;
        self.execution_policy
            .validate_against(&self.workspace_grant)
            .map_err(|error| invalid(format!("retained policy failed: {error}")))?;
        if self.sprint_spec.workspace_grant != self.workspace_grant
            || self.sprint_spec.provider.execution_origin != ExecutionOrigin::HostIsolated
            || self.sprint_spec_digest != shared_sprint_digest(&self.sprint_spec)?
            || self.workspace_identity.device_id == 0
            || self.workspace_identity.inode == 0
            || self.workspace_identity.canonical_root
                != self.workspace_grant.canonical_root.to_string_lossy()
            || self.execution_policy.computed_hash().map_err(|error| {
                invalid(format!("retained policy hash computation failed: {error}"))
            })? != self.execution_policy.policy_hash
        {
            return Err(invalid(
                "retained sprint, grant, workspace identity, or compiled policy is crossed",
            ));
        }
        Ok(())
    }
}

/// Complete current sprint authority retained by a V2 macOS command plan.
///
/// The five digests are deliberately independent fields. The core spec,
/// complete graph envelope, graph payload, repair reserve, and runner-owned
/// sprint domain are distinct identities and may never substitute for one
/// another merely because they were derived from the same pair.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct MacosTrustedSprintAuthorityV2 {
    sprint_authority_version: u32,
    sprint_spec: SprintSpecV2,
    task_graph: TaskGraphV2,
    core_sprint_spec_digest: Digest,
    core_task_graph_digest: Digest,
    core_task_graph_payload_digest: Digest,
    core_repair_slot_reserve_digest: Digest,
    runner_sprint_spec_digest_v2: Digest,
    workspace_grant: WorkspaceGrant,
    workspace_identity: MacosWorkspaceIdentityV1,
    execution_policy: ExecutionPolicy,
}

impl MacosTrustedSprintAuthorityV2 {
    fn from_trusted(
        sprint: &SprintSpecV2,
        graph: &TaskGraphV2,
        grant: &IssuedWorkspaceGrant,
        policy: &CompiledExecutionPolicy,
    ) -> Result<Self, MacosProductionCommandPlanError> {
        graph
            .validate_for_sprint(sprint)
            .map_err(|error| invalid(format!("current sprint/graph pair failed: {error}")))?;
        grant
            .validate_integrity()
            .map_err(|error| invalid(format!("workspace grant integrity failed: {error}")))?;
        policy
            .validate_integrity(grant)
            .map_err(|error| invalid(format!("compiled policy integrity failed: {error}")))?;
        if sprint.workspace_grant != *grant.contract() {
            return Err(invalid(
                "current sprint workspace grant differs from the independently restored grant",
            ));
        }
        if sprint.provider.execution_origin != ExecutionOrigin::HostIsolated {
            return Err(invalid(
                "native macOS command plan requires a host-isolated provider profile",
            ));
        }
        let canonical_root = grant
            .identity()
            .canonical_root()
            .to_str()
            .ok_or_else(|| invalid("workspace root is not normalized UTF-8"))?
            .to_owned();
        let value = Self {
            sprint_authority_version: SPRINT_AUTHORITY_CONTRACT_VERSION_V2,
            sprint_spec: sprint.clone(),
            task_graph: graph.clone(),
            core_sprint_spec_digest: sprint
                .canonical_digest()
                .map_err(|error| invalid(format!("current sprint digest failed: {error}")))?,
            core_task_graph_digest: graph
                .canonical_digest_for_sprint(sprint)
                .map_err(|error| invalid(format!("current graph digest failed: {error}")))?,
            core_task_graph_payload_digest: graph
                .payload_digest()
                .map_err(|error| invalid(format!("current graph payload failed: {error}")))?,
            core_repair_slot_reserve_digest: graph
                .computed_repair_slot_reserve_digest()
                .map_err(|error| invalid(format!("current repair reserve failed: {error}")))?,
            runner_sprint_spec_digest_v2: sprint_spec_digest_v2(sprint, graph).map_err(
                |error| invalid(format!("runner V2 sprint-spec digest failed: {error}")),
            )?,
            workspace_grant: grant.contract().clone(),
            workspace_identity: MacosWorkspaceIdentityV1 {
                canonical_root,
                device_id: grant.identity().device_id(),
                inode: grant.identity().inode(),
            },
            execution_policy: policy.contract().clone(),
        };
        value.validate_retained()?;
        Ok(value)
    }

    fn validate_retained(&self) -> Result<(), MacosProductionCommandPlanError> {
        self.task_graph
            .validate_for_sprint(&self.sprint_spec)
            .map_err(|error| invalid(format!("retained current sprint/graph failed: {error}")))?;
        self.workspace_grant
            .validate()
            .map_err(|error| invalid(format!("retained grant failed: {error}")))?;
        self.execution_policy
            .validate_against(&self.workspace_grant)
            .map_err(|error| invalid(format!("retained policy failed: {error}")))?;

        let expected_core_sprint = self
            .sprint_spec
            .canonical_digest()
            .map_err(|error| invalid(format!("retained current sprint digest failed: {error}")))?;
        let expected_graph = self
            .task_graph
            .canonical_digest_for_sprint(&self.sprint_spec)
            .map_err(|error| invalid(format!("retained current graph digest failed: {error}")))?;
        let expected_payload = self
            .task_graph
            .payload_digest()
            .map_err(|error| invalid(format!("retained current graph payload failed: {error}")))?;
        let expected_reserve = self
            .task_graph
            .computed_repair_slot_reserve_digest()
            .map_err(|error| invalid(format!("retained current repair reserve failed: {error}")))?;
        let expected_runner_sprint = sprint_spec_digest_v2(&self.sprint_spec, &self.task_graph)
            .map_err(|error| {
                invalid(format!(
                    "retained runner V2 sprint-spec digest failed: {error}"
                ))
            })?;
        let expected_policy_hash = self.execution_policy.computed_hash().map_err(|error| {
            invalid(format!("retained policy hash computation failed: {error}"))
        })?;

        if self.sprint_authority_version != SPRINT_AUTHORITY_CONTRACT_VERSION_V2
            || self.sprint_spec.sprint_authority_version != SPRINT_AUTHORITY_CONTRACT_VERSION_V2
            || self.task_graph.sprint_authority_version != SPRINT_AUTHORITY_CONTRACT_VERSION_V2
            || self.sprint_spec.workspace_grant != self.workspace_grant
            || self.sprint_spec.provider.execution_origin != ExecutionOrigin::HostIsolated
            || self.core_sprint_spec_digest != expected_core_sprint
            || self.core_task_graph_digest != expected_graph
            || self.core_task_graph_payload_digest != expected_payload
            || self.core_repair_slot_reserve_digest != expected_reserve
            || self.runner_sprint_spec_digest_v2 != expected_runner_sprint
            || self.workspace_identity.device_id == 0
            || self.workspace_identity.inode == 0
            || self.workspace_identity.canonical_root
                != self.workspace_grant.canonical_root.to_string_lossy()
            || expected_policy_hash != self.execution_policy.policy_hash
        {
            return Err(invalid(
                "retained current sprint, graph, digest, grant, workspace identity, or compiled policy is crossed",
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct MacosIdentityPoolContractV1 {
    records: Vec<MacosExecutionIdentityRecord>,
    pool_record_digest: Digest,
}

impl MacosIdentityPoolContractV1 {
    fn from_observation(pool: &MacosIdentityPoolObservation) -> Self {
        Self {
            records: pool.records.clone(),
            pool_record_digest: pool.pool_record_digest.clone(),
        }
    }

    fn observation(&self) -> MacosIdentityPoolObservation {
        MacosIdentityPoolObservation {
            records: self.records.clone(),
            pool_record_digest: self.pool_record_digest.clone(),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct MacosNativeCommandAuthorityV1 {
    helper_session: MacosHelperSession,
    helper_request: MacosHelperLaunchRequest,
    identity_pool: MacosIdentityPoolContractV1,
    assigned_identity: MacosAssignedIdentity,
    helper_journal_reference_bytes: Vec<u8>,
    helper_journal_reference_digest: Digest,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum MacosHeldRequirementV1 {
    ExactSignedHelperSetupReadbackWhileChildCannotRunProjectCode,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum MacosReleaseRequirementV1 {
    DisabledUntilLiveCoreClaimAndSignedNativeHoldProof,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum MacosCleanupRequirementV1 {
    ServiceOwnedUidDomainReconciliation,
    PersistCleaningBeforeSignal,
    TwoStableCreationSealedEmptyObservations,
    ReleaseIdentityOnlyAfterDurableCleaned,
}

const REQUIRED_CLEANUP: &[MacosCleanupRequirementV1] = &[
    MacosCleanupRequirementV1::ServiceOwnedUidDomainReconciliation,
    MacosCleanupRequirementV1::PersistCleaningBeforeSignal,
    MacosCleanupRequirementV1::TwoStableCreationSealedEmptyObservations,
    MacosCleanupRequirementV1::ReleaseIdentityOnlyAfterDurableCleaned,
];

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct MacosProductionSafetyBoundaryV1 {
    held_requirement: MacosHeldRequirementV1,
    release_requirement: MacosReleaseRequirementV1,
    cleanup_requirements_in_order: Vec<MacosCleanupRequirementV1>,
    permits_execution: bool,
    permits_release: bool,
}

/// Complete canonical native command plan. Fields are intentionally private.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct MacosProductionCommandPlanV1 {
    schema_version: u32,
    contract_version: u32,
    trusted_sprint_authority: MacosTrustedSprintAuthorityV1,
    command_effect_authority: CommandEffectAuthorityV1,
    native_command_authority: MacosNativeCommandAuthorityV1,
    service_journal_binding: MacosProductionServiceJournalBindingV1,
    safety_boundary: MacosProductionSafetyBoundaryV1,
}

/// Canonical, internally validated plan plus its exact domain-separated bytes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ValidatedMacosProductionCommandPlanV1 {
    plan: MacosProductionCommandPlanV1,
    canonical_bytes: Vec<u8>,
    plan_digest: Digest,
}

impl MacosProductionCommandPlanV1 {
    #[allow(
        clippy::too_many_arguments,
        reason = "the lossless bridge intentionally receives each independent authority source"
    )]
    pub(crate) fn build(
        sprint: &SprintSpec,
        command_effect_authority: CommandEffectAuthorityV1,
        grant: &IssuedWorkspaceGrant,
        policy: &CompiledExecutionPolicy,
        helper_session: MacosHelperSession,
        helper_request: MacosHelperLaunchRequest,
        identity_pool: &MacosIdentityPoolObservation,
        assigned_identity: MacosAssignedIdentity,
        helper_journal_reference: &MacosHelperJournalReference,
        service_journal_binding: MacosProductionServiceJournalBindingV1,
    ) -> Result<ValidatedMacosProductionCommandPlanV1, MacosProductionCommandPlanError> {
        let helper_journal_reference_bytes = helper_journal_reference
            .canonical_bytes()
            .map_err(|error| invalid(format!("helper journal reference failed: {error}")))?;
        if helper_journal_reference_bytes.len() > MAX_HELPER_JOURNAL_REFERENCE_BYTES {
            return Err(invalid("helper journal reference exceeds its hard bound"));
        }
        let helper_journal_reference_digest =
            digest_helper_journal_reference(&helper_journal_reference_bytes);
        let plan = Self {
            schema_version: MACOS_PRODUCTION_COMMAND_PLAN_SCHEMA_VERSION,
            contract_version: CONTRACT_VERSION,
            trusted_sprint_authority: MacosTrustedSprintAuthorityV1::from_trusted(
                sprint, grant, policy,
            )?,
            command_effect_authority,
            native_command_authority: MacosNativeCommandAuthorityV1 {
                helper_session,
                helper_request,
                identity_pool: MacosIdentityPoolContractV1::from_observation(identity_pool),
                assigned_identity,
                helper_journal_reference_bytes,
                helper_journal_reference_digest,
            },
            service_journal_binding,
            safety_boundary: MacosProductionSafetyBoundaryV1 {
                held_requirement:
                    MacosHeldRequirementV1::ExactSignedHelperSetupReadbackWhileChildCannotRunProjectCode,
                release_requirement:
                    MacosReleaseRequirementV1::DisabledUntilLiveCoreClaimAndSignedNativeHoldProof,
                cleanup_requirements_in_order: REQUIRED_CLEANUP.to_vec(),
                permits_execution: false,
                permits_release: false,
            },
        };
        ValidatedMacosProductionCommandPlanV1::from_plan(plan)
    }

    #[allow(
        clippy::too_many_lines,
        reason = "one validator keeps every lossless cross-boundary join adjacent for audit"
    )]
    fn validate(&self) -> Result<(), MacosProductionCommandPlanError> {
        if self.schema_version != MACOS_PRODUCTION_COMMAND_PLAN_SCHEMA_VERSION
            || self.contract_version != CONTRACT_VERSION
        {
            return Err(invalid("macOS command-plan version differs"));
        }
        self.trusted_sprint_authority.validate_retained()?;
        self.command_effect_authority
            .validate_integrity()
            .map_err(|error| invalid(format!("command-effect authority failed: {error}")))?;
        self.service_journal_binding.validate()?;
        let native = &self.native_command_authority;
        native
            .helper_session
            .validate()
            .map_err(|error| invalid(format!("helper session failed: {error}")))?;
        native
            .helper_request
            .validate_archived_session_binding(&native.helper_session)
            .map_err(|error| invalid(format!("helper request failed: {error}")))?;
        native
            .identity_pool
            .observation()
            .validate_for_session(&native.helper_session)
            .map_err(|error| invalid(format!("identity pool failed: {error}")))?;
        if native.identity_pool.records.len() != MACOS_EXECUTION_IDENTITY_COUNT
            || !native.identity_pool.records.iter().any(|record| {
                record.account_name == native.assigned_identity.account_name
                    && record.uid == native.assigned_identity.uid
                    && record.gid == native.assigned_identity.gid
                    && record.record_digest == native.assigned_identity.account_record_digest
            })
        {
            return Err(invalid(
                "assigned dedicated identity is not an exact member of the fixed pool",
            ));
        }
        if native.helper_journal_reference_bytes.is_empty()
            || native.helper_journal_reference_bytes.len() > MAX_HELPER_JOURNAL_REFERENCE_BYTES
            || MacosHelperJournalReference::decode_canonical(&native.helper_journal_reference_bytes)
                .map_err(|error| invalid(format!("helper journal reference failed: {error}")))?
                .pool_record_digest()
                != &native.identity_pool.pool_record_digest
            || native.helper_journal_reference_digest
                != digest_helper_journal_reference(&native.helper_journal_reference_bytes)
        {
            return Err(invalid(
                "helper journal reference is noncanonical, oversized, or pool-crossed",
            ));
        }

        let trusted = &self.trusted_sprint_authority;
        let authority = &self.command_effect_authority;
        let envelope = authority.envelope();
        let effect = envelope
            .effect
            .as_ref()
            .ok_or_else(|| invalid("command plan requires durable effect context"))?;
        let command = match &envelope.request {
            RunnerRequest::WorkerRunCommand { command, .. }
                if authority.role() == RunnerRole::Worker =>
            {
                command
            }
            RunnerRequest::FinalVerifierRunCommand { command, .. }
                if authority.role() == RunnerRole::FinalVerifier =>
            {
                command
            }
            _ => {
                return Err(invalid(
                    "command plan retained a role-crossed command request",
                ));
            }
        };
        if trusted.sprint_spec.sprint_id != effect.sprint_id
            || trusted.sprint_spec.workspace_grant.grant_hash != *authority.grant_hash()
            || trusted.workspace_grant.grant_hash != *authority.grant_hash()
            || trusted.execution_policy.grant_hash != *authority.grant_hash()
            || trusted.execution_policy.policy_hash != effect.policy_hash
            || !trusted.workspace_grant.permissions.execute_commands
        {
            return Err(invalid(
                "sprint, workspace grant, compiled policy, or command effect authority differs",
            ));
        }

        let request = &native.helper_request;
        let preparation = &request.preparation;
        if preparation.sprint_id != effect.sprint_id
            || preparation.launch_id != effect.launch_id
            || preparation.runner_session_id != envelope.session_id
            || preparation.input_snapshot != effect.input_snapshot
            || request.runner_session_id != envelope.session_id
            || request.effect_id != effect.effect_id
            || request.workspace_grant_hash != *authority.grant_hash()
            || request.execution_policy_hash != effect.policy_hash
            || native.helper_session.workspace_grant_hash != *authority.grant_hash()
            || native.helper_session.execution_policy_hash != effect.policy_hash
        {
            return Err(invalid(
                "helper request lost launch, session, effect, snapshot, grant, or policy authority",
            ));
        }
        if let Some(lease) = &effect.worker_lease {
            lease
                .validate_assignment(
                    &trusted.sprint_spec.sprint_id,
                    &lease.task_id,
                    &lease.worker_id,
                )
                .map_err(|error| invalid(format!("worker lease failed: {error}")))?;
        }

        let mut expected_argv = Vec::with_capacity(command.arguments.len() + 1);
        expected_argv.push(command.program.clone());
        expected_argv.extend(command.arguments.iter().cloned());
        let expected_working_directory = if command.working_directory.is_empty() {
            "."
        } else {
            command.working_directory.as_str()
        };
        let expected_environment = trusted
            .execution_policy
            .environment
            .iter()
            .map(|entry| (entry.name.clone(), entry.value.clone()))
            .collect::<BTreeMap<_, _>>();
        let expected_network = match trusted.execution_policy.network {
            ExecutionNetwork::None => MacosHelperNetwork::Denied,
            ExecutionNetwork::FullForAction => MacosHelperNetwork::Allowed,
        };
        let limits = trusted.execution_policy.resource_limits;
        if request.argv != expected_argv
            || request.relative_working_directory != expected_working_directory
            || request.environment != expected_environment
            || request.command_network != expected_network
            || request.max_output_bytes != limits.max_output_bytes
            || request.max_processes != limits.max_processes
            || request.max_memory_bytes != limits.max_memory_bytes
        {
            return Err(invalid(
                "helper argv, working directory, environment, network, or limits differ from the exact compiled command",
            ));
        }

        let service = &self.service_journal_binding;
        if service.helper_protocol_version != native.helper_session.protocol_version
            || service.helper_policy_version != native.helper_session.policy_version
            || service.authenticated_helper_binary_digest
                != native.helper_session.helper_binary_digest
            || service.helper_requirement_digest != native.helper_session.helper_requirement_digest
            || service.authenticated_client_binary_digest
                != native.helper_session.client_binary_digest
            || service.client_requirement_digest != native.helper_session.client_requirement_digest
            || service.pool_record_digest != native.identity_pool.pool_record_digest
            || service.helper_journal_reference_digest != native.helper_journal_reference_digest
        {
            return Err(invalid(
                "authenticated helper service, client, pool, or store identity differs from the plan",
            ));
        }
        if self.safety_boundary.held_requirement
            != MacosHeldRequirementV1::ExactSignedHelperSetupReadbackWhileChildCannotRunProjectCode
            || self.safety_boundary.release_requirement
                != MacosReleaseRequirementV1::DisabledUntilLiveCoreClaimAndSignedNativeHoldProof
            || self.safety_boundary.cleanup_requirements_in_order != REQUIRED_CLEANUP
            || self.safety_boundary.permits_execution
            || self.safety_boundary.permits_release
        {
            return Err(invalid(
                "macOS plan weakens held setup, release, cleanup, or non-admissibility",
            ));
        }
        Ok(())
    }
}

impl ValidatedMacosProductionCommandPlanV1 {
    fn from_plan(
        plan: MacosProductionCommandPlanV1,
    ) -> Result<Self, MacosProductionCommandPlanError> {
        plan.validate()?;
        let json = serde_json::to_vec(&plan)
            .map_err(|error| MacosProductionCommandPlanError::Encode(error.to_string()))?;
        let mut canonical_bytes = Vec::with_capacity(COMMAND_PLAN_DOMAIN.len() + json.len());
        canonical_bytes.extend_from_slice(COMMAND_PLAN_DOMAIN);
        canonical_bytes.extend_from_slice(&json);
        if canonical_bytes.len() > MAX_MACOS_PRODUCTION_COMMAND_PLAN_BYTES {
            return Err(MacosProductionCommandPlanError::TooLarge {
                actual: canonical_bytes.len(),
            });
        }
        let plan_digest = Digest::sha256(&canonical_bytes);
        Ok(Self {
            plan,
            canonical_bytes,
            plan_digest,
        })
    }

    pub(crate) fn decode_exact(bytes: &[u8]) -> Result<Self, MacosProductionCommandPlanError> {
        if bytes.len() > MAX_MACOS_PRODUCTION_COMMAND_PLAN_BYTES {
            return Err(MacosProductionCommandPlanError::TooLarge {
                actual: bytes.len(),
            });
        }
        let json = bytes
            .strip_prefix(COMMAND_PLAN_DOMAIN)
            .ok_or_else(|| MacosProductionCommandPlanError::Decode("domain differs".into()))?;
        let plan: MacosProductionCommandPlanV1 = serde_json::from_slice(json)
            .map_err(|error| MacosProductionCommandPlanError::Decode(error.to_string()))?;
        let validated = Self::from_plan(plan)?;
        if validated.canonical_bytes != bytes {
            return Err(MacosProductionCommandPlanError::NonCanonical);
        }
        Ok(validated)
    }

    pub(crate) fn canonical_bytes(&self) -> &[u8] {
        &self.canonical_bytes
    }

    pub(crate) const fn plan_digest(&self) -> &Digest {
        &self.plan_digest
    }

    pub(crate) fn effect_id(&self) -> &str {
        &self
            .plan
            .command_effect_authority
            .envelope()
            .effect
            .as_ref()
            .expect("validated command plans retain an effect")
            .effect_id
    }

    pub(crate) const fn service_journal_binding(&self) -> &MacosProductionServiceJournalBindingV1 {
        &self.plan.service_journal_binding
    }

    pub(crate) const fn helper_session(&self) -> &MacosHelperSession {
        &self.plan.native_command_authority.helper_session
    }

    pub(crate) const fn helper_request(&self) -> &MacosHelperLaunchRequest {
        &self.plan.native_command_authority.helper_request
    }

    pub(crate) const fn assigned_identity(&self) -> &MacosAssignedIdentity {
        &self.plan.native_command_authority.assigned_identity
    }

    pub(crate) fn helper_journal_reference_bytes(&self) -> &[u8] {
        &self
            .plan
            .native_command_authority
            .helper_journal_reference_bytes
    }

    pub(crate) const fn helper_journal_reference_digest(&self) -> &Digest {
        &self
            .plan
            .native_command_authority
            .helper_journal_reference_digest
    }

    pub(crate) const fn command_effect_authority(&self) -> &CommandEffectAuthorityV1 {
        &self.plan.command_effect_authority
    }

    pub(crate) const fn permits_execution() -> bool {
        false
    }

    pub(crate) const fn permits_release() -> bool {
        false
    }
}

/// Complete canonical current-authority native command plan.
///
/// This type is deliberately parallel to V1. It cannot be constructed from a
/// legacy sprint or command authority, and no service or native backend admits
/// it yet.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct MacosProductionCommandPlanV2 {
    schema_version: u32,
    sprint_authority_version: u32,
    contract_version: u32,
    trusted_sprint_authority: MacosTrustedSprintAuthorityV2,
    command_effect_authority: CommandEffectAuthorityV13,
    native_command_authority: MacosNativeCommandAuthorityV1,
    service_journal_binding: MacosProductionServiceJournalBindingV1,
    safety_boundary: MacosProductionSafetyBoundaryV1,
}

/// Canonical, internally validated V2 plan plus exact domain-separated bytes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ValidatedMacosProductionCommandPlanV2 {
    plan: MacosProductionCommandPlanV2,
    canonical_bytes: Vec<u8>,
    plan_digest: Digest,
}

impl MacosProductionCommandPlanV2 {
    #[allow(
        clippy::too_many_arguments,
        reason = "the V2 lossless bridge intentionally receives each independent authority source"
    )]
    pub(crate) fn build(
        sprint: &SprintSpecV2,
        task_graph: &TaskGraphV2,
        command_effect_authority: CommandEffectAuthorityV13,
        grant: &IssuedWorkspaceGrant,
        policy: &CompiledExecutionPolicy,
        helper_session: MacosHelperSession,
        helper_request: MacosHelperLaunchRequest,
        identity_pool: &MacosIdentityPoolObservation,
        assigned_identity: MacosAssignedIdentity,
        helper_journal_reference: &MacosHelperJournalReference,
        service_journal_binding: MacosProductionServiceJournalBindingV1,
    ) -> Result<ValidatedMacosProductionCommandPlanV2, MacosProductionCommandPlanError> {
        let helper_journal_reference_bytes = helper_journal_reference
            .canonical_bytes()
            .map_err(|error| invalid(format!("helper journal reference failed: {error}")))?;
        if helper_journal_reference_bytes.len() > MAX_HELPER_JOURNAL_REFERENCE_BYTES {
            return Err(invalid("helper journal reference exceeds its hard bound"));
        }
        let helper_journal_reference_digest =
            digest_helper_journal_reference(&helper_journal_reference_bytes);
        let plan = Self {
            schema_version: MACOS_PRODUCTION_COMMAND_PLAN_SCHEMA_VERSION_V2,
            sprint_authority_version: SPRINT_AUTHORITY_CONTRACT_VERSION_V2,
            contract_version: CONTRACT_VERSION,
            trusted_sprint_authority: MacosTrustedSprintAuthorityV2::from_trusted(
                sprint, task_graph, grant, policy,
            )?,
            command_effect_authority,
            native_command_authority: MacosNativeCommandAuthorityV1 {
                helper_session,
                helper_request,
                identity_pool: MacosIdentityPoolContractV1::from_observation(identity_pool),
                assigned_identity,
                helper_journal_reference_bytes,
                helper_journal_reference_digest,
            },
            service_journal_binding,
            safety_boundary: MacosProductionSafetyBoundaryV1 {
                held_requirement:
                    MacosHeldRequirementV1::ExactSignedHelperSetupReadbackWhileChildCannotRunProjectCode,
                release_requirement:
                    MacosReleaseRequirementV1::DisabledUntilLiveCoreClaimAndSignedNativeHoldProof,
                cleanup_requirements_in_order: REQUIRED_CLEANUP.to_vec(),
                permits_execution: false,
                permits_release: false,
            },
        };
        ValidatedMacosProductionCommandPlanV2::from_plan(plan)
    }

    #[allow(
        clippy::too_many_lines,
        reason = "one V2 validator keeps every current authority and native identity join adjacent for audit"
    )]
    fn validate(&self) -> Result<(), MacosProductionCommandPlanError> {
        if self.schema_version != MACOS_PRODUCTION_COMMAND_PLAN_SCHEMA_VERSION_V2
            || self.sprint_authority_version != SPRINT_AUTHORITY_CONTRACT_VERSION_V2
            || self.contract_version != CONTRACT_VERSION
        {
            return Err(invalid("macOS V2 command-plan version differs"));
        }
        self.trusted_sprint_authority.validate_retained()?;
        self.command_effect_authority
            .validate_integrity()
            .map_err(|error| {
                invalid(format!("current command-effect authority failed: {error}"))
            })?;
        self.service_journal_binding.validate()?;

        let native = &self.native_command_authority;
        native
            .helper_session
            .validate()
            .map_err(|error| invalid(format!("helper session failed: {error}")))?;
        native
            .helper_request
            .validate_archived_session_binding(&native.helper_session)
            .map_err(|error| invalid(format!("helper request failed: {error}")))?;
        native
            .identity_pool
            .observation()
            .validate_for_session(&native.helper_session)
            .map_err(|error| invalid(format!("identity pool failed: {error}")))?;
        if native.identity_pool.records.len() != MACOS_EXECUTION_IDENTITY_COUNT
            || !native.identity_pool.records.iter().any(|record| {
                record.account_name == native.assigned_identity.account_name
                    && record.uid == native.assigned_identity.uid
                    && record.gid == native.assigned_identity.gid
                    && record.record_digest == native.assigned_identity.account_record_digest
            })
        {
            return Err(invalid(
                "assigned dedicated identity is not an exact member of the fixed pool",
            ));
        }
        if native.helper_journal_reference_bytes.is_empty()
            || native.helper_journal_reference_bytes.len() > MAX_HELPER_JOURNAL_REFERENCE_BYTES
            || MacosHelperJournalReference::decode_canonical(&native.helper_journal_reference_bytes)
                .map_err(|error| invalid(format!("helper journal reference failed: {error}")))?
                .pool_record_digest()
                != &native.identity_pool.pool_record_digest
            || native.helper_journal_reference_digest
                != digest_helper_journal_reference(&native.helper_journal_reference_bytes)
        {
            return Err(invalid(
                "helper journal reference is noncanonical, oversized, or pool-crossed",
            ));
        }

        let trusted = &self.trusted_sprint_authority;
        let authority = &self.command_effect_authority;
        let envelope = authority.envelope();
        let effect = authority.effect();
        let command = authority.command();
        if trusted.sprint_spec.sprint_id != effect.sprint_id
            || authority.sprint_spec() != &trusted.sprint_spec
            || authority.task_graph() != &trusted.task_graph
            || trusted.sprint_spec.workspace_grant.grant_hash != *authority.grant_hash()
            || trusted.workspace_grant.grant_hash != *authority.grant_hash()
            || trusted.execution_policy.grant_hash != *authority.grant_hash()
            || trusted.execution_policy.policy_hash != effect.policy_hash
            || !trusted.workspace_grant.permissions.execute_commands
        {
            return Err(invalid(
                "current sprint, workspace grant, compiled policy, or command effect authority differs",
            ));
        }

        let request = &native.helper_request;
        let preparation = &request.preparation;
        if preparation.sprint_id != effect.sprint_id
            || preparation.attempt_id != authority.attempt_id()
            || preparation.launch_id != effect.launch_id
            || preparation.runner_session_id != envelope.session_id
            || preparation.input_snapshot != effect.input_snapshot
            || request.runner_session_id != envelope.session_id
            || request.effect_id != effect.effect_id
            || request.workspace_grant_hash != *authority.grant_hash()
            || request.execution_policy_hash != effect.policy_hash
            || native.helper_session.workspace_grant_hash != *authority.grant_hash()
            || native.helper_session.execution_policy_hash != effect.policy_hash
        {
            return Err(invalid(
                "helper request lost launch, session, effect, snapshot, grant, or policy authority",
            ));
        }
        if let Some(lease) = &effect.worker_lease {
            lease
                .validate_assignment(
                    &trusted.sprint_spec.sprint_id,
                    &lease.task_id,
                    &lease.worker_id,
                )
                .map_err(|error| invalid(format!("worker lease failed: {error}")))?;
        }

        let mut expected_argv = Vec::with_capacity(command.arguments.len() + 1);
        expected_argv.push(command.program.clone());
        expected_argv.extend(command.arguments.iter().cloned());
        let expected_working_directory = if command.working_directory.is_empty() {
            "."
        } else {
            command.working_directory.as_str()
        };
        let expected_environment = trusted
            .execution_policy
            .environment
            .iter()
            .map(|entry| (entry.name.clone(), entry.value.clone()))
            .collect::<BTreeMap<_, _>>();
        let expected_network = match trusted.execution_policy.network {
            ExecutionNetwork::None => MacosHelperNetwork::Denied,
            ExecutionNetwork::FullForAction => MacosHelperNetwork::Allowed,
        };
        let limits = trusted.execution_policy.resource_limits;
        if request.argv != expected_argv
            || request.relative_working_directory != expected_working_directory
            || request.environment != expected_environment
            || request.command_network != expected_network
            || request.max_output_bytes != limits.max_output_bytes
            || request.max_processes != limits.max_processes
            || request.max_memory_bytes != limits.max_memory_bytes
        {
            return Err(invalid(
                "helper argv, working directory, environment, network, or limits differ from the exact compiled command",
            ));
        }
        if preparation.claimed_at_unix_ms < native.helper_session.authenticated_at_unix_ms {
            return Err(invalid(
                "helper preparation claim predates the authenticated controller session",
            ));
        }
        let controller_interval_ms = request
            .deadline_unix_ms
            .checked_sub(preparation.claimed_at_unix_ms)
            .ok_or_else(|| invalid("helper deadline precedes its controller claim"))?;
        if controller_interval_ms == 0 || controller_interval_ms > limits.wall_time_ms {
            return Err(invalid(
                "helper controller deadline interval exceeds the exact compiled wall-time limit",
            ));
        }

        let service = &self.service_journal_binding;
        if service.helper_protocol_version != native.helper_session.protocol_version
            || service.helper_policy_version != native.helper_session.policy_version
            || service.authenticated_helper_binary_digest
                != native.helper_session.helper_binary_digest
            || service.helper_requirement_digest != native.helper_session.helper_requirement_digest
            || service.authenticated_client_binary_digest
                != native.helper_session.client_binary_digest
            || service.client_requirement_digest != native.helper_session.client_requirement_digest
            || service.pool_record_digest != native.identity_pool.pool_record_digest
            || service.helper_journal_reference_digest != native.helper_journal_reference_digest
        {
            return Err(invalid(
                "authenticated helper service, client, pool, or store identity differs from the V2 plan",
            ));
        }
        if self.safety_boundary.held_requirement
            != MacosHeldRequirementV1::ExactSignedHelperSetupReadbackWhileChildCannotRunProjectCode
            || self.safety_boundary.release_requirement
                != MacosReleaseRequirementV1::DisabledUntilLiveCoreClaimAndSignedNativeHoldProof
            || self.safety_boundary.cleanup_requirements_in_order != REQUIRED_CLEANUP
            || self.safety_boundary.permits_execution
            || self.safety_boundary.permits_release
        {
            return Err(invalid(
                "macOS V2 plan weakens held setup, release, cleanup, or non-admissibility",
            ));
        }
        Ok(())
    }
}

impl ValidatedMacosProductionCommandPlanV2 {
    fn from_plan(
        plan: MacosProductionCommandPlanV2,
    ) -> Result<Self, MacosProductionCommandPlanError> {
        plan.validate()?;
        let json = serde_json::to_vec(&plan)
            .map_err(|error| MacosProductionCommandPlanError::Encode(error.to_string()))?;
        let mut canonical_bytes = Vec::with_capacity(COMMAND_PLAN_DOMAIN_V2.len() + json.len());
        canonical_bytes.extend_from_slice(COMMAND_PLAN_DOMAIN_V2);
        canonical_bytes.extend_from_slice(&json);
        if canonical_bytes.len() > MAX_MACOS_PRODUCTION_COMMAND_PLAN_BYTES {
            return Err(MacosProductionCommandPlanError::TooLarge {
                actual: canonical_bytes.len(),
            });
        }
        let plan_digest = Digest::sha256(&canonical_bytes);
        Ok(Self {
            plan,
            canonical_bytes,
            plan_digest,
        })
    }

    pub(crate) fn decode_exact(bytes: &[u8]) -> Result<Self, MacosProductionCommandPlanError> {
        if bytes.len() > MAX_MACOS_PRODUCTION_COMMAND_PLAN_BYTES {
            return Err(MacosProductionCommandPlanError::TooLarge {
                actual: bytes.len(),
            });
        }
        let json = bytes
            .strip_prefix(COMMAND_PLAN_DOMAIN_V2)
            .ok_or_else(|| MacosProductionCommandPlanError::Decode("V2 domain differs".into()))?;
        let plan: MacosProductionCommandPlanV2 = serde_json::from_slice(json)
            .map_err(|error| MacosProductionCommandPlanError::Decode(error.to_string()))?;
        let validated = Self::from_plan(plan)?;
        if validated.canonical_bytes != bytes {
            return Err(MacosProductionCommandPlanError::NonCanonical);
        }
        Ok(validated)
    }

    pub(crate) fn canonical_bytes(&self) -> &[u8] {
        &self.canonical_bytes
    }

    pub(crate) const fn plan_digest(&self) -> &Digest {
        &self.plan_digest
    }

    pub(crate) fn effect_id(&self) -> &str {
        &self
            .plan
            .command_effect_authority
            .envelope()
            .effect
            .effect_id
    }

    pub(crate) const fn service_journal_binding(&self) -> &MacosProductionServiceJournalBindingV1 {
        &self.plan.service_journal_binding
    }

    pub(crate) const fn helper_session(&self) -> &MacosHelperSession {
        &self.plan.native_command_authority.helper_session
    }

    pub(crate) const fn helper_request(&self) -> &MacosHelperLaunchRequest {
        &self.plan.native_command_authority.helper_request
    }

    pub(crate) const fn assigned_identity(&self) -> &MacosAssignedIdentity {
        &self.plan.native_command_authority.assigned_identity
    }

    pub(crate) fn helper_journal_reference_bytes(&self) -> &[u8] {
        &self
            .plan
            .native_command_authority
            .helper_journal_reference_bytes
    }

    pub(crate) const fn helper_journal_reference_digest(&self) -> &Digest {
        &self
            .plan
            .native_command_authority
            .helper_journal_reference_digest
    }

    pub(crate) const fn command_effect_authority(&self) -> &CommandEffectAuthorityV13 {
        &self.plan.command_effect_authority
    }

    pub(crate) const fn permits_execution() -> bool {
        false
    }

    pub(crate) const fn permits_release() -> bool {
        false
    }
}

fn shared_sprint_digest(sprint: &SprintSpec) -> Result<Digest, MacosProductionCommandPlanError> {
    sprint_spec_digest(sprint).map_err(|error| {
        invalid(format!(
            "shared sprint-spec digest validation failed: {error}"
        ))
    })
}

fn domain_digest(domain: &[u8], bytes: &[u8]) -> Digest {
    let mut preimage = Vec::with_capacity(domain.len() + bytes.len());
    preimage.extend_from_slice(domain);
    preimage.extend_from_slice(bytes);
    Digest::sha256(&preimage)
}

pub(crate) fn digest_helper_journal_reference(bytes: &[u8]) -> Digest {
    domain_digest(HELPER_JOURNAL_REFERENCE_DOMAIN, bytes)
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use grok_build_core::{
        AcceptanceCriterion, AcceptanceKind, CommandOutputArtifactSourceV1, CommandSpec,
        ExecutionPolicy, ExecutionPolicyCompiler, ExecutionPolicyRequest,
        FINAL_VERIFICATION_ATTEMPT_AUTHORITY_VERSION_V1, FinalVerificationAttemptAuthorityV1,
        FinalVerificationAttemptPredecessorV1, FinalVerificationAttemptProvenanceV1, MutationMode,
        PathScope, ProviderProfile, ResourceLimits, SprintBudget, SprintBudgetV2, TaskAttempt,
        TaskAttemptRunningBoundary, TaskPurposeV2, TaskSpecV2, WorkerLease, WorkspaceGrantIssuer,
        WorkspaceGrantRequest, WorkspaceNetworkPolicy, WorkspacePermissions,
    };

    use super::*;
    use crate::macos_helper_protocol::{
        MacosChildDescriptorBinding, MacosChildDescriptorPurpose, MacosExecutableIdentity,
        MacosHelperAttestation, MacosHelperInstallAudit, MacosHelperPreparationBinding,
    };
    use crate::wire::{
        COMMAND_EFFECT_AUTHORITY_V2_SCHEMA_VERSION, CommandEffectAuthorityV2,
        RUNNER_WIRE_PROTOCOL_VERSION_V12, RunnerRequestEnvelopeV12, RunnerRequestV12,
        WireCommandSpec, WireEffectContext, command_output_capture_maximum,
        test_command_output_capture_anchor,
    };
    use crate::wire_v13::{
        RUNNER_WIRE_PROTOCOL_VERSION_V13, RunnerCommandRequestEnvelopeV13, RunnerCommandRequestV13,
        test_command_effect_authority_v13,
    };
    use grok_build_core::SensitiveOutputDetectionPolicyReferenceV1;

    fn digest(marker: u8) -> Digest {
        Digest::sha256(&[marker])
    }

    fn grant() -> WorkspaceGrant {
        WorkspaceGrant {
            grant_id: "grant-macos-plan-golden".into(),
            canonical_root: PathBuf::from("/work/project"),
            permissions: WorkspacePermissions::trusted(),
            network: WorkspaceNetworkPolicy::Denied,
            policy_version: 1,
            grant_hash: digest(1),
        }
    }

    fn policy(grant: &WorkspaceGrant) -> ExecutionPolicy {
        let mut policy = ExecutionPolicy {
            policy_id: "policy-macos-plan-golden".into(),
            grant_hash: grant.grant_hash.clone(),
            workspace_root: grant.canonical_root.clone(),
            read_scopes: vec![PathScope::Workspace],
            write_scopes: vec![PathScope::Relative(PathBuf::from("src"))],
            environment: Vec::new(),
            network: ExecutionNetwork::None,
            mutation_mode: MutationMode::ShadowWorkspace,
            resource_limits: ResourceLimits {
                wall_time_ms: 60_000,
                max_output_bytes: 1_048_576,
                max_processes: 16,
                max_memory_bytes: None,
            },
            approval_id: None,
            policy_hash: digest(0),
        };
        policy.policy_hash = policy.computed_hash().expect("compute policy hash");
        policy
            .validate_against(grant)
            .expect("validate deterministic policy");
        policy
    }

    fn criterion() -> AcceptanceCriterion {
        AcceptanceCriterion {
            criterion_id: "criterion-macos-plan".into(),
            description: "the exact locked command passes".into(),
            kind: AcceptanceKind::Automated(CommandSpec {
                program: "cargo".into(),
                arguments: vec!["test".into()],
                working_directory: PathBuf::new(),
            }),
        }
    }

    fn provider() -> ProviderProfile {
        ProviderProfile {
            backend_id: "fake-provider".into(),
            model_id: "deterministic-v2".into(),
            execution_origin: ExecutionOrigin::HostIsolated,
        }
    }

    fn repair_task(slot_ordinal: u8, dependencies: &[&str]) -> TaskSpecV2 {
        TaskSpecV2 {
            sprint_authority_version: SPRINT_AUTHORITY_CONTRACT_VERSION_V2,
            task_id: format!("repair-{slot_ordinal}"),
            purpose: TaskPurposeV2::FinalVerificationRepairSlot { slot_ordinal },
            goal: format!("repair final verification {slot_ordinal}"),
            dependencies: dependencies.iter().map(ToString::to_string).collect(),
            path_scopes: vec![PathScope::Relative(PathBuf::from("src"))],
            acceptance_checks: vec!["criterion-macos-plan".into()],
            base_snapshot: digest(60),
            required: false,
        }
    }

    fn v2_pair(workspace_grant: &WorkspaceGrant) -> (SprintSpecV2, TaskGraphV2) {
        let mut graph = TaskGraphV2 {
            sprint_authority_version: SPRINT_AUTHORITY_CONTRACT_VERSION_V2,
            graph_id: "graph-macos-plan-v2".into(),
            sprint_id: "sprint-macos-plan".into(),
            sprint_spec_digest: digest(0),
            repair_slot_reserve_digest: digest(0),
            tasks: vec![
                TaskSpecV2 {
                    sprint_authority_version: SPRINT_AUTHORITY_CONTRACT_VERSION_V2,
                    task_id: "task-macos-plan".into(),
                    purpose: TaskPurposeV2::Ordinary,
                    goal: "prove the exact macOS command bridge".into(),
                    dependencies: Vec::new(),
                    path_scopes: vec![PathScope::Relative(PathBuf::from("src"))],
                    acceptance_checks: vec!["criterion-macos-plan".into()],
                    base_snapshot: digest(60),
                    required: true,
                },
                repair_task(1, &["task-macos-plan"]),
                repair_task(2, &["task-macos-plan", "repair-1"]),
            ],
        };
        graph.repair_slot_reserve_digest = graph
            .computed_repair_slot_reserve_digest()
            .expect("compute repair reserve");
        let sprint = SprintSpecV2 {
            sprint_authority_version: SPRINT_AUTHORITY_CONTRACT_VERSION_V2,
            sprint_id: graph.sprint_id.clone(),
            objective: "prove the exact macOS command bridge".into(),
            acceptance_criteria: vec![criterion()],
            provider: provider(),
            budget: SprintBudgetV2 {
                sprint_authority_version: SPRINT_AUTHORITY_CONTRACT_VERSION_V2,
                max_tasks: graph.tasks.len(),
                max_attempts_per_task: 3,
                max_final_verification_attempts: 3,
                max_tool_calls: 32,
                max_duration_ms: 600_000,
            },
            max_workers: 3,
            workspace_grant: workspace_grant.clone(),
            base_snapshot: digest(60),
            task_graph_id: graph.graph_id.clone(),
            task_graph_payload_digest: graph.payload_digest().expect("compute graph payload"),
            repair_slot_reserve_digest: graph.repair_slot_reserve_digest.clone(),
        };
        graph.sprint_spec_digest = sprint.canonical_digest().expect("compute sprint digest");
        graph
            .validate_for_sprint(&sprint)
            .expect("validate deterministic current pair");
        (sprint, graph)
    }

    fn identity(uid: u32) -> MacosExecutionIdentityRecord {
        MacosExecutionIdentityRecord {
            account_name: format!("_grokbuild{uid}"),
            uid,
            gid: uid,
            record_digest: Digest::sha256(&uid.to_be_bytes()),
            login_shell: "/usr/bin/false".into(),
            home_directory: format!("/var/empty/grok-build/{uid}"),
            supplementary_groups: Vec::new(),
            password_locked: true,
            interactive_session_count: 0,
        }
    }

    fn assigned(uid: u32) -> MacosAssignedIdentity {
        let identity = identity(uid);
        MacosAssignedIdentity {
            account_name: identity.account_name,
            uid,
            gid: identity.gid,
            account_record_digest: identity.record_digest,
        }
    }

    fn descriptors() -> Vec<MacosChildDescriptorBinding> {
        [
            (0, MacosChildDescriptorPurpose::StandardInput, true),
            (1, MacosChildDescriptorPurpose::StandardOutput, true),
            (2, MacosChildDescriptorPurpose::StandardError, true),
            (3, MacosChildDescriptorPurpose::HoldControl, false),
            (4, MacosChildDescriptorPurpose::SetupReport, false),
        ]
        .into_iter()
        .map(
            |(target_fd, purpose, inherited_through_exec)| MacosChildDescriptorBinding {
                target_fd,
                purpose,
                object_digest: digest(90 + u8::try_from(target_fd).expect("small descriptor")),
                inherited_through_exec,
            },
        )
        .collect()
    }

    fn command_authority_v2(
        workspace_grant: &WorkspaceGrant,
        execution_policy: &ExecutionPolicy,
    ) -> CommandEffectAuthorityV2 {
        let command = CommandSpec {
            program: "cargo".into(),
            arguments: vec!["test".into()],
            working_directory: PathBuf::new(),
        };
        let request_digest = Digest::sha256(
            &serde_json::to_vec(&command).expect("encode deterministic exact command"),
        );
        let worker_lease = WorkerLease::new(
            "sprint-macos-plan".into(),
            1,
            "task-macos-plan".into(),
            "worker-macos-plan".into(),
            vec![PathScope::Relative(PathBuf::from("src"))],
            11,
        )
        .expect("construct worker lease");
        let output_capture = test_command_output_capture_anchor(
            CommandOutputArtifactSourceV1 {
                sprint_id: "sprint-macos-plan".into(),
                runner_launch_id: "launch-macos-plan".into(),
                runner_session_id: "runner-session-macos-plan".into(),
                effect_id: "effect-macos-plan".into(),
                request_digest: request_digest.clone(),
            },
            digest(72),
            command_output_capture_maximum(execution_policy.resource_limits.max_output_bytes)
                .expect("capture maximum"),
            7,
        );
        let mut envelope = RunnerRequestEnvelopeV12 {
            protocol_version: RUNNER_WIRE_PROTOCOL_VERSION_V12,
            session_id: "runner-session-macos-plan".into(),
            runner_nonce: digest(70),
            sequence: 7,
            request_id: "wire-request-macos-plan".into(),
            effect: WireEffectContext {
                contract_version: CONTRACT_VERSION,
                launch_id: "launch-macos-plan".into(),
                effect_id: "effect-macos-plan".into(),
                idempotency_key: "idempotency-macos-plan".into(),
                sprint_id: "sprint-macos-plan".into(),
                task_id: Some("task-macos-plan".into()),
                worker_id: Some("worker-macos-plan".into()),
                worker_lease: Some(worker_lease),
                policy_hash: execution_policy.policy_hash.clone(),
                input_snapshot: digest(71),
                request_digest,
                transport_commitment_digest: digest(0),
            },
            request: RunnerRequestV12::RunCommand {
                request: RunnerRequest::WorkerRunCommand {
                    command: WireCommandSpec {
                        program: command.program,
                        arguments: command.arguments,
                        working_directory: String::new(),
                    },
                    output_capture,
                },
                detector_policy: SensitiveOutputDetectionPolicyReferenceV1::core_v1(),
            },
        };
        envelope
            .bind_transport_commitment_digest()
            .expect("bind V12 transport commitment");
        let authority: CommandEffectAuthorityV2 = serde_json::from_value(serde_json::json!({
            "schema_version": COMMAND_EFFECT_AUTHORITY_V2_SCHEMA_VERSION,
            "contract_version": CONTRACT_VERSION,
            "grant_hash": workspace_grant.grant_hash,
            "role": RunnerRole::Worker,
            "envelope": envelope,
        }))
        .expect("decode deterministic internal current command authority");
        authority
            .validate_integrity()
            .expect("validate current command authority");
        authority
    }

    fn command_authority_v13(
        workspace_grant: &WorkspaceGrant,
        execution_policy: &ExecutionPolicy,
        sprint: &SprintSpecV2,
        task_graph: &TaskGraphV2,
    ) -> CommandEffectAuthorityV13 {
        let command = CommandSpec {
            program: "cargo".into(),
            arguments: vec!["test".into()],
            working_directory: PathBuf::new(),
        };
        let request_digest = Digest::sha256(
            &serde_json::to_vec(&command).expect("encode deterministic exact V13 command"),
        );
        let worker_lease = WorkerLease::new(
            sprint.sprint_id.clone(),
            1,
            "task-macos-plan".into(),
            "worker-macos-plan".into(),
            vec![PathScope::Relative(PathBuf::from("src"))],
            11,
        )
        .expect("construct V13 worker lease");
        let attempt = TaskAttempt::new(worker_lease.clone(), 1, "opening-event-macos-plan".into())
            .expect("construct V13 task attempt");
        let running_boundary = TaskAttemptRunningBoundary {
            contract_version: CONTRACT_VERSION,
            boundary_id: "running-boundary-macos-plan".into(),
            attempt,
            runner_launch_id: "launch-macos-plan".into(),
            runner_session_id: "runner-session-macos-plan".into(),
            transition_event_id: "running-event-macos-plan".into(),
            started_at_unix_ms: 12,
        };
        running_boundary
            .validate()
            .expect("validate V13 running boundary");
        let output_capture = test_command_output_capture_anchor(
            CommandOutputArtifactSourceV1 {
                sprint_id: sprint.sprint_id.clone(),
                runner_launch_id: "launch-macos-plan".into(),
                runner_session_id: "runner-session-macos-plan".into(),
                effect_id: "effect-macos-plan".into(),
                request_digest: request_digest.clone(),
            },
            digest(72),
            command_output_capture_maximum(execution_policy.resource_limits.max_output_bytes)
                .expect("capture maximum"),
            7,
        );
        let mut envelope = RunnerCommandRequestEnvelopeV13 {
            protocol_version: RUNNER_WIRE_PROTOCOL_VERSION_V13,
            session_id: "runner-session-macos-plan".into(),
            runner_nonce: digest(70),
            sequence: 7,
            request_id: "wire-request-macos-plan-v13".into(),
            sprint_spec: Box::new(sprint.clone()),
            task_graph: Box::new(task_graph.clone()),
            effect: WireEffectContext {
                contract_version: CONTRACT_VERSION,
                launch_id: "launch-macos-plan".into(),
                effect_id: "effect-macos-plan".into(),
                idempotency_key: "idempotency-macos-plan".into(),
                sprint_id: sprint.sprint_id.clone(),
                task_id: Some("task-macos-plan".into()),
                worker_id: Some("worker-macos-plan".into()),
                worker_lease: Some(worker_lease),
                policy_hash: execution_policy.policy_hash.clone(),
                input_snapshot: digest(71),
                request_digest,
                transport_commitment_digest: digest(0),
            },
            request: RunnerCommandRequestV13::WorkerRunCommand {
                command: WireCommandSpec {
                    program: command.program,
                    arguments: command.arguments,
                    working_directory: String::new(),
                },
                output_capture,
                detector_policy: SensitiveOutputDetectionPolicyReferenceV1::core_v1(),
                task: Box::new(task_graph.tasks[0].clone()),
                running_boundary: Box::new(running_boundary),
            },
        };
        envelope
            .bind_transport_commitment_digest()
            .expect("bind V13 transport commitment");
        test_command_effect_authority_v13(envelope, workspace_grant.grant_hash.clone())
            .expect("mint test-only service-validated V13 command authority")
    }

    fn final_verifier_authority_v13(
        workspace_grant: &WorkspaceGrant,
        execution_policy: &ExecutionPolicy,
        sprint: &SprintSpecV2,
        task_graph: &TaskGraphV2,
    ) -> CommandEffectAuthorityV13 {
        let command = CommandSpec {
            program: "cargo".into(),
            arguments: vec!["test".into()],
            working_directory: PathBuf::new(),
        };
        let request_digest = Digest::sha256(
            &serde_json::to_vec(&command).expect("encode deterministic final command"),
        );
        let attempt = FinalVerificationAttemptAuthorityV1 {
            authority_version: FINAL_VERIFICATION_ATTEMPT_AUTHORITY_VERSION_V1,
            attempt_id: "final-attempt-macos-plan".into(),
            sprint_id: sprint.sprint_id.clone(),
            attempt_ordinal: 1,
            max_final_verification_attempts: sprint.budget.max_final_verification_attempts,
            final_verification_admission_id: "final-admission-macos-plan".into(),
            input_snapshot: digest(71),
            complete_task_done_set_digest: digest(75),
            complete_criterion_evidence_set_digest: digest(76),
            final_verification_check: command.clone(),
            execution_policy_digest: execution_policy.policy_hash.clone(),
            provenance: FinalVerificationAttemptProvenanceV1 {
                coordinator_instance_id: "coordinator-macos-plan".into(),
                admission_event_id: "final-admission-event-macos-plan".into(),
                admission_event_sequence: 20,
                admitted_at_unix_ms: 20,
            },
            predecessor: FinalVerificationAttemptPredecessorV1::Initial,
        };
        attempt.validate().expect("validate final attempt fixture");
        let output_capture = test_command_output_capture_anchor(
            CommandOutputArtifactSourceV1 {
                sprint_id: sprint.sprint_id.clone(),
                runner_launch_id: "launch-macos-plan".into(),
                runner_session_id: "runner-session-macos-plan".into(),
                effect_id: "effect-macos-plan".into(),
                request_digest: request_digest.clone(),
            },
            digest(72),
            command_output_capture_maximum(execution_policy.resource_limits.max_output_bytes)
                .expect("capture maximum"),
            8,
        );
        let mut envelope = RunnerCommandRequestEnvelopeV13 {
            protocol_version: RUNNER_WIRE_PROTOCOL_VERSION_V13,
            session_id: "runner-session-macos-plan".into(),
            runner_nonce: digest(70),
            sequence: 8,
            request_id: "final-wire-request-macos-plan-v13".into(),
            sprint_spec: Box::new(sprint.clone()),
            task_graph: Box::new(task_graph.clone()),
            effect: WireEffectContext {
                contract_version: CONTRACT_VERSION,
                launch_id: "launch-macos-plan".into(),
                effect_id: "effect-macos-plan".into(),
                idempotency_key: "final-idempotency-macos-plan".into(),
                sprint_id: sprint.sprint_id.clone(),
                task_id: None,
                worker_id: None,
                worker_lease: None,
                policy_hash: execution_policy.policy_hash.clone(),
                input_snapshot: digest(71),
                request_digest,
                transport_commitment_digest: digest(0),
            },
            request: RunnerCommandRequestV13::FinalVerifierRunCommand {
                command: WireCommandSpec {
                    program: command.program,
                    arguments: command.arguments,
                    working_directory: String::new(),
                },
                output_capture,
                detector_policy: SensitiveOutputDetectionPolicyReferenceV1::core_v1(),
                final_verification_attempt: Box::new(attempt),
            },
        };
        envelope
            .bind_transport_commitment_digest()
            .expect("bind final V13 transport commitment");
        test_command_effect_authority_v13(envelope, workspace_grant.grant_hash.clone())
            .expect("mint test-only final V13 command authority")
    }

    #[allow(
        clippy::too_many_lines,
        reason = "the deterministic native-plan fixture keeps all mutually bound helper identities adjacent"
    )]
    fn native_fixture(
        workspace_grant: &WorkspaceGrant,
        execution_policy: &ExecutionPolicy,
        attempt_id: &str,
    ) -> (
        MacosHelperSession,
        MacosHelperLaunchRequest,
        MacosIdentityPoolContractV1,
        MacosAssignedIdentity,
        Vec<u8>,
        Digest,
        MacosProductionServiceJournalBindingV1,
    ) {
        let mut pool = MacosIdentityPoolObservation {
            records: vec![identity(601), identity(602), identity(603)],
            pool_record_digest: digest(0),
        };
        pool.pool_record_digest = pool.computed_digest().expect("compute pool digest");
        let session = MacosHelperSession {
            protocol_version: MACOS_HELPER_PROTOCOL_VERSION,
            policy_version: 7,
            session_nonce: digest(10),
            helper_binary_digest: digest(11),
            helper_requirement_digest: digest(12),
            client_binary_digest: digest(13),
            client_requirement_digest: digest(14),
            pool_record_digest: pool.pool_record_digest.clone(),
            workspace_grant_hash: workspace_grant.grant_hash.clone(),
            execution_policy_hash: execution_policy.policy_hash.clone(),
            command_network: MacosHelperNetwork::Denied,
            authenticated_at_unix_ms: 10,
            peer_requirement_matched: true,
            attestation: MacosHelperAttestation::LocalCodeIdentity {
                install_audit: MacosHelperInstallAudit {
                    auditing_uid: 501,
                    binary_owner_uid: 0,
                    binary_mode: 0o755,
                    directory_owner_uid: 0,
                    directory_mode: 0o755,
                },
            },
        };
        let helper_reference: MacosHelperJournalReference =
            serde_json::from_value(serde_json::json!({
                "format_version": 3,
                "pool_record_digest": pool.pool_record_digest,
                "manifest_digest": digest(15),
                "root_identity": { "device": 21, "inode": 22 },
                "manifest_identity": { "device": 21, "inode": 23 },
            }))
            .expect("decode deterministic helper reference");
        let helper_journal_reference_bytes = helper_reference
            .canonical_bytes()
            .expect("encode helper reference");
        MacosHelperJournalReference::decode_canonical(&helper_journal_reference_bytes)
            .expect("validate helper reference");
        let helper_journal_reference_digest =
            digest_helper_journal_reference(&helper_journal_reference_bytes);
        let service_binding = MacosProductionServiceJournalBindingV1::try_new(
            &session,
            MacosJournalObjectIdentityV1 {
                device_id: 31,
                inode: 32,
            },
            MacosJournalObjectIdentityV1 {
                device_id: 31,
                inode: 33,
            },
            helper_journal_reference_digest.clone(),
            501,
            PRIVATE_DIRECTORY_MODE,
            PRIVATE_DIRECTORY_MODE,
        )
        .expect("construct service binding");
        let mut helper_request = MacosHelperLaunchRequest {
            protocol_version: MACOS_HELPER_PROTOCOL_VERSION,
            policy_version: session.policy_version,
            session_nonce: session.session_nonce.clone(),
            request_id: "helper-request-macos-plan".into(),
            preparation: MacosHelperPreparationBinding {
                contract_version: CONTRACT_VERSION,
                attempt_id: attempt_id.into(),
                sprint_id: "sprint-macos-plan".into(),
                launch_id: "launch-macos-plan".into(),
                runner_session_id: "runner-session-macos-plan".into(),
                cleanup_effect_id: "cleanup-macos-plan".into(),
                input_snapshot: digest(71),
                native_journal_id: "native-journal-macos-plan".into(),
                expected_platform_binding_digest: digest(72),
                claimed_at_unix_ms: 11,
            },
            runner_session_id: "runner-session-macos-plan".into(),
            effect_id: "effect-macos-plan".into(),
            workspace_grant_hash: workspace_grant.grant_hash.clone(),
            execution_policy_hash: execution_policy.policy_hash.clone(),
            staged_workspace_id: "shadow-macos-plan".into(),
            executable_identity: MacosExecutableIdentity::SystemToolchain {
                policy_entry_id: "cargo-1.97.0".into(),
                binary_digest: digest(73),
            },
            descriptor_bindings: descriptors(),
            argv: vec!["cargo".into(), "test".into()],
            relative_working_directory: ".".into(),
            environment: BTreeMap::new(),
            deadline_unix_ms: 1_000,
            max_output_bytes: execution_policy.resource_limits.max_output_bytes,
            max_processes: execution_policy.resource_limits.max_processes,
            max_memory_bytes: execution_policy.resource_limits.max_memory_bytes,
            command_network: MacosHelperNetwork::Denied,
            seatbelt_profile_digest: digest(74),
            request_digest: digest(0),
        };
        helper_request.request_digest = helper_request
            .computed_digest()
            .expect("compute helper request digest");
        helper_request
            .validate_archived_session_binding(&session)
            .expect("validate helper request");
        (
            session,
            helper_request,
            MacosIdentityPoolContractV1::from_observation(&pool),
            assigned(601),
            helper_journal_reference_bytes,
            helper_journal_reference_digest,
            service_binding,
        )
    }

    fn current_plan() -> ValidatedMacosProductionCommandPlanV2 {
        let workspace_grant = grant();
        let execution_policy = policy(&workspace_grant);
        let (sprint, task_graph) = v2_pair(&workspace_grant);
        let command_effect_authority =
            command_authority_v13(&workspace_grant, &execution_policy, &sprint, &task_graph);
        let attempt_id = command_effect_authority.attempt_id().to_owned();
        let (
            helper_session,
            helper_request,
            identity_pool,
            assigned_identity,
            helper_journal_reference_bytes,
            helper_journal_reference_digest,
            service_journal_binding,
        ) = native_fixture(&workspace_grant, &execution_policy, &attempt_id);
        let trusted_sprint_authority = MacosTrustedSprintAuthorityV2 {
            sprint_authority_version: SPRINT_AUTHORITY_CONTRACT_VERSION_V2,
            core_sprint_spec_digest: sprint.canonical_digest().expect("core sprint digest"),
            core_task_graph_digest: task_graph
                .canonical_digest_for_sprint(&sprint)
                .expect("core graph digest"),
            core_task_graph_payload_digest: task_graph.payload_digest().expect("payload digest"),
            core_repair_slot_reserve_digest: task_graph
                .computed_repair_slot_reserve_digest()
                .expect("reserve digest"),
            runner_sprint_spec_digest_v2: sprint_spec_digest_v2(&sprint, &task_graph)
                .expect("runner sprint digest"),
            sprint_spec: sprint,
            task_graph,
            workspace_grant,
            workspace_identity: MacosWorkspaceIdentityV1 {
                canonical_root: "/work/project".into(),
                device_id: 41,
                inode: 42,
            },
            execution_policy,
        };
        ValidatedMacosProductionCommandPlanV2::from_plan(MacosProductionCommandPlanV2 {
            schema_version: MACOS_PRODUCTION_COMMAND_PLAN_SCHEMA_VERSION_V2,
            sprint_authority_version: SPRINT_AUTHORITY_CONTRACT_VERSION_V2,
            contract_version: CONTRACT_VERSION,
            trusted_sprint_authority,
            command_effect_authority,
            native_command_authority: MacosNativeCommandAuthorityV1 {
                helper_session,
                helper_request,
                identity_pool,
                assigned_identity,
                helper_journal_reference_bytes,
                helper_journal_reference_digest,
            },
            service_journal_binding,
            safety_boundary: MacosProductionSafetyBoundaryV1 {
                held_requirement:
                    MacosHeldRequirementV1::ExactSignedHelperSetupReadbackWhileChildCannotRunProjectCode,
                release_requirement:
                    MacosReleaseRequirementV1::DisabledUntilLiveCoreClaimAndSignedNativeHoldProof,
                cleanup_requirements_in_order: REQUIRED_CLEANUP.to_vec(),
                permits_execution: false,
                permits_release: false,
            },
        })
        .expect("validate deterministic current macOS plan")
    }

    fn legacy_plan(
        current: &ValidatedMacosProductionCommandPlanV2,
    ) -> ValidatedMacosProductionCommandPlanV1 {
        let current_sprint = &current.plan.trusted_sprint_authority.sprint_spec;
        let sprint = SprintSpec {
            sprint_id: current_sprint.sprint_id.clone(),
            objective: current_sprint.objective.clone(),
            acceptance_criteria: current_sprint.acceptance_criteria.clone(),
            provider: current_sprint.provider.clone(),
            budget: SprintBudget {
                max_tasks: current_sprint.budget.max_tasks,
                max_attempts_per_task: current_sprint.budget.max_attempts_per_task,
                max_tool_calls: current_sprint.budget.max_tool_calls,
                max_duration_ms: current_sprint.budget.max_duration_ms,
            },
            max_workers: current_sprint.max_workers,
            workspace_grant: current_sprint.workspace_grant.clone(),
            base_snapshot: current_sprint.base_snapshot.clone(),
        };
        let trusted = MacosTrustedSprintAuthorityV1 {
            sprint_spec_digest: shared_sprint_digest(&sprint).expect("legacy sprint digest"),
            sprint_spec: sprint,
            workspace_grant: current
                .plan
                .trusted_sprint_authority
                .workspace_grant
                .clone(),
            workspace_identity: current
                .plan
                .trusted_sprint_authority
                .workspace_identity
                .clone(),
            execution_policy: current
                .plan
                .trusted_sprint_authority
                .execution_policy
                .clone(),
        };
        let command_effect_authority =
            command_authority_v2(&trusted.workspace_grant, &trusted.execution_policy)
                .v11_execution_projection()
                .expect("derive frozen V1 execution projection for byte fixture");
        let mut native_command_authority = current.plan.native_command_authority.clone();
        native_command_authority
            .helper_request
            .preparation
            .attempt_id = "attempt-macos-plan".into();
        native_command_authority.helper_request.request_digest = native_command_authority
            .helper_request
            .computed_digest()
            .expect("restore frozen V1 helper request bytes");
        ValidatedMacosProductionCommandPlanV1::from_plan(MacosProductionCommandPlanV1 {
            schema_version: MACOS_PRODUCTION_COMMAND_PLAN_SCHEMA_VERSION,
            contract_version: CONTRACT_VERSION,
            trusted_sprint_authority: trusted,
            command_effect_authority,
            native_command_authority,
            service_journal_binding: current.plan.service_journal_binding.clone(),
            safety_boundary: current.plan.safety_boundary.clone(),
        })
        .expect("validate deterministic frozen V1 plan")
    }

    fn mutate_current_json(
        plan: &ValidatedMacosProductionCommandPlanV2,
        mutation: impl FnOnce(&mut serde_json::Value),
    ) -> Vec<u8> {
        let json = plan
            .canonical_bytes()
            .strip_prefix(COMMAND_PLAN_DOMAIN_V2)
            .expect("current plan domain");
        let mut value: serde_json::Value =
            serde_json::from_slice(json).expect("decode current plan fixture");
        mutation(&mut value);
        let changed = serde_json::to_vec(&value).expect("encode changed current plan");
        let mut bytes = Vec::with_capacity(COMMAND_PLAN_DOMAIN_V2.len() + changed.len());
        bytes.extend_from_slice(COMMAND_PLAN_DOMAIN_V2);
        bytes.extend_from_slice(&changed);
        bytes
    }

    fn rebind_helper_request(plan: &mut MacosProductionCommandPlanV2) {
        plan.native_command_authority.helper_request.request_digest = plan
            .native_command_authority
            .helper_request
            .computed_digest()
            .expect("rebind changed helper request");
    }

    #[test]
    fn current_and_frozen_plan_bytes_have_separate_canonical_goldens() {
        let current = current_plan();
        let legacy = legacy_plan(&current);
        // These goldens use ADR-0012 typed attestation identities.
        assert_eq!(
            current.plan_digest(),
            &Digest::parse("904796d4acd7b5549fc3ca05523a0ec3194fbb05ecf1ccc55ed4bdc816d3aff2")
                .expect("current plan golden")
        );
        assert_eq!(
            legacy.plan_digest(),
            &Digest::parse("f0f676d264295e64ff5f6f0d958cdcb875f6fe3b0fa18721e47932fa3e369d3d")
                .expect("frozen V1 plan golden")
        );
        assert_eq!(
            ValidatedMacosProductionCommandPlanV2::decode_exact(current.canonical_bytes())
                .expect("decode exact current plan"),
            current
        );
        assert_eq!(
            ValidatedMacosProductionCommandPlanV1::decode_exact(legacy.canonical_bytes())
                .expect("decode exact legacy plan"),
            legacy
        );
        assert!(!ValidatedMacosProductionCommandPlanV2::permits_execution());
        assert!(!ValidatedMacosProductionCommandPlanV2::permits_release());
    }

    #[test]
    fn current_plan_rejects_legacy_domain_and_current_legacy_substitution() {
        let current = current_plan();
        let legacy = legacy_plan(&current);
        assert!(
            ValidatedMacosProductionCommandPlanV2::decode_exact(legacy.canonical_bytes()).is_err()
        );
        assert!(
            ValidatedMacosProductionCommandPlanV1::decode_exact(current.canonical_bytes()).is_err()
        );

        let mut wrong_domain = COMMAND_PLAN_DOMAIN.to_vec();
        wrong_domain.extend_from_slice(
            current
                .canonical_bytes()
                .strip_prefix(COMMAND_PLAN_DOMAIN_V2)
                .expect("strip current domain"),
        );
        assert!(ValidatedMacosProductionCommandPlanV2::decode_exact(&wrong_domain).is_err());
        assert!(ValidatedMacosProductionCommandPlanV1::decode_exact(&wrong_domain).is_err());
    }

    #[test]
    fn current_plan_rejects_every_sprint_graph_reserve_and_runner_digest_crossing() {
        let current = current_plan();
        for field in [
            "core_sprint_spec_digest",
            "core_task_graph_digest",
            "core_task_graph_payload_digest",
            "core_repair_slot_reserve_digest",
            "runner_sprint_spec_digest_v2",
        ] {
            let changed = mutate_current_json(&current, |value| {
                value["trusted_sprint_authority"][field] =
                    serde_json::Value::String(digest(250).to_string());
            });
            assert!(
                ValidatedMacosProductionCommandPlanV2::decode_exact(&changed).is_err(),
                "crossed {field} must fail closed"
            );
        }

        let changed_spec = mutate_current_json(&current, |value| {
            value["trusted_sprint_authority"]["sprint_spec"]["objective"] =
                serde_json::Value::String("caller-manufactured objective".into());
        });
        assert!(ValidatedMacosProductionCommandPlanV2::decode_exact(&changed_spec).is_err());

        let changed_graph = mutate_current_json(&current, |value| {
            value["trusted_sprint_authority"]["task_graph"]["tasks"][0]["goal"] =
                serde_json::Value::String("caller-manufactured graph".into());
        });
        assert!(ValidatedMacosProductionCommandPlanV2::decode_exact(&changed_graph).is_err());
    }

    #[test]
    fn current_plan_rejects_caller_manufactured_versions_grant_and_release_authority() {
        let current = current_plan();
        let wrong_schema = mutate_current_json(&current, |value| {
            value["schema_version"] = serde_json::Value::from(1);
        });
        assert!(ValidatedMacosProductionCommandPlanV2::decode_exact(&wrong_schema).is_err());

        let wrong_authority_version = mutate_current_json(&current, |value| {
            value["sprint_authority_version"] = serde_json::Value::from(1);
        });
        assert!(
            ValidatedMacosProductionCommandPlanV2::decode_exact(&wrong_authority_version).is_err()
        );

        let crossed_grant = mutate_current_json(&current, |value| {
            value["trusted_sprint_authority"]["workspace_grant"]["grant_hash"] =
                serde_json::Value::String(digest(251).to_string());
        });
        assert!(ValidatedMacosProductionCommandPlanV2::decode_exact(&crossed_grant).is_err());

        let manufactured_release = mutate_current_json(&current, |value| {
            value["safety_boundary"]["permits_release"] = serde_json::Value::Bool(true);
        });
        assert!(
            ValidatedMacosProductionCommandPlanV2::decode_exact(&manufactured_release).is_err()
        );

        let mut noncanonical = current.canonical_bytes().to_vec();
        noncanonical.push(b' ');
        assert!(ValidatedMacosProductionCommandPlanV2::decode_exact(&noncanonical).is_err());
    }

    #[test]
    fn current_plan_rejects_v12_authority_substitution_and_binds_exact_v13_pair() {
        let current = current_plan();
        let trusted = &current.plan.trusted_sprint_authority;
        let v12 = command_authority_v2(&trusted.workspace_grant, &trusted.execution_policy);
        let substituted = mutate_current_json(&current, |value| {
            value["command_effect_authority"] =
                serde_json::to_value(v12).expect("encode diagnostic-only V12 authority");
        });
        assert!(
            ValidatedMacosProductionCommandPlanV2::decode_exact(&substituted).is_err(),
            "a diagnostic-only V12 authority cannot inhabit a current macOS plan"
        );

        let crossed = mutate_current_json(&current, |value| {
            value["command_effect_authority"]["envelope"]["sprint_spec"]["objective"] =
                serde_json::Value::String("crossed V13 objective".into());
        });
        assert!(ValidatedMacosProductionCommandPlanV2::decode_exact(&crossed).is_err());
    }

    #[test]
    fn current_plan_accepts_exact_final_attempt_and_rejects_attempt_substitution() {
        let current = current_plan();
        let trusted = &current.plan.trusted_sprint_authority;
        let final_authority = final_verifier_authority_v13(
            &trusted.workspace_grant,
            &trusted.execution_policy,
            &trusted.sprint_spec,
            &trusted.task_graph,
        );
        let final_attempt_id = final_authority.attempt_id().to_owned();
        let mut final_plan = current.plan.clone();
        final_plan.command_effect_authority = final_authority;
        final_plan
            .native_command_authority
            .helper_request
            .preparation
            .attempt_id = final_attempt_id;
        rebind_helper_request(&mut final_plan);
        let final_plan = ValidatedMacosProductionCommandPlanV2::from_plan(final_plan)
            .expect("accept exact V13 final-verifier attempt authority");
        assert_eq!(
            ValidatedMacosProductionCommandPlanV2::decode_exact(final_plan.canonical_bytes())
                .expect("reopen exact final-verifier plan"),
            final_plan
        );

        let crossed_attempt = mutate_current_json(&final_plan, |value| {
            value["command_effect_authority"]["envelope"]["request"]["final_verification_attempt"]
                ["input_snapshot"] = serde_json::Value::String(digest(250).to_string());
        });
        assert!(ValidatedMacosProductionCommandPlanV2::decode_exact(&crossed_attempt).is_err());
    }

    #[test]
    fn helper_deadline_is_an_overflow_safe_controller_interval_bounded_by_wall_time() {
        let current = current_plan();
        let wall_time_ms = current
            .plan
            .trusted_sprint_authority
            .execution_policy
            .resource_limits
            .wall_time_ms;

        let mut overlong = current.plan.clone();
        let claimed = overlong
            .native_command_authority
            .helper_request
            .preparation
            .claimed_at_unix_ms;
        overlong
            .native_command_authority
            .helper_request
            .deadline_unix_ms = claimed
            .checked_add(wall_time_ms)
            .and_then(|value| value.checked_add(1))
            .expect("fixture deadline addition is bounded");
        rebind_helper_request(&mut overlong);
        assert!(ValidatedMacosProductionCommandPlanV2::from_plan(overlong).is_err());

        let mut maximum_deadline = current.plan.clone();
        maximum_deadline
            .native_command_authority
            .helper_request
            .deadline_unix_ms = u64::MAX;
        rebind_helper_request(&mut maximum_deadline);
        assert!(
            ValidatedMacosProductionCommandPlanV2::from_plan(maximum_deadline).is_err(),
            "a huge deadline cannot wrap an addition into the compiled limit"
        );

        let mut near_maximum_but_bounded = current.plan.clone();
        near_maximum_but_bounded
            .native_command_authority
            .helper_request
            .preparation
            .claimed_at_unix_ms = u64::MAX - 10;
        near_maximum_but_bounded
            .native_command_authority
            .helper_request
            .deadline_unix_ms = u64::MAX;
        rebind_helper_request(&mut near_maximum_but_bounded);
        ValidatedMacosProductionCommandPlanV2::from_plan(near_maximum_but_bounded)
            .expect("checked subtraction accepts the exact ten-millisecond interval");

        let mut claim_before_controller = current.plan.clone();
        let claimed_at = claim_before_controller
            .native_command_authority
            .helper_request
            .preparation
            .claimed_at_unix_ms;
        claim_before_controller
            .native_command_authority
            .helper_session
            .authenticated_at_unix_ms = claimed_at.saturating_add(1);
        assert!(ValidatedMacosProductionCommandPlanV2::from_plan(claim_before_controller).is_err());

        let mut crossed_attempt = current.plan.clone();
        crossed_attempt
            .native_command_authority
            .helper_request
            .preparation
            .attempt_id = "crossed-attempt".into();
        rebind_helper_request(&mut crossed_attempt);
        assert!(ValidatedMacosProductionCommandPlanV2::from_plan(crossed_attempt).is_err());
    }

    #[test]
    fn current_builder_requires_the_exact_live_grant_policy_and_v2_pair() {
        let root = std::env::temp_dir().join(format!(
            "grok-build-macos-plan-v2-builder-{}",
            std::process::id()
        ));
        std::fs::create_dir(&root).expect("create current-builder workspace");
        let canonical_root = std::fs::canonicalize(&root).expect("canonical builder workspace");
        let issued = WorkspaceGrantIssuer::issue(WorkspaceGrantRequest {
            grant_id: "grant-macos-plan-builder".into(),
            workspace_root: canonical_root,
            permissions: WorkspacePermissions::trusted(),
            network: WorkspaceNetworkPolicy::Denied,
            policy_version: 1,
        })
        .expect("issue builder grant");
        let compiled = ExecutionPolicyCompiler::compile(
            &issued,
            ExecutionPolicyRequest {
                policy_id: "policy-macos-plan-builder".into(),
                read_scopes: vec![PathScope::Workspace],
                write_scopes: vec![PathScope::Relative(PathBuf::from("src"))],
                environment: Vec::new(),
                network: ExecutionNetwork::None,
                mutation_mode: MutationMode::ShadowWorkspace,
                resource_limits: ResourceLimits {
                    wall_time_ms: 60_000,
                    max_output_bytes: 1_048_576,
                    max_processes: 16,
                    max_memory_bytes: None,
                },
                approval_id: None,
            },
        )
        .expect("compile builder policy");
        let (sprint, graph) = v2_pair(issued.contract());
        let authority =
            command_authority_v13(issued.contract(), compiled.contract(), &sprint, &graph);
        let attempt_id = authority.attempt_id().to_owned();
        let (
            session,
            request,
            pool,
            assigned_identity,
            reference_bytes,
            _reference_digest,
            binding,
        ) = native_fixture(issued.contract(), compiled.contract(), &attempt_id);
        let reference = MacosHelperJournalReference::decode_canonical(&reference_bytes)
            .expect("decode exact helper reference");
        let built = MacosProductionCommandPlanV2::build(
            &sprint,
            &graph,
            authority.clone(),
            &issued,
            &compiled,
            session.clone(),
            request.clone(),
            &pool.observation(),
            assigned_identity.clone(),
            &reference,
            binding.clone(),
        )
        .expect("build exact current plan from live trusted inputs");
        assert_eq!(
            ValidatedMacosProductionCommandPlanV2::decode_exact(built.canonical_bytes())
                .expect("reopen built current plan"),
            built
        );

        let mut crossed_sprint = sprint.clone();
        crossed_sprint.objective.push_str(" crossed");
        assert!(
            MacosProductionCommandPlanV2::build(
                &crossed_sprint,
                &graph,
                authority,
                &issued,
                &compiled,
                session,
                request,
                &pool.observation(),
                assigned_identity,
                &reference,
                binding,
            )
            .is_err()
        );
        std::fs::remove_dir_all(&root).expect("remove current-builder workspace");
    }
}
