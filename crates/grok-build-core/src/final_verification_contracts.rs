//! Version-separated sprint and final-verification authority contracts.
//!
//! The legacy family in this module is diagnostic/readback-only. It freezes
//! the exact pre-schema-v32 sprint and graph byte shape without providing a
//! conversion into current authority. The V2 family is intentionally dormant:
//! it defines and validates bytes, but no ledger, scheduler, provider, runner,
//! or coordinator path consumes it yet.
//!
//! The legacy core DTOs expose no newly invented digest. Pre-v32 core owned
//! their exact bytes but no standalone `TaskGraph` digest contract; the
//! runner-owned sprint-digest-v1 boundary remains frozen in its owning crate.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::path::{Component, Path};

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

use crate::{
    AcceptanceCriterion, AcceptanceKind, CommandSpec, ContractError, Digest, PathScope,
    ProviderProfile, WorkspaceGrant,
};

/// Exact sprint-authority discriminator for the schema-v32 V2 contract family.
pub const SPRINT_AUTHORITY_CONTRACT_VERSION_V2: u32 = 2;
/// Minimum admitted repository-wide final-verification attempt cap.
pub const MIN_FINAL_VERIFICATION_ATTEMPTS: u8 = 1;
/// Maximum admitted repository-wide final-verification attempt cap.
pub const MAX_FINAL_VERIFICATION_ATTEMPTS: u8 = 3;
/// Explicit product-authored v0.1 final-verification attempt cap.
pub const PRODUCT_DEFAULT_MAX_FINAL_VERIFICATION_ATTEMPTS_V01: u8 = 3;
/// Exact discriminator for one schema-v32 final-verification attempt authority.
pub const FINAL_VERIFICATION_ATTEMPT_AUTHORITY_VERSION_V1: u32 = 1;

const SPRINT_SPEC_V2_DIGEST_DOMAIN: &[u8] = b"grok-build/sprint-spec-v2/canonical-json\0";
const TASK_GRAPH_V2_PAYLOAD_DIGEST_DOMAIN: &[u8] =
    b"grok-build/task-graph-v2/payload/canonical-json\0";
const TASK_GRAPH_V2_DIGEST_DOMAIN: &[u8] = b"grok-build/task-graph-v2/canonical-json\0";
const REPAIR_SLOT_RESERVE_V2_DIGEST_DOMAIN: &[u8] =
    b"grok-build/final-verification-repair-slot-reserve-v2/canonical-json\0";
const FINAL_VERIFICATION_ATTEMPT_V1_DIGEST_DOMAIN: &[u8] =
    b"grok-build/final-verification-attempt-authority-v1/canonical-json\0";

/// Frozen pre-schema-v32 sprint budget.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LegacySprintBudgetV1 {
    /// Maximum number of graph tasks.
    pub max_tasks: usize,
    /// Maximum execution attempts for each task.
    pub max_attempts_per_task: u8,
    /// Maximum provider-requested tool calls.
    pub max_tool_calls: u32,
    /// Maximum sprint wall-clock duration.
    pub max_duration_ms: u64,
}

impl LegacySprintBudgetV1 {
    fn validate(self) -> Result<(), ContractError> {
        validate_budget_members(
            self.max_tasks,
            self.max_attempts_per_task,
            self.max_tool_calls,
            self.max_duration_ms,
        )
    }
}

/// Frozen pre-schema-v32 immutable sprint input.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LegacySprintSpecV1 {
    /// Stable sprint identifier.
    pub sprint_id: String,
    /// User-requested outcome.
    pub objective: String,
    /// Conditions required for computed completion.
    pub acceptance_criteria: Vec<AcceptanceCriterion>,
    /// Provider and model configuration.
    pub provider: ProviderProfile,
    /// Historical resource and retry ceilings.
    pub budget: LegacySprintBudgetV1,
    /// Maximum concurrent workers.
    pub max_workers: u8,
    /// Persistent project authority.
    pub workspace_grant: WorkspaceGrant,
    /// Content-addressed snapshot from which planning began.
    pub base_snapshot: Digest,
}

impl LegacySprintSpecV1 {
    /// Validates the frozen pre-schema-v32 contract without granting current authority.
    ///
    /// # Errors
    ///
    /// Returns [`ContractError`] when the bytes describe a sprint that the
    /// historical contract rejected.
    pub fn validate(&self) -> Result<(), ContractError> {
        validate_sprint_identity_acceptance_provider(
            &self.sprint_id,
            &self.objective,
            &self.acceptance_criteria,
            &self.provider,
        )?;
        self.budget.validate()?;
        validate_sprint_workers_and_grant(self.max_workers, &self.workspace_grant)
    }

    /// Returns the exact compact canonical JSON bytes after legacy validation.
    ///
    /// # Errors
    ///
    /// Returns [`ContractError`] when validation or serialization fails.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, ContractError> {
        self.validate()?;
        encode_canonical("legacy_sprint_spec_v1", self)
    }

    /// Decodes only the exact canonical legacy byte shape.
    ///
    /// This loader is diagnostic/readback-only and does not return a current
    /// [`SprintSpecV2`].
    ///
    /// # Errors
    ///
    /// Returns [`ContractError`] for invalid, noncanonical, unknown-field, or
    /// V2 bytes.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, ContractError> {
        decode_canonical("legacy_sprint_spec_v1", bytes, Self::validate)
    }
}

/// Frozen pre-schema-v32 task node.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LegacyTaskSpecV1 {
    /// Stable task identifier.
    pub task_id: String,
    /// Observable task outcome.
    pub goal: String,
    /// Task identifiers that must integrate first.
    pub dependencies: Vec<String>,
    /// Tentative write scopes used for scheduling and leases.
    pub path_scopes: Vec<PathScope>,
    /// Sprint acceptance criterion identifiers this task contributes to.
    pub acceptance_checks: Vec<String>,
    /// Snapshot on which the task was planned.
    pub base_snapshot: Digest,
    /// Whether sprint completion requires this task to integrate.
    pub required: bool,
}

impl LegacyTaskSpecV1 {
    fn validate(&self) -> Result<(), ContractError> {
        validate_task_members(
            &self.task_id,
            &self.goal,
            &self.dependencies,
            &self.path_scopes,
            &self.acceptance_checks,
        )
    }
}

/// Frozen pre-schema-v32 task graph.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LegacyTaskGraphV1 {
    /// Stable graph identifier.
    pub graph_id: String,
    /// Historical graph nodes in canonical declaration order.
    pub tasks: Vec<LegacyTaskSpecV1>,
}

impl LegacyTaskGraphV1 {
    /// Validates the frozen graph against one frozen legacy sprint.
    ///
    /// # Errors
    ///
    /// Returns [`ContractError`] when the historical graph contract rejected
    /// the graph or its sprint linkage.
    pub fn validate_for_sprint(&self, sprint: &LegacySprintSpecV1) -> Result<(), ContractError> {
        sprint.validate()?;
        require_nonblank("task_graph.graph_id", &self.graph_id)?;
        if self.tasks.is_empty() {
            return Err(ContractError::new(
                "task_graph.tasks",
                "must contain at least one task",
            ));
        }
        if self.tasks.len() > sprint.budget.max_tasks {
            return Err(ContractError::new(
                "task_graph.tasks",
                "exceeds the sprint task budget",
            ));
        }
        for task in &self.tasks {
            task.validate()?;
            if task.base_snapshot != sprint.base_snapshot {
                return Err(ContractError::new(
                    "task.base_snapshot",
                    format!("task `{}` must use the sprint base snapshot", task.task_id),
                ));
            }
        }
        validate_graph_relationships(
            &sprint.acceptance_criteria,
            self.tasks.iter().map(|task| TaskRelationshipView {
                task_id: &task.task_id,
                dependencies: &task.dependencies,
                acceptance_checks: &task.acceptance_checks,
            }),
        )
    }

    /// Returns the exact compact canonical JSON bytes after legacy validation.
    ///
    /// # Errors
    ///
    /// Returns [`ContractError`] when validation or serialization fails.
    pub fn canonical_bytes_for_sprint(
        &self,
        sprint: &LegacySprintSpecV1,
    ) -> Result<Vec<u8>, ContractError> {
        self.validate_for_sprint(sprint)?;
        encode_canonical("legacy_task_graph_v1", self)
    }

    /// Decodes only the exact canonical legacy graph byte shape.
    ///
    /// # Errors
    ///
    /// Returns [`ContractError`] for invalid, noncanonical, unknown-field, or
    /// V2 bytes.
    pub fn from_canonical_bytes_for_sprint(
        bytes: &[u8],
        sprint: &LegacySprintSpecV1,
    ) -> Result<Self, ContractError> {
        let graph: Self = decode_canonical_shape("legacy_task_graph_v1", bytes)?;
        graph.validate_for_sprint(sprint)?;
        Ok(graph)
    }
}

/// Schema-v32 sprint budget with a separate repository-verification cap.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SprintBudgetV2 {
    /// Required sprint-authority discriminator.
    pub sprint_authority_version: u32,
    /// Maximum number of graph tasks, including repair-slot reserve.
    pub max_tasks: usize,
    /// Maximum execution attempts for each task.
    pub max_attempts_per_task: u8,
    /// Maximum admitted sprint-scoped final-verification attempts.
    pub max_final_verification_attempts: u8,
    /// Maximum provider-requested tool calls.
    pub max_tool_calls: u32,
    /// Maximum sprint wall-clock duration.
    pub max_duration_ms: u64,
}

impl SprintBudgetV2 {
    /// Authors a v0.1 budget while explicitly writing the product default `3`.
    ///
    /// This is an authoring helper, not a deserialization default. Missing
    /// `max_final_verification_attempts` bytes remain invalid.
    #[must_use]
    pub const fn author_v01(
        max_tasks: usize,
        max_attempts_per_task: u8,
        max_tool_calls: u32,
        max_duration_ms: u64,
    ) -> Self {
        Self {
            sprint_authority_version: SPRINT_AUTHORITY_CONTRACT_VERSION_V2,
            max_tasks,
            max_attempts_per_task,
            max_final_verification_attempts: PRODUCT_DEFAULT_MAX_FINAL_VERIFICATION_ATTEMPTS_V01,
            max_tool_calls,
            max_duration_ms,
        }
    }

    /// Validates all budget bounds, including the explicit `1..=3` cap.
    ///
    /// # Errors
    ///
    /// Returns [`ContractError`] for a version mismatch or zero/out-of-range
    /// budget member.
    pub fn validate(self) -> Result<(), ContractError> {
        require_v2_version(
            "sprint_budget_v2.sprint_authority_version",
            self.sprint_authority_version,
        )?;
        if self.max_tasks == 0 {
            return Err(ContractError::new(
                "sprint_v2.budget.max_tasks",
                "must be greater than zero",
            ));
        }
        if self.max_attempts_per_task == 0 {
            return Err(ContractError::new(
                "sprint_v2.budget.max_attempts_per_task",
                "must be greater than zero",
            ));
        }
        if !(MIN_FINAL_VERIFICATION_ATTEMPTS..=MAX_FINAL_VERIFICATION_ATTEMPTS)
            .contains(&self.max_final_verification_attempts)
        {
            return Err(ContractError::new(
                "sprint_v2.budget.max_final_verification_attempts",
                "must be between one and three",
            ));
        }
        if self.max_tool_calls == 0 {
            return Err(ContractError::new(
                "sprint_v2.budget.max_tool_calls",
                "must be greater than zero",
            ));
        }
        if self.max_duration_ms == 0 {
            return Err(ContractError::new(
                "sprint_v2.budget.max_duration_ms",
                "must be greater than zero",
            ));
        }
        Ok(())
    }
}

/// Schema-v32 immutable sprint input.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SprintSpecV2 {
    /// Required sprint-authority discriminator.
    pub sprint_authority_version: u32,
    /// Stable sprint identifier.
    pub sprint_id: String,
    /// User-requested outcome.
    pub objective: String,
    /// Conditions required for computed completion.
    pub acceptance_criteria: Vec<AcceptanceCriterion>,
    /// Provider and model configuration.
    pub provider: ProviderProfile,
    /// Resource and retry ceilings.
    pub budget: SprintBudgetV2,
    /// Maximum concurrent workers; v0.1 permits one through three.
    pub max_workers: u8,
    /// Persistent project authority.
    pub workspace_grant: WorkspaceGrant,
    /// Content-addressed snapshot from which planning began.
    pub base_snapshot: Digest,
    /// Exact graph identifier paired with this sprint.
    pub task_graph_id: String,
    /// Digest of the graph's canonical payload, excluding only its reciprocal
    /// `sprint_spec_digest` field to avoid a cyclic digest definition.
    pub task_graph_payload_digest: Digest,
    /// Digest of the complete ordered repair-slot reserve.
    pub repair_slot_reserve_digest: Digest,
}

impl SprintSpecV2 {
    /// Validates sprint-local structure and the explicit V2 budget.
    ///
    /// Full graph and repair-reserve linkage is validated by
    /// [`TaskGraphV2::validate_for_sprint`].
    ///
    /// # Errors
    ///
    /// Returns [`ContractError`] for invalid structure, version, or budget.
    pub fn validate(&self) -> Result<(), ContractError> {
        require_v2_version(
            "sprint_spec_v2.sprint_authority_version",
            self.sprint_authority_version,
        )?;
        validate_sprint_identity_acceptance_provider(
            &self.sprint_id,
            &self.objective,
            &self.acceptance_criteria,
            &self.provider,
        )?;
        self.budget.validate()?;
        validate_sprint_workers_and_grant(self.max_workers, &self.workspace_grant)?;
        require_nonblank("sprint_spec_v2.task_graph_id", &self.task_graph_id)
    }

    /// Returns the exact compact canonical V2 bytes after local validation.
    ///
    /// # Errors
    ///
    /// Returns [`ContractError`] when validation or serialization fails.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, ContractError> {
        self.validate()?;
        encode_canonical("sprint_spec_v2", self)
    }

    /// Decodes only exact canonical locally valid V2 sprint bytes.
    ///
    /// # Errors
    ///
    /// Returns [`ContractError`] for missing/unknown fields, wrong versions,
    /// legacy bytes, invalid structure, or noncanonical encoding.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, ContractError> {
        decode_canonical("sprint_spec_v2", bytes, Self::validate)
    }

    /// Computes the domain-separated digest of the complete canonical V2 spec.
    ///
    /// # Errors
    ///
    /// Returns [`ContractError`] when validation or serialization fails.
    pub fn canonical_digest(&self) -> Result<Digest, ContractError> {
        let bytes = self.canonical_bytes()?;
        Ok(domain_digest(SPRINT_SPEC_V2_DIGEST_DOMAIN, &bytes))
    }
}

/// Closed purpose set for a schema-v32 task.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum TaskPurposeV2 {
    /// Ordinary user-objective work.
    Ordinary,
    /// One dormant, ordered final-verification repair slot.
    FinalVerificationRepairSlot {
        /// One-based contiguous slot ordinal.
        slot_ordinal: u8,
    },
}

/// Schema-v32 task node with an explicit purpose.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TaskSpecV2 {
    /// Required sprint-authority discriminator.
    pub sprint_authority_version: u32,
    /// Stable task identifier.
    pub task_id: String,
    /// Typed task purpose.
    pub purpose: TaskPurposeV2,
    /// Observable task outcome.
    pub goal: String,
    /// Task identifiers that must integrate first.
    pub dependencies: Vec<String>,
    /// Tentative write scopes used for scheduling and leases.
    pub path_scopes: Vec<PathScope>,
    /// Sprint acceptance criterion identifiers this task contributes to.
    pub acceptance_checks: Vec<String>,
    /// Snapshot on which the task was planned.
    pub base_snapshot: Digest,
    /// Whether sprint completion requires this task to integrate.
    pub required: bool,
}

impl TaskSpecV2 {
    /// Validates task-local V2 structure and purpose constraints.
    ///
    /// # Errors
    ///
    /// Returns [`ContractError`] for invalid legacy-compatible task structure,
    /// version, repair ordinal, or repair requiredness.
    pub fn validate(&self) -> Result<(), ContractError> {
        require_v2_version(
            "task_spec_v2.sprint_authority_version",
            self.sprint_authority_version,
        )?;
        validate_task_members(
            &self.task_id,
            &self.goal,
            &self.dependencies,
            &self.path_scopes,
            &self.acceptance_checks,
        )?;
        if let TaskPurposeV2::FinalVerificationRepairSlot { slot_ordinal } = self.purpose {
            if slot_ordinal == 0 {
                return Err(ContractError::new(
                    "task_spec_v2.purpose.slot_ordinal",
                    "must be a one-based ordinal",
                ));
            }
            if self.required {
                return Err(ContractError::new(
                    "task_spec_v2.required",
                    "a final-verification repair slot must be optional",
                ));
            }
        }
        Ok(())
    }

    fn is_repair_slot(&self) -> bool {
        matches!(
            self.purpose,
            TaskPurposeV2::FinalVerificationRepairSlot { .. }
        )
    }
}

#[derive(Serialize)]
struct TaskGraphPayloadV2<'a> {
    sprint_authority_version: u32,
    graph_id: &'a str,
    sprint_id: &'a str,
    repair_slot_reserve_digest: &'a Digest,
    tasks: &'a [TaskSpecV2],
}

#[derive(Serialize)]
struct RepairSlotReserveV2<'a> {
    sprint_authority_version: u32,
    sprint_id: &'a str,
    graph_id: &'a str,
    repair_slots: Vec<&'a TaskSpecV2>,
}

/// Schema-v32 task graph with reciprocal sprint and repair-reserve bindings.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TaskGraphV2 {
    /// Required sprint-authority discriminator.
    pub sprint_authority_version: u32,
    /// Stable graph identifier.
    pub graph_id: String,
    /// Stable owning sprint identifier.
    pub sprint_id: String,
    /// Digest of the complete canonical paired [`SprintSpecV2`].
    pub sprint_spec_digest: Digest,
    /// Digest of the complete ordered repair-slot reserve.
    pub repair_slot_reserve_digest: Digest,
    /// Graph nodes in canonical declaration order.
    pub tasks: Vec<TaskSpecV2>,
}

impl TaskGraphV2 {
    /// Computes the domain-separated digest of the ordered repair-slot reserve.
    ///
    /// The reserve includes each complete repair task, so task identity,
    /// ordinal, dependencies, path scopes, checks, base snapshot, and
    /// requiredness are all bound.
    ///
    /// # Errors
    ///
    /// Returns [`ContractError`] when canonical serialization fails.
    pub fn computed_repair_slot_reserve_digest(&self) -> Result<Digest, ContractError> {
        let repair_slots = self
            .tasks
            .iter()
            .filter(|task| task.is_repair_slot())
            .collect();
        digest_canonical(
            "task_graph_v2.repair_slot_reserve",
            REPAIR_SLOT_RESERVE_V2_DIGEST_DOMAIN,
            &RepairSlotReserveV2 {
                sprint_authority_version: self.sprint_authority_version,
                sprint_id: &self.sprint_id,
                graph_id: &self.graph_id,
                repair_slots,
            },
        )
    }

    /// Computes the canonical graph-payload digest used by [`SprintSpecV2`].
    ///
    /// The payload excludes only `sprint_spec_digest`; including that field
    /// would create a cyclic digest definition because the sprint spec itself
    /// binds this payload digest.
    ///
    /// # Errors
    ///
    /// Returns [`ContractError`] when canonical serialization fails.
    pub fn payload_digest(&self) -> Result<Digest, ContractError> {
        digest_canonical(
            "task_graph_v2.payload",
            TASK_GRAPH_V2_PAYLOAD_DIGEST_DOMAIN,
            &TaskGraphPayloadV2 {
                sprint_authority_version: self.sprint_authority_version,
                graph_id: &self.graph_id,
                sprint_id: &self.sprint_id,
                repair_slot_reserve_digest: &self.repair_slot_reserve_digest,
                tasks: &self.tasks,
            },
        )
    }

    /// Validates the complete graph, exact reserve, and reciprocal spec links.
    ///
    /// # Errors
    ///
    /// Returns [`ContractError`] for invalid versions, graph structure,
    /// missing/duplicate/noncontiguous repair slots, bad repair dependencies,
    /// crossed identities, or crossed canonical digests.
    pub fn validate_for_sprint(&self, sprint: &SprintSpecV2) -> Result<(), ContractError> {
        self.validate_graph_shape(sprint)?;
        self.validate_ordinary_criterion_coverage(sprint)?;
        self.validate_repair_slots(sprint)?;
        self.validate_pair_digests(sprint)
    }

    fn validate_graph_shape(&self, sprint: &SprintSpecV2) -> Result<(), ContractError> {
        sprint.validate()?;
        require_v2_version(
            "task_graph_v2.sprint_authority_version",
            self.sprint_authority_version,
        )?;
        require_nonblank("task_graph_v2.graph_id", &self.graph_id)?;
        require_nonblank("task_graph_v2.sprint_id", &self.sprint_id)?;
        if self.sprint_id != sprint.sprint_id {
            return Err(ContractError::new(
                "task_graph_v2.sprint_id",
                "must equal the paired sprint identifier",
            ));
        }
        if self.graph_id != sprint.task_graph_id {
            return Err(ContractError::new(
                "task_graph_v2.graph_id",
                "must equal the paired sprint graph identifier",
            ));
        }
        if self.tasks.is_empty() {
            return Err(ContractError::new(
                "task_graph_v2.tasks",
                "must contain at least one task",
            ));
        }
        if self.tasks.len() > sprint.budget.max_tasks {
            return Err(ContractError::new(
                "task_graph_v2.tasks",
                "exceeds the sprint task budget including repair reserve",
            ));
        }

        let mut task_ids = BTreeSet::new();
        for task in &self.tasks {
            task.validate()?;
            if task.base_snapshot != sprint.base_snapshot {
                return Err(ContractError::new(
                    "task_spec_v2.base_snapshot",
                    format!("task `{}` must use the sprint base snapshot", task.task_id),
                ));
            }
            if !task_ids.insert(task.task_id.as_str()) {
                return Err(ContractError::new(
                    "task_graph_v2.tasks",
                    format!("duplicate task id `{}`", task.task_id),
                ));
            }
        }

        validate_graph_relationships(
            &sprint.acceptance_criteria,
            self.tasks.iter().map(|task| TaskRelationshipView {
                task_id: &task.task_id,
                dependencies: &task.dependencies,
                acceptance_checks: &task.acceptance_checks,
            }),
        )
    }

    fn validate_ordinary_criterion_coverage(
        &self,
        sprint: &SprintSpecV2,
    ) -> Result<(), ContractError> {
        let ordinary_criterion_coverage = self
            .tasks
            .iter()
            .filter(|task| task.purpose == TaskPurposeV2::Ordinary)
            .flat_map(|task| task.acceptance_checks.iter().map(String::as_str))
            .collect::<BTreeSet<_>>();
        let criterion_ids = sprint
            .acceptance_criteria
            .iter()
            .map(|criterion| criterion.criterion_id.as_str())
            .collect::<BTreeSet<_>>();
        if ordinary_criterion_coverage != criterion_ids {
            return Err(ContractError::new(
                "task_graph_v2.ordinary_acceptance_coverage",
                "ordinary tasks must cover the complete sprint criterion set",
            ));
        }
        Ok(())
    }

    fn validate_repair_slots(&self, sprint: &SprintSpecV2) -> Result<(), ContractError> {
        let repair_slots = self
            .tasks
            .iter()
            .filter(|task| task.is_repair_slot())
            .collect::<Vec<_>>();
        let expected_slot_count = usize::from(
            sprint
                .budget
                .max_final_verification_attempts
                .saturating_sub(1),
        );
        if repair_slots.len() != expected_slot_count {
            return Err(ContractError::new(
                "task_graph_v2.repair_slots",
                format!(
                    "must contain exactly {expected_slot_count} slots for the final-verification cap"
                ),
            ));
        }
        let required_ordinary_ids = self
            .tasks
            .iter()
            .filter(|task| task.required && task.purpose == TaskPurposeV2::Ordinary)
            .map(|task| task.task_id.as_str())
            .collect::<BTreeSet<_>>();
        let repair_ids = repair_slots
            .iter()
            .map(|task| task.task_id.as_str())
            .collect::<BTreeSet<_>>();
        for (index, slot) in repair_slots.iter().enumerate() {
            let expected_ordinal = u8::try_from(index + 1).map_err(|_| {
                ContractError::new(
                    "task_graph_v2.repair_slots",
                    "slot ordinal exceeds the supported range",
                )
            })?;
            let TaskPurposeV2::FinalVerificationRepairSlot { slot_ordinal } = slot.purpose else {
                unreachable!("filtered repair slots have repair purpose");
            };
            if slot_ordinal != expected_ordinal {
                return Err(ContractError::new(
                    "task_graph_v2.repair_slots",
                    "slot ordinals must be unique, ordered, and contiguous from one",
                ));
            }
            let dependencies = slot
                .dependencies
                .iter()
                .map(String::as_str)
                .collect::<BTreeSet<_>>();
            if !required_ordinary_ids.is_subset(&dependencies) {
                return Err(ContractError::new(
                    "task_graph_v2.repair_slots",
                    "every repair slot must depend on every required ordinary task",
                ));
            }
            let repair_dependencies = dependencies
                .intersection(&repair_ids)
                .copied()
                .collect::<BTreeSet<_>>();
            let expected_repair_dependencies = if index == 0 {
                BTreeSet::new()
            } else {
                BTreeSet::from([repair_slots[index - 1].task_id.as_str()])
            };
            if repair_dependencies != expected_repair_dependencies {
                return Err(ContractError::new(
                    "task_graph_v2.repair_slots",
                    "each repair slot may depend on exactly the immediately preceding repair slot",
                ));
            }
        }
        Ok(())
    }

    fn validate_pair_digests(&self, sprint: &SprintSpecV2) -> Result<(), ContractError> {
        let reserve_digest = self.computed_repair_slot_reserve_digest()?;
        if self.repair_slot_reserve_digest != reserve_digest
            || sprint.repair_slot_reserve_digest != reserve_digest
        {
            return Err(ContractError::new(
                "task_graph_v2.repair_slot_reserve_digest",
                "graph and sprint must bind the exact ordered repair-slot reserve",
            ));
        }
        if self.payload_digest()? != sprint.task_graph_payload_digest {
            return Err(ContractError::new(
                "sprint_spec_v2.task_graph_payload_digest",
                "does not match the paired canonical graph payload",
            ));
        }
        if sprint.canonical_digest()? != self.sprint_spec_digest {
            return Err(ContractError::new(
                "task_graph_v2.sprint_spec_digest",
                "does not match the complete paired canonical sprint spec",
            ));
        }
        Ok(())
    }

    /// Returns exact compact canonical graph bytes after complete pair validation.
    ///
    /// # Errors
    ///
    /// Returns [`ContractError`] when validation or serialization fails.
    pub fn canonical_bytes_for_sprint(
        &self,
        sprint: &SprintSpecV2,
    ) -> Result<Vec<u8>, ContractError> {
        self.validate_for_sprint(sprint)?;
        encode_canonical("task_graph_v2", self)
    }

    /// Decodes exact canonical graph bytes and validates the complete pair.
    ///
    /// # Errors
    ///
    /// Returns [`ContractError`] for missing/unknown fields, wrong versions,
    /// legacy bytes, noncanonical encoding, or crossed graph/spec authority.
    pub fn from_canonical_bytes_for_sprint(
        bytes: &[u8],
        sprint: &SprintSpecV2,
    ) -> Result<Self, ContractError> {
        let graph: Self = decode_canonical_shape("task_graph_v2", bytes)?;
        graph.validate_for_sprint(sprint)?;
        Ok(graph)
    }

    /// Computes the domain-separated digest of the complete graph envelope.
    ///
    /// # Errors
    ///
    /// Returns [`ContractError`] when pair validation or serialization fails.
    pub fn canonical_digest_for_sprint(
        &self,
        sprint: &SprintSpecV2,
    ) -> Result<Digest, ContractError> {
        let bytes = self.canonical_bytes_for_sprint(sprint)?;
        Ok(domain_digest(TASK_GRAPH_V2_DIGEST_DOMAIN, &bytes))
    }
}

/// Immutable provenance recorded when core admits a final-verification attempt.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FinalVerificationAttemptProvenanceV1 {
    /// Coordinator process instance that held admission authority.
    pub coordinator_instance_id: String,
    /// Exact admission event identity.
    pub admission_event_id: String,
    /// Exact contiguous sprint event sequence used for admission.
    pub admission_event_sequence: u64,
    /// Durable admission timestamp.
    pub admitted_at_unix_ms: u64,
}

impl FinalVerificationAttemptProvenanceV1 {
    fn validate(&self) -> Result<(), ContractError> {
        require_nonblank(
            "final_verification_attempt_v1.provenance.coordinator_instance_id",
            &self.coordinator_instance_id,
        )?;
        require_nonblank(
            "final_verification_attempt_v1.provenance.admission_event_id",
            &self.admission_event_id,
        )?;
        require_nonzero(
            "final_verification_attempt_v1.provenance.admission_event_sequence",
            self.admission_event_sequence,
        )?;
        require_nonzero(
            "final_verification_attempt_v1.provenance.admitted_at_unix_ms",
            self.admitted_at_unix_ms,
        )
    }
}

/// Complete predecessor authority for a follow-up final-verification attempt.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum FinalVerificationAttemptPredecessorV1 {
    /// First admitted final-verification attempt.
    Initial,
    /// Same-snapshot continuation after exact failure before any effect.
    SameSnapshotAfterFailedBeforeEffect {
        /// Exact prior attempt identity.
        prior_attempt_id: String,
        /// Exact closure proving the prior attempt ended before effect.
        closure_id: String,
    },
    /// Same-snapshot continuation after authenticated pre-effect control.
    SameSnapshotAfterControlInterruption {
        /// Exact prior attempt identity.
        prior_attempt_id: String,
        /// Exact authenticated control record.
        control_id: String,
        /// Exact complete closure record.
        closure_id: String,
    },
    /// Changed-snapshot continuation after one predeclared repair slot.
    ChangedSnapshotAfterRepair {
        /// Exact typed prior failure identity.
        prior_failure_id: String,
        /// Exact repair-slot activation/admission identity.
        repair_admission_id: String,
        /// Fresh repair-slot `TaskDone` proof identity.
        repair_task_done_proof_id: String,
        /// Exact changed-snapshot integration receipt identity.
        integration_receipt_id: String,
    },
}

impl FinalVerificationAttemptPredecessorV1 {
    fn validate(&self) -> Result<(), ContractError> {
        match self {
            Self::Initial => Ok(()),
            Self::SameSnapshotAfterFailedBeforeEffect {
                prior_attempt_id,
                closure_id,
            } => {
                require_nonblank(
                    "final_verification_attempt_v1.predecessor.prior_attempt_id",
                    prior_attempt_id,
                )?;
                require_nonblank(
                    "final_verification_attempt_v1.predecessor.closure_id",
                    closure_id,
                )
            }
            Self::SameSnapshotAfterControlInterruption {
                prior_attempt_id,
                control_id,
                closure_id,
            } => {
                require_nonblank(
                    "final_verification_attempt_v1.predecessor.prior_attempt_id",
                    prior_attempt_id,
                )?;
                require_nonblank(
                    "final_verification_attempt_v1.predecessor.control_id",
                    control_id,
                )?;
                require_nonblank(
                    "final_verification_attempt_v1.predecessor.closure_id",
                    closure_id,
                )
            }
            Self::ChangedSnapshotAfterRepair {
                prior_failure_id,
                repair_admission_id,
                repair_task_done_proof_id,
                integration_receipt_id,
            } => {
                for (field, value) in [
                    (
                        "final_verification_attempt_v1.predecessor.prior_failure_id",
                        prior_failure_id,
                    ),
                    (
                        "final_verification_attempt_v1.predecessor.repair_admission_id",
                        repair_admission_id,
                    ),
                    (
                        "final_verification_attempt_v1.predecessor.repair_task_done_proof_id",
                        repair_task_done_proof_id,
                    ),
                    (
                        "final_verification_attempt_v1.predecessor.integration_receipt_id",
                        integration_receipt_id,
                    ),
                ] {
                    require_nonblank(field, value)?;
                }
                Ok(())
            }
        }
    }
}

/// Trusted expected inputs against which an attempt authority is crossed.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FinalVerificationAttemptExpectedInputsV1 {
    /// Fresh attempt identity minted by core for this admission.
    pub attempt_id: String,
    /// Next contiguous sprint-local ordinal computed by the ledger.
    pub attempt_ordinal: u8,
    /// Fresh final-verification admission identity minted by core.
    pub final_verification_admission_id: String,
    /// Exact integration snapshot to verify.
    pub input_snapshot: Digest,
    /// Exact repository-wide verification command.
    pub final_verification_check: CommandSpec,
    /// Exact execution policy digest.
    pub execution_policy_digest: Digest,
    /// Digest of the complete current `TaskDone` set.
    pub complete_task_done_set_digest: Digest,
    /// Digest of the complete same-snapshot criterion-evidence set.
    pub complete_criterion_evidence_set_digest: Digest,
    /// Exact core admission provenance.
    pub provenance: FinalVerificationAttemptProvenanceV1,
    /// Exact core-derived predecessor authority.
    pub predecessor: FinalVerificationAttemptPredecessorV1,
}

/// Immutable schema-v32 authority for one admitted final-verification attempt.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FinalVerificationAttemptAuthorityV1 {
    /// Required attempt-authority discriminator.
    pub authority_version: u32,
    /// Stable fresh attempt identity.
    pub attempt_id: String,
    /// Owning sprint identity.
    pub sprint_id: String,
    /// One-based contiguous sprint-local attempt ordinal.
    pub attempt_ordinal: u8,
    /// Immutable cap copied from the paired sprint budget.
    pub max_final_verification_attempts: u8,
    /// Exact admission identity for this fresh attempt.
    pub final_verification_admission_id: String,
    /// Exact snapshot tested by this attempt.
    pub input_snapshot: Digest,
    /// Digest of the complete current `TaskDone` set.
    pub complete_task_done_set_digest: Digest,
    /// Digest of the complete same-snapshot criterion-evidence set.
    pub complete_criterion_evidence_set_digest: Digest,
    /// Exact repository-wide verification command.
    pub final_verification_check: CommandSpec,
    /// Exact runner execution-policy digest.
    pub execution_policy_digest: Digest,
    /// Core admission provenance.
    pub provenance: FinalVerificationAttemptProvenanceV1,
    /// Complete source of initial or follow-up authority.
    pub predecessor: FinalVerificationAttemptPredecessorV1,
}

impl FinalVerificationAttemptAuthorityV1 {
    /// Validates the attempt's intrinsic shape, cap, and ordinal/predecessor relation.
    ///
    /// # Errors
    ///
    /// Returns [`ContractError`] for unsupported versions, blank identities,
    /// invalid caps/ordinals, invalid command/provenance, or an impossible
    /// initial/follow-up predecessor shape.
    pub fn validate(&self) -> Result<(), ContractError> {
        if self.authority_version != FINAL_VERIFICATION_ATTEMPT_AUTHORITY_VERSION_V1 {
            return Err(ContractError::new(
                "final_verification_attempt_v1.authority_version",
                format!(
                    "expected version {FINAL_VERIFICATION_ATTEMPT_AUTHORITY_VERSION_V1}, got {}",
                    self.authority_version
                ),
            ));
        }
        require_nonblank("final_verification_attempt_v1.attempt_id", &self.attempt_id)?;
        require_nonblank("final_verification_attempt_v1.sprint_id", &self.sprint_id)?;
        require_nonblank(
            "final_verification_attempt_v1.final_verification_admission_id",
            &self.final_verification_admission_id,
        )?;
        if !(MIN_FINAL_VERIFICATION_ATTEMPTS..=MAX_FINAL_VERIFICATION_ATTEMPTS)
            .contains(&self.max_final_verification_attempts)
        {
            return Err(ContractError::new(
                "final_verification_attempt_v1.max_final_verification_attempts",
                "must be between one and three",
            ));
        }
        if self.attempt_ordinal == 0 || self.attempt_ordinal > self.max_final_verification_attempts
        {
            return Err(ContractError::new(
                "final_verification_attempt_v1.attempt_ordinal",
                "must be one-based and no greater than the immutable cap",
            ));
        }
        self.final_verification_check.validate()?;
        self.provenance.validate()?;
        self.predecessor.validate()?;
        match (&self.predecessor, self.attempt_ordinal) {
            (FinalVerificationAttemptPredecessorV1::Initial, 1) => Ok(()),
            (FinalVerificationAttemptPredecessorV1::Initial, _) => Err(ContractError::new(
                "final_verification_attempt_v1.predecessor",
                "Initial is valid only for ordinal one",
            )),
            (_, 1) => Err(ContractError::new(
                "final_verification_attempt_v1.predecessor",
                "ordinal one must use Initial",
            )),
            _ => Ok(()),
        }
    }

    /// Crosses this authority against the exact trusted sprint/graph inputs.
    ///
    /// # Errors
    ///
    /// Returns [`ContractError`] for any crossed sprint, cap, ordinal,
    /// snapshot, command, policy, complete-set digest, or provenance.
    pub fn validate_for(
        &self,
        sprint: &SprintSpecV2,
        graph: &TaskGraphV2,
        expected: &FinalVerificationAttemptExpectedInputsV1,
    ) -> Result<(), ContractError> {
        self.validate()?;
        graph.validate_for_sprint(sprint)?;
        if self.sprint_id != sprint.sprint_id {
            return Err(ContractError::new(
                "final_verification_attempt_v1.sprint_id",
                "must equal the current sprint identity",
            ));
        }
        if self.max_final_verification_attempts != sprint.budget.max_final_verification_attempts {
            return Err(ContractError::new(
                "final_verification_attempt_v1.max_final_verification_attempts",
                "must equal the immutable sprint cap",
            ));
        }
        if self.attempt_id != expected.attempt_id {
            return Err(ContractError::new(
                "final_verification_attempt_v1.attempt_id",
                "must equal the fresh core-minted attempt identity",
            ));
        }
        if self.attempt_ordinal != expected.attempt_ordinal {
            return Err(ContractError::new(
                "final_verification_attempt_v1.attempt_ordinal",
                "must equal the next contiguous ledger-derived ordinal",
            ));
        }
        if self.final_verification_admission_id != expected.final_verification_admission_id {
            return Err(ContractError::new(
                "final_verification_attempt_v1.final_verification_admission_id",
                "must equal the fresh core-minted admission identity",
            ));
        }
        if self.input_snapshot != expected.input_snapshot {
            return Err(ContractError::new(
                "final_verification_attempt_v1.input_snapshot",
                "must equal the exact integration snapshot selected for verification",
            ));
        }
        if self.final_verification_check != expected.final_verification_check {
            return Err(ContractError::new(
                "final_verification_attempt_v1.final_verification_check",
                "must equal the exact repository-wide check",
            ));
        }
        if self.execution_policy_digest != expected.execution_policy_digest {
            return Err(ContractError::new(
                "final_verification_attempt_v1.execution_policy_digest",
                "must equal the exact admitted execution policy",
            ));
        }
        if self.complete_task_done_set_digest != expected.complete_task_done_set_digest {
            return Err(ContractError::new(
                "final_verification_attempt_v1.complete_task_done_set_digest",
                "must equal the complete current TaskDone-set digest",
            ));
        }
        if self.complete_criterion_evidence_set_digest
            != expected.complete_criterion_evidence_set_digest
        {
            return Err(ContractError::new(
                "final_verification_attempt_v1.complete_criterion_evidence_set_digest",
                "must equal the complete same-snapshot criterion-evidence-set digest",
            ));
        }
        if self.provenance != expected.provenance {
            return Err(ContractError::new(
                "final_verification_attempt_v1.provenance",
                "must equal the exact core admission provenance",
            ));
        }
        if self.predecessor != expected.predecessor {
            return Err(ContractError::new(
                "final_verification_attempt_v1.predecessor",
                "must equal the exact core-derived predecessor authority",
            ));
        }
        Ok(())
    }

    /// Validates immutable successor linkage to the immediately prior attempt.
    ///
    /// # Errors
    ///
    /// Returns [`ContractError`] for crossed sprint/cap/ordinal/check/policy or
    /// predecessor linkage, for same-snapshot variants that change bound
    /// evidence, or for a repair variant that does not change snapshot and
    /// complete evidence sets.
    pub fn validate_successor_of(&self, prior: &Self) -> Result<(), ContractError> {
        self.validate()?;
        prior.validate()?;
        if self.sprint_id != prior.sprint_id
            || self.max_final_verification_attempts != prior.max_final_verification_attempts
            || self.final_verification_check != prior.final_verification_check
            || self.execution_policy_digest != prior.execution_policy_digest
        {
            return Err(ContractError::new(
                "final_verification_attempt_v1.predecessor",
                "successor crosses immutable sprint, cap, check, or policy authority",
            ));
        }
        if self.attempt_ordinal != prior.attempt_ordinal.saturating_add(1) {
            return Err(ContractError::new(
                "final_verification_attempt_v1.attempt_ordinal",
                "successor ordinal must be exactly prior ordinal plus one",
            ));
        }
        match &self.predecessor {
            FinalVerificationAttemptPredecessorV1::Initial => Err(ContractError::new(
                "final_verification_attempt_v1.predecessor",
                "a successor cannot use Initial",
            )),
            FinalVerificationAttemptPredecessorV1::SameSnapshotAfterFailedBeforeEffect {
                prior_attempt_id,
                ..
            }
            | FinalVerificationAttemptPredecessorV1::SameSnapshotAfterControlInterruption {
                prior_attempt_id,
                ..
            } => {
                if prior_attempt_id != &prior.attempt_id
                    || self.input_snapshot != prior.input_snapshot
                    || self.complete_task_done_set_digest != prior.complete_task_done_set_digest
                    || self.complete_criterion_evidence_set_digest
                        != prior.complete_criterion_evidence_set_digest
                {
                    return Err(ContractError::new(
                        "final_verification_attempt_v1.predecessor",
                        "same-snapshot successor must bind the prior attempt and unchanged complete sets",
                    ));
                }
                Ok(())
            }
            FinalVerificationAttemptPredecessorV1::ChangedSnapshotAfterRepair { .. } => {
                if self.input_snapshot == prior.input_snapshot
                    || self.complete_task_done_set_digest == prior.complete_task_done_set_digest
                    || self.complete_criterion_evidence_set_digest
                        == prior.complete_criterion_evidence_set_digest
                {
                    return Err(ContractError::new(
                        "final_verification_attempt_v1.predecessor",
                        "repair successor requires changed snapshot and fresh complete evidence sets",
                    ));
                }
                Ok(())
            }
        }
    }

    /// Returns exact compact canonical attempt-authority bytes.
    ///
    /// # Errors
    ///
    /// Returns [`ContractError`] when validation or serialization fails.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, ContractError> {
        self.validate()?;
        encode_canonical("final_verification_attempt_v1", self)
    }

    /// Decodes only exact canonical attempt-authority bytes.
    ///
    /// # Errors
    ///
    /// Returns [`ContractError`] for invalid, unknown-field, or noncanonical
    /// bytes.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, ContractError> {
        decode_canonical("final_verification_attempt_v1", bytes, Self::validate)
    }

    /// Computes the domain-separated digest of the complete canonical authority.
    ///
    /// # Errors
    ///
    /// Returns [`ContractError`] when validation or serialization fails.
    pub fn canonical_digest(&self) -> Result<Digest, ContractError> {
        let bytes = self.canonical_bytes()?;
        Ok(domain_digest(
            FINAL_VERIFICATION_ATTEMPT_V1_DIGEST_DOMAIN,
            &bytes,
        ))
    }
}

fn validate_budget_members(
    max_tasks: usize,
    max_attempts_per_task: u8,
    max_tool_calls: u32,
    max_duration_ms: u64,
) -> Result<(), ContractError> {
    if max_tasks == 0 {
        return Err(ContractError::new(
            "sprint.budget.max_tasks",
            "must be greater than zero",
        ));
    }
    if max_attempts_per_task == 0 {
        return Err(ContractError::new(
            "sprint.budget.max_attempts_per_task",
            "must be greater than zero",
        ));
    }
    if max_tool_calls == 0 {
        return Err(ContractError::new(
            "sprint.budget.max_tool_calls",
            "must be greater than zero",
        ));
    }
    if max_duration_ms == 0 {
        return Err(ContractError::new(
            "sprint.budget.max_duration_ms",
            "must be greater than zero",
        ));
    }
    Ok(())
}

fn validate_sprint_identity_acceptance_provider(
    sprint_id: &str,
    objective: &str,
    acceptance_criteria: &[AcceptanceCriterion],
    provider: &ProviderProfile,
) -> Result<(), ContractError> {
    require_nonblank("sprint.sprint_id", sprint_id)?;
    require_nonblank("sprint.objective", objective)?;
    if acceptance_criteria.is_empty() {
        return Err(ContractError::new(
            "sprint.acceptance_criteria",
            "must contain at least one criterion",
        ));
    }
    let mut criterion_ids = BTreeSet::new();
    for criterion in acceptance_criteria {
        require_nonblank("acceptance.criterion_id", &criterion.criterion_id)?;
        require_nonblank("acceptance.description", &criterion.description)?;
        if let AcceptanceKind::Automated(command) = &criterion.kind {
            command.validate()?;
        }
        if !criterion_ids.insert(criterion.criterion_id.as_str()) {
            return Err(ContractError::new(
                "sprint.acceptance_criteria",
                format!("duplicate criterion id `{}`", criterion.criterion_id),
            ));
        }
    }
    require_nonblank("provider.backend_id", &provider.backend_id)?;
    require_nonblank("provider.model_id", &provider.model_id)
}

fn validate_sprint_workers_and_grant(
    max_workers: u8,
    workspace_grant: &WorkspaceGrant,
) -> Result<(), ContractError> {
    if !(1..=3).contains(&max_workers) {
        return Err(ContractError::new(
            "sprint.max_workers",
            "must be between one and three",
        ));
    }
    workspace_grant.validate()
}

fn validate_task_members(
    task_id: &str,
    goal: &str,
    dependencies: &[String],
    path_scopes: &[PathScope],
    acceptance_checks: &[String],
) -> Result<(), ContractError> {
    require_nonblank("task.task_id", task_id)?;
    require_nonblank("task.goal", goal)?;
    if path_scopes.is_empty() {
        return Err(ContractError::new(
            "task.path_scopes",
            "must declare at least one scope",
        ));
    }
    let mut scopes = BTreeSet::new();
    for scope in path_scopes {
        if let PathScope::Relative(path) = scope {
            require_normalized_relative("task.path_scope", path)?;
        }
        if !scopes.insert(scope) {
            return Err(ContractError::new(
                "task.path_scopes",
                "must not contain duplicate scopes",
            ));
        }
    }
    if acceptance_checks.is_empty() {
        return Err(ContractError::new(
            "task.acceptance_checks",
            "must contain at least one criterion id",
        ));
    }
    require_unique_nonblank("task.dependencies", dependencies)?;
    require_unique_nonblank("task.acceptance_checks", acceptance_checks)
}

#[derive(Clone, Copy)]
struct TaskRelationshipView<'a> {
    task_id: &'a str,
    dependencies: &'a [String],
    acceptance_checks: &'a [String],
}

fn validate_graph_relationships<'a>(
    acceptance_criteria: &[AcceptanceCriterion],
    tasks: impl IntoIterator<Item = TaskRelationshipView<'a>>,
) -> Result<(), ContractError> {
    let tasks = tasks.into_iter().collect::<Vec<_>>();
    let mut task_indices = BTreeMap::new();
    for (index, task) in tasks.iter().enumerate() {
        if task_indices.insert(task.task_id, index).is_some() {
            return Err(ContractError::new(
                "task_graph.tasks",
                format!("duplicate task id `{}`", task.task_id),
            ));
        }
    }
    let criterion_ids = acceptance_criteria
        .iter()
        .map(|criterion| criterion.criterion_id.as_str())
        .collect::<BTreeSet<_>>();
    let mut covered_criteria = BTreeSet::new();
    let mut indegrees = vec![0_usize; tasks.len()];
    let mut dependents = vec![Vec::new(); tasks.len()];
    for (index, task) in tasks.iter().enumerate() {
        validate_task_references(
            task,
            index,
            &task_indices,
            &criterion_ids,
            &mut covered_criteria,
            &mut indegrees,
            &mut dependents,
        )?;
    }
    if covered_criteria != criterion_ids {
        let missing = criterion_ids
            .difference(&covered_criteria)
            .copied()
            .collect::<Vec<_>>()
            .join(", ");
        return Err(ContractError::new(
            "task_graph.acceptance_coverage",
            format!("criteria not covered by any task: {missing}"),
        ));
    }
    validate_acyclic_graph(indegrees, &dependents)
}

fn validate_task_references<'a>(
    task: &TaskRelationshipView<'a>,
    index: usize,
    task_indices: &BTreeMap<&'a str, usize>,
    criterion_ids: &BTreeSet<&str>,
    covered_criteria: &mut BTreeSet<&'a str>,
    indegrees: &mut [usize],
    dependents: &mut [Vec<usize>],
) -> Result<(), ContractError> {
    for criterion_id in task.acceptance_checks {
        if !criterion_ids.contains(criterion_id.as_str()) {
            return Err(ContractError::new(
                "task.acceptance_checks",
                format!("unknown criterion id `{criterion_id}`"),
            ));
        }
        covered_criteria.insert(criterion_id);
    }
    for dependency_id in task.dependencies {
        let Some(&dependency_index) = task_indices.get(dependency_id.as_str()) else {
            return Err(ContractError::new(
                "task.dependencies",
                format!("unknown dependency `{dependency_id}`"),
            ));
        };
        if dependency_index == index {
            return Err(ContractError::new(
                "task.dependencies",
                "a task cannot depend on itself",
            ));
        }
        indegrees[index] += 1;
        dependents[dependency_index].push(index);
    }
    Ok(())
}

fn validate_acyclic_graph(
    mut indegrees: Vec<usize>,
    dependents: &[Vec<usize>],
) -> Result<(), ContractError> {
    let mut ready = indegrees
        .iter()
        .enumerate()
        .filter_map(|(index, &degree)| (degree == 0).then_some(index))
        .collect::<VecDeque<_>>();
    let mut visited = 0_usize;
    while let Some(index) = ready.pop_front() {
        visited += 1;
        for &dependent in &dependents[index] {
            indegrees[dependent] -= 1;
            if indegrees[dependent] == 0 {
                ready.push_back(dependent);
            }
        }
    }
    if visited != indegrees.len() {
        return Err(ContractError::new(
            "task_graph.tasks",
            "dependencies must form an acyclic graph",
        ));
    }
    Ok(())
}

fn require_unique_nonblank(field: &'static str, values: &[String]) -> Result<(), ContractError> {
    let mut unique = BTreeSet::new();
    for value in values {
        require_nonblank(field, value)?;
        if !unique.insert(value.as_str()) {
            return Err(ContractError::new(
                field,
                format!("duplicate identifier `{value}`"),
            ));
        }
    }
    Ok(())
}

fn require_normalized_relative(field: &'static str, path: &Path) -> Result<(), ContractError> {
    if path.to_str().is_none() {
        return Err(ContractError::new(
            field,
            "must be exactly representable as UTF-8",
        ));
    }
    if path.as_os_str().is_empty() || path.is_absolute() {
        return Err(ContractError::new(
            field,
            "must be a non-empty workspace-relative path",
        ));
    }
    if path
        .components()
        .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err(ContractError::new(
            field,
            "must contain only normalized relative components",
        ));
    }
    Ok(())
}

fn require_v2_version(field: &'static str, version: u32) -> Result<(), ContractError> {
    if version == SPRINT_AUTHORITY_CONTRACT_VERSION_V2 {
        Ok(())
    } else {
        Err(ContractError::new(
            field,
            format!("expected version {SPRINT_AUTHORITY_CONTRACT_VERSION_V2}, got {version}"),
        ))
    }
}

fn require_nonblank(field: &'static str, value: &str) -> Result<(), ContractError> {
    if value.trim().is_empty() {
        Err(ContractError::new(field, "must not be blank"))
    } else {
        Ok(())
    }
}

fn require_nonzero(field: &'static str, value: u64) -> Result<(), ContractError> {
    if value == 0 {
        Err(ContractError::new(field, "must be greater than zero"))
    } else {
        Ok(())
    }
}

fn encode_canonical<T: Serialize + ?Sized>(
    field: &'static str,
    value: &T,
) -> Result<Vec<u8>, ContractError> {
    serde_json::to_vec(value).map_err(|error| {
        ContractError::new(field, format!("cannot encode canonical JSON: {error}"))
    })
}

fn decode_canonical<T>(
    field: &'static str,
    bytes: &[u8],
    validate: impl FnOnce(&T) -> Result<(), ContractError>,
) -> Result<T, ContractError>
where
    T: DeserializeOwned + Serialize,
{
    let value = decode_canonical_shape(field, bytes)?;
    validate(&value)?;
    Ok(value)
}

fn decode_canonical_shape<T>(field: &'static str, bytes: &[u8]) -> Result<T, ContractError>
where
    T: DeserializeOwned + Serialize,
{
    let value: T = serde_json::from_slice(bytes)
        .map_err(|error| ContractError::new(field, format!("cannot decode JSON: {error}")))?;
    let canonical = encode_canonical(field, &value)?;
    if canonical != bytes {
        return Err(ContractError::new(
            field,
            "JSON bytes are not the exact canonical encoding",
        ));
    }
    Ok(value)
}

fn digest_canonical<T: Serialize + ?Sized>(
    field: &'static str,
    domain: &[u8],
    value: &T,
) -> Result<Digest, ContractError> {
    let bytes = encode_canonical(field, value)?;
    Ok(domain_digest(domain, &bytes))
}

fn domain_digest(domain: &[u8], canonical: &[u8]) -> Digest {
    let mut preimage = Vec::with_capacity(domain.len() + 8 + canonical.len());
    preimage.extend_from_slice(domain);
    preimage.extend_from_slice(
        &u64::try_from(canonical.len())
            .expect("supported targets use at most 64-bit usize")
            .to_be_bytes(),
    );
    preimage.extend_from_slice(canonical);
    Digest::sha256(&preimage)
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use crate::{
        ExecutionOrigin, SprintBudget, SprintSpec, TaskGraph, TaskSpec, WorkspaceNetworkPolicy,
        WorkspacePermissions,
    };

    use super::*;

    fn digest(character: char) -> Digest {
        Digest::parse(character.to_string().repeat(64)).expect("valid digest")
    }

    fn criterion() -> AcceptanceCriterion {
        AcceptanceCriterion {
            criterion_id: "tests-pass".into(),
            description: "Focused tests pass".into(),
            kind: AcceptanceKind::Automated(CommandSpec {
                program: "cargo".into(),
                arguments: vec!["test".into()],
                working_directory: PathBuf::new(),
            }),
        }
    }

    fn provider() -> ProviderProfile {
        ProviderProfile {
            backend_id: "fake".into(),
            model_id: "deterministic-v1".into(),
            execution_origin: ExecutionOrigin::HostIsolated,
        }
    }

    fn grant() -> WorkspaceGrant {
        WorkspaceGrant {
            grant_id: "grant-1".into(),
            canonical_root: PathBuf::from("/work/project"),
            permissions: WorkspacePermissions::trusted(),
            network: WorkspaceNetworkPolicy::Denied,
            policy_version: 1,
            grant_hash: digest('a'),
        }
    }

    fn legacy_sprint() -> LegacySprintSpecV1 {
        LegacySprintSpecV1 {
            sprint_id: "sprint-legacy-1".into(),
            objective: "Implement feature".into(),
            acceptance_criteria: vec![criterion()],
            provider: provider(),
            budget: LegacySprintBudgetV1 {
                max_tasks: 8,
                max_attempts_per_task: 3,
                max_tool_calls: 100,
                max_duration_ms: 60_000,
            },
            max_workers: 1,
            workspace_grant: grant(),
            base_snapshot: digest('b'),
        }
    }

    fn legacy_graph() -> LegacyTaskGraphV1 {
        LegacyTaskGraphV1 {
            graph_id: "graph-legacy-1".into(),
            tasks: vec![LegacyTaskSpecV1 {
                task_id: "task-ordinary-1".into(),
                goal: "Implement feature".into(),
                dependencies: Vec::new(),
                path_scopes: vec![PathScope::Relative(PathBuf::from("src"))],
                acceptance_checks: vec!["tests-pass".into()],
                base_snapshot: digest('b'),
                required: true,
            }],
        }
    }

    fn existing_v1_sprint() -> SprintSpec {
        SprintSpec {
            sprint_id: "sprint-legacy-1".into(),
            objective: "Implement feature".into(),
            acceptance_criteria: vec![criterion()],
            provider: provider(),
            budget: SprintBudget {
                max_tasks: 8,
                max_attempts_per_task: 3,
                max_tool_calls: 100,
                max_duration_ms: 60_000,
            },
            max_workers: 1,
            workspace_grant: grant(),
            base_snapshot: digest('b'),
        }
    }

    fn existing_v1_graph() -> TaskGraph {
        TaskGraph {
            graph_id: "graph-legacy-1".into(),
            tasks: vec![TaskSpec {
                task_id: "task-ordinary-1".into(),
                goal: "Implement feature".into(),
                dependencies: Vec::new(),
                path_scopes: vec![PathScope::Relative(PathBuf::from("src"))],
                acceptance_checks: vec!["tests-pass".into()],
                base_snapshot: digest('b'),
                required: true,
            }],
        }
    }

    fn repair_task(slot_ordinal: u8, dependencies: &[&str]) -> TaskSpecV2 {
        TaskSpecV2 {
            sprint_authority_version: SPRINT_AUTHORITY_CONTRACT_VERSION_V2,
            task_id: format!("repair-{slot_ordinal}"),
            purpose: TaskPurposeV2::FinalVerificationRepairSlot { slot_ordinal },
            goal: format!("Repair final verification attempt {slot_ordinal}"),
            dependencies: dependencies.iter().map(ToString::to_string).collect(),
            path_scopes: vec![PathScope::Workspace],
            acceptance_checks: vec!["tests-pass".into()],
            base_snapshot: digest('b'),
            required: false,
        }
    }

    fn v2_pair(cap: u8) -> (SprintSpecV2, TaskGraphV2) {
        let mut tasks = vec![TaskSpecV2 {
            sprint_authority_version: SPRINT_AUTHORITY_CONTRACT_VERSION_V2,
            task_id: "ordinary-1".into(),
            purpose: TaskPurposeV2::Ordinary,
            goal: "Implement feature".into(),
            dependencies: Vec::new(),
            path_scopes: vec![PathScope::Relative(PathBuf::from("src"))],
            acceptance_checks: vec!["tests-pass".into()],
            base_snapshot: digest('b'),
            required: true,
        }];
        if cap >= 2 {
            tasks.push(repair_task(1, &["ordinary-1"]));
        }
        if cap >= 3 {
            tasks.push(repair_task(2, &["ordinary-1", "repair-1"]));
        }
        let mut graph = TaskGraphV2 {
            sprint_authority_version: SPRINT_AUTHORITY_CONTRACT_VERSION_V2,
            graph_id: "graph-v2-1".into(),
            sprint_id: "sprint-v2-1".into(),
            sprint_spec_digest: digest('0'),
            repair_slot_reserve_digest: digest('0'),
            tasks,
        };
        graph.repair_slot_reserve_digest = graph
            .computed_repair_slot_reserve_digest()
            .expect("compute repair reserve");
        let spec = SprintSpecV2 {
            sprint_authority_version: SPRINT_AUTHORITY_CONTRACT_VERSION_V2,
            sprint_id: graph.sprint_id.clone(),
            objective: "Implement feature".into(),
            acceptance_criteria: vec![criterion()],
            provider: provider(),
            budget: SprintBudgetV2 {
                sprint_authority_version: SPRINT_AUTHORITY_CONTRACT_VERSION_V2,
                max_tasks: graph.tasks.len(),
                max_attempts_per_task: 3,
                max_final_verification_attempts: cap,
                max_tool_calls: 100,
                max_duration_ms: 60_000,
            },
            max_workers: 1,
            workspace_grant: grant(),
            base_snapshot: digest('b'),
            task_graph_id: graph.graph_id.clone(),
            task_graph_payload_digest: graph.payload_digest().expect("graph payload digest"),
            repair_slot_reserve_digest: graph.repair_slot_reserve_digest.clone(),
        };
        graph.sprint_spec_digest = spec.canonical_digest().expect("sprint spec digest");
        (spec, graph)
    }

    fn rebind_v2_pair(spec: &mut SprintSpecV2, graph: &mut TaskGraphV2) {
        graph.repair_slot_reserve_digest = graph
            .computed_repair_slot_reserve_digest()
            .expect("recompute repair reserve");
        spec.sprint_id.clone_from(&graph.sprint_id);
        spec.task_graph_id.clone_from(&graph.graph_id);
        spec.repair_slot_reserve_digest
            .clone_from(&graph.repair_slot_reserve_digest);
        spec.task_graph_payload_digest = graph.payload_digest().expect("recompute graph payload");
        graph.sprint_spec_digest = spec.canonical_digest().expect("recompute sprint digest");
    }

    fn provenance(sequence: u64) -> FinalVerificationAttemptProvenanceV1 {
        FinalVerificationAttemptProvenanceV1 {
            coordinator_instance_id: "coordinator-1".into(),
            admission_event_id: format!("event-{sequence}"),
            admission_event_sequence: sequence,
            admitted_at_unix_ms: 1_000 + sequence,
        }
    }

    fn attempt(
        ordinal: u8,
        snapshot: char,
        task_done: char,
        criterion_evidence: char,
        predecessor: FinalVerificationAttemptPredecessorV1,
    ) -> FinalVerificationAttemptAuthorityV1 {
        FinalVerificationAttemptAuthorityV1 {
            authority_version: FINAL_VERIFICATION_ATTEMPT_AUTHORITY_VERSION_V1,
            attempt_id: format!("final-attempt-{ordinal}"),
            sprint_id: "sprint-v2-1".into(),
            attempt_ordinal: ordinal,
            max_final_verification_attempts: 3,
            final_verification_admission_id: format!("final-admission-{ordinal}"),
            input_snapshot: digest(snapshot),
            complete_task_done_set_digest: digest(task_done),
            complete_criterion_evidence_set_digest: digest(criterion_evidence),
            final_verification_check: CommandSpec {
                program: "cargo".into(),
                arguments: vec!["test".into(), "--workspace".into()],
                working_directory: PathBuf::new(),
            },
            execution_policy_digest: digest('e'),
            provenance: provenance(u64::from(ordinal)),
            predecessor,
        }
    }

    #[test]
    fn legacy_v1_sprint_and_graph_bytes_are_golden_and_match_pre_v32_dtos() {
        let sprint = legacy_sprint();
        let graph = legacy_graph();
        let existing_sprint = existing_v1_sprint();
        let existing_graph = existing_v1_graph();
        assert_eq!(existing_sprint.validate(), Ok(()));
        assert_eq!(existing_graph.validate_for_sprint(&existing_sprint), Ok(()));
        let sprint_bytes = sprint.canonical_bytes().expect("canonical legacy sprint");
        let graph_bytes = graph
            .canonical_bytes_for_sprint(&sprint)
            .expect("canonical legacy graph");

        let expected_sprint = concat!(
            "{\"sprint_id\":\"sprint-legacy-1\",\"objective\":\"Implement feature\",",
            "\"acceptance_criteria\":[{\"criterion_id\":\"tests-pass\",",
            "\"description\":\"Focused tests pass\",\"kind\":{\"Automated\":{",
            "\"program\":\"cargo\",\"arguments\":[\"test\"],\"working_directory\":\"\"}}}],",
            "\"provider\":{\"backend_id\":\"fake\",\"model_id\":\"deterministic-v1\",",
            "\"execution_origin\":\"HostIsolated\"},\"budget\":{\"max_tasks\":8,",
            "\"max_attempts_per_task\":3,\"max_tool_calls\":100,",
            "\"max_duration_ms\":60000},\"max_workers\":1,\"workspace_grant\":{",
            "\"grant_id\":\"grant-1\",\"canonical_root\":\"/work/project\",",
            "\"permissions\":{\"read\":true,\"write_regular_files\":true,",
            "\"execute_commands\":true,\"integrate_changes\":true,",
            "\"apply_verified_changes\":true},\"network\":\"Denied\",",
            "\"policy_version\":1,\"grant_hash\":",
            "\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"},",
            "\"base_snapshot\":",
            "\"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\"}"
        );
        let expected_graph = concat!(
            "{\"graph_id\":\"graph-legacy-1\",\"tasks\":[{",
            "\"task_id\":\"task-ordinary-1\",\"goal\":\"Implement feature\",",
            "\"dependencies\":[],\"path_scopes\":[{\"Relative\":\"src\"}],",
            "\"acceptance_checks\":[\"tests-pass\"],\"base_snapshot\":",
            "\"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\",",
            "\"required\":true}]}"
        );
        assert_eq!(sprint_bytes, expected_sprint.as_bytes());
        assert_eq!(graph_bytes, expected_graph.as_bytes());
        assert_eq!(
            sprint_bytes,
            serde_json::to_vec(&existing_sprint).expect("existing V1 sprint bytes")
        );
        assert_eq!(
            graph_bytes,
            serde_json::to_vec(&existing_graph).expect("existing V1 graph bytes")
        );
    }

    #[test]
    fn legacy_v1_roundtrip_is_exact_and_rejects_drift() {
        let sprint = legacy_sprint();
        let graph = legacy_graph();
        let sprint_bytes = sprint.canonical_bytes().expect("legacy sprint bytes");
        let graph_bytes = graph
            .canonical_bytes_for_sprint(&sprint)
            .expect("legacy graph bytes");
        assert_eq!(
            LegacySprintSpecV1::from_canonical_bytes(&sprint_bytes),
            Ok(sprint.clone())
        );
        assert_eq!(
            LegacyTaskGraphV1::from_canonical_bytes_for_sprint(&graph_bytes, &sprint),
            Ok(graph)
        );

        let mut spaced = sprint_bytes.clone();
        spaced.insert(1, b' ');
        assert!(LegacySprintSpecV1::from_canonical_bytes(&spaced).is_err());

        let mut value: serde_json::Value =
            serde_json::from_slice(&sprint_bytes).expect("legacy sprint JSON");
        value
            .as_object_mut()
            .expect("sprint object")
            .insert("unknown".into(), serde_json::Value::Bool(true));
        assert!(
            LegacySprintSpecV1::from_canonical_bytes(
                &serde_json::to_vec(&value).expect("unknown-field bytes")
            )
            .is_err()
        );

        let mut invalid = sprint;
        invalid
            .acceptance_criteria
            .push(invalid.acceptance_criteria[0].clone());
        assert!(invalid.validate().is_err());
    }

    #[test]
    fn legacy_v1_sprint_validation_matches_existing_pre_v32_rejection_matrix() {
        let sprint_mutations: [fn(&mut LegacySprintSpecV1, &mut SprintSpec); 11] = [
            |legacy, existing| {
                legacy.sprint_id.clear();
                existing.sprint_id.clear();
            },
            |legacy, existing| {
                legacy.objective.clear();
                existing.objective.clear();
            },
            |legacy, existing| {
                legacy.acceptance_criteria.clear();
                existing.acceptance_criteria.clear();
            },
            |legacy, existing| {
                legacy
                    .acceptance_criteria
                    .push(legacy.acceptance_criteria[0].clone());
                existing
                    .acceptance_criteria
                    .push(existing.acceptance_criteria[0].clone());
            },
            |legacy, existing| {
                legacy.provider.backend_id.clear();
                existing.provider.backend_id.clear();
            },
            |legacy, existing| {
                legacy.budget.max_tasks = 0;
                existing.budget.max_tasks = 0;
            },
            |legacy, existing| {
                legacy.budget.max_attempts_per_task = 0;
                existing.budget.max_attempts_per_task = 0;
            },
            |legacy, existing| {
                legacy.budget.max_tool_calls = 0;
                existing.budget.max_tool_calls = 0;
            },
            |legacy, existing| {
                legacy.budget.max_duration_ms = 0;
                existing.budget.max_duration_ms = 0;
            },
            |legacy, existing| {
                legacy.max_workers = 4;
                existing.max_workers = 4;
            },
            |legacy, existing| {
                legacy.workspace_grant.policy_version = 0;
                existing.workspace_grant.policy_version = 0;
            },
        ];
        for mutate in sprint_mutations {
            let mut legacy = legacy_sprint();
            let mut existing = existing_v1_sprint();
            mutate(&mut legacy, &mut existing);
            assert_eq!(legacy.validate(), existing.validate());
        }
    }

    #[test]
    fn legacy_v1_graph_validation_matches_existing_pre_v32_rejection_matrix() {
        let graph_mutations: [fn(&mut LegacyTaskGraphV1, &mut TaskGraph); 8] = [
            |legacy, existing| {
                legacy.graph_id.clear();
                existing.graph_id.clear();
            },
            |legacy, existing| {
                legacy.tasks.clear();
                existing.tasks.clear();
            },
            |legacy, existing| {
                legacy.tasks.push(legacy.tasks[0].clone());
                existing.tasks.push(existing.tasks[0].clone());
            },
            |legacy, existing| {
                legacy.tasks[0].base_snapshot = digest('c');
                existing.tasks[0].base_snapshot = digest('c');
            },
            |legacy, existing| {
                legacy.tasks[0].acceptance_checks = vec!["unknown".into()];
                existing.tasks[0].acceptance_checks = vec!["unknown".into()];
            },
            |legacy, existing| {
                legacy.tasks[0].dependencies = vec!["missing".into()];
                existing.tasks[0].dependencies = vec!["missing".into()];
            },
            |legacy, existing| {
                legacy.tasks[0].dependencies = vec![legacy.tasks[0].task_id.clone()];
                existing.tasks[0].dependencies = vec![existing.tasks[0].task_id.clone()];
            },
            |legacy, existing| {
                let legacy_scope = legacy.tasks[0].path_scopes[0].clone();
                let existing_scope = existing.tasks[0].path_scopes[0].clone();
                legacy.tasks[0].path_scopes.push(legacy_scope);
                existing.tasks[0].path_scopes.push(existing_scope);
            },
        ];
        for mutate in graph_mutations {
            let sprint = legacy_sprint();
            let existing_sprint = existing_v1_sprint();
            let mut legacy = legacy_graph();
            let mut existing = existing_v1_graph();
            mutate(&mut legacy, &mut existing);
            assert_eq!(
                legacy.validate_for_sprint(&sprint),
                existing.validate_for_sprint(&existing_sprint)
            );
        }
    }

    #[test]
    fn v2_budget_has_no_decode_default_and_enforces_one_through_three() {
        let authored = SprintBudgetV2::author_v01(3, 3, 100, 60_000);
        assert_eq!(
            authored.max_final_verification_attempts,
            PRODUCT_DEFAULT_MAX_FINAL_VERIFICATION_ATTEMPTS_V01
        );
        assert_eq!(authored.validate(), Ok(()));

        let missing = br#"{"sprint_authority_version":2,"max_tasks":3,"max_attempts_per_task":3,"max_tool_calls":100,"max_duration_ms":60000}"#;
        assert!(serde_json::from_slice::<SprintBudgetV2>(missing).is_err());
        let noninteger = br#"{"sprint_authority_version":2,"max_tasks":3,"max_attempts_per_task":3,"max_final_verification_attempts":1.5,"max_tool_calls":100,"max_duration_ms":60000}"#;
        assert!(serde_json::from_slice::<SprintBudgetV2>(noninteger).is_err());

        for cap in [0, 4] {
            let mut budget = authored;
            budget.max_final_verification_attempts = cap;
            assert!(budget.validate().is_err());
        }
        for cap in 1..=3 {
            let mut budget = authored;
            budget.max_final_verification_attempts = cap;
            assert_eq!(budget.validate(), Ok(()));
        }
        let mut wrong_version = authored;
        wrong_version.sprint_authority_version = 1;
        assert!(wrong_version.validate().is_err());
    }

    #[test]
    fn v2_pair_binds_exact_ordered_repair_reserve_and_both_canonical_digests() {
        for cap in 1..=3 {
            let (spec, graph) = v2_pair(cap);
            assert_eq!(graph.validate_for_sprint(&spec), Ok(()));
            let spec_bytes = spec.canonical_bytes().expect("V2 spec bytes");
            let graph_bytes = graph
                .canonical_bytes_for_sprint(&spec)
                .expect("V2 graph bytes");
            assert_eq!(
                SprintSpecV2::from_canonical_bytes(&spec_bytes),
                Ok(spec.clone())
            );
            assert_eq!(
                TaskGraphV2::from_canonical_bytes_for_sprint(&graph_bytes, &spec),
                Ok(graph)
            );
        }
    }

    #[test]
    fn v2_graph_payload_digest_excludes_only_reciprocal_spec_digest() {
        let (spec, graph) = v2_pair(3);
        let baseline = graph.payload_digest().expect("baseline graph payload");

        let mut excluded = graph.clone();
        excluded.sprint_spec_digest = digest('f');
        assert_eq!(
            excluded.payload_digest().expect("excluded-field payload"),
            baseline
        );
        assert!(excluded.validate_for_sprint(&spec).is_err());

        let included_mutations: [fn(&mut TaskGraphV2); 5] = [
            |value| value.sprint_authority_version = 3,
            |value| value.graph_id = "crossed-graph".into(),
            |value| value.sprint_id = "crossed-sprint".into(),
            |value| value.repair_slot_reserve_digest = digest('f'),
            |value| value.tasks[0].goal.push_str(" crossed"),
        ];
        for mutate in included_mutations {
            let mut crossed = graph.clone();
            mutate(&mut crossed);
            assert_ne!(
                crossed.payload_digest().expect("mutated graph payload"),
                baseline
            );
            assert!(crossed.validate_for_sprint(&spec).is_err());
        }
    }

    #[test]
    fn v2_pair_and_digest_domain_swaps_fail_closed() {
        let (spec, graph) = v2_pair(3);

        let wrong_graph_payload = digest_canonical(
            "wrong_domain_graph_payload",
            SPRINT_SPEC_V2_DIGEST_DOMAIN,
            &TaskGraphPayloadV2 {
                sprint_authority_version: graph.sprint_authority_version,
                graph_id: &graph.graph_id,
                sprint_id: &graph.sprint_id,
                repair_slot_reserve_digest: &graph.repair_slot_reserve_digest,
                tasks: &graph.tasks,
            },
        )
        .expect("wrong-domain graph payload");
        assert_ne!(wrong_graph_payload, spec.task_graph_payload_digest);
        let mut wrong_payload_spec = spec.clone();
        wrong_payload_spec.task_graph_payload_digest = wrong_graph_payload;
        assert!(graph.validate_for_sprint(&wrong_payload_spec).is_err());

        let spec_bytes = spec.canonical_bytes().expect("canonical spec bytes");
        let wrong_spec_digest = domain_digest(TASK_GRAPH_V2_PAYLOAD_DIGEST_DOMAIN, &spec_bytes);
        assert_ne!(wrong_spec_digest, graph.sprint_spec_digest);
        let mut wrong_spec_graph = graph.clone();
        wrong_spec_graph.sprint_spec_digest = wrong_spec_digest;
        assert!(wrong_spec_graph.validate_for_sprint(&spec).is_err());

        let repair_slots = graph
            .tasks
            .iter()
            .filter(|task| task.is_repair_slot())
            .collect();
        let wrong_reserve_digest = digest_canonical(
            "wrong_domain_repair_reserve",
            TASK_GRAPH_V2_PAYLOAD_DIGEST_DOMAIN,
            &RepairSlotReserveV2 {
                sprint_authority_version: graph.sprint_authority_version,
                sprint_id: &graph.sprint_id,
                graph_id: &graph.graph_id,
                repair_slots,
            },
        )
        .expect("wrong-domain reserve digest");
        assert_ne!(wrong_reserve_digest, graph.repair_slot_reserve_digest);
        let mut wrong_reserve_spec = spec.clone();
        let mut wrong_reserve_graph = graph.clone();
        wrong_reserve_spec.repair_slot_reserve_digest = wrong_reserve_digest.clone();
        wrong_reserve_graph.repair_slot_reserve_digest = wrong_reserve_digest;
        wrong_reserve_spec.task_graph_payload_digest = wrong_reserve_graph
            .payload_digest()
            .expect("wrong-reserve graph payload");
        wrong_reserve_graph.sprint_spec_digest = wrong_reserve_spec
            .canonical_digest()
            .expect("wrong-reserve spec digest");
        assert!(
            wrong_reserve_graph
                .validate_for_sprint(&wrong_reserve_spec)
                .is_err()
        );

        let mut other_spec = spec.clone();
        let mut other_graph = graph.clone();
        other_spec.objective = "Other objective".into();
        other_graph.sprint_id = "sprint-v2-2".into();
        other_graph.graph_id = "graph-v2-2".into();
        rebind_v2_pair(&mut other_spec, &mut other_graph);
        assert_eq!(other_graph.validate_for_sprint(&other_spec), Ok(()));
        assert!(graph.validate_for_sprint(&other_spec).is_err());
        assert!(other_graph.validate_for_sprint(&spec).is_err());
    }

    #[test]
    fn v2_rejects_missing_duplicate_noncontiguous_and_unordered_slots() {
        let (spec, graph) = v2_pair(3);

        let mut missing = graph.clone();
        missing.tasks.pop();
        assert!(missing.validate_for_sprint(&spec).is_err());

        let mut duplicate = graph.clone();
        duplicate.tasks[2].purpose = TaskPurposeV2::FinalVerificationRepairSlot { slot_ordinal: 1 };
        assert!(duplicate.validate_for_sprint(&spec).is_err());

        let mut noncontiguous = graph.clone();
        noncontiguous.tasks[2].purpose =
            TaskPurposeV2::FinalVerificationRepairSlot { slot_ordinal: 3 };
        assert!(noncontiguous.validate_for_sprint(&spec).is_err());

        let mut reordered = graph.clone();
        reordered.tasks.swap(1, 2);
        assert!(reordered.validate_for_sprint(&spec).is_err());

        let mut crossed_dependencies = graph;
        crossed_dependencies.tasks[2].dependencies = vec!["ordinary-1".into()];
        assert!(crossed_dependencies.validate_for_sprint(&spec).is_err());
    }

    #[test]
    fn v2_rejects_crossed_graph_spec_reserve_snapshot_and_version() {
        let (spec, graph) = v2_pair(3);

        let mut crossed_graph_digest = spec.clone();
        crossed_graph_digest.task_graph_payload_digest = digest('f');
        assert!(graph.validate_for_sprint(&crossed_graph_digest).is_err());

        let mut crossed_spec_digest = graph.clone();
        crossed_spec_digest.sprint_spec_digest = digest('f');
        assert!(crossed_spec_digest.validate_for_sprint(&spec).is_err());

        let mut crossed_reserve = graph.clone();
        crossed_reserve.repair_slot_reserve_digest = digest('f');
        assert!(crossed_reserve.validate_for_sprint(&spec).is_err());

        let mut crossed_snapshot = graph.clone();
        crossed_snapshot.tasks[1].base_snapshot = digest('c');
        assert!(crossed_snapshot.validate_for_sprint(&spec).is_err());

        let mut wrong_version = spec.clone();
        wrong_version.sprint_authority_version = 1;
        assert!(wrong_version.validate().is_err());

        let mut wrong_graph_version = graph.clone();
        wrong_graph_version.sprint_authority_version = 1;
        assert!(wrong_graph_version.validate_for_sprint(&spec).is_err());

        let mut wrong_task_version = graph;
        wrong_task_version.tasks[0].sprint_authority_version = 1;
        assert!(wrong_task_version.validate_for_sprint(&spec).is_err());
    }

    #[test]
    fn legacy_and_v2_bytes_are_mutually_non_substitutable() {
        let legacy_sprint_bytes = legacy_sprint()
            .canonical_bytes()
            .expect("legacy sprint bytes");
        let legacy_graph_bytes = legacy_graph()
            .canonical_bytes_for_sprint(&legacy_sprint())
            .expect("legacy graph bytes");
        let (v2_sprint, v2_graph) = v2_pair(3);
        let v2_sprint_bytes = v2_sprint.canonical_bytes().expect("V2 sprint bytes");
        let v2_graph_bytes = v2_graph
            .canonical_bytes_for_sprint(&v2_sprint)
            .expect("V2 graph bytes");

        assert!(SprintSpecV2::from_canonical_bytes(&legacy_sprint_bytes).is_err());
        assert!(LegacySprintSpecV1::from_canonical_bytes(&v2_sprint_bytes).is_err());
        assert!(
            TaskGraphV2::from_canonical_bytes_for_sprint(&legacy_graph_bytes, &v2_sprint).is_err()
        );
        assert!(
            LegacyTaskGraphV1::from_canonical_bytes_for_sprint(&v2_graph_bytes, &legacy_sprint())
                .is_err()
        );

        let mut unknown: serde_json::Value =
            serde_json::from_slice(&v2_sprint_bytes).expect("V2 sprint JSON");
        unknown
            .as_object_mut()
            .expect("V2 sprint object")
            .insert("unknown".into(), serde_json::Value::Bool(true));
        assert!(
            SprintSpecV2::from_canonical_bytes(
                &serde_json::to_vec(&unknown).expect("unknown field bytes")
            )
            .is_err()
        );

        let mut noncanonical = v2_sprint_bytes;
        noncanonical.push(b'\n');
        assert!(SprintSpecV2::from_canonical_bytes(&noncanonical).is_err());
    }

    #[test]
    fn attempt_authority_crosses_complete_sets_snapshot_check_policy_and_provenance() {
        let (spec, graph) = v2_pair(3);
        let authority = attempt(
            1,
            'c',
            'd',
            'f',
            FinalVerificationAttemptPredecessorV1::Initial,
        );
        let expected = FinalVerificationAttemptExpectedInputsV1 {
            attempt_id: authority.attempt_id.clone(),
            attempt_ordinal: 1,
            final_verification_admission_id: authority.final_verification_admission_id.clone(),
            input_snapshot: authority.input_snapshot.clone(),
            final_verification_check: authority.final_verification_check.clone(),
            execution_policy_digest: authority.execution_policy_digest.clone(),
            complete_task_done_set_digest: authority.complete_task_done_set_digest.clone(),
            complete_criterion_evidence_set_digest: authority
                .complete_criterion_evidence_set_digest
                .clone(),
            provenance: authority.provenance.clone(),
            predecessor: authority.predecessor.clone(),
        };
        assert_eq!(authority.validate_for(&spec, &graph, &expected), Ok(()));

        let mutations: [fn(&mut FinalVerificationAttemptExpectedInputsV1); 9] = [
            |value| value.attempt_id = "crossed-attempt".into(),
            |value| value.attempt_ordinal = 2,
            |value| value.final_verification_admission_id = "crossed-admission".into(),
            |value| value.input_snapshot = digest('9'),
            |value| value.execution_policy_digest = digest('9'),
            |value| value.complete_task_done_set_digest = digest('9'),
            |value| value.complete_criterion_evidence_set_digest = digest('9'),
            |value| value.provenance.admission_event_id = "crossed-event".into(),
            |value| {
                value.predecessor =
                    FinalVerificationAttemptPredecessorV1::SameSnapshotAfterFailedBeforeEffect {
                        prior_attempt_id: "crossed-prior".into(),
                        closure_id: "crossed-closure".into(),
                    };
            },
        ];
        for mutate in mutations {
            let mut crossed = expected.clone();
            mutate(&mut crossed);
            assert!(authority.validate_for(&spec, &graph, &crossed).is_err());
        }

        let mut crossed_check = expected;
        crossed_check
            .final_verification_check
            .arguments
            .push("--all".into());
        assert!(
            authority
                .validate_for(&spec, &graph, &crossed_check)
                .is_err()
        );
    }

    #[test]
    fn attempt_successors_enforce_contiguous_ordinal_and_snapshot_branch() {
        let initial = attempt(
            1,
            'c',
            'd',
            'f',
            FinalVerificationAttemptPredecessorV1::Initial,
        );
        let same_snapshot = attempt(
            2,
            'c',
            'd',
            'f',
            FinalVerificationAttemptPredecessorV1::SameSnapshotAfterFailedBeforeEffect {
                prior_attempt_id: initial.attempt_id.clone(),
                closure_id: "closure-1".into(),
            },
        );
        assert_eq!(same_snapshot.validate_successor_of(&initial), Ok(()));

        let repair = attempt(
            2,
            '9',
            '8',
            '7',
            FinalVerificationAttemptPredecessorV1::ChangedSnapshotAfterRepair {
                prior_failure_id: "failure-1".into(),
                repair_admission_id: "repair-admission-1".into(),
                repair_task_done_proof_id: "repair-task-done-1".into(),
                integration_receipt_id: "integration-1".into(),
            },
        );
        assert_eq!(repair.validate_successor_of(&initial), Ok(()));

        let mut skipped = same_snapshot.clone();
        skipped.attempt_ordinal = 3;
        assert!(skipped.validate_successor_of(&initial).is_err());

        let mut crossed_prior = same_snapshot;
        crossed_prior.predecessor =
            FinalVerificationAttemptPredecessorV1::SameSnapshotAfterFailedBeforeEffect {
                prior_attempt_id: "other-attempt".into(),
                closure_id: "closure-1".into(),
            };
        assert!(crossed_prior.validate_successor_of(&initial).is_err());

        let mut unchanged_repair = repair;
        unchanged_repair.input_snapshot = initial.input_snapshot.clone();
        assert!(unchanged_repair.validate_successor_of(&initial).is_err());
    }

    #[test]
    fn attempt_bytes_are_strict_canonical_and_versioned() {
        let authority = attempt(
            1,
            'c',
            'd',
            'f',
            FinalVerificationAttemptPredecessorV1::Initial,
        );
        let bytes = authority.canonical_bytes().expect("attempt bytes");
        assert_eq!(
            FinalVerificationAttemptAuthorityV1::from_canonical_bytes(&bytes),
            Ok(authority.clone())
        );
        assert!(authority.canonical_digest().is_ok());

        let mut unknown: serde_json::Value = serde_json::from_slice(&bytes).expect("attempt JSON");
        unknown
            .as_object_mut()
            .expect("attempt object")
            .insert("unknown".into(), serde_json::Value::Bool(true));
        assert!(
            FinalVerificationAttemptAuthorityV1::from_canonical_bytes(
                &serde_json::to_vec(&unknown).expect("unknown attempt bytes")
            )
            .is_err()
        );

        let mut wrong_version = authority;
        wrong_version.authority_version = 2;
        assert!(wrong_version.validate().is_err());
    }

    #[test]
    fn nested_unknown_fields_and_reordered_canonical_bytes_fail_closed() {
        let (spec, graph) = v2_pair(3);
        let bytes = spec.canonical_bytes().expect("V2 spec bytes");
        let mut value: serde_json::Value = serde_json::from_slice(&bytes).expect("V2 JSON");
        value["provider"]["unknown"] = serde_json::Value::Bool(true);
        assert!(
            SprintSpecV2::from_canonical_bytes(
                &serde_json::to_vec(&value).expect("nested unknown bytes")
            )
            .is_err()
        );

        let reordered_value: serde_json::Value =
            serde_json::from_slice(&bytes).expect("V2 JSON for reordering");
        let reordered = serde_json::to_vec(&reordered_value).expect("reordered V2 bytes");
        assert_ne!(reordered, bytes);
        assert!(SprintSpecV2::from_canonical_bytes(&reordered).is_err());

        let mut missing_spec_version: serde_json::Value =
            serde_json::from_slice(&bytes).expect("V2 spec for missing version");
        missing_spec_version
            .as_object_mut()
            .expect("V2 spec object")
            .remove("sprint_authority_version");
        assert!(serde_json::from_value::<SprintSpecV2>(missing_spec_version).is_err());

        let graph_bytes = graph
            .canonical_bytes_for_sprint(&spec)
            .expect("V2 graph bytes");
        let mut missing_task_purpose: serde_json::Value =
            serde_json::from_slice(&graph_bytes).expect("V2 graph for missing purpose");
        missing_task_purpose["tasks"][0]
            .as_object_mut()
            .expect("V2 task object")
            .remove("purpose");
        assert!(serde_json::from_value::<TaskGraphV2>(missing_task_purpose).is_err());
    }
}
