use std::collections::{BTreeMap, BTreeSet};
use std::fmt::{self, Write as _};

use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

const CHECKED_IN_GATE_1_REGISTRY: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../fixtures/gate-cases/gate-1-v1.json"
));
const CHECKED_IN_GATE_2_REGISTRY: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../fixtures/gate-cases/gate-2-v1.json"
));
const CHECKED_IN_GATE_3_REGISTRY: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../fixtures/gate-cases/gate-3-v1.json"
));
const MAX_REGISTRY_BYTES: usize = 4 * 1_048_576;
const REGISTRY_DIGEST_DOMAIN: &[u8] = b"grok-build/gate-case-registry/v1\0";

const TARGETS: [GateTargetV1; 3] = [
    GateTargetV1::Macos15AppleSilicon,
    GateTargetV1::Ubuntu2604X8664,
    GateTargetV1::Fedora44X8664,
];

const COMMON_CASES: [CaseDefinition; 25] = [
    case(
        "native_evidence_only_authority_sealed",
        FixtureSpecIdV1::NativeAdmission,
        ValidatorIdV1::NativeAdmission,
        "native-admission",
        AuthorityPhaseV1::PreAdmission,
        InternalVectorAxisV1::None,
        MutationClassV1::ProcessDomainDestructive,
    ),
    case(
        "walking_skeleton_contract_identity",
        FixtureSpecIdV1::WalkingSkeleton,
        ValidatorIdV1::WalkingSkeleton,
        "walking-skeleton",
        AuthorityPhaseV1::PostAdmission,
        InternalVectorAxisV1::None,
        MutationClassV1::WorkspaceDestructive,
    ),
    case(
        "workspace_root_traversal_denied",
        FixtureSpecIdV1::WorkspaceDenial,
        ValidatorIdV1::WorkspaceDenial,
        "workspace-denial",
        AuthorityPhaseV1::PostAdmission,
        InternalVectorAxisV1::None,
        MutationClassV1::WorkspaceDestructive,
    ),
    case(
        "workspace_sibling_read_denied",
        FixtureSpecIdV1::WorkspaceDenial,
        ValidatorIdV1::WorkspaceDenial,
        "workspace-denial",
        AuthorityPhaseV1::PostAdmission,
        InternalVectorAxisV1::None,
        MutationClassV1::WorkspaceDestructive,
    ),
    case(
        "workspace_home_read_denied",
        FixtureSpecIdV1::WorkspaceDenial,
        ValidatorIdV1::WorkspaceDenial,
        "workspace-denial",
        AuthorityPhaseV1::PostAdmission,
        InternalVectorAxisV1::None,
        MutationClassV1::WorkspaceDestructive,
    ),
    case(
        "workspace_symlink_swap_denied",
        FixtureSpecIdV1::WorkspaceDenial,
        ValidatorIdV1::WorkspaceDenial,
        "workspace-denial",
        AuthorityPhaseV1::PostAdmission,
        InternalVectorAxisV1::None,
        MutationClassV1::WorkspaceDestructive,
    ),
    case(
        "workspace_rename_swap_denied",
        FixtureSpecIdV1::WorkspaceDenial,
        ValidatorIdV1::WorkspaceDenial,
        "workspace-denial",
        AuthorityPhaseV1::PostAdmission,
        InternalVectorAxisV1::None,
        MutationClassV1::WorkspaceDestructive,
    ),
    case(
        "workspace_hardlink_escape_denied",
        FixtureSpecIdV1::WorkspaceDenial,
        ValidatorIdV1::WorkspaceDenial,
        "workspace-denial",
        AuthorityPhaseV1::PostAdmission,
        InternalVectorAxisV1::None,
        MutationClassV1::WorkspaceDestructive,
    ),
    case(
        "workspace_git_case_alias_denied",
        FixtureSpecIdV1::WorkspaceDenial,
        ValidatorIdV1::WorkspaceDenial,
        "workspace-denial",
        AuthorityPhaseV1::PostAdmission,
        InternalVectorAxisV1::None,
        MutationClassV1::WorkspaceDestructive,
    ),
    case(
        "workspace_special_file_denied",
        FixtureSpecIdV1::WorkspaceDenial,
        ValidatorIdV1::WorkspaceDenial,
        "workspace-denial",
        AuthorityPhaseV1::PostAdmission,
        InternalVectorAxisV1::None,
        MutationClassV1::WorkspaceDestructive,
    ),
    case(
        "workspace_device_access_denied",
        FixtureSpecIdV1::WorkspaceDenial,
        ValidatorIdV1::WorkspaceDenial,
        "workspace-denial",
        AuthorityPhaseV1::PostAdmission,
        InternalVectorAxisV1::None,
        MutationClassV1::WorkspaceDestructive,
    ),
    case(
        "command_inherited_descriptors_absent",
        FixtureSpecIdV1::CommandIsolation,
        ValidatorIdV1::CommandIsolation,
        "command-isolation",
        AuthorityPhaseV1::PostAdmission,
        InternalVectorAxisV1::None,
        MutationClassV1::ProcessDomainDestructive,
    ),
    case(
        "command_credentials_absent",
        FixtureSpecIdV1::CommandIsolation,
        ValidatorIdV1::CommandIsolation,
        "command-isolation",
        AuthorityPhaseV1::PostAdmission,
        InternalVectorAxisV1::None,
        MutationClassV1::ProcessDomainDestructive,
    ),
    case(
        "command_local_network_denied",
        FixtureSpecIdV1::CommandIsolation,
        ValidatorIdV1::CommandIsolation,
        "command-isolation",
        AuthorityPhaseV1::PostAdmission,
        InternalVectorAxisV1::None,
        MutationClassV1::ProcessDomainDestructive,
    ),
    case(
        "command_external_network_denied",
        FixtureSpecIdV1::CommandIsolation,
        ValidatorIdV1::CommandIsolation,
        "command-isolation",
        AuthorityPhaseV1::PostAdmission,
        InternalVectorAxisV1::None,
        MutationClassV1::ProcessDomainDestructive,
    ),
    case(
        "command_nested_namespace_mount_denied",
        FixtureSpecIdV1::CommandIsolation,
        ValidatorIdV1::CommandIsolation,
        "command-isolation",
        AuthorityPhaseV1::PostAdmission,
        InternalVectorAxisV1::None,
        MutationClassV1::ProcessDomainDestructive,
    ),
    case(
        "command_detached_descendant_cleanup",
        FixtureSpecIdV1::CommandIsolation,
        ValidatorIdV1::CommandIsolation,
        "command-isolation",
        AuthorityPhaseV1::PostAdmission,
        InternalVectorAxisV1::None,
        MutationClassV1::ProcessDomainDestructive,
    ),
    case(
        "cancellation_zero_descendants",
        FixtureSpecIdV1::Cancel,
        ValidatorIdV1::Cancel,
        "cancel",
        AuthorityPhaseV1::PostAdmission,
        InternalVectorAxisV1::None,
        MutationClassV1::ProcessDomainDestructive,
    ),
    case(
        "stale_content_blocks_application",
        FixtureSpecIdV1::StaleApply,
        ValidatorIdV1::StaleApply,
        "stale-apply",
        AuthorityPhaseV1::PostAdmission,
        InternalVectorAxisV1::None,
        MutationClassV1::WorkspaceDestructive,
    ),
    case(
        "launch_cleanup_race_single_live_claim",
        FixtureSpecIdV1::LaunchCleanupRace,
        ValidatorIdV1::LaunchCleanupRace,
        "launch-cleanup-race",
        AuthorityPhaseV1::PostAdmission,
        InternalVectorAxisV1::None,
        MutationClassV1::ProcessDomainDestructive,
    ),
    case(
        "crash_journal_boundaries_no_uncertain_replay",
        FixtureSpecIdV1::CrashJournal,
        ValidatorIdV1::CrashJournal,
        "crash-journal",
        AuthorityPhaseV1::PostAdmission,
        InternalVectorAxisV1::ClosedFixtureVectorTable,
        MutationClassV1::WorkspaceDestructive,
    ),
    case(
        "restart_sqlite_reconstruction",
        FixtureSpecIdV1::Restart,
        ValidatorIdV1::Restart,
        "restart",
        AuthorityPhaseV1::PostAdmission,
        InternalVectorAxisV1::None,
        MutationClassV1::WorkspaceDestructive,
    ),
    case(
        "target_only_application",
        FixtureSpecIdV1::Apply,
        ValidatorIdV1::Apply,
        "apply",
        AuthorityPhaseV1::PostAdmission,
        InternalVectorAxisV1::None,
        MutationClassV1::WorkspaceDestructive,
    ),
    case(
        "rollback_exact_pre_sprint_snapshot",
        FixtureSpecIdV1::Rollback,
        ValidatorIdV1::Rollback,
        "rollback",
        AuthorityPhaseV1::PostAdmission,
        InternalVectorAxisV1::None,
        MutationClassV1::WorkspaceDestructive,
    ),
    case(
        "offline_locked_compiler_succeeds",
        FixtureSpecIdV1::OfflineBuild,
        ValidatorIdV1::OfflineBuild,
        "offline-build",
        AuthorityPhaseV1::PostAdmission,
        InternalVectorAxisV1::None,
        MutationClassV1::ReadOnly,
    ),
];

const MACOS_CASES: [CaseDefinition; 4] = [
    case(
        "macos_signed_helper_identity",
        FixtureSpecIdV1::MacosNative,
        ValidatorIdV1::MacosNative,
        "native-admission",
        AuthorityPhaseV1::PreAdmission,
        InternalVectorAxisV1::None,
        MutationClassV1::ProcessDomainDestructive,
    ),
    case(
        "macos_dedicated_uid",
        FixtureSpecIdV1::MacosNative,
        ValidatorIdV1::MacosNative,
        "native-admission",
        AuthorityPhaseV1::PreAdmission,
        InternalVectorAxisV1::None,
        MutationClassV1::ProcessDomainDestructive,
    ),
    case(
        "macos_seatbelt_canary",
        FixtureSpecIdV1::MacosNative,
        ValidatorIdV1::MacosNative,
        "native-admission",
        AuthorityPhaseV1::PreAdmission,
        InternalVectorAxisV1::None,
        MutationClassV1::ProcessDomainDestructive,
    ),
    case(
        "macos_process_tree_cleanup",
        FixtureSpecIdV1::MacosNative,
        ValidatorIdV1::MacosNative,
        "native-admission",
        AuthorityPhaseV1::PreAdmission,
        InternalVectorAxisV1::None,
        MutationClassV1::ProcessDomainDestructive,
    ),
];

const LINUX_CASES: [CaseDefinition; 7] = [
    case(
        "linux_bubblewrap_namespace_canary",
        FixtureSpecIdV1::LinuxNative,
        ValidatorIdV1::LinuxNative,
        "native-admission",
        AuthorityPhaseV1::PreAdmission,
        InternalVectorAxisV1::None,
        MutationClassV1::ProcessDomainDestructive,
    ),
    case(
        "linux_landlock_canary",
        FixtureSpecIdV1::LinuxNative,
        ValidatorIdV1::LinuxNative,
        "native-admission",
        AuthorityPhaseV1::PreAdmission,
        InternalVectorAxisV1::None,
        MutationClassV1::ProcessDomainDestructive,
    ),
    case(
        "linux_seccomp_canary",
        FixtureSpecIdV1::LinuxNative,
        ValidatorIdV1::LinuxNative,
        "native-admission",
        AuthorityPhaseV1::PreAdmission,
        InternalVectorAxisV1::None,
        MutationClassV1::ProcessDomainDestructive,
    ),
    case(
        "linux_capabilities_removed",
        FixtureSpecIdV1::LinuxNative,
        ValidatorIdV1::LinuxNative,
        "native-admission",
        AuthorityPhaseV1::PreAdmission,
        InternalVectorAxisV1::None,
        MutationClassV1::ProcessDomainDestructive,
    ),
    case(
        "linux_no_new_privs",
        FixtureSpecIdV1::LinuxNative,
        ValidatorIdV1::LinuxNative,
        "native-admission",
        AuthorityPhaseV1::PreAdmission,
        InternalVectorAxisV1::None,
        MutationClassV1::ProcessDomainDestructive,
    ),
    case(
        "linux_cgroup_v2_membership",
        FixtureSpecIdV1::LinuxNative,
        ValidatorIdV1::LinuxNative,
        "native-admission",
        AuthorityPhaseV1::PreAdmission,
        InternalVectorAxisV1::None,
        MutationClassV1::ProcessDomainDestructive,
    ),
    case(
        "linux_pidfd_process_tree_cleanup",
        FixtureSpecIdV1::LinuxNative,
        ValidatorIdV1::LinuxNative,
        "native-admission",
        AuthorityPhaseV1::PreAdmission,
        InternalVectorAxisV1::None,
        MutationClassV1::ProcessDomainDestructive,
    ),
];

const GATE_2_BASE_CASES: [Gate2CaseDefinition; 5] = [
    gate2_case(
        "gate_1_identity_remains_valid",
        FixtureSpecIdV1::Gate2CumulativeIdentity,
        ValidatorIdV1::Gate2CumulativeIdentity,
        "cumulative-identity",
        MutationClassV1::ReadOnly,
    ),
    gate2_case(
        "worker_ceiling_never_exceeded",
        FixtureSpecIdV1::Gate2SchedulerCollision,
        ValidatorIdV1::Gate2SchedulerCollision,
        "scheduler-collision",
        MutationClassV1::WorkspaceDestructive,
    ),
    gate2_case(
        "crash_never_duplicates_command_or_write",
        FixtureSpecIdV1::Gate2Crash,
        ValidatorIdV1::Gate2Crash,
        "crash",
        MutationClassV1::WorkspaceDestructive,
    ),
    gate2_case(
        "single_grant_no_mid_sprint_approval",
        FixtureSpecIdV1::Gate2SingleGrant,
        ValidatorIdV1::Gate2SingleGrant,
        "single-grant",
        MutationClassV1::WorkspaceDestructive,
    ),
    gate2_case(
        "task_attempt_and_lease_history_closes",
        FixtureSpecIdV1::Gate2AttemptClosure,
        ValidatorIdV1::Gate2AttemptClosure,
        "attempt-closure",
        MutationClassV1::WorkspaceDestructive,
    ),
];

const GATE_2_KNOWN_OUTCOME_CASES: [Gate2CaseDefinition; 6] = [
    gate2_case(
        "independent_modules_integrate_without_loss",
        FixtureSpecIdV1::Gate2SchedulerCollision,
        ValidatorIdV1::Gate2SchedulerCollision,
        "scheduler-collision",
        MutationClassV1::WorkspaceDestructive,
    ),
    gate2_case(
        "shared_file_collision_serializes_or_reconciles",
        FixtureSpecIdV1::Gate2SchedulerCollision,
        ValidatorIdV1::Gate2SchedulerCollision,
        "scheduler-collision",
        MutationClassV1::WorkspaceDestructive,
    ),
    gate2_case(
        "last_writer_wins_absent",
        FixtureSpecIdV1::Gate2SchedulerCollision,
        ValidatorIdV1::Gate2SchedulerCollision,
        "scheduler-collision",
        MutationClassV1::WorkspaceDestructive,
    ),
    gate2_case(
        "cross_snapshot_receipt_rejected",
        FixtureSpecIdV1::Gate2VerificationApply,
        ValidatorIdV1::Gate2VerificationApply,
        "verification-apply",
        MutationClassV1::WorkspaceDestructive,
    ),
    gate2_case(
        "final_verification_precedes_application",
        FixtureSpecIdV1::Gate2VerificationApply,
        ValidatorIdV1::Gate2VerificationApply,
        "verification-apply",
        MutationClassV1::WorkspaceDestructive,
    ),
    gate2_case(
        "completed_and_rollback_reconstruct_after_restart",
        FixtureSpecIdV1::Gate2RestartRollback,
        ValidatorIdV1::Gate2RestartRollback,
        "restart-rollback",
        MutationClassV1::WorkspaceDestructive,
    ),
];

const GATE_2_REPAIR_CASE: Gate2CaseDefinition = gate2_case(
    "failed_verification_repairs_at_most_twice",
    FixtureSpecIdV1::Gate2Repair,
    ValidatorIdV1::Gate2Repair,
    "repair",
    MutationClassV1::WorkspaceDestructive,
);

const GATE_2_RUN_CONTROL_CASE: Gate2CaseDefinition = gate2_case(
    "pause_steer_resume_reconstructs_without_replay",
    FixtureSpecIdV1::Gate2RunControl,
    ValidatorIdV1::Gate2RunControl,
    "run-control",
    MutationClassV1::WorkspaceDestructive,
);

const GATE_2_DIRTY_REPOSITORY_CASE: Gate2CaseDefinition = gate2_case(
    "dirty_repository_gate2_workflow",
    FixtureSpecIdV1::Gate2RepositoryShape,
    ValidatorIdV1::Gate2RepositoryShape,
    "dirty-repository",
    MutationClassV1::WorkspaceDestructive,
);

const GATE_2_NON_GIT_REPOSITORY_CASE: Gate2CaseDefinition = gate2_case(
    "non_git_repository_gate2_workflow",
    FixtureSpecIdV1::Gate2RepositoryShape,
    ValidatorIdV1::Gate2RepositoryShape,
    "non-git-repository",
    MutationClassV1::WorkspaceDestructive,
);

const GATE_2_PROVIDER_CASES: [ProviderCaseDefinition; 3] = [
    provider_case(
        ProviderIdV1::Xai,
        "xai_normalized_contract",
        "xai_live_completed_sprint",
        FixtureSpecIdV1::Gate2XaiLive,
        ValidatorIdV1::Gate2XaiLive,
    ),
    provider_case(
        ProviderIdV1::Ollama,
        "ollama_normalized_contract",
        "ollama_live_completed_sprint",
        FixtureSpecIdV1::Gate2LocalProviderLive,
        ValidatorIdV1::Gate2LocalProviderLive,
    ),
    provider_case(
        ProviderIdV1::LmStudio,
        "lm_studio_normalized_contract",
        "lm_studio_live_completed_sprint",
        FixtureSpecIdV1::Gate2LocalProviderLive,
        ValidatorIdV1::Gate2LocalProviderLive,
    ),
];

const GATE_3_PACKAGE_CASES: [Gate3CaseDefinition; 5] = [
    gate3_case(
        "artifact_signature_and_provenance_match_tag",
        FixtureSpecIdV1::Gate3Artifact,
        ValidatorIdV1::Gate3Artifact,
        "artifact",
        InternalVectorAxisV1::None,
        MutationClassV1::ReadOnly,
    ),
    gate3_case(
        "sbom_and_notices_match_artifact",
        FixtureSpecIdV1::Gate3Artifact,
        ValidatorIdV1::Gate3Artifact,
        "artifact",
        InternalVectorAxisV1::None,
        MutationClassV1::ReadOnly,
    ),
    gate3_case(
        "fresh_install",
        FixtureSpecIdV1::Gate3Lifecycle,
        ValidatorIdV1::Gate3Lifecycle,
        "lifecycle",
        InternalVectorAxisV1::None,
        MutationClassV1::HostDestructive,
    ),
    gate3_case(
        "signed_baseline_upgrade",
        FixtureSpecIdV1::Gate3Lifecycle,
        ValidatorIdV1::Gate3Lifecycle,
        "lifecycle",
        InternalVectorAxisV1::None,
        MutationClassV1::HostDestructive,
    ),
    gate3_case(
        "uninstall",
        FixtureSpecIdV1::Gate3Lifecycle,
        ValidatorIdV1::Gate3Lifecycle,
        "lifecycle",
        InternalVectorAxisV1::None,
        MutationClassV1::HostDestructive,
    ),
];

const GATE_3_UI_OPERATION_CASES: [Gate3CaseDefinition; 2] = [
    gate3_case(
        "keyboard_complete_operation",
        FixtureSpecIdV1::Gate3UiOperation,
        ValidatorIdV1::Gate3UiOperation,
        "ui-operation",
        InternalVectorAxisV1::None,
        MutationClassV1::WorkspaceDestructive,
    ),
    gate3_case(
        "ime_and_scaling",
        FixtureSpecIdV1::Gate3UiOperation,
        ValidatorIdV1::Gate3UiOperation,
        "ui-operation",
        InternalVectorAxisV1::ClosedFixtureVectorTable,
        MutationClassV1::ReadOnly,
    ),
];

const GATE_3_RUNTIME_CASES: [Gate3CaseDefinition; 15] = [
    gate3_case(
        "completed_restart_and_rollback",
        FixtureSpecIdV1::Gate3WorkspaceLifecycle,
        ValidatorIdV1::Gate3WorkspaceLifecycle,
        "workspace-lifecycle",
        InternalVectorAxisV1::None,
        MutationClassV1::WorkspaceDestructive,
    ),
    gate3_case(
        "dirty_repository_reconciliation",
        FixtureSpecIdV1::Gate3WorkspaceLifecycle,
        ValidatorIdV1::Gate3WorkspaceLifecycle,
        "workspace-lifecycle",
        InternalVectorAxisV1::ClosedFixtureVectorTable,
        MutationClassV1::WorkspaceDestructive,
    ),
    gate3_case(
        "external_edit_reconciliation",
        FixtureSpecIdV1::Gate3WorkspaceLifecycle,
        ValidatorIdV1::Gate3WorkspaceLifecycle,
        "workspace-lifecycle",
        InternalVectorAxisV1::ClosedFixtureVectorTable,
        MutationClassV1::WorkspaceDestructive,
    ),
    gate3_case(
        "crash_recovery_every_sprint_state",
        FixtureSpecIdV1::Gate3AllStateCrash,
        ValidatorIdV1::Gate3AllStateCrash,
        "all-state-crash",
        InternalVectorAxisV1::ClosedFixtureVectorTable,
        MutationClassV1::WorkspaceDestructive,
    ),
    gate3_case(
        "provider_outage_and_resume",
        FixtureSpecIdV1::Gate3ProviderOutage,
        ValidatorIdV1::Gate3ProviderOutage,
        "provider-outage",
        InternalVectorAxisV1::ClosedFixtureVectorTable,
        MutationClassV1::WorkspaceDestructive,
    ),
    gate3_case(
        "transport_backpressure_bound",
        FixtureSpecIdV1::Gate3Budget,
        ValidatorIdV1::Gate3Budget,
        "budget",
        InternalVectorAxisV1::ClosedFixtureVectorTable,
        MutationClassV1::ReadOnly,
    ),
    gate3_case(
        "context_compaction_bound",
        FixtureSpecIdV1::Gate3Budget,
        ValidatorIdV1::Gate3Budget,
        "budget",
        InternalVectorAxisV1::ClosedFixtureVectorTable,
        MutationClassV1::ReadOnly,
    ),
    gate3_case(
        "maximum_output_bound",
        FixtureSpecIdV1::Gate3Budget,
        ValidatorIdV1::Gate3Budget,
        "budget",
        InternalVectorAxisV1::ClosedFixtureVectorTable,
        MutationClassV1::ReadOnly,
    ),
    gate3_case(
        "full_disk_fail_closed",
        FixtureSpecIdV1::Gate3FullDisk,
        ValidatorIdV1::Gate3FullDisk,
        "full-disk",
        InternalVectorAxisV1::ClosedFixtureVectorTable,
        MutationClassV1::WorkspaceDestructive,
    ),
    gate3_case(
        "local_model_discovery_drift",
        FixtureSpecIdV1::Gate3LocalModelDrift,
        ValidatorIdV1::Gate3LocalModelDrift,
        "local-model-drift",
        InternalVectorAxisV1::ClosedFixtureVectorTable,
        MutationClassV1::ReadOnly,
    ),
    gate3_case(
        "dependency_rejection",
        FixtureSpecIdV1::Gate3DependencyPolicy,
        ValidatorIdV1::Gate3DependencyPolicy,
        "dependency-policy",
        InternalVectorAxisV1::ClosedFixtureVectorTable,
        MutationClassV1::ReadOnly,
    ),
    gate3_case(
        "diagnostic_secret_redaction",
        FixtureSpecIdV1::Gate3Redaction,
        ValidatorIdV1::Gate3Redaction,
        "redaction",
        InternalVectorAxisV1::ClosedFixtureVectorTable,
        MutationClassV1::ReadOnly,
    ),
    gate3_case(
        "performance_budgets",
        FixtureSpecIdV1::Gate3Budget,
        ValidatorIdV1::Gate3Budget,
        "budget",
        InternalVectorAxisV1::ClosedFixtureVectorTable,
        MutationClassV1::ReadOnly,
    ),
    gate3_case(
        "provider_secret_store_isolated",
        FixtureSpecIdV1::Gate3SecretStore,
        ValidatorIdV1::Gate3SecretStore,
        "secret-store",
        InternalVectorAxisV1::ClosedFixtureVectorTable,
        MutationClassV1::ReadOnly,
    ),
    gate3_case(
        "platform_state_paths_and_permissions",
        FixtureSpecIdV1::Gate3PlatformState,
        ValidatorIdV1::Gate3PlatformState,
        "platform-state",
        InternalVectorAxisV1::ClosedFixtureVectorTable,
        MutationClassV1::HostDestructive,
    ),
];

const GATE_3_REQUIREMENTS_CLOSURE_CASE: Gate3CaseDefinition = gate3_case(
    "requirements_evidence_base_closure",
    FixtureSpecIdV1::Gate3RequirementsBaseClosure,
    ValidatorIdV1::Gate3RequirementsBaseClosure,
    "requirements-base-closure",
    InternalVectorAxisV1::None,
    MutationClassV1::ReadOnly,
);

const GATE_3_PACKAGE_ROWS: [Gate3PackageRow; 4] = [
    Gate3PackageRow {
        row_id: Gate3RowIdV1::PackageMacosDmg,
        target: GateTargetV1::Macos15AppleSilicon,
        artifact: Gate3ArtifactV1::MacosDmg,
    },
    Gate3PackageRow {
        row_id: Gate3RowIdV1::PackageMacosZip,
        target: GateTargetV1::Macos15AppleSilicon,
        artifact: Gate3ArtifactV1::MacosZip,
    },
    Gate3PackageRow {
        row_id: Gate3RowIdV1::PackageUbuntuDeb,
        target: GateTargetV1::Ubuntu2604X8664,
        artifact: Gate3ArtifactV1::UbuntuDeb,
    },
    Gate3PackageRow {
        row_id: Gate3RowIdV1::PackageFedoraTar,
        target: GateTargetV1::Fedora44X8664,
        artifact: Gate3ArtifactV1::FedoraTarZst,
    },
];

const GATE_3_UI_ROWS: [Gate3UiRow; 5] = [
    Gate3UiRow {
        row_id: Gate3RowIdV1::UiMacosVoiceover,
        target: GateTargetV1::Macos15AppleSilicon,
        artifact: Gate3ArtifactV1::MacosDmg,
        native_session: Gate3NativeSessionV1::MacosVoiceoverAccessibility,
    },
    Gate3UiRow {
        row_id: Gate3RowIdV1::UiUbuntuWayland,
        target: GateTargetV1::Ubuntu2604X8664,
        artifact: Gate3ArtifactV1::UbuntuDeb,
        native_session: Gate3NativeSessionV1::UbuntuWaylandAtSpiOrca,
    },
    Gate3UiRow {
        row_id: Gate3RowIdV1::UiUbuntuX11,
        target: GateTargetV1::Ubuntu2604X8664,
        artifact: Gate3ArtifactV1::UbuntuDeb,
        native_session: Gate3NativeSessionV1::UbuntuX11AtSpiOrca,
    },
    Gate3UiRow {
        row_id: Gate3RowIdV1::UiFedoraWayland,
        target: GateTargetV1::Fedora44X8664,
        artifact: Gate3ArtifactV1::FedoraTarZst,
        native_session: Gate3NativeSessionV1::FedoraWaylandAtSpiOrca,
    },
    Gate3UiRow {
        row_id: Gate3RowIdV1::UiFedoraX11,
        target: GateTargetV1::Fedora44X8664,
        artifact: Gate3ArtifactV1::FedoraTarZst,
        native_session: Gate3NativeSessionV1::FedoraX11AtSpiOrca,
    },
];

const GATE_3_RUNTIME_ROWS: [Gate3RuntimeRow; 3] = [
    Gate3RuntimeRow {
        row_id: Gate3RowIdV1::RuntimeMacos,
        target: GateTargetV1::Macos15AppleSilicon,
        artifact: Gate3ArtifactV1::MacosDmg,
        native_session: Gate3NativeSessionV1::MacosSignedNormal,
    },
    Gate3RuntimeRow {
        row_id: Gate3RowIdV1::RuntimeUbuntu,
        target: GateTargetV1::Ubuntu2604X8664,
        artifact: Gate3ArtifactV1::UbuntuDeb,
        native_session: Gate3NativeSessionV1::UbuntuWaylandAtSpiOrca,
    },
    Gate3RuntimeRow {
        row_id: Gate3RowIdV1::RuntimeFedora,
        target: GateTargetV1::Fedora44X8664,
        artifact: Gate3ArtifactV1::FedoraTarZst,
        native_session: Gate3NativeSessionV1::FedoraWaylandAtSpiOrca,
    },
];

const COMPLETED_DISPOSITIONS: [Gate3ApplicationDispositionV1; 4] = [
    Gate3ApplicationDispositionV1::AppliedRollbackAvailable,
    Gate3ApplicationDispositionV1::VerifiedNoopNotApplicable,
    Gate3ApplicationDispositionV1::RolledBack,
    Gate3ApplicationDispositionV1::RollbackUnknown,
];
const BLOCKED_DISPOSITIONS: [Gate3ApplicationDispositionV1; 2] = [
    Gate3ApplicationDispositionV1::NoApplicationNotApplicable,
    Gate3ApplicationDispositionV1::AppliedRollbackAvailable,
];
const FAILED_DISPOSITIONS: [Gate3ApplicationDispositionV1; 1] =
    [Gate3ApplicationDispositionV1::NoApplicationNotApplicable];
const CANCELED_DISPOSITIONS: [Gate3ApplicationDispositionV1; 1] =
    [Gate3ApplicationDispositionV1::NoApplicationNotApplicable];
const UNKNOWN_DISPOSITIONS: [Gate3ApplicationDispositionV1; 4] = [
    Gate3ApplicationDispositionV1::NoApplicationNotApplicable,
    Gate3ApplicationDispositionV1::AppliedRollbackAvailable,
    Gate3ApplicationDispositionV1::ApplicationUnknown,
    Gate3ApplicationDispositionV1::RollbackUnknown,
];

const GATE_3_TERMINAL_CASES: [Gate3TerminalCaseDefinition; 5] = [
    terminal_case(
        "terminal_state_accessibility_completed",
        Gate3TerminalStateV1::Completed,
        &COMPLETED_DISPOSITIONS,
    ),
    terminal_case(
        "terminal_state_accessibility_blocked",
        Gate3TerminalStateV1::Blocked,
        &BLOCKED_DISPOSITIONS,
    ),
    terminal_case(
        "terminal_state_accessibility_failed",
        Gate3TerminalStateV1::Failed,
        &FAILED_DISPOSITIONS,
    ),
    terminal_case(
        "terminal_state_accessibility_canceled",
        Gate3TerminalStateV1::Canceled,
        &CANCELED_DISPOSITIONS,
    ),
    terminal_case(
        "terminal_state_accessibility_unknown",
        Gate3TerminalStateV1::Unknown,
        &UNKNOWN_DISPOSITIONS,
    ),
];

#[derive(Clone, Copy)]
struct CaseDefinition {
    case_id: &'static str,
    fixture_id: FixtureSpecIdV1,
    validator_id: ValidatorIdV1,
    run_group_slug: &'static str,
    authority_phase: AuthorityPhaseV1,
    internal_vector_axis: InternalVectorAxisV1,
    mutation_class: MutationClassV1,
}

const fn case(
    case_id: &'static str,
    fixture_id: FixtureSpecIdV1,
    validator_id: ValidatorIdV1,
    run_group_slug: &'static str,
    authority_phase: AuthorityPhaseV1,
    internal_vector_axis: InternalVectorAxisV1,
    mutation_class: MutationClassV1,
) -> CaseDefinition {
    CaseDefinition {
        case_id,
        fixture_id,
        validator_id,
        run_group_slug,
        authority_phase,
        internal_vector_axis,
        mutation_class,
    }
}

#[derive(Clone, Copy)]
struct Gate2CaseDefinition {
    case_id: &'static str,
    fixture_id: FixtureSpecIdV1,
    validator_id: ValidatorIdV1,
    run_group_slug: &'static str,
    mutation_class: MutationClassV1,
}

const fn gate2_case(
    case_id: &'static str,
    fixture_id: FixtureSpecIdV1,
    validator_id: ValidatorIdV1,
    run_group_slug: &'static str,
    mutation_class: MutationClassV1,
) -> Gate2CaseDefinition {
    Gate2CaseDefinition {
        case_id,
        fixture_id,
        validator_id,
        run_group_slug,
        mutation_class,
    }
}

#[derive(Clone, Copy)]
struct ProviderCaseDefinition {
    provider: ProviderIdV1,
    normalized_case_id: &'static str,
    live_case_id: &'static str,
    live_fixture_id: FixtureSpecIdV1,
    live_validator_id: ValidatorIdV1,
}

const fn provider_case(
    provider: ProviderIdV1,
    normalized_case_id: &'static str,
    live_case_id: &'static str,
    live_fixture_id: FixtureSpecIdV1,
    live_validator_id: ValidatorIdV1,
) -> ProviderCaseDefinition {
    ProviderCaseDefinition {
        provider,
        normalized_case_id,
        live_case_id,
        live_fixture_id,
        live_validator_id,
    }
}

#[derive(Clone, Copy)]
struct Gate3CaseDefinition {
    case_id: &'static str,
    fixture_id: FixtureSpecIdV1,
    validator_id: ValidatorIdV1,
    run_group_slug: &'static str,
    internal_vector_axis: InternalVectorAxisV1,
    mutation_class: MutationClassV1,
}

const fn gate3_case(
    case_id: &'static str,
    fixture_id: FixtureSpecIdV1,
    validator_id: ValidatorIdV1,
    run_group_slug: &'static str,
    internal_vector_axis: InternalVectorAxisV1,
    mutation_class: MutationClassV1,
) -> Gate3CaseDefinition {
    Gate3CaseDefinition {
        case_id,
        fixture_id,
        validator_id,
        run_group_slug,
        internal_vector_axis,
        mutation_class,
    }
}

#[derive(Clone, Copy)]
struct Gate3PackageRow {
    row_id: Gate3RowIdV1,
    target: GateTargetV1,
    artifact: Gate3ArtifactV1,
}

#[derive(Clone, Copy)]
struct Gate3UiRow {
    row_id: Gate3RowIdV1,
    target: GateTargetV1,
    artifact: Gate3ArtifactV1,
    native_session: Gate3NativeSessionV1,
}

#[derive(Clone, Copy)]
struct Gate3RuntimeRow {
    row_id: Gate3RowIdV1,
    target: GateTargetV1,
    artifact: Gate3ArtifactV1,
    native_session: Gate3NativeSessionV1,
}

#[derive(Clone, Copy)]
struct Gate3TerminalCaseDefinition {
    case: Gate3CaseDefinition,
    terminal_state: Gate3TerminalStateV1,
    dispositions: &'static [Gate3ApplicationDispositionV1],
}

const fn terminal_case(
    case_id: &'static str,
    terminal_state: Gate3TerminalStateV1,
    dispositions: &'static [Gate3ApplicationDispositionV1],
) -> Gate3TerminalCaseDefinition {
    Gate3TerminalCaseDefinition {
        case: gate3_case(
            case_id,
            FixtureSpecIdV1::Gate3TerminalAccessibility,
            ValidatorIdV1::Gate3TerminalAccessibility,
            "terminal-accessibility",
            InternalVectorAxisV1::None,
            MutationClassV1::ReadOnly,
        ),
        terminal_state,
        dispositions,
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RegistryGateSelectionV1 {
    Gate1,
    Gate2,
    Gate3,
}

impl RegistryGateSelectionV1 {
    pub(crate) const fn label(self) -> &'static str {
        match self {
            Self::Gate1 => "Gate 1",
            Self::Gate2 => "Gate 2",
            Self::Gate3 => "Gate 3 additions",
        }
    }

    const fn result_prefix(self) -> &'static str {
        match self {
            Self::Gate1 => "g1.",
            Self::Gate2 => "g2.",
            Self::Gate3 => "g3.",
        }
    }

    const fn coordinator(self) -> ProgramIdV1 {
        match self {
            Self::Gate1 => ProgramIdV1::Gate1,
            Self::Gate2 => ProgramIdV1::Gate2,
            Self::Gate3 => ProgramIdV1::Gate3,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct GateCaseRegistryV1 {
    schema: RegistrySchemaV1,
    registry_version: u32,
    authority_status: RegistryAuthorityStatusV1,
    projection_of_manifest_version: u32,
    pub(crate) specifications: Vec<GateCaseSpecV1>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
enum RegistrySchemaV1 {
    #[serde(rename = "gb.gate-case-registry.v1")]
    GateCaseRegistryV1,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
enum RegistryAuthorityStatusV1 {
    NonAuthoritativeProjection,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct GateCaseSpecV1 {
    result_id: String,
    case_id: String,
    gate: GateIdV1,
    target: GateTargetV1,
    fixture_id: FixtureSpecIdV1,
    run_group_id: String,
    axes: GateCaseAxesV1,
    preconditions: Vec<GatePreconditionV1>,
    execution: GateExecutionV1,
    validator: GateValidatorV1,
    expected_artifacts: Vec<ExpectedArtifactV1>,
    bound_inputs: Vec<BoundInputIdentityV1>,
    deterministic_output: bool,
    shared_evidence_ids: Vec<String>,
    isolation: IsolationRequirementV1,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
enum GateIdV1 {
    #[serde(rename = "hard-gate-1")]
    HardGate1,
    #[serde(rename = "hard-gate-2")]
    HardGate2,
    #[serde(rename = "hard-gate-3")]
    HardGate3,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
enum GateTargetV1 {
    #[serde(rename = "macos-15-apple-silicon")]
    Macos15AppleSilicon,
    #[serde(rename = "ubuntu-26.04-x86_64")]
    Ubuntu2604X8664,
    #[serde(rename = "fedora-44-x86_64")]
    Fedora44X8664,
    #[serde(rename = "global")]
    Global,
}

impl GateTargetV1 {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Macos15AppleSilicon => "macos-15-apple-silicon",
            Self::Ubuntu2604X8664 => "ubuntu-26.04-x86_64",
            Self::Fedora44X8664 => "fedora-44-x86_64",
            Self::Global => "global",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
enum FixtureSpecIdV1 {
    #[serde(rename = "gb.fixture.g1.native-admission.v1")]
    NativeAdmission,
    #[serde(rename = "gb.fixture.g1.macos-native.v1")]
    MacosNative,
    #[serde(rename = "gb.fixture.g1.linux-native.v1")]
    LinuxNative,
    #[serde(rename = "gb.fixture.g1.walking-skeleton.v1")]
    WalkingSkeleton,
    #[serde(rename = "gb.fixture.g1.workspace-denial.v1")]
    WorkspaceDenial,
    #[serde(rename = "gb.fixture.g1.command-isolation.v1")]
    CommandIsolation,
    #[serde(rename = "gb.fixture.g1.cancel.v1")]
    Cancel,
    #[serde(rename = "gb.fixture.g1.stale-apply.v1")]
    StaleApply,
    #[serde(rename = "gb.fixture.g1.launch-cleanup-race.v1")]
    LaunchCleanupRace,
    #[serde(rename = "gb.fixture.g1.crash-journal.v1")]
    CrashJournal,
    #[serde(rename = "gb.fixture.g1.restart.v1")]
    Restart,
    #[serde(rename = "gb.fixture.g1.apply.v1")]
    Apply,
    #[serde(rename = "gb.fixture.g1.rollback.v1")]
    Rollback,
    #[serde(rename = "gb.fixture.g1.offline-build.v1")]
    OfflineBuild,
    #[serde(rename = "gb.fixture.g2.cumulative-identity.v1")]
    Gate2CumulativeIdentity,
    #[serde(rename = "gb.fixture.g2.scheduler-collision.v1")]
    Gate2SchedulerCollision,
    #[serde(rename = "gb.fixture.g2.repair.v1")]
    Gate2Repair,
    #[serde(rename = "gb.fixture.g2.crash.v1")]
    Gate2Crash,
    #[serde(rename = "gb.fixture.g2.verification-apply.v1")]
    Gate2VerificationApply,
    #[serde(rename = "gb.fixture.g2.single-grant.v1")]
    Gate2SingleGrant,
    #[serde(rename = "gb.fixture.g2.attempt-closure.v1")]
    Gate2AttemptClosure,
    #[serde(rename = "gb.fixture.g2.restart-rollback.v1")]
    Gate2RestartRollback,
    #[serde(rename = "gb.fixture.g2.run-control.v1")]
    Gate2RunControl,
    #[serde(rename = "gb.fixture.g2.repository-shape.v1")]
    Gate2RepositoryShape,
    #[serde(rename = "gb.fixture.g2.provider-contract.v1")]
    Gate2ProviderContract,
    #[serde(rename = "gb.fixture.g2.xai-live.v1")]
    Gate2XaiLive,
    #[serde(rename = "gb.fixture.g2.local-provider-live.v1")]
    Gate2LocalProviderLive,
    #[serde(rename = "gb.fixture.g3.artifact.v1")]
    Gate3Artifact,
    #[serde(rename = "gb.fixture.g3.lifecycle.v1")]
    Gate3Lifecycle,
    #[serde(rename = "gb.fixture.g3.workspace-lifecycle.v1")]
    Gate3WorkspaceLifecycle,
    #[serde(rename = "gb.fixture.g3.all-state-crash.v1")]
    Gate3AllStateCrash,
    #[serde(rename = "gb.fixture.g3.terminal-accessibility.v1")]
    Gate3TerminalAccessibility,
    #[serde(rename = "gb.fixture.g3.ui-operation.v1")]
    Gate3UiOperation,
    #[serde(rename = "gb.fixture.g3.provider-outage.v1")]
    Gate3ProviderOutage,
    #[serde(rename = "gb.fixture.g3.budget.v1")]
    Gate3Budget,
    #[serde(rename = "gb.fixture.g3.full-disk.v1")]
    Gate3FullDisk,
    #[serde(rename = "gb.fixture.g3.local-model-drift.v1")]
    Gate3LocalModelDrift,
    #[serde(rename = "gb.fixture.g3.dependency-policy.v1")]
    Gate3DependencyPolicy,
    #[serde(rename = "gb.fixture.g3.redaction.v1")]
    Gate3Redaction,
    #[serde(rename = "gb.fixture.g3.secret-store.v1")]
    Gate3SecretStore,
    #[serde(rename = "gb.fixture.g3.platform-state.v1")]
    Gate3PlatformState,
    #[serde(rename = "gb.fixture.g3.requirements-base-closure.v1")]
    Gate3RequirementsBaseClosure,
}

impl FixtureSpecIdV1 {
    const fn as_str(self) -> &'static str {
        match self {
            Self::NativeAdmission => "gb.fixture.g1.native-admission.v1",
            Self::MacosNative => "gb.fixture.g1.macos-native.v1",
            Self::LinuxNative => "gb.fixture.g1.linux-native.v1",
            Self::WalkingSkeleton => "gb.fixture.g1.walking-skeleton.v1",
            Self::WorkspaceDenial => "gb.fixture.g1.workspace-denial.v1",
            Self::CommandIsolation => "gb.fixture.g1.command-isolation.v1",
            Self::Cancel => "gb.fixture.g1.cancel.v1",
            Self::StaleApply => "gb.fixture.g1.stale-apply.v1",
            Self::LaunchCleanupRace => "gb.fixture.g1.launch-cleanup-race.v1",
            Self::CrashJournal => "gb.fixture.g1.crash-journal.v1",
            Self::Restart => "gb.fixture.g1.restart.v1",
            Self::Apply => "gb.fixture.g1.apply.v1",
            Self::Rollback => "gb.fixture.g1.rollback.v1",
            Self::OfflineBuild => "gb.fixture.g1.offline-build.v1",
            Self::Gate2CumulativeIdentity => "gb.fixture.g2.cumulative-identity.v1",
            Self::Gate2SchedulerCollision => "gb.fixture.g2.scheduler-collision.v1",
            Self::Gate2Repair => "gb.fixture.g2.repair.v1",
            Self::Gate2Crash => "gb.fixture.g2.crash.v1",
            Self::Gate2VerificationApply => "gb.fixture.g2.verification-apply.v1",
            Self::Gate2SingleGrant => "gb.fixture.g2.single-grant.v1",
            Self::Gate2AttemptClosure => "gb.fixture.g2.attempt-closure.v1",
            Self::Gate2RestartRollback => "gb.fixture.g2.restart-rollback.v1",
            Self::Gate2RunControl => "gb.fixture.g2.run-control.v1",
            Self::Gate2RepositoryShape => "gb.fixture.g2.repository-shape.v1",
            Self::Gate2ProviderContract => "gb.fixture.g2.provider-contract.v1",
            Self::Gate2XaiLive => "gb.fixture.g2.xai-live.v1",
            Self::Gate2LocalProviderLive => "gb.fixture.g2.local-provider-live.v1",
            Self::Gate3Artifact => "gb.fixture.g3.artifact.v1",
            Self::Gate3Lifecycle => "gb.fixture.g3.lifecycle.v1",
            Self::Gate3WorkspaceLifecycle => "gb.fixture.g3.workspace-lifecycle.v1",
            Self::Gate3AllStateCrash => "gb.fixture.g3.all-state-crash.v1",
            Self::Gate3TerminalAccessibility => "gb.fixture.g3.terminal-accessibility.v1",
            Self::Gate3UiOperation => "gb.fixture.g3.ui-operation.v1",
            Self::Gate3ProviderOutage => "gb.fixture.g3.provider-outage.v1",
            Self::Gate3Budget => "gb.fixture.g3.budget.v1",
            Self::Gate3FullDisk => "gb.fixture.g3.full-disk.v1",
            Self::Gate3LocalModelDrift => "gb.fixture.g3.local-model-drift.v1",
            Self::Gate3DependencyPolicy => "gb.fixture.g3.dependency-policy.v1",
            Self::Gate3Redaction => "gb.fixture.g3.redaction.v1",
            Self::Gate3SecretStore => "gb.fixture.g3.secret-store.v1",
            Self::Gate3PlatformState => "gb.fixture.g3.platform-state.v1",
            Self::Gate3RequirementsBaseClosure => "gb.fixture.g3.requirements-base-closure.v1",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
enum ValidatorIdV1 {
    #[serde(rename = "gb.validator.g1.native-admission.v1")]
    NativeAdmission,
    #[serde(rename = "gb.validator.g1.macos-native.v1")]
    MacosNative,
    #[serde(rename = "gb.validator.g1.linux-native.v1")]
    LinuxNative,
    #[serde(rename = "gb.validator.g1.walking-skeleton.v1")]
    WalkingSkeleton,
    #[serde(rename = "gb.validator.g1.workspace-denial.v1")]
    WorkspaceDenial,
    #[serde(rename = "gb.validator.g1.command-isolation.v1")]
    CommandIsolation,
    #[serde(rename = "gb.validator.g1.cancel.v1")]
    Cancel,
    #[serde(rename = "gb.validator.g1.stale-apply.v1")]
    StaleApply,
    #[serde(rename = "gb.validator.g1.launch-cleanup-race.v1")]
    LaunchCleanupRace,
    #[serde(rename = "gb.validator.g1.crash-journal.v1")]
    CrashJournal,
    #[serde(rename = "gb.validator.g1.restart.v1")]
    Restart,
    #[serde(rename = "gb.validator.g1.apply.v1")]
    Apply,
    #[serde(rename = "gb.validator.g1.rollback.v1")]
    Rollback,
    #[serde(rename = "gb.validator.g1.offline-build.v1")]
    OfflineBuild,
    #[serde(rename = "gb.validator.g2.cumulative-identity.v1")]
    Gate2CumulativeIdentity,
    #[serde(rename = "gb.validator.g2.scheduler-collision.v1")]
    Gate2SchedulerCollision,
    #[serde(rename = "gb.validator.g2.repair.v1")]
    Gate2Repair,
    #[serde(rename = "gb.validator.g2.crash.v1")]
    Gate2Crash,
    #[serde(rename = "gb.validator.g2.verification-apply.v1")]
    Gate2VerificationApply,
    #[serde(rename = "gb.validator.g2.single-grant.v1")]
    Gate2SingleGrant,
    #[serde(rename = "gb.validator.g2.attempt-closure.v1")]
    Gate2AttemptClosure,
    #[serde(rename = "gb.validator.g2.restart-rollback.v1")]
    Gate2RestartRollback,
    #[serde(rename = "gb.validator.g2.run-control.v1")]
    Gate2RunControl,
    #[serde(rename = "gb.validator.g2.repository-shape.v1")]
    Gate2RepositoryShape,
    #[serde(rename = "gb.validator.g2.provider-contract.v1")]
    Gate2ProviderContract,
    #[serde(rename = "gb.validator.g2.xai-live.v1")]
    Gate2XaiLive,
    #[serde(rename = "gb.validator.g2.local-provider-live.v1")]
    Gate2LocalProviderLive,
    #[serde(rename = "gb.validator.g3.artifact.v1")]
    Gate3Artifact,
    #[serde(rename = "gb.validator.g3.lifecycle.v1")]
    Gate3Lifecycle,
    #[serde(rename = "gb.validator.g3.workspace-lifecycle.v1")]
    Gate3WorkspaceLifecycle,
    #[serde(rename = "gb.validator.g3.all-state-crash.v1")]
    Gate3AllStateCrash,
    #[serde(rename = "gb.validator.g3.terminal-accessibility.v1")]
    Gate3TerminalAccessibility,
    #[serde(rename = "gb.validator.g3.ui-operation.v1")]
    Gate3UiOperation,
    #[serde(rename = "gb.validator.g3.provider-outage.v1")]
    Gate3ProviderOutage,
    #[serde(rename = "gb.validator.g3.budget.v1")]
    Gate3Budget,
    #[serde(rename = "gb.validator.g3.full-disk.v1")]
    Gate3FullDisk,
    #[serde(rename = "gb.validator.g3.local-model-drift.v1")]
    Gate3LocalModelDrift,
    #[serde(rename = "gb.validator.g3.dependency-policy.v1")]
    Gate3DependencyPolicy,
    #[serde(rename = "gb.validator.g3.redaction.v1")]
    Gate3Redaction,
    #[serde(rename = "gb.validator.g3.secret-store.v1")]
    Gate3SecretStore,
    #[serde(rename = "gb.validator.g3.platform-state.v1")]
    Gate3PlatformState,
    #[serde(rename = "gb.validator.g3.requirements-base-closure.v1")]
    Gate3RequirementsBaseClosure,
}

impl ValidatorIdV1 {
    const fn as_str(self) -> &'static str {
        match self {
            Self::NativeAdmission => "gb.validator.g1.native-admission.v1",
            Self::MacosNative => "gb.validator.g1.macos-native.v1",
            Self::LinuxNative => "gb.validator.g1.linux-native.v1",
            Self::WalkingSkeleton => "gb.validator.g1.walking-skeleton.v1",
            Self::WorkspaceDenial => "gb.validator.g1.workspace-denial.v1",
            Self::CommandIsolation => "gb.validator.g1.command-isolation.v1",
            Self::Cancel => "gb.validator.g1.cancel.v1",
            Self::StaleApply => "gb.validator.g1.stale-apply.v1",
            Self::LaunchCleanupRace => "gb.validator.g1.launch-cleanup-race.v1",
            Self::CrashJournal => "gb.validator.g1.crash-journal.v1",
            Self::Restart => "gb.validator.g1.restart.v1",
            Self::Apply => "gb.validator.g1.apply.v1",
            Self::Rollback => "gb.validator.g1.rollback.v1",
            Self::OfflineBuild => "gb.validator.g1.offline-build.v1",
            Self::Gate2CumulativeIdentity => "gb.validator.g2.cumulative-identity.v1",
            Self::Gate2SchedulerCollision => "gb.validator.g2.scheduler-collision.v1",
            Self::Gate2Repair => "gb.validator.g2.repair.v1",
            Self::Gate2Crash => "gb.validator.g2.crash.v1",
            Self::Gate2VerificationApply => "gb.validator.g2.verification-apply.v1",
            Self::Gate2SingleGrant => "gb.validator.g2.single-grant.v1",
            Self::Gate2AttemptClosure => "gb.validator.g2.attempt-closure.v1",
            Self::Gate2RestartRollback => "gb.validator.g2.restart-rollback.v1",
            Self::Gate2RunControl => "gb.validator.g2.run-control.v1",
            Self::Gate2RepositoryShape => "gb.validator.g2.repository-shape.v1",
            Self::Gate2ProviderContract => "gb.validator.g2.provider-contract.v1",
            Self::Gate2XaiLive => "gb.validator.g2.xai-live.v1",
            Self::Gate2LocalProviderLive => "gb.validator.g2.local-provider-live.v1",
            Self::Gate3Artifact => "gb.validator.g3.artifact.v1",
            Self::Gate3Lifecycle => "gb.validator.g3.lifecycle.v1",
            Self::Gate3WorkspaceLifecycle => "gb.validator.g3.workspace-lifecycle.v1",
            Self::Gate3AllStateCrash => "gb.validator.g3.all-state-crash.v1",
            Self::Gate3TerminalAccessibility => "gb.validator.g3.terminal-accessibility.v1",
            Self::Gate3UiOperation => "gb.validator.g3.ui-operation.v1",
            Self::Gate3ProviderOutage => "gb.validator.g3.provider-outage.v1",
            Self::Gate3Budget => "gb.validator.g3.budget.v1",
            Self::Gate3FullDisk => "gb.validator.g3.full-disk.v1",
            Self::Gate3LocalModelDrift => "gb.validator.g3.local-model-drift.v1",
            Self::Gate3DependencyPolicy => "gb.validator.g3.dependency-policy.v1",
            Self::Gate3Redaction => "gb.validator.g3.redaction.v1",
            Self::Gate3SecretStore => "gb.validator.g3.secret-store.v1",
            Self::Gate3PlatformState => "gb.validator.g3.platform-state.v1",
            Self::Gate3RequirementsBaseClosure => "gb.validator.g3.requirements-base-closure.v1",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum AuthorityPhaseV1 {
    PreAdmission,
    PostAdmission,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum InternalVectorAxisV1 {
    None,
    ClosedFixtureVectorTable,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum MutationClassV1 {
    ReadOnly,
    WorkspaceDestructive,
    ProcessDomainDestructive,
    HostDestructive,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct GateCaseAxesV1 {
    authority_phase: AuthorityPhaseV1,
    internal_vector_axis: InternalVectorAxisV1,
    mutation_class: MutationClassV1,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    worker_ceiling: Option<u8>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    crash_cut: Option<CrashCutV1>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    expected_outcome_class: Option<ExpectedOutcomeClassV1>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    repository_shape: Option<RepositoryShapeV1>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    provider: Option<ProviderIdV1>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    provider_mode: Option<ProviderModeV1>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    gate_3_group: Option<Gate3CaseGroupV1>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    gate_3_row_id: Option<Gate3RowIdV1>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    artifact: Option<Gate3ArtifactV1>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    native_session: Option<Gate3NativeSessionV1>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    terminal_state: Option<Gate3TerminalStateV1>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    application_disposition: Option<Gate3ApplicationDispositionV1>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum CrashCutV1 {
    None,
    BeforeCommandWrite,
    AfterCommandWrite,
    AfterMutation,
    AfterTaskVerification,
    AfterIntegration,
    BeforeFinalApplication,
}

impl CrashCutV1 {
    const ALL: [Self; 7] = [
        Self::None,
        Self::BeforeCommandWrite,
        Self::AfterCommandWrite,
        Self::AfterMutation,
        Self::AfterTaskVerification,
        Self::AfterIntegration,
        Self::BeforeFinalApplication,
    ];

    const fn slug(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::BeforeCommandWrite => "before-command-write",
            Self::AfterCommandWrite => "after-command-write",
            Self::AfterMutation => "after-mutation",
            Self::AfterTaskVerification => "after-task-verification",
            Self::AfterIntegration => "after-integration",
            Self::BeforeFinalApplication => "before-final-application",
        }
    }

    const fn expected_outcome_class(self) -> ExpectedOutcomeClassV1 {
        match self {
            Self::BeforeCommandWrite => ExpectedOutcomeClassV1::KnownBeforeEffect,
            Self::AfterCommandWrite | Self::AfterMutation => {
                ExpectedOutcomeClassV1::TruthfulSprintUnknown
            }
            Self::None
            | Self::AfterTaskVerification
            | Self::AfterIntegration
            | Self::BeforeFinalApplication => ExpectedOutcomeClassV1::KnownTerminal,
        }
    }

    const fn continues_to_completion(self) -> bool {
        !matches!(self, Self::AfterCommandWrite | Self::AfterMutation)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
enum ExpectedOutcomeClassV1 {
    KnownBeforeEffect,
    KnownTerminal,
    TruthfulSprintUnknown,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum RepositoryShapeV1 {
    CleanGitCollision,
    DirtyGit,
    NonGit,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum ProviderIdV1 {
    Xai,
    Ollama,
    LmStudio,
}

impl ProviderIdV1 {
    const fn slug(self) -> &'static str {
        match self {
            Self::Xai => "xai",
            Self::Ollama => "ollama",
            Self::LmStudio => "lm-studio",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum ProviderModeV1 {
    NormalizedContract,
    LiveCompletedSprint,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum Gate3CaseGroupV1 {
    PackageLifecycle,
    UiAccessibility,
    RuntimeResilience,
    RequirementsEvidenceBaseClosure,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
enum Gate3RowIdV1 {
    #[serde(rename = "g3-package-macos-dmg-v1")]
    PackageMacosDmg,
    #[serde(rename = "g3-package-macos-zip-v1")]
    PackageMacosZip,
    #[serde(rename = "g3-package-ubuntu-deb-v1")]
    PackageUbuntuDeb,
    #[serde(rename = "g3-package-fedora-tar-v1")]
    PackageFedoraTar,
    #[serde(rename = "g3-ui-macos-voiceover-v1")]
    UiMacosVoiceover,
    #[serde(rename = "g3-ui-ubuntu-wayland-v1")]
    UiUbuntuWayland,
    #[serde(rename = "g3-ui-ubuntu-x11-v1")]
    UiUbuntuX11,
    #[serde(rename = "g3-ui-fedora-wayland-v1")]
    UiFedoraWayland,
    #[serde(rename = "g3-ui-fedora-x11-v1")]
    UiFedoraX11,
    #[serde(rename = "g3-runtime-macos-v1")]
    RuntimeMacos,
    #[serde(rename = "g3-runtime-ubuntu-v1")]
    RuntimeUbuntu,
    #[serde(rename = "g3-runtime-fedora-v1")]
    RuntimeFedora,
}

impl Gate3RowIdV1 {
    const fn as_str(self) -> &'static str {
        match self {
            Self::PackageMacosDmg => "g3-package-macos-dmg-v1",
            Self::PackageMacosZip => "g3-package-macos-zip-v1",
            Self::PackageUbuntuDeb => "g3-package-ubuntu-deb-v1",
            Self::PackageFedoraTar => "g3-package-fedora-tar-v1",
            Self::UiMacosVoiceover => "g3-ui-macos-voiceover-v1",
            Self::UiUbuntuWayland => "g3-ui-ubuntu-wayland-v1",
            Self::UiUbuntuX11 => "g3-ui-ubuntu-x11-v1",
            Self::UiFedoraWayland => "g3-ui-fedora-wayland-v1",
            Self::UiFedoraX11 => "g3-ui-fedora-x11-v1",
            Self::RuntimeMacos => "g3-runtime-macos-v1",
            Self::RuntimeUbuntu => "g3-runtime-ubuntu-v1",
            Self::RuntimeFedora => "g3-runtime-fedora-v1",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum Gate3ArtifactV1 {
    MacosDmg,
    MacosZip,
    UbuntuDeb,
    FedoraTarZst,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum Gate3NativeSessionV1 {
    MacosSignedNormal,
    MacosVoiceoverAccessibility,
    UbuntuWaylandAtSpiOrca,
    UbuntuX11AtSpiOrca,
    FedoraWaylandAtSpiOrca,
    FedoraX11AtSpiOrca,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum Gate3TerminalStateV1 {
    Completed,
    Blocked,
    Failed,
    Canceled,
    Unknown,
}

impl Gate3TerminalStateV1 {
    const fn slug(self) -> &'static str {
        match self {
            Self::Completed => "completed",
            Self::Blocked => "blocked",
            Self::Failed => "failed",
            Self::Canceled => "canceled",
            Self::Unknown => "unknown",
        }
    }
}

const fn terminal_case_id(state: Gate3TerminalStateV1) -> &'static str {
    match state {
        Gate3TerminalStateV1::Completed => "terminal_state_accessibility_completed",
        Gate3TerminalStateV1::Blocked => "terminal_state_accessibility_blocked",
        Gate3TerminalStateV1::Failed => "terminal_state_accessibility_failed",
        Gate3TerminalStateV1::Canceled => "terminal_state_accessibility_canceled",
        Gate3TerminalStateV1::Unknown => "terminal_state_accessibility_unknown",
    }
}

const fn legal_terminal_dispositions(
    state: Gate3TerminalStateV1,
) -> &'static [Gate3ApplicationDispositionV1] {
    match state {
        Gate3TerminalStateV1::Completed => &COMPLETED_DISPOSITIONS,
        Gate3TerminalStateV1::Blocked => &BLOCKED_DISPOSITIONS,
        Gate3TerminalStateV1::Failed => &FAILED_DISPOSITIONS,
        Gate3TerminalStateV1::Canceled => &CANCELED_DISPOSITIONS,
        Gate3TerminalStateV1::Unknown => &UNKNOWN_DISPOSITIONS,
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
enum Gate3ApplicationDispositionV1 {
    AppliedRollbackAvailable,
    VerifiedNoopNotApplicable,
    RolledBack,
    RollbackUnknown,
    NoApplicationNotApplicable,
    ApplicationUnknown,
}

impl Gate3ApplicationDispositionV1 {
    const fn slug(self) -> &'static str {
        match self {
            Self::AppliedRollbackAvailable => "applied-rollback-available",
            Self::VerifiedNoopNotApplicable => "verified-noop-not-applicable",
            Self::RolledBack => "rolled-back",
            Self::RollbackUnknown => "rollback-unknown",
            Self::NoApplicationNotApplicable => "no-application-not-applicable",
            Self::ApplicationUnknown => "application-unknown",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
enum GatePreconditionV1 {
    ImmutableSourceIdentity,
    ExactTargetImage,
    SourceBoundFixtureBinary,
    EvidenceOnlyAuthority,
    ProductionAdmittedAuthority,
    Gate1IdentityValid,
    HumanLaunchedLiveProvider,
    ProviderCapabilityProbe,
    Gate2IdentityValid,
    ProtectedReleaseIdentity,
    SignedReleaseArtifact,
    CleanHost,
    InstalledReleaseArtifact,
    NativeDisplaySession,
    TwoIndependentReleaseMatricesComplete,
    ClosedDefectSnapshot,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct GateExecutionV1 {
    availability: ExecutionAvailabilityV1,
    program: ProgramIdV1,
    argv: Vec<String>,
    missing_capability: ExecutionMissingCapabilityV1,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum ExecutionAvailabilityV1 {
    Unavailable,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
enum ProgramIdV1 {
    #[serde(rename = "grok-build-gate-1")]
    Gate1,
    #[serde(rename = "grok-build-gate-2")]
    Gate2,
    #[serde(rename = "grok-build-gate-3")]
    Gate3,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum ExecutionMissingCapabilityV1 {
    ProductionFixtureExecutor,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct GateValidatorV1 {
    validator_id: ValidatorIdV1,
    availability: ValidatorAvailabilityV1,
    missing_capability: ValidatorMissingCapabilityV1,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum ValidatorAvailabilityV1 {
    ContractOnly,
    Unavailable,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum ValidatorMissingCapabilityV1 {
    ProductionObservationJoin,
    ValidatorImplementation,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct ExpectedArtifactV1 {
    role: ArtifactRoleV1,
    identity_field: ArtifactIdentityFieldV1,
    digest_field: ArtifactDigestFieldV1,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
enum ArtifactRoleV1 {
    TypedObservation,
    Stdout,
    Stderr,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum ArtifactIdentityFieldV1 {
    ResultId,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum ArtifactDigestFieldV1 {
    Sha256,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
enum BoundInputIdentityV1 {
    SourceCommit,
    SourceTree,
    CargoLock,
    Toolchain,
    ReleaseTargetManifestV1,
    GateCaseManifestV2,
    Policy,
    FixtureBinary,
    BackendBinary,
    InputFixture,
    PlatformImage,
    EvidenceOnlyAuthority,
    WorkspaceGrant,
    SprintSpec,
    ProductionAdmission,
    Gate1EvidenceIdentity,
    CrashOutcomeClassTable,
    SchedulerPolicy,
    IntegrationPolicy,
    VerificationPolicy,
    ApplicationPolicy,
    RepositoryShapeFixture,
    ProviderPolicy,
    ProviderRecording,
    ProviderEndpoint,
    ProviderModel,
    ProviderCapabilities,
    Gate2EvidenceIdentity,
    ProtectedTag,
    ReleaseArtifact,
    SigningNotarizationPolicy,
    SbomNoticesProvenancePolicy,
    PlatformStateUninstallPolicyV1,
    AccessibilityPolicy,
    PerformanceResourceBudget,
    RequirementsTraceability,
    RequirementsEvidenceClosure,
    SupportArtifactRegistry,
    DefectSnapshot,
    Gate3NonClosureCaseResults,
    ReleaseMatrixR1,
    ReleaseMatrixR2,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct IsolationRequirementV1 {
    executor_scope: ExecutorIsolationV1,
    fixture_reset: FixtureResetV1,
    cleanup: CleanupRequirementV1,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum ExecutorIsolationV1 {
    EphemeralTargetRow,
    FreshCleanHost,
    InstalledNativeSession,
    InstalledRuntimeTarget,
    GlobalReadOnlyClosure,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum FixtureResetV1 {
    FreshFixtureRootPerRunGroup,
    FreshHostPerPackageRow,
    FreshInstalledSessionPerUiRow,
    FreshInstalledRuntimePerRuntimeRow,
    NotApplicableReadOnly,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum CleanupRequirementV1 {
    ProofRequiredBeforeNextRunGroup,
    NoNativeDomainExpected,
}

#[derive(Debug)]
pub(crate) struct RegistryError(String);

impl fmt::Display for RegistryError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl std::error::Error for RegistryError {}

pub(crate) fn checked_in_registry(
    gate: RegistryGateSelectionV1,
) -> Result<GateCaseRegistryV1, RegistryError> {
    let bytes = match gate {
        RegistryGateSelectionV1::Gate1 => CHECKED_IN_GATE_1_REGISTRY,
        RegistryGateSelectionV1::Gate2 => CHECKED_IN_GATE_2_REGISTRY,
        RegistryGateSelectionV1::Gate3 => CHECKED_IN_GATE_3_REGISTRY,
    };
    decode_registry(bytes, gate)
}

fn decode_registry(
    bytes: &[u8],
    expected_gate: RegistryGateSelectionV1,
) -> Result<GateCaseRegistryV1, RegistryError> {
    if bytes.is_empty() || bytes.len() > MAX_REGISTRY_BYTES {
        return Err(invalid("gate registry is empty or exceeds 4 MiB"));
    }
    let registry: GateCaseRegistryV1 = serde_json::from_slice(bytes)
        .map_err(|error| invalid(format!("cannot decode gate registry: {error}")))?;
    let canonical = serde_json::to_vec(&registry)
        .map_err(|error| invalid(format!("cannot canonicalize gate registry: {error}")))?;
    if canonical != bytes {
        return Err(invalid("registry is not the exact canonical JSON encoding"));
    }
    registry.validate()?;
    if registry.gate()? != expected_gate {
        return Err(invalid("checked-in registry crossed its selected gate"));
    }
    Ok(registry)
}

impl GateCaseRegistryV1 {
    fn gate(&self) -> Result<RegistryGateSelectionV1, RegistryError> {
        let gate = self
            .specifications
            .first()
            .ok_or_else(|| invalid("gate registry contains no specifications"))?
            .gate;
        if self
            .specifications
            .iter()
            .any(|specification| specification.gate != gate)
        {
            return Err(invalid("registry crosses gate identities"));
        }
        Ok(match gate {
            GateIdV1::HardGate1 => RegistryGateSelectionV1::Gate1,
            GateIdV1::HardGate2 => RegistryGateSelectionV1::Gate2,
            GateIdV1::HardGate3 => RegistryGateSelectionV1::Gate3,
        })
    }

    pub(crate) fn validate(&self) -> Result<(), RegistryError> {
        if self.schema != RegistrySchemaV1::GateCaseRegistryV1
            || self.registry_version != 1
            || self.authority_status != RegistryAuthorityStatusV1::NonAuthoritativeProjection
            || self.projection_of_manifest_version != 2
        {
            return Err(invalid(
                "registry schema, version, authority status, or manifest projection crossed",
            ));
        }
        let gate = self.gate()?;
        let expected_total = match gate {
            RegistryGateSelectionV1::Gate1 => 93,
            RegistryGateSelectionV1::Gate2 => 615,
            RegistryGateSelectionV1::Gate3 => 136,
        };
        if self.specifications.len() != expected_total {
            return Err(invalid(format!(
                "{} projection contains {} specifications; expected {expected_total}",
                gate.label(),
                self.specifications.len(),
            )));
        }

        let mut result_ids = BTreeSet::new();
        let mut target_counts = BTreeMap::new();
        let mut shared_counts = BTreeMap::<String, usize>::new();
        let mut run_groups = BTreeMap::<String, (GateTargetV1, GateExecutionV1)>::new();
        for specification in &self.specifications {
            specification.validate()?;
            if !result_ids.insert(specification.result_id.as_str()) {
                return Err(invalid(format!(
                    "duplicate gate result ID {}",
                    specification.result_id
                )));
            }
            *target_counts.entry(specification.target).or_insert(0_usize) += 1;
            for shared_id in &specification.shared_evidence_ids {
                *shared_counts.entry(shared_id.clone()).or_insert(0) += 1;
            }
            match run_groups.get(&specification.run_group_id) {
                Some((target, execution))
                    if *target == specification.target && execution == &specification.execution => {
                }
                Some(_) => {
                    return Err(invalid(format!(
                        "run group {} crosses target or execution identity",
                        specification.run_group_id
                    )));
                }
                None => {
                    run_groups.insert(
                        specification.run_group_id.clone(),
                        (specification.target, specification.execution.clone()),
                    );
                }
            }
        }

        let expected_target_counts = match gate {
            RegistryGateSelectionV1::Gate1 => vec![
                (GateTargetV1::Macos15AppleSilicon, 29),
                (GateTargetV1::Ubuntu2604X8664, 32),
                (GateTargetV1::Fedora44X8664, 32),
            ],
            RegistryGateSelectionV1::Gate2 => vec![
                (GateTargetV1::Macos15AppleSilicon, 207),
                (GateTargetV1::Ubuntu2604X8664, 204),
                (GateTargetV1::Fedora44X8664, 204),
            ],
            RegistryGateSelectionV1::Gate3 => vec![
                (GateTargetV1::Macos15AppleSilicon, 39),
                (GateTargetV1::Ubuntu2604X8664, 48),
                (GateTargetV1::Fedora44X8664, 48),
                (GateTargetV1::Global, 1),
            ],
        };
        for (target, expected_count) in expected_target_counts {
            if target_counts.get(&target).copied() != Some(expected_count) {
                return Err(invalid(format!(
                    "target {} does not contain exactly {expected_count} specifications",
                    target.as_str()
                )));
            }
        }
        if shared_counts.values().any(|count| *count < 2) {
            return Err(invalid(
                "shared evidence identity is declared by fewer than two results",
            ));
        }
        if self != &manifest_v2_projection(gate) {
            return Err(invalid(
                "checked projection differs from the exact manifest-v2 gate projection",
            ));
        }
        Ok(())
    }

    pub(crate) fn digest(&self) -> Result<String, RegistryError> {
        self.validate()?;
        let canonical = serde_json::to_vec(self)
            .map_err(|error| invalid(format!("cannot encode registry digest input: {error}")))?;
        let mut hasher = Sha256::new();
        hasher.update(REGISTRY_DIGEST_DOMAIN);
        hasher.update(
            u64::try_from(canonical.len())
                .map_err(|_| invalid("registry length does not fit u64"))?
                .to_be_bytes(),
        );
        hasher.update(canonical);
        Ok(lowercase_hex(&hasher.finalize()))
    }

    pub(crate) fn render_markdown(&self) -> String {
        let label = self
            .gate()
            .map_or("Unknown gate", RegistryGateSelectionV1::label);
        let mut output = format!(
            "<!-- Generated diagnostic listing from fixtures/gate-cases. -->\n\
# {label} canonical-JSON review projection\n\n\
Status: non-authoritative projection of gate-case manifest version 2.\n\n\
| Result ID | Case ID | Target | Fixture | Run group | Execution | Validator |\n\
|---|---|---|---|---|---|---|\n"
        );
        for specification in &self.specifications {
            writeln!(
                output,
                "| `{}` | `{}` | `{}` | `{}` | `{}` | `unavailable` | `{}` (`{}`) |",
                specification.result_id,
                specification.case_id,
                specification.target.as_str(),
                specification.fixture_id.as_str(),
                specification.run_group_id,
                specification.validator.validator_id.as_str(),
                match specification.validator.availability {
                    ValidatorAvailabilityV1::ContractOnly => "contract-only",
                    ValidatorAvailabilityV1::Unavailable => "unavailable",
                }
            )
            .expect("writing to a String cannot fail");
        }
        output
    }
}

impl GateCaseSpecV1 {
    fn validate(&self) -> Result<(), RegistryError> {
        require_identifier("result ID", &self.result_id, 256)?;
        require_identifier("case ID", &self.case_id, 160)?;
        require_identifier("run group ID", &self.run_group_id, 256)?;
        let gate = match self.gate {
            GateIdV1::HardGate1 => RegistryGateSelectionV1::Gate1,
            GateIdV1::HardGate2 => RegistryGateSelectionV1::Gate2,
            GateIdV1::HardGate3 => RegistryGateSelectionV1::Gate3,
        };
        let expected_result_prefix = format!("{}{}.", gate.result_prefix(), self.target.as_str());
        if !self.result_id.starts_with(&expected_result_prefix)
            || !self.result_id.ends_with(&self.case_id)
        {
            return Err(invalid(format!(
                "result ID {} is not gate/target-qualified or does not end in its exact case ID",
                self.result_id
            )));
        }
        let expected_argv = vec![
            "--target".to_owned(),
            self.target.as_str().to_owned(),
            "--run-group".to_owned(),
            self.run_group_id.clone(),
        ];
        if self.execution.availability != ExecutionAvailabilityV1::Unavailable
            || self.execution.program != gate.coordinator()
            || self.execution.argv != expected_argv
            || self.execution.missing_capability
                != ExecutionMissingCapabilityV1::ProductionFixtureExecutor
        {
            return Err(invalid(format!(
                "specification {} falsely claims execution availability or crosses its exact argv",
                self.result_id
            )));
        }
        if self.expected_artifacts != expected_artifacts() {
            return Err(invalid(format!(
                "specification {} has missing, extra, reordered, or crossed artifact roles",
                self.result_id
            )));
        }
        if self.deterministic_output {
            return Err(invalid(format!(
                "specification {} claims deterministic bytes before an executor exists",
                self.result_id
            )));
        }
        let expected_isolation = match gate {
            RegistryGateSelectionV1::Gate1 | RegistryGateSelectionV1::Gate2 => {
                isolation_requirement()
            }
            RegistryGateSelectionV1::Gate3 => gate_3_isolation_requirement(
                self.axes
                    .gate_3_group
                    .ok_or_else(|| invalid("Gate 3 specification lacks its case group"))?,
            ),
        };
        if self.isolation != expected_isolation {
            return Err(invalid(format!(
                "specification {} weakens its target-row isolation or fixture reset",
                self.result_id
            )));
        }
        require_exact_set("precondition", &self.preconditions)?;
        require_exact_set("bound input", &self.bound_inputs)?;
        self.axes.validate(gate, self.target, &self.case_id)?;
        for shared_id in &self.shared_evidence_ids {
            require_identifier("shared evidence ID", shared_id, 256)?;
        }
        Ok(())
    }
}

impl GateCaseAxesV1 {
    fn validate(
        &self,
        gate: RegistryGateSelectionV1,
        target: GateTargetV1,
        case_id: &str,
    ) -> Result<(), RegistryError> {
        match gate {
            RegistryGateSelectionV1::Gate1 => self.validate_gate_1(),
            RegistryGateSelectionV1::Gate2 => self.validate_gate_2(case_id),
            RegistryGateSelectionV1::Gate3 => self.validate_gate_3(target, case_id),
        }
    }

    fn validate_gate_1(&self) -> Result<(), RegistryError> {
        if self.has_gate_2_axes() || self.has_gate_3_axes() {
            return Err(invalid("Gate 1 specification carries a later-gate axis"));
        }
        Ok(())
    }

    fn validate_gate_2(&self, case_id: &str) -> Result<(), RegistryError> {
        if self.has_gate_3_axes() {
            return Err(invalid("Gate 2 specification carries a Gate 3 axis"));
        }
        if self.authority_phase != AuthorityPhaseV1::PostAdmission {
            return Err(invalid("Gate 2 specification is not post-admission"));
        }
        if self
            .worker_ceiling
            .is_some_and(|ceiling| !(1..=3).contains(&ceiling))
        {
            return Err(invalid("Gate 2 worker ceiling is outside 1..=3"));
        }
        let provider_case = self.provider_mode.is_some();
        if provider_case != self.provider.is_some() {
            return Err(invalid(
                "Gate 2 provider and provider-mode axes are crossed",
            ));
        }
        if provider_case {
            self.validate_gate_2_provider_axes()?;
        } else if self.worker_ceiling.is_none()
            || self.crash_cut.is_none()
            || self.expected_outcome_class.is_none()
            || self.repository_shape.is_none()
        {
            return Err(invalid(
                "Gate 2 workflow specification lacks a required axis",
            ));
        }
        let expected_internal_axis = if case_id == "pause_steer_resume_reconstructs_without_replay"
        {
            InternalVectorAxisV1::ClosedFixtureVectorTable
        } else {
            InternalVectorAxisV1::None
        };
        if self.internal_vector_axis != expected_internal_axis {
            return Err(invalid("Gate 2 internal vector axis is crossed"));
        }
        Ok(())
    }

    fn validate_gate_2_provider_axes(&self) -> Result<(), RegistryError> {
        match self.provider_mode {
            Some(ProviderModeV1::NormalizedContract)
                if self.worker_ceiling.is_none()
                    && self.crash_cut.is_none()
                    && self.expected_outcome_class.is_none()
                    && self.repository_shape.is_none() =>
            {
                Ok(())
            }
            Some(ProviderModeV1::LiveCompletedSprint)
                if self.worker_ceiling == Some(3)
                    && self.crash_cut == Some(CrashCutV1::None)
                    && self.expected_outcome_class
                        == Some(ExpectedOutcomeClassV1::KnownTerminal)
                    && self.repository_shape == Some(RepositoryShapeV1::CleanGitCollision) =>
            {
                Ok(())
            }
            _ => Err(invalid("Gate 2 provider axes are not exact")),
        }
    }

    fn validate_gate_3(&self, target: GateTargetV1, case_id: &str) -> Result<(), RegistryError> {
        if self.has_gate_2_axes() {
            return Err(invalid("Gate 3 specification carries a Gate 2 axis"));
        }
        if self.authority_phase != AuthorityPhaseV1::PostAdmission {
            return Err(invalid("Gate 3 specification is not post-admission"));
        }
        match self
            .gate_3_group
            .ok_or_else(|| invalid("Gate 3 specification lacks its case group"))?
        {
            Gate3CaseGroupV1::PackageLifecycle => self.validate_gate_3_package(target, case_id),
            Gate3CaseGroupV1::UiAccessibility => self.validate_gate_3_ui(target, case_id),
            Gate3CaseGroupV1::RuntimeResilience => self.validate_gate_3_runtime(target, case_id),
            Gate3CaseGroupV1::RequirementsEvidenceBaseClosure => {
                self.validate_gate_3_closure(target, case_id)
            }
        }
    }

    fn validate_gate_3_package(
        &self,
        target: GateTargetV1,
        case_id: &str,
    ) -> Result<(), RegistryError> {
        if target == GateTargetV1::Global
            || self.gate_3_row_id.is_none()
            || self.artifact.is_none()
            || self.native_session.is_some()
            || self.terminal_state.is_some()
            || self.application_disposition.is_some()
        {
            return Err(invalid("Gate 3 package axes are not exact"));
        }
        let row_matches = GATE_3_PACKAGE_ROWS.iter().any(|row| {
            Some(row.row_id) == self.gate_3_row_id
                && row.target == target
                && Some(row.artifact) == self.artifact
        });
        let case_matches = GATE_3_PACKAGE_CASES
            .iter()
            .any(|definition| definition.case_id == case_id);
        if !row_matches || !case_matches {
            return Err(invalid(
                "Gate 3 package row, target, artifact, or case crossed",
            ));
        }
        Ok(())
    }

    fn validate_gate_3_ui(&self, target: GateTargetV1, case_id: &str) -> Result<(), RegistryError> {
        if target == GateTargetV1::Global
            || self.gate_3_row_id.is_none()
            || self.artifact.is_none()
            || self.native_session.is_none()
            || self.terminal_state.is_some() != self.application_disposition.is_some()
        {
            return Err(invalid("Gate 3 UI axes are not exact"));
        }
        if !GATE_3_UI_ROWS.iter().any(|row| {
            Some(row.row_id) == self.gate_3_row_id
                && row.target == target
                && Some(row.artifact) == self.artifact
                && Some(row.native_session) == self.native_session
        }) {
            return Err(invalid(
                "Gate 3 UI row, target, artifact, or session crossed",
            ));
        }
        match (self.terminal_state, self.application_disposition) {
            (Some(state), Some(disposition))
                if case_id == terminal_case_id(state)
                    && legal_terminal_dispositions(state).contains(&disposition) =>
            {
                Ok(())
            }
            (None, None)
                if matches!(case_id, "keyboard_complete_operation" | "ime_and_scaling") =>
            {
                Ok(())
            }
            _ => Err(invalid("Gate 3 UI case axes are crossed or illegal")),
        }
    }

    fn validate_gate_3_runtime(
        &self,
        target: GateTargetV1,
        case_id: &str,
    ) -> Result<(), RegistryError> {
        if target == GateTargetV1::Global
            || self.gate_3_row_id.is_none()
            || self.artifact.is_none()
            || self.native_session.is_none()
            || self.terminal_state.is_some()
            || self.application_disposition.is_some()
        {
            return Err(invalid("Gate 3 runtime axes are not exact"));
        }
        let row_matches = GATE_3_RUNTIME_ROWS.iter().any(|row| {
            Some(row.row_id) == self.gate_3_row_id
                && row.target == target
                && Some(row.artifact) == self.artifact
                && Some(row.native_session) == self.native_session
        });
        let case_matches = GATE_3_RUNTIME_CASES
            .iter()
            .any(|definition| definition.case_id == case_id);
        if !row_matches || !case_matches {
            return Err(invalid(
                "Gate 3 runtime row, target, artifact, session, or case crossed",
            ));
        }
        Ok(())
    }

    fn validate_gate_3_closure(
        &self,
        target: GateTargetV1,
        case_id: &str,
    ) -> Result<(), RegistryError> {
        if target != GateTargetV1::Global
            || self.gate_3_row_id.is_some()
            || self.artifact.is_some()
            || self.native_session.is_some()
            || self.terminal_state.is_some()
            || self.application_disposition.is_some()
            || case_id != "requirements_evidence_base_closure"
        {
            return Err(invalid("Gate 3 Phase-A closure axes are not exact"));
        }
        Ok(())
    }

    const fn has_gate_2_axes(&self) -> bool {
        self.worker_ceiling.is_some()
            || self.crash_cut.is_some()
            || self.expected_outcome_class.is_some()
            || self.repository_shape.is_some()
            || self.provider.is_some()
            || self.provider_mode.is_some()
    }

    const fn has_gate_3_axes(&self) -> bool {
        self.gate_3_group.is_some()
            || self.gate_3_row_id.is_some()
            || self.artifact.is_some()
            || self.native_session.is_some()
            || self.terminal_state.is_some()
            || self.application_disposition.is_some()
    }
}

pub(crate) fn manifest_v2_projection(gate: RegistryGateSelectionV1) -> GateCaseRegistryV1 {
    match gate {
        RegistryGateSelectionV1::Gate1 => gate_1_manifest_v2_projection(),
        RegistryGateSelectionV1::Gate2 => gate_2_manifest_v2_projection(),
        RegistryGateSelectionV1::Gate3 => gate_3_manifest_v2_projection(),
    }
}

fn gate_3_manifest_v2_projection() -> GateCaseRegistryV1 {
    let mut specifications = Vec::with_capacity(136);
    for row in GATE_3_PACKAGE_ROWS {
        specifications.extend(
            GATE_3_PACKAGE_CASES
                .iter()
                .copied()
                .map(|definition| gate_3_package_specification(row, definition)),
        );
    }
    for row in GATE_3_UI_ROWS {
        for terminal in GATE_3_TERMINAL_CASES {
            specifications.extend(
                terminal.dispositions.iter().copied().map(|disposition| {
                    gate_3_terminal_ui_specification(row, terminal, disposition)
                }),
            );
        }
        specifications.extend(
            GATE_3_UI_OPERATION_CASES
                .iter()
                .copied()
                .map(|definition| gate_3_ui_operation_specification(row, definition)),
        );
    }
    for row in GATE_3_RUNTIME_ROWS {
        specifications.extend(
            GATE_3_RUNTIME_CASES
                .iter()
                .copied()
                .map(|definition| gate_3_runtime_specification(row, definition)),
        );
    }
    specifications.push(gate_3_requirements_closure_specification());
    GateCaseRegistryV1 {
        schema: RegistrySchemaV1::GateCaseRegistryV1,
        registry_version: 1,
        authority_status: RegistryAuthorityStatusV1::NonAuthoritativeProjection,
        projection_of_manifest_version: 2,
        specifications,
    }
}

fn gate_3_package_specification(
    row: Gate3PackageRow,
    definition: Gate3CaseDefinition,
) -> GateCaseSpecV1 {
    let run_group_id = format!(
        "g3.{}.{}.{}",
        row.target.as_str(),
        row.row_id.as_str(),
        definition.run_group_slug
    );
    gate_3_specification(
        format!(
            "g3.{}.{}.{}",
            row.target.as_str(),
            row.row_id.as_str(),
            definition.case_id
        ),
        row.target,
        definition,
        run_group_id,
        gate_3_axes(
            definition,
            Gate3CaseGroupV1::PackageLifecycle,
            Some(row.row_id),
            Some(row.artifact),
            None,
            None,
            None,
        ),
        gate_3_package_preconditions(),
        gate_3_package_bound_inputs(),
        vec![format!("g3.shared.{}", row.row_id.as_str())],
    )
}

fn gate_3_terminal_ui_specification(
    row: Gate3UiRow,
    terminal: Gate3TerminalCaseDefinition,
    disposition: Gate3ApplicationDispositionV1,
) -> GateCaseSpecV1 {
    let run_group_id = format!(
        "g3.{}.{}.terminal-accessibility.{}.{}",
        row.target.as_str(),
        row.row_id.as_str(),
        terminal.terminal_state.slug(),
        disposition.slug()
    );
    gate_3_specification(
        format!(
            "g3.{}.{}.{}.{}",
            row.target.as_str(),
            row.row_id.as_str(),
            disposition.slug(),
            terminal.case.case_id
        ),
        row.target,
        terminal.case,
        run_group_id,
        gate_3_axes(
            terminal.case,
            Gate3CaseGroupV1::UiAccessibility,
            Some(row.row_id),
            Some(row.artifact),
            Some(row.native_session),
            Some(terminal.terminal_state),
            Some(disposition),
        ),
        gate_3_ui_preconditions(),
        gate_3_ui_bound_inputs(),
        vec![format!("g3.shared.{}", row.row_id.as_str())],
    )
}

fn gate_3_ui_operation_specification(
    row: Gate3UiRow,
    definition: Gate3CaseDefinition,
) -> GateCaseSpecV1 {
    let run_group_id = format!(
        "g3.{}.{}.{}",
        row.target.as_str(),
        row.row_id.as_str(),
        definition.run_group_slug
    );
    gate_3_specification(
        format!(
            "g3.{}.{}.{}",
            row.target.as_str(),
            row.row_id.as_str(),
            definition.case_id
        ),
        row.target,
        definition,
        run_group_id,
        gate_3_axes(
            definition,
            Gate3CaseGroupV1::UiAccessibility,
            Some(row.row_id),
            Some(row.artifact),
            Some(row.native_session),
            None,
            None,
        ),
        gate_3_ui_preconditions(),
        gate_3_ui_bound_inputs(),
        vec![format!("g3.shared.{}", row.row_id.as_str())],
    )
}

fn gate_3_runtime_specification(
    row: Gate3RuntimeRow,
    definition: Gate3CaseDefinition,
) -> GateCaseSpecV1 {
    let run_group_id = format!(
        "g3.{}.{}.{}",
        row.target.as_str(),
        row.row_id.as_str(),
        definition.run_group_slug
    );
    gate_3_specification(
        format!(
            "g3.{}.{}.{}",
            row.target.as_str(),
            row.row_id.as_str(),
            definition.case_id
        ),
        row.target,
        definition,
        run_group_id,
        gate_3_axes(
            definition,
            Gate3CaseGroupV1::RuntimeResilience,
            Some(row.row_id),
            Some(row.artifact),
            Some(row.native_session),
            None,
            None,
        ),
        gate_3_runtime_preconditions(),
        gate_3_runtime_bound_inputs(),
        vec![format!("g3.shared.{}", row.row_id.as_str())],
    )
}

fn gate_3_requirements_closure_specification() -> GateCaseSpecV1 {
    let definition = GATE_3_REQUIREMENTS_CLOSURE_CASE;
    gate_3_specification(
        "g3.global.requirements_evidence_base_closure".into(),
        GateTargetV1::Global,
        definition,
        "g3.global.requirements-base-closure".into(),
        gate_3_axes(
            definition,
            Gate3CaseGroupV1::RequirementsEvidenceBaseClosure,
            None,
            None,
            None,
            None,
            None,
        ),
        gate_3_closure_preconditions(),
        gate_3_closure_bound_inputs(),
        Vec::new(),
    )
}

#[allow(clippy::too_many_arguments)]
const fn gate_3_axes(
    definition: Gate3CaseDefinition,
    group: Gate3CaseGroupV1,
    row_id: Option<Gate3RowIdV1>,
    artifact: Option<Gate3ArtifactV1>,
    native_session: Option<Gate3NativeSessionV1>,
    terminal_state: Option<Gate3TerminalStateV1>,
    application_disposition: Option<Gate3ApplicationDispositionV1>,
) -> GateCaseAxesV1 {
    GateCaseAxesV1 {
        authority_phase: AuthorityPhaseV1::PostAdmission,
        internal_vector_axis: definition.internal_vector_axis,
        mutation_class: definition.mutation_class,
        worker_ceiling: None,
        crash_cut: None,
        expected_outcome_class: None,
        repository_shape: None,
        provider: None,
        provider_mode: None,
        gate_3_group: Some(group),
        gate_3_row_id: row_id,
        artifact,
        native_session,
        terminal_state,
        application_disposition,
    }
}

#[allow(clippy::too_many_arguments)]
fn gate_3_specification(
    result_id: String,
    target: GateTargetV1,
    definition: Gate3CaseDefinition,
    run_group_id: String,
    axes: GateCaseAxesV1,
    preconditions: Vec<GatePreconditionV1>,
    bound_inputs: Vec<BoundInputIdentityV1>,
    shared_evidence_ids: Vec<String>,
) -> GateCaseSpecV1 {
    let group = axes
        .gate_3_group
        .expect("Gate 3 builders always provide a closed case group");
    GateCaseSpecV1 {
        result_id,
        case_id: definition.case_id.into(),
        gate: GateIdV1::HardGate3,
        target,
        fixture_id: definition.fixture_id,
        run_group_id: run_group_id.clone(),
        axes,
        preconditions,
        execution: GateExecutionV1 {
            availability: ExecutionAvailabilityV1::Unavailable,
            program: ProgramIdV1::Gate3,
            argv: vec![
                "--target".into(),
                target.as_str().into(),
                "--run-group".into(),
                run_group_id,
            ],
            missing_capability: ExecutionMissingCapabilityV1::ProductionFixtureExecutor,
        },
        validator: GateValidatorV1 {
            validator_id: definition.validator_id,
            availability: ValidatorAvailabilityV1::Unavailable,
            missing_capability: ValidatorMissingCapabilityV1::ValidatorImplementation,
        },
        expected_artifacts: expected_artifacts(),
        bound_inputs,
        deterministic_output: false,
        shared_evidence_ids,
        isolation: gate_3_isolation_requirement(group),
    }
}

fn gate_1_manifest_v2_projection() -> GateCaseRegistryV1 {
    let mut specifications = Vec::with_capacity(93);
    for target in TARGETS {
        specifications.extend(
            COMMON_CASES
                .iter()
                .copied()
                .map(|definition| specification(target, definition)),
        );
        let platform_cases: &[CaseDefinition] = match target {
            GateTargetV1::Macos15AppleSilicon => &MACOS_CASES,
            GateTargetV1::Ubuntu2604X8664 | GateTargetV1::Fedora44X8664 => &LINUX_CASES,
            GateTargetV1::Global => &[],
        };
        specifications.extend(
            platform_cases
                .iter()
                .copied()
                .map(|definition| specification(target, definition)),
        );
    }
    GateCaseRegistryV1 {
        schema: RegistrySchemaV1::GateCaseRegistryV1,
        registry_version: 1,
        authority_status: RegistryAuthorityStatusV1::NonAuthoritativeProjection,
        projection_of_manifest_version: 2,
        specifications,
    }
}

fn gate_2_manifest_v2_projection() -> GateCaseRegistryV1 {
    let mut specifications = Vec::with_capacity(615);
    for target in TARGETS {
        for worker_ceiling in 1..=3 {
            for crash_cut in CrashCutV1::ALL {
                specifications.extend(GATE_2_BASE_CASES.iter().copied().map(|definition| {
                    gate_2_matrix_specification(target, worker_ceiling, crash_cut, definition)
                }));
                if crash_cut.continues_to_completion() {
                    specifications.extend(GATE_2_KNOWN_OUTCOME_CASES.iter().copied().map(
                        |definition| {
                            gate_2_matrix_specification(
                                target,
                                worker_ceiling,
                                crash_cut,
                                definition,
                            )
                        },
                    ));
                }
                if crash_cut == CrashCutV1::None {
                    specifications.push(gate_2_matrix_specification(
                        target,
                        worker_ceiling,
                        crash_cut,
                        GATE_2_REPAIR_CASE,
                    ));
                }
            }
        }

        specifications.push(gate_2_run_control_specification(target));
        specifications.push(gate_2_repository_shape_specification(
            target,
            RepositoryShapeV1::DirtyGit,
            GATE_2_DIRTY_REPOSITORY_CASE,
        ));
        specifications.push(gate_2_repository_shape_specification(
            target,
            RepositoryShapeV1::NonGit,
            GATE_2_NON_GIT_REPOSITORY_CASE,
        ));
        specifications.extend(
            GATE_2_PROVIDER_CASES
                .iter()
                .copied()
                .map(|definition| gate_2_provider_contract_specification(target, definition)),
        );
        if target == GateTargetV1::Macos15AppleSilicon {
            specifications.extend(
                GATE_2_PROVIDER_CASES
                    .iter()
                    .copied()
                    .map(|definition| gate_2_live_provider_specification(target, definition)),
            );
        }
    }
    GateCaseRegistryV1 {
        schema: RegistrySchemaV1::GateCaseRegistryV1,
        registry_version: 1,
        authority_status: RegistryAuthorityStatusV1::NonAuthoritativeProjection,
        projection_of_manifest_version: 2,
        specifications,
    }
}

fn gate_2_matrix_specification(
    target: GateTargetV1,
    worker_ceiling: u8,
    crash_cut: CrashCutV1,
    definition: Gate2CaseDefinition,
) -> GateCaseSpecV1 {
    let axis_slug = format!("workers-{worker_ceiling}.{}", crash_cut.slug());
    let run_group_id = format!(
        "g2.{}.{}.{}",
        target.as_str(),
        axis_slug,
        definition.run_group_slug
    );
    gate_2_specification(
        format!(
            "g2.{}.{}.{}",
            target.as_str(),
            axis_slug,
            definition.case_id
        ),
        target,
        definition,
        run_group_id,
        GateCaseAxesV1 {
            authority_phase: AuthorityPhaseV1::PostAdmission,
            internal_vector_axis: InternalVectorAxisV1::None,
            mutation_class: definition.mutation_class,
            worker_ceiling: Some(worker_ceiling),
            crash_cut: Some(crash_cut),
            expected_outcome_class: Some(crash_cut.expected_outcome_class()),
            repository_shape: Some(RepositoryShapeV1::CleanGitCollision),
            provider: None,
            provider_mode: None,
            gate_3_group: None,
            gate_3_row_id: None,
            artifact: None,
            native_session: None,
            terminal_state: None,
            application_disposition: None,
        },
        gate_2_preconditions(false),
        gate_2_workflow_bound_inputs(),
        vec![format!("g2.shared.{}.{}", target.as_str(), axis_slug)],
    )
}

fn gate_2_run_control_specification(target: GateTargetV1) -> GateCaseSpecV1 {
    let definition = GATE_2_RUN_CONTROL_CASE;
    let run_group_id = format!("g2.{}.workers-3.none.run-control", target.as_str());
    gate_2_specification(
        format!(
            "g2.{}.workers-3.none.{}",
            target.as_str(),
            definition.case_id
        ),
        target,
        definition,
        run_group_id,
        GateCaseAxesV1 {
            authority_phase: AuthorityPhaseV1::PostAdmission,
            internal_vector_axis: InternalVectorAxisV1::ClosedFixtureVectorTable,
            mutation_class: definition.mutation_class,
            worker_ceiling: Some(3),
            crash_cut: Some(CrashCutV1::None),
            expected_outcome_class: Some(ExpectedOutcomeClassV1::KnownTerminal),
            repository_shape: Some(RepositoryShapeV1::CleanGitCollision),
            provider: None,
            provider_mode: None,
            gate_3_group: None,
            gate_3_row_id: None,
            artifact: None,
            native_session: None,
            terminal_state: None,
            application_disposition: None,
        },
        gate_2_preconditions(false),
        gate_2_workflow_bound_inputs(),
        Vec::new(),
    )
}

fn gate_2_repository_shape_specification(
    target: GateTargetV1,
    repository_shape: RepositoryShapeV1,
    definition: Gate2CaseDefinition,
) -> GateCaseSpecV1 {
    let shape_slug = match repository_shape {
        RepositoryShapeV1::DirtyGit => "dirty-git",
        RepositoryShapeV1::NonGit => "non-git",
        RepositoryShapeV1::CleanGitCollision => "clean-git-collision",
    };
    let run_group_id = format!("g2.{}.workers-3.none.{shape_slug}", target.as_str());
    let mut inputs = gate_2_workflow_bound_inputs();
    inputs.push(BoundInputIdentityV1::RepositoryShapeFixture);
    gate_2_specification(
        format!(
            "g2.{}.workers-3.none.{shape_slug}.{}",
            target.as_str(),
            definition.case_id
        ),
        target,
        definition,
        run_group_id,
        GateCaseAxesV1 {
            authority_phase: AuthorityPhaseV1::PostAdmission,
            internal_vector_axis: InternalVectorAxisV1::None,
            mutation_class: definition.mutation_class,
            worker_ceiling: Some(3),
            crash_cut: Some(CrashCutV1::None),
            expected_outcome_class: Some(ExpectedOutcomeClassV1::KnownTerminal),
            repository_shape: Some(repository_shape),
            provider: None,
            provider_mode: None,
            gate_3_group: None,
            gate_3_row_id: None,
            artifact: None,
            native_session: None,
            terminal_state: None,
            application_disposition: None,
        },
        gate_2_preconditions(false),
        inputs,
        Vec::new(),
    )
}

fn gate_2_provider_contract_specification(
    target: GateTargetV1,
    definition: ProviderCaseDefinition,
) -> GateCaseSpecV1 {
    let provider_slug = definition.provider.slug();
    let case = gate2_case(
        definition.normalized_case_id,
        FixtureSpecIdV1::Gate2ProviderContract,
        ValidatorIdV1::Gate2ProviderContract,
        "provider-contract",
        MutationClassV1::ReadOnly,
    );
    let run_group_id = format!(
        "g2.{}.provider.{}.normalized-contract",
        target.as_str(),
        provider_slug
    );
    gate_2_specification(
        format!(
            "g2.{}.provider.{}.normalized-contract.{}",
            target.as_str(),
            provider_slug,
            case.case_id
        ),
        target,
        case,
        run_group_id,
        GateCaseAxesV1 {
            authority_phase: AuthorityPhaseV1::PostAdmission,
            internal_vector_axis: InternalVectorAxisV1::None,
            mutation_class: MutationClassV1::ReadOnly,
            worker_ceiling: None,
            crash_cut: None,
            expected_outcome_class: None,
            repository_shape: None,
            provider: Some(definition.provider),
            provider_mode: Some(ProviderModeV1::NormalizedContract),
            gate_3_group: None,
            gate_3_row_id: None,
            artifact: None,
            native_session: None,
            terminal_state: None,
            application_disposition: None,
        },
        gate_2_preconditions(false),
        gate_2_provider_contract_bound_inputs(),
        vec![format!("g2.shared.{}.provider-contracts", target.as_str())],
    )
}

fn gate_2_live_provider_specification(
    target: GateTargetV1,
    definition: ProviderCaseDefinition,
) -> GateCaseSpecV1 {
    let provider_slug = definition.provider.slug();
    let case = gate2_case(
        definition.live_case_id,
        definition.live_fixture_id,
        definition.live_validator_id,
        "provider-live",
        MutationClassV1::WorkspaceDestructive,
    );
    let run_group_id = format!(
        "g2.{}.provider.{}.live-sprint",
        target.as_str(),
        provider_slug
    );
    gate_2_specification(
        format!(
            "g2.{}.provider.{}.live-sprint.{}",
            target.as_str(),
            provider_slug,
            case.case_id
        ),
        target,
        case,
        run_group_id,
        GateCaseAxesV1 {
            authority_phase: AuthorityPhaseV1::PostAdmission,
            internal_vector_axis: InternalVectorAxisV1::None,
            mutation_class: MutationClassV1::WorkspaceDestructive,
            worker_ceiling: Some(3),
            crash_cut: Some(CrashCutV1::None),
            expected_outcome_class: Some(ExpectedOutcomeClassV1::KnownTerminal),
            repository_shape: Some(RepositoryShapeV1::CleanGitCollision),
            provider: Some(definition.provider),
            provider_mode: Some(ProviderModeV1::LiveCompletedSprint),
            gate_3_group: None,
            gate_3_row_id: None,
            artifact: None,
            native_session: None,
            terminal_state: None,
            application_disposition: None,
        },
        gate_2_preconditions(true),
        gate_2_live_provider_bound_inputs(),
        vec![format!(
            "g2.shared.{}.live-provider-smokes",
            target.as_str()
        )],
    )
}

#[allow(clippy::too_many_arguments)]
fn gate_2_specification(
    result_id: String,
    target: GateTargetV1,
    definition: Gate2CaseDefinition,
    run_group_id: String,
    axes: GateCaseAxesV1,
    preconditions: Vec<GatePreconditionV1>,
    bound_inputs: Vec<BoundInputIdentityV1>,
    shared_evidence_ids: Vec<String>,
) -> GateCaseSpecV1 {
    GateCaseSpecV1 {
        result_id,
        case_id: definition.case_id.into(),
        gate: GateIdV1::HardGate2,
        target,
        fixture_id: definition.fixture_id,
        run_group_id: run_group_id.clone(),
        axes,
        preconditions,
        execution: GateExecutionV1 {
            availability: ExecutionAvailabilityV1::Unavailable,
            program: ProgramIdV1::Gate2,
            argv: vec![
                "--target".into(),
                target.as_str().into(),
                "--run-group".into(),
                run_group_id,
            ],
            missing_capability: ExecutionMissingCapabilityV1::ProductionFixtureExecutor,
        },
        validator: GateValidatorV1 {
            validator_id: definition.validator_id,
            availability: ValidatorAvailabilityV1::Unavailable,
            missing_capability: ValidatorMissingCapabilityV1::ValidatorImplementation,
        },
        expected_artifacts: expected_artifacts(),
        bound_inputs,
        deterministic_output: false,
        shared_evidence_ids,
        isolation: isolation_requirement(),
    }
}

fn specification(target: GateTargetV1, definition: CaseDefinition) -> GateCaseSpecV1 {
    let run_group_id = format!("g1.{}.{}", target.as_str(), definition.run_group_slug);
    let shared_evidence_ids = if matches!(
        definition.run_group_slug,
        "native-admission" | "workspace-denial" | "command-isolation"
    ) {
        vec![format!(
            "g1.shared.{}.{}",
            target.as_str(),
            definition.run_group_slug
        )]
    } else {
        Vec::new()
    };
    let (availability, missing_capability) =
        validator_availability(target, definition.validator_id);
    GateCaseSpecV1 {
        result_id: format!("g1.{}.{}", target.as_str(), definition.case_id),
        case_id: definition.case_id.into(),
        gate: GateIdV1::HardGate1,
        target,
        fixture_id: definition.fixture_id,
        run_group_id: run_group_id.clone(),
        axes: GateCaseAxesV1 {
            authority_phase: definition.authority_phase,
            internal_vector_axis: definition.internal_vector_axis,
            mutation_class: definition.mutation_class,
            worker_ceiling: None,
            crash_cut: None,
            expected_outcome_class: None,
            repository_shape: None,
            provider: None,
            provider_mode: None,
            gate_3_group: None,
            gate_3_row_id: None,
            artifact: None,
            native_session: None,
            terminal_state: None,
            application_disposition: None,
        },
        preconditions: preconditions(definition.authority_phase),
        execution: GateExecutionV1 {
            availability: ExecutionAvailabilityV1::Unavailable,
            program: ProgramIdV1::Gate1,
            argv: vec![
                "--target".into(),
                target.as_str().into(),
                "--run-group".into(),
                run_group_id,
            ],
            missing_capability: ExecutionMissingCapabilityV1::ProductionFixtureExecutor,
        },
        validator: GateValidatorV1 {
            validator_id: definition.validator_id,
            availability,
            missing_capability,
        },
        expected_artifacts: expected_artifacts(),
        bound_inputs: bound_inputs(definition.authority_phase),
        deterministic_output: false,
        shared_evidence_ids,
        isolation: isolation_requirement(),
    }
}

const fn validator_availability(
    target: GateTargetV1,
    validator_id: ValidatorIdV1,
) -> (ValidatorAvailabilityV1, ValidatorMissingCapabilityV1) {
    if matches!(
        target,
        GateTargetV1::Ubuntu2604X8664 | GateTargetV1::Fedora44X8664
    ) && matches!(
        validator_id,
        ValidatorIdV1::NativeAdmission | ValidatorIdV1::LinuxNative
    ) {
        (
            ValidatorAvailabilityV1::ContractOnly,
            ValidatorMissingCapabilityV1::ProductionObservationJoin,
        )
    } else {
        (
            ValidatorAvailabilityV1::Unavailable,
            ValidatorMissingCapabilityV1::ValidatorImplementation,
        )
    }
}

fn preconditions(phase: AuthorityPhaseV1) -> Vec<GatePreconditionV1> {
    let mut values = vec![
        GatePreconditionV1::ImmutableSourceIdentity,
        GatePreconditionV1::ExactTargetImage,
        GatePreconditionV1::SourceBoundFixtureBinary,
    ];
    values.push(match phase {
        AuthorityPhaseV1::PreAdmission => GatePreconditionV1::EvidenceOnlyAuthority,
        AuthorityPhaseV1::PostAdmission => GatePreconditionV1::ProductionAdmittedAuthority,
    });
    values
}

fn expected_artifacts() -> Vec<ExpectedArtifactV1> {
    [
        ArtifactRoleV1::TypedObservation,
        ArtifactRoleV1::Stdout,
        ArtifactRoleV1::Stderr,
    ]
    .into_iter()
    .map(|role| ExpectedArtifactV1 {
        role,
        identity_field: ArtifactIdentityFieldV1::ResultId,
        digest_field: ArtifactDigestFieldV1::Sha256,
    })
    .collect()
}

fn bound_inputs(phase: AuthorityPhaseV1) -> Vec<BoundInputIdentityV1> {
    let mut values = vec![
        BoundInputIdentityV1::SourceCommit,
        BoundInputIdentityV1::SourceTree,
        BoundInputIdentityV1::CargoLock,
        BoundInputIdentityV1::Toolchain,
        BoundInputIdentityV1::ReleaseTargetManifestV1,
        BoundInputIdentityV1::GateCaseManifestV2,
        BoundInputIdentityV1::Policy,
        BoundInputIdentityV1::FixtureBinary,
        BoundInputIdentityV1::BackendBinary,
        BoundInputIdentityV1::InputFixture,
    ];
    match phase {
        AuthorityPhaseV1::PreAdmission => {
            values.push(BoundInputIdentityV1::PlatformImage);
            values.push(BoundInputIdentityV1::EvidenceOnlyAuthority);
        }
        AuthorityPhaseV1::PostAdmission => {
            values.push(BoundInputIdentityV1::WorkspaceGrant);
            values.push(BoundInputIdentityV1::SprintSpec);
            values.push(BoundInputIdentityV1::ProductionAdmission);
        }
    }
    values
}

fn gate_2_preconditions(live_provider: bool) -> Vec<GatePreconditionV1> {
    let mut values = vec![
        GatePreconditionV1::ImmutableSourceIdentity,
        GatePreconditionV1::ExactTargetImage,
        GatePreconditionV1::SourceBoundFixtureBinary,
        GatePreconditionV1::ProductionAdmittedAuthority,
        GatePreconditionV1::Gate1IdentityValid,
    ];
    if live_provider {
        values.push(GatePreconditionV1::HumanLaunchedLiveProvider);
        values.push(GatePreconditionV1::ProviderCapabilityProbe);
    }
    values
}

fn gate_2_common_bound_inputs() -> Vec<BoundInputIdentityV1> {
    vec![
        BoundInputIdentityV1::SourceCommit,
        BoundInputIdentityV1::SourceTree,
        BoundInputIdentityV1::CargoLock,
        BoundInputIdentityV1::Toolchain,
        BoundInputIdentityV1::ReleaseTargetManifestV1,
        BoundInputIdentityV1::GateCaseManifestV2,
        BoundInputIdentityV1::Policy,
        BoundInputIdentityV1::FixtureBinary,
        BoundInputIdentityV1::BackendBinary,
        BoundInputIdentityV1::InputFixture,
        BoundInputIdentityV1::WorkspaceGrant,
        BoundInputIdentityV1::SprintSpec,
        BoundInputIdentityV1::ProductionAdmission,
        BoundInputIdentityV1::Gate1EvidenceIdentity,
    ]
}

fn gate_2_workflow_bound_inputs() -> Vec<BoundInputIdentityV1> {
    let mut values = gate_2_common_bound_inputs();
    values.extend([
        BoundInputIdentityV1::CrashOutcomeClassTable,
        BoundInputIdentityV1::SchedulerPolicy,
        BoundInputIdentityV1::IntegrationPolicy,
        BoundInputIdentityV1::VerificationPolicy,
        BoundInputIdentityV1::ApplicationPolicy,
    ]);
    values
}

fn gate_2_provider_contract_bound_inputs() -> Vec<BoundInputIdentityV1> {
    let mut values = gate_2_common_bound_inputs();
    values.extend([
        BoundInputIdentityV1::ProviderPolicy,
        BoundInputIdentityV1::ProviderRecording,
    ]);
    values
}

fn gate_2_live_provider_bound_inputs() -> Vec<BoundInputIdentityV1> {
    let mut values = gate_2_common_bound_inputs();
    values.extend([
        BoundInputIdentityV1::SchedulerPolicy,
        BoundInputIdentityV1::IntegrationPolicy,
        BoundInputIdentityV1::VerificationPolicy,
        BoundInputIdentityV1::ApplicationPolicy,
        BoundInputIdentityV1::ProviderPolicy,
        BoundInputIdentityV1::ProviderEndpoint,
        BoundInputIdentityV1::ProviderModel,
        BoundInputIdentityV1::ProviderCapabilities,
    ]);
    values
}

fn gate_3_target_preconditions() -> Vec<GatePreconditionV1> {
    vec![
        GatePreconditionV1::ImmutableSourceIdentity,
        GatePreconditionV1::ExactTargetImage,
        GatePreconditionV1::SourceBoundFixtureBinary,
        GatePreconditionV1::Gate1IdentityValid,
        GatePreconditionV1::Gate2IdentityValid,
        GatePreconditionV1::ProtectedReleaseIdentity,
    ]
}

fn gate_3_package_preconditions() -> Vec<GatePreconditionV1> {
    let mut values = gate_3_target_preconditions();
    values.extend([
        GatePreconditionV1::SignedReleaseArtifact,
        GatePreconditionV1::CleanHost,
    ]);
    values
}

fn gate_3_ui_preconditions() -> Vec<GatePreconditionV1> {
    let mut values = gate_3_target_preconditions();
    values.extend([
        GatePreconditionV1::InstalledReleaseArtifact,
        GatePreconditionV1::NativeDisplaySession,
    ]);
    values
}

fn gate_3_runtime_preconditions() -> Vec<GatePreconditionV1> {
    gate_3_ui_preconditions()
}

fn gate_3_closure_preconditions() -> Vec<GatePreconditionV1> {
    vec![
        GatePreconditionV1::ImmutableSourceIdentity,
        GatePreconditionV1::SourceBoundFixtureBinary,
        GatePreconditionV1::Gate1IdentityValid,
        GatePreconditionV1::Gate2IdentityValid,
        GatePreconditionV1::ProtectedReleaseIdentity,
        GatePreconditionV1::TwoIndependentReleaseMatricesComplete,
        GatePreconditionV1::ClosedDefectSnapshot,
    ]
}

fn gate_3_target_bound_inputs() -> Vec<BoundInputIdentityV1> {
    vec![
        BoundInputIdentityV1::SourceCommit,
        BoundInputIdentityV1::SourceTree,
        BoundInputIdentityV1::CargoLock,
        BoundInputIdentityV1::Toolchain,
        BoundInputIdentityV1::ReleaseTargetManifestV1,
        BoundInputIdentityV1::GateCaseManifestV2,
        BoundInputIdentityV1::Policy,
        BoundInputIdentityV1::FixtureBinary,
        BoundInputIdentityV1::BackendBinary,
        BoundInputIdentityV1::InputFixture,
        BoundInputIdentityV1::PlatformImage,
        BoundInputIdentityV1::Gate1EvidenceIdentity,
        BoundInputIdentityV1::Gate2EvidenceIdentity,
        BoundInputIdentityV1::ProtectedTag,
        BoundInputIdentityV1::ReleaseArtifact,
    ]
}

fn gate_3_package_bound_inputs() -> Vec<BoundInputIdentityV1> {
    let mut values = gate_3_target_bound_inputs();
    values.extend([
        BoundInputIdentityV1::SigningNotarizationPolicy,
        BoundInputIdentityV1::SbomNoticesProvenancePolicy,
        BoundInputIdentityV1::PlatformStateUninstallPolicyV1,
    ]);
    values
}

fn gate_3_ui_bound_inputs() -> Vec<BoundInputIdentityV1> {
    let mut values = gate_3_target_bound_inputs();
    values.extend([
        BoundInputIdentityV1::AccessibilityPolicy,
        BoundInputIdentityV1::PlatformStateUninstallPolicyV1,
    ]);
    values
}

fn gate_3_runtime_bound_inputs() -> Vec<BoundInputIdentityV1> {
    let mut values = gate_3_target_bound_inputs();
    values.extend([
        BoundInputIdentityV1::PerformanceResourceBudget,
        BoundInputIdentityV1::PlatformStateUninstallPolicyV1,
    ]);
    values
}

fn gate_3_closure_bound_inputs() -> Vec<BoundInputIdentityV1> {
    vec![
        BoundInputIdentityV1::SourceCommit,
        BoundInputIdentityV1::SourceTree,
        BoundInputIdentityV1::CargoLock,
        BoundInputIdentityV1::Toolchain,
        BoundInputIdentityV1::GateCaseManifestV2,
        BoundInputIdentityV1::Policy,
        BoundInputIdentityV1::FixtureBinary,
        BoundInputIdentityV1::Gate1EvidenceIdentity,
        BoundInputIdentityV1::Gate2EvidenceIdentity,
        BoundInputIdentityV1::ProtectedTag,
        BoundInputIdentityV1::RequirementsTraceability,
        BoundInputIdentityV1::RequirementsEvidenceClosure,
        BoundInputIdentityV1::SupportArtifactRegistry,
        BoundInputIdentityV1::DefectSnapshot,
        BoundInputIdentityV1::Gate3NonClosureCaseResults,
        BoundInputIdentityV1::ReleaseMatrixR1,
        BoundInputIdentityV1::ReleaseMatrixR2,
    ]
}

const fn isolation_requirement() -> IsolationRequirementV1 {
    IsolationRequirementV1 {
        executor_scope: ExecutorIsolationV1::EphemeralTargetRow,
        fixture_reset: FixtureResetV1::FreshFixtureRootPerRunGroup,
        cleanup: CleanupRequirementV1::ProofRequiredBeforeNextRunGroup,
    }
}

const fn gate_3_isolation_requirement(group: Gate3CaseGroupV1) -> IsolationRequirementV1 {
    match group {
        Gate3CaseGroupV1::PackageLifecycle => IsolationRequirementV1 {
            executor_scope: ExecutorIsolationV1::FreshCleanHost,
            fixture_reset: FixtureResetV1::FreshHostPerPackageRow,
            cleanup: CleanupRequirementV1::ProofRequiredBeforeNextRunGroup,
        },
        Gate3CaseGroupV1::UiAccessibility => IsolationRequirementV1 {
            executor_scope: ExecutorIsolationV1::InstalledNativeSession,
            fixture_reset: FixtureResetV1::FreshInstalledSessionPerUiRow,
            cleanup: CleanupRequirementV1::ProofRequiredBeforeNextRunGroup,
        },
        Gate3CaseGroupV1::RuntimeResilience => IsolationRequirementV1 {
            executor_scope: ExecutorIsolationV1::InstalledRuntimeTarget,
            fixture_reset: FixtureResetV1::FreshInstalledRuntimePerRuntimeRow,
            cleanup: CleanupRequirementV1::ProofRequiredBeforeNextRunGroup,
        },
        Gate3CaseGroupV1::RequirementsEvidenceBaseClosure => IsolationRequirementV1 {
            executor_scope: ExecutorIsolationV1::GlobalReadOnlyClosure,
            fixture_reset: FixtureResetV1::NotApplicableReadOnly,
            cleanup: CleanupRequirementV1::NoNativeDomainExpected,
        },
    }
}

fn require_identifier(name: &str, value: &str, maximum: usize) -> Result<(), RegistryError> {
    if value.is_empty()
        || value.len() > maximum
        || !value.bytes().all(|byte| {
            byte.is_ascii_lowercase()
                || byte.is_ascii_digit()
                || matches!(byte, b'-' | b'_' | b'.' | b':')
        })
    {
        return Err(invalid(format!("{name} is not one canonical identifier")));
    }
    Ok(())
}

fn require_exact_set<T: Copy + Ord>(name: &str, values: &[T]) -> Result<(), RegistryError> {
    let mut observed = BTreeSet::new();
    if values.iter().copied().any(|value| !observed.insert(value)) {
        return Err(invalid(format!("{name} set contains a duplicate")));
    }
    Ok(())
}

fn lowercase_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len().saturating_mul(2));
    for byte in bytes {
        encoded.push(char::from(HEX[usize::from(byte >> 4)]));
        encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    encoded
}

fn invalid(message: impl Into<String>) -> RegistryError {
    RegistryError(message.into())
}

#[cfg(test)]
mod tests;
