//! Complete ledger schema migration chain (v1 through v38).

use super::{
    application_artifact_authority, command_domain_cleanup, command_output_capture_authority,
    current_final_verification_capture_v36, current_final_verification_launch_v35,
    current_final_verification_native_preparation_v37, migrations_v1_v8, migrations_v9,
    post_completion_rollback, runner_launch_cleanup_admission, sensitive_output_rejection,
    task_attempt_authority, worker_lease_authority,
};

/// Additive schema-v33 collision guards for current schema-v32 authority:
/// BEFORE INSERT triggers only, no contract or authority change.
pub(super) const MIGRATION_V33: &str = include_str!("current_authority_no_replace_v33.sql");

/// Additive schema-v34 operational final-verification admission foundation:
/// sprint-local event stream and operational-attempt overlay, no launch or
/// dispatch authority.
pub(super) const MIGRATION_V34: &str =
    include_str!("current_final_verification_operational_v34.sql");

/// Additive schema-v38 contained-command release subject.
///
/// Distinct from the v13 runner-launch family on purpose: a contained command
/// is an effect inside a sprint rather than a launch, so it needs its own
/// admission and its own claim. Nothing in v13 is altered by it.
pub(super) const MIGRATION_V38: &str = include_str!("contained_command_release_v38.sql");

pub(super) const MIGRATIONS: [&str; 38] = [
    migrations_v1_v8::MIGRATION_V1,
    migrations_v1_v8::MIGRATION_V2,
    migrations_v1_v8::MIGRATION_V3,
    migrations_v1_v8::MIGRATION_V4,
    migrations_v1_v8::MIGRATION_V5,
    migrations_v1_v8::MIGRATION_V6,
    migrations_v1_v8::MIGRATION_V7,
    migrations_v1_v8::MIGRATION_V8,
    migrations_v9::MIGRATION_V9,
    post_completion_rollback::MIGRATION_V10,
    command_domain_cleanup::MIGRATION_V11,
    application_artifact_authority::MIGRATION_V12,
    runner_launch_cleanup_admission::MIGRATION_V13,
    worker_lease_authority::MIGRATION_V14,
    task_attempt_authority::MIGRATION_V15,
    include_str!("task_verified_noop_v16.sql"),
    include_str!("runner_effect_dispatch_claim_v17.sql"),
    include_str!("optional_task_completion_v18.sql"),
    include_str!("runner_effect_dispatch_authority_v19.sql"),
    include_str!("runner_effect_dispatch_authority_v20.sql"),
    include_str!("runner_effect_dispatch_authority_v21.sql"),
    include_str!("sprint_application_authority_v22.sql"),
    include_str!("sprint_live_state_capture_authority_v23.sql"),
    include_str!("completion_live_state_capture_authority_v24.sql"),
    include_str!("live_state_drift_blocked_authority_v25.sql"),
    include_str!("command_output_artifact_sets_v26.sql"),
    command_output_capture_authority::MIGRATION_V27,
    include_str!("human_acceptance_claim_v28.sql"),
    sensitive_output_rejection::MIGRATION_V29,
    include_str!("sensitive_output_attempt_repair_v30.sql"),
    include_str!("sensitive_output_clean_same_head_v31.sql"),
    include_str!("final_verification_authority_v32.sql"),
    MIGRATION_V33,
    MIGRATION_V34,
    current_final_verification_launch_v35::MIGRATION_V35,
    current_final_verification_capture_v36::MIGRATION_V36,
    current_final_verification_native_preparation_v37::MIGRATION_V37,
    MIGRATION_V38,
];
