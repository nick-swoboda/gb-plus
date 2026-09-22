//! Append-only rollback operations over immutable successful completions.
//!
//! These rows deliberately do not reuse the sprint event, effect, launch, or
//! receipt tables. Those tables remain terminal-fenced after `Completed`.

use std::collections::BTreeSet;
use std::path::PathBuf;

use rusqlite::{Connection, OptionalExtension, Transaction, TransactionBehavior, params};
use serde::{Deserialize, Serialize};

use super::application_artifact_authority::{
    derive_post_completion_application_artifact_authority,
    insert_post_completion_application_artifact_authority,
    load_post_completion_application_artifact_authority_state,
    require_post_completion_application_artifact_authority,
    schema_is_installed as application_artifact_authority_schema_is_installed,
};
use super::{
    EventLedger, LedgerError, PersistedCompletionApplication,
    PostCompletionRollbackApplicationArtifactAuthorityState,
    completion_live_state_capture_authority_schema_is_installed, decode_stored, encode,
    ensure_artifact_absent, load_application_evidence_from, load_change_set_from,
    load_completion_evidence_from, load_rollback_reference_evidence_from,
    load_runner_session_policy_from, reference_mismatch, require_contract_version,
    runner_role_policy_matches, secure_database_files, sqlite_integer, unsigned_integer,
};
#[cfg(test)]
use super::{
    load_completion_receipt_from, load_event_by_id, load_final_report_from,
    validate_completion_event_shape, validate_completion_evidence,
};
#[cfg(test)]
use crate::CompletionApplication;
use crate::{
    ApplicationEvidence, CONTRACT_VERSION, CompiledExecutionPolicy, CompletionReceipt,
    ContractError, Digest, ExecutionPolicy, FileOperation, LiveConflictReceipt, RollbackEvidence,
    RollbackReferenceEvidence, RollbackRequest, RollbackValidationEvidence, RollbackValidationMode,
    RunnerLaunchIntent, RunnerSessionPolicyRecord, RunnerSessionPurpose, WorkerCleanupBackend,
    WorkerCleanupEvidence, WorkerCleanupRequest,
};

/// Schema v10 adds a separate operation ledger without weakening any sprint
/// completion trigger installed by v9.
pub(super) const MIGRATION_V10: &str = r"
    CREATE TABLE post_completion_rollback_operations (
        operation_id TEXT PRIMARY KEY NOT NULL,
        idempotency_key TEXT NOT NULL,
        rollback_effect_id TEXT NOT NULL UNIQUE,
        sprint_id TEXT NOT NULL,
        completion_receipt_id TEXT NOT NULL,
        application_receipt_id TEXT NOT NULL,
        rollback_reference_id TEXT NOT NULL,
        request_digest TEXT NOT NULL,
        completion_receipt_digest TEXT NOT NULL,
        application_evidence_digest TEXT NOT NULL,
        rollback_reference_evidence_digest TEXT NOT NULL,
        policy_hash TEXT NOT NULL,
        grant_hash TEXT NOT NULL,
        policy_version INTEGER NOT NULL CHECK (policy_version > 0),
        contract_version INTEGER NOT NULL CHECK (contract_version > 0),
        created_at_unix_ms INTEGER NOT NULL CHECK (created_at_unix_ms > 0),
        request_json BLOB NOT NULL CHECK (length(request_json) > 0),
        intent_json BLOB NOT NULL CHECK (length(intent_json) > 0),
        UNIQUE (application_receipt_id, idempotency_key),
        UNIQUE (sprint_id, operation_id),
        FOREIGN KEY (sprint_id, completion_receipt_id)
            REFERENCES v9_completion_receipts(sprint_id, receipt_id) ON DELETE RESTRICT,
        FOREIGN KEY (sprint_id, application_receipt_id)
            REFERENCES application_receipts(sprint_id, receipt_id) ON DELETE RESTRICT,
        FOREIGN KEY (sprint_id, rollback_reference_id)
            REFERENCES rollback_references(sprint_id, reference_id) ON DELETE RESTRICT
    ) STRICT, WITHOUT ROWID;

    CREATE TABLE post_completion_rollback_applier_launches (
        launch_id TEXT PRIMARY KEY NOT NULL,
        operation_id TEXT NOT NULL,
        sprint_id TEXT NOT NULL,
        launch_role TEXT NOT NULL CHECK (launch_role IN ('Executor', 'RecoveryValidator')),
        session_id TEXT NOT NULL UNIQUE,
        policy_hash TEXT NOT NULL,
        runner_binary_digest TEXT NOT NULL,
        protocol_digest TEXT NOT NULL,
        private_state_digest TEXT NOT NULL,
        grant_hash TEXT NOT NULL,
        policy_version INTEGER NOT NULL CHECK (policy_version > 0),
        contract_version INTEGER NOT NULL CHECK (contract_version > 0),
        created_at_unix_ms INTEGER NOT NULL CHECK (created_at_unix_ms > 0),
        launch_json BLOB NOT NULL CHECK (length(launch_json) > 0),
        execution_policy_json BLOB NOT NULL CHECK (length(execution_policy_json) > 0),
        UNIQUE (operation_id, launch_role),
        UNIQUE (operation_id, launch_id),
        UNIQUE (sprint_id, launch_id),
        FOREIGN KEY (sprint_id, operation_id)
            REFERENCES post_completion_rollback_operations(sprint_id, operation_id)
            ON DELETE RESTRICT
    ) STRICT, WITHOUT ROWID;

    CREATE TABLE post_completion_rollback_applier_sessions (
        session_id TEXT PRIMARY KEY NOT NULL,
        operation_id TEXT NOT NULL,
        sprint_id TEXT NOT NULL,
        launch_id TEXT NOT NULL UNIQUE,
        launch_role TEXT NOT NULL CHECK (launch_role IN ('Executor', 'RecoveryValidator')),
        policy_hash TEXT NOT NULL,
        session_nonce TEXT NOT NULL UNIQUE,
        runner_binary_digest TEXT NOT NULL,
        protocol_digest TEXT NOT NULL,
        private_state_digest TEXT NOT NULL,
        grant_hash TEXT NOT NULL,
        policy_version INTEGER NOT NULL CHECK (policy_version > 0),
        contract_version INTEGER NOT NULL CHECK (contract_version > 0),
        registered_at_unix_ms INTEGER NOT NULL CHECK (registered_at_unix_ms > 0),
        session_json BLOB NOT NULL CHECK (length(session_json) > 0),
        execution_policy_json BLOB NOT NULL CHECK (length(execution_policy_json) > 0),
        UNIQUE (sprint_id, session_id),
        UNIQUE (operation_id, session_id),
        FOREIGN KEY (operation_id, launch_id)
            REFERENCES post_completion_rollback_applier_launches(operation_id, launch_id)
            ON DELETE RESTRICT
    ) STRICT, WITHOUT ROWID;

    CREATE TABLE post_completion_rollback_receipt_ids (
        receipt_id TEXT PRIMARY KEY NOT NULL,
        operation_id TEXT NOT NULL,
        sprint_id TEXT NOT NULL,
        receipt_kind TEXT NOT NULL CHECK (
            receipt_kind IN ('Rollback', 'LiveConflict', 'UnknownEvidence', 'WorkerCleanup')
        ),
        contract_version INTEGER NOT NULL CHECK (contract_version > 0),
        UNIQUE (operation_id, receipt_id),
        FOREIGN KEY (sprint_id, operation_id)
            REFERENCES post_completion_rollback_operations(sprint_id, operation_id)
            ON DELETE RESTRICT
    ) STRICT, WITHOUT ROWID;

    CREATE TABLE post_completion_rollback_observations (
        observation_id TEXT PRIMARY KEY NOT NULL,
        operation_id TEXT NOT NULL UNIQUE,
        sprint_id TEXT NOT NULL,
        rollback_effect_id TEXT NOT NULL UNIQUE,
        request_digest TEXT NOT NULL,
        executor_launch_id TEXT NOT NULL,
        executor_session_id TEXT NOT NULL,
        outcome_kind TEXT NOT NULL CHECK (
            outcome_kind IN ('Succeeded', 'LiveConflict', 'Unknown')
        ),
        outcome_receipt_id TEXT NOT NULL UNIQUE,
        validator_launch_id TEXT NOT NULL,
        validator_session_id TEXT NOT NULL,
        validation_mode TEXT NOT NULL CHECK (
            validation_mode IN ('DirectEffectResponse', 'RecoveryApplierReconciliation')
        ),
        contract_version INTEGER NOT NULL CHECK (contract_version > 0),
        effect_started_at_unix_ms INTEGER NOT NULL CHECK (effect_started_at_unix_ms > 0),
        observed_at_unix_ms INTEGER NOT NULL CHECK (observed_at_unix_ms > 0),
        observation_json BLOB NOT NULL CHECK (length(observation_json) > 0),
        UNIQUE (sprint_id, observation_id),
        UNIQUE (operation_id, observation_id),
        FOREIGN KEY (sprint_id, operation_id)
            REFERENCES post_completion_rollback_operations(sprint_id, operation_id)
            ON DELETE RESTRICT,
        FOREIGN KEY (operation_id, executor_launch_id)
            REFERENCES post_completion_rollback_applier_launches(operation_id, launch_id)
            ON DELETE RESTRICT,
        FOREIGN KEY (operation_id, executor_session_id)
            REFERENCES post_completion_rollback_applier_sessions(operation_id, session_id)
            ON DELETE RESTRICT,
        FOREIGN KEY (operation_id, validator_launch_id)
            REFERENCES post_completion_rollback_applier_launches(operation_id, launch_id)
            ON DELETE RESTRICT,
        FOREIGN KEY (operation_id, validator_session_id)
            REFERENCES post_completion_rollback_applier_sessions(operation_id, session_id)
            ON DELETE RESTRICT,
        FOREIGN KEY (operation_id, outcome_receipt_id)
            REFERENCES post_completion_rollback_receipt_ids(operation_id, receipt_id)
            ON DELETE RESTRICT
    ) STRICT, WITHOUT ROWID;

    CREATE TABLE post_completion_rollback_launch_failures (
        failure_id TEXT PRIMARY KEY NOT NULL,
        operation_id TEXT NOT NULL UNIQUE,
        sprint_id TEXT NOT NULL,
        launch_id TEXT NOT NULL,
        expected_session_id TEXT NOT NULL,
        launch_role TEXT NOT NULL CHECK (launch_role IN ('Executor', 'RecoveryValidator')),
        failure_kind TEXT NOT NULL CHECK (
            failure_kind IN (
                'LaunchRefusedBeforeSpawn', 'SpawnFailedBeforeChild',
                'InitializationOutcomeUnknown'
            )
        ),
        terminal_kind TEXT NOT NULL CHECK (terminal_kind IN ('NoEffect', 'Unknown')),
        failure_evidence_digest TEXT NOT NULL,
        contract_version INTEGER NOT NULL CHECK (contract_version > 0),
        failed_at_unix_ms INTEGER NOT NULL CHECK (failed_at_unix_ms > 0),
        failure_evidence_bytes BLOB NOT NULL CHECK (length(failure_evidence_bytes) > 0),
        failure_json BLOB NOT NULL CHECK (length(failure_json) > 0),
        UNIQUE (sprint_id, failure_id),
        FOREIGN KEY (sprint_id, operation_id)
            REFERENCES post_completion_rollback_operations(sprint_id, operation_id)
            ON DELETE RESTRICT,
        FOREIGN KEY (operation_id, launch_id)
            REFERENCES post_completion_rollback_applier_launches(operation_id, launch_id)
            ON DELETE RESTRICT
    ) STRICT, WITHOUT ROWID;

    CREATE TABLE post_completion_rollback_cleanup_intents (
        cleanup_effect_id TEXT PRIMARY KEY NOT NULL,
        operation_id TEXT NOT NULL,
        sprint_id TEXT NOT NULL,
        launch_id TEXT NOT NULL UNIQUE,
        session_id TEXT NOT NULL,
        request_digest TEXT NOT NULL,
        contract_version INTEGER NOT NULL CHECK (contract_version > 0),
        created_at_unix_ms INTEGER NOT NULL CHECK (created_at_unix_ms > 0),
        request_json BLOB NOT NULL CHECK (length(request_json) > 0),
        intent_json BLOB NOT NULL CHECK (length(intent_json) > 0),
        UNIQUE (operation_id, cleanup_effect_id),
        UNIQUE (sprint_id, cleanup_effect_id),
        FOREIGN KEY (sprint_id, operation_id)
            REFERENCES post_completion_rollback_operations(sprint_id, operation_id)
            ON DELETE RESTRICT,
        FOREIGN KEY (operation_id, launch_id)
            REFERENCES post_completion_rollback_applier_launches(operation_id, launch_id)
            ON DELETE RESTRICT
    ) STRICT, WITHOUT ROWID;

    CREATE TABLE post_completion_rollback_cleanups (
        cleanup_receipt_id TEXT PRIMARY KEY NOT NULL,
        operation_id TEXT NOT NULL,
        sprint_id TEXT NOT NULL,
        launch_id TEXT NOT NULL UNIQUE,
        session_id TEXT NOT NULL,
        cleanup_effect_id TEXT NOT NULL UNIQUE,
        cleanup_observation_id TEXT NOT NULL UNIQUE,
        request_digest TEXT NOT NULL,
        policy_hash TEXT NOT NULL,
        grant_hash TEXT NOT NULL,
        policy_version INTEGER NOT NULL CHECK (policy_version > 0),
        cleaned_at_unix_ms INTEGER NOT NULL CHECK (cleaned_at_unix_ms > 0),
        contract_version INTEGER NOT NULL CHECK (contract_version > 0),
        cleanup_json BLOB NOT NULL CHECK (length(cleanup_json) > 0),
        UNIQUE (sprint_id, cleanup_receipt_id),
        UNIQUE (operation_id, cleanup_receipt_id),
        FOREIGN KEY (sprint_id, operation_id)
            REFERENCES post_completion_rollback_operations(sprint_id, operation_id)
            ON DELETE RESTRICT,
        FOREIGN KEY (operation_id, launch_id)
            REFERENCES post_completion_rollback_applier_launches(operation_id, launch_id)
            ON DELETE RESTRICT,
        FOREIGN KEY (operation_id, cleanup_effect_id)
            REFERENCES post_completion_rollback_cleanup_intents(operation_id, cleanup_effect_id)
            ON DELETE RESTRICT,
        FOREIGN KEY (operation_id, cleanup_receipt_id)
            REFERENCES post_completion_rollback_receipt_ids(operation_id, receipt_id)
            ON DELETE RESTRICT
    ) STRICT, WITHOUT ROWID;

    CREATE TABLE post_completion_rollback_terminals (
        terminal_id TEXT PRIMARY KEY NOT NULL,
        operation_id TEXT NOT NULL UNIQUE,
        sprint_id TEXT NOT NULL,
        application_receipt_id TEXT NOT NULL,
        outcome_id TEXT NOT NULL UNIQUE,
        terminal_kind TEXT NOT NULL CHECK (
            terminal_kind IN ('Succeeded', 'LiveConflict', 'Unknown', 'NoEffect')
        ),
        cleanup_count INTEGER NOT NULL CHECK (cleanup_count > 0),
        contract_version INTEGER NOT NULL CHECK (contract_version > 0),
        terminal_at_unix_ms INTEGER NOT NULL CHECK (terminal_at_unix_ms > 0),
        terminal_json BLOB NOT NULL CHECK (length(terminal_json) > 0),
        UNIQUE (sprint_id, terminal_id),
        UNIQUE (operation_id, terminal_id),
        FOREIGN KEY (sprint_id, operation_id)
            REFERENCES post_completion_rollback_operations(sprint_id, operation_id)
            ON DELETE RESTRICT,
        UNIQUE (operation_id, outcome_id)
    ) STRICT, WITHOUT ROWID;

    CREATE UNIQUE INDEX post_completion_rollback_one_success_per_application
    ON post_completion_rollback_terminals (application_receipt_id)
    WHERE terminal_kind = 'Succeeded';

    CREATE TABLE post_completion_rollback_terminal_cleanups (
        terminal_id TEXT NOT NULL,
        operation_id TEXT NOT NULL,
        ordinal INTEGER NOT NULL CHECK (ordinal >= 0),
        cleanup_receipt_id TEXT NOT NULL,
        PRIMARY KEY (terminal_id, ordinal),
        UNIQUE (terminal_id, cleanup_receipt_id),
        FOREIGN KEY (operation_id, terminal_id)
            REFERENCES post_completion_rollback_terminals(operation_id, terminal_id)
            ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED,
        FOREIGN KEY (operation_id, cleanup_receipt_id)
            REFERENCES post_completion_rollback_cleanups(operation_id, cleanup_receipt_id)
            ON DELETE RESTRICT
    ) STRICT, WITHOUT ROWID;

    CREATE TRIGGER post_completion_rollback_operations_no_update
    BEFORE UPDATE ON post_completion_rollback_operations
    BEGIN SELECT RAISE(ABORT, 'post-completion rollback intents are immutable'); END;
    CREATE TRIGGER post_completion_rollback_operations_no_delete
    BEFORE DELETE ON post_completion_rollback_operations
    BEGIN SELECT RAISE(ABORT, 'post-completion rollback intents are immutable'); END;
    CREATE TRIGGER post_completion_rollback_launches_no_update
    BEFORE UPDATE ON post_completion_rollback_applier_launches
    BEGIN SELECT RAISE(ABORT, 'post-completion rollback launches are immutable'); END;
    CREATE TRIGGER post_completion_rollback_launches_no_delete
    BEFORE DELETE ON post_completion_rollback_applier_launches
    BEGIN SELECT RAISE(ABORT, 'post-completion rollback launches are immutable'); END;
    CREATE TRIGGER post_completion_rollback_sessions_no_update
    BEFORE UPDATE ON post_completion_rollback_applier_sessions
    BEGIN SELECT RAISE(ABORT, 'post-completion rollback sessions are immutable'); END;
    CREATE TRIGGER post_completion_rollback_sessions_no_delete
    BEFORE DELETE ON post_completion_rollback_applier_sessions
    BEGIN SELECT RAISE(ABORT, 'post-completion rollback sessions are immutable'); END;
    CREATE TRIGGER post_completion_rollback_receipt_ids_no_update
    BEFORE UPDATE ON post_completion_rollback_receipt_ids
    BEGIN SELECT RAISE(ABORT, 'post-completion rollback receipt identities are immutable'); END;
    CREATE TRIGGER post_completion_rollback_receipt_ids_no_delete
    BEFORE DELETE ON post_completion_rollback_receipt_ids
    BEGIN SELECT RAISE(ABORT, 'post-completion rollback receipt identities are immutable'); END;
    CREATE TRIGGER post_completion_rollback_observations_no_update
    BEFORE UPDATE ON post_completion_rollback_observations
    BEGIN SELECT RAISE(ABORT, 'post-completion rollback observations are immutable'); END;
    CREATE TRIGGER post_completion_rollback_observations_no_delete
    BEFORE DELETE ON post_completion_rollback_observations
    BEGIN SELECT RAISE(ABORT, 'post-completion rollback observations are immutable'); END;
    CREATE TRIGGER post_completion_rollback_launch_failures_no_update
    BEFORE UPDATE ON post_completion_rollback_launch_failures
    BEGIN SELECT RAISE(ABORT, 'post-completion rollback launch failures are immutable'); END;
    CREATE TRIGGER post_completion_rollback_launch_failures_no_delete
    BEFORE DELETE ON post_completion_rollback_launch_failures
    BEGIN SELECT RAISE(ABORT, 'post-completion rollback launch failures are immutable'); END;
    CREATE TRIGGER post_completion_rollback_cleanup_intents_no_update
    BEFORE UPDATE ON post_completion_rollback_cleanup_intents
    BEGIN SELECT RAISE(ABORT, 'post-completion rollback cleanup intents are immutable'); END;
    CREATE TRIGGER post_completion_rollback_cleanup_intents_no_delete
    BEFORE DELETE ON post_completion_rollback_cleanup_intents
    BEGIN SELECT RAISE(ABORT, 'post-completion rollback cleanup intents are immutable'); END;
    CREATE TRIGGER post_completion_rollback_cleanups_no_update
    BEFORE UPDATE ON post_completion_rollback_cleanups
    BEGIN SELECT RAISE(ABORT, 'post-completion rollback cleanups are immutable'); END;
    CREATE TRIGGER post_completion_rollback_cleanups_no_delete
    BEFORE DELETE ON post_completion_rollback_cleanups
    BEGIN SELECT RAISE(ABORT, 'post-completion rollback cleanups are immutable'); END;
    CREATE TRIGGER post_completion_rollback_terminals_no_update
    BEFORE UPDATE ON post_completion_rollback_terminals
    BEGIN SELECT RAISE(ABORT, 'post-completion rollback terminals are immutable'); END;
    CREATE TRIGGER post_completion_rollback_terminals_no_delete
    BEFORE DELETE ON post_completion_rollback_terminals
    BEGIN SELECT RAISE(ABORT, 'post-completion rollback terminals are immutable'); END;
    CREATE TRIGGER post_completion_rollback_terminal_cleanups_no_update
    BEFORE UPDATE ON post_completion_rollback_terminal_cleanups
    BEGIN SELECT RAISE(ABORT, 'post-completion rollback terminal cleanup links are immutable'); END;
    CREATE TRIGGER post_completion_rollback_terminal_cleanups_no_delete
    BEFORE DELETE ON post_completion_rollback_terminal_cleanups
    BEGIN SELECT RAISE(ABORT, 'post-completion rollback terminal cleanup links are immutable'); END;

    CREATE TRIGGER post_completion_rollback_operation_requires_proven_applied_completion
    BEFORE INSERT ON post_completion_rollback_operations
    WHEN NOT EXISTS (
        SELECT 1
        FROM sprint_completion_proof_states proof
        JOIN v9_completion_receipts completion
          ON completion.sprint_id = proof.sprint_id
         AND completion.receipt_id = proof.completion_receipt_id
        WHERE proof.sprint_id = NEW.sprint_id
          AND proof.proof_state = 'ProvenV9'
          AND completion.receipt_id = NEW.completion_receipt_id
          AND completion.application_kind = 'Applied'
          AND completion.application_receipt_id = NEW.application_receipt_id
          AND completion.rollback_reference_id = NEW.rollback_reference_id
          AND completion.grant_hash = NEW.grant_hash
          AND completion.policy_version = NEW.policy_version
          AND completion.completed_at_unix_ms <= NEW.created_at_unix_ms
    ) OR EXISTS (
        SELECT 1 FROM post_completion_rollback_terminals terminal
        WHERE terminal.application_receipt_id = NEW.application_receipt_id
          AND terminal.terminal_kind IN ('Succeeded', 'Unknown')
    )
    BEGIN SELECT RAISE(ABORT, 'rollback operation requires exact applied completion without prior success or unknown effect'); END;

    CREATE TRIGGER post_completion_rollback_one_active_operation
    BEFORE INSERT ON post_completion_rollback_operations
    WHEN EXISTS (
        SELECT 1
        FROM post_completion_rollback_operations operation
        LEFT JOIN post_completion_rollback_terminals terminal
          ON terminal.operation_id = operation.operation_id
        WHERE operation.application_receipt_id = NEW.application_receipt_id
          AND terminal.operation_id IS NULL
    )
    BEGIN SELECT RAISE(ABORT, 'application already has an active rollback operation'); END;

    CREATE TRIGGER post_completion_rollback_launch_requires_live_operation
    BEFORE INSERT ON post_completion_rollback_applier_launches
    WHEN EXISTS (
        SELECT 1 FROM post_completion_rollback_terminals
        WHERE operation_id = NEW.operation_id
    ) OR EXISTS (
        SELECT 1 FROM post_completion_rollback_observations
        WHERE operation_id = NEW.operation_id
    ) OR EXISTS (
        SELECT 1 FROM post_completion_rollback_launch_failures
        WHERE operation_id = NEW.operation_id
    ) OR NOT EXISTS (
        SELECT 1 FROM post_completion_rollback_operations operation
        WHERE operation.operation_id = NEW.operation_id
          AND operation.sprint_id = NEW.sprint_id
          AND operation.policy_hash = NEW.policy_hash
          AND operation.grant_hash = NEW.grant_hash
          AND operation.policy_version = NEW.policy_version
          AND operation.created_at_unix_ms <= NEW.created_at_unix_ms
    ) OR NEW.launch_role = 'RecoveryValidator' AND NOT EXISTS (
        SELECT 1
        FROM post_completion_rollback_applier_sessions session
        WHERE session.operation_id = NEW.operation_id
          AND session.launch_role = 'Executor'
    )
    BEGIN SELECT RAISE(ABORT, 'rollback launch requires a live prior intent and initialized executor'); END;

    CREATE TRIGGER post_completion_rollback_session_requires_exact_launch
    BEFORE INSERT ON post_completion_rollback_applier_sessions
    WHEN EXISTS (
        SELECT 1 FROM post_completion_rollback_terminals
        WHERE operation_id = NEW.operation_id
    ) OR EXISTS (
        SELECT 1 FROM post_completion_rollback_observations
        WHERE operation_id = NEW.operation_id
    ) OR EXISTS (
        SELECT 1 FROM post_completion_rollback_launch_failures
        WHERE operation_id = NEW.operation_id
    ) OR NOT EXISTS (
        SELECT 1 FROM post_completion_rollback_applier_launches launch
        WHERE launch.operation_id = NEW.operation_id
          AND launch.sprint_id = NEW.sprint_id
          AND launch.launch_id = NEW.launch_id
          AND launch.session_id = NEW.session_id
          AND launch.launch_role = NEW.launch_role
          AND launch.policy_hash = NEW.policy_hash
          AND launch.runner_binary_digest = NEW.runner_binary_digest
          AND launch.protocol_digest = NEW.protocol_digest
          AND launch.private_state_digest = NEW.private_state_digest
          AND launch.grant_hash = NEW.grant_hash
          AND launch.policy_version = NEW.policy_version
          AND launch.created_at_unix_ms <= NEW.registered_at_unix_ms
    )
    BEGIN SELECT RAISE(ABORT, 'rollback session must exactly authenticate its pre-spawn launch'); END;

    CREATE TRIGGER post_completion_rollback_observation_requires_exact_executor
    BEFORE INSERT ON post_completion_rollback_observations
    WHEN EXISTS (
        SELECT 1 FROM post_completion_rollback_terminals
        WHERE operation_id = NEW.operation_id
    ) OR NOT EXISTS (
        SELECT 1
        FROM post_completion_rollback_operations operation
        JOIN post_completion_rollback_applier_launches launch
          ON launch.operation_id = operation.operation_id
         AND launch.launch_role = 'Executor'
        JOIN post_completion_rollback_applier_sessions session
          ON session.operation_id = operation.operation_id
         AND session.launch_id = launch.launch_id
        WHERE operation.operation_id = NEW.operation_id
          AND operation.sprint_id = NEW.sprint_id
          AND operation.rollback_effect_id = NEW.rollback_effect_id
          AND operation.request_digest = NEW.request_digest
          AND launch.launch_id = NEW.executor_launch_id
          AND session.session_id = NEW.executor_session_id
          AND session.registered_at_unix_ms <= NEW.effect_started_at_unix_ms
          AND NEW.effect_started_at_unix_ms <= NEW.observed_at_unix_ms
    )
    BEGIN SELECT RAISE(ABORT, 'rollback observation must match its exact initialized executor'); END;

    CREATE TRIGGER post_completion_rollback_observation_excludes_launch_failure
    BEFORE INSERT ON post_completion_rollback_observations
    WHEN EXISTS (
        SELECT 1 FROM post_completion_rollback_launch_failures
        WHERE operation_id = NEW.operation_id
    )
    BEGIN SELECT RAISE(ABORT, 'rollback operation already has a launch-failure outcome'); END;

    CREATE TRIGGER post_completion_rollback_launch_failure_requires_exact_uninitialized_launch
    BEFORE INSERT ON post_completion_rollback_launch_failures
    WHEN EXISTS (
        SELECT 1 FROM post_completion_rollback_terminals
        WHERE operation_id = NEW.operation_id
    ) OR EXISTS (
        SELECT 1 FROM post_completion_rollback_observations
        WHERE operation_id = NEW.operation_id
    ) OR EXISTS (
        SELECT 1 FROM post_completion_rollback_applier_sessions
        WHERE operation_id = NEW.operation_id AND launch_id = NEW.launch_id
    ) OR NOT EXISTS (
        SELECT 1 FROM post_completion_rollback_applier_launches launch
        WHERE launch.operation_id = NEW.operation_id
          AND launch.sprint_id = NEW.sprint_id
          AND launch.launch_id = NEW.launch_id
          AND launch.session_id = NEW.expected_session_id
          AND launch.launch_role = NEW.launch_role
          AND launch.created_at_unix_ms <= NEW.failed_at_unix_ms
          AND (
              (launch.launch_role = 'Executor'
               AND NEW.failure_kind IN ('LaunchRefusedBeforeSpawn', 'SpawnFailedBeforeChild')
               AND NEW.terminal_kind = 'NoEffect')
              OR
              ((launch.launch_role = 'RecoveryValidator'
                OR NEW.failure_kind = 'InitializationOutcomeUnknown')
               AND NEW.terminal_kind = 'Unknown')
          )
    )
    BEGIN SELECT RAISE(ABORT, 'launch failure must exactly classify one uninitialized fresh launch'); END;

    CREATE TRIGGER post_completion_rollback_launch_failure_global_unique
    BEFORE INSERT ON post_completion_rollback_launch_failures
    WHEN EXISTS (SELECT 1 FROM effect_observations WHERE observation_id = NEW.failure_id)
      OR EXISTS (SELECT 1 FROM post_completion_rollback_observations WHERE observation_id = NEW.failure_id)
      OR EXISTS (SELECT 1 FROM post_completion_rollback_cleanups WHERE cleanup_observation_id = NEW.failure_id)
    BEGIN SELECT RAISE(ABORT, 'post-completion launch-failure identity must be globally unique'); END;

    CREATE TRIGGER post_completion_rollback_cleanup_intent_requires_exact_launch_and_outcome
    BEFORE INSERT ON post_completion_rollback_cleanup_intents
    WHEN EXISTS (
        SELECT 1 FROM post_completion_rollback_terminals
        WHERE operation_id = NEW.operation_id
    ) OR NOT EXISTS (
        SELECT 1
        FROM post_completion_rollback_applier_launches launch
        LEFT JOIN post_completion_rollback_observations observation
          ON observation.operation_id = launch.operation_id
        LEFT JOIN post_completion_rollback_launch_failures failure
          ON failure.operation_id = launch.operation_id
        WHERE launch.operation_id = NEW.operation_id
          AND launch.sprint_id = NEW.sprint_id
          AND launch.launch_id = NEW.launch_id
          AND launch.session_id = NEW.session_id
          AND COALESCE(observation.observed_at_unix_ms, failure.failed_at_unix_ms)
              <= NEW.created_at_unix_ms
          AND (observation.operation_id IS NOT NULL OR failure.operation_id IS NOT NULL)
    )
    BEGIN SELECT RAISE(ABORT, 'rollback cleanup intent requires an exact fresh launch after final outcome activity'); END;

    CREATE TRIGGER post_completion_rollback_cleanup_requires_exact_intent
    BEFORE INSERT ON post_completion_rollback_cleanups
    WHEN EXISTS (
        SELECT 1 FROM post_completion_rollback_terminals
        WHERE operation_id = NEW.operation_id
    ) OR NOT EXISTS (
        SELECT 1
        FROM post_completion_rollback_cleanup_intents intent
        JOIN post_completion_rollback_applier_launches launch
          ON launch.operation_id = intent.operation_id
         AND launch.launch_id = intent.launch_id
        WHERE intent.operation_id = NEW.operation_id
          AND intent.sprint_id = NEW.sprint_id
          AND intent.cleanup_effect_id = NEW.cleanup_effect_id
          AND intent.launch_id = NEW.launch_id
          AND intent.session_id = NEW.session_id
          AND intent.request_digest = NEW.request_digest
          AND intent.created_at_unix_ms <= NEW.cleaned_at_unix_ms
          AND launch.policy_hash = NEW.policy_hash
          AND launch.grant_hash = NEW.grant_hash
          AND launch.policy_version = NEW.policy_version
    )
    BEGIN SELECT RAISE(ABORT, 'rollback cleanup observation must match its prior exact cleanup intent'); END;

    CREATE TRIGGER post_completion_rollback_terminal_requires_exact_outcome_and_cleanup
    BEFORE INSERT ON post_completion_rollback_terminals
    WHEN NOT EXISTS (
        SELECT 1
        FROM post_completion_rollback_operations operation
        LEFT JOIN post_completion_rollback_observations observation
          ON observation.operation_id = operation.operation_id
        LEFT JOIN post_completion_rollback_launch_failures failure
          ON failure.operation_id = operation.operation_id
        WHERE operation.operation_id = NEW.operation_id
          AND operation.sprint_id = NEW.sprint_id
          AND operation.application_receipt_id = NEW.application_receipt_id
          AND (
              (observation.observation_id = NEW.outcome_id
               AND observation.outcome_kind = NEW.terminal_kind
               AND observation.observed_at_unix_ms <= NEW.terminal_at_unix_ms)
              OR
              (failure.failure_id = NEW.outcome_id
               AND failure.terminal_kind = NEW.terminal_kind
               AND failure.failed_at_unix_ms <= NEW.terminal_at_unix_ms)
          )
    ) OR NEW.cleanup_count != (
        SELECT COUNT(*) FROM post_completion_rollback_applier_launches
        WHERE operation_id = NEW.operation_id
    ) OR NEW.cleanup_count != (
        SELECT COUNT(*) FROM post_completion_rollback_cleanups
        WHERE operation_id = NEW.operation_id
    ) OR NEW.cleanup_count != (
        SELECT COUNT(*) FROM post_completion_rollback_terminal_cleanups
        WHERE operation_id = NEW.operation_id AND terminal_id = NEW.terminal_id
    ) OR EXISTS (
        SELECT 1 FROM post_completion_rollback_applier_launches launch
        LEFT JOIN post_completion_rollback_cleanups cleanup
          ON cleanup.operation_id = launch.operation_id
         AND cleanup.launch_id = launch.launch_id
        LEFT JOIN post_completion_rollback_terminal_cleanups link
          ON link.operation_id = cleanup.operation_id
         AND link.terminal_id = NEW.terminal_id
         AND link.cleanup_receipt_id = cleanup.cleanup_receipt_id
        WHERE launch.operation_id = NEW.operation_id
          AND (cleanup.cleanup_receipt_id IS NULL OR link.cleanup_receipt_id IS NULL
               OR cleanup.cleaned_at_unix_ms > NEW.terminal_at_unix_ms)
    )
    BEGIN SELECT RAISE(ABORT, 'rollback terminal requires the exact zero-descendant cleanup set'); END;

    CREATE TRIGGER post_completion_rollback_receipt_ids_global_unique
    BEFORE INSERT ON post_completion_rollback_receipt_ids
    WHEN EXISTS (SELECT 1 FROM finish_receipt_ids WHERE receipt_id = NEW.receipt_id)
      OR EXISTS (SELECT 1 FROM verification_receipts WHERE receipt_id = NEW.receipt_id)
      OR EXISTS (SELECT 1 FROM acceptance_receipts WHERE receipt_id = NEW.receipt_id)
      OR EXISTS (SELECT 1 FROM completion_receipts WHERE receipt_id = NEW.receipt_id)
      OR EXISTS (SELECT 1 FROM v9_completion_receipts WHERE receipt_id = NEW.receipt_id)
    BEGIN SELECT RAISE(ABORT, 'post-completion receipt identity must be globally unique'); END;
    CREATE TRIGGER finish_receipt_ids_post_completion_unique
    BEFORE INSERT ON finish_receipt_ids
    WHEN EXISTS (SELECT 1 FROM post_completion_rollback_receipt_ids WHERE receipt_id = NEW.receipt_id)
    BEGIN SELECT RAISE(ABORT, 'receipt identity must be globally unique'); END;
    CREATE TRIGGER verification_receipts_post_completion_unique
    BEFORE INSERT ON verification_receipts
    WHEN EXISTS (SELECT 1 FROM post_completion_rollback_receipt_ids WHERE receipt_id = NEW.receipt_id)
    BEGIN SELECT RAISE(ABORT, 'receipt identity must be globally unique'); END;
    CREATE TRIGGER acceptance_receipts_post_completion_unique
    BEFORE INSERT ON acceptance_receipts
    WHEN EXISTS (SELECT 1 FROM post_completion_rollback_receipt_ids WHERE receipt_id = NEW.receipt_id)
    BEGIN SELECT RAISE(ABORT, 'receipt identity must be globally unique'); END;
    CREATE TRIGGER completion_receipts_post_completion_unique
    BEFORE INSERT ON completion_receipts
    WHEN EXISTS (SELECT 1 FROM post_completion_rollback_receipt_ids WHERE receipt_id = NEW.receipt_id)
    BEGIN SELECT RAISE(ABORT, 'receipt identity must be globally unique'); END;
    CREATE TRIGGER v9_completion_receipts_post_completion_unique
    BEFORE INSERT ON v9_completion_receipts
    WHEN EXISTS (SELECT 1 FROM post_completion_rollback_receipt_ids WHERE receipt_id = NEW.receipt_id)
    BEGIN SELECT RAISE(ABORT, 'receipt identity must be globally unique'); END;

    CREATE TRIGGER post_completion_rollback_launch_global_unique
    BEFORE INSERT ON post_completion_rollback_applier_launches
    WHEN EXISTS (
        SELECT 1 FROM runner_launch_intents
        WHERE launch_id IN (NEW.launch_id, NEW.session_id)
           OR session_id IN (NEW.launch_id, NEW.session_id)
    ) OR EXISTS (
        SELECT 1 FROM post_completion_rollback_applier_launches
        WHERE launch_id IN (NEW.launch_id, NEW.session_id)
           OR session_id IN (NEW.launch_id, NEW.session_id)
    )
    BEGIN SELECT RAISE(ABORT, 'post-completion launch and session identities must be globally unique'); END;
    CREATE TRIGGER runner_launch_post_completion_unique
    BEFORE INSERT ON runner_launch_intents
    WHEN EXISTS (
        SELECT 1 FROM post_completion_rollback_applier_launches
        WHERE launch_id IN (NEW.launch_id, NEW.session_id)
           OR session_id IN (NEW.launch_id, NEW.session_id)
    )
    BEGIN SELECT RAISE(ABORT, 'runner launch and session identities must be globally unique'); END;
    CREATE TRIGGER post_completion_rollback_session_global_unique
    BEFORE INSERT ON post_completion_rollback_applier_sessions
    WHEN EXISTS (SELECT 1 FROM runner_session_policies WHERE session_id = NEW.session_id)
      OR EXISTS (SELECT 1 FROM runner_session_policies WHERE session_nonce = NEW.session_nonce)
    BEGIN SELECT RAISE(ABORT, 'post-completion session identity and nonce must be globally unique'); END;
    CREATE TRIGGER runner_session_post_completion_unique
    BEFORE INSERT ON runner_session_policies
    WHEN EXISTS (SELECT 1 FROM post_completion_rollback_applier_sessions WHERE session_id = NEW.session_id)
      OR EXISTS (SELECT 1 FROM post_completion_rollback_applier_sessions WHERE session_nonce = NEW.session_nonce)
    BEGIN SELECT RAISE(ABORT, 'runner session identity and nonce must be globally unique'); END;

    CREATE TRIGGER post_completion_rollback_effect_global_unique
    BEFORE INSERT ON post_completion_rollback_operations
    WHEN EXISTS (SELECT 1 FROM effect_intents WHERE effect_id = NEW.rollback_effect_id)
      OR EXISTS (
          SELECT 1 FROM post_completion_rollback_cleanup_intents
          WHERE cleanup_effect_id = NEW.rollback_effect_id
      )
    BEGIN SELECT RAISE(ABORT, 'post-completion rollback effect identity must be globally unique'); END;
    CREATE TRIGGER effect_intents_post_completion_unique
    BEFORE INSERT ON effect_intents
    WHEN EXISTS (SELECT 1 FROM post_completion_rollback_operations WHERE rollback_effect_id = NEW.effect_id)
      OR EXISTS (SELECT 1 FROM post_completion_rollback_cleanup_intents WHERE cleanup_effect_id = NEW.effect_id)
    BEGIN SELECT RAISE(ABORT, 'effect identity must be globally unique'); END;
    CREATE TRIGGER post_completion_rollback_cleanup_effect_global_unique
    BEFORE INSERT ON post_completion_rollback_cleanup_intents
    WHEN EXISTS (SELECT 1 FROM effect_intents WHERE effect_id = NEW.cleanup_effect_id)
      OR EXISTS (SELECT 1 FROM post_completion_rollback_operations WHERE rollback_effect_id = NEW.cleanup_effect_id)
    BEGIN SELECT RAISE(ABORT, 'post-completion cleanup effect identity must be globally unique'); END;
    CREATE TRIGGER post_completion_rollback_observation_global_unique
    BEFORE INSERT ON post_completion_rollback_observations
    WHEN EXISTS (SELECT 1 FROM effect_observations WHERE observation_id = NEW.observation_id)
      OR EXISTS (
          SELECT 1 FROM post_completion_rollback_cleanups
          WHERE cleanup_observation_id = NEW.observation_id
      ) OR EXISTS (
          SELECT 1 FROM post_completion_rollback_launch_failures
          WHERE failure_id = NEW.observation_id
      )
    BEGIN SELECT RAISE(ABORT, 'post-completion rollback observation identity must be globally unique'); END;
    CREATE TRIGGER post_completion_rollback_cleanup_observation_global_unique
    BEFORE INSERT ON post_completion_rollback_cleanups
    WHEN EXISTS (SELECT 1 FROM effect_observations WHERE observation_id = NEW.cleanup_observation_id)
      OR EXISTS (SELECT 1 FROM post_completion_rollback_observations WHERE observation_id = NEW.cleanup_observation_id)
      OR EXISTS (SELECT 1 FROM post_completion_rollback_launch_failures WHERE failure_id = NEW.cleanup_observation_id)
    BEGIN SELECT RAISE(ABORT, 'post-completion cleanup observation identity must be globally unique'); END;
    CREATE TRIGGER effect_observations_post_completion_unique
    BEFORE INSERT ON effect_observations
    WHEN EXISTS (SELECT 1 FROM post_completion_rollback_observations WHERE observation_id = NEW.observation_id)
      OR EXISTS (SELECT 1 FROM post_completion_rollback_cleanups WHERE cleanup_observation_id = NEW.observation_id)
      OR EXISTS (SELECT 1 FROM post_completion_rollback_launch_failures WHERE failure_id = NEW.observation_id)
    BEGIN SELECT RAISE(ABORT, 'effect observation identity must be globally unique'); END;
";

/// Maximum exact recovery evidence retained for an `Unknown` outcome.
pub const MAX_POST_COMPLETION_ROLLBACK_UNKNOWN_EVIDENCE_BYTES: usize = 1_048_576;
/// Maximum human-readable reason retained with an `Unknown` outcome.
pub const MAX_POST_COMPLETION_ROLLBACK_REASON_BYTES: usize = 16 * 1024;
/// Maximum exact launch-failure evidence retained by one operation.
pub const MAX_POST_COMPLETION_ROLLBACK_LAUNCH_FAILURE_EVIDENCE_BYTES: usize = 1_048_576;

/// Closed role of a fresh applier launch within one rollback operation.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub enum PostCompletionRollbackApplierRole {
    /// Executes the exact rollback request.
    Executor,
    /// Distinct applier that reconciles a lost executor response.
    RecoveryValidator,
}

impl PostCompletionRollbackApplierRole {
    const fn storage_name(self) -> &'static str {
        match self {
            Self::Executor => "Executor",
            Self::RecoveryValidator => "RecoveryValidator",
        }
    }
}

/// Immutable authorization committed before any post-completion applier may
/// launch or execute the rollback.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PostCompletionRollbackIntent {
    /// Wire-contract version.
    pub contract_version: u32,
    /// Stable operation identity.
    pub operation_id: String,
    /// Retry identity unique for this application.
    pub idempotency_key: String,
    /// Exact effect identity carried by a successful rollback receipt.
    pub rollback_effect_id: String,
    /// Immutable completed sprint.
    pub sprint_id: String,
    /// Exact successful completion receipt.
    pub completion_receipt_id: String,
    /// SHA-256 of the exact canonical completion receipt.
    pub completion_receipt_digest: Digest,
    /// SHA-256 of the exact canonical `ApplicationEvidence` envelope.
    pub application_evidence_digest: Digest,
    /// SHA-256 of the exact canonical `RollbackReferenceEvidence` envelope.
    pub rollback_reference_evidence_digest: Digest,
    /// Exact rollback request.
    pub request: RollbackRequest,
    /// SHA-256 of the canonical request bytes.
    pub request_digest: Digest,
    /// Exact compiler-produced application/applier policy.
    pub policy_hash: Digest,
    /// Exact immutable workspace grant.
    pub grant_hash: Digest,
    /// Exact grant policy version.
    pub policy_version: u32,
    /// Durable intent time, before launch or execution.
    pub created_at_unix_ms: u64,
}

impl PostCompletionRollbackIntent {
    /// Validates the self-contained canonical intent envelope.
    ///
    /// # Errors
    ///
    /// Returns [`ContractError`] when a version, identity, request binding,
    /// policy version, or timestamp is invalid.
    pub fn validate(&self) -> Result<(), ContractError> {
        require_version(
            self.contract_version,
            "post_completion_rollback_intent.contract_version",
        )?;
        require_text(
            "post_completion_rollback_intent.operation_id",
            &self.operation_id,
        )?;
        require_text(
            "post_completion_rollback_intent.idempotency_key",
            &self.idempotency_key,
        )?;
        require_text(
            "post_completion_rollback_intent.rollback_effect_id",
            &self.rollback_effect_id,
        )?;
        require_text("post_completion_rollback_intent.sprint_id", &self.sprint_id)?;
        require_text(
            "post_completion_rollback_intent.completion_receipt_id",
            &self.completion_receipt_id,
        )?;
        self.request.validate()?;
        if self.request.sprint_id != self.sprint_id {
            return Err(contract_error(
                "post_completion_rollback_intent.request.sprint_id",
                "must match the immutable completed sprint",
            ));
        }
        let request_bytes = canonical("post-completion rollback request", &self.request)?;
        if Digest::sha256(&request_bytes) != self.request_digest {
            return Err(contract_error(
                "post_completion_rollback_intent.request_digest",
                "does not authenticate the canonical rollback request",
            ));
        }
        if self.policy_version == 0 {
            return Err(contract_error(
                "post_completion_rollback_intent.policy_version",
                "must be greater than zero",
            ));
        }
        require_time(
            "post_completion_rollback_intent.created_at_unix_ms",
            self.created_at_unix_ms,
        )
    }
}

/// Exact bounded reconciliation evidence for an operation whose live result
/// cannot be proven.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PostCompletionRollbackUnknownEvidence {
    /// Stable receipt-like evidence identity.
    pub evidence_id: String,
    /// Human-readable reason that makes no live-state claim.
    pub reason: String,
    /// SHA-256 of the retained reconciler evidence bytes.
    pub reconciliation_evidence_digest: Digest,
    /// Exact bounded reconciler evidence bytes.
    pub reconciliation_evidence_bytes: Vec<u8>,
}

impl PostCompletionRollbackUnknownEvidence {
    fn validate(&self) -> Result<(), ContractError> {
        require_text(
            "post_completion_rollback_unknown_evidence.evidence_id",
            &self.evidence_id,
        )?;
        require_text(
            "post_completion_rollback_unknown_evidence.reason",
            &self.reason,
        )?;
        if self.reason.len() > MAX_POST_COMPLETION_ROLLBACK_REASON_BYTES {
            return Err(contract_error(
                "post_completion_rollback_unknown_evidence.reason",
                format!("must not exceed {MAX_POST_COMPLETION_ROLLBACK_REASON_BYTES} bytes"),
            ));
        }
        if self.reconciliation_evidence_bytes.is_empty()
            || self.reconciliation_evidence_bytes.len()
                > MAX_POST_COMPLETION_ROLLBACK_UNKNOWN_EVIDENCE_BYTES
        {
            return Err(contract_error(
                "post_completion_rollback_unknown_evidence.reconciliation_evidence_bytes",
                format!(
                    "must contain 1..={MAX_POST_COMPLETION_ROLLBACK_UNKNOWN_EVIDENCE_BYTES} bytes"
                ),
            ));
        }
        if Digest::sha256(&self.reconciliation_evidence_bytes)
            != self.reconciliation_evidence_digest
        {
            return Err(contract_error(
                "post_completion_rollback_unknown_evidence.reconciliation_evidence_bytes",
                "digest does not match the retained reconciler evidence",
            ));
        }
        Ok(())
    }
}

/// Closed, non-overlapping classification of a failed fresh applier launch.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum PostCompletionRollbackLaunchFailureKind {
    /// Policy/admission refused the launch before an operating-system spawn.
    LaunchRefusedBeforeSpawn,
    /// Spawn failed with proof that no child/process domain was created.
    SpawnFailedBeforeChild,
    /// A child may exist, but initialization outcome is not provable.
    InitializationOutcomeUnknown,
}

impl PostCompletionRollbackLaunchFailureKind {
    const fn storage_name(self) -> &'static str {
        match self {
            Self::LaunchRefusedBeforeSpawn => "LaunchRefusedBeforeSpawn",
            Self::SpawnFailedBeforeChild => "SpawnFailedBeforeChild",
            Self::InitializationOutcomeUnknown => "InitializationOutcomeUnknown",
        }
    }
}

/// Exact outcome for a committed launch that never produced a registered
/// session. This path can terminalize only after cleanup of the launch's
/// process/accounting domain.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PostCompletionRollbackLaunchFailure {
    /// Wire-contract version.
    pub contract_version: u32,
    /// Stable failure/outcome identity.
    pub failure_id: String,
    /// Owning rollback operation.
    pub operation_id: String,
    /// Immutable completed sprint.
    pub sprint_id: String,
    /// Fresh launch that failed to register.
    pub launch_id: String,
    /// Expected session identity reserved by the launch intent.
    pub expected_session_id: String,
    /// Executor or distinct recovery validator.
    pub launch_role: PostCompletionRollbackApplierRole,
    /// Exact non-overlapping launch failure class.
    pub kind: PostCompletionRollbackLaunchFailureKind,
    /// SHA-256 of the exact retained launcher evidence.
    pub failure_evidence_digest: Digest,
    /// Exact bounded launcher/admission evidence.
    pub failure_evidence_bytes: Vec<u8>,
    /// Failure observation time.
    pub failed_at_unix_ms: u64,
}

impl PostCompletionRollbackLaunchFailure {
    /// Returns the truthful operation outcome implied by role and failure class.
    #[must_use]
    pub const fn outcome_kind(&self) -> PostCompletionRollbackOutcomeKind {
        match (self.launch_role, self.kind) {
            (
                PostCompletionRollbackApplierRole::Executor,
                PostCompletionRollbackLaunchFailureKind::LaunchRefusedBeforeSpawn
                | PostCompletionRollbackLaunchFailureKind::SpawnFailedBeforeChild,
            ) => PostCompletionRollbackOutcomeKind::NoEffect,
            _ => PostCompletionRollbackOutcomeKind::Unknown,
        }
    }

    /// Validates the self-contained launch-failure evidence.
    ///
    /// # Errors
    ///
    /// Returns [`ContractError`] for invalid identities, empty/oversized or
    /// unauthenticated evidence, or a zero timestamp.
    pub fn validate(&self) -> Result<(), ContractError> {
        require_version(
            self.contract_version,
            "post_completion_rollback_launch_failure.contract_version",
        )?;
        require_text(
            "post_completion_rollback_launch_failure.failure_id",
            &self.failure_id,
        )?;
        require_text(
            "post_completion_rollback_launch_failure.operation_id",
            &self.operation_id,
        )?;
        require_text(
            "post_completion_rollback_launch_failure.sprint_id",
            &self.sprint_id,
        )?;
        require_text(
            "post_completion_rollback_launch_failure.launch_id",
            &self.launch_id,
        )?;
        require_text(
            "post_completion_rollback_launch_failure.expected_session_id",
            &self.expected_session_id,
        )?;
        if self.failure_evidence_bytes.is_empty()
            || self.failure_evidence_bytes.len()
                > MAX_POST_COMPLETION_ROLLBACK_LAUNCH_FAILURE_EVIDENCE_BYTES
        {
            return Err(contract_error(
                "post_completion_rollback_launch_failure.failure_evidence_bytes",
                format!(
                    "must contain 1..={MAX_POST_COMPLETION_ROLLBACK_LAUNCH_FAILURE_EVIDENCE_BYTES} bytes"
                ),
            ));
        }
        if Digest::sha256(&self.failure_evidence_bytes) != self.failure_evidence_digest {
            return Err(contract_error(
                "post_completion_rollback_launch_failure.failure_evidence_bytes",
                "digest does not match exact retained launcher evidence",
            ));
        }
        require_time(
            "post_completion_rollback_launch_failure.failed_at_unix_ms",
            self.failed_at_unix_ms,
        )
    }
}

/// One typed observation of a touched target immediately before rollback.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PostCompletionRollbackEndpointObservation {
    /// Normalized workspace-relative target.
    pub path: PathBuf,
    /// Endpoint produced by the completed application (`None` means absent).
    pub expected_application_hash: Option<Digest>,
    /// Endpoint observed immediately before rollback (`None` means absent).
    pub observed_hash: Option<Digest>,
}

/// Canonical proof that all touched targets still matched the completed
/// application at the instant rollback began.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PostCompletionRollbackPreconditionEvidence {
    /// Strictly path-sorted exact target set.
    pub endpoints: Vec<PostCompletionRollbackEndpointObservation>,
    /// Domain-separated digest of the canonical target observations.
    pub endpoints_digest: Digest,
    /// Capture time, exactly equal to rollback effect start.
    pub captured_at_unix_ms: u64,
}

impl PostCompletionRollbackPreconditionEvidence {
    /// Constructs and validates an exact pre-rollback endpoint observation.
    ///
    /// # Errors
    ///
    /// Returns [`ContractError`] when the endpoint set is empty,
    /// noncanonical, mismatched, cannot be encoded, or has a zero timestamp.
    pub fn new(
        endpoints: Vec<PostCompletionRollbackEndpointObservation>,
        captured_at_unix_ms: u64,
    ) -> Result<Self, ContractError> {
        let endpoints_digest = precondition_digest(&endpoints)?;
        let evidence = Self {
            endpoints,
            endpoints_digest,
            captured_at_unix_ms,
        };
        evidence.validate()?;
        Ok(evidence)
    }

    fn validate(&self) -> Result<(), ContractError> {
        if self.endpoints.is_empty() {
            return Err(contract_error(
                "post_completion_rollback_precondition.endpoints",
                "must contain every application target",
            ));
        }
        let strictly_sorted = self
            .endpoints
            .windows(2)
            .all(|pair| pair[0].path < pair[1].path);
        if !strictly_sorted
            || self.endpoints.iter().any(|endpoint| {
                endpoint.path.as_os_str().is_empty()
                    || endpoint.expected_application_hash != endpoint.observed_hash
            })
        {
            return Err(contract_error(
                "post_completion_rollback_precondition.endpoints",
                "must be strictly path-sorted, unique, and observed exactly at application endpoints",
            ));
        }
        if precondition_digest(&self.endpoints)? != self.endpoints_digest {
            return Err(contract_error(
                "post_completion_rollback_precondition.endpoints_digest",
                "does not authenticate the canonical endpoint observations",
            ));
        }
        require_time(
            "post_completion_rollback_precondition.captured_at_unix_ms",
            self.captured_at_unix_ms,
        )
    }
}

/// Closed exact outcome of a post-completion rollback effect.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", deny_unknown_fields)]
pub enum PostCompletionRollbackOutcome {
    /// Every application endpoint was restored without conflict.
    Succeeded {
        /// Exact immediate pre-effect touched-endpoint observation.
        precondition: PostCompletionRollbackPreconditionEvidence,
        /// Exact successful rollback receipt and validation authority.
        rollback_evidence: RollbackEvidence,
    },
    /// At least one touched live endpoint changed externally.
    LiveConflict {
        /// Exact touched-target conflict receipt.
        conflict_receipt: LiveConflictReceipt,
        /// Direct executor or distinct recovery-validator authority.
        validation: RollbackValidationEvidence,
    },
    /// Reconciliation could not prove whether the rollback took effect.
    Unknown {
        /// Exact bounded evidence explaining why state is unprovable.
        evidence: PostCompletionRollbackUnknownEvidence,
        /// Direct executor or distinct recovery-validator authority.
        validation: RollbackValidationEvidence,
    },
}

impl PostCompletionRollbackOutcome {
    /// Returns the closed outcome class.
    #[must_use]
    pub const fn kind(&self) -> PostCompletionRollbackOutcomeKind {
        match self {
            Self::Succeeded { .. } => PostCompletionRollbackOutcomeKind::Succeeded,
            Self::LiveConflict { .. } => PostCompletionRollbackOutcomeKind::LiveConflict,
            Self::Unknown { .. } => PostCompletionRollbackOutcomeKind::Unknown,
        }
    }

    fn receipt_id(&self) -> &str {
        match self {
            Self::Succeeded {
                rollback_evidence, ..
            } => &rollback_evidence.receipt.receipt_id,
            Self::LiveConflict {
                conflict_receipt, ..
            } => &conflict_receipt.receipt_id,
            Self::Unknown { evidence, .. } => &evidence.evidence_id,
        }
    }

    fn validation(&self) -> &RollbackValidationEvidence {
        match self {
            Self::Succeeded {
                rollback_evidence, ..
            } => &rollback_evidence.validation,
            Self::LiveConflict { validation, .. } | Self::Unknown { validation, .. } => validation,
        }
    }

    fn validate(&self) -> Result<(), ContractError> {
        match self {
            Self::Succeeded {
                precondition,
                rollback_evidence,
            } => {
                precondition.validate()?;
                rollback_evidence.validate()
            }
            Self::LiveConflict {
                conflict_receipt,
                validation,
            } => {
                conflict_receipt.validate()?;
                validation.validate()
            }
            Self::Unknown {
                evidence,
                validation,
            } => {
                evidence.validate()?;
                validation.validate()
            }
        }
    }
}

/// Closed operation outcome class. This is not a `SprintState`.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum PostCompletionRollbackOutcomeKind {
    /// Exact rollback success.
    Succeeded,
    /// Exact touched-target conflict.
    LiveConflict,
    /// Effect result remains unprovable.
    Unknown,
    /// Executor launch provably failed before any child/effect could exist.
    NoEffect,
}

impl PostCompletionRollbackOutcomeKind {
    const fn storage_name(self) -> &'static str {
        match self {
            Self::Succeeded => "Succeeded",
            Self::LiveConflict => "LiveConflict",
            Self::Unknown => "Unknown",
            Self::NoEffect => "NoEffect",
        }
    }
}

/// Exact append-only observation for the authorized rollback effect.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PostCompletionRollbackObservation {
    /// Wire-contract version.
    pub contract_version: u32,
    /// Stable observation identity.
    pub observation_id: String,
    /// Owning operation.
    pub operation_id: String,
    /// Immutable completed sprint.
    pub sprint_id: String,
    /// Exact pre-authorized rollback effect identity.
    pub rollback_effect_id: String,
    /// Exact pre-authorized request digest.
    pub request_digest: Digest,
    /// Fresh executor launch.
    pub executor_launch_id: String,
    /// Fresh initialized executor session.
    pub executor_session_id: String,
    /// Exact known result or truthful unknown evidence.
    pub outcome: PostCompletionRollbackOutcome,
    /// Time after executor initialization when the authorized effect began.
    pub effect_started_at_unix_ms: u64,
    /// Observation/reconciliation time.
    pub observed_at_unix_ms: u64,
}

impl PostCompletionRollbackObservation {
    /// Validates the self-contained observation envelope.
    ///
    /// # Errors
    ///
    /// Returns [`ContractError`] when an identity, outcome, request binding,
    /// or timestamp is invalid or noncanonical.
    pub fn validate(&self) -> Result<(), ContractError> {
        require_version(
            self.contract_version,
            "post_completion_rollback_observation.contract_version",
        )?;
        require_text(
            "post_completion_rollback_observation.observation_id",
            &self.observation_id,
        )?;
        require_text(
            "post_completion_rollback_observation.operation_id",
            &self.operation_id,
        )?;
        require_text(
            "post_completion_rollback_observation.sprint_id",
            &self.sprint_id,
        )?;
        require_text(
            "post_completion_rollback_observation.rollback_effect_id",
            &self.rollback_effect_id,
        )?;
        require_text(
            "post_completion_rollback_observation.executor_launch_id",
            &self.executor_launch_id,
        )?;
        require_text(
            "post_completion_rollback_observation.executor_session_id",
            &self.executor_session_id,
        )?;
        self.outcome.validate()?;
        require_time(
            "post_completion_rollback_observation.effect_started_at_unix_ms",
            self.effect_started_at_unix_ms,
        )?;
        if self.effect_started_at_unix_ms > self.observed_at_unix_ms {
            return Err(contract_error(
                "post_completion_rollback_observation.effect_started_at_unix_ms",
                "must not follow the final observation",
            ));
        }
        require_time(
            "post_completion_rollback_observation.observed_at_unix_ms",
            self.observed_at_unix_ms,
        )
    }
}

/// Operation-local cleanup authorization committed before cleanup execution.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PostCompletionRollbackCleanupIntent {
    /// Wire-contract version.
    pub contract_version: u32,
    /// Owning rollback operation.
    pub operation_id: String,
    /// Stable cleanup effect identity.
    pub cleanup_effect_id: String,
    /// Exact cleanup request.
    pub request: WorkerCleanupRequest,
    /// SHA-256 of the canonical cleanup request.
    pub request_digest: Digest,
    /// Durable time after this launch's final operation activity.
    pub created_at_unix_ms: u64,
}

impl PostCompletionRollbackCleanupIntent {
    /// Constructs a cleanup intent with its canonical request digest.
    ///
    /// # Errors
    ///
    /// Returns [`ContractError`] when the request cannot be encoded or the
    /// resulting cleanup intent is invalid.
    pub fn new(
        operation_id: String,
        cleanup_effect_id: String,
        request: WorkerCleanupRequest,
        created_at_unix_ms: u64,
    ) -> Result<Self, ContractError> {
        let request_digest = Digest::sha256(&canonical("worker cleanup request", &request)?);
        let intent = Self {
            contract_version: CONTRACT_VERSION,
            operation_id,
            cleanup_effect_id,
            request,
            request_digest,
            created_at_unix_ms,
        };
        intent.validate()?;
        Ok(intent)
    }

    /// Validates the canonical pre-execution cleanup intent.
    ///
    /// # Errors
    ///
    /// Returns [`ContractError`] when an identity, request, digest binding, or
    /// timestamp is invalid.
    pub fn validate(&self) -> Result<(), ContractError> {
        require_version(
            self.contract_version,
            "post_completion_rollback_cleanup_intent.contract_version",
        )?;
        require_text(
            "post_completion_rollback_cleanup_intent.operation_id",
            &self.operation_id,
        )?;
        require_text(
            "post_completion_rollback_cleanup_intent.cleanup_effect_id",
            &self.cleanup_effect_id,
        )?;
        self.request.validate()?;
        if Digest::sha256(&canonical("worker cleanup request", &self.request)?)
            != self.request_digest
        {
            return Err(contract_error(
                "post_completion_rollback_cleanup_intent.request_digest",
                "does not authenticate the canonical cleanup request",
            ));
        }
        require_time(
            "post_completion_rollback_cleanup_intent.created_at_unix_ms",
            self.created_at_unix_ms,
        )
    }
}

/// Exact zero-descendant observation bound to a prior operation-local cleanup
/// intent.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PostCompletionRollbackCleanupEvidence {
    /// Wire-contract version.
    pub contract_version: u32,
    /// Owning rollback operation.
    pub operation_id: String,
    /// Exact prior cleanup effect intent.
    pub cleanup_effect_id: String,
    /// Exact prior cleanup request digest.
    pub request_digest: Digest,
    /// Exact authoritative operating-system evidence.
    pub evidence: WorkerCleanupEvidence,
}

impl PostCompletionRollbackCleanupEvidence {
    /// Validates the self-contained cleanup observation.
    ///
    /// # Errors
    ///
    /// Returns [`ContractError`] when an identity, cleanup receipt, operating
    /// system proof, or effect binding is invalid.
    pub fn validate(&self) -> Result<(), ContractError> {
        require_version(
            self.contract_version,
            "post_completion_rollback_cleanup_evidence.contract_version",
        )?;
        require_text(
            "post_completion_rollback_cleanup_evidence.operation_id",
            &self.operation_id,
        )?;
        require_text(
            "post_completion_rollback_cleanup_evidence.cleanup_effect_id",
            &self.cleanup_effect_id,
        )?;
        self.evidence.validate()?;
        if self.evidence.receipt.effect_id != self.cleanup_effect_id {
            return Err(contract_error(
                "post_completion_rollback_cleanup_evidence.cleanup_effect_id",
                "must match the exact successful cleanup receipt",
            ));
        }
        Ok(())
    }
}

/// Fully bound cleanup intent and observation for one fresh launch.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PostCompletionRollbackCleanup {
    /// Pre-execution durable intent.
    pub intent: PostCompletionRollbackCleanupIntent,
    /// Exact zero-descendant observation.
    pub evidence: PostCompletionRollbackCleanupEvidence,
}

/// Immutable terminal record for one rollback operation. It never mutates the
/// completed sprint or its historical receipt chain.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PostCompletionRollbackTerminal {
    /// Wire-contract version.
    pub contract_version: u32,
    /// Stable operation-terminal identity.
    pub terminal_id: String,
    /// Owning operation.
    pub operation_id: String,
    /// Immutable completed sprint.
    pub sprint_id: String,
    /// Exact application referenced by completion.
    pub application_receipt_id: String,
    /// Exact effect observation or launch-failure outcome.
    pub outcome_id: String,
    /// Exact operation outcome class.
    pub kind: PostCompletionRollbackOutcomeKind,
    /// Canonically sorted exact cleanup set, one per fresh launch.
    pub cleanup_receipt_ids: Vec<String>,
    /// Time after every cleanup proof was observed.
    pub terminal_at_unix_ms: u64,
}

impl PostCompletionRollbackTerminal {
    /// Validates the self-contained terminal envelope and canonical cleanup set.
    ///
    /// # Errors
    ///
    /// Returns [`ContractError`] when an identity, timestamp, or exact cleanup
    /// receipt set is invalid or noncanonical.
    pub fn validate(&self) -> Result<(), ContractError> {
        require_version(
            self.contract_version,
            "post_completion_rollback_terminal.contract_version",
        )?;
        require_text(
            "post_completion_rollback_terminal.terminal_id",
            &self.terminal_id,
        )?;
        require_text(
            "post_completion_rollback_terminal.operation_id",
            &self.operation_id,
        )?;
        require_text(
            "post_completion_rollback_terminal.sprint_id",
            &self.sprint_id,
        )?;
        require_text(
            "post_completion_rollback_terminal.application_receipt_id",
            &self.application_receipt_id,
        )?;
        require_text(
            "post_completion_rollback_terminal.outcome_id",
            &self.outcome_id,
        )?;
        if self.cleanup_receipt_ids.is_empty() {
            return Err(contract_error(
                "post_completion_rollback_terminal.cleanup_receipt_ids",
                "must contain one exact cleanup receipt per fresh launch",
            ));
        }
        let canonical = self
            .cleanup_receipt_ids
            .windows(2)
            .all(|pair| pair[0] < pair[1]);
        if !canonical
            || self
                .cleanup_receipt_ids
                .iter()
                .any(|id| id.trim().is_empty())
        {
            return Err(contract_error(
                "post_completion_rollback_terminal.cleanup_receipt_ids",
                "must be strictly sorted, unique, and nonblank",
            ));
        }
        require_time(
            "post_completion_rollback_terminal.terminal_at_unix_ms",
            self.terminal_at_unix_ms,
        )
    }
}

/// One fully verified fresh applier lifecycle.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PostCompletionRollbackApplier {
    /// Executor or distinct recovery validator.
    pub role: PostCompletionRollbackApplierRole,
    /// Pre-spawn durable launch.
    pub launch: RunnerLaunchIntent,
    /// Initialized session, absent when launch/initialization failed.
    pub session: Option<RunnerSessionPolicyRecord>,
}

/// Fully validated append-only rollback operation readback.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PersistedPostCompletionRollback {
    /// Immutable pre-launch authorization.
    pub intent: PostCompletionRollbackIntent,
    /// Exact v12 artifact authority or an explicit migration-only legacy gap.
    pub application_artifact_authority: PostCompletionRollbackApplicationArtifactAuthorityState,
    /// Fresh applier attempts ordered executor then recovery validator.
    pub appliers: Vec<PostCompletionRollbackApplier>,
    /// Exact effect outcome, absent while execution or reconciliation is live.
    pub observation: Option<PostCompletionRollbackObservation>,
    /// Exact uninitialized-launch outcome, mutually exclusive with `observation`.
    pub launch_failure: Option<PostCompletionRollbackLaunchFailure>,
    /// Pre-execution cleanup intents ordered by launch role.
    pub cleanup_intents: Vec<PostCompletionRollbackCleanupIntent>,
    /// Exact cleanup evidence ordered by launch role.
    pub cleanups: Vec<PostCompletionRollbackCleanup>,
    /// Immutable operation terminal, absent until outcome and exact cleanup set exist.
    pub terminal: Option<PostCompletionRollbackTerminal>,
}

impl PersistedPostCompletionRollback {
    /// Classifies operation progress without changing the sprint state.
    #[must_use]
    pub const fn status(&self) -> PostCompletionRollbackStatus {
        if let Some(terminal) = &self.terminal {
            return PostCompletionRollbackStatus::Terminal(terminal.kind);
        }
        if let Some(observation) = &self.observation {
            return PostCompletionRollbackStatus::OutcomeAwaitingCleanup(
                observation.outcome.kind(),
            );
        }
        if let Some(failure) = &self.launch_failure {
            return PostCompletionRollbackStatus::OutcomeAwaitingCleanup(failure.outcome_kind());
        }
        if self.appliers.is_empty() {
            PostCompletionRollbackStatus::IntentRecorded
        } else {
            PostCompletionRollbackStatus::ExecutingOrReconciling
        }
    }
}

/// Closed operation progress classification. No variant is a sprint state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PostCompletionRollbackStatus {
    /// Durable intent exists; no applier launch has been authorized yet.
    IntentRecorded,
    /// At least one fresh applier is live or awaiting reconciliation.
    ExecutingOrReconciling,
    /// Outcome exists but the exact launch cleanup set is incomplete.
    OutcomeAwaitingCleanup(PostCompletionRollbackOutcomeKind),
    /// Outcome and exact fresh-launch cleanup set are immutable.
    Terminal(PostCompletionRollbackOutcomeKind),
}

fn contract_error(field: &'static str, message: impl Into<String>) -> ContractError {
    ContractError::new(field, message)
}

fn require_version(version: u32, field: &'static str) -> Result<(), ContractError> {
    if version == CONTRACT_VERSION {
        Ok(())
    } else {
        Err(contract_error(
            field,
            format!("expected version {CONTRACT_VERSION}, got {version}"),
        ))
    }
}

fn require_text(field: &'static str, value: &str) -> Result<(), ContractError> {
    if value.trim().is_empty() {
        Err(contract_error(field, "must not be blank"))
    } else {
        Ok(())
    }
}

fn require_time(field: &'static str, value: u64) -> Result<(), ContractError> {
    if value == 0 {
        Err(contract_error(field, "must be greater than zero"))
    } else {
        Ok(())
    }
}

fn canonical<T: Serialize + ?Sized>(
    entity: &'static str,
    value: &T,
) -> Result<Vec<u8>, ContractError> {
    serde_json::to_vec(value)
        .map_err(|error| contract_error(entity, format!("cannot encode canonically: {error}")))
}

fn precondition_digest(
    endpoints: &[PostCompletionRollbackEndpointObservation],
) -> Result<Digest, ContractError> {
    let bytes = canonical("post-completion rollback endpoint observations", endpoints)?;
    let mut preimage = b"grok-build.post-completion-rollback-precondition.v1\0".to_vec();
    preimage.extend_from_slice(&bytes);
    Ok(Digest::sha256(&preimage))
}

fn application_endpoint_observations(
    operations: &[FileOperation],
) -> Vec<PostCompletionRollbackEndpointObservation> {
    let mut endpoints = operations
        .iter()
        .map(|operation| match operation {
            FileOperation::Create { path, result_hash }
            | FileOperation::Modify {
                path, result_hash, ..
            } => PostCompletionRollbackEndpointObservation {
                path: path.clone(),
                expected_application_hash: Some(result_hash.clone()),
                observed_hash: Some(result_hash.clone()),
            },
            FileOperation::Delete { path, .. } => PostCompletionRollbackEndpointObservation {
                path: path.clone(),
                expected_application_hash: None,
                observed_hash: None,
            },
        })
        .collect::<Vec<_>>();
    endpoints.sort_by(|left, right| left.path.cmp(&right.path));
    endpoints
}

fn absent_application_endpoint_digest() -> Digest {
    Digest::sha256(b"grok-build.post-completion-rollback.endpoint.absent.v1\0")
}

/// Returns the canonical post-application endpoint digest a trusted conflict
/// observer must bind for one exact [`FileOperation`]. Deletes map to the
/// domain-separated absent-endpoint sentinel; creates and modifications map to
/// their result-content digest.
#[must_use]
pub fn post_completion_rollback_expected_endpoint_digest(operation: &FileOperation) -> Digest {
    match operation {
        FileOperation::Create { result_hash, .. } | FileOperation::Modify { result_hash, .. } => {
            result_hash.clone()
        }
        FileOperation::Delete { .. } => absent_application_endpoint_digest(),
    }
}

struct AppliedCompletionRollbackSource {
    receipt: CompletionReceipt,
    application_evidence: ApplicationEvidence,
    rollback_reference: RollbackReferenceEvidence,
}

fn load_applied_completion_rollback_source(
    connection: &Connection,
    sprint_id: &str,
) -> Result<Option<AppliedCompletionRollbackSource>, LedgerError> {
    if completion_live_state_capture_authority_schema_is_installed(connection)? {
        let Some(completion) = load_completion_evidence_from(connection, sprint_id)? else {
            return Ok(None);
        };
        let PersistedCompletionApplication::Applied {
            application_evidence,
            rollback_reference,
        } = completion.application
        else {
            return Err(reference_mismatch(
                "post-completion rollback intent",
                "verified-no-op completion has no application to roll back",
            ));
        };
        return Ok(Some(AppliedCompletionRollbackSource {
            receipt: completion.receipt,
            application_evidence,
            rollback_reference,
        }));
    }

    #[cfg(not(test))]
    {
        Err(LedgerError::Corrupt {
            entity: "post-completion rollback intent",
            detail: "current completion live-state authority schema is absent".into(),
        })
    }
    #[cfg(test)]
    {
        load_pre_v24_applied_completion_rollback_source_for_test(connection, sprint_id)
    }
}

#[cfg(test)]
fn load_pre_v24_applied_completion_rollback_source_for_test(
    connection: &Connection,
    sprint_id: &str,
) -> Result<Option<AppliedCompletionRollbackSource>, LedgerError> {
    let stored = connection
        .query_row(
            "SELECT proof_state, completion_receipt_id, completion_event_id,
                    contract_version, terminal_at_unix_ms
             FROM sprint_completion_proof_states WHERE sprint_id = ?1",
            [sprint_id],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, i64>(4)?,
                ))
            },
        )
        .optional()?;
    let Some(stored) = stored else {
        return Ok(None);
    };
    require_contract_version("pre-v24 completion rollback source", stored.3)?;
    if stored.0 != "ProvenV9" {
        return Err(LedgerError::Corrupt {
            entity: "pre-v24 completion rollback source",
            detail: "historical operation requires exact ProvenV9 completion authority".into(),
        });
    }
    let receipt = load_completion_receipt_from(connection, &stored.1)?;
    let report = load_final_report_from(connection, &receipt.final_report_id)?;
    let event = load_event_by_id(connection, &stored.2)?;
    validate_completion_event_shape(&event, &receipt).map_err(|error| LedgerError::Corrupt {
        entity: "pre-v24 completion rollback source",
        detail: error.to_string(),
    })?;
    let terminal_at = unsigned_integer(
        "pre_v24_completion_rollback_source.terminal_at_unix_ms",
        stored.4,
    )?;
    if receipt.sprint_id != sprint_id
        || receipt.completed_at_unix_ms != terminal_at
        || event.sprint_id != sprint_id
        || event.occurred_at_unix_ms != terminal_at
    {
        return Err(LedgerError::Corrupt {
            entity: "pre-v24 completion rollback source",
            detail: "historical receipt, proof, event, sprint, or terminal time differs".into(),
        });
    }
    validate_completion_evidence(connection, &report, &receipt)?;
    let CompletionApplication::Applied {
        application_receipt_id,
        rollback_reference_id,
    } = &receipt.application
    else {
        return Err(reference_mismatch(
            "post-completion rollback intent",
            "verified-no-op completion has no application to roll back",
        ));
    };
    Ok(Some(AppliedCompletionRollbackSource {
        application_evidence: load_application_evidence_from(connection, application_receipt_id)?,
        rollback_reference: load_rollback_reference_evidence_from(
            connection,
            rollback_reference_id,
        )?,
        receipt,
    }))
}

impl EventLedger {
    /// Builds the only canonical rollback intent for one proven applied
    /// completion from durable ledger bytes.
    ///
    /// # Errors
    ///
    /// Returns a ledger error when the sprint is not proven `Completed`, used
    /// the verified-no-op branch, or its completion evidence is corrupt.
    pub fn build_post_completion_rollback_intent(
        &self,
        sprint_id: &str,
        operation_id: String,
        idempotency_key: String,
        rollback_effect_id: String,
        created_at_unix_ms: u64,
    ) -> Result<PostCompletionRollbackIntent, LedgerError> {
        let completion = load_applied_completion_rollback_source(&self.connection, sprint_id)?
            .ok_or_else(|| {
                reference_mismatch(
                    "post-completion rollback intent",
                    "sprint does not have proven completion evidence",
                )
            })?;
        let application_evidence = &completion.application_evidence;
        let rollback_reference = &completion.rollback_reference;
        let request = RollbackRequest {
            contract_version: CONTRACT_VERSION,
            sprint_id: sprint_id.to_owned(),
            application_receipt_id: application_evidence.receipt.receipt_id.clone(),
            application_transaction_id: application_evidence.receipt.transaction_id.clone(),
            rollback_reference_id: rollback_reference.reference.reference_id.clone(),
        };
        let request_bytes = encode("post-completion rollback request", &request)?;
        let intent = PostCompletionRollbackIntent {
            contract_version: CONTRACT_VERSION,
            operation_id,
            idempotency_key,
            rollback_effect_id,
            sprint_id: sprint_id.to_owned(),
            completion_receipt_id: completion.receipt.receipt_id.clone(),
            completion_receipt_digest: Digest::sha256(&encode(
                "completion receipt",
                &completion.receipt,
            )?),
            application_evidence_digest: Digest::sha256(&encode(
                "application evidence",
                application_evidence,
            )?),
            rollback_reference_evidence_digest: Digest::sha256(&encode(
                "rollback reference evidence",
                rollback_reference,
            )?),
            request,
            request_digest: Digest::sha256(&request_bytes),
            policy_hash: application_evidence.receipt.policy_hash.clone(),
            grant_hash: application_evidence.receipt.grant_hash.clone(),
            policy_version: application_evidence.receipt.policy_version,
            created_at_unix_ms,
        };
        intent.validate()?;
        validate_operation_intent_chain(&self.connection, &intent, &request_bytes)?;
        if application_artifact_authority_schema_is_installed(&self.connection)? {
            derive_post_completion_application_artifact_authority(
                &self.connection,
                sprint_id,
                &intent.operation_id,
                &intent.request.application_receipt_id,
            )?;
        }
        Ok(intent)
    }

    /// Commits a one-click rollback authorization before any fresh applier may
    /// launch. Exact replay is idempotent.
    ///
    /// # Errors
    ///
    /// Returns a ledger error unless the intent names the exact applied branch
    /// of a proven completion and authenticates its full completion,
    /// application, rollback-reference, policy, and request preimages.
    pub fn record_post_completion_rollback_intent(
        &mut self,
        intent: &PostCompletionRollbackIntent,
    ) -> Result<PersistedPostCompletionRollback, LedgerError> {
        self.require_writable()?;
        intent.validate()?;
        if let Some(existing) =
            load_post_completion_rollback_optional(&self.connection, &intent.operation_id)?
        {
            return exact_replay_or_conflict(existing, intent, "rollback operation intent");
        }
        let same_key = self
            .connection
            .query_row(
                "SELECT operation_id FROM post_completion_rollback_operations
                 WHERE application_receipt_id = ?1 AND idempotency_key = ?2",
                params![
                    intent.request.application_receipt_id,
                    intent.idempotency_key
                ],
                |row| row.get::<_, String>(0),
            )
            .optional()?;
        if let Some(operation_id) = same_key {
            let existing = load_post_completion_rollback_from(&self.connection, &operation_id)?;
            return exact_replay_or_conflict(existing, intent, "rollback idempotency key");
        }

        let request_bytes = encode("post-completion rollback request", &intent.request)?;
        let intent_bytes = encode("post-completion rollback intent", intent)?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        validate_operation_intent(&transaction, intent, &request_bytes)?;
        ensure_global_effect_id_available(&transaction, &intent.rollback_effect_id)?;
        if application_artifact_authority_schema_is_installed(&transaction)? {
            let artifact_authority = derive_post_completion_application_artifact_authority(
                &transaction,
                &intent.sprint_id,
                &intent.operation_id,
                &intent.request.application_receipt_id,
            )?;
            insert_post_completion_application_artifact_authority(
                &transaction,
                &artifact_authority,
            )?;
        }
        transaction.execute(
            "INSERT INTO post_completion_rollback_operations (
                operation_id, idempotency_key, rollback_effect_id, sprint_id,
                completion_receipt_id, application_receipt_id,
                rollback_reference_id, request_digest,
                completion_receipt_digest, application_evidence_digest,
                rollback_reference_evidence_digest, policy_hash, grant_hash,
                policy_version, contract_version, created_at_unix_ms,
                request_json, intent_json
             ) VALUES (
                ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12,
                ?13, ?14, ?15, ?16, ?17, ?18
             )",
            params![
                intent.operation_id,
                intent.idempotency_key,
                intent.rollback_effect_id,
                intent.sprint_id,
                intent.completion_receipt_id,
                intent.request.application_receipt_id,
                intent.request.rollback_reference_id,
                intent.request_digest.as_str(),
                intent.completion_receipt_digest.as_str(),
                intent.application_evidence_digest.as_str(),
                intent.rollback_reference_evidence_digest.as_str(),
                intent.policy_hash.as_str(),
                intent.grant_hash.as_str(),
                i64::from(intent.policy_version),
                i64::from(intent.contract_version),
                sqlite_integer(
                    "post_completion_rollback_intent.created_at_unix_ms",
                    intent.created_at_unix_ms,
                )?,
                request_bytes,
                intent_bytes,
            ],
        )?;
        transaction.commit()?;
        let persisted = load_post_completion_rollback_from(&self.connection, &intent.operation_id)?;
        secure_database_files(&self.database_path)?;
        Ok(persisted)
    }

    /// Records one fresh executor or recovery-validator launch before spawn.
    /// Exact replay is idempotent.
    ///
    /// # Errors
    ///
    /// Returns a ledger error for a missing/terminal operation, a non-applier
    /// role, a non-fresh identity, an early timestamp, or any policy, grant,
    /// private-state, runtime, or protocol mismatch.
    pub fn record_post_completion_rollback_applier_launch(
        &mut self,
        operation_id: &str,
        role: PostCompletionRollbackApplierRole,
        launch: &RunnerLaunchIntent,
        compiled_policy: &CompiledExecutionPolicy,
    ) -> Result<PersistedPostCompletionRollback, LedgerError> {
        self.require_writable()?;
        launch.validate()?;
        if let Some(existing) =
            load_post_completion_launch_by_role_optional(&self.connection, operation_id, role)?
        {
            let (_, stored_policy) = load_post_completion_launch_from(
                &self.connection,
                operation_id,
                &existing.launch_id,
            )?;
            if existing == *launch && stored_policy == *compiled_policy.contract() {
                return load_post_completion_rollback_from(&self.connection, operation_id);
            }
            return Err(reference_mismatch(
                "post-completion rollback launch",
                "the operation role already has a different immutable launch",
            ));
        }
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let intent = load_post_completion_intent_from(&transaction, operation_id)?;
        ensure_operation_accepts_work(&transaction, operation_id)?;
        if application_artifact_authority_schema_is_installed(&transaction)? {
            require_post_completion_application_artifact_authority(
                &transaction,
                &intent.sprint_id,
                operation_id,
                &intent.request.application_receipt_id,
            )?;
        }
        validate_post_completion_launch(
            &transaction,
            &intent,
            role,
            launch,
            compiled_policy.contract(),
        )?;
        ensure_global_launch_ids_available(&transaction, launch)?;
        insert_post_completion_launch(
            &transaction,
            operation_id,
            role,
            launch,
            compiled_policy.contract(),
        )?;
        transaction.commit()?;
        let persisted = load_post_completion_rollback_from(&self.connection, operation_id)?;
        secure_database_files(&self.database_path)?;
        Ok(persisted)
    }

    /// Registers the initialized session for one pre-spawn rollback applier
    /// launch. Exact replay is idempotent.
    ///
    /// # Errors
    ///
    /// Returns a ledger error unless the record exactly authenticates the
    /// stored launch and compiler-produced policy with a globally fresh nonce.
    pub fn register_post_completion_rollback_applier_session(
        &mut self,
        operation_id: &str,
        record: &RunnerSessionPolicyRecord,
        compiled_policy: &CompiledExecutionPolicy,
    ) -> Result<PersistedPostCompletionRollback, LedgerError> {
        self.require_writable()?;
        record.validate()?;
        if let Some((stored, stored_policy, _)) = load_post_completion_session_optional(
            &self.connection,
            operation_id,
            &record.session_id,
        )? {
            if stored == *record && stored_policy == *compiled_policy.contract() {
                return load_post_completion_rollback_from(&self.connection, operation_id);
            }
            return Err(reference_mismatch(
                "post-completion rollback session",
                "session identity already authenticates different immutable bytes",
            ));
        }
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        ensure_operation_accepts_work(&transaction, operation_id)?;
        let intent = load_post_completion_intent_from(&transaction, operation_id)?;
        if application_artifact_authority_schema_is_installed(&transaction)? {
            require_post_completion_application_artifact_authority(
                &transaction,
                &intent.sprint_id,
                operation_id,
                &intent.request.application_receipt_id,
            )?;
        }
        let (launch, launch_policy, role) = load_post_completion_launch_with_role_from(
            &transaction,
            operation_id,
            &record.launch_id,
        )?;
        validate_post_completion_session(
            operation_id,
            &launch,
            &launch_policy,
            role,
            record,
            compiled_policy.contract(),
        )?;
        ensure_global_session_ids_available(&transaction, record)?;
        insert_post_completion_session(
            &transaction,
            operation_id,
            role,
            record,
            compiled_policy.contract(),
        )?;
        transaction.commit()?;
        let persisted = load_post_completion_rollback_from(&self.connection, operation_id)?;
        secure_database_files(&self.database_path)?;
        Ok(persisted)
    }

    /// Records the exact success, live-conflict, or truthful-unknown outcome.
    /// Exact replay is idempotent. This does not terminalize the operation and
    /// never changes the sprint state.
    ///
    /// # Errors
    ///
    /// Returns a ledger error unless the observation matches the immutable
    /// intent, executor, request, application, rollback reference, and direct
    /// or distinct-recovery validation authority.
    pub fn record_post_completion_rollback_observation(
        &mut self,
        observation: &PostCompletionRollbackObservation,
    ) -> Result<PersistedPostCompletionRollback, LedgerError> {
        self.require_writable()?;
        observation.validate()?;
        if let Some(existing) =
            load_post_completion_observation_optional(&self.connection, &observation.operation_id)?
        {
            if existing == *observation {
                return load_post_completion_rollback_from(
                    &self.connection,
                    &observation.operation_id,
                );
            }
            return Err(reference_mismatch(
                "post-completion rollback observation",
                "operation already has a different immutable outcome",
            ));
        }
        let observation_bytes = encode("post-completion rollback observation", observation)?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        ensure_operation_accepts_work(&transaction, &observation.operation_id)?;
        let intent = load_post_completion_intent_from(&transaction, &observation.operation_id)?;
        if application_artifact_authority_schema_is_installed(&transaction)? {
            require_post_completion_application_artifact_authority(
                &transaction,
                &intent.sprint_id,
                &intent.operation_id,
                &intent.request.application_receipt_id,
            )?;
        }
        validate_post_completion_observation(&transaction, observation)?;
        ensure_global_observation_id_available(&transaction, &observation.observation_id)?;
        ensure_global_receipt_id_available(&transaction, observation.outcome.receipt_id())?;
        insert_post_completion_receipt_id(
            &transaction,
            &observation.operation_id,
            &observation.sprint_id,
            observation.outcome.receipt_id(),
            match observation.outcome.kind() {
                PostCompletionRollbackOutcomeKind::Succeeded => "Rollback",
                PostCompletionRollbackOutcomeKind::LiveConflict => "LiveConflict",
                PostCompletionRollbackOutcomeKind::Unknown => "UnknownEvidence",
                PostCompletionRollbackOutcomeKind::NoEffect => {
                    return Err(reference_mismatch(
                        "post-completion rollback observation",
                        "effect observations cannot classify a no-effect launch failure",
                    ));
                }
            },
        )?;
        let validation = observation.outcome.validation();
        transaction.execute(
            "INSERT INTO post_completion_rollback_observations (
                observation_id, operation_id, sprint_id, rollback_effect_id,
                request_digest, executor_launch_id, executor_session_id,
                outcome_kind, outcome_receipt_id, validator_launch_id,
                validator_session_id, validation_mode, contract_version,
                effect_started_at_unix_ms, observed_at_unix_ms, observation_json
             ) VALUES (
                ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12,
                ?13, ?14, ?15, ?16
             )",
            params![
                observation.observation_id,
                observation.operation_id,
                observation.sprint_id,
                observation.rollback_effect_id,
                observation.request_digest.as_str(),
                observation.executor_launch_id,
                observation.executor_session_id,
                observation.outcome.kind().storage_name(),
                observation.outcome.receipt_id(),
                validation.runner_launch_id,
                validation.runner_session_id,
                validation_mode_name(validation.mode),
                i64::from(observation.contract_version),
                sqlite_integer(
                    "post_completion_rollback_observation.effect_started_at_unix_ms",
                    observation.effect_started_at_unix_ms,
                )?,
                sqlite_integer(
                    "post_completion_rollback_observation.observed_at_unix_ms",
                    observation.observed_at_unix_ms,
                )?,
                observation_bytes,
            ],
        )?;
        transaction.commit()?;
        let persisted =
            load_post_completion_rollback_from(&self.connection, &observation.operation_id)?;
        secure_database_files(&self.database_path)?;
        Ok(persisted)
    }

    /// Records a typed outcome for a committed fresh launch that never
    /// produced a registered session. Exact replay is idempotent.
    ///
    /// # Errors
    ///
    /// Returns a ledger error unless the failure names an exact uninitialized
    /// launch, retains authenticated bounded evidence, follows the launch, and
    /// truthfully classifies no-effect versus unknown.
    pub fn record_post_completion_rollback_launch_failure(
        &mut self,
        failure: &PostCompletionRollbackLaunchFailure,
    ) -> Result<PersistedPostCompletionRollback, LedgerError> {
        self.require_writable()?;
        failure.validate()?;
        if let Some(existing) =
            load_post_completion_launch_failure_optional(&self.connection, &failure.operation_id)?
        {
            if existing == *failure {
                return load_post_completion_rollback_from(&self.connection, &failure.operation_id);
            }
            return Err(reference_mismatch(
                "post-completion rollback launch failure",
                "operation already has a different immutable launch-failure outcome",
            ));
        }
        let failure_bytes = encode("post-completion rollback launch failure", failure)?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        ensure_operation_accepts_work(&transaction, &failure.operation_id)?;
        load_post_completion_intent_from(&transaction, &failure.operation_id)?;
        validate_post_completion_launch_failure(&transaction, failure)?;
        ensure_global_observation_id_available(&transaction, &failure.failure_id)?;
        transaction.execute(
            "INSERT INTO post_completion_rollback_launch_failures (
                failure_id, operation_id, sprint_id, launch_id,
                expected_session_id, launch_role, failure_kind,
                terminal_kind, failure_evidence_digest, contract_version,
                failed_at_unix_ms, failure_evidence_bytes, failure_json
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11,
                       ?12, ?13)",
            params![
                failure.failure_id,
                failure.operation_id,
                failure.sprint_id,
                failure.launch_id,
                failure.expected_session_id,
                failure.launch_role.storage_name(),
                failure.kind.storage_name(),
                failure.outcome_kind().storage_name(),
                failure.failure_evidence_digest.as_str(),
                i64::from(failure.contract_version),
                sqlite_integer(
                    "post_completion_rollback_launch_failure.failed_at_unix_ms",
                    failure.failed_at_unix_ms,
                )?,
                &failure.failure_evidence_bytes,
                failure_bytes,
            ],
        )?;
        transaction.commit()?;
        let persisted =
            load_post_completion_rollback_from(&self.connection, &failure.operation_id)?;
        secure_database_files(&self.database_path)?;
        Ok(persisted)
    }

    /// Records one operation-local cleanup intent after the launch's final
    /// outcome activity and before cleanup execution. Exact replay is
    /// idempotent.
    ///
    /// # Errors
    ///
    /// Returns a ledger error unless the request exactly names one fresh
    /// launch, uses the authoritative applier backend and policy/grant, and is
    /// ordered after the immutable operation outcome.
    pub fn record_post_completion_rollback_cleanup_intent(
        &mut self,
        cleanup: &PostCompletionRollbackCleanupIntent,
    ) -> Result<PersistedPostCompletionRollback, LedgerError> {
        self.require_writable()?;
        cleanup.validate()?;
        if let Some(existing) = load_post_completion_cleanup_intent_by_launch_optional(
            &self.connection,
            &cleanup.operation_id,
            &cleanup.request.launch_id,
        )? {
            if existing == *cleanup {
                return load_post_completion_rollback_from(&self.connection, &cleanup.operation_id);
            }
            return Err(reference_mismatch(
                "post-completion rollback cleanup intent",
                "fresh launch already has a different immutable cleanup intent",
            ));
        }
        let request_bytes = encode("worker cleanup request", &cleanup.request)?;
        let intent_bytes = encode("post-completion rollback cleanup intent", cleanup)?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        ensure_operation_not_terminal(&transaction, &cleanup.operation_id)?;
        load_post_completion_intent_from(&transaction, &cleanup.operation_id)?;
        validate_post_completion_cleanup_intent(&transaction, cleanup, &request_bytes)?;
        ensure_global_effect_id_available(&transaction, &cleanup.cleanup_effect_id)?;
        transaction.execute(
            "INSERT INTO post_completion_rollback_cleanup_intents (
                cleanup_effect_id, operation_id, sprint_id, launch_id,
                session_id, request_digest, contract_version,
                created_at_unix_ms, request_json, intent_json
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
            params![
                cleanup.cleanup_effect_id,
                cleanup.operation_id,
                cleanup.request.sprint_id,
                cleanup.request.launch_id,
                cleanup.request.session_id,
                cleanup.request_digest.as_str(),
                i64::from(cleanup.contract_version),
                sqlite_integer(
                    "post_completion_rollback_cleanup_intent.created_at_unix_ms",
                    cleanup.created_at_unix_ms,
                )?,
                request_bytes,
                intent_bytes,
            ],
        )?;
        transaction.commit()?;
        let persisted =
            load_post_completion_rollback_from(&self.connection, &cleanup.operation_id)?;
        secure_database_files(&self.database_path)?;
        Ok(persisted)
    }

    /// Records one exact zero-descendant proof for one fresh applier launch.
    /// Exact replay is idempotent.
    ///
    /// # Errors
    ///
    /// Returns a ledger error for a missing launch, mismatched request,
    /// unsupported cleanup backend, nonzero survivor count, reused identity,
    /// or any policy/grant/timestamp mismatch.
    pub fn record_post_completion_rollback_cleanup(
        &mut self,
        cleanup: &PostCompletionRollbackCleanupEvidence,
    ) -> Result<PersistedPostCompletionRollback, LedgerError> {
        self.require_writable()?;
        cleanup.validate()?;
        if let Some(existing) = load_post_completion_cleanup_by_launch_optional(
            &self.connection,
            &cleanup.operation_id,
            &cleanup.evidence.receipt.launch_id,
        )? {
            if existing == *cleanup {
                return load_post_completion_rollback_from(&self.connection, &cleanup.operation_id);
            }
            return Err(reference_mismatch(
                "post-completion rollback cleanup",
                "fresh launch already has different immutable cleanup evidence",
            ));
        }
        let cleanup_bytes = encode("post-completion rollback cleanup evidence", cleanup)?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        ensure_operation_not_terminal(&transaction, &cleanup.operation_id)?;
        load_post_completion_intent_from(&transaction, &cleanup.operation_id)?;
        validate_post_completion_cleanup(&transaction, cleanup)?;
        let receipt = &cleanup.evidence.receipt;
        ensure_global_receipt_id_available(&transaction, &receipt.receipt_id)?;
        ensure_global_observation_id_available(&transaction, &receipt.observation_id)?;
        insert_post_completion_receipt_id(
            &transaction,
            &cleanup.operation_id,
            &receipt.sprint_id,
            &receipt.receipt_id,
            "WorkerCleanup",
        )?;
        transaction.execute(
            "INSERT INTO post_completion_rollback_cleanups (
                cleanup_receipt_id, operation_id, sprint_id, launch_id,
                session_id, cleanup_effect_id, cleanup_observation_id,
                request_digest, policy_hash, grant_hash, policy_version,
                cleaned_at_unix_ms, contract_version, cleanup_json
             ) VALUES (
                ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12,
                ?13, ?14
             )",
            params![
                receipt.receipt_id,
                cleanup.operation_id,
                receipt.sprint_id,
                receipt.launch_id,
                receipt.session_id,
                receipt.effect_id,
                receipt.observation_id,
                cleanup.request_digest.as_str(),
                receipt.policy_hash.as_str(),
                receipt.grant_hash.as_str(),
                i64::from(receipt.policy_version),
                sqlite_integer(
                    "post_completion_rollback_cleanup.cleaned_at_unix_ms",
                    receipt.cleaned_at_unix_ms,
                )?,
                i64::from(cleanup.contract_version),
                cleanup_bytes,
            ],
        )?;
        transaction.commit()?;
        let persisted =
            load_post_completion_rollback_from(&self.connection, &cleanup.operation_id)?;
        secure_database_files(&self.database_path)?;
        Ok(persisted)
    }

    /// Terminalizes one operation only after its outcome and the exact
    /// zero-descendant cleanup set for every fresh launch are durable. Exact
    /// replay is idempotent.
    ///
    /// # Errors
    ///
    /// Returns a ledger error for an absent/mismatched outcome, incomplete or
    /// noncanonical cleanup set, early timestamp, or a second successful
    /// rollback for the same application.
    pub fn finalize_post_completion_rollback(
        &mut self,
        terminal: &PostCompletionRollbackTerminal,
    ) -> Result<PersistedPostCompletionRollback, LedgerError> {
        self.require_writable()?;
        terminal.validate()?;
        if let Some(existing) =
            load_post_completion_terminal_optional(&self.connection, &terminal.operation_id)?
        {
            if existing == *terminal {
                return load_post_completion_rollback_from(
                    &self.connection,
                    &terminal.operation_id,
                );
            }
            return Err(reference_mismatch(
                "post-completion rollback terminal",
                "operation already has a different immutable terminal",
            ));
        }
        let terminal_bytes = encode("post-completion rollback terminal", terminal)?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        validate_post_completion_terminal(&transaction, terminal)?;
        ensure_artifact_absent(
            &transaction,
            "SELECT 1 FROM post_completion_rollback_terminals WHERE terminal_id = ?1",
            "post-completion rollback terminal",
            &terminal.terminal_id,
        )?;
        for (ordinal, receipt_id) in terminal.cleanup_receipt_ids.iter().enumerate() {
            transaction.execute(
                "INSERT INTO post_completion_rollback_terminal_cleanups (
                    terminal_id, operation_id, ordinal, cleanup_receipt_id
                 ) VALUES (?1, ?2, ?3, ?4)",
                params![
                    terminal.terminal_id,
                    terminal.operation_id,
                    i64::try_from(ordinal)
                        .map_err(|_| LedgerError::IntegerOutOfRange("rollback cleanup ordinal"))?,
                    receipt_id,
                ],
            )?;
        }
        transaction.execute(
            "INSERT INTO post_completion_rollback_terminals (
                terminal_id, operation_id, sprint_id, application_receipt_id,
                outcome_id, terminal_kind, cleanup_count,
                contract_version, terminal_at_unix_ms, terminal_json
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
            params![
                terminal.terminal_id,
                terminal.operation_id,
                terminal.sprint_id,
                terminal.application_receipt_id,
                terminal.outcome_id,
                terminal.kind.storage_name(),
                i64::try_from(terminal.cleanup_receipt_ids.len())
                    .map_err(|_| LedgerError::IntegerOutOfRange("rollback cleanup count"))?,
                i64::from(terminal.contract_version),
                sqlite_integer(
                    "post_completion_rollback_terminal.terminal_at_unix_ms",
                    terminal.terminal_at_unix_ms,
                )?,
                terminal_bytes,
            ],
        )?;
        transaction.commit()?;
        let persisted =
            load_post_completion_rollback_from(&self.connection, &terminal.operation_id)?;
        secure_database_files(&self.database_path)?;
        Ok(persisted)
    }

    /// Loads and fully revalidates one post-completion rollback operation.
    ///
    /// # Errors
    ///
    /// Returns [`LedgerError`] when the operation is absent or any persisted
    /// canonical bytes, indexed bindings, lifecycle ordering, or proof is
    /// corrupt.
    pub fn load_post_completion_rollback(
        &self,
        operation_id: &str,
    ) -> Result<PersistedPostCompletionRollback, LedgerError> {
        load_post_completion_rollback_from(&self.connection, operation_id)
    }

    /// Loads the exact artifact authority or explicit migration-only legacy
    /// gap for one post-completion rollback operation.
    ///
    /// # Errors
    ///
    /// Returns [`LedgerError`] when the operation is absent, authority is
    /// crossed/corrupt, or authoritative and legacy classifications coexist
    /// or are both absent.
    pub fn load_post_completion_rollback_application_artifact_authority(
        &self,
        operation_id: &str,
    ) -> Result<PostCompletionRollbackApplicationArtifactAuthorityState, LedgerError> {
        let intent = load_post_completion_intent_from(&self.connection, operation_id)?;
        load_post_completion_application_artifact_authority_state(
            &self.connection,
            &intent.sprint_id,
            operation_id,
            &intent.request.application_receipt_id,
        )
    }

    /// Loads every rollback operation for one sprint in durable intent order.
    ///
    /// # Errors
    ///
    /// Returns [`LedgerError`] when `SQLite` cannot enumerate the operations
    /// or any operation fails full canonical readback validation.
    pub fn load_post_completion_rollbacks(
        &self,
        sprint_id: &str,
    ) -> Result<Vec<PersistedPostCompletionRollback>, LedgerError> {
        let mut statement = self.connection.prepare(
            "SELECT operation_id FROM post_completion_rollback_operations
             WHERE sprint_id = ?1 ORDER BY created_at_unix_ms, operation_id",
        )?;
        let ids = statement
            .query_map([sprint_id], |row| row.get::<_, String>(0))?
            .collect::<Result<Vec<_>, _>>()?;
        ids.iter()
            .map(|operation_id| load_post_completion_rollback_from(&self.connection, operation_id))
            .collect()
    }
}

fn exact_replay_or_conflict(
    existing: PersistedPostCompletionRollback,
    expected: &PostCompletionRollbackIntent,
    entity: &'static str,
) -> Result<PersistedPostCompletionRollback, LedgerError> {
    if existing.intent == *expected {
        Ok(existing)
    } else {
        Err(reference_mismatch(
            entity,
            "immutable retry identity names different canonical intent bytes",
        ))
    }
}

fn validate_operation_intent(
    connection: &Connection,
    intent: &PostCompletionRollbackIntent,
    request_bytes: &[u8],
) -> Result<(), LedgerError> {
    validate_operation_intent_chain(connection, intent, request_bytes)?;
    validate_new_operation_availability(connection, intent)
}

fn validate_operation_intent_chain(
    connection: &Connection,
    intent: &PostCompletionRollbackIntent,
    request_bytes: &[u8],
) -> Result<(), LedgerError> {
    if Digest::sha256(request_bytes) != intent.request_digest {
        return Err(reference_mismatch(
            "post-completion rollback intent",
            "canonical request bytes differ from the authenticated digest",
        ));
    }
    let completion = load_applied_completion_rollback_source(connection, &intent.sprint_id)?
        .ok_or_else(|| {
            reference_mismatch(
                "post-completion rollback intent",
                "sprint does not have proven successful-completion authority",
            )
        })?;
    let application_evidence = &completion.application_evidence;
    let rollback_reference = &completion.rollback_reference;
    let application = &application_evidence.receipt;
    let reference = &rollback_reference.reference;
    let completion_bytes = encode("completion receipt", &completion.receipt)?;
    let application_bytes = encode("application evidence", application_evidence)?;
    let reference_bytes = encode("rollback reference evidence", rollback_reference)?;
    if intent.completion_receipt_id != completion.receipt.receipt_id
        || intent.completion_receipt_digest != Digest::sha256(&completion_bytes)
        || intent.application_evidence_digest != Digest::sha256(&application_bytes)
        || intent.rollback_reference_evidence_digest != Digest::sha256(&reference_bytes)
        || intent.request.sprint_id != intent.sprint_id
        || intent.request.application_receipt_id != application.receipt_id
        || intent.request.application_transaction_id != application.transaction_id
        || intent.request.rollback_reference_id != reference.reference_id
        || reference.application_receipt_id != application.receipt_id
        || reference.transaction_id != application.transaction_id
        || intent.policy_hash != application.policy_hash
        || intent.grant_hash != application.grant_hash
        || intent.grant_hash != completion.receipt.grant_hash
        || intent.policy_version != application.policy_version
        || intent.policy_version != completion.receipt.policy_version
        || intent.created_at_unix_ms < completion.receipt.completed_at_unix_ms
        || intent.created_at_unix_ms < reference.validated_at_unix_ms
    {
        return Err(reference_mismatch(
            "post-completion rollback intent",
            "completion, application, rollback reference, request, grant, policy, or timestamp differs",
        ));
    }
    Ok(())
}

fn validate_new_operation_availability(
    connection: &Connection,
    intent: &PostCompletionRollbackIntent,
) -> Result<(), LedgerError> {
    let ordinary_success = connection
        .query_row(
            "SELECT receipt_id FROM rollback_receipts
             WHERE application_receipt_id = ?1",
            [&intent.request.application_receipt_id],
            |row| row.get::<_, String>(0),
        )
        .optional()?;
    let post_completion_fence = connection
        .query_row(
            "SELECT terminal_kind FROM post_completion_rollback_terminals
             WHERE application_receipt_id = ?1
               AND terminal_kind IN ('Succeeded', 'Unknown')",
            [&intent.request.application_receipt_id],
            |row| row.get::<_, String>(0),
        )
        .optional()?;
    let active_operation = connection
        .query_row(
            "SELECT operation.operation_id
             FROM post_completion_rollback_operations operation
             LEFT JOIN post_completion_rollback_terminals terminal
               ON terminal.operation_id = operation.operation_id
             WHERE operation.application_receipt_id = ?1
               AND terminal.operation_id IS NULL",
            [&intent.request.application_receipt_id],
            |row| row.get::<_, String>(0),
        )
        .optional()?;
    if ordinary_success.is_some() || post_completion_fence.is_some() {
        return Err(reference_mismatch(
            "post-completion rollback intent",
            "application already has an authoritative success or an unknown effect that forbids replay",
        ));
    }
    if active_operation.is_some() {
        return Err(reference_mismatch(
            "post-completion rollback intent",
            "application already has a nonterminal rollback operation",
        ));
    }
    Ok(())
}

fn validate_post_completion_launch(
    connection: &Connection,
    intent: &PostCompletionRollbackIntent,
    role: PostCompletionRollbackApplierRole,
    launch: &RunnerLaunchIntent,
    policy: &ExecutionPolicy,
) -> Result<(), LedgerError> {
    let application =
        load_application_evidence_from(connection, &intent.request.application_receipt_id)?;
    let (application_executor, application_policy) = load_runner_session_policy_from(
        connection,
        &intent.sprint_id,
        &application.receipt.applier_session_id,
    )?;
    if launch.sprint_id != intent.sprint_id
        || launch.purpose != RunnerSessionPurpose::Applier
        || launch.worker_id.is_some()
        || launch.policy_hash != intent.policy_hash
        || launch.grant_hash != intent.grant_hash
        || launch.policy_version != intent.policy_version
        || launch.created_at_unix_ms < intent.created_at_unix_ms
        || policy != &application_policy
        || policy.policy_hash != launch.policy_hash
        || policy.grant_hash != launch.grant_hash
        || policy.computed_hash()? != policy.policy_hash
        || !runner_role_policy_matches(launch.purpose, policy)
        || launch.private_state_digest != application_executor.private_state_digest
        || launch.runner_binary_digest != application_executor.runner_binary_digest
        || launch.protocol_digest != application_executor.protocol_digest
    {
        return Err(reference_mismatch(
            "post-completion rollback launch",
            "fresh applier differs from the exact application policy, grant, private state, runtime, protocol, role, or ordering",
        ));
    }
    if role == PostCompletionRollbackApplierRole::RecoveryValidator {
        let executor = load_post_completion_applier_by_role(
            connection,
            &intent.operation_id,
            PostCompletionRollbackApplierRole::Executor,
        )?;
        let Some(executor_session) = executor.session else {
            return Err(reference_mismatch(
                "post-completion rollback recovery launch",
                "recovery requires an initialized original executor",
            ));
        };
        if launch.launch_id == executor.launch.launch_id
            || launch.session_id == executor_session.session_id
            || launch.created_at_unix_ms < executor_session.registered_at_unix_ms
        {
            return Err(reference_mismatch(
                "post-completion rollback recovery launch",
                "recovery validator must be a distinct fresh launch after executor initialization",
            ));
        }
    }
    Ok(())
}

fn validate_post_completion_session(
    operation_id: &str,
    launch: &RunnerLaunchIntent,
    launch_policy: &ExecutionPolicy,
    role: PostCompletionRollbackApplierRole,
    record: &RunnerSessionPolicyRecord,
    policy: &ExecutionPolicy,
) -> Result<(), LedgerError> {
    if record.sprint_id != launch.sprint_id
        || record.launch_id != launch.launch_id
        || record.session_id != launch.session_id
        || record.purpose != RunnerSessionPurpose::Applier
        || record.worker_id.is_some()
        || record.policy_hash != launch.policy_hash
        || record.runner_binary_digest != launch.runner_binary_digest
        || record.protocol_digest != launch.protocol_digest
        || record.private_state_digest != launch.private_state_digest
        || record.grant_hash != launch.grant_hash
        || record.policy_version != launch.policy_version
        || record.registered_at_unix_ms < launch.created_at_unix_ms
        || policy != launch_policy
        || policy.policy_hash != record.policy_hash
        || policy.grant_hash != record.grant_hash
        || policy.computed_hash()? != policy.policy_hash
        || !runner_role_policy_matches(record.purpose, policy)
    {
        return Err(reference_mismatch(
            "post-completion rollback session",
            "registration does not exactly authenticate its fresh applier launch and compiled policy",
        ));
    }
    if role == PostCompletionRollbackApplierRole::RecoveryValidator {
        require_text(
            "post_completion_rollback_session.operation_id",
            operation_id,
        )?;
    }
    Ok(())
}

fn validate_post_completion_launch_failure(
    connection: &Connection,
    failure: &PostCompletionRollbackLaunchFailure,
) -> Result<(), LedgerError> {
    let (intent, _) = load_post_completion_intent_envelope_from(connection, &failure.operation_id)?;
    let (launch, _, role) = load_post_completion_launch_with_role_from(
        connection,
        &failure.operation_id,
        &failure.launch_id,
    )?;
    let registered_session = connection
        .query_row(
            "SELECT session_id FROM post_completion_rollback_applier_sessions
             WHERE operation_id = ?1 AND launch_id = ?2",
            params![failure.operation_id, failure.launch_id],
            |row| row.get::<_, String>(0),
        )
        .optional()?;
    let truthful_kind = match (failure.launch_role, failure.kind) {
        (
            PostCompletionRollbackApplierRole::Executor,
            PostCompletionRollbackLaunchFailureKind::LaunchRefusedBeforeSpawn
            | PostCompletionRollbackLaunchFailureKind::SpawnFailedBeforeChild,
        ) => PostCompletionRollbackOutcomeKind::NoEffect,
        _ => PostCompletionRollbackOutcomeKind::Unknown,
    };
    if failure.sprint_id != intent.sprint_id
        || failure.launch_id != launch.launch_id
        || failure.expected_session_id != launch.session_id
        || failure.launch_role != role
        || registered_session.is_some()
        || failure.failed_at_unix_ms < launch.created_at_unix_ms
        || failure.outcome_kind() != truthful_kind
    {
        return Err(reference_mismatch(
            "post-completion rollback launch failure",
            "failure differs from its exact uninitialized launch, truthful outcome class, or ordering",
        ));
    }
    Ok(())
}
fn validate_post_completion_observation(
    connection: &Connection,
    observation: &PostCompletionRollbackObservation,
) -> Result<(), LedgerError> {
    let (intent, _) =
        load_post_completion_intent_envelope_from(connection, &observation.operation_id)?;
    let executor = load_post_completion_applier_by_role(
        connection,
        &observation.operation_id,
        PostCompletionRollbackApplierRole::Executor,
    )?;
    let Some(executor_session) = &executor.session else {
        return Err(reference_mismatch(
            "post-completion rollback observation",
            "rollback execution requires its initialized fresh executor",
        ));
    };
    if observation.sprint_id != intent.sprint_id
        || observation.rollback_effect_id != intent.rollback_effect_id
        || observation.request_digest != intent.request_digest
        || observation.executor_launch_id != executor.launch.launch_id
        || observation.executor_session_id != executor_session.session_id
        || observation.effect_started_at_unix_ms < executor_session.registered_at_unix_ms
        || observation.effect_started_at_unix_ms < intent.created_at_unix_ms
        || observation.observed_at_unix_ms < observation.effect_started_at_unix_ms
    {
        return Err(reference_mismatch(
            "post-completion rollback observation",
            "observation differs from its exact intent, request, executor, or timestamp",
        ));
    }
    validate_post_completion_validation_authority(connection, observation, executor_session)?;
    let application =
        load_application_evidence_from(connection, &intent.request.application_receipt_id)?;
    let reference =
        load_rollback_reference_evidence_from(connection, &intent.request.rollback_reference_id)?;
    let change_set = load_change_set_from(
        connection,
        &intent.sprint_id,
        &application.receipt.change_set_id,
    )?;
    match &observation.outcome {
        PostCompletionRollbackOutcome::Succeeded {
            precondition,
            rollback_evidence,
        } => {
            let receipt = &rollback_evidence.receipt;
            let expected_endpoints = application_endpoint_observations(&change_set.operations);
            if precondition.endpoints != expected_endpoints
                || precondition.captured_at_unix_ms != observation.effect_started_at_unix_ms
                || receipt.sprint_id != intent.sprint_id
                || receipt.effect_id != intent.rollback_effect_id
                || receipt.observation_id != observation.observation_id
                || receipt.application_receipt_id != application.receipt.receipt_id
                || receipt.application_transaction_id != application.receipt.transaction_id
                || receipt.restored_base_snapshot != application.receipt.base_snapshot
                || receipt.restored_endpoints_digest
                    != change_set.restored_base_endpoints_digest()?
                || receipt.completed_at_unix_ms != observation.observed_at_unix_ms
                || receipt.completed_at_unix_ms < reference.reference.validated_at_unix_ms
            {
                return Err(reference_mismatch(
                    "post-completion rollback success",
                    "receipt differs from the exact effect, application, restored endpoint set, reference, or timestamp",
                ));
            }
        }
        PostCompletionRollbackOutcome::LiveConflict {
            conflict_receipt, ..
        } => {
            let every_conflict_is_exact_application_endpoint =
                conflict_receipt.conflicts.iter().all(|conflict| {
                    change_set
                        .operations
                        .iter()
                        .find(|operation| operation.path() == conflict.path)
                        .is_some_and(|operation| {
                            conflict.expected_endpoint_digest
                                == post_completion_rollback_expected_endpoint_digest(operation)
                        })
                });
            if conflict_receipt.sprint_id != intent.sprint_id
                || conflict_receipt.application_receipt_id != application.receipt.receipt_id
                || conflict_receipt.transaction_id != application.receipt.transaction_id
                || conflict_receipt.observed_at_unix_ms != observation.observed_at_unix_ms
                || !every_conflict_is_exact_application_endpoint
            {
                return Err(reference_mismatch(
                    "post-completion rollback live conflict",
                    "conflict differs from an exact touched post-application endpoint, transaction, or observation time",
                ));
            }
        }
        PostCompletionRollbackOutcome::Unknown { .. } => {}
    }
    Ok(())
}

fn validate_post_completion_validation_authority(
    connection: &Connection,
    observation: &PostCompletionRollbackObservation,
    executor: &RunnerSessionPolicyRecord,
) -> Result<(), LedgerError> {
    let validation = observation.outcome.validation();
    let (validator, validator_policy, role) = load_post_completion_session_from(
        connection,
        &observation.operation_id,
        &validation.runner_session_id,
    )?;
    let (validator_launch, _, stored_role) = load_post_completion_launch_with_role_from(
        connection,
        &observation.operation_id,
        &validation.runner_launch_id,
    )?;
    let path_matches = match validation.mode {
        RollbackValidationMode::DirectEffectResponse => {
            role == PostCompletionRollbackApplierRole::Executor
                && stored_role == PostCompletionRollbackApplierRole::Executor
                && validator.launch_id == observation.executor_launch_id
                && validator.session_id == observation.executor_session_id
        }
        RollbackValidationMode::RecoveryApplierReconciliation => {
            role == PostCompletionRollbackApplierRole::RecoveryValidator
                && stored_role == PostCompletionRollbackApplierRole::RecoveryValidator
                && validator.launch_id != observation.executor_launch_id
                && validator.session_id != observation.executor_session_id
                && validator_launch.created_at_unix_ms >= executor.registered_at_unix_ms
                && validator_launch.created_at_unix_ms >= observation.effect_started_at_unix_ms
                && validator.registered_at_unix_ms >= observation.effect_started_at_unix_ms
        }
    };
    if validator.purpose != RunnerSessionPurpose::Applier
        || validator.worker_id.is_some()
        || validator.launch_id != validation.runner_launch_id
        || validator.session_id != validation.runner_session_id
        || validator.policy_hash != validation.policy_hash
        || validator.grant_hash != validation.grant_hash
        || validator.policy_version != validation.policy_version
        || validator.private_state_digest != validation.private_state_digest
        || validator.policy_hash != executor.policy_hash
        || validator.grant_hash != executor.grant_hash
        || validator.policy_version != executor.policy_version
        || validator.private_state_digest != executor.private_state_digest
        || validator.runner_binary_digest != executor.runner_binary_digest
        || validator.protocol_digest != executor.protocol_digest
        || validator.registered_at_unix_ms > observation.observed_at_unix_ms
        || validator_launch.created_at_unix_ms > observation.observed_at_unix_ms
        || !runner_role_policy_matches(validator.purpose, &validator_policy)
        || !path_matches
    {
        return Err(reference_mismatch(
            "post-completion rollback validation",
            "validation mode, executor/validator identity, policy, grant, private state, runtime, protocol, or timestamp differs",
        ));
    }
    Ok(())
}

fn validate_post_completion_cleanup(
    connection: &Connection,
    cleanup: &PostCompletionRollbackCleanupEvidence,
) -> Result<(), LedgerError> {
    let (intent, _) = load_post_completion_intent_envelope_from(connection, &cleanup.operation_id)?;
    let cleanup_intent =
        load_post_completion_cleanup_intent_from(connection, &cleanup.cleanup_effect_id)?;
    let receipt = &cleanup.evidence.receipt;
    let (launch, _, _) = load_post_completion_launch_with_role_from(
        connection,
        &cleanup.operation_id,
        &receipt.launch_id,
    )?;
    if receipt.sprint_id != intent.sprint_id
        || cleanup_intent.operation_id != cleanup.operation_id
        || cleanup_intent.cleanup_effect_id != cleanup.cleanup_effect_id
        || cleanup_intent.request_digest != cleanup.request_digest
        || cleanup_intent.request.sprint_id != receipt.sprint_id
        || cleanup_intent.request.launch_id != receipt.launch_id
        || cleanup_intent.request.session_id != receipt.session_id
        || cleanup_intent.request.policy_hash != receipt.policy_hash
        || cleanup_intent.request.grant_hash != receipt.grant_hash
        || cleanup_intent.request.policy_version != receipt.policy_version
        || cleanup_intent.request.platform_backend != receipt.platform_backend
        || receipt.session_id != launch.session_id
        || receipt.policy_hash != launch.policy_hash
        || receipt.grant_hash != launch.grant_hash
        || receipt.policy_version != launch.policy_version
        || receipt.platform_backend != WorkerCleanupBackend::TrustedApplierDirectChildWait
        || receipt.cleaned_at_unix_ms < cleanup_intent.created_at_unix_ms
        || receipt.effect_id == intent.rollback_effect_id
        || receipt.observation_id.trim().is_empty()
    {
        return Err(reference_mismatch(
            "post-completion rollback cleanup",
            "cleanup differs from its exact launch, policy, grant, authoritative applier backend, or ordering",
        ));
    }
    Ok(())
}

fn validate_post_completion_cleanup_intent(
    connection: &Connection,
    cleanup: &PostCompletionRollbackCleanupIntent,
    request_bytes: &[u8],
) -> Result<(), LedgerError> {
    let (intent, _) = load_post_completion_intent_envelope_from(connection, &cleanup.operation_id)?;
    let final_activity_at = post_completion_outcome_time(connection, &cleanup.operation_id)?;
    let (launch, _, _) = load_post_completion_launch_with_role_from(
        connection,
        &cleanup.operation_id,
        &cleanup.request.launch_id,
    )?;
    if Digest::sha256(request_bytes) != cleanup.request_digest
        || cleanup.request.sprint_id != intent.sprint_id
        || cleanup.request.session_id != launch.session_id
        || cleanup.request.policy_hash != launch.policy_hash
        || cleanup.request.grant_hash != launch.grant_hash
        || cleanup.request.policy_version != launch.policy_version
        || cleanup.request.platform_backend != WorkerCleanupBackend::TrustedApplierDirectChildWait
        || cleanup.created_at_unix_ms < final_activity_at
        || cleanup.created_at_unix_ms < launch.created_at_unix_ms
        || cleanup.cleanup_effect_id == intent.rollback_effect_id
    {
        return Err(reference_mismatch(
            "post-completion rollback cleanup intent",
            "request differs from its launch/policy/grant/backend or precedes the launch's final outcome activity",
        ));
    }
    Ok(())
}

fn validate_post_completion_terminal(
    connection: &Connection,
    terminal: &PostCompletionRollbackTerminal,
) -> Result<(), LedgerError> {
    let intent = load_post_completion_intent_from(connection, &terminal.operation_id)?;
    let observation =
        load_post_completion_observation_optional(connection, &terminal.operation_id)?;
    let launch_failure =
        load_post_completion_launch_failure_optional(connection, &terminal.operation_id)?;
    let appliers = load_post_completion_appliers_from(connection, &terminal.operation_id)?;
    let cleanups = load_post_completion_cleanups_from(connection, &terminal.operation_id)?;
    let mut expected_cleanup_ids = cleanups
        .iter()
        .map(|cleanup| cleanup.evidence.evidence.receipt.receipt_id.clone())
        .collect::<Vec<_>>();
    expected_cleanup_ids.sort();
    let cleaned_launches = cleanups
        .iter()
        .map(|cleanup| cleanup.evidence.evidence.receipt.launch_id.as_str())
        .collect::<BTreeSet<_>>();
    let (outcome_id, outcome_kind, outcome_at) = match (&observation, &launch_failure) {
        (Some(observation), None) => (
            observation.observation_id.as_str(),
            observation.outcome.kind(),
            observation.observed_at_unix_ms,
        ),
        (None, Some(failure)) => (
            failure.failure_id.as_str(),
            failure.outcome_kind(),
            failure.failed_at_unix_ms,
        ),
        _ => {
            return Err(reference_mismatch(
                "post-completion rollback terminal",
                "requires exactly one effect observation or launch-failure outcome",
            ));
        }
    };
    if terminal.sprint_id != intent.sprint_id
        || terminal.application_receipt_id != intent.request.application_receipt_id
        || terminal.outcome_id != outcome_id
        || terminal.kind != outcome_kind
        || terminal.cleanup_receipt_ids != expected_cleanup_ids
        || cleanups.len() != appliers.len()
        || cleaned_launches.len() != appliers.len()
        || appliers
            .iter()
            .any(|applier| !cleaned_launches.contains(applier.launch.launch_id.as_str()))
        || terminal.terminal_at_unix_ms < outcome_at
        || cleanups.iter().any(|cleanup| {
            cleanup.evidence.evidence.receipt.cleaned_at_unix_ms > terminal.terminal_at_unix_ms
        })
    {
        return Err(reference_mismatch(
            "post-completion rollback terminal",
            "outcome, application, exact initialized-launch cleanup set, or timestamp differs",
        ));
    }
    if terminal.kind == PostCompletionRollbackOutcomeKind::Succeeded {
        let prior = connection
            .query_row(
                "SELECT operation_id FROM post_completion_rollback_terminals
                 WHERE application_receipt_id = ?1 AND terminal_kind = 'Succeeded'",
                [&terminal.application_receipt_id],
                |row| row.get::<_, String>(0),
            )
            .optional()?;
        if prior
            .as_deref()
            .is_some_and(|operation_id| operation_id != terminal.operation_id)
        {
            return Err(reference_mismatch(
                "post-completion rollback terminal",
                "application already has a different successful rollback operation",
            ));
        }
    }
    Ok(())
}

fn ensure_operation_accepts_work(
    connection: &Connection,
    operation_id: &str,
) -> Result<(), LedgerError> {
    ensure_operation_not_terminal(connection, operation_id)?;
    let has_observation = connection
        .query_row(
            "SELECT 1 FROM post_completion_rollback_observations WHERE operation_id = ?1",
            [operation_id],
            |_| Ok(()),
        )
        .optional()?
        .is_some();
    let has_launch_failure = connection
        .query_row(
            "SELECT 1 FROM post_completion_rollback_launch_failures WHERE operation_id = ?1",
            [operation_id],
            |_| Ok(()),
        )
        .optional()?
        .is_some();
    if has_observation || has_launch_failure {
        Err(reference_mismatch(
            "post-completion rollback operation",
            "outcome is already immutable; no new launch, session, or observation is permitted",
        ))
    } else {
        Ok(())
    }
}

fn ensure_operation_not_terminal(
    connection: &Connection,
    operation_id: &str,
) -> Result<(), LedgerError> {
    let terminal = connection
        .query_row(
            "SELECT 1 FROM post_completion_rollback_terminals WHERE operation_id = ?1",
            [operation_id],
            |_| Ok(()),
        )
        .optional()?
        .is_some();
    if terminal {
        Err(reference_mismatch(
            "post-completion rollback operation",
            "operation is already terminal",
        ))
    } else {
        Ok(())
    }
}

#[allow(clippy::too_many_lines)]
fn load_post_completion_intent_envelope_from(
    connection: &Connection,
    operation_id: &str,
) -> Result<(PostCompletionRollbackIntent, Vec<u8>), LedgerError> {
    let stored = connection
        .query_row(
            "SELECT idempotency_key, rollback_effect_id, sprint_id,
                    completion_receipt_id, application_receipt_id,
                    rollback_reference_id, request_digest,
                    completion_receipt_digest, application_evidence_digest,
                    rollback_reference_evidence_digest, policy_hash, grant_hash,
                    policy_version, contract_version, created_at_unix_ms,
                    request_json, intent_json
             FROM post_completion_rollback_operations WHERE operation_id = ?1",
            [operation_id],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, String>(5)?,
                    row.get::<_, String>(6)?,
                    row.get::<_, String>(7)?,
                    row.get::<_, String>(8)?,
                    row.get::<_, String>(9)?,
                    row.get::<_, String>(10)?,
                    row.get::<_, String>(11)?,
                    row.get::<_, i64>(12)?,
                    row.get::<_, i64>(13)?,
                    row.get::<_, i64>(14)?,
                    row.get::<_, Vec<u8>>(15)?,
                    row.get::<_, Vec<u8>>(16)?,
                ))
            },
        )
        .optional()?
        .ok_or_else(|| LedgerError::ArtifactNotFound {
            entity: "post-completion rollback operation",
            id: operation_id.to_owned(),
        })?;
    require_contract_version("post-completion rollback intent", stored.13)?;
    let intent: PostCompletionRollbackIntent =
        decode_stored("post-completion rollback intent", &stored.16)?;
    let request: RollbackRequest = decode_stored("post-completion rollback request", &stored.15)?;
    intent.validate().map_err(|error| LedgerError::Corrupt {
        entity: "post-completion rollback intent",
        detail: error.to_string(),
    })?;
    let created_at = unsigned_integer(
        "post_completion_rollback_intent.created_at_unix_ms",
        stored.14,
    )?;
    if encode("post-completion rollback intent", &intent)? != stored.16
        || encode("post-completion rollback request", &request)? != stored.15
        || intent.request != request
        || intent.operation_id != operation_id
        || intent.idempotency_key != stored.0
        || intent.rollback_effect_id != stored.1
        || intent.sprint_id != stored.2
        || intent.completion_receipt_id != stored.3
        || intent.request.application_receipt_id != stored.4
        || intent.request.rollback_reference_id != stored.5
        || intent.request_digest.as_str() != stored.6
        || intent.completion_receipt_digest.as_str() != stored.7
        || intent.application_evidence_digest.as_str() != stored.8
        || intent.rollback_reference_evidence_digest.as_str() != stored.9
        || intent.policy_hash.as_str() != stored.10
        || intent.grant_hash.as_str() != stored.11
        || i64::from(intent.policy_version) != stored.12
        || intent.created_at_unix_ms != created_at
    {
        return Err(LedgerError::Corrupt {
            entity: "post-completion rollback intent",
            detail: "canonical intent/request bytes disagree with indexed columns".into(),
        });
    }
    Ok((intent, stored.15))
}

fn load_post_completion_intent_from(
    connection: &Connection,
    operation_id: &str,
) -> Result<PostCompletionRollbackIntent, LedgerError> {
    let (intent, request_bytes) =
        load_post_completion_intent_envelope_from(connection, operation_id)?;
    validate_operation_intent_chain(connection, &intent, &request_bytes).map_err(|error| {
        LedgerError::Corrupt {
            entity: "post-completion rollback intent",
            detail: error.to_string(),
        }
    })?;
    Ok(intent)
}

fn load_post_completion_rollback_optional(
    connection: &Connection,
    operation_id: &str,
) -> Result<Option<PersistedPostCompletionRollback>, LedgerError> {
    let exists = connection
        .query_row(
            "SELECT 1 FROM post_completion_rollback_operations WHERE operation_id = ?1",
            [operation_id],
            |_| Ok(()),
        )
        .optional()?
        .is_some();
    if exists {
        load_post_completion_rollback_from(connection, operation_id).map(Some)
    } else {
        Ok(None)
    }
}

fn load_post_completion_rollback_from(
    connection: &Connection,
    operation_id: &str,
) -> Result<PersistedPostCompletionRollback, LedgerError> {
    let intent = load_post_completion_intent_from(connection, operation_id)?;
    let application_artifact_authority =
        if application_artifact_authority_schema_is_installed(connection)? {
            load_post_completion_application_artifact_authority_state(
                connection,
                &intent.sprint_id,
                operation_id,
                &intent.request.application_receipt_id,
            )?
        } else {
            PostCompletionRollbackApplicationArtifactAuthorityState::LegacyMissing
        };
    let appliers = load_post_completion_appliers_from(connection, operation_id)?;
    let observation = load_post_completion_observation_optional(connection, operation_id)?;
    let launch_failure = load_post_completion_launch_failure_optional(connection, operation_id)?;
    let cleanup_intents = load_post_completion_cleanup_intents_from(connection, operation_id)?;
    let cleanups = load_post_completion_cleanups_from(connection, operation_id)?;
    let terminal = load_post_completion_terminal_optional(connection, operation_id)?;
    if observation.is_some() && launch_failure.is_some() {
        return Err(LedgerError::Corrupt {
            entity: "post-completion rollback operation",
            detail: "operation contains both an effect observation and a launch-failure outcome"
                .into(),
        });
    }
    if observation.is_none()
        && launch_failure.is_none()
        && (!cleanup_intents.is_empty() || !cleanups.is_empty() || terminal.is_some())
    {
        return Err(LedgerError::Corrupt {
            entity: "post-completion rollback operation",
            detail: "cleanup or terminal state exists without an outcome".into(),
        });
    }
    if terminal.is_some() && cleanup_intents.len() != cleanups.len() {
        return Err(LedgerError::Corrupt {
            entity: "post-completion rollback operation",
            detail: "terminal operation has an unresolved cleanup intent".into(),
        });
    }
    Ok(PersistedPostCompletionRollback {
        intent,
        application_artifact_authority,
        appliers,
        observation,
        launch_failure,
        cleanup_intents,
        cleanups,
        terminal,
    })
}

fn insert_post_completion_launch(
    transaction: &Transaction<'_>,
    operation_id: &str,
    role: PostCompletionRollbackApplierRole,
    launch: &RunnerLaunchIntent,
    policy: &ExecutionPolicy,
) -> Result<(), LedgerError> {
    transaction.execute(
        "INSERT INTO post_completion_rollback_applier_launches (
            launch_id, operation_id, sprint_id, launch_role, session_id,
            policy_hash, runner_binary_digest, protocol_digest,
            private_state_digest, grant_hash, policy_version,
            contract_version, created_at_unix_ms, launch_json,
            execution_policy_json
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11,
                   ?12, ?13, ?14, ?15)",
        params![
            launch.launch_id,
            operation_id,
            launch.sprint_id,
            role.storage_name(),
            launch.session_id,
            launch.policy_hash.as_str(),
            launch.runner_binary_digest.as_str(),
            launch.protocol_digest.as_str(),
            launch.private_state_digest.as_str(),
            launch.grant_hash.as_str(),
            i64::from(launch.policy_version),
            i64::from(launch.contract_version),
            sqlite_integer(
                "post_completion_rollback_launch.created_at_unix_ms",
                launch.created_at_unix_ms,
            )?,
            encode("post-completion rollback launch", launch)?,
            encode("post-completion rollback execution policy", policy)?,
        ],
    )?;
    Ok(())
}

#[allow(clippy::too_many_lines)]
fn load_post_completion_launch_with_role_from(
    connection: &Connection,
    operation_id: &str,
    launch_id: &str,
) -> Result<
    (
        RunnerLaunchIntent,
        ExecutionPolicy,
        PostCompletionRollbackApplierRole,
    ),
    LedgerError,
> {
    let stored = connection
        .query_row(
            "SELECT sprint_id, launch_role, session_id, policy_hash,
                    runner_binary_digest, protocol_digest, private_state_digest,
                    grant_hash, policy_version, contract_version,
                    created_at_unix_ms, launch_json, execution_policy_json
             FROM post_completion_rollback_applier_launches
             WHERE operation_id = ?1 AND launch_id = ?2",
            params![operation_id, launch_id],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, String>(5)?,
                    row.get::<_, String>(6)?,
                    row.get::<_, String>(7)?,
                    row.get::<_, i64>(8)?,
                    row.get::<_, i64>(9)?,
                    row.get::<_, i64>(10)?,
                    row.get::<_, Vec<u8>>(11)?,
                    row.get::<_, Vec<u8>>(12)?,
                ))
            },
        )
        .optional()?
        .ok_or_else(|| LedgerError::ArtifactNotFound {
            entity: "post-completion rollback launch",
            id: format!("{operation_id}/{launch_id}"),
        })?;
    require_contract_version("post-completion rollback launch", stored.9)?;
    let launch: RunnerLaunchIntent = decode_stored("post-completion rollback launch", &stored.11)?;
    let policy: ExecutionPolicy =
        decode_stored("post-completion rollback execution policy", &stored.12)?;
    let role = parse_applier_role(&stored.1)?;
    launch.validate().map_err(|error| LedgerError::Corrupt {
        entity: "post-completion rollback launch",
        detail: error.to_string(),
    })?;
    if encode("post-completion rollback launch", &launch)? != stored.11
        || encode("post-completion rollback execution policy", &policy)? != stored.12
        || launch.launch_id != launch_id
        || launch.sprint_id != stored.0
        || launch.session_id != stored.2
        || launch.policy_hash.as_str() != stored.3
        || launch.runner_binary_digest.as_str() != stored.4
        || launch.protocol_digest.as_str() != stored.5
        || launch.private_state_digest.as_str() != stored.6
        || launch.grant_hash.as_str() != stored.7
        || i64::from(launch.policy_version) != stored.8
        || launch.created_at_unix_ms
            != unsigned_integer(
                "post_completion_rollback_launch.created_at_unix_ms",
                stored.10,
            )?
    {
        return Err(LedgerError::Corrupt {
            entity: "post-completion rollback launch",
            detail: "canonical launch/policy bytes disagree with indexed columns".into(),
        });
    }
    // The outer chain is already validated. Recheck nested envelopes without
    // recursively traversing the same proofs.
    let (intent, _) = load_post_completion_intent_envelope_from(connection, operation_id)?;
    validate_post_completion_launch(connection, &intent, role, &launch, &policy).map_err(
        |error| LedgerError::Corrupt {
            entity: "post-completion rollback launch",
            detail: error.to_string(),
        },
    )?;
    Ok((launch, policy, role))
}

fn load_post_completion_launch_from(
    connection: &Connection,
    operation_id: &str,
    launch_id: &str,
) -> Result<(RunnerLaunchIntent, ExecutionPolicy), LedgerError> {
    load_post_completion_launch_with_role_from(connection, operation_id, launch_id)
        .map(|(launch, policy, _)| (launch, policy))
}

fn load_post_completion_launch_by_role_optional(
    connection: &Connection,
    operation_id: &str,
    role: PostCompletionRollbackApplierRole,
) -> Result<Option<RunnerLaunchIntent>, LedgerError> {
    let launch_id = connection
        .query_row(
            "SELECT launch_id FROM post_completion_rollback_applier_launches
             WHERE operation_id = ?1 AND launch_role = ?2",
            params![operation_id, role.storage_name()],
            |row| row.get::<_, String>(0),
        )
        .optional()?;
    launch_id
        .map(|launch_id| {
            load_post_completion_launch_with_role_from(connection, operation_id, &launch_id)
                .map(|(launch, _, _)| launch)
        })
        .transpose()
}

fn insert_post_completion_session(
    transaction: &Transaction<'_>,
    operation_id: &str,
    role: PostCompletionRollbackApplierRole,
    record: &RunnerSessionPolicyRecord,
    policy: &ExecutionPolicy,
) -> Result<(), LedgerError> {
    transaction.execute(
        "INSERT INTO post_completion_rollback_applier_sessions (
            session_id, operation_id, sprint_id, launch_id, launch_role,
            policy_hash, session_nonce, runner_binary_digest, protocol_digest,
            private_state_digest, grant_hash, policy_version, contract_version,
            registered_at_unix_ms, session_json, execution_policy_json
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12,
                   ?13, ?14, ?15, ?16)",
        params![
            record.session_id,
            operation_id,
            record.sprint_id,
            record.launch_id,
            role.storage_name(),
            record.policy_hash.as_str(),
            record.session_nonce.as_str(),
            record.runner_binary_digest.as_str(),
            record.protocol_digest.as_str(),
            record.private_state_digest.as_str(),
            record.grant_hash.as_str(),
            i64::from(record.policy_version),
            i64::from(record.contract_version),
            sqlite_integer(
                "post_completion_rollback_session.registered_at_unix_ms",
                record.registered_at_unix_ms,
            )?,
            encode("post-completion rollback session", record)?,
            encode("post-completion rollback execution policy", policy)?,
        ],
    )?;
    Ok(())
}

#[allow(clippy::too_many_lines)]
fn load_post_completion_session_from(
    connection: &Connection,
    operation_id: &str,
    session_id: &str,
) -> Result<
    (
        RunnerSessionPolicyRecord,
        ExecutionPolicy,
        PostCompletionRollbackApplierRole,
    ),
    LedgerError,
> {
    let stored = connection
        .query_row(
            "SELECT sprint_id, launch_id, launch_role, policy_hash,
                    session_nonce, runner_binary_digest, protocol_digest,
                    private_state_digest, grant_hash, policy_version,
                    contract_version, registered_at_unix_ms, session_json,
                    execution_policy_json
             FROM post_completion_rollback_applier_sessions
             WHERE operation_id = ?1 AND session_id = ?2",
            params![operation_id, session_id],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, String>(5)?,
                    row.get::<_, String>(6)?,
                    row.get::<_, String>(7)?,
                    row.get::<_, String>(8)?,
                    row.get::<_, i64>(9)?,
                    row.get::<_, i64>(10)?,
                    row.get::<_, i64>(11)?,
                    row.get::<_, Vec<u8>>(12)?,
                    row.get::<_, Vec<u8>>(13)?,
                ))
            },
        )
        .optional()?
        .ok_or_else(|| LedgerError::ArtifactNotFound {
            entity: "post-completion rollback session",
            id: format!("{operation_id}/{session_id}"),
        })?;
    require_contract_version("post-completion rollback session", stored.10)?;
    let record: RunnerSessionPolicyRecord =
        decode_stored("post-completion rollback session", &stored.12)?;
    let policy: ExecutionPolicy =
        decode_stored("post-completion rollback execution policy", &stored.13)?;
    let role = parse_applier_role(&stored.2)?;
    record.validate().map_err(|error| LedgerError::Corrupt {
        entity: "post-completion rollback session",
        detail: error.to_string(),
    })?;
    if encode("post-completion rollback session", &record)? != stored.12
        || encode("post-completion rollback execution policy", &policy)? != stored.13
        || record.session_id != session_id
        || record.sprint_id != stored.0
        || record.launch_id != stored.1
        || record.policy_hash.as_str() != stored.3
        || record.session_nonce.as_str() != stored.4
        || record.runner_binary_digest.as_str() != stored.5
        || record.protocol_digest.as_str() != stored.6
        || record.private_state_digest.as_str() != stored.7
        || record.grant_hash.as_str() != stored.8
        || i64::from(record.policy_version) != stored.9
        || record.registered_at_unix_ms
            != unsigned_integer(
                "post_completion_rollback_session.registered_at_unix_ms",
                stored.11,
            )?
    {
        return Err(LedgerError::Corrupt {
            entity: "post-completion rollback session",
            detail: "canonical session/policy bytes disagree with indexed columns".into(),
        });
    }
    let (launch, launch_policy, launch_role) =
        load_post_completion_launch_with_role_from(connection, operation_id, &record.launch_id)?;
    if role != launch_role {
        return Err(LedgerError::Corrupt {
            entity: "post-completion rollback session",
            detail: "session role differs from its launch role".into(),
        });
    }
    validate_post_completion_session(
        operation_id,
        &launch,
        &launch_policy,
        role,
        &record,
        &policy,
    )
    .map_err(|error| LedgerError::Corrupt {
        entity: "post-completion rollback session",
        detail: error.to_string(),
    })?;
    Ok((record, policy, role))
}

fn load_post_completion_session_optional(
    connection: &Connection,
    operation_id: &str,
    session_id: &str,
) -> Result<
    Option<(
        RunnerSessionPolicyRecord,
        ExecutionPolicy,
        PostCompletionRollbackApplierRole,
    )>,
    LedgerError,
> {
    let exists = connection
        .query_row(
            "SELECT 1 FROM post_completion_rollback_applier_sessions
             WHERE operation_id = ?1 AND session_id = ?2",
            params![operation_id, session_id],
            |_| Ok(()),
        )
        .optional()?
        .is_some();
    if exists {
        load_post_completion_session_from(connection, operation_id, session_id).map(Some)
    } else {
        Ok(None)
    }
}

fn load_post_completion_applier_by_role(
    connection: &Connection,
    operation_id: &str,
    role: PostCompletionRollbackApplierRole,
) -> Result<PostCompletionRollbackApplier, LedgerError> {
    let launch = load_post_completion_launch_by_role_optional(connection, operation_id, role)?
        .ok_or_else(|| LedgerError::ArtifactNotFound {
            entity: "post-completion rollback applier",
            id: format!("{operation_id}/{}", role.storage_name()),
        })?;
    let session =
        load_post_completion_session_optional(connection, operation_id, &launch.session_id)?
            .map(|(session, _, stored_role)| {
                if stored_role == role {
                    Ok(session)
                } else {
                    Err(LedgerError::Corrupt {
                        entity: "post-completion rollback applier",
                        detail: "session role differs from its launch role".into(),
                    })
                }
            })
            .transpose()?;
    Ok(PostCompletionRollbackApplier {
        role,
        launch,
        session,
    })
}

fn load_post_completion_appliers_from(
    connection: &Connection,
    operation_id: &str,
) -> Result<Vec<PostCompletionRollbackApplier>, LedgerError> {
    let mut appliers = Vec::new();
    for role in [
        PostCompletionRollbackApplierRole::Executor,
        PostCompletionRollbackApplierRole::RecoveryValidator,
    ] {
        if load_post_completion_launch_by_role_optional(connection, operation_id, role)?.is_some() {
            appliers.push(load_post_completion_applier_by_role(
                connection,
                operation_id,
                role,
            )?);
        }
    }
    let launch_count: i64 = connection.query_row(
        "SELECT COUNT(*) FROM post_completion_rollback_applier_launches
         WHERE operation_id = ?1",
        [operation_id],
        |row| row.get(0),
    )?;
    let session_count: i64 = connection.query_row(
        "SELECT COUNT(*) FROM post_completion_rollback_applier_sessions
         WHERE operation_id = ?1",
        [operation_id],
        |row| row.get(0),
    )?;
    if i64::try_from(appliers.len()).ok() != Some(launch_count)
        || session_count
            != i64::try_from(
                appliers
                    .iter()
                    .filter(|applier| applier.session.is_some())
                    .count(),
            )
            .map_err(|_| LedgerError::IntegerOutOfRange("rollback session count"))?
    {
        return Err(LedgerError::Corrupt {
            entity: "post-completion rollback appliers",
            detail: "launch/session rows do not form the closed executor/recovery role set".into(),
        });
    }
    Ok(appliers)
}

fn parse_applier_role(value: &str) -> Result<PostCompletionRollbackApplierRole, LedgerError> {
    match value {
        "Executor" => Ok(PostCompletionRollbackApplierRole::Executor),
        "RecoveryValidator" => Ok(PostCompletionRollbackApplierRole::RecoveryValidator),
        _ => Err(LedgerError::Corrupt {
            entity: "post-completion rollback applier role",
            detail: format!("unsupported role '{value}'"),
        }),
    }
}

fn parse_launch_failure_kind(
    value: &str,
) -> Result<PostCompletionRollbackLaunchFailureKind, LedgerError> {
    match value {
        "LaunchRefusedBeforeSpawn" => {
            Ok(PostCompletionRollbackLaunchFailureKind::LaunchRefusedBeforeSpawn)
        }
        "SpawnFailedBeforeChild" => {
            Ok(PostCompletionRollbackLaunchFailureKind::SpawnFailedBeforeChild)
        }
        "InitializationOutcomeUnknown" => {
            Ok(PostCompletionRollbackLaunchFailureKind::InitializationOutcomeUnknown)
        }
        _ => Err(LedgerError::Corrupt {
            entity: "post-completion rollback launch failure kind",
            detail: format!("unsupported kind '{value}'"),
        }),
    }
}

fn validation_mode_name(mode: RollbackValidationMode) -> &'static str {
    match mode {
        RollbackValidationMode::DirectEffectResponse => "DirectEffectResponse",
        RollbackValidationMode::RecoveryApplierReconciliation => "RecoveryApplierReconciliation",
    }
}

#[allow(clippy::too_many_lines)]
fn load_post_completion_observation_from(
    connection: &Connection,
    operation_id: &str,
) -> Result<PostCompletionRollbackObservation, LedgerError> {
    let stored = connection
        .query_row(
            "SELECT observation_id, sprint_id, rollback_effect_id,
                    request_digest, executor_launch_id, executor_session_id,
                    outcome_kind, outcome_receipt_id, validator_launch_id,
                    validator_session_id, validation_mode, contract_version,
                    effect_started_at_unix_ms, observed_at_unix_ms,
                    observation_json
             FROM post_completion_rollback_observations WHERE operation_id = ?1",
            [operation_id],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, String>(5)?,
                    row.get::<_, String>(6)?,
                    row.get::<_, String>(7)?,
                    row.get::<_, String>(8)?,
                    row.get::<_, String>(9)?,
                    row.get::<_, String>(10)?,
                    row.get::<_, i64>(11)?,
                    row.get::<_, i64>(12)?,
                    row.get::<_, i64>(13)?,
                    row.get::<_, Vec<u8>>(14)?,
                ))
            },
        )
        .optional()?
        .ok_or_else(|| LedgerError::ArtifactNotFound {
            entity: "post-completion rollback observation",
            id: operation_id.to_owned(),
        })?;
    require_contract_version("post-completion rollback observation", stored.11)?;
    let observation: PostCompletionRollbackObservation =
        decode_stored("post-completion rollback observation", &stored.14)?;
    observation
        .validate()
        .map_err(|error| LedgerError::Corrupt {
            entity: "post-completion rollback observation",
            detail: error.to_string(),
        })?;
    let validation = observation.outcome.validation();
    if encode("post-completion rollback observation", &observation)? != stored.14
        || observation.observation_id != stored.0
        || observation.operation_id != operation_id
        || observation.sprint_id != stored.1
        || observation.rollback_effect_id != stored.2
        || observation.request_digest.as_str() != stored.3
        || observation.executor_launch_id != stored.4
        || observation.executor_session_id != stored.5
        || observation.outcome.kind().storage_name() != stored.6
        || observation.outcome.receipt_id() != stored.7
        || validation.runner_launch_id != stored.8
        || validation.runner_session_id != stored.9
        || validation_mode_name(validation.mode) != stored.10
        || observation.effect_started_at_unix_ms
            != unsigned_integer(
                "post_completion_rollback_observation.effect_started_at_unix_ms",
                stored.12,
            )?
        || observation.observed_at_unix_ms
            != unsigned_integer(
                "post_completion_rollback_observation.observed_at_unix_ms",
                stored.13,
            )?
    {
        return Err(LedgerError::Corrupt {
            entity: "post-completion rollback observation",
            detail: "canonical observation bytes disagree with indexed columns".into(),
        });
    }
    validate_post_completion_receipt_registry(
        connection,
        operation_id,
        &observation.sprint_id,
        observation.outcome.receipt_id(),
        match observation.outcome.kind() {
            PostCompletionRollbackOutcomeKind::Succeeded => "Rollback",
            PostCompletionRollbackOutcomeKind::LiveConflict => "LiveConflict",
            PostCompletionRollbackOutcomeKind::Unknown => "UnknownEvidence",
            PostCompletionRollbackOutcomeKind::NoEffect => {
                return Err(LedgerError::Corrupt {
                    entity: "post-completion rollback observation",
                    detail: "effect observation has impossible NoEffect outcome".into(),
                });
            }
        },
    )?;
    validate_post_completion_observation(connection, &observation).map_err(|error| {
        LedgerError::Corrupt {
            entity: "post-completion rollback observation",
            detail: error.to_string(),
        }
    })?;
    Ok(observation)
}

fn load_post_completion_observation_optional(
    connection: &Connection,
    operation_id: &str,
) -> Result<Option<PostCompletionRollbackObservation>, LedgerError> {
    let exists = connection
        .query_row(
            "SELECT 1 FROM post_completion_rollback_observations WHERE operation_id = ?1",
            [operation_id],
            |_| Ok(()),
        )
        .optional()?
        .is_some();
    if exists {
        load_post_completion_observation_from(connection, operation_id).map(Some)
    } else {
        Ok(None)
    }
}

#[allow(clippy::too_many_lines)]
fn load_post_completion_launch_failure_from(
    connection: &Connection,
    operation_id: &str,
) -> Result<PostCompletionRollbackLaunchFailure, LedgerError> {
    let stored = connection
        .query_row(
            "SELECT failure_id, sprint_id, launch_id, expected_session_id,
                    launch_role, failure_kind, terminal_kind,
                    failure_evidence_digest, contract_version,
                    failed_at_unix_ms, failure_evidence_bytes, failure_json
             FROM post_completion_rollback_launch_failures
             WHERE operation_id = ?1",
            [operation_id],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, String>(5)?,
                    row.get::<_, String>(6)?,
                    row.get::<_, String>(7)?,
                    row.get::<_, i64>(8)?,
                    row.get::<_, i64>(9)?,
                    row.get::<_, Vec<u8>>(10)?,
                    row.get::<_, Vec<u8>>(11)?,
                ))
            },
        )
        .optional()?
        .ok_or_else(|| LedgerError::ArtifactNotFound {
            entity: "post-completion rollback launch failure",
            id: operation_id.to_owned(),
        })?;
    require_contract_version("post-completion rollback launch failure", stored.8)?;
    let failure: PostCompletionRollbackLaunchFailure =
        decode_stored("post-completion rollback launch failure", &stored.11)?;
    failure.validate().map_err(|error| LedgerError::Corrupt {
        entity: "post-completion rollback launch failure",
        detail: error.to_string(),
    })?;
    let role = parse_applier_role(&stored.4)?;
    let kind = parse_launch_failure_kind(&stored.5)?;
    if encode("post-completion rollback launch failure", &failure)? != stored.11
        || failure.failure_id != stored.0
        || failure.operation_id != operation_id
        || failure.sprint_id != stored.1
        || failure.launch_id != stored.2
        || failure.expected_session_id != stored.3
        || failure.launch_role != role
        || failure.kind != kind
        || failure.outcome_kind().storage_name() != stored.6
        || failure.failure_evidence_digest.as_str() != stored.7
        || failure.failed_at_unix_ms
            != unsigned_integer(
                "post_completion_rollback_launch_failure.failed_at_unix_ms",
                stored.9,
            )?
        || failure.failure_evidence_bytes != stored.10
    {
        return Err(LedgerError::Corrupt {
            entity: "post-completion rollback launch failure",
            detail: "canonical launch-failure bytes disagree with indexed columns".into(),
        });
    }
    validate_post_completion_launch_failure(connection, &failure).map_err(|error| {
        LedgerError::Corrupt {
            entity: "post-completion rollback launch failure",
            detail: error.to_string(),
        }
    })?;
    Ok(failure)
}

fn load_post_completion_launch_failure_optional(
    connection: &Connection,
    operation_id: &str,
) -> Result<Option<PostCompletionRollbackLaunchFailure>, LedgerError> {
    let exists = connection
        .query_row(
            "SELECT 1 FROM post_completion_rollback_launch_failures
             WHERE operation_id = ?1",
            [operation_id],
            |_| Ok(()),
        )
        .optional()?
        .is_some();
    if exists {
        load_post_completion_launch_failure_from(connection, operation_id).map(Some)
    } else {
        Ok(None)
    }
}

fn post_completion_outcome_time(
    connection: &Connection,
    operation_id: &str,
) -> Result<u64, LedgerError> {
    let observation = load_post_completion_observation_optional(connection, operation_id)?;
    let launch_failure = load_post_completion_launch_failure_optional(connection, operation_id)?;
    match (observation, launch_failure) {
        (Some(observation), None) => Ok(observation.observed_at_unix_ms),
        (None, Some(failure)) => Ok(failure.failed_at_unix_ms),
        (None, None) => Err(LedgerError::ArtifactNotFound {
            entity: "post-completion rollback outcome",
            id: operation_id.to_owned(),
        }),
        (Some(_), Some(_)) => Err(LedgerError::Corrupt {
            entity: "post-completion rollback operation",
            detail: "operation contains both an effect observation and a launch-failure outcome"
                .into(),
        }),
    }
}

fn insert_post_completion_receipt_id(
    transaction: &Transaction<'_>,
    operation_id: &str,
    sprint_id: &str,
    receipt_id: &str,
    receipt_kind: &str,
) -> Result<(), LedgerError> {
    transaction.execute(
        "INSERT INTO post_completion_rollback_receipt_ids (
            receipt_id, operation_id, sprint_id, receipt_kind,
            contract_version
         ) VALUES (?1, ?2, ?3, ?4, ?5)",
        params![
            receipt_id,
            operation_id,
            sprint_id,
            receipt_kind,
            i64::from(CONTRACT_VERSION),
        ],
    )?;
    Ok(())
}

fn validate_post_completion_receipt_registry(
    connection: &Connection,
    operation_id: &str,
    sprint_id: &str,
    receipt_id: &str,
    receipt_kind: &str,
) -> Result<(), LedgerError> {
    let stored = connection
        .query_row(
            "SELECT operation_id, sprint_id, receipt_kind, contract_version
             FROM post_completion_rollback_receipt_ids WHERE receipt_id = ?1",
            [receipt_id],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, i64>(3)?,
                ))
            },
        )
        .optional()?
        .ok_or_else(|| LedgerError::Corrupt {
            entity: "post-completion rollback receipt identity",
            detail: format!("receipt '{receipt_id}' has no registry row"),
        })?;
    require_contract_version("post-completion rollback receipt identity", stored.3)?;
    if stored.0 != operation_id || stored.1 != sprint_id || stored.2 != receipt_kind {
        return Err(LedgerError::Corrupt {
            entity: "post-completion rollback receipt identity",
            detail: "registry row differs from its typed operation evidence".into(),
        });
    }
    if live_state_capture_receipt_identity_exists(connection, receipt_id)? {
        return Err(LedgerError::Corrupt {
            entity: "post-completion rollback receipt identity",
            detail: "receipt identity collides with live-state capture authority".into(),
        });
    }
    Ok(())
}

#[allow(clippy::too_many_lines)]
fn load_post_completion_cleanup_intent_from(
    connection: &Connection,
    cleanup_effect_id: &str,
) -> Result<PostCompletionRollbackCleanupIntent, LedgerError> {
    let stored = connection
        .query_row(
            "SELECT operation_id, sprint_id, launch_id, session_id,
                    request_digest, contract_version, created_at_unix_ms,
                    request_json, intent_json
             FROM post_completion_rollback_cleanup_intents
             WHERE cleanup_effect_id = ?1",
            [cleanup_effect_id],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, i64>(5)?,
                    row.get::<_, i64>(6)?,
                    row.get::<_, Vec<u8>>(7)?,
                    row.get::<_, Vec<u8>>(8)?,
                ))
            },
        )
        .optional()?
        .ok_or_else(|| LedgerError::ArtifactNotFound {
            entity: "post-completion rollback cleanup intent",
            id: cleanup_effect_id.to_owned(),
        })?;
    require_contract_version("post-completion rollback cleanup intent", stored.5)?;
    let intent: PostCompletionRollbackCleanupIntent =
        decode_stored("post-completion rollback cleanup intent", &stored.8)?;
    let request: WorkerCleanupRequest =
        decode_stored("post-completion rollback cleanup request", &stored.7)?;
    intent.validate().map_err(|error| LedgerError::Corrupt {
        entity: "post-completion rollback cleanup intent",
        detail: error.to_string(),
    })?;
    if encode("post-completion rollback cleanup intent", &intent)? != stored.8
        || encode("worker cleanup request", &request)? != stored.7
        || intent.request != request
        || intent.cleanup_effect_id != cleanup_effect_id
        || intent.operation_id != stored.0
        || intent.request.sprint_id != stored.1
        || intent.request.launch_id != stored.2
        || intent.request.session_id != stored.3
        || intent.request_digest.as_str() != stored.4
        || intent.created_at_unix_ms
            != unsigned_integer(
                "post_completion_rollback_cleanup_intent.created_at_unix_ms",
                stored.6,
            )?
    {
        return Err(LedgerError::Corrupt {
            entity: "post-completion rollback cleanup intent",
            detail: "canonical intent/request bytes disagree with indexed columns".into(),
        });
    }
    validate_post_completion_cleanup_intent(connection, &intent, &stored.7).map_err(|error| {
        LedgerError::Corrupt {
            entity: "post-completion rollback cleanup intent",
            detail: error.to_string(),
        }
    })?;
    Ok(intent)
}

fn load_post_completion_cleanup_intent_by_launch_optional(
    connection: &Connection,
    operation_id: &str,
    launch_id: &str,
) -> Result<Option<PostCompletionRollbackCleanupIntent>, LedgerError> {
    let effect_id = connection
        .query_row(
            "SELECT cleanup_effect_id FROM post_completion_rollback_cleanup_intents
             WHERE operation_id = ?1 AND launch_id = ?2",
            params![operation_id, launch_id],
            |row| row.get::<_, String>(0),
        )
        .optional()?;
    effect_id
        .map(|effect_id| load_post_completion_cleanup_intent_from(connection, &effect_id))
        .transpose()
}

fn load_post_completion_cleanup_intents_from(
    connection: &Connection,
    operation_id: &str,
) -> Result<Vec<PostCompletionRollbackCleanupIntent>, LedgerError> {
    let mut statement = connection.prepare(
        "SELECT intent.cleanup_effect_id
         FROM post_completion_rollback_cleanup_intents intent
         JOIN post_completion_rollback_applier_launches launch
           ON launch.operation_id = intent.operation_id
          AND launch.launch_id = intent.launch_id
         WHERE intent.operation_id = ?1
         ORDER BY CASE launch.launch_role
             WHEN 'Executor' THEN 0 ELSE 1 END",
    )?;
    let ids = statement
        .query_map([operation_id], |row| row.get::<_, String>(0))?
        .collect::<Result<Vec<_>, _>>()?;
    ids.iter()
        .map(|effect_id| load_post_completion_cleanup_intent_from(connection, effect_id))
        .collect()
}

#[allow(clippy::too_many_lines)]
fn load_post_completion_cleanup_evidence_from(
    connection: &Connection,
    receipt_id: &str,
) -> Result<PostCompletionRollbackCleanupEvidence, LedgerError> {
    let stored = connection
        .query_row(
            "SELECT operation_id, sprint_id, launch_id, session_id,
                    cleanup_effect_id, cleanup_observation_id, request_digest,
                    policy_hash, grant_hash, policy_version,
                    cleaned_at_unix_ms, contract_version, cleanup_json
             FROM post_completion_rollback_cleanups
             WHERE cleanup_receipt_id = ?1",
            [receipt_id],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, String>(5)?,
                    row.get::<_, String>(6)?,
                    row.get::<_, String>(7)?,
                    row.get::<_, String>(8)?,
                    row.get::<_, i64>(9)?,
                    row.get::<_, i64>(10)?,
                    row.get::<_, i64>(11)?,
                    row.get::<_, Vec<u8>>(12)?,
                ))
            },
        )
        .optional()?
        .ok_or_else(|| LedgerError::ArtifactNotFound {
            entity: "post-completion rollback cleanup evidence",
            id: receipt_id.to_owned(),
        })?;
    require_contract_version("post-completion rollback cleanup evidence", stored.11)?;
    let cleanup: PostCompletionRollbackCleanupEvidence =
        decode_stored("post-completion rollback cleanup evidence", &stored.12)?;
    cleanup.validate().map_err(|error| LedgerError::Corrupt {
        entity: "post-completion rollback cleanup evidence",
        detail: error.to_string(),
    })?;
    let receipt = &cleanup.evidence.receipt;
    if encode("post-completion rollback cleanup evidence", &cleanup)? != stored.12
        || receipt.receipt_id != receipt_id
        || cleanup.operation_id != stored.0
        || receipt.sprint_id != stored.1
        || receipt.launch_id != stored.2
        || receipt.session_id != stored.3
        || cleanup.cleanup_effect_id != stored.4
        || receipt.effect_id != stored.4
        || receipt.observation_id != stored.5
        || cleanup.request_digest.as_str() != stored.6
        || receipt.policy_hash.as_str() != stored.7
        || receipt.grant_hash.as_str() != stored.8
        || i64::from(receipt.policy_version) != stored.9
        || receipt.cleaned_at_unix_ms
            != unsigned_integer(
                "post_completion_rollback_cleanup.cleaned_at_unix_ms",
                stored.10,
            )?
    {
        return Err(LedgerError::Corrupt {
            entity: "post-completion rollback cleanup evidence",
            detail: "canonical cleanup bytes disagree with indexed columns".into(),
        });
    }
    validate_post_completion_receipt_registry(
        connection,
        &cleanup.operation_id,
        &receipt.sprint_id,
        receipt_id,
        "WorkerCleanup",
    )?;
    validate_post_completion_cleanup(connection, &cleanup).map_err(|error| {
        LedgerError::Corrupt {
            entity: "post-completion rollback cleanup evidence",
            detail: error.to_string(),
        }
    })?;
    Ok(cleanup)
}

fn load_post_completion_cleanup_by_launch_optional(
    connection: &Connection,
    operation_id: &str,
    launch_id: &str,
) -> Result<Option<PostCompletionRollbackCleanupEvidence>, LedgerError> {
    let receipt_id = connection
        .query_row(
            "SELECT cleanup_receipt_id FROM post_completion_rollback_cleanups
             WHERE operation_id = ?1 AND launch_id = ?2",
            params![operation_id, launch_id],
            |row| row.get::<_, String>(0),
        )
        .optional()?;
    receipt_id
        .map(|receipt_id| load_post_completion_cleanup_evidence_from(connection, &receipt_id))
        .transpose()
}

fn load_post_completion_cleanups_from(
    connection: &Connection,
    operation_id: &str,
) -> Result<Vec<PostCompletionRollbackCleanup>, LedgerError> {
    let mut statement = connection.prepare(
        "SELECT cleanup.cleanup_receipt_id
         FROM post_completion_rollback_cleanups cleanup
         JOIN post_completion_rollback_applier_launches launch
           ON launch.operation_id = cleanup.operation_id
          AND launch.launch_id = cleanup.launch_id
         WHERE cleanup.operation_id = ?1
         ORDER BY CASE launch.launch_role
             WHEN 'Executor' THEN 0 ELSE 1 END",
    )?;
    let ids = statement
        .query_map([operation_id], |row| row.get::<_, String>(0))?
        .collect::<Result<Vec<_>, _>>()?;
    ids.iter()
        .map(|receipt_id| {
            let evidence = load_post_completion_cleanup_evidence_from(connection, receipt_id)?;
            let intent =
                load_post_completion_cleanup_intent_from(connection, &evidence.cleanup_effect_id)?;
            Ok(PostCompletionRollbackCleanup { intent, evidence })
        })
        .collect()
}

#[allow(clippy::too_many_lines)]
fn load_post_completion_terminal_from(
    connection: &Connection,
    operation_id: &str,
) -> Result<PostCompletionRollbackTerminal, LedgerError> {
    let stored = connection
        .query_row(
            "SELECT terminal_id, sprint_id, application_receipt_id,
                    outcome_id, terminal_kind, cleanup_count,
                    contract_version, terminal_at_unix_ms, terminal_json
             FROM post_completion_rollback_terminals WHERE operation_id = ?1",
            [operation_id],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, i64>(5)?,
                    row.get::<_, i64>(6)?,
                    row.get::<_, i64>(7)?,
                    row.get::<_, Vec<u8>>(8)?,
                ))
            },
        )
        .optional()?
        .ok_or_else(|| LedgerError::ArtifactNotFound {
            entity: "post-completion rollback terminal",
            id: operation_id.to_owned(),
        })?;
    require_contract_version("post-completion rollback terminal", stored.6)?;
    let terminal: PostCompletionRollbackTerminal =
        decode_stored("post-completion rollback terminal", &stored.8)?;
    terminal.validate().map_err(|error| LedgerError::Corrupt {
        entity: "post-completion rollback terminal",
        detail: error.to_string(),
    })?;
    let mut statement = connection.prepare(
        "SELECT ordinal, cleanup_receipt_id
         FROM post_completion_rollback_terminal_cleanups
         WHERE operation_id = ?1 AND terminal_id = ?2 ORDER BY ordinal",
    )?;
    let links = statement
        .query_map(params![operation_id, stored.0], |row| {
            Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?))
        })?
        .collect::<Result<Vec<_>, _>>()?;
    for (expected, (actual, _)) in links.iter().enumerate() {
        if i64::try_from(expected).ok() != Some(*actual) {
            return Err(LedgerError::Corrupt {
                entity: "post-completion rollback terminal cleanup links",
                detail: "cleanup ordinals are not contiguous from zero".into(),
            });
        }
    }
    let linked_ids = links
        .into_iter()
        .map(|(_, receipt_id)| receipt_id)
        .collect::<Vec<_>>();
    if encode("post-completion rollback terminal", &terminal)? != stored.8
        || terminal.terminal_id != stored.0
        || terminal.operation_id != operation_id
        || terminal.sprint_id != stored.1
        || terminal.application_receipt_id != stored.2
        || terminal.outcome_id != stored.3
        || terminal.kind.storage_name() != stored.4
        || i64::try_from(terminal.cleanup_receipt_ids.len()).ok() != Some(stored.5)
        || terminal.cleanup_receipt_ids != linked_ids
        || terminal.terminal_at_unix_ms
            != unsigned_integer(
                "post_completion_rollback_terminal.terminal_at_unix_ms",
                stored.7,
            )?
    {
        return Err(LedgerError::Corrupt {
            entity: "post-completion rollback terminal",
            detail: "canonical terminal bytes or cleanup links disagree with indexed columns"
                .into(),
        });
    }
    validate_post_completion_terminal(connection, &terminal).map_err(|error| {
        LedgerError::Corrupt {
            entity: "post-completion rollback terminal",
            detail: error.to_string(),
        }
    })?;
    Ok(terminal)
}

fn load_post_completion_terminal_optional(
    connection: &Connection,
    operation_id: &str,
) -> Result<Option<PostCompletionRollbackTerminal>, LedgerError> {
    let exists = connection
        .query_row(
            "SELECT 1 FROM post_completion_rollback_terminals WHERE operation_id = ?1",
            [operation_id],
            |_| Ok(()),
        )
        .optional()?
        .is_some();
    if exists {
        load_post_completion_terminal_from(connection, operation_id).map(Some)
    } else {
        Ok(None)
    }
}

fn ensure_global_effect_id_available(
    connection: &Connection,
    effect_id: &str,
) -> Result<(), LedgerError> {
    let exists = connection
        .query_row(
            "SELECT 1 FROM effect_intents WHERE effect_id = ?1
             UNION ALL
             SELECT 1 FROM post_completion_rollback_operations
             WHERE rollback_effect_id = ?1
             UNION ALL
             SELECT 1 FROM post_completion_rollback_cleanup_intents
             WHERE cleanup_effect_id = ?1
             LIMIT 1",
            [effect_id],
            |_| Ok(()),
        )
        .optional()?
        .is_some();
    if exists {
        Err(LedgerError::ArtifactAlreadyExists {
            entity: "global effect identity",
            id: effect_id.to_owned(),
        })
    } else {
        Ok(())
    }
}

fn ensure_global_observation_id_available(
    connection: &Connection,
    observation_id: &str,
) -> Result<(), LedgerError> {
    let exists = connection
        .query_row(
            "SELECT 1 FROM effect_observations WHERE observation_id = ?1
             UNION ALL
             SELECT 1 FROM post_completion_rollback_observations
             WHERE observation_id = ?1
             UNION ALL
             SELECT 1 FROM post_completion_rollback_cleanups
             WHERE cleanup_observation_id = ?1
             UNION ALL
             SELECT 1 FROM post_completion_rollback_launch_failures
             WHERE failure_id = ?1
             LIMIT 1",
            [observation_id],
            |_| Ok(()),
        )
        .optional()?
        .is_some();
    if exists {
        Err(LedgerError::ArtifactAlreadyExists {
            entity: "global observation identity",
            id: observation_id.to_owned(),
        })
    } else {
        Ok(())
    }
}

fn ensure_global_receipt_id_available(
    connection: &Connection,
    receipt_id: &str,
) -> Result<(), LedgerError> {
    let capture_exists = live_state_capture_receipt_identity_exists(connection, receipt_id)?;
    let exists = capture_exists
        || connection
            .query_row(
                "SELECT 1 FROM finish_receipt_ids WHERE receipt_id = ?1
             UNION ALL SELECT 1 FROM verification_receipts WHERE receipt_id = ?1
             UNION ALL SELECT 1 FROM acceptance_receipts WHERE receipt_id = ?1
             UNION ALL SELECT 1 FROM completion_receipts WHERE receipt_id = ?1
             UNION ALL SELECT 1 FROM v9_completion_receipts WHERE receipt_id = ?1
             UNION ALL SELECT 1 FROM post_completion_rollback_receipt_ids
                 WHERE receipt_id = ?1
             LIMIT 1",
                [receipt_id],
                |_| Ok(()),
            )
            .optional()?
            .is_some();
    if exists {
        Err(LedgerError::ArtifactAlreadyExists {
            entity: "global receipt identity",
            id: receipt_id.to_owned(),
        })
    } else {
        Ok(())
    }
}

fn live_state_capture_receipt_identity_exists(
    connection: &Connection,
    receipt_id: &str,
) -> Result<bool, LedgerError> {
    let schema_is_installed = connection
        .query_row(
            "SELECT 1 FROM sqlite_schema
             WHERE type = 'table' AND name = 'live_state_capture_receipt_ids'",
            [],
            |_| Ok(()),
        )
        .optional()?
        .is_some();
    if !schema_is_installed {
        return Ok(false);
    }
    Ok(connection
        .query_row(
            "SELECT 1 FROM live_state_capture_receipt_ids WHERE receipt_id = ?1",
            [receipt_id],
            |_| Ok(()),
        )
        .optional()?
        .is_some())
}

fn ensure_global_launch_ids_available(
    connection: &Connection,
    launch: &RunnerLaunchIntent,
) -> Result<(), LedgerError> {
    let exists = connection
        .query_row(
            "SELECT 1 FROM runner_launch_intents
             WHERE launch_id IN (?1, ?2) OR session_id IN (?1, ?2)
             UNION ALL
             SELECT 1 FROM post_completion_rollback_applier_launches
             WHERE launch_id IN (?1, ?2) OR session_id IN (?1, ?2)
             LIMIT 1",
            params![launch.launch_id, launch.session_id],
            |_| Ok(()),
        )
        .optional()?
        .is_some();
    if exists {
        Err(LedgerError::ArtifactAlreadyExists {
            entity: "global runner launch/session identity",
            id: format!("{}/{}", launch.launch_id, launch.session_id),
        })
    } else {
        Ok(())
    }
}

fn ensure_global_session_ids_available(
    connection: &Connection,
    record: &RunnerSessionPolicyRecord,
) -> Result<(), LedgerError> {
    let exists = connection
        .query_row(
            "SELECT 1 FROM runner_session_policies
             WHERE session_id = ?1 OR session_nonce = ?2
             UNION ALL
             SELECT 1 FROM post_completion_rollback_applier_sessions
             WHERE session_id = ?1 OR session_nonce = ?2
             LIMIT 1",
            params![record.session_id, record.session_nonce.as_str()],
            |_| Ok(()),
        )
        .optional()?
        .is_some();
    if exists {
        Err(LedgerError::ArtifactAlreadyExists {
            entity: "global runner session/nonce identity",
            id: record.session_id.clone(),
        })
    } else {
        Ok(())
    }
}
