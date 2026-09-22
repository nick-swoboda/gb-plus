//! Ledger schema migration v9 (raw SQL, moved verbatim from the inline
//! `MIGRATIONS` array).

pub(super) const MIGRATION_V9: &str = r"
    CREATE TABLE finish_effect_kinds (
        effect_id TEXT PRIMARY KEY NOT NULL,
        sprint_id TEXT NOT NULL,
        effect_kind TEXT NOT NULL CHECK (
            effect_kind IN (
                'IntegrateChangeSet', 'ApplyChangeSet',
                'CleanupWorkerDomain', 'RollbackChangeSet'
            )
        ),
        contract_version INTEGER NOT NULL CHECK (contract_version > 0),
        UNIQUE (sprint_id, effect_id),
        FOREIGN KEY (sprint_id, effect_id)
            REFERENCES effect_intents(sprint_id, effect_id)
            ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED
    ) STRICT, WITHOUT ROWID;

    INSERT INTO finish_effect_kinds (
        effect_id, sprint_id, effect_kind, contract_version
    )
    SELECT effect_id, sprint_id, effect_kind, contract_version
    FROM effect_intents
    WHERE effect_kind IN ('IntegrateChangeSet', 'ApplyChangeSet');

    CREATE TABLE legacy_finish_receipt_gaps (
        effect_id TEXT PRIMARY KEY NOT NULL,
        sprint_id TEXT NOT NULL,
        receipt_kind TEXT NOT NULL CHECK (
            receipt_kind IN ('TaskIntegration', 'Application')
        ),
        UNIQUE (sprint_id, effect_id),
        FOREIGN KEY (sprint_id, effect_id)
            REFERENCES effect_intents(sprint_id, effect_id) ON DELETE RESTRICT
    ) STRICT, WITHOUT ROWID;

    INSERT INTO legacy_finish_receipt_gaps (
        effect_id, sprint_id, receipt_kind
    )
    SELECT intent.effect_id, intent.sprint_id,
           CASE intent.effect_kind
               WHEN 'IntegrateChangeSet' THEN 'TaskIntegration'
               ELSE 'Application'
           END
    FROM effect_intents intent
    JOIN effect_observations observation
      ON observation.effect_id = intent.effect_id
    WHERE intent.effect_kind IN ('IntegrateChangeSet', 'ApplyChangeSet')
      AND observation.outcome = 'Succeeded';

    CREATE TRIGGER legacy_finish_receipt_gaps_no_insert
    BEFORE INSERT ON legacy_finish_receipt_gaps
    BEGIN SELECT RAISE(ABORT, 'legacy finish gaps are migration-only'); END;
    CREATE TRIGGER legacy_finish_receipt_gaps_no_update
    BEFORE UPDATE ON legacy_finish_receipt_gaps
    BEGIN SELECT RAISE(ABORT, 'legacy finish gaps are immutable'); END;
    CREATE TRIGGER legacy_finish_receipt_gaps_no_delete
    BEFORE DELETE ON legacy_finish_receipt_gaps
    BEGIN SELECT RAISE(ABORT, 'legacy finish gaps are immutable'); END;

    CREATE TRIGGER finish_effect_kinds_no_existing_insert
    BEFORE INSERT ON finish_effect_kinds
    WHEN EXISTS (
        SELECT 1 FROM effect_intents WHERE effect_id = NEW.effect_id
    )
    BEGIN SELECT RAISE(ABORT, 'finish effect kind must commit with its new intent'); END;
    CREATE TRIGGER finish_effect_kinds_no_update
    BEFORE UPDATE ON finish_effect_kinds
    BEGIN SELECT RAISE(ABORT, 'finish effect kinds are immutable'); END;
    CREATE TRIGGER finish_effect_kinds_no_delete
    BEFORE DELETE ON finish_effect_kinds
    BEGIN SELECT RAISE(ABORT, 'finish effect kinds are immutable'); END;

    CREATE TRIGGER effect_intents_require_finish_kind
    AFTER INSERT ON effect_intents
    WHEN NEW.effect_kind IN ('IntegrateChangeSet', 'ApplyChangeSet') AND NOT EXISTS (
        SELECT 1 FROM finish_effect_kinds kind
        WHERE kind.effect_id = NEW.effect_id
          AND kind.sprint_id = NEW.sprint_id
          AND kind.contract_version = NEW.contract_version
    )
    BEGIN SELECT RAISE(ABORT, 'finish effect intent requires its closed kind'); END;

    CREATE TRIGGER effect_observations_require_finish_kind
    BEFORE INSERT ON effect_observations
    WHEN NEW.effect_kind IN ('IntegrateChangeSet', 'ApplyChangeSet') AND NOT EXISTS (
        SELECT 1 FROM finish_effect_kinds kind
        WHERE kind.effect_id = NEW.effect_id
          AND kind.sprint_id = NEW.sprint_id
          AND kind.contract_version = NEW.contract_version
    )
    BEGIN SELECT RAISE(ABORT, 'finish effect observation requires its closed kind'); END;

    CREATE TABLE finish_receipt_ids (
        receipt_id TEXT PRIMARY KEY NOT NULL,
        sprint_id TEXT NOT NULL,
        receipt_kind TEXT NOT NULL CHECK (
            receipt_kind IN (
                'TaskIntegration', 'Application', 'WorkerCleanup', 'RollbackReference',
                'Rollback', 'LiveWorkspaceUnchanged', 'LiveConflict',
                'VerifiedNoOp', 'Completion'
            )
        ),
        contract_version INTEGER NOT NULL CHECK (contract_version > 0),
        FOREIGN KEY (sprint_id) REFERENCES sprints(sprint_id) ON DELETE RESTRICT
    ) STRICT, WITHOUT ROWID;

    CREATE TRIGGER finish_receipt_ids_global_unique
    BEFORE INSERT ON finish_receipt_ids
    WHEN EXISTS (
        SELECT 1 FROM verification_receipts WHERE receipt_id = NEW.receipt_id
        UNION ALL
        SELECT 1 FROM acceptance_receipts WHERE receipt_id = NEW.receipt_id
        UNION ALL
        SELECT 1 FROM completion_receipts WHERE receipt_id = NEW.receipt_id
    )
    BEGIN SELECT RAISE(ABORT, 'finish receipt identity must be globally unique'); END;
    CREATE TRIGGER verification_receipts_finish_id_unique
    BEFORE INSERT ON verification_receipts
    WHEN EXISTS (
        SELECT 1 FROM finish_receipt_ids WHERE receipt_id = NEW.receipt_id
    )
    BEGIN SELECT RAISE(ABORT, 'receipt identity must be globally unique'); END;
    CREATE TRIGGER acceptance_receipts_finish_id_unique
    BEFORE INSERT ON acceptance_receipts
    WHEN EXISTS (
        SELECT 1 FROM finish_receipt_ids WHERE receipt_id = NEW.receipt_id
    )
    BEGIN SELECT RAISE(ABORT, 'receipt identity must be globally unique'); END;
    CREATE TRIGGER completion_receipts_finish_id_unique
    BEFORE INSERT ON completion_receipts
    WHEN EXISTS (
        SELECT 1 FROM finish_receipt_ids WHERE receipt_id = NEW.receipt_id
    )
    BEGIN SELECT RAISE(ABORT, 'receipt identity must be globally unique'); END;
    CREATE TRIGGER finish_receipt_ids_no_update
    BEFORE UPDATE ON finish_receipt_ids
    BEGIN SELECT RAISE(ABORT, 'finish receipt identities are immutable'); END;
    CREATE TRIGGER finish_receipt_ids_no_delete
    BEFORE DELETE ON finish_receipt_ids
    BEGIN SELECT RAISE(ABORT, 'finish receipt identities are immutable'); END;

    CREATE TABLE application_receipts (
        receipt_id TEXT PRIMARY KEY NOT NULL,
        sprint_id TEXT NOT NULL UNIQUE,
        effect_id TEXT NOT NULL UNIQUE,
        observation_id TEXT NOT NULL UNIQUE,
        applier_session_id TEXT NOT NULL,
        transaction_id TEXT NOT NULL UNIQUE,
        change_set_id TEXT NOT NULL,
        base_snapshot TEXT NOT NULL,
        result_snapshot TEXT NOT NULL,
        policy_hash TEXT NOT NULL,
        grant_hash TEXT NOT NULL,
        policy_version INTEGER NOT NULL CHECK (policy_version > 0),
        applied_operations_digest TEXT NOT NULL,
        touched_path_endpoints_digest TEXT NOT NULL,
        live_manifest_digest TEXT NOT NULL,
        contract_version INTEGER NOT NULL CHECK (contract_version > 0),
        applied_at_unix_ms INTEGER NOT NULL CHECK (applied_at_unix_ms > 0),
        receipt_json BLOB NOT NULL CHECK (length(receipt_json) > 0),
        evidence_json BLOB NOT NULL CHECK (length(evidence_json) > 0),
        UNIQUE (sprint_id, receipt_id),
        UNIQUE (sprint_id, transaction_id),
        CHECK (base_snapshot != result_snapshot),
        FOREIGN KEY (receipt_id) REFERENCES finish_receipt_ids(receipt_id) ON DELETE RESTRICT,
        FOREIGN KEY (sprint_id, effect_id)
            REFERENCES effect_intents(sprint_id, effect_id) ON DELETE RESTRICT,
        FOREIGN KEY (observation_id)
            REFERENCES effect_observations(observation_id)
            ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED,
        FOREIGN KEY (sprint_id, applier_session_id)
            REFERENCES runner_session_policies(sprint_id, session_id)
            ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED,
        FOREIGN KEY (sprint_id, change_set_id)
            REFERENCES change_sets(sprint_id, change_set_id) ON DELETE RESTRICT,
        FOREIGN KEY (sprint_id, base_snapshot)
            REFERENCES workspace_snapshots(sprint_id, snapshot_id) ON DELETE RESTRICT,
        FOREIGN KEY (sprint_id, result_snapshot)
            REFERENCES workspace_snapshots(sprint_id, snapshot_id) ON DELETE RESTRICT
    ) STRICT;

    CREATE TABLE runner_launch_intents (
        launch_id TEXT PRIMARY KEY NOT NULL,
        sprint_id TEXT NOT NULL,
        session_id TEXT NOT NULL,
        purpose TEXT NOT NULL CHECK (
            purpose IN ('TaskWorker', 'FinalVerifier', 'Applier')
        ),
        worker_id TEXT,
        policy_hash TEXT NOT NULL,
        runner_binary_digest TEXT NOT NULL,
        protocol_digest TEXT NOT NULL,
        private_state_digest TEXT NOT NULL,
        grant_hash TEXT NOT NULL,
        policy_version INTEGER NOT NULL CHECK (policy_version > 0),
        contract_version INTEGER NOT NULL CHECK (contract_version > 0),
        created_at_unix_ms INTEGER NOT NULL CHECK (created_at_unix_ms > 0),
        intent_json BLOB NOT NULL CHECK (length(intent_json) > 0),
        execution_policy_json BLOB NOT NULL CHECK (length(execution_policy_json) > 0),
        UNIQUE (sprint_id, launch_id),
        UNIQUE (sprint_id, session_id),
        CHECK (
            (purpose = 'TaskWorker' AND worker_id IS NOT NULL)
            OR (purpose IN ('FinalVerifier', 'Applier') AND worker_id IS NULL)
        ),
        FOREIGN KEY (sprint_id) REFERENCES sprints(sprint_id) ON DELETE RESTRICT
    ) STRICT, WITHOUT ROWID;

    CREATE TABLE runner_session_policies (
        session_id TEXT PRIMARY KEY NOT NULL,
        sprint_id TEXT NOT NULL,
        launch_id TEXT NOT NULL UNIQUE,
        purpose TEXT NOT NULL CHECK (
            purpose IN ('TaskWorker', 'FinalVerifier', 'Applier')
        ),
        worker_id TEXT,
        policy_hash TEXT NOT NULL,
        session_nonce TEXT NOT NULL UNIQUE,
        runner_binary_digest TEXT NOT NULL,
        protocol_digest TEXT NOT NULL,
        private_state_digest TEXT NOT NULL,
        grant_hash TEXT NOT NULL,
        policy_version INTEGER NOT NULL CHECK (policy_version > 0),
        contract_version INTEGER NOT NULL CHECK (contract_version > 0),
        registered_at_unix_ms INTEGER NOT NULL CHECK (registered_at_unix_ms > 0),
        record_json BLOB NOT NULL CHECK (length(record_json) > 0),
        execution_policy_json BLOB NOT NULL CHECK (length(execution_policy_json) > 0),
        UNIQUE (sprint_id, session_id),
        UNIQUE (sprint_id, launch_id),
        CHECK (
            (purpose = 'TaskWorker' AND worker_id IS NOT NULL)
            OR (purpose IN ('FinalVerifier', 'Applier') AND worker_id IS NULL)
        ),
        FOREIGN KEY (sprint_id) REFERENCES sprints(sprint_id) ON DELETE RESTRICT,
        FOREIGN KEY (sprint_id, launch_id)
            REFERENCES runner_launch_intents(sprint_id, launch_id) ON DELETE RESTRICT
    ) STRICT, WITHOUT ROWID;

    CREATE TABLE verification_session_bindings (
        verification_receipt_id TEXT PRIMARY KEY NOT NULL,
        sprint_id TEXT NOT NULL,
        session_id TEXT NOT NULL,
        contract_version INTEGER NOT NULL CHECK (contract_version > 0),
        UNIQUE (sprint_id, verification_receipt_id),
        FOREIGN KEY (sprint_id, verification_receipt_id)
            REFERENCES verification_receipts(sprint_id, receipt_id) ON DELETE RESTRICT,
        FOREIGN KEY (sprint_id, session_id)
            REFERENCES runner_session_policies(sprint_id, session_id) ON DELETE RESTRICT
    ) STRICT, WITHOUT ROWID;

    CREATE TABLE effect_session_bindings (
        effect_id TEXT PRIMARY KEY NOT NULL,
        sprint_id TEXT NOT NULL,
        launch_id TEXT NOT NULL,
        session_id TEXT,
        contract_version INTEGER NOT NULL CHECK (contract_version > 0),
        UNIQUE (sprint_id, effect_id),
        FOREIGN KEY (sprint_id, effect_id)
            REFERENCES effect_intents(sprint_id, effect_id)
            ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED,
        FOREIGN KEY (sprint_id, launch_id)
            REFERENCES runner_launch_intents(sprint_id, launch_id) ON DELETE RESTRICT,
        FOREIGN KEY (sprint_id, session_id)
            REFERENCES runner_session_policies(sprint_id, session_id) ON DELETE RESTRICT
    ) STRICT, WITHOUT ROWID;

    CREATE TRIGGER effect_session_bindings_no_existing_insert
    BEFORE INSERT ON effect_session_bindings
    WHEN EXISTS (SELECT 1 FROM effect_intents WHERE effect_id = NEW.effect_id)
    BEGIN SELECT RAISE(ABORT, 'runner session binding must commit with its new intent'); END;

    CREATE TABLE verification_effect_evidence (
        verification_receipt_id TEXT PRIMARY KEY NOT NULL,
        sprint_id TEXT NOT NULL,
        effect_id TEXT NOT NULL UNIQUE,
        observation_id TEXT NOT NULL UNIQUE,
        runner_launch_id TEXT NOT NULL,
        runner_session_id TEXT NOT NULL,
        output_evidence_digest TEXT NOT NULL,
        contract_version INTEGER NOT NULL CHECK (contract_version > 0),
        output_evidence_bytes BLOB NOT NULL CHECK (length(output_evidence_bytes) > 0),
        evidence_json BLOB NOT NULL CHECK (length(evidence_json) > 0),
        UNIQUE (sprint_id, verification_receipt_id),
        FOREIGN KEY (sprint_id, verification_receipt_id)
            REFERENCES verification_receipts(sprint_id, receipt_id)
            ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED,
        FOREIGN KEY (sprint_id, effect_id)
            REFERENCES effect_intents(sprint_id, effect_id) ON DELETE RESTRICT,
        FOREIGN KEY (observation_id)
            REFERENCES effect_observations(observation_id)
            ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED,
        FOREIGN KEY (sprint_id, runner_launch_id)
            REFERENCES runner_launch_intents(sprint_id, launch_id) ON DELETE RESTRICT,
        FOREIGN KEY (sprint_id, runner_session_id)
            REFERENCES runner_session_policies(sprint_id, session_id) ON DELETE RESTRICT
    ) STRICT, WITHOUT ROWID;

    CREATE TRIGGER verification_effect_evidence_no_backfill
    BEFORE INSERT ON verification_effect_evidence
    WHEN EXISTS (
        SELECT 1 FROM effect_observations WHERE observation_id = NEW.observation_id
    )
    BEGIN SELECT RAISE(ABORT, 'verification evidence must commit with its new observation'); END;

    CREATE TABLE task_integration_receipts (
        receipt_id TEXT PRIMARY KEY NOT NULL,
        sprint_id TEXT NOT NULL,
        task_id TEXT NOT NULL,
        worker_id TEXT NOT NULL,
        worker_launch_id TEXT NOT NULL,
        worker_session_id TEXT NOT NULL,
        worker_policy_hash TEXT NOT NULL,
        effect_id TEXT NOT NULL UNIQUE,
        observation_id TEXT NOT NULL UNIQUE,
        change_set_id TEXT NOT NULL,
        input_snapshot TEXT NOT NULL,
        result_snapshot TEXT NOT NULL,
        integration_ordinal INTEGER NOT NULL CHECK (integration_ordinal >= 0),
        verification_count INTEGER NOT NULL CHECK (verification_count > 0),
        contract_version INTEGER NOT NULL CHECK (contract_version > 0),
        integrated_at_unix_ms INTEGER NOT NULL CHECK (integrated_at_unix_ms > 0),
        receipt_json BLOB NOT NULL CHECK (length(receipt_json) > 0),
        UNIQUE (sprint_id, receipt_id),
        UNIQUE (sprint_id, task_id),
        UNIQUE (sprint_id, integration_ordinal),
        CHECK (input_snapshot != result_snapshot),
        FOREIGN KEY (receipt_id) REFERENCES finish_receipt_ids(receipt_id) ON DELETE RESTRICT,
        FOREIGN KEY (sprint_id, effect_id)
            REFERENCES effect_intents(sprint_id, effect_id) ON DELETE RESTRICT,
        FOREIGN KEY (observation_id)
            REFERENCES effect_observations(observation_id)
            ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED,
        FOREIGN KEY (sprint_id, worker_launch_id)
            REFERENCES runner_launch_intents(sprint_id, launch_id) ON DELETE RESTRICT,
        FOREIGN KEY (sprint_id, worker_session_id)
            REFERENCES runner_session_policies(sprint_id, session_id) ON DELETE RESTRICT,
        FOREIGN KEY (sprint_id, change_set_id)
            REFERENCES change_sets(sprint_id, change_set_id) ON DELETE RESTRICT,
        FOREIGN KEY (sprint_id, input_snapshot)
            REFERENCES workspace_snapshots(sprint_id, snapshot_id) ON DELETE RESTRICT,
        FOREIGN KEY (sprint_id, result_snapshot)
            REFERENCES workspace_snapshots(sprint_id, snapshot_id) ON DELETE RESTRICT
    ) STRICT;

    CREATE TABLE task_integration_verification_receipts (
        integration_receipt_id TEXT NOT NULL,
        sprint_id TEXT NOT NULL,
        ordinal INTEGER NOT NULL CHECK (ordinal >= 0),
        verification_receipt_id TEXT NOT NULL,
        PRIMARY KEY (integration_receipt_id, ordinal),
        UNIQUE (integration_receipt_id, verification_receipt_id),
        FOREIGN KEY (sprint_id, integration_receipt_id)
            REFERENCES task_integration_receipts(sprint_id, receipt_id) ON DELETE RESTRICT,
        FOREIGN KEY (sprint_id, verification_receipt_id)
            REFERENCES verification_receipts(sprint_id, receipt_id) ON DELETE RESTRICT
    ) STRICT, WITHOUT ROWID;

    CREATE TABLE worker_cleanup_receipts (
        receipt_id TEXT PRIMARY KEY NOT NULL,
        sprint_id TEXT NOT NULL,
        effect_id TEXT NOT NULL UNIQUE,
        observation_id TEXT NOT NULL UNIQUE,
        launch_id TEXT NOT NULL UNIQUE,
        session_id TEXT NOT NULL,
        policy_hash TEXT NOT NULL,
        grant_hash TEXT NOT NULL,
        policy_version INTEGER NOT NULL CHECK (policy_version > 0),
        platform_backend TEXT NOT NULL CHECK (
            platform_backend IN (
                'MacOsDedicatedIdentity', 'LinuxCgroupV2',
                'TrustedApplierDirectChildWait'
            )
        ),
        os_evidence_digest TEXT NOT NULL,
        surviving_processes INTEGER NOT NULL CHECK (surviving_processes = 0),
        contract_version INTEGER NOT NULL CHECK (contract_version > 0),
        cleaned_at_unix_ms INTEGER NOT NULL CHECK (cleaned_at_unix_ms > 0),
        receipt_json BLOB NOT NULL CHECK (length(receipt_json) > 0),
        os_evidence_bytes BLOB NOT NULL CHECK (length(os_evidence_bytes) > 0),
        evidence_json BLOB NOT NULL CHECK (length(evidence_json) > 0),
        UNIQUE (sprint_id, receipt_id),
        UNIQUE (sprint_id, launch_id),
        UNIQUE (sprint_id, session_id),
        FOREIGN KEY (receipt_id) REFERENCES finish_receipt_ids(receipt_id) ON DELETE RESTRICT,
        FOREIGN KEY (sprint_id, effect_id)
            REFERENCES effect_intents(sprint_id, effect_id) ON DELETE RESTRICT,
        FOREIGN KEY (observation_id)
            REFERENCES effect_observations(observation_id)
            ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED,
        FOREIGN KEY (sprint_id, launch_id)
            REFERENCES runner_launch_intents(sprint_id, launch_id) ON DELETE RESTRICT
    ) STRICT;

    CREATE TABLE rollback_references (
        reference_id TEXT PRIMARY KEY NOT NULL,
        sprint_id TEXT NOT NULL,
        application_receipt_id TEXT NOT NULL UNIQUE,
        transaction_id TEXT NOT NULL UNIQUE,
        journal_binding_digest TEXT NOT NULL,
        base_snapshot TEXT NOT NULL,
        touched_target_set_digest TEXT NOT NULL,
        reopened_artifacts_digest TEXT NOT NULL,
        contract_version INTEGER NOT NULL CHECK (contract_version > 0),
        validated_at_unix_ms INTEGER NOT NULL CHECK (validated_at_unix_ms > 0),
        reference_json BLOB NOT NULL CHECK (length(reference_json) > 0),
        reopened_artifacts_bytes BLOB NOT NULL CHECK (length(reopened_artifacts_bytes) > 0),
        evidence_json BLOB NOT NULL CHECK (length(evidence_json) > 0),
        UNIQUE (sprint_id, reference_id),
        FOREIGN KEY (reference_id) REFERENCES finish_receipt_ids(receipt_id) ON DELETE RESTRICT,
        FOREIGN KEY (sprint_id, application_receipt_id)
            REFERENCES application_receipts(sprint_id, receipt_id) ON DELETE RESTRICT,
        FOREIGN KEY (sprint_id, transaction_id)
            REFERENCES application_receipts(sprint_id, transaction_id) ON DELETE RESTRICT,
        FOREIGN KEY (sprint_id, base_snapshot)
            REFERENCES workspace_snapshots(sprint_id, snapshot_id) ON DELETE RESTRICT
    ) STRICT;

    CREATE TABLE verified_no_op_receipts (
        receipt_id TEXT PRIMARY KEY NOT NULL,
        sprint_id TEXT NOT NULL UNIQUE,
        final_verification_receipt_id TEXT NOT NULL UNIQUE,
        base_snapshot TEXT NOT NULL,
        live_manifest_digest TEXT NOT NULL,
        grant_hash TEXT NOT NULL,
        policy_version INTEGER NOT NULL CHECK (policy_version > 0),
        contract_version INTEGER NOT NULL CHECK (contract_version > 0),
        observed_at_unix_ms INTEGER NOT NULL CHECK (observed_at_unix_ms > 0),
        receipt_json BLOB NOT NULL CHECK (length(receipt_json) > 0),
        UNIQUE (sprint_id, receipt_id),
        CHECK (base_snapshot = live_manifest_digest),
        FOREIGN KEY (receipt_id) REFERENCES finish_receipt_ids(receipt_id) ON DELETE RESTRICT,
        FOREIGN KEY (sprint_id, final_verification_receipt_id)
            REFERENCES verification_receipts(sprint_id, receipt_id) ON DELETE RESTRICT,
        FOREIGN KEY (sprint_id, base_snapshot)
            REFERENCES workspace_snapshots(sprint_id, snapshot_id) ON DELETE RESTRICT
    ) STRICT;

    CREATE TABLE rollback_receipts (
        receipt_id TEXT PRIMARY KEY NOT NULL,
        sprint_id TEXT NOT NULL UNIQUE,
        effect_id TEXT NOT NULL UNIQUE,
        observation_id TEXT NOT NULL UNIQUE,
        application_receipt_id TEXT NOT NULL UNIQUE,
        application_transaction_id TEXT NOT NULL UNIQUE,
        restored_base_snapshot TEXT NOT NULL,
        restored_endpoints_digest TEXT NOT NULL,
        live_manifest_digest TEXT NOT NULL,
        unresolved_conflicts INTEGER NOT NULL CHECK (unresolved_conflicts = 0),
        contract_version INTEGER NOT NULL CHECK (contract_version > 0),
        completed_at_unix_ms INTEGER NOT NULL CHECK (completed_at_unix_ms > 0),
        receipt_json BLOB NOT NULL CHECK (length(receipt_json) > 0),
        evidence_json BLOB NOT NULL CHECK (length(evidence_json) > 0),
        UNIQUE (sprint_id, receipt_id),
        FOREIGN KEY (receipt_id) REFERENCES finish_receipt_ids(receipt_id) ON DELETE RESTRICT,
        FOREIGN KEY (sprint_id, effect_id)
            REFERENCES effect_intents(sprint_id, effect_id) ON DELETE RESTRICT,
        FOREIGN KEY (observation_id)
            REFERENCES effect_observations(observation_id)
            ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED,
        FOREIGN KEY (sprint_id, application_receipt_id)
            REFERENCES application_receipts(sprint_id, receipt_id) ON DELETE RESTRICT,
        FOREIGN KEY (sprint_id, application_transaction_id)
            REFERENCES application_receipts(sprint_id, transaction_id) ON DELETE RESTRICT,
        FOREIGN KEY (sprint_id, restored_base_snapshot)
            REFERENCES workspace_snapshots(sprint_id, snapshot_id) ON DELETE RESTRICT
    ) STRICT;

    CREATE TABLE live_workspace_unchanged_receipts (
        receipt_id TEXT PRIMARY KEY NOT NULL,
        sprint_id TEXT NOT NULL UNIQUE,
        base_snapshot TEXT NOT NULL,
        live_manifest_digest TEXT NOT NULL,
        grant_hash TEXT NOT NULL,
        contract_version INTEGER NOT NULL CHECK (contract_version > 0),
        captured_at_unix_ms INTEGER NOT NULL CHECK (captured_at_unix_ms > 0),
        receipt_json BLOB NOT NULL CHECK (length(receipt_json) > 0),
        UNIQUE (sprint_id, receipt_id),
        FOREIGN KEY (receipt_id) REFERENCES finish_receipt_ids(receipt_id) ON DELETE RESTRICT,
        FOREIGN KEY (sprint_id, base_snapshot)
            REFERENCES workspace_snapshots(sprint_id, snapshot_id) ON DELETE RESTRICT
    ) STRICT;

    CREATE TABLE live_conflict_receipts (
        receipt_id TEXT PRIMARY KEY NOT NULL,
        sprint_id TEXT NOT NULL UNIQUE,
        application_receipt_id TEXT NOT NULL UNIQUE,
        transaction_id TEXT NOT NULL UNIQUE,
        live_manifest_digest TEXT NOT NULL,
        conflict_count INTEGER NOT NULL CHECK (conflict_count > 0),
        required_user_decision TEXT NOT NULL CHECK (
            required_user_decision = 'ChoosePreservedEndpointAndReconcile'
        ),
        contract_version INTEGER NOT NULL CHECK (contract_version > 0),
        observed_at_unix_ms INTEGER NOT NULL CHECK (observed_at_unix_ms > 0),
        receipt_json BLOB NOT NULL CHECK (length(receipt_json) > 0),
        UNIQUE (sprint_id, receipt_id),
        FOREIGN KEY (receipt_id) REFERENCES finish_receipt_ids(receipt_id) ON DELETE RESTRICT,
        FOREIGN KEY (sprint_id, application_receipt_id)
            REFERENCES application_receipts(sprint_id, receipt_id) ON DELETE RESTRICT,
        FOREIGN KEY (sprint_id, transaction_id)
            REFERENCES application_receipts(sprint_id, transaction_id) ON DELETE RESTRICT
    ) STRICT;

    CREATE TABLE terminal_cleanup_proofs (
        sprint_id TEXT PRIMARY KEY NOT NULL,
        proof_kind TEXT NOT NULL CHECK (
            proof_kind IN (
                'LegacyCleanupUnproven', 'UnknownNoProof',
                'LiveWorkspaceUnchanged', 'Rollback', 'LiveConflict'
            )
        ),
        unchanged_receipt_id TEXT,
        rollback_receipt_id TEXT,
        conflict_receipt_id TEXT,
        contract_version INTEGER NOT NULL CHECK (contract_version > 0),
        CHECK (
            (proof_kind IN ('LegacyCleanupUnproven', 'UnknownNoProof')
             AND unchanged_receipt_id IS NULL
             AND rollback_receipt_id IS NULL
             AND conflict_receipt_id IS NULL)
            OR
            (proof_kind = 'LiveWorkspaceUnchanged'
             AND unchanged_receipt_id IS NOT NULL
             AND rollback_receipt_id IS NULL
             AND conflict_receipt_id IS NULL)
            OR
            (proof_kind = 'Rollback'
             AND unchanged_receipt_id IS NULL
             AND rollback_receipt_id IS NOT NULL
             AND conflict_receipt_id IS NULL)
            OR
            (proof_kind = 'LiveConflict'
             AND unchanged_receipt_id IS NULL
             AND rollback_receipt_id IS NULL
             AND conflict_receipt_id IS NOT NULL)
        ),
        FOREIGN KEY (sprint_id) REFERENCES sprints(sprint_id) ON DELETE RESTRICT,
        FOREIGN KEY (unchanged_receipt_id)
            REFERENCES live_workspace_unchanged_receipts(receipt_id) ON DELETE RESTRICT,
        FOREIGN KEY (rollback_receipt_id)
            REFERENCES rollback_receipts(receipt_id) ON DELETE RESTRICT,
        FOREIGN KEY (conflict_receipt_id)
            REFERENCES live_conflict_receipts(receipt_id) ON DELETE RESTRICT
    ) STRICT, WITHOUT ROWID;

    INSERT INTO terminal_cleanup_proofs (
        sprint_id, proof_kind, unchanged_receipt_id, rollback_receipt_id,
        conflict_receipt_id, contract_version
    )
    SELECT sprint_id,
           CASE terminal_state
               WHEN 'Unknown' THEN 'UnknownNoProof'
               ELSE 'LegacyCleanupUnproven'
           END,
           NULL, NULL, NULL, contract_version
    FROM sprint_non_success_terminal_outcomes;

    CREATE TABLE v9_completion_receipts (
        receipt_id TEXT PRIMARY KEY NOT NULL,
        sprint_id TEXT NOT NULL UNIQUE,
        final_snapshot TEXT NOT NULL,
        grant_hash TEXT NOT NULL,
        policy_version INTEGER NOT NULL CHECK (policy_version > 0),
        final_verification_receipt_id TEXT NOT NULL,
        application_kind TEXT NOT NULL CHECK (
            application_kind IN ('Applied', 'VerifiedNoOp')
        ),
        application_receipt_id TEXT UNIQUE,
        rollback_reference_id TEXT UNIQUE,
        verified_no_op_receipt_id TEXT UNIQUE,
        final_report_id TEXT NOT NULL UNIQUE,
        provider_backend TEXT NOT NULL,
        provider_model TEXT NOT NULL,
        contract_version INTEGER NOT NULL CHECK (contract_version > 0),
        completed_at_unix_ms INTEGER NOT NULL CHECK (completed_at_unix_ms > 0),
        receipt_json BLOB NOT NULL CHECK (length(receipt_json) > 0),
        UNIQUE (sprint_id, receipt_id),
        CHECK (
            (application_kind = 'Applied'
             AND application_receipt_id IS NOT NULL
             AND rollback_reference_id IS NOT NULL
             AND verified_no_op_receipt_id IS NULL)
            OR
            (application_kind = 'VerifiedNoOp'
             AND application_receipt_id IS NULL
             AND rollback_reference_id IS NULL
             AND verified_no_op_receipt_id IS NOT NULL)
        ),
        FOREIGN KEY (receipt_id) REFERENCES finish_receipt_ids(receipt_id) ON DELETE RESTRICT,
        FOREIGN KEY (sprint_id, final_snapshot)
            REFERENCES workspace_snapshots(sprint_id, snapshot_id) ON DELETE RESTRICT,
        FOREIGN KEY (final_verification_receipt_id)
            REFERENCES verification_receipts(receipt_id) ON DELETE RESTRICT,
        FOREIGN KEY (sprint_id, application_receipt_id)
            REFERENCES application_receipts(sprint_id, receipt_id) ON DELETE RESTRICT,
        FOREIGN KEY (sprint_id, rollback_reference_id)
            REFERENCES rollback_references(sprint_id, reference_id) ON DELETE RESTRICT,
        FOREIGN KEY (sprint_id, verified_no_op_receipt_id)
            REFERENCES verified_no_op_receipts(sprint_id, receipt_id) ON DELETE RESTRICT,
        FOREIGN KEY (sprint_id, final_report_id)
            REFERENCES final_reports(sprint_id, report_id) ON DELETE RESTRICT
    ) STRICT;

    CREATE TABLE v9_completion_cleanup_receipts (
        completion_receipt_id TEXT NOT NULL,
        sprint_id TEXT NOT NULL,
        ordinal INTEGER NOT NULL CHECK (ordinal >= 0),
        cleanup_receipt_id TEXT NOT NULL,
        PRIMARY KEY (completion_receipt_id, ordinal),
        UNIQUE (completion_receipt_id, cleanup_receipt_id),
        FOREIGN KEY (sprint_id, completion_receipt_id)
            REFERENCES v9_completion_receipts(sprint_id, receipt_id) ON DELETE RESTRICT,
        FOREIGN KEY (sprint_id, cleanup_receipt_id)
            REFERENCES worker_cleanup_receipts(sprint_id, receipt_id) ON DELETE RESTRICT
    ) STRICT, WITHOUT ROWID;

    CREATE TABLE v9_completion_verification_receipts (
        completion_receipt_id TEXT NOT NULL,
        sprint_id TEXT NOT NULL,
        ordinal INTEGER NOT NULL CHECK (ordinal >= 0),
        verification_receipt_id TEXT NOT NULL,
        PRIMARY KEY (completion_receipt_id, ordinal),
        UNIQUE (completion_receipt_id, verification_receipt_id),
        FOREIGN KEY (sprint_id, completion_receipt_id)
            REFERENCES v9_completion_receipts(sprint_id, receipt_id) ON DELETE RESTRICT,
        FOREIGN KEY (sprint_id, verification_receipt_id)
            REFERENCES verification_receipts(sprint_id, receipt_id) ON DELETE RESTRICT
    ) STRICT, WITHOUT ROWID;

    CREATE TABLE v9_completion_task_integration_receipts (
        completion_receipt_id TEXT NOT NULL,
        sprint_id TEXT NOT NULL,
        ordinal INTEGER NOT NULL CHECK (ordinal >= 0),
        integration_receipt_id TEXT NOT NULL,
        PRIMARY KEY (completion_receipt_id, ordinal),
        UNIQUE (completion_receipt_id, integration_receipt_id),
        FOREIGN KEY (sprint_id, completion_receipt_id)
            REFERENCES v9_completion_receipts(sprint_id, receipt_id) ON DELETE RESTRICT,
        FOREIGN KEY (sprint_id, integration_receipt_id)
            REFERENCES task_integration_receipts(sprint_id, receipt_id) ON DELETE RESTRICT
    ) STRICT, WITHOUT ROWID;

    CREATE TABLE v9_completion_acceptance_receipts (
        completion_receipt_id TEXT NOT NULL,
        sprint_id TEXT NOT NULL,
        ordinal INTEGER NOT NULL CHECK (ordinal >= 0),
        acceptance_receipt_id TEXT NOT NULL,
        PRIMARY KEY (completion_receipt_id, ordinal),
        UNIQUE (completion_receipt_id, acceptance_receipt_id),
        FOREIGN KEY (sprint_id, completion_receipt_id)
            REFERENCES v9_completion_receipts(sprint_id, receipt_id) ON DELETE RESTRICT,
        FOREIGN KEY (sprint_id, acceptance_receipt_id)
            REFERENCES acceptance_receipts(sprint_id, receipt_id) ON DELETE RESTRICT
    ) STRICT, WITHOUT ROWID;

    CREATE TABLE sprint_completion_proof_states (
        sprint_id TEXT PRIMARY KEY NOT NULL,
        proof_state TEXT NOT NULL CHECK (
            proof_state IN ('LegacyCompletionUnproven', 'ProvenV9')
        ),
        completion_receipt_id TEXT NOT NULL UNIQUE,
        completion_event_id TEXT NOT NULL UNIQUE,
        contract_version INTEGER NOT NULL CHECK (contract_version > 0),
        terminal_at_unix_ms INTEGER NOT NULL CHECK (terminal_at_unix_ms > 0),
        FOREIGN KEY (sprint_id) REFERENCES sprints(sprint_id) ON DELETE RESTRICT,
        FOREIGN KEY (completion_event_id)
            REFERENCES agent_events(event_id) ON DELETE RESTRICT
    ) STRICT, WITHOUT ROWID;

    INSERT INTO sprint_completion_proof_states (
        sprint_id, proof_state, completion_receipt_id, completion_event_id,
        contract_version, terminal_at_unix_ms
    )
    SELECT sprint_id, 'LegacyCompletionUnproven', completion_receipt_id,
           completion_event_id, contract_version, terminal_at_unix_ms
    FROM sprint_terminal_states;

    CREATE TRIGGER sprint_completion_proof_states_no_legacy_insert
    BEFORE INSERT ON sprint_completion_proof_states
    WHEN NEW.proof_state = 'LegacyCompletionUnproven'
    BEGIN SELECT RAISE(ABORT, 'legacy completion proof markers are migration-only'); END;
    CREATE TRIGGER terminal_cleanup_proofs_no_legacy_insert
    BEFORE INSERT ON terminal_cleanup_proofs
    WHEN NEW.proof_kind = 'LegacyCleanupUnproven'
    BEGIN SELECT RAISE(ABORT, 'legacy cleanup proof markers are migration-only'); END;

    CREATE TRIGGER non_success_terminal_requires_cleanup_proof
    AFTER INSERT ON sprint_non_success_terminal_outcomes
    WHEN NOT EXISTS (
        SELECT 1 FROM terminal_cleanup_proofs proof
        WHERE proof.sprint_id = NEW.sprint_id
          AND (
              (NEW.terminal_state = 'Unknown'
               AND proof.proof_kind = 'UnknownNoProof')
              OR
              (NEW.terminal_state IN ('Failed', 'Canceled')
               AND proof.proof_kind IN ('LiveWorkspaceUnchanged', 'Rollback'))
              OR
              (NEW.terminal_state = 'Blocked'
               AND proof.proof_kind IN (
                   'LiveWorkspaceUnchanged', 'Rollback', 'LiveConflict'
               ))
          )
    )
    BEGIN SELECT RAISE(ABORT, 'terminal state requires its exact cleanup proof'); END;

    CREATE TRIGGER successful_finish_observations_require_receipt
    AFTER INSERT ON effect_observations
    WHEN NEW.outcome = 'Succeeded' AND EXISTS (
        SELECT 1 FROM finish_effect_kinds kind
        WHERE kind.effect_id = NEW.effect_id
    ) AND NOT EXISTS (
        SELECT 1
        FROM finish_effect_kinds kind
        WHERE kind.effect_id = NEW.effect_id
          AND kind.sprint_id = NEW.sprint_id
          AND (
              (kind.effect_kind = 'IntegrateChangeSet' AND EXISTS (
                  SELECT 1 FROM task_integration_receipts receipt
                  WHERE receipt.effect_id = NEW.effect_id
                    AND receipt.observation_id = NEW.observation_id
                    AND receipt.sprint_id = NEW.sprint_id
                    AND receipt.worker_policy_hash = NEW.policy_hash
                    AND receipt.input_snapshot = NEW.input_snapshot
                    AND receipt.integrated_at_unix_ms = NEW.observed_at_unix_ms
              ))
              OR
              (kind.effect_kind = 'ApplyChangeSet' AND EXISTS (
                  SELECT 1 FROM application_receipts receipt
                  WHERE receipt.effect_id = NEW.effect_id
                    AND receipt.observation_id = NEW.observation_id
                    AND receipt.sprint_id = NEW.sprint_id
                    AND receipt.policy_hash = NEW.policy_hash
                    AND receipt.base_snapshot = NEW.input_snapshot
                    AND receipt.applied_at_unix_ms = NEW.observed_at_unix_ms
              ))
              OR
              (kind.effect_kind = 'CleanupWorkerDomain' AND EXISTS (
                  SELECT 1 FROM worker_cleanup_receipts receipt
                  WHERE receipt.effect_id = NEW.effect_id
                    AND receipt.observation_id = NEW.observation_id
                    AND receipt.sprint_id = NEW.sprint_id
                    AND receipt.policy_hash = NEW.policy_hash
                    AND receipt.cleaned_at_unix_ms = NEW.observed_at_unix_ms
              ))
              OR
              (kind.effect_kind = 'RollbackChangeSet' AND EXISTS (
                  SELECT 1 FROM rollback_receipts receipt
                  WHERE receipt.effect_id = NEW.effect_id
                    AND receipt.observation_id = NEW.observation_id
                    AND receipt.sprint_id = NEW.sprint_id
                    AND receipt.completed_at_unix_ms = NEW.observed_at_unix_ms
              ))
          )
    )
    BEGIN SELECT RAISE(ABORT, 'successful finish effect requires atomic typed receipt'); END;

    CREATE TRIGGER sprint_completion_proof_states_references_match
    BEFORE INSERT ON sprint_completion_proof_states
    WHEN NEW.proof_state = 'ProvenV9' AND (
        NOT EXISTS (
            SELECT 1 FROM v9_completion_receipts receipt
            WHERE receipt.receipt_id = NEW.completion_receipt_id
              AND receipt.sprint_id = NEW.sprint_id
              AND receipt.contract_version = NEW.contract_version
              AND receipt.completed_at_unix_ms = NEW.terminal_at_unix_ms
        )
        OR NOT EXISTS (
            SELECT 1 FROM agent_events event
            WHERE event.event_id = NEW.completion_event_id
              AND event.sprint_id = NEW.sprint_id
              AND event.contract_version = NEW.contract_version
              AND event.occurred_at_unix_ms = NEW.terminal_at_unix_ms
        )
        OR EXISTS (
            SELECT 1 FROM sprint_non_success_terminal_outcomes outcome
            WHERE outcome.sprint_id = NEW.sprint_id
        )
        OR EXISTS (
            SELECT 1 FROM sprint_terminal_states legacy
            WHERE legacy.sprint_id = NEW.sprint_id
        )
        OR EXISTS (
            SELECT 1 FROM legacy_finish_receipt_gaps gap
            WHERE gap.sprint_id = NEW.sprint_id
        )
        OR EXISTS (
            SELECT 1
            FROM effect_intents intent
            LEFT JOIN effect_request_payloads request
              ON request.effect_id = intent.effect_id
            LEFT JOIN effect_observations observation
              ON observation.effect_id = intent.effect_id
            LEFT JOIN effect_evidence_payloads evidence
              ON evidence.effect_id = intent.effect_id
            LEFT JOIN unresolved_mutation_effects mutation
              ON mutation.effect_id = intent.effect_id
            WHERE intent.sprint_id = NEW.sprint_id
              AND (
                  request.effect_id IS NULL
                  OR observation.effect_id IS NULL
                  OR observation.outcome = 'Unknown'
                  OR evidence.effect_id IS NULL
                  OR mutation.effect_id IS NOT NULL
              )
        )
    )
    BEGIN SELECT RAISE(ABORT, 'proven completion requires the exact durable chain'); END;

    CREATE TRIGGER sprint_non_success_v9_completion_conflict
    BEFORE INSERT ON sprint_non_success_terminal_outcomes
    WHEN EXISTS (
        SELECT 1 FROM sprint_completion_proof_states proof
        WHERE proof.sprint_id = NEW.sprint_id
    )
    BEGIN SELECT RAISE(ABORT, 'sprint already has completion proof state'); END;

    CREATE TRIGGER sprint_completion_proof_states_no_update
    BEFORE UPDATE ON sprint_completion_proof_states
    BEGIN SELECT RAISE(ABORT, 'completion proof states are immutable'); END;
    CREATE TRIGGER sprint_completion_proof_states_no_delete
    BEFORE DELETE ON sprint_completion_proof_states
    BEGIN SELECT RAISE(ABORT, 'completion proof states are immutable'); END;
    CREATE TRIGGER terminal_cleanup_proofs_no_update
    BEFORE UPDATE ON terminal_cleanup_proofs
    BEGIN SELECT RAISE(ABORT, 'terminal cleanup proofs are immutable'); END;
    CREATE TRIGGER terminal_cleanup_proofs_no_delete
    BEFORE DELETE ON terminal_cleanup_proofs
    BEGIN SELECT RAISE(ABORT, 'terminal cleanup proofs are immutable'); END;

    CREATE TRIGGER application_receipts_no_update BEFORE UPDATE ON application_receipts
    BEGIN SELECT RAISE(ABORT, 'application receipts are immutable'); END;
    CREATE TRIGGER application_receipts_no_delete BEFORE DELETE ON application_receipts
    BEGIN SELECT RAISE(ABORT, 'application receipts are immutable'); END;
    CREATE TRIGGER runner_launch_intents_no_update BEFORE UPDATE ON runner_launch_intents
    BEGIN SELECT RAISE(ABORT, 'runner launch intents are immutable'); END;
    CREATE TRIGGER runner_launch_intents_no_delete BEFORE DELETE ON runner_launch_intents
    BEGIN SELECT RAISE(ABORT, 'runner launch intents are immutable'); END;
    CREATE TRIGGER runner_session_policies_no_update BEFORE UPDATE ON runner_session_policies
    BEGIN SELECT RAISE(ABORT, 'runner session policies are immutable'); END;
    CREATE TRIGGER runner_session_policies_no_delete BEFORE DELETE ON runner_session_policies
    BEGIN SELECT RAISE(ABORT, 'runner session policies are immutable'); END;
    CREATE TRIGGER verification_session_bindings_no_update
    BEFORE UPDATE ON verification_session_bindings
    BEGIN SELECT RAISE(ABORT, 'verification session bindings are immutable'); END;
    CREATE TRIGGER verification_session_bindings_no_delete
    BEFORE DELETE ON verification_session_bindings
    BEGIN SELECT RAISE(ABORT, 'verification session bindings are immutable'); END;
    CREATE TRIGGER verification_effect_evidence_no_update
    BEFORE UPDATE ON verification_effect_evidence
    BEGIN SELECT RAISE(ABORT, 'verification effect evidence is immutable'); END;
    CREATE TRIGGER verification_effect_evidence_no_delete
    BEFORE DELETE ON verification_effect_evidence
    BEGIN SELECT RAISE(ABORT, 'verification effect evidence is immutable'); END;
    CREATE TRIGGER task_integration_receipts_no_update
    BEFORE UPDATE ON task_integration_receipts
    BEGIN SELECT RAISE(ABORT, 'task integration receipts are immutable'); END;
    CREATE TRIGGER task_integration_receipts_no_delete
    BEFORE DELETE ON task_integration_receipts
    BEGIN SELECT RAISE(ABORT, 'task integration receipts are immutable'); END;
    CREATE TRIGGER task_integration_verifications_no_update
    BEFORE UPDATE ON task_integration_verification_receipts
    BEGIN SELECT RAISE(ABORT, 'task integration verification links are immutable'); END;
    CREATE TRIGGER task_integration_verifications_no_delete
    BEFORE DELETE ON task_integration_verification_receipts
    BEGIN SELECT RAISE(ABORT, 'task integration verification links are immutable'); END;
    CREATE TRIGGER effect_session_bindings_no_update BEFORE UPDATE ON effect_session_bindings
    BEGIN SELECT RAISE(ABORT, 'effect session bindings are immutable'); END;
    CREATE TRIGGER effect_session_bindings_no_delete BEFORE DELETE ON effect_session_bindings
    BEGIN SELECT RAISE(ABORT, 'effect session bindings are immutable'); END;
    CREATE TRIGGER worker_cleanup_receipts_no_update BEFORE UPDATE ON worker_cleanup_receipts
    BEGIN SELECT RAISE(ABORT, 'worker cleanup receipts are immutable'); END;
    CREATE TRIGGER worker_cleanup_receipts_no_delete BEFORE DELETE ON worker_cleanup_receipts
    BEGIN SELECT RAISE(ABORT, 'worker cleanup receipts are immutable'); END;
    CREATE TRIGGER rollback_references_no_update BEFORE UPDATE ON rollback_references
    BEGIN SELECT RAISE(ABORT, 'rollback references are immutable'); END;
    CREATE TRIGGER rollback_references_no_delete BEFORE DELETE ON rollback_references
    BEGIN SELECT RAISE(ABORT, 'rollback references are immutable'); END;
    CREATE TRIGGER verified_no_op_receipts_no_update BEFORE UPDATE ON verified_no_op_receipts
    BEGIN SELECT RAISE(ABORT, 'verified no-op receipts are immutable'); END;
    CREATE TRIGGER verified_no_op_receipts_no_delete BEFORE DELETE ON verified_no_op_receipts
    BEGIN SELECT RAISE(ABORT, 'verified no-op receipts are immutable'); END;
    CREATE TRIGGER rollback_receipts_no_update BEFORE UPDATE ON rollback_receipts
    BEGIN SELECT RAISE(ABORT, 'rollback receipts are immutable'); END;
    CREATE TRIGGER rollback_receipts_no_delete BEFORE DELETE ON rollback_receipts
    BEGIN SELECT RAISE(ABORT, 'rollback receipts are immutable'); END;
    CREATE TRIGGER live_workspace_unchanged_receipts_no_update
    BEFORE UPDATE ON live_workspace_unchanged_receipts
    BEGIN SELECT RAISE(ABORT, 'unchanged receipts are immutable'); END;
    CREATE TRIGGER live_workspace_unchanged_receipts_no_delete
    BEFORE DELETE ON live_workspace_unchanged_receipts
    BEGIN SELECT RAISE(ABORT, 'unchanged receipts are immutable'); END;
    CREATE TRIGGER live_conflict_receipts_no_update BEFORE UPDATE ON live_conflict_receipts
    BEGIN SELECT RAISE(ABORT, 'live conflict receipts are immutable'); END;
    CREATE TRIGGER live_conflict_receipts_no_delete BEFORE DELETE ON live_conflict_receipts
    BEGIN SELECT RAISE(ABORT, 'live conflict receipts are immutable'); END;
    CREATE TRIGGER v9_completion_receipts_no_update BEFORE UPDATE ON v9_completion_receipts
    BEGIN SELECT RAISE(ABORT, 'v9 completion receipts are immutable'); END;
    CREATE TRIGGER v9_completion_receipts_no_delete BEFORE DELETE ON v9_completion_receipts
    BEGIN SELECT RAISE(ABORT, 'v9 completion receipts are immutable'); END;
    CREATE TRIGGER v9_completion_cleanup_no_update
    BEFORE UPDATE ON v9_completion_cleanup_receipts
    BEGIN SELECT RAISE(ABORT, 'v9 completion cleanup links are immutable'); END;
    CREATE TRIGGER v9_completion_cleanup_no_delete
    BEFORE DELETE ON v9_completion_cleanup_receipts
    BEGIN SELECT RAISE(ABORT, 'v9 completion cleanup links are immutable'); END;
    CREATE TRIGGER v9_completion_verification_no_update
    BEFORE UPDATE ON v9_completion_verification_receipts
    BEGIN SELECT RAISE(ABORT, 'v9 completion verification links are immutable'); END;
    CREATE TRIGGER v9_completion_verification_no_delete
    BEFORE DELETE ON v9_completion_verification_receipts
    BEGIN SELECT RAISE(ABORT, 'v9 completion verification links are immutable'); END;
    CREATE TRIGGER v9_completion_task_integration_no_update
    BEFORE UPDATE ON v9_completion_task_integration_receipts
    BEGIN SELECT RAISE(ABORT, 'v9 completion task-integration links are immutable'); END;
    CREATE TRIGGER v9_completion_task_integration_no_delete
    BEFORE DELETE ON v9_completion_task_integration_receipts
    BEGIN SELECT RAISE(ABORT, 'v9 completion task-integration links are immutable'); END;
    CREATE TRIGGER v9_completion_acceptance_no_update
    BEFORE UPDATE ON v9_completion_acceptance_receipts
    BEGIN SELECT RAISE(ABORT, 'v9 completion acceptance links are immutable'); END;
    CREATE TRIGGER v9_completion_acceptance_no_delete
    BEFORE DELETE ON v9_completion_acceptance_receipts
    BEGIN SELECT RAISE(ABORT, 'v9 completion acceptance links are immutable'); END;

    CREATE TRIGGER agent_events_v9_completion_fence BEFORE INSERT ON agent_events
    WHEN EXISTS (
        SELECT 1 FROM sprint_completion_proof_states WHERE sprint_id = NEW.sprint_id
    )
    BEGIN SELECT RAISE(ABORT, 'terminal sprints reject new events'); END;
    CREATE TRIGGER workspace_snapshots_v9_completion_fence BEFORE INSERT ON workspace_snapshots
    WHEN EXISTS (
        SELECT 1 FROM sprint_completion_proof_states WHERE sprint_id = NEW.sprint_id
    )
    BEGIN SELECT RAISE(ABORT, 'terminal sprints reject new snapshots'); END;
    CREATE TRIGGER change_sets_v9_completion_fence BEFORE INSERT ON change_sets
    WHEN EXISTS (
        SELECT 1 FROM sprint_completion_proof_states WHERE sprint_id = NEW.sprint_id
    )
    BEGIN SELECT RAISE(ABORT, 'terminal sprints reject new change sets'); END;
    CREATE TRIGGER verification_receipts_v9_completion_fence
    BEFORE INSERT ON verification_receipts
    WHEN EXISTS (
        SELECT 1 FROM sprint_completion_proof_states WHERE sprint_id = NEW.sprint_id
    )
    BEGIN SELECT RAISE(ABORT, 'terminal sprints reject new verification receipts'); END;
    CREATE TRIGGER acceptance_receipts_v9_completion_fence
    BEFORE INSERT ON acceptance_receipts
    WHEN EXISTS (
        SELECT 1 FROM sprint_completion_proof_states WHERE sprint_id = NEW.sprint_id
    )
    BEGIN SELECT RAISE(ABORT, 'terminal sprints reject new acceptance receipts'); END;
    CREATE TRIGGER runner_session_policies_v9_completion_fence
    BEFORE INSERT ON runner_session_policies
    WHEN EXISTS (
        SELECT 1 FROM sprint_completion_proof_states WHERE sprint_id = NEW.sprint_id
    ) OR EXISTS (
        SELECT 1 FROM sprint_non_success_terminal_outcomes WHERE sprint_id = NEW.sprint_id
    ) OR EXISTS (
        SELECT 1 FROM sprint_terminal_states WHERE sprint_id = NEW.sprint_id
    )
    BEGIN SELECT RAISE(ABORT, 'terminal sprints reject runner sessions'); END;
    CREATE TRIGGER runner_launch_intents_v9_completion_fence
    BEFORE INSERT ON runner_launch_intents
    WHEN EXISTS (
        SELECT 1 FROM sprint_completion_proof_states WHERE sprint_id = NEW.sprint_id
    ) OR EXISTS (
        SELECT 1 FROM sprint_non_success_terminal_outcomes WHERE sprint_id = NEW.sprint_id
    ) OR EXISTS (
        SELECT 1 FROM sprint_terminal_states WHERE sprint_id = NEW.sprint_id
    )
    BEGIN SELECT RAISE(ABORT, 'terminal sprints reject runner launch attempts'); END;
    CREATE TRIGGER verification_session_bindings_v9_completion_fence
    BEFORE INSERT ON verification_session_bindings
    WHEN EXISTS (
        SELECT 1 FROM sprint_completion_proof_states WHERE sprint_id = NEW.sprint_id
    ) OR EXISTS (
        SELECT 1 FROM sprint_non_success_terminal_outcomes WHERE sprint_id = NEW.sprint_id
    ) OR EXISTS (
        SELECT 1 FROM sprint_terminal_states WHERE sprint_id = NEW.sprint_id
    )
    BEGIN SELECT RAISE(ABORT, 'terminal sprints reject verification bindings'); END;
    CREATE TRIGGER verification_effect_evidence_terminal_fence
    BEFORE INSERT ON verification_effect_evidence
    WHEN EXISTS (
        SELECT 1 FROM sprint_completion_proof_states WHERE sprint_id = NEW.sprint_id
    ) OR EXISTS (
        SELECT 1 FROM sprint_non_success_terminal_outcomes WHERE sprint_id = NEW.sprint_id
    ) OR EXISTS (
        SELECT 1 FROM sprint_terminal_states WHERE sprint_id = NEW.sprint_id
    )
    BEGIN SELECT RAISE(ABORT, 'terminal sprints reject verification effect evidence'); END;
    CREATE TRIGGER task_integration_receipts_terminal_fence
    BEFORE INSERT ON task_integration_receipts
    WHEN EXISTS (
        SELECT 1 FROM sprint_completion_proof_states WHERE sprint_id = NEW.sprint_id
    ) OR EXISTS (
        SELECT 1 FROM sprint_non_success_terminal_outcomes WHERE sprint_id = NEW.sprint_id
    ) OR EXISTS (
        SELECT 1 FROM sprint_terminal_states WHERE sprint_id = NEW.sprint_id
    )
    BEGIN SELECT RAISE(ABORT, 'terminal sprints reject task integration receipts'); END;
    CREATE TRIGGER task_integration_verifications_terminal_fence
    BEFORE INSERT ON task_integration_verification_receipts
    WHEN EXISTS (
        SELECT 1 FROM sprint_completion_proof_states WHERE sprint_id = NEW.sprint_id
    ) OR EXISTS (
        SELECT 1 FROM sprint_non_success_terminal_outcomes WHERE sprint_id = NEW.sprint_id
    ) OR EXISTS (
        SELECT 1 FROM sprint_terminal_states WHERE sprint_id = NEW.sprint_id
    )
    BEGIN SELECT RAISE(ABORT, 'terminal sprints reject task integration verification links'); END;
    CREATE TRIGGER effect_session_bindings_v9_completion_fence
    BEFORE INSERT ON effect_session_bindings
    WHEN EXISTS (
        SELECT 1 FROM sprint_completion_proof_states WHERE sprint_id = NEW.sprint_id
    ) OR EXISTS (
        SELECT 1 FROM sprint_non_success_terminal_outcomes WHERE sprint_id = NEW.sprint_id
    ) OR EXISTS (
        SELECT 1 FROM sprint_terminal_states WHERE sprint_id = NEW.sprint_id
    )
    BEGIN SELECT RAISE(ABORT, 'terminal sprints reject effect session bindings'); END;
    CREATE TRIGGER final_reports_v9_completion_fence BEFORE INSERT ON final_reports
    WHEN EXISTS (
        SELECT 1 FROM sprint_completion_proof_states WHERE sprint_id = NEW.sprint_id
    )
    BEGIN SELECT RAISE(ABORT, 'terminal sprints reject new final reports'); END;
    CREATE TRIGGER effect_request_payloads_v9_completion_fence
    BEFORE INSERT ON effect_request_payloads
    WHEN EXISTS (
        SELECT 1 FROM sprint_completion_proof_states WHERE sprint_id = NEW.sprint_id
    )
    BEGIN SELECT RAISE(ABORT, 'terminal sprints reject new effect request bytes'); END;
    CREATE TRIGGER effect_intents_v9_completion_fence BEFORE INSERT ON effect_intents
    WHEN EXISTS (
        SELECT 1 FROM sprint_completion_proof_states WHERE sprint_id = NEW.sprint_id
    )
    BEGIN SELECT RAISE(ABORT, 'terminal sprints reject new effect intents'); END;
    CREATE TRIGGER effect_evidence_payloads_v9_completion_fence
    BEFORE INSERT ON effect_evidence_payloads
    WHEN EXISTS (
        SELECT 1 FROM sprint_completion_proof_states WHERE sprint_id = NEW.sprint_id
    )
    BEGIN SELECT RAISE(ABORT, 'terminal sprints reject new effect evidence bytes'); END;
    CREATE TRIGGER effect_observations_v9_completion_fence
    BEFORE INSERT ON effect_observations
    WHEN EXISTS (
        SELECT 1 FROM sprint_completion_proof_states WHERE sprint_id = NEW.sprint_id
    )
    BEGIN SELECT RAISE(ABORT, 'terminal sprints reject new effect observations'); END;
    CREATE TRIGGER mutation_artifact_links_v9_completion_fence
    BEFORE INSERT ON mutation_artifact_links
    WHEN EXISTS (
        SELECT 1 FROM sprint_completion_proof_states WHERE sprint_id = NEW.sprint_id
    )
    BEGIN SELECT RAISE(ABORT, 'terminal sprints reject mutation links'); END;
    CREATE TRIGGER sprint_task_graphs_v9_completion_fence BEFORE INSERT ON sprint_task_graphs
    WHEN EXISTS (
        SELECT 1 FROM sprint_completion_proof_states WHERE sprint_id = NEW.sprint_id
    )
    BEGIN SELECT RAISE(ABORT, 'terminal sprints reject task graphs'); END;
    CREATE TRIGGER sprint_graph_provenance_v9_completion_fence
    BEFORE INSERT ON sprint_graph_provenance
    WHEN EXISTS (
        SELECT 1 FROM sprint_completion_proof_states WHERE sprint_id = NEW.sprint_id
    )
    BEGIN SELECT RAISE(ABORT, 'terminal sprints reject graph provenance'); END;

    CREATE TRIGGER finish_effect_kinds_terminal_fence BEFORE INSERT ON finish_effect_kinds
    WHEN EXISTS (
        SELECT 1 FROM sprint_completion_proof_states WHERE sprint_id = NEW.sprint_id
    ) OR EXISTS (
        SELECT 1 FROM sprint_non_success_terminal_outcomes WHERE sprint_id = NEW.sprint_id
    ) OR EXISTS (
        SELECT 1 FROM sprint_terminal_states WHERE sprint_id = NEW.sprint_id
    )
    BEGIN SELECT RAISE(ABORT, 'terminal sprints reject finish effect kinds'); END;
    CREATE TRIGGER finish_receipt_ids_terminal_fence BEFORE INSERT ON finish_receipt_ids
    WHEN EXISTS (
        SELECT 1 FROM sprint_completion_proof_states WHERE sprint_id = NEW.sprint_id
    ) OR EXISTS (
        SELECT 1 FROM sprint_non_success_terminal_outcomes WHERE sprint_id = NEW.sprint_id
    ) OR EXISTS (
        SELECT 1 FROM sprint_terminal_states WHERE sprint_id = NEW.sprint_id
    )
    BEGIN SELECT RAISE(ABORT, 'terminal sprints reject finish receipts'); END;

    CREATE TRIGGER legacy_finish_agent_events_fence
    BEFORE INSERT ON agent_events
    WHEN EXISTS (
        SELECT 1 FROM legacy_finish_receipt_gaps
        WHERE sprint_id = NEW.sprint_id
    ) AND NOT EXISTS (
        SELECT 1 FROM sprint_non_success_terminal_outcomes outcome
        WHERE outcome.sprint_id = NEW.sprint_id
          AND outcome.terminal_state = 'Unknown'
          AND outcome.terminal_event_id = NEW.event_id
    )
    BEGIN SELECT RAISE(ABORT, 'legacy-unproven finish effects reject new work'); END;
    CREATE TRIGGER legacy_finish_workspace_snapshots_fence
    BEFORE INSERT ON workspace_snapshots
    WHEN EXISTS (
        SELECT 1 FROM legacy_finish_receipt_gaps WHERE sprint_id = NEW.sprint_id
    )
    BEGIN SELECT RAISE(ABORT, 'legacy-unproven finish effects reject new work'); END;
    CREATE TRIGGER legacy_finish_change_sets_fence
    BEFORE INSERT ON change_sets
    WHEN EXISTS (
        SELECT 1 FROM legacy_finish_receipt_gaps WHERE sprint_id = NEW.sprint_id
    )
    BEGIN SELECT RAISE(ABORT, 'legacy-unproven finish effects reject new work'); END;
    CREATE TRIGGER legacy_finish_verification_receipts_fence
    BEFORE INSERT ON verification_receipts
    WHEN EXISTS (
        SELECT 1 FROM legacy_finish_receipt_gaps WHERE sprint_id = NEW.sprint_id
    )
    BEGIN SELECT RAISE(ABORT, 'legacy-unproven finish effects reject new work'); END;
    CREATE TRIGGER legacy_finish_acceptance_receipts_fence
    BEFORE INSERT ON acceptance_receipts
    WHEN EXISTS (
        SELECT 1 FROM legacy_finish_receipt_gaps WHERE sprint_id = NEW.sprint_id
    )
    BEGIN SELECT RAISE(ABORT, 'legacy-unproven finish effects reject new work'); END;
    CREATE TRIGGER legacy_finish_final_reports_fence
    BEFORE INSERT ON final_reports
    WHEN EXISTS (
        SELECT 1 FROM legacy_finish_receipt_gaps WHERE sprint_id = NEW.sprint_id
    )
    BEGIN SELECT RAISE(ABORT, 'legacy-unproven finish effects reject new work'); END;
    CREATE TRIGGER legacy_finish_completion_receipts_fence
    BEFORE INSERT ON completion_receipts
    WHEN EXISTS (
        SELECT 1 FROM legacy_finish_receipt_gaps WHERE sprint_id = NEW.sprint_id
    )
    BEGIN SELECT RAISE(ABORT, 'legacy-unproven finish effects reject new work'); END;
    CREATE TRIGGER legacy_finish_v9_completion_receipts_fence
    BEFORE INSERT ON v9_completion_receipts
    WHEN EXISTS (
        SELECT 1 FROM legacy_finish_receipt_gaps WHERE sprint_id = NEW.sprint_id
    )
    BEGIN SELECT RAISE(ABORT, 'legacy-unproven finish effects reject v9 completion'); END;
    CREATE TRIGGER legacy_finish_completion_proof_fence
    BEFORE INSERT ON sprint_completion_proof_states
    WHEN EXISTS (
        SELECT 1 FROM legacy_finish_receipt_gaps WHERE sprint_id = NEW.sprint_id
    )
    BEGIN SELECT RAISE(ABORT, 'legacy-unproven finish effects reject v9 completion'); END;
    CREATE TRIGGER legacy_finish_effect_requests_fence
    BEFORE INSERT ON effect_request_payloads
    WHEN EXISTS (
        SELECT 1 FROM legacy_finish_receipt_gaps WHERE sprint_id = NEW.sprint_id
    )
    BEGIN SELECT RAISE(ABORT, 'legacy-unproven finish effects reject new work'); END;
    CREATE TRIGGER legacy_finish_effect_intents_fence
    BEFORE INSERT ON effect_intents
    WHEN EXISTS (
        SELECT 1 FROM legacy_finish_receipt_gaps WHERE sprint_id = NEW.sprint_id
    )
    BEGIN SELECT RAISE(ABORT, 'legacy-unproven finish effects reject new work'); END;
    CREATE TRIGGER legacy_finish_effect_evidence_fence
    BEFORE INSERT ON effect_evidence_payloads
    WHEN EXISTS (
        SELECT 1 FROM legacy_finish_receipt_gaps WHERE sprint_id = NEW.sprint_id
    )
    BEGIN SELECT RAISE(ABORT, 'legacy-unproven finish effects reject new work'); END;
    CREATE TRIGGER legacy_finish_effect_observations_fence
    BEFORE INSERT ON effect_observations
    WHEN EXISTS (
        SELECT 1 FROM legacy_finish_receipt_gaps WHERE sprint_id = NEW.sprint_id
    )
    BEGIN SELECT RAISE(ABORT, 'legacy-unproven finish effects reject new work'); END;
    CREATE TRIGGER legacy_finish_runner_launches_fence
    BEFORE INSERT ON runner_launch_intents
    WHEN EXISTS (
        SELECT 1 FROM legacy_finish_receipt_gaps WHERE sprint_id = NEW.sprint_id
    )
    BEGIN SELECT RAISE(ABORT, 'legacy-unproven finish effects reject new work'); END;
    CREATE TRIGGER legacy_finish_runner_sessions_fence
    BEFORE INSERT ON runner_session_policies
    WHEN EXISTS (
        SELECT 1 FROM legacy_finish_receipt_gaps WHERE sprint_id = NEW.sprint_id
    )
    BEGIN SELECT RAISE(ABORT, 'legacy-unproven finish effects reject new work'); END;
    CREATE TRIGGER legacy_finish_effect_bindings_fence
    BEFORE INSERT ON effect_session_bindings
    WHEN EXISTS (
        SELECT 1 FROM legacy_finish_receipt_gaps WHERE sprint_id = NEW.sprint_id
    )
    BEGIN SELECT RAISE(ABORT, 'legacy-unproven finish effects reject new work'); END;
    CREATE TRIGGER legacy_finish_receipt_ids_fence
    BEFORE INSERT ON finish_receipt_ids
    WHEN EXISTS (
        SELECT 1 FROM legacy_finish_receipt_gaps WHERE sprint_id = NEW.sprint_id
    )
    BEGIN SELECT RAISE(ABORT, 'legacy-unproven finish effects reject receipt backfill'); END;
    CREATE TRIGGER legacy_finish_terminal_states_fence
    BEFORE INSERT ON sprint_terminal_states
    WHEN EXISTS (
        SELECT 1 FROM legacy_finish_receipt_gaps WHERE sprint_id = NEW.sprint_id
    )
    BEGIN SELECT RAISE(ABORT, 'legacy-unproven finish effects reject successful terminalization'); END;
    CREATE TRIGGER legacy_finish_known_terminal_fence
    BEFORE INSERT ON sprint_non_success_terminal_outcomes
    WHEN NEW.terminal_state != 'Unknown' AND EXISTS (
        SELECT 1 FROM legacy_finish_receipt_gaps WHERE sprint_id = NEW.sprint_id
    )
    BEGIN SELECT RAISE(ABORT, 'legacy-unproven finish effects permit only Unknown'); END;

    DROP TRIGGER sprint_non_success_terminal_outcomes_unknown_effect_fence;
    CREATE TRIGGER sprint_non_success_terminal_outcomes_unknown_effect_fence
    BEFORE INSERT ON sprint_non_success_terminal_outcomes
    WHEN NEW.terminal_state = 'Unknown' AND (
        (
            NOT EXISTS (
                SELECT 1
                FROM effect_intents intent
                LEFT JOIN effect_observations observation
                  ON observation.effect_id = intent.effect_id
                LEFT JOIN unresolved_mutation_effects mutation
                  ON mutation.effect_id = intent.effect_id
                WHERE intent.sprint_id = NEW.sprint_id
                  AND (
                      observation.effect_id IS NULL
                      OR observation.outcome = 'Unknown'
                      OR mutation.effect_id IS NOT NULL
                  )
            )
            AND NOT EXISTS (
                SELECT 1 FROM legacy_finish_receipt_gaps
                WHERE sprint_id = NEW.sprint_id
            )
        )
        OR EXISTS (
            SELECT 1
            FROM effect_intents intent
            LEFT JOIN effect_request_payloads request
              ON request.effect_id = intent.effect_id
            WHERE intent.sprint_id = NEW.sprint_id
              AND request.effect_id IS NULL
        )
        OR EXISTS (
            SELECT 1
            FROM effect_intents intent
            JOIN effect_observations observation
              ON observation.effect_id = intent.effect_id
            LEFT JOIN effect_evidence_payloads evidence
              ON evidence.effect_id = intent.effect_id
            WHERE intent.sprint_id = NEW.sprint_id
              AND evidence.effect_id IS NULL
        )
    )
    BEGIN
        SELECT RAISE(ABORT, 'Unknown requires exact durable unresolved effect evidence');
    END;
";
