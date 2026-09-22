//! Ledger schema migrations v1 through v8 (raw SQL, moved verbatim from
//! the inline `MIGRATIONS` array).

pub(super) const MIGRATION_V1: &str = r"
    CREATE TABLE sprints (
        sprint_id TEXT PRIMARY KEY NOT NULL,
        contract_version INTEGER NOT NULL CHECK (contract_version > 0),
        spec_json BLOB NOT NULL,
        graph_json BLOB NOT NULL,
        created_at_unix_ms INTEGER NOT NULL CHECK (created_at_unix_ms > 0)
    ) STRICT;

    CREATE TABLE agent_events (
        sprint_id TEXT NOT NULL,
        sequence INTEGER NOT NULL CHECK (sequence > 0),
        event_id TEXT NOT NULL UNIQUE,
        contract_version INTEGER NOT NULL CHECK (contract_version > 0),
        occurred_at_unix_ms INTEGER NOT NULL CHECK (occurred_at_unix_ms > 0),
        event_json BLOB NOT NULL,
        PRIMARY KEY (sprint_id, sequence),
        FOREIGN KEY (sprint_id) REFERENCES sprints(sprint_id) ON DELETE RESTRICT
    ) STRICT, WITHOUT ROWID;

    CREATE TRIGGER agent_events_monotonic_sequence
    BEFORE INSERT ON agent_events
    WHEN NEW.sequence != COALESCE(
        (SELECT MAX(sequence) + 1 FROM agent_events WHERE sprint_id = NEW.sprint_id),
        1
    )
    BEGIN
        SELECT RAISE(ABORT, 'event sequence must be the next monotonic value');
    END;

    CREATE TRIGGER agent_events_no_update
    BEFORE UPDATE ON agent_events
    BEGIN
        SELECT RAISE(ABORT, 'agent events are append-only');
    END;

    CREATE TRIGGER agent_events_no_delete
    BEFORE DELETE ON agent_events
    BEGIN
        SELECT RAISE(ABORT, 'agent events are append-only');
    END;

    CREATE TRIGGER sprints_no_update
    BEFORE UPDATE ON sprints
    BEGIN
        SELECT RAISE(ABORT, 'sprint inputs are immutable');
    END;

    CREATE TRIGGER sprints_no_delete
    BEFORE DELETE ON sprints
    BEGIN
        SELECT RAISE(ABORT, 'persisted sprints cannot be deleted');
    END;
";

pub(super) const MIGRATION_V2: &str = r"
    CREATE TABLE workspace_snapshots (
        sprint_id TEXT NOT NULL,
        snapshot_id TEXT NOT NULL,
        grant_hash TEXT NOT NULL,
        contract_version INTEGER NOT NULL CHECK (contract_version > 0),
        created_at_unix_ms INTEGER NOT NULL CHECK (created_at_unix_ms > 0),
        snapshot_json BLOB NOT NULL,
        PRIMARY KEY (sprint_id, snapshot_id),
        FOREIGN KEY (sprint_id) REFERENCES sprints(sprint_id) ON DELETE RESTRICT
    ) STRICT, WITHOUT ROWID;

    CREATE INDEX workspace_snapshots_grant_idx
    ON workspace_snapshots (sprint_id, grant_hash);

    CREATE TABLE change_sets (
        sprint_id TEXT NOT NULL,
        change_set_id TEXT NOT NULL,
        base_snapshot TEXT NOT NULL,
        result_snapshot TEXT NOT NULL,
        contract_version INTEGER NOT NULL CHECK (contract_version > 0),
        change_set_json BLOB NOT NULL,
        PRIMARY KEY (sprint_id, change_set_id),
        FOREIGN KEY (sprint_id) REFERENCES sprints(sprint_id) ON DELETE RESTRICT,
        FOREIGN KEY (sprint_id, base_snapshot)
            REFERENCES workspace_snapshots(sprint_id, snapshot_id) ON DELETE RESTRICT,
        FOREIGN KEY (sprint_id, result_snapshot)
            REFERENCES workspace_snapshots(sprint_id, snapshot_id) ON DELETE RESTRICT
    ) STRICT, WITHOUT ROWID;

    CREATE INDEX change_sets_snapshots_idx
    ON change_sets (sprint_id, base_snapshot, result_snapshot);

    CREATE TABLE verification_receipts (
        receipt_id TEXT PRIMARY KEY NOT NULL,
        sprint_id TEXT NOT NULL,
        snapshot_id TEXT NOT NULL,
        passed INTEGER NOT NULL CHECK (passed IN (0, 1)),
        contract_version INTEGER NOT NULL CHECK (contract_version > 0),
        finished_at_unix_ms INTEGER NOT NULL CHECK (finished_at_unix_ms > 0),
        receipt_json BLOB NOT NULL,
        UNIQUE (sprint_id, receipt_id),
        FOREIGN KEY (sprint_id) REFERENCES sprints(sprint_id) ON DELETE RESTRICT,
        FOREIGN KEY (sprint_id, snapshot_id)
            REFERENCES workspace_snapshots(sprint_id, snapshot_id) ON DELETE RESTRICT
    ) STRICT;

    CREATE INDEX verification_receipts_snapshot_idx
    ON verification_receipts (sprint_id, snapshot_id, passed);

    CREATE TABLE acceptance_receipts (
        receipt_id TEXT PRIMARY KEY NOT NULL,
        sprint_id TEXT NOT NULL,
        criterion_id TEXT NOT NULL,
        snapshot_id TEXT NOT NULL,
        evidence_kind TEXT NOT NULL
            CHECK (evidence_kind IN ('Automated', 'HumanJudgment')),
        verification_receipt_id TEXT,
        decision_id TEXT UNIQUE,
        contract_version INTEGER NOT NULL CHECK (contract_version > 0),
        accepted_at_unix_ms INTEGER NOT NULL CHECK (accepted_at_unix_ms > 0),
        receipt_json BLOB NOT NULL,
        UNIQUE (sprint_id, receipt_id),
        UNIQUE (sprint_id, criterion_id),
        CHECK (
            (evidence_kind = 'Automated'
             AND verification_receipt_id IS NOT NULL
             AND decision_id IS NULL)
            OR
            (evidence_kind = 'HumanJudgment'
             AND verification_receipt_id IS NULL
             AND decision_id IS NOT NULL)
        ),
        FOREIGN KEY (sprint_id) REFERENCES sprints(sprint_id) ON DELETE RESTRICT,
        FOREIGN KEY (sprint_id, snapshot_id)
            REFERENCES workspace_snapshots(sprint_id, snapshot_id) ON DELETE RESTRICT,
        FOREIGN KEY (verification_receipt_id)
            REFERENCES verification_receipts(receipt_id) ON DELETE RESTRICT
    ) STRICT;

    CREATE INDEX acceptance_receipts_snapshot_idx
    ON acceptance_receipts (sprint_id, snapshot_id, criterion_id);

    CREATE TABLE final_reports (
        report_id TEXT PRIMARY KEY NOT NULL,
        sprint_id TEXT NOT NULL,
        final_snapshot TEXT NOT NULL,
        content_digest TEXT NOT NULL,
        contract_version INTEGER NOT NULL CHECK (contract_version > 0),
        created_at_unix_ms INTEGER NOT NULL CHECK (created_at_unix_ms > 0),
        report_json BLOB NOT NULL,
        UNIQUE (sprint_id, report_id),
        FOREIGN KEY (sprint_id) REFERENCES sprints(sprint_id) ON DELETE RESTRICT,
        FOREIGN KEY (sprint_id, final_snapshot)
            REFERENCES workspace_snapshots(sprint_id, snapshot_id) ON DELETE RESTRICT
    ) STRICT;

    CREATE INDEX final_reports_snapshot_idx
    ON final_reports (sprint_id, final_snapshot);

    CREATE TABLE completion_receipts (
        receipt_id TEXT PRIMARY KEY NOT NULL,
        sprint_id TEXT NOT NULL UNIQUE,
        final_snapshot TEXT NOT NULL,
        rollback_snapshot TEXT NOT NULL,
        final_report_id TEXT NOT NULL UNIQUE,
        provider_backend TEXT NOT NULL,
        provider_model TEXT NOT NULL,
        contract_version INTEGER NOT NULL CHECK (contract_version > 0),
        completed_at_unix_ms INTEGER NOT NULL CHECK (completed_at_unix_ms > 0),
        receipt_json BLOB NOT NULL,
        UNIQUE (sprint_id, receipt_id),
        FOREIGN KEY (sprint_id) REFERENCES sprints(sprint_id) ON DELETE RESTRICT,
        FOREIGN KEY (sprint_id, final_snapshot)
            REFERENCES workspace_snapshots(sprint_id, snapshot_id) ON DELETE RESTRICT,
        FOREIGN KEY (sprint_id, rollback_snapshot)
            REFERENCES workspace_snapshots(sprint_id, snapshot_id) ON DELETE RESTRICT,
        FOREIGN KEY (sprint_id, final_report_id)
            REFERENCES final_reports(sprint_id, report_id) ON DELETE RESTRICT
    ) STRICT;

    CREATE INDEX completion_receipts_snapshots_idx
    ON completion_receipts (sprint_id, final_snapshot, rollback_snapshot);

    CREATE TABLE completion_verification_receipts (
        completion_receipt_id TEXT NOT NULL,
        sprint_id TEXT NOT NULL,
        ordinal INTEGER NOT NULL CHECK (ordinal >= 0),
        verification_receipt_id TEXT NOT NULL,
        PRIMARY KEY (completion_receipt_id, ordinal),
        UNIQUE (completion_receipt_id, verification_receipt_id),
        FOREIGN KEY (sprint_id, completion_receipt_id)
            REFERENCES completion_receipts(sprint_id, receipt_id) ON DELETE RESTRICT,
        FOREIGN KEY (sprint_id, verification_receipt_id)
            REFERENCES verification_receipts(sprint_id, receipt_id) ON DELETE RESTRICT
    ) STRICT, WITHOUT ROWID;

    CREATE INDEX completion_verification_sprint_idx
    ON completion_verification_receipts (sprint_id, verification_receipt_id);

    CREATE TABLE completion_acceptance_receipts (
        completion_receipt_id TEXT NOT NULL,
        sprint_id TEXT NOT NULL,
        ordinal INTEGER NOT NULL CHECK (ordinal >= 0),
        acceptance_receipt_id TEXT NOT NULL,
        PRIMARY KEY (completion_receipt_id, ordinal),
        UNIQUE (completion_receipt_id, acceptance_receipt_id),
        FOREIGN KEY (sprint_id, completion_receipt_id)
            REFERENCES completion_receipts(sprint_id, receipt_id) ON DELETE RESTRICT,
        FOREIGN KEY (sprint_id, acceptance_receipt_id)
            REFERENCES acceptance_receipts(sprint_id, receipt_id) ON DELETE RESTRICT
    ) STRICT, WITHOUT ROWID;

    CREATE INDEX completion_acceptance_sprint_idx
    ON completion_acceptance_receipts (sprint_id, acceptance_receipt_id);

    CREATE TABLE sprint_terminal_states (
        sprint_id TEXT PRIMARY KEY NOT NULL,
        terminal_state TEXT NOT NULL CHECK (terminal_state = 'Completed'),
        completion_receipt_id TEXT NOT NULL UNIQUE,
        completion_event_id TEXT NOT NULL UNIQUE,
        contract_version INTEGER NOT NULL CHECK (contract_version > 0),
        terminal_at_unix_ms INTEGER NOT NULL CHECK (terminal_at_unix_ms > 0),
        FOREIGN KEY (sprint_id) REFERENCES sprints(sprint_id) ON DELETE RESTRICT,
        FOREIGN KEY (completion_receipt_id)
            REFERENCES completion_receipts(receipt_id) ON DELETE RESTRICT,
        FOREIGN KEY (completion_event_id)
            REFERENCES agent_events(event_id) ON DELETE RESTRICT
    ) STRICT, WITHOUT ROWID;

    CREATE TRIGGER sprint_terminal_states_references_match
    BEFORE INSERT ON sprint_terminal_states
    WHEN NOT EXISTS (
        SELECT 1 FROM completion_receipts
        WHERE receipt_id = NEW.completion_receipt_id
          AND sprint_id = NEW.sprint_id
          AND completed_at_unix_ms = NEW.terminal_at_unix_ms
    ) OR NOT EXISTS (
        SELECT 1 FROM agent_events
        WHERE event_id = NEW.completion_event_id
          AND sprint_id = NEW.sprint_id
          AND occurred_at_unix_ms = NEW.terminal_at_unix_ms
    )
    BEGIN
        SELECT RAISE(ABORT, 'terminal references must match sprint and timestamp');
    END;

    CREATE TRIGGER workspace_snapshots_no_update BEFORE UPDATE ON workspace_snapshots
    BEGIN SELECT RAISE(ABORT, 'workspace snapshots are append-only'); END;
    CREATE TRIGGER workspace_snapshots_no_delete BEFORE DELETE ON workspace_snapshots
    BEGIN SELECT RAISE(ABORT, 'workspace snapshots are append-only'); END;
    CREATE TRIGGER change_sets_no_update BEFORE UPDATE ON change_sets
    BEGIN SELECT RAISE(ABORT, 'change sets are append-only'); END;
    CREATE TRIGGER change_sets_no_delete BEFORE DELETE ON change_sets
    BEGIN SELECT RAISE(ABORT, 'change sets are append-only'); END;
    CREATE TRIGGER verification_receipts_no_update BEFORE UPDATE ON verification_receipts
    BEGIN SELECT RAISE(ABORT, 'verification receipts are append-only'); END;
    CREATE TRIGGER verification_receipts_no_delete BEFORE DELETE ON verification_receipts
    BEGIN SELECT RAISE(ABORT, 'verification receipts are append-only'); END;
    CREATE TRIGGER acceptance_receipts_no_update BEFORE UPDATE ON acceptance_receipts
    BEGIN SELECT RAISE(ABORT, 'acceptance receipts are append-only'); END;
    CREATE TRIGGER acceptance_receipts_no_delete BEFORE DELETE ON acceptance_receipts
    BEGIN SELECT RAISE(ABORT, 'acceptance receipts are append-only'); END;
    CREATE TRIGGER final_reports_no_update BEFORE UPDATE ON final_reports
    BEGIN SELECT RAISE(ABORT, 'final reports are append-only'); END;
    CREATE TRIGGER final_reports_no_delete BEFORE DELETE ON final_reports
    BEGIN SELECT RAISE(ABORT, 'final reports are append-only'); END;
    CREATE TRIGGER completion_receipts_no_update BEFORE UPDATE ON completion_receipts
    BEGIN SELECT RAISE(ABORT, 'completion receipts are append-only'); END;
    CREATE TRIGGER completion_receipts_no_delete BEFORE DELETE ON completion_receipts
    BEGIN SELECT RAISE(ABORT, 'completion receipts are append-only'); END;
    CREATE TRIGGER completion_verification_no_update BEFORE UPDATE ON completion_verification_receipts
    BEGIN SELECT RAISE(ABORT, 'completion verification links are append-only'); END;
    CREATE TRIGGER completion_verification_no_delete BEFORE DELETE ON completion_verification_receipts
    BEGIN SELECT RAISE(ABORT, 'completion verification links are append-only'); END;
    CREATE TRIGGER completion_acceptance_no_update BEFORE UPDATE ON completion_acceptance_receipts
    BEGIN SELECT RAISE(ABORT, 'completion acceptance links are append-only'); END;
    CREATE TRIGGER completion_acceptance_no_delete BEFORE DELETE ON completion_acceptance_receipts
    BEGIN SELECT RAISE(ABORT, 'completion acceptance links are append-only'); END;
    CREATE TRIGGER sprint_terminal_states_no_update BEFORE UPDATE ON sprint_terminal_states
    BEGIN SELECT RAISE(ABORT, 'sprint terminal states are immutable'); END;
    CREATE TRIGGER sprint_terminal_states_no_delete BEFORE DELETE ON sprint_terminal_states
    BEGIN SELECT RAISE(ABORT, 'sprint terminal states are immutable'); END;

    CREATE TRIGGER agent_events_terminal_fence BEFORE INSERT ON agent_events
    WHEN EXISTS (
        SELECT 1 FROM sprint_terminal_states WHERE sprint_id = NEW.sprint_id
    )
    BEGIN SELECT RAISE(ABORT, 'terminal sprints reject new events'); END;
    CREATE TRIGGER workspace_snapshots_terminal_fence BEFORE INSERT ON workspace_snapshots
    WHEN EXISTS (
        SELECT 1 FROM sprint_terminal_states WHERE sprint_id = NEW.sprint_id
    )
    BEGIN SELECT RAISE(ABORT, 'terminal sprints reject new snapshots'); END;
    CREATE TRIGGER change_sets_terminal_fence BEFORE INSERT ON change_sets
    WHEN EXISTS (
        SELECT 1 FROM sprint_terminal_states WHERE sprint_id = NEW.sprint_id
    )
    BEGIN SELECT RAISE(ABORT, 'terminal sprints reject new change sets'); END;
    CREATE TRIGGER verification_receipts_terminal_fence BEFORE INSERT ON verification_receipts
    WHEN EXISTS (
        SELECT 1 FROM sprint_terminal_states WHERE sprint_id = NEW.sprint_id
    )
    BEGIN SELECT RAISE(ABORT, 'terminal sprints reject new verification receipts'); END;
    CREATE TRIGGER acceptance_receipts_terminal_fence BEFORE INSERT ON acceptance_receipts
    WHEN EXISTS (
        SELECT 1 FROM sprint_terminal_states WHERE sprint_id = NEW.sprint_id
    )
    BEGIN SELECT RAISE(ABORT, 'terminal sprints reject new acceptance receipts'); END;
    CREATE TRIGGER final_reports_terminal_fence BEFORE INSERT ON final_reports
    WHEN EXISTS (
        SELECT 1 FROM sprint_terminal_states WHERE sprint_id = NEW.sprint_id
    )
    BEGIN SELECT RAISE(ABORT, 'terminal sprints reject new final reports'); END;
    CREATE TRIGGER completion_receipts_terminal_fence BEFORE INSERT ON completion_receipts
    WHEN EXISTS (
        SELECT 1 FROM sprint_terminal_states WHERE sprint_id = NEW.sprint_id
    )
    BEGIN SELECT RAISE(ABORT, 'terminal sprints reject new completion receipts'); END;
    CREATE TRIGGER completion_verification_terminal_fence
    BEFORE INSERT ON completion_verification_receipts
    WHEN EXISTS (
        SELECT 1 FROM sprint_terminal_states WHERE sprint_id = NEW.sprint_id
    )
    BEGIN SELECT RAISE(ABORT, 'terminal sprints reject new verification links'); END;
    CREATE TRIGGER completion_acceptance_terminal_fence
    BEFORE INSERT ON completion_acceptance_receipts
    WHEN EXISTS (
        SELECT 1 FROM sprint_terminal_states WHERE sprint_id = NEW.sprint_id
    )
    BEGIN SELECT RAISE(ABORT, 'terminal sprints reject new acceptance links'); END;
";

pub(super) const MIGRATION_V3: &str = r"
    CREATE TABLE effect_intents (
        effect_id TEXT PRIMARY KEY NOT NULL,
        sprint_id TEXT NOT NULL,
        idempotency_key TEXT NOT NULL,
        task_id TEXT,
        worker_id TEXT,
        causation_event_id TEXT,
        correlation_id TEXT NOT NULL,
        effect_kind TEXT NOT NULL CHECK (
            effect_kind IN (
                'ProviderRequest', 'ReadRelativeFile', 'SearchLiteral',
                'RunCommand', 'CreateRegularFile', 'ReplaceRegularFile',
                'DeleteRegularFile', 'IntegrateChangeSet', 'ApplyChangeSet'
            )
        ),
        request_digest TEXT NOT NULL,
        policy_hash TEXT NOT NULL,
        input_snapshot TEXT NOT NULL,
        proposed_event_id TEXT NOT NULL UNIQUE,
        contract_version INTEGER NOT NULL CHECK (contract_version > 0),
        created_at_unix_ms INTEGER NOT NULL CHECK (created_at_unix_ms > 0),
        intent_json BLOB NOT NULL,
        UNIQUE (sprint_id, effect_id),
        UNIQUE (sprint_id, idempotency_key),
        CHECK (
            (task_id IS NULL AND worker_id IS NULL)
            OR (task_id IS NOT NULL AND worker_id IS NOT NULL)
        ),
        FOREIGN KEY (sprint_id) REFERENCES sprints(sprint_id) ON DELETE RESTRICT,
        FOREIGN KEY (sprint_id, input_snapshot)
            REFERENCES workspace_snapshots(sprint_id, snapshot_id) ON DELETE RESTRICT,
        FOREIGN KEY (proposed_event_id)
            REFERENCES agent_events(event_id) ON DELETE RESTRICT,
        FOREIGN KEY (causation_event_id)
            REFERENCES agent_events(event_id) ON DELETE RESTRICT
    ) STRICT;

    CREATE INDEX effect_intents_sprint_sequence_idx
    ON effect_intents (sprint_id, created_at_unix_ms, effect_id);

    CREATE TABLE effect_observations (
        observation_id TEXT PRIMARY KEY NOT NULL,
        effect_id TEXT NOT NULL UNIQUE,
        sprint_id TEXT NOT NULL,
        idempotency_key TEXT NOT NULL,
        task_id TEXT,
        worker_id TEXT,
        correlation_id TEXT NOT NULL,
        effect_kind TEXT NOT NULL CHECK (
            effect_kind IN (
                'ProviderRequest', 'ReadRelativeFile', 'SearchLiteral',
                'RunCommand', 'CreateRegularFile', 'ReplaceRegularFile',
                'DeleteRegularFile', 'IntegrateChangeSet', 'ApplyChangeSet'
            )
        ),
        request_digest TEXT NOT NULL,
        policy_hash TEXT NOT NULL,
        input_snapshot TEXT NOT NULL,
        outcome TEXT NOT NULL CHECK (
            outcome IN (
                'Succeeded', 'FailedBeforeEffect', 'FailedAfterKnownEffect',
                'CancelledBeforeEffect', 'Unknown'
            )
        ),
        evidence_digest TEXT NOT NULL,
        terminal_event_id TEXT NOT NULL UNIQUE,
        contract_version INTEGER NOT NULL CHECK (contract_version > 0),
        observed_at_unix_ms INTEGER NOT NULL CHECK (observed_at_unix_ms > 0),
        observation_json BLOB NOT NULL,
        CHECK (
            (task_id IS NULL AND worker_id IS NULL)
            OR (task_id IS NOT NULL AND worker_id IS NOT NULL)
        ),
        FOREIGN KEY (sprint_id, effect_id)
            REFERENCES effect_intents(sprint_id, effect_id) ON DELETE RESTRICT,
        FOREIGN KEY (terminal_event_id)
            REFERENCES agent_events(event_id) ON DELETE RESTRICT
    ) STRICT;

    CREATE INDEX effect_observations_sprint_idx
    ON effect_observations (sprint_id, observed_at_unix_ms, effect_id);

    CREATE TRIGGER effect_intents_references_match
    BEFORE INSERT ON effect_intents
    WHEN NOT EXISTS (
        SELECT 1 FROM agent_events proposed
        WHERE proposed.event_id = NEW.proposed_event_id
          AND proposed.sprint_id = NEW.sprint_id
          AND proposed.occurred_at_unix_ms = NEW.created_at_unix_ms
    ) OR (
        NEW.causation_event_id IS NOT NULL
        AND NOT EXISTS (
            SELECT 1
            FROM agent_events cause
            JOIN agent_events proposed
              ON proposed.event_id = NEW.proposed_event_id
            WHERE cause.event_id = NEW.causation_event_id
              AND cause.sprint_id = NEW.sprint_id
              AND cause.sequence < proposed.sequence
        )
    )
    BEGIN
        SELECT RAISE(ABORT, 'effect intent event references must match');
    END;

    CREATE TRIGGER effect_observations_identity_match
    BEFORE INSERT ON effect_observations
    WHEN NOT EXISTS (
        SELECT 1 FROM effect_intents intent
        WHERE intent.effect_id = NEW.effect_id
          AND intent.sprint_id = NEW.sprint_id
          AND intent.idempotency_key = NEW.idempotency_key
          AND intent.task_id IS NEW.task_id
          AND intent.worker_id IS NEW.worker_id
          AND intent.correlation_id = NEW.correlation_id
          AND intent.effect_kind = NEW.effect_kind
          AND intent.request_digest = NEW.request_digest
          AND intent.policy_hash = NEW.policy_hash
          AND intent.input_snapshot = NEW.input_snapshot
          AND intent.created_at_unix_ms <= NEW.observed_at_unix_ms
    )
    BEGIN
        SELECT RAISE(ABORT, 'effect observation identity must match its intent');
    END;

    CREATE TRIGGER effect_observations_event_match
    BEFORE INSERT ON effect_observations
    WHEN NOT EXISTS (
        SELECT 1
        FROM agent_events terminal
        JOIN effect_intents intent ON intent.effect_id = NEW.effect_id
        JOIN agent_events proposed ON proposed.event_id = intent.proposed_event_id
        WHERE terminal.event_id = NEW.terminal_event_id
          AND terminal.sprint_id = NEW.sprint_id
          AND terminal.occurred_at_unix_ms = NEW.observed_at_unix_ms
          AND terminal.sequence > proposed.sequence
    )
    BEGIN
        SELECT RAISE(ABORT, 'effect observation event must follow its proposal');
    END;

    CREATE TRIGGER effect_intents_no_update BEFORE UPDATE ON effect_intents
    BEGIN SELECT RAISE(ABORT, 'effect intents are append-only'); END;
    CREATE TRIGGER effect_intents_no_delete BEFORE DELETE ON effect_intents
    BEGIN SELECT RAISE(ABORT, 'effect intents are append-only'); END;
    CREATE TRIGGER effect_observations_no_update BEFORE UPDATE ON effect_observations
    BEGIN SELECT RAISE(ABORT, 'effect observations are append-only'); END;
    CREATE TRIGGER effect_observations_no_delete BEFORE DELETE ON effect_observations
    BEGIN SELECT RAISE(ABORT, 'effect observations are append-only'); END;

    CREATE TRIGGER effect_intents_terminal_fence BEFORE INSERT ON effect_intents
    WHEN EXISTS (
        SELECT 1 FROM sprint_terminal_states WHERE sprint_id = NEW.sprint_id
    )
    BEGIN SELECT RAISE(ABORT, 'terminal sprints reject new effect intents'); END;
    CREATE TRIGGER effect_observations_terminal_fence BEFORE INSERT ON effect_observations
    WHEN EXISTS (
        SELECT 1 FROM sprint_terminal_states WHERE sprint_id = NEW.sprint_id
    )
    BEGIN SELECT RAISE(ABORT, 'terminal sprints reject new effect observations'); END;

    CREATE TRIGGER sprint_terminal_states_effect_fence
    BEFORE INSERT ON sprint_terminal_states
    WHEN EXISTS (
        SELECT 1
        FROM effect_intents intent
        LEFT JOIN effect_observations observation
          ON observation.effect_id = intent.effect_id
        WHERE intent.sprint_id = NEW.sprint_id
          AND (observation.effect_id IS NULL OR observation.outcome = 'Unknown')
    )
    BEGIN
        SELECT RAISE(ABORT, 'terminal sprints require every effect to be reconciled');
    END;
";

pub(super) const MIGRATION_V4: &str = r"
    CREATE TABLE legacy_effect_payload_gaps (
        effect_id TEXT PRIMARY KEY NOT NULL,
        sprint_id TEXT NOT NULL,
        missing_request INTEGER NOT NULL CHECK (missing_request = 1),
        missing_evidence INTEGER NOT NULL CHECK (missing_evidence IN (0, 1)),
        FOREIGN KEY (sprint_id, effect_id)
            REFERENCES effect_intents(sprint_id, effect_id) ON DELETE RESTRICT
    ) STRICT, WITHOUT ROWID;

    INSERT INTO legacy_effect_payload_gaps (
        effect_id, sprint_id, missing_request, missing_evidence
    )
    SELECT intent.effect_id, intent.sprint_id, 1,
           CASE WHEN observation.effect_id IS NULL THEN 0 ELSE 1 END
    FROM effect_intents intent
    LEFT JOIN effect_observations observation
      ON observation.effect_id = intent.effect_id;

    CREATE TRIGGER legacy_effect_payload_gaps_no_insert
    BEFORE INSERT ON legacy_effect_payload_gaps
    BEGIN SELECT RAISE(ABORT, 'legacy effect gap markers are migration-only'); END;
    CREATE TRIGGER legacy_effect_payload_gaps_no_update
    BEFORE UPDATE ON legacy_effect_payload_gaps
    BEGIN SELECT RAISE(ABORT, 'legacy effect gap markers are immutable'); END;
    CREATE TRIGGER legacy_effect_payload_gaps_no_delete
    BEFORE DELETE ON legacy_effect_payload_gaps
    BEGIN SELECT RAISE(ABORT, 'legacy effect gap markers are immutable'); END;

    CREATE TABLE effect_request_payloads (
        effect_id TEXT PRIMARY KEY NOT NULL,
        sprint_id TEXT NOT NULL,
        request_digest TEXT NOT NULL,
        request_bytes BLOB NOT NULL
            CHECK (length(request_bytes) BETWEEN 1 AND 8388608),
        contract_version INTEGER NOT NULL CHECK (contract_version > 0),
        UNIQUE (sprint_id, effect_id),
        FOREIGN KEY (sprint_id) REFERENCES sprints(sprint_id) ON DELETE RESTRICT,
        FOREIGN KEY (sprint_id, effect_id)
            REFERENCES effect_intents(sprint_id, effect_id)
            ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED
    ) STRICT, WITHOUT ROWID;

    CREATE INDEX effect_request_payloads_sprint_idx
    ON effect_request_payloads (sprint_id, effect_id);

    CREATE TABLE effect_evidence_payloads (
        effect_id TEXT PRIMARY KEY NOT NULL,
        observation_id TEXT NOT NULL UNIQUE,
        sprint_id TEXT NOT NULL,
        evidence_digest TEXT NOT NULL,
        evidence_bytes BLOB NOT NULL
            CHECK (length(evidence_bytes) BETWEEN 1 AND 8388608),
        contract_version INTEGER NOT NULL CHECK (contract_version > 0),
        FOREIGN KEY (sprint_id, effect_id)
            REFERENCES effect_intents(sprint_id, effect_id) ON DELETE RESTRICT,
        FOREIGN KEY (observation_id)
            REFERENCES effect_observations(observation_id)
            ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED
    ) STRICT, WITHOUT ROWID;

    CREATE INDEX effect_evidence_payloads_sprint_idx
    ON effect_evidence_payloads (sprint_id, effect_id);

    CREATE TRIGGER effect_request_payloads_no_legacy_backfill
    BEFORE INSERT ON effect_request_payloads
    WHEN EXISTS (
        SELECT 1 FROM effect_intents WHERE effect_id = NEW.effect_id
    )
    BEGIN
        SELECT RAISE(ABORT, 'legacy effect requests cannot be backfilled');
    END;

    CREATE TRIGGER effect_evidence_payloads_no_legacy_backfill
    BEFORE INSERT ON effect_evidence_payloads
    WHEN EXISTS (
        SELECT 1 FROM effect_observations
        WHERE observation_id = NEW.observation_id OR effect_id = NEW.effect_id
    )
    BEGIN
        SELECT RAISE(ABORT, 'legacy effect evidence cannot be backfilled');
    END;

    CREATE TRIGGER effect_intents_require_request_payload
    AFTER INSERT ON effect_intents
    WHEN NOT EXISTS (
        SELECT 1 FROM effect_request_payloads payload
        WHERE payload.effect_id = NEW.effect_id
          AND payload.sprint_id = NEW.sprint_id
          AND payload.request_digest = NEW.request_digest
          AND payload.contract_version = NEW.contract_version
    )
    BEGIN
        SELECT RAISE(ABORT, 'effect intent requires exact request bytes');
    END;

    CREATE TRIGGER effect_observations_require_evidence_payload
    AFTER INSERT ON effect_observations
    WHEN NOT EXISTS (
        SELECT 1 FROM effect_evidence_payloads payload
        WHERE payload.effect_id = NEW.effect_id
          AND payload.observation_id = NEW.observation_id
          AND payload.sprint_id = NEW.sprint_id
          AND payload.evidence_digest = NEW.evidence_digest
          AND payload.contract_version = NEW.contract_version
    )
    BEGIN
        SELECT RAISE(ABORT, 'effect observation requires exact evidence bytes');
    END;

    CREATE TRIGGER effect_request_payloads_no_update
    BEFORE UPDATE ON effect_request_payloads
    BEGIN SELECT RAISE(ABORT, 'effect request bytes are append-only'); END;
    CREATE TRIGGER effect_request_payloads_no_delete
    BEFORE DELETE ON effect_request_payloads
    BEGIN SELECT RAISE(ABORT, 'effect request bytes are append-only'); END;
    CREATE TRIGGER effect_evidence_payloads_no_update
    BEFORE UPDATE ON effect_evidence_payloads
    BEGIN SELECT RAISE(ABORT, 'effect evidence bytes are append-only'); END;
    CREATE TRIGGER effect_evidence_payloads_no_delete
    BEFORE DELETE ON effect_evidence_payloads
    BEGIN SELECT RAISE(ABORT, 'effect evidence bytes are append-only'); END;

    CREATE TRIGGER effect_request_payloads_terminal_fence
    BEFORE INSERT ON effect_request_payloads
    WHEN EXISTS (
        SELECT 1 FROM sprint_terminal_states WHERE sprint_id = NEW.sprint_id
    )
    BEGIN SELECT RAISE(ABORT, 'terminal sprints reject new effect request bytes'); END;
    CREATE TRIGGER effect_evidence_payloads_terminal_fence
    BEFORE INSERT ON effect_evidence_payloads
    WHEN EXISTS (
        SELECT 1 FROM sprint_terminal_states WHERE sprint_id = NEW.sprint_id
    )
    BEGIN SELECT RAISE(ABORT, 'terminal sprints reject new effect evidence bytes'); END;

    DROP TRIGGER sprint_terminal_states_effect_fence;
    CREATE TRIGGER sprint_terminal_states_effect_fence
    BEFORE INSERT ON sprint_terminal_states
    WHEN EXISTS (
        SELECT 1
        FROM effect_intents intent
        LEFT JOIN effect_request_payloads request
          ON request.effect_id = intent.effect_id
        LEFT JOIN effect_observations observation
          ON observation.effect_id = intent.effect_id
        LEFT JOIN effect_evidence_payloads evidence
          ON evidence.effect_id = intent.effect_id
        WHERE intent.sprint_id = NEW.sprint_id
          AND (
              request.effect_id IS NULL
              OR observation.effect_id IS NULL
              OR observation.outcome = 'Unknown'
              OR evidence.effect_id IS NULL
          )
    )
    BEGIN
        SELECT RAISE(ABORT, 'terminal sprints require effect request and evidence bytes');
    END;
";

pub(super) const MIGRATION_V5: &str = r"
    CREATE TABLE sprint_planning_states (
        sprint_id TEXT PRIMARY KEY NOT NULL,
        base_snapshot TEXT NOT NULL,
        contract_version INTEGER NOT NULL CHECK (contract_version > 0),
        UNIQUE (sprint_id, base_snapshot),
        FOREIGN KEY (sprint_id) REFERENCES sprints(sprint_id) ON DELETE RESTRICT
    ) STRICT, WITHOUT ROWID;

    INSERT INTO sprint_planning_states (
        sprint_id, base_snapshot, contract_version
    )
    SELECT sprint_id,
           CAST(json_extract(CAST(spec_json AS TEXT), '$.base_snapshot') AS TEXT),
           contract_version
    FROM sprints;

    CREATE TABLE sprint_task_graphs (
        sprint_id TEXT PRIMARY KEY NOT NULL,
        graph_id TEXT NOT NULL,
        base_snapshot TEXT NOT NULL,
        contract_version INTEGER NOT NULL CHECK (contract_version > 0),
        graph_json BLOB NOT NULL CHECK (length(graph_json) > 0),
        FOREIGN KEY (sprint_id, base_snapshot)
            REFERENCES sprint_planning_states(sprint_id, base_snapshot)
            ON DELETE RESTRICT
    ) STRICT, WITHOUT ROWID;

    INSERT INTO sprint_task_graphs (
        sprint_id, graph_id, base_snapshot, contract_version, graph_json
    )
    SELECT sprint.sprint_id,
           CAST(json_extract(CAST(sprint.graph_json AS TEXT), '$.graph_id') AS TEXT),
           planning.base_snapshot,
           sprint.contract_version,
           sprint.graph_json
    FROM sprints sprint
    JOIN sprint_planning_states planning
      ON planning.sprint_id = sprint.sprint_id;

    CREATE TRIGGER sprints_v5_require_empty_legacy_graph
    BEFORE INSERT ON sprints
    WHEN length(NEW.graph_json) != 0
    BEGIN
        SELECT RAISE(ABORT, 'new sprint rows reserve legacy graph storage');
    END;

    CREATE TRIGGER sprint_planning_states_spec_match
    BEFORE INSERT ON sprint_planning_states
    WHEN NOT EXISTS (
        SELECT 1 FROM sprints sprint
        WHERE sprint.sprint_id = NEW.sprint_id
          AND sprint.contract_version = NEW.contract_version
          AND CAST(
                json_extract(CAST(sprint.spec_json AS TEXT), '$.base_snapshot')
                AS TEXT
              ) = NEW.base_snapshot
    )
    BEGIN
        SELECT RAISE(ABORT, 'planning state must match the immutable sprint spec');
    END;

    CREATE TRIGGER sprint_planning_states_no_update
    BEFORE UPDATE ON sprint_planning_states
    BEGIN SELECT RAISE(ABORT, 'sprint planning state is immutable'); END;
    CREATE TRIGGER sprint_planning_states_no_delete
    BEFORE DELETE ON sprint_planning_states
    BEGIN SELECT RAISE(ABORT, 'sprint planning state is immutable'); END;

    CREATE TRIGGER sprint_task_graphs_state_match
    BEFORE INSERT ON sprint_task_graphs
    WHEN NOT EXISTS (
        SELECT 1 FROM sprint_planning_states planning
        WHERE planning.sprint_id = NEW.sprint_id
          AND planning.base_snapshot = NEW.base_snapshot
          AND planning.contract_version = NEW.contract_version
    ) OR json_valid(CAST(NEW.graph_json AS TEXT)) != 1
       OR CAST(
            json_extract(CAST(NEW.graph_json AS TEXT), '$.graph_id') AS TEXT
          ) IS NOT NEW.graph_id
       OR json_type(CAST(NEW.graph_json AS TEXT), '$.tasks') IS NOT 'array'
       OR json_array_length(CAST(NEW.graph_json AS TEXT), '$.tasks') < 1
       OR EXISTS (
            SELECT 1
            FROM json_each(CAST(NEW.graph_json AS TEXT), '$.tasks') task
            WHERE CAST(json_extract(task.value, '$.base_snapshot') AS TEXT)
                  IS NOT NEW.base_snapshot
       )
    BEGIN
        SELECT RAISE(ABORT, 'task graph must match immutable planning state');
    END;

    CREATE TRIGGER sprint_task_graphs_no_update
    BEFORE UPDATE ON sprint_task_graphs
    BEGIN SELECT RAISE(ABORT, 'task graph is append-only'); END;
    CREATE TRIGGER sprint_task_graphs_no_delete
    BEFORE DELETE ON sprint_task_graphs
    BEGIN SELECT RAISE(ABORT, 'task graph is append-only'); END;

    CREATE TRIGGER draft_workspace_snapshots_fence
    BEFORE INSERT ON workspace_snapshots
    WHEN NOT EXISTS (
        SELECT 1 FROM sprint_task_graphs graph
        WHERE graph.sprint_id = NEW.sprint_id
    ) AND NOT EXISTS (
        SELECT 1
        FROM sprint_planning_states planning
        JOIN sprints sprint ON sprint.sprint_id = planning.sprint_id
        WHERE planning.sprint_id = NEW.sprint_id
          AND planning.base_snapshot = NEW.snapshot_id
          AND NEW.created_at_unix_ms <= sprint.created_at_unix_ms
          AND CAST(
                json_extract(
                    CAST(sprint.spec_json AS TEXT),
                    '$.workspace_grant.grant_hash'
                ) AS TEXT
              ) = NEW.grant_hash
    )
    BEGIN
        SELECT RAISE(ABORT, 'draft sprints accept only their authenticated base snapshot');
    END;

    CREATE TRIGGER draft_agent_events_fence
    BEFORE INSERT ON agent_events
    WHEN NOT EXISTS (
        SELECT 1 FROM sprint_task_graphs graph
        WHERE graph.sprint_id = NEW.sprint_id
    ) AND (
        json_extract(CAST(NEW.event_json AS TEXT), '$.task_id') IS NOT NULL
        OR json_extract(CAST(NEW.event_json AS TEXT), '$.worker_id') IS NOT NULL
        OR json_type(
            CAST(NEW.event_json AS TEXT), '$.payload.TaskStateChanged'
        ) IS NOT NULL
        OR json_type(
            CAST(NEW.event_json AS TEXT), '$.payload.WorkerStateChanged'
        ) IS NOT NULL
        OR json_type(
            CAST(NEW.event_json AS TEXT), '$.payload.ChangeSetStaged'
        ) IS NOT NULL
        OR json_type(
            CAST(NEW.event_json AS TEXT), '$.payload.VerificationRecorded'
        ) IS NOT NULL
        OR json_type(
            CAST(NEW.event_json AS TEXT), '$.payload.CompletionRecorded'
        ) IS NOT NULL
    )
    BEGIN
        SELECT RAISE(ABORT, 'draft sprints reject task and completion events');
    END;

    CREATE TRIGGER draft_effect_intents_fence
    BEFORE INSERT ON effect_intents
    WHEN NOT EXISTS (
        SELECT 1 FROM sprint_task_graphs graph
        WHERE graph.sprint_id = NEW.sprint_id
    ) AND (
        NEW.effect_kind != 'ProviderRequest'
        OR NEW.task_id IS NOT NULL
        OR NEW.worker_id IS NOT NULL
        OR NOT EXISTS (
            SELECT 1
            FROM sprint_planning_states planning
            JOIN workspace_snapshots snapshot
              ON snapshot.sprint_id = planning.sprint_id
             AND snapshot.snapshot_id = planning.base_snapshot
            JOIN sprints sprint ON sprint.sprint_id = planning.sprint_id
            WHERE planning.sprint_id = NEW.sprint_id
              AND planning.base_snapshot = NEW.input_snapshot
              AND snapshot.created_at_unix_ms <= sprint.created_at_unix_ms
              AND snapshot.grant_hash = CAST(
                    json_extract(
                        CAST(sprint.spec_json AS TEXT),
                        '$.workspace_grant.grant_hash'
                    ) AS TEXT
                  )
        )
    )
    BEGIN
        SELECT RAISE(ABORT, 'draft sprints allow only base-bound provider requests');
    END;

    CREATE TRIGGER draft_change_sets_fence BEFORE INSERT ON change_sets
    WHEN NOT EXISTS (
        SELECT 1 FROM sprint_task_graphs WHERE sprint_id = NEW.sprint_id
    )
    BEGIN SELECT RAISE(ABORT, 'draft sprints reject change sets'); END;

    CREATE TRIGGER draft_verification_receipts_fence
    BEFORE INSERT ON verification_receipts
    WHEN NOT EXISTS (
        SELECT 1 FROM sprint_task_graphs WHERE sprint_id = NEW.sprint_id
    )
    BEGIN SELECT RAISE(ABORT, 'draft sprints reject verification receipts'); END;

    CREATE TRIGGER draft_acceptance_receipts_fence
    BEFORE INSERT ON acceptance_receipts
    WHEN NOT EXISTS (
        SELECT 1 FROM sprint_task_graphs WHERE sprint_id = NEW.sprint_id
    )
    BEGIN SELECT RAISE(ABORT, 'draft sprints reject acceptance receipts'); END;

    CREATE TRIGGER draft_final_reports_fence BEFORE INSERT ON final_reports
    WHEN NOT EXISTS (
        SELECT 1 FROM sprint_task_graphs WHERE sprint_id = NEW.sprint_id
    )
    BEGIN SELECT RAISE(ABORT, 'draft sprints reject final reports'); END;

    CREATE TRIGGER draft_completion_receipts_fence
    BEFORE INSERT ON completion_receipts
    WHEN NOT EXISTS (
        SELECT 1 FROM sprint_task_graphs WHERE sprint_id = NEW.sprint_id
    )
    BEGIN SELECT RAISE(ABORT, 'draft sprints reject completion receipts'); END;

    CREATE TRIGGER draft_terminal_states_fence
    BEFORE INSERT ON sprint_terminal_states
    WHEN NOT EXISTS (
        SELECT 1 FROM sprint_task_graphs WHERE sprint_id = NEW.sprint_id
    )
    BEGIN SELECT RAISE(ABORT, 'draft sprints cannot become terminal'); END;
";

pub(super) const MIGRATION_V6: &str = r"
    CREATE TABLE sprint_graph_provenance (
        sprint_id TEXT PRIMARY KEY NOT NULL,
        provenance_kind TEXT NOT NULL CHECK (
            provenance_kind IN (
                'ProviderEffect', 'DirectTrusted', 'LegacyUnproven'
            )
        ),
        effect_id TEXT UNIQUE,
        observation_id TEXT UNIQUE,
        response_digest TEXT,
        contract_version INTEGER NOT NULL CHECK (contract_version > 0),
        CHECK (
            (provenance_kind = 'ProviderEffect'
             AND effect_id IS NOT NULL
             AND observation_id IS NOT NULL
             AND response_digest IS NOT NULL)
            OR
            (provenance_kind IN ('DirectTrusted', 'LegacyUnproven')
             AND effect_id IS NULL
             AND observation_id IS NULL
             AND response_digest IS NULL)
        ),
        FOREIGN KEY (sprint_id) REFERENCES sprints(sprint_id) ON DELETE RESTRICT,
        FOREIGN KEY (sprint_id)
            REFERENCES sprint_task_graphs(sprint_id)
            ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED,
        FOREIGN KEY (sprint_id, effect_id)
            REFERENCES effect_intents(sprint_id, effect_id) ON DELETE RESTRICT,
        FOREIGN KEY (observation_id)
            REFERENCES effect_observations(observation_id) ON DELETE RESTRICT
    ) STRICT, WITHOUT ROWID;

    INSERT INTO sprint_graph_provenance (
        sprint_id, provenance_kind, effect_id, observation_id,
        response_digest, contract_version
    )
    SELECT sprint_id, 'LegacyUnproven', NULL, NULL, NULL, contract_version
    FROM sprint_task_graphs;

    CREATE TRIGGER sprint_graph_provenance_provider_match
    BEFORE INSERT ON sprint_graph_provenance
    WHEN NEW.provenance_kind = 'ProviderEffect' AND NOT EXISTS (
        SELECT 1
        FROM effect_intents intent
        JOIN effect_request_payloads request
          ON request.effect_id = intent.effect_id
        JOIN effect_observations observation
          ON observation.effect_id = intent.effect_id
        JOIN effect_evidence_payloads evidence
          ON evidence.effect_id = intent.effect_id
        WHERE intent.sprint_id = NEW.sprint_id
          AND intent.effect_id = NEW.effect_id
          AND intent.effect_kind = 'ProviderRequest'
          AND intent.task_id IS NULL
          AND intent.worker_id IS NULL
          AND observation.observation_id = NEW.observation_id
          AND observation.outcome = 'Succeeded'
          AND evidence.observation_id = observation.observation_id
          AND evidence.evidence_digest = NEW.response_digest
          AND request.request_digest = intent.request_digest
    )
    BEGIN
        SELECT RAISE(ABORT, 'provider graph provenance requires exact successful effect evidence');
    END;

    CREATE TRIGGER sprint_graph_provenance_no_update
    BEFORE UPDATE ON sprint_graph_provenance
    BEGIN SELECT RAISE(ABORT, 'graph provenance is immutable'); END;
    CREATE TRIGGER sprint_graph_provenance_no_delete
    BEFORE DELETE ON sprint_graph_provenance
    BEGIN SELECT RAISE(ABORT, 'graph provenance is immutable'); END;

    CREATE TRIGGER sprint_task_graphs_require_provenance
    AFTER INSERT ON sprint_task_graphs
    WHEN NOT EXISTS (
        SELECT 1 FROM sprint_graph_provenance
        WHERE sprint_id = NEW.sprint_id
    )
    BEGIN SELECT RAISE(ABORT, 'task graph requires durable provenance'); END;

    CREATE TRIGGER legacy_unproven_agent_events_fence
    BEFORE INSERT ON agent_events
    WHEN EXISTS (
        SELECT 1 FROM sprint_graph_provenance
        WHERE sprint_id = NEW.sprint_id
          AND provenance_kind = 'LegacyUnproven'
    )
    BEGIN SELECT RAISE(ABORT, 'legacy-unproven graphs reject new work'); END;
    CREATE TRIGGER legacy_unproven_workspace_snapshots_fence
    BEFORE INSERT ON workspace_snapshots
    WHEN EXISTS (
        SELECT 1 FROM sprint_graph_provenance
        WHERE sprint_id = NEW.sprint_id
          AND provenance_kind = 'LegacyUnproven'
    )
    BEGIN SELECT RAISE(ABORT, 'legacy-unproven graphs reject new work'); END;
    CREATE TRIGGER legacy_unproven_change_sets_fence
    BEFORE INSERT ON change_sets
    WHEN EXISTS (
        SELECT 1 FROM sprint_graph_provenance
        WHERE sprint_id = NEW.sprint_id
          AND provenance_kind = 'LegacyUnproven'
    )
    BEGIN SELECT RAISE(ABORT, 'legacy-unproven graphs reject new work'); END;
    CREATE TRIGGER legacy_unproven_verification_receipts_fence
    BEFORE INSERT ON verification_receipts
    WHEN EXISTS (
        SELECT 1 FROM sprint_graph_provenance
        WHERE sprint_id = NEW.sprint_id
          AND provenance_kind = 'LegacyUnproven'
    )
    BEGIN SELECT RAISE(ABORT, 'legacy-unproven graphs reject new work'); END;
    CREATE TRIGGER legacy_unproven_acceptance_receipts_fence
    BEFORE INSERT ON acceptance_receipts
    WHEN EXISTS (
        SELECT 1 FROM sprint_graph_provenance
        WHERE sprint_id = NEW.sprint_id
          AND provenance_kind = 'LegacyUnproven'
    )
    BEGIN SELECT RAISE(ABORT, 'legacy-unproven graphs reject new work'); END;
    CREATE TRIGGER legacy_unproven_final_reports_fence
    BEFORE INSERT ON final_reports
    WHEN EXISTS (
        SELECT 1 FROM sprint_graph_provenance
        WHERE sprint_id = NEW.sprint_id
          AND provenance_kind = 'LegacyUnproven'
    )
    BEGIN SELECT RAISE(ABORT, 'legacy-unproven graphs reject new work'); END;
    CREATE TRIGGER legacy_unproven_completion_receipts_fence
    BEFORE INSERT ON completion_receipts
    WHEN EXISTS (
        SELECT 1 FROM sprint_graph_provenance
        WHERE sprint_id = NEW.sprint_id
          AND provenance_kind = 'LegacyUnproven'
    )
    BEGIN SELECT RAISE(ABORT, 'legacy-unproven graphs reject new work'); END;
    CREATE TRIGGER legacy_unproven_completion_verification_fence
    BEFORE INSERT ON completion_verification_receipts
    WHEN EXISTS (
        SELECT 1 FROM sprint_graph_provenance
        WHERE sprint_id = NEW.sprint_id
          AND provenance_kind = 'LegacyUnproven'
    )
    BEGIN SELECT RAISE(ABORT, 'legacy-unproven graphs reject new work'); END;
    CREATE TRIGGER legacy_unproven_completion_acceptance_fence
    BEFORE INSERT ON completion_acceptance_receipts
    WHEN EXISTS (
        SELECT 1 FROM sprint_graph_provenance
        WHERE sprint_id = NEW.sprint_id
          AND provenance_kind = 'LegacyUnproven'
    )
    BEGIN SELECT RAISE(ABORT, 'legacy-unproven graphs reject new work'); END;
    CREATE TRIGGER legacy_unproven_effect_requests_fence
    BEFORE INSERT ON effect_request_payloads
    WHEN EXISTS (
        SELECT 1 FROM sprint_graph_provenance
        WHERE sprint_id = NEW.sprint_id
          AND provenance_kind = 'LegacyUnproven'
    )
    BEGIN SELECT RAISE(ABORT, 'legacy-unproven graphs reject new work'); END;
    CREATE TRIGGER legacy_unproven_effect_intents_fence
    BEFORE INSERT ON effect_intents
    WHEN EXISTS (
        SELECT 1 FROM sprint_graph_provenance
        WHERE sprint_id = NEW.sprint_id
          AND provenance_kind = 'LegacyUnproven'
    )
    BEGIN SELECT RAISE(ABORT, 'legacy-unproven graphs reject new work'); END;
    CREATE TRIGGER legacy_unproven_effect_evidence_fence
    BEFORE INSERT ON effect_evidence_payloads
    WHEN EXISTS (
        SELECT 1 FROM sprint_graph_provenance
        WHERE sprint_id = NEW.sprint_id
          AND provenance_kind = 'LegacyUnproven'
    )
    BEGIN SELECT RAISE(ABORT, 'legacy-unproven graphs reject new work'); END;
    CREATE TRIGGER legacy_unproven_effect_observations_fence
    BEFORE INSERT ON effect_observations
    WHEN EXISTS (
        SELECT 1 FROM sprint_graph_provenance
        WHERE sprint_id = NEW.sprint_id
          AND provenance_kind = 'LegacyUnproven'
    )
    BEGIN SELECT RAISE(ABORT, 'legacy-unproven graphs reject new work'); END;
    CREATE TRIGGER legacy_unproven_terminal_states_fence
    BEFORE INSERT ON sprint_terminal_states
    WHEN EXISTS (
        SELECT 1 FROM sprint_graph_provenance
        WHERE sprint_id = NEW.sprint_id
          AND provenance_kind = 'LegacyUnproven'
    )
    BEGIN SELECT RAISE(ABORT, 'legacy-unproven graphs reject new work'); END;
";

pub(super) const MIGRATION_V7: &str = r"
    CREATE TABLE sprint_non_success_terminal_outcomes (
        sprint_id TEXT PRIMARY KEY NOT NULL,
        record_id TEXT NOT NULL UNIQUE,
        terminal_state TEXT NOT NULL CHECK (
            terminal_state IN ('Blocked', 'Failed', 'Canceled', 'Unknown')
        ),
        evidence_digest TEXT NOT NULL CHECK (
            length(evidence_digest) = 64
            AND evidence_digest NOT GLOB '*[^0-9a-f]*'
        ),
        terminal_event_id TEXT NOT NULL UNIQUE,
        contract_version INTEGER NOT NULL CHECK (contract_version > 0),
        terminal_at_unix_ms INTEGER NOT NULL CHECK (terminal_at_unix_ms > 0),
        evidence_json BLOB NOT NULL CHECK (
            length(evidence_json) BETWEEN 1 AND 8388608
        ),
        CHECK (terminal_event_id = record_id),
        FOREIGN KEY (sprint_id) REFERENCES sprints(sprint_id) ON DELETE RESTRICT,
        FOREIGN KEY (terminal_event_id)
            REFERENCES agent_events(event_id)
            ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED
    ) STRICT, WITHOUT ROWID;

    CREATE TRIGGER sprint_non_success_terminal_outcomes_envelope_match
    BEFORE INSERT ON sprint_non_success_terminal_outcomes
    WHEN json_valid(CAST(NEW.evidence_json AS TEXT)) != 1
      OR json_type(CAST(NEW.evidence_json AS TEXT), '$') IS NOT 'object'
      OR json_type(
            CAST(NEW.evidence_json AS TEXT), '$.contract_version'
         ) IS NOT 'integer'
      OR json_extract(
            CAST(NEW.evidence_json AS TEXT), '$.contract_version'
         ) IS NOT NEW.contract_version
      OR json_type(
            CAST(NEW.evidence_json AS TEXT), '$.record_id'
         ) IS NOT 'text'
      OR json_extract(
            CAST(NEW.evidence_json AS TEXT), '$.record_id'
         ) IS NOT NEW.record_id
      OR json_type(
            CAST(NEW.evidence_json AS TEXT), '$.sprint_id'
         ) IS NOT 'text'
      OR json_extract(
            CAST(NEW.evidence_json AS TEXT), '$.sprint_id'
         ) IS NOT NEW.sprint_id
      OR json_type(
            CAST(NEW.evidence_json AS TEXT), '$.state'
         ) IS NOT 'text'
      OR json_extract(
            CAST(NEW.evidence_json AS TEXT), '$.state'
         ) IS NOT NEW.terminal_state
      OR json_type(
            CAST(NEW.evidence_json AS TEXT), '$.reason'
         ) IS NOT 'text'
      OR trim(CAST(json_extract(
            CAST(NEW.evidence_json AS TEXT), '$.reason'
         ) AS TEXT)) = ''
      OR length(CAST(json_extract(
            CAST(NEW.evidence_json AS TEXT), '$.reason'
         ) AS BLOB)) NOT BETWEEN 1 AND 65536
      OR json_type(
            CAST(NEW.evidence_json AS TEXT), '$.terminal_at_unix_ms'
         ) IS NOT 'integer'
      OR json_extract(
            CAST(NEW.evidence_json AS TEXT), '$.terminal_at_unix_ms'
         ) IS NOT NEW.terminal_at_unix_ms
    BEGIN
        SELECT RAISE(ABORT, 'terminal evidence envelope must match indexed state');
    END;

    CREATE TRIGGER sprint_non_success_terminal_outcomes_completed_conflict
    BEFORE INSERT ON sprint_non_success_terminal_outcomes
    WHEN EXISTS (
        SELECT 1 FROM sprint_terminal_states WHERE sprint_id = NEW.sprint_id
    )
    BEGIN SELECT RAISE(ABORT, 'sprint already has a successful terminal outcome'); END;

    CREATE TRIGGER sprint_terminal_states_non_success_conflict
    BEFORE INSERT ON sprint_terminal_states
    WHEN EXISTS (
        SELECT 1 FROM sprint_non_success_terminal_outcomes
        WHERE sprint_id = NEW.sprint_id
    )
    BEGIN SELECT RAISE(ABORT, 'sprint already has a non-success terminal outcome'); END;

    CREATE TRIGGER sprint_non_success_terminal_outcomes_legacy_fence
    BEFORE INSERT ON sprint_non_success_terminal_outcomes
    WHEN EXISTS (
        SELECT 1 FROM sprint_graph_provenance
        WHERE sprint_id = NEW.sprint_id
          AND provenance_kind = 'LegacyUnproven'
    )
    BEGIN SELECT RAISE(ABORT, 'legacy-unproven graphs reject new work'); END;

    CREATE TRIGGER sprint_non_success_terminal_outcomes_known_effect_fence
    BEFORE INSERT ON sprint_non_success_terminal_outcomes
    WHEN NEW.terminal_state IN ('Blocked', 'Failed', 'Canceled')
      AND EXISTS (
        SELECT 1
        FROM effect_intents intent
        LEFT JOIN effect_request_payloads request
          ON request.effect_id = intent.effect_id
        LEFT JOIN effect_observations observation
          ON observation.effect_id = intent.effect_id
        LEFT JOIN effect_evidence_payloads evidence
          ON evidence.effect_id = intent.effect_id
        WHERE intent.sprint_id = NEW.sprint_id
          AND (
              request.effect_id IS NULL
              OR observation.effect_id IS NULL
              OR observation.outcome = 'Unknown'
              OR evidence.effect_id IS NULL
          )
    )
    BEGIN
        SELECT RAISE(ABORT, 'known terminal outcomes require every effect to be reconciled');
    END;

    CREATE TRIGGER sprint_non_success_terminal_outcomes_unknown_effect_fence
    BEFORE INSERT ON sprint_non_success_terminal_outcomes
    WHEN NEW.terminal_state = 'Unknown' AND (
        NOT EXISTS (
            SELECT 1
            FROM effect_intents intent
            LEFT JOIN effect_observations observation
              ON observation.effect_id = intent.effect_id
            WHERE intent.sprint_id = NEW.sprint_id
              AND (
                  observation.effect_id IS NULL
                  OR observation.outcome = 'Unknown'
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

    CREATE TRIGGER sprint_non_success_terminal_outcomes_no_update
    BEFORE UPDATE ON sprint_non_success_terminal_outcomes
    BEGIN SELECT RAISE(ABORT, 'non-success terminal outcomes are immutable'); END;
    CREATE TRIGGER sprint_non_success_terminal_outcomes_no_delete
    BEFORE DELETE ON sprint_non_success_terminal_outcomes
    BEGIN SELECT RAISE(ABORT, 'non-success terminal outcomes are immutable'); END;

    CREATE TRIGGER agent_events_non_success_terminal_fence
    BEFORE INSERT ON agent_events
    WHEN EXISTS (
        SELECT 1 FROM sprint_non_success_terminal_outcomes outcome
        WHERE outcome.sprint_id = NEW.sprint_id
          AND outcome.terminal_event_id != NEW.event_id
    )
    BEGIN SELECT RAISE(ABORT, 'terminal sprints reject new events'); END;

    CREATE TRIGGER agent_events_non_success_terminal_match
    AFTER INSERT ON agent_events
    WHEN (
        EXISTS (
            SELECT 1 FROM sprint_non_success_terminal_outcomes
            WHERE terminal_event_id = NEW.event_id
        )
        OR json_type(
            CAST(NEW.event_json AS TEXT),
            '$.payload.SprintTerminalRecorded'
        ) IS NOT NULL
    ) AND NOT EXISTS (
        SELECT 1
        FROM sprint_non_success_terminal_outcomes outcome
        WHERE outcome.terminal_event_id = NEW.event_id
          AND outcome.sprint_id = NEW.sprint_id
          AND outcome.contract_version = NEW.contract_version
          AND outcome.terminal_at_unix_ms = NEW.occurred_at_unix_ms
          AND json_extract(
                CAST(NEW.event_json AS TEXT), '$.contract_version'
              ) = outcome.contract_version
          AND json_extract(
                CAST(NEW.event_json AS TEXT), '$.sequence'
              ) = NEW.sequence
          AND json_extract(
                CAST(NEW.event_json AS TEXT), '$.event_id'
              ) = outcome.terminal_event_id
          AND json_extract(
                CAST(NEW.event_json AS TEXT), '$.sprint_id'
              ) = outcome.sprint_id
          AND json_type(
                CAST(NEW.event_json AS TEXT), '$.task_id'
              ) = 'null'
          AND json_type(
                CAST(NEW.event_json AS TEXT), '$.worker_id'
              ) = 'null'
          AND json_type(
                CAST(NEW.event_json AS TEXT), '$.causation_id'
              ) = 'null'
          AND json_extract(
                CAST(NEW.event_json AS TEXT), '$.correlation_id'
              ) = outcome.record_id
          AND json_type(
                CAST(NEW.event_json AS TEXT), '$.policy_hash'
              ) = 'null'
          AND json_extract(
                CAST(NEW.event_json AS TEXT), '$.occurred_at_unix_ms'
              ) = outcome.terminal_at_unix_ms
          AND json_extract(
                CAST(NEW.event_json AS TEXT),
                '$.payload.SprintTerminalRecorded.record_id'
              ) = outcome.record_id
          AND json_extract(
                CAST(NEW.event_json AS TEXT),
                '$.payload.SprintTerminalRecorded.state'
              ) = outcome.terminal_state
          AND json_extract(
                CAST(NEW.event_json AS TEXT),
                '$.payload.SprintTerminalRecorded.evidence_digest'
              ) = outcome.evidence_digest
    )
    BEGIN SELECT RAISE(ABORT, 'terminal event must atomically match its evidence'); END;

    CREATE TRIGGER workspace_snapshots_non_success_terminal_fence
    BEFORE INSERT ON workspace_snapshots
    WHEN EXISTS (
        SELECT 1 FROM sprint_non_success_terminal_outcomes
        WHERE sprint_id = NEW.sprint_id
    )
    BEGIN SELECT RAISE(ABORT, 'terminal sprints reject new snapshots'); END;
    CREATE TRIGGER change_sets_non_success_terminal_fence
    BEFORE INSERT ON change_sets
    WHEN EXISTS (
        SELECT 1 FROM sprint_non_success_terminal_outcomes
        WHERE sprint_id = NEW.sprint_id
    )
    BEGIN SELECT RAISE(ABORT, 'terminal sprints reject new change sets'); END;
    CREATE TRIGGER verification_receipts_non_success_terminal_fence
    BEFORE INSERT ON verification_receipts
    WHEN EXISTS (
        SELECT 1 FROM sprint_non_success_terminal_outcomes
        WHERE sprint_id = NEW.sprint_id
    )
    BEGIN SELECT RAISE(ABORT, 'terminal sprints reject new verification receipts'); END;
    CREATE TRIGGER acceptance_receipts_non_success_terminal_fence
    BEFORE INSERT ON acceptance_receipts
    WHEN EXISTS (
        SELECT 1 FROM sprint_non_success_terminal_outcomes
        WHERE sprint_id = NEW.sprint_id
    )
    BEGIN SELECT RAISE(ABORT, 'terminal sprints reject new acceptance receipts'); END;
    CREATE TRIGGER final_reports_non_success_terminal_fence
    BEFORE INSERT ON final_reports
    WHEN EXISTS (
        SELECT 1 FROM sprint_non_success_terminal_outcomes
        WHERE sprint_id = NEW.sprint_id
    )
    BEGIN SELECT RAISE(ABORT, 'terminal sprints reject new final reports'); END;
    CREATE TRIGGER completion_receipts_non_success_terminal_fence
    BEFORE INSERT ON completion_receipts
    WHEN EXISTS (
        SELECT 1 FROM sprint_non_success_terminal_outcomes
        WHERE sprint_id = NEW.sprint_id
    )
    BEGIN SELECT RAISE(ABORT, 'terminal sprints reject new completion receipts'); END;
    CREATE TRIGGER completion_verification_non_success_terminal_fence
    BEFORE INSERT ON completion_verification_receipts
    WHEN EXISTS (
        SELECT 1 FROM sprint_non_success_terminal_outcomes
        WHERE sprint_id = NEW.sprint_id
    )
    BEGIN SELECT RAISE(ABORT, 'terminal sprints reject new verification links'); END;
    CREATE TRIGGER completion_acceptance_non_success_terminal_fence
    BEFORE INSERT ON completion_acceptance_receipts
    WHEN EXISTS (
        SELECT 1 FROM sprint_non_success_terminal_outcomes
        WHERE sprint_id = NEW.sprint_id
    )
    BEGIN SELECT RAISE(ABORT, 'terminal sprints reject new acceptance links'); END;
    CREATE TRIGGER effect_request_payloads_non_success_terminal_fence
    BEFORE INSERT ON effect_request_payloads
    WHEN EXISTS (
        SELECT 1 FROM sprint_non_success_terminal_outcomes
        WHERE sprint_id = NEW.sprint_id
    )
    BEGIN SELECT RAISE(ABORT, 'terminal sprints reject new effect request bytes'); END;
    CREATE TRIGGER effect_intents_non_success_terminal_fence
    BEFORE INSERT ON effect_intents
    WHEN EXISTS (
        SELECT 1 FROM sprint_non_success_terminal_outcomes
        WHERE sprint_id = NEW.sprint_id
    )
    BEGIN SELECT RAISE(ABORT, 'terminal sprints reject new effect intents'); END;
    CREATE TRIGGER effect_evidence_payloads_non_success_terminal_fence
    BEFORE INSERT ON effect_evidence_payloads
    WHEN EXISTS (
        SELECT 1 FROM sprint_non_success_terminal_outcomes
        WHERE sprint_id = NEW.sprint_id
    )
    BEGIN SELECT RAISE(ABORT, 'terminal sprints reject new effect evidence bytes'); END;
    CREATE TRIGGER effect_observations_non_success_terminal_fence
    BEFORE INSERT ON effect_observations
    WHEN EXISTS (
        SELECT 1 FROM sprint_non_success_terminal_outcomes
        WHERE sprint_id = NEW.sprint_id
    )
    BEGIN SELECT RAISE(ABORT, 'terminal sprints reject new effect observations'); END;
    CREATE TRIGGER sprint_task_graphs_non_success_terminal_fence
    BEFORE INSERT ON sprint_task_graphs
    WHEN EXISTS (
        SELECT 1 FROM sprint_non_success_terminal_outcomes
        WHERE sprint_id = NEW.sprint_id
    )
    BEGIN SELECT RAISE(ABORT, 'terminal sprints reject new task graphs'); END;
    CREATE TRIGGER sprint_graph_provenance_non_success_terminal_fence
    BEFORE INSERT ON sprint_graph_provenance
    WHEN EXISTS (
        SELECT 1 FROM sprint_non_success_terminal_outcomes
        WHERE sprint_id = NEW.sprint_id
    )
    BEGIN SELECT RAISE(ABORT, 'terminal sprints reject new graph provenance'); END;
";

pub(super) const MIGRATION_V8: &str = r"
    CREATE TABLE mutation_artifact_links (
        effect_id TEXT PRIMARY KEY NOT NULL,
        sprint_id TEXT NOT NULL,
        link_status TEXT NOT NULL CHECK (
            link_status IN ('Linked', 'LegacyUnlinked')
        ),
        observation_id TEXT NOT NULL UNIQUE,
        input_snapshot TEXT NOT NULL,
        result_snapshot TEXT,
        change_set_id TEXT,
        contract_version INTEGER NOT NULL CHECK (contract_version > 0),
        link_json BLOB,
        UNIQUE (sprint_id, effect_id),
        UNIQUE (sprint_id, change_set_id),
        CHECK (
            (link_status = 'Linked'
             AND result_snapshot IS NOT NULL
             AND change_set_id IS NOT NULL
             AND link_json IS NOT NULL)
            OR
            (link_status = 'LegacyUnlinked'
             AND result_snapshot IS NULL
             AND change_set_id IS NULL
             AND link_json IS NULL)
        ),
        FOREIGN KEY (sprint_id, effect_id)
            REFERENCES effect_intents(sprint_id, effect_id) ON DELETE RESTRICT,
        FOREIGN KEY (observation_id)
            REFERENCES effect_observations(observation_id)
            ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED,
        FOREIGN KEY (sprint_id, input_snapshot)
            REFERENCES workspace_snapshots(sprint_id, snapshot_id) ON DELETE RESTRICT,
        FOREIGN KEY (sprint_id, result_snapshot)
            REFERENCES workspace_snapshots(sprint_id, snapshot_id) ON DELETE RESTRICT,
        FOREIGN KEY (sprint_id, change_set_id)
            REFERENCES change_sets(sprint_id, change_set_id) ON DELETE RESTRICT
    ) STRICT, WITHOUT ROWID;

    INSERT INTO mutation_artifact_links (
        effect_id, sprint_id, link_status, observation_id, input_snapshot,
        result_snapshot, change_set_id, contract_version, link_json
    )
    SELECT intent.effect_id, intent.sprint_id, 'LegacyUnlinked',
           observation.observation_id, intent.input_snapshot,
           NULL, NULL, observation.contract_version, NULL
    FROM effect_intents intent
    JOIN effect_observations observation
      ON observation.effect_id = intent.effect_id
    WHERE intent.effect_kind IN (
              'CreateRegularFile', 'ReplaceRegularFile', 'DeleteRegularFile'
          )
      AND observation.outcome = 'Succeeded';

    CREATE VIEW unresolved_mutation_effects AS
    SELECT sprint_id, effect_id
    FROM mutation_artifact_links
    WHERE link_status = 'LegacyUnlinked'
    UNION ALL
    SELECT sprint_id, effect_id
    FROM effect_observations
    WHERE effect_kind IN (
              'CreateRegularFile', 'ReplaceRegularFile', 'DeleteRegularFile'
          )
      AND outcome = 'FailedAfterKnownEffect';

    CREATE TRIGGER mutation_artifact_links_no_legacy_insert
    BEFORE INSERT ON mutation_artifact_links
    WHEN NEW.link_status = 'LegacyUnlinked'
    BEGIN SELECT RAISE(ABORT, 'legacy mutation markers are migration-only'); END;

    CREATE TRIGGER mutation_artifact_links_envelope_match
    BEFORE INSERT ON mutation_artifact_links
    WHEN NEW.link_status = 'Linked' AND (
        json_valid(CAST(NEW.link_json AS TEXT)) != 1
        OR json_type(CAST(NEW.link_json AS TEXT), '$') IS NOT 'object'
        OR json_extract(
              CAST(NEW.link_json AS TEXT), '$.contract_version'
           ) IS NOT NEW.contract_version
        OR json_extract(
              CAST(NEW.link_json AS TEXT), '$.sprint_id'
           ) IS NOT NEW.sprint_id
        OR json_extract(
              CAST(NEW.link_json AS TEXT), '$.effect_id'
           ) IS NOT NEW.effect_id
        OR json_extract(
              CAST(NEW.link_json AS TEXT), '$.observation_id'
           ) IS NOT NEW.observation_id
        OR json_extract(
              CAST(NEW.link_json AS TEXT), '$.input_snapshot'
           ) IS NOT NEW.input_snapshot
        OR json_extract(
              CAST(NEW.link_json AS TEXT), '$.result_snapshot'
           ) IS NOT NEW.result_snapshot
        OR json_extract(
              CAST(NEW.link_json AS TEXT), '$.change_set_id'
           ) IS NOT NEW.change_set_id
    )
    BEGIN SELECT RAISE(ABORT, 'mutation link envelope must match indexed state'); END;

    CREATE TRIGGER mutation_artifact_links_relationship_match
    BEFORE INSERT ON mutation_artifact_links
    WHEN NEW.link_status = 'Linked' AND NOT EXISTS (
        SELECT 1
        FROM effect_intents intent
        JOIN workspace_snapshots result
          ON result.sprint_id = intent.sprint_id
         AND result.snapshot_id = NEW.result_snapshot
        JOIN workspace_snapshots input
          ON input.sprint_id = intent.sprint_id
         AND input.snapshot_id = NEW.input_snapshot
        JOIN change_sets changes
          ON changes.sprint_id = intent.sprint_id
         AND changes.change_set_id = NEW.change_set_id
        WHERE intent.effect_id = NEW.effect_id
          AND intent.sprint_id = NEW.sprint_id
          AND intent.effect_kind IN (
              'CreateRegularFile', 'ReplaceRegularFile', 'DeleteRegularFile'
          )
          AND intent.input_snapshot = NEW.input_snapshot
          AND intent.contract_version = NEW.contract_version
          AND NEW.input_snapshot != NEW.result_snapshot
          AND result.grant_hash = input.grant_hash
          AND result.contract_version = NEW.contract_version
          AND changes.contract_version = NEW.contract_version
          AND changes.base_snapshot = NEW.input_snapshot
          AND changes.result_snapshot = NEW.result_snapshot
          AND json_valid(CAST(changes.change_set_json AS TEXT)) = 1
          AND json_extract(
                  CAST(changes.change_set_json AS TEXT), '$.change_set_id'
              ) IS changes.change_set_id
          AND json_extract(
                  CAST(changes.change_set_json AS TEXT), '$.base_snapshot'
              ) IS changes.base_snapshot
          AND json_extract(
                  CAST(changes.change_set_json AS TEXT), '$.result_snapshot'
              ) IS changes.result_snapshot
          AND json_array_length(
                  CAST(changes.change_set_json AS TEXT), '$.operations'
              ) = 1
          AND (
              (intent.effect_kind = 'CreateRegularFile'
               AND json_type(
                       CAST(changes.change_set_json AS TEXT),
                       '$.operations[0].Create'
                   ) = 'object')
              OR (intent.effect_kind = 'ReplaceRegularFile'
                  AND json_type(
                          CAST(changes.change_set_json AS TEXT),
                          '$.operations[0].Modify'
                      ) = 'object')
              OR (intent.effect_kind = 'DeleteRegularFile'
                  AND json_type(
                          CAST(changes.change_set_json AS TEXT),
                          '$.operations[0].Delete'
                      ) = 'object')
          )
    )
    BEGIN SELECT RAISE(ABORT, 'mutation link must match intent and artifacts'); END;

    CREATE TRIGGER successful_mutation_observations_require_link
    AFTER INSERT ON effect_observations
    WHEN NEW.effect_kind IN (
            'CreateRegularFile', 'ReplaceRegularFile', 'DeleteRegularFile'
         )
      AND NEW.outcome = 'Succeeded'
      AND NOT EXISTS (
        SELECT 1 FROM mutation_artifact_links link
        WHERE link.effect_id = NEW.effect_id
          AND link.sprint_id = NEW.sprint_id
          AND link.link_status = 'Linked'
          AND link.contract_version = NEW.contract_version
          AND link.observation_id = NEW.observation_id
          AND link.input_snapshot = NEW.input_snapshot
          AND EXISTS (
              SELECT 1 FROM workspace_snapshots result
              WHERE result.sprint_id = NEW.sprint_id
                AND result.snapshot_id = link.result_snapshot
                AND result.created_at_unix_ms <= NEW.observed_at_unix_ms
          )
    )
    BEGIN SELECT RAISE(ABORT, 'successful mutation requires atomic artifact link'); END;

    CREATE TRIGGER mutation_observations_link_shape
    AFTER INSERT ON effect_observations
    WHEN EXISTS (
        SELECT 1 FROM mutation_artifact_links link
        WHERE link.effect_id = NEW.effect_id
          AND link.link_status = 'Linked'
    ) AND NOT (
        NEW.effect_kind IN (
            'CreateRegularFile', 'ReplaceRegularFile', 'DeleteRegularFile'
        )
        AND NEW.outcome = 'Succeeded'
        AND EXISTS (
            SELECT 1 FROM mutation_artifact_links link
            WHERE link.effect_id = NEW.effect_id
              AND link.sprint_id = NEW.sprint_id
              AND link.observation_id = NEW.observation_id
              AND link.input_snapshot = NEW.input_snapshot
        )
    )
    BEGIN SELECT RAISE(ABORT, 'mutation link requires exact successful observation'); END;

    CREATE TRIGGER mutation_artifact_links_terminal_fence
    BEFORE INSERT ON mutation_artifact_links
    WHEN EXISTS (
        SELECT 1 FROM sprint_terminal_states WHERE sprint_id = NEW.sprint_id
    ) OR EXISTS (
        SELECT 1 FROM sprint_non_success_terminal_outcomes
        WHERE sprint_id = NEW.sprint_id
    )
    BEGIN SELECT RAISE(ABORT, 'terminal sprints reject mutation links'); END;

    CREATE TRIGGER mutation_artifact_links_no_update
    BEFORE UPDATE ON mutation_artifact_links
    BEGIN SELECT RAISE(ABORT, 'mutation artifact links are immutable'); END;
    CREATE TRIGGER mutation_artifact_links_no_delete
    BEFORE DELETE ON mutation_artifact_links
    BEGIN SELECT RAISE(ABORT, 'mutation artifact links are immutable'); END;

    DROP TRIGGER sprint_terminal_states_effect_fence;
    CREATE TRIGGER sprint_terminal_states_effect_fence
    BEFORE INSERT ON sprint_terminal_states
    WHEN EXISTS (
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
    BEGIN
        SELECT RAISE(ABORT, 'terminal sprints require reconciled effect artifacts');
    END;

    DROP TRIGGER sprint_non_success_terminal_outcomes_known_effect_fence;
    CREATE TRIGGER sprint_non_success_terminal_outcomes_known_effect_fence
    BEFORE INSERT ON sprint_non_success_terminal_outcomes
    WHEN NEW.terminal_state IN ('Blocked', 'Failed', 'Canceled')
      AND EXISTS (
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
    BEGIN
        SELECT RAISE(ABORT, 'known terminal outcomes require every effect to be reconciled');
    END;

    DROP TRIGGER sprint_non_success_terminal_outcomes_unknown_effect_fence;
    CREATE TRIGGER sprint_non_success_terminal_outcomes_unknown_effect_fence
    BEFORE INSERT ON sprint_non_success_terminal_outcomes
    WHEN NEW.terminal_state = 'Unknown' AND (
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

    CREATE TRIGGER legacy_unlinked_agent_events_fence
    BEFORE INSERT ON agent_events
    WHEN EXISTS (
        SELECT 1 FROM unresolved_mutation_effects
        WHERE sprint_id = NEW.sprint_id
    ) AND NOT EXISTS (
        SELECT 1 FROM sprint_non_success_terminal_outcomes outcome
        WHERE outcome.sprint_id = NEW.sprint_id
          AND outcome.terminal_state = 'Unknown'
          AND outcome.terminal_event_id = NEW.event_id
    )
    BEGIN SELECT RAISE(ABORT, 'legacy-unlinked mutations reject new work'); END;
    CREATE TRIGGER legacy_unlinked_workspace_snapshots_fence
    BEFORE INSERT ON workspace_snapshots
    WHEN EXISTS (
        SELECT 1 FROM unresolved_mutation_effects
        WHERE sprint_id = NEW.sprint_id
    )
    BEGIN SELECT RAISE(ABORT, 'legacy-unlinked mutations reject new work'); END;
    CREATE TRIGGER legacy_unlinked_change_sets_fence
    BEFORE INSERT ON change_sets
    WHEN EXISTS (
        SELECT 1 FROM unresolved_mutation_effects
        WHERE sprint_id = NEW.sprint_id
    )
    BEGIN SELECT RAISE(ABORT, 'legacy-unlinked mutations reject new work'); END;
    CREATE TRIGGER legacy_unlinked_verification_receipts_fence
    BEFORE INSERT ON verification_receipts
    WHEN EXISTS (
        SELECT 1 FROM unresolved_mutation_effects
        WHERE sprint_id = NEW.sprint_id
    )
    BEGIN SELECT RAISE(ABORT, 'legacy-unlinked mutations reject new work'); END;
    CREATE TRIGGER legacy_unlinked_acceptance_receipts_fence
    BEFORE INSERT ON acceptance_receipts
    WHEN EXISTS (
        SELECT 1 FROM unresolved_mutation_effects
        WHERE sprint_id = NEW.sprint_id
    )
    BEGIN SELECT RAISE(ABORT, 'legacy-unlinked mutations reject new work'); END;
    CREATE TRIGGER legacy_unlinked_final_reports_fence
    BEFORE INSERT ON final_reports
    WHEN EXISTS (
        SELECT 1 FROM unresolved_mutation_effects
        WHERE sprint_id = NEW.sprint_id
    )
    BEGIN SELECT RAISE(ABORT, 'legacy-unlinked mutations reject new work'); END;
    CREATE TRIGGER legacy_unlinked_completion_receipts_fence
    BEFORE INSERT ON completion_receipts
    WHEN EXISTS (
        SELECT 1 FROM unresolved_mutation_effects
        WHERE sprint_id = NEW.sprint_id
    )
    BEGIN SELECT RAISE(ABORT, 'legacy-unlinked mutations reject new work'); END;
    CREATE TRIGGER legacy_unlinked_completion_verification_fence
    BEFORE INSERT ON completion_verification_receipts
    WHEN EXISTS (
        SELECT 1 FROM unresolved_mutation_effects
        WHERE sprint_id = NEW.sprint_id
    )
    BEGIN SELECT RAISE(ABORT, 'legacy-unlinked mutations reject new work'); END;
    CREATE TRIGGER legacy_unlinked_completion_acceptance_fence
    BEFORE INSERT ON completion_acceptance_receipts
    WHEN EXISTS (
        SELECT 1 FROM unresolved_mutation_effects
        WHERE sprint_id = NEW.sprint_id
    )
    BEGIN SELECT RAISE(ABORT, 'legacy-unlinked mutations reject new work'); END;
    CREATE TRIGGER legacy_unlinked_effect_requests_fence
    BEFORE INSERT ON effect_request_payloads
    WHEN EXISTS (
        SELECT 1 FROM unresolved_mutation_effects
        WHERE sprint_id = NEW.sprint_id
    )
    BEGIN SELECT RAISE(ABORT, 'legacy-unlinked mutations reject new work'); END;
    CREATE TRIGGER legacy_unlinked_effect_intents_fence
    BEFORE INSERT ON effect_intents
    WHEN EXISTS (
        SELECT 1 FROM unresolved_mutation_effects
        WHERE sprint_id = NEW.sprint_id
    )
    BEGIN SELECT RAISE(ABORT, 'legacy-unlinked mutations reject new work'); END;
    CREATE TRIGGER legacy_unlinked_effect_evidence_fence
    BEFORE INSERT ON effect_evidence_payloads
    WHEN EXISTS (
        SELECT 1 FROM unresolved_mutation_effects
        WHERE sprint_id = NEW.sprint_id
    )
    BEGIN SELECT RAISE(ABORT, 'legacy-unlinked mutations reject new work'); END;
    CREATE TRIGGER legacy_unlinked_effect_observations_fence
    BEFORE INSERT ON effect_observations
    WHEN EXISTS (
        SELECT 1 FROM unresolved_mutation_effects
        WHERE sprint_id = NEW.sprint_id
    )
    BEGIN SELECT RAISE(ABORT, 'legacy-unlinked mutations reject new work'); END;
    CREATE TRIGGER legacy_unlinked_terminal_states_fence
    BEFORE INSERT ON sprint_terminal_states
    WHEN EXISTS (
        SELECT 1 FROM unresolved_mutation_effects
        WHERE sprint_id = NEW.sprint_id
    )
    BEGIN SELECT RAISE(ABORT, 'legacy-unlinked mutations reject new work'); END;
    CREATE TRIGGER legacy_unlinked_non_success_terminal_fence
    BEFORE INSERT ON sprint_non_success_terminal_outcomes
    WHEN NEW.terminal_state != 'Unknown' AND EXISTS (
        SELECT 1 FROM unresolved_mutation_effects
        WHERE sprint_id = NEW.sprint_id
    )
    BEGIN SELECT RAISE(ABORT, 'legacy-unlinked mutations reject new work'); END;
    CREATE TRIGGER legacy_unlinked_task_graphs_fence
    BEFORE INSERT ON sprint_task_graphs
    WHEN EXISTS (
        SELECT 1 FROM unresolved_mutation_effects
        WHERE sprint_id = NEW.sprint_id
    )
    BEGIN SELECT RAISE(ABORT, 'legacy-unlinked mutations reject new work'); END;
    CREATE TRIGGER legacy_unlinked_graph_provenance_fence
    BEFORE INSERT ON sprint_graph_provenance
    WHEN EXISTS (
        SELECT 1 FROM unresolved_mutation_effects
        WHERE sprint_id = NEW.sprint_id
    )
    BEGIN SELECT RAISE(ABORT, 'legacy-unlinked mutations reject new work'); END;
    CREATE TRIGGER legacy_unlinked_mutation_links_fence
    BEFORE INSERT ON mutation_artifact_links
    WHEN EXISTS (
        SELECT 1 FROM unresolved_mutation_effects
        WHERE sprint_id = NEW.sprint_id
    )
    BEGIN SELECT RAISE(ABORT, 'legacy-unlinked mutations reject new work'); END;
";
