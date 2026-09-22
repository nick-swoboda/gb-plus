-- Dormant current-only TaskDone source projection and exact complete-set
-- membership joins. No production writer exists in schema v32.
-- The insertion UDF is a connection-local trusted-desktop guard, not a
-- cryptographic same-user boundary; the Rust module documents that threat cut.

CREATE TABLE current_task_done_sources_v32 (
    task_done_proof_id TEXT PRIMARY KEY NOT NULL
        CHECK (length(task_done_proof_id) BETWEEN 1 AND 4096),
    source_digest TEXT NOT NULL UNIQUE CHECK (length(source_digest) = 64),
    sprint_id TEXT NOT NULL,
    task_id TEXT NOT NULL,
    winning_attempt_id TEXT NOT NULL CHECK (length(winning_attempt_id) BETWEEN 1 AND 4096),
    winning_attempt_ordinal INTEGER NOT NULL CHECK (winning_attempt_ordinal > 0),
    winning_lease_id TEXT NOT NULL CHECK (length(winning_lease_id) BETWEEN 1 AND 4096),
    winning_lease_epoch INTEGER NOT NULL CHECK (winning_lease_epoch > 0),
    integration_receipt_id TEXT NOT NULL
        CHECK (length(integration_receipt_id) BETWEEN 1 AND 4096),
    integration_kind TEXT NOT NULL CHECK (integration_kind IN ('Changed', 'VerifiedNoOp')),
    change_set_id TEXT CHECK (change_set_id IS NULL OR length(change_set_id) BETWEEN 1 AND 4096),
    empty_change_set_id TEXT CHECK (
        empty_change_set_id IS NULL OR length(empty_change_set_id) BETWEEN 1 AND 4096
    ),
    operation_count INTEGER NOT NULL CHECK (operation_count >= 0),
    input_snapshot TEXT NOT NULL CHECK (length(input_snapshot) = 64),
    result_snapshot TEXT NOT NULL CHECK (length(result_snapshot) = 64),
    zero_active_leases_proof_id TEXT NOT NULL
        CHECK (length(zero_active_leases_proof_id) BETWEEN 1 AND 4096),
    active_lease_count INTEGER NOT NULL CHECK (active_lease_count = 0),
    zero_replay_dispatch_authority_proof_id TEXT NOT NULL
        CHECK (length(zero_replay_dispatch_authority_proof_id) BETWEEN 1 AND 4096),
    replay_dispatch_authority_count INTEGER NOT NULL CHECK (replay_dispatch_authority_count = 0),
    derived_at_unix_ms INTEGER NOT NULL CHECK (derived_at_unix_ms > 0),
    source_json BLOB NOT NULL CHECK (length(source_json) BETWEEN 1 AND 8388608),
    UNIQUE (
        task_done_proof_id, sprint_id, task_id, integration_receipt_id,
        integration_kind, empty_change_set_id, input_snapshot, result_snapshot
    ),
    FOREIGN KEY (sprint_id, task_id)
        REFERENCES current_task_nodes_v32(sprint_id, task_id) ON DELETE RESTRICT,
    CHECK (
        (integration_kind = 'Changed'
         AND change_set_id IS NOT NULL
         AND empty_change_set_id IS NULL
         AND operation_count > 0
         AND input_snapshot != result_snapshot)
        OR
        (integration_kind = 'VerifiedNoOp'
         AND change_set_id IS NULL
         AND empty_change_set_id IS NOT NULL
         AND operation_count = 0
         AND input_snapshot = result_snapshot)
    )
) STRICT, WITHOUT ROWID;

-- Parent identity needed by the exact criterion-member composite FK declared
-- in the primary v32 migration before this current-only source table exists.
CREATE UNIQUE INDEX current_criterion_evidence_receipts_v32_member_source_unique
ON current_criterion_evidence_receipts_v32 (
    receipt_id, sprint_id, criterion_id, snapshot_digest, evidence_kind
);

CREATE TRIGGER current_task_done_sources_v32_validate_insert
BEFORE INSERT ON current_task_done_sources_v32
WHEN grok_current_task_done_source_write_admitted_v32(
         NEW.sprint_id, NEW.task_id, NEW.task_done_proof_id, NEW.source_digest
     ) != 1
  OR grok_current_task_done_source_canonical_v32(
         NEW.source_json, NEW.source_digest, NEW.task_done_proof_id,
         NEW.sprint_id, NEW.task_id, NEW.winning_attempt_id,
         NEW.winning_attempt_ordinal, NEW.winning_lease_id,
         NEW.winning_lease_epoch, NEW.integration_receipt_id,
         NEW.integration_kind, NEW.change_set_id, NEW.empty_change_set_id,
         NEW.operation_count, NEW.input_snapshot, NEW.result_snapshot,
         NEW.zero_active_leases_proof_id, NEW.active_lease_count,
         NEW.zero_replay_dispatch_authority_proof_id,
         NEW.replay_dispatch_authority_count, NEW.derived_at_unix_ms
     ) != 1
  OR NOT EXISTS (
      SELECT 1
      FROM current_task_nodes_v32 task
      JOIN current_sprint_authorities_v32 sprint
        ON sprint.sprint_id = task.sprint_id
      WHERE task.sprint_id = NEW.sprint_id
        AND task.task_id = NEW.task_id
        AND grok_current_task_done_source_matches_task_v32(
            NEW.source_json, task.task_json, sprint.spec_json
        ) = 1
  )
BEGIN SELECT RAISE(ABORT, 'current TaskDone source requires exact admitted source and task membership'); END;

-- These triggers close SQLite's NULL-composite-FK bypass for the Changed
-- branch and make source resolution explicit at member insertion time.
CREATE TRIGGER current_task_done_members_v32_validate_source
BEFORE INSERT ON current_task_done_members_v32
WHEN NOT EXISTS (
    SELECT 1
    FROM current_task_done_sets_v32 set_row
    JOIN current_task_done_sources_v32 source
      ON source.task_done_proof_id = NEW.task_done_proof_id
     AND source.sprint_id = NEW.sprint_id
     AND source.task_id = NEW.task_id
     AND source.integration_receipt_id = NEW.integration_receipt_id
     AND source.integration_kind = NEW.integration_kind
     AND source.empty_change_set_id IS NEW.empty_change_set_id
     AND source.input_snapshot = NEW.input_snapshot
     AND source.result_snapshot = NEW.result_snapshot
    WHERE set_row.set_digest = NEW.set_digest
      AND set_row.sprint_id = NEW.sprint_id
      AND source.derived_at_unix_ms <= set_row.recorded_at_unix_ms
)
BEGIN SELECT RAISE(ABORT, 'current TaskDone member requires one exact immutable source receipt'); END;

CREATE TRIGGER current_criterion_evidence_members_v32_validate_source
BEFORE INSERT ON current_criterion_evidence_members_v32
WHEN NOT EXISTS (
    SELECT 1
    FROM current_criterion_evidence_sets_v32 set_row
    JOIN current_criterion_evidence_receipts_v32 source
      ON source.receipt_id = NEW.evidence_receipt_id
     AND source.sprint_id = NEW.sprint_id
     AND source.criterion_id = NEW.criterion_id
     AND source.snapshot_digest = NEW.snapshot_digest
     AND source.evidence_kind = NEW.evidence_kind
    WHERE set_row.set_digest = NEW.set_digest
      AND set_row.sprint_id = NEW.sprint_id
      AND source.recorded_at_unix_ms <= set_row.recorded_at_unix_ms
)
BEGIN SELECT RAISE(ABORT, 'current criterion-evidence member requires one exact immutable source receipt'); END;

CREATE TRIGGER current_task_done_sources_v32_no_update
BEFORE UPDATE ON current_task_done_sources_v32
BEGIN SELECT RAISE(ABORT, 'current TaskDone source is immutable'); END;

CREATE TRIGGER current_task_done_sources_v32_no_delete
BEFORE DELETE ON current_task_done_sources_v32
BEGIN SELECT RAISE(ABORT, 'current TaskDone source is immutable'); END;

CREATE VIEW current_task_done_source_capture_v32 AS
SELECT source.task_done_proof_id, source.source_digest, source.sprint_id,
       source.task_id, source.winning_attempt_id,
       source.winning_attempt_ordinal, source.winning_lease_id,
       source.winning_lease_epoch, source.integration_receipt_id,
       source.integration_kind, source.change_set_id,
       source.empty_change_set_id, source.operation_count,
       source.input_snapshot, source.result_snapshot,
       source.zero_active_leases_proof_id, source.active_lease_count,
       source.zero_replay_dispatch_authority_proof_id,
       source.replay_dispatch_authority_count, source.derived_at_unix_ms,
       source.source_json
FROM current_task_done_sources_v32 source
JOIN current_task_nodes_v32 task
  ON task.sprint_id = source.sprint_id
 AND task.task_id = source.task_id;
