-- Schema v16 admits exactly represented task-level verified no-ops. The
-- contract requires an explicit empty ChangeSet whose base and result digest
-- are identical; absence of a ChangeSet remains invalid. Existing child rows
-- are deferred while the two constrained parent tables are rebuilt in place.
PRAGMA defer_foreign_keys = ON;

-- Completion receipts written before v16 cannot retroactively acquire the
-- TaskDone and per-command cleanup proof sets introduced by the v16 reader.
-- Capture exactly the rows that already exist while this migration runs. A
-- fresh v16 database starts empty, so every subsequently recorded completion
-- must satisfy the complete current evidence contract.
CREATE TABLE pre_v16_completion_evidence_exemptions (
    completion_receipt_id TEXT PRIMARY KEY NOT NULL,
    sprint_id TEXT NOT NULL UNIQUE,
    recorded_schema_ceiling INTEGER NOT NULL CHECK (recorded_schema_ceiling = 15),
    FOREIGN KEY (sprint_id, completion_receipt_id)
        REFERENCES v9_completion_receipts(sprint_id, receipt_id) ON DELETE RESTRICT
) STRICT, WITHOUT ROWID;

INSERT INTO pre_v16_completion_evidence_exemptions (
    completion_receipt_id, sprint_id, recorded_schema_ceiling
)
SELECT receipt_id, sprint_id, 15
FROM v9_completion_receipts;

CREATE TRIGGER pre_v16_completion_evidence_exemptions_no_update
BEFORE UPDATE ON pre_v16_completion_evidence_exemptions
BEGIN SELECT RAISE(ABORT, 'pre-v16 completion evidence exemptions are immutable'); END;
CREATE TRIGGER pre_v16_completion_evidence_exemptions_no_delete
BEFORE DELETE ON pre_v16_completion_evidence_exemptions
BEGIN SELECT RAISE(ABORT, 'pre-v16 completion evidence exemptions are immutable'); END;
CREATE TRIGGER pre_v16_completion_evidence_exemptions_no_insert
BEFORE INSERT ON pre_v16_completion_evidence_exemptions
BEGIN SELECT RAISE(ABORT, 'pre-v16 completion evidence exemptions are migration-only'); END;

CREATE TEMP TABLE v16_preserved_task_integration_admissions AS
SELECT admission_id, attempt_id, candidate_boundary_id, sprint_id, task_id,
       worker_id, worker_lease_id, lease_epoch, effect_id, worker_launch_id,
       worker_session_id, input_snapshot_id, result_snapshot_id,
       contract_version, admitted_at_unix_ms, request_json, admission_json
FROM task_attempt_integration_admissions;

DROP TABLE task_attempt_integration_admissions;

CREATE TABLE task_attempt_integration_admissions (
    admission_id TEXT PRIMARY KEY NOT NULL,
    attempt_id TEXT NOT NULL UNIQUE,
    candidate_boundary_id TEXT NOT NULL UNIQUE,
    sprint_id TEXT NOT NULL,
    task_id TEXT NOT NULL,
    worker_id TEXT NOT NULL,
    worker_lease_id TEXT NOT NULL UNIQUE,
    lease_epoch INTEGER NOT NULL CHECK (lease_epoch > 0),
    effect_id TEXT NOT NULL UNIQUE,
    worker_launch_id TEXT NOT NULL,
    worker_session_id TEXT NOT NULL,
    input_snapshot_id TEXT NOT NULL,
    result_snapshot_id TEXT NOT NULL,
    contract_version INTEGER NOT NULL CHECK (contract_version > 0),
    admitted_at_unix_ms INTEGER NOT NULL CHECK (admitted_at_unix_ms > 0),
    request_json BLOB NOT NULL CHECK (length(request_json) > 0),
    admission_json BLOB NOT NULL CHECK (length(admission_json) > 0),
    FOREIGN KEY (attempt_id) REFERENCES task_attempts(attempt_id) ON DELETE RESTRICT,
    FOREIGN KEY (candidate_boundary_id)
        REFERENCES task_attempt_candidate_boundaries(boundary_id) ON DELETE RESTRICT,
    FOREIGN KEY (worker_lease_id)
        REFERENCES worker_lease_acquisitions(lease_id) ON DELETE RESTRICT,
    FOREIGN KEY (sprint_id, worker_launch_id)
        REFERENCES runner_launch_intents(sprint_id, launch_id) ON DELETE RESTRICT,
    FOREIGN KEY (sprint_id, worker_session_id)
        REFERENCES runner_session_policies(sprint_id, session_id) ON DELETE RESTRICT,
    FOREIGN KEY (sprint_id, input_snapshot_id)
        REFERENCES workspace_snapshots(sprint_id, snapshot_id) ON DELETE RESTRICT,
    FOREIGN KEY (sprint_id, result_snapshot_id)
        REFERENCES workspace_snapshots(sprint_id, snapshot_id) ON DELETE RESTRICT,
    FOREIGN KEY (sprint_id, effect_id)
        REFERENCES effect_intents(sprint_id, effect_id)
        ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED
) STRICT, WITHOUT ROWID;

INSERT INTO task_attempt_integration_admissions (
    admission_id, attempt_id, candidate_boundary_id, sprint_id, task_id,
    worker_id, worker_lease_id, lease_epoch, effect_id, worker_launch_id,
    worker_session_id, input_snapshot_id, result_snapshot_id,
    contract_version, admitted_at_unix_ms, request_json, admission_json
)
SELECT admission_id, attempt_id, candidate_boundary_id, sprint_id, task_id,
       worker_id, worker_lease_id, lease_epoch, effect_id, worker_launch_id,
       worker_session_id, input_snapshot_id, result_snapshot_id,
       contract_version, admitted_at_unix_ms, request_json, admission_json
FROM v16_preserved_task_integration_admissions;

CREATE TRIGGER task_attempt_integration_admissions_no_update
BEFORE UPDATE ON task_attempt_integration_admissions
BEGIN SELECT RAISE(ABORT, 'attempt integration admissions are immutable'); END;
CREATE TRIGGER task_attempt_integration_admissions_no_delete
BEFORE DELETE ON task_attempt_integration_admissions
BEGIN SELECT RAISE(ABORT, 'attempt integration admissions are immutable'); END;

CREATE TRIGGER task_attempt_integration_admission_validate
BEFORE INSERT ON task_attempt_integration_admissions
WHEN NOT EXISTS (
       SELECT 1
       FROM task_attempts attempt
       JOIN active_worker_leases active ON active.lease_id = attempt.worker_lease_id
       JOIN task_attempt_candidate_boundaries candidate
         ON candidate.attempt_id = attempt.attempt_id
       JOIN task_attempt_verification_boundaries verification
         ON verification.boundary_id = candidate.verification_boundary_id
       JOIN change_sets change_set
         ON change_set.sprint_id = attempt.sprint_id
        AND change_set.change_set_id = candidate.change_set_id
       JOIN runner_launch_intents launch
         ON launch.launch_id = NEW.worker_launch_id
       JOIN runner_session_policies session
         ON session.session_id = NEW.worker_session_id
       WHERE attempt.attempt_id = NEW.attempt_id
         AND attempt.schema_generation = 15
         AND attempt.sprint_id = NEW.sprint_id
         AND attempt.task_id = NEW.task_id
         AND attempt.worker_id = NEW.worker_id
         AND attempt.worker_lease_id = NEW.worker_lease_id
         AND attempt.lease_epoch = NEW.lease_epoch
         AND candidate.boundary_id = NEW.candidate_boundary_id
         AND candidate.sealed_snapshot_id = NEW.result_snapshot_id
         AND verification.attempt_id = attempt.attempt_id
         AND verification.worker_launch_id = NEW.worker_launch_id
         AND verification.worker_session_id = NEW.worker_session_id
         AND change_set.base_snapshot = NEW.input_snapshot_id
         AND change_set.result_snapshot = NEW.result_snapshot_id
         AND launch.worker_lease_id = NEW.worker_lease_id
         AND launch.worker_lease_epoch = NEW.lease_epoch
         AND session.launch_id = launch.launch_id
         AND session.worker_lease_id = NEW.worker_lease_id
         AND session.worker_lease_epoch = NEW.lease_epoch
         AND NEW.contract_version = attempt.contract_version
         AND NEW.admitted_at_unix_ms >= candidate.admitted_at_unix_ms
         AND json_type(CAST(NEW.request_json AS TEXT), '$.artifact.format_version') = 'integer'
         AND json_extract(CAST(NEW.request_json AS TEXT), '$.artifact.format_version') > 0
         AND length(json_extract(
             CAST(NEW.request_json AS TEXT), '$.artifact.artifact_digest')) = 64
         AND json_extract(CAST(NEW.request_json AS TEXT), '$.artifact.artifact_digest')
             NOT GLOB '*[^0-9a-f]*'
         AND NEW.request_json = CAST(json_object(
             'contract_version', NEW.contract_version,
             'change_set', json(CAST(change_set.change_set_json AS TEXT)),
             'artifact', json_object(
                 'format_version', json_extract(
                     CAST(NEW.request_json AS TEXT), '$.artifact.format_version'),
                 'artifact_digest', json_extract(
                     CAST(NEW.request_json AS TEXT), '$.artifact.artifact_digest'),
                 'change_set_id', candidate.change_set_id,
                 'base_snapshot', NEW.input_snapshot_id,
                 'result_snapshot', NEW.result_snapshot_id
             )
         ) AS BLOB)
         AND NEW.admission_json = CAST(json_object(
             'contract_version', NEW.contract_version,
             'admission_id', NEW.admission_id,
             'candidate_boundary', json(CAST(candidate.boundary_json AS TEXT)),
             'effect_id', NEW.effect_id,
             'runner_launch_id', NEW.worker_launch_id,
             'runner_session_id', NEW.worker_session_id,
             'input_snapshot', NEW.input_snapshot_id,
             'result_snapshot', NEW.result_snapshot_id,
             'admitted_at_unix_ms', NEW.admitted_at_unix_ms
         ) AS BLOB)
     )
 OR COALESCE((
       SELECT json_extract(CAST(event.event_json AS TEXT),
                           '$.payload.TaskStateChanged.to')
       FROM agent_events event
       WHERE event.sprint_id = NEW.sprint_id
         AND json_extract(CAST(event.event_json AS TEXT), '$.task_id') = NEW.task_id
         AND json_type(CAST(event.event_json AS TEXT),
                       '$.payload.TaskStateChanged') = 'object'
       ORDER BY event.sequence DESC LIMIT 1
     ), '') != 'Candidate'
 OR EXISTS (SELECT 1 FROM effect_intents intent WHERE intent.effect_id = NEW.effect_id)
BEGIN
    SELECT RAISE(ABORT, 'integration admission requires exact active Candidate attempt authority');
END;

DROP TABLE v16_preserved_task_integration_admissions;

CREATE TEMP TABLE v16_preserved_task_integration_receipts AS
SELECT receipt_id, sprint_id, task_id, worker_id, worker_launch_id,
       worker_session_id, worker_policy_hash, effect_id, observation_id,
       change_set_id, input_snapshot, result_snapshot, integration_ordinal,
       verification_count, contract_version, integrated_at_unix_ms,
       receipt_json, worker_lease_id, worker_lease_epoch
FROM task_integration_receipts;

DROP TABLE task_integration_receipts;

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
    verification_count INTEGER NOT NULL CHECK (verification_count >= 0),
    contract_version INTEGER NOT NULL CHECK (contract_version > 0),
    integrated_at_unix_ms INTEGER NOT NULL CHECK (integrated_at_unix_ms > 0),
    receipt_json BLOB NOT NULL CHECK (length(receipt_json) > 0),
    worker_lease_id TEXT
        REFERENCES worker_lease_acquisitions(lease_id) ON DELETE RESTRICT,
    worker_lease_epoch INTEGER
        CHECK (worker_lease_epoch IS NULL OR worker_lease_epoch > 0),
    UNIQUE (sprint_id, receipt_id),
    UNIQUE (sprint_id, task_id),
    UNIQUE (sprint_id, integration_ordinal),
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

INSERT INTO task_integration_receipts (
    receipt_id, sprint_id, task_id, worker_id, worker_launch_id,
    worker_session_id, worker_policy_hash, effect_id, observation_id,
    change_set_id, input_snapshot, result_snapshot, integration_ordinal,
    verification_count, contract_version, integrated_at_unix_ms,
    receipt_json, worker_lease_id, worker_lease_epoch
)
SELECT receipt_id, sprint_id, task_id, worker_id, worker_launch_id,
       worker_session_id, worker_policy_hash, effect_id, observation_id,
       change_set_id, input_snapshot, result_snapshot, integration_ordinal,
       verification_count, contract_version, integrated_at_unix_ms,
       receipt_json, worker_lease_id, worker_lease_epoch
FROM v16_preserved_task_integration_receipts;

CREATE INDEX task_integration_worker_lease_idx
ON task_integration_receipts (sprint_id, worker_lease_id, worker_lease_epoch);

CREATE TRIGGER task_integration_receipts_no_update
BEFORE UPDATE ON task_integration_receipts
BEGIN SELECT RAISE(ABORT, 'task integration receipts are immutable'); END;
CREATE TRIGGER task_integration_receipts_no_delete
BEFORE DELETE ON task_integration_receipts
BEGIN SELECT RAISE(ABORT, 'task integration receipts are immutable'); END;

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

CREATE TRIGGER worker_lease_bound_task_integration
BEFORE INSERT ON task_integration_receipts
WHEN json_type(CAST(NEW.receipt_json AS TEXT), '$.worker_lease') IS NULL
 OR NEW.worker_lease_id IS NULL OR NEW.worker_lease_epoch IS NULL
 OR NOT EXISTS (
      SELECT 1 FROM active_worker_leases lease
      JOIN effect_intents intent ON intent.effect_id = NEW.effect_id
      JOIN runner_launch_intents launch ON launch.launch_id = NEW.worker_launch_id
      JOIN runner_session_policies session ON session.session_id = NEW.worker_session_id
      WHERE lease.lease_id = NEW.worker_lease_id
        AND lease.sprint_id = NEW.sprint_id
        AND lease.lease_epoch = NEW.worker_lease_epoch
        AND lease.task_id = NEW.task_id
        AND lease.worker_id = NEW.worker_id
        AND intent.worker_lease_id = lease.lease_id
        AND intent.worker_lease_epoch = lease.lease_epoch
        AND launch.worker_lease_id = lease.lease_id
        AND launch.worker_lease_epoch = lease.lease_epoch
        AND session.worker_lease_id = lease.lease_id
        AND session.worker_lease_epoch = lease.lease_epoch
    )
 OR json_extract(CAST(NEW.receipt_json AS TEXT), '$.worker_lease.lease_id') != NEW.worker_lease_id
 OR json_extract(CAST(NEW.receipt_json AS TEXT), '$.worker_lease.lease_epoch') != NEW.worker_lease_epoch
BEGIN SELECT RAISE(ABORT, 'task integration lacks its exact active worker lease chain'); END;

CREATE TRIGGER task_integration_receipts_require_v15_result_coverage
BEFORE INSERT ON task_integration_receipts
WHEN EXISTS (
       SELECT 1 FROM task_attempt_integration_admissions admission
       WHERE admission.effect_id = NEW.effect_id
     )
 AND NOT EXISTS (
       SELECT 1
       FROM task_attempt_integrated_result_coverage coverage
       JOIN task_attempt_integration_admissions admission
         ON admission.admission_id = coverage.admission_id
       JOIN task_attempts attempt ON attempt.attempt_id = coverage.attempt_id
       WHERE coverage.receipt_id = NEW.receipt_id
         AND admission.effect_id = NEW.effect_id
         AND admission.attempt_id = attempt.attempt_id
         AND attempt.sprint_id = NEW.sprint_id
         AND attempt.task_id = NEW.task_id
         AND attempt.worker_id = NEW.worker_id
         AND attempt.worker_lease_id = NEW.worker_lease_id
         AND attempt.lease_epoch = NEW.worker_lease_epoch
     )
BEGIN
    SELECT RAISE(ABORT, 'current task integration receipt requires deferred Integrated disposition coverage');
END;

DROP TABLE v16_preserved_task_integration_receipts;

-- The v15 boundary trigger required snapshot progression independently of the
-- typed ChangeSet. In v16 the ChangeSet contract itself enforces the exact
-- biconditional: equal snapshots iff the operation vector is explicitly empty.
DROP TRIGGER task_attempt_verification_boundary_validate;
CREATE TRIGGER task_attempt_verification_boundary_validate
BEFORE INSERT ON task_attempt_verification_boundaries
WHEN EXISTS (
       SELECT 1 FROM agent_events event
       WHERE event.event_id = NEW.transition_event_id
     )
 OR NOT EXISTS (
       SELECT 1
       FROM task_attempts attempt
       JOIN active_worker_leases active
         ON active.lease_id = attempt.worker_lease_id
       JOIN task_attempt_running_boundaries running
         ON running.attempt_id = attempt.attempt_id
       JOIN runner_launch_intents launch
         ON launch.worker_lease_id = attempt.worker_lease_id
        AND launch.sprint_id = attempt.sprint_id
        AND launch.worker_id = attempt.worker_id
       JOIN runner_session_policies session
         ON session.launch_id = launch.launch_id
        AND session.worker_lease_id = attempt.worker_lease_id
        AND session.sprint_id = attempt.sprint_id
        AND session.worker_id = attempt.worker_id
       WHERE attempt.attempt_id = NEW.attempt_id
         AND attempt.schema_generation = 15
         AND attempt.sprint_id = NEW.sprint_id
         AND attempt.task_id = NEW.task_id
         AND attempt.worker_lease_id = NEW.worker_lease_id
         AND attempt.lease_epoch = NEW.lease_epoch
         AND running.runner_launch_id = NEW.worker_launch_id
         AND running.runner_session_id = NEW.worker_session_id
         AND launch.launch_id = NEW.worker_launch_id
         AND session.session_id = NEW.worker_session_id
         AND EXISTS (
             SELECT 1 FROM change_sets change_set
             WHERE change_set.sprint_id = NEW.sprint_id
               AND change_set.change_set_id = NEW.change_set_id
               AND change_set.result_snapshot = NEW.sealed_snapshot_id
         )
         AND NEW.contract_version = attempt.contract_version
         AND NEW.sealed_at_unix_ms >= running.started_at_unix_ms
         AND NEW.terminal_effect_count = json_array_length(
             CAST(NEW.boundary_json AS TEXT), '$.terminal_non_cleanup_effects')
         AND NEW.boundary_json = CAST(json_object(
             'contract_version', NEW.contract_version,
             'boundary_id', NEW.boundary_id,
             'attempt', json(CAST(attempt.attempt_json AS TEXT)),
             'runner_launch_id', NEW.worker_launch_id,
             'runner_session_id', NEW.worker_session_id,
             'change_set_id', NEW.change_set_id,
             'sealed_snapshot', NEW.sealed_snapshot_id,
             'transition_event_id', NEW.transition_event_id,
             'terminal_non_cleanup_effects', json(json_extract(
                 CAST(NEW.boundary_json AS TEXT), '$.terminal_non_cleanup_effects')),
             'sealed_at_unix_ms', NEW.sealed_at_unix_ms
         ) AS BLOB)
     )
 OR COALESCE((
       SELECT json_extract(CAST(event.event_json AS TEXT),
                           '$.payload.TaskStateChanged.to')
       FROM agent_events event
       WHERE event.sprint_id = NEW.sprint_id
         AND json_extract(CAST(event.event_json AS TEXT), '$.task_id') = NEW.task_id
         AND json_type(CAST(event.event_json AS TEXT),
                       '$.payload.TaskStateChanged') = 'object'
       ORDER BY event.sequence DESC LIMIT 1
     ), '') != 'Running'
 OR EXISTS (
       SELECT 1
       FROM effect_intents intent
       LEFT JOIN effect_observations observation ON observation.effect_id = intent.effect_id
       WHERE intent.worker_lease_id = NEW.worker_lease_id
         AND intent.worker_lease_epoch = NEW.lease_epoch
         AND NOT EXISTS (
             SELECT 1 FROM runner_launch_cleanup_admissions cleanup
             WHERE cleanup.cleanup_effect_id = intent.effect_id
         )
         AND (
             observation.effect_id IS NULL
             OR observation.outcome = 'Unknown'
             OR EXISTS (
                 SELECT 1 FROM unresolved_mutation_effects mutation
                 WHERE mutation.effect_id = intent.effect_id
             )
         )
     )
 OR EXISTS (
       SELECT 1 FROM task_attempt_dispositions disposition
       WHERE disposition.attempt_id = NEW.attempt_id
     )
BEGIN
    SELECT RAISE(ABORT, 'verification boundary requires exact active Running attempt and terminal earlier effects');
END;
