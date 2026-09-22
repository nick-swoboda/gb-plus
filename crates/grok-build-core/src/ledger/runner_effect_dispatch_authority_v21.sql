-- Schema-v21 distinguishes the historical claimless task-phase admissions
-- that already existed when this migration began from every admission created
-- afterward.  Absence of a dispatch claim is never itself legacy authority.
CREATE TABLE task_phase_claimless_legacy_exemptions (
    authority_class TEXT NOT NULL
        CHECK (authority_class IN ('TaskFormalCheck', 'TaskIntegration')),
    admission_id TEXT NOT NULL,
    effect_id TEXT NOT NULL UNIQUE,
    admitted_contract_version INTEGER NOT NULL CHECK (admitted_contract_version > 0),
    marked_at_schema_version INTEGER NOT NULL CHECK (marked_at_schema_version = 21),
    PRIMARY KEY (authority_class, admission_id)
) STRICT, WITHOUT ROWID;

INSERT INTO task_phase_claimless_legacy_exemptions (
    authority_class, admission_id, effect_id, admitted_contract_version,
    marked_at_schema_version
)
SELECT 'TaskFormalCheck', admission_id, effect_id, contract_version, 21
FROM task_attempt_formal_check_admissions
UNION ALL
SELECT 'TaskIntegration', admission_id, effect_id, contract_version, 21
FROM task_attempt_integration_admissions;

CREATE TRIGGER task_phase_claimless_legacy_exemptions_no_insert
BEFORE INSERT ON task_phase_claimless_legacy_exemptions
BEGIN SELECT RAISE(ABORT, 'claimless task-phase exemptions are migration-only'); END;
CREATE TRIGGER task_phase_claimless_legacy_exemptions_no_update
BEFORE UPDATE ON task_phase_claimless_legacy_exemptions
BEGIN SELECT RAISE(ABORT, 'claimless task-phase exemptions are immutable'); END;
CREATE TRIGGER task_phase_claimless_legacy_exemptions_no_delete
BEFORE DELETE ON task_phase_claimless_legacy_exemptions
BEGIN SELECT RAISE(ABORT, 'claimless task-phase exemptions are immutable'); END;

-- V15 through v20 serialized automated checks in TaskSpec reference order.
-- Mark only histories that were already complete, passing, internally exact,
-- and observably different from the v21 SprintSpec order at migration time.
-- Partial histories are intentionally not grandfathered: after migration they
-- cannot be extended by mixing the two orderings.
CREATE TABLE task_formal_order_legacy_exemptions (
    attempt_id TEXT PRIMARY KEY NOT NULL,
    sprint_id TEXT NOT NULL,
    task_id TEXT NOT NULL,
    formal_check_count INTEGER NOT NULL CHECK (formal_check_count > 0),
    marked_at_schema_version INTEGER NOT NULL CHECK (marked_at_schema_version = 21),
    UNIQUE (sprint_id, task_id, attempt_id),
    FOREIGN KEY (attempt_id) REFERENCES task_attempts(attempt_id) ON DELETE RESTRICT
) STRICT, WITHOUT ROWID;

INSERT INTO task_formal_order_legacy_exemptions (
    attempt_id, sprint_id, task_id, formal_check_count, marked_at_schema_version
)
SELECT attempt.attempt_id, attempt.sprint_id, attempt.task_id,
       (SELECT COUNT(*)
        FROM json_each(graph_task.value, '$.acceptance_checks') task_check
        JOIN json_each(CAST(sprint.spec_json AS TEXT), '$.acceptance_criteria') criterion
          ON json_extract(criterion.value, '$.criterion_id') = task_check.value
        WHERE json_type(criterion.value, '$.kind.Automated') = 'object'),
       21
FROM task_attempts attempt
JOIN sprints sprint ON sprint.sprint_id = attempt.sprint_id
JOIN sprint_task_graphs graph ON graph.sprint_id = attempt.sprint_id,
     json_each(CAST(graph.graph_json AS TEXT), '$.tasks') graph_task
WHERE attempt.schema_generation = 15
  AND json_extract(graph_task.value, '$.task_id') = attempt.task_id
  AND (SELECT COUNT(*)
       FROM json_each(graph_task.value, '$.acceptance_checks') task_check
       JOIN json_each(CAST(sprint.spec_json AS TEXT), '$.acceptance_criteria') criterion
         ON json_extract(criterion.value, '$.criterion_id') = task_check.value
       WHERE json_type(criterion.value, '$.kind.Automated') = 'object') > 0
  AND (SELECT COUNT(*)
       FROM task_attempt_formal_check_admissions admission
       WHERE admission.attempt_id = attempt.attempt_id) =
      (SELECT COUNT(*)
       FROM json_each(graph_task.value, '$.acceptance_checks') task_check
       JOIN json_each(CAST(sprint.spec_json AS TEXT), '$.acceptance_criteria') criterion
         ON json_extract(criterion.value, '$.criterion_id') = task_check.value
       WHERE json_type(criterion.value, '$.kind.Automated') = 'object')
  AND NOT EXISTS (
      SELECT 1
      FROM task_attempt_formal_check_admissions admission
      LEFT JOIN task_attempt_formal_checks formal
        ON formal.admission_id = admission.admission_id
      WHERE admission.attempt_id = attempt.attempt_id
        AND (
            formal.formal_check_id IS NULL
            OR formal.attempt_id != attempt.attempt_id
            OR formal.criterion_id != admission.criterion_id
            OR formal.criterion_ordinal != admission.criterion_ordinal
            OR formal.passed != 1
            OR NOT EXISTS (
                SELECT 1
                FROM json_each(graph_task.value, '$.acceptance_checks') task_check
                JOIN json_each(CAST(sprint.spec_json AS TEXT), '$.acceptance_criteria') criterion
                  ON json_extract(criterion.value, '$.criterion_id') = task_check.value
                WHERE json_type(criterion.value, '$.kind.Automated') = 'object'
                  AND task_check.value = admission.criterion_id
                  AND admission.criterion_ordinal = (
                      SELECT COUNT(*)
                      FROM json_each(graph_task.value, '$.acceptance_checks') prior_check
                      JOIN json_each(
                          CAST(sprint.spec_json AS TEXT), '$.acceptance_criteria'
                      ) prior_criterion
                        ON json_extract(prior_criterion.value, '$.criterion_id') = prior_check.value
                      WHERE CAST(prior_check.key AS INTEGER) < CAST(task_check.key AS INTEGER)
                        AND json_type(prior_criterion.value, '$.kind.Automated') = 'object'
                  )
            )
        )
  )
  AND EXISTS (
      SELECT 1
      FROM json_each(graph_task.value, '$.acceptance_checks') task_check
      JOIN json_each(CAST(sprint.spec_json AS TEXT), '$.acceptance_criteria') criterion
        ON json_extract(criterion.value, '$.criterion_id') = task_check.value
      WHERE json_type(criterion.value, '$.kind.Automated') = 'object'
        AND (
            SELECT COUNT(*)
            FROM json_each(graph_task.value, '$.acceptance_checks') prior_check
            JOIN json_each(CAST(sprint.spec_json AS TEXT), '$.acceptance_criteria') prior_criterion
              ON json_extract(prior_criterion.value, '$.criterion_id') = prior_check.value
            WHERE CAST(prior_check.key AS INTEGER) < CAST(task_check.key AS INTEGER)
              AND json_type(prior_criterion.value, '$.kind.Automated') = 'object'
        ) != (
            SELECT COUNT(*)
            FROM json_each(CAST(sprint.spec_json AS TEXT), '$.acceptance_criteria') prior
            WHERE CAST(prior.key AS INTEGER) < CAST(criterion.key AS INTEGER)
              AND json_type(prior.value, '$.kind.Automated') = 'object'
              AND EXISTS (
                  SELECT 1
                  FROM json_each(graph_task.value, '$.acceptance_checks') referenced
                  WHERE referenced.value = json_extract(prior.value, '$.criterion_id')
              )
        )
  );

CREATE TRIGGER task_formal_order_legacy_exemptions_no_insert
BEFORE INSERT ON task_formal_order_legacy_exemptions
BEGIN SELECT RAISE(ABORT, 'legacy formal-order exemptions are migration-only'); END;
CREATE TRIGGER task_formal_order_legacy_exemptions_no_update
BEFORE UPDATE ON task_formal_order_legacy_exemptions
BEGIN SELECT RAISE(ABORT, 'legacy formal-order exemptions are immutable'); END;
CREATE TRIGGER task_formal_order_legacy_exemptions_no_delete
BEFORE DELETE ON task_formal_order_legacy_exemptions
BEGIN SELECT RAISE(ABORT, 'legacy formal-order exemptions are immutable'); END;

-- Exact normalized sprint final-verification admission. The phase event is
-- inserted first and the effect parent follows under a deferred foreign key.
CREATE TABLE sprint_final_verification_admissions (
    admission_id TEXT PRIMARY KEY NOT NULL,
    sprint_id TEXT NOT NULL,
    sprint_phase_event_id TEXT NOT NULL UNIQUE,
    final_snapshot TEXT NOT NULL,
    effect_id TEXT NOT NULL UNIQUE,
    runner_launch_id TEXT NOT NULL,
    runner_session_id TEXT NOT NULL,
    command_digest TEXT NOT NULL,
    command_bytes BLOB NOT NULL CHECK (length(command_bytes) BETWEEN 1 AND 8388608),
    contract_version INTEGER NOT NULL CHECK (contract_version > 0),
    admitted_at_unix_ms INTEGER NOT NULL CHECK (admitted_at_unix_ms > 0),
    admission_json BLOB NOT NULL CHECK (length(admission_json) > 0),
    UNIQUE (sprint_id, admission_id),
    FOREIGN KEY (sprint_phase_event_id)
        REFERENCES agent_events(event_id) ON DELETE RESTRICT,
    FOREIGN KEY (sprint_id, final_snapshot)
        REFERENCES workspace_snapshots(sprint_id, snapshot_id) ON DELETE RESTRICT,
    FOREIGN KEY (sprint_id, runner_launch_id)
        REFERENCES runner_launch_intents(sprint_id, launch_id) ON DELETE RESTRICT,
    FOREIGN KEY (sprint_id, runner_session_id)
        REFERENCES runner_session_policies(sprint_id, session_id) ON DELETE RESTRICT,
    FOREIGN KEY (sprint_id, effect_id)
        REFERENCES effect_intents(sprint_id, effect_id)
        ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED
) STRICT, WITHOUT ROWID;

CREATE TRIGGER sprint_final_verification_admissions_no_update
BEFORE UPDATE ON sprint_final_verification_admissions
BEGIN SELECT RAISE(ABORT, 'sprint final-verification admissions are immutable'); END;
CREATE TRIGGER sprint_final_verification_admissions_no_delete
BEFORE DELETE ON sprint_final_verification_admissions
BEGIN SELECT RAISE(ABORT, 'sprint final-verification admissions are immutable'); END;

-- SQL mirrors the hard structural subset of TaskDone needed to prevent direct
-- insertion from fabricating a final snapshot. Rust readback recomputes the
-- complete conjunction, including canonical evidence bytes.
CREATE TRIGGER sprint_final_verification_admissions_v21_validate
BEFORE INSERT ON sprint_final_verification_admissions
WHEN CASE
       WHEN json_valid(CAST(NEW.admission_json AS TEXT)) = 1
        AND json_valid(CAST(NEW.command_bytes AS TEXT)) = 1
       THEN (
           CAST(NEW.command_bytes AS TEXT) != json_object(
               'program', json_extract(CAST(NEW.command_bytes AS TEXT), '$.program'),
               'arguments', json(json_extract(CAST(NEW.command_bytes AS TEXT), '$.arguments')),
               'working_directory', json_extract(
                   CAST(NEW.command_bytes AS TEXT), '$.working_directory')
           )
           OR CAST(NEW.admission_json AS TEXT) != json_object(
               'contract_version', NEW.contract_version,
               'admission_id', NEW.admission_id,
               'sprint_id', NEW.sprint_id,
               'sprint_phase_event_id', NEW.sprint_phase_event_id,
               'final_snapshot', NEW.final_snapshot,
               'effect_id', NEW.effect_id,
               'runner_launch_id', NEW.runner_launch_id,
               'runner_session_id', NEW.runner_session_id,
               'command', json(CAST(NEW.command_bytes AS TEXT)),
               'admitted_at_unix_ms', NEW.admitted_at_unix_ms
           )
       )
       ELSE 1
     END
 OR NEW.command_digest != grok_sha256(NEW.command_bytes)
 OR NOT EXISTS (SELECT 1 FROM sprint_task_graphs WHERE sprint_id = NEW.sprint_id)
 OR EXISTS (SELECT 1 FROM effect_intents WHERE effect_id = NEW.effect_id)
 OR EXISTS (SELECT 1 FROM active_worker_leases WHERE sprint_id = NEW.sprint_id)
 OR NOT EXISTS (
    SELECT 1
    FROM agent_events phase
    JOIN runner_launch_intents launch
      ON launch.sprint_id = NEW.sprint_id AND launch.launch_id = NEW.runner_launch_id
    JOIN runner_session_policies session
      ON session.sprint_id = NEW.sprint_id
     AND session.session_id = NEW.runner_session_id
     AND session.launch_id = launch.launch_id
    JOIN workspace_snapshots snapshot
      ON snapshot.sprint_id = NEW.sprint_id
     AND snapshot.snapshot_id = NEW.final_snapshot
    WHERE phase.sprint_id = NEW.sprint_id
      AND phase.event_id = NEW.sprint_phase_event_id
      AND launch.purpose = 'FinalVerifier'
      AND session.purpose = 'FinalVerifier'
      AND launch.worker_id IS NULL
      AND session.worker_id IS NULL
      AND launch.worker_lease_id IS NULL
      AND session.worker_lease_id IS NULL
      AND launch.contract_version = NEW.contract_version
      AND session.contract_version = NEW.contract_version
      AND phase.contract_version = NEW.contract_version
      AND json_extract(CAST(phase.event_json AS TEXT), '$.policy_hash') = launch.policy_hash
      AND json_extract(CAST(phase.event_json AS TEXT), '$.policy_hash') = session.policy_hash
      AND phase.occurred_at_unix_ms <= NEW.admitted_at_unix_ms
      AND launch.created_at_unix_ms <= NEW.admitted_at_unix_ms
      AND session.registered_at_unix_ms <= NEW.admitted_at_unix_ms
      AND snapshot.created_at_unix_ms <= NEW.admitted_at_unix_ms
      AND json_extract(CAST(phase.event_json AS TEXT), '$.payload.SprintStateChanged.from') = 'Running'
      AND json_extract(CAST(phase.event_json AS TEXT), '$.payload.SprintStateChanged.to') = 'FinalVerification'
      AND json_extract(CAST(phase.event_json AS TEXT), '$.task_id') IS NULL
      AND json_extract(CAST(phase.event_json AS TEXT), '$.worker_id') IS NULL
      AND NOT EXISTS (
          SELECT 1 FROM agent_events later
          WHERE later.sprint_id = NEW.sprint_id
            AND later.sequence > phase.sequence
            AND json_type(CAST(later.event_json AS TEXT), '$.payload.SprintStateChanged') = 'object'
      )
 )
 OR EXISTS (
    SELECT 1
    FROM agent_events current
    WHERE current.sprint_id = NEW.sprint_id
      AND json_type(CAST(current.event_json AS TEXT), '$.payload.SprintStateChanged') = 'object'
      AND (
          json_extract(CAST(current.event_json AS TEXT), '$.task_id') IS NOT NULL
          OR json_extract(CAST(current.event_json AS TEXT), '$.worker_id') IS NOT NULL
          OR COALESCE(json_extract(CAST(current.event_json AS TEXT), '$.payload.SprintStateChanged.from'), '') NOT IN (
              'Draft', 'Planning', 'Running', 'AwaitingAcceptance', 'FinalVerification',
              'Applying', 'Completed', 'Blocked', 'Failed', 'Canceled', 'Unknown'
          )
          OR COALESCE(json_extract(CAST(current.event_json AS TEXT), '$.payload.SprintStateChanged.to'), '') NOT IN (
              'Draft', 'Planning', 'Running', 'AwaitingAcceptance', 'FinalVerification',
              'Applying', 'Completed', 'Blocked', 'Failed', 'Canceled', 'Unknown'
          )
          OR COALESCE((
              SELECT json_extract(CAST(prior.event_json AS TEXT), '$.payload.SprintStateChanged.to')
              FROM agent_events prior
              WHERE prior.sprint_id = current.sprint_id
                AND prior.sequence < current.sequence
                AND json_type(CAST(prior.event_json AS TEXT), '$.payload.SprintStateChanged') = 'object'
              ORDER BY prior.sequence DESC LIMIT 1
          ), CASE
                 WHEN json_extract(CAST(current.event_json AS TEXT), '$.payload.SprintStateChanged.from') = 'Draft'
                 THEN 'Draft'
                 ELSE 'Running'
             END) != json_extract(CAST(current.event_json AS TEXT), '$.payload.SprintStateChanged.from')
          OR NOT (
              (json_extract(CAST(current.event_json AS TEXT), '$.payload.SprintStateChanged.from') = 'Draft'
               AND json_extract(CAST(current.event_json AS TEXT), '$.payload.SprintStateChanged.to') = 'Planning')
              OR (json_extract(CAST(current.event_json AS TEXT), '$.payload.SprintStateChanged.from') = 'Planning'
                  AND json_extract(CAST(current.event_json AS TEXT), '$.payload.SprintStateChanged.to') IN ('Running', 'AwaitingAcceptance'))
              OR (json_extract(CAST(current.event_json AS TEXT), '$.payload.SprintStateChanged.from') = 'Running'
                  AND json_extract(CAST(current.event_json AS TEXT), '$.payload.SprintStateChanged.to') IN ('AwaitingAcceptance', 'FinalVerification'))
              OR (json_extract(CAST(current.event_json AS TEXT), '$.payload.SprintStateChanged.from') = 'AwaitingAcceptance'
                  AND json_extract(CAST(current.event_json AS TEXT), '$.payload.SprintStateChanged.to') IN ('Running', 'FinalVerification'))
              OR (json_extract(CAST(current.event_json AS TEXT), '$.payload.SprintStateChanged.from') = 'FinalVerification'
                  AND json_extract(CAST(current.event_json AS TEXT), '$.payload.SprintStateChanged.to') IN ('Running', 'AwaitingAcceptance', 'Applying'))
              OR (json_extract(CAST(current.event_json AS TEXT), '$.payload.SprintStateChanged.from') IN (
                      'Draft', 'Planning', 'Running', 'AwaitingAcceptance', 'FinalVerification', 'Applying'
                  )
                  AND json_extract(CAST(current.event_json AS TEXT), '$.payload.SprintStateChanged.to') IN (
                      'Blocked', 'Failed', 'Canceled', 'Unknown'
                  ))
          )
      )
 )
 OR EXISTS (
    SELECT 1
    FROM sprint_task_graphs graph
    JOIN json_each(CAST(graph.graph_json AS TEXT), '$.tasks') task
    WHERE graph.sprint_id = NEW.sprint_id
      AND json_extract(task.value, '$.required') = 1
      AND NOT EXISTS (
          SELECT 1
          FROM task_attempts attempt
          JOIN task_attempt_dispositions disposition
            ON disposition.attempt_id = attempt.attempt_id
           AND disposition.disposition_kind = 'Integrated'
          JOIN task_integration_receipts receipt
            ON receipt.receipt_id = disposition.integration_receipt_id
           AND receipt.sprint_id = attempt.sprint_id
           AND receipt.task_id = attempt.task_id
          WHERE attempt.sprint_id = NEW.sprint_id
            AND attempt.task_id = json_extract(task.value, '$.task_id')
            AND attempt.schema_generation = 15
            AND attempt.attempt_ordinal = (
                SELECT MAX(latest.attempt_ordinal)
                FROM task_attempts latest
                WHERE latest.sprint_id = attempt.sprint_id
                  AND latest.task_id = attempt.task_id
                  AND latest.schema_generation = 15
            )
            AND COALESCE((
                SELECT json_extract(CAST(state.event_json AS TEXT), '$.payload.TaskStateChanged.to')
                FROM agent_events state
                WHERE state.sprint_id = attempt.sprint_id
                  AND json_extract(CAST(state.event_json AS TEXT), '$.task_id') = attempt.task_id
                  AND json_type(CAST(state.event_json AS TEXT), '$.payload.TaskStateChanged') = 'object'
                ORDER BY state.sequence DESC LIMIT 1
            ), '') = 'Integrated'
      )
 )
 OR EXISTS (
    SELECT 1 FROM task_attempts attempt
    LEFT JOIN task_attempt_dispositions disposition
      ON disposition.attempt_id = attempt.attempt_id
    WHERE attempt.sprint_id = NEW.sprint_id
      AND attempt.schema_generation = 15
      AND disposition.attempt_id IS NULL
 )
 OR EXISTS (
    SELECT 1
    FROM runner_launch_intents launch
    LEFT JOIN worker_cleanup_receipts cleanup
      ON cleanup.sprint_id = launch.sprint_id AND cleanup.launch_id = launch.launch_id
    WHERE launch.sprint_id = NEW.sprint_id
      AND launch.purpose = 'TaskWorker'
      AND (cleanup.receipt_id IS NULL OR cleanup.surviving_processes != 0)
 )
 OR EXISTS (
    SELECT 1
    FROM effect_intents intent
    LEFT JOIN effect_session_bindings binding
      ON binding.sprint_id = intent.sprint_id AND binding.effect_id = intent.effect_id
    LEFT JOIN runner_launch_intents launch
      ON launch.sprint_id = binding.sprint_id AND launch.launch_id = binding.launch_id
    LEFT JOIN effect_observations observation ON observation.effect_id = intent.effect_id
    WHERE intent.sprint_id = NEW.sprint_id
      AND (
          intent.task_id IS NOT NULL
          OR intent.worker_lease_id IS NOT NULL
          OR launch.purpose = 'TaskWorker'
      )
      AND (observation.effect_id IS NULL OR observation.outcome = 'Unknown')
 )
 OR EXISTS (
    SELECT 1
    FROM effect_session_bindings binding
    JOIN runner_session_policies session
      ON session.sprint_id = binding.sprint_id AND session.session_id = binding.session_id
    JOIN effect_intents intent ON intent.effect_id = binding.effect_id
    LEFT JOIN command_domain_cleanup_proofs proof ON proof.effect_id = intent.effect_id
    WHERE binding.sprint_id = NEW.sprint_id
      AND session.purpose = 'TaskWorker'
      AND intent.effect_kind = 'RunCommand'
      AND proof.effect_id IS NULL
 )
 OR EXISTS (
    SELECT 1
    FROM task_attempts attempt
    WHERE attempt.sprint_id = NEW.sprint_id
      AND attempt.schema_generation = 15
      AND NOT EXISTS (
          SELECT 1
          FROM sprint_task_graphs graph
          JOIN json_each(CAST(graph.graph_json AS TEXT), '$.tasks') task
            ON json_extract(task.value, '$.task_id') = attempt.task_id
          WHERE graph.sprint_id = NEW.sprint_id
      )
 )
 OR EXISTS (
    SELECT 1
    FROM task_attempts attempt
    JOIN task_attempt_dispositions disposition
      ON disposition.attempt_id = attempt.attempt_id
    WHERE attempt.sprint_id = NEW.sprint_id
      AND attempt.schema_generation = 15
      AND attempt.attempt_ordinal < (
          SELECT MAX(latest.attempt_ordinal)
          FROM task_attempts latest
          WHERE latest.sprint_id = attempt.sprint_id
            AND latest.task_id = attempt.task_id
            AND latest.schema_generation = 15
      )
      AND disposition.disposition_kind != 'Retryable'
 )
 OR EXISTS (
    SELECT 1
    FROM task_attempts attempt
    JOIN task_attempt_dispositions disposition
      ON disposition.attempt_id = attempt.attempt_id
    JOIN sprint_task_graphs graph ON graph.sprint_id = attempt.sprint_id
    JOIN json_each(CAST(graph.graph_json AS TEXT), '$.tasks') task
      ON json_extract(task.value, '$.task_id') = attempt.task_id
     AND json_extract(task.value, '$.required') = 0
    WHERE attempt.sprint_id = NEW.sprint_id
      AND attempt.schema_generation = 15
      AND attempt.attempt_ordinal = (
          SELECT MAX(latest.attempt_ordinal)
          FROM task_attempts latest
          WHERE latest.sprint_id = attempt.sprint_id
            AND latest.task_id = attempt.task_id
            AND latest.schema_generation = 15
      )
      AND NOT (
          (disposition.disposition_kind = 'Integrated'
           AND COALESCE((
               SELECT json_extract(CAST(state.event_json AS TEXT), '$.payload.TaskStateChanged.to')
               FROM agent_events state
               WHERE state.sprint_id = attempt.sprint_id
                 AND json_extract(CAST(state.event_json AS TEXT), '$.task_id') = attempt.task_id
                 AND json_type(CAST(state.event_json AS TEXT), '$.payload.TaskStateChanged') = 'object'
               ORDER BY state.sequence DESC LIMIT 1
           ), '') = 'Integrated')
          OR (disposition.disposition_kind IN ('AttemptsExhausted', 'PermanentFailure')
              AND COALESCE((
                  SELECT json_extract(CAST(state.event_json AS TEXT), '$.payload.TaskStateChanged.to')
                  FROM agent_events state
                  WHERE state.sprint_id = attempt.sprint_id
                    AND json_extract(CAST(state.event_json AS TEXT), '$.task_id') = attempt.task_id
                    AND json_type(CAST(state.event_json AS TEXT), '$.payload.TaskStateChanged') = 'object'
                  ORDER BY state.sequence DESC LIMIT 1
              ), '') = 'Failed')
          OR (disposition.disposition_kind = 'Blocked'
              AND COALESCE((
                  SELECT json_extract(CAST(state.event_json AS TEXT), '$.payload.TaskStateChanged.to')
                  FROM agent_events state
                  WHERE state.sprint_id = attempt.sprint_id
                    AND json_extract(CAST(state.event_json AS TEXT), '$.task_id') = attempt.task_id
                    AND json_type(CAST(state.event_json AS TEXT), '$.payload.TaskStateChanged') = 'object'
                  ORDER BY state.sequence DESC LIMIT 1
              ), '') = 'Blocked')
          OR (disposition.disposition_kind = 'Canceled'
              AND COALESCE((
                  SELECT json_extract(CAST(state.event_json AS TEXT), '$.payload.TaskStateChanged.to')
                  FROM agent_events state
                  WHERE state.sprint_id = attempt.sprint_id
                    AND json_extract(CAST(state.event_json AS TEXT), '$.task_id') = attempt.task_id
                    AND json_type(CAST(state.event_json AS TEXT), '$.payload.TaskStateChanged') = 'object'
                  ORDER BY state.sequence DESC LIMIT 1
              ), '') = 'Canceled')
      )
 )
 OR EXISTS (
    SELECT 1
    FROM task_attempts attempt
    JOIN sprints sprint ON sprint.sprint_id = attempt.sprint_id
    WHERE attempt.sprint_id = NEW.sprint_id
      AND attempt.schema_generation = 15
    GROUP BY attempt.task_id
    HAVING COUNT(*) > json_extract(CAST(sprint.spec_json AS TEXT), '$.budget.max_attempts_per_task')
 )
 OR (
    (SELECT COUNT(*)
     FROM task_integration_receipts receipt
     JOIN task_attempt_dispositions disposition
       ON disposition.integration_receipt_id = receipt.receipt_id
      AND disposition.disposition_kind = 'Integrated'
     JOIN task_attempts attempt
       ON attempt.attempt_id = disposition.attempt_id
      AND attempt.sprint_id = receipt.sprint_id
      AND attempt.task_id = receipt.task_id
      AND attempt.schema_generation = 15
     JOIN sprint_task_graphs graph ON graph.sprint_id = receipt.sprint_id
     JOIN json_each(CAST(graph.graph_json AS TEXT), '$.tasks') task
       ON json_extract(task.value, '$.task_id') = receipt.task_id
     WHERE receipt.sprint_id = NEW.sprint_id
       AND attempt.attempt_ordinal = (
           SELECT MAX(latest.attempt_ordinal)
           FROM task_attempts latest
           WHERE latest.sprint_id = attempt.sprint_id
             AND latest.task_id = attempt.task_id
             AND latest.schema_generation = 15
       ))
    != COALESCE((
        SELECT MAX(receipt.integration_ordinal) + 1
        FROM task_integration_receipts receipt
        JOIN task_attempt_dispositions disposition
          ON disposition.integration_receipt_id = receipt.receipt_id
         AND disposition.disposition_kind = 'Integrated'
        JOIN task_attempts attempt
          ON attempt.attempt_id = disposition.attempt_id
         AND attempt.sprint_id = receipt.sprint_id
         AND attempt.task_id = receipt.task_id
         AND attempt.schema_generation = 15
        JOIN sprint_task_graphs graph ON graph.sprint_id = receipt.sprint_id
        JOIN json_each(CAST(graph.graph_json AS TEXT), '$.tasks') task
          ON json_extract(task.value, '$.task_id') = receipt.task_id
        WHERE receipt.sprint_id = NEW.sprint_id
          AND attempt.attempt_ordinal = (
              SELECT MAX(latest.attempt_ordinal)
              FROM task_attempts latest
              WHERE latest.sprint_id = attempt.sprint_id
                AND latest.task_id = attempt.task_id
                AND latest.schema_generation = 15
          )
    ), 0)
 )
 OR EXISTS (
    SELECT 1
    FROM task_integration_receipts receipt
    JOIN task_attempt_dispositions disposition
      ON disposition.integration_receipt_id = receipt.receipt_id
     AND disposition.disposition_kind = 'Integrated'
    JOIN task_attempts attempt
      ON attempt.attempt_id = disposition.attempt_id
     AND attempt.sprint_id = receipt.sprint_id
     AND attempt.task_id = receipt.task_id
     AND attempt.schema_generation = 15
    JOIN sprint_task_graphs graph ON graph.sprint_id = receipt.sprint_id
    JOIN json_each(CAST(graph.graph_json AS TEXT), '$.tasks') task
      ON json_extract(task.value, '$.task_id') = receipt.task_id
    WHERE receipt.sprint_id = NEW.sprint_id
      AND attempt.attempt_ordinal = (
          SELECT MAX(latest.attempt_ordinal)
          FROM task_attempts latest
          WHERE latest.sprint_id = attempt.sprint_id
            AND latest.task_id = attempt.task_id
            AND latest.schema_generation = 15
      )
      AND (
          (receipt.integration_ordinal = 0
           AND receipt.input_snapshot != (
               SELECT json_extract(CAST(sprint.spec_json AS TEXT), '$.base_snapshot')
               FROM sprints sprint WHERE sprint.sprint_id = NEW.sprint_id
           ))
          OR (receipt.integration_ordinal > 0 AND NOT EXISTS (
              SELECT 1
              FROM task_integration_receipts prior
              JOIN task_attempt_dispositions prior_disposition
                ON prior_disposition.integration_receipt_id = prior.receipt_id
               AND prior_disposition.disposition_kind = 'Integrated'
              JOIN task_attempts prior_attempt
                ON prior_attempt.attempt_id = prior_disposition.attempt_id
               AND prior_attempt.sprint_id = prior.sprint_id
               AND prior_attempt.task_id = prior.task_id
               AND prior_attempt.schema_generation = 15
              JOIN sprint_task_graphs prior_graph ON prior_graph.sprint_id = prior.sprint_id
              JOIN json_each(CAST(prior_graph.graph_json AS TEXT), '$.tasks') prior_task
                ON json_extract(prior_task.value, '$.task_id') = prior.task_id
              WHERE prior.sprint_id = NEW.sprint_id
                AND prior.integration_ordinal = receipt.integration_ordinal - 1
                AND prior.result_snapshot = receipt.input_snapshot
                AND prior_attempt.attempt_ordinal = (
                    SELECT MAX(latest.attempt_ordinal)
                    FROM task_attempts latest
                    WHERE latest.sprint_id = prior_attempt.sprint_id
                      AND latest.task_id = prior_attempt.task_id
                      AND latest.schema_generation = 15
                )
          ))
      )
 )
 OR NEW.final_snapshot != COALESCE(
    (SELECT receipt.result_snapshot
     FROM task_integration_receipts receipt
     JOIN task_attempt_dispositions disposition
       ON disposition.integration_receipt_id = receipt.receipt_id
      AND disposition.disposition_kind = 'Integrated'
     JOIN task_attempts attempt
       ON attempt.attempt_id = disposition.attempt_id
      AND attempt.sprint_id = receipt.sprint_id
      AND attempt.task_id = receipt.task_id
      AND attempt.schema_generation = 15
     JOIN sprint_task_graphs graph ON graph.sprint_id = receipt.sprint_id
     JOIN json_each(CAST(graph.graph_json AS TEXT), '$.tasks') task
       ON json_extract(task.value, '$.task_id') = receipt.task_id
     WHERE receipt.sprint_id = NEW.sprint_id
       AND attempt.attempt_ordinal = (
           SELECT MAX(latest.attempt_ordinal)
           FROM task_attempts latest
           WHERE latest.sprint_id = attempt.sprint_id
             AND latest.task_id = attempt.task_id
             AND latest.schema_generation = 15
       )
     ORDER BY receipt.integration_ordinal DESC LIMIT 1),
    (SELECT json_extract(CAST(sprint.spec_json AS TEXT), '$.base_snapshot')
     FROM sprints sprint WHERE sprint.sprint_id = NEW.sprint_id)
 )
BEGIN SELECT RAISE(ABORT, 'final verification admission requires exact closed TaskDone snapshot authority'); END;

-- Schema v15 serialized checks in TaskSpec reference order. Schema v21
-- normalizes new authority to the referenced automated criteria filtered in
-- SprintSpec declaration order. Historical rows remain readable in Rust, but
-- direct SQL can mint only the normalized order from this point forward.
DROP TRIGGER task_attempt_formal_check_admission_validate;

CREATE TRIGGER task_attempt_formal_check_admission_validate
BEFORE INSERT ON task_attempt_formal_check_admissions
WHEN NOT EXISTS (
       SELECT 1
       FROM task_attempts attempt
       JOIN active_worker_leases active ON active.lease_id = attempt.worker_lease_id
       JOIN task_attempt_verification_boundaries boundary
         ON boundary.attempt_id = attempt.attempt_id
       JOIN runner_session_policies session
         ON session.session_id = NEW.worker_session_id
       WHERE attempt.attempt_id = NEW.attempt_id
         AND attempt.schema_generation = 15
         AND attempt.sprint_id = NEW.sprint_id
         AND attempt.task_id = NEW.task_id
         AND boundary.sealed_snapshot_id = NEW.sealed_snapshot_id
         AND boundary.worker_session_id = NEW.worker_session_id
         AND session.worker_lease_id = attempt.worker_lease_id
         AND session.worker_lease_epoch = attempt.lease_epoch
         AND NEW.contract_version = attempt.contract_version
         AND NEW.admitted_at_unix_ms >= boundary.sealed_at_unix_ms
         AND CAST(NEW.command_spec_json AS TEXT) = CAST(json_object(
             'program', json_extract(CAST(NEW.command_spec_json AS TEXT), '$.program'),
             'arguments', json(json_extract(CAST(NEW.command_spec_json AS TEXT), '$.arguments')),
             'working_directory', json_extract(
                 CAST(NEW.command_spec_json AS TEXT), '$.working_directory')
         ) AS TEXT)
         AND NEW.admission_json = CAST(json_object(
             'contract_version', NEW.contract_version,
             'admission_id', NEW.admission_id,
             'attempt', json(CAST(attempt.attempt_json AS TEXT)),
             'criterion_ordinal', NEW.criterion_ordinal,
             'criterion_id', NEW.criterion_id,
             'effect_id', NEW.effect_id,
             'runner_session_id', NEW.worker_session_id,
             'sealed_snapshot', NEW.sealed_snapshot_id,
             'command', json(CAST(NEW.command_spec_json AS TEXT)),
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
     ), '') != 'Verifying'
 OR EXISTS (
       SELECT 1
       FROM task_attempt_formal_check_admissions existing
       LEFT JOIN task_attempt_formal_checks completed
              ON completed.admission_id = existing.admission_id
       WHERE existing.attempt_id = NEW.attempt_id
         AND completed.formal_check_id IS NULL
     )
 OR EXISTS (
       SELECT 1
       FROM task_attempt_formal_checks failed
       WHERE failed.attempt_id = NEW.attempt_id
         AND failed.passed = 0
     )
 OR NEW.criterion_ordinal != (
       SELECT COUNT(*) FROM task_attempt_formal_check_admissions existing
       WHERE existing.attempt_id = NEW.attempt_id
     )
 OR EXISTS (
       SELECT 1 FROM task_formal_order_legacy_exemptions legacy
       WHERE legacy.attempt_id = NEW.attempt_id
     )
 OR NOT EXISTS (
       SELECT 1
       FROM sprints sprint
       JOIN sprint_task_graphs graph ON graph.sprint_id = sprint.sprint_id,
            json_each(CAST(graph.graph_json AS TEXT), '$.tasks') graph_task,
            json_each(CAST(sprint.spec_json AS TEXT), '$.acceptance_criteria') criterion
       WHERE sprint.sprint_id = NEW.sprint_id
         AND json_extract(graph_task.value, '$.task_id') = NEW.task_id
         AND EXISTS (
             SELECT 1 FROM json_each(graph_task.value, '$.acceptance_checks') task_check
             WHERE task_check.value = json_extract(criterion.value, '$.criterion_id')
         )
         AND json_extract(criterion.value, '$.criterion_id') = NEW.criterion_id
         AND json_type(criterion.value, '$.kind.Automated') = 'object'
         AND json(json_extract(criterion.value, '$.kind.Automated')) =
             json(CAST(NEW.command_spec_json AS TEXT))
         AND NEW.criterion_ordinal = (
             SELECT COUNT(*)
             FROM json_each(CAST(sprint.spec_json AS TEXT), '$.acceptance_criteria') prior
             WHERE CAST(prior.key AS INTEGER) < CAST(criterion.key AS INTEGER)
               AND json_type(prior.value, '$.kind.Automated') = 'object'
               AND EXISTS (
                   SELECT 1
                   FROM json_each(graph_task.value, '$.acceptance_checks') prior_task_check
                   WHERE prior_task_check.value = json_extract(prior.value, '$.criterion_id')
               )
         )
     )
 OR EXISTS (SELECT 1 FROM effect_intents intent WHERE intent.effect_id = NEW.effect_id)
BEGIN
    SELECT RAISE(ABORT, 'formal-check admission must be the next SprintSpec-ordered automated criterion');
END;

DROP TRIGGER agent_events_cover_candidate_boundary;

CREATE TRIGGER agent_events_cover_candidate_boundary
AFTER INSERT ON agent_events
WHEN EXISTS (
       SELECT 1 FROM task_attempt_candidate_boundaries boundary
       WHERE boundary.transition_event_id = NEW.event_id
     )
 AND NOT EXISTS (
       SELECT 1
       FROM task_attempt_candidate_boundaries boundary
       JOIN task_attempts attempt ON attempt.attempt_id = boundary.attempt_id
       WHERE boundary.transition_event_id = NEW.event_id
         AND attempt.schema_generation = 15
         AND boundary.sprint_id = attempt.sprint_id
         AND boundary.task_id = attempt.task_id
         AND boundary.worker_lease_id = attempt.worker_lease_id
         AND boundary.lease_epoch = attempt.lease_epoch
         AND EXISTS (
             SELECT 1 FROM task_attempt_verification_boundaries verification
             WHERE verification.boundary_id = boundary.verification_boundary_id
               AND verification.attempt_id = boundary.attempt_id
               AND verification.change_set_id = boundary.change_set_id
               AND verification.sealed_snapshot_id = boundary.sealed_snapshot_id
         )
         AND NEW.sprint_id = attempt.sprint_id
         AND NEW.occurred_at_unix_ms = boundary.admitted_at_unix_ms
         AND json_type(CAST(NEW.event_json AS TEXT), '$.payload.TaskStateChanged') = 'object'
         AND json_extract(CAST(NEW.event_json AS TEXT), '$.payload.TaskStateChanged.from') = 'Verifying'
         AND json_extract(CAST(NEW.event_json AS TEXT), '$.payload.TaskStateChanged.to') = 'Candidate'
         AND json_extract(CAST(NEW.event_json AS TEXT), '$.task_id') = attempt.task_id
         AND json_extract(CAST(NEW.event_json AS TEXT), '$.worker_id') = attempt.worker_id
         AND boundary.formal_check_count = (
             SELECT COUNT(*) FROM task_attempt_candidate_formal_checks link
             WHERE link.candidate_boundary_id = boundary.boundary_id
         )
         AND NOT EXISTS (
             SELECT 1
             FROM json_each(CAST(boundary.boundary_json AS TEXT), '$.formal_check_ids') formal_id
             JOIN json_each(
                 CAST(boundary.boundary_json AS TEXT), '$.verification_receipt_ids'
             ) receipt_id ON receipt_id.key = formal_id.key
             LEFT JOIN task_attempt_candidate_formal_checks link
               ON link.candidate_boundary_id = boundary.boundary_id
              AND link.ordinal = CAST(formal_id.key AS INTEGER)
              AND link.formal_check_id = formal_id.value
              AND link.verification_receipt_id = receipt_id.value
             WHERE link.candidate_boundary_id IS NULL
         )
         AND boundary.formal_check_count = (
             SELECT COUNT(*)
             FROM sprints sprint
             JOIN sprint_task_graphs graph ON graph.sprint_id = sprint.sprint_id,
                  json_each(CAST(graph.graph_json AS TEXT), '$.tasks') graph_task,
                  json_each(CAST(sprint.spec_json AS TEXT), '$.acceptance_criteria') criterion
             WHERE sprint.sprint_id = boundary.sprint_id
               AND json_extract(graph_task.value, '$.task_id') = boundary.task_id
               AND json_type(criterion.value, '$.kind.Automated') = 'object'
               AND EXISTS (
                   SELECT 1 FROM json_each(graph_task.value, '$.acceptance_checks') task_check
                   WHERE task_check.value = json_extract(criterion.value, '$.criterion_id')
               )
         )
         AND (
             (
                 EXISTS (
                     SELECT 1 FROM task_formal_order_legacy_exemptions legacy
                     WHERE legacy.attempt_id = attempt.attempt_id
                       AND legacy.sprint_id = boundary.sprint_id
                       AND legacy.task_id = boundary.task_id
                       AND legacy.formal_check_count = boundary.formal_check_count
                 )
                 AND NOT EXISTS (
                     SELECT 1
                     FROM sprints sprint
                     JOIN sprint_task_graphs graph ON graph.sprint_id = sprint.sprint_id,
                          json_each(CAST(graph.graph_json AS TEXT), '$.tasks') graph_task,
                          json_each(graph_task.value, '$.acceptance_checks') task_check,
                          json_each(CAST(sprint.spec_json AS TEXT), '$.acceptance_criteria') criterion
                     WHERE sprint.sprint_id = boundary.sprint_id
                       AND json_extract(graph_task.value, '$.task_id') = boundary.task_id
                       AND json_extract(criterion.value, '$.criterion_id') = task_check.value
                       AND json_type(criterion.value, '$.kind.Automated') = 'object'
                       AND NOT EXISTS (
                           SELECT 1 FROM task_attempt_candidate_formal_checks expected_link
                           WHERE expected_link.candidate_boundary_id = boundary.boundary_id
                             AND expected_link.criterion_id = task_check.value
                             AND expected_link.ordinal = (
                                 SELECT COUNT(*)
                                 FROM json_each(graph_task.value, '$.acceptance_checks') prior_check
                                 JOIN json_each(
                                     CAST(sprint.spec_json AS TEXT), '$.acceptance_criteria'
                                 ) prior_criterion
                                   ON json_extract(prior_criterion.value, '$.criterion_id') = prior_check.value
                                 WHERE CAST(prior_check.key AS INTEGER) < CAST(task_check.key AS INTEGER)
                                   AND json_type(prior_criterion.value, '$.kind.Automated') = 'object'
                             )
                       )
                 )
             )
             OR
             (
                 NOT EXISTS (
                     SELECT 1 FROM task_formal_order_legacy_exemptions legacy
                     WHERE legacy.attempt_id = attempt.attempt_id
                 )
                 AND NOT EXISTS (
                     SELECT 1
                     FROM sprints sprint
                     JOIN sprint_task_graphs graph ON graph.sprint_id = sprint.sprint_id,
                          json_each(CAST(graph.graph_json AS TEXT), '$.tasks') graph_task,
                          json_each(CAST(sprint.spec_json AS TEXT), '$.acceptance_criteria') criterion
                     WHERE sprint.sprint_id = boundary.sprint_id
                       AND json_extract(graph_task.value, '$.task_id') = boundary.task_id
                       AND json_type(criterion.value, '$.kind.Automated') = 'object'
                       AND EXISTS (
                           SELECT 1 FROM json_each(graph_task.value, '$.acceptance_checks') task_check
                           WHERE task_check.value = json_extract(criterion.value, '$.criterion_id')
                       )
                       AND NOT EXISTS (
                           SELECT 1 FROM task_attempt_candidate_formal_checks expected_link
                           WHERE expected_link.candidate_boundary_id = boundary.boundary_id
                             AND expected_link.criterion_id = json_extract(criterion.value, '$.criterion_id')
                             AND expected_link.ordinal = (
                                 SELECT COUNT(*)
                                 FROM json_each(CAST(sprint.spec_json AS TEXT), '$.acceptance_criteria') prior
                                 WHERE CAST(prior.key AS INTEGER) < CAST(criterion.key AS INTEGER)
                                   AND json_type(prior.value, '$.kind.Automated') = 'object'
                                   AND EXISTS (
                                       SELECT 1
                                       FROM json_each(graph_task.value, '$.acceptance_checks') prior_task_check
                                       WHERE prior_task_check.value = json_extract(prior.value, '$.criterion_id')
                                   )
                             )
                       )
                 )
             )
         )
         AND NOT EXISTS (
             SELECT 1
             FROM task_attempt_candidate_formal_checks link
             LEFT JOIN task_attempt_formal_checks formal
                    ON formal.formal_check_id = link.formal_check_id
             WHERE link.candidate_boundary_id = boundary.boundary_id
               AND (
                   formal.formal_check_id IS NULL
                   OR formal.attempt_id != attempt.attempt_id
                   OR formal.criterion_id != link.criterion_id
                   OR formal.criterion_ordinal != link.ordinal
                   OR formal.verification_receipt_id != link.verification_receipt_id
                   OR formal.passed != 1
               )
         )
     )
BEGIN
    SELECT RAISE(ABORT, 'candidate-boundary event must close SprintSpec-ordered passing-check authority');
END;

CREATE TRIGGER effect_intents_cover_sprint_final_verification_admission
AFTER INSERT ON effect_intents
WHEN (
       EXISTS (
           SELECT 1 FROM sprint_final_verification_admissions admission
           WHERE admission.effect_id = NEW.effect_id
       )
       OR (
           NEW.effect_kind = 'RunCommand'
           AND NEW.task_id IS NULL
           AND NEW.worker_id IS NULL
           AND NEW.worker_lease_id IS NULL
           AND EXISTS (
               SELECT 1
               FROM effect_session_bindings binding
               JOIN runner_session_policies session
                 ON session.sprint_id = binding.sprint_id
                AND session.session_id = binding.session_id
               WHERE binding.effect_id = NEW.effect_id
                 AND binding.sprint_id = NEW.sprint_id
                 AND session.purpose = 'FinalVerifier'
           )
           AND COALESCE((
               SELECT json_extract(CAST(phase.event_json AS TEXT), '$.payload.SprintStateChanged.to')
               FROM agent_events phase
               WHERE phase.sprint_id = NEW.sprint_id
                 AND json_type(CAST(phase.event_json AS TEXT), '$.payload.SprintStateChanged') = 'object'
               ORDER BY phase.sequence DESC LIMIT 1
           ), '') = 'FinalVerification'
       )
     )
 AND NOT EXISTS (
       SELECT 1
       FROM sprint_final_verification_admissions admission
       JOIN agent_events phase
         ON phase.event_id = admission.sprint_phase_event_id
        AND phase.sprint_id = admission.sprint_id
       JOIN effect_session_bindings binding
         ON binding.effect_id = NEW.effect_id
        AND binding.sprint_id = NEW.sprint_id
       JOIN runner_launch_intents launch
         ON launch.sprint_id = binding.sprint_id
        AND launch.launch_id = binding.launch_id
       JOIN runner_session_policies session
         ON session.sprint_id = binding.sprint_id
        AND session.session_id = binding.session_id
        AND session.launch_id = launch.launch_id
       JOIN effect_request_payloads request
         ON request.effect_id = NEW.effect_id
        AND request.sprint_id = NEW.sprint_id
       WHERE admission.effect_id = NEW.effect_id
         AND admission.sprint_id = NEW.sprint_id
         AND admission.final_snapshot = NEW.input_snapshot
         AND admission.runner_launch_id = binding.launch_id
         AND admission.runner_session_id = binding.session_id
         AND admission.command_digest = NEW.request_digest
         AND admission.command_digest = request.request_digest
         AND admission.command_bytes = request.request_bytes
         AND admission.sprint_phase_event_id = NEW.causation_event_id
         AND NEW.effect_kind = 'RunCommand'
         AND NEW.task_id IS NULL
         AND NEW.worker_id IS NULL
         AND NEW.worker_lease_id IS NULL
         AND NEW.worker_lease_epoch IS NULL
         AND NEW.correlation_id = json_extract(CAST(phase.event_json AS TEXT), '$.correlation_id')
         AND NEW.policy_hash = json_extract(CAST(phase.event_json AS TEXT), '$.policy_hash')
         AND NEW.policy_hash = launch.policy_hash
         AND NEW.policy_hash = session.policy_hash
         AND NEW.created_at_unix_ms = admission.admitted_at_unix_ms
         AND phase.occurred_at_unix_ms <= NEW.created_at_unix_ms
         AND launch.created_at_unix_ms <= NEW.created_at_unix_ms
         AND session.registered_at_unix_ms <= NEW.created_at_unix_ms
         AND launch.purpose = 'FinalVerifier'
         AND session.purpose = 'FinalVerifier'
         AND launch.worker_id IS NULL
         AND session.worker_id IS NULL
         AND launch.worker_lease_id IS NULL
         AND session.worker_lease_id IS NULL
         AND request.contract_version = NEW.contract_version
         AND admission.contract_version = NEW.contract_version
         AND phase.contract_version = NEW.contract_version
         AND launch.contract_version = NEW.contract_version
         AND session.contract_version = NEW.contract_version
         AND json_extract(CAST(phase.event_json AS TEXT), '$.payload.SprintStateChanged.from') = 'Running'
         AND json_extract(CAST(phase.event_json AS TEXT), '$.payload.SprintStateChanged.to') = 'FinalVerification'
         AND NOT EXISTS (
             SELECT 1 FROM agent_events later
             WHERE later.sprint_id = NEW.sprint_id
               AND later.sequence > phase.sequence
               AND json_type(CAST(later.event_json AS TEXT), '$.payload.SprintStateChanged') = 'object'
         )
     )
BEGIN
    SELECT RAISE(ABORT, 'FinalVerifier RunCommand must exactly match one current sprint final-verification admission');
END;

-- Every schema-v21 phase admission must cross the durable claim boundary
-- before any terminal observation.  Only rows explicitly marked by the v21
-- migration retain historical claimless compatibility.
CREATE TRIGGER effect_observations_v21_phase_admission_claim_required
BEFORE INSERT ON effect_observations
WHEN NEW.dispatch_claim_id IS NULL
 AND (
       EXISTS (
           SELECT 1 FROM sprint_final_verification_admissions admission
           WHERE admission.effect_id = NEW.effect_id
       )
       OR EXISTS (
           SELECT 1 FROM task_attempt_formal_check_admissions admission
           WHERE admission.effect_id = NEW.effect_id
             AND NOT EXISTS (
                 SELECT 1 FROM task_phase_claimless_legacy_exemptions legacy
                 WHERE legacy.authority_class = 'TaskFormalCheck'
                   AND legacy.admission_id = admission.admission_id
                   AND legacy.effect_id = admission.effect_id
                   AND legacy.admitted_contract_version = admission.contract_version
             )
       )
       OR EXISTS (
           SELECT 1 FROM task_attempt_integration_admissions admission
           WHERE admission.effect_id = NEW.effect_id
             AND NOT EXISTS (
                 SELECT 1 FROM task_phase_claimless_legacy_exemptions legacy
                 WHERE legacy.authority_class = 'TaskIntegration'
                   AND legacy.admission_id = admission.admission_id
                   AND legacy.effect_id = admission.effect_id
                   AND legacy.admitted_contract_version = admission.contract_version
             )
       )
     )
BEGIN
    SELECT RAISE(ABORT, 'current phase admission requires its exact runner dispatch claim');
END;

-- Schema v21 implements SprintFinalVerification while preserving every
-- immutable v17-v20 claim and task-phase companion.
DROP TRIGGER runner_effect_dispatch_claim_authorities_v20_runtime_shape;
DROP TRIGGER runner_effect_dispatch_claims_v20_companion_required;
DROP TRIGGER runner_effect_dispatch_claims_identity_match;

CREATE TRIGGER runner_effect_dispatch_claim_authorities_v21_runtime_shape
BEFORE INSERT ON runner_effect_dispatch_claim_authorities
WHEN NEW.authority_class NOT IN ('TaskRunning', 'TaskFormalCheck', 'TaskIntegration', 'SprintFinalVerification')
  OR EXISTS (
      SELECT 1 FROM runner_effect_dispatch_claims claim
      WHERE claim.dispatch_claim_id = NEW.dispatch_claim_id
  )
BEGIN SELECT RAISE(ABORT, 'v21 runtime companion must be pre-parent implemented phase authority'); END;

-- The companion is inserted first under the deferred parent FK.  The parent
-- trigger below proves the exact effect/phase relationship before commit.
CREATE TRIGGER runner_effect_dispatch_claims_v21_companion_required
BEFORE INSERT ON runner_effect_dispatch_claims
WHEN NOT EXISTS (
    SELECT 1 FROM runner_effect_dispatch_claim_authorities authority
    WHERE authority.dispatch_claim_id = NEW.dispatch_claim_id
      AND authority.contract_version = NEW.contract_version
      AND (
          (authority.authority_class = 'TaskRunning'
           AND authority.running_boundary_id = NEW.running_boundary_id)
          OR (authority.authority_class = 'TaskFormalCheck'
              AND NEW.running_boundary_id IS NULL
              AND EXISTS (
                  SELECT 1 FROM task_attempt_formal_check_admissions admission
                  WHERE admission.admission_id = authority.formal_check_admission_id
                    AND admission.effect_id = NEW.effect_id
                    AND admission.sprint_id = NEW.sprint_id
              ))
          OR (authority.authority_class = 'TaskIntegration'
              AND NEW.running_boundary_id IS NULL
              AND EXISTS (
                  SELECT 1 FROM task_attempt_integration_admissions admission
                  WHERE admission.admission_id = authority.integration_admission_id
                    AND admission.effect_id = NEW.effect_id
                    AND admission.sprint_id = NEW.sprint_id
              ))
          OR (authority.authority_class = 'SprintFinalVerification'
              AND NEW.running_boundary_id IS NULL
              AND EXISTS (
                  SELECT 1 FROM sprint_final_verification_admissions admission
                  WHERE admission.sprint_phase_event_id = authority.sprint_phase_event_id
                    AND admission.effect_id = NEW.effect_id
                    AND admission.sprint_id = NEW.sprint_id
              ))
      )
)
BEGIN SELECT RAISE(ABORT, 'v21 runner dispatch claim requires exact implemented phase companion'); END;

CREATE TRIGGER runner_effect_dispatch_claims_identity_match
BEFORE INSERT ON runner_effect_dispatch_claims
WHEN NOT EXISTS (
    SELECT 1
    FROM effect_intents intent
    JOIN effect_session_bindings binding
      ON binding.effect_id = intent.effect_id AND binding.sprint_id = intent.sprint_id
    JOIN runner_launch_intents launch
      ON launch.launch_id = binding.launch_id AND launch.sprint_id = binding.sprint_id
    JOIN runner_session_policies session
      ON session.session_id = binding.session_id AND session.sprint_id = binding.sprint_id
     AND session.launch_id = binding.launch_id
    JOIN runner_launch_cleanup_admissions cleanup
      ON cleanup.launch_id = launch.launch_id AND cleanup.sprint_id = launch.sprint_id
     AND cleanup.session_id = session.session_id
    LEFT JOIN effect_observations cleanup_observation ON cleanup_observation.effect_id = cleanup.cleanup_effect_id
    JOIN runner_effect_dispatch_claim_authorities authority
      ON authority.dispatch_claim_id = NEW.dispatch_claim_id
     AND authority.contract_version = NEW.contract_version
    WHERE intent.effect_id = NEW.effect_id
      AND intent.sprint_id = NEW.sprint_id
      AND binding.launch_id = NEW.launch_id
      AND binding.session_id = NEW.session_id
      AND intent.request_digest = NEW.request_digest
      AND intent.policy_hash = NEW.policy_hash
      AND intent.input_snapshot = NEW.input_snapshot
      AND intent.policy_hash = session.policy_hash
      AND launch.policy_hash = session.policy_hash
      AND launch.purpose = session.purpose
      AND launch.worker_id IS session.worker_id
      AND cleanup_observation.effect_id IS NULL
      AND (
          NOT EXISTS (
              SELECT 1 FROM runner_launch_preparation_attempts preparation
              WHERE preparation.sprint_id = NEW.sprint_id
                AND preparation.launch_id = NEW.launch_id
          )
          OR EXISTS (
              SELECT 1
              FROM runner_launch_preparation_attempts preparation
              JOIN runner_launch_preparation_outcomes outcome
                ON outcome.attempt_id = preparation.attempt_id
               AND outcome.sprint_id = preparation.sprint_id
               AND outcome.launch_id = preparation.launch_id
              WHERE preparation.sprint_id = NEW.sprint_id
                AND preparation.launch_id = NEW.launch_id
                AND outcome.disposition = 'HeldChildPrepared'
          )
      )
      AND NOT EXISTS (
          SELECT 1 FROM finish_effect_kinds kind
          WHERE kind.effect_id = intent.effect_id
            AND kind.effect_kind = 'CleanupWorkerDomain'
      )
      AND intent.contract_version = NEW.contract_version
      AND binding.contract_version = NEW.contract_version
      AND launch.contract_version = NEW.contract_version
      AND session.contract_version = NEW.contract_version
      AND NOT EXISTS (SELECT 1 FROM effect_observations observation WHERE observation.effect_id = NEW.effect_id)
      AND NOT EXISTS (SELECT 1 FROM sprint_terminal_states terminal WHERE terminal.sprint_id = NEW.sprint_id)
      AND NOT EXISTS (SELECT 1 FROM sprint_non_success_terminal_outcomes terminal WHERE terminal.sprint_id = NEW.sprint_id)
      AND (
          (authority.authority_class = 'TaskRunning'
           AND session.purpose = 'TaskWorker'
           AND NEW.running_boundary_id = authority.running_boundary_id
           AND EXISTS (
               SELECT 1 FROM task_attempt_running_boundaries running
               JOIN task_attempts attempt ON attempt.attempt_id = running.attempt_id
               JOIN active_worker_leases active ON active.lease_id = attempt.worker_lease_id
               WHERE running.boundary_id = authority.running_boundary_id
                 AND running.runner_launch_id = NEW.launch_id
                 AND running.runner_session_id = NEW.session_id
                 AND running.sprint_id = NEW.sprint_id
                 AND running.task_id = intent.task_id
                 AND running.worker_id = intent.worker_id
                 AND running.worker_lease_id = intent.worker_lease_id
                 AND running.lease_epoch = intent.worker_lease_epoch
                 AND launch.worker_lease_id = intent.worker_lease_id
                 AND launch.worker_lease_epoch = intent.worker_lease_epoch
                 AND session.worker_lease_id = intent.worker_lease_id
                 AND session.worker_lease_epoch = intent.worker_lease_epoch
                 AND running.contract_version = NEW.contract_version
                 AND attempt.sprint_id = NEW.sprint_id
                 AND attempt.task_id = intent.task_id
                 AND attempt.worker_id = intent.worker_id
                 AND attempt.worker_lease_id = intent.worker_lease_id
                 AND attempt.lease_epoch = intent.worker_lease_epoch
                 AND attempt.schema_generation = 15
                 AND attempt.contract_version = NEW.contract_version
                 AND attempt.attempt_ordinal = (
                     SELECT MAX(latest.attempt_ordinal)
                     FROM task_attempts latest
                     WHERE latest.sprint_id = attempt.sprint_id
                       AND latest.task_id = attempt.task_id
                       AND latest.schema_generation = 15
                 )
                 AND active.sprint_id = NEW.sprint_id
                 AND active.task_id = intent.task_id
                 AND active.worker_id = intent.worker_id
                 AND active.lease_epoch = intent.worker_lease_epoch
                 AND NOT EXISTS (SELECT 1 FROM task_attempt_dispositions disposition WHERE disposition.attempt_id = attempt.attempt_id)
                 AND NOT EXISTS (SELECT 1 FROM worker_lease_releases release WHERE release.lease_id = attempt.worker_lease_id)
                 AND COALESCE((SELECT json_extract(CAST(event.event_json AS TEXT), '$.payload.TaskStateChanged.to')
                               FROM agent_events event WHERE event.sprint_id = NEW.sprint_id
                                AND json_extract(CAST(event.event_json AS TEXT), '$.task_id') = intent.task_id
                                AND json_type(CAST(event.event_json AS TEXT), '$.payload.TaskStateChanged') = 'object'
                               ORDER BY event.sequence DESC LIMIT 1), '') = 'Running'
                 AND intent.effect_kind IN (
                     'ReadRelativeFile', 'SearchLiteral', 'RunCommand',
                     'CreateRegularFile', 'ReplaceRegularFile',
                     'DeleteRegularFile'
                 )
           ))
          OR (authority.authority_class = 'TaskFormalCheck'
              AND session.purpose = 'TaskWorker'
              AND NEW.running_boundary_id IS NULL
              AND intent.effect_kind = 'RunCommand'
              AND EXISTS (
                  SELECT 1 FROM task_attempt_formal_check_admissions admission
                  JOIN task_attempts attempt ON attempt.attempt_id = admission.attempt_id
                  JOIN active_worker_leases active ON active.lease_id = attempt.worker_lease_id
                  JOIN task_attempt_verification_boundaries verification ON verification.attempt_id = attempt.attempt_id
                  WHERE admission.admission_id = authority.formal_check_admission_id
                    AND admission.effect_id = NEW.effect_id
                    AND admission.sprint_id = NEW.sprint_id
                    AND admission.task_id = intent.task_id
                    AND admission.worker_session_id = NEW.session_id
                    AND verification.worker_launch_id = NEW.launch_id
                    AND verification.worker_session_id = NEW.session_id
                    AND verification.sealed_snapshot_id = admission.sealed_snapshot_id
                    AND intent.worker_id = attempt.worker_id
                    AND intent.worker_lease_id = attempt.worker_lease_id
                    AND intent.worker_lease_epoch = attempt.lease_epoch
                    AND intent.input_snapshot = admission.sealed_snapshot_id
                    AND launch.worker_lease_id = intent.worker_lease_id
                    AND launch.worker_lease_epoch = intent.worker_lease_epoch
                    AND session.worker_lease_id = intent.worker_lease_id
                    AND session.worker_lease_epoch = intent.worker_lease_epoch
                    AND admission.contract_version = NEW.contract_version
                    AND verification.contract_version = NEW.contract_version
                    AND attempt.sprint_id = NEW.sprint_id
                    AND attempt.task_id = intent.task_id
                    AND attempt.worker_lease_id = intent.worker_lease_id
                    AND attempt.lease_epoch = intent.worker_lease_epoch
                    AND attempt.schema_generation = 15
                    AND attempt.contract_version = NEW.contract_version
                    AND attempt.attempt_ordinal = (
                        SELECT MAX(latest.attempt_ordinal)
                        FROM task_attempts latest
                        WHERE latest.sprint_id = attempt.sprint_id
                          AND latest.task_id = attempt.task_id
                          AND latest.schema_generation = 15
                    )
                    AND active.sprint_id = NEW.sprint_id
                    AND active.task_id = intent.task_id
                    AND active.worker_id = intent.worker_id
                    AND active.lease_epoch = intent.worker_lease_epoch
                    AND NOT EXISTS (SELECT 1 FROM task_attempt_dispositions disposition WHERE disposition.attempt_id = attempt.attempt_id)
                    AND NOT EXISTS (SELECT 1 FROM worker_lease_releases release WHERE release.lease_id = attempt.worker_lease_id)
                    AND NOT EXISTS (
                        SELECT 1 FROM task_attempt_formal_checks completed
                        WHERE completed.admission_id = admission.admission_id
                    )
                    AND NOT EXISTS (
                        SELECT 1 FROM task_attempt_formal_checks failed
                        WHERE failed.attempt_id = attempt.attempt_id
                          AND failed.passed = 0
                    )
                    AND NOT EXISTS (
                        SELECT 1
                        FROM task_attempt_formal_check_admissions prior
                        LEFT JOIN task_attempt_formal_checks completed_prior
                          ON completed_prior.admission_id = prior.admission_id
                        WHERE prior.attempt_id = attempt.attempt_id
                          AND prior.criterion_ordinal < admission.criterion_ordinal
                          AND completed_prior.formal_check_id IS NULL
                    )
                    AND COALESCE((SELECT json_extract(CAST(event.event_json AS TEXT), '$.payload.TaskStateChanged.to')
                                  FROM agent_events event WHERE event.sprint_id = NEW.sprint_id
                                   AND json_extract(CAST(event.event_json AS TEXT), '$.task_id') = intent.task_id
                                   AND json_type(CAST(event.event_json AS TEXT), '$.payload.TaskStateChanged') = 'object'
                                  ORDER BY event.sequence DESC LIMIT 1), '') = 'Verifying'
              ))
          OR (authority.authority_class = 'TaskIntegration'
              AND session.purpose = 'TaskWorker'
              AND NEW.running_boundary_id IS NULL
              AND intent.effect_kind = 'IntegrateChangeSet'
              AND EXISTS (
                  SELECT 1 FROM task_attempt_integration_admissions admission
                  JOIN task_attempts attempt ON attempt.attempt_id = admission.attempt_id
                  JOIN active_worker_leases active ON active.lease_id = attempt.worker_lease_id
                  JOIN task_attempt_candidate_boundaries candidate
                    ON candidate.boundary_id = admission.candidate_boundary_id
                   AND candidate.attempt_id = attempt.attempt_id
                  JOIN task_attempt_verification_boundaries verification
                    ON verification.boundary_id = candidate.verification_boundary_id
                   AND verification.attempt_id = attempt.attempt_id
                  WHERE admission.admission_id = authority.integration_admission_id
                    AND admission.effect_id = NEW.effect_id
                    AND admission.sprint_id = NEW.sprint_id
                    AND admission.worker_launch_id = NEW.launch_id
                    AND admission.worker_session_id = NEW.session_id
                    AND intent.task_id = admission.task_id
                    AND intent.worker_id = admission.worker_id
                    AND intent.worker_lease_id = admission.worker_lease_id
                    AND intent.worker_lease_epoch = admission.lease_epoch
                    AND intent.input_snapshot = admission.input_snapshot_id
                    AND admission.attempt_id = attempt.attempt_id
                    AND admission.worker_lease_id = attempt.worker_lease_id
                    AND admission.lease_epoch = attempt.lease_epoch
                    AND admission.result_snapshot_id = candidate.sealed_snapshot_id
                    AND verification.worker_launch_id = NEW.launch_id
                    AND verification.worker_session_id = NEW.session_id
                    AND launch.worker_lease_id = intent.worker_lease_id
                    AND launch.worker_lease_epoch = intent.worker_lease_epoch
                    AND session.worker_lease_id = intent.worker_lease_id
                    AND session.worker_lease_epoch = intent.worker_lease_epoch
                    AND admission.contract_version = NEW.contract_version
                    AND candidate.contract_version = NEW.contract_version
                    AND verification.contract_version = NEW.contract_version
                    AND attempt.sprint_id = NEW.sprint_id
                    AND attempt.task_id = intent.task_id
                    AND attempt.worker_id = intent.worker_id
                    AND attempt.worker_lease_id = intent.worker_lease_id
                    AND attempt.lease_epoch = intent.worker_lease_epoch
                    AND attempt.schema_generation = 15
                    AND attempt.contract_version = NEW.contract_version
                    AND attempt.attempt_ordinal = (
                        SELECT MAX(latest.attempt_ordinal)
                        FROM task_attempts latest
                        WHERE latest.sprint_id = attempt.sprint_id
                          AND latest.task_id = attempt.task_id
                          AND latest.schema_generation = 15
                    )
                    AND active.sprint_id = NEW.sprint_id
                    AND active.task_id = intent.task_id
                    AND active.worker_id = intent.worker_id
                    AND active.lease_epoch = intent.worker_lease_epoch
                    AND NOT EXISTS (SELECT 1 FROM task_attempt_dispositions disposition WHERE disposition.attempt_id = attempt.attempt_id)
                    AND NOT EXISTS (SELECT 1 FROM worker_lease_releases release WHERE release.lease_id = attempt.worker_lease_id)
                    AND COALESCE((SELECT json_extract(CAST(event.event_json AS TEXT), '$.payload.TaskStateChanged.to')
                                  FROM agent_events event WHERE event.sprint_id = NEW.sprint_id
                                   AND json_extract(CAST(event.event_json AS TEXT), '$.task_id') = intent.task_id
                                   AND json_type(CAST(event.event_json AS TEXT), '$.payload.TaskStateChanged') = 'object'
                                  ORDER BY event.sequence DESC LIMIT 1), '') = 'Candidate'
              ))
          OR (authority.authority_class = 'SprintFinalVerification'
              AND session.purpose = 'FinalVerifier'
              AND launch.purpose = 'FinalVerifier'
              AND launch.worker_id IS NULL
              AND session.worker_id IS NULL
              AND NEW.running_boundary_id IS NULL
              AND intent.task_id IS NULL
              AND intent.worker_id IS NULL
              AND intent.worker_lease_id IS NULL
              AND intent.worker_lease_epoch IS NULL
              AND launch.worker_lease_id IS NULL
              AND launch.worker_lease_epoch IS NULL
              AND session.worker_lease_id IS NULL
              AND session.worker_lease_epoch IS NULL
              AND intent.effect_kind = 'RunCommand'
              AND EXISTS (
                  SELECT 1
                  FROM sprint_final_verification_admissions admission
                  JOIN agent_events phase
                    ON phase.event_id = admission.sprint_phase_event_id
                   AND phase.sprint_id = admission.sprint_id
                  WHERE admission.sprint_phase_event_id = authority.sprint_phase_event_id
                    AND admission.effect_id = NEW.effect_id
                    AND admission.sprint_id = NEW.sprint_id
                    AND admission.final_snapshot = intent.input_snapshot
                    AND admission.runner_launch_id = NEW.launch_id
                    AND admission.runner_session_id = NEW.session_id
                    AND admission.command_digest = intent.request_digest
                    AND admission.contract_version = NEW.contract_version
                    AND phase.contract_version = NEW.contract_version
                    AND intent.causation_event_id = phase.event_id
                    AND json_extract(CAST(phase.event_json AS TEXT), '$.correlation_id') = intent.correlation_id
                    AND json_extract(CAST(phase.event_json AS TEXT), '$.policy_hash') = intent.policy_hash
                    AND json_extract(CAST(phase.event_json AS TEXT), '$.policy_hash') = launch.policy_hash
                    AND json_extract(CAST(phase.event_json AS TEXT), '$.policy_hash') = session.policy_hash
                    AND phase.occurred_at_unix_ms <= admission.admitted_at_unix_ms
                    AND phase.occurred_at_unix_ms <= intent.created_at_unix_ms
                    AND json_extract(CAST(phase.event_json AS TEXT), '$.payload.SprintStateChanged.from') = 'Running'
                    AND json_extract(CAST(phase.event_json AS TEXT), '$.payload.SprintStateChanged.to') = 'FinalVerification'
                    AND NOT EXISTS (
                        SELECT 1 FROM agent_events later
                        WHERE later.sprint_id = NEW.sprint_id
                          AND later.sequence > phase.sequence
                          AND json_type(CAST(later.event_json AS TEXT), '$.payload.SprintStateChanged') = 'object'
                    )
              ))
      )
)
BEGIN SELECT RAISE(ABORT, 'runner dispatch claim must match one exact implemented phase authority'); END;

-- Task and worker work exists only while the durable sprint phase is Running.
-- Cleanup effects are excluded because resource reconciliation must remain
-- possible after phase advance or terminalization.
CREATE TRIGGER worker_lease_acquisitions_v21_sprint_running_fence
BEFORE INSERT ON worker_lease_acquisitions
WHEN COALESCE((
       SELECT json_extract(CAST(phase.event_json AS TEXT), '$.payload.SprintStateChanged.to')
       FROM agent_events phase
       WHERE phase.sprint_id = NEW.sprint_id
         AND json_type(CAST(phase.event_json AS TEXT), '$.payload.SprintStateChanged') = 'object'
       ORDER BY phase.sequence DESC LIMIT 1
     ), CASE WHEN EXISTS (
          SELECT 1 FROM sprint_task_graphs graph WHERE graph.sprint_id = NEW.sprint_id
        ) THEN 'Running' ELSE 'Draft' END) != 'Running'
BEGIN SELECT RAISE(ABORT, 'worker lease acquisition requires current sprint phase Running'); END;

CREATE TRIGGER runner_launch_intents_v21_task_worker_sprint_running_fence
BEFORE INSERT ON runner_launch_intents
WHEN NEW.purpose = 'TaskWorker'
 AND COALESCE((
       SELECT json_extract(CAST(phase.event_json AS TEXT), '$.payload.SprintStateChanged.to')
       FROM agent_events phase
       WHERE phase.sprint_id = NEW.sprint_id
         AND json_type(CAST(phase.event_json AS TEXT), '$.payload.SprintStateChanged') = 'object'
       ORDER BY phase.sequence DESC LIMIT 1
     ), CASE WHEN EXISTS (
          SELECT 1 FROM sprint_task_graphs graph WHERE graph.sprint_id = NEW.sprint_id
        ) THEN 'Running' ELSE 'Draft' END) != 'Running'
BEGIN SELECT RAISE(ABORT, 'task-worker launch requires current sprint phase Running'); END;

CREATE TRIGGER runner_session_policies_v21_task_worker_sprint_running_fence
BEFORE INSERT ON runner_session_policies
WHEN NEW.purpose = 'TaskWorker'
 AND COALESCE((
       SELECT json_extract(CAST(phase.event_json AS TEXT), '$.payload.SprintStateChanged.to')
       FROM agent_events phase
       WHERE phase.sprint_id = NEW.sprint_id
         AND json_type(CAST(phase.event_json AS TEXT), '$.payload.SprintStateChanged') = 'object'
       ORDER BY phase.sequence DESC LIMIT 1
     ), CASE WHEN EXISTS (
          SELECT 1 FROM sprint_task_graphs graph WHERE graph.sprint_id = NEW.sprint_id
        ) THEN 'Running' ELSE 'Draft' END) != 'Running'
BEGIN SELECT RAISE(ABORT, 'task-worker session requires current sprint phase Running'); END;

CREATE TRIGGER effect_intents_v21_task_worker_sprint_running_fence
BEFORE INSERT ON effect_intents
WHEN (NEW.task_id IS NOT NULL OR NEW.worker_id IS NOT NULL OR NEW.worker_lease_id IS NOT NULL)
 AND NOT EXISTS (
       SELECT 1 FROM runner_launch_cleanup_admissions cleanup
       WHERE cleanup.cleanup_effect_id = NEW.effect_id
         AND cleanup.sprint_id = NEW.sprint_id
     )
 AND COALESCE((
       SELECT json_extract(CAST(phase.event_json AS TEXT), '$.payload.SprintStateChanged.to')
       FROM agent_events phase
       WHERE phase.sprint_id = NEW.sprint_id
         AND json_type(CAST(phase.event_json AS TEXT), '$.payload.SprintStateChanged') = 'object'
       ORDER BY phase.sequence DESC LIMIT 1
     ), CASE WHEN EXISTS (
          SELECT 1 FROM sprint_task_graphs graph WHERE graph.sprint_id = NEW.sprint_id
        ) THEN 'Running' ELSE 'Draft' END) != 'Running'
BEGIN SELECT RAISE(ABORT, 'task or worker effect requires current sprint phase Running'); END;

CREATE TRIGGER agent_events_v21_unobserved_sprint_final_claim_phase_fence
BEFORE INSERT ON agent_events
WHEN json_type(CAST(NEW.event_json AS TEXT), '$.payload.SprintStateChanged') = 'object'
 AND EXISTS (
    SELECT 1
    FROM runner_effect_dispatch_claims claim
    JOIN runner_effect_dispatch_claim_authorities authority
      ON authority.dispatch_claim_id = claim.dispatch_claim_id
    LEFT JOIN effect_observations observation ON observation.effect_id = claim.effect_id
    WHERE claim.sprint_id = NEW.sprint_id
      AND authority.authority_class = 'SprintFinalVerification'
      AND observation.effect_id IS NULL
 )
BEGIN SELECT RAISE(ABORT, 'unobserved sprint final-verification claim blocks every sprint phase transition'); END;

-- Every non-Running sprint phase freezes task/worker lifecycle events. Sprint
-- phase events remain legal because they carry neither task nor worker scope.
CREATE TRIGGER agent_events_v21_non_running_task_freeze
BEFORE INSERT ON agent_events
WHEN (
       json_extract(CAST(NEW.event_json AS TEXT), '$.task_id') IS NOT NULL
       OR json_extract(CAST(NEW.event_json AS TEXT), '$.worker_id') IS NOT NULL
       OR json_type(CAST(NEW.event_json AS TEXT), '$.payload.TaskStateChanged') = 'object'
     )
 AND COALESCE((
       SELECT json_extract(CAST(phase.event_json AS TEXT), '$.payload.SprintStateChanged.to')
       FROM agent_events phase
       WHERE phase.sprint_id = NEW.sprint_id
         AND json_type(CAST(phase.event_json AS TEXT), '$.payload.SprintStateChanged') = 'object'
       ORDER BY phase.sequence DESC LIMIT 1
     ), CASE WHEN EXISTS (
          SELECT 1 FROM sprint_task_graphs graph WHERE graph.sprint_id = NEW.sprint_id
        ) THEN 'Running' ELSE 'Draft' END) != 'Running'
BEGIN SELECT RAISE(ABORT, 'non-Running sprint phase freezes task and worker events'); END;
