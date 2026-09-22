
-- This TEMP-only assertion is deliberately the first executable statement.
-- It gives direct SQL execution the same fail-closed boundary as the Rust
-- preflight without allowing a rejected image to partially install v15.
-- Every source is qualified with `main` so TEMP shadowing cannot bypass it.
CREATE TEMP TABLE v15_task_attempt_admission_assertion (
    safe INTEGER NOT NULL CHECK (safe = 1)
) STRICT;
INSERT INTO temp.v15_task_attempt_admission_assertion (safe)
WITH legacy_sprints AS (
    SELECT DISTINCT sprint_id FROM main.worker_lease_acquisitions
)
SELECT 0
WHERE EXISTS (SELECT 1 FROM main.worker_lease_legacy_sprints)
   OR EXISTS (
      SELECT 1
      FROM main.runner_launch_intents launch
      LEFT JOIN main.worker_lease_acquisitions acquisition
        ON acquisition.lease_id = launch.worker_lease_id
      WHERE launch.purpose = 'TaskWorker'
        AND (acquisition.lease_id IS NULL
             OR launch.sprint_id != acquisition.sprint_id
             OR launch.worker_id != acquisition.worker_id
             OR launch.worker_lease_epoch != acquisition.lease_epoch)
   )
   OR EXISTS (
      SELECT 1
      FROM main.effect_intents intent
      LEFT JOIN main.worker_lease_acquisitions acquisition
        ON acquisition.lease_id = intent.worker_lease_id
      WHERE (intent.task_id IS NOT NULL OR intent.worker_id IS NOT NULL)
        AND (acquisition.lease_id IS NULL
             OR intent.sprint_id != acquisition.sprint_id
             OR intent.task_id != acquisition.task_id
             OR intent.worker_id != acquisition.worker_id
             OR intent.worker_lease_epoch != acquisition.lease_epoch)
   )
   OR EXISTS (
      SELECT 1
      FROM main.task_integration_receipts integration
      LEFT JOIN main.worker_lease_acquisitions acquisition
        ON acquisition.lease_id = integration.worker_lease_id
      WHERE acquisition.lease_id IS NULL
         OR integration.sprint_id != acquisition.sprint_id
         OR integration.task_id != acquisition.task_id
         OR integration.worker_id != acquisition.worker_id
         OR integration.worker_lease_epoch != acquisition.lease_epoch
   )
   OR EXISTS (
      SELECT 1
      FROM main.runner_session_policies session
      LEFT JOIN main.worker_lease_acquisitions acquisition
        ON acquisition.lease_id = session.worker_lease_id
      WHERE session.purpose = 'TaskWorker'
        AND (acquisition.lease_id IS NULL
             OR session.sprint_id != acquisition.sprint_id
             OR session.worker_id != acquisition.worker_id
             OR session.worker_lease_epoch != acquisition.lease_epoch)
   )
   OR EXISTS (
      SELECT 1
      FROM main.effect_observations observation
      LEFT JOIN main.worker_lease_acquisitions acquisition
        ON acquisition.lease_id = observation.worker_lease_id
      WHERE (observation.task_id IS NOT NULL OR observation.worker_id IS NOT NULL)
        AND (acquisition.lease_id IS NULL
             OR observation.sprint_id != acquisition.sprint_id
             OR observation.task_id != acquisition.task_id
             OR observation.worker_id != acquisition.worker_id
             OR observation.worker_lease_epoch != acquisition.lease_epoch)
   )
   OR EXISTS (
      SELECT 1
      FROM main.worker_cleanup_receipts cleanup
      LEFT JOIN main.worker_lease_acquisitions acquisition
        ON acquisition.lease_id = cleanup.worker_lease_id
      WHERE cleanup.worker_lease_id IS NOT NULL
        AND (acquisition.lease_id IS NULL
             OR cleanup.sprint_id != acquisition.sprint_id
             OR cleanup.worker_lease_epoch != acquisition.lease_epoch)
   )
   OR EXISTS (
      SELECT 1
      FROM main.worker_lease_acquisitions acquisition
      JOIN main.sprints sprint ON sprint.sprint_id = acquisition.sprint_id
      WHERE (
          SELECT COUNT(*) FROM main.worker_lease_acquisitions counted
          WHERE counted.sprint_id = acquisition.sprint_id
            AND counted.task_id = acquisition.task_id
      ) > COALESCE(
          CASE
            WHEN json_type(CAST(sprint.spec_json AS TEXT),
                           '$.budget.max_attempts_per_task') = 'integer'
            THEN json_extract(CAST(sprint.spec_json AS TEXT),
                              '$.budget.max_attempts_per_task')
          END,
          0
      )
   )
   OR EXISTS (
      SELECT 1 FROM main.worker_lease_acquisitions acquisition
      WHERE COALESCE((
          SELECT json_extract(CAST(event.event_json AS TEXT),
                              '$.payload.TaskStateChanged.to')
          FROM main.agent_events event
          WHERE event.sprint_id = acquisition.sprint_id
            AND json_extract(CAST(event.event_json AS TEXT), '$.task_id') =
                acquisition.task_id
            AND json_type(CAST(event.event_json AS TEXT),
                          '$.payload.TaskStateChanged') = 'object'
          ORDER BY event.sequence DESC LIMIT 1
      ), '') != 'Integrated'
         OR COALESCE((
          SELECT json_extract(CAST(event.event_json AS TEXT), '$.worker_id')
          FROM main.agent_events event
          WHERE event.sprint_id = acquisition.sprint_id
            AND json_extract(CAST(event.event_json AS TEXT), '$.task_id') =
                acquisition.task_id
            AND json_type(CAST(event.event_json AS TEXT),
                          '$.payload.TaskStateChanged') = 'object'
          ORDER BY event.sequence DESC LIMIT 1
      ), '') != acquisition.worker_id
   )
   OR EXISTS (
      SELECT 1
      FROM main.sprint_task_graphs graph,
           json_each(CAST(graph.graph_json AS TEXT), '$.tasks') task
      WHERE graph.sprint_id IN (SELECT sprint_id FROM legacy_sprints)
        AND (
            SELECT COUNT(*) FROM main.worker_lease_acquisitions acquisition
            WHERE acquisition.sprint_id = graph.sprint_id
              AND acquisition.task_id = json_extract(task.value, '$.task_id')
        ) != 1
   )
   OR EXISTS (
      SELECT 1 FROM main.sprint_task_graphs graph
      WHERE graph.sprint_id IN (SELECT sprint_id FROM legacy_sprints)
        AND json_array_length(CAST(graph.graph_json AS TEXT), '$.tasks') != (
            SELECT COUNT(DISTINCT json_extract(task.value, '$.task_id'))
            FROM json_each(CAST(graph.graph_json AS TEXT), '$.tasks') task
        )
   )
   OR EXISTS (
      SELECT 1 FROM main.worker_lease_acquisitions acquisition
      WHERE NOT EXISTS (
          SELECT 1
          FROM main.sprint_task_graphs graph,
               json_each(CAST(graph.graph_json AS TEXT), '$.tasks') task
          WHERE graph.sprint_id = acquisition.sprint_id
            AND json_extract(task.value, '$.task_id') = acquisition.task_id
      )
   )
   OR EXISTS (
      SELECT 1 FROM main.worker_lease_acquisitions acquisition
      WHERE NOT EXISTS (
          SELECT 1
          FROM main.task_integration_receipts integration
          JOIN main.effect_intents intent ON intent.effect_id = integration.effect_id
          JOIN main.effect_observations observation
            ON observation.observation_id = integration.observation_id
           AND observation.effect_id = integration.effect_id
          JOIN main.finish_effect_kinds kind ON kind.effect_id = integration.effect_id
          JOIN main.runner_launch_intents launch
            ON launch.launch_id = integration.worker_launch_id
          JOIN main.runner_session_policies session
            ON session.session_id = integration.worker_session_id
          JOIN main.effect_session_bindings binding
            ON binding.effect_id = integration.effect_id
          JOIN main.effect_request_payloads request
            ON request.effect_id = integration.effect_id
           AND request.request_digest = intent.request_digest
          JOIN main.effect_evidence_payloads evidence
            ON evidence.effect_id = integration.effect_id
           AND evidence.observation_id = integration.observation_id
           AND evidence.evidence_digest = observation.evidence_digest
          WHERE integration.worker_lease_id = acquisition.lease_id
            AND integration.worker_lease_epoch = acquisition.lease_epoch
            AND integration.sprint_id = acquisition.sprint_id
            AND integration.task_id = acquisition.task_id
            AND integration.worker_id = acquisition.worker_id
            AND integration.contract_version = acquisition.contract_version
            AND integration.integrated_at_unix_ms = observation.observed_at_unix_ms
            AND integration.integrated_at_unix_ms >= acquisition.acquired_at_unix_ms
            AND launch.sprint_id = acquisition.sprint_id
            AND launch.purpose = 'TaskWorker'
            AND launch.worker_id = acquisition.worker_id
            AND launch.worker_lease_id = acquisition.lease_id
            AND launch.worker_lease_epoch = acquisition.lease_epoch
            AND integration.worker_policy_hash = launch.policy_hash
            AND session.sprint_id = acquisition.sprint_id
            AND session.launch_id = launch.launch_id
            AND session.purpose = 'TaskWorker'
            AND session.worker_id = acquisition.worker_id
            AND session.worker_lease_id = acquisition.lease_id
            AND session.worker_lease_epoch = acquisition.lease_epoch
            AND binding.sprint_id = acquisition.sprint_id
            AND binding.launch_id = launch.launch_id
            AND binding.session_id = session.session_id
            AND intent.sprint_id = acquisition.sprint_id
            AND intent.task_id = acquisition.task_id
            AND intent.worker_id = acquisition.worker_id
            AND intent.worker_lease_id = acquisition.lease_id
            AND intent.worker_lease_epoch = acquisition.lease_epoch
            AND intent.effect_kind = 'IntegrateChangeSet'
            AND observation.sprint_id = acquisition.sprint_id
            AND observation.task_id = acquisition.task_id
            AND observation.worker_id = acquisition.worker_id
            AND observation.worker_lease_id = acquisition.lease_id
            AND observation.worker_lease_epoch = acquisition.lease_epoch
            AND observation.effect_kind = 'IntegrateChangeSet'
            AND observation.outcome = 'Succeeded'
            AND kind.sprint_id = acquisition.sprint_id
            AND kind.effect_kind = 'IntegrateChangeSet'
            AND kind.contract_version = acquisition.contract_version
      )
      OR (
          SELECT COUNT(*) FROM main.task_integration_receipts integration
          WHERE integration.worker_lease_id = acquisition.lease_id
      ) != 1
   )
   OR EXISTS (
      SELECT 1 FROM main.worker_lease_acquisitions acquisition
      WHERE NOT EXISTS (
          SELECT 1
          FROM main.worker_lease_releases release
          JOIN main.worker_cleanup_receipts cleanup
            ON cleanup.receipt_id = release.cleanup_receipt_id
           AND cleanup.effect_id = release.cleanup_effect_id
           AND cleanup.observation_id = release.cleanup_observation_id
          JOIN main.effect_intents intent ON intent.effect_id = cleanup.effect_id
          JOIN main.effect_observations observation
            ON observation.observation_id = cleanup.observation_id
           AND observation.effect_id = cleanup.effect_id
          JOIN main.finish_effect_kinds kind ON kind.effect_id = cleanup.effect_id
          JOIN main.runner_launch_intents launch ON launch.launch_id = cleanup.launch_id
          JOIN main.runner_session_policies session
            ON session.session_id = cleanup.session_id
          JOIN main.runner_launch_cleanup_admissions admission
            ON admission.launch_id = cleanup.launch_id
           AND admission.cleanup_effect_id = cleanup.effect_id
          JOIN main.effect_session_bindings binding
            ON binding.effect_id = cleanup.effect_id
          JOIN main.effect_request_payloads request
            ON request.effect_id = cleanup.effect_id
           AND request.request_digest = intent.request_digest
          JOIN main.effect_evidence_payloads evidence
            ON evidence.effect_id = cleanup.effect_id
           AND evidence.observation_id = cleanup.observation_id
           AND evidence.evidence_digest = observation.evidence_digest
          WHERE release.lease_id = acquisition.lease_id
            AND release.sprint_id = acquisition.sprint_id
            AND release.lease_epoch = acquisition.lease_epoch
            AND release.contract_version = acquisition.contract_version
            AND release.released_at_unix_ms >= acquisition.acquired_at_unix_ms
            AND cleanup.sprint_id = acquisition.sprint_id
            AND cleanup.worker_lease_id = acquisition.lease_id
            AND cleanup.worker_lease_epoch = acquisition.lease_epoch
            AND cleanup.contract_version = acquisition.contract_version
            AND cleanup.cleaned_at_unix_ms = release.released_at_unix_ms
            AND cleanup.cleaned_at_unix_ms = observation.observed_at_unix_ms
            AND cleanup.cleaned_at_unix_ms >= (
                SELECT integration.integrated_at_unix_ms
                FROM main.task_integration_receipts integration
                WHERE integration.worker_lease_id = acquisition.lease_id
            )
            AND launch.sprint_id = acquisition.sprint_id
            AND launch.purpose = 'TaskWorker'
            AND launch.worker_id = acquisition.worker_id
            AND launch.worker_lease_id = acquisition.lease_id
            AND launch.worker_lease_epoch = acquisition.lease_epoch
            AND session.sprint_id = acquisition.sprint_id
            AND session.launch_id = launch.launch_id
            AND session.purpose = 'TaskWorker'
            AND session.worker_id = acquisition.worker_id
            AND session.worker_lease_id = acquisition.lease_id
            AND session.worker_lease_epoch = acquisition.lease_epoch
            AND cleanup.policy_hash = launch.policy_hash
            AND cleanup.grant_hash = launch.grant_hash
            AND cleanup.policy_version = launch.policy_version
            AND admission.sprint_id = acquisition.sprint_id
            AND admission.session_id = cleanup.session_id
            AND admission.contract_version = acquisition.contract_version
            AND binding.sprint_id = acquisition.sprint_id
            AND binding.launch_id = launch.launch_id
            AND binding.session_id IS NULL
            AND intent.sprint_id = acquisition.sprint_id
            AND intent.worker_lease_id = acquisition.lease_id
            AND intent.worker_lease_epoch = acquisition.lease_epoch
            AND intent.task_id IS NULL AND intent.worker_id IS NULL
            AND intent.effect_kind = 'ApplyChangeSet'
            AND observation.sprint_id = acquisition.sprint_id
            AND observation.worker_lease_id = acquisition.lease_id
            AND observation.worker_lease_epoch = acquisition.lease_epoch
            AND observation.task_id IS NULL AND observation.worker_id IS NULL
            AND observation.effect_kind = 'ApplyChangeSet'
            AND observation.outcome = 'Succeeded'
            AND kind.sprint_id = acquisition.sprint_id
            AND kind.effect_kind = 'CleanupWorkerDomain'
            AND kind.contract_version = acquisition.contract_version
      )
      OR (
          SELECT COUNT(*) FROM main.worker_cleanup_receipts cleanup
          WHERE cleanup.worker_lease_id = acquisition.lease_id
      ) != 1
   )
   OR EXISTS (
      SELECT 1 FROM main.effect_intents intent
      LEFT JOIN main.effect_observations observation
        ON observation.effect_id = intent.effect_id
      WHERE intent.sprint_id IN (SELECT sprint_id FROM legacy_sprints)
        AND (observation.effect_id IS NULL OR observation.outcome = 'Unknown')
   )
   OR EXISTS (
      SELECT 1 FROM main.effect_intents intent
      WHERE intent.sprint_id IN (SELECT sprint_id FROM legacy_sprints)
        AND (
            NOT EXISTS (
                SELECT 1 FROM main.effect_request_payloads request
                WHERE request.effect_id = intent.effect_id
                  AND request.sprint_id = intent.sprint_id
                  AND request.request_digest = intent.request_digest
                  AND request.contract_version = intent.contract_version
            )
            OR EXISTS (
                SELECT 1 FROM main.effect_observations observation
                WHERE observation.effect_id = intent.effect_id
                  AND NOT EXISTS (
                      SELECT 1 FROM main.effect_evidence_payloads evidence
                      WHERE evidence.effect_id = observation.effect_id
                        AND evidence.observation_id = observation.observation_id
                        AND evidence.sprint_id = observation.sprint_id
                        AND evidence.evidence_digest = observation.evidence_digest
                        AND evidence.contract_version = observation.contract_version
                  )
            )
        )
   )
   OR EXISTS (
      SELECT 1 FROM main.unresolved_mutation_effects unresolved
      WHERE unresolved.sprint_id IN (SELECT sprint_id FROM legacy_sprints)
   )
   OR EXISTS (
      SELECT 1
      FROM main.runner_launch_preparation_attempts preparation
      LEFT JOIN main.runner_launch_preparation_outcomes outcome
        ON outcome.attempt_id = preparation.attempt_id
      WHERE preparation.sprint_id IN (SELECT sprint_id FROM legacy_sprints)
        AND (outcome.attempt_id IS NULL
             OR outcome.disposition = 'NativeEffectUncertain'
             OR (outcome.disposition = 'RefusedBeforeNativeEffect' AND EXISTS (
                 SELECT 1 FROM main.runner_session_policies session
                 WHERE session.sprint_id = preparation.sprint_id
                   AND session.launch_id = preparation.launch_id
             ))
             OR (outcome.disposition = 'HeldChildPrepared' AND NOT EXISTS (
                 SELECT 1 FROM main.runner_session_policies session
                 WHERE session.sprint_id = preparation.sprint_id
                   AND session.launch_id = preparation.launch_id
             )))
   )
   OR EXISTS (
      SELECT 1 FROM main.legacy_effect_payload_gaps gap
      WHERE gap.sprint_id IN (SELECT sprint_id FROM legacy_sprints)
   )
   OR EXISTS (
      SELECT 1 FROM main.legacy_finish_receipt_gaps gap
      WHERE gap.sprint_id IN (SELECT sprint_id FROM legacy_sprints)
   )
   OR EXISTS (
      SELECT 1
      FROM main.finish_effect_kinds kind
      JOIN main.effect_observations observation
        ON observation.effect_id = kind.effect_id
      WHERE kind.sprint_id IN (SELECT sprint_id FROM legacy_sprints)
        AND observation.outcome = 'Succeeded'
        AND NOT (
            (kind.effect_kind = 'IntegrateChangeSet' AND EXISTS (
                SELECT 1 FROM main.task_integration_receipts receipt
                WHERE receipt.effect_id = kind.effect_id
                  AND receipt.observation_id = observation.observation_id
                  AND receipt.sprint_id = kind.sprint_id
            ))
            OR (kind.effect_kind = 'ApplyChangeSet' AND EXISTS (
                SELECT 1 FROM main.application_receipts receipt
                WHERE receipt.effect_id = kind.effect_id
                  AND receipt.observation_id = observation.observation_id
                  AND receipt.sprint_id = kind.sprint_id
            ))
            OR (kind.effect_kind = 'CleanupWorkerDomain' AND EXISTS (
                SELECT 1 FROM main.worker_cleanup_receipts receipt
                WHERE receipt.effect_id = kind.effect_id
                  AND receipt.observation_id = observation.observation_id
                  AND receipt.sprint_id = kind.sprint_id
            ))
            OR (kind.effect_kind = 'RollbackChangeSet' AND EXISTS (
                SELECT 1 FROM main.rollback_receipts receipt
                WHERE receipt.effect_id = kind.effect_id
                  AND receipt.observation_id = observation.observation_id
                  AND receipt.sprint_id = kind.sprint_id
            ))
        )
   )
   OR EXISTS (
      SELECT 1
      FROM main.runner_launch_cleanup_admissions admission
      LEFT JOIN main.effect_observations observation
        ON observation.effect_id = admission.cleanup_effect_id
      WHERE admission.sprint_id IN (SELECT sprint_id FROM legacy_sprints)
        AND (observation.effect_id IS NULL
             OR (observation.outcome = 'Succeeded' AND NOT EXISTS (
                 SELECT 1 FROM main.worker_cleanup_receipts cleanup
                 WHERE cleanup.sprint_id = admission.sprint_id
                   AND cleanup.launch_id = admission.launch_id
                   AND cleanup.session_id = admission.session_id
                   AND cleanup.effect_id = admission.cleanup_effect_id
                   AND cleanup.observation_id = observation.observation_id
             ))
             OR (observation.outcome IN (
                     'FailedBeforeEffect', 'CancelledBeforeEffect'
                 ) AND NOT EXISTS (
                 SELECT 1
                 FROM main.runner_launch_preparation_attempts preparation
                 JOIN main.runner_launch_preparation_outcomes outcome
                   ON outcome.attempt_id = preparation.attempt_id
                 WHERE preparation.sprint_id = admission.sprint_id
                   AND preparation.launch_id = admission.launch_id
                   AND preparation.cleanup_effect_id = admission.cleanup_effect_id
                   AND outcome.disposition = 'RefusedBeforeNativeEffect'
                   AND NOT EXISTS (
                       SELECT 1 FROM main.runner_session_policies session
                       WHERE session.sprint_id = preparation.sprint_id
                         AND session.launch_id = preparation.launch_id
                   )
             ))
             OR observation.outcome NOT IN (
                 'Succeeded', 'FailedBeforeEffect', 'CancelledBeforeEffect'
             ))
   )
   OR EXISTS (
      SELECT 1 FROM main.sprint_non_success_terminal_outcomes terminal
      WHERE terminal.sprint_id IN (SELECT sprint_id FROM legacy_sprints)
   )
   OR EXISTS (
      SELECT 1 FROM main.sprint_terminal_states terminal
      WHERE terminal.sprint_id IN (SELECT sprint_id FROM legacy_sprints)
        AND terminal.terminal_state != 'Completed'
   );
DROP TABLE temp.v15_task_attempt_admission_assertion;

-- Rebuild the integration authority before v15 tables reference it.  The
-- original v8 shape incorrectly required at least one automated verification
-- receipt, which made a graph task with only human acceptance criteria
-- impossible to integrate.  Every historical row and byte column is copied
-- exactly; only the forward-looking CHECK becomes non-negative.
CREATE TEMP TABLE v15_preserved_task_integration_receipts AS
SELECT receipt_id, sprint_id, task_id, worker_id, worker_launch_id,
       worker_session_id, worker_policy_hash, effect_id, observation_id,
       change_set_id, input_snapshot, result_snapshot, integration_ordinal,
       verification_count, contract_version, integrated_at_unix_ms,
       receipt_json, worker_lease_id, worker_lease_epoch
FROM task_integration_receipts;

CREATE TEMP TABLE v15_preserved_task_integration_verifications AS
SELECT integration_receipt_id, sprint_id, ordinal, verification_receipt_id
FROM task_integration_verification_receipts;

CREATE TEMP TABLE v15_preserved_completion_task_integrations AS
SELECT completion_receipt_id, sprint_id, ordinal, integration_receipt_id
FROM v9_completion_task_integration_receipts;

DROP TABLE task_integration_verification_receipts;
DROP TABLE v9_completion_task_integration_receipts;
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
FROM v15_preserved_task_integration_receipts;

CREATE INDEX task_integration_worker_lease_idx
ON task_integration_receipts (sprint_id, worker_lease_id, worker_lease_epoch);

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

INSERT INTO task_integration_verification_receipts (
    integration_receipt_id, sprint_id, ordinal, verification_receipt_id
)
SELECT integration_receipt_id, sprint_id, ordinal, verification_receipt_id
FROM v15_preserved_task_integration_verifications;

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

INSERT INTO v9_completion_task_integration_receipts (
    completion_receipt_id, sprint_id, ordinal, integration_receipt_id
)
SELECT completion_receipt_id, sprint_id, ordinal, integration_receipt_id
FROM v15_preserved_completion_task_integrations;

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
CREATE TRIGGER v9_completion_task_integration_no_update
BEFORE UPDATE ON v9_completion_task_integration_receipts
BEGIN SELECT RAISE(ABORT, 'v9 completion task-integration links are immutable'); END;
CREATE TRIGGER v9_completion_task_integration_no_delete
BEFORE DELETE ON v9_completion_task_integration_receipts
BEGIN SELECT RAISE(ABORT, 'v9 completion task-integration links are immutable'); END;

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

DROP TABLE v15_preserved_task_integration_receipts;
DROP TABLE v15_preserved_task_integration_verifications;
DROP TABLE v15_preserved_completion_task_integrations;

CREATE TABLE task_attempts (
    attempt_id TEXT PRIMARY KEY NOT NULL,
    sprint_id TEXT NOT NULL,
    task_id TEXT NOT NULL,
    worker_id TEXT NOT NULL,
    worker_lease_id TEXT NOT NULL UNIQUE,
    lease_epoch INTEGER NOT NULL CHECK (lease_epoch > 0),
    attempt_ordinal INTEGER NOT NULL CHECK (attempt_ordinal > 0),
    opening_event_id TEXT NOT NULL UNIQUE,
    opened_at_unix_ms INTEGER NOT NULL CHECK (opened_at_unix_ms > 0),
    contract_version INTEGER NOT NULL CHECK (contract_version > 0),
    schema_generation INTEGER NOT NULL CHECK (schema_generation IN (14, 15)),
    attempt_json BLOB NOT NULL CHECK (length(attempt_json) > 0),
    UNIQUE (sprint_id, task_id, attempt_ordinal),
    UNIQUE (sprint_id, lease_epoch),
    UNIQUE (sprint_id, attempt_id),
    FOREIGN KEY (worker_lease_id)
        REFERENCES worker_lease_acquisitions(lease_id) ON DELETE RESTRICT,
    FOREIGN KEY (opening_event_id)
        REFERENCES agent_events(event_id)
        ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED
) STRICT, WITHOUT ROWID;

INSERT INTO task_attempts (
    attempt_id, sprint_id, task_id, worker_id, worker_lease_id, lease_epoch,
    attempt_ordinal, opening_event_id, opened_at_unix_ms, contract_version,
    schema_generation, attempt_json
)
SELECT acquisition.lease_id,
       acquisition.sprint_id,
       acquisition.task_id,
       acquisition.worker_id,
       acquisition.lease_id,
       acquisition.lease_epoch,
       ROW_NUMBER() OVER (
           PARTITION BY acquisition.sprint_id, acquisition.task_id
           ORDER BY acquisition.lease_epoch ASC, acquisition.lease_id ASC
       ),
       acquisition.acquisition_event_id,
       acquisition.acquired_at_unix_ms,
       acquisition.contract_version,
       14,
       CAST(json_object(
           'contract_version', acquisition.contract_version,
           'attempt_id', acquisition.lease_id,
           'worker_lease', json(CAST(acquisition.lease_json AS TEXT)),
           'attempt_ordinal', ROW_NUMBER() OVER (
               PARTITION BY acquisition.sprint_id, acquisition.task_id
               ORDER BY acquisition.lease_epoch ASC, acquisition.lease_id ASC
           ),
           'opening_event_id', acquisition.acquisition_event_id,
           'opened_at_unix_ms', acquisition.acquired_at_unix_ms
       ) AS BLOB)
FROM worker_lease_acquisitions acquisition;

CREATE TABLE task_attempt_legacy_classifications (
    attempt_id TEXT PRIMARY KEY NOT NULL,
    sprint_id TEXT NOT NULL,
    task_id TEXT NOT NULL,
    attempt_ordinal INTEGER NOT NULL CHECK (attempt_ordinal > 0),
    classification TEXT NOT NULL CHECK (classification IN (
        'LegacyReleased', 'LegacyOpen',
        'LegacyIntegratedCleanupPending', 'LegacyIntegratedReleased',
        'LegacyReleasedActiveState', 'LegacyUnknownQuarantine'
    )),
    budget_classification TEXT NOT NULL CHECK (
        budget_classification IN ('WithinBudget', 'OverBudget')
    ),
    classified_at_schema INTEGER NOT NULL CHECK (classified_at_schema = 15),
    UNIQUE (sprint_id, task_id, attempt_ordinal),
    FOREIGN KEY (attempt_id) REFERENCES task_attempts(attempt_id) ON DELETE RESTRICT
) STRICT, WITHOUT ROWID;

INSERT INTO task_attempt_legacy_classifications (
    attempt_id, sprint_id, task_id, attempt_ordinal, classification,
    budget_classification, classified_at_schema
)
SELECT attempt.attempt_id,
       attempt.sprint_id,
       attempt.task_id,
       attempt.attempt_ordinal,
       CASE
         WHEN integration.receipt_id IS NOT NULL AND release.lease_id IS NOT NULL
           THEN 'LegacyIntegratedReleased'
         WHEN integration.receipt_id IS NOT NULL
           THEN 'LegacyIntegratedCleanupPending'
         WHEN release.lease_id IS NULL AND COALESCE((
              SELECT json_extract(CAST(event.event_json AS TEXT),
                                  '$.payload.TaskStateChanged.to')
              FROM agent_events event
              WHERE event.sprint_id = attempt.sprint_id
                AND json_extract(CAST(event.event_json AS TEXT), '$.task_id') = attempt.task_id
                AND json_type(CAST(event.event_json AS TEXT),
                              '$.payload.TaskStateChanged') = 'object'
              ORDER BY event.sequence DESC LIMIT 1
           ), '') = 'Unknown'
           AND attempt.attempt_ordinal = (
               SELECT MAX(latest.attempt_ordinal) FROM task_attempts latest
               WHERE latest.sprint_id = attempt.sprint_id
                 AND latest.task_id = attempt.task_id
           )
           THEN 'LegacyUnknownQuarantine'
         WHEN release.lease_id IS NULL
           THEN 'LegacyOpen'
         WHEN COALESCE((
              SELECT json_extract(CAST(event.event_json AS TEXT),
                                  '$.payload.TaskStateChanged.to')
              FROM agent_events event
              WHERE event.sprint_id = attempt.sprint_id
                AND json_extract(CAST(event.event_json AS TEXT), '$.task_id') = attempt.task_id
                AND json_type(CAST(event.event_json AS TEXT),
                              '$.payload.TaskStateChanged') = 'object'
              ORDER BY event.sequence DESC LIMIT 1
           ), '') IN ('Leased', 'Running', 'Verifying', 'Candidate')
           AND attempt.attempt_ordinal = (
               SELECT MAX(latest.attempt_ordinal) FROM task_attempts latest
               WHERE latest.sprint_id = attempt.sprint_id
                 AND latest.task_id = attempt.task_id
           )
           THEN 'LegacyReleasedActiveState'
         ELSE 'LegacyReleased'
       END,
       CASE WHEN (
           SELECT COUNT(*) FROM task_attempts counted
           WHERE counted.sprint_id = attempt.sprint_id
             AND counted.task_id = attempt.task_id
       ) > COALESCE((
           SELECT CASE
             WHEN json_type(CAST(sprint.spec_json AS TEXT),
                            '$.budget.max_attempts_per_task') = 'integer'
             THEN json_extract(CAST(sprint.spec_json AS TEXT),
                               '$.budget.max_attempts_per_task')
             ELSE 0
           END
           FROM sprints sprint WHERE sprint.sprint_id = attempt.sprint_id
       ), 0)
       THEN 'OverBudget' ELSE 'WithinBudget' END,
       15
FROM task_attempts attempt
LEFT JOIN worker_lease_releases release ON release.lease_id = attempt.worker_lease_id
LEFT JOIN task_integration_receipts integration
       ON integration.worker_lease_id = attempt.worker_lease_id
WHERE attempt.schema_generation = 14;

CREATE TABLE task_attempt_legacy_completion_invalidations (
    sprint_id TEXT PRIMARY KEY NOT NULL,
    completion_receipt_id TEXT NOT NULL UNIQUE,
    reason TEXT NOT NULL CHECK (reason IN (
        'OverBudgetHistory', 'UnsafeLegacyAttemptHistory'
    )),
    contract_version INTEGER NOT NULL CHECK (contract_version > 0),
    invalidated_at_schema INTEGER NOT NULL CHECK (invalidated_at_schema = 15),
    invalidation_json BLOB NOT NULL CHECK (length(invalidation_json) > 0),
    FOREIGN KEY (sprint_id, completion_receipt_id)
        REFERENCES v9_completion_receipts(sprint_id, receipt_id) ON DELETE RESTRICT
) STRICT, WITHOUT ROWID;

INSERT INTO task_attempt_legacy_completion_invalidations (
    sprint_id, completion_receipt_id, reason, contract_version,
    invalidated_at_schema, invalidation_json
)
SELECT proof.sprint_id,
       proof.completion_receipt_id,
       CASE WHEN EXISTS (
           SELECT 1 FROM task_attempt_legacy_classifications legacy
           WHERE legacy.sprint_id = proof.sprint_id
             AND legacy.budget_classification = 'OverBudget'
       ) THEN 'OverBudgetHistory' ELSE 'UnsafeLegacyAttemptHistory' END,
       proof.contract_version,
       15,
       CAST(json_object(
           'contract_version', proof.contract_version,
           'sprint_id', proof.sprint_id,
           'completion_receipt_id', proof.completion_receipt_id,
           'reason', CASE WHEN EXISTS (
               SELECT 1 FROM task_attempt_legacy_classifications legacy
               WHERE legacy.sprint_id = proof.sprint_id
                 AND legacy.budget_classification = 'OverBudget'
           ) THEN 'OverBudgetHistory' ELSE 'UnsafeLegacyAttemptHistory' END,
           'invalidated_at_schema', 15
       ) AS BLOB)
FROM sprint_completion_proof_states proof
WHERE proof.proof_state = 'ProvenV9'
  AND EXISTS (
      SELECT 1 FROM task_attempt_legacy_classifications legacy
      WHERE legacy.sprint_id = proof.sprint_id
        AND (
            legacy.budget_classification = 'OverBudget'
            OR legacy.classification != 'LegacyIntegratedReleased'
        )
  );

CREATE TRIGGER task_attempt_legacy_completion_invalidations_no_insert
BEFORE INSERT ON task_attempt_legacy_completion_invalidations
BEGIN SELECT RAISE(ABORT, 'legacy completion invalidations are migration-only'); END;
CREATE TRIGGER task_attempt_legacy_completion_invalidations_no_update
BEFORE UPDATE ON task_attempt_legacy_completion_invalidations
BEGIN SELECT RAISE(ABORT, 'legacy completion invalidations are immutable'); END;
CREATE TRIGGER task_attempt_legacy_completion_invalidations_no_delete
BEFORE DELETE ON task_attempt_legacy_completion_invalidations
BEGIN SELECT RAISE(ABORT, 'legacy completion invalidations are immutable'); END;

CREATE TABLE worker_lease_never_launched_releases (
    release_id TEXT PRIMARY KEY NOT NULL,
    disposition_id TEXT NOT NULL UNIQUE,
    attempt_id TEXT NOT NULL UNIQUE,
    sprint_id TEXT NOT NULL,
    task_id TEXT NOT NULL,
    worker_id TEXT NOT NULL,
    worker_lease_id TEXT NOT NULL UNIQUE,
    lease_epoch INTEGER NOT NULL CHECK (lease_epoch > 0),
    absence_evidence_id TEXT NOT NULL UNIQUE,
    absence_evidence_digest TEXT NOT NULL CHECK (
        length(absence_evidence_digest) = 64
        AND absence_evidence_digest NOT GLOB '*[^0-9a-f]*'
    ),
    absence_evidence_bytes BLOB NOT NULL CHECK (length(absence_evidence_bytes) > 0),
    contract_version INTEGER NOT NULL CHECK (contract_version > 0),
    released_at_unix_ms INTEGER NOT NULL CHECK (released_at_unix_ms > 0),
    release_json BLOB NOT NULL CHECK (length(release_json) > 0),
    UNIQUE (sprint_id, lease_epoch),
    FOREIGN KEY (attempt_id) REFERENCES task_attempts(attempt_id) ON DELETE RESTRICT,
    FOREIGN KEY (worker_lease_id)
        REFERENCES worker_lease_acquisitions(lease_id) ON DELETE RESTRICT,
    FOREIGN KEY (disposition_id)
        REFERENCES task_attempt_dispositions(disposition_id)
        ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED
) STRICT, WITHOUT ROWID;

CREATE TABLE task_attempt_running_boundaries (
    boundary_id TEXT PRIMARY KEY NOT NULL CHECK (length(boundary_id) > 0),
    attempt_id TEXT NOT NULL UNIQUE,
    sprint_id TEXT NOT NULL,
    task_id TEXT NOT NULL,
    worker_id TEXT NOT NULL,
    worker_lease_id TEXT NOT NULL UNIQUE,
    lease_epoch INTEGER NOT NULL CHECK (lease_epoch > 0),
    runner_launch_id TEXT NOT NULL UNIQUE,
    runner_session_id TEXT NOT NULL UNIQUE,
    transition_event_id TEXT NOT NULL UNIQUE,
    contract_version INTEGER NOT NULL CHECK (contract_version > 0),
    started_at_unix_ms INTEGER NOT NULL CHECK (started_at_unix_ms > 0),
    boundary_json BLOB NOT NULL CHECK (length(boundary_json) > 0),
    FOREIGN KEY (attempt_id) REFERENCES task_attempts(attempt_id) ON DELETE RESTRICT,
    FOREIGN KEY (sprint_id, runner_launch_id)
        REFERENCES runner_launch_intents(sprint_id, launch_id) ON DELETE RESTRICT,
    FOREIGN KEY (sprint_id, runner_session_id)
        REFERENCES runner_session_policies(sprint_id, session_id) ON DELETE RESTRICT,
    FOREIGN KEY (transition_event_id)
        REFERENCES agent_events(event_id)
        ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED
) STRICT, WITHOUT ROWID;

CREATE TABLE task_attempt_verification_boundaries (
    boundary_id TEXT PRIMARY KEY NOT NULL,
    attempt_id TEXT NOT NULL UNIQUE,
    sprint_id TEXT NOT NULL,
    task_id TEXT NOT NULL,
    worker_lease_id TEXT NOT NULL UNIQUE,
    lease_epoch INTEGER NOT NULL CHECK (lease_epoch > 0),
    worker_launch_id TEXT NOT NULL,
    worker_session_id TEXT NOT NULL,
    change_set_id TEXT NOT NULL,
    sealed_snapshot_id TEXT NOT NULL,
    transition_event_id TEXT NOT NULL UNIQUE,
    terminal_effect_count INTEGER NOT NULL CHECK (terminal_effect_count >= 0),
    contract_version INTEGER NOT NULL CHECK (contract_version > 0),
    sealed_at_unix_ms INTEGER NOT NULL CHECK (sealed_at_unix_ms > 0),
    boundary_json BLOB NOT NULL CHECK (length(boundary_json) > 0),
    FOREIGN KEY (attempt_id) REFERENCES task_attempts(attempt_id) ON DELETE RESTRICT,
    FOREIGN KEY (sprint_id, worker_launch_id)
        REFERENCES runner_launch_intents(sprint_id, launch_id) ON DELETE RESTRICT,
    FOREIGN KEY (sprint_id, worker_session_id)
        REFERENCES runner_session_policies(sprint_id, session_id) ON DELETE RESTRICT,
    FOREIGN KEY (sprint_id, change_set_id)
        REFERENCES change_sets(sprint_id, change_set_id) ON DELETE RESTRICT,
    FOREIGN KEY (sprint_id, sealed_snapshot_id)
        REFERENCES workspace_snapshots(sprint_id, snapshot_id) ON DELETE RESTRICT,
    FOREIGN KEY (transition_event_id)
        REFERENCES agent_events(event_id)
        ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED
) STRICT, WITHOUT ROWID;

CREATE TABLE task_attempt_verification_terminal_effects (
    verification_boundary_id TEXT NOT NULL,
    sprint_id TEXT NOT NULL,
    ordinal INTEGER NOT NULL CHECK (ordinal >= 0),
    effect_id TEXT NOT NULL,
    observation_id TEXT NOT NULL,
    PRIMARY KEY (verification_boundary_id, ordinal),
    UNIQUE (verification_boundary_id, effect_id),
    UNIQUE (verification_boundary_id, observation_id),
    FOREIGN KEY (verification_boundary_id)
        REFERENCES task_attempt_verification_boundaries(boundary_id) ON DELETE RESTRICT,
    FOREIGN KEY (sprint_id, effect_id)
        REFERENCES effect_intents(sprint_id, effect_id) ON DELETE RESTRICT,
    FOREIGN KEY (observation_id)
        REFERENCES effect_observations(observation_id) ON DELETE RESTRICT
) STRICT, WITHOUT ROWID;

CREATE TABLE task_attempt_formal_check_admissions (
    admission_id TEXT PRIMARY KEY NOT NULL,
    attempt_id TEXT NOT NULL,
    sprint_id TEXT NOT NULL,
    task_id TEXT NOT NULL,
    criterion_id TEXT NOT NULL,
    criterion_ordinal INTEGER NOT NULL CHECK (criterion_ordinal >= 0),
    effect_id TEXT NOT NULL UNIQUE,
    worker_session_id TEXT NOT NULL,
    sealed_snapshot_id TEXT NOT NULL,
    command_spec_json BLOB NOT NULL CHECK (length(command_spec_json) > 0),
    contract_version INTEGER NOT NULL CHECK (contract_version > 0),
    admitted_at_unix_ms INTEGER NOT NULL CHECK (admitted_at_unix_ms > 0),
    admission_json BLOB NOT NULL CHECK (length(admission_json) > 0),
    UNIQUE (attempt_id, criterion_id),
    UNIQUE (attempt_id, criterion_ordinal),
    FOREIGN KEY (attempt_id) REFERENCES task_attempts(attempt_id) ON DELETE RESTRICT,
    FOREIGN KEY (sprint_id, worker_session_id)
        REFERENCES runner_session_policies(sprint_id, session_id) ON DELETE RESTRICT,
    FOREIGN KEY (sprint_id, sealed_snapshot_id)
        REFERENCES workspace_snapshots(sprint_id, snapshot_id) ON DELETE RESTRICT,
    FOREIGN KEY (sprint_id, effect_id)
        REFERENCES effect_intents(sprint_id, effect_id)
        ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED
) STRICT, WITHOUT ROWID;

CREATE TABLE task_attempt_formal_checks (
    formal_check_id TEXT PRIMARY KEY NOT NULL,
    admission_id TEXT NOT NULL UNIQUE,
    attempt_id TEXT NOT NULL,
    sprint_id TEXT NOT NULL,
    task_id TEXT NOT NULL,
    criterion_id TEXT NOT NULL,
    criterion_ordinal INTEGER NOT NULL CHECK (criterion_ordinal >= 0),
    effect_id TEXT NOT NULL UNIQUE,
    observation_id TEXT NOT NULL UNIQUE,
    verification_receipt_id TEXT NOT NULL UNIQUE,
    worker_session_id TEXT NOT NULL,
    sealed_snapshot_id TEXT NOT NULL,
    passed INTEGER NOT NULL CHECK (passed IN (0, 1)),
    contract_version INTEGER NOT NULL CHECK (contract_version > 0),
    checked_at_unix_ms INTEGER NOT NULL CHECK (checked_at_unix_ms > 0),
    formal_check_json BLOB NOT NULL CHECK (length(formal_check_json) > 0),
    UNIQUE (attempt_id, criterion_id),
    UNIQUE (attempt_id, criterion_ordinal),
    FOREIGN KEY (admission_id)
        REFERENCES task_attempt_formal_check_admissions(admission_id) ON DELETE RESTRICT,
    FOREIGN KEY (attempt_id) REFERENCES task_attempts(attempt_id) ON DELETE RESTRICT,
    FOREIGN KEY (sprint_id, effect_id)
        REFERENCES effect_intents(sprint_id, effect_id) ON DELETE RESTRICT,
    FOREIGN KEY (observation_id)
        REFERENCES effect_observations(observation_id) ON DELETE RESTRICT,
    FOREIGN KEY (sprint_id, verification_receipt_id)
        REFERENCES verification_receipts(sprint_id, receipt_id) ON DELETE RESTRICT
) STRICT, WITHOUT ROWID;

CREATE TABLE task_attempt_candidate_boundaries (
    boundary_id TEXT PRIMARY KEY NOT NULL,
    attempt_id TEXT NOT NULL UNIQUE,
    sprint_id TEXT NOT NULL,
    task_id TEXT NOT NULL,
    worker_lease_id TEXT NOT NULL UNIQUE,
    lease_epoch INTEGER NOT NULL CHECK (lease_epoch > 0),
    verification_boundary_id TEXT NOT NULL UNIQUE,
    change_set_id TEXT NOT NULL,
    sealed_snapshot_id TEXT NOT NULL,
    transition_event_id TEXT NOT NULL UNIQUE,
    formal_check_count INTEGER NOT NULL CHECK (formal_check_count >= 0),
    contract_version INTEGER NOT NULL CHECK (contract_version > 0),
    admitted_at_unix_ms INTEGER NOT NULL CHECK (admitted_at_unix_ms > 0),
    boundary_json BLOB NOT NULL CHECK (length(boundary_json) > 0),
    FOREIGN KEY (attempt_id) REFERENCES task_attempts(attempt_id) ON DELETE RESTRICT,
    FOREIGN KEY (verification_boundary_id)
        REFERENCES task_attempt_verification_boundaries(boundary_id) ON DELETE RESTRICT,
    FOREIGN KEY (sprint_id, change_set_id)
        REFERENCES change_sets(sprint_id, change_set_id) ON DELETE RESTRICT,
    FOREIGN KEY (sprint_id, sealed_snapshot_id)
        REFERENCES workspace_snapshots(sprint_id, snapshot_id) ON DELETE RESTRICT,
    FOREIGN KEY (transition_event_id)
        REFERENCES agent_events(event_id)
        ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED
) STRICT, WITHOUT ROWID;

CREATE TABLE task_attempt_candidate_formal_checks (
    candidate_boundary_id TEXT NOT NULL,
    sprint_id TEXT NOT NULL,
    ordinal INTEGER NOT NULL CHECK (ordinal >= 0),
    formal_check_id TEXT NOT NULL,
    criterion_id TEXT NOT NULL,
    verification_receipt_id TEXT NOT NULL,
    PRIMARY KEY (candidate_boundary_id, ordinal),
    UNIQUE (candidate_boundary_id, formal_check_id),
    UNIQUE (candidate_boundary_id, criterion_id),
    UNIQUE (candidate_boundary_id, verification_receipt_id),
    FOREIGN KEY (candidate_boundary_id)
        REFERENCES task_attempt_candidate_boundaries(boundary_id) ON DELETE RESTRICT,
    FOREIGN KEY (formal_check_id)
        REFERENCES task_attempt_formal_checks(formal_check_id) ON DELETE RESTRICT,
    FOREIGN KEY (sprint_id, verification_receipt_id)
        REFERENCES verification_receipts(sprint_id, receipt_id) ON DELETE RESTRICT
) STRICT, WITHOUT ROWID;

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
    result_snapshot_id TEXT NOT NULL CHECK (result_snapshot_id != input_snapshot_id),
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

-- A current task integration receipt is not standalone authority.  The
-- coverage row is inserted before the receipt and its deferred references
-- require the exact Integrated disposition to exist by commit.
CREATE TABLE task_attempt_integrated_result_coverage (
    disposition_id TEXT PRIMARY KEY NOT NULL,
    receipt_id TEXT NOT NULL UNIQUE,
    admission_id TEXT NOT NULL UNIQUE,
    attempt_id TEXT NOT NULL UNIQUE,
    FOREIGN KEY (disposition_id)
        REFERENCES task_attempt_dispositions(disposition_id)
        ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED,
    FOREIGN KEY (receipt_id)
        REFERENCES task_integration_receipts(receipt_id)
        ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED,
    FOREIGN KEY (admission_id)
        REFERENCES task_attempt_integration_admissions(admission_id) ON DELETE RESTRICT,
    FOREIGN KEY (attempt_id)
        REFERENCES task_attempts(attempt_id) ON DELETE RESTRICT
) STRICT, WITHOUT ROWID;

-- A successful cleanup result for a current task attempt is never standalone
-- authority. The coverage row precedes the receipt and has deferred joins to
-- both the exact disposition and append-only lease release, making all three
-- artifacts one commit unit. Integrated attempts use the same coverage after
-- their disposition already exists and before their cleanup receipt.
CREATE TABLE task_attempt_cleanup_result_coverage (
    cleanup_receipt_id TEXT PRIMARY KEY NOT NULL,
    disposition_id TEXT NOT NULL UNIQUE,
    attempt_id TEXT NOT NULL UNIQUE,
    sprint_id TEXT NOT NULL,
    worker_lease_id TEXT NOT NULL UNIQUE,
    lease_epoch INTEGER NOT NULL CHECK (lease_epoch > 0),
    cleanup_effect_id TEXT NOT NULL UNIQUE,
    contract_version INTEGER NOT NULL CHECK (contract_version > 0),
    FOREIGN KEY (attempt_id) REFERENCES task_attempts(attempt_id) ON DELETE RESTRICT,
    FOREIGN KEY (worker_lease_id)
        REFERENCES worker_lease_acquisitions(lease_id) ON DELETE RESTRICT,
    FOREIGN KEY (sprint_id, cleanup_effect_id)
        REFERENCES runner_launch_cleanup_admissions(sprint_id, cleanup_effect_id)
        ON DELETE RESTRICT,
    FOREIGN KEY (sprint_id, cleanup_receipt_id)
        REFERENCES worker_cleanup_receipts(sprint_id, receipt_id)
        ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED,
    FOREIGN KEY (disposition_id)
        REFERENCES task_attempt_dispositions(disposition_id)
        ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED,
    FOREIGN KEY (worker_lease_id)
        REFERENCES worker_lease_releases(lease_id)
        ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED
) STRICT, WITHOUT ROWID;

CREATE TABLE task_attempt_worker_exit_authorities (
    authority_id TEXT PRIMARY KEY NOT NULL,
    attempt_id TEXT NOT NULL UNIQUE,
    sprint_id TEXT NOT NULL,
    worker_lease_id TEXT NOT NULL UNIQUE,
    lease_epoch INTEGER NOT NULL CHECK (lease_epoch > 0),
    launch_id TEXT NOT NULL UNIQUE,
    session_id TEXT NOT NULL UNIQUE,
    evidence_id TEXT NOT NULL UNIQUE,
    evidence_digest TEXT NOT NULL CHECK (
        length(evidence_digest) = 64 AND evidence_digest NOT GLOB '*[^0-9a-f]*'
    ),
    evidence_bytes BLOB NOT NULL CHECK (length(evidence_bytes) > 0),
    contract_version INTEGER NOT NULL CHECK (contract_version > 0),
    observed_at_unix_ms INTEGER NOT NULL CHECK (observed_at_unix_ms > 0),
    authority_json BLOB NOT NULL CHECK (length(authority_json) > 0),
    FOREIGN KEY (attempt_id) REFERENCES task_attempts(attempt_id) ON DELETE RESTRICT,
    FOREIGN KEY (sprint_id, launch_id)
        REFERENCES runner_launch_intents(sprint_id, launch_id) ON DELETE RESTRICT,
    FOREIGN KEY (sprint_id, session_id)
        REFERENCES runner_session_policies(sprint_id, session_id) ON DELETE RESTRICT
) STRICT, WITHOUT ROWID;

CREATE TABLE task_attempt_candidate_rejection_authorities (
    authority_id TEXT PRIMARY KEY NOT NULL,
    attempt_id TEXT NOT NULL UNIQUE,
    sprint_id TEXT NOT NULL,
    candidate_boundary_id TEXT NOT NULL UNIQUE,
    evidence_id TEXT NOT NULL UNIQUE,
    evidence_digest TEXT NOT NULL CHECK (
        length(evidence_digest) = 64 AND evidence_digest NOT GLOB '*[^0-9a-f]*'
    ),
    evidence_bytes BLOB NOT NULL CHECK (length(evidence_bytes) > 0),
    contract_version INTEGER NOT NULL CHECK (contract_version > 0),
    rejected_at_unix_ms INTEGER NOT NULL CHECK (rejected_at_unix_ms > 0),
    authority_json BLOB NOT NULL CHECK (length(authority_json) > 0),
    FOREIGN KEY (attempt_id) REFERENCES task_attempts(attempt_id) ON DELETE RESTRICT,
    FOREIGN KEY (candidate_boundary_id)
        REFERENCES task_attempt_candidate_boundaries(boundary_id) ON DELETE RESTRICT
) STRICT, WITHOUT ROWID;

CREATE TABLE task_attempt_policy_cause_authorities (
    authority_id TEXT PRIMARY KEY NOT NULL,
    attempt_id TEXT NOT NULL,
    sprint_id TEXT NOT NULL,
    task_id TEXT NOT NULL,
    cause_kind TEXT NOT NULL CHECK (cause_kind IN (
        'PermanentContractViolation', 'CriterionProvenUnsatisfiable',
        'AuthorityExpansionRequired', 'VerifiedDependencyUnavailable',
        'OperatorCanceled'
    )),
    subject_id TEXT NOT NULL,
    evidence_id TEXT NOT NULL UNIQUE,
    evidence_digest TEXT NOT NULL CHECK (
        length(evidence_digest) = 64 AND evidence_digest NOT GLOB '*[^0-9a-f]*'
    ),
    evidence_bytes BLOB NOT NULL CHECK (length(evidence_bytes) > 0),
    contract_version INTEGER NOT NULL CHECK (contract_version > 0),
    decided_at_unix_ms INTEGER NOT NULL CHECK (decided_at_unix_ms > 0),
    authority_json BLOB NOT NULL CHECK (length(authority_json) > 0),
    UNIQUE (attempt_id, cause_kind),
    FOREIGN KEY (attempt_id) REFERENCES task_attempts(attempt_id) ON DELETE RESTRICT
) STRICT, WITHOUT ROWID;

CREATE TABLE task_attempt_disposition_uncertain_authorities (
    disposition_id TEXT NOT NULL,
    ordinal INTEGER NOT NULL CHECK (ordinal >= 0),
    authority_reference_id TEXT NOT NULL,
    PRIMARY KEY (disposition_id, ordinal),
    UNIQUE (disposition_id, authority_reference_id),
    FOREIGN KEY (disposition_id)
        REFERENCES task_attempt_dispositions(disposition_id) ON DELETE RESTRICT
) STRICT, WITHOUT ROWID;

CREATE TABLE task_attempt_dispositions (
    disposition_id TEXT PRIMARY KEY NOT NULL,
    attempt_id TEXT NOT NULL UNIQUE,
    sprint_id TEXT NOT NULL,
    task_id TEXT NOT NULL,
    worker_id TEXT NOT NULL,
    worker_lease_id TEXT NOT NULL UNIQUE,
    lease_epoch INTEGER NOT NULL CHECK (lease_epoch > 0),
    attempt_ordinal INTEGER NOT NULL CHECK (attempt_ordinal > 0),
    from_state TEXT NOT NULL CHECK (
        from_state IN ('Leased', 'Running', 'Verifying', 'Candidate')
    ),
    disposition_kind TEXT NOT NULL CHECK (disposition_kind IN (
        'Integrated', 'Retryable', 'AttemptsExhausted', 'PermanentFailure',
        'Blocked', 'Canceled', 'UnknownCleaned', 'UnknownQuarantined'
    )),
    cause_kind TEXT CHECK (cause_kind IS NULL OR cause_kind IN (
        'NeverLaunched', 'LaunchRefusedBeforeNativeEffect', 'KnownWorkerExit',
        'FormalVerificationFailed', 'CandidateRejectedKnown',
        'PermanentContractViolation', 'CriterionProvenUnsatisfiable',
        'AuthorityExpansionRequired', 'VerifiedDependencyUnavailable',
        'OperatorCanceled'
    )),
    cause_launch_id TEXT,
    cause_session_id TEXT,
    cause_formal_check_id TEXT,
    cause_candidate_boundary_id TEXT,
    cause_effect_id TEXT,
    cause_observation_id TEXT,
    cause_authority_id TEXT,
    uncertainty_id TEXT,
    uncertain_authority_count INTEGER NOT NULL CHECK (uncertain_authority_count >= 0),
    candidate_boundary_id TEXT,
    integration_receipt_id TEXT,
    cleanup_receipt_id TEXT,
    never_launched_release_id TEXT,
    release_id TEXT,
    transition_event_id TEXT NOT NULL UNIQUE,
    evidence_id TEXT NOT NULL,
    evidence_kind TEXT NOT NULL CHECK (evidence_kind IN (
        'Integrated', 'NeverLaunched', 'LaunchRefusedBeforeNativeEffect',
        'KnownWorkerExit', 'FormalVerificationFailed', 'CandidateRejectedKnown',
        'PermanentContractViolation', 'CriterionProvenUnsatisfiable',
        'AuthorityExpansionRequired', 'VerifiedDependencyUnavailable',
        'OperatorCanceled', 'UnknownTerminalEffect', 'UncertainAuthority'
    )),
    evidence_digest TEXT NOT NULL,
    evidence_bytes BLOB NOT NULL CHECK (length(evidence_bytes) > 0),
    contract_version INTEGER NOT NULL CHECK (contract_version > 0),
    disposed_at_unix_ms INTEGER NOT NULL CHECK (disposed_at_unix_ms > 0),
    disposition_json BLOB NOT NULL CHECK (length(disposition_json) > 0),
    FOREIGN KEY (attempt_id) REFERENCES task_attempts(attempt_id) ON DELETE RESTRICT,
    FOREIGN KEY (candidate_boundary_id)
        REFERENCES task_attempt_candidate_boundaries(boundary_id) ON DELETE RESTRICT,
    FOREIGN KEY (sprint_id, integration_receipt_id)
        REFERENCES task_integration_receipts(sprint_id, receipt_id) ON DELETE RESTRICT,
    FOREIGN KEY (sprint_id, cleanup_receipt_id)
        REFERENCES worker_cleanup_receipts(sprint_id, receipt_id) ON DELETE RESTRICT,
    FOREIGN KEY (never_launched_release_id)
        REFERENCES worker_lease_never_launched_releases(release_id) ON DELETE RESTRICT,
    FOREIGN KEY (transition_event_id)
        REFERENCES agent_events(event_id)
        ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED,
    CHECK (
        (disposition_kind = 'Integrated'
         AND uncertain_authority_count = 0
         AND cause_kind IS NULL
         AND candidate_boundary_id IS NOT NULL
         AND integration_receipt_id IS NOT NULL
         AND cleanup_receipt_id IS NULL
         AND never_launched_release_id IS NULL
         AND release_id IS NULL)
        OR
        (disposition_kind IN (
             'Retryable', 'AttemptsExhausted', 'PermanentFailure', 'Blocked', 'Canceled'
         )
         AND uncertain_authority_count = 0
         AND cause_kind IS NOT NULL
         AND candidate_boundary_id IS NULL
         AND integration_receipt_id IS NULL
         AND release_id IS NOT NULL
         AND (cleanup_receipt_id IS NOT NULL) != (never_launched_release_id IS NOT NULL))
        OR
        (disposition_kind = 'UnknownCleaned'
         AND uncertain_authority_count = 0
         AND cause_kind IS NULL
         AND candidate_boundary_id IS NULL
         AND integration_receipt_id IS NULL
         AND cleanup_receipt_id IS NOT NULL
         AND never_launched_release_id IS NULL
         AND release_id IS NOT NULL)
        OR
        (disposition_kind = 'UnknownQuarantined'
         AND uncertain_authority_count > 0
         AND cause_kind IS NULL
         AND candidate_boundary_id IS NULL
         AND integration_receipt_id IS NULL
         AND cleanup_receipt_id IS NULL
         AND never_launched_release_id IS NULL
         AND release_id IS NULL)
    )
) STRICT, WITHOUT ROWID;

-- One canonical source set drives quarantine insertion, Rust recovery, and
-- the direct-SQL closure fence. Unknown effects use their observation ID;
-- every other effect uses its effect ID; native preparation uses its journal
-- ID. Aliases therefore cannot produce distinct immutable quarantine bytes.
CREATE VIEW task_attempt_canonical_unresolved_authorities AS
    SELECT intent.sprint_id,
           intent.worker_lease_id,
           intent.worker_lease_epoch AS lease_epoch,
           'Effect' AS authority_kind,
           CASE WHEN observation.outcome = 'Unknown'
                THEN observation.observation_id ELSE intent.effect_id END
             AS authority_reference_id,
           intent.effect_id AS source_effect_id,
           CASE WHEN observation.outcome = 'Unknown'
                THEN observation.observed_at_unix_ms
                ELSE intent.created_at_unix_ms END AS authority_at_unix_ms
    FROM effect_intents intent
    LEFT JOIN effect_observations observation
      ON observation.effect_id = intent.effect_id
    LEFT JOIN unresolved_mutation_effects mutation
      ON mutation.effect_id = intent.effect_id
    LEFT JOIN legacy_finish_receipt_gaps finish_gap
      ON finish_gap.effect_id = intent.effect_id
    WHERE intent.worker_lease_id IS NOT NULL
      AND intent.worker_lease_epoch IS NOT NULL
      AND NOT EXISTS (
              SELECT 1 FROM runner_launch_cleanup_admissions cleanup
              WHERE cleanup.cleanup_effect_id = intent.effect_id
          )
      AND (
          observation.effect_id IS NULL
          OR observation.outcome = 'Unknown'
          OR mutation.effect_id IS NOT NULL
          OR finish_gap.effect_id IS NOT NULL
      )
    UNION ALL
    SELECT launch.sprint_id,
           launch.worker_lease_id,
           launch.worker_lease_epoch AS lease_epoch,
           'Preparation' AS authority_kind,
           preparation.native_journal_id AS authority_reference_id,
           NULL AS source_effect_id,
           preparation.claimed_at_unix_ms AS authority_at_unix_ms
    FROM runner_launch_preparation_attempts preparation
    JOIN runner_launch_intents launch ON launch.launch_id = preparation.launch_id
    LEFT JOIN runner_launch_preparation_outcomes outcome
      ON outcome.attempt_id = preparation.attempt_id
    WHERE outcome.attempt_id IS NULL
       OR outcome.disposition = 'NativeEffectUncertain'
       OR (
           outcome.disposition = 'HeldChildPrepared'
           AND NOT EXISTS (
               SELECT 1 FROM runner_session_policies session
               WHERE session.launch_id = launch.launch_id
           )
       );

-- Every known cleanup source participates in one total order. The final typed
-- discriminator is necessary because source identities are unique only inside
-- their own authority family.
CREATE VIEW task_attempt_known_cleanup_sources AS
    SELECT attempt_id,
           3 AS outcome_rank,
           observed_at_unix_ms AS source_at_unix_ms,
           evidence_id AS source_id,
           'WorkerExit' AS source_kind
      FROM task_attempt_worker_exit_authorities
    UNION ALL
    SELECT attempt_id,
           3,
           rejected_at_unix_ms,
           evidence_id,
           'CandidateRejection'
      FROM task_attempt_candidate_rejection_authorities
    UNION ALL
    SELECT attempt_id,
           CASE cause_kind
             WHEN 'PermanentContractViolation' THEN 0
             WHEN 'CriterionProvenUnsatisfiable' THEN 0
             WHEN 'OperatorCanceled' THEN 1
             ELSE 2
           END,
           decided_at_unix_ms,
           evidence_id,
           'PolicyCause'
      FROM task_attempt_policy_cause_authorities
    UNION ALL
    SELECT attempt_id,
           3,
           checked_at_unix_ms,
           observation_id,
           'FormalVerificationFailure'
      FROM task_attempt_formal_checks
     WHERE passed = 0
    UNION ALL
    SELECT attempt.attempt_id,
           3,
           outcome.finished_at_unix_ms,
           preparation.attempt_id,
           'LaunchRefusal'
      FROM runner_launch_preparation_attempts preparation
      JOIN runner_launch_preparation_outcomes outcome
        ON outcome.attempt_id = preparation.attempt_id
      JOIN runner_launch_intents launch ON launch.launch_id = preparation.launch_id
      JOIN task_attempts attempt
        ON attempt.worker_lease_id = launch.worker_lease_id
       AND attempt.lease_epoch = launch.worker_lease_epoch
     WHERE outcome.disposition = 'RefusedBeforeNativeEffect';

-- A resolved authority leaves the canonical view. A still-Unknown effect may
-- instead be covered by the exact durable zero-survivor cleanup disposition.
CREATE VIEW task_attempt_uncovered_uncertain_authorities AS
SELECT unresolved.sprint_id,
       unresolved.worker_lease_id,
       unresolved.lease_epoch,
       unresolved.authority_kind,
       unresolved.authority_reference_id,
       unresolved.source_effect_id,
       unresolved.authority_at_unix_ms
FROM task_attempt_canonical_unresolved_authorities unresolved
WHERE NOT EXISTS (
    SELECT 1
    FROM task_attempt_dispositions disposition
    WHERE disposition.sprint_id = unresolved.sprint_id
      AND disposition.worker_lease_id = unresolved.worker_lease_id
      AND disposition.lease_epoch = unresolved.lease_epoch
      AND (
          (
              disposition.disposition_kind = 'UnknownQuarantined'
              AND EXISTS (
                  SELECT 1
                  FROM task_attempt_disposition_uncertain_authorities link
                  WHERE link.disposition_id = disposition.disposition_id
                    AND link.authority_reference_id = unresolved.authority_reference_id
              )
          )
          OR (
              disposition.disposition_kind = 'UnknownCleaned'
              AND unresolved.authority_kind = 'Effect'
              AND disposition.cause_effect_id = unresolved.source_effect_id
              AND disposition.cause_observation_id = unresolved.authority_reference_id
          )
      )
);

CREATE TABLE sprint_unknown_terminalization_pending (
    marker_id TEXT PRIMARY KEY NOT NULL,
    sprint_id TEXT NOT NULL UNIQUE,
    first_attempt_id TEXT NOT NULL,
    first_disposition_id TEXT NOT NULL UNIQUE,
    contract_version INTEGER NOT NULL CHECK (contract_version > 0),
    pending_at_unix_ms INTEGER NOT NULL CHECK (pending_at_unix_ms > 0),
    marker_json BLOB NOT NULL CHECK (length(marker_json) > 0),
    FOREIGN KEY (sprint_id) REFERENCES sprints(sprint_id) ON DELETE RESTRICT,
    FOREIGN KEY (first_attempt_id) REFERENCES task_attempts(attempt_id) ON DELETE RESTRICT,
    FOREIGN KEY (first_disposition_id)
        REFERENCES task_attempt_dispositions(disposition_id) ON DELETE RESTRICT
) STRICT, WITHOUT ROWID;

CREATE TABLE sprint_unknown_terminalization_closures (
    marker_id TEXT PRIMARY KEY NOT NULL,
    sprint_id TEXT NOT NULL UNIQUE,
    terminal_evidence_id TEXT NOT NULL UNIQUE,
    terminal_event_id TEXT NOT NULL UNIQUE,
    contract_version INTEGER NOT NULL CHECK (contract_version > 0),
    closed_at_unix_ms INTEGER NOT NULL CHECK (closed_at_unix_ms > 0),
    closure_json BLOB NOT NULL CHECK (length(closure_json) > 0),
    FOREIGN KEY (marker_id)
        REFERENCES sprint_unknown_terminalization_pending(marker_id) ON DELETE RESTRICT,
    FOREIGN KEY (sprint_id)
        REFERENCES sprint_unknown_terminalization_pending(sprint_id) ON DELETE RESTRICT,
    FOREIGN KEY (terminal_evidence_id)
        REFERENCES sprint_non_success_terminal_outcomes(record_id) ON DELETE RESTRICT,
    FOREIGN KEY (terminal_event_id)
        REFERENCES agent_events(event_id) ON DELETE RESTRICT
) STRICT, WITHOUT ROWID;

-- Reciprocal deferred coverage makes an open pending marker and sprint
-- `Unknown` inseparable at commit. The requirement is inserted before the
-- terminal evidence/event; its deferred joins require the exact closure to
-- exist by commit, so direct SQL cannot strand a terminal sprint with an open
-- marker.
CREATE TABLE sprint_unknown_terminalization_closure_requirements (
    marker_id TEXT PRIMARY KEY NOT NULL,
    sprint_id TEXT NOT NULL UNIQUE,
    terminal_evidence_id TEXT NOT NULL UNIQUE,
    terminal_event_id TEXT NOT NULL UNIQUE,
    contract_version INTEGER NOT NULL CHECK (contract_version > 0),
    closed_at_unix_ms INTEGER NOT NULL CHECK (closed_at_unix_ms > 0),
    FOREIGN KEY (marker_id)
        REFERENCES sprint_unknown_terminalization_pending(marker_id) ON DELETE RESTRICT,
    FOREIGN KEY (terminal_evidence_id)
        REFERENCES sprint_non_success_terminal_outcomes(record_id)
        ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED,
    FOREIGN KEY (terminal_event_id)
        REFERENCES agent_events(event_id)
        ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED,
    FOREIGN KEY (marker_id)
        REFERENCES sprint_unknown_terminalization_closures(marker_id)
        ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED
) STRICT, WITHOUT ROWID;

CREATE TABLE sprint_unknown_pending_observation_admissions (
    observation_id TEXT PRIMARY KEY NOT NULL,
    effect_id TEXT NOT NULL UNIQUE,
    sprint_id TEXT NOT NULL,
    attempt_id TEXT,
    worker_lease_id TEXT,
    terminal_event_id TEXT NOT NULL UNIQUE,
    contract_version INTEGER NOT NULL CHECK (contract_version > 0),
    admitted_at_unix_ms INTEGER NOT NULL CHECK (admitted_at_unix_ms > 0),
    FOREIGN KEY (effect_id) REFERENCES effect_intents(effect_id) ON DELETE RESTRICT,
    FOREIGN KEY (attempt_id) REFERENCES task_attempts(attempt_id) ON DELETE RESTRICT,
    FOREIGN KEY (worker_lease_id)
        REFERENCES worker_lease_acquisitions(lease_id) ON DELETE RESTRICT,
    FOREIGN KEY (observation_id)
        REFERENCES effect_observations(observation_id)
        ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED,
    FOREIGN KEY (terminal_event_id)
        REFERENCES agent_events(event_id)
        ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED,
    CHECK ((attempt_id IS NULL) = (worker_lease_id IS NULL))
) STRICT, WITHOUT ROWID;

DROP VIEW active_worker_leases;
CREATE VIEW active_worker_leases AS
SELECT acquisition.*
FROM worker_lease_acquisitions acquisition
LEFT JOIN worker_lease_releases cleanup_release
       ON cleanup_release.lease_id = acquisition.lease_id
LEFT JOIN worker_lease_never_launched_releases no_launch_release
       ON no_launch_release.worker_lease_id = acquisition.lease_id
WHERE cleanup_release.lease_id IS NULL
  AND no_launch_release.worker_lease_id IS NULL;

CREATE VIEW task_attempt_open_cleanup_source_admissions AS
SELECT attempt.attempt_id,
       attempt.sprint_id,
       attempt.task_id,
       attempt.worker_id,
       attempt.worker_lease_id,
       attempt.lease_epoch,
       launch.launch_id,
       launch.session_id
FROM task_attempts attempt
JOIN active_worker_leases active
  ON active.lease_id = attempt.worker_lease_id
 AND active.lease_epoch = attempt.lease_epoch
JOIN runner_launch_intents launch
  ON launch.worker_lease_id = attempt.worker_lease_id
 AND launch.worker_lease_epoch = attempt.lease_epoch
JOIN runner_launch_cleanup_admissions cleanup
  ON cleanup.launch_id = launch.launch_id
 AND cleanup.sprint_id = launch.sprint_id
JOIN effect_intents cleanup_intent
  ON cleanup_intent.effect_id = cleanup.cleanup_effect_id
 AND cleanup_intent.sprint_id = cleanup.sprint_id
JOIN finish_effect_kinds cleanup_kind
  ON cleanup_kind.effect_id = cleanup_intent.effect_id
 AND cleanup_kind.sprint_id = cleanup_intent.sprint_id
LEFT JOIN effect_observations cleanup_observation
  ON cleanup_observation.effect_id = cleanup.cleanup_effect_id
 AND cleanup_observation.sprint_id = cleanup.sprint_id
WHERE attempt.schema_generation = 15
  AND active.sprint_id = attempt.sprint_id
  AND launch.sprint_id = attempt.sprint_id
  AND launch.purpose = 'TaskWorker'
  AND launch.worker_id = attempt.worker_id
  AND cleanup.session_id = launch.session_id
  AND cleanup.contract_version = attempt.contract_version
  AND cleanup_intent.worker_lease_id = attempt.worker_lease_id
  AND cleanup_intent.worker_lease_epoch = attempt.lease_epoch
  AND cleanup_kind.effect_kind = 'CleanupWorkerDomain'
  AND cleanup_kind.contract_version = attempt.contract_version
  AND cleanup_observation.effect_id IS NULL
  AND NOT EXISTS (
      SELECT 1 FROM task_attempt_dispositions disposition
      WHERE disposition.attempt_id = attempt.attempt_id
  )
  AND NOT EXISTS (
      SELECT 1
      FROM sprint_unknown_terminalization_pending pending
      LEFT JOIN sprint_unknown_terminalization_closures closure
        ON closure.marker_id = pending.marker_id
      WHERE pending.sprint_id = attempt.sprint_id
        AND closure.marker_id IS NULL
  )
  AND NOT EXISTS (
      SELECT 1 FROM (
          SELECT sprint_id FROM sprint_terminal_states
          UNION ALL
          SELECT sprint_id FROM sprint_completion_proof_states
          UNION ALL
          SELECT sprint_id FROM sprint_non_success_terminal_outcomes
      ) terminal
      WHERE terminal.sprint_id = attempt.sprint_id
  );

CREATE TRIGGER task_attempts_no_update BEFORE UPDATE ON task_attempts
BEGIN SELECT RAISE(ABORT, 'task attempts are immutable'); END;
CREATE TRIGGER task_attempts_no_delete BEFORE DELETE ON task_attempts
BEGIN SELECT RAISE(ABORT, 'task attempts are immutable'); END;
CREATE TRIGGER task_attempt_legacy_classifications_no_insert
BEFORE INSERT ON task_attempt_legacy_classifications
BEGIN SELECT RAISE(ABORT, 'legacy task-attempt classifications are migration-only'); END;
CREATE TRIGGER task_attempt_legacy_classifications_no_update
BEFORE UPDATE ON task_attempt_legacy_classifications
BEGIN SELECT RAISE(ABORT, 'legacy task-attempt classifications are immutable'); END;
CREATE TRIGGER task_attempt_legacy_classifications_no_delete
BEFORE DELETE ON task_attempt_legacy_classifications
BEGIN SELECT RAISE(ABORT, 'legacy task-attempt classifications are immutable'); END;

CREATE TRIGGER task_attempt_append_only_no_update
BEFORE UPDATE ON worker_lease_never_launched_releases
BEGIN SELECT RAISE(ABORT, 'never-launched releases are immutable'); END;
CREATE TRIGGER task_attempt_append_only_no_delete
BEFORE DELETE ON worker_lease_never_launched_releases
BEGIN SELECT RAISE(ABORT, 'never-launched releases are immutable'); END;
CREATE TRIGGER task_attempt_running_boundaries_no_update
BEFORE UPDATE ON task_attempt_running_boundaries
BEGIN SELECT RAISE(ABORT, 'attempt running boundaries are immutable'); END;
CREATE TRIGGER task_attempt_running_boundaries_no_delete
BEFORE DELETE ON task_attempt_running_boundaries
BEGIN SELECT RAISE(ABORT, 'attempt running boundaries are immutable'); END;
CREATE TRIGGER task_attempt_verification_boundaries_no_update
BEFORE UPDATE ON task_attempt_verification_boundaries
BEGIN SELECT RAISE(ABORT, 'attempt verification boundaries are immutable'); END;
CREATE TRIGGER task_attempt_verification_boundaries_no_delete
BEFORE DELETE ON task_attempt_verification_boundaries
BEGIN SELECT RAISE(ABORT, 'attempt verification boundaries are immutable'); END;
CREATE TRIGGER task_attempt_verification_terminal_effects_no_update
BEFORE UPDATE ON task_attempt_verification_terminal_effects
BEGIN SELECT RAISE(ABORT, 'verification terminal-effect links are immutable'); END;
CREATE TRIGGER task_attempt_verification_terminal_effects_no_delete
BEFORE DELETE ON task_attempt_verification_terminal_effects
BEGIN SELECT RAISE(ABORT, 'verification terminal-effect links are immutable'); END;
CREATE TRIGGER task_attempt_formal_check_admissions_no_update
BEFORE UPDATE ON task_attempt_formal_check_admissions
BEGIN SELECT RAISE(ABORT, 'formal-check admissions are immutable'); END;
CREATE TRIGGER task_attempt_formal_check_admissions_no_delete
BEFORE DELETE ON task_attempt_formal_check_admissions
BEGIN SELECT RAISE(ABORT, 'formal-check admissions are immutable'); END;
CREATE TRIGGER task_attempt_formal_checks_no_update
BEFORE UPDATE ON task_attempt_formal_checks
BEGIN SELECT RAISE(ABORT, 'formal checks are immutable'); END;
CREATE TRIGGER task_attempt_formal_checks_no_delete
BEFORE DELETE ON task_attempt_formal_checks
BEGIN SELECT RAISE(ABORT, 'formal checks are immutable'); END;
CREATE TRIGGER task_attempt_candidate_boundaries_no_update
BEFORE UPDATE ON task_attempt_candidate_boundaries
BEGIN SELECT RAISE(ABORT, 'attempt candidate boundaries are immutable'); END;
CREATE TRIGGER task_attempt_candidate_boundaries_no_delete
BEFORE DELETE ON task_attempt_candidate_boundaries
BEGIN SELECT RAISE(ABORT, 'attempt candidate boundaries are immutable'); END;
CREATE TRIGGER task_attempt_candidate_formal_checks_no_update
BEFORE UPDATE ON task_attempt_candidate_formal_checks
BEGIN SELECT RAISE(ABORT, 'candidate formal-check links are immutable'); END;
CREATE TRIGGER task_attempt_candidate_formal_checks_no_delete
BEFORE DELETE ON task_attempt_candidate_formal_checks
BEGIN SELECT RAISE(ABORT, 'candidate formal-check links are immutable'); END;
CREATE TRIGGER task_attempt_integration_admissions_no_update
BEFORE UPDATE ON task_attempt_integration_admissions
BEGIN SELECT RAISE(ABORT, 'attempt integration admissions are immutable'); END;
CREATE TRIGGER task_attempt_integration_admissions_no_delete
BEFORE DELETE ON task_attempt_integration_admissions
BEGIN SELECT RAISE(ABORT, 'attempt integration admissions are immutable'); END;
CREATE TRIGGER task_attempt_integrated_result_coverage_no_update
BEFORE UPDATE ON task_attempt_integrated_result_coverage
BEGIN SELECT RAISE(ABORT, 'integrated-result coverage is immutable'); END;
CREATE TRIGGER task_attempt_integrated_result_coverage_no_delete
BEFORE DELETE ON task_attempt_integrated_result_coverage
BEGIN SELECT RAISE(ABORT, 'integrated-result coverage is immutable'); END;
CREATE TRIGGER task_attempt_worker_exit_authorities_no_update
BEFORE UPDATE ON task_attempt_worker_exit_authorities
BEGIN SELECT RAISE(ABORT, 'worker-exit authorities are immutable'); END;
CREATE TRIGGER task_attempt_worker_exit_authorities_no_delete
BEFORE DELETE ON task_attempt_worker_exit_authorities
BEGIN SELECT RAISE(ABORT, 'worker-exit authorities are immutable'); END;
CREATE TRIGGER task_attempt_candidate_rejection_authorities_no_update
BEFORE UPDATE ON task_attempt_candidate_rejection_authorities
BEGIN SELECT RAISE(ABORT, 'candidate-rejection authorities are immutable'); END;
CREATE TRIGGER task_attempt_candidate_rejection_authorities_no_delete
BEFORE DELETE ON task_attempt_candidate_rejection_authorities
BEGIN SELECT RAISE(ABORT, 'candidate-rejection authorities are immutable'); END;
CREATE TRIGGER task_attempt_policy_cause_authorities_no_update
BEFORE UPDATE ON task_attempt_policy_cause_authorities
BEGIN SELECT RAISE(ABORT, 'policy cause authorities are immutable'); END;
CREATE TRIGGER task_attempt_policy_cause_authorities_no_delete
BEFORE DELETE ON task_attempt_policy_cause_authorities
BEGIN SELECT RAISE(ABORT, 'policy cause authorities are immutable'); END;
CREATE TRIGGER task_attempt_disposition_uncertain_authorities_no_update
BEFORE UPDATE ON task_attempt_disposition_uncertain_authorities
BEGIN SELECT RAISE(ABORT, 'disposition uncertain-authority links are immutable'); END;
CREATE TRIGGER task_attempt_disposition_uncertain_authorities_no_delete
BEFORE DELETE ON task_attempt_disposition_uncertain_authorities
BEGIN SELECT RAISE(ABORT, 'disposition uncertain-authority links are immutable'); END;
CREATE TRIGGER task_attempt_cleanup_result_coverage_no_update
BEFORE UPDATE ON task_attempt_cleanup_result_coverage
BEGIN SELECT RAISE(ABORT, 'task-attempt cleanup result coverage is immutable'); END;
CREATE TRIGGER task_attempt_cleanup_result_coverage_no_delete
BEFORE DELETE ON task_attempt_cleanup_result_coverage
BEGIN SELECT RAISE(ABORT, 'task-attempt cleanup result coverage is immutable'); END;
CREATE TRIGGER task_attempt_dispositions_no_update
BEFORE UPDATE ON task_attempt_dispositions
BEGIN SELECT RAISE(ABORT, 'task-attempt dispositions are immutable'); END;
CREATE TRIGGER task_attempt_dispositions_no_delete
BEFORE DELETE ON task_attempt_dispositions
BEGIN SELECT RAISE(ABORT, 'task-attempt dispositions are immutable'); END;
CREATE TRIGGER sprint_unknown_terminalization_pending_no_update
BEFORE UPDATE ON sprint_unknown_terminalization_pending
BEGIN SELECT RAISE(ABORT, 'unknown-terminalization pending markers are immutable'); END;
CREATE TRIGGER sprint_unknown_terminalization_pending_no_delete
BEFORE DELETE ON sprint_unknown_terminalization_pending
BEGIN SELECT RAISE(ABORT, 'unknown-terminalization pending markers are immutable'); END;
CREATE TRIGGER sprint_unknown_terminalization_closures_no_update
BEFORE UPDATE ON sprint_unknown_terminalization_closures
BEGIN SELECT RAISE(ABORT, 'unknown-terminalization closures are immutable'); END;
CREATE TRIGGER sprint_unknown_terminalization_closures_no_delete
BEFORE DELETE ON sprint_unknown_terminalization_closures
BEGIN SELECT RAISE(ABORT, 'unknown-terminalization closures are immutable'); END;
CREATE TRIGGER sprint_unknown_terminalization_closure_requirements_no_update
BEFORE UPDATE ON sprint_unknown_terminalization_closure_requirements
BEGIN SELECT RAISE(ABORT, 'unknown-terminalization closure requirements are immutable'); END;
CREATE TRIGGER sprint_unknown_terminalization_closure_requirements_no_delete
BEFORE DELETE ON sprint_unknown_terminalization_closure_requirements
BEGIN SELECT RAISE(ABORT, 'unknown-terminalization closure requirements are immutable'); END;
CREATE TRIGGER sprint_unknown_pending_observation_admissions_no_update
BEFORE UPDATE ON sprint_unknown_pending_observation_admissions
BEGIN SELECT RAISE(ABORT, 'pending observation admissions are immutable'); END;
CREATE TRIGGER sprint_unknown_pending_observation_admissions_no_delete
BEFORE DELETE ON sprint_unknown_pending_observation_admissions
BEGIN SELECT RAISE(ABORT, 'pending observation admissions are immutable'); END;

CREATE TRIGGER runner_launch_intents_unknown_pending_fence
BEFORE INSERT ON runner_launch_intents
WHEN EXISTS (
    SELECT 1
    FROM sprint_unknown_terminalization_pending pending
    LEFT JOIN sprint_unknown_terminalization_closures closure
           ON closure.marker_id = pending.marker_id
    WHERE pending.sprint_id = NEW.sprint_id AND closure.marker_id IS NULL
)
BEGIN SELECT RAISE(ABORT, 'pending sprint Unknown rejects new runner launches'); END;

CREATE TRIGGER runner_session_policies_unknown_pending_fence
BEFORE INSERT ON runner_session_policies
WHEN EXISTS (
    SELECT 1
    FROM sprint_unknown_terminalization_pending pending
    LEFT JOIN sprint_unknown_terminalization_closures closure
           ON closure.marker_id = pending.marker_id
    WHERE pending.sprint_id = NEW.sprint_id AND closure.marker_id IS NULL
)
BEGIN SELECT RAISE(ABORT, 'pending sprint Unknown rejects new runner sessions'); END;

CREATE TRIGGER effect_intents_unknown_pending_fence
BEFORE INSERT ON effect_intents
WHEN EXISTS (
    SELECT 1
    FROM sprint_unknown_terminalization_pending pending
    LEFT JOIN sprint_unknown_terminalization_closures closure
           ON closure.marker_id = pending.marker_id
    WHERE pending.sprint_id = NEW.sprint_id AND closure.marker_id IS NULL
)
BEGIN SELECT RAISE(ABORT, 'pending sprint Unknown rejects new effects'); END;

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
 OR NOT EXISTS (
       SELECT 1
       FROM sprints sprint
       JOIN sprint_task_graphs graph ON graph.sprint_id = sprint.sprint_id,
            json_each(CAST(graph.graph_json AS TEXT), '$.tasks') graph_task,
            json_each(graph_task.value, '$.acceptance_checks') task_check,
            json_each(CAST(sprint.spec_json AS TEXT), '$.acceptance_criteria') criterion
       WHERE sprint.sprint_id = NEW.sprint_id
         AND json_extract(graph_task.value, '$.task_id') = NEW.task_id
         AND task_check.value = NEW.criterion_id
         AND json_extract(criterion.value, '$.criterion_id') = NEW.criterion_id
         AND json_type(criterion.value, '$.kind.Automated') = 'object'
         AND json(json_extract(criterion.value, '$.kind.Automated')) =
             json(CAST(NEW.command_spec_json AS TEXT))
         AND NEW.criterion_ordinal = (
             SELECT COUNT(*)
             FROM json_each(graph_task.value, '$.acceptance_checks') prior_check,
                  json_each(CAST(sprint.spec_json AS TEXT), '$.acceptance_criteria') prior_criterion
             WHERE CAST(prior_check.key AS INTEGER) < CAST(task_check.key AS INTEGER)
               AND json_extract(prior_criterion.value, '$.criterion_id') = prior_check.value
               AND json_type(prior_criterion.value, '$.kind.Automated') = 'object'
         )
     )
 OR EXISTS (SELECT 1 FROM effect_intents intent WHERE intent.effect_id = NEW.effect_id)
BEGIN
    SELECT RAISE(ABORT, 'formal-check admission must be the next exact serialized automated criterion');
END;

CREATE TRIGGER task_attempt_formal_check_validate
BEFORE INSERT ON task_attempt_formal_checks
WHEN NOT EXISTS (
       SELECT 1
       FROM task_attempt_formal_check_admissions admission
       JOIN task_attempts attempt ON attempt.attempt_id = admission.attempt_id
       JOIN effect_intents intent ON intent.effect_id = admission.effect_id
       JOIN effect_observations observation ON observation.effect_id = intent.effect_id
       JOIN verification_receipts receipt
         ON receipt.receipt_id = NEW.verification_receipt_id
       JOIN verification_effect_evidence evidence
         ON evidence.verification_receipt_id = receipt.receipt_id
       JOIN effect_session_bindings binding ON binding.effect_id = intent.effect_id
       WHERE admission.admission_id = NEW.admission_id
         AND admission.attempt_id = NEW.attempt_id
         AND admission.sprint_id = NEW.sprint_id
         AND admission.task_id = NEW.task_id
         AND admission.criterion_id = NEW.criterion_id
         AND admission.criterion_ordinal = NEW.criterion_ordinal
         AND admission.effect_id = NEW.effect_id
         AND admission.worker_session_id = NEW.worker_session_id
         AND admission.sealed_snapshot_id = NEW.sealed_snapshot_id
         AND attempt.worker_lease_id = intent.worker_lease_id
         AND attempt.lease_epoch = intent.worker_lease_epoch
         AND intent.input_snapshot = NEW.sealed_snapshot_id
         AND observation.observation_id = NEW.observation_id
         AND observation.outcome = 'Succeeded'
         AND evidence.effect_id = NEW.effect_id
         AND evidence.observation_id = NEW.observation_id
         AND evidence.runner_session_id = NEW.worker_session_id
         AND binding.session_id = NEW.worker_session_id
         AND receipt.sprint_id = NEW.sprint_id
         AND receipt.snapshot_id = NEW.sealed_snapshot_id
         AND receipt.passed = NEW.passed
         AND receipt.finished_at_unix_ms = NEW.checked_at_unix_ms
         AND NEW.contract_version = attempt.contract_version
         AND NEW.formal_check_json = CAST(json_object(
             'contract_version', NEW.contract_version,
             'formal_check_id', NEW.formal_check_id,
             'attempt', json(CAST(attempt.attempt_json AS TEXT)),
             'criterion_ordinal', NEW.criterion_ordinal,
             'criterion_id', NEW.criterion_id,
             'effect_id', NEW.effect_id,
             'observation_id', NEW.observation_id,
             'verification_receipt', json(CAST(receipt.receipt_json AS TEXT)),
             'runner_session_id', NEW.worker_session_id,
             'sealed_snapshot', NEW.sealed_snapshot_id
         ) AS BLOB)
     )
BEGIN
    SELECT RAISE(ABORT, 'formal check requires exact attempt, effect, observation, receipt, session, and sealed snapshot');
END;

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

CREATE TRIGGER task_attempt_integrated_result_coverage_validate
BEFORE INSERT ON task_attempt_integrated_result_coverage
WHEN length(NEW.disposition_id) = 0
 OR length(NEW.receipt_id) = 0
 OR NOT EXISTS (
      SELECT 1
      FROM task_attempt_integration_admissions admission
      JOIN task_attempts attempt ON attempt.attempt_id = admission.attempt_id
      WHERE admission.admission_id = NEW.admission_id
        AND admission.attempt_id = NEW.attempt_id
        AND attempt.schema_generation = 15
        AND NOT EXISTS (
            SELECT 1 FROM task_integration_receipts receipt
            WHERE receipt.receipt_id = NEW.receipt_id
        )
        AND NOT EXISTS (
            SELECT 1 FROM task_attempt_dispositions disposition
            WHERE disposition.disposition_id = NEW.disposition_id
        )
    )
BEGIN
    SELECT RAISE(ABORT, 'integrated-result coverage must precede one exact receipt and disposition');
END;

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

CREATE TRIGGER task_attempt_cleanup_result_coverage_validate
BEFORE INSERT ON task_attempt_cleanup_result_coverage
WHEN length(NEW.cleanup_receipt_id) = 0
 OR length(NEW.disposition_id) = 0
 OR length(NEW.attempt_id) = 0
 OR length(NEW.worker_lease_id) = 0
 OR length(NEW.cleanup_effect_id) = 0
 OR NOT EXISTS (
      SELECT 1
      FROM task_attempts attempt
      JOIN active_worker_leases active
        ON active.lease_id = attempt.worker_lease_id
       AND active.lease_epoch = attempt.lease_epoch
      JOIN runner_launch_intents launch
        ON launch.worker_lease_id = attempt.worker_lease_id
       AND launch.worker_lease_epoch = attempt.lease_epoch
      JOIN runner_launch_cleanup_admissions cleanup
        ON cleanup.launch_id = launch.launch_id
       AND cleanup.sprint_id = launch.sprint_id
      WHERE attempt.attempt_id = NEW.attempt_id
        AND attempt.schema_generation = 15
        AND attempt.sprint_id = NEW.sprint_id
        AND attempt.worker_lease_id = NEW.worker_lease_id
        AND attempt.lease_epoch = NEW.lease_epoch
        AND attempt.contract_version = NEW.contract_version
        AND active.sprint_id = NEW.sprint_id
        AND cleanup.cleanup_effect_id = NEW.cleanup_effect_id
        AND NOT EXISTS (
            SELECT 1 FROM worker_cleanup_receipts receipt
            WHERE receipt.receipt_id = NEW.cleanup_receipt_id
        )
        AND NOT EXISTS (
            SELECT 1 FROM worker_lease_releases release
            WHERE release.lease_id = NEW.worker_lease_id
        )
        AND (
            (
                NOT EXISTS (
                    SELECT 1 FROM task_attempt_dispositions disposition
                    WHERE disposition.disposition_id = NEW.disposition_id
                       OR disposition.attempt_id = NEW.attempt_id
                )
            )
            OR EXISTS (
                SELECT 1 FROM task_attempt_dispositions disposition
                WHERE disposition.disposition_id = NEW.disposition_id
                  AND disposition.attempt_id = NEW.attempt_id
                  AND disposition.sprint_id = NEW.sprint_id
                  AND disposition.worker_lease_id = NEW.worker_lease_id
                  AND disposition.lease_epoch = NEW.lease_epoch
                  AND disposition.disposition_kind = 'Integrated'
                  AND disposition.contract_version = NEW.contract_version
            )
        )
    )
BEGIN
    SELECT RAISE(ABORT, 'cleanup-result coverage must precede one exact current receipt, disposition, and release');
END;

CREATE TRIGGER worker_cleanup_receipts_require_v15_result_coverage
BEFORE INSERT ON worker_cleanup_receipts
WHEN EXISTS (
       SELECT 1 FROM task_attempts attempt
       WHERE attempt.worker_lease_id = NEW.worker_lease_id
         AND attempt.schema_generation = 15
     )
 AND NOT EXISTS (
       SELECT 1
       FROM task_attempt_cleanup_result_coverage coverage
       JOIN task_attempts attempt ON attempt.attempt_id = coverage.attempt_id
       JOIN runner_launch_cleanup_admissions cleanup
         ON cleanup.cleanup_effect_id = coverage.cleanup_effect_id
        AND cleanup.sprint_id = coverage.sprint_id
       WHERE coverage.cleanup_receipt_id = NEW.receipt_id
         AND coverage.sprint_id = NEW.sprint_id
         AND coverage.worker_lease_id = NEW.worker_lease_id
         AND coverage.lease_epoch = NEW.worker_lease_epoch
         AND coverage.cleanup_effect_id = NEW.effect_id
         AND coverage.contract_version = NEW.contract_version
         AND attempt.schema_generation = 15
         AND attempt.sprint_id = NEW.sprint_id
         AND attempt.worker_lease_id = NEW.worker_lease_id
         AND attempt.lease_epoch = NEW.worker_lease_epoch
         AND cleanup.launch_id = NEW.launch_id
     )
BEGIN
    SELECT RAISE(ABORT, 'current task cleanup receipt requires deferred disposition and release coverage');
END;

CREATE TRIGGER task_attempt_dispositions_require_cleanup_result_coverage
BEFORE INSERT ON task_attempt_dispositions
WHEN NEW.cleanup_receipt_id IS NOT NULL
 AND EXISTS (
       SELECT 1 FROM task_attempts attempt
       WHERE attempt.attempt_id = NEW.attempt_id
         AND attempt.schema_generation = 15
     )
 AND NOT EXISTS (
       SELECT 1 FROM task_attempt_cleanup_result_coverage coverage
       WHERE coverage.cleanup_receipt_id = NEW.cleanup_receipt_id
         AND coverage.disposition_id = NEW.disposition_id
         AND coverage.attempt_id = NEW.attempt_id
         AND coverage.sprint_id = NEW.sprint_id
         AND coverage.worker_lease_id = NEW.worker_lease_id
         AND coverage.lease_epoch = NEW.lease_epoch
         AND coverage.contract_version = NEW.contract_version
     )
BEGIN
    SELECT RAISE(ABORT, 'cleanup disposition requires its exact deferred receipt and release coverage');
END;

CREATE TRIGGER effect_intents_task_attempt_phase_fence
BEFORE INSERT ON effect_intents
WHEN NEW.worker_lease_id IS NOT NULL
 AND NOT EXISTS (
       SELECT 1 FROM runner_launch_cleanup_admissions cleanup
       WHERE cleanup.cleanup_effect_id = NEW.effect_id
         AND cleanup.sprint_id = NEW.sprint_id
     )
 AND NOT EXISTS (
       SELECT 1
       FROM task_attempts attempt
       JOIN active_worker_leases active ON active.lease_id = attempt.worker_lease_id
       WHERE attempt.worker_lease_id = NEW.worker_lease_id
         AND attempt.lease_epoch = NEW.worker_lease_epoch
         AND attempt.sprint_id = NEW.sprint_id
         AND attempt.task_id = NEW.task_id
         AND attempt.worker_id = NEW.worker_id
         AND attempt.schema_generation = 15
         AND NOT EXISTS (
             SELECT 1 FROM task_attempt_dispositions disposition
             WHERE disposition.attempt_id = attempt.attempt_id
         )
         AND NOT EXISTS (
             SELECT 1 FROM task_attempt_formal_checks failed
             WHERE failed.attempt_id = attempt.attempt_id AND failed.passed = 0
         )
         AND (
             (
               COALESCE((
                   SELECT json_extract(CAST(event.event_json AS TEXT),
                                       '$.payload.TaskStateChanged.to')
                   FROM agent_events event
                   WHERE event.sprint_id = NEW.sprint_id
                     AND json_extract(CAST(event.event_json AS TEXT), '$.task_id') = NEW.task_id
                     AND json_type(CAST(event.event_json AS TEXT),
                                   '$.payload.TaskStateChanged') = 'object'
                   ORDER BY event.sequence DESC LIMIT 1
               ), '') = 'Running'
               AND NEW.effect_kind IN (
                   'ReadRelativeFile', 'SearchLiteral', 'RunCommand',
                   'CreateRegularFile', 'ReplaceRegularFile', 'DeleteRegularFile'
               )
               AND EXISTS (
                   SELECT 1
                   FROM task_attempt_running_boundaries running
                   JOIN effect_session_bindings binding ON binding.effect_id = NEW.effect_id
                   WHERE running.attempt_id = attempt.attempt_id
                     AND running.runner_launch_id = binding.launch_id
                     AND running.runner_session_id = binding.session_id
                     AND binding.sprint_id = NEW.sprint_id
               )
             )
             OR
             (
               COALESCE((
                   SELECT json_extract(CAST(event.event_json AS TEXT),
                                       '$.payload.TaskStateChanged.to')
                   FROM agent_events event
                   WHERE event.sprint_id = NEW.sprint_id
                     AND json_extract(CAST(event.event_json AS TEXT), '$.task_id') = NEW.task_id
                     AND json_type(CAST(event.event_json AS TEXT),
                                   '$.payload.TaskStateChanged') = 'object'
                   ORDER BY event.sequence DESC LIMIT 1
               ), '') = 'Running'
               AND NEW.effect_kind = 'ProviderRequest'
               AND NOT EXISTS (
                   SELECT 1 FROM effect_session_bindings binding
                   WHERE binding.effect_id = NEW.effect_id
               )
               AND EXISTS (
                   SELECT 1 FROM task_attempt_running_boundaries running
                   WHERE running.attempt_id = attempt.attempt_id
                     AND running.sprint_id = attempt.sprint_id
                     AND running.task_id = attempt.task_id
                     AND running.worker_id = attempt.worker_id
                     AND running.worker_lease_id = attempt.worker_lease_id
                     AND running.lease_epoch = attempt.lease_epoch
                     AND running.contract_version = attempt.contract_version
                     AND running.started_at_unix_ms <= NEW.created_at_unix_ms
               )
             )
             OR
             (
               COALESCE((
                   SELECT json_extract(CAST(event.event_json AS TEXT),
                                       '$.payload.TaskStateChanged.to')
                   FROM agent_events event
                   WHERE event.sprint_id = NEW.sprint_id
                     AND json_extract(CAST(event.event_json AS TEXT), '$.task_id') = NEW.task_id
                     AND json_type(CAST(event.event_json AS TEXT),
                                   '$.payload.TaskStateChanged') = 'object'
                   ORDER BY event.sequence DESC LIMIT 1
               ), '') = 'Verifying'
               AND NEW.effect_kind = 'RunCommand'
               AND EXISTS (
                   SELECT 1 FROM task_attempt_formal_check_admissions admission
                   WHERE admission.effect_id = NEW.effect_id
                     AND admission.attempt_id = attempt.attempt_id
                     AND admission.sprint_id = NEW.sprint_id
                     AND admission.task_id = NEW.task_id
                     AND admission.sealed_snapshot_id = NEW.input_snapshot
               )
             )
             OR
             (
               COALESCE((
                   SELECT json_extract(CAST(event.event_json AS TEXT),
                                       '$.payload.TaskStateChanged.to')
                   FROM agent_events event
                   WHERE event.sprint_id = NEW.sprint_id
                     AND json_extract(CAST(event.event_json AS TEXT), '$.task_id') = NEW.task_id
                     AND json_type(CAST(event.event_json AS TEXT),
                                   '$.payload.TaskStateChanged') = 'object'
                   ORDER BY event.sequence DESC LIMIT 1
               ), '') = 'Candidate'
               AND NEW.effect_kind = 'IntegrateChangeSet'
               AND EXISTS (
                   SELECT 1 FROM task_attempt_integration_admissions admission
                   WHERE admission.effect_id = NEW.effect_id
                     AND admission.attempt_id = attempt.attempt_id
                     AND admission.sprint_id = NEW.sprint_id
                     AND admission.task_id = NEW.task_id
                     AND admission.worker_id = NEW.worker_id
                     AND admission.input_snapshot_id = NEW.input_snapshot
               )
             )
         )
     )
BEGIN
    SELECT RAISE(ABORT, 'task effect is not admitted by the exact current attempt phase');
END;

CREATE TRIGGER effect_intents_cover_formal_check_admission
AFTER INSERT ON effect_intents
WHEN EXISTS (
       SELECT 1 FROM task_attempt_formal_check_admissions admission
       WHERE admission.effect_id = NEW.effect_id
     )
 AND NOT EXISTS (
       SELECT 1
       FROM task_attempt_formal_check_admissions admission
       JOIN task_attempts attempt ON attempt.attempt_id = admission.attempt_id
       JOIN task_attempt_verification_boundaries boundary
         ON boundary.attempt_id = attempt.attempt_id
       JOIN effect_session_bindings binding ON binding.effect_id = NEW.effect_id
       JOIN runner_session_policies session ON session.session_id = binding.session_id
       JOIN effect_request_payloads request ON request.effect_id = NEW.effect_id
       WHERE admission.effect_id = NEW.effect_id
         AND admission.sprint_id = NEW.sprint_id
         AND admission.task_id = NEW.task_id
         AND attempt.worker_id = NEW.worker_id
         AND attempt.worker_lease_id = NEW.worker_lease_id
         AND attempt.lease_epoch = NEW.worker_lease_epoch
         AND NEW.effect_kind = 'RunCommand'
         AND NEW.input_snapshot = admission.sealed_snapshot_id
         AND boundary.sealed_snapshot_id = admission.sealed_snapshot_id
         AND boundary.worker_session_id = admission.worker_session_id
         AND binding.sprint_id = NEW.sprint_id
         AND binding.launch_id = boundary.worker_launch_id
         AND binding.session_id = admission.worker_session_id
         AND session.worker_lease_id = attempt.worker_lease_id
         AND session.worker_lease_epoch = attempt.lease_epoch
         AND request.sprint_id = NEW.sprint_id
         AND request.request_digest = NEW.request_digest
         AND request.contract_version = NEW.contract_version
         AND CAST(request.request_bytes AS TEXT) = CAST(admission.command_spec_json AS TEXT)
     )
BEGIN
    SELECT RAISE(ABORT, 'formal-check effect must exactly match criterion command, attempt, session, and sealed snapshot');
END;

CREATE TRIGGER effect_intents_cover_integration_admission
AFTER INSERT ON effect_intents
WHEN EXISTS (
       SELECT 1 FROM task_attempt_integration_admissions admission
       WHERE admission.effect_id = NEW.effect_id
     )
 AND NOT EXISTS (
       SELECT 1
       FROM task_attempt_integration_admissions admission
       JOIN task_attempts attempt ON attempt.attempt_id = admission.attempt_id
       JOIN task_attempt_candidate_boundaries candidate
         ON candidate.boundary_id = admission.candidate_boundary_id
       JOIN effect_session_bindings binding ON binding.effect_id = NEW.effect_id
       JOIN effect_request_payloads request ON request.effect_id = NEW.effect_id
       WHERE admission.effect_id = NEW.effect_id
         AND admission.sprint_id = NEW.sprint_id
         AND admission.task_id = NEW.task_id
         AND admission.worker_id = NEW.worker_id
         AND admission.worker_lease_id = NEW.worker_lease_id
         AND admission.lease_epoch = NEW.worker_lease_epoch
         AND attempt.worker_lease_id = NEW.worker_lease_id
         AND attempt.lease_epoch = NEW.worker_lease_epoch
         AND candidate.attempt_id = attempt.attempt_id
         AND admission.input_snapshot_id = NEW.input_snapshot
         AND admission.result_snapshot_id = candidate.sealed_snapshot_id
         AND NEW.effect_kind = 'IntegrateChangeSet'
         AND binding.sprint_id = NEW.sprint_id
         AND binding.launch_id = admission.worker_launch_id
         AND binding.session_id = admission.worker_session_id
         AND request.sprint_id = NEW.sprint_id
         AND request.request_digest = NEW.request_digest
         AND request.contract_version = NEW.contract_version
         AND request.request_bytes = admission.request_json
         AND json_extract(CAST(request.request_bytes AS TEXT), '$.change_set.change_set_id') =
             candidate.change_set_id
         AND json_extract(CAST(request.request_bytes AS TEXT), '$.change_set.base_snapshot') =
             admission.input_snapshot_id
         AND json_extract(CAST(request.request_bytes AS TEXT), '$.change_set.result_snapshot') =
             candidate.sealed_snapshot_id
         AND json_extract(CAST(request.request_bytes AS TEXT), '$.artifact.change_set_id') =
             candidate.change_set_id
         AND json_extract(CAST(request.request_bytes AS TEXT), '$.artifact.base_snapshot') =
             admission.input_snapshot_id
         AND json_extract(CAST(request.request_bytes AS TEXT), '$.artifact.result_snapshot') =
             candidate.sealed_snapshot_id
     )
BEGIN
    SELECT RAISE(ABORT, 'integration effect must exactly match pre-admitted candidate, request, session, and lease');
END;

CREATE TRIGGER agent_events_unknown_pending_fence
BEFORE INSERT ON agent_events
WHEN EXISTS (
       SELECT 1
       FROM sprint_unknown_terminalization_pending pending
       LEFT JOIN sprint_unknown_terminalization_closures closure
              ON closure.marker_id = pending.marker_id
       WHERE pending.sprint_id = NEW.sprint_id AND closure.marker_id IS NULL
     )
 AND NOT EXISTS (
       SELECT 1 FROM sprint_unknown_pending_observation_admissions admission
       WHERE admission.terminal_event_id = NEW.event_id
         AND admission.sprint_id = NEW.sprint_id
     )
 AND NOT EXISTS (
       SELECT 1 FROM task_attempt_dispositions disposition
       WHERE disposition.transition_event_id = NEW.event_id
         AND disposition.sprint_id = NEW.sprint_id
     )
 AND NOT EXISTS (
       SELECT 1 FROM sprint_non_success_terminal_outcomes terminal
       WHERE terminal.terminal_event_id = NEW.event_id
         AND terminal.sprint_id = NEW.sprint_id
         AND terminal.terminal_state = 'Unknown'
     )
BEGIN SELECT RAISE(ABORT, 'pending sprint Unknown rejects unrelated state advance'); END;

CREATE TRIGGER sprint_unknown_pending_observation_admission_validate
BEFORE INSERT ON sprint_unknown_pending_observation_admissions
WHEN NOT EXISTS (
       SELECT 1
       FROM sprint_unknown_terminalization_pending pending
       LEFT JOIN sprint_unknown_terminalization_closures closure
              ON closure.marker_id = pending.marker_id
       JOIN effect_intents intent ON intent.effect_id = NEW.effect_id
       LEFT JOIN task_attempts attempt ON attempt.worker_lease_id = intent.worker_lease_id
       WHERE pending.sprint_id = NEW.sprint_id
         AND closure.marker_id IS NULL
         AND intent.sprint_id = NEW.sprint_id
         AND NOT EXISTS (
             SELECT 1 FROM effect_observations observation
             WHERE observation.effect_id = intent.effect_id
         )
         AND NOT EXISTS (
             SELECT 1 FROM agent_events event
             WHERE event.event_id = NEW.terminal_event_id
         )
         AND COALESCE(attempt.attempt_id, '') = COALESCE(NEW.attempt_id, '')
         AND COALESCE(intent.worker_lease_id, '') = COALESCE(NEW.worker_lease_id, '')
     )
BEGIN
    SELECT RAISE(ABORT, 'pending observation admission requires one exact unfinished pre-admitted effect');
END;

CREATE TRIGGER effect_observations_cover_unknown_pending_admission
AFTER INSERT ON effect_observations
WHEN EXISTS (
       SELECT 1 FROM sprint_unknown_pending_observation_admissions admission
       WHERE admission.observation_id = NEW.observation_id
     )
 AND NOT EXISTS (
       SELECT 1
       FROM sprint_unknown_pending_observation_admissions admission
       JOIN effect_intents intent ON intent.effect_id = admission.effect_id
       JOIN agent_events event ON event.event_id = admission.terminal_event_id
       WHERE admission.observation_id = NEW.observation_id
         AND admission.effect_id = NEW.effect_id
         AND admission.sprint_id = NEW.sprint_id
         AND admission.terminal_event_id = NEW.terminal_event_id
         AND admission.contract_version = NEW.contract_version
         AND admission.admitted_at_unix_ms <= NEW.observed_at_unix_ms
         AND intent.sprint_id = NEW.sprint_id
         AND COALESCE(intent.worker_lease_id, '') = COALESCE(NEW.worker_lease_id, '')
         AND COALESCE(admission.worker_lease_id, '') = COALESCE(NEW.worker_lease_id, '')
         AND event.sprint_id = NEW.sprint_id
         AND event.occurred_at_unix_ms = NEW.observed_at_unix_ms
     )
BEGIN
    SELECT RAISE(ABORT, 'pending observation must exactly close its admitted effect and terminal event');
END;

CREATE TRIGGER worker_lease_acquisitions_v15_budget_and_coverage
BEFORE INSERT ON worker_lease_acquisitions
WHEN EXISTS (
       SELECT 1 FROM agent_events event
       WHERE event.event_id = NEW.acquisition_event_id
     )
 OR NOT EXISTS (
       SELECT 1 FROM sprints sprint
       WHERE sprint.sprint_id = NEW.sprint_id
         AND json_valid(CAST(sprint.spec_json AS TEXT))
         AND json_type(CAST(sprint.spec_json AS TEXT),
                       '$.budget.max_attempts_per_task') = 'integer'
         AND json_extract(CAST(sprint.spec_json AS TEXT),
                          '$.budget.max_attempts_per_task') BETWEEN 1 AND 255
     )
 OR (SELECT COUNT(*) FROM worker_lease_acquisitions acquisition
     WHERE acquisition.sprint_id = NEW.sprint_id
       AND acquisition.task_id = NEW.task_id) >= COALESCE((
       SELECT json_extract(CAST(sprint.spec_json AS TEXT),
                           '$.budget.max_attempts_per_task')
       FROM sprints sprint WHERE sprint.sprint_id = NEW.sprint_id
     ), 0)
 OR EXISTS (
       SELECT 1 FROM sprint_unknown_terminalization_pending pending
       LEFT JOIN sprint_unknown_terminalization_closures closure
              ON closure.marker_id = pending.marker_id
       WHERE pending.sprint_id = NEW.sprint_id
         AND closure.marker_id IS NULL
     )
 OR EXISTS (
       SELECT 1 FROM task_attempt_legacy_classifications legacy
       WHERE legacy.sprint_id = NEW.sprint_id
     )
 OR CAST(NEW.path_scopes_json AS TEXT) != json(CAST(NEW.path_scopes_json AS TEXT))
 OR CAST(NEW.lease_json AS TEXT) != CAST(json_object(
       'contract_version', NEW.contract_version,
       'lease_id', NEW.lease_id,
       'sprint_id', NEW.sprint_id,
       'lease_epoch', NEW.lease_epoch,
       'task_id', NEW.task_id,
       'worker_id', NEW.worker_id,
       'path_scopes', json(CAST(NEW.path_scopes_json AS TEXT)),
       'acquired_at_unix_ms', NEW.acquired_at_unix_ms
     ) AS TEXT)
BEGIN
    SELECT RAISE(ABORT, 'v15 lease acquisition violates attempt budget or coverage');
END;

CREATE TRIGGER task_attempts_validate_current
BEFORE INSERT ON task_attempts
WHEN NEW.schema_generation != 15
 OR NOT EXISTS (
      SELECT 1 FROM worker_lease_acquisitions acquisition
      WHERE acquisition.lease_id = NEW.attempt_id
        AND acquisition.lease_id = NEW.worker_lease_id
        AND acquisition.sprint_id = NEW.sprint_id
        AND acquisition.task_id = NEW.task_id
        AND acquisition.worker_id = NEW.worker_id
        AND acquisition.lease_epoch = NEW.lease_epoch
        AND acquisition.acquisition_event_id = NEW.opening_event_id
        AND acquisition.acquired_at_unix_ms = NEW.opened_at_unix_ms
        AND acquisition.contract_version = NEW.contract_version
    )
 OR NEW.attempt_ordinal != COALESCE((
      SELECT MAX(existing.attempt_ordinal) + 1
      FROM task_attempts existing
      WHERE existing.sprint_id = NEW.sprint_id
        AND existing.task_id = NEW.task_id
    ), 1)
 OR json_valid(CAST(NEW.attempt_json AS TEXT)) = 0
 OR json_type(CAST(NEW.attempt_json AS TEXT), '$.contract_version') != 'integer'
 OR json_type(CAST(NEW.attempt_json AS TEXT), '$.attempt_id') != 'text'
 OR json_type(CAST(NEW.attempt_json AS TEXT), '$.worker_lease') != 'object'
 OR json_type(CAST(NEW.attempt_json AS TEXT), '$.attempt_ordinal') != 'integer'
 OR json_type(CAST(NEW.attempt_json AS TEXT), '$.opening_event_id') != 'text'
 OR json_type(CAST(NEW.attempt_json AS TEXT), '$.opened_at_unix_ms') != 'integer'
 OR json_extract(CAST(NEW.attempt_json AS TEXT), '$.contract_version') != NEW.contract_version
 OR json_extract(CAST(NEW.attempt_json AS TEXT), '$.attempt_id') != NEW.attempt_id
 OR json_extract(CAST(NEW.attempt_json AS TEXT), '$.worker_lease.lease_id') != NEW.worker_lease_id
 OR json_extract(CAST(NEW.attempt_json AS TEXT), '$.worker_lease.sprint_id') != NEW.sprint_id
 OR json_extract(CAST(NEW.attempt_json AS TEXT), '$.worker_lease.task_id') != NEW.task_id
 OR json_extract(CAST(NEW.attempt_json AS TEXT), '$.worker_lease.worker_id') != NEW.worker_id
 OR json_extract(CAST(NEW.attempt_json AS TEXT), '$.worker_lease.lease_epoch') != NEW.lease_epoch
 OR json_extract(CAST(NEW.attempt_json AS TEXT), '$.attempt_ordinal') != NEW.attempt_ordinal
 OR json_extract(CAST(NEW.attempt_json AS TEXT), '$.opening_event_id') != NEW.opening_event_id
 OR json_extract(CAST(NEW.attempt_json AS TEXT), '$.opened_at_unix_ms') != NEW.opened_at_unix_ms
 OR json(json_extract(CAST(NEW.attempt_json AS TEXT), '$.worker_lease')) IS NOT COALESCE((
      SELECT json(CAST(acquisition.lease_json AS TEXT))
      FROM worker_lease_acquisitions acquisition
      WHERE acquisition.lease_id = NEW.worker_lease_id
    ), '')
 OR CAST(NEW.attempt_json AS TEXT) != COALESCE((
      SELECT CAST(json_object(
          'contract_version', NEW.contract_version,
          'attempt_id', NEW.attempt_id,
          'worker_lease', json(CAST(acquisition.lease_json AS TEXT)),
          'attempt_ordinal', NEW.attempt_ordinal,
          'opening_event_id', NEW.opening_event_id,
          'opened_at_unix_ms', NEW.opened_at_unix_ms
      ) AS TEXT)
      FROM worker_lease_acquisitions acquisition
      WHERE acquisition.lease_id = NEW.worker_lease_id
    ), '')
BEGIN
    SELECT RAISE(ABORT, 'invalid or noncontiguous current task attempt');
END;

CREATE TRIGGER agent_events_require_task_attempt
AFTER INSERT ON agent_events
WHEN json_extract(CAST(NEW.event_json AS TEXT), '$.payload.TaskStateChanged.from') = 'Ready'
 AND json_extract(CAST(NEW.event_json AS TEXT), '$.payload.TaskStateChanged.to') = 'Leased'
 AND NOT EXISTS (
    SELECT 1
    FROM worker_lease_acquisitions acquisition
    JOIN task_attempts attempt ON attempt.worker_lease_id = acquisition.lease_id
    WHERE acquisition.acquisition_event_id = NEW.event_id
      AND attempt.opening_event_id = NEW.event_id
      AND attempt.attempt_id = acquisition.lease_id
      AND attempt.schema_generation = 15
      AND attempt.sprint_id = NEW.sprint_id
      AND attempt.task_id = json_extract(CAST(NEW.event_json AS TEXT), '$.task_id')
      AND attempt.worker_id = json_extract(CAST(NEW.event_json AS TEXT), '$.worker_id')
      AND attempt.opened_at_unix_ms = NEW.occurred_at_unix_ms
 )
BEGIN
    SELECT RAISE(ABORT, 'Ready-to-Leased event requires exact atomic v15 task attempt');
END;

-- Reverse coverage is deliberately scoped to every event referenced by a new
-- acquisition, not merely events that self-identify as Ready -> Leased. The
-- acquisition trigger requires this event ID to be fresh, so the event is the
-- final statement and can prove the complete three-way join before commit.
CREATE TRIGGER agent_events_cover_every_v15_acquisition
AFTER INSERT ON agent_events
WHEN EXISTS (
       SELECT 1 FROM worker_lease_acquisitions acquisition
       WHERE acquisition.acquisition_event_id = NEW.event_id
     )
 AND NOT EXISTS (
    SELECT 1
    FROM worker_lease_acquisitions acquisition
    JOIN task_attempts attempt ON attempt.worker_lease_id = acquisition.lease_id
    WHERE acquisition.acquisition_event_id = NEW.event_id
      AND attempt.opening_event_id = NEW.event_id
      AND attempt.attempt_id = acquisition.lease_id
      AND attempt.schema_generation = 15
      AND attempt.sprint_id = acquisition.sprint_id
      AND attempt.task_id = acquisition.task_id
      AND attempt.worker_id = acquisition.worker_id
      AND attempt.lease_epoch = acquisition.lease_epoch
      AND attempt.opened_at_unix_ms = acquisition.acquired_at_unix_ms
      AND NEW.sprint_id = acquisition.sprint_id
      AND NEW.occurred_at_unix_ms = acquisition.acquired_at_unix_ms
      AND json_type(CAST(NEW.event_json AS TEXT), '$.payload.TaskStateChanged') = 'object'
      AND json_extract(CAST(NEW.event_json AS TEXT), '$.payload.TaskStateChanged.from') = 'Ready'
      AND json_extract(CAST(NEW.event_json AS TEXT), '$.payload.TaskStateChanged.to') = 'Leased'
      AND json_extract(CAST(NEW.event_json AS TEXT), '$.task_id') = acquisition.task_id
      AND json_extract(CAST(NEW.event_json AS TEXT), '$.worker_id') = acquisition.worker_id
 )
BEGIN
    SELECT RAISE(ABORT, 'acquisition event must close exact v15 acquisition-attempt-event coverage');
END;

CREATE TRIGGER worker_lease_never_launched_release_validate
BEFORE INSERT ON worker_lease_never_launched_releases
WHEN NOT EXISTS (
       SELECT 1 FROM task_attempts attempt
       JOIN active_worker_leases active ON active.lease_id = attempt.worker_lease_id
       WHERE attempt.attempt_id = NEW.attempt_id
         AND attempt.schema_generation = 15
         AND attempt.worker_lease_id = NEW.worker_lease_id
         AND attempt.sprint_id = NEW.sprint_id
         AND attempt.task_id = NEW.task_id
         AND attempt.worker_id = NEW.worker_id
         AND attempt.lease_epoch = NEW.lease_epoch
     )
 OR EXISTS (
       SELECT 1 FROM runner_launch_intents launch
       WHERE launch.worker_lease_id = NEW.worker_lease_id
     )
 OR EXISTS (
       SELECT 1 FROM runner_session_policies session
       WHERE session.worker_lease_id = NEW.worker_lease_id
     )
 OR EXISTS (
       SELECT 1 FROM effect_intents effect
       WHERE effect.worker_lease_id = NEW.worker_lease_id
     )
 OR EXISTS (
       SELECT 1 FROM runner_launch_cleanup_admissions admission
       JOIN runner_launch_intents launch ON launch.launch_id = admission.launch_id
       WHERE launch.worker_lease_id = NEW.worker_lease_id
     )
 OR EXISTS (
       SELECT 1 FROM runner_launch_preparation_attempts preparation
       JOIN runner_launch_intents launch ON launch.launch_id = preparation.launch_id
       WHERE launch.worker_lease_id = NEW.worker_lease_id
     )
 OR json_valid(CAST(NEW.release_json AS TEXT)) = 0
 OR json_extract(CAST(NEW.release_json AS TEXT), '$.contract_version') != NEW.contract_version
 OR json_extract(CAST(NEW.release_json AS TEXT), '$.release_id') != NEW.release_id
 OR json_extract(CAST(NEW.release_json AS TEXT), '$.attempt.attempt_id') != NEW.attempt_id
 OR json_extract(CAST(NEW.release_json AS TEXT), '$.attempt.worker_lease.lease_id') != NEW.worker_lease_id
 OR json_extract(CAST(NEW.release_json AS TEXT), '$.absence_evidence.evidence_id') != NEW.absence_evidence_id
 OR json_extract(CAST(NEW.release_json AS TEXT), '$.absence_evidence.kind') != 'NeverLaunched'
 OR json_extract(CAST(NEW.release_json AS TEXT), '$.absence_evidence.digest') != NEW.absence_evidence_digest
 OR NEW.absence_evidence_digest != grok_sha256(NEW.absence_evidence_bytes)
 OR json_extract(CAST(NEW.release_json AS TEXT), '$.released_at_unix_ms') != NEW.released_at_unix_ms
 OR lower(COALESCE((
       SELECT group_concat(printf('%02x', CAST(value AS INTEGER)), '')
       FROM json_each(CAST(NEW.release_json AS TEXT),
                      '$.absence_evidence.canonical_bytes')
     ), '')) != lower(hex(NEW.absence_evidence_bytes))
 OR CAST(NEW.release_json AS TEXT) != COALESCE((
       SELECT CAST(json_object(
           'contract_version', NEW.contract_version,
           'release_id', NEW.release_id,
           'attempt', json(CAST(attempt.attempt_json AS TEXT)),
           'absence_evidence', json_object(
               'evidence_id', NEW.absence_evidence_id,
               'kind', 'NeverLaunched',
               'canonical_bytes', json_extract(CAST(NEW.release_json AS TEXT),
                                                '$.absence_evidence.canonical_bytes'),
               'digest', NEW.absence_evidence_digest
           ),
           'released_at_unix_ms', NEW.released_at_unix_ms
       ) AS TEXT)
       FROM task_attempts attempt WHERE attempt.attempt_id = NEW.attempt_id
     ), '')
BEGIN
    SELECT RAISE(ABORT, 'never-launched release requires an exact authority-free active attempt');
END;

CREATE TRIGGER task_attempt_dispositions_validate_identity_and_budget
BEFORE INSERT ON task_attempt_dispositions
WHEN EXISTS (
       SELECT 1 FROM agent_events event
       WHERE event.event_id = NEW.transition_event_id
     )
 OR NOT EXISTS (
       SELECT 1 FROM task_attempts attempt
       WHERE attempt.attempt_id = NEW.attempt_id
         AND attempt.sprint_id = NEW.sprint_id
         AND attempt.task_id = NEW.task_id
         AND attempt.worker_id = NEW.worker_id
         AND attempt.worker_lease_id = NEW.worker_lease_id
         AND attempt.lease_epoch = NEW.lease_epoch
         AND attempt.attempt_ordinal = NEW.attempt_ordinal
         AND attempt.schema_generation = 15
     )
 OR (
       NEW.disposition_kind = 'Retryable'
       AND NEW.attempt_ordinal >= COALESCE((
          SELECT json_extract(CAST(sprint.spec_json AS TEXT),
                              '$.budget.max_attempts_per_task')
          FROM sprints sprint WHERE sprint.sprint_id = NEW.sprint_id
       ), 0)
     )
 OR (
       NEW.disposition_kind = 'AttemptsExhausted'
       AND NEW.attempt_ordinal != COALESCE((
          SELECT json_extract(CAST(sprint.spec_json AS TEXT),
                              '$.budget.max_attempts_per_task')
          FROM sprints sprint WHERE sprint.sprint_id = NEW.sprint_id
       ), 0)
     )
 OR (
       NEW.cause_kind IN (
          'NeverLaunched', 'LaunchRefusedBeforeNativeEffect', 'KnownWorkerExit',
          'FormalVerificationFailed', 'CandidateRejectedKnown'
       ) AND NEW.disposition_kind NOT IN ('Retryable', 'AttemptsExhausted')
     )
 OR (
       NEW.cause_kind IN ('PermanentContractViolation', 'CriterionProvenUnsatisfiable')
       AND NEW.disposition_kind != 'PermanentFailure'
     )
 OR (
       NEW.cause_kind IN ('AuthorityExpansionRequired', 'VerifiedDependencyUnavailable')
       AND NEW.disposition_kind != 'Blocked'
     )
 OR (NEW.cause_kind = 'OperatorCanceled' AND NEW.disposition_kind != 'Canceled')
 OR NEW.evidence_digest != grok_sha256(NEW.evidence_bytes)
BEGIN
    SELECT RAISE(ABORT, 'invalid task-attempt disposition identity, cause, or budget result');
END;

CREATE TRIGGER task_attempt_dispositions_validate_canonical_envelope
BEFORE INSERT ON task_attempt_dispositions
WHEN json_valid(CAST(NEW.disposition_json AS TEXT)) = 0
 OR json_type(CAST(NEW.disposition_json AS TEXT), '$') != 'object'
 OR (SELECT COUNT(*) FROM json_each(CAST(NEW.disposition_json AS TEXT))) != 1
 OR (SELECT key FROM json_each(CAST(NEW.disposition_json AS TEXT)) LIMIT 1) != NEW.disposition_kind
 OR COALESCE(
       json_extract(CAST(NEW.disposition_json AS TEXT), '$.Integrated.metadata.disposition_id'),
       json_extract(CAST(NEW.disposition_json AS TEXT), '$.Retryable.metadata.disposition_id'),
       json_extract(CAST(NEW.disposition_json AS TEXT), '$.AttemptsExhausted.metadata.disposition_id'),
       json_extract(CAST(NEW.disposition_json AS TEXT), '$.PermanentFailure.metadata.disposition_id'),
       json_extract(CAST(NEW.disposition_json AS TEXT), '$.Blocked.metadata.disposition_id'),
       json_extract(CAST(NEW.disposition_json AS TEXT), '$.Canceled.metadata.disposition_id'),
       json_extract(CAST(NEW.disposition_json AS TEXT), '$.UnknownCleaned.metadata.disposition_id'),
       json_extract(CAST(NEW.disposition_json AS TEXT), '$.UnknownQuarantined.metadata.disposition_id')
    ) != NEW.disposition_id
 OR COALESCE(
       json_extract(CAST(NEW.disposition_json AS TEXT), '$.Integrated.metadata.attempt.attempt_id'),
       json_extract(CAST(NEW.disposition_json AS TEXT), '$.Retryable.metadata.attempt.attempt_id'),
       json_extract(CAST(NEW.disposition_json AS TEXT), '$.AttemptsExhausted.metadata.attempt.attempt_id'),
       json_extract(CAST(NEW.disposition_json AS TEXT), '$.PermanentFailure.metadata.attempt.attempt_id'),
       json_extract(CAST(NEW.disposition_json AS TEXT), '$.Blocked.metadata.attempt.attempt_id'),
       json_extract(CAST(NEW.disposition_json AS TEXT), '$.Canceled.metadata.attempt.attempt_id'),
       json_extract(CAST(NEW.disposition_json AS TEXT), '$.UnknownCleaned.metadata.attempt.attempt_id'),
       json_extract(CAST(NEW.disposition_json AS TEXT), '$.UnknownQuarantined.metadata.attempt.attempt_id')
    ) != NEW.attempt_id
 OR COALESCE(
       json_extract(CAST(NEW.disposition_json AS TEXT), '$.Integrated.metadata.from_state'),
       json_extract(CAST(NEW.disposition_json AS TEXT), '$.Retryable.metadata.from_state'),
       json_extract(CAST(NEW.disposition_json AS TEXT), '$.AttemptsExhausted.metadata.from_state'),
       json_extract(CAST(NEW.disposition_json AS TEXT), '$.PermanentFailure.metadata.from_state'),
       json_extract(CAST(NEW.disposition_json AS TEXT), '$.Blocked.metadata.from_state'),
       json_extract(CAST(NEW.disposition_json AS TEXT), '$.Canceled.metadata.from_state'),
       json_extract(CAST(NEW.disposition_json AS TEXT), '$.UnknownCleaned.metadata.from_state'),
       json_extract(CAST(NEW.disposition_json AS TEXT), '$.UnknownQuarantined.metadata.from_state')
    ) != NEW.from_state
 OR COALESCE(
       json_extract(CAST(NEW.disposition_json AS TEXT), '$.Integrated.metadata.state_transition_event_id'),
       json_extract(CAST(NEW.disposition_json AS TEXT), '$.Retryable.metadata.state_transition_event_id'),
       json_extract(CAST(NEW.disposition_json AS TEXT), '$.AttemptsExhausted.metadata.state_transition_event_id'),
       json_extract(CAST(NEW.disposition_json AS TEXT), '$.PermanentFailure.metadata.state_transition_event_id'),
       json_extract(CAST(NEW.disposition_json AS TEXT), '$.Blocked.metadata.state_transition_event_id'),
       json_extract(CAST(NEW.disposition_json AS TEXT), '$.Canceled.metadata.state_transition_event_id'),
       json_extract(CAST(NEW.disposition_json AS TEXT), '$.UnknownCleaned.metadata.state_transition_event_id'),
       json_extract(CAST(NEW.disposition_json AS TEXT), '$.UnknownQuarantined.metadata.state_transition_event_id')
    ) != NEW.transition_event_id
 OR COALESCE(
       json_extract(CAST(NEW.disposition_json AS TEXT), '$.Integrated.metadata.disposed_at_unix_ms'),
       json_extract(CAST(NEW.disposition_json AS TEXT), '$.Retryable.metadata.disposed_at_unix_ms'),
       json_extract(CAST(NEW.disposition_json AS TEXT), '$.AttemptsExhausted.metadata.disposed_at_unix_ms'),
       json_extract(CAST(NEW.disposition_json AS TEXT), '$.PermanentFailure.metadata.disposed_at_unix_ms'),
       json_extract(CAST(NEW.disposition_json AS TEXT), '$.Blocked.metadata.disposed_at_unix_ms'),
       json_extract(CAST(NEW.disposition_json AS TEXT), '$.Canceled.metadata.disposed_at_unix_ms'),
       json_extract(CAST(NEW.disposition_json AS TEXT), '$.UnknownCleaned.metadata.disposed_at_unix_ms'),
       json_extract(CAST(NEW.disposition_json AS TEXT), '$.UnknownQuarantined.metadata.disposed_at_unix_ms')
    ) != NEW.disposed_at_unix_ms
 OR CAST(NEW.disposition_json AS TEXT) != COALESCE((
       SELECT CASE NEW.disposition_kind
         WHEN 'Integrated' THEN CAST(json_object('Integrated', json_object(
           'metadata', json_object(
             'contract_version', NEW.contract_version,
             'disposition_id', NEW.disposition_id,
             'attempt', json(CAST(attempt.attempt_json AS TEXT)),
             'from_state', NEW.from_state,
             'state_transition_event_id', NEW.transition_event_id,
             'disposed_at_unix_ms', NEW.disposed_at_unix_ms),
           'candidate_boundary', json_extract(CAST(NEW.disposition_json AS TEXT), '$.Integrated.candidate_boundary'),
           'integration_receipt', json_extract(CAST(NEW.disposition_json AS TEXT), '$.Integrated.integration_receipt'),
           'evidence', json_extract(CAST(NEW.disposition_json AS TEXT), '$.Integrated.evidence')
         )) AS TEXT)
         WHEN 'Retryable' THEN CAST(json_object('Retryable', json_object(
           'metadata', json_object(
             'contract_version', NEW.contract_version, 'disposition_id', NEW.disposition_id,
             'attempt', json(CAST(attempt.attempt_json AS TEXT)), 'from_state', NEW.from_state,
             'state_transition_event_id', NEW.transition_event_id,
             'disposed_at_unix_ms', NEW.disposed_at_unix_ms),
           'cause', json_extract(CAST(NEW.disposition_json AS TEXT), '$.Retryable.cause'),
           'release_proof', json_extract(CAST(NEW.disposition_json AS TEXT), '$.Retryable.release_proof')
         )) AS TEXT)
         WHEN 'AttemptsExhausted' THEN CAST(json_object('AttemptsExhausted', json_object(
           'metadata', json_object(
             'contract_version', NEW.contract_version, 'disposition_id', NEW.disposition_id,
             'attempt', json(CAST(attempt.attempt_json AS TEXT)), 'from_state', NEW.from_state,
             'state_transition_event_id', NEW.transition_event_id,
             'disposed_at_unix_ms', NEW.disposed_at_unix_ms),
           'cause', json_extract(CAST(NEW.disposition_json AS TEXT), '$.AttemptsExhausted.cause'),
           'release_proof', json_extract(CAST(NEW.disposition_json AS TEXT), '$.AttemptsExhausted.release_proof')
         )) AS TEXT)
         WHEN 'PermanentFailure' THEN CAST(json_object('PermanentFailure', json_object(
           'metadata', json_object(
             'contract_version', NEW.contract_version, 'disposition_id', NEW.disposition_id,
             'attempt', json(CAST(attempt.attempt_json AS TEXT)), 'from_state', NEW.from_state,
             'state_transition_event_id', NEW.transition_event_id,
             'disposed_at_unix_ms', NEW.disposed_at_unix_ms),
           'cause', json_extract(CAST(NEW.disposition_json AS TEXT), '$.PermanentFailure.cause'),
           'release_proof', json_extract(CAST(NEW.disposition_json AS TEXT), '$.PermanentFailure.release_proof')
         )) AS TEXT)
         WHEN 'Blocked' THEN CAST(json_object('Blocked', json_object(
           'metadata', json_object(
             'contract_version', NEW.contract_version, 'disposition_id', NEW.disposition_id,
             'attempt', json(CAST(attempt.attempt_json AS TEXT)), 'from_state', NEW.from_state,
             'state_transition_event_id', NEW.transition_event_id,
             'disposed_at_unix_ms', NEW.disposed_at_unix_ms),
           'cause', json_extract(CAST(NEW.disposition_json AS TEXT), '$.Blocked.cause'),
           'release_proof', json_extract(CAST(NEW.disposition_json AS TEXT), '$.Blocked.release_proof')
         )) AS TEXT)
         WHEN 'Canceled' THEN CAST(json_object('Canceled', json_object(
           'metadata', json_object(
             'contract_version', NEW.contract_version, 'disposition_id', NEW.disposition_id,
             'attempt', json(CAST(attempt.attempt_json AS TEXT)), 'from_state', NEW.from_state,
             'state_transition_event_id', NEW.transition_event_id,
             'disposed_at_unix_ms', NEW.disposed_at_unix_ms),
           'cause', json_extract(CAST(NEW.disposition_json AS TEXT), '$.Canceled.cause'),
           'release_proof', json_extract(CAST(NEW.disposition_json AS TEXT), '$.Canceled.release_proof')
         )) AS TEXT)
         WHEN 'UnknownCleaned' THEN CAST(json_object('UnknownCleaned', json_object(
           'metadata', json_object(
             'contract_version', NEW.contract_version, 'disposition_id', NEW.disposition_id,
             'attempt', json(CAST(attempt.attempt_json AS TEXT)), 'from_state', NEW.from_state,
             'state_transition_event_id', NEW.transition_event_id,
             'disposed_at_unix_ms', NEW.disposed_at_unix_ms),
           'unknown_evidence', json_extract(CAST(NEW.disposition_json AS TEXT), '$.UnknownCleaned.unknown_evidence'),
           'cleanup_release', json_extract(CAST(NEW.disposition_json AS TEXT), '$.UnknownCleaned.cleanup_release')
         )) AS TEXT)
         WHEN 'UnknownQuarantined' THEN CAST(json_object('UnknownQuarantined', json_object(
           'metadata', json_object(
             'contract_version', NEW.contract_version, 'disposition_id', NEW.disposition_id,
             'attempt', json(CAST(attempt.attempt_json AS TEXT)), 'from_state', NEW.from_state,
             'state_transition_event_id', NEW.transition_event_id,
             'disposed_at_unix_ms', NEW.disposed_at_unix_ms),
           'uncertain_evidence', json_extract(CAST(NEW.disposition_json AS TEXT), '$.UnknownQuarantined.uncertain_evidence')
         )) AS TEXT)
       END
       FROM task_attempts attempt WHERE attempt.attempt_id = NEW.attempt_id
    ), '')
BEGIN
    SELECT RAISE(ABORT, 'task-attempt disposition JSON must be exact canonical variant bytes');
END;

CREATE TRIGGER task_attempt_dispositions_validate_typed_index
BEFORE INSERT ON task_attempt_dispositions
WHEN NOT EXISTS (
    SELECT 1
    FROM (
        SELECT grok_task_attempt_disposition_index(
            NEW.disposition_json,
            (SELECT json_extract(
                CAST(sprint.spec_json AS TEXT), '$.budget.max_attempts_per_task'
             ) FROM sprints sprint WHERE sprint.sprint_id = NEW.sprint_id)
        ) AS projection
    ) typed
    WHERE json_extract(typed.projection, '$.contract_version') IS NEW.contract_version
      AND json_extract(typed.projection, '$.disposition_id') IS NEW.disposition_id
      AND json_extract(typed.projection, '$.attempt_id') IS NEW.attempt_id
      AND json_extract(typed.projection, '$.sprint_id') IS NEW.sprint_id
      AND json_extract(typed.projection, '$.task_id') IS NEW.task_id
      AND json_extract(typed.projection, '$.worker_id') IS NEW.worker_id
      AND json_extract(typed.projection, '$.worker_lease_id') IS NEW.worker_lease_id
      AND json_extract(typed.projection, '$.lease_epoch') IS NEW.lease_epoch
      AND json_extract(typed.projection, '$.attempt_ordinal') IS NEW.attempt_ordinal
      AND json_extract(typed.projection, '$.from_state') IS NEW.from_state
      AND json_extract(typed.projection, '$.transition_event_id') IS NEW.transition_event_id
      AND json_extract(typed.projection, '$.disposed_at_unix_ms') IS NEW.disposed_at_unix_ms
      AND json_extract(typed.projection, '$.disposition_kind') IS NEW.disposition_kind
      AND json_extract(typed.projection, '$.cause_kind') IS NEW.cause_kind
      AND json_extract(typed.projection, '$.cause_launch_id') IS NEW.cause_launch_id
      AND json_extract(typed.projection, '$.cause_session_id') IS NEW.cause_session_id
      AND json_extract(typed.projection, '$.cause_formal_check_id') IS NEW.cause_formal_check_id
      AND json_extract(typed.projection, '$.cause_candidate_boundary_id') IS NEW.cause_candidate_boundary_id
      AND json_extract(typed.projection, '$.cause_effect_id') IS NEW.cause_effect_id
      AND json_extract(typed.projection, '$.cause_observation_id') IS NEW.cause_observation_id
      AND json_extract(typed.projection, '$.cause_authority_id') IS NEW.cause_authority_id
      AND json_extract(typed.projection, '$.cause_subject_id') IS (
          SELECT authority.subject_id
          FROM task_attempt_policy_cause_authorities authority
          WHERE authority.authority_id = NEW.cause_authority_id
      )
      AND json_extract(typed.projection, '$.uncertainty_id') IS NEW.uncertainty_id
      AND json_array_length(typed.projection, '$.uncertain_authority_ids')
          IS NEW.uncertain_authority_count
      AND json_extract(typed.projection, '$.candidate_boundary_id') IS NEW.candidate_boundary_id
      AND json_extract(typed.projection, '$.candidate_boundary_digest') IS CASE
          WHEN NEW.candidate_boundary_id IS NULL THEN NULL
          ELSE grok_sha256((
              SELECT candidate.boundary_json
              FROM task_attempt_candidate_boundaries candidate
              WHERE candidate.boundary_id = NEW.candidate_boundary_id
          )) END
      AND json_extract(typed.projection, '$.integration_receipt_id') IS NEW.integration_receipt_id
      AND json_extract(typed.projection, '$.integration_receipt_digest') IS CASE
          WHEN NEW.integration_receipt_id IS NULL THEN NULL
          ELSE grok_sha256((
              SELECT integration.receipt_json
              FROM task_integration_receipts integration
              WHERE integration.receipt_id = NEW.integration_receipt_id
                AND integration.sprint_id = NEW.sprint_id
          )) END
      AND json_extract(typed.projection, '$.cleanup_receipt_id') IS NEW.cleanup_receipt_id
      AND json_extract(typed.projection, '$.cleanup_receipt_digest') IS CASE
          WHEN NEW.cleanup_receipt_id IS NULL THEN NULL
          ELSE grok_sha256((
              SELECT cleanup.receipt_json
              FROM worker_cleanup_receipts cleanup
              WHERE cleanup.receipt_id = NEW.cleanup_receipt_id
                AND cleanup.sprint_id = NEW.sprint_id
          )) END
      AND json_extract(typed.projection, '$.never_launched_release_id')
          IS NEW.never_launched_release_id
      AND json_extract(typed.projection, '$.never_launched_release_digest') IS CASE
          WHEN NEW.never_launched_release_id IS NULL THEN NULL
          ELSE grok_sha256((
              SELECT release.release_json
              FROM worker_lease_never_launched_releases release
              WHERE release.release_id = NEW.never_launched_release_id
                AND release.attempt_id = NEW.attempt_id
          )) END
      AND json_extract(typed.projection, '$.release_id') IS NEW.release_id
      AND json_extract(typed.projection, '$.evidence_id') IS NEW.evidence_id
      AND json_extract(typed.projection, '$.evidence_kind') IS NEW.evidence_kind
      AND json_extract(typed.projection, '$.evidence_digest') IS NEW.evidence_digest
)
BEGIN
    SELECT RAISE(ABORT, 'task-attempt disposition typed bytes must exactly match every indexed and nested authority');
END;

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
               AND change_set.base_snapshot != change_set.result_snapshot
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

CREATE TRIGGER task_attempt_running_boundary_validate
BEFORE INSERT ON task_attempt_running_boundaries
WHEN EXISTS (
       SELECT 1 FROM agent_events event
       WHERE event.event_id = NEW.transition_event_id
     )
 OR NOT EXISTS (
       SELECT 1
       FROM task_attempts attempt
       JOIN active_worker_leases active ON active.lease_id = attempt.worker_lease_id
       JOIN runner_launch_intents launch ON launch.launch_id = NEW.runner_launch_id
       JOIN runner_launch_cleanup_admissions cleanup ON cleanup.launch_id = launch.launch_id
       JOIN runner_session_policies session ON session.session_id = NEW.runner_session_id
       WHERE attempt.attempt_id = NEW.attempt_id
         AND attempt.schema_generation = 15
         AND attempt.sprint_id = NEW.sprint_id
         AND attempt.task_id = NEW.task_id
         AND attempt.worker_id = NEW.worker_id
         AND attempt.worker_lease_id = NEW.worker_lease_id
         AND attempt.lease_epoch = NEW.lease_epoch
         AND launch.sprint_id = NEW.sprint_id
         AND launch.worker_id = NEW.worker_id
         AND launch.worker_lease_id = NEW.worker_lease_id
         AND launch.worker_lease_epoch = NEW.lease_epoch
         AND cleanup.sprint_id = NEW.sprint_id
         AND cleanup.session_id = session.session_id
         AND session.sprint_id = NEW.sprint_id
         AND session.launch_id = launch.launch_id
         AND session.worker_id = NEW.worker_id
         AND session.worker_lease_id = NEW.worker_lease_id
         AND session.worker_lease_epoch = NEW.lease_epoch
         AND NEW.contract_version = attempt.contract_version
         AND NEW.started_at_unix_ms >= session.registered_at_unix_ms
         AND NEW.boundary_json = CAST(json_object(
             'contract_version', NEW.contract_version,
             'boundary_id', NEW.boundary_id,
             'attempt', json(CAST(attempt.attempt_json AS TEXT)),
             'runner_launch_id', NEW.runner_launch_id,
             'runner_session_id', NEW.runner_session_id,
             'transition_event_id', NEW.transition_event_id,
             'started_at_unix_ms', NEW.started_at_unix_ms
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
     ), '') != 'Leased'
 OR EXISTS (
       SELECT 1 FROM task_attempt_dispositions disposition
       WHERE disposition.attempt_id = NEW.attempt_id
     )
BEGIN
    SELECT RAISE(ABORT, 'Running boundary requires exact active attempt launch, cleanup admission, and initialized session');
END;

CREATE TRIGGER task_attempt_candidate_boundary_validate
BEFORE INSERT ON task_attempt_candidate_boundaries
WHEN EXISTS (
       SELECT 1 FROM agent_events event
       WHERE event.event_id = NEW.transition_event_id
     )
 OR NOT EXISTS (
       SELECT 1
       FROM task_attempts attempt
       JOIN active_worker_leases active ON active.lease_id = attempt.worker_lease_id
       JOIN task_attempt_verification_boundaries verification
         ON verification.attempt_id = attempt.attempt_id
       WHERE attempt.attempt_id = NEW.attempt_id
         AND attempt.schema_generation = 15
         AND attempt.sprint_id = NEW.sprint_id
         AND attempt.task_id = NEW.task_id
         AND attempt.worker_lease_id = NEW.worker_lease_id
         AND attempt.lease_epoch = NEW.lease_epoch
         AND verification.boundary_id = NEW.verification_boundary_id
         AND verification.change_set_id = NEW.change_set_id
         AND verification.sealed_snapshot_id = NEW.sealed_snapshot_id
         AND NEW.contract_version = attempt.contract_version
         AND NEW.admitted_at_unix_ms >= verification.sealed_at_unix_ms
         AND NEW.formal_check_count = json_array_length(
             CAST(NEW.boundary_json AS TEXT), '$.formal_check_ids')
         AND NEW.formal_check_count = json_array_length(
             CAST(NEW.boundary_json AS TEXT), '$.verification_receipt_ids')
         AND NEW.boundary_json = CAST(json_object(
             'contract_version', NEW.contract_version,
             'boundary_id', NEW.boundary_id,
             'attempt', json(CAST(attempt.attempt_json AS TEXT)),
             'verification_boundary_id', NEW.verification_boundary_id,
             'change_set_id', NEW.change_set_id,
             'sealed_snapshot', NEW.sealed_snapshot_id,
             'formal_check_ids', json(json_extract(
                 CAST(NEW.boundary_json AS TEXT), '$.formal_check_ids')),
             'verification_receipt_ids', json(json_extract(
                 CAST(NEW.boundary_json AS TEXT), '$.verification_receipt_ids')),
             'transition_event_id', NEW.transition_event_id,
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
       SELECT 1 FROM task_attempt_formal_checks formal
       WHERE formal.attempt_id = NEW.attempt_id AND formal.passed = 0
     )
 OR EXISTS (
       SELECT 1
       FROM task_attempt_formal_check_admissions admission
       LEFT JOIN task_attempt_formal_checks formal
              ON formal.admission_id = admission.admission_id
       WHERE admission.attempt_id = NEW.attempt_id
         AND formal.formal_check_id IS NULL
     )
BEGIN
    SELECT RAISE(ABORT, 'candidate boundary requires exact active Verifying attempt and terminal passing checks');
END;

CREATE TRIGGER task_attempt_worker_exit_authority_validate
BEFORE INSERT ON task_attempt_worker_exit_authorities
WHEN NOT EXISTS (
       SELECT 1
       FROM task_attempt_open_cleanup_source_admissions admission
       JOIN task_attempts attempt ON attempt.attempt_id = admission.attempt_id
       JOIN runner_session_policies session ON session.session_id = NEW.session_id
       WHERE attempt.attempt_id = NEW.attempt_id
         AND admission.sprint_id = NEW.sprint_id
         AND admission.worker_lease_id = NEW.worker_lease_id
         AND admission.lease_epoch = NEW.lease_epoch
         AND admission.launch_id = NEW.launch_id
         AND admission.session_id = NEW.session_id
         AND session.sprint_id = NEW.sprint_id
         AND session.launch_id = NEW.launch_id
         AND session.worker_lease_id = NEW.worker_lease_id
         AND session.worker_lease_epoch = NEW.lease_epoch
         AND NEW.observed_at_unix_ms >= attempt.opened_at_unix_ms
     )
 OR json_extract(CAST(NEW.authority_json AS TEXT), '$.authority_id') != NEW.authority_id
 OR json_extract(CAST(NEW.authority_json AS TEXT), '$.attempt_id') != NEW.attempt_id
 OR json_extract(CAST(NEW.authority_json AS TEXT), '$.launch_id') != NEW.launch_id
 OR json_extract(CAST(NEW.authority_json AS TEXT), '$.session_id') != NEW.session_id
 OR json_extract(CAST(NEW.authority_json AS TEXT), '$.evidence_id') != NEW.evidence_id
 OR json_extract(CAST(NEW.authority_json AS TEXT), '$.evidence_digest') != NEW.evidence_digest
 OR NEW.evidence_digest != grok_sha256(NEW.evidence_bytes)
 OR json_extract(CAST(NEW.authority_json AS TEXT), '$.observed_at_unix_ms') != NEW.observed_at_unix_ms
 OR CAST(NEW.authority_json AS TEXT) != CAST(json_object(
       'authority_id', NEW.authority_id,
       'attempt_id', NEW.attempt_id,
       'launch_id', NEW.launch_id,
       'session_id', NEW.session_id,
       'evidence_id', NEW.evidence_id,
       'evidence_digest', NEW.evidence_digest,
       'observed_at_unix_ms', NEW.observed_at_unix_ms
    ) AS TEXT)
BEGIN
    SELECT RAISE(ABORT, 'worker-exit authority must exactly bind attempt, launch, session, and evidence');
END;

CREATE TRIGGER task_attempt_candidate_rejection_authority_validate
BEFORE INSERT ON task_attempt_candidate_rejection_authorities
WHEN NOT EXISTS (
       SELECT 1
       FROM task_attempt_open_cleanup_source_admissions admission
       JOIN task_attempts attempt ON attempt.attempt_id = admission.attempt_id
       JOIN task_attempt_candidate_boundaries candidate
         ON candidate.boundary_id = NEW.candidate_boundary_id
       WHERE attempt.attempt_id = NEW.attempt_id
         AND admission.sprint_id = NEW.sprint_id
         AND candidate.attempt_id = NEW.attempt_id
         AND candidate.sprint_id = NEW.sprint_id
         AND NEW.rejected_at_unix_ms >= candidate.admitted_at_unix_ms
     )
 OR json_extract(CAST(NEW.authority_json AS TEXT), '$.authority_id') != NEW.authority_id
 OR json_extract(CAST(NEW.authority_json AS TEXT), '$.attempt_id') != NEW.attempt_id
 OR json_extract(CAST(NEW.authority_json AS TEXT), '$.candidate_boundary_id') != NEW.candidate_boundary_id
 OR json_extract(CAST(NEW.authority_json AS TEXT), '$.evidence_id') != NEW.evidence_id
 OR json_extract(CAST(NEW.authority_json AS TEXT), '$.evidence_digest') != NEW.evidence_digest
 OR NEW.evidence_digest != grok_sha256(NEW.evidence_bytes)
 OR json_extract(CAST(NEW.authority_json AS TEXT), '$.rejected_at_unix_ms') != NEW.rejected_at_unix_ms
 OR CAST(NEW.authority_json AS TEXT) != CAST(json_object(
       'authority_id', NEW.authority_id,
       'attempt_id', NEW.attempt_id,
       'candidate_boundary_id', NEW.candidate_boundary_id,
       'evidence_id', NEW.evidence_id,
       'evidence_digest', NEW.evidence_digest,
       'rejected_at_unix_ms', NEW.rejected_at_unix_ms
    ) AS TEXT)
BEGIN
    SELECT RAISE(ABORT, 'candidate rejection authority must exactly bind its attempt and candidate');
END;

CREATE TRIGGER task_attempt_policy_cause_authority_validate
BEFORE INSERT ON task_attempt_policy_cause_authorities
WHEN NOT EXISTS (
       SELECT 1 FROM task_attempts attempt
       WHERE attempt.attempt_id = NEW.attempt_id
         AND attempt.schema_generation = 15
         AND attempt.sprint_id = NEW.sprint_id
         AND attempt.task_id = NEW.task_id
         AND NEW.decided_at_unix_ms >= attempt.opened_at_unix_ms
     )
 OR NOT EXISTS (
      SELECT 1
      FROM task_attempt_open_cleanup_source_admissions admission
      WHERE admission.attempt_id = NEW.attempt_id
        AND admission.sprint_id = NEW.sprint_id
        AND admission.task_id = NEW.task_id
    )
 OR (
       NEW.cause_kind = 'CriterionProvenUnsatisfiable'
       AND NOT EXISTS (
          SELECT 1
          FROM sprints sprint
          JOIN sprint_task_graphs graph ON graph.sprint_id = sprint.sprint_id,
               json_each(CAST(graph.graph_json AS TEXT), '$.tasks') graph_task,
               json_each(graph_task.value, '$.acceptance_checks') task_check
          WHERE sprint.sprint_id = NEW.sprint_id
            AND json_extract(graph_task.value, '$.task_id') = NEW.task_id
            AND task_check.value = NEW.subject_id
       )
     )
 OR (
       NEW.cause_kind = 'VerifiedDependencyUnavailable'
       AND NOT EXISTS (
          SELECT 1
          FROM sprint_task_graphs graph,
               json_each(CAST(graph.graph_json AS TEXT), '$.tasks') graph_task,
               json_each(graph_task.value, '$.dependencies') dependency
          WHERE graph.sprint_id = NEW.sprint_id
            AND json_extract(graph_task.value, '$.task_id') = NEW.task_id
            AND dependency.value = NEW.subject_id
       )
     )
 OR json_extract(CAST(NEW.authority_json AS TEXT), '$.authority_id') != NEW.authority_id
 OR json_extract(CAST(NEW.authority_json AS TEXT), '$.attempt_id') != NEW.attempt_id
 OR json_extract(CAST(NEW.authority_json AS TEXT), '$.cause_kind') != NEW.cause_kind
 OR json_extract(CAST(NEW.authority_json AS TEXT), '$.subject_id') != NEW.subject_id
 OR json_extract(CAST(NEW.authority_json AS TEXT), '$.evidence_id') != NEW.evidence_id
 OR json_extract(CAST(NEW.authority_json AS TEXT), '$.evidence_digest') != NEW.evidence_digest
 OR NEW.evidence_digest != grok_sha256(NEW.evidence_bytes)
 OR json_extract(CAST(NEW.authority_json AS TEXT), '$.decided_at_unix_ms') != NEW.decided_at_unix_ms
 OR CAST(NEW.authority_json AS TEXT) != CAST(json_object(
       'authority_id', NEW.authority_id,
       'attempt_id', NEW.attempt_id,
       'cause_kind', NEW.cause_kind,
       'subject_id', NEW.subject_id,
       'evidence_id', NEW.evidence_id,
       'evidence_digest', NEW.evidence_digest,
       'decided_at_unix_ms', NEW.decided_at_unix_ms
    ) AS TEXT)
BEGIN
    SELECT RAISE(ABORT, 'policy cause authority must exactly bind its typed attempt subject and evidence');
END;

CREATE TRIGGER task_attempt_disposition_exact_authority
BEFORE INSERT ON task_attempt_dispositions
WHEN (
       NEW.disposition_kind = 'Integrated'
       AND (
          NEW.from_state != 'Candidate'
          OR NEW.evidence_kind != 'Integrated'
          OR NOT EXISTS (
              SELECT 1
              FROM task_attempt_candidate_boundaries candidate
              JOIN task_integration_receipts integration
                ON integration.receipt_id = NEW.integration_receipt_id
              JOIN task_attempt_integration_admissions admission
                ON admission.attempt_id = NEW.attempt_id
              JOIN task_attempt_integrated_result_coverage coverage
                ON coverage.disposition_id = NEW.disposition_id
              JOIN effect_intents intent ON intent.effect_id = integration.effect_id
              JOIN effect_observations observation
                ON observation.observation_id = integration.observation_id
              JOIN effect_evidence_payloads evidence ON evidence.effect_id = integration.effect_id
              WHERE candidate.boundary_id = NEW.candidate_boundary_id
                AND candidate.attempt_id = NEW.attempt_id
                AND candidate.sprint_id = NEW.sprint_id
                AND candidate.task_id = NEW.task_id
                AND integration.sprint_id = NEW.sprint_id
                AND integration.task_id = NEW.task_id
                AND integration.worker_id = NEW.worker_id
                AND integration.worker_lease_id = NEW.worker_lease_id
                AND integration.worker_lease_epoch = NEW.lease_epoch
                AND candidate.change_set_id = integration.change_set_id
                AND candidate.sealed_snapshot_id = integration.result_snapshot
                AND admission.candidate_boundary_id = candidate.boundary_id
                AND admission.effect_id = integration.effect_id
                AND coverage.receipt_id = integration.receipt_id
                AND coverage.admission_id = admission.admission_id
                AND coverage.attempt_id = NEW.attempt_id
                AND admission.worker_launch_id = integration.worker_launch_id
                AND admission.worker_session_id = integration.worker_session_id
                AND admission.input_snapshot_id = integration.input_snapshot
                AND admission.result_snapshot_id = integration.result_snapshot
                AND intent.worker_lease_id = NEW.worker_lease_id
                AND intent.worker_lease_epoch = NEW.lease_epoch
                AND observation.effect_id = intent.effect_id
                AND observation.outcome = 'Succeeded'
                AND evidence.observation_id = observation.observation_id
                AND evidence.evidence_digest = NEW.evidence_digest
                AND evidence.evidence_bytes = NEW.evidence_bytes
                AND integration.verification_count = candidate.formal_check_count
                AND NOT EXISTS (
                    SELECT 1
                    FROM task_attempt_candidate_formal_checks candidate_link
                    LEFT JOIN task_integration_verification_receipts integration_link
                      ON integration_link.integration_receipt_id = integration.receipt_id
                     AND integration_link.ordinal = candidate_link.ordinal
                     AND integration_link.verification_receipt_id =
                         candidate_link.verification_receipt_id
                    WHERE candidate_link.candidate_boundary_id = candidate.boundary_id
                      AND integration_link.integration_receipt_id IS NULL
                )
          )
       )
     )
 OR (
       NEW.cause_kind = 'NeverLaunched'
       AND (
          NEW.evidence_kind != 'NeverLaunched'
          OR NEW.never_launched_release_id IS NULL
          OR NEW.cleanup_receipt_id IS NOT NULL
          OR NOT EXISTS (
              SELECT 1 FROM worker_lease_never_launched_releases release
              WHERE release.release_id = NEW.never_launched_release_id
                AND release.disposition_id = NEW.disposition_id
                AND release.attempt_id = NEW.attempt_id
                AND release.worker_lease_id = NEW.worker_lease_id
                AND release.sprint_id = NEW.sprint_id
                AND release.task_id = NEW.task_id
                AND release.worker_id = NEW.worker_id
                AND release.lease_epoch = NEW.lease_epoch
                AND release.absence_evidence_id = NEW.evidence_id
                AND release.absence_evidence_digest = NEW.evidence_digest
                AND release.absence_evidence_bytes = NEW.evidence_bytes
          )
       )
     )
 OR (
       NEW.cause_kind IS NOT NULL AND NEW.cause_kind != 'NeverLaunched'
       AND (
          NEW.cleanup_receipt_id IS NULL
          OR NEW.never_launched_release_id IS NOT NULL
          OR NOT EXISTS (
              SELECT 1
              FROM worker_cleanup_receipts cleanup
              WHERE cleanup.receipt_id = NEW.cleanup_receipt_id
                AND cleanup.sprint_id = NEW.sprint_id
                AND cleanup.worker_lease_id = NEW.worker_lease_id
                AND cleanup.worker_lease_epoch = NEW.lease_epoch
          )
       )
     )
 OR (
       NEW.cause_kind = 'LaunchRefusedBeforeNativeEffect'
       AND (
          NEW.evidence_kind != 'LaunchRefusedBeforeNativeEffect'
          OR NOT EXISTS (
              SELECT 1
              FROM runner_launch_intents launch
              JOIN runner_launch_preparation_attempts preparation
                ON preparation.launch_id = launch.launch_id
              JOIN runner_launch_preparation_outcomes outcome
                ON outcome.attempt_id = preparation.attempt_id
              WHERE launch.launch_id = NEW.cause_launch_id
                AND launch.worker_lease_id = NEW.worker_lease_id
                AND launch.worker_lease_epoch = NEW.lease_epoch
                AND outcome.disposition = 'RefusedBeforeNativeEffect'
                AND outcome.native_evidence_digest = NEW.evidence_digest
                AND outcome.native_evidence_bytes = NEW.evidence_bytes
                AND outcome.finished_at_unix_ms <= NEW.disposed_at_unix_ms
          )
       )
     )
 OR (
       NEW.cause_kind = 'KnownWorkerExit'
       AND (
          NEW.evidence_kind != 'KnownWorkerExit'
          OR NOT EXISTS (
              SELECT 1
              FROM task_attempt_worker_exit_authorities authority
              WHERE authority.authority_id = NEW.cause_authority_id
                AND authority.attempt_id = NEW.attempt_id
                AND authority.launch_id = NEW.cause_launch_id
                AND authority.session_id = NEW.cause_session_id
                AND authority.worker_lease_id = NEW.worker_lease_id
                AND authority.lease_epoch = NEW.lease_epoch
                AND authority.evidence_id = NEW.evidence_id
                AND authority.evidence_digest = NEW.evidence_digest
                AND authority.evidence_bytes = NEW.evidence_bytes
                AND authority.observed_at_unix_ms <= NEW.disposed_at_unix_ms
          )
       )
     )
 OR (
       NEW.cause_kind = 'FormalVerificationFailed'
       AND (
          NEW.evidence_kind != 'FormalVerificationFailed'
          OR NOT EXISTS (
              SELECT 1
              FROM task_attempt_formal_checks formal
              JOIN effect_evidence_payloads evidence
                ON evidence.observation_id = formal.observation_id
              WHERE formal.formal_check_id = NEW.cause_formal_check_id
                AND formal.attempt_id = NEW.attempt_id
                AND formal.passed = 0
                AND evidence.evidence_digest = NEW.evidence_digest
                AND evidence.evidence_bytes = NEW.evidence_bytes
                AND formal.checked_at_unix_ms <= NEW.disposed_at_unix_ms
          )
       )
     )
 OR (
       NEW.cause_kind = 'CandidateRejectedKnown'
       AND (
          NEW.evidence_kind != 'CandidateRejectedKnown'
          OR NOT EXISTS (
              SELECT 1 FROM task_attempt_candidate_rejection_authorities authority
              WHERE authority.authority_id = NEW.cause_authority_id
                AND authority.candidate_boundary_id = NEW.cause_candidate_boundary_id
                AND authority.attempt_id = NEW.attempt_id
                AND authority.evidence_id = NEW.evidence_id
                AND authority.evidence_digest = NEW.evidence_digest
                AND authority.evidence_bytes = NEW.evidence_bytes
                AND authority.rejected_at_unix_ms <= NEW.disposed_at_unix_ms
          )
       )
     )
 OR (
       NEW.disposition_kind = 'UnknownCleaned'
       AND (
          NEW.evidence_kind != 'UnknownTerminalEffect'
          OR NOT EXISTS (
              SELECT 1
              FROM effect_intents intent
              JOIN effect_observations observation ON observation.effect_id = intent.effect_id
              JOIN worker_cleanup_receipts cleanup
                ON cleanup.receipt_id = NEW.cleanup_receipt_id
              JOIN effect_evidence_payloads evidence ON evidence.effect_id = intent.effect_id
              WHERE intent.effect_id = NEW.cause_effect_id
                AND observation.observation_id = NEW.cause_observation_id
                AND observation.outcome = 'Unknown'
                AND intent.worker_lease_id = NEW.worker_lease_id
                AND observation.worker_lease_id = NEW.worker_lease_id
                AND cleanup.worker_lease_id = NEW.worker_lease_id
                AND evidence.observation_id = observation.observation_id
                AND evidence.evidence_digest = NEW.evidence_digest
                AND evidence.evidence_bytes = NEW.evidence_bytes
          )
       )
     )
 OR (
       NEW.cause_kind IN (
          'PermanentContractViolation', 'CriterionProvenUnsatisfiable',
          'AuthorityExpansionRequired', 'VerifiedDependencyUnavailable',
          'OperatorCanceled'
       )
       AND (
          NEW.evidence_kind != NEW.cause_kind
          OR NOT EXISTS (
              SELECT 1 FROM task_attempt_policy_cause_authorities authority
              WHERE authority.authority_id = NEW.cause_authority_id
                AND authority.attempt_id = NEW.attempt_id
                AND authority.sprint_id = NEW.sprint_id
                AND authority.task_id = NEW.task_id
                AND authority.cause_kind = NEW.cause_kind
                AND authority.evidence_id = NEW.evidence_id
                AND authority.evidence_digest = NEW.evidence_digest
                AND authority.evidence_bytes = NEW.evidence_bytes
                AND authority.decided_at_unix_ms <= NEW.disposed_at_unix_ms
          )
       )
     )
 OR (
       NEW.disposition_kind = 'UnknownQuarantined'
       AND (
          NEW.evidence_kind != 'UncertainAuthority'
          OR NOT EXISTS (
              SELECT 1 FROM active_worker_leases active
              WHERE active.lease_id = NEW.worker_lease_id
                AND active.lease_epoch = NEW.lease_epoch
          )
       )
     )
 OR (
       NEW.disposition_kind NOT IN ('Integrated', 'UnknownQuarantined')
       AND EXISTS (
          SELECT 1
          FROM effect_intents intent
          LEFT JOIN effect_observations observation ON observation.effect_id = intent.effect_id
          LEFT JOIN unresolved_mutation_effects mutation ON mutation.effect_id = intent.effect_id
          WHERE intent.worker_lease_id = NEW.worker_lease_id
            AND (
                observation.effect_id IS NULL
                OR (NEW.disposition_kind != 'UnknownCleaned' AND observation.outcome = 'Unknown')
                OR mutation.effect_id IS NOT NULL
            )
       )
     )
BEGIN
    SELECT RAISE(ABORT, 'task-attempt disposition lacks exact variant-specific durable authority');
END;

CREATE TRIGGER task_attempt_disposition_canonical_cleanup_source
BEFORE INSERT ON task_attempt_dispositions
WHEN NEW.cause_kind IN (
       'LaunchRefusedBeforeNativeEffect', 'KnownWorkerExit',
       'FormalVerificationFailed', 'CandidateRejectedKnown',
       'PermanentContractViolation', 'CriterionProvenUnsatisfiable',
       'AuthorityExpansionRequired', 'VerifiedDependencyUnavailable',
       'OperatorCanceled'
     )
 AND NOT EXISTS (
       SELECT 1
       FROM task_attempt_known_cleanup_sources selected
       WHERE selected.attempt_id = NEW.attempt_id
         AND selected.source_id = NEW.evidence_id
         AND selected.source_kind = CASE NEW.cause_kind
               WHEN 'LaunchRefusedBeforeNativeEffect' THEN 'LaunchRefusal'
               WHEN 'KnownWorkerExit' THEN 'WorkerExit'
               WHEN 'FormalVerificationFailed' THEN 'FormalVerificationFailure'
               WHEN 'CandidateRejectedKnown' THEN 'CandidateRejection'
               ELSE 'PolicyCause'
             END
         AND selected.source_at_unix_ms <= NEW.disposed_at_unix_ms
         AND NOT EXISTS (
               SELECT 1
               FROM task_attempt_known_cleanup_sources prior
               WHERE prior.attempt_id = NEW.attempt_id
                 AND (
                      prior.outcome_rank < selected.outcome_rank
                      OR (
                           prior.outcome_rank = selected.outcome_rank
                           AND prior.source_at_unix_ms < selected.source_at_unix_ms
                         )
                      OR (
                           prior.outcome_rank = selected.outcome_rank
                           AND prior.source_at_unix_ms = selected.source_at_unix_ms
                           AND prior.source_id < selected.source_id
                         )
                      OR (
                           prior.outcome_rank = selected.outcome_rank
                           AND prior.source_at_unix_ms = selected.source_at_unix_ms
                           AND prior.source_id = selected.source_id
                           AND prior.source_kind < selected.source_kind
                         )
                 )
           )
     )
BEGIN
    SELECT RAISE(ABORT, 'task-attempt disposition cause is not the canonical known-cleanup source winner');
END;

-- A quarantine is immutable, so its sorted reference list must equal the
-- complete canonical unresolved set at insertion time. A subset, alias,
-- crossed lease, duplicate, or postdated authority is rejected before any
-- disposition, marker, link, or event can be written.
CREATE TRIGGER task_attempt_unknown_quarantine_references_validate
BEFORE INSERT ON task_attempt_dispositions
WHEN NEW.disposition_kind = 'UnknownQuarantined'
 AND (
      json_array_length(
          CAST(NEW.disposition_json AS TEXT),
          '$.UnknownQuarantined.uncertain_evidence.authority_reference_ids'
      ) != (
          SELECT COUNT(*)
          FROM task_attempt_canonical_unresolved_authorities expected
          WHERE expected.worker_lease_id = NEW.worker_lease_id
            AND expected.lease_epoch = NEW.lease_epoch
      )
      OR EXISTS (
          SELECT 1
          FROM task_attempt_canonical_unresolved_authorities expected
          WHERE expected.worker_lease_id = NEW.worker_lease_id
            AND expected.lease_epoch = NEW.lease_epoch
            AND expected.authority_at_unix_ms > NEW.disposed_at_unix_ms
      )
      OR EXISTS (
          SELECT 1
          FROM task_attempt_canonical_unresolved_authorities expected
          WHERE expected.worker_lease_id = NEW.worker_lease_id
            AND expected.lease_epoch = NEW.lease_epoch
            AND NOT EXISTS (
                SELECT 1
                FROM json_each(
                    CAST(NEW.disposition_json AS TEXT),
                    '$.UnknownQuarantined.uncertain_evidence.authority_reference_ids'
                ) supplied
                WHERE supplied.value = expected.authority_reference_id
                  AND CAST(supplied.key AS INTEGER) = (
                      SELECT COUNT(*)
                      FROM task_attempt_canonical_unresolved_authorities prior
                      WHERE prior.worker_lease_id = NEW.worker_lease_id
                        AND prior.lease_epoch = NEW.lease_epoch
                        AND prior.authority_reference_id
                            < expected.authority_reference_id
                  )
            )
      )
      OR (
          SELECT COUNT(*)
          FROM task_attempt_canonical_unresolved_authorities expected
          WHERE expected.worker_lease_id = NEW.worker_lease_id
            AND expected.lease_epoch = NEW.lease_epoch
      ) != (
          SELECT COUNT(DISTINCT expected.authority_reference_id)
          FROM task_attempt_canonical_unresolved_authorities expected
          WHERE expected.worker_lease_id = NEW.worker_lease_id
            AND expected.lease_epoch = NEW.lease_epoch
      )
 )
BEGIN
    SELECT RAISE(ABORT, 'UnknownQuarantined requires the complete canonical attempt-scoped uncertain-authority set');
END;

CREATE TRIGGER worker_lease_release_requires_v15_disposition
BEFORE INSERT ON worker_lease_releases
WHEN EXISTS (
       SELECT 1 FROM task_attempts attempt
       WHERE attempt.worker_lease_id = NEW.lease_id
         AND attempt.schema_generation = 15
     )
 AND NOT EXISTS (
       SELECT 1
       FROM task_attempts attempt
       JOIN task_attempt_dispositions disposition
         ON disposition.attempt_id = attempt.attempt_id
       WHERE attempt.worker_lease_id = NEW.lease_id
         AND attempt.sprint_id = NEW.sprint_id
         AND attempt.lease_epoch = NEW.lease_epoch
         AND disposition.worker_lease_id = NEW.lease_id
         AND disposition.lease_epoch = NEW.lease_epoch
         AND (
             (disposition.disposition_kind IN (
                 'Retryable', 'AttemptsExhausted', 'PermanentFailure',
                 'Blocked', 'Canceled', 'UnknownCleaned'
              ) AND disposition.cleanup_receipt_id = NEW.cleanup_receipt_id)
             OR disposition.disposition_kind = 'Integrated'
         )
     )
BEGIN
    SELECT RAISE(ABORT, 'current task-attempt cleanup release requires its exact prior disposition');
END;

CREATE TRIGGER worker_lease_release_rejects_unreconciled_legacy_attempt
BEFORE INSERT ON worker_lease_releases
WHEN EXISTS (
       SELECT 1
       FROM task_attempts attempt
       JOIN task_attempt_legacy_classifications legacy
         ON legacy.attempt_id = attempt.attempt_id
       WHERE attempt.worker_lease_id = NEW.lease_id
     )
BEGIN
    SELECT RAISE(ABORT, 'classified legacy task-attempt release requires an explicit atomic legacy reconciliation');
END;

DROP TRIGGER agent_events_validate_task_transition;
CREATE TRIGGER agent_events_validate_task_transition
BEFORE INSERT ON agent_events
WHEN json_type(CAST(NEW.event_json AS TEXT), '$.payload.TaskStateChanged') = 'object'
 AND (
    json_type(CAST(NEW.event_json AS TEXT), '$.task_id') IS NOT 'text'
    OR json_type(CAST(NEW.event_json AS TEXT), '$.payload.TaskStateChanged.from') IS NOT 'text'
    OR json_type(CAST(NEW.event_json AS TEXT), '$.payload.TaskStateChanged.to') IS NOT 'text'
    OR json_extract(CAST(NEW.event_json AS TEXT), '$.payload.TaskStateChanged.from')
       IS NOT COALESCE((
          SELECT json_extract(CAST(event.event_json AS TEXT),
                              '$.payload.TaskStateChanged.to')
          FROM agent_events event
          WHERE event.sprint_id = NEW.sprint_id
            AND json_extract(CAST(event.event_json AS TEXT), '$.task_id') =
                json_extract(CAST(NEW.event_json AS TEXT), '$.task_id')
            AND json_type(CAST(event.event_json AS TEXT),
                          '$.payload.TaskStateChanged') = 'object'
          ORDER BY event.sequence DESC LIMIT 1
       ), 'Planned')
    OR NOT (
        (json_extract(CAST(NEW.event_json AS TEXT), '$.payload.TaskStateChanged.from') = 'Planned'
         AND json_extract(CAST(NEW.event_json AS TEXT), '$.payload.TaskStateChanged.to') = 'Ready')
        OR (json_extract(CAST(NEW.event_json AS TEXT), '$.payload.TaskStateChanged.from') = 'Ready'
            AND json_extract(CAST(NEW.event_json AS TEXT), '$.payload.TaskStateChanged.to') = 'Leased')
        OR (json_extract(CAST(NEW.event_json AS TEXT), '$.payload.TaskStateChanged.from') = 'Leased'
            AND json_extract(CAST(NEW.event_json AS TEXT), '$.payload.TaskStateChanged.to') = 'Running')
        OR (json_extract(CAST(NEW.event_json AS TEXT), '$.payload.TaskStateChanged.from') = 'Running'
            AND json_extract(CAST(NEW.event_json AS TEXT), '$.payload.TaskStateChanged.to') = 'Verifying')
        OR (json_extract(CAST(NEW.event_json AS TEXT), '$.payload.TaskStateChanged.from') = 'Verifying'
            AND json_extract(CAST(NEW.event_json AS TEXT), '$.payload.TaskStateChanged.to') = 'Candidate')
        OR (json_extract(CAST(NEW.event_json AS TEXT), '$.payload.TaskStateChanged.from') = 'Candidate'
            AND json_extract(CAST(NEW.event_json AS TEXT), '$.payload.TaskStateChanged.to') = 'Integrated')
        OR (
            json_extract(CAST(NEW.event_json AS TEXT), '$.payload.TaskStateChanged.from')
                IN ('Leased', 'Running', 'Verifying', 'Candidate')
            AND json_extract(CAST(NEW.event_json AS TEXT), '$.payload.TaskStateChanged.to')
                IN ('Ready', 'Blocked', 'Failed', 'Canceled', 'Unknown')
        )
        OR (
            json_extract(CAST(NEW.event_json AS TEXT), '$.payload.TaskStateChanged.from')
                IN ('Planned', 'Ready')
            AND json_extract(CAST(NEW.event_json AS TEXT), '$.payload.TaskStateChanged.to')
                IN ('Blocked', 'Failed', 'Canceled', 'Unknown')
        )
    )
    OR (
       json_extract(CAST(NEW.event_json AS TEXT), '$.payload.TaskStateChanged.to') = 'Ready'
       AND EXISTS (
          SELECT 1 FROM active_worker_leases active
          WHERE active.sprint_id = NEW.sprint_id
            AND active.task_id = json_extract(CAST(NEW.event_json AS TEXT), '$.task_id')
       )
    )
    OR (
       json_extract(CAST(NEW.event_json AS TEXT), '$.payload.TaskStateChanged.to') = 'Ready'
       AND EXISTS (
          SELECT 1
          FROM sprint_task_graphs graph,
               json_each(CAST(graph.graph_json AS TEXT), '$.tasks') task,
               json_each(task.value, '$.dependencies') dependency
          WHERE graph.sprint_id = NEW.sprint_id
            AND json_extract(task.value, '$.task_id') =
                json_extract(CAST(NEW.event_json AS TEXT), '$.task_id')
            AND COALESCE((
                SELECT json_extract(CAST(event.event_json AS TEXT),
                                    '$.payload.TaskStateChanged.to')
                FROM agent_events event
                WHERE event.sprint_id = NEW.sprint_id
                  AND json_extract(CAST(event.event_json AS TEXT), '$.task_id') = dependency.value
                  AND json_type(CAST(event.event_json AS TEXT),
                                '$.payload.TaskStateChanged') = 'object'
                ORDER BY event.sequence DESC LIMIT 1
            ), 'Planned') != 'Integrated'
       )
    )
 )
BEGIN SELECT RAISE(ABORT, 'invalid, stale, or dependency-unready v15 task transition'); END;

CREATE TRIGGER agent_events_require_attempt_phase_authority
AFTER INSERT ON agent_events
WHEN json_type(CAST(NEW.event_json AS TEXT), '$.payload.TaskStateChanged') = 'object'
 AND (
    (
      json_extract(CAST(NEW.event_json AS TEXT), '$.payload.TaskStateChanged.from') = 'Leased'
      AND json_extract(CAST(NEW.event_json AS TEXT), '$.payload.TaskStateChanged.to') = 'Running'
      AND NOT EXISTS (
        SELECT 1 FROM task_attempt_running_boundaries boundary
        JOIN task_attempts attempt ON attempt.attempt_id = boundary.attempt_id
        WHERE boundary.transition_event_id = NEW.event_id
          AND boundary.sprint_id = NEW.sprint_id
          AND boundary.task_id = json_extract(CAST(NEW.event_json AS TEXT), '$.task_id')
          AND boundary.worker_id = json_extract(CAST(NEW.event_json AS TEXT), '$.worker_id')
          AND attempt.worker_lease_id = boundary.worker_lease_id
          AND attempt.lease_epoch = boundary.lease_epoch
      )
    ) OR (
      json_extract(CAST(NEW.event_json AS TEXT), '$.payload.TaskStateChanged.from') = 'Running'
      AND json_extract(CAST(NEW.event_json AS TEXT), '$.payload.TaskStateChanged.to') = 'Verifying'
      AND NOT EXISTS (
        SELECT 1 FROM task_attempt_verification_boundaries boundary
        JOIN task_attempts attempt ON attempt.attempt_id = boundary.attempt_id
        WHERE boundary.transition_event_id = NEW.event_id
          AND boundary.sprint_id = NEW.sprint_id
          AND boundary.task_id = json_extract(CAST(NEW.event_json AS TEXT), '$.task_id')
          AND attempt.worker_id = json_extract(CAST(NEW.event_json AS TEXT), '$.worker_id')
      )
    ) OR (
      json_extract(CAST(NEW.event_json AS TEXT), '$.payload.TaskStateChanged.from') = 'Verifying'
      AND json_extract(CAST(NEW.event_json AS TEXT), '$.payload.TaskStateChanged.to') = 'Candidate'
      AND NOT EXISTS (
        SELECT 1 FROM task_attempt_candidate_boundaries boundary
        JOIN task_attempts attempt ON attempt.attempt_id = boundary.attempt_id
        WHERE boundary.transition_event_id = NEW.event_id
          AND boundary.sprint_id = NEW.sprint_id
          AND boundary.task_id = json_extract(CAST(NEW.event_json AS TEXT), '$.task_id')
          AND attempt.worker_id = json_extract(CAST(NEW.event_json AS TEXT), '$.worker_id')
      )
    ) OR (
      json_extract(CAST(NEW.event_json AS TEXT), '$.payload.TaskStateChanged.from') = 'Candidate'
      AND json_extract(CAST(NEW.event_json AS TEXT), '$.payload.TaskStateChanged.to') = 'Integrated'
      AND NOT EXISTS (
        SELECT 1 FROM task_attempt_dispositions disposition
        WHERE disposition.transition_event_id = NEW.event_id
          AND disposition.disposition_kind = 'Integrated'
          AND disposition.sprint_id = NEW.sprint_id
          AND disposition.task_id = json_extract(CAST(NEW.event_json AS TEXT), '$.task_id')
          AND disposition.worker_id = json_extract(CAST(NEW.event_json AS TEXT), '$.worker_id')
      )
    ) OR (
      json_extract(CAST(NEW.event_json AS TEXT), '$.payload.TaskStateChanged.from')
          IN ('Leased', 'Running', 'Verifying', 'Candidate')
      AND json_extract(CAST(NEW.event_json AS TEXT), '$.payload.TaskStateChanged.to')
          IN ('Ready', 'Blocked', 'Failed', 'Canceled', 'Unknown')
      AND NOT EXISTS (
        SELECT 1 FROM task_attempt_dispositions disposition
        WHERE disposition.transition_event_id = NEW.event_id
          AND disposition.sprint_id = NEW.sprint_id
          AND disposition.task_id = json_extract(CAST(NEW.event_json AS TEXT), '$.task_id')
          AND disposition.worker_id = json_extract(CAST(NEW.event_json AS TEXT), '$.worker_id')
          AND (
            (json_extract(CAST(NEW.event_json AS TEXT), '$.payload.TaskStateChanged.to') = 'Ready'
             AND disposition.disposition_kind = 'Retryable')
            OR (json_extract(CAST(NEW.event_json AS TEXT), '$.payload.TaskStateChanged.to') = 'Failed'
                AND disposition.disposition_kind IN ('AttemptsExhausted', 'PermanentFailure'))
            OR (json_extract(CAST(NEW.event_json AS TEXT), '$.payload.TaskStateChanged.to') = 'Blocked'
                AND disposition.disposition_kind = 'Blocked')
            OR (json_extract(CAST(NEW.event_json AS TEXT), '$.payload.TaskStateChanged.to') = 'Canceled'
                AND disposition.disposition_kind = 'Canceled')
            OR (json_extract(CAST(NEW.event_json AS TEXT), '$.payload.TaskStateChanged.to') = 'Unknown'
                AND disposition.disposition_kind IN ('UnknownCleaned', 'UnknownQuarantined'))
          )
      )
    )
 )
BEGIN SELECT RAISE(ABORT, 'attempted-state transition lacks exact v15 phase or disposition authority'); END;

CREATE TRIGGER agent_events_cover_verification_boundary
AFTER INSERT ON agent_events
WHEN EXISTS (
       SELECT 1 FROM task_attempt_verification_boundaries boundary
       WHERE boundary.transition_event_id = NEW.event_id
     )
 AND NOT EXISTS (
       SELECT 1
       FROM task_attempt_verification_boundaries boundary
       JOIN task_attempts attempt ON attempt.attempt_id = boundary.attempt_id
       WHERE boundary.transition_event_id = NEW.event_id
         AND attempt.schema_generation = 15
         AND boundary.sprint_id = attempt.sprint_id
         AND boundary.task_id = attempt.task_id
         AND boundary.worker_lease_id = attempt.worker_lease_id
         AND boundary.lease_epoch = attempt.lease_epoch
         AND NEW.sprint_id = attempt.sprint_id
         AND NEW.occurred_at_unix_ms = boundary.sealed_at_unix_ms
         AND json_type(CAST(NEW.event_json AS TEXT), '$.payload.TaskStateChanged') = 'object'
         AND json_extract(CAST(NEW.event_json AS TEXT), '$.payload.TaskStateChanged.from') = 'Running'
         AND json_extract(CAST(NEW.event_json AS TEXT), '$.payload.TaskStateChanged.to') = 'Verifying'
         AND json_extract(CAST(NEW.event_json AS TEXT), '$.task_id') = attempt.task_id
         AND json_extract(CAST(NEW.event_json AS TEXT), '$.worker_id') = attempt.worker_id
         AND boundary.terminal_effect_count = (
             SELECT COUNT(*) FROM task_attempt_verification_terminal_effects link
             WHERE link.verification_boundary_id = boundary.boundary_id
         )
         AND NOT EXISTS (
             SELECT 1
             FROM json_each(
                 CAST(boundary.boundary_json AS TEXT),
                 '$.terminal_non_cleanup_effects'
             ) expected
             LEFT JOIN task_attempt_verification_terminal_effects link
               ON link.verification_boundary_id = boundary.boundary_id
              AND link.ordinal = CAST(expected.key AS INTEGER)
              AND link.effect_id = json_extract(expected.value, '$.effect_id')
              AND link.observation_id = json_extract(expected.value, '$.observation_id')
             WHERE link.verification_boundary_id IS NULL
         )
         AND boundary.terminal_effect_count = (
             SELECT COUNT(*)
             FROM effect_intents intent
             WHERE intent.worker_lease_id = attempt.worker_lease_id
               AND intent.worker_lease_epoch = attempt.lease_epoch
               AND NOT EXISTS (
                   SELECT 1 FROM runner_launch_cleanup_admissions cleanup
                   WHERE cleanup.cleanup_effect_id = intent.effect_id
               )
         )
         AND NOT EXISTS (
             SELECT 1
             FROM effect_intents intent
             JOIN effect_observations observation ON observation.effect_id = intent.effect_id
             WHERE intent.worker_lease_id = attempt.worker_lease_id
               AND intent.worker_lease_epoch = attempt.lease_epoch
               AND NOT EXISTS (
                   SELECT 1 FROM runner_launch_cleanup_admissions cleanup
                   WHERE cleanup.cleanup_effect_id = intent.effect_id
               )
               AND NOT EXISTS (
                   SELECT 1 FROM task_attempt_verification_terminal_effects link
                   WHERE link.verification_boundary_id = boundary.boundary_id
                     AND link.sprint_id = attempt.sprint_id
                     AND link.effect_id = intent.effect_id
                     AND link.observation_id = observation.observation_id
                     AND link.ordinal = (
                         SELECT COUNT(*) FROM effect_intents prior
                         WHERE prior.worker_lease_id = attempt.worker_lease_id
                           AND prior.worker_lease_epoch = attempt.lease_epoch
                           AND prior.effect_id < intent.effect_id
                           AND NOT EXISTS (
                               SELECT 1 FROM runner_launch_cleanup_admissions cleanup
                               WHERE cleanup.cleanup_effect_id = prior.effect_id
                           )
                     )
               )
         )
     )
BEGIN
    SELECT RAISE(ABORT, 'verification-boundary event must be its exact Running-to-Verifying transition');
END;

CREATE TRIGGER agent_events_cover_running_boundary
AFTER INSERT ON agent_events
WHEN EXISTS (
       SELECT 1 FROM task_attempt_running_boundaries boundary
       WHERE boundary.transition_event_id = NEW.event_id
     )
 AND NOT EXISTS (
       SELECT 1
       FROM task_attempt_running_boundaries boundary
       JOIN task_attempts attempt ON attempt.attempt_id = boundary.attempt_id
       WHERE boundary.transition_event_id = NEW.event_id
         AND attempt.schema_generation = 15
         AND boundary.sprint_id = attempt.sprint_id
         AND boundary.task_id = attempt.task_id
         AND boundary.worker_id = attempt.worker_id
         AND boundary.worker_lease_id = attempt.worker_lease_id
         AND boundary.lease_epoch = attempt.lease_epoch
         AND NEW.sprint_id = attempt.sprint_id
         AND NEW.occurred_at_unix_ms = boundary.started_at_unix_ms
         AND json_type(CAST(NEW.event_json AS TEXT), '$.payload.TaskStateChanged') = 'object'
         AND json_extract(CAST(NEW.event_json AS TEXT), '$.payload.TaskStateChanged.from') = 'Leased'
         AND json_extract(CAST(NEW.event_json AS TEXT), '$.payload.TaskStateChanged.to') = 'Running'
         AND json_extract(CAST(NEW.event_json AS TEXT), '$.task_id') = attempt.task_id
         AND json_extract(CAST(NEW.event_json AS TEXT), '$.worker_id') = attempt.worker_id
     )
BEGIN
    SELECT RAISE(ABORT, 'Running-boundary event must be its exact Leased-to-Running transition');
END;

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
                  json_each(graph_task.value, '$.acceptance_checks') task_check,
                  json_each(CAST(sprint.spec_json AS TEXT), '$.acceptance_criteria') criterion
             WHERE sprint.sprint_id = boundary.sprint_id
               AND json_extract(graph_task.value, '$.task_id') = boundary.task_id
               AND json_extract(criterion.value, '$.criterion_id') = task_check.value
               AND json_type(criterion.value, '$.kind.Automated') = 'object'
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
                         FROM json_each(graph_task.value, '$.acceptance_checks') prior_check,
                              json_each(CAST(sprint.spec_json AS TEXT), '$.acceptance_criteria') prior_criterion
                         WHERE CAST(prior_check.key AS INTEGER) < CAST(task_check.key AS INTEGER)
                           AND json_extract(prior_criterion.value, '$.criterion_id') = prior_check.value
                           AND json_type(prior_criterion.value, '$.kind.Automated') = 'object'
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
    SELECT RAISE(ABORT, 'candidate-boundary event must close exact passing-check Verifying-to-Candidate authority');
END;

CREATE TRIGGER agent_events_cover_attempt_disposition
AFTER INSERT ON agent_events
WHEN EXISTS (
       SELECT 1 FROM task_attempt_dispositions disposition
       WHERE disposition.transition_event_id = NEW.event_id
     )
 AND NOT EXISTS (
       SELECT 1
       FROM task_attempt_dispositions disposition
       JOIN task_attempts attempt ON attempt.attempt_id = disposition.attempt_id
       WHERE disposition.transition_event_id = NEW.event_id
         AND attempt.schema_generation = 15
         AND disposition.sprint_id = attempt.sprint_id
         AND disposition.task_id = attempt.task_id
         AND disposition.worker_id = attempt.worker_id
         AND disposition.worker_lease_id = attempt.worker_lease_id
         AND disposition.lease_epoch = attempt.lease_epoch
         AND disposition.attempt_ordinal = attempt.attempt_ordinal
         AND NEW.sprint_id = attempt.sprint_id
         AND NEW.occurred_at_unix_ms = disposition.disposed_at_unix_ms
         AND json_type(CAST(NEW.event_json AS TEXT), '$.payload.TaskStateChanged') = 'object'
         AND json_extract(CAST(NEW.event_json AS TEXT), '$.payload.TaskStateChanged.from') = disposition.from_state
         AND json_extract(CAST(NEW.event_json AS TEXT), '$.payload.TaskStateChanged.to') = CASE disposition.disposition_kind
               WHEN 'Integrated' THEN 'Integrated'
               WHEN 'Retryable' THEN 'Ready'
               WHEN 'AttemptsExhausted' THEN 'Failed'
               WHEN 'PermanentFailure' THEN 'Failed'
               WHEN 'Blocked' THEN 'Blocked'
               WHEN 'Canceled' THEN 'Canceled'
               WHEN 'UnknownCleaned' THEN 'Unknown'
               WHEN 'UnknownQuarantined' THEN 'Unknown'
             END
         AND json_extract(CAST(NEW.event_json AS TEXT), '$.task_id') = attempt.task_id
         AND json_extract(CAST(NEW.event_json AS TEXT), '$.worker_id') = attempt.worker_id
         AND (
             disposition.disposition_kind NOT IN ('UnknownCleaned', 'UnknownQuarantined')
             OR EXISTS (
                 SELECT 1
                 FROM sprint_unknown_terminalization_pending pending
                 LEFT JOIN sprint_unknown_terminalization_closures closure
                   ON closure.marker_id = pending.marker_id
                 WHERE pending.sprint_id = disposition.sprint_id
                   AND closure.marker_id IS NULL
             )
             OR EXISTS (
                 SELECT 1 FROM sprint_non_success_terminal_outcomes terminal
                 WHERE terminal.sprint_id = disposition.sprint_id
                   AND terminal.terminal_state = 'Unknown'
             )
         )
         AND (
             disposition.disposition_kind != 'UnknownQuarantined'
             OR (
                 disposition.uncertain_authority_count = (
                     SELECT COUNT(*)
                     FROM task_attempt_disposition_uncertain_authorities link
                     WHERE link.disposition_id = disposition.disposition_id
                 )
                 AND disposition.uncertain_authority_count = json_array_length(
                     CAST(disposition.disposition_json AS TEXT),
                     '$.UnknownQuarantined.uncertain_evidence.authority_reference_ids'
                 )
                 AND NOT EXISTS (
                     SELECT 1
                     FROM json_each(
                         CAST(disposition.disposition_json AS TEXT),
                         '$.UnknownQuarantined.uncertain_evidence.authority_reference_ids'
                     ) expected
                     LEFT JOIN task_attempt_disposition_uncertain_authorities link
                            ON link.disposition_id = disposition.disposition_id
                           AND link.ordinal = CAST(expected.key AS INTEGER)
                           AND link.authority_reference_id = expected.value
                     WHERE link.disposition_id IS NULL
                 )
                 AND NOT EXISTS (
                     SELECT 1
                     FROM task_attempt_disposition_uncertain_authorities current
                     JOIN task_attempt_disposition_uncertain_authorities prior
                       ON prior.disposition_id = current.disposition_id
                      AND prior.ordinal + 1 = current.ordinal
                     WHERE current.disposition_id = disposition.disposition_id
                       AND prior.authority_reference_id >= current.authority_reference_id
                 )
             )
         )
         AND (
             (disposition.disposition_kind IN ('Integrated', 'UnknownQuarantined')
              AND EXISTS (
                  SELECT 1 FROM active_worker_leases active
                  WHERE active.lease_id = disposition.worker_lease_id
                    AND active.lease_epoch = disposition.lease_epoch
              ))
             OR
             (disposition.disposition_kind NOT IN ('Integrated', 'UnknownQuarantined')
              AND NOT EXISTS (
                  SELECT 1 FROM active_worker_leases active
                  WHERE active.lease_id = disposition.worker_lease_id
              ))
         )
     )
BEGIN
    SELECT RAISE(ABORT, 'disposition event must close exact v15 disposition, release, and task transition authority');
END;

CREATE TRIGGER sprint_unknown_terminalization_pending_validate
BEFORE INSERT ON sprint_unknown_terminalization_pending
WHEN NOT EXISTS (
       SELECT 1
       FROM task_attempt_dispositions disposition
       WHERE disposition.disposition_id = NEW.first_disposition_id
         AND disposition.attempt_id = NEW.first_attempt_id
         AND disposition.sprint_id = NEW.sprint_id
         AND disposition.disposition_kind IN ('UnknownCleaned', 'UnknownQuarantined')
         AND disposition.contract_version = NEW.contract_version
         AND disposition.disposed_at_unix_ms = NEW.pending_at_unix_ms
     )
 OR json_valid(CAST(NEW.marker_json AS TEXT)) = 0
 OR json_extract(CAST(NEW.marker_json AS TEXT), '$.contract_version') != NEW.contract_version
 OR json_extract(CAST(NEW.marker_json AS TEXT), '$.marker_id') != NEW.marker_id
 OR json_extract(CAST(NEW.marker_json AS TEXT), '$.sprint_id') != NEW.sprint_id
 OR json_extract(CAST(NEW.marker_json AS TEXT), '$.first_attempt_id') != NEW.first_attempt_id
 OR json_extract(CAST(NEW.marker_json AS TEXT), '$.first_disposition_id') != NEW.first_disposition_id
 OR json_extract(CAST(NEW.marker_json AS TEXT), '$.created_at_unix_ms') != NEW.pending_at_unix_ms
 OR CAST(NEW.marker_json AS TEXT) != CAST(json_object(
       'contract_version', NEW.contract_version,
       'marker_id', NEW.marker_id,
       'sprint_id', NEW.sprint_id,
       'first_attempt_id', NEW.first_attempt_id,
       'first_disposition_id', NEW.first_disposition_id,
       'created_at_unix_ms', NEW.pending_at_unix_ms
    ) AS TEXT)
BEGIN
    SELECT RAISE(ABORT, 'unknown-terminalization marker requires its exact first unknown disposition');
END;

CREATE TRIGGER sprint_unknown_terminalization_closure_requirement_validate
BEFORE INSERT ON sprint_unknown_terminalization_closure_requirements
WHEN NEW.terminal_evidence_id != NEW.terminal_event_id
 OR NOT EXISTS (
      SELECT 1
      FROM sprint_unknown_terminalization_pending pending
      LEFT JOIN sprint_unknown_terminalization_closures closure
        ON closure.marker_id = pending.marker_id
      WHERE pending.marker_id = NEW.marker_id
        AND pending.sprint_id = NEW.sprint_id
        AND pending.contract_version = NEW.contract_version
        AND pending.pending_at_unix_ms <= NEW.closed_at_unix_ms
        AND closure.marker_id IS NULL
    )
 OR EXISTS (
      SELECT 1 FROM sprint_non_success_terminal_outcomes terminal
      WHERE terminal.sprint_id = NEW.sprint_id
         OR terminal.record_id = NEW.terminal_evidence_id
    )
BEGIN
    SELECT RAISE(ABORT, 'unknown closure requirement must reserve one exact open marker and terminal identity');
END;

CREATE TRIGGER sprint_unknown_terminal_outcome_requires_closure
BEFORE INSERT ON sprint_non_success_terminal_outcomes
WHEN NEW.terminal_state = 'Unknown'
 AND EXISTS (
      SELECT 1
      FROM sprint_unknown_terminalization_pending pending
      LEFT JOIN sprint_unknown_terminalization_closures closure
        ON closure.marker_id = pending.marker_id
      WHERE pending.sprint_id = NEW.sprint_id
        AND closure.marker_id IS NULL
    )
 AND NOT EXISTS (
      SELECT 1
      FROM sprint_unknown_terminalization_closure_requirements requirement
      JOIN sprint_unknown_terminalization_pending pending
        ON pending.marker_id = requirement.marker_id
      WHERE requirement.sprint_id = NEW.sprint_id
        AND requirement.terminal_evidence_id = NEW.record_id
        AND requirement.terminal_event_id = NEW.terminal_event_id
        AND requirement.contract_version = NEW.contract_version
        AND requirement.closed_at_unix_ms = NEW.terminal_at_unix_ms
        AND pending.sprint_id = NEW.sprint_id
    )
BEGIN
    SELECT RAISE(ABORT, 'pending sprint Unknown requires its exact deferred marker closure');
END;

CREATE TRIGGER sprint_unknown_terminalization_closure_validate
BEFORE INSERT ON sprint_unknown_terminalization_closures
WHEN json_valid(CAST(NEW.closure_json AS TEXT)) = 0
 OR CAST(NEW.closure_json AS TEXT) != CAST(json_object(
       'marker_id', NEW.marker_id,
       'sprint_id', NEW.sprint_id,
       'terminal_evidence_id', NEW.terminal_evidence_id,
       'terminal_event_id', NEW.terminal_event_id,
       'contract_version', NEW.contract_version,
       'closed_at_unix_ms', NEW.closed_at_unix_ms
    ) AS TEXT)
 OR NOT EXISTS (
      SELECT 1
      FROM sprint_unknown_terminalization_closure_requirements requirement
      WHERE requirement.marker_id = NEW.marker_id
        AND requirement.sprint_id = NEW.sprint_id
        AND requirement.terminal_evidence_id = NEW.terminal_evidence_id
        AND requirement.terminal_event_id = NEW.terminal_event_id
        AND requirement.contract_version = NEW.contract_version
        AND requirement.closed_at_unix_ms = NEW.closed_at_unix_ms
    )
 OR NOT EXISTS (
       SELECT 1
       FROM sprint_unknown_terminalization_pending pending
       JOIN sprint_non_success_terminal_outcomes terminal
         ON terminal.record_id = NEW.terminal_evidence_id
       WHERE pending.marker_id = NEW.marker_id
         AND pending.sprint_id = NEW.sprint_id
         AND terminal.sprint_id = NEW.sprint_id
         AND terminal.terminal_state = 'Unknown'
         AND terminal.terminal_event_id = NEW.terminal_event_id
         AND terminal.contract_version = NEW.contract_version
         AND terminal.terminal_at_unix_ms = NEW.closed_at_unix_ms
         AND NEW.closed_at_unix_ms >= pending.pending_at_unix_ms
     )
 OR EXISTS (
       SELECT 1
       FROM active_worker_leases active
       LEFT JOIN task_attempt_dispositions disposition
              ON disposition.worker_lease_id = active.lease_id
       WHERE active.sprint_id = NEW.sprint_id
         AND (
             disposition.disposition_kind IS NULL
             OR disposition.disposition_kind NOT IN ('UnknownQuarantined', 'Integrated')
         )
     )
 OR EXISTS (
       SELECT 1
       FROM task_attempts attempt
       LEFT JOIN task_attempt_dispositions disposition
              ON disposition.attempt_id = attempt.attempt_id
       LEFT JOIN task_attempt_legacy_classifications legacy
              ON legacy.attempt_id = attempt.attempt_id
       WHERE attempt.sprint_id = NEW.sprint_id
         AND disposition.attempt_id IS NULL
         AND legacy.attempt_id IS NULL
     )
 OR EXISTS (
       SELECT 1
       FROM task_attempt_dispositions disposition
       JOIN active_worker_leases active
         ON active.lease_id = disposition.worker_lease_id
       WHERE disposition.sprint_id = NEW.sprint_id
         AND disposition.disposition_kind NOT IN ('UnknownQuarantined', 'Integrated')
     )
 OR EXISTS (
       SELECT 1
       FROM task_attempt_uncovered_uncertain_authorities uncovered
       WHERE uncovered.sprint_id = NEW.sprint_id
     )
BEGIN
    SELECT RAISE(ABORT, 'unknown-terminalization closure requires exact sprint Unknown, active quarantine matrix, and complete uncertain-authority coverage');
END;

-- Successful completion is a computed predicate over the whole attempt
-- history.  A caller cannot complete merely by presenting an otherwise valid
-- completion receipt while an attempt is open, retry history is malformed,
-- authority remains active/unknown, or migration diagnosed an unsafe legacy
-- or over-budget history.
CREATE TRIGGER sprint_completion_task_attempt_predicate
BEFORE INSERT ON sprint_completion_proof_states
WHEN NEW.proof_state = 'ProvenV9'
 AND (
    EXISTS (
        SELECT 1 FROM active_worker_leases active
        WHERE active.sprint_id = NEW.sprint_id
    )
    OR EXISTS (
        SELECT 1
        FROM sprint_unknown_terminalization_pending pending
        LEFT JOIN sprint_unknown_terminalization_closures closure
          ON closure.marker_id = pending.marker_id
        WHERE pending.sprint_id = NEW.sprint_id
          AND closure.marker_id IS NULL
    )
    OR EXISTS (
        SELECT 1
        FROM task_attempts attempt
        LEFT JOIN task_attempt_dispositions disposition
          ON disposition.attempt_id = attempt.attempt_id
        WHERE attempt.sprint_id = NEW.sprint_id
          AND attempt.schema_generation = 15
          AND disposition.attempt_id IS NULL
    )
    OR EXISTS (
        SELECT 1
        FROM task_attempts attempt
        JOIN sprints sprint ON sprint.sprint_id = attempt.sprint_id
        WHERE attempt.sprint_id = NEW.sprint_id
          AND attempt.schema_generation = 15
        GROUP BY attempt.sprint_id, attempt.task_id
        HAVING COUNT(*) > json_extract(
            CAST(sprint.spec_json AS TEXT), '$.budget.max_attempts_per_task'
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
        WHERE attempt.sprint_id = NEW.sprint_id
          AND attempt.schema_generation = 15
          AND attempt.attempt_ordinal = (
              SELECT MAX(latest.attempt_ordinal)
              FROM task_attempts latest
              WHERE latest.sprint_id = attempt.sprint_id
                AND latest.task_id = attempt.task_id
                AND latest.schema_generation = 15
          )
          AND (
              disposition.disposition_kind != 'Integrated'
              OR NOT EXISTS (
                  SELECT 1
                  FROM v9_completion_task_integration_receipts link
                  WHERE link.completion_receipt_id = NEW.completion_receipt_id
                    AND link.sprint_id = NEW.sprint_id
                    AND link.integration_receipt_id = disposition.integration_receipt_id
              )
          )
    )
    OR EXISTS (
        SELECT 1
        FROM task_attempts attempt
        LEFT JOIN task_attempt_legacy_classifications legacy
          ON legacy.attempt_id = attempt.attempt_id
        WHERE attempt.sprint_id = NEW.sprint_id
          AND attempt.schema_generation = 14
          AND (
              legacy.attempt_id IS NULL
              OR legacy.classification != 'LegacyIntegratedReleased'
              OR legacy.budget_classification != 'WithinBudget'
          )
    )
 )
BEGIN
    SELECT RAISE(ABORT, 'completion requires exact closed attempt history with latest Integrated and zero active or uncertain authority');
END;
