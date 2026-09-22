-- Schema v17 closes the stale fresh-permit race by making the point at which
-- an ordinary runner effect may enter transport durable and immutable.  The
-- opaque transport digest authenticates bytes supplied by the owning adapter;
-- it deliberately does not make the core ledger interpret runner protocol.
CREATE TABLE runner_effect_dispatch_claims (
    dispatch_claim_id TEXT PRIMARY KEY NOT NULL CHECK (length(dispatch_claim_id) > 0),
    effect_id TEXT NOT NULL UNIQUE,
    sprint_id TEXT NOT NULL,
    launch_id TEXT NOT NULL,
    session_id TEXT NOT NULL,
    running_boundary_id TEXT,
    request_digest TEXT NOT NULL CHECK (
        length(request_digest) = 64
        AND request_digest NOT GLOB '*[^0-9a-f]*'
    ),
    opaque_transport_request_digest TEXT NOT NULL CHECK (
        length(opaque_transport_request_digest) = 64
        AND opaque_transport_request_digest NOT GLOB '*[^0-9a-f]*'
    ),
    policy_hash TEXT NOT NULL CHECK (
        length(policy_hash) = 64
        AND policy_hash NOT GLOB '*[^0-9a-f]*'
    ),
    input_snapshot TEXT NOT NULL CHECK (
        length(input_snapshot) = 64
        AND input_snapshot NOT GLOB '*[^0-9a-f]*'
    ),
    contract_version INTEGER NOT NULL CHECK (contract_version > 0),
    UNIQUE (sprint_id, effect_id),
    FOREIGN KEY (sprint_id, effect_id)
        REFERENCES effect_intents(sprint_id, effect_id) ON DELETE RESTRICT,
    FOREIGN KEY (sprint_id, launch_id)
        REFERENCES runner_launch_intents(sprint_id, launch_id) ON DELETE RESTRICT,
    FOREIGN KEY (sprint_id, session_id)
        REFERENCES runner_session_policies(sprint_id, session_id) ON DELETE RESTRICT,
    FOREIGN KEY (running_boundary_id)
        REFERENCES task_attempt_running_boundaries(boundary_id) ON DELETE RESTRICT
) STRICT, WITHOUT ROWID;

CREATE INDEX runner_effect_dispatch_claims_session_idx
ON runner_effect_dispatch_claims (sprint_id, session_id, effect_id);

CREATE TRIGGER runner_effect_dispatch_claims_identity_match
BEFORE INSERT ON runner_effect_dispatch_claims
WHEN NOT EXISTS (
    SELECT 1
    FROM effect_intents intent
    JOIN effect_session_bindings binding
      ON binding.effect_id = intent.effect_id
     AND binding.sprint_id = intent.sprint_id
    JOIN runner_launch_intents launch
      ON launch.launch_id = binding.launch_id
     AND launch.sprint_id = binding.sprint_id
    JOIN runner_session_policies session
      ON session.session_id = binding.session_id
     AND session.sprint_id = binding.sprint_id
     AND session.launch_id = binding.launch_id
    JOIN runner_launch_cleanup_admissions cleanup
      ON cleanup.launch_id = launch.launch_id
     AND cleanup.sprint_id = launch.sprint_id
     AND cleanup.session_id = session.session_id
    LEFT JOIN effect_observations cleanup_observation
      ON cleanup_observation.effect_id = cleanup.cleanup_effect_id
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
      AND (
          (
              session.purpose = 'TaskWorker'
              AND NEW.running_boundary_id IS NOT NULL
              AND EXISTS (
                  SELECT 1
                  FROM task_attempt_running_boundaries running
                  JOIN task_attempts attempt
                    ON attempt.attempt_id = running.attempt_id
                  JOIN active_worker_leases active
                    ON active.lease_id = attempt.worker_lease_id
                  WHERE running.boundary_id = NEW.running_boundary_id
                    AND running.sprint_id = NEW.sprint_id
                    AND running.runner_launch_id = NEW.launch_id
                    AND running.runner_session_id = NEW.session_id
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
                    AND NOT EXISTS (
                        SELECT 1 FROM task_attempt_dispositions disposition
                        WHERE disposition.attempt_id = attempt.attempt_id
                    )
                    AND NOT EXISTS (
                        SELECT 1 FROM worker_lease_releases release
                        WHERE release.lease_id = attempt.worker_lease_id
                    )
                    AND COALESCE((
                        SELECT json_extract(
                                   CAST(event.event_json AS TEXT),
                                   '$.payload.TaskStateChanged.to'
                               )
                        FROM agent_events event
                        WHERE event.sprint_id = NEW.sprint_id
                          AND json_extract(
                                  CAST(event.event_json AS TEXT), '$.task_id'
                              ) = intent.task_id
                          AND json_type(
                                  CAST(event.event_json AS TEXT),
                                  '$.payload.TaskStateChanged'
                              ) = 'object'
                        ORDER BY event.sequence DESC
                        LIMIT 1
                    ), '') = 'Running'
                    AND intent.effect_kind IN (
                        'ReadRelativeFile', 'SearchLiteral', 'RunCommand',
                        'CreateRegularFile', 'ReplaceRegularFile',
                        'DeleteRegularFile'
                    )
              )
          )
          OR (
              session.purpose IN ('FinalVerifier', 'Applier')
              AND NEW.running_boundary_id IS NULL
              AND intent.task_id IS NULL
              AND intent.worker_id IS NULL
              AND intent.worker_lease_id IS NULL
              AND intent.worker_lease_epoch IS NULL
          )
      )
)
BEGIN SELECT RAISE(ABORT, 'runner dispatch claim must match one exact ordinary runner authority'); END;

CREATE TRIGGER runner_effect_dispatch_claims_require_pristine_effect
BEFORE INSERT ON runner_effect_dispatch_claims
WHEN EXISTS (
    SELECT 1 FROM effect_observations
    WHERE effect_id = NEW.effect_id
)
OR EXISTS (
    SELECT 1 FROM sprint_terminal_states
    WHERE sprint_id = NEW.sprint_id
)
OR EXISTS (
    SELECT 1 FROM sprint_non_success_terminal_outcomes
    WHERE sprint_id = NEW.sprint_id
)
BEGIN SELECT RAISE(ABORT, 'runner dispatch claim requires a pristine nonterminal effect'); END;

CREATE TRIGGER runner_effect_dispatch_claims_no_update
BEFORE UPDATE ON runner_effect_dispatch_claims
BEGIN SELECT RAISE(ABORT, 'runner dispatch claims are immutable'); END;

CREATE TRIGGER runner_effect_dispatch_claims_no_delete
BEFORE DELETE ON runner_effect_dispatch_claims
BEGIN SELECT RAISE(ABORT, 'runner dispatch claims are immutable'); END;

ALTER TABLE effect_observations
ADD COLUMN dispatch_claim_id TEXT
    REFERENCES runner_effect_dispatch_claims(dispatch_claim_id) ON DELETE RESTRICT;

CREATE UNIQUE INDEX effect_observations_dispatch_claim_idx
ON effect_observations (dispatch_claim_id)
WHERE dispatch_claim_id IS NOT NULL;

CREATE TRIGGER effect_observations_dispatch_claim_match
BEFORE INSERT ON effect_observations
WHEN (
    EXISTS (
        SELECT 1 FROM runner_effect_dispatch_claims claim
        WHERE claim.effect_id = NEW.effect_id
    )
    AND NEW.dispatch_claim_id IS NULL
)
OR (
    NEW.dispatch_claim_id IS NOT NULL
    AND NOT EXISTS (
        SELECT 1 FROM runner_effect_dispatch_claims claim
        WHERE claim.dispatch_claim_id = NEW.dispatch_claim_id
          AND claim.effect_id = NEW.effect_id
          AND claim.sprint_id = NEW.sprint_id
          AND claim.request_digest = NEW.request_digest
          AND claim.policy_hash = NEW.policy_hash
          AND claim.input_snapshot = NEW.input_snapshot
          AND claim.contract_version = NEW.contract_version
    )
)
BEGIN SELECT RAISE(ABORT, 'effect observation must carry its exact runner dispatch claim'); END;
