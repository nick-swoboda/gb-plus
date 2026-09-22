-- Schema v20 implements the two already-reserved task phase authorities.  It
-- replaces only insertion-time v17/v19 fences; historic claims and immutable
-- companion rows retain their original meaning.
DROP TRIGGER runner_effect_dispatch_claim_authorities_v19_runtime_shape;
DROP TRIGGER runner_effect_dispatch_claims_v19_companion_required;
DROP TRIGGER runner_effect_dispatch_claims_identity_match;
DROP TRIGGER agent_events_v19_unobserved_running_claim_phase_fence;

CREATE TRIGGER runner_effect_dispatch_claim_authorities_v20_runtime_shape
BEFORE INSERT ON runner_effect_dispatch_claim_authorities
WHEN NEW.authority_class NOT IN ('TaskRunning', 'TaskFormalCheck', 'TaskIntegration')
  OR EXISTS (
      SELECT 1 FROM runner_effect_dispatch_claims claim
      WHERE claim.dispatch_claim_id = NEW.dispatch_claim_id
  )
BEGIN SELECT RAISE(ABORT, 'v20 runtime companion must be pre-parent implemented task authority'); END;

-- The companion is inserted first under the deferred parent FK.  The parent
-- trigger below proves the exact effect/phase relationship before commit.
CREATE TRIGGER runner_effect_dispatch_claims_v20_companion_required
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
      )
)
BEGIN SELECT RAISE(ABORT, 'v20 runner dispatch claim requires exact implemented phase companion'); END;

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
      )
)
BEGIN SELECT RAISE(ABORT, 'runner dispatch claim must match one exact implemented task phase authority'); END;

CREATE TRIGGER agent_events_v20_unobserved_task_claim_phase_fence
BEFORE INSERT ON agent_events
WHEN json_type(CAST(NEW.event_json AS TEXT), '$.payload.TaskStateChanged') = 'object'
 AND json_extract(CAST(NEW.event_json AS TEXT), '$.payload.TaskStateChanged.to') != 'Unknown'
 AND EXISTS (
    SELECT 1 FROM runner_effect_dispatch_claims claim
    JOIN runner_effect_dispatch_claim_authorities authority ON authority.dispatch_claim_id = claim.dispatch_claim_id
    JOIN effect_intents intent ON intent.effect_id = claim.effect_id
    LEFT JOIN effect_observations observation ON observation.effect_id = claim.effect_id
    WHERE claim.sprint_id = NEW.sprint_id
      AND intent.task_id = json_extract(CAST(NEW.event_json AS TEXT), '$.task_id')
      AND authority.authority_class IN ('TaskRunning', 'TaskFormalCheck', 'TaskIntegration')
      AND observation.effect_id IS NULL
 )
BEGIN SELECT RAISE(ABORT, 'unobserved task dispatch claim blocks known task phase transition'); END;
