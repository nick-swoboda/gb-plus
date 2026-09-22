-- Schema v30 makes one complete schema-v29 sensitive-output rejection a
-- first-class retryable task-attempt cleanup source. The rejected output is
-- never retained: the only task evidence bytes are the exact canonical,
-- secret-free rejection anchor already authenticated by v29.

-- SQLite cannot add a CHECK alternative with ALTER TABLE. This is the
-- documented schema-text widening procedure for a change that does not alter
-- the table layout or any stored row. The exact old rows and their canonical
-- disposition_json/evidence_bytes remain byte-for-byte untouched. The schema
-- cookie forces every statement compiled after this point to reparse the
-- widened constraint, and open-time integrity/schema verification rejects any
-- malformed edit.
PRAGMA writable_schema = ON;
UPDATE sqlite_schema
   SET sql = replace(
       sql,
       '''FormalVerificationFailed'', ''CandidateRejectedKnown'',
        ''PermanentContractViolation''',
       '''FormalVerificationFailed'', ''CandidateRejectedKnown'',
        ''SensitiveOutputRejected'', ''PermanentContractViolation'''
   )
 WHERE type = 'table'
   AND name = 'task_attempt_dispositions'
   AND instr(sql, '''SensitiveOutputRejected''') = 0;
PRAGMA schema_version = 300030;
PRAGMA writable_schema = OFF;

CREATE TEMP TABLE v30_task_attempt_disposition_schema_assertion (
    safe INTEGER NOT NULL CHECK (safe = 1)
) STRICT;
INSERT INTO temp.v30_task_attempt_disposition_schema_assertion (safe)
SELECT 0
WHERE (
    SELECT length(sql) - length(replace(sql, '''SensitiveOutputRejected''', ''))
    FROM sqlite_schema
    WHERE type = 'table' AND name = 'task_attempt_dispositions'
) != 2 * length('''SensitiveOutputRejected''');
DROP TABLE temp.v30_task_attempt_disposition_schema_assertion;

-- Replace the single canonical source projection so SQL and Rust select the
-- same total-order winner. The rejection branch exists only after the full
-- v29 anchor/cleanup/closure proof view succeeds and the command effect joins
-- the exact task-attempt lease epoch.
DROP VIEW task_attempt_known_cleanup_sources;
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
           closure.closed_at_unix_ms,
           anchor.observation_id,
           'SensitiveOutputRejection'
      FROM command_output_sensitive_rejection_exact_finishes_v29 finish
      JOIN command_output_sensitive_rejection_anchors_v29 anchor
        ON anchor.effect_id = finish.effect_id
       AND anchor.rejection_anchor_digest = finish.rejection_anchor_digest
      JOIN command_output_sensitive_rejection_closures_v29 closure
        ON closure.closure_digest = finish.closure_digest
       AND closure.effect_id = anchor.effect_id
       AND closure.observation_id = anchor.observation_id
      JOIN effect_intents intent ON intent.effect_id = anchor.effect_id
      JOIN effect_observations observation
        ON observation.effect_id = anchor.effect_id
       AND observation.observation_id = anchor.observation_id
      JOIN task_attempts attempt
        ON attempt.sprint_id = intent.sprint_id
       AND attempt.task_id = intent.task_id
       AND attempt.worker_id = intent.worker_id
       AND attempt.worker_lease_id = intent.worker_lease_id
       AND attempt.lease_epoch = intent.worker_lease_epoch
       AND attempt.schema_generation = 15
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

-- The v15 exact-authority trigger remains authoritative for every older
-- variant. This additional closed trigger owns only the new typed cause and
-- therefore cannot weaken any pre-v30 row admission.
CREATE TRIGGER task_attempt_sensitive_output_rejection_disposition_exact_v30
BEFORE INSERT ON task_attempt_dispositions
WHEN NEW.cause_kind = 'SensitiveOutputRejected'
 AND (
       NEW.disposition_kind NOT IN ('Retryable', 'AttemptsExhausted')
       OR NEW.evidence_kind != 'SensitiveOutputRejected'
       OR NEW.cause_effect_id IS NULL
       OR NEW.cause_observation_id IS NULL
       OR NEW.evidence_id != NEW.cause_observation_id
       OR NEW.cause_launch_id IS NOT NULL
       OR NEW.cause_session_id IS NOT NULL
       OR NEW.cause_formal_check_id IS NOT NULL
       OR NEW.cause_candidate_boundary_id IS NOT NULL
       OR NEW.cause_authority_id IS NOT NULL
       OR NOT EXISTS (
          SELECT 1
            FROM command_output_sensitive_rejection_exact_finishes_v29 finish
            JOIN command_output_sensitive_rejection_anchors_v29 anchor
              ON anchor.effect_id = finish.effect_id
             AND anchor.rejection_anchor_digest = finish.rejection_anchor_digest
            JOIN command_output_sensitive_rejection_closures_v29 closure
              ON closure.closure_digest = finish.closure_digest
             AND closure.effect_id = anchor.effect_id
             AND closure.observation_id = anchor.observation_id
            JOIN effect_intents intent ON intent.effect_id = anchor.effect_id
            JOIN effect_observations observation
              ON observation.effect_id = anchor.effect_id
             AND observation.observation_id = anchor.observation_id
           WHERE finish.effect_id = NEW.cause_effect_id
             AND anchor.observation_id = NEW.cause_observation_id
             AND anchor.observation_id = NEW.evidence_id
             AND anchor.rejection_json = NEW.evidence_bytes
             AND anchor.effect_evidence_digest = NEW.evidence_digest
             AND anchor.contract_version = NEW.contract_version
             AND intent.sprint_id = NEW.sprint_id
             AND intent.task_id = NEW.task_id
             AND intent.worker_id = NEW.worker_id
             AND intent.worker_lease_id = NEW.worker_lease_id
             AND intent.worker_lease_epoch = NEW.lease_epoch
             AND closure.closed_at_unix_ms <= NEW.disposed_at_unix_ms
             AND observation.observed_at_unix_ms <= NEW.disposed_at_unix_ms
       )
     )
BEGIN
    SELECT RAISE(ABORT, 'sensitive-output-rejected disposition requires the exact complete v29 rejection anchor for this attempt lease');
END;

-- The existing canonical-winner trigger intentionally does not recognize a
-- future cause. This companion applies its identical rank/time/id/kind total
-- order to the new source without changing old trigger behavior.
CREATE TRIGGER task_attempt_sensitive_output_rejection_canonical_source_v30
BEFORE INSERT ON task_attempt_dispositions
WHEN NEW.cause_kind = 'SensitiveOutputRejected'
 AND NOT EXISTS (
       SELECT 1
         FROM task_attempt_known_cleanup_sources selected
        WHERE selected.attempt_id = NEW.attempt_id
          AND selected.source_id = NEW.evidence_id
          AND selected.source_kind = 'SensitiveOutputRejection'
          AND selected.source_at_unix_ms <= NEW.disposed_at_unix_ms
          AND NOT EXISTS (
              SELECT 1
                FROM task_attempt_known_cleanup_sources prior
               WHERE prior.attempt_id = NEW.attempt_id
                 AND (
                      prior.outcome_rank < selected.outcome_rank
                      OR (prior.outcome_rank = selected.outcome_rank
                          AND prior.source_at_unix_ms < selected.source_at_unix_ms)
                      OR (prior.outcome_rank = selected.outcome_rank
                          AND prior.source_at_unix_ms = selected.source_at_unix_ms
                          AND prior.source_id < selected.source_id)
                      OR (prior.outcome_rank = selected.outcome_rank
                          AND prior.source_at_unix_ms = selected.source_at_unix_ms
                          AND prior.source_id = selected.source_id
                          AND prior.source_kind < selected.source_kind)
                 )
          )
     )
BEGIN
    SELECT RAISE(ABORT, 'sensitive-output-rejected disposition is not the canonical known-cleanup source winner');
END;
