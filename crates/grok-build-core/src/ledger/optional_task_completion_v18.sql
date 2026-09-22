-- Schema v18 corrects the successful-completion attempt predicate for
-- optional graph tasks. Required tasks still need their exact latest
-- Integrated disposition linked by the completion receipt. An unattempted
-- optional task contributes no finish obligation. Once an optional task has
-- acquired attempt authority, however, its complete history must be closed
-- and its latest disposition must be a safe terminal outcome. Optional
-- Integrated work may be omitted from the required-task integration chain
-- only when its represented ChangeSet is an exact verified no-op.
DROP TRIGGER sprint_completion_task_attempt_predicate;

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
          AND EXISTS (
              SELECT 1
              FROM sprint_task_graphs graph,
                   json_each(CAST(graph.graph_json AS TEXT), '$.tasks') graph_task
              WHERE graph.sprint_id = NEW.sprint_id
                AND json_extract(graph_task.value, '$.task_id') = attempt.task_id
                AND json_extract(graph_task.value, '$.required') = 1
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
        WHERE attempt.sprint_id = NEW.sprint_id
          AND attempt.schema_generation = 15
          AND NOT EXISTS (
              SELECT 1
              FROM sprint_task_graphs graph,
                   json_each(CAST(graph.graph_json AS TEXT), '$.tasks') graph_task
              WHERE graph.sprint_id = NEW.sprint_id
                AND json_extract(graph_task.value, '$.task_id') = attempt.task_id
          )
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
          AND EXISTS (
              SELECT 1
              FROM sprint_task_graphs graph,
                   json_each(CAST(graph.graph_json AS TEXT), '$.tasks') graph_task
              WHERE graph.sprint_id = NEW.sprint_id
                AND json_extract(graph_task.value, '$.task_id') = attempt.task_id
                AND json_extract(graph_task.value, '$.required') = 0
          )
          AND (
              disposition.disposition_kind NOT IN (
                  'Integrated', 'AttemptsExhausted', 'PermanentFailure',
                  'Blocked', 'Canceled'
              )
              OR (
                  disposition.disposition_kind = 'Integrated'
                  AND NOT EXISTS (
                      SELECT 1
                      FROM task_integration_receipts integration
                      JOIN change_sets change_set
                        ON change_set.sprint_id = integration.sprint_id
                       AND change_set.change_set_id = integration.change_set_id
                      WHERE integration.sprint_id = NEW.sprint_id
                        AND integration.receipt_id = disposition.integration_receipt_id
                        AND integration.input_snapshot = integration.result_snapshot
                        AND change_set.base_snapshot = change_set.result_snapshot
                        AND change_set.base_snapshot = integration.input_snapshot
                        AND json_type(
                            CAST(change_set.change_set_json AS TEXT), '$.operations'
                        ) = 'array'
                        AND json_array_length(
                            CAST(change_set.change_set_json AS TEXT), '$.operations'
                        ) = 0
                  )
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
    SELECT RAISE(ABORT, 'completion requires exact required TaskDone links and safely closed attempted optional tasks');
END;
