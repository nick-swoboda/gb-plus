-- Schema v34 makes current final-verification admission operational without
-- reinterpreting or widening any schema-v32 row. A v32 attempt is operational
-- only when one exact event and one exact overlay are committed with it.

CREATE TABLE current_final_verification_events_v34 (
    sprint_id TEXT NOT NULL CHECK (length(CAST(sprint_id AS BLOB)) BETWEEN 1 AND 256),
    event_sequence INTEGER NOT NULL CHECK (event_sequence > 0),
    event_id TEXT NOT NULL UNIQUE CHECK (length(event_id) = 64),
    event_version INTEGER NOT NULL CHECK (event_version = 1),
    event_kind TEXT NOT NULL CHECK (event_kind IN (
        'AttemptAdmitted', 'LaunchCommitted', 'CaptureAcquired',
        'V13Initialized', 'CommandDispatched', 'ControlIssued',
        'ControlObserved', 'ControlReconciled', 'TerminalObserved',
        'EffectCutObserved', 'OutputCustodyClosed',
        'CommandDomainCleanupObserved', 'RunnerDirectChildObserved',
        'RunnerDomainObserved', 'RunnerCleanupClosed', 'EvidenceClosed',
        'OutcomeDerived'
    )),
    attempt_id TEXT NOT NULL CHECK (length(CAST(attempt_id AS BLOB)) BETWEEN 1 AND 256),
    request_id TEXT NOT NULL CHECK (length(CAST(request_id AS BLOB)) BETWEEN 1 AND 256),
    request_digest TEXT NOT NULL CHECK (length(request_digest) = 64),
    occurred_at_unix_ms INTEGER NOT NULL CHECK (occurred_at_unix_ms > 0),
    event_digest TEXT NOT NULL UNIQUE CHECK (length(event_digest) = 64),
    event_json BLOB NOT NULL CHECK (length(event_json) BETWEEN 1 AND 1048576),
    PRIMARY KEY (sprint_id, event_sequence),
    UNIQUE (attempt_id, event_kind),
    FOREIGN KEY (sprint_id, attempt_id)
        REFERENCES current_final_verification_attempts_v32(sprint_id, attempt_id)
        ON DELETE RESTRICT,
    FOREIGN KEY (request_id)
        REFERENCES current_final_verification_attempts_v32(request_id) ON DELETE RESTRICT,
    CHECK (grok_current_final_verification_event_v34_canonical(event_json) = 1),
    CHECK (grok_current_final_verification_event_v34_digest(event_json) = event_digest)
) STRICT, WITHOUT ROWID;

CREATE TABLE current_final_verification_operational_attempts_v34 (
    attempt_id TEXT PRIMARY KEY NOT NULL CHECK (length(CAST(attempt_id AS BLOB)) BETWEEN 1 AND 256),
    operational_version INTEGER NOT NULL CHECK (operational_version = 1),
    sprint_id TEXT NOT NULL CHECK (length(CAST(sprint_id AS BLOB)) BETWEEN 1 AND 256),
    attempt_ordinal INTEGER NOT NULL CHECK (attempt_ordinal BETWEEN 1 AND 3),
    final_verification_admission_id TEXT NOT NULL UNIQUE
        CHECK (length(CAST(final_verification_admission_id AS BLOB)) BETWEEN 1 AND 256),
    attempt_authority_digest TEXT NOT NULL UNIQUE CHECK (length(attempt_authority_digest) = 64),
    diagnostic_v32_admission_event_id TEXT NOT NULL
        CHECK (length(CAST(diagnostic_v32_admission_event_id AS BLOB)) BETWEEN 1 AND 256),
    diagnostic_v32_admission_event_sequence INTEGER NOT NULL
        CHECK (diagnostic_v32_admission_event_sequence BETWEEN 1 AND 3),
    request_id TEXT NOT NULL UNIQUE CHECK (length(CAST(request_id AS BLOB)) BETWEEN 1 AND 256),
    request_digest TEXT NOT NULL UNIQUE CHECK (length(request_digest) = 64),
    admission_event_id TEXT NOT NULL UNIQUE CHECK (length(admission_event_id) = 64),
    admission_event_sequence INTEGER NOT NULL CHECK (admission_event_sequence > 0),
    sprint_spec_digest TEXT NOT NULL CHECK (length(sprint_spec_digest) = 64),
    task_graph_id TEXT NOT NULL CHECK (length(CAST(task_graph_id AS BLOB)) BETWEEN 1 AND 256),
    task_graph_digest TEXT NOT NULL CHECK (length(task_graph_digest) = 64),
    task_graph_payload_digest TEXT NOT NULL CHECK (length(task_graph_payload_digest) = 64),
    repair_slot_reserve_digest TEXT NOT NULL CHECK (length(repair_slot_reserve_digest) = 64),
    input_snapshot TEXT NOT NULL CHECK (length(input_snapshot) = 64),
    complete_task_done_set_digest TEXT NOT NULL CHECK (length(complete_task_done_set_digest) = 64),
    complete_criterion_evidence_set_digest TEXT NOT NULL
        CHECK (length(complete_criterion_evidence_set_digest) = 64),
    workspace_grant_hash TEXT NOT NULL CHECK (length(workspace_grant_hash) = 64),
    verification_command_digest TEXT NOT NULL CHECK (length(verification_command_digest) = 64),
    execution_policy_digest TEXT NOT NULL CHECK (length(execution_policy_digest) = 64),
    coordinator_instance_id TEXT NOT NULL
        CHECK (length(CAST(coordinator_instance_id AS BLOB)) BETWEEN 1 AND 256),
    admitted_at_unix_ms INTEGER NOT NULL CHECK (admitted_at_unix_ms > 0),
    operational_attempt_digest TEXT NOT NULL UNIQUE
        CHECK (length(operational_attempt_digest) = 64),
    operational_json BLOB NOT NULL CHECK (length(operational_json) BETWEEN 1 AND 1048576),
    UNIQUE (sprint_id, attempt_id),
    UNIQUE (sprint_id, attempt_ordinal),
    FOREIGN KEY (sprint_id, attempt_id)
        REFERENCES current_final_verification_attempts_v32(sprint_id, attempt_id)
        ON DELETE RESTRICT,
    FOREIGN KEY (request_id)
        REFERENCES current_final_verification_attempts_v32(request_id) ON DELETE RESTRICT,
    FOREIGN KEY (final_verification_admission_id)
        REFERENCES current_final_verification_attempts_v32(final_verification_admission_id)
        ON DELETE RESTRICT,
    FOREIGN KEY (attempt_authority_digest)
        REFERENCES current_final_verification_attempts_v32(authority_digest) ON DELETE RESTRICT,
    FOREIGN KEY (admission_event_id)
        REFERENCES current_final_verification_events_v34(event_id) ON DELETE RESTRICT,
    FOREIGN KEY (sprint_spec_digest)
        REFERENCES current_sprint_authorities_v32(sprint_spec_digest) ON DELETE RESTRICT,
    FOREIGN KEY (task_graph_id)
        REFERENCES current_task_graph_authorities_v32(graph_id) ON DELETE RESTRICT,
    FOREIGN KEY (task_graph_digest)
        REFERENCES current_task_graph_authorities_v32(graph_digest) ON DELETE RESTRICT,
    FOREIGN KEY (complete_task_done_set_digest)
        REFERENCES current_task_done_set_seals_v32(set_digest) ON DELETE RESTRICT,
    FOREIGN KEY (complete_criterion_evidence_set_digest)
        REFERENCES current_criterion_evidence_set_seals_v32(set_digest) ON DELETE RESTRICT,
    CHECK (grok_current_final_verification_operational_attempt_v34_canonical(operational_json) = 1),
    CHECK (
        grok_current_final_verification_operational_attempt_v34_digest(operational_json)
        = operational_attempt_digest
    )
) STRICT, WITHOUT ROWID;

CREATE TRIGGER current_final_verification_events_v34_validate_insert
BEFORE INSERT ON current_final_verification_events_v34
WHEN grok_current_final_verification_operational_write_admitted_v34(
         'event', NEW.attempt_id, NEW.event_digest
     ) != 1
  OR NEW.event_kind != 'AttemptAdmitted'
  OR json_extract(CAST(NEW.event_json AS TEXT), '$.event_version') != NEW.event_version
  OR json_extract(CAST(NEW.event_json AS TEXT), '$.event_id') != NEW.event_id
  OR json_extract(CAST(NEW.event_json AS TEXT), '$.sprint_id') != NEW.sprint_id
  OR json_extract(CAST(NEW.event_json AS TEXT), '$.event_sequence') != NEW.event_sequence
  OR CASE json_extract(CAST(NEW.event_json AS TEXT), '$.event_kind')
       WHEN 'attempt_admitted' THEN 'AttemptAdmitted'
       WHEN 'launch_committed' THEN 'LaunchCommitted'
       WHEN 'capture_acquired' THEN 'CaptureAcquired'
       WHEN 'v13_initialized' THEN 'V13Initialized'
       WHEN 'command_dispatched' THEN 'CommandDispatched'
       WHEN 'control_issued' THEN 'ControlIssued'
       WHEN 'control_observed' THEN 'ControlObserved'
       WHEN 'control_reconciled' THEN 'ControlReconciled'
       WHEN 'terminal_observed' THEN 'TerminalObserved'
       WHEN 'effect_cut_observed' THEN 'EffectCutObserved'
       WHEN 'output_custody_closed' THEN 'OutputCustodyClosed'
       WHEN 'command_domain_cleanup_observed' THEN 'CommandDomainCleanupObserved'
       WHEN 'runner_direct_child_observed' THEN 'RunnerDirectChildObserved'
       WHEN 'runner_domain_observed' THEN 'RunnerDomainObserved'
       WHEN 'runner_cleanup_closed' THEN 'RunnerCleanupClosed'
       WHEN 'evidence_closed' THEN 'EvidenceClosed'
       WHEN 'outcome_derived' THEN 'OutcomeDerived'
       ELSE NULL
     END != NEW.event_kind
  OR json_extract(CAST(NEW.event_json AS TEXT), '$.attempt_id') != NEW.attempt_id
  OR json_extract(CAST(NEW.event_json AS TEXT), '$.request_id') != NEW.request_id
  OR json_extract(CAST(NEW.event_json AS TEXT), '$.request_digest') != NEW.request_digest
  OR json_extract(CAST(NEW.event_json AS TEXT), '$.occurred_at_unix_ms') != NEW.occurred_at_unix_ms
  OR json_extract(CAST(NEW.event_json AS TEXT), '$.event_digest') != NEW.event_digest
  OR NOT EXISTS (
      SELECT 1
      FROM current_final_verification_attempts_v32 attempt
      WHERE attempt.sprint_id = NEW.sprint_id
        AND attempt.attempt_id = NEW.attempt_id
        AND attempt.request_id = NEW.request_id
        AND attempt.request_digest = NEW.request_digest
        AND attempt.admitted_at_unix_ms = NEW.occurred_at_unix_ms
  )
BEGIN SELECT RAISE(ABORT, 'current final-verification event requires exact fresh operational admission'); END;

CREATE TRIGGER current_final_verification_events_v34_monotonic_sequence
BEFORE INSERT ON current_final_verification_events_v34
WHEN NEW.event_sequence != COALESCE(
    (
        SELECT MAX(event_sequence) + 1
        FROM current_final_verification_events_v34
        WHERE sprint_id = NEW.sprint_id
    ),
    1
)
BEGIN SELECT RAISE(ABORT, 'current final-verification event sequence must be contiguous'); END;

CREATE TRIGGER current_final_verification_operational_attempts_v34_validate_insert
BEFORE INSERT ON current_final_verification_operational_attempts_v34
WHEN grok_current_final_verification_operational_write_admitted_v34(
         'operational-attempt', NEW.attempt_id, NEW.operational_attempt_digest
     ) != 1
  OR NEW.attempt_ordinal != 1
  OR NOT EXISTS (
      SELECT 1
      FROM current_final_verification_attempts_v32 attempt
      JOIN current_sprint_authorities_v32 sprint
        ON sprint.sprint_id = attempt.sprint_id
      JOIN current_task_graph_authorities_v32 graph
        ON graph.sprint_id = attempt.sprint_id
      JOIN current_task_done_set_seals_v32 task_set
        ON task_set.set_digest = attempt.complete_task_done_set_digest
       AND task_set.sprint_id = attempt.sprint_id
       AND task_set.snapshot_digest = attempt.input_snapshot
      JOIN current_criterion_evidence_set_seals_v32 criterion_set
        ON criterion_set.set_digest = attempt.complete_criterion_evidence_set_digest
       AND criterion_set.sprint_id = attempt.sprint_id
       AND criterion_set.snapshot_digest = attempt.input_snapshot
      JOIN current_final_verification_events_v34 event
        ON event.event_id = NEW.admission_event_id
       AND event.sprint_id = attempt.sprint_id
       AND event.attempt_id = attempt.attempt_id
       AND event.event_sequence = NEW.admission_event_sequence
       AND event.event_kind = 'AttemptAdmitted'
       AND event.request_id = attempt.request_id
       AND event.request_digest = attempt.request_digest
      WHERE attempt.attempt_id = NEW.attempt_id
        AND attempt.sprint_id = NEW.sprint_id
        AND attempt.attempt_ordinal = NEW.attempt_ordinal
        AND attempt.final_verification_admission_id = NEW.final_verification_admission_id
        AND attempt.authority_digest = NEW.attempt_authority_digest
        AND attempt.request_id = NEW.request_id
        AND attempt.request_digest = NEW.request_digest
        AND attempt.input_snapshot = NEW.input_snapshot
        AND attempt.complete_task_done_set_digest = NEW.complete_task_done_set_digest
        AND attempt.complete_criterion_evidence_set_digest = NEW.complete_criterion_evidence_set_digest
        AND attempt.admitted_at_unix_ms = NEW.admitted_at_unix_ms
        AND sprint.sprint_spec_digest = NEW.sprint_spec_digest
        AND sprint.task_graph_id = NEW.task_graph_id
        AND sprint.task_graph_payload_digest = NEW.task_graph_payload_digest
        AND sprint.repair_slot_reserve_digest = NEW.repair_slot_reserve_digest
        AND sprint.workspace_grant_hash = NEW.workspace_grant_hash
        AND graph.graph_id = NEW.task_graph_id
        AND graph.graph_digest = NEW.task_graph_digest
        AND graph.graph_payload_digest = NEW.task_graph_payload_digest
        AND graph.repair_slot_reserve_digest = NEW.repair_slot_reserve_digest
        AND grok_current_final_verification_operational_attempt_v34_matches(
            NEW.operational_json, event.event_json, attempt.authority_json,
            attempt.request_json, sprint.spec_json, graph.graph_json
        ) = 1
  )
  OR EXISTS (
      SELECT 1
      FROM current_final_verification_attempts_v32 prior
      WHERE prior.sprint_id = NEW.sprint_id
        AND prior.attempt_id != NEW.attempt_id
  )
BEGIN SELECT RAISE(ABORT, 'current final-verification operational attempt crosses exact current authority or violates first-only T0 admission'); END;

CREATE TRIGGER current_final_verification_events_v34_no_update
BEFORE UPDATE ON current_final_verification_events_v34
BEGIN SELECT RAISE(ABORT, 'current final-verification events are append-only'); END;

CREATE TRIGGER current_final_verification_events_v34_no_delete
BEFORE DELETE ON current_final_verification_events_v34
BEGIN SELECT RAISE(ABORT, 'current final-verification events are append-only'); END;

CREATE TRIGGER current_final_verification_operational_attempts_v34_no_update
BEFORE UPDATE ON current_final_verification_operational_attempts_v34
BEGIN SELECT RAISE(ABORT, 'current final-verification operational attempts are immutable'); END;

CREATE TRIGGER current_final_verification_operational_attempts_v34_no_delete
BEFORE DELETE ON current_final_verification_operational_attempts_v34
BEGIN SELECT RAISE(ABORT, 'current final-verification operational attempts are immutable'); END;

-- Explicit guards precede SQLite conflict handling, including REPLACE with
-- recursive triggers disabled. Every primary and alternate unique identity is
-- listed independently of child-FK side effects.
CREATE TRIGGER current_final_verification_events_v34_no_replace
BEFORE INSERT ON current_final_verification_events_v34
WHEN EXISTS (
    SELECT 1 FROM current_final_verification_events_v34 existing
    WHERE (existing.sprint_id = NEW.sprint_id
           AND existing.event_sequence = NEW.event_sequence)
       OR existing.event_id = NEW.event_id
       OR existing.event_digest = NEW.event_digest
       OR (existing.attempt_id = NEW.attempt_id
           AND existing.event_kind = NEW.event_kind)
)
BEGIN SELECT RAISE(ABORT, 'current final-verification event identity already exists'); END;

CREATE TRIGGER current_final_verification_operational_attempts_v34_no_replace
BEFORE INSERT ON current_final_verification_operational_attempts_v34
WHEN EXISTS (
    SELECT 1 FROM current_final_verification_operational_attempts_v34 existing
    WHERE existing.attempt_id = NEW.attempt_id
       OR existing.final_verification_admission_id = NEW.final_verification_admission_id
       OR existing.attempt_authority_digest = NEW.attempt_authority_digest
       OR existing.request_id = NEW.request_id
       OR existing.request_digest = NEW.request_digest
       OR existing.admission_event_id = NEW.admission_event_id
       OR existing.operational_attempt_digest = NEW.operational_attempt_digest
       OR (existing.sprint_id = NEW.sprint_id AND existing.attempt_id = NEW.attempt_id)
       OR (existing.sprint_id = NEW.sprint_id
           AND existing.attempt_ordinal = NEW.attempt_ordinal)
)
BEGIN SELECT RAISE(ABORT, 'current final-verification operational-attempt identity already exists'); END;
