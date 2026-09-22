-- Inert current-only repair-task dormancy authority. These rows do not route
-- into the production coordinator or legacy task/lease/attempt tables.

CREATE TABLE current_repair_task_ready_events_v32 (
    event_id TEXT PRIMARY KEY NOT NULL CHECK (length(event_id) = 64),
    activation_id TEXT NOT NULL UNIQUE,
    sprint_id TEXT NOT NULL,
    task_id TEXT NOT NULL,
    slot_ordinal INTEGER NOT NULL CHECK (slot_ordinal BETWEEN 1 AND 2),
    occurred_at_unix_ms INTEGER NOT NULL CHECK (occurred_at_unix_ms > 0),
    event_json BLOB NOT NULL CHECK (length(event_json) BETWEEN 1 AND 8388608),
    UNIQUE (sprint_id, task_id),
    FOREIGN KEY (activation_id)
        REFERENCES current_final_verification_repair_activations_v32(activation_id)
        ON DELETE RESTRICT,
    FOREIGN KEY (sprint_id, task_id)
        REFERENCES current_task_nodes_v32(sprint_id, task_id) ON DELETE RESTRICT,
    CHECK (grok_current_repair_ready_event_v32_canonical(event_json) = 1)
) STRICT, WITHOUT ROWID;

CREATE TABLE current_repair_task_lease_admissions_v32 (
    lease_admission_id TEXT PRIMARY KEY NOT NULL CHECK (length(lease_admission_id) = 64),
    activation_id TEXT NOT NULL UNIQUE,
    ready_event_id TEXT NOT NULL UNIQUE,
    sprint_id TEXT NOT NULL,
    task_id TEXT NOT NULL,
    slot_ordinal INTEGER NOT NULL CHECK (slot_ordinal BETWEEN 1 AND 2),
    lease_id TEXT NOT NULL UNIQUE CHECK (length(lease_id) BETWEEN 1 AND 4096),
    lease_epoch INTEGER NOT NULL UNIQUE CHECK (lease_epoch > 0),
    worker_id TEXT NOT NULL CHECK (length(worker_id) BETWEEN 1 AND 128),
    acquired_at_unix_ms INTEGER NOT NULL CHECK (acquired_at_unix_ms > 0),
    admission_json BLOB NOT NULL CHECK (length(admission_json) BETWEEN 1 AND 8388608),
    UNIQUE (sprint_id, task_id),
    FOREIGN KEY (activation_id)
        REFERENCES current_final_verification_repair_activations_v32(activation_id)
        ON DELETE RESTRICT,
    FOREIGN KEY (ready_event_id)
        REFERENCES current_repair_task_ready_events_v32(event_id) ON DELETE RESTRICT,
    FOREIGN KEY (sprint_id, task_id)
        REFERENCES current_task_nodes_v32(sprint_id, task_id) ON DELETE RESTRICT,
    CHECK (grok_current_repair_lease_admission_v32_canonical(admission_json) = 1)
) STRICT, WITHOUT ROWID;

CREATE TABLE current_repair_task_attempt_admissions_v32 (
    attempt_admission_id TEXT PRIMARY KEY NOT NULL CHECK (length(attempt_admission_id) = 64),
    activation_id TEXT NOT NULL UNIQUE,
    ready_event_id TEXT NOT NULL UNIQUE,
    lease_admission_id TEXT NOT NULL UNIQUE,
    sprint_id TEXT NOT NULL,
    task_id TEXT NOT NULL,
    slot_ordinal INTEGER NOT NULL CHECK (slot_ordinal BETWEEN 1 AND 2),
    attempt_id TEXT NOT NULL UNIQUE CHECK (length(attempt_id) BETWEEN 1 AND 4096),
    attempt_ordinal INTEGER NOT NULL CHECK (attempt_ordinal = 1),
    admitted_at_unix_ms INTEGER NOT NULL CHECK (admitted_at_unix_ms > 0),
    admission_json BLOB NOT NULL CHECK (length(admission_json) BETWEEN 1 AND 8388608),
    UNIQUE (sprint_id, task_id),
    FOREIGN KEY (activation_id)
        REFERENCES current_final_verification_repair_activations_v32(activation_id)
        ON DELETE RESTRICT,
    FOREIGN KEY (ready_event_id)
        REFERENCES current_repair_task_ready_events_v32(event_id) ON DELETE RESTRICT,
    FOREIGN KEY (lease_admission_id)
        REFERENCES current_repair_task_lease_admissions_v32(lease_admission_id)
        ON DELETE RESTRICT,
    FOREIGN KEY (sprint_id, task_id)
        REFERENCES current_task_nodes_v32(sprint_id, task_id) ON DELETE RESTRICT,
    CHECK (grok_current_repair_attempt_admission_v32_canonical(admission_json) = 1)
) STRICT, WITHOUT ROWID;

-- SQLite's REPLACE conflict algorithm may delete a conflicting row without
-- running DELETE triggers when recursive_triggers is disabled. These guards
-- run before conflict resolution and make every unique identity insert-only,
-- both before and after dependent child rows exist.
CREATE TRIGGER current_repair_task_ready_events_v32_no_replace
BEFORE INSERT ON current_repair_task_ready_events_v32
WHEN EXISTS (
    SELECT 1 FROM current_repair_task_ready_events_v32 existing
    WHERE existing.event_id = NEW.event_id
       OR existing.activation_id = NEW.activation_id
       OR (existing.sprint_id = NEW.sprint_id AND existing.task_id = NEW.task_id)
)
BEGIN SELECT RAISE(ABORT, 'current repair Ready identity already exists'); END;

CREATE TRIGGER current_repair_task_lease_admissions_v32_no_replace
BEFORE INSERT ON current_repair_task_lease_admissions_v32
WHEN EXISTS (
    SELECT 1 FROM current_repair_task_lease_admissions_v32 existing
    WHERE existing.lease_admission_id = NEW.lease_admission_id
       OR existing.activation_id = NEW.activation_id
       OR existing.ready_event_id = NEW.ready_event_id
       OR existing.lease_id = NEW.lease_id
       OR existing.lease_epoch = NEW.lease_epoch
       OR (existing.sprint_id = NEW.sprint_id AND existing.task_id = NEW.task_id)
)
BEGIN SELECT RAISE(ABORT, 'current repair lease identity already exists'); END;

CREATE TRIGGER current_repair_task_attempt_admissions_v32_no_replace
BEFORE INSERT ON current_repair_task_attempt_admissions_v32
WHEN EXISTS (
    SELECT 1 FROM current_repair_task_attempt_admissions_v32 existing
    WHERE existing.attempt_admission_id = NEW.attempt_admission_id
       OR existing.activation_id = NEW.activation_id
       OR existing.ready_event_id = NEW.ready_event_id
       OR existing.lease_admission_id = NEW.lease_admission_id
       OR existing.attempt_id = NEW.attempt_id
       OR (existing.sprint_id = NEW.sprint_id AND existing.task_id = NEW.task_id)
)
BEGIN SELECT RAISE(ABORT, 'current repair attempt identity already exists'); END;

CREATE TRIGGER current_repair_task_ready_events_v32_validate
BEFORE INSERT ON current_repair_task_ready_events_v32
WHEN NOT EXISTS (
    SELECT 1
    FROM current_final_verification_repair_activations_v32 activation
    JOIN current_final_verification_attempts_v32 failed
      ON failed.attempt_id = activation.failed_attempt_id
     AND failed.sprint_id = activation.sprint_id
    JOIN current_task_nodes_v32 task
      ON task.sprint_id = activation.sprint_id
     AND task.task_id = activation.repair_task_id
    WHERE activation.activation_id = NEW.activation_id
      AND activation.sprint_id = NEW.sprint_id
      AND activation.repair_task_id = NEW.task_id
      AND activation.slot_ordinal = NEW.slot_ordinal
      AND task.purpose = 'FinalVerificationRepairSlot'
      AND task.repair_slot_ordinal = NEW.slot_ordinal
      AND activation.activated_at_unix_ms <= NEW.occurred_at_unix_ms
      AND json_extract(CAST(NEW.event_json AS TEXT), '$.event_id') = NEW.event_id
      AND json_extract(CAST(NEW.event_json AS TEXT), '$.activation_id') = NEW.activation_id
      AND json_extract(CAST(NEW.event_json AS TEXT), '$.sprint_id') = NEW.sprint_id
      AND json_extract(CAST(NEW.event_json AS TEXT), '$.task_id') = NEW.task_id
      AND json_extract(CAST(NEW.event_json AS TEXT), '$.slot_ordinal') = NEW.slot_ordinal
      AND json_extract(CAST(NEW.event_json AS TEXT), '$.from_state') = 'Planned'
      AND json_extract(CAST(NEW.event_json AS TEXT), '$.to_state') = 'Ready'
      AND json_extract(CAST(NEW.event_json AS TEXT), '$.occurred_at_unix_ms') = NEW.occurred_at_unix_ms
      AND NOT EXISTS (
          SELECT 1 FROM current_final_verification_repair_completions_v32 completion
          WHERE completion.activation_id = activation.activation_id
      )
      AND NOT EXISTS (
          SELECT 1 FROM current_sprint_terminal_outcomes_v32 terminal
          WHERE terminal.sprint_id = activation.sprint_id
      )
      AND NOT EXISTS (
          SELECT 1 FROM current_final_verification_attempts_v32 later
          WHERE later.sprint_id = activation.sprint_id
            AND later.attempt_ordinal > failed.attempt_ordinal
      )
)
BEGIN SELECT RAISE(ABORT, 'repair Ready requires the exact live core activation'); END;

CREATE TRIGGER current_repair_task_lease_admissions_v32_validate
BEFORE INSERT ON current_repair_task_lease_admissions_v32
WHEN NOT EXISTS (
    SELECT 1
    FROM current_repair_task_ready_events_v32 ready
    JOIN current_final_verification_repair_activations_v32 activation
      ON activation.activation_id = ready.activation_id
    JOIN current_final_verification_attempts_v32 failed
      ON failed.attempt_id = activation.failed_attempt_id
     AND failed.sprint_id = activation.sprint_id
    JOIN current_task_nodes_v32 task
      ON task.sprint_id = activation.sprint_id
     AND task.task_id = activation.repair_task_id
    WHERE ready.event_id = NEW.ready_event_id
      AND ready.activation_id = NEW.activation_id
      AND ready.sprint_id = NEW.sprint_id
      AND ready.task_id = NEW.task_id
      AND ready.slot_ordinal = NEW.slot_ordinal
      AND activation.sprint_id = NEW.sprint_id
      AND activation.repair_task_id = NEW.task_id
      AND activation.slot_ordinal = NEW.slot_ordinal
      AND task.purpose = 'FinalVerificationRepairSlot'
      AND task.repair_slot_ordinal = NEW.slot_ordinal
      AND ready.occurred_at_unix_ms <= NEW.acquired_at_unix_ms
      AND json_extract(CAST(NEW.admission_json AS TEXT), '$.lease_admission_id') = NEW.lease_admission_id
      AND json_extract(CAST(NEW.admission_json AS TEXT), '$.activation_id') = NEW.activation_id
      AND json_extract(CAST(NEW.admission_json AS TEXT), '$.ready_event_id') = NEW.ready_event_id
      AND json_extract(CAST(NEW.admission_json AS TEXT), '$.sprint_id') = NEW.sprint_id
      AND json_extract(CAST(NEW.admission_json AS TEXT), '$.task_id') = NEW.task_id
      AND json_extract(CAST(NEW.admission_json AS TEXT), '$.slot_ordinal') = NEW.slot_ordinal
      AND json_extract(CAST(NEW.admission_json AS TEXT), '$.worker_lease.lease_id') = NEW.lease_id
      AND json_extract(CAST(NEW.admission_json AS TEXT), '$.worker_lease.sprint_id') = NEW.sprint_id
      AND json_extract(CAST(NEW.admission_json AS TEXT), '$.worker_lease.task_id') = NEW.task_id
      AND json_extract(CAST(NEW.admission_json AS TEXT), '$.worker_lease.lease_epoch') = NEW.lease_epoch
      AND json_extract(CAST(NEW.admission_json AS TEXT), '$.worker_lease.worker_id') = NEW.worker_id
      AND json_extract(CAST(NEW.admission_json AS TEXT), '$.worker_lease.acquired_at_unix_ms') = NEW.acquired_at_unix_ms
      AND json_extract(CAST(NEW.admission_json AS TEXT), '$.worker_lease.path_scopes')
          = json_extract(CAST(task.task_json AS TEXT), '$.path_scopes')
      AND NOT EXISTS (
          SELECT 1 FROM current_final_verification_repair_completions_v32 completion
          WHERE completion.activation_id = activation.activation_id
      )
      AND NOT EXISTS (
          SELECT 1 FROM current_sprint_terminal_outcomes_v32 terminal
          WHERE terminal.sprint_id = activation.sprint_id
      )
      AND NOT EXISTS (
          SELECT 1 FROM current_final_verification_attempts_v32 later
          WHERE later.sprint_id = activation.sprint_id
            AND later.attempt_ordinal > failed.attempt_ordinal
      )
)
BEGIN SELECT RAISE(ABORT, 'repair lease requires exact live activation and Ready event'); END;

CREATE TRIGGER current_repair_task_attempt_admissions_v32_validate
BEFORE INSERT ON current_repair_task_attempt_admissions_v32
WHEN NOT EXISTS (
    SELECT 1
    FROM current_repair_task_lease_admissions_v32 lease
    JOIN current_repair_task_ready_events_v32 ready
      ON ready.event_id = lease.ready_event_id
    JOIN current_final_verification_repair_activations_v32 activation
      ON activation.activation_id = lease.activation_id
    JOIN current_final_verification_attempts_v32 failed
      ON failed.attempt_id = activation.failed_attempt_id
     AND failed.sprint_id = activation.sprint_id
    JOIN current_task_nodes_v32 task
      ON task.sprint_id = activation.sprint_id
     AND task.task_id = activation.repair_task_id
    WHERE lease.lease_admission_id = NEW.lease_admission_id
      AND lease.activation_id = NEW.activation_id
      AND lease.ready_event_id = NEW.ready_event_id
      AND lease.sprint_id = NEW.sprint_id
      AND lease.task_id = NEW.task_id
      AND lease.slot_ordinal = NEW.slot_ordinal
      AND ready.activation_id = NEW.activation_id
      AND activation.sprint_id = NEW.sprint_id
      AND activation.repair_task_id = NEW.task_id
      AND activation.slot_ordinal = NEW.slot_ordinal
      AND task.purpose = 'FinalVerificationRepairSlot'
      AND task.repair_slot_ordinal = NEW.slot_ordinal
      AND lease.acquired_at_unix_ms = NEW.admitted_at_unix_ms
      AND json_extract(CAST(NEW.admission_json AS TEXT), '$.attempt_admission_id') = NEW.attempt_admission_id
      AND json_extract(CAST(NEW.admission_json AS TEXT), '$.activation_id') = NEW.activation_id
      AND json_extract(CAST(NEW.admission_json AS TEXT), '$.ready_event_id') = NEW.ready_event_id
      AND json_extract(CAST(NEW.admission_json AS TEXT), '$.lease_admission_id') = NEW.lease_admission_id
      AND json_extract(CAST(NEW.admission_json AS TEXT), '$.sprint_id') = NEW.sprint_id
      AND json_extract(CAST(NEW.admission_json AS TEXT), '$.task_id') = NEW.task_id
      AND json_extract(CAST(NEW.admission_json AS TEXT), '$.slot_ordinal') = NEW.slot_ordinal
      AND json_extract(CAST(NEW.admission_json AS TEXT), '$.task_attempt.attempt_id') = NEW.attempt_id
      AND json_extract(CAST(NEW.admission_json AS TEXT), '$.task_attempt.attempt_ordinal') = NEW.attempt_ordinal
      AND json_extract(CAST(NEW.admission_json AS TEXT), '$.task_attempt.opening_event_id') = NEW.lease_admission_id
      AND json_extract(CAST(NEW.admission_json AS TEXT), '$.task_attempt.opened_at_unix_ms') = NEW.admitted_at_unix_ms
      AND json_extract(CAST(NEW.admission_json AS TEXT), '$.task_attempt.worker_lease')
          = json_extract(CAST(lease.admission_json AS TEXT), '$.worker_lease')
      AND NOT EXISTS (
          SELECT 1 FROM current_final_verification_repair_completions_v32 completion
          WHERE completion.activation_id = activation.activation_id
      )
      AND NOT EXISTS (
          SELECT 1 FROM current_sprint_terminal_outcomes_v32 terminal
          WHERE terminal.sprint_id = activation.sprint_id
      )
      AND NOT EXISTS (
          SELECT 1 FROM current_final_verification_attempts_v32 later
          WHERE later.sprint_id = activation.sprint_id
            AND later.attempt_ordinal > failed.attempt_ordinal
      )
)
BEGIN SELECT RAISE(ABORT, 'repair attempt requires exact live activation, Ready event, and lease'); END;

CREATE VIEW current_repair_task_admission_capture_v32 AS
SELECT ready.event_id AS ready_event_id, ready.activation_id, ready.sprint_id,
       ready.task_id, ready.slot_ordinal, ready.occurred_at_unix_ms,
       lease.lease_admission_id, lease.lease_id, lease.lease_epoch,
       lease.worker_id, lease.acquired_at_unix_ms,
       attempt.attempt_admission_id, attempt.attempt_id,
       attempt.attempt_ordinal, attempt.admitted_at_unix_ms
FROM current_repair_task_ready_events_v32 ready
LEFT JOIN current_repair_task_lease_admissions_v32 lease
  ON lease.activation_id = ready.activation_id
LEFT JOIN current_repair_task_attempt_admissions_v32 attempt
  ON attempt.activation_id = ready.activation_id;

CREATE TRIGGER current_repair_task_ready_events_v32_no_update
BEFORE UPDATE ON current_repair_task_ready_events_v32
BEGIN SELECT RAISE(ABORT, 'current repair Ready events are immutable'); END;
CREATE TRIGGER current_repair_task_ready_events_v32_no_delete
BEFORE DELETE ON current_repair_task_ready_events_v32
BEGIN SELECT RAISE(ABORT, 'current repair Ready events are immutable'); END;
CREATE TRIGGER current_repair_task_lease_admissions_v32_no_update
BEFORE UPDATE ON current_repair_task_lease_admissions_v32
BEGIN SELECT RAISE(ABORT, 'current repair lease admissions are immutable'); END;
CREATE TRIGGER current_repair_task_lease_admissions_v32_no_delete
BEFORE DELETE ON current_repair_task_lease_admissions_v32
BEGIN SELECT RAISE(ABORT, 'current repair lease admissions are immutable'); END;
CREATE TRIGGER current_repair_task_attempt_admissions_v32_no_update
BEFORE UPDATE ON current_repair_task_attempt_admissions_v32
BEGIN SELECT RAISE(ABORT, 'current repair attempt admissions are immutable'); END;
CREATE TRIGGER current_repair_task_attempt_admissions_v32_no_delete
BEFORE DELETE ON current_repair_task_attempt_admissions_v32
BEGIN SELECT RAISE(ABORT, 'current repair attempt admissions are immutable'); END;
