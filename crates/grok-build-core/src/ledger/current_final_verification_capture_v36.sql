-- Schema v36 admits only the exact current capture-acquisition frontier.
-- It is additive over v35: no v27 capture row is projected or promoted.

CREATE TABLE current_final_verification_capture_acquisitions_v36 (
    attempt_id TEXT PRIMARY KEY NOT NULL
        CHECK (length(CAST(attempt_id AS BLOB)) BETWEEN 1 AND 256),
    acquisition_version INTEGER NOT NULL CHECK (acquisition_version = 1),
    sprint_id TEXT NOT NULL
        CHECK (length(CAST(sprint_id AS BLOB)) BETWEEN 1 AND 256),
    launch_authority_digest TEXT NOT NULL UNIQUE
        CHECK (length(launch_authority_digest) = 64),
    acquisition_request_digest TEXT NOT NULL UNIQUE
        CHECK (length(acquisition_request_digest) = 64),
    acquisition_request_json BLOB NOT NULL
        CHECK (length(acquisition_request_json) BETWEEN 1 AND 1048576),
    capture_intent_id TEXT NOT NULL UNIQUE CHECK (length(capture_intent_id) = 64),
    capture_id TEXT NOT NULL UNIQUE CHECK (length(capture_id) = 64),
    capture_intent_digest TEXT NOT NULL UNIQUE CHECK (length(capture_intent_digest) = 64),
    acquired_anchor_digest TEXT NOT NULL UNIQUE CHECK (length(acquired_anchor_digest) = 64),
    acquired_json BLOB NOT NULL CHECK (length(acquired_json) BETWEEN 1 AND 1048576),
    acquired_store_head_generation INTEGER NOT NULL
        CHECK (acquired_store_head_generation = 2),
    acquired_store_head_digest TEXT NOT NULL UNIQUE
        CHECK (length(acquired_store_head_digest) = 64),
    sensitive_output_journal_id TEXT NOT NULL UNIQUE
        CHECK (length(CAST(sensitive_output_journal_id AS BLOB)) BETWEEN 1 AND 512),
    intent_bound_journal_generation INTEGER NOT NULL
        CHECK (intent_bound_journal_generation = 1),
    intent_bound_journal_digest TEXT NOT NULL UNIQUE
        CHECK (length(intent_bound_journal_digest) = 64),
    acquired_bound_journal_generation INTEGER NOT NULL
        CHECK (acquired_bound_journal_generation = 2),
    acquired_bound_journal_digest TEXT NOT NULL UNIQUE
        CHECK (length(acquired_bound_journal_digest) = 64),
    launch_event_id TEXT NOT NULL CHECK (length(launch_event_id) = 64),
    launch_event_sequence INTEGER NOT NULL CHECK (launch_event_sequence > 0),
    capture_event_id TEXT NOT NULL UNIQUE CHECK (length(capture_event_id) = 64),
    capture_event_sequence INTEGER NOT NULL CHECK (capture_event_sequence > 0),
    acquired_at_unix_ms INTEGER NOT NULL CHECK (acquired_at_unix_ms > 0),
    capture_authority_digest TEXT NOT NULL UNIQUE
        CHECK (length(capture_authority_digest) = 64),
    capture_authority_json BLOB NOT NULL
        CHECK (length(capture_authority_json) BETWEEN 1 AND 1048576),
    UNIQUE (sprint_id, attempt_id),
    UNIQUE (attempt_id, capture_event_sequence),
    FOREIGN KEY (attempt_id)
        REFERENCES current_final_verification_launches_v35(attempt_id) ON DELETE RESTRICT,
    FOREIGN KEY (sprint_id, attempt_id)
        REFERENCES current_final_verification_launches_v35(sprint_id, attempt_id)
        ON DELETE RESTRICT,
    FOREIGN KEY (launch_authority_digest)
        REFERENCES current_final_verification_launches_v35(launch_authority_digest)
        ON DELETE RESTRICT,
    FOREIGN KEY (capture_intent_id)
        REFERENCES current_final_verification_launches_v35(capture_intent_id)
        ON DELETE RESTRICT,
    FOREIGN KEY (capture_intent_digest)
        REFERENCES current_final_verification_launches_v35(capture_intent_digest)
        ON DELETE RESTRICT,
    FOREIGN KEY (capture_event_id)
        REFERENCES current_final_verification_events_v34(event_id)
        ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED,
    CHECK (
        grok_current_final_verification_capture_request_v36_canonical(
            acquisition_request_json
        ) = 1
    ),
    CHECK (
        grok_current_final_verification_capture_request_v36_digest(
            acquisition_request_json
        ) = acquisition_request_digest
    ),
    CHECK (grok_command_output_capture_acquired_v36_canonical(acquired_json) = 1),
    CHECK (
        grok_command_output_capture_acquired_v36_digest(acquired_json)
        = acquired_anchor_digest
    ),
    CHECK (
        grok_current_final_verification_capture_v36_canonical(
            capture_authority_json
        ) = 1
    ),
    CHECK (
        grok_current_final_verification_capture_v36_digest(
            capture_authority_json
        ) = capture_authority_digest
    )
) STRICT, WITHOUT ROWID;

-- Replace the v35 frontier writer fence. AttemptAdmitted and LaunchCommitted
-- retain their exact writers; CaptureAcquired gains only the private v36
-- writer. Every later lifecycle event remains closed.
DROP TRIGGER current_final_verification_events_v34_validate_insert;
CREATE TRIGGER current_final_verification_events_v34_validate_insert
BEFORE INSERT ON current_final_verification_events_v34
WHEN json_extract(CAST(NEW.event_json AS TEXT), '$.event_version') != NEW.event_version
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
  OR CASE NEW.event_kind
       WHEN 'AttemptAdmitted' THEN
           grok_current_final_verification_operational_write_admitted_v34(
               'event', NEW.attempt_id, NEW.event_digest
           ) != 1
           OR NOT EXISTS (
               SELECT 1 FROM current_final_verification_attempts_v32 attempt
               WHERE attempt.sprint_id = NEW.sprint_id
                 AND attempt.attempt_id = NEW.attempt_id
                 AND attempt.request_id = NEW.request_id
                 AND attempt.request_digest = NEW.request_digest
                 AND attempt.admitted_at_unix_ms = NEW.occurred_at_unix_ms
           )
       WHEN 'LaunchCommitted' THEN
           grok_current_final_verification_launch_write_admitted_v35(
               'event', NEW.attempt_id, NEW.event_digest
           ) != 1
           OR NOT EXISTS (
               SELECT 1
               FROM current_final_verification_launches_v35 launch
               JOIN current_final_verification_operational_attempts_v34 operational
                 ON operational.attempt_id = launch.attempt_id
               WHERE operational.sprint_id = NEW.sprint_id
                 AND operational.attempt_id = NEW.attempt_id
                 AND launch.launch_request_id = NEW.request_id
                 AND launch.launch_request_digest = NEW.request_digest
                 AND launch.launch_event_id = NEW.event_id
                 AND launch.launch_event_sequence = NEW.event_sequence
                 AND launch.committed_at_unix_ms = NEW.occurred_at_unix_ms
                 AND NEW.event_sequence = operational.admission_event_sequence + 1
                 AND NEW.occurred_at_unix_ms >= operational.admitted_at_unix_ms
                 AND 49 = (
                     SELECT COUNT(*)
                     FROM current_final_verification_lifecycle_reservations_v35 reservation
                     WHERE reservation.attempt_id = launch.attempt_id
                       AND reservation.reservation_digest = launch.reservation_digest
                 )
           )
       WHEN 'CaptureAcquired' THEN
           grok_current_final_verification_capture_write_admitted_v36(
               'event', NEW.attempt_id, NEW.event_digest
           ) != 1
           OR NOT EXISTS (
               SELECT 1
               FROM current_final_verification_capture_acquisitions_v36 capture
               JOIN current_final_verification_launches_v35 launch
                 ON launch.attempt_id = capture.attempt_id
               WHERE capture.sprint_id = NEW.sprint_id
                 AND capture.attempt_id = NEW.attempt_id
                 AND capture.capture_intent_id = NEW.request_id
                 AND capture.capture_intent_digest = NEW.request_digest
                 AND capture.capture_event_id = NEW.event_id
                 AND capture.capture_event_sequence = NEW.event_sequence
                 AND capture.acquired_at_unix_ms = NEW.occurred_at_unix_ms
                 AND NEW.event_sequence = launch.launch_event_sequence + 1
                 AND NEW.occurred_at_unix_ms >= launch.committed_at_unix_ms
           )
       ELSE 1
     END
BEGIN SELECT RAISE(ABORT, 'current final-verification event kind lacks exact current writer authority'); END;

CREATE TRIGGER current_final_verification_capture_acquisitions_v36_validate_insert
BEFORE INSERT ON current_final_verification_capture_acquisitions_v36
WHEN grok_current_final_verification_capture_write_admitted_v36(
         'capture', NEW.attempt_id, NEW.capture_authority_digest
     ) != 1
  OR json_extract(CAST(NEW.capture_authority_json AS TEXT), '$.acquisition_version')
       != NEW.acquisition_version
  OR json_extract(CAST(NEW.capture_authority_json AS TEXT), '$.attempt_id')
       != NEW.attempt_id
  OR json_extract(CAST(NEW.capture_authority_json AS TEXT), '$.sprint_id')
       != NEW.sprint_id
  OR json_extract(CAST(NEW.capture_authority_json AS TEXT), '$.launch_authority_digest')
       != NEW.launch_authority_digest
  OR json_extract(CAST(NEW.capture_authority_json AS TEXT), '$.acquisition_request_digest')
       != NEW.acquisition_request_digest
  OR json_extract(CAST(NEW.capture_authority_json AS TEXT), '$.capture_intent_id')
       != NEW.capture_intent_id
  OR json_extract(CAST(NEW.capture_authority_json AS TEXT), '$.acquired.capture_id')
       != NEW.capture_id
  OR json_extract(CAST(NEW.capture_authority_json AS TEXT), '$.acquired.intent_digest')
       != NEW.capture_intent_digest
  OR json_extract(CAST(NEW.capture_authority_json AS TEXT), '$.acquired.acquired_anchor_digest')
       != NEW.acquired_anchor_digest
  OR json_extract(CAST(NEW.capture_authority_json AS TEXT), '$.acquired.store_head.generation')
       != NEW.acquired_store_head_generation
  OR json_extract(CAST(NEW.capture_authority_json AS TEXT), '$.acquired.store_head.record_digest')
       != NEW.acquired_store_head_digest
  OR json_extract(CAST(NEW.capture_authority_json AS TEXT), '$.sensitive_output_journal_id')
       != NEW.sensitive_output_journal_id
  OR json_extract(CAST(NEW.capture_authority_json AS TEXT), '$.intent_bound_journal_head.generation')
       != NEW.intent_bound_journal_generation
  OR json_extract(CAST(NEW.capture_authority_json AS TEXT), '$.intent_bound_journal_head.record_digest')
       != NEW.intent_bound_journal_digest
  OR json_extract(CAST(NEW.capture_authority_json AS TEXT), '$.acquired_bound_journal_head.generation')
       != NEW.acquired_bound_journal_generation
  OR json_extract(CAST(NEW.capture_authority_json AS TEXT), '$.acquired_bound_journal_head.record_digest')
       != NEW.acquired_bound_journal_digest
  OR json_extract(CAST(NEW.capture_authority_json AS TEXT), '$.launch_event_id')
       != NEW.launch_event_id
  OR json_extract(CAST(NEW.capture_authority_json AS TEXT), '$.launch_event_sequence')
       != NEW.launch_event_sequence
  OR json_extract(CAST(NEW.capture_authority_json AS TEXT), '$.capture_event_id')
       != NEW.capture_event_id
  OR json_extract(CAST(NEW.capture_authority_json AS TEXT), '$.capture_event_sequence')
       != NEW.capture_event_sequence
  OR json_extract(CAST(NEW.capture_authority_json AS TEXT), '$.acquired_at_unix_ms')
       != NEW.acquired_at_unix_ms
  OR json_extract(CAST(NEW.capture_authority_json AS TEXT), '$.capture_authority_digest')
       != NEW.capture_authority_digest
  OR NOT EXISTS (
      SELECT 1
      FROM current_final_verification_launches_v35 launch
      WHERE launch.attempt_id = NEW.attempt_id
        AND launch.sprint_id = NEW.sprint_id
        AND launch.launch_authority_digest = NEW.launch_authority_digest
        AND launch.capture_intent_id = NEW.capture_intent_id
        AND launch.capture_intent_digest = NEW.capture_intent_digest
        AND launch.launch_event_id = NEW.launch_event_id
        AND launch.launch_event_sequence = NEW.launch_event_sequence
        AND NEW.capture_event_sequence = launch.launch_event_sequence + 1
        AND NEW.acquired_at_unix_ms >= launch.committed_at_unix_ms
        AND grok_current_final_verification_capture_v36_matches(
            NEW.capture_authority_json,
            NEW.acquisition_request_json,
            launch.launch_authority_json
        ) = 1
  )
  OR EXISTS (
      SELECT 1 FROM current_final_verification_events_v34 later
      WHERE later.attempt_id = NEW.attempt_id
        AND later.event_kind NOT IN ('AttemptAdmitted', 'LaunchCommitted')
  )
BEGIN SELECT RAISE(ABORT, 'current final-verification capture crosses launch authority or a later frontier'); END;

CREATE TRIGGER current_final_verification_capture_acquisitions_v36_no_update
BEFORE UPDATE ON current_final_verification_capture_acquisitions_v36
BEGIN SELECT RAISE(ABORT, 'current final-verification capture acquisitions are immutable'); END;

CREATE TRIGGER current_final_verification_capture_acquisitions_v36_no_delete
BEFORE DELETE ON current_final_verification_capture_acquisitions_v36
BEGIN SELECT RAISE(ABORT, 'current final-verification capture acquisitions are immutable'); END;

CREATE TRIGGER current_final_verification_capture_acquisitions_v36_no_replace
BEFORE INSERT ON current_final_verification_capture_acquisitions_v36
WHEN EXISTS (
    SELECT 1 FROM current_final_verification_capture_acquisitions_v36 existing
    WHERE existing.attempt_id = NEW.attempt_id
       OR existing.launch_authority_digest = NEW.launch_authority_digest
       OR existing.acquisition_request_digest = NEW.acquisition_request_digest
       OR existing.capture_intent_id = NEW.capture_intent_id
       OR existing.capture_id = NEW.capture_id
       OR existing.capture_intent_digest = NEW.capture_intent_digest
       OR existing.acquired_anchor_digest = NEW.acquired_anchor_digest
       OR existing.acquired_store_head_digest = NEW.acquired_store_head_digest
       OR existing.sensitive_output_journal_id = NEW.sensitive_output_journal_id
       OR existing.intent_bound_journal_digest = NEW.intent_bound_journal_digest
       OR existing.acquired_bound_journal_digest = NEW.acquired_bound_journal_digest
       OR existing.capture_event_id = NEW.capture_event_id
       OR existing.capture_authority_digest = NEW.capture_authority_digest
       OR (existing.sprint_id = NEW.sprint_id AND existing.attempt_id = NEW.attempt_id)
       OR (existing.attempt_id = NEW.attempt_id
           AND existing.capture_event_sequence = NEW.capture_event_sequence)
)
BEGIN SELECT RAISE(ABORT, 'current final-verification capture identity already exists'); END;
