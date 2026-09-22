-- Schema v35 commits one exact launch/capture intent for a schema-v34
-- operational attempt.  It does not acquire capture storage, spawn, initialize
-- V13, dispatch, or admit any later lifecycle event.

-- Event V1 originally had an unconditional request_id FK to the schema-v32
-- attempt request. LaunchCommitted instead binds its own exact launch request.
-- Rebuild both the parent and its sole child in this one migration transaction,
-- preserving every existing scalar and byte string exactly.
CREATE TABLE current_final_verification_events_v35_rebuild (
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
    CHECK (grok_current_final_verification_event_v34_canonical(event_json) = 1),
    CHECK (grok_current_final_verification_event_v34_digest(event_json) = event_digest)
) STRICT, WITHOUT ROWID;

CREATE TABLE current_final_verification_operational_attempts_v35_rebuild (
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
        REFERENCES current_final_verification_events_v35_rebuild(event_id) ON DELETE RESTRICT,
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

INSERT INTO current_final_verification_events_v35_rebuild (
    sprint_id, event_sequence, event_id, event_version, event_kind, attempt_id,
    request_id, request_digest, occurred_at_unix_ms, event_digest, event_json
)
SELECT sprint_id, event_sequence, event_id, event_version, event_kind, attempt_id,
       request_id, request_digest, occurred_at_unix_ms, event_digest, event_json
FROM current_final_verification_events_v34;

INSERT INTO current_final_verification_operational_attempts_v35_rebuild (
    attempt_id, operational_version, sprint_id, attempt_ordinal,
    final_verification_admission_id, attempt_authority_digest,
    diagnostic_v32_admission_event_id, diagnostic_v32_admission_event_sequence,
    request_id, request_digest, admission_event_id, admission_event_sequence,
    sprint_spec_digest, task_graph_id, task_graph_digest,
    task_graph_payload_digest, repair_slot_reserve_digest, input_snapshot,
    complete_task_done_set_digest, complete_criterion_evidence_set_digest,
    workspace_grant_hash, verification_command_digest, execution_policy_digest,
    coordinator_instance_id, admitted_at_unix_ms, operational_attempt_digest,
    operational_json
)
SELECT attempt_id, operational_version, sprint_id, attempt_ordinal,
       final_verification_admission_id, attempt_authority_digest,
       diagnostic_v32_admission_event_id, diagnostic_v32_admission_event_sequence,
       request_id, request_digest, admission_event_id, admission_event_sequence,
       sprint_spec_digest, task_graph_id, task_graph_digest,
       task_graph_payload_digest, repair_slot_reserve_digest, input_snapshot,
       complete_task_done_set_digest, complete_criterion_evidence_set_digest,
       workspace_grant_hash, verification_command_digest, execution_policy_digest,
       coordinator_instance_id, admitted_at_unix_ms, operational_attempt_digest,
       operational_json
FROM current_final_verification_operational_attempts_v34;

DROP TRIGGER current_final_verification_events_v34_validate_insert;
DROP TRIGGER current_final_verification_events_v34_monotonic_sequence;
DROP TRIGGER current_final_verification_operational_attempts_v34_validate_insert;
DROP TRIGGER current_final_verification_events_v34_no_update;
DROP TRIGGER current_final_verification_events_v34_no_delete;
DROP TRIGGER current_final_verification_operational_attempts_v34_no_update;
DROP TRIGGER current_final_verification_operational_attempts_v34_no_delete;
DROP TRIGGER current_final_verification_events_v34_no_replace;
DROP TRIGGER current_final_verification_operational_attempts_v34_no_replace;

DROP TABLE current_final_verification_operational_attempts_v34;
DROP TABLE current_final_verification_events_v34;
ALTER TABLE current_final_verification_events_v35_rebuild
    RENAME TO current_final_verification_events_v34;
ALTER TABLE current_final_verification_operational_attempts_v35_rebuild
    RENAME TO current_final_verification_operational_attempts_v34;

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
      SELECT 1 FROM current_final_verification_attempts_v32 prior
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

CREATE TABLE current_final_verification_launches_v35 (
    attempt_id TEXT PRIMARY KEY NOT NULL
        CHECK (length(CAST(attempt_id AS BLOB)) BETWEEN 1 AND 256),
    launch_version INTEGER NOT NULL CHECK (launch_version = 1),
    sprint_id TEXT NOT NULL
        CHECK (length(CAST(sprint_id AS BLOB)) BETWEEN 1 AND 256),
    operational_attempt_digest TEXT NOT NULL UNIQUE CHECK (length(operational_attempt_digest) = 64),
    launch_request_id TEXT NOT NULL UNIQUE
        CHECK (length(CAST(launch_request_id AS BLOB)) BETWEEN 1 AND 256),
    launch_request_digest TEXT NOT NULL UNIQUE CHECK (length(launch_request_digest) = 64),
    launch_request_json BLOB NOT NULL CHECK (length(launch_request_json) BETWEEN 1 AND 1048576),
    preparation_id TEXT NOT NULL UNIQUE
        CHECK (length(CAST(preparation_id AS BLOB)) BETWEEN 1 AND 256),
    launch_preparation_digest TEXT NOT NULL UNIQUE CHECK (length(launch_preparation_digest) = 64),
    reservation_digest TEXT NOT NULL UNIQUE CHECK (length(reservation_digest) = 64),
    reservations_json BLOB NOT NULL CHECK (length(reservations_json) BETWEEN 1 AND 1048576),
    capture_intent_id TEXT NOT NULL UNIQUE CHECK (length(capture_intent_id) = 64),
    capture_intent_digest TEXT NOT NULL UNIQUE CHECK (length(capture_intent_digest) = 64),
    containment_backend TEXT NOT NULL CHECK (containment_backend IN (
        'MacOsDedicatedIdentitySeatbelt',
        'LinuxBubblewrapLandlockSeccompCgroupV2'
    )),
    target_identity_digest TEXT NOT NULL CHECK (length(target_identity_digest) = 64),
    native_policy_digest TEXT NOT NULL CHECK (length(native_policy_digest) = 64),
    runner_binary_digest TEXT NOT NULL CHECK (length(runner_binary_digest) = 64),
    runner_binary_size_bytes INTEGER NOT NULL CHECK (runner_binary_size_bytes > 0),
    runner_protocol_version INTEGER NOT NULL CHECK (runner_protocol_version = 13),
    runner_protocol_digest TEXT NOT NULL CHECK (length(runner_protocol_digest) = 64),
    private_state_id TEXT NOT NULL UNIQUE
        CHECK (length(CAST(private_state_id AS BLOB)) BETWEEN 1 AND 256),
    private_state_digest TEXT NOT NULL UNIQUE CHECK (length(private_state_digest) = 64),
    workspace_grant_hash TEXT NOT NULL CHECK (length(workspace_grant_hash) = 64),
    execution_policy_digest TEXT NOT NULL CHECK (length(execution_policy_digest) = 64),
    verification_command_digest TEXT NOT NULL CHECK (length(verification_command_digest) = 64),
    v13_command_request_digest TEXT NOT NULL CHECK (length(v13_command_request_digest) = 64),
    detector_policy_digest TEXT NOT NULL CHECK (length(detector_policy_digest) = 64),
    max_aggregate_output_bytes INTEGER NOT NULL CHECK (max_aggregate_output_bytes > 0),
    launch_event_id TEXT NOT NULL UNIQUE CHECK (length(launch_event_id) = 64),
    launch_event_sequence INTEGER NOT NULL CHECK (launch_event_sequence > 0),
    committed_at_unix_ms INTEGER NOT NULL CHECK (committed_at_unix_ms > 0),
    launch_authority_digest TEXT NOT NULL UNIQUE CHECK (length(launch_authority_digest) = 64),
    launch_authority_json BLOB NOT NULL CHECK (length(launch_authority_json) BETWEEN 1 AND 1048576),
    UNIQUE (sprint_id, attempt_id),
    UNIQUE (attempt_id, launch_event_sequence),
    FOREIGN KEY (attempt_id)
        REFERENCES current_final_verification_operational_attempts_v34(attempt_id)
        ON DELETE RESTRICT,
    FOREIGN KEY (sprint_id, attempt_id)
        REFERENCES current_final_verification_operational_attempts_v34(sprint_id, attempt_id)
        ON DELETE RESTRICT,
    FOREIGN KEY (operational_attempt_digest)
        REFERENCES current_final_verification_operational_attempts_v34(operational_attempt_digest)
        ON DELETE RESTRICT,
    FOREIGN KEY (launch_event_id)
        REFERENCES current_final_verification_events_v34(event_id)
        ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED,
    CHECK (grok_current_final_verification_launch_request_v35_canonical(launch_request_json) = 1),
    CHECK (
        grok_current_final_verification_launch_request_v35_digest(launch_request_json)
        = launch_request_digest
    ),
    CHECK (grok_current_final_verification_reservations_v35_canonical(reservations_json) = 1),
    CHECK (
        grok_current_final_verification_reservations_v35_digest(reservations_json)
        = reservation_digest
    ),
    CHECK (grok_current_final_verification_launch_v35_canonical(launch_authority_json) = 1),
    CHECK (
        grok_current_final_verification_launch_v35_digest(launch_authority_json)
        = launch_authority_digest
    )
) STRICT, WITHOUT ROWID;

CREATE TABLE current_final_verification_lifecycle_reservations_v35 (
    attempt_id TEXT NOT NULL CHECK (length(CAST(attempt_id AS BLOB)) BETWEEN 1 AND 256),
    reservation_role TEXT NOT NULL CHECK (reservation_role IN (
        'runner_launch_id', 'runner_session_id', 'effect_id', 'capture_id',
        'capture_intent_id', 'dispatch_id', 'command_request_id',
        'effect_idempotency_key',
        'native_launch_preparation_attempt_id', 'native_launch_journal_id',
        'native_launch_cleanup_effect_id', 'native_launch_preparation_receipt_id',
        'native_launch_release_receipt_id', 'native_launch_cleanup_receipt_id',
        'capture_acquired_event_id',
        'v13_initialized_event_id', 'command_dispatched_event_id',
        'control_issued_event_id', 'control_observed_event_id',
        'control_reconciled_event_id', 'terminal_event_id',
        'effect_cut_event_id', 'output_custody_event_id',
        'command_cleanup_event_id', 'runner_direct_child_observed_event_id',
        'runner_domain_observed_event_id', 'runner_cleanup_event_id',
        'evidence_closure_event_id', 'outcome_derived_event_id',
        'initialization_request_id', 'initialization_receipt_id', 'control_id',
        'control_reconciliation_id', 'terminal_observation_id',
        'effect_cut_observation_id', 'shutdown_request_id',
        'shutdown_receipt_id', 'command_accounting_domain_id',
        'command_cleanup_observation_id', 'runner_accounting_domain_id',
        'runner_direct_child_observer_id',
        'runner_direct_child_observation_id', 'runner_domain_observation_id',
        'runner_domain_observer_id',
        'output_custody_closure_receipt_id', 'runner_cleanup_proof_id',
        'evidence_closure_id', 'outcome_id', 'verification_receipt_id'
    )),
    reserved_id TEXT NOT NULL UNIQUE CHECK (length(reserved_id) = 64),
    reservation_digest TEXT NOT NULL CHECK (length(reservation_digest) = 64),
    PRIMARY KEY (attempt_id, reservation_role),
    FOREIGN KEY (attempt_id)
        REFERENCES current_final_verification_launches_v35(attempt_id) ON DELETE RESTRICT,
    FOREIGN KEY (reservation_digest)
        REFERENCES current_final_verification_launches_v35(reservation_digest) ON DELETE RESTRICT
) STRICT, WITHOUT ROWID;

-- Replace only the v34 T0 writer fence.  Admission retains its byte-exact v34
-- rule, LaunchCommitted receives one private schema-v35 writer, and every
-- post-launch kind remains closed until its own additive source migration.
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
       ELSE 1
     END
BEGIN SELECT RAISE(ABORT, 'current final-verification event kind lacks exact current writer authority'); END;

CREATE TRIGGER current_final_verification_launches_v35_validate_insert
BEFORE INSERT ON current_final_verification_launches_v35
WHEN grok_current_final_verification_launch_write_admitted_v35(
         'launch', NEW.attempt_id, NEW.launch_authority_digest
     ) != 1
  OR json_extract(CAST(NEW.launch_authority_json AS TEXT), '$.attempt_id') != NEW.attempt_id
  OR json_extract(CAST(NEW.launch_authority_json AS TEXT), '$.launch_version') != NEW.launch_version
  OR json_extract(CAST(NEW.launch_authority_json AS TEXT), '$.sprint_id') != NEW.sprint_id
  OR json_extract(CAST(NEW.launch_authority_json AS TEXT), '$.operational_attempt_digest')
       != NEW.operational_attempt_digest
  OR json_extract(CAST(NEW.launch_authority_json AS TEXT), '$.launch_request_id')
       != NEW.launch_request_id
  OR json_extract(CAST(NEW.launch_authority_json AS TEXT), '$.launch_request_digest')
       != NEW.launch_request_digest
  OR json_extract(CAST(NEW.launch_authority_json AS TEXT), '$.launch_preparation.preparation_id')
       != NEW.preparation_id
  OR json_extract(CAST(NEW.launch_authority_json AS TEXT), '$.launch_preparation_digest')
       != NEW.launch_preparation_digest
  OR json_extract(CAST(NEW.launch_authority_json AS TEXT), '$.reservations.reservation_digest')
       != NEW.reservation_digest
  OR json_extract(CAST(NEW.launch_authority_json AS TEXT), '$.reservations.fields.capture_intent_id')
       != NEW.capture_intent_id
  OR json_extract(CAST(NEW.launch_authority_json AS TEXT), '$.capture_intent.intent_digest')
       != NEW.capture_intent_digest
  OR CASE json_extract(
       CAST(NEW.launch_authority_json AS TEXT),
       '$.launch_preparation.containment_backend'
     )
       WHEN 'mac_os_dedicated_identity_seatbelt' THEN 'MacOsDedicatedIdentitySeatbelt'
       WHEN 'linux_bubblewrap_landlock_seccomp_cgroup_v2' THEN
           'LinuxBubblewrapLandlockSeccompCgroupV2'
       ELSE NULL
     END != NEW.containment_backend
  OR json_extract(CAST(NEW.launch_authority_json AS TEXT), '$.launch_preparation.target_identity_digest')
       != NEW.target_identity_digest
  OR json_extract(CAST(NEW.launch_authority_json AS TEXT), '$.launch_preparation.native_policy_digest')
       != NEW.native_policy_digest
  OR json_extract(CAST(NEW.launch_authority_json AS TEXT), '$.launch_preparation.runner_binary_digest')
       != NEW.runner_binary_digest
  OR json_extract(CAST(NEW.launch_authority_json AS TEXT), '$.launch_preparation.runner_binary_size_bytes')
       != NEW.runner_binary_size_bytes
  OR json_extract(CAST(NEW.launch_authority_json AS TEXT), '$.launch_preparation.runner_protocol_version')
       != NEW.runner_protocol_version
  OR json_extract(CAST(NEW.launch_authority_json AS TEXT), '$.launch_preparation.runner_protocol_digest')
       != NEW.runner_protocol_digest
  OR json_extract(CAST(NEW.launch_authority_json AS TEXT), '$.launch_preparation.private_state_id')
       != NEW.private_state_id
  OR json_extract(CAST(NEW.launch_authority_json AS TEXT), '$.launch_preparation.private_state_digest')
       != NEW.private_state_digest
  OR json_extract(CAST(NEW.launch_authority_json AS TEXT), '$.workspace_grant.grant_hash')
       != NEW.workspace_grant_hash
  OR json_extract(CAST(NEW.launch_authority_json AS TEXT), '$.execution_policy.policy_hash')
       != NEW.execution_policy_digest
  OR json_extract(CAST(NEW.launch_authority_json AS TEXT), '$.verification_command_digest')
       != NEW.verification_command_digest
  OR json_extract(CAST(NEW.launch_authority_json AS TEXT), '$.v13_command_request_digest')
       != NEW.v13_command_request_digest
  OR json_extract(CAST(NEW.launch_authority_json AS TEXT), '$.detector_policy.policy_digest')
       != NEW.detector_policy_digest
  OR json_extract(CAST(NEW.launch_authority_json AS TEXT), '$.max_aggregate_output_bytes')
       != NEW.max_aggregate_output_bytes
  OR json_extract(CAST(NEW.launch_authority_json AS TEXT), '$.launch_event_id')
       != NEW.launch_event_id
  OR json_extract(CAST(NEW.launch_authority_json AS TEXT), '$.launch_event_sequence')
       != NEW.launch_event_sequence
  OR json_extract(CAST(NEW.launch_authority_json AS TEXT), '$.committed_at_unix_ms')
       != NEW.committed_at_unix_ms
  OR json_extract(CAST(NEW.launch_authority_json AS TEXT), '$.launch_authority_digest')
       != NEW.launch_authority_digest
  OR NOT EXISTS (
      SELECT 1
      FROM current_final_verification_operational_attempts_v34 operational
      JOIN current_sprint_authorities_v32 sprint
        ON sprint.sprint_id = operational.sprint_id
      WHERE operational.attempt_id = NEW.attempt_id
        AND operational.sprint_id = NEW.sprint_id
        AND operational.operational_attempt_digest = NEW.operational_attempt_digest
        AND NEW.launch_event_sequence = operational.admission_event_sequence + 1
        AND NEW.committed_at_unix_ms >= operational.admitted_at_unix_ms
        AND grok_current_final_verification_launch_v35_matches(
            NEW.launch_authority_json, NEW.launch_request_json,
            NEW.reservations_json, operational.operational_json,
            sprint.spec_json
        ) = 1
  )
  OR EXISTS (
      SELECT 1 FROM current_final_verification_events_v34 later
      WHERE later.attempt_id = NEW.attempt_id
        AND later.event_kind NOT IN ('AttemptAdmitted', 'LaunchCommitted')
  )
BEGIN SELECT RAISE(ABORT, 'current final-verification launch crosses operational authority or a later frontier'); END;

CREATE TRIGGER current_final_verification_lifecycle_reservations_v35_validate_insert
BEFORE INSERT ON current_final_verification_lifecycle_reservations_v35
WHEN grok_current_final_verification_launch_write_admitted_v35(
         'reservation', NEW.attempt_id, NEW.reserved_id
     ) != 1
  OR NOT EXISTS (
      SELECT 1 FROM current_final_verification_launches_v35 launch
      WHERE launch.attempt_id = NEW.attempt_id
        AND launch.reservation_digest = NEW.reservation_digest
        AND grok_current_final_verification_reservation_member_v35(
            launch.reservations_json, NEW.reservation_role, NEW.reserved_id
        ) = 1
  )
BEGIN SELECT RAISE(ABORT, 'current final-verification lifecycle reservation is not an exact launch member'); END;

CREATE TRIGGER current_final_verification_launches_v35_no_update
BEFORE UPDATE ON current_final_verification_launches_v35
BEGIN SELECT RAISE(ABORT, 'current final-verification launches are immutable'); END;

CREATE TRIGGER current_final_verification_launches_v35_no_delete
BEFORE DELETE ON current_final_verification_launches_v35
BEGIN SELECT RAISE(ABORT, 'current final-verification launches are immutable'); END;

CREATE TRIGGER current_final_verification_lifecycle_reservations_v35_no_update
BEFORE UPDATE ON current_final_verification_lifecycle_reservations_v35
BEGIN SELECT RAISE(ABORT, 'current final-verification lifecycle reservations are immutable'); END;

CREATE TRIGGER current_final_verification_lifecycle_reservations_v35_no_delete
BEFORE DELETE ON current_final_verification_lifecycle_reservations_v35
BEGIN SELECT RAISE(ABORT, 'current final-verification lifecycle reservations are immutable'); END;

CREATE TRIGGER current_final_verification_launches_v35_no_replace
BEFORE INSERT ON current_final_verification_launches_v35
WHEN EXISTS (
    SELECT 1 FROM current_final_verification_launches_v35 existing
    WHERE existing.attempt_id = NEW.attempt_id
       OR existing.operational_attempt_digest = NEW.operational_attempt_digest
       OR existing.launch_request_id = NEW.launch_request_id
       OR existing.launch_request_digest = NEW.launch_request_digest
       OR existing.preparation_id = NEW.preparation_id
       OR existing.launch_preparation_digest = NEW.launch_preparation_digest
       OR existing.reservation_digest = NEW.reservation_digest
       OR existing.capture_intent_id = NEW.capture_intent_id
       OR existing.capture_intent_digest = NEW.capture_intent_digest
       OR existing.private_state_id = NEW.private_state_id
       OR existing.private_state_digest = NEW.private_state_digest
       OR existing.launch_event_id = NEW.launch_event_id
       OR existing.launch_authority_digest = NEW.launch_authority_digest
       OR (existing.sprint_id = NEW.sprint_id AND existing.attempt_id = NEW.attempt_id)
       OR (existing.attempt_id = NEW.attempt_id
           AND existing.launch_event_sequence = NEW.launch_event_sequence)
)
BEGIN SELECT RAISE(ABORT, 'current final-verification launch identity already exists'); END;

CREATE TRIGGER current_final_verification_lifecycle_reservations_v35_no_replace
BEFORE INSERT ON current_final_verification_lifecycle_reservations_v35
WHEN EXISTS (
    SELECT 1 FROM current_final_verification_lifecycle_reservations_v35 existing
    WHERE (existing.attempt_id = NEW.attempt_id
           AND existing.reservation_role = NEW.reservation_role)
       OR existing.reserved_id = NEW.reserved_id
)
BEGIN SELECT RAISE(ABORT, 'current final-verification lifecycle reservation identity already exists'); END;
