-- Schema v32 is a parallel current-authority lattice. Historical sprint,
-- graph, admission, capture, and completion tables retain their end-of-v31
-- meanings and are not widened or recreated here.

CREATE TABLE legacy_sprint_authority_exemptions_v32 (
    sprint_id TEXT PRIMARY KEY NOT NULL,
    legacy_spec_digest TEXT NOT NULL CHECK (length(legacy_spec_digest) = 64),
    marked_at_schema_version INTEGER NOT NULL CHECK (marked_at_schema_version = 32),
    FOREIGN KEY (sprint_id) REFERENCES sprints(sprint_id) ON DELETE RESTRICT
) STRICT, WITHOUT ROWID;

INSERT INTO legacy_sprint_authority_exemptions_v32 (
    sprint_id, legacy_spec_digest, marked_at_schema_version
)
SELECT sprint_id, grok_sha256(spec_json), 32
FROM sprints;

CREATE TABLE current_sprint_authorities_v32 (
    sprint_id TEXT PRIMARY KEY NOT NULL,
    sprint_authority_version INTEGER NOT NULL CHECK (sprint_authority_version = 2),
    sprint_spec_digest TEXT NOT NULL UNIQUE CHECK (length(sprint_spec_digest) = 64),
    task_graph_id TEXT NOT NULL UNIQUE CHECK (length(task_graph_id) BETWEEN 1 AND 4096),
    task_graph_payload_digest TEXT NOT NULL CHECK (length(task_graph_payload_digest) = 64),
    repair_slot_reserve_digest TEXT NOT NULL CHECK (length(repair_slot_reserve_digest) = 64),
    max_final_verification_attempts INTEGER NOT NULL
        CHECK (max_final_verification_attempts BETWEEN 1 AND 3),
    base_snapshot TEXT NOT NULL CHECK (length(base_snapshot) = 64),
    workspace_grant_hash TEXT NOT NULL CHECK (length(workspace_grant_hash) = 64),
    created_at_unix_ms INTEGER NOT NULL CHECK (created_at_unix_ms > 0),
    spec_json BLOB NOT NULL CHECK (length(spec_json) BETWEEN 1 AND 8388608),
    CHECK (grok_sprint_spec_v32_canonical(spec_json) = 1),
    CHECK (grok_sprint_spec_v32_digest(spec_json) = sprint_spec_digest)
) STRICT, WITHOUT ROWID;

CREATE TABLE current_task_graph_authorities_v32 (
    graph_id TEXT PRIMARY KEY NOT NULL,
    sprint_id TEXT NOT NULL UNIQUE,
    sprint_authority_version INTEGER NOT NULL CHECK (sprint_authority_version = 2),
    graph_digest TEXT NOT NULL UNIQUE CHECK (length(graph_digest) = 64),
    sprint_spec_digest TEXT NOT NULL CHECK (length(sprint_spec_digest) = 64),
    graph_payload_digest TEXT NOT NULL CHECK (length(graph_payload_digest) = 64),
    repair_slot_reserve_digest TEXT NOT NULL CHECK (length(repair_slot_reserve_digest) = 64),
    graph_json BLOB NOT NULL CHECK (length(graph_json) BETWEEN 1 AND 8388608),
    FOREIGN KEY (sprint_id)
        REFERENCES current_sprint_authorities_v32(sprint_id) ON DELETE RESTRICT
) STRICT, WITHOUT ROWID;

CREATE TABLE current_task_nodes_v32 (
    sprint_id TEXT NOT NULL,
    task_id TEXT NOT NULL,
    declaration_ordinal INTEGER NOT NULL CHECK (declaration_ordinal >= 0),
    purpose TEXT NOT NULL CHECK (purpose IN ('Ordinary', 'FinalVerificationRepairSlot')),
    repair_slot_ordinal INTEGER,
    required INTEGER NOT NULL CHECK (required IN (0, 1)),
    task_json BLOB NOT NULL CHECK (length(task_json) BETWEEN 1 AND 8388608),
    PRIMARY KEY (sprint_id, task_id),
    UNIQUE (sprint_id, declaration_ordinal),
    UNIQUE (sprint_id, repair_slot_ordinal),
    CHECK (
        (purpose = 'Ordinary' AND repair_slot_ordinal IS NULL)
        OR
        (purpose = 'FinalVerificationRepairSlot'
         AND repair_slot_ordinal > 0 AND required = 0)
    ),
    FOREIGN KEY (sprint_id)
        REFERENCES current_task_graph_authorities_v32(sprint_id) ON DELETE RESTRICT
) STRICT, WITHOUT ROWID;

-- Complete sets are inert until a seal exists. Direct SQL can stage a partial
-- set, but no attempt or repair authority may reference it.
CREATE TABLE current_task_done_sets_v32 (
    set_digest TEXT PRIMARY KEY NOT NULL CHECK (length(set_digest) = 64),
    sprint_id TEXT NOT NULL,
    snapshot_digest TEXT NOT NULL CHECK (length(snapshot_digest) = 64),
    member_count INTEGER NOT NULL CHECK (member_count > 0),
    recorded_at_unix_ms INTEGER NOT NULL CHECK (recorded_at_unix_ms > 0),
    set_json BLOB NOT NULL CHECK (length(set_json) BETWEEN 1 AND 8388608),
    UNIQUE (sprint_id, set_digest),
    FOREIGN KEY (sprint_id)
        REFERENCES current_sprint_authorities_v32(sprint_id) ON DELETE RESTRICT,
    CHECK (grok_task_done_set_v32_canonical(set_json) = 1),
    CHECK (grok_task_done_set_v32_digest(set_json) = set_digest)
) STRICT, WITHOUT ROWID;

CREATE TABLE current_task_done_members_v32 (
    set_digest TEXT NOT NULL,
    sprint_id TEXT NOT NULL,
    member_ordinal INTEGER NOT NULL CHECK (member_ordinal >= 0),
    task_id TEXT NOT NULL,
    task_done_proof_id TEXT NOT NULL CHECK (length(task_done_proof_id) BETWEEN 1 AND 4096),
    integration_receipt_id TEXT NOT NULL CHECK (length(integration_receipt_id) BETWEEN 1 AND 4096),
    integration_kind TEXT NOT NULL CHECK (integration_kind IN ('Changed', 'VerifiedNoOp')),
    empty_change_set_id TEXT CHECK (
        empty_change_set_id IS NULL OR length(empty_change_set_id) BETWEEN 1 AND 4096
    ),
    input_snapshot TEXT NOT NULL CHECK (length(input_snapshot) = 64),
    result_snapshot TEXT NOT NULL CHECK (length(result_snapshot) = 64),
    PRIMARY KEY (set_digest, member_ordinal),
    UNIQUE (set_digest, task_id),
    UNIQUE (set_digest, task_done_proof_id),
    UNIQUE (set_digest, integration_receipt_id),
    UNIQUE (set_digest, empty_change_set_id),
    FOREIGN KEY (sprint_id, set_digest)
        REFERENCES current_task_done_sets_v32(sprint_id, set_digest) ON DELETE RESTRICT,
    FOREIGN KEY (sprint_id, task_id)
        REFERENCES current_task_nodes_v32(sprint_id, task_id) ON DELETE RESTRICT,
    FOREIGN KEY (
        task_done_proof_id, sprint_id, task_id, integration_receipt_id,
        integration_kind, empty_change_set_id, input_snapshot, result_snapshot
    ) REFERENCES current_task_done_sources_v32 (
        task_done_proof_id, sprint_id, task_id, integration_receipt_id,
        integration_kind, empty_change_set_id, input_snapshot, result_snapshot
    ) ON DELETE RESTRICT,
    CHECK (
        (integration_kind = 'Changed'
         AND empty_change_set_id IS NULL
         AND result_snapshot != input_snapshot)
        OR
        (integration_kind = 'VerifiedNoOp'
         AND empty_change_set_id IS NOT NULL
         AND result_snapshot = input_snapshot)
    )
) STRICT, WITHOUT ROWID;

CREATE TABLE current_task_done_set_seals_v32 (
    set_digest TEXT PRIMARY KEY NOT NULL,
    sprint_id TEXT NOT NULL,
    snapshot_digest TEXT NOT NULL CHECK (length(snapshot_digest) = 64),
    sealed_at_unix_ms INTEGER NOT NULL CHECK (sealed_at_unix_ms > 0),
    FOREIGN KEY (sprint_id, set_digest)
        REFERENCES current_task_done_sets_v32(sprint_id, set_digest) ON DELETE RESTRICT,
    FOREIGN KEY (set_digest)
        REFERENCES current_task_done_sets_v32(set_digest) ON DELETE RESTRICT
) STRICT, WITHOUT ROWID;

CREATE TABLE current_criterion_evidence_sets_v32 (
    set_digest TEXT PRIMARY KEY NOT NULL CHECK (length(set_digest) = 64),
    sprint_id TEXT NOT NULL,
    snapshot_digest TEXT NOT NULL CHECK (length(snapshot_digest) = 64),
    member_count INTEGER NOT NULL CHECK (member_count > 0),
    recorded_at_unix_ms INTEGER NOT NULL CHECK (recorded_at_unix_ms > 0),
    set_json BLOB NOT NULL CHECK (length(set_json) BETWEEN 1 AND 8388608),
    UNIQUE (sprint_id, set_digest),
    FOREIGN KEY (sprint_id)
        REFERENCES current_sprint_authorities_v32(sprint_id) ON DELETE RESTRICT,
    CHECK (grok_criterion_evidence_set_v32_canonical(set_json) = 1),
    CHECK (grok_criterion_evidence_set_v32_digest(set_json) = set_digest)
) STRICT, WITHOUT ROWID;

CREATE TABLE current_criterion_evidence_members_v32 (
    set_digest TEXT NOT NULL,
    sprint_id TEXT NOT NULL,
    member_ordinal INTEGER NOT NULL CHECK (member_ordinal >= 0),
    criterion_id TEXT NOT NULL,
    evidence_receipt_id TEXT NOT NULL CHECK (length(evidence_receipt_id) BETWEEN 1 AND 4096),
    evidence_kind TEXT NOT NULL CHECK (evidence_kind IN ('Verified', 'AcceptedByYou')),
    snapshot_digest TEXT NOT NULL CHECK (length(snapshot_digest) = 64),
    PRIMARY KEY (set_digest, member_ordinal),
    UNIQUE (set_digest, criterion_id),
    UNIQUE (set_digest, evidence_receipt_id),
    FOREIGN KEY (sprint_id, set_digest)
        REFERENCES current_criterion_evidence_sets_v32(sprint_id, set_digest) ON DELETE RESTRICT,
    FOREIGN KEY (
        evidence_receipt_id, sprint_id, criterion_id, snapshot_digest, evidence_kind
    ) REFERENCES current_criterion_evidence_receipts_v32 (
        receipt_id, sprint_id, criterion_id, snapshot_digest, evidence_kind
    ) ON DELETE RESTRICT
) STRICT, WITHOUT ROWID;

CREATE TABLE current_criterion_evidence_set_seals_v32 (
    set_digest TEXT PRIMARY KEY NOT NULL,
    sprint_id TEXT NOT NULL,
    snapshot_digest TEXT NOT NULL CHECK (length(snapshot_digest) = 64),
    sealed_at_unix_ms INTEGER NOT NULL CHECK (sealed_at_unix_ms > 0),
    FOREIGN KEY (sprint_id, set_digest)
        REFERENCES current_criterion_evidence_sets_v32(sprint_id, set_digest) ON DELETE RESTRICT,
    FOREIGN KEY (set_digest)
        REFERENCES current_criterion_evidence_sets_v32(set_digest) ON DELETE RESTRICT
) STRICT, WITHOUT ROWID;

CREATE TABLE current_final_verification_controls_v32 (
    control_id TEXT PRIMARY KEY NOT NULL,
    sprint_id TEXT NOT NULL,
    attempt_id TEXT NOT NULL,
    control_kind TEXT NOT NULL CHECK (control_kind IN ('Pause', 'SteeringInterruption', 'Cancel')),
    before_effect INTEGER NOT NULL CHECK (before_effect IN (0, 1)),
    issued_at_unix_ms INTEGER NOT NULL CHECK (issued_at_unix_ms > 0),
    control_json BLOB NOT NULL CHECK (length(control_json) BETWEEN 1 AND 8388608),
    UNIQUE (sprint_id, control_id),
    FOREIGN KEY (sprint_id)
        REFERENCES current_sprint_authorities_v32(sprint_id) ON DELETE RESTRICT,
    CHECK (grok_final_verification_control_v32_canonical(control_json) = 1)
) STRICT, WITHOUT ROWID;

CREATE TABLE current_final_verification_attempts_v32 (
    attempt_id TEXT PRIMARY KEY NOT NULL,
    request_id TEXT NOT NULL UNIQUE,
    request_digest TEXT NOT NULL CHECK (length(request_digest) = 64),
    request_json BLOB NOT NULL CHECK (length(request_json) BETWEEN 1 AND 8388608),
    sprint_id TEXT NOT NULL,
    attempt_ordinal INTEGER NOT NULL CHECK (attempt_ordinal BETWEEN 1 AND 3),
    max_final_verification_attempts INTEGER NOT NULL
        CHECK (max_final_verification_attempts BETWEEN 1 AND 3),
    final_verification_admission_id TEXT NOT NULL UNIQUE,
    input_snapshot TEXT NOT NULL CHECK (length(input_snapshot) = 64),
    complete_task_done_set_digest TEXT NOT NULL CHECK (length(complete_task_done_set_digest) = 64),
    complete_criterion_evidence_set_digest TEXT NOT NULL CHECK (length(complete_criterion_evidence_set_digest) = 64),
    predecessor_kind TEXT NOT NULL CHECK (predecessor_kind IN (
        'Initial', 'SameSnapshotAfterFailedBeforeEffect',
        'SameSnapshotAfterControlInterruption', 'ChangedSnapshotAfterRepair'
    )),
    predecessor_attempt_id TEXT,
    predecessor_outcome_id TEXT,
    predecessor_control_id TEXT,
    predecessor_closure_id TEXT,
    repair_activation_id TEXT,
    repair_task_done_proof_id TEXT,
    repair_integration_receipt_id TEXT,
    authority_digest TEXT NOT NULL UNIQUE CHECK (length(authority_digest) = 64),
    admitted_at_unix_ms INTEGER NOT NULL CHECK (admitted_at_unix_ms > 0),
    authority_json BLOB NOT NULL CHECK (length(authority_json) BETWEEN 1 AND 8388608),
    UNIQUE (sprint_id, attempt_ordinal),
    UNIQUE (sprint_id, attempt_id),
    FOREIGN KEY (sprint_id)
        REFERENCES current_sprint_authorities_v32(sprint_id) ON DELETE RESTRICT,
    FOREIGN KEY (complete_task_done_set_digest)
        REFERENCES current_task_done_set_seals_v32(set_digest) ON DELETE RESTRICT,
    FOREIGN KEY (complete_criterion_evidence_set_digest)
        REFERENCES current_criterion_evidence_set_seals_v32(set_digest) ON DELETE RESTRICT,
    CHECK (grok_final_verification_attempt_v32_canonical(authority_json) = 1),
    CHECK (grok_final_verification_attempt_v32_digest(authority_json) = authority_digest),
    CHECK (grok_final_verification_admission_request_v32_canonical(request_json) = 1),
    CHECK (grok_final_verification_admission_request_v32_digest(request_json) = request_digest)
) STRICT, WITHOUT ROWID;

CREATE TABLE current_final_verification_capture_closures_v32 (
    closure_id TEXT PRIMARY KEY NOT NULL,
    sprint_id TEXT NOT NULL,
    attempt_id TEXT NOT NULL UNIQUE,
    termination_kind TEXT NOT NULL CHECK (termination_kind IN (
        'Exited', 'Signaled', 'TimedOut', 'OutputLimitExceeded',
        'FailedBeforeEffect', 'InterruptedBeforeEffect',
        'InterruptedAfterEffect', 'Canceled', 'Unknown'
    )),
    termination_code INTEGER,
    control_id TEXT,
    custody_kind TEXT NOT NULL CHECK (custody_kind IN (
        'PublishedClean', 'AbandonedSensitive', 'ClosedBeforeCapture', 'Unknown'
    )),
    custody_receipt_id TEXT,
    runner_cleanup_proof_id TEXT,
    command_domain_cleanup_proof_id TEXT,
    terminal_at_unix_ms INTEGER NOT NULL CHECK (terminal_at_unix_ms > 0),
    closure_json BLOB NOT NULL CHECK (length(closure_json) BETWEEN 1 AND 8388608),
    UNIQUE (sprint_id, closure_id),
    FOREIGN KEY (sprint_id, attempt_id)
        REFERENCES current_final_verification_attempts_v32(sprint_id, attempt_id) ON DELETE RESTRICT,
    CHECK (grok_final_verification_capture_v32_canonical(closure_json) = 1)
) STRICT, WITHOUT ROWID;

CREATE TABLE current_final_verification_outcomes_v32 (
    outcome_id TEXT PRIMARY KEY NOT NULL,
    sprint_id TEXT NOT NULL,
    attempt_id TEXT NOT NULL UNIQUE,
    closure_id TEXT NOT NULL UNIQUE,
    outcome_kind TEXT NOT NULL CHECK (outcome_kind IN (
        'Verified', 'NonzeroExit', 'Signaled', 'TimedOut',
        'OutputLimitExceeded', 'SensitiveOutputRejected',
        'FailedBeforeEffect', 'ControlInterruptedBeforeEffect',
        'Canceled', 'Unknown'
    )),
    outcome_code INTEGER,
    terminal_at_unix_ms INTEGER NOT NULL CHECK (terminal_at_unix_ms > 0),
    outcome_json BLOB NOT NULL CHECK (length(outcome_json) BETWEEN 1 AND 8388608),
    UNIQUE (sprint_id, outcome_id),
    FOREIGN KEY (sprint_id, attempt_id)
        REFERENCES current_final_verification_attempts_v32(sprint_id, attempt_id) ON DELETE RESTRICT,
    FOREIGN KEY (closure_id)
        REFERENCES current_final_verification_capture_closures_v32(closure_id) ON DELETE RESTRICT,
    CHECK (grok_final_verification_outcome_v32_canonical(outcome_json) = 1)
) STRICT, WITHOUT ROWID;

CREATE TABLE current_final_verification_repair_activations_v32 (
    activation_id TEXT PRIMARY KEY NOT NULL,
    sprint_id TEXT NOT NULL,
    failed_attempt_id TEXT NOT NULL UNIQUE,
    failure_outcome_id TEXT NOT NULL UNIQUE,
    failed_snapshot TEXT NOT NULL CHECK (length(failed_snapshot) = 64),
    slot_ordinal INTEGER NOT NULL CHECK (slot_ordinal BETWEEN 1 AND 2),
    repair_task_id TEXT NOT NULL,
    activated_at_unix_ms INTEGER NOT NULL CHECK (activated_at_unix_ms > 0),
    activation_json BLOB NOT NULL CHECK (length(activation_json) BETWEEN 1 AND 8388608),
    UNIQUE (sprint_id, slot_ordinal),
    UNIQUE (sprint_id, repair_task_id),
    FOREIGN KEY (sprint_id, failed_attempt_id)
        REFERENCES current_final_verification_attempts_v32(sprint_id, attempt_id) ON DELETE RESTRICT,
    FOREIGN KEY (sprint_id, failure_outcome_id)
        REFERENCES current_final_verification_outcomes_v32(sprint_id, outcome_id) ON DELETE RESTRICT,
    FOREIGN KEY (sprint_id, repair_task_id)
        REFERENCES current_task_nodes_v32(sprint_id, task_id) ON DELETE RESTRICT,
    CHECK (grok_final_verification_repair_activation_v32_canonical(activation_json) = 1)
) STRICT, WITHOUT ROWID;

CREATE TABLE current_final_verification_repair_completions_v32 (
    completion_id TEXT PRIMARY KEY NOT NULL,
    request_id TEXT NOT NULL UNIQUE,
    request_digest TEXT NOT NULL CHECK (length(request_digest) = 64),
    sprint_id TEXT NOT NULL,
    activation_id TEXT NOT NULL UNIQUE,
    failed_attempt_id TEXT NOT NULL UNIQUE,
    repair_task_id TEXT NOT NULL,
    repair_task_done_proof_id TEXT NOT NULL UNIQUE,
    integration_receipt_id TEXT NOT NULL UNIQUE,
    input_snapshot TEXT NOT NULL CHECK (length(input_snapshot) = 64),
    result_snapshot TEXT NOT NULL CHECK (length(result_snapshot) = 64),
    change_set_id TEXT NOT NULL UNIQUE,
    operation_count INTEGER NOT NULL CHECK (operation_count > 0),
    complete_task_done_set_digest TEXT NOT NULL CHECK (length(complete_task_done_set_digest) = 64),
    complete_criterion_evidence_set_digest TEXT NOT NULL CHECK (length(complete_criterion_evidence_set_digest) = 64),
    completed_at_unix_ms INTEGER NOT NULL CHECK (completed_at_unix_ms > 0),
    completion_json BLOB NOT NULL CHECK (length(completion_json) BETWEEN 1 AND 8388608),
    UNIQUE (sprint_id, completion_id),
    FOREIGN KEY (activation_id)
        REFERENCES current_final_verification_repair_activations_v32(activation_id) ON DELETE RESTRICT,
    FOREIGN KEY (sprint_id, failed_attempt_id)
        REFERENCES current_final_verification_attempts_v32(sprint_id, attempt_id) ON DELETE RESTRICT,
    FOREIGN KEY (sprint_id, repair_task_id)
        REFERENCES current_task_nodes_v32(sprint_id, task_id) ON DELETE RESTRICT,
    FOREIGN KEY (complete_task_done_set_digest)
        REFERENCES current_task_done_set_seals_v32(set_digest) ON DELETE RESTRICT,
    FOREIGN KEY (complete_criterion_evidence_set_digest)
        REFERENCES current_criterion_evidence_set_seals_v32(set_digest) ON DELETE RESTRICT,
    CHECK (input_snapshot != result_snapshot),
    CHECK (grok_final_verification_repair_completion_v32_canonical(completion_json) = 1)
) STRICT, WITHOUT ROWID;

CREATE TABLE current_sprint_terminal_outcomes_v32 (
    sprint_id TEXT PRIMARY KEY NOT NULL,
    terminal_state TEXT NOT NULL CHECK (terminal_state IN ('Failed', 'Canceled', 'Unknown')),
    source_attempt_id TEXT NOT NULL UNIQUE,
    source_outcome_id TEXT NOT NULL UNIQUE,
    terminal_reason TEXT NOT NULL CHECK (terminal_reason IN (
        'FinalVerificationAttemptsExhausted', 'ExplicitCancel', 'AmbiguousFinalVerification'
    )),
    terminal_at_unix_ms INTEGER NOT NULL CHECK (terminal_at_unix_ms > 0),
    FOREIGN KEY (sprint_id, source_attempt_id)
        REFERENCES current_final_verification_attempts_v32(sprint_id, attempt_id) ON DELETE RESTRICT,
    FOREIGN KEY (sprint_id, source_outcome_id)
        REFERENCES current_final_verification_outcomes_v32(sprint_id, outcome_id) ON DELETE RESTRICT
) STRICT, WITHOUT ROWID;

CREATE TRIGGER current_sprint_authorities_v32_validate
BEFORE INSERT ON current_sprint_authorities_v32
WHEN NOT (
    json_extract(CAST(NEW.spec_json AS TEXT), '$.sprint_authority_version') = NEW.sprint_authority_version
    AND json_extract(CAST(NEW.spec_json AS TEXT), '$.sprint_id') = NEW.sprint_id
    AND json_extract(CAST(NEW.spec_json AS TEXT), '$.task_graph_id') = NEW.task_graph_id
    AND json_extract(CAST(NEW.spec_json AS TEXT), '$.task_graph_payload_digest') = NEW.task_graph_payload_digest
    AND json_extract(CAST(NEW.spec_json AS TEXT), '$.repair_slot_reserve_digest') = NEW.repair_slot_reserve_digest
    AND json_extract(CAST(NEW.spec_json AS TEXT), '$.budget.max_final_verification_attempts') = NEW.max_final_verification_attempts
    AND json_extract(CAST(NEW.spec_json AS TEXT), '$.base_snapshot') = NEW.base_snapshot
    AND json_extract(CAST(NEW.spec_json AS TEXT), '$.workspace_grant.grant_hash') = NEW.workspace_grant_hash
)
BEGIN SELECT RAISE(ABORT, 'current sprint columns must match exact canonical V2 bytes'); END;

CREATE TRIGGER current_task_graph_authorities_v32_validate
BEFORE INSERT ON current_task_graph_authorities_v32
WHEN NOT EXISTS (
    SELECT 1 FROM current_sprint_authorities_v32 sprint
    WHERE sprint.sprint_id = NEW.sprint_id
      AND sprint.task_graph_id = NEW.graph_id
      AND sprint.sprint_authority_version = NEW.sprint_authority_version
      AND sprint.sprint_spec_digest = NEW.sprint_spec_digest
      AND sprint.task_graph_payload_digest = NEW.graph_payload_digest
      AND sprint.repair_slot_reserve_digest = NEW.repair_slot_reserve_digest
      AND json_extract(CAST(NEW.graph_json AS TEXT), '$.sprint_authority_version') = NEW.sprint_authority_version
      AND json_extract(CAST(NEW.graph_json AS TEXT), '$.graph_id') = NEW.graph_id
      AND json_extract(CAST(NEW.graph_json AS TEXT), '$.sprint_id') = NEW.sprint_id
      AND json_extract(CAST(NEW.graph_json AS TEXT), '$.sprint_spec_digest') = NEW.sprint_spec_digest
      AND json_extract(CAST(NEW.graph_json AS TEXT), '$.repair_slot_reserve_digest') = NEW.repair_slot_reserve_digest
      AND grok_task_graph_v32_pair_canonical(NEW.graph_json, sprint.spec_json) = 1
      AND grok_task_graph_v32_digest(NEW.graph_json, sprint.spec_json) = NEW.graph_digest
)
BEGIN SELECT RAISE(ABORT, 'current task graph crosses its exact sprint authority'); END;

CREATE TRIGGER current_task_nodes_v32_validate
BEFORE INSERT ON current_task_nodes_v32
WHEN NOT EXISTS (
    SELECT 1 FROM current_task_graph_authorities_v32 graph
    WHERE graph.sprint_id = NEW.sprint_id
      AND NEW.declaration_ordinal < json_array_length(CAST(graph.graph_json AS TEXT), '$.tasks')
      AND json(CAST(NEW.task_json AS TEXT)) = json_extract(
          CAST(graph.graph_json AS TEXT), printf('$.tasks[%d]', NEW.declaration_ordinal)
      )
      AND json_extract(CAST(NEW.task_json AS TEXT), '$.task_id') = NEW.task_id
      AND CASE json_extract(CAST(NEW.task_json AS TEXT), '$.purpose.kind')
          WHEN 'ordinary' THEN 'Ordinary'
          WHEN 'final_verification_repair_slot' THEN 'FinalVerificationRepairSlot'
          ELSE NULL
      END = NEW.purpose
      AND json_extract(CAST(NEW.task_json AS TEXT), '$.purpose.slot_ordinal') IS NEW.repair_slot_ordinal
      AND json_extract(CAST(NEW.task_json AS TEXT), '$.required') = NEW.required
)
BEGIN SELECT RAISE(ABORT, 'current task node must equal its exact canonical graph member'); END;

CREATE TRIGGER current_final_verification_controls_v32_validate
BEFORE INSERT ON current_final_verification_controls_v32
WHEN NOT EXISTS (
    SELECT 1 FROM current_final_verification_attempts_v32 attempt
    WHERE attempt.attempt_id = NEW.attempt_id
      AND attempt.sprint_id = NEW.sprint_id
      AND attempt.admitted_at_unix_ms <= NEW.issued_at_unix_ms
      AND json_extract(CAST(NEW.control_json AS TEXT), '$.control_id') = NEW.control_id
      AND json_extract(CAST(NEW.control_json AS TEXT), '$.sprint_id') = NEW.sprint_id
      AND json_extract(CAST(NEW.control_json AS TEXT), '$.attempt_id') = NEW.attempt_id
      AND json_extract(CAST(NEW.control_json AS TEXT), '$.control_kind') = NEW.control_kind
      AND json_extract(CAST(NEW.control_json AS TEXT), '$.before_effect') = NEW.before_effect
      AND json_extract(CAST(NEW.control_json AS TEXT), '$.issued_at_unix_ms') = NEW.issued_at_unix_ms
      AND NOT EXISTS (
          SELECT 1 FROM current_final_verification_outcomes_v32 outcome
          WHERE outcome.attempt_id = NEW.attempt_id
      )
      AND NOT EXISTS (
          SELECT 1 FROM current_sprint_terminal_outcomes_v32 terminal
          WHERE terminal.sprint_id = NEW.sprint_id
      )
)
BEGIN SELECT RAISE(ABORT, 'current final-verification control crosses attempt, outcome, terminal, or time authority'); END;

-- Seal validation. A set is authority-bearing only after exact source joins,
-- full sprint/graph coverage, contiguous ordinals, and snapshot closure.
CREATE TRIGGER current_task_done_set_seals_v32_validate
BEFORE INSERT ON current_task_done_set_seals_v32
WHEN NOT EXISTS (
    SELECT 1
    FROM current_task_done_sets_v32 set_row
    JOIN current_sprint_authorities_v32 sprint
      ON sprint.sprint_id = set_row.sprint_id
    JOIN current_task_graph_authorities_v32 graph
      ON graph.sprint_id = set_row.sprint_id
    WHERE set_row.set_digest = NEW.set_digest
      AND set_row.sprint_id = NEW.sprint_id
      AND set_row.snapshot_digest = NEW.snapshot_digest
      AND set_row.recorded_at_unix_ms <= NEW.sealed_at_unix_ms
      AND json_extract(CAST(set_row.set_json AS TEXT), '$.sprint_id') = set_row.sprint_id
      AND json_extract(CAST(set_row.set_json AS TEXT), '$.snapshot_digest') = set_row.snapshot_digest
      AND json_extract(CAST(set_row.set_json AS TEXT), '$.recorded_at_unix_ms') = set_row.recorded_at_unix_ms
      AND json_array_length(CAST(set_row.set_json AS TEXT), '$.members') = set_row.member_count
      AND grok_task_done_set_v32_matches_authority(
          set_row.set_json, sprint.spec_json, graph.graph_json
      ) = 1
      AND set_row.member_count = (
          SELECT COUNT(*) FROM current_task_done_members_v32 member
          WHERE member.set_digest = NEW.set_digest
      )
      AND 0 = (
          SELECT MIN(member_ordinal) FROM current_task_done_members_v32 member
          WHERE member.set_digest = NEW.set_digest
      )
      AND set_row.member_count - 1 = (
          SELECT MAX(member_ordinal) FROM current_task_done_members_v32 member
          WHERE member.set_digest = NEW.set_digest
      )
      AND NEW.snapshot_digest = (
          SELECT result_snapshot FROM current_task_done_members_v32 member
          WHERE member.set_digest = NEW.set_digest
          ORDER BY member_ordinal DESC LIMIT 1
      )
      AND NOT EXISTS (
          SELECT 1 FROM current_task_done_members_v32 member
          WHERE member.set_digest = NEW.set_digest
            AND (member.sprint_id != NEW.sprint_id
                OR NOT EXISTS (
                    SELECT 1 FROM current_task_done_sources_v32 source
                    WHERE source.task_done_proof_id = member.task_done_proof_id
                      AND source.sprint_id = member.sprint_id
                      AND source.task_id = member.task_id
                      AND source.integration_receipt_id = member.integration_receipt_id
                      AND source.integration_kind = member.integration_kind
                      AND source.empty_change_set_id IS member.empty_change_set_id
                      AND source.input_snapshot = member.input_snapshot
                      AND source.result_snapshot = member.result_snapshot
                      AND source.derived_at_unix_ms <= set_row.recorded_at_unix_ms
                )
                OR
                json_extract(CAST(set_row.set_json AS TEXT), printf('$.members[%d].source_ordinal', member.member_ordinal)) != member.member_ordinal
                OR json_extract(CAST(set_row.set_json AS TEXT), printf('$.members[%d].task_id', member.member_ordinal)) != member.task_id
                OR json_extract(CAST(set_row.set_json AS TEXT), printf('$.members[%d].task_done_proof_id', member.member_ordinal)) != member.task_done_proof_id
                OR json_extract(CAST(set_row.set_json AS TEXT), printf('$.members[%d].integration_receipt_id', member.member_ordinal)) != member.integration_receipt_id
                OR CASE json_extract(CAST(set_row.set_json AS TEXT), printf('$.members[%d].integration_evidence.kind', member.member_ordinal))
                       WHEN 'changed' THEN 'Changed'
                       WHEN 'verified_no_op' THEN 'VerifiedNoOp'
                       ELSE NULL
                   END != member.integration_kind
                OR CASE member.integration_kind
                       WHEN 'VerifiedNoOp' THEN json_extract(CAST(set_row.set_json AS TEXT), printf('$.members[%d].integration_evidence.empty_change_set_id', member.member_ordinal))
                       ELSE NULL
                   END IS NOT member.empty_change_set_id
                OR json_extract(CAST(set_row.set_json AS TEXT), printf('$.members[%d].input_snapshot', member.member_ordinal)) != member.input_snapshot
                OR json_extract(CAST(set_row.set_json AS TEXT), printf('$.members[%d].result_snapshot', member.member_ordinal)) != member.result_snapshot
            )
      )
)
BEGIN SELECT RAISE(ABORT, 'current TaskDone set seal requires exact contiguous same-snapshot members'); END;

CREATE TRIGGER current_criterion_evidence_set_seals_v32_validate
BEFORE INSERT ON current_criterion_evidence_set_seals_v32
WHEN NOT EXISTS (
    SELECT 1
    FROM current_criterion_evidence_sets_v32 set_row
    JOIN current_sprint_authorities_v32 sprint
      ON sprint.sprint_id = set_row.sprint_id
    WHERE set_row.set_digest = NEW.set_digest
      AND set_row.sprint_id = NEW.sprint_id
      AND set_row.snapshot_digest = NEW.snapshot_digest
      AND set_row.recorded_at_unix_ms <= NEW.sealed_at_unix_ms
      AND json_extract(CAST(set_row.set_json AS TEXT), '$.sprint_id') = set_row.sprint_id
      AND json_extract(CAST(set_row.set_json AS TEXT), '$.snapshot_digest') = set_row.snapshot_digest
      AND json_extract(CAST(set_row.set_json AS TEXT), '$.recorded_at_unix_ms') = set_row.recorded_at_unix_ms
      AND json_array_length(CAST(set_row.set_json AS TEXT), '$.members') = set_row.member_count
      AND grok_criterion_evidence_set_v32_matches_sprint(
          set_row.set_json, sprint.spec_json
      ) = 1
      AND set_row.member_count = (
          SELECT COUNT(*) FROM current_criterion_evidence_members_v32 member
          WHERE member.set_digest = NEW.set_digest
      )
      AND 0 = (
          SELECT MIN(member_ordinal) FROM current_criterion_evidence_members_v32 member
          WHERE member.set_digest = NEW.set_digest
      )
      AND set_row.member_count - 1 = (
          SELECT MAX(member_ordinal) FROM current_criterion_evidence_members_v32 member
          WHERE member.set_digest = NEW.set_digest
      )
      AND NOT EXISTS (
          SELECT 1 FROM current_criterion_evidence_members_v32 member
          WHERE member.set_digest = NEW.set_digest
            AND member.snapshot_digest != NEW.snapshot_digest
      )
      AND NOT EXISTS (
          SELECT 1 FROM current_criterion_evidence_members_v32 member
          WHERE member.set_digest = NEW.set_digest
            AND (member.sprint_id != NEW.sprint_id
                OR NOT EXISTS (
                    SELECT 1 FROM current_criterion_evidence_receipts_v32 source
                    WHERE source.receipt_id = member.evidence_receipt_id
                      AND source.sprint_id = member.sprint_id
                      AND source.criterion_id = member.criterion_id
                      AND source.snapshot_digest = member.snapshot_digest
                      AND source.evidence_kind = member.evidence_kind
                      AND source.recorded_at_unix_ms <= set_row.recorded_at_unix_ms
                )
                OR
                json_extract(CAST(set_row.set_json AS TEXT), printf('$.members[%d].criterion_ordinal', member.member_ordinal)) != member.member_ordinal
                OR json_extract(CAST(set_row.set_json AS TEXT), printf('$.members[%d].criterion_id', member.member_ordinal)) != member.criterion_id
                OR json_extract(CAST(set_row.set_json AS TEXT), printf('$.members[%d].evidence_receipt_id', member.member_ordinal)) != member.evidence_receipt_id
                OR CASE json_extract(CAST(set_row.set_json AS TEXT), printf('$.members[%d].evidence_kind', member.member_ordinal))
                    WHEN 'Verified' THEN 'Verified'
                    WHEN 'AcceptedByYou' THEN 'AcceptedByYou'
                    ELSE NULL
                END != member.evidence_kind
                OR json_extract(CAST(set_row.set_json AS TEXT), printf('$.members[%d].snapshot_digest', member.member_ordinal)) != member.snapshot_digest
            )
      )
)
BEGIN SELECT RAISE(ABORT, 'current criterion-evidence set seal requires exact contiguous same-snapshot members'); END;

-- Direct SQL cannot skip or exceed an ordinal, use crossed complete sets, or
-- admit a successor while the prior attempt lacks one exact terminal outcome.
CREATE TRIGGER current_final_verification_attempts_v32_validate
BEFORE INSERT ON current_final_verification_attempts_v32
WHEN NOT EXISTS (
    SELECT 1
    FROM current_sprint_authorities_v32 sprint
    JOIN current_task_done_set_seals_v32 task_set
      ON task_set.set_digest = NEW.complete_task_done_set_digest
     AND task_set.sprint_id = NEW.sprint_id
     AND task_set.snapshot_digest = NEW.input_snapshot
    JOIN current_criterion_evidence_set_seals_v32 criterion_set
      ON criterion_set.set_digest = NEW.complete_criterion_evidence_set_digest
     AND criterion_set.sprint_id = NEW.sprint_id
     AND criterion_set.snapshot_digest = NEW.input_snapshot
    WHERE sprint.sprint_id = NEW.sprint_id
      AND sprint.max_final_verification_attempts = NEW.max_final_verification_attempts
      AND NEW.attempt_ordinal <= sprint.max_final_verification_attempts
      AND grok_final_verification_attempt_request_matches_v32(
          NEW.request_json, NEW.authority_json, NEW.request_id
      ) = 1
      AND json_extract(CAST(NEW.authority_json AS TEXT), '$.attempt_id') = NEW.attempt_id
      AND json_extract(CAST(NEW.authority_json AS TEXT), '$.sprint_id') = NEW.sprint_id
      AND json_extract(CAST(NEW.authority_json AS TEXT), '$.attempt_ordinal') = NEW.attempt_ordinal
      AND json_extract(CAST(NEW.authority_json AS TEXT), '$.max_final_verification_attempts') = NEW.max_final_verification_attempts
      AND json_extract(CAST(NEW.authority_json AS TEXT), '$.final_verification_admission_id') = NEW.final_verification_admission_id
      AND json_extract(CAST(NEW.authority_json AS TEXT), '$.input_snapshot') = NEW.input_snapshot
      AND json_extract(CAST(NEW.authority_json AS TEXT), '$.complete_task_done_set_digest') = NEW.complete_task_done_set_digest
      AND json_extract(CAST(NEW.authority_json AS TEXT), '$.complete_criterion_evidence_set_digest') = NEW.complete_criterion_evidence_set_digest
      AND json_extract(CAST(NEW.authority_json AS TEXT), '$.provenance.admitted_at_unix_ms') = NEW.admitted_at_unix_ms
      AND CASE json_extract(CAST(NEW.authority_json AS TEXT), '$.predecessor.kind')
          WHEN 'initial' THEN 'Initial'
          WHEN 'same_snapshot_after_failed_before_effect' THEN 'SameSnapshotAfterFailedBeforeEffect'
          WHEN 'same_snapshot_after_control_interruption' THEN 'SameSnapshotAfterControlInterruption'
          WHEN 'changed_snapshot_after_repair' THEN 'ChangedSnapshotAfterRepair'
          ELSE NULL
      END = NEW.predecessor_kind
      AND CASE WHEN NEW.predecessor_kind IN (
          'SameSnapshotAfterFailedBeforeEffect', 'SameSnapshotAfterControlInterruption'
      ) THEN json_extract(CAST(NEW.authority_json AS TEXT), '$.predecessor.prior_attempt_id')
      ELSE NEW.predecessor_attempt_id END IS NEW.predecessor_attempt_id
      AND CASE WHEN NEW.predecessor_kind = 'SameSnapshotAfterControlInterruption'
          THEN json_extract(CAST(NEW.authority_json AS TEXT), '$.predecessor.control_id')
          ELSE NULL END IS NEW.predecessor_control_id
      AND CASE WHEN NEW.predecessor_kind IN (
          'SameSnapshotAfterFailedBeforeEffect', 'SameSnapshotAfterControlInterruption'
      ) THEN json_extract(CAST(NEW.authority_json AS TEXT), '$.predecessor.closure_id')
      ELSE NEW.predecessor_closure_id END IS NEW.predecessor_closure_id
      AND CASE WHEN NEW.predecessor_kind = 'ChangedSnapshotAfterRepair'
          THEN json_extract(CAST(NEW.authority_json AS TEXT), '$.predecessor.prior_failure_id')
          ELSE NEW.predecessor_outcome_id END IS NEW.predecessor_outcome_id
      AND CASE WHEN NEW.predecessor_kind = 'ChangedSnapshotAfterRepair'
          THEN json_extract(CAST(NEW.authority_json AS TEXT), '$.predecessor.repair_admission_id')
          ELSE NULL END IS NEW.repair_activation_id
      AND CASE WHEN NEW.predecessor_kind = 'ChangedSnapshotAfterRepair'
          THEN json_extract(CAST(NEW.authority_json AS TEXT), '$.predecessor.repair_task_done_proof_id')
          ELSE NULL END IS NEW.repair_task_done_proof_id
      AND CASE WHEN NEW.predecessor_kind = 'ChangedSnapshotAfterRepair'
          THEN json_extract(CAST(NEW.authority_json AS TEXT), '$.predecessor.integration_receipt_id')
          ELSE NULL END IS NEW.repair_integration_receipt_id
      AND NEW.attempt_ordinal = 1 + COALESCE((
          SELECT MAX(prior.attempt_ordinal)
          FROM current_final_verification_attempts_v32 prior
          WHERE prior.sprint_id = NEW.sprint_id
      ), 0)
      AND NOT EXISTS (
          SELECT 1 FROM current_sprint_terminal_outcomes_v32 terminal
          WHERE terminal.sprint_id = NEW.sprint_id
      )
      AND (
          (NEW.attempt_ordinal = 1 AND NEW.predecessor_kind = 'Initial'
           AND NEW.predecessor_attempt_id IS NULL AND NEW.predecessor_outcome_id IS NULL
           AND NEW.predecessor_control_id IS NULL AND NEW.predecessor_closure_id IS NULL
           AND NEW.repair_activation_id IS NULL AND NEW.repair_task_done_proof_id IS NULL
           AND NEW.repair_integration_receipt_id IS NULL
           AND NOT EXISTS (
               SELECT 1
               FROM current_task_done_members_v32 member
               JOIN current_task_nodes_v32 task
                 ON task.sprint_id = NEW.sprint_id
                AND task.task_id = member.task_id
               WHERE member.set_digest = NEW.complete_task_done_set_digest
                 AND task.purpose = 'FinalVerificationRepairSlot'
           ))
          OR
          (NEW.attempt_ordinal > 1
           AND NEW.predecessor_kind = 'SameSnapshotAfterFailedBeforeEffect'
           AND NEW.predecessor_control_id IS NULL
           AND NEW.repair_activation_id IS NULL
           AND NEW.repair_task_done_proof_id IS NULL
           AND NEW.repair_integration_receipt_id IS NULL
           AND EXISTS (
              SELECT 1
              FROM current_final_verification_attempts_v32 prior
              JOIN current_final_verification_outcomes_v32 outcome
                ON outcome.attempt_id = prior.attempt_id
              WHERE prior.sprint_id = NEW.sprint_id
                AND prior.attempt_ordinal = NEW.attempt_ordinal - 1
                AND prior.attempt_id = NEW.predecessor_attempt_id
                AND outcome.outcome_id = NEW.predecessor_outcome_id
                AND outcome.outcome_kind = 'FailedBeforeEffect'
                AND outcome.closure_id = NEW.predecessor_closure_id
                AND NEW.input_snapshot = prior.input_snapshot
                AND NEW.complete_task_done_set_digest = prior.complete_task_done_set_digest
                AND NEW.complete_criterion_evidence_set_digest = prior.complete_criterion_evidence_set_digest
          ))
          OR
          (NEW.attempt_ordinal > 1
           AND NEW.predecessor_kind = 'SameSnapshotAfterControlInterruption'
           AND NEW.repair_activation_id IS NULL
           AND NEW.repair_task_done_proof_id IS NULL
           AND NEW.repair_integration_receipt_id IS NULL
           AND EXISTS (
              SELECT 1
              FROM current_final_verification_attempts_v32 prior
              JOIN current_final_verification_outcomes_v32 outcome
                ON outcome.attempt_id = prior.attempt_id
              JOIN current_final_verification_capture_closures_v32 closure
                ON closure.closure_id = outcome.closure_id
              WHERE prior.sprint_id = NEW.sprint_id
                AND prior.attempt_ordinal = NEW.attempt_ordinal - 1
                AND prior.attempt_id = NEW.predecessor_attempt_id
                AND outcome.outcome_id = NEW.predecessor_outcome_id
                AND outcome.outcome_kind = 'ControlInterruptedBeforeEffect'
                AND outcome.closure_id = NEW.predecessor_closure_id
                AND closure.control_id = NEW.predecessor_control_id
                AND NEW.input_snapshot = prior.input_snapshot
                AND NEW.complete_task_done_set_digest = prior.complete_task_done_set_digest
                AND NEW.complete_criterion_evidence_set_digest = prior.complete_criterion_evidence_set_digest
           ))
          OR
          (NEW.attempt_ordinal > 1
           AND NEW.predecessor_kind = 'ChangedSnapshotAfterRepair'
           AND NEW.predecessor_control_id IS NULL
           AND EXISTS (
              SELECT 1
              FROM current_final_verification_attempts_v32 prior
              JOIN current_final_verification_outcomes_v32 outcome
                ON outcome.attempt_id = prior.attempt_id
              JOIN current_final_verification_repair_completions_v32 completion
                ON completion.failed_attempt_id = prior.attempt_id
              WHERE prior.sprint_id = NEW.sprint_id
                AND prior.attempt_ordinal = NEW.attempt_ordinal - 1
                AND prior.attempt_id = NEW.predecessor_attempt_id
                AND outcome.outcome_id = NEW.predecessor_outcome_id
                AND outcome.outcome_kind IN (
                    'NonzeroExit', 'Signaled', 'TimedOut',
                    'OutputLimitExceeded', 'SensitiveOutputRejected'
                )
                AND outcome.closure_id = NEW.predecessor_closure_id
                AND completion.activation_id = NEW.repair_activation_id
                AND completion.repair_task_done_proof_id = NEW.repair_task_done_proof_id
                AND completion.integration_receipt_id = NEW.repair_integration_receipt_id
                AND completion.result_snapshot = NEW.input_snapshot
                AND completion.complete_task_done_set_digest = NEW.complete_task_done_set_digest
                AND completion.complete_criterion_evidence_set_digest = NEW.complete_criterion_evidence_set_digest
                AND completion.completed_at_unix_ms <= NEW.admitted_at_unix_ms
           ))
      )
)
BEGIN SELECT RAISE(ABORT, 'current final-verification attempt crosses cap, ordinal, terminal, set, or predecessor authority'); END;

CREATE TRIGGER current_final_verification_capture_closures_v32_validate
BEFORE INSERT ON current_final_verification_capture_closures_v32
WHEN NOT EXISTS (
    SELECT 1 FROM current_final_verification_attempts_v32 attempt
    WHERE attempt.attempt_id = NEW.attempt_id
      AND attempt.sprint_id = NEW.sprint_id
      AND attempt.admitted_at_unix_ms <= NEW.terminal_at_unix_ms
      AND json_extract(CAST(NEW.closure_json AS TEXT), '$.closure_id') = NEW.closure_id
      AND json_extract(CAST(NEW.closure_json AS TEXT), '$.sprint_id') = NEW.sprint_id
      AND json_extract(CAST(NEW.closure_json AS TEXT), '$.attempt_id') = NEW.attempt_id
      AND CASE json_extract(CAST(NEW.closure_json AS TEXT), '$.termination.kind')
          WHEN 'exited' THEN 'Exited'
          WHEN 'signaled' THEN 'Signaled'
          WHEN 'timed_out' THEN 'TimedOut'
          WHEN 'output_limit_exceeded' THEN 'OutputLimitExceeded'
          WHEN 'failed_before_effect' THEN 'FailedBeforeEffect'
          WHEN 'interrupted_before_effect' THEN 'InterruptedBeforeEffect'
          WHEN 'interrupted_after_effect' THEN 'InterruptedAfterEffect'
          WHEN 'canceled' THEN 'Canceled'
          WHEN 'unknown' THEN 'Unknown'
          ELSE NULL
      END = NEW.termination_kind
      AND CASE NEW.termination_kind
          WHEN 'Exited' THEN json_extract(CAST(NEW.closure_json AS TEXT), '$.termination.code')
          WHEN 'Signaled' THEN json_extract(CAST(NEW.closure_json AS TEXT), '$.termination.signal')
          ELSE NULL
      END IS NEW.termination_code
      AND CASE WHEN NEW.termination_kind IN (
          'InterruptedBeforeEffect', 'InterruptedAfterEffect', 'Canceled'
      ) THEN json_extract(CAST(NEW.closure_json AS TEXT), '$.termination.control_id')
      ELSE NULL END IS NEW.control_id
      AND CASE json_extract(CAST(NEW.closure_json AS TEXT), '$.output_custody.kind')
          WHEN 'published_clean' THEN 'PublishedClean'
          WHEN 'abandoned_sensitive' THEN 'AbandonedSensitive'
          WHEN 'closed_before_capture' THEN 'ClosedBeforeCapture'
          WHEN 'unknown' THEN 'Unknown'
          ELSE NULL
      END = NEW.custody_kind
      AND CASE NEW.custody_kind
          WHEN 'PublishedClean' THEN json_extract(CAST(NEW.closure_json AS TEXT), '$.output_custody.publication_receipt_id')
          WHEN 'AbandonedSensitive' THEN json_extract(CAST(NEW.closure_json AS TEXT), '$.output_custody.rejection_closure_id')
          WHEN 'ClosedBeforeCapture' THEN json_extract(CAST(NEW.closure_json AS TEXT), '$.output_custody.closure_receipt_id')
          ELSE NULL
      END IS NEW.custody_receipt_id
      AND json_extract(CAST(NEW.closure_json AS TEXT), '$.runner_cleanup_proof_id') IS NEW.runner_cleanup_proof_id
      AND json_extract(CAST(NEW.closure_json AS TEXT), '$.command_domain_cleanup_proof_id') IS NEW.command_domain_cleanup_proof_id
      AND json_extract(CAST(NEW.closure_json AS TEXT), '$.terminal_at_unix_ms') = NEW.terminal_at_unix_ms
      AND NOT EXISTS (
          SELECT 1 FROM current_sprint_terminal_outcomes_v32 terminal
          WHERE terminal.sprint_id = NEW.sprint_id
      )
)
BEGIN SELECT RAISE(ABORT, 'current final-verification capture crosses attempt, terminal, or time authority'); END;

CREATE TRIGGER current_final_verification_outcomes_v32_validate
BEFORE INSERT ON current_final_verification_outcomes_v32
WHEN NOT EXISTS (
    SELECT 1
    FROM current_final_verification_capture_closures_v32 closure
    WHERE closure.closure_id = NEW.closure_id
      AND closure.sprint_id = NEW.sprint_id
      AND closure.attempt_id = NEW.attempt_id
      AND closure.terminal_at_unix_ms = NEW.terminal_at_unix_ms
      AND json_extract(CAST(NEW.outcome_json AS TEXT), '$.outcome_id') = NEW.outcome_id
      AND json_extract(CAST(NEW.outcome_json AS TEXT), '$.sprint_id') = NEW.sprint_id
      AND json_extract(CAST(NEW.outcome_json AS TEXT), '$.attempt_id') = NEW.attempt_id
      AND json_extract(CAST(NEW.outcome_json AS TEXT), '$.closure_id') = NEW.closure_id
      AND CASE json_extract(CAST(NEW.outcome_json AS TEXT), '$.outcome.kind')
          WHEN 'verified' THEN 'Verified'
          WHEN 'nonzero_exit' THEN 'NonzeroExit'
          WHEN 'signaled' THEN 'Signaled'
          WHEN 'timed_out' THEN 'TimedOut'
          WHEN 'output_limit_exceeded' THEN 'OutputLimitExceeded'
          WHEN 'sensitive_output_rejected' THEN 'SensitiveOutputRejected'
          WHEN 'failed_before_effect' THEN 'FailedBeforeEffect'
          WHEN 'control_interrupted_before_effect' THEN 'ControlInterruptedBeforeEffect'
          WHEN 'canceled' THEN 'Canceled'
          WHEN 'unknown' THEN 'Unknown'
          ELSE NULL
      END = NEW.outcome_kind
      AND CASE NEW.outcome_kind
          WHEN 'NonzeroExit' THEN json_extract(CAST(NEW.outcome_json AS TEXT), '$.outcome.code')
          WHEN 'Signaled' THEN json_extract(CAST(NEW.outcome_json AS TEXT), '$.outcome.signal')
          ELSE NULL
      END IS NEW.outcome_code
      AND json_extract(CAST(NEW.outcome_json AS TEXT), '$.terminal_at_unix_ms') = NEW.terminal_at_unix_ms
      AND (
          (NEW.outcome_kind = 'Verified' AND NEW.outcome_code IS NULL
           AND closure.termination_kind = 'Exited' AND closure.termination_code = 0
           AND closure.custody_kind = 'PublishedClean'
           AND closure.custody_receipt_id IS NOT NULL
           AND closure.runner_cleanup_proof_id IS NOT NULL
           AND closure.command_domain_cleanup_proof_id IS NOT NULL)
          OR
          (NEW.outcome_kind = 'NonzeroExit' AND NEW.outcome_code > 0
           AND closure.termination_kind = 'Exited'
           AND closure.termination_code = NEW.outcome_code
           AND closure.custody_kind = 'PublishedClean'
           AND closure.custody_receipt_id IS NOT NULL
           AND closure.runner_cleanup_proof_id IS NOT NULL
           AND closure.command_domain_cleanup_proof_id IS NOT NULL)
          OR
          (NEW.outcome_kind = 'Signaled' AND NEW.outcome_code > 0
           AND closure.termination_kind = 'Signaled'
           AND closure.termination_code = NEW.outcome_code
           AND closure.custody_kind = 'PublishedClean'
           AND closure.custody_receipt_id IS NOT NULL
           AND closure.runner_cleanup_proof_id IS NOT NULL
           AND closure.command_domain_cleanup_proof_id IS NOT NULL)
          OR
          (NEW.outcome_kind = 'TimedOut' AND NEW.outcome_code IS NULL
           AND closure.termination_kind = 'TimedOut'
           AND closure.custody_kind = 'PublishedClean'
           AND closure.custody_receipt_id IS NOT NULL
           AND closure.runner_cleanup_proof_id IS NOT NULL
           AND closure.command_domain_cleanup_proof_id IS NOT NULL)
          OR
          (NEW.outcome_kind = 'OutputLimitExceeded' AND NEW.outcome_code IS NULL
           AND closure.termination_kind = 'OutputLimitExceeded'
           AND closure.custody_kind = 'PublishedClean'
           AND closure.custody_receipt_id IS NOT NULL
           AND closure.runner_cleanup_proof_id IS NOT NULL
           AND closure.command_domain_cleanup_proof_id IS NOT NULL)
          OR
          (NEW.outcome_kind = 'SensitiveOutputRejected' AND NEW.outcome_code IS NULL
           AND closure.custody_kind = 'AbandonedSensitive'
           AND closure.termination_kind NOT IN ('Unknown', 'InterruptedAfterEffect', 'Canceled')
           AND closure.custody_receipt_id IS NOT NULL
           AND closure.runner_cleanup_proof_id IS NOT NULL
           AND closure.command_domain_cleanup_proof_id IS NOT NULL)
          OR
          (NEW.outcome_kind = 'FailedBeforeEffect' AND NEW.outcome_code IS NULL
           AND closure.termination_kind = 'FailedBeforeEffect'
           AND closure.custody_kind = 'ClosedBeforeCapture'
           AND closure.custody_receipt_id IS NOT NULL
           AND closure.runner_cleanup_proof_id IS NOT NULL
           AND closure.command_domain_cleanup_proof_id IS NOT NULL)
          OR
          (NEW.outcome_kind = 'ControlInterruptedBeforeEffect' AND NEW.outcome_code IS NULL
           AND closure.termination_kind = 'InterruptedBeforeEffect'
           AND closure.custody_kind = 'ClosedBeforeCapture'
           AND closure.custody_receipt_id IS NOT NULL
           AND closure.runner_cleanup_proof_id IS NOT NULL
           AND closure.command_domain_cleanup_proof_id IS NOT NULL
           AND EXISTS (
               SELECT 1 FROM current_final_verification_controls_v32 control
               WHERE control.control_id = closure.control_id
                 AND control.sprint_id = closure.sprint_id
                 AND control.attempt_id = closure.attempt_id
                 AND control.before_effect = 1
                 AND control.control_kind IN ('Pause', 'SteeringInterruption')
                 AND control.issued_at_unix_ms <= closure.terminal_at_unix_ms
           ))
          OR
          (NEW.outcome_kind = 'Canceled' AND NEW.outcome_code IS NULL
           AND closure.termination_kind = 'Canceled'
           AND closure.custody_kind IN (
               'ClosedBeforeCapture', 'PublishedClean', 'AbandonedSensitive'
           )
           AND closure.custody_receipt_id IS NOT NULL
           AND closure.runner_cleanup_proof_id IS NOT NULL
           AND closure.command_domain_cleanup_proof_id IS NOT NULL
           AND EXISTS (
               SELECT 1 FROM current_final_verification_controls_v32 control
               WHERE control.control_id = closure.control_id
                 AND control.sprint_id = closure.sprint_id
                 AND control.attempt_id = closure.attempt_id
                 AND control.control_kind = 'Cancel'
                 AND control.issued_at_unix_ms <= closure.terminal_at_unix_ms
                 AND (
                     (control.before_effect = 1
                      AND closure.custody_kind = 'ClosedBeforeCapture')
                     OR
                     (control.before_effect = 0
                      AND closure.custody_kind IN ('PublishedClean', 'AbandonedSensitive'))
                 )
           ))
          OR
          (NEW.outcome_kind = 'Unknown' AND NEW.outcome_code IS NULL
           AND CASE
               WHEN closure.termination_kind = 'Exited'
                    AND closure.termination_code >= 0
                    AND closure.custody_kind = 'PublishedClean'
                    AND closure.custody_receipt_id IS NOT NULL
                    AND closure.runner_cleanup_proof_id IS NOT NULL
                    AND closure.command_domain_cleanup_proof_id IS NOT NULL
                 THEN 0
               WHEN closure.termination_kind = 'Signaled'
                    AND closure.termination_code > 0
                    AND closure.custody_kind = 'PublishedClean'
                    AND closure.custody_receipt_id IS NOT NULL
                    AND closure.runner_cleanup_proof_id IS NOT NULL
                    AND closure.command_domain_cleanup_proof_id IS NOT NULL
                 THEN 0
               WHEN closure.termination_kind IN ('TimedOut', 'OutputLimitExceeded')
                    AND closure.custody_kind = 'PublishedClean'
                    AND closure.custody_receipt_id IS NOT NULL
                    AND closure.runner_cleanup_proof_id IS NOT NULL
                    AND closure.command_domain_cleanup_proof_id IS NOT NULL
                 THEN 0
               WHEN closure.termination_kind NOT IN (
                        'Unknown', 'InterruptedAfterEffect', 'Canceled'
                    )
                    AND closure.custody_kind = 'AbandonedSensitive'
                    AND closure.custody_receipt_id IS NOT NULL
                    AND closure.runner_cleanup_proof_id IS NOT NULL
                    AND closure.command_domain_cleanup_proof_id IS NOT NULL
                 THEN 0
               WHEN closure.termination_kind = 'FailedBeforeEffect'
                    AND closure.custody_kind = 'ClosedBeforeCapture'
                    AND closure.custody_receipt_id IS NOT NULL
                    AND closure.runner_cleanup_proof_id IS NOT NULL
                    AND closure.command_domain_cleanup_proof_id IS NOT NULL
                 THEN 0
               WHEN closure.termination_kind = 'InterruptedBeforeEffect'
                    AND closure.custody_kind = 'ClosedBeforeCapture'
                    AND closure.custody_receipt_id IS NOT NULL
                    AND closure.runner_cleanup_proof_id IS NOT NULL
                    AND closure.command_domain_cleanup_proof_id IS NOT NULL
                    AND EXISTS (
                        SELECT 1 FROM current_final_verification_controls_v32 control
                        WHERE control.control_id = closure.control_id
                          AND control.sprint_id = closure.sprint_id
                          AND control.attempt_id = closure.attempt_id
                          AND control.before_effect = 1
                          AND control.control_kind IN ('Pause', 'SteeringInterruption')
                          AND control.issued_at_unix_ms <= closure.terminal_at_unix_ms
                    )
                 THEN 0
               WHEN closure.termination_kind = 'Canceled'
                    AND closure.custody_kind IN (
                        'ClosedBeforeCapture', 'PublishedClean', 'AbandonedSensitive'
                    )
                    AND closure.custody_receipt_id IS NOT NULL
                    AND closure.runner_cleanup_proof_id IS NOT NULL
                    AND closure.command_domain_cleanup_proof_id IS NOT NULL
                    AND EXISTS (
                        SELECT 1 FROM current_final_verification_controls_v32 control
                        WHERE control.control_id = closure.control_id
                          AND control.sprint_id = closure.sprint_id
                          AND control.attempt_id = closure.attempt_id
                          AND control.control_kind = 'Cancel'
                          AND control.issued_at_unix_ms <= closure.terminal_at_unix_ms
                          AND (
                              (control.before_effect = 1
                               AND closure.custody_kind = 'ClosedBeforeCapture')
                              OR
                              (control.before_effect = 0
                               AND closure.custody_kind IN (
                                   'PublishedClean', 'AbandonedSensitive'
                               ))
                          )
                    )
                 THEN 0
               ELSE 1
           END = 1)
      )
)
BEGIN SELECT RAISE(ABORT, 'typed final-verification outcome does not match exact capture, custody, control, and cleanup evidence'); END;

CREATE TRIGGER current_sprint_terminal_outcomes_v32_validate
BEFORE INSERT ON current_sprint_terminal_outcomes_v32
WHEN NOT EXISTS (
    SELECT 1
    FROM current_final_verification_attempts_v32 attempt
    JOIN current_final_verification_outcomes_v32 outcome
      ON outcome.attempt_id = attempt.attempt_id
     AND outcome.outcome_id = NEW.source_outcome_id
    WHERE attempt.sprint_id = NEW.sprint_id
      AND attempt.attempt_id = NEW.source_attempt_id
      AND outcome.terminal_at_unix_ms = NEW.terminal_at_unix_ms
      AND NOT EXISTS (
          SELECT 1 FROM current_final_verification_attempts_v32 later
          WHERE later.sprint_id = attempt.sprint_id
            AND later.attempt_ordinal > attempt.attempt_ordinal
      )
      AND (
          (NEW.terminal_state = 'Failed'
           AND NEW.terminal_reason = 'FinalVerificationAttemptsExhausted'
           AND attempt.attempt_ordinal = attempt.max_final_verification_attempts
           AND outcome.outcome_kind NOT IN ('Verified', 'Canceled', 'Unknown'))
          OR
          (NEW.terminal_state = 'Canceled'
           AND NEW.terminal_reason = 'ExplicitCancel'
           AND outcome.outcome_kind = 'Canceled')
          OR
          (NEW.terminal_state = 'Unknown'
           AND NEW.terminal_reason = 'AmbiguousFinalVerification'
           AND outcome.outcome_kind = 'Unknown')
      )
)
BEGIN SELECT RAISE(ABORT, 'current sprint terminal must be the exact latest typed exhaustion, cancel, or ambiguity'); END;

CREATE TRIGGER current_final_verification_repair_activations_v32_validate
BEFORE INSERT ON current_final_verification_repair_activations_v32
WHEN NOT EXISTS (
    SELECT 1
    FROM current_final_verification_attempts_v32 attempt
    JOIN current_final_verification_outcomes_v32 outcome
      ON outcome.attempt_id = attempt.attempt_id
     AND outcome.outcome_id = NEW.failure_outcome_id
    JOIN current_task_nodes_v32 task
      ON task.sprint_id = attempt.sprint_id
     AND task.task_id = NEW.repair_task_id
     AND task.purpose = 'FinalVerificationRepairSlot'
     AND task.repair_slot_ordinal = NEW.slot_ordinal
    WHERE attempt.sprint_id = NEW.sprint_id
      AND attempt.attempt_id = NEW.failed_attempt_id
      AND json_extract(CAST(NEW.activation_json AS TEXT), '$.activation_id') = NEW.activation_id
      AND json_extract(CAST(NEW.activation_json AS TEXT), '$.sprint_id') = NEW.sprint_id
      AND json_extract(CAST(NEW.activation_json AS TEXT), '$.failed_attempt_id') = NEW.failed_attempt_id
      AND json_extract(CAST(NEW.activation_json AS TEXT), '$.failure_outcome_id') = NEW.failure_outcome_id
      AND json_extract(CAST(NEW.activation_json AS TEXT), '$.failed_snapshot') = NEW.failed_snapshot
      AND json_extract(CAST(NEW.activation_json AS TEXT), '$.slot_ordinal') = NEW.slot_ordinal
      AND json_extract(CAST(NEW.activation_json AS TEXT), '$.repair_task_id') = NEW.repair_task_id
      AND json_extract(CAST(NEW.activation_json AS TEXT), '$.activated_at_unix_ms') = NEW.activated_at_unix_ms
      AND attempt.input_snapshot = NEW.failed_snapshot
      AND attempt.attempt_ordinal = NEW.slot_ordinal
      AND attempt.attempt_ordinal < attempt.max_final_verification_attempts
      AND outcome.outcome_kind IN (
          'NonzeroExit', 'Signaled', 'TimedOut',
          'OutputLimitExceeded', 'SensitiveOutputRejected'
      )
      AND outcome.terminal_at_unix_ms <= NEW.activated_at_unix_ms
      AND NOT EXISTS (
          SELECT 1 FROM current_final_verification_attempts_v32 later
          WHERE later.sprint_id = attempt.sprint_id
            AND later.attempt_ordinal > attempt.attempt_ordinal
      )
      AND NOT EXISTS (
          SELECT 1 FROM current_sprint_terminal_outcomes_v32 terminal
          WHERE terminal.sprint_id = NEW.sprint_id
      )
)
BEGIN SELECT RAISE(ABORT, 'repair activation requires the next dormant slot and exact known after-effect failure'); END;

CREATE TRIGGER current_final_verification_repair_completions_v32_validate
BEFORE INSERT ON current_final_verification_repair_completions_v32
WHEN NOT EXISTS (
    SELECT 1
    FROM current_final_verification_repair_activations_v32 activation
    JOIN current_final_verification_attempts_v32 failed
      ON failed.attempt_id = activation.failed_attempt_id
    JOIN current_task_done_set_seals_v32 task_set
      ON task_set.set_digest = NEW.complete_task_done_set_digest
     AND task_set.sprint_id = NEW.sprint_id
     AND task_set.snapshot_digest = NEW.result_snapshot
    JOIN current_criterion_evidence_set_seals_v32 criterion_set
      ON criterion_set.set_digest = NEW.complete_criterion_evidence_set_digest
     AND criterion_set.sprint_id = NEW.sprint_id
     AND criterion_set.snapshot_digest = NEW.result_snapshot
    WHERE activation.activation_id = NEW.activation_id
      AND activation.sprint_id = NEW.sprint_id
      AND json_extract(CAST(NEW.completion_json AS TEXT), '$.completion_id') = NEW.completion_id
      AND json_extract(CAST(NEW.completion_json AS TEXT), '$.sprint_id') = NEW.sprint_id
      AND json_extract(CAST(NEW.completion_json AS TEXT), '$.activation_id') = NEW.activation_id
      AND json_extract(CAST(NEW.completion_json AS TEXT), '$.failed_attempt_id') = NEW.failed_attempt_id
      AND json_extract(CAST(NEW.completion_json AS TEXT), '$.repair_task_id') = NEW.repair_task_id
      AND json_extract(CAST(NEW.completion_json AS TEXT), '$.repair_task_done_proof_id') = NEW.repair_task_done_proof_id
      AND json_extract(CAST(NEW.completion_json AS TEXT), '$.integration_receipt_id') = NEW.integration_receipt_id
      AND json_extract(CAST(NEW.completion_json AS TEXT), '$.input_snapshot') = NEW.input_snapshot
      AND json_extract(CAST(NEW.completion_json AS TEXT), '$.result_snapshot') = NEW.result_snapshot
      AND json_extract(CAST(NEW.completion_json AS TEXT), '$.change_set_id') = NEW.change_set_id
      AND json_extract(CAST(NEW.completion_json AS TEXT), '$.operation_count') = NEW.operation_count
      AND json_extract(CAST(NEW.completion_json AS TEXT), '$.complete_task_done_set_digest') = NEW.complete_task_done_set_digest
      AND json_extract(CAST(NEW.completion_json AS TEXT), '$.complete_criterion_evidence_set_digest') = NEW.complete_criterion_evidence_set_digest
      AND json_extract(CAST(NEW.completion_json AS TEXT), '$.completed_at_unix_ms') = NEW.completed_at_unix_ms
      AND activation.failed_attempt_id = NEW.failed_attempt_id
      AND activation.repair_task_id = NEW.repair_task_id
      AND activation.failed_snapshot = NEW.input_snapshot
      AND failed.input_snapshot = NEW.input_snapshot
      AND NEW.result_snapshot != NEW.input_snapshot
      AND activation.activated_at_unix_ms <= NEW.completed_at_unix_ms
      AND EXISTS (
          SELECT 1 FROM current_task_done_sets_v32 source
          WHERE source.set_digest = NEW.complete_task_done_set_digest
            AND source.recorded_at_unix_ms <= NEW.completed_at_unix_ms
      )
      AND EXISTS (
          SELECT 1 FROM current_criterion_evidence_sets_v32 source
          WHERE source.set_digest = NEW.complete_criterion_evidence_set_digest
            AND source.recorded_at_unix_ms <= NEW.completed_at_unix_ms
      )
      AND EXISTS (
          SELECT 1 FROM current_task_done_members_v32 member
          WHERE member.set_digest = NEW.complete_task_done_set_digest
            AND member.task_id = NEW.repair_task_id
            AND member.task_done_proof_id = NEW.repair_task_done_proof_id
            AND member.integration_receipt_id = NEW.integration_receipt_id
            AND member.integration_kind = 'Changed'
            AND member.empty_change_set_id IS NULL
            AND member.member_ordinal = (
                SELECT COUNT(*) FROM current_task_done_members_v32 stale
                WHERE stale.set_digest = failed.complete_task_done_set_digest
            )
            AND member.input_snapshot = NEW.input_snapshot
            AND member.result_snapshot = NEW.result_snapshot
      )
      AND (
          SELECT COUNT(*) FROM current_task_done_members_v32 fresh
          WHERE fresh.set_digest = NEW.complete_task_done_set_digest
      ) = 1 + (
          SELECT COUNT(*) FROM current_task_done_members_v32 stale
          WHERE stale.set_digest = failed.complete_task_done_set_digest
      )
      AND NOT EXISTS (
          SELECT 1 FROM current_task_done_members_v32 stale
          WHERE stale.set_digest = failed.complete_task_done_set_digest
            AND NOT EXISTS (
                SELECT 1 FROM current_task_done_members_v32 fresh
                WHERE fresh.set_digest = NEW.complete_task_done_set_digest
                  AND fresh.member_ordinal = stale.member_ordinal
                  AND fresh.task_id = stale.task_id
                  AND fresh.task_done_proof_id = stale.task_done_proof_id
                  AND fresh.integration_receipt_id = stale.integration_receipt_id
                  AND fresh.integration_kind = stale.integration_kind
                  AND fresh.empty_change_set_id IS stale.empty_change_set_id
                  AND fresh.input_snapshot = stale.input_snapshot
                  AND fresh.result_snapshot = stale.result_snapshot
            )
      )
      AND NOT EXISTS (
          SELECT 1
          FROM current_criterion_evidence_members_v32 fresh
          JOIN current_criterion_evidence_members_v32 stale
            ON stale.set_digest = failed.complete_criterion_evidence_set_digest
           AND stale.criterion_id = fresh.criterion_id
          WHERE fresh.set_digest = NEW.complete_criterion_evidence_set_digest
            AND fresh.evidence_receipt_id = stale.evidence_receipt_id
      )
      AND NOT EXISTS (
          SELECT 1 FROM current_sprint_terminal_outcomes_v32 terminal
          WHERE terminal.sprint_id = NEW.sprint_id
      )
)
BEGIN SELECT RAISE(ABORT, 'repair completion requires activated nonempty changed-snapshot TaskDone and fresh criterion evidence'); END;

-- Historical and current capture views are intentionally separate. These
-- views expose identity-bound readback only; none grants dispatch capability.
CREATE VIEW legacy_sprint_authority_capture_v32 AS
SELECT sprint.sprint_id, sprint.spec_json, exemption.legacy_spec_digest,
       exemption.marked_at_schema_version
FROM sprints sprint
JOIN legacy_sprint_authority_exemptions_v32 exemption
  ON exemption.sprint_id = sprint.sprint_id;

CREATE VIEW current_sprint_authority_capture_v32 AS
SELECT sprint.sprint_id, sprint.sprint_spec_digest, sprint.spec_json,
       graph.graph_id, graph.graph_digest, graph.graph_json,
       sprint.repair_slot_reserve_digest, sprint.max_final_verification_attempts,
       sprint.base_snapshot, sprint.workspace_grant_hash, sprint.created_at_unix_ms
FROM current_sprint_authorities_v32 sprint
JOIN current_task_graph_authorities_v32 graph
  ON graph.sprint_id = sprint.sprint_id
 AND graph.sprint_spec_digest = sprint.sprint_spec_digest
 AND graph.graph_payload_digest = sprint.task_graph_payload_digest
 AND graph.repair_slot_reserve_digest = sprint.repair_slot_reserve_digest;

CREATE VIEW current_final_verification_attempt_capture_v32 AS
SELECT attempt.*, outcome.outcome_id, outcome.outcome_kind,
       outcome.outcome_code, outcome.terminal_at_unix_ms
FROM current_final_verification_attempts_v32 attempt
JOIN current_task_done_set_seals_v32 task_set
  ON task_set.set_digest = attempt.complete_task_done_set_digest
 AND task_set.sprint_id = attempt.sprint_id
 AND task_set.snapshot_digest = attempt.input_snapshot
JOIN current_criterion_evidence_set_seals_v32 criterion_set
  ON criterion_set.set_digest = attempt.complete_criterion_evidence_set_digest
 AND criterion_set.sprint_id = attempt.sprint_id
 AND criterion_set.snapshot_digest = attempt.input_snapshot
LEFT JOIN current_final_verification_outcomes_v32 outcome
  ON outcome.attempt_id = attempt.attempt_id;

CREATE VIEW current_final_verification_repair_capture_v32 AS
SELECT activation.*, completion.completion_id,
       completion.repair_task_done_proof_id, completion.integration_receipt_id,
       completion.result_snapshot, completion.complete_task_done_set_digest,
       completion.complete_criterion_evidence_set_digest,
       completion.completed_at_unix_ms
FROM current_final_verification_repair_activations_v32 activation
LEFT JOIN current_final_verification_repair_completions_v32 completion
  ON completion.activation_id = activation.activation_id;

CREATE VIEW current_final_verification_ready_for_composition_v32 AS
SELECT attempt.sprint_id, attempt.attempt_id, attempt.attempt_ordinal,
       attempt.input_snapshot, attempt.complete_task_done_set_digest,
       attempt.complete_criterion_evidence_set_digest, outcome.outcome_id
FROM current_final_verification_attempts_v32 attempt
JOIN current_final_verification_outcomes_v32 outcome
  ON outcome.attempt_id = attempt.attempt_id
 AND outcome.outcome_kind = 'Verified'
WHERE NOT EXISTS (
    SELECT 1 FROM current_final_verification_attempts_v32 later
    WHERE later.sprint_id = attempt.sprint_id
      AND later.attempt_ordinal > attempt.attempt_ordinal
)
AND NOT EXISTS (
    SELECT 1 FROM current_sprint_terminal_outcomes_v32 terminal
    WHERE terminal.sprint_id = attempt.sprint_id
);

-- All new authority tables are immutable. Set rows may be staged only until
-- their one immutable seal is written; afterward every row remains append-only.
CREATE TRIGGER legacy_sprint_authority_exemptions_v32_no_insert
BEFORE INSERT ON legacy_sprint_authority_exemptions_v32
BEGIN SELECT RAISE(ABORT, 'legacy sprint authority exemptions are migration-only'); END;
CREATE TRIGGER legacy_sprint_authority_exemptions_v32_no_update
BEFORE UPDATE ON legacy_sprint_authority_exemptions_v32
BEGIN SELECT RAISE(ABORT, 'legacy sprint authority exemptions are immutable'); END;
CREATE TRIGGER legacy_sprint_authority_exemptions_v32_no_delete
BEFORE DELETE ON legacy_sprint_authority_exemptions_v32
BEGIN SELECT RAISE(ABORT, 'legacy sprint authority exemptions are immutable'); END;

CREATE TRIGGER current_sprint_authorities_v32_no_update BEFORE UPDATE ON current_sprint_authorities_v32
BEGIN SELECT RAISE(ABORT, 'current sprint authority is immutable'); END;
CREATE TRIGGER current_sprint_authorities_v32_no_delete BEFORE DELETE ON current_sprint_authorities_v32
BEGIN SELECT RAISE(ABORT, 'current sprint authority is immutable'); END;
CREATE TRIGGER current_task_graph_authorities_v32_no_update BEFORE UPDATE ON current_task_graph_authorities_v32
BEGIN SELECT RAISE(ABORT, 'current task graph authority is immutable'); END;
CREATE TRIGGER current_task_graph_authorities_v32_no_delete BEFORE DELETE ON current_task_graph_authorities_v32
BEGIN SELECT RAISE(ABORT, 'current task graph authority is immutable'); END;
CREATE TRIGGER current_task_nodes_v32_no_update BEFORE UPDATE ON current_task_nodes_v32
BEGIN SELECT RAISE(ABORT, 'current task nodes are immutable'); END;
CREATE TRIGGER current_task_nodes_v32_no_delete BEFORE DELETE ON current_task_nodes_v32
BEGIN SELECT RAISE(ABORT, 'current task nodes are immutable'); END;

CREATE TRIGGER current_task_done_sets_v32_no_update BEFORE UPDATE ON current_task_done_sets_v32
BEGIN SELECT RAISE(ABORT, 'current TaskDone sets are immutable'); END;
CREATE TRIGGER current_task_done_sets_v32_no_delete BEFORE DELETE ON current_task_done_sets_v32
BEGIN SELECT RAISE(ABORT, 'current TaskDone sets are immutable'); END;
CREATE TRIGGER current_task_done_members_v32_no_update BEFORE UPDATE ON current_task_done_members_v32
BEGIN SELECT RAISE(ABORT, 'current TaskDone members are immutable'); END;
CREATE TRIGGER current_task_done_members_v32_no_delete BEFORE DELETE ON current_task_done_members_v32
BEGIN SELECT RAISE(ABORT, 'current TaskDone members are immutable'); END;
CREATE TRIGGER current_task_done_set_seals_v32_no_update BEFORE UPDATE ON current_task_done_set_seals_v32
BEGIN SELECT RAISE(ABORT, 'current TaskDone set seals are immutable'); END;
CREATE TRIGGER current_task_done_set_seals_v32_no_delete BEFORE DELETE ON current_task_done_set_seals_v32
BEGIN SELECT RAISE(ABORT, 'current TaskDone set seals are immutable'); END;

CREATE TRIGGER current_criterion_evidence_sets_v32_no_update BEFORE UPDATE ON current_criterion_evidence_sets_v32
BEGIN SELECT RAISE(ABORT, 'current criterion-evidence sets are immutable'); END;
CREATE TRIGGER current_criterion_evidence_sets_v32_no_delete BEFORE DELETE ON current_criterion_evidence_sets_v32
BEGIN SELECT RAISE(ABORT, 'current criterion-evidence sets are immutable'); END;
CREATE TRIGGER current_criterion_evidence_members_v32_no_update BEFORE UPDATE ON current_criterion_evidence_members_v32
BEGIN SELECT RAISE(ABORT, 'current criterion-evidence members are immutable'); END;
CREATE TRIGGER current_criterion_evidence_members_v32_no_delete BEFORE DELETE ON current_criterion_evidence_members_v32
BEGIN SELECT RAISE(ABORT, 'current criterion-evidence members are immutable'); END;
CREATE TRIGGER current_criterion_evidence_set_seals_v32_no_update BEFORE UPDATE ON current_criterion_evidence_set_seals_v32
BEGIN SELECT RAISE(ABORT, 'current criterion-evidence set seals are immutable'); END;
CREATE TRIGGER current_criterion_evidence_set_seals_v32_no_delete BEFORE DELETE ON current_criterion_evidence_set_seals_v32
BEGIN SELECT RAISE(ABORT, 'current criterion-evidence set seals are immutable'); END;

CREATE TRIGGER current_final_verification_controls_v32_no_update BEFORE UPDATE ON current_final_verification_controls_v32
BEGIN SELECT RAISE(ABORT, 'current final-verification controls are immutable'); END;
CREATE TRIGGER current_final_verification_controls_v32_no_delete BEFORE DELETE ON current_final_verification_controls_v32
BEGIN SELECT RAISE(ABORT, 'current final-verification controls are immutable'); END;
CREATE TRIGGER current_final_verification_attempts_v32_no_update BEFORE UPDATE ON current_final_verification_attempts_v32
BEGIN SELECT RAISE(ABORT, 'current final-verification attempts are immutable'); END;
CREATE TRIGGER current_final_verification_attempts_v32_no_delete BEFORE DELETE ON current_final_verification_attempts_v32
BEGIN SELECT RAISE(ABORT, 'current final-verification attempts are immutable'); END;
CREATE TRIGGER current_final_verification_capture_closures_v32_no_update BEFORE UPDATE ON current_final_verification_capture_closures_v32
BEGIN SELECT RAISE(ABORT, 'current final-verification captures are immutable'); END;
CREATE TRIGGER current_final_verification_capture_closures_v32_no_delete BEFORE DELETE ON current_final_verification_capture_closures_v32
BEGIN SELECT RAISE(ABORT, 'current final-verification captures are immutable'); END;
CREATE TRIGGER current_final_verification_outcomes_v32_no_update BEFORE UPDATE ON current_final_verification_outcomes_v32
BEGIN SELECT RAISE(ABORT, 'current final-verification outcomes are immutable'); END;
CREATE TRIGGER current_final_verification_outcomes_v32_no_delete BEFORE DELETE ON current_final_verification_outcomes_v32
BEGIN SELECT RAISE(ABORT, 'current final-verification outcomes are immutable'); END;
CREATE TRIGGER current_final_verification_repair_activations_v32_no_update BEFORE UPDATE ON current_final_verification_repair_activations_v32
BEGIN SELECT RAISE(ABORT, 'current final-verification repair activations are immutable'); END;
CREATE TRIGGER current_final_verification_repair_activations_v32_no_delete BEFORE DELETE ON current_final_verification_repair_activations_v32
BEGIN SELECT RAISE(ABORT, 'current final-verification repair activations are immutable'); END;
CREATE TRIGGER current_final_verification_repair_completions_v32_no_update BEFORE UPDATE ON current_final_verification_repair_completions_v32
BEGIN SELECT RAISE(ABORT, 'current final-verification repair completions are immutable'); END;
CREATE TRIGGER current_final_verification_repair_completions_v32_no_delete BEFORE DELETE ON current_final_verification_repair_completions_v32
BEGIN SELECT RAISE(ABORT, 'current final-verification repair completions are immutable'); END;
CREATE TRIGGER current_sprint_terminal_outcomes_v32_no_update BEFORE UPDATE ON current_sprint_terminal_outcomes_v32
BEGIN SELECT RAISE(ABORT, 'current sprint terminal outcomes are immutable'); END;
CREATE TRIGGER current_sprint_terminal_outcomes_v32_no_delete BEFORE DELETE ON current_sprint_terminal_outcomes_v32
BEGIN SELECT RAISE(ABORT, 'current sprint terminal outcomes are immutable'); END;

-- Current ordinary rollback is deliberately closed until its exact
-- SprintRollback phase admission and move-only claimed terminal are installed.
-- Historical/V1 rows remain readable and writable under their exact prior
-- contract, but no V2 sprint can mint a fresh subtype or claimless success.
CREATE TRIGGER ordinary_rollback_effect_intents_v32_require_phase_admission
BEFORE INSERT ON effect_intents
WHEN EXISTS (
    SELECT 1 FROM current_sprint_authorities_v32 current
    WHERE current.sprint_id = NEW.sprint_id
)
AND (
    NEW.effect_kind = 'RollbackChangeSet'
    OR json_extract(CAST(NEW.intent_json AS TEXT), '$.kind') = 'RollbackChangeSet'
)
BEGIN
    SELECT RAISE(ABORT, 'current rollback effect intent requires phase-specific SprintRollback admission');
END;

CREATE TRIGGER ordinary_rollback_intents_v32_require_phase_admission
BEFORE INSERT ON finish_effect_kinds
WHEN NEW.effect_kind = 'RollbackChangeSet'
 AND EXISTS (
     SELECT 1 FROM current_sprint_authorities_v32 current
     WHERE current.sprint_id = NEW.sprint_id
 )
BEGIN
    SELECT RAISE(ABORT, 'current rollback requires phase-specific SprintRollback admission');
END;

CREATE TRIGGER ordinary_rollback_success_v32_requires_claimed_terminal
BEFORE INSERT ON effect_observations
WHEN NEW.outcome = 'Succeeded'
 AND EXISTS (
     SELECT 1 FROM current_sprint_authorities_v32 current
     WHERE current.sprint_id = NEW.sprint_id
 )
 AND (
     NEW.effect_kind = 'RollbackChangeSet'
     OR json_extract(CAST(NEW.observation_json AS TEXT), '$.kind') = 'RollbackChangeSet'
     OR EXISTS (
         SELECT 1
         FROM finish_effect_kinds kind
         WHERE kind.effect_id = NEW.effect_id
           AND kind.sprint_id = NEW.sprint_id
           AND kind.effect_kind = 'RollbackChangeSet'
     )
 )
BEGIN
    SELECT RAISE(ABORT, 'current rollback success requires claimed SprintRollback terminal');
END;

CREATE TRIGGER ordinary_rollback_receipts_v32_require_claimed_terminal
BEFORE INSERT ON rollback_receipts
WHEN EXISTS (
    SELECT 1 FROM current_sprint_authorities_v32 current
    WHERE current.sprint_id = NEW.sprint_id
)
BEGIN
    SELECT RAISE(ABORT, 'current rollback receipt requires claimed SprintRollback terminal');
END;
