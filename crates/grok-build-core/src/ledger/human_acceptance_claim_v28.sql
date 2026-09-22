CREATE TABLE human_acceptance_prompts_v1 (
    prompt_id TEXT PRIMARY KEY NOT NULL,
    ui_session_id TEXT NOT NULL,
    sprint_id TEXT NOT NULL,
    criterion_id TEXT NOT NULL,
    criterion_text_digest TEXT NOT NULL,
    snapshot_digest TEXT NOT NULL,
    workspace_grant_hash TEXT NOT NULL,
    rendered_claim_digest TEXT NOT NULL,
    backing TEXT NOT NULL CHECK (backing = 'OneToOne'),
    issued_event_sequence INTEGER NOT NULL CHECK (issued_event_sequence > 0),
    prompt_json BLOB NOT NULL
        CHECK (grok_human_acceptance_prompt_v28_canonical(prompt_json) = 1),
    UNIQUE (sprint_id, prompt_id),
    FOREIGN KEY (sprint_id) REFERENCES sprints(sprint_id) ON DELETE RESTRICT,
    FOREIGN KEY (sprint_id, snapshot_digest)
        REFERENCES workspace_snapshots(sprint_id, snapshot_id) ON DELETE RESTRICT,
    FOREIGN KEY (sprint_id, issued_event_sequence)
        REFERENCES agent_events(sprint_id, sequence) ON DELETE RESTRICT
) STRICT;

CREATE INDEX human_acceptance_prompts_v1_criterion_idx
ON human_acceptance_prompts_v1 (
    sprint_id, criterion_id, snapshot_digest, issued_event_sequence
);

CREATE TABLE human_acceptance_decisions_v1 (
    decision_id TEXT PRIMARY KEY NOT NULL,
    prompt_id TEXT NOT NULL UNIQUE,
    sprint_id TEXT NOT NULL,
    outcome TEXT NOT NULL
        CHECK (outcome IN ('AcceptedByYou', 'RejectedByYou')),
    consumed_event_sequence INTEGER NOT NULL CHECK (consumed_event_sequence > 0),
    decided_at_unix_ms INTEGER NOT NULL CHECK (decided_at_unix_ms > 0),
    decision_json BLOB NOT NULL
        CHECK (grok_human_acceptance_decision_v28_canonical(decision_json) = 1),
    UNIQUE (sprint_id, decision_id),
    FOREIGN KEY (sprint_id, prompt_id)
        REFERENCES human_acceptance_prompts_v1(sprint_id, prompt_id) ON DELETE RESTRICT,
    FOREIGN KEY (sprint_id, consumed_event_sequence)
        REFERENCES agent_events(sprint_id, sequence) ON DELETE RESTRICT
) STRICT;

CREATE INDEX human_acceptance_decisions_v1_sprint_idx
ON human_acceptance_decisions_v1 (sprint_id, outcome, decided_at_unix_ms);

CREATE TABLE criterion_evidence_receipts_v2 (
    receipt_id TEXT PRIMARY KEY NOT NULL,
    sprint_id TEXT NOT NULL,
    criterion_id TEXT NOT NULL,
    snapshot_digest TEXT NOT NULL,
    evidence_kind TEXT NOT NULL
        CHECK (evidence_kind IN ('Verified', 'AcceptedByYou')),
    verification_receipt_id TEXT,
    human_decision_id TEXT UNIQUE,
    prompt_id TEXT,
    backing TEXT,
    recorded_at_unix_ms INTEGER NOT NULL CHECK (recorded_at_unix_ms > 0),
    receipt_json BLOB NOT NULL
        CHECK (grok_criterion_evidence_receipt_v28_canonical(receipt_json) = 1),
    UNIQUE (sprint_id, receipt_id),
    UNIQUE (sprint_id, criterion_id, snapshot_digest),
    CHECK (
        (evidence_kind = 'Verified'
         AND verification_receipt_id IS NOT NULL
         AND human_decision_id IS NULL
         AND prompt_id IS NULL
         AND backing IS NULL)
        OR
        (evidence_kind = 'AcceptedByYou'
         AND verification_receipt_id IS NULL
         AND human_decision_id IS NOT NULL
         AND prompt_id IS NOT NULL
         AND backing = 'OneToOne')
    ),
    FOREIGN KEY (sprint_id) REFERENCES sprints(sprint_id) ON DELETE RESTRICT,
    FOREIGN KEY (sprint_id, snapshot_digest)
        REFERENCES workspace_snapshots(sprint_id, snapshot_id) ON DELETE RESTRICT,
    FOREIGN KEY (verification_receipt_id)
        REFERENCES verification_receipts(receipt_id) ON DELETE RESTRICT,
    FOREIGN KEY (sprint_id, human_decision_id)
        REFERENCES human_acceptance_decisions_v1(sprint_id, decision_id) ON DELETE RESTRICT,
    FOREIGN KEY (sprint_id, prompt_id)
        REFERENCES human_acceptance_prompts_v1(sprint_id, prompt_id) ON DELETE RESTRICT
) STRICT;

CREATE INDEX criterion_evidence_receipts_v2_snapshot_idx
ON criterion_evidence_receipts_v2 (sprint_id, snapshot_digest, criterion_id);

CREATE TABLE v28_completion_criterion_evidence_receipts (
    completion_receipt_id TEXT NOT NULL,
    sprint_id TEXT NOT NULL,
    ordinal INTEGER NOT NULL CHECK (ordinal >= 0),
    criterion_evidence_receipt_id TEXT NOT NULL,
    PRIMARY KEY (completion_receipt_id, ordinal),
    UNIQUE (completion_receipt_id, criterion_evidence_receipt_id),
    FOREIGN KEY (sprint_id, completion_receipt_id)
        REFERENCES v9_completion_receipts(sprint_id, receipt_id) ON DELETE RESTRICT,
    FOREIGN KEY (sprint_id, criterion_evidence_receipt_id)
        REFERENCES criterion_evidence_receipts_v2(sprint_id, receipt_id) ON DELETE RESTRICT
) STRICT, WITHOUT ROWID;

CREATE INDEX v28_completion_criterion_evidence_sprint_idx
ON v28_completion_criterion_evidence_receipts (
    sprint_id, criterion_evidence_receipt_id
);

-- A pre-v28 completion remains byte-exact historical evidence. This marker is
-- populated only during migration and prevents its legacy acceptance links
-- from being mistaken for the current typed-evidence completion path.
CREATE TABLE v28_legacy_completion_acceptance_sets (
    completion_receipt_id TEXT PRIMARY KEY NOT NULL,
    sprint_id TEXT NOT NULL,
    FOREIGN KEY (sprint_id, completion_receipt_id)
        REFERENCES v9_completion_receipts(sprint_id, receipt_id) ON DELETE RESTRICT
) STRICT, WITHOUT ROWID;

INSERT INTO v28_legacy_completion_acceptance_sets (
    completion_receipt_id, sprint_id
)
SELECT DISTINCT completion_receipt_id, sprint_id
FROM v9_completion_acceptance_receipts;

-- Every completion parent that predates v28 had a non-empty legacy acceptance
-- set. Refuse migration instead of silently reclassifying a torn or fabricated
-- historical parent as a current typed-evidence completion.
CREATE TEMP TABLE v28_legacy_completion_marker_migration_guard (
    expected_count INTEGER NOT NULL,
    actual_count INTEGER NOT NULL,
    CHECK (expected_count = actual_count)
) STRICT;

INSERT INTO v28_legacy_completion_marker_migration_guard (
    expected_count, actual_count
)
SELECT (SELECT COUNT(*) FROM v9_completion_receipts),
       (SELECT COUNT(*) FROM v28_legacy_completion_acceptance_sets);

DROP TABLE v28_legacy_completion_marker_migration_guard;

CREATE TRIGGER human_acceptance_prompts_v1_no_update
BEFORE UPDATE ON human_acceptance_prompts_v1
BEGIN SELECT RAISE(ABORT, 'human acceptance prompts are immutable'); END;

CREATE TRIGGER human_acceptance_prompts_v1_no_delete
BEFORE DELETE ON human_acceptance_prompts_v1
BEGIN SELECT RAISE(ABORT, 'human acceptance prompts are immutable'); END;

CREATE TRIGGER human_acceptance_decisions_v1_no_update
BEFORE UPDATE ON human_acceptance_decisions_v1
BEGIN SELECT RAISE(ABORT, 'human acceptance decisions are immutable'); END;

CREATE TRIGGER human_acceptance_decisions_v1_no_delete
BEFORE DELETE ON human_acceptance_decisions_v1
BEGIN SELECT RAISE(ABORT, 'human acceptance decisions are immutable'); END;

CREATE TRIGGER criterion_evidence_receipts_v2_no_update
BEFORE UPDATE ON criterion_evidence_receipts_v2
BEGIN SELECT RAISE(ABORT, 'criterion evidence receipts are immutable'); END;

CREATE TRIGGER criterion_evidence_receipts_v2_no_delete
BEFORE DELETE ON criterion_evidence_receipts_v2
BEGIN SELECT RAISE(ABORT, 'criterion evidence receipts are immutable'); END;

CREATE TRIGGER v28_completion_criterion_evidence_no_update
BEFORE UPDATE ON v28_completion_criterion_evidence_receipts
BEGIN SELECT RAISE(ABORT, 'completion criterion-evidence links are immutable'); END;

CREATE TRIGGER v28_completion_criterion_evidence_no_delete
BEFORE DELETE ON v28_completion_criterion_evidence_receipts
BEGIN SELECT RAISE(ABORT, 'completion criterion-evidence links are immutable'); END;

CREATE TRIGGER v28_legacy_completion_acceptance_sets_no_insert
BEFORE INSERT ON v28_legacy_completion_acceptance_sets
BEGIN SELECT RAISE(ABORT, 'legacy completion acceptance markers are migration-only'); END;

CREATE TRIGGER v28_legacy_completion_acceptance_sets_no_update
BEFORE UPDATE ON v28_legacy_completion_acceptance_sets
BEGIN SELECT RAISE(ABORT, 'legacy completion acceptance markers are immutable'); END;

CREATE TRIGGER v28_legacy_completion_acceptance_sets_no_delete
BEFORE DELETE ON v28_legacy_completion_acceptance_sets
BEGIN SELECT RAISE(ABORT, 'legacy completion acceptance markers are immutable'); END;

CREATE TRIGGER human_acceptance_prompts_v1_envelope_match
BEFORE INSERT ON human_acceptance_prompts_v1
WHEN COALESCE(
    json_extract(CAST(NEW.prompt_json AS TEXT), '$.prompt_id') IS NEW.prompt_id
    AND json_extract(CAST(NEW.prompt_json AS TEXT), '$.ui_session_id') IS NEW.ui_session_id
    AND json_extract(CAST(NEW.prompt_json AS TEXT), '$.sprint_id') IS NEW.sprint_id
    AND json_extract(CAST(NEW.prompt_json AS TEXT), '$.criterion_id') IS NEW.criterion_id
    AND json_extract(CAST(NEW.prompt_json AS TEXT), '$.criterion_text_digest')
        IS NEW.criterion_text_digest
    AND json_extract(CAST(NEW.prompt_json AS TEXT), '$.snapshot_digest')
        IS NEW.snapshot_digest
    AND json_extract(CAST(NEW.prompt_json AS TEXT), '$.workspace_grant_hash')
        IS NEW.workspace_grant_hash
    AND json_extract(CAST(NEW.prompt_json AS TEXT), '$.rendered_claim_digest')
        IS NEW.rendered_claim_digest
    AND NEW.backing = 'OneToOne'
    AND json_extract(CAST(NEW.prompt_json AS TEXT), '$.backing') = 'one-to-one'
    AND json_extract(CAST(NEW.prompt_json AS TEXT), '$.issued_event_sequence')
        IS NEW.issued_event_sequence,
    0
) != 1
BEGIN
    SELECT RAISE(ABORT, 'human prompt envelope must match every indexed authority field');
END;

CREATE TRIGGER human_acceptance_decisions_v1_envelope_match
BEFORE INSERT ON human_acceptance_decisions_v1
WHEN COALESCE(
    json_extract(CAST(NEW.decision_json AS TEXT), '$.decision_id') IS NEW.decision_id
    AND json_extract(CAST(NEW.decision_json AS TEXT), '$.prompt_id') IS NEW.prompt_id
    AND (
        (NEW.outcome = 'AcceptedByYou'
         AND json_extract(CAST(NEW.decision_json AS TEXT), '$.outcome')
             = 'accepted-by-you')
        OR
        (NEW.outcome = 'RejectedByYou'
         AND json_extract(CAST(NEW.decision_json AS TEXT), '$.outcome')
             = 'rejected-by-you')
    )
    AND json_extract(CAST(NEW.decision_json AS TEXT), '$.consumed_event_sequence')
        IS NEW.consumed_event_sequence
    AND json_extract(CAST(NEW.decision_json AS TEXT), '$.decided_at')
        IS NEW.decided_at_unix_ms,
    0
) != 1
BEGIN
    SELECT RAISE(ABORT, 'human decision envelope must match every indexed authority field');
END;

CREATE TRIGGER human_acceptance_decisions_v1_prompt_match
BEFORE INSERT ON human_acceptance_decisions_v1
WHEN NOT EXISTS (
    SELECT 1
    FROM human_acceptance_prompts_v1 prompt
    WHERE prompt.prompt_id = NEW.prompt_id
      AND prompt.sprint_id = NEW.sprint_id
      AND prompt.issued_event_sequence = NEW.consumed_event_sequence
      AND prompt.issued_event_sequence = (
          SELECT MAX(event.sequence)
          FROM agent_events event
          WHERE event.sprint_id = prompt.sprint_id
      )
      AND EXISTS (
          SELECT 1
          FROM agent_events event
          WHERE event.sprint_id = prompt.sprint_id
            AND event.sequence = prompt.issued_event_sequence
            AND event.occurred_at_unix_ms <= NEW.decided_at_unix_ms
      )
      AND grok_human_acceptance_decision_v28_identity_matches(
              prompt.prompt_json, NEW.decision_json
          ) = 1
)
BEGIN
    SELECT RAISE(ABORT, 'human decision must consume the exact unchanged prompt event cut');
END;

CREATE TRIGGER criterion_evidence_receipts_v2_envelope_match
BEFORE INSERT ON criterion_evidence_receipts_v2
WHEN COALESCE(
    (
        NEW.evidence_kind = 'Verified'
        AND json_extract(CAST(NEW.receipt_json AS TEXT), '$.kind') = 'verified'
        AND json_extract(CAST(NEW.receipt_json AS TEXT), '$.receipt_id')
            IS NEW.receipt_id
        AND json_extract(CAST(NEW.receipt_json AS TEXT), '$.sprint_id')
            IS NEW.sprint_id
        AND json_extract(CAST(NEW.receipt_json AS TEXT), '$.criterion_id')
            IS NEW.criterion_id
        AND json_extract(CAST(NEW.receipt_json AS TEXT), '$.snapshot_digest')
            IS NEW.snapshot_digest
        AND json_extract(
            CAST(NEW.receipt_json AS TEXT), '$.verification_receipt_id'
        ) IS NEW.verification_receipt_id
        AND json_extract(CAST(NEW.receipt_json AS TEXT), '$.recorded_at')
            IS NEW.recorded_at_unix_ms
        AND NEW.human_decision_id IS NULL
        AND NEW.prompt_id IS NULL
        AND NEW.backing IS NULL
    )
    OR (
        NEW.evidence_kind = 'AcceptedByYou'
        AND json_extract(CAST(NEW.receipt_json AS TEXT), '$.kind') = 'accepted-by-you'
        AND json_extract(CAST(NEW.receipt_json AS TEXT), '$.receipt_id')
            IS NEW.receipt_id
        AND json_extract(CAST(NEW.receipt_json AS TEXT), '$.sprint_id')
            IS NEW.sprint_id
        AND json_extract(CAST(NEW.receipt_json AS TEXT), '$.criterion_id')
            IS NEW.criterion_id
        AND json_extract(CAST(NEW.receipt_json AS TEXT), '$.snapshot_digest')
            IS NEW.snapshot_digest
        AND json_extract(
            CAST(NEW.receipt_json AS TEXT), '$.human_decision_id'
        ) IS NEW.human_decision_id
        AND json_extract(CAST(NEW.receipt_json AS TEXT), '$.prompt_id')
            IS NEW.prompt_id
        AND NEW.backing = 'OneToOne'
        AND json_extract(CAST(NEW.receipt_json AS TEXT), '$.backing') = 'one-to-one'
        AND json_extract(CAST(NEW.receipt_json AS TEXT), '$.recorded_at')
            IS NEW.recorded_at_unix_ms
        AND NEW.verification_receipt_id IS NULL
    ),
    0
) != 1
BEGIN
    SELECT RAISE(ABORT, 'criterion evidence envelope must match every indexed authority field');
END;

CREATE TRIGGER criterion_evidence_receipts_v2_verified_match
BEFORE INSERT ON criterion_evidence_receipts_v2
WHEN NEW.evidence_kind = 'Verified' AND NOT EXISTS (
    SELECT 1
    FROM verification_receipts verification
    WHERE verification.receipt_id = NEW.verification_receipt_id
      AND verification.sprint_id = NEW.sprint_id
      AND verification.snapshot_id = NEW.snapshot_digest
      AND verification.passed = 1
      AND verification.finished_at_unix_ms <= NEW.recorded_at_unix_ms
)
BEGIN
    SELECT RAISE(ABORT, 'verified criterion evidence must match one passing same-snapshot verification');
END;

CREATE TRIGGER criterion_evidence_receipts_v2_human_match
BEFORE INSERT ON criterion_evidence_receipts_v2
WHEN NEW.evidence_kind = 'AcceptedByYou' AND NOT EXISTS (
    SELECT 1
    FROM human_acceptance_decisions_v1 decision
    JOIN human_acceptance_prompts_v1 prompt
      ON prompt.prompt_id = decision.prompt_id
     AND prompt.sprint_id = decision.sprint_id
    WHERE decision.decision_id = NEW.human_decision_id
      AND decision.prompt_id = NEW.prompt_id
      AND decision.sprint_id = NEW.sprint_id
      AND decision.outcome = 'AcceptedByYou'
      AND decision.decided_at_unix_ms <= NEW.recorded_at_unix_ms
      AND prompt.criterion_id = NEW.criterion_id
      AND prompt.snapshot_digest = NEW.snapshot_digest
      AND prompt.backing = NEW.backing
)
BEGIN
    SELECT RAISE(ABORT, 'accepted-by-you evidence must match one exact accepted prompt decision');
END;

CREATE TRIGGER acceptance_receipts_v28_human_diagnostic_only
BEFORE INSERT ON acceptance_receipts
WHEN NEW.evidence_kind = 'HumanJudgment'
BEGIN
    SELECT RAISE(ABORT, 'legacy human-judgment receipts are diagnostic-only in schema v28');
END;

CREATE TRIGGER v9_completion_acceptance_receipts_v28_diagnostic_only
BEFORE INSERT ON v9_completion_acceptance_receipts
BEGIN
    SELECT RAISE(ABORT, 'legacy completion acceptance links are diagnostic-only in schema v28');
END;

CREATE TRIGGER human_acceptance_prompts_v1_terminal_fence
BEFORE INSERT ON human_acceptance_prompts_v1
WHEN EXISTS (
    SELECT 1 FROM sprint_terminal_states WHERE sprint_id = NEW.sprint_id
    UNION ALL
    SELECT 1 FROM sprint_completion_proof_states WHERE sprint_id = NEW.sprint_id
    UNION ALL
    SELECT 1 FROM sprint_non_success_terminal_outcomes WHERE sprint_id = NEW.sprint_id
)
BEGIN SELECT RAISE(ABORT, 'terminal sprints reject human acceptance prompts'); END;

CREATE TRIGGER human_acceptance_decisions_v1_terminal_fence
BEFORE INSERT ON human_acceptance_decisions_v1
WHEN EXISTS (
    SELECT 1 FROM sprint_terminal_states WHERE sprint_id = NEW.sprint_id
    UNION ALL
    SELECT 1 FROM sprint_completion_proof_states WHERE sprint_id = NEW.sprint_id
    UNION ALL
    SELECT 1 FROM sprint_non_success_terminal_outcomes WHERE sprint_id = NEW.sprint_id
)
BEGIN SELECT RAISE(ABORT, 'terminal sprints reject human acceptance decisions'); END;

CREATE TRIGGER criterion_evidence_receipts_v2_terminal_fence
BEFORE INSERT ON criterion_evidence_receipts_v2
WHEN EXISTS (
    SELECT 1 FROM sprint_terminal_states WHERE sprint_id = NEW.sprint_id
    UNION ALL
    SELECT 1 FROM sprint_completion_proof_states WHERE sprint_id = NEW.sprint_id
    UNION ALL
    SELECT 1 FROM sprint_non_success_terminal_outcomes WHERE sprint_id = NEW.sprint_id
)
BEGIN SELECT RAISE(ABORT, 'terminal sprints reject criterion evidence'); END;

CREATE TRIGGER v28_completion_criterion_evidence_terminal_fence
BEFORE INSERT ON v28_completion_criterion_evidence_receipts
WHEN EXISTS (
    SELECT 1 FROM sprint_terminal_states WHERE sprint_id = NEW.sprint_id
    UNION ALL
    SELECT 1 FROM sprint_completion_proof_states WHERE sprint_id = NEW.sprint_id
    UNION ALL
    SELECT 1 FROM sprint_non_success_terminal_outcomes WHERE sprint_id = NEW.sprint_id
)
BEGIN SELECT RAISE(ABORT, 'terminal sprints reject completion criterion-evidence links'); END;

-- The schema-v24 terminal trigger authenticates the historical
-- `acceptance_receipts` child array. Current receipts use a different child
-- table and JSON property, for which a missing legacy path evaluates to NULL
-- in SQLite. This additive trigger closes that three-valued-logic gap without
-- changing the immutable historical branch.
CREATE TRIGGER sprint_completion_proof_states_v28_current_criterion_evidence_required
BEFORE INSERT ON sprint_completion_proof_states
WHEN NEW.proof_state = 'ProvenV9'
 AND NOT EXISTS (
     SELECT 1 FROM v28_legacy_completion_acceptance_sets legacy
     WHERE legacy.completion_receipt_id = NEW.completion_receipt_id
       AND legacy.sprint_id = NEW.sprint_id
 )
 AND (
     EXISTS (
         SELECT 1 FROM v9_completion_acceptance_receipts legacy_child
         WHERE legacy_child.completion_receipt_id = NEW.completion_receipt_id
     )
     OR NOT EXISTS (
         SELECT 1 FROM v9_completion_receipts receipt
         WHERE receipt.receipt_id = NEW.completion_receipt_id
           AND receipt.sprint_id = NEW.sprint_id
           AND json_type(
               CAST(receipt.receipt_json AS TEXT),
               '$.criterion_evidence_receipt_ids'
           ) = 'array'
           AND json_type(
               CAST(receipt.receipt_json AS TEXT),
               '$.acceptance_receipts'
           ) IS NULL
     )
     OR (
         SELECT COUNT(*) FROM v28_completion_criterion_evidence_receipts child
         WHERE child.completion_receipt_id = NEW.completion_receipt_id
           AND child.sprint_id = NEW.sprint_id
     ) != (
         SELECT json_array_length(
             CAST(receipt.receipt_json AS TEXT),
             '$.criterion_evidence_receipt_ids'
         )
         FROM v9_completion_receipts receipt
         WHERE receipt.receipt_id = NEW.completion_receipt_id
           AND receipt.sprint_id = NEW.sprint_id
     )
     OR EXISTS (
         SELECT 1
         FROM v28_completion_criterion_evidence_receipts child
         JOIN v9_completion_receipts receipt
           ON receipt.receipt_id = child.completion_receipt_id
          AND receipt.sprint_id = child.sprint_id
         WHERE child.completion_receipt_id = NEW.completion_receipt_id
           AND child.sprint_id = NEW.sprint_id
           AND child.criterion_evidence_receipt_id IS NOT json_extract(
               CAST(receipt.receipt_json AS TEXT),
               '$.criterion_evidence_receipt_ids[' || child.ordinal || ']'
           )
     )
     OR COALESCE((
         SELECT MAX(child.ordinal)
         FROM v28_completion_criterion_evidence_receipts child
         WHERE child.completion_receipt_id = NEW.completion_receipt_id
           AND child.sprint_id = NEW.sprint_id
     ), -1) != (
         SELECT json_array_length(
             CAST(receipt.receipt_json AS TEXT),
             '$.criterion_evidence_receipt_ids'
         ) - 1
         FROM v9_completion_receipts receipt
         WHERE receipt.receipt_id = NEW.completion_receipt_id
           AND receipt.sprint_id = NEW.sprint_id
     )
     OR NOT EXISTS (
         SELECT 1
         FROM v9_completion_receipts receipt
         JOIN sprints sprint ON sprint.sprint_id = receipt.sprint_id
         WHERE receipt.receipt_id = NEW.completion_receipt_id
           AND receipt.sprint_id = NEW.sprint_id
           AND json_type(
               CAST(receipt.receipt_json AS TEXT),
               '$.satisfied_criterion_ids'
           ) = 'array'
           AND json_array_length(
               CAST(receipt.receipt_json AS TEXT),
               '$.satisfied_criterion_ids'
           ) = json_array_length(
               CAST(sprint.spec_json AS TEXT),
               '$.acceptance_criteria'
           )
           AND json_array_length(
               CAST(receipt.receipt_json AS TEXT),
               '$.criterion_evidence_receipt_ids'
           ) = json_array_length(
               CAST(sprint.spec_json AS TEXT),
               '$.acceptance_criteria'
           )
     )
     OR EXISTS (
         SELECT 1
         FROM v9_completion_receipts receipt
         JOIN sprints sprint ON sprint.sprint_id = receipt.sprint_id
         JOIN json_each(
             CAST(sprint.spec_json AS TEXT),
             '$.acceptance_criteria'
         ) criterion
         WHERE receipt.receipt_id = NEW.completion_receipt_id
           AND receipt.sprint_id = NEW.sprint_id
           AND (
               NOT EXISTS (
                   SELECT 1
                   FROM json_each(
                       CAST(receipt.receipt_json AS TEXT),
                       '$.satisfied_criterion_ids'
                   ) satisfied
                   WHERE satisfied.value IS json_extract(
                       criterion.value, '$.criterion_id'
                   )
               )
               OR NOT EXISTS (
                   SELECT 1
                   FROM v28_completion_criterion_evidence_receipts child
                   JOIN criterion_evidence_receipts_v2 evidence
                     ON evidence.receipt_id = child.criterion_evidence_receipt_id
                    AND evidence.sprint_id = child.sprint_id
                   LEFT JOIN verification_receipts verification
                     ON verification.receipt_id = evidence.verification_receipt_id
                    AND verification.sprint_id = evidence.sprint_id
                   WHERE child.completion_receipt_id = receipt.receipt_id
                     AND child.sprint_id = receipt.sprint_id
                     AND evidence.criterion_id IS json_extract(
                         criterion.value, '$.criterion_id'
                     )
                     AND evidence.snapshot_digest IS receipt.final_snapshot
                     AND evidence.recorded_at_unix_ms <= receipt.completed_at_unix_ms
                     AND COALESCE(
                         (
                             json_type(
                                 criterion.value, '$.kind.Automated'
                             ) = 'object'
                             AND evidence.evidence_kind = 'Verified'
                             AND verification.receipt_id IS NOT NULL
                             AND json_extract(
                                 CAST(verification.receipt_json AS TEXT), '$.command'
                             ) IS json_extract(
                                 criterion.value, '$.kind.Automated'
                             )
                             AND EXISTS (
                                 SELECT 1
                                 FROM v9_completion_verification_receipts linked
                                 WHERE linked.completion_receipt_id = receipt.receipt_id
                                   AND linked.sprint_id = receipt.sprint_id
                                   AND linked.verification_receipt_id
                                       = evidence.verification_receipt_id
                             )
                         )
                         OR (
                             json_extract(
                                 criterion.value, '$.kind'
                             ) = 'HumanJudgment'
                             AND evidence.evidence_kind = 'AcceptedByYou'
                         ),
                         0
                     ) = 1
               )
           )
     )
 )
BEGIN
    SELECT RAISE(ABORT, 'current completion requires exact typed criterion-evidence child links');
END;


-- Final verification may leave AwaitingAcceptance only through the same
-- specialized atomic admission used by Running, and only after complete
-- same-snapshot AcceptedByYou evidence exists for every human criterion.
DROP TRIGGER sprint_final_verification_admissions_v21_validate;

CREATE TRIGGER sprint_final_verification_admissions_v28_validate
BEFORE INSERT ON sprint_final_verification_admissions
WHEN CASE
       WHEN json_valid(CAST(NEW.admission_json AS TEXT)) = 1
        AND json_valid(CAST(NEW.command_bytes AS TEXT)) = 1
       THEN (
           CAST(NEW.command_bytes AS TEXT) != json_object(
               'program', json_extract(CAST(NEW.command_bytes AS TEXT), '$.program'),
               'arguments', json(json_extract(CAST(NEW.command_bytes AS TEXT), '$.arguments')),
               'working_directory', json_extract(
                   CAST(NEW.command_bytes AS TEXT), '$.working_directory')
           )
           OR CAST(NEW.admission_json AS TEXT) != json_object(
               'contract_version', NEW.contract_version,
               'admission_id', NEW.admission_id,
               'sprint_id', NEW.sprint_id,
               'sprint_phase_event_id', NEW.sprint_phase_event_id,
               'final_snapshot', NEW.final_snapshot,
               'effect_id', NEW.effect_id,
               'runner_launch_id', NEW.runner_launch_id,
               'runner_session_id', NEW.runner_session_id,
               'command', json(CAST(NEW.command_bytes AS TEXT)),
               'admitted_at_unix_ms', NEW.admitted_at_unix_ms
           )
       )
       ELSE 1
     END
 OR NEW.command_digest != grok_sha256(NEW.command_bytes)
 OR NOT EXISTS (SELECT 1 FROM sprint_task_graphs WHERE sprint_id = NEW.sprint_id)
 OR EXISTS (SELECT 1 FROM effect_intents WHERE effect_id = NEW.effect_id)
 OR EXISTS (SELECT 1 FROM active_worker_leases WHERE sprint_id = NEW.sprint_id)
 OR NOT EXISTS (
    SELECT 1
    FROM agent_events phase
    JOIN runner_launch_intents launch
      ON launch.sprint_id = NEW.sprint_id AND launch.launch_id = NEW.runner_launch_id
    JOIN runner_session_policies session
      ON session.sprint_id = NEW.sprint_id
     AND session.session_id = NEW.runner_session_id
     AND session.launch_id = launch.launch_id
    JOIN workspace_snapshots snapshot
      ON snapshot.sprint_id = NEW.sprint_id
     AND snapshot.snapshot_id = NEW.final_snapshot
    WHERE phase.sprint_id = NEW.sprint_id
      AND phase.event_id = NEW.sprint_phase_event_id
      AND launch.purpose = 'FinalVerifier'
      AND session.purpose = 'FinalVerifier'
      AND launch.worker_id IS NULL
      AND session.worker_id IS NULL
      AND launch.worker_lease_id IS NULL
      AND session.worker_lease_id IS NULL
      AND launch.contract_version = NEW.contract_version
      AND session.contract_version = NEW.contract_version
      AND phase.contract_version = NEW.contract_version
      AND json_extract(CAST(phase.event_json AS TEXT), '$.policy_hash') = launch.policy_hash
      AND json_extract(CAST(phase.event_json AS TEXT), '$.policy_hash') = session.policy_hash
      AND phase.occurred_at_unix_ms <= NEW.admitted_at_unix_ms
      AND launch.created_at_unix_ms <= NEW.admitted_at_unix_ms
      AND session.registered_at_unix_ms <= NEW.admitted_at_unix_ms
      AND snapshot.created_at_unix_ms <= NEW.admitted_at_unix_ms
      AND json_extract(CAST(phase.event_json AS TEXT), '$.payload.SprintStateChanged.from')
          IN ('Running', 'AwaitingAcceptance')
      AND json_extract(CAST(phase.event_json AS TEXT), '$.payload.SprintStateChanged.to') = 'FinalVerification'
      AND (
          (
              json_extract(CAST(phase.event_json AS TEXT), '$.payload.SprintStateChanged.from') = 'Running'
              AND NOT EXISTS (
                  SELECT 1
                  FROM sprints accepting_sprint,
                       json_each(CAST(accepting_sprint.spec_json AS TEXT), '$.acceptance_criteria') human
                  WHERE accepting_sprint.sprint_id = NEW.sprint_id
                    AND json_extract(human.value, '$.kind') = 'HumanJudgment'
              )
          )
          OR (
              json_extract(CAST(phase.event_json AS TEXT), '$.payload.SprintStateChanged.from') = 'AwaitingAcceptance'
              AND EXISTS (
                  SELECT 1
                  FROM sprints accepting_sprint,
                       json_each(CAST(accepting_sprint.spec_json AS TEXT), '$.acceptance_criteria') human
                  WHERE accepting_sprint.sprint_id = NEW.sprint_id
                    AND json_extract(human.value, '$.kind') = 'HumanJudgment'
              )
              AND NOT EXISTS (
                  SELECT 1
                  FROM sprints accepting_sprint,
                       json_each(CAST(accepting_sprint.spec_json AS TEXT), '$.acceptance_criteria') human
                  WHERE accepting_sprint.sprint_id = NEW.sprint_id
                    AND json_extract(human.value, '$.kind') = 'HumanJudgment'
                    AND NOT EXISTS (
                        SELECT 1
                        FROM criterion_evidence_receipts_v2 evidence
                        WHERE evidence.sprint_id = NEW.sprint_id
                          AND evidence.criterion_id = json_extract(human.value, '$.criterion_id')
                          AND evidence.snapshot_digest = NEW.final_snapshot
                          AND evidence.evidence_kind = 'AcceptedByYou'
                          AND evidence.recorded_at_unix_ms <= NEW.admitted_at_unix_ms
                    )
              )
              AND NOT EXISTS (
                  SELECT 1
                  FROM criterion_evidence_receipts_v2 evidence
                  WHERE evidence.sprint_id = NEW.sprint_id
                    AND evidence.snapshot_digest = NEW.final_snapshot
                    AND evidence.evidence_kind = 'AcceptedByYou'
                    AND (
                        evidence.recorded_at_unix_ms > NEW.admitted_at_unix_ms
                        OR NOT EXISTS (
                            SELECT 1
                            FROM sprints accepting_sprint,
                                 json_each(CAST(accepting_sprint.spec_json AS TEXT), '$.acceptance_criteria') human
                            WHERE accepting_sprint.sprint_id = NEW.sprint_id
                              AND json_extract(human.value, '$.criterion_id') = evidence.criterion_id
                              AND json_extract(human.value, '$.kind') = 'HumanJudgment'
                        )
                    )
              )
          )
      )
      AND json_extract(CAST(phase.event_json AS TEXT), '$.task_id') IS NULL
      AND json_extract(CAST(phase.event_json AS TEXT), '$.worker_id') IS NULL
      AND NOT EXISTS (
          SELECT 1 FROM agent_events later
          WHERE later.sprint_id = NEW.sprint_id
            AND later.sequence > phase.sequence
            AND json_type(CAST(later.event_json AS TEXT), '$.payload.SprintStateChanged') = 'object'
      )
 )
 OR EXISTS (
    SELECT 1
    FROM agent_events current
    WHERE current.sprint_id = NEW.sprint_id
      AND json_type(CAST(current.event_json AS TEXT), '$.payload.SprintStateChanged') = 'object'
      AND (
          json_extract(CAST(current.event_json AS TEXT), '$.task_id') IS NOT NULL
          OR json_extract(CAST(current.event_json AS TEXT), '$.worker_id') IS NOT NULL
          OR COALESCE(json_extract(CAST(current.event_json AS TEXT), '$.payload.SprintStateChanged.from'), '') NOT IN (
              'Draft', 'Planning', 'Running', 'AwaitingAcceptance', 'FinalVerification',
              'Applying', 'Completed', 'Blocked', 'Failed', 'Canceled', 'Unknown'
          )
          OR COALESCE(json_extract(CAST(current.event_json AS TEXT), '$.payload.SprintStateChanged.to'), '') NOT IN (
              'Draft', 'Planning', 'Running', 'AwaitingAcceptance', 'FinalVerification',
              'Applying', 'Completed', 'Blocked', 'Failed', 'Canceled', 'Unknown'
          )
          OR COALESCE((
              SELECT json_extract(CAST(prior.event_json AS TEXT), '$.payload.SprintStateChanged.to')
              FROM agent_events prior
              WHERE prior.sprint_id = current.sprint_id
                AND prior.sequence < current.sequence
                AND json_type(CAST(prior.event_json AS TEXT), '$.payload.SprintStateChanged') = 'object'
              ORDER BY prior.sequence DESC LIMIT 1
          ), CASE
                 WHEN json_extract(CAST(current.event_json AS TEXT), '$.payload.SprintStateChanged.from') = 'Draft'
                 THEN 'Draft'
                 ELSE 'Running'
             END) != json_extract(CAST(current.event_json AS TEXT), '$.payload.SprintStateChanged.from')
          OR NOT (
              (json_extract(CAST(current.event_json AS TEXT), '$.payload.SprintStateChanged.from') = 'Draft'
               AND json_extract(CAST(current.event_json AS TEXT), '$.payload.SprintStateChanged.to') = 'Planning')
              OR (json_extract(CAST(current.event_json AS TEXT), '$.payload.SprintStateChanged.from') = 'Planning'
                  AND json_extract(CAST(current.event_json AS TEXT), '$.payload.SprintStateChanged.to') IN ('Running', 'AwaitingAcceptance'))
              OR (json_extract(CAST(current.event_json AS TEXT), '$.payload.SprintStateChanged.from') = 'Running'
                  AND json_extract(CAST(current.event_json AS TEXT), '$.payload.SprintStateChanged.to') IN ('AwaitingAcceptance', 'FinalVerification'))
              OR (json_extract(CAST(current.event_json AS TEXT), '$.payload.SprintStateChanged.from') = 'AwaitingAcceptance'
                  AND json_extract(CAST(current.event_json AS TEXT), '$.payload.SprintStateChanged.to') IN ('Running', 'FinalVerification'))
              OR (json_extract(CAST(current.event_json AS TEXT), '$.payload.SprintStateChanged.from') = 'FinalVerification'
                  AND json_extract(CAST(current.event_json AS TEXT), '$.payload.SprintStateChanged.to') IN ('Running', 'AwaitingAcceptance', 'Applying'))
              OR (json_extract(CAST(current.event_json AS TEXT), '$.payload.SprintStateChanged.from') IN (
                      'Draft', 'Planning', 'Running', 'AwaitingAcceptance', 'FinalVerification', 'Applying'
                  )
                  AND json_extract(CAST(current.event_json AS TEXT), '$.payload.SprintStateChanged.to') IN (
                      'Blocked', 'Failed', 'Canceled', 'Unknown'
                  ))
          )
      )
 )
 OR EXISTS (
    SELECT 1
    FROM sprint_task_graphs graph
    JOIN json_each(CAST(graph.graph_json AS TEXT), '$.tasks') task
    WHERE graph.sprint_id = NEW.sprint_id
      AND json_extract(task.value, '$.required') = 1
      AND NOT EXISTS (
          SELECT 1
          FROM task_attempts attempt
          JOIN task_attempt_dispositions disposition
            ON disposition.attempt_id = attempt.attempt_id
           AND disposition.disposition_kind = 'Integrated'
          JOIN task_integration_receipts receipt
            ON receipt.receipt_id = disposition.integration_receipt_id
           AND receipt.sprint_id = attempt.sprint_id
           AND receipt.task_id = attempt.task_id
          WHERE attempt.sprint_id = NEW.sprint_id
            AND attempt.task_id = json_extract(task.value, '$.task_id')
            AND attempt.schema_generation = 15
            AND attempt.attempt_ordinal = (
                SELECT MAX(latest.attempt_ordinal)
                FROM task_attempts latest
                WHERE latest.sprint_id = attempt.sprint_id
                  AND latest.task_id = attempt.task_id
                  AND latest.schema_generation = 15
            )
            AND COALESCE((
                SELECT json_extract(CAST(state.event_json AS TEXT), '$.payload.TaskStateChanged.to')
                FROM agent_events state
                WHERE state.sprint_id = attempt.sprint_id
                  AND json_extract(CAST(state.event_json AS TEXT), '$.task_id') = attempt.task_id
                  AND json_type(CAST(state.event_json AS TEXT), '$.payload.TaskStateChanged') = 'object'
                ORDER BY state.sequence DESC LIMIT 1
            ), '') = 'Integrated'
      )
 )
 OR EXISTS (
    SELECT 1 FROM task_attempts attempt
    LEFT JOIN task_attempt_dispositions disposition
      ON disposition.attempt_id = attempt.attempt_id
    WHERE attempt.sprint_id = NEW.sprint_id
      AND attempt.schema_generation = 15
      AND disposition.attempt_id IS NULL
 )
 OR EXISTS (
    SELECT 1
    FROM runner_launch_intents launch
    LEFT JOIN worker_cleanup_receipts cleanup
      ON cleanup.sprint_id = launch.sprint_id AND cleanup.launch_id = launch.launch_id
    WHERE launch.sprint_id = NEW.sprint_id
      AND launch.purpose = 'TaskWorker'
      AND (cleanup.receipt_id IS NULL OR cleanup.surviving_processes != 0)
 )
 OR EXISTS (
    SELECT 1
    FROM effect_intents intent
    LEFT JOIN effect_session_bindings binding
      ON binding.sprint_id = intent.sprint_id AND binding.effect_id = intent.effect_id
    LEFT JOIN runner_launch_intents launch
      ON launch.sprint_id = binding.sprint_id AND launch.launch_id = binding.launch_id
    LEFT JOIN effect_observations observation ON observation.effect_id = intent.effect_id
    WHERE intent.sprint_id = NEW.sprint_id
      AND (
          intent.task_id IS NOT NULL
          OR intent.worker_lease_id IS NOT NULL
          OR launch.purpose = 'TaskWorker'
      )
      AND (observation.effect_id IS NULL OR observation.outcome = 'Unknown')
 )
 OR EXISTS (
    SELECT 1
    FROM effect_session_bindings binding
    JOIN runner_session_policies session
      ON session.sprint_id = binding.sprint_id AND session.session_id = binding.session_id
    JOIN effect_intents intent ON intent.effect_id = binding.effect_id
    LEFT JOIN command_domain_cleanup_proofs proof ON proof.effect_id = intent.effect_id
    WHERE binding.sprint_id = NEW.sprint_id
      AND session.purpose = 'TaskWorker'
      AND intent.effect_kind = 'RunCommand'
      AND proof.effect_id IS NULL
 )
 OR EXISTS (
    SELECT 1
    FROM task_attempts attempt
    WHERE attempt.sprint_id = NEW.sprint_id
      AND attempt.schema_generation = 15
      AND NOT EXISTS (
          SELECT 1
          FROM sprint_task_graphs graph
          JOIN json_each(CAST(graph.graph_json AS TEXT), '$.tasks') task
            ON json_extract(task.value, '$.task_id') = attempt.task_id
          WHERE graph.sprint_id = NEW.sprint_id
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
    JOIN sprint_task_graphs graph ON graph.sprint_id = attempt.sprint_id
    JOIN json_each(CAST(graph.graph_json AS TEXT), '$.tasks') task
      ON json_extract(task.value, '$.task_id') = attempt.task_id
     AND json_extract(task.value, '$.required') = 0
    WHERE attempt.sprint_id = NEW.sprint_id
      AND attempt.schema_generation = 15
      AND attempt.attempt_ordinal = (
          SELECT MAX(latest.attempt_ordinal)
          FROM task_attempts latest
          WHERE latest.sprint_id = attempt.sprint_id
            AND latest.task_id = attempt.task_id
            AND latest.schema_generation = 15
      )
      AND NOT (
          (disposition.disposition_kind = 'Integrated'
           AND COALESCE((
               SELECT json_extract(CAST(state.event_json AS TEXT), '$.payload.TaskStateChanged.to')
               FROM agent_events state
               WHERE state.sprint_id = attempt.sprint_id
                 AND json_extract(CAST(state.event_json AS TEXT), '$.task_id') = attempt.task_id
                 AND json_type(CAST(state.event_json AS TEXT), '$.payload.TaskStateChanged') = 'object'
               ORDER BY state.sequence DESC LIMIT 1
           ), '') = 'Integrated')
          OR (disposition.disposition_kind IN ('AttemptsExhausted', 'PermanentFailure')
              AND COALESCE((
                  SELECT json_extract(CAST(state.event_json AS TEXT), '$.payload.TaskStateChanged.to')
                  FROM agent_events state
                  WHERE state.sprint_id = attempt.sprint_id
                    AND json_extract(CAST(state.event_json AS TEXT), '$.task_id') = attempt.task_id
                    AND json_type(CAST(state.event_json AS TEXT), '$.payload.TaskStateChanged') = 'object'
                  ORDER BY state.sequence DESC LIMIT 1
              ), '') = 'Failed')
          OR (disposition.disposition_kind = 'Blocked'
              AND COALESCE((
                  SELECT json_extract(CAST(state.event_json AS TEXT), '$.payload.TaskStateChanged.to')
                  FROM agent_events state
                  WHERE state.sprint_id = attempt.sprint_id
                    AND json_extract(CAST(state.event_json AS TEXT), '$.task_id') = attempt.task_id
                    AND json_type(CAST(state.event_json AS TEXT), '$.payload.TaskStateChanged') = 'object'
                  ORDER BY state.sequence DESC LIMIT 1
              ), '') = 'Blocked')
          OR (disposition.disposition_kind = 'Canceled'
              AND COALESCE((
                  SELECT json_extract(CAST(state.event_json AS TEXT), '$.payload.TaskStateChanged.to')
                  FROM agent_events state
                  WHERE state.sprint_id = attempt.sprint_id
                    AND json_extract(CAST(state.event_json AS TEXT), '$.task_id') = attempt.task_id
                    AND json_type(CAST(state.event_json AS TEXT), '$.payload.TaskStateChanged') = 'object'
                  ORDER BY state.sequence DESC LIMIT 1
              ), '') = 'Canceled')
      )
 )
 OR EXISTS (
    SELECT 1
    FROM task_attempts attempt
    JOIN sprints sprint ON sprint.sprint_id = attempt.sprint_id
    WHERE attempt.sprint_id = NEW.sprint_id
      AND attempt.schema_generation = 15
    GROUP BY attempt.task_id
    HAVING COUNT(*) > json_extract(CAST(sprint.spec_json AS TEXT), '$.budget.max_attempts_per_task')
 )
 OR (
    (SELECT COUNT(*)
     FROM task_integration_receipts receipt
     JOIN task_attempt_dispositions disposition
       ON disposition.integration_receipt_id = receipt.receipt_id
      AND disposition.disposition_kind = 'Integrated'
     JOIN task_attempts attempt
       ON attempt.attempt_id = disposition.attempt_id
      AND attempt.sprint_id = receipt.sprint_id
      AND attempt.task_id = receipt.task_id
      AND attempt.schema_generation = 15
     JOIN sprint_task_graphs graph ON graph.sprint_id = receipt.sprint_id
     JOIN json_each(CAST(graph.graph_json AS TEXT), '$.tasks') task
       ON json_extract(task.value, '$.task_id') = receipt.task_id
     WHERE receipt.sprint_id = NEW.sprint_id
       AND attempt.attempt_ordinal = (
           SELECT MAX(latest.attempt_ordinal)
           FROM task_attempts latest
           WHERE latest.sprint_id = attempt.sprint_id
             AND latest.task_id = attempt.task_id
             AND latest.schema_generation = 15
       ))
    != COALESCE((
        SELECT MAX(receipt.integration_ordinal) + 1
        FROM task_integration_receipts receipt
        JOIN task_attempt_dispositions disposition
          ON disposition.integration_receipt_id = receipt.receipt_id
         AND disposition.disposition_kind = 'Integrated'
        JOIN task_attempts attempt
          ON attempt.attempt_id = disposition.attempt_id
         AND attempt.sprint_id = receipt.sprint_id
         AND attempt.task_id = receipt.task_id
         AND attempt.schema_generation = 15
        JOIN sprint_task_graphs graph ON graph.sprint_id = receipt.sprint_id
        JOIN json_each(CAST(graph.graph_json AS TEXT), '$.tasks') task
          ON json_extract(task.value, '$.task_id') = receipt.task_id
        WHERE receipt.sprint_id = NEW.sprint_id
          AND attempt.attempt_ordinal = (
              SELECT MAX(latest.attempt_ordinal)
              FROM task_attempts latest
              WHERE latest.sprint_id = attempt.sprint_id
                AND latest.task_id = attempt.task_id
                AND latest.schema_generation = 15
          )
    ), 0)
 )
 OR EXISTS (
    SELECT 1
    FROM task_integration_receipts receipt
    JOIN task_attempt_dispositions disposition
      ON disposition.integration_receipt_id = receipt.receipt_id
     AND disposition.disposition_kind = 'Integrated'
    JOIN task_attempts attempt
      ON attempt.attempt_id = disposition.attempt_id
     AND attempt.sprint_id = receipt.sprint_id
     AND attempt.task_id = receipt.task_id
     AND attempt.schema_generation = 15
    JOIN sprint_task_graphs graph ON graph.sprint_id = receipt.sprint_id
    JOIN json_each(CAST(graph.graph_json AS TEXT), '$.tasks') task
      ON json_extract(task.value, '$.task_id') = receipt.task_id
    WHERE receipt.sprint_id = NEW.sprint_id
      AND attempt.attempt_ordinal = (
          SELECT MAX(latest.attempt_ordinal)
          FROM task_attempts latest
          WHERE latest.sprint_id = attempt.sprint_id
            AND latest.task_id = attempt.task_id
            AND latest.schema_generation = 15
      )
      AND (
          (receipt.integration_ordinal = 0
           AND receipt.input_snapshot != (
               SELECT json_extract(CAST(sprint.spec_json AS TEXT), '$.base_snapshot')
               FROM sprints sprint WHERE sprint.sprint_id = NEW.sprint_id
           ))
          OR (receipt.integration_ordinal > 0 AND NOT EXISTS (
              SELECT 1
              FROM task_integration_receipts prior
              JOIN task_attempt_dispositions prior_disposition
                ON prior_disposition.integration_receipt_id = prior.receipt_id
               AND prior_disposition.disposition_kind = 'Integrated'
              JOIN task_attempts prior_attempt
                ON prior_attempt.attempt_id = prior_disposition.attempt_id
               AND prior_attempt.sprint_id = prior.sprint_id
               AND prior_attempt.task_id = prior.task_id
               AND prior_attempt.schema_generation = 15
              JOIN sprint_task_graphs prior_graph ON prior_graph.sprint_id = prior.sprint_id
              JOIN json_each(CAST(prior_graph.graph_json AS TEXT), '$.tasks') prior_task
                ON json_extract(prior_task.value, '$.task_id') = prior.task_id
              WHERE prior.sprint_id = NEW.sprint_id
                AND prior.integration_ordinal = receipt.integration_ordinal - 1
                AND prior.result_snapshot = receipt.input_snapshot
                AND prior_attempt.attempt_ordinal = (
                    SELECT MAX(latest.attempt_ordinal)
                    FROM task_attempts latest
                    WHERE latest.sprint_id = prior_attempt.sprint_id
                      AND latest.task_id = prior_attempt.task_id
                      AND latest.schema_generation = 15
                )
          ))
      )
 )
 OR NEW.final_snapshot != COALESCE(
    (SELECT receipt.result_snapshot
     FROM task_integration_receipts receipt
     JOIN task_attempt_dispositions disposition
       ON disposition.integration_receipt_id = receipt.receipt_id
      AND disposition.disposition_kind = 'Integrated'
     JOIN task_attempts attempt
       ON attempt.attempt_id = disposition.attempt_id
      AND attempt.sprint_id = receipt.sprint_id
      AND attempt.task_id = receipt.task_id
      AND attempt.schema_generation = 15
     JOIN sprint_task_graphs graph ON graph.sprint_id = receipt.sprint_id
     JOIN json_each(CAST(graph.graph_json AS TEXT), '$.tasks') task
       ON json_extract(task.value, '$.task_id') = receipt.task_id
     WHERE receipt.sprint_id = NEW.sprint_id
       AND attempt.attempt_ordinal = (
           SELECT MAX(latest.attempt_ordinal)
           FROM task_attempts latest
           WHERE latest.sprint_id = attempt.sprint_id
             AND latest.task_id = attempt.task_id
             AND latest.schema_generation = 15
       )
     ORDER BY receipt.integration_ordinal DESC LIMIT 1),
    (SELECT json_extract(CAST(sprint.spec_json AS TEXT), '$.base_snapshot')
     FROM sprints sprint WHERE sprint.sprint_id = NEW.sprint_id)
 )
BEGIN SELECT RAISE(ABORT, 'final verification admission requires exact closed TaskDone snapshot authority'); END;


-- The final effect and its one-use dispatch claim must accept the same two
-- phase sources as the v28 admission gate. The admission table remains the
-- sole source of human-evidence authority for these downstream mirrors.
DROP TRIGGER effect_intents_cover_sprint_final_verification_admission;
CREATE TRIGGER effect_intents_cover_sprint_final_verification_admission
AFTER INSERT ON effect_intents
WHEN (
       EXISTS (
           SELECT 1 FROM sprint_final_verification_admissions admission
           WHERE admission.effect_id = NEW.effect_id
       )
       OR (
           NEW.effect_kind = 'RunCommand'
           AND NEW.task_id IS NULL
           AND NEW.worker_id IS NULL
           AND NEW.worker_lease_id IS NULL
           AND EXISTS (
               SELECT 1
               FROM effect_session_bindings binding
               JOIN runner_session_policies session
                 ON session.sprint_id = binding.sprint_id
                AND session.session_id = binding.session_id
               WHERE binding.effect_id = NEW.effect_id
                 AND binding.sprint_id = NEW.sprint_id
                 AND session.purpose = 'FinalVerifier'
           )
           AND COALESCE((
               SELECT json_extract(CAST(phase.event_json AS TEXT), '$.payload.SprintStateChanged.to')
               FROM agent_events phase
               WHERE phase.sprint_id = NEW.sprint_id
                 AND json_type(CAST(phase.event_json AS TEXT), '$.payload.SprintStateChanged') = 'object'
               ORDER BY phase.sequence DESC LIMIT 1
           ), '') = 'FinalVerification'
       )
     )
 AND NOT EXISTS (
       SELECT 1
       FROM sprint_final_verification_admissions admission
       JOIN agent_events phase
         ON phase.event_id = admission.sprint_phase_event_id
        AND phase.sprint_id = admission.sprint_id
       JOIN effect_session_bindings binding
         ON binding.effect_id = NEW.effect_id
        AND binding.sprint_id = NEW.sprint_id
       JOIN runner_launch_intents launch
         ON launch.sprint_id = binding.sprint_id
        AND launch.launch_id = binding.launch_id
       JOIN runner_session_policies session
         ON session.sprint_id = binding.sprint_id
        AND session.session_id = binding.session_id
        AND session.launch_id = launch.launch_id
       JOIN effect_request_payloads request
         ON request.effect_id = NEW.effect_id
        AND request.sprint_id = NEW.sprint_id
       WHERE admission.effect_id = NEW.effect_id
         AND admission.sprint_id = NEW.sprint_id
         AND admission.final_snapshot = NEW.input_snapshot
         AND admission.runner_launch_id = binding.launch_id
         AND admission.runner_session_id = binding.session_id
         AND admission.command_digest = NEW.request_digest
         AND admission.command_digest = request.request_digest
         AND admission.command_bytes = request.request_bytes
         AND admission.sprint_phase_event_id = NEW.causation_event_id
         AND NEW.effect_kind = 'RunCommand'
         AND NEW.task_id IS NULL
         AND NEW.worker_id IS NULL
         AND NEW.worker_lease_id IS NULL
         AND NEW.worker_lease_epoch IS NULL
         AND NEW.correlation_id = json_extract(CAST(phase.event_json AS TEXT), '$.correlation_id')
         AND NEW.policy_hash = json_extract(CAST(phase.event_json AS TEXT), '$.policy_hash')
         AND NEW.policy_hash = launch.policy_hash
         AND NEW.policy_hash = session.policy_hash
         AND NEW.created_at_unix_ms = admission.admitted_at_unix_ms
         AND phase.occurred_at_unix_ms <= NEW.created_at_unix_ms
         AND launch.created_at_unix_ms <= NEW.created_at_unix_ms
         AND session.registered_at_unix_ms <= NEW.created_at_unix_ms
         AND launch.purpose = 'FinalVerifier'
         AND session.purpose = 'FinalVerifier'
         AND launch.worker_id IS NULL
         AND session.worker_id IS NULL
         AND launch.worker_lease_id IS NULL
         AND session.worker_lease_id IS NULL
         AND request.contract_version = NEW.contract_version
         AND admission.contract_version = NEW.contract_version
         AND phase.contract_version = NEW.contract_version
         AND launch.contract_version = NEW.contract_version
         AND session.contract_version = NEW.contract_version
         AND json_extract(CAST(phase.event_json AS TEXT), '$.payload.SprintStateChanged.from')
             IN ('Running', 'AwaitingAcceptance')
         AND json_extract(CAST(phase.event_json AS TEXT), '$.payload.SprintStateChanged.to') = 'FinalVerification'
         AND NOT EXISTS (
             SELECT 1 FROM agent_events later
             WHERE later.sprint_id = NEW.sprint_id
               AND later.sequence > phase.sequence
               AND json_type(CAST(later.event_json AS TEXT), '$.payload.SprintStateChanged') = 'object'
         )
     )
BEGIN
    SELECT RAISE(ABORT, 'FinalVerifier RunCommand must exactly match one current sprint final-verification admission');
END;

DROP TRIGGER runner_effect_dispatch_claims_identity_match;
CREATE TRIGGER runner_effect_dispatch_claims_identity_match
BEFORE INSERT ON runner_effect_dispatch_claims
WHEN NOT EXISTS (
    SELECT 1 FROM live_state_capture_dispatch_claim_authorities capture_authority
    WHERE capture_authority.dispatch_claim_id = NEW.dispatch_claim_id
)
AND NOT EXISTS (
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
          OR (authority.authority_class = 'SprintFinalVerification'
              AND session.purpose = 'FinalVerifier'
              AND launch.purpose = 'FinalVerifier'
              AND launch.worker_id IS NULL
              AND session.worker_id IS NULL
              AND NEW.running_boundary_id IS NULL
              AND intent.task_id IS NULL
              AND intent.worker_id IS NULL
              AND intent.worker_lease_id IS NULL
              AND intent.worker_lease_epoch IS NULL
              AND launch.worker_lease_id IS NULL
              AND launch.worker_lease_epoch IS NULL
              AND session.worker_lease_id IS NULL
              AND session.worker_lease_epoch IS NULL
              AND intent.effect_kind = 'RunCommand'
              AND EXISTS (
                  SELECT 1
                  FROM sprint_final_verification_admissions admission
                  JOIN agent_events phase
                    ON phase.event_id = admission.sprint_phase_event_id
                   AND phase.sprint_id = admission.sprint_id
                  WHERE admission.sprint_phase_event_id = authority.sprint_phase_event_id
                    AND admission.effect_id = NEW.effect_id
                    AND admission.sprint_id = NEW.sprint_id
                    AND admission.final_snapshot = intent.input_snapshot
                    AND admission.runner_launch_id = NEW.launch_id
                    AND admission.runner_session_id = NEW.session_id
                    AND admission.command_digest = intent.request_digest
                    AND admission.contract_version = NEW.contract_version
                    AND phase.contract_version = NEW.contract_version
                    AND intent.causation_event_id = phase.event_id
                    AND json_extract(CAST(phase.event_json AS TEXT), '$.correlation_id') = intent.correlation_id
                    AND json_extract(CAST(phase.event_json AS TEXT), '$.policy_hash') = intent.policy_hash
                    AND json_extract(CAST(phase.event_json AS TEXT), '$.policy_hash') = launch.policy_hash
                    AND json_extract(CAST(phase.event_json AS TEXT), '$.policy_hash') = session.policy_hash
                    AND phase.occurred_at_unix_ms <= admission.admitted_at_unix_ms
                    AND phase.occurred_at_unix_ms <= intent.created_at_unix_ms
                    AND json_extract(CAST(phase.event_json AS TEXT), '$.payload.SprintStateChanged.from')
                        IN ('Running', 'AwaitingAcceptance')
                    AND json_extract(CAST(phase.event_json AS TEXT), '$.payload.SprintStateChanged.to') = 'FinalVerification'
                    AND NOT EXISTS (
                        SELECT 1 FROM agent_events later
                        WHERE later.sprint_id = NEW.sprint_id
                          AND later.sequence > phase.sequence
                          AND json_type(CAST(later.event_json AS TEXT), '$.payload.SprintStateChanged') = 'object'
                    )
              ))
          OR (authority.authority_class = 'SprintApplication'
              AND session.purpose = 'Applier'
              AND launch.purpose = 'Applier'
              AND launch.worker_id IS NULL
              AND session.worker_id IS NULL
              AND NEW.running_boundary_id IS NULL
              AND intent.task_id IS NULL
              AND intent.worker_id IS NULL
              AND intent.worker_lease_id IS NULL
              AND intent.worker_lease_epoch IS NULL
              AND launch.worker_lease_id IS NULL
              AND launch.worker_lease_epoch IS NULL
              AND session.worker_lease_id IS NULL
              AND session.worker_lease_epoch IS NULL
              AND intent.effect_kind = 'ApplyChangeSet'
              AND EXISTS (
                  SELECT 1
                  FROM sprint_application_admissions admission
                  JOIN application_artifact_assemblies assembly
                    ON assembly.assembly_id = admission.artifact_assembly_id
                   AND assembly.sprint_id = admission.sprint_id
                  JOIN agent_events phase
                    ON phase.event_id = admission.sprint_phase_event_id
                   AND phase.sprint_id = admission.sprint_id
                  JOIN application_request_artifact_authorities request
                    ON request.effect_id = admission.effect_id
                   AND request.sprint_id = admission.sprint_id
                  WHERE admission.sprint_phase_event_id = authority.sprint_phase_event_id
                    AND admission.effect_id = NEW.effect_id
                    AND admission.sprint_id = NEW.sprint_id
                    AND admission.base_snapshot = intent.input_snapshot
                    AND admission.base_snapshot = assembly.base_snapshot
                    AND admission.result_snapshot = assembly.result_snapshot
                    AND admission.runner_launch_id = NEW.launch_id
                    AND admission.runner_session_id = NEW.session_id
                    AND admission.request_digest = intent.request_digest
                    AND admission.request_digest = request.request_digest
                    AND admission.contract_version = NEW.contract_version
                    AND phase.contract_version = NEW.contract_version
                    AND assembly.contract_version = NEW.contract_version
                    AND request.contract_version = NEW.contract_version
                    AND intent.causation_event_id = phase.event_id
                    AND json_extract(CAST(phase.event_json AS TEXT), '$.correlation_id') = intent.correlation_id
                    AND json_extract(CAST(phase.event_json AS TEXT), '$.policy_hash') = intent.policy_hash
                    AND json_extract(CAST(phase.event_json AS TEXT), '$.policy_hash') = launch.policy_hash
                    AND json_extract(CAST(phase.event_json AS TEXT), '$.policy_hash') = session.policy_hash
                    AND phase.occurred_at_unix_ms <= admission.admitted_at_unix_ms
                    AND phase.occurred_at_unix_ms <= intent.created_at_unix_ms
                    AND json_extract(CAST(phase.event_json AS TEXT), '$.payload.SprintStateChanged.from') = 'FinalVerification'
                    AND json_extract(CAST(phase.event_json AS TEXT), '$.payload.SprintStateChanged.to') = 'Applying'
                    AND NOT EXISTS (
                        SELECT 1 FROM agent_events later
                        WHERE later.sprint_id = NEW.sprint_id
                          AND later.sequence > phase.sequence
                          AND json_type(CAST(later.event_json AS TEXT), '$.payload.SprintStateChanged') = 'object'
                    )
              ))
      )
)
BEGIN SELECT RAISE(ABORT, 'runner dispatch claim must match one exact implemented phase authority'); END;


-- Schema-v27 capture readback is downstream of final-verification admission
-- and must preserve either lawful phase source in its exact runner/dispatch
-- joins. Dependent views retain these stable view names.
DROP VIEW command_output_capture_exact_dispatch_authorities_v27;
DROP VIEW command_output_capture_exact_runner_sources_v27;
CREATE VIEW command_output_capture_exact_runner_sources_v27 AS
SELECT capture.capture_id,
       effect.effect_id,
       effect.sprint_id,
       binding.launch_id,
       binding.session_id,
       effect.request_digest,
       effect.policy_hash,
       effect.input_snapshot,
       effect.task_id,
       effect.worker_id,
       effect.worker_lease_id,
       effect.worker_lease_epoch,
       session.purpose,
       effect.created_at_unix_ms,
       effect.contract_version
FROM command_output_capture_intents capture
JOIN effect_intents effect
  ON effect.effect_id = capture.effect_id
 AND effect.sprint_id = capture.sprint_id
 AND effect.effect_kind = 'RunCommand'
 AND effect.request_digest = capture.request_digest
 AND effect.created_at_unix_ms = capture.created_at_unix_ms
 AND effect.contract_version = capture.contract_version
JOIN effect_request_payloads request
  ON request.effect_id = effect.effect_id
 AND request.sprint_id = effect.sprint_id
 AND request.request_digest = effect.request_digest
 AND request.contract_version = effect.contract_version
JOIN agent_events proposal
  ON proposal.event_id = effect.proposed_event_id
 AND proposal.sprint_id = effect.sprint_id
 AND proposal.contract_version = effect.contract_version
 AND proposal.occurred_at_unix_ms = effect.created_at_unix_ms
JOIN effect_session_bindings binding
  ON binding.effect_id = effect.effect_id
 AND binding.sprint_id = effect.sprint_id
 AND binding.launch_id = capture.runner_launch_id
 AND binding.session_id = capture.runner_session_id
 AND binding.contract_version = effect.contract_version
JOIN runner_launch_intents launch
  ON launch.sprint_id = binding.sprint_id
 AND launch.launch_id = binding.launch_id
JOIN runner_session_policies session
  ON session.sprint_id = binding.sprint_id
 AND session.session_id = binding.session_id
 AND session.launch_id = launch.launch_id
JOIN workspace_snapshots snapshot
  ON snapshot.sprint_id = effect.sprint_id
 AND snapshot.snapshot_id = effect.input_snapshot
JOIN sprints sprint ON sprint.sprint_id = effect.sprint_id
WHERE grok_sprint_spec_v27_canonical(sprint.spec_json) = 1
  AND json_extract(CAST(sprint.spec_json AS TEXT), '$.sprint_id') = sprint.sprint_id
  AND sprint.contract_version = effect.contract_version
  AND sprint.created_at_unix_ms <= launch.created_at_unix_ms
  AND grok_effect_intent_v27_canonical(effect.intent_json) = 1
  AND grok_effect_proposal_v27_canonical(
        effect.intent_json, proposal.event_json
      ) = 1
  AND grok_runner_launch_v27_canonical(
        launch.intent_json, launch.execution_policy_json
      ) = 1
  AND grok_runner_session_v27_canonical(
        session.record_json, session.execution_policy_json
      ) = 1
  AND grok_agent_event_v27_canonical(proposal.event_json) = 1
  AND grok_sha256(request.request_bytes) = effect.request_digest
  AND launch.execution_policy_json = session.execution_policy_json
  AND json_extract(CAST(effect.intent_json AS TEXT), '$.contract_version') =
      effect.contract_version
  AND json_extract(CAST(effect.intent_json AS TEXT), '$.effect_id') = effect.effect_id
  AND json_extract(CAST(effect.intent_json AS TEXT), '$.idempotency_key') =
      effect.idempotency_key
  AND json_extract(CAST(effect.intent_json AS TEXT), '$.sprint_id') = effect.sprint_id
  AND json_extract(CAST(effect.intent_json AS TEXT), '$.task_id') IS effect.task_id
  AND json_extract(CAST(effect.intent_json AS TEXT), '$.worker_id') IS effect.worker_id
  AND json_extract(
        CAST(effect.intent_json AS TEXT), '$.worker_lease.lease_id'
      ) IS effect.worker_lease_id
  AND json_extract(
        CAST(effect.intent_json AS TEXT), '$.worker_lease.lease_epoch'
      ) IS effect.worker_lease_epoch
  AND json_extract(CAST(effect.intent_json AS TEXT), '$.causation_event_id') IS
      effect.causation_event_id
  AND json_extract(CAST(effect.intent_json AS TEXT), '$.correlation_id') =
      effect.correlation_id
  AND json_extract(CAST(effect.intent_json AS TEXT), '$.kind') = 'RunCommand'
  AND json_extract(CAST(effect.intent_json AS TEXT), '$.request_digest') =
      effect.request_digest
  AND json_extract(CAST(effect.intent_json AS TEXT), '$.policy_hash') = effect.policy_hash
  AND json_extract(CAST(effect.intent_json AS TEXT), '$.input_snapshot') =
      effect.input_snapshot
  AND json_extract(CAST(effect.intent_json AS TEXT), '$.created_at_unix_ms') =
      effect.created_at_unix_ms
  AND json_extract(CAST(proposal.event_json AS TEXT), '$.contract_version') =
      proposal.contract_version
  AND json_extract(CAST(proposal.event_json AS TEXT), '$.sequence') = proposal.sequence
  AND json_extract(CAST(proposal.event_json AS TEXT), '$.event_id') = proposal.event_id
  AND json_extract(CAST(proposal.event_json AS TEXT), '$.sprint_id') = proposal.sprint_id
  AND json_extract(CAST(proposal.event_json AS TEXT), '$.occurred_at_unix_ms') =
      proposal.occurred_at_unix_ms
  AND (
      effect.causation_event_id IS NULL
      OR EXISTS (
          SELECT 1 FROM agent_events cause
          WHERE cause.event_id = effect.causation_event_id
            AND cause.sprint_id = effect.sprint_id
            AND cause.sequence < proposal.sequence
      )
  )
  AND json_extract(CAST(launch.intent_json AS TEXT), '$.contract_version') =
      launch.contract_version
  AND json_extract(CAST(launch.intent_json AS TEXT), '$.launch_id') = launch.launch_id
  AND json_extract(CAST(launch.intent_json AS TEXT), '$.sprint_id') = launch.sprint_id
  AND json_extract(CAST(launch.intent_json AS TEXT), '$.session_id') = launch.session_id
  AND json_extract(CAST(launch.intent_json AS TEXT), '$.purpose') = launch.purpose
  AND json_extract(CAST(launch.intent_json AS TEXT), '$.worker_id') IS launch.worker_id
  AND json_extract(
        CAST(launch.intent_json AS TEXT), '$.worker_lease.lease_id'
      ) IS launch.worker_lease_id
  AND json_extract(
        CAST(launch.intent_json AS TEXT), '$.worker_lease.lease_epoch'
      ) IS launch.worker_lease_epoch
  AND json_extract(CAST(launch.intent_json AS TEXT), '$.policy_hash') = launch.policy_hash
  AND json_extract(CAST(launch.intent_json AS TEXT), '$.runner_binary_digest') =
      launch.runner_binary_digest
  AND json_extract(CAST(launch.intent_json AS TEXT), '$.protocol_digest') =
      launch.protocol_digest
  AND json_extract(CAST(launch.intent_json AS TEXT), '$.private_state_digest') =
      launch.private_state_digest
  AND json_extract(CAST(launch.intent_json AS TEXT), '$.grant_hash') = launch.grant_hash
  AND json_extract(CAST(launch.intent_json AS TEXT), '$.policy_version') =
      launch.policy_version
  AND json_extract(CAST(launch.intent_json AS TEXT), '$.created_at_unix_ms') =
      launch.created_at_unix_ms
  AND json_extract(CAST(session.record_json AS TEXT), '$.contract_version') =
      session.contract_version
  AND json_extract(CAST(session.record_json AS TEXT), '$.sprint_id') = session.sprint_id
  AND json_extract(CAST(session.record_json AS TEXT), '$.launch_id') = session.launch_id
  AND json_extract(CAST(session.record_json AS TEXT), '$.session_id') = session.session_id
  AND json_extract(CAST(session.record_json AS TEXT), '$.purpose') = session.purpose
  AND json_extract(CAST(session.record_json AS TEXT), '$.worker_id') IS session.worker_id
  AND json_extract(
        CAST(session.record_json AS TEXT), '$.worker_lease.lease_id'
      ) IS session.worker_lease_id
  AND json_extract(
        CAST(session.record_json AS TEXT), '$.worker_lease.lease_epoch'
      ) IS session.worker_lease_epoch
  AND json_extract(CAST(session.record_json AS TEXT), '$.policy_hash') = session.policy_hash
  AND json_extract(CAST(session.record_json AS TEXT), '$.session_nonce') =
      session.session_nonce
  AND json_extract(CAST(session.record_json AS TEXT), '$.runner_binary_digest') =
      session.runner_binary_digest
  AND json_extract(CAST(session.record_json AS TEXT), '$.protocol_digest') =
      session.protocol_digest
  AND json_extract(CAST(session.record_json AS TEXT), '$.private_state_digest') =
      session.private_state_digest
  AND json_extract(CAST(session.record_json AS TEXT), '$.grant_hash') = session.grant_hash
  AND json_extract(CAST(session.record_json AS TEXT), '$.policy_version') =
      session.policy_version
  AND json_extract(CAST(session.record_json AS TEXT), '$.registered_at_unix_ms') =
      session.registered_at_unix_ms
  AND launch.session_id = session.session_id
  AND launch.purpose = session.purpose
  AND launch.worker_id IS session.worker_id
  AND launch.worker_lease_id IS session.worker_lease_id
  AND launch.worker_lease_epoch IS session.worker_lease_epoch
  AND launch.policy_hash = session.policy_hash
  AND launch.runner_binary_digest = session.runner_binary_digest
  AND launch.protocol_digest = session.protocol_digest
  AND launch.private_state_digest = session.private_state_digest
  AND launch.grant_hash = session.grant_hash
  AND launch.policy_version = session.policy_version
  AND launch.contract_version = session.contract_version
  AND effect.policy_hash = launch.policy_hash
  AND capture.private_state_digest = launch.private_state_digest
  AND session.registered_at_unix_ms >= launch.created_at_unix_ms
  AND session.registered_at_unix_ms <= effect.created_at_unix_ms
  AND snapshot.created_at_unix_ms <= effect.created_at_unix_ms
  AND json_extract(
        CAST(sprint.spec_json AS TEXT), '$.workspace_grant.grant_hash'
      ) = launch.grant_hash
  AND json_extract(
        CAST(sprint.spec_json AS TEXT), '$.workspace_grant.policy_version'
      ) = launch.policy_version
  AND json_extract(
        CAST(sprint.spec_json AS TEXT), '$.workspace_grant.canonical_root'
      ) = json_extract(
        CAST(launch.execution_policy_json AS TEXT), '$.workspace_root'
      )
  AND json_extract(CAST(launch.execution_policy_json AS TEXT), '$.policy_hash') =
      launch.policy_hash
  AND json_extract(CAST(launch.execution_policy_json AS TEXT), '$.grant_hash') =
      launch.grant_hash
  AND NOT EXISTS (
      SELECT 1 FROM live_state_verifier_launch_purposes marker
      WHERE marker.launch_id = launch.launch_id
  )
  AND NOT EXISTS (
      SELECT 1 FROM live_state_verifier_session_purposes marker
      WHERE marker.session_id = session.session_id
  )
  AND (
      (session.purpose = 'TaskWorker'
       AND effect.task_id IS NOT NULL
       AND effect.worker_id = session.worker_id
       AND effect.worker_lease_id = launch.worker_lease_id
       AND effect.worker_lease_id = session.worker_lease_id
       AND effect.worker_lease_epoch = launch.worker_lease_epoch
       AND effect.worker_lease_epoch = session.worker_lease_epoch
       AND EXISTS (
           SELECT 1
           FROM task_attempt_running_boundaries running
           JOIN task_attempts attempt ON attempt.attempt_id = running.attempt_id
           WHERE running.sprint_id = effect.sprint_id
             AND running.task_id = effect.task_id
             AND running.worker_id = effect.worker_id
             AND running.runner_launch_id = launch.launch_id
             AND running.runner_session_id = session.session_id
             AND running.worker_lease_id = effect.worker_lease_id
             AND running.lease_epoch = effect.worker_lease_epoch
             AND running.contract_version = effect.contract_version
             AND attempt.sprint_id = effect.sprint_id
             AND attempt.task_id = effect.task_id
             AND attempt.worker_id = effect.worker_id
             AND attempt.worker_lease_id = effect.worker_lease_id
             AND attempt.lease_epoch = effect.worker_lease_epoch
             AND attempt.schema_generation = 15
             AND attempt.contract_version = effect.contract_version
             AND grok_task_running_authority_v27_canonical(
                   attempt.attempt_json, running.boundary_json
                 ) = 1
       ))
      OR
      (session.purpose = 'FinalVerifier'
       AND effect.task_id IS NULL
       AND effect.worker_id IS NULL
       AND effect.worker_lease_id IS NULL
       AND effect.worker_lease_epoch IS NULL
       AND launch.worker_id IS NULL
       AND launch.worker_lease_id IS NULL
       AND launch.worker_lease_epoch IS NULL
       AND session.worker_id IS NULL
       AND session.worker_lease_id IS NULL
       AND session.worker_lease_epoch IS NULL
       AND EXISTS (
           SELECT 1
           FROM sprint_final_verification_admissions admission
           JOIN agent_events phase
             ON phase.event_id = admission.sprint_phase_event_id
            AND phase.sprint_id = admission.sprint_id
           WHERE admission.effect_id = effect.effect_id
             AND admission.sprint_id = effect.sprint_id
             AND admission.runner_launch_id = launch.launch_id
             AND admission.runner_session_id = session.session_id
             AND admission.final_snapshot = effect.input_snapshot
             AND admission.contract_version = effect.contract_version
             AND admission.admitted_at_unix_ms = effect.created_at_unix_ms
             AND admission.command_digest = effect.request_digest
             AND admission.command_digest = grok_sha256(admission.command_bytes)
             AND grok_final_verification_admission_v27_canonical(
                   admission.admission_json, admission.command_bytes
                 ) = 1
             AND json_extract(
                   CAST(admission.admission_json AS TEXT), '$.contract_version'
                 ) = admission.contract_version
             AND json_extract(
                   CAST(admission.admission_json AS TEXT), '$.admission_id'
                 ) = admission.admission_id
             AND json_extract(
                   CAST(admission.admission_json AS TEXT), '$.sprint_id'
                 ) = admission.sprint_id
             AND json_extract(
                   CAST(admission.admission_json AS TEXT),
                   '$.sprint_phase_event_id'
                 ) = admission.sprint_phase_event_id
             AND json_extract(
                   CAST(admission.admission_json AS TEXT), '$.final_snapshot'
                 ) = admission.final_snapshot
             AND json_extract(
                   CAST(admission.admission_json AS TEXT), '$.effect_id'
                 ) = admission.effect_id
             AND json_extract(
                   CAST(admission.admission_json AS TEXT), '$.runner_launch_id'
                 ) = admission.runner_launch_id
             AND json_extract(
                   CAST(admission.admission_json AS TEXT), '$.runner_session_id'
                 ) = admission.runner_session_id
             AND json_extract(
                   CAST(admission.admission_json AS TEXT), '$.admitted_at_unix_ms'
                 ) = admission.admitted_at_unix_ms
             AND grok_agent_event_v27_canonical(phase.event_json) = 1
             AND json_extract(CAST(phase.event_json AS TEXT), '$.event_id') =
                 phase.event_id
             AND json_extract(CAST(phase.event_json AS TEXT), '$.sequence') =
                 phase.sequence
             AND json_extract(CAST(phase.event_json AS TEXT), '$.sprint_id') =
                 phase.sprint_id
             AND json_extract(CAST(phase.event_json AS TEXT), '$.task_id') IS NULL
             AND json_extract(CAST(phase.event_json AS TEXT), '$.worker_id') IS NULL
             AND json_extract(CAST(phase.event_json AS TEXT), '$.policy_hash') =
                 effect.policy_hash
             AND json_extract(
                   CAST(phase.event_json AS TEXT),
                   '$.payload.SprintStateChanged.from'
                 ) IN ('Running', 'AwaitingAcceptance')
             AND json_extract(
                   CAST(phase.event_json AS TEXT),
                   '$.payload.SprintStateChanged.to'
                 ) = 'FinalVerification'
             AND phase.contract_version = admission.contract_version
             AND phase.occurred_at_unix_ms <= admission.admitted_at_unix_ms
             AND phase.sequence < proposal.sequence
       ))
  );

CREATE VIEW command_output_capture_exact_dispatch_authorities_v27 AS
SELECT source.capture_id, claim.dispatch_claim_id
FROM command_output_capture_exact_runner_sources_v27 source
JOIN runner_effect_dispatch_claims claim
  ON claim.effect_id = source.effect_id
 AND claim.sprint_id = source.sprint_id
 AND claim.launch_id = source.launch_id
 AND claim.session_id = source.session_id
 AND claim.request_digest = source.request_digest
 AND claim.policy_hash = source.policy_hash
 AND claim.input_snapshot = source.input_snapshot
 AND claim.contract_version = source.contract_version
JOIN runner_effect_dispatch_claim_authorities authority
  ON authority.dispatch_claim_id = claim.dispatch_claim_id
 AND authority.contract_version = claim.contract_version
WHERE NOT EXISTS (
    SELECT 1 FROM live_state_capture_dispatch_claim_authorities live
    WHERE live.dispatch_claim_id = claim.dispatch_claim_id
)
AND (
    (authority.authority_class = 'TaskRunning'
     AND source.purpose = 'TaskWorker'
     AND claim.running_boundary_id = authority.running_boundary_id
     AND authority.running_boundary_id IS NOT NULL
     AND authority.formal_check_admission_id IS NULL
     AND authority.integration_admission_id IS NULL
     AND authority.sprint_phase_event_id IS NULL
     AND authority.rollback_reference_id IS NULL
     AND EXISTS (
         SELECT 1
         FROM task_attempt_running_boundaries running
         JOIN task_attempts attempt ON attempt.attempt_id = running.attempt_id
         WHERE running.boundary_id = claim.running_boundary_id
           AND running.sprint_id = source.sprint_id
           AND running.runner_launch_id = source.launch_id
           AND running.runner_session_id = source.session_id
           AND running.task_id = source.task_id
           AND running.worker_id = source.worker_id
           AND running.worker_lease_id = source.worker_lease_id
           AND running.lease_epoch = source.worker_lease_epoch
           AND running.contract_version = source.contract_version
           AND attempt.sprint_id = source.sprint_id
           AND attempt.task_id = source.task_id
           AND attempt.worker_id = source.worker_id
           AND attempt.worker_lease_id = source.worker_lease_id
           AND attempt.lease_epoch = source.worker_lease_epoch
           AND attempt.schema_generation = 15
           AND attempt.contract_version = source.contract_version
           AND grok_task_running_authority_v27_canonical(
                 attempt.attempt_json, running.boundary_json
               ) = 1
     ))
    OR
    (authority.authority_class = 'TaskFormalCheck'
     AND source.purpose = 'TaskWorker'
     AND claim.running_boundary_id IS NULL
     AND authority.running_boundary_id IS NULL
     AND authority.formal_check_admission_id IS NOT NULL
     AND authority.integration_admission_id IS NULL
     AND authority.sprint_phase_event_id IS NULL
     AND authority.rollback_reference_id IS NULL
     AND EXISTS (
         SELECT 1
         FROM task_attempt_formal_check_admissions admission
         JOIN task_attempts attempt ON attempt.attempt_id = admission.attempt_id
         WHERE admission.admission_id = authority.formal_check_admission_id
           AND admission.effect_id = source.effect_id
           AND admission.sprint_id = source.sprint_id
           AND admission.task_id = source.task_id
           AND admission.worker_session_id = source.session_id
           AND admission.sealed_snapshot_id = source.input_snapshot
           AND admission.contract_version = source.contract_version
           AND admission.admitted_at_unix_ms = source.created_at_unix_ms
           AND attempt.sprint_id = source.sprint_id
           AND attempt.task_id = source.task_id
           AND attempt.worker_id = source.worker_id
           AND attempt.worker_lease_id = source.worker_lease_id
           AND attempt.lease_epoch = source.worker_lease_epoch
           AND attempt.schema_generation = 15
           AND attempt.contract_version = source.contract_version
           AND grok_formal_check_admission_v27_canonical(
                 admission.admission_json, admission.command_spec_json
               ) = 1
           AND json_extract(
                 CAST(admission.admission_json AS TEXT), '$.contract_version'
               ) = admission.contract_version
           AND json_extract(
                 CAST(admission.admission_json AS TEXT), '$.admission_id'
               ) = admission.admission_id
           AND json_extract(
                 CAST(admission.admission_json AS TEXT), '$.attempt.attempt_id'
               ) = admission.attempt_id
           AND json_extract(
                 CAST(admission.admission_json AS TEXT),
                 '$.attempt.worker_lease.sprint_id'
               ) = admission.sprint_id
           AND json_extract(
                 CAST(admission.admission_json AS TEXT),
                 '$.attempt.worker_lease.task_id'
               ) = admission.task_id
           AND json_extract(
                 CAST(admission.admission_json AS TEXT), '$.criterion_id'
               ) = admission.criterion_id
           AND json_extract(
                 CAST(admission.admission_json AS TEXT), '$.criterion_ordinal'
               ) = admission.criterion_ordinal
           AND json_extract(
                 CAST(admission.admission_json AS TEXT), '$.effect_id'
               ) = admission.effect_id
           AND json_extract(
                 CAST(admission.admission_json AS TEXT), '$.runner_session_id'
               ) = admission.worker_session_id
           AND json_extract(
                 CAST(admission.admission_json AS TEXT), '$.sealed_snapshot'
               ) = admission.sealed_snapshot_id
           AND json_extract(
                 CAST(admission.admission_json AS TEXT), '$.admitted_at_unix_ms'
               ) = admission.admitted_at_unix_ms
           AND grok_sha256(admission.command_spec_json) = source.request_digest
     ))
    OR
    (authority.authority_class = 'SprintFinalVerification'
     AND source.purpose = 'FinalVerifier'
     AND claim.running_boundary_id IS NULL
     AND authority.running_boundary_id IS NULL
     AND authority.formal_check_admission_id IS NULL
     AND authority.integration_admission_id IS NULL
     AND authority.sprint_phase_event_id IS NOT NULL
     AND authority.rollback_reference_id IS NULL
     AND EXISTS (
         SELECT 1
         FROM sprint_final_verification_admissions admission
         JOIN agent_events phase
           ON phase.event_id = admission.sprint_phase_event_id
          AND phase.sprint_id = admission.sprint_id
         JOIN workspace_snapshots snapshot
           ON snapshot.sprint_id = admission.sprint_id
          AND snapshot.snapshot_id = admission.final_snapshot
         WHERE admission.sprint_phase_event_id = authority.sprint_phase_event_id
           AND admission.effect_id = source.effect_id
           AND admission.sprint_id = source.sprint_id
           AND admission.runner_launch_id = source.launch_id
           AND admission.runner_session_id = source.session_id
           AND admission.final_snapshot = source.input_snapshot
           AND admission.contract_version = source.contract_version
           AND admission.admitted_at_unix_ms = source.created_at_unix_ms
           AND admission.command_digest = source.request_digest
           AND admission.command_digest = grok_sha256(admission.command_bytes)
           AND grok_final_verification_admission_v27_canonical(
                 admission.admission_json, admission.command_bytes
               ) = 1
           AND json_extract(
                 CAST(admission.admission_json AS TEXT), '$.contract_version'
               ) = admission.contract_version
           AND json_extract(
                 CAST(admission.admission_json AS TEXT), '$.admission_id'
               ) = admission.admission_id
           AND json_extract(
                 CAST(admission.admission_json AS TEXT), '$.sprint_id'
               ) = admission.sprint_id
           AND json_extract(
                 CAST(admission.admission_json AS TEXT),
                 '$.sprint_phase_event_id'
               ) = admission.sprint_phase_event_id
           AND json_extract(
                 CAST(admission.admission_json AS TEXT), '$.final_snapshot'
               ) = admission.final_snapshot
           AND json_extract(
                 CAST(admission.admission_json AS TEXT), '$.effect_id'
               ) = admission.effect_id
           AND json_extract(
                 CAST(admission.admission_json AS TEXT), '$.runner_launch_id'
               ) = admission.runner_launch_id
           AND json_extract(
                 CAST(admission.admission_json AS TEXT), '$.runner_session_id'
               ) = admission.runner_session_id
           AND json_extract(
                 CAST(admission.admission_json AS TEXT), '$.admitted_at_unix_ms'
               ) = admission.admitted_at_unix_ms
           AND grok_agent_event_v27_canonical(phase.event_json) = 1
           AND json_extract(CAST(phase.event_json AS TEXT), '$.event_id') =
               phase.event_id
           AND json_extract(CAST(phase.event_json AS TEXT), '$.sequence') =
               phase.sequence
           AND json_extract(CAST(phase.event_json AS TEXT), '$.sprint_id') =
               phase.sprint_id
           AND json_extract(CAST(phase.event_json AS TEXT), '$.task_id') IS NULL
           AND json_extract(CAST(phase.event_json AS TEXT), '$.worker_id') IS NULL
           AND json_extract(CAST(phase.event_json AS TEXT), '$.policy_hash') =
               source.policy_hash
           AND json_extract(
                 CAST(phase.event_json AS TEXT),
                 '$.payload.SprintStateChanged.from'
               ) IN ('Running', 'AwaitingAcceptance')
           AND json_extract(
                 CAST(phase.event_json AS TEXT),
                 '$.payload.SprintStateChanged.to'
               ) = 'FinalVerification'
           AND phase.contract_version = admission.contract_version
           AND phase.occurred_at_unix_ms <= admission.admitted_at_unix_ms
           AND snapshot.created_at_unix_ms <= admission.admitted_at_unix_ms
     ))
);
