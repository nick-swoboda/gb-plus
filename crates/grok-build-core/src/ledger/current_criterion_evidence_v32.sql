-- Current-only criterion source substrate for schema v32. These tables bind
-- exclusively to the parallel V2 sprint lattice. They deliberately have no
-- foreign keys or joins to legacy `sprints`, schema-v28 prompts/decisions, or
-- schema-v28 criterion evidence.

CREATE TABLE current_sprint_criteria_v32 (
    sprint_id TEXT NOT NULL,
    criterion_id TEXT NOT NULL CHECK (length(criterion_id) BETWEEN 1 AND 4096),
    criterion_ordinal INTEGER NOT NULL CHECK (criterion_ordinal >= 0),
    criterion_kind TEXT NOT NULL CHECK (criterion_kind IN ('Automated', 'HumanJudgment')),
    criterion_text_digest TEXT NOT NULL CHECK (length(criterion_text_digest) = 64),
    command_digest TEXT NOT NULL CHECK (length(command_digest) IN (0, 64)),
    sprint_spec_digest TEXT NOT NULL CHECK (length(sprint_spec_digest) = 64),
    criterion_json BLOB NOT NULL CHECK (length(criterion_json) BETWEEN 1 AND 8388608),
    PRIMARY KEY (sprint_id, criterion_id),
    UNIQUE (sprint_id, criterion_ordinal),
    FOREIGN KEY (sprint_id)
        REFERENCES current_sprint_authorities_v32(sprint_id) ON DELETE RESTRICT,
    FOREIGN KEY (sprint_spec_digest)
        REFERENCES current_sprint_authorities_v32(sprint_spec_digest) ON DELETE RESTRICT,
    CHECK (
        (criterion_kind = 'Automated' AND length(command_digest) = 64)
        OR
        (criterion_kind = 'HumanJudgment' AND command_digest = '')
    )
) STRICT, WITHOUT ROWID;

-- A future trusted runner/effect join writes this exact source receipt only
-- after successful same-snapshot automated verification, clean output
-- publication, and both cleanup proofs exist. Schema v32 exposes no public
-- writer while those current-only source tables are absent.
CREATE TABLE current_automated_verification_sources_v32 (
    verification_receipt_id TEXT PRIMARY KEY NOT NULL
        CHECK (length(verification_receipt_id) BETWEEN 1 AND 4096),
    sprint_id TEXT NOT NULL,
    criterion_id TEXT NOT NULL,
    snapshot_digest TEXT NOT NULL CHECK (length(snapshot_digest) = 64),
    command_digest TEXT NOT NULL CHECK (length(command_digest) = 64),
    runner_effect_id TEXT NOT NULL CHECK (length(runner_effect_id) BETWEEN 1 AND 4096),
    runner_session_id TEXT NOT NULL CHECK (length(runner_session_id) BETWEEN 1 AND 4096),
    output_artifact_set_id TEXT NOT NULL
        CHECK (length(output_artifact_set_id) BETWEEN 1 AND 4096),
    runner_cleanup_proof_id TEXT NOT NULL
        CHECK (length(runner_cleanup_proof_id) BETWEEN 1 AND 4096),
    command_domain_cleanup_proof_id TEXT NOT NULL
        CHECK (length(command_domain_cleanup_proof_id) BETWEEN 1 AND 4096),
    verified_at_unix_ms INTEGER NOT NULL CHECK (verified_at_unix_ms > 0),
    source_json BLOB NOT NULL CHECK (length(source_json) BETWEEN 1 AND 8388608),
    UNIQUE (verification_receipt_id, sprint_id, criterion_id, snapshot_digest),
    FOREIGN KEY (sprint_id, criterion_id)
        REFERENCES current_sprint_criteria_v32(sprint_id, criterion_id) ON DELETE RESTRICT
) STRICT, WITHOUT ROWID;

CREATE TABLE current_human_acceptance_prompts_v32 (
    prompt_id TEXT PRIMARY KEY NOT NULL CHECK (length(prompt_id) BETWEEN 1 AND 4096),
    ui_session_id TEXT NOT NULL CHECK (length(ui_session_id) BETWEEN 1 AND 4096),
    sprint_id TEXT NOT NULL,
    criterion_id TEXT NOT NULL,
    criterion_text_digest TEXT NOT NULL CHECK (length(criterion_text_digest) = 64),
    snapshot_digest TEXT NOT NULL CHECK (length(snapshot_digest) = 64),
    workspace_grant_hash TEXT NOT NULL CHECK (length(workspace_grant_hash) = 64),
    rendered_claim_digest TEXT NOT NULL CHECK (length(rendered_claim_digest) = 64),
    backing TEXT NOT NULL CHECK (backing = 'OneToOne'),
    issued_event_sequence INTEGER NOT NULL CHECK (issued_event_sequence > 0),
    prompt_json BLOB NOT NULL CHECK (length(prompt_json) BETWEEN 1 AND 8388608),
    UNIQUE (prompt_id, sprint_id, criterion_id, snapshot_digest),
    UNIQUE (sprint_id, criterion_id, issued_event_sequence),
    FOREIGN KEY (sprint_id, criterion_id)
        REFERENCES current_sprint_criteria_v32(sprint_id, criterion_id) ON DELETE RESTRICT
) STRICT, WITHOUT ROWID;

CREATE TABLE current_human_acceptance_decisions_v32 (
    decision_id TEXT PRIMARY KEY NOT NULL CHECK (length(decision_id) BETWEEN 1 AND 4096),
    prompt_id TEXT NOT NULL UNIQUE,
    sprint_id TEXT NOT NULL,
    criterion_id TEXT NOT NULL,
    snapshot_digest TEXT NOT NULL CHECK (length(snapshot_digest) = 64),
    outcome TEXT NOT NULL CHECK (outcome IN ('AcceptedByYou', 'RejectedByYou')),
    consumed_event_sequence INTEGER NOT NULL CHECK (consumed_event_sequence > 0),
    decided_at_unix_ms INTEGER NOT NULL CHECK (decided_at_unix_ms > 0),
    decision_json BLOB NOT NULL CHECK (length(decision_json) BETWEEN 1 AND 8388608),
    UNIQUE (decision_id, prompt_id, sprint_id, criterion_id, snapshot_digest),
    FOREIGN KEY (prompt_id, sprint_id, criterion_id, snapshot_digest)
        REFERENCES current_human_acceptance_prompts_v32(
            prompt_id, sprint_id, criterion_id, snapshot_digest
        ) ON DELETE RESTRICT
) STRICT, WITHOUT ROWID;

CREATE TABLE current_criterion_evidence_receipts_v32 (
    receipt_id TEXT PRIMARY KEY NOT NULL CHECK (length(receipt_id) BETWEEN 1 AND 4096),
    sprint_id TEXT NOT NULL,
    criterion_id TEXT NOT NULL,
    snapshot_digest TEXT NOT NULL CHECK (length(snapshot_digest) = 64),
    evidence_kind TEXT NOT NULL CHECK (evidence_kind IN ('Verified', 'AcceptedByYou')),
    verification_receipt_id TEXT,
    human_decision_id TEXT,
    prompt_id TEXT,
    backing TEXT,
    recorded_at_unix_ms INTEGER NOT NULL CHECK (recorded_at_unix_ms > 0),
    receipt_json BLOB NOT NULL CHECK (length(receipt_json) BETWEEN 1 AND 8388608),
    UNIQUE (sprint_id, criterion_id, snapshot_digest),
    FOREIGN KEY (sprint_id, criterion_id)
        REFERENCES current_sprint_criteria_v32(sprint_id, criterion_id) ON DELETE RESTRICT,
    FOREIGN KEY (verification_receipt_id, sprint_id, criterion_id, snapshot_digest)
        REFERENCES current_automated_verification_sources_v32(
            verification_receipt_id, sprint_id, criterion_id, snapshot_digest
        ) ON DELETE RESTRICT,
    FOREIGN KEY (human_decision_id, prompt_id, sprint_id, criterion_id, snapshot_digest)
        REFERENCES current_human_acceptance_decisions_v32(
            decision_id, prompt_id, sprint_id, criterion_id, snapshot_digest
        ) ON DELETE RESTRICT,
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
    )
) STRICT, WITHOUT ROWID;

CREATE TRIGGER current_sprint_criteria_v32_validate_insert
BEFORE INSERT ON current_sprint_criteria_v32
WHEN grok_current_criterion_write_admitted_v32(
         'criterion', NEW.sprint_id, NEW.criterion_id,
         CAST(NEW.criterion_ordinal AS TEXT)
     ) != 1
  OR NOT EXISTS (
      SELECT 1
      FROM current_sprint_authorities_v32 sprint
      WHERE sprint.sprint_id = NEW.sprint_id
        AND sprint.sprint_spec_digest = NEW.sprint_spec_digest
        AND grok_current_criterion_projection_matches_v32(
            sprint.spec_json, NEW.criterion_ordinal, NEW.criterion_id,
            NEW.criterion_kind, NEW.criterion_text_digest,
            NEW.command_digest, NEW.criterion_json
        ) = 1
  )
BEGIN SELECT RAISE(ABORT, 'current criterion projection requires exact admitted SprintSpecV2 membership'); END;

CREATE TRIGGER current_automated_verification_sources_v32_validate_insert
BEFORE INSERT ON current_automated_verification_sources_v32
WHEN grok_current_criterion_write_admitted_v32(
         'automated-source', NEW.sprint_id, NEW.verification_receipt_id,
         NEW.criterion_id
     ) != 1
  OR grok_current_automated_source_canonical_v32(
         NEW.source_json, NEW.verification_receipt_id, NEW.sprint_id,
         NEW.criterion_id, NEW.snapshot_digest, NEW.command_digest,
         NEW.runner_effect_id, NEW.runner_session_id,
         NEW.output_artifact_set_id, NEW.runner_cleanup_proof_id,
         NEW.command_domain_cleanup_proof_id, NEW.verified_at_unix_ms
     ) != 1
  OR NOT EXISTS (
      SELECT 1 FROM current_sprint_criteria_v32 criterion
      WHERE criterion.sprint_id = NEW.sprint_id
        AND criterion.criterion_id = NEW.criterion_id
        AND criterion.criterion_kind = 'Automated'
        AND criterion.command_digest = NEW.command_digest
  )
BEGIN SELECT RAISE(ABORT, 'current automated verification source requires an exact trusted source join'); END;

CREATE TRIGGER current_human_acceptance_prompts_v32_validate_insert
BEFORE INSERT ON current_human_acceptance_prompts_v32
WHEN grok_current_criterion_write_admitted_v32(
         'human-prompt', NEW.sprint_id, NEW.prompt_id, NEW.criterion_id
     ) != 1
  OR grok_current_human_prompt_canonical_v32(
         NEW.prompt_json, NEW.prompt_id, NEW.ui_session_id, NEW.sprint_id,
         NEW.criterion_id, NEW.criterion_text_digest, NEW.snapshot_digest,
         NEW.workspace_grant_hash, NEW.rendered_claim_digest, NEW.backing,
         NEW.issued_event_sequence
     ) != 1
  OR NOT EXISTS (
      SELECT 1
      FROM current_sprint_criteria_v32 criterion
      JOIN current_sprint_authorities_v32 sprint
        ON sprint.sprint_id = criterion.sprint_id
      WHERE criterion.sprint_id = NEW.sprint_id
        AND criterion.criterion_id = NEW.criterion_id
        AND criterion.criterion_kind = 'HumanJudgment'
        AND criterion.criterion_text_digest = NEW.criterion_text_digest
        AND sprint.workspace_grant_hash = NEW.workspace_grant_hash
  )
BEGIN SELECT RAISE(ABORT, 'current human prompt requires exact criterion, grant, event, and UI-session backing'); END;

CREATE TRIGGER current_human_acceptance_decisions_v32_validate_insert
BEFORE INSERT ON current_human_acceptance_decisions_v32
WHEN grok_current_criterion_write_admitted_v32(
         'human-decision', NEW.sprint_id, NEW.decision_id, NEW.prompt_id
     ) != 1
  OR grok_current_human_decision_canonical_v32(
         NEW.decision_json, NEW.decision_id, NEW.prompt_id, NEW.outcome,
         NEW.consumed_event_sequence, NEW.decided_at_unix_ms
     ) != 1
  OR NOT EXISTS (
      SELECT 1 FROM current_human_acceptance_prompts_v32 prompt
      WHERE prompt.prompt_id = NEW.prompt_id
        AND prompt.sprint_id = NEW.sprint_id
        AND prompt.criterion_id = NEW.criterion_id
        AND prompt.snapshot_digest = NEW.snapshot_digest
        AND prompt.issued_event_sequence = NEW.consumed_event_sequence
        AND grok_current_human_decision_matches_prompt_v32(
            prompt.prompt_json, NEW.decision_json, NEW.sprint_id,
            NEW.criterion_id, NEW.snapshot_digest
        ) = 1
  )
BEGIN SELECT RAISE(ABORT, 'current human decision requires one exact unconsumed prompt cut'); END;

CREATE TRIGGER current_criterion_evidence_receipts_v32_validate_insert
BEFORE INSERT ON current_criterion_evidence_receipts_v32
WHEN grok_current_criterion_write_admitted_v32(
         'criterion-receipt', NEW.sprint_id, NEW.receipt_id, NEW.criterion_id
     ) != 1
  OR grok_current_criterion_receipt_canonical_v32(
         NEW.receipt_json, NEW.receipt_id, NEW.sprint_id, NEW.criterion_id,
         NEW.snapshot_digest, NEW.evidence_kind, NEW.verification_receipt_id,
         NEW.human_decision_id, NEW.prompt_id, NEW.backing,
         NEW.recorded_at_unix_ms
     ) != 1
  OR (
      NEW.evidence_kind = 'Verified'
      AND NOT EXISTS (
          SELECT 1 FROM current_automated_verification_sources_v32 source
          WHERE source.verification_receipt_id = NEW.verification_receipt_id
            AND source.sprint_id = NEW.sprint_id
            AND source.criterion_id = NEW.criterion_id
            AND source.snapshot_digest = NEW.snapshot_digest
            AND source.verified_at_unix_ms <= NEW.recorded_at_unix_ms
      )
  )
  OR (
      NEW.evidence_kind = 'AcceptedByYou'
      AND NOT EXISTS (
          SELECT 1
          FROM current_human_acceptance_decisions_v32 decision
          JOIN current_human_acceptance_prompts_v32 prompt
            ON prompt.prompt_id = decision.prompt_id
          WHERE decision.decision_id = NEW.human_decision_id
            AND decision.prompt_id = NEW.prompt_id
            AND decision.sprint_id = NEW.sprint_id
            AND decision.criterion_id = NEW.criterion_id
            AND decision.snapshot_digest = NEW.snapshot_digest
            AND decision.outcome = 'AcceptedByYou'
            AND decision.decided_at_unix_ms <= NEW.recorded_at_unix_ms
            AND prompt.backing = 'OneToOne'
      )
  )
BEGIN SELECT RAISE(ABORT, 'current criterion evidence requires exact disjoint source backing'); END;

CREATE TRIGGER current_sprint_criteria_v32_no_update
BEFORE UPDATE ON current_sprint_criteria_v32
BEGIN SELECT RAISE(ABORT, 'current criterion projection is immutable'); END;
CREATE TRIGGER current_sprint_criteria_v32_no_delete
BEFORE DELETE ON current_sprint_criteria_v32
BEGIN SELECT RAISE(ABORT, 'current criterion projection is immutable'); END;
CREATE TRIGGER current_automated_verification_sources_v32_no_update
BEFORE UPDATE ON current_automated_verification_sources_v32
BEGIN SELECT RAISE(ABORT, 'current automated verification source is immutable'); END;
CREATE TRIGGER current_automated_verification_sources_v32_no_delete
BEFORE DELETE ON current_automated_verification_sources_v32
BEGIN SELECT RAISE(ABORT, 'current automated verification source is immutable'); END;
CREATE TRIGGER current_human_acceptance_prompts_v32_no_update
BEFORE UPDATE ON current_human_acceptance_prompts_v32
BEGIN SELECT RAISE(ABORT, 'current human acceptance prompt is immutable'); END;
CREATE TRIGGER current_human_acceptance_prompts_v32_no_delete
BEFORE DELETE ON current_human_acceptance_prompts_v32
BEGIN SELECT RAISE(ABORT, 'current human acceptance prompt is immutable'); END;
CREATE TRIGGER current_human_acceptance_decisions_v32_no_update
BEFORE UPDATE ON current_human_acceptance_decisions_v32
BEGIN SELECT RAISE(ABORT, 'current human acceptance decision is immutable'); END;
CREATE TRIGGER current_human_acceptance_decisions_v32_no_delete
BEFORE DELETE ON current_human_acceptance_decisions_v32
BEGIN SELECT RAISE(ABORT, 'current human acceptance decision is immutable'); END;
CREATE TRIGGER current_criterion_evidence_receipts_v32_no_update
BEFORE UPDATE ON current_criterion_evidence_receipts_v32
BEGIN SELECT RAISE(ABORT, 'current criterion evidence receipt is immutable'); END;
CREATE TRIGGER current_criterion_evidence_receipts_v32_no_delete
BEFORE DELETE ON current_criterion_evidence_receipts_v32
BEGIN SELECT RAISE(ABORT, 'current criterion evidence receipt is immutable'); END;

CREATE VIEW current_criterion_evidence_source_capture_v32 AS
SELECT receipt.receipt_id, receipt.sprint_id, receipt.criterion_id,
       receipt.snapshot_digest, receipt.evidence_kind,
       receipt.verification_receipt_id, receipt.human_decision_id,
       receipt.prompt_id, receipt.backing, receipt.recorded_at_unix_ms,
       receipt.receipt_json
FROM current_criterion_evidence_receipts_v32 receipt
JOIN current_sprint_criteria_v32 criterion
  ON criterion.sprint_id = receipt.sprint_id
 AND criterion.criterion_id = receipt.criterion_id
 AND (
     (criterion.criterion_kind = 'Automated' AND receipt.evidence_kind = 'Verified')
     OR
     (criterion.criterion_kind = 'HumanJudgment' AND receipt.evidence_kind = 'AcceptedByYou')
 );
