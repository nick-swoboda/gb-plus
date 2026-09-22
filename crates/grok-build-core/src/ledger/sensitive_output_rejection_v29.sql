-- Schema v29 adds a mutually exclusive, length-free terminal family for
-- private output rejected by a pre-effect detector policy. Existing v27
-- terminal and wire contracts remain byte-for-byte unchanged.

CREATE TABLE pre_v29_sensitive_output_policy_exemptions (
    effect_id TEXT PRIMARY KEY NOT NULL,
    capture_id TEXT NOT NULL UNIQUE,
    intent_digest TEXT NOT NULL UNIQUE,
    contract_version INTEGER NOT NULL CHECK (contract_version > 0),
    FOREIGN KEY (capture_id, effect_id, intent_digest)
        REFERENCES command_output_capture_intents(capture_id, effect_id, intent_digest)
        ON DELETE RESTRICT
) STRICT, WITHOUT ROWID;

INSERT INTO pre_v29_sensitive_output_policy_exemptions (
    effect_id, capture_id, intent_digest, contract_version
)
SELECT effect_id, capture_id, intent_digest, contract_version
FROM command_output_capture_intents;

CREATE TRIGGER pre_v29_sensitive_output_policy_exemptions_no_insert
BEFORE INSERT ON pre_v29_sensitive_output_policy_exemptions
BEGIN SELECT RAISE(ABORT, 'pre-v29 sensitive-output exemptions are migration-only'); END;
CREATE TRIGGER pre_v29_sensitive_output_policy_exemptions_no_update
BEFORE UPDATE ON pre_v29_sensitive_output_policy_exemptions
BEGIN SELECT RAISE(ABORT, 'pre-v29 sensitive-output exemptions are immutable'); END;
CREATE TRIGGER pre_v29_sensitive_output_policy_exemptions_no_delete
BEFORE DELETE ON pre_v29_sensitive_output_policy_exemptions
BEGIN SELECT RAISE(ABORT, 'pre-v29 sensitive-output exemptions are immutable'); END;

-- Migration exemptions preserve historical evidence and cleanup authority;
-- they never authorize a post-migration first launch or redispatch.
CREATE TRIGGER pre_v29_sensitive_output_exemption_rejects_new_dispatch
BEFORE INSERT ON runner_effect_dispatch_claims
WHEN EXISTS (
    SELECT 1 FROM pre_v29_sensitive_output_policy_exemptions exemption
    WHERE exemption.effect_id = NEW.effect_id
)
BEGIN SELECT RAISE(ABORT, 'pre-v29 exempt command cannot acquire new dispatch authority'); END;

CREATE TRIGGER pre_v29_sensitive_output_exemption_rejects_new_acquisition
BEFORE INSERT ON command_output_capture_acquisitions
WHEN EXISTS (
    SELECT 1 FROM pre_v29_sensitive_output_policy_exemptions exemption
    WHERE exemption.effect_id = NEW.effect_id OR exemption.capture_id = NEW.capture_id
)
BEGIN SELECT RAISE(ABORT, 'pre-v29 exempt command cannot acquire new output custody'); END;

CREATE TABLE command_output_sensitive_detection_policy_admissions_v29 (
    capture_id TEXT PRIMARY KEY NOT NULL,
    effect_id TEXT NOT NULL UNIQUE,
    policy_id TEXT NOT NULL CHECK (length(policy_id) BETWEEN 1 AND 4096),
    policy_version INTEGER NOT NULL CHECK (policy_version > 0),
    policy_digest TEXT NOT NULL CHECK (
        length(policy_digest) = 64 AND policy_digest NOT GLOB '*[^0-9a-f]*'
    ),
    admitted_at_unix_ms INTEGER NOT NULL CHECK (admitted_at_unix_ms > 0),
    contract_version INTEGER NOT NULL CHECK (contract_version > 0),
    policy_json BLOB NOT NULL CHECK (
        length(policy_json) > 0
        AND grok_sensitive_output_policy_v29_canonical(policy_json) = 'ok'
    ),
    FOREIGN KEY (capture_id, effect_id)
        REFERENCES command_output_capture_intents(capture_id, effect_id)
        ON DELETE RESTRICT
) STRICT, WITHOUT ROWID;

CREATE TRIGGER command_output_sensitive_policy_no_backfill
BEFORE INSERT ON command_output_sensitive_detection_policy_admissions_v29
WHEN EXISTS (SELECT 1 FROM effect_intents WHERE effect_id = NEW.effect_id)
  OR EXISTS (
      SELECT 1 FROM pre_v29_sensitive_output_policy_exemptions
      WHERE effect_id = NEW.effect_id OR capture_id = NEW.capture_id
  )
BEGIN SELECT RAISE(ABORT, 'sensitive-output policy must precede effect admission'); END;

CREATE TRIGGER command_output_sensitive_policy_exact_capture
BEFORE INSERT ON command_output_sensitive_detection_policy_admissions_v29
WHEN NOT EXISTS (
    SELECT 1 FROM command_output_capture_intents intent
    WHERE intent.capture_id = NEW.capture_id
      AND intent.effect_id = NEW.effect_id
      AND intent.created_at_unix_ms = NEW.admitted_at_unix_ms
      AND intent.contract_version = NEW.contract_version
      AND json_extract(CAST(NEW.policy_json AS TEXT), '$.policy_id') = NEW.policy_id
      AND json_extract(CAST(NEW.policy_json AS TEXT), '$.policy_version') = NEW.policy_version
      AND json_extract(CAST(NEW.policy_json AS TEXT), '$.policy_digest') = NEW.policy_digest
)
BEGIN SELECT RAISE(ABORT, 'sensitive-output policy must match exact capture admission'); END;

CREATE TRIGGER command_output_sensitive_policy_no_update
BEFORE UPDATE ON command_output_sensitive_detection_policy_admissions_v29
BEGIN SELECT RAISE(ABORT, 'sensitive-output policy admissions are immutable'); END;
CREATE TRIGGER command_output_sensitive_policy_no_delete
BEFORE DELETE ON command_output_sensitive_detection_policy_admissions_v29
BEGIN SELECT RAISE(ABORT, 'sensitive-output policy admissions are immutable'); END;

-- The effect row is the final pre-dispatch commit boundary. Exactly one policy
-- state must already exist; runtime rows can never claim the migration escape.
CREATE TRIGGER effect_intents_require_v29_sensitive_output_policy
BEFORE INSERT ON effect_intents
WHEN NEW.effect_kind = 'RunCommand' AND NOT (
    (SELECT COUNT(*) FROM command_output_sensitive_detection_policy_admissions_v29 policy
      WHERE policy.effect_id = NEW.effect_id) = 1
    AND
    (SELECT COUNT(*) FROM pre_v29_sensitive_output_policy_exemptions exemption
      WHERE exemption.effect_id = NEW.effect_id) = 0
)
BEGIN SELECT RAISE(ABORT, 'new RunCommand requires pre-effect sensitive-output policy'); END;

-- A current-policy Published terminal is authoritative only when core retains
-- the complete runner-v2 clean branch and binds it to the exact v27 terminal.
-- The terminal FK is deferred so the receipt can be inserted first and the
-- terminal's reciprocal trigger can require it in the same transaction.
CREATE TABLE command_output_clean_scan_publication_receipts_v29 (
    clean_scan_receipt_digest TEXT PRIMARY KEY NOT NULL CHECK (
        length(clean_scan_receipt_digest) = 64
        AND clean_scan_receipt_digest NOT GLOB '*[^0-9a-f]*'
    ),
    clean_scan_receipt_id TEXT NOT NULL UNIQUE CHECK (
        length(clean_scan_receipt_id) BETWEEN 1 AND 4096
    ),
    capture_id TEXT NOT NULL UNIQUE,
    effect_id TEXT NOT NULL UNIQUE,
    observation_id TEXT NOT NULL UNIQUE,
    runner_session_id TEXT NOT NULL CHECK (length(runner_session_id) BETWEEN 1 AND 4096),
    request_digest TEXT NOT NULL CHECK (
        length(request_digest) = 64 AND request_digest NOT GLOB '*[^0-9a-f]*'
    ),
    intent_digest TEXT NOT NULL UNIQUE CHECK (
        length(intent_digest) = 64 AND intent_digest NOT GLOB '*[^0-9a-f]*'
    ),
    acquired_anchor_digest TEXT NOT NULL UNIQUE CHECK (
        length(acquired_anchor_digest) = 64
        AND acquired_anchor_digest NOT GLOB '*[^0-9a-f]*'
    ),
    detector_policy_id TEXT NOT NULL,
    detector_policy_version INTEGER NOT NULL CHECK (detector_policy_version > 0),
    detector_policy_digest TEXT NOT NULL CHECK (
        length(detector_policy_digest) = 64
        AND detector_policy_digest NOT GLOB '*[^0-9a-f]*'
    ),
    core_dump_schema_version INTEGER NOT NULL CHECK (core_dump_schema_version = 1),
    core_limit_current INTEGER NOT NULL CHECK (core_limit_current = 0),
    core_limit_maximum INTEGER NOT NULL CHECK (core_limit_maximum = 0),
    linux_dumpable_disabled INTEGER CHECK (linux_dumpable_disabled IS NULL OR linux_dumpable_disabled = 1),
    core_dump_profile_digest TEXT NOT NULL CHECK (
        length(core_dump_profile_digest) = 64
        AND core_dump_profile_digest NOT GLOB '*[^0-9a-f]*'
    ),
    runner_journal_id TEXT NOT NULL UNIQUE CHECK (length(runner_journal_id) BETWEEN 1 AND 4096),
    launch_intended_head_generation INTEGER NOT NULL CHECK (launch_intended_head_generation = 4),
    launch_intended_head_digest TEXT NOT NULL UNIQUE CHECK (
        length(launch_intended_head_digest) = 64
        AND launch_intended_head_digest NOT GLOB '*[^0-9a-f]*'
    ),
    scanned_clean_head_generation INTEGER NOT NULL CHECK (scanned_clean_head_generation = 5),
    scanned_clean_head_digest TEXT NOT NULL UNIQUE CHECK (
        length(scanned_clean_head_digest) = 64
        AND scanned_clean_head_digest NOT GLOB '*[^0-9a-f]*'
        AND scanned_clean_head_digest != launch_intended_head_digest
    ),
    finished_head_generation INTEGER NOT NULL CHECK (finished_head_generation = 6),
    finished_head_digest TEXT NOT NULL UNIQUE CHECK (
        length(finished_head_digest) = 64
        AND finished_head_digest NOT GLOB '*[^0-9a-f]*'
        AND finished_head_digest != scanned_clean_head_digest
    ),
    published_head_generation INTEGER NOT NULL CHECK (published_head_generation = 7),
    published_head_digest TEXT NOT NULL UNIQUE CHECK (
        length(published_head_digest) = 64
        AND published_head_digest NOT GLOB '*[^0-9a-f]*'
        AND published_head_digest != scanned_clean_head_digest
        AND published_head_digest != finished_head_digest
    ),
    terminal_prepared_head_generation INTEGER NOT NULL CHECK (
        terminal_prepared_head_generation = 8
    ),
    terminal_prepared_head_digest TEXT NOT NULL UNIQUE CHECK (
        length(terminal_prepared_head_digest) = 64
        AND terminal_prepared_head_digest NOT GLOB '*[^0-9a-f]*'
        AND terminal_prepared_head_digest != scanned_clean_head_digest
        AND terminal_prepared_head_digest != finished_head_digest
        AND terminal_prepared_head_digest != published_head_digest
    ),
    acquired_store_head_generation INTEGER NOT NULL CHECK (acquired_store_head_generation > 0),
    acquired_store_head_digest TEXT NOT NULL CHECK (
        length(acquired_store_head_digest) = 64
        AND acquired_store_head_digest NOT GLOB '*[^0-9a-f]*'
    ),
    writer_attached_store_head_generation INTEGER NOT NULL CHECK (
        writer_attached_store_head_generation > acquired_store_head_generation
    ),
    writer_attached_store_head_digest TEXT NOT NULL CHECK (
        length(writer_attached_store_head_digest) = 64
        AND writer_attached_store_head_digest NOT GLOB '*[^0-9a-f]*'
        AND writer_attached_store_head_digest != acquired_store_head_digest
    ),
    launch_intended_store_head_generation INTEGER NOT NULL CHECK (
        launch_intended_store_head_generation > writer_attached_store_head_generation
    ),
    launch_intended_store_head_digest TEXT NOT NULL CHECK (
        length(launch_intended_store_head_digest) = 64
        AND launch_intended_store_head_digest NOT GLOB '*[^0-9a-f]*'
        AND launch_intended_store_head_digest != acquired_store_head_digest
        AND launch_intended_store_head_digest != writer_attached_store_head_digest
    ),
    finished_store_head_generation INTEGER NOT NULL CHECK (
        finished_store_head_generation > launch_intended_store_head_generation
    ),
    finished_store_head_digest TEXT NOT NULL CHECK (
        length(finished_store_head_digest) = 64
        AND finished_store_head_digest NOT GLOB '*[^0-9a-f]*'
        AND finished_store_head_digest != acquired_store_head_digest
        AND finished_store_head_digest != writer_attached_store_head_digest
        AND finished_store_head_digest != launch_intended_store_head_digest
    ),
    published_store_head_generation INTEGER NOT NULL CHECK (
        published_store_head_generation > finished_store_head_generation
    ),
    published_store_head_digest TEXT NOT NULL CHECK (
        length(published_store_head_digest) = 64
        AND published_store_head_digest NOT GLOB '*[^0-9a-f]*'
        AND published_store_head_digest != acquired_store_head_digest
        AND published_store_head_digest != writer_attached_store_head_digest
        AND published_store_head_digest != launch_intended_store_head_digest
        AND published_store_head_digest != finished_store_head_digest
    ),
    terminal_prepared_store_head_generation INTEGER NOT NULL CHECK (
        terminal_prepared_store_head_generation > published_store_head_generation
    ),
    terminal_prepared_store_head_digest TEXT NOT NULL CHECK (
        length(terminal_prepared_store_head_digest) = 64
        AND terminal_prepared_store_head_digest NOT GLOB '*[^0-9a-f]*'
        AND terminal_prepared_store_head_digest != acquired_store_head_digest
        AND terminal_prepared_store_head_digest != writer_attached_store_head_digest
        AND terminal_prepared_store_head_digest != launch_intended_store_head_digest
        AND terminal_prepared_store_head_digest != finished_store_head_digest
        AND terminal_prepared_store_head_digest != published_store_head_digest
    ),
    terminal_record_digest TEXT NOT NULL CHECK (
        length(terminal_record_digest) = 64
        AND terminal_record_digest NOT GLOB '*[^0-9a-f]*'
    ),
    termination_kind TEXT NOT NULL CHECK (
        termination_kind IN ('Exited', 'Signaled', 'TimedOut', 'Canceled', 'OutputLimitExceeded')
    ),
    termination_code INTEGER,
    termination_signal INTEGER,
    scanned_clean_at_unix_ms INTEGER NOT NULL CHECK (scanned_clean_at_unix_ms > 0),
    finished_at_unix_ms INTEGER NOT NULL CHECK (
        finished_at_unix_ms >= scanned_clean_at_unix_ms
    ),
    published_at_unix_ms INTEGER NOT NULL CHECK (
        published_at_unix_ms >= finished_at_unix_ms
    ),
    terminal_prepared_at_unix_ms INTEGER NOT NULL CHECK (
        terminal_prepared_at_unix_ms >= published_at_unix_ms
    ),
    terminal_anchor_digest TEXT NOT NULL UNIQUE CHECK (
        length(terminal_anchor_digest) = 64
        AND terminal_anchor_digest NOT GLOB '*[^0-9a-f]*'
    ),
    layout_version INTEGER NOT NULL CHECK (layout_version = 1),
    contract_version INTEGER NOT NULL CHECK (contract_version > 0),
    clean_scan_receipt_json BLOB NOT NULL CHECK (
        length(clean_scan_receipt_json) > 0
        AND clean_scan_receipt_digest =
            grok_sensitive_output_clean_scan_v29_digest(clean_scan_receipt_json)
    ),
    CHECK (
        (termination_kind = 'Exited' AND termination_code >= 0 AND termination_signal IS NULL)
        OR (termination_kind = 'Signaled' AND termination_code IS NULL AND termination_signal > 0)
        OR (termination_kind IN ('TimedOut', 'Canceled', 'OutputLimitExceeded')
            AND termination_code IS NULL AND termination_signal IS NULL)
    ),
    FOREIGN KEY (capture_id, effect_id, intent_digest)
        REFERENCES command_output_capture_intents(capture_id, effect_id, intent_digest)
        ON DELETE RESTRICT,
    FOREIGN KEY (acquired_anchor_digest)
        REFERENCES command_output_capture_acquisitions(acquired_anchor_digest)
        ON DELETE RESTRICT,
    FOREIGN KEY (terminal_anchor_digest)
        REFERENCES command_output_capture_terminal_anchors(terminal_anchor_digest)
        ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED,
    FOREIGN KEY (observation_id)
        REFERENCES effect_observations(observation_id)
        ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED
) STRICT, WITHOUT ROWID;

CREATE TRIGGER command_output_clean_scan_publication_no_backfill
BEFORE INSERT ON command_output_clean_scan_publication_receipts_v29
WHEN EXISTS (SELECT 1 FROM effect_observations WHERE effect_id = NEW.effect_id)
   OR EXISTS (SELECT 1 FROM command_output_capture_terminal_anchors WHERE effect_id = NEW.effect_id)
   OR EXISTS (SELECT 1 FROM command_output_sensitive_rejection_anchors_v29 WHERE effect_id = NEW.effect_id)
   OR EXISTS (SELECT 1 FROM pre_v29_sensitive_output_policy_exemptions WHERE effect_id = NEW.effect_id)
BEGIN SELECT RAISE(ABORT, 'clean-scan publication receipt must precede terminal observation and cannot backfill'); END;

CREATE TRIGGER command_output_clean_scan_publication_exact
BEFORE INSERT ON command_output_clean_scan_publication_receipts_v29
WHEN NOT EXISTS (
    SELECT 1
    FROM command_output_capture_intents intent
    JOIN command_output_capture_acquisitions acquired
      ON acquired.capture_id = intent.capture_id AND acquired.effect_id = intent.effect_id
    JOIN runner_effect_dispatch_claims claim
      ON claim.dispatch_claim_id = acquired.dispatch_claim_id
     AND claim.effect_id = intent.effect_id
     AND claim.sprint_id = intent.sprint_id
     AND claim.launch_id = intent.runner_launch_id
     AND claim.session_id = intent.runner_session_id
     AND claim.request_digest = intent.request_digest
    JOIN command_output_sensitive_detection_policy_admissions_v29 policy
      ON policy.capture_id = intent.capture_id AND policy.effect_id = intent.effect_id
    WHERE intent.capture_id = NEW.capture_id
      AND intent.effect_id = NEW.effect_id
      AND intent.runner_session_id = NEW.runner_session_id
      AND intent.request_digest = NEW.request_digest
      AND intent.intent_digest = NEW.intent_digest
      AND acquired.acquired_anchor_digest = NEW.acquired_anchor_digest
      AND acquired.store_head_generation = NEW.acquired_store_head_generation
      AND acquired.store_head_digest = NEW.acquired_store_head_digest
      AND acquired.acquired_at_unix_ms <= NEW.scanned_clean_at_unix_ms
      AND acquired.contract_version = NEW.contract_version
      AND claim.contract_version = NEW.contract_version
      AND policy.policy_id = NEW.detector_policy_id
      AND policy.policy_version = NEW.detector_policy_version
      AND policy.policy_digest = NEW.detector_policy_digest
      AND policy.contract_version = NEW.contract_version
      AND NEW.linux_dumpable_disabled IS CASE
            WHEN json_extract(CAST(NEW.clean_scan_receipt_json AS TEXT), '$.core_dump_suppression.linux_dumpable_disabled') = 1 THEN 1
            ELSE NULL
          END
      AND json_extract(CAST(NEW.clean_scan_receipt_json AS TEXT), '$.clean_scan_receipt_id') = NEW.clean_scan_receipt_id
      AND json_extract(CAST(NEW.clean_scan_receipt_json AS TEXT), '$.capture_id') = NEW.capture_id
      AND json_extract(CAST(NEW.clean_scan_receipt_json AS TEXT), '$.effect_id') = NEW.effect_id
      AND json_extract(CAST(NEW.clean_scan_receipt_json AS TEXT), '$.observation_id') = NEW.observation_id
      AND json_extract(CAST(NEW.clean_scan_receipt_json AS TEXT), '$.runner_session_id') = NEW.runner_session_id
      AND json_extract(CAST(NEW.clean_scan_receipt_json AS TEXT), '$.request_digest') = NEW.request_digest
      AND json_extract(CAST(NEW.clean_scan_receipt_json AS TEXT), '$.intent_digest') = NEW.intent_digest
      AND json_extract(CAST(NEW.clean_scan_receipt_json AS TEXT), '$.acquired.acquired_anchor_digest') = NEW.acquired_anchor_digest
      AND json_extract(CAST(NEW.clean_scan_receipt_json AS TEXT), '$.detector_policy.policy_id') = NEW.detector_policy_id
      AND json_extract(CAST(NEW.clean_scan_receipt_json AS TEXT), '$.detector_policy.policy_version') = NEW.detector_policy_version
      AND json_extract(CAST(NEW.clean_scan_receipt_json AS TEXT), '$.detector_policy.policy_digest') = NEW.detector_policy_digest
      AND json_extract(CAST(NEW.clean_scan_receipt_json AS TEXT), '$.core_dump_suppression.schema_version') = NEW.core_dump_schema_version
      AND json_extract(CAST(NEW.clean_scan_receipt_json AS TEXT), '$.core_dump_suppression.core_limit_current') = NEW.core_limit_current
      AND json_extract(CAST(NEW.clean_scan_receipt_json AS TEXT), '$.core_dump_suppression.core_limit_maximum') = NEW.core_limit_maximum
      AND json_extract(CAST(NEW.clean_scan_receipt_json AS TEXT), '$.core_dump_suppression.profile_digest') = NEW.core_dump_profile_digest
      AND json_extract(CAST(NEW.clean_scan_receipt_json AS TEXT), '$.runner_journal_id') = NEW.runner_journal_id
      AND json_extract(CAST(NEW.clean_scan_receipt_json AS TEXT), '$.launch_intended_journal_head.generation') = NEW.launch_intended_head_generation
      AND json_extract(CAST(NEW.clean_scan_receipt_json AS TEXT), '$.launch_intended_journal_head.record_digest') = NEW.launch_intended_head_digest
      AND json_extract(CAST(NEW.clean_scan_receipt_json AS TEXT), '$.scanned_clean_journal_head.generation') = NEW.scanned_clean_head_generation
      AND json_extract(CAST(NEW.clean_scan_receipt_json AS TEXT), '$.scanned_clean_journal_head.record_digest') = NEW.scanned_clean_head_digest
      AND json_extract(CAST(NEW.clean_scan_receipt_json AS TEXT), '$.finished_journal_head.generation') = NEW.finished_head_generation
      AND json_extract(CAST(NEW.clean_scan_receipt_json AS TEXT), '$.finished_journal_head.record_digest') = NEW.finished_head_digest
      AND json_extract(CAST(NEW.clean_scan_receipt_json AS TEXT), '$.published_journal_head.generation') = NEW.published_head_generation
      AND json_extract(CAST(NEW.clean_scan_receipt_json AS TEXT), '$.published_journal_head.record_digest') = NEW.published_head_digest
      AND json_extract(CAST(NEW.clean_scan_receipt_json AS TEXT), '$.terminal_prepared_journal_head.generation') = NEW.terminal_prepared_head_generation
      AND json_extract(CAST(NEW.clean_scan_receipt_json AS TEXT), '$.terminal_prepared_journal_head.record_digest') = NEW.terminal_prepared_head_digest
      AND json_extract(CAST(NEW.clean_scan_receipt_json AS TEXT), '$.acquired_store_head.generation') = NEW.acquired_store_head_generation
      AND json_extract(CAST(NEW.clean_scan_receipt_json AS TEXT), '$.acquired_store_head.record_digest') = NEW.acquired_store_head_digest
      AND json_extract(CAST(NEW.clean_scan_receipt_json AS TEXT), '$.writer_attached_store_head.generation') = NEW.writer_attached_store_head_generation
      AND json_extract(CAST(NEW.clean_scan_receipt_json AS TEXT), '$.writer_attached_store_head.record_digest') = NEW.writer_attached_store_head_digest
      AND json_extract(CAST(NEW.clean_scan_receipt_json AS TEXT), '$.launch_intended_store_head.generation') = NEW.launch_intended_store_head_generation
      AND json_extract(CAST(NEW.clean_scan_receipt_json AS TEXT), '$.launch_intended_store_head.record_digest') = NEW.launch_intended_store_head_digest
      AND json_extract(CAST(NEW.clean_scan_receipt_json AS TEXT), '$.finished_store_head.generation') = NEW.finished_store_head_generation
      AND json_extract(CAST(NEW.clean_scan_receipt_json AS TEXT), '$.finished_store_head.record_digest') = NEW.finished_store_head_digest
      AND json_extract(CAST(NEW.clean_scan_receipt_json AS TEXT), '$.published_store_head.generation') = NEW.published_store_head_generation
      AND json_extract(CAST(NEW.clean_scan_receipt_json AS TEXT), '$.published_store_head.record_digest') = NEW.published_store_head_digest
      AND json_extract(CAST(NEW.clean_scan_receipt_json AS TEXT), '$.terminal_prepared_store_head.generation') = NEW.terminal_prepared_store_head_generation
      AND json_extract(CAST(NEW.clean_scan_receipt_json AS TEXT), '$.terminal_prepared_store_head.record_digest') = NEW.terminal_prepared_store_head_digest
      AND json_extract(CAST(NEW.clean_scan_receipt_json AS TEXT), '$.terminal_record_digest') = NEW.terminal_record_digest
      AND json_extract(CAST(NEW.clean_scan_receipt_json AS TEXT), '$.termination.kind') = CASE NEW.termination_kind
            WHEN 'Exited' THEN 'exited'
            WHEN 'Signaled' THEN 'signaled'
            WHEN 'TimedOut' THEN 'timed_out'
            WHEN 'Canceled' THEN 'canceled'
            WHEN 'OutputLimitExceeded' THEN 'output_limit_exceeded'
          END
      AND json_extract(CAST(NEW.clean_scan_receipt_json AS TEXT), '$.termination.code') IS NEW.termination_code
      AND json_extract(CAST(NEW.clean_scan_receipt_json AS TEXT), '$.termination.signal') IS NEW.termination_signal
      AND json_extract(CAST(NEW.clean_scan_receipt_json AS TEXT), '$.scanned_clean_at_unix_ms') = NEW.scanned_clean_at_unix_ms
      AND json_extract(CAST(NEW.clean_scan_receipt_json AS TEXT), '$.finished_at_unix_ms') = NEW.finished_at_unix_ms
      AND json_extract(CAST(NEW.clean_scan_receipt_json AS TEXT), '$.published_at_unix_ms') = NEW.published_at_unix_ms
      AND json_extract(CAST(NEW.clean_scan_receipt_json AS TEXT), '$.terminal_prepared_at_unix_ms') = NEW.terminal_prepared_at_unix_ms
      AND json_extract(CAST(NEW.clean_scan_receipt_json AS TEXT), '$.terminal_anchor_digest') = NEW.terminal_anchor_digest
      AND json_extract(CAST(NEW.clean_scan_receipt_json AS TEXT), '$.layout_version') = NEW.layout_version
      AND json_extract(CAST(NEW.clean_scan_receipt_json AS TEXT), '$.contract_version') = NEW.contract_version
      AND json_extract(CAST(NEW.clean_scan_receipt_json AS TEXT), '$.clean_scan_receipt_digest') = NEW.clean_scan_receipt_digest
)
BEGIN SELECT RAISE(ABORT, 'clean-scan publication receipt must match exact request, acquisition, and policy'); END;

CREATE TRIGGER command_output_clean_scan_publication_no_update
BEFORE UPDATE ON command_output_clean_scan_publication_receipts_v29
BEGIN SELECT RAISE(ABORT, 'clean-scan publication receipts are immutable'); END;
CREATE TRIGGER command_output_clean_scan_publication_no_delete
BEFORE DELETE ON command_output_clean_scan_publication_receipts_v29
BEGIN SELECT RAISE(ABORT, 'clean-scan publication receipts are immutable'); END;

-- A later Published resolution of an immutable Unknown terminal needs its own
-- clean-scan authority. A direct-terminal receipt cannot be replayed here: the
-- new receipt embeds the original intent/acquisition/terminal, the exact live
-- claim and proposed resolution, and the complete runner-v2 clean branch.
-- Its resolution FK is deferred so the receipt can be staged first and the
-- reciprocal resolution trigger can require it in the same transaction.
CREATE TABLE command_output_clean_scan_resolution_receipts_v29 (
    clean_scan_resolution_receipt_digest TEXT PRIMARY KEY NOT NULL CHECK (
        length(clean_scan_resolution_receipt_digest) = 64
        AND clean_scan_resolution_receipt_digest NOT GLOB '*[^0-9a-f]*'
    ),
    clean_scan_resolution_receipt_id TEXT NOT NULL UNIQUE CHECK (
        length(clean_scan_resolution_receipt_id) BETWEEN 1 AND 4096
    ),
    capture_id TEXT NOT NULL UNIQUE,
    effect_id TEXT NOT NULL UNIQUE,
    observation_id TEXT NOT NULL UNIQUE,
    intent_digest TEXT NOT NULL UNIQUE CHECK (
        length(intent_digest) = 64 AND intent_digest NOT GLOB '*[^0-9a-f]*'
    ),
    acquired_anchor_digest TEXT NOT NULL UNIQUE CHECK (
        length(acquired_anchor_digest) = 64
        AND acquired_anchor_digest NOT GLOB '*[^0-9a-f]*'
    ),
    terminal_anchor_digest TEXT NOT NULL UNIQUE CHECK (
        length(terminal_anchor_digest) = 64
        AND terminal_anchor_digest NOT GLOB '*[^0-9a-f]*'
    ),
    reconciliation_claim_id TEXT NOT NULL UNIQUE,
    reconciliation_fencing_token TEXT NOT NULL UNIQUE CHECK (
        length(reconciliation_fencing_token) = 64
        AND reconciliation_fencing_token NOT GLOB '*[^0-9a-f]*'
    ),
    resolution_anchor_digest TEXT NOT NULL UNIQUE CHECK (
        length(resolution_anchor_digest) = 64
        AND resolution_anchor_digest NOT GLOB '*[^0-9a-f]*'
    ),
    artifact_manifest_digest TEXT NOT NULL CHECK (
        length(artifact_manifest_digest) = 64
        AND artifact_manifest_digest NOT GLOB '*[^0-9a-f]*'
    ),
    resolution_store_head_generation INTEGER NOT NULL CHECK (
        resolution_store_head_generation > 0
    ),
    resolution_store_head_digest TEXT NOT NULL CHECK (
        length(resolution_store_head_digest) = 64
        AND resolution_store_head_digest NOT GLOB '*[^0-9a-f]*'
    ),
    resolution_record_digest TEXT NOT NULL CHECK (
        length(resolution_record_digest) = 64
        AND resolution_record_digest NOT GLOB '*[^0-9a-f]*'
    ),
    detector_policy_id TEXT NOT NULL CHECK (length(detector_policy_id) BETWEEN 1 AND 4096),
    detector_policy_version INTEGER NOT NULL CHECK (detector_policy_version > 0),
    detector_policy_digest TEXT NOT NULL CHECK (
        length(detector_policy_digest) = 64
        AND detector_policy_digest NOT GLOB '*[^0-9a-f]*'
    ),
    runner_journal_id TEXT NOT NULL UNIQUE CHECK (
        length(runner_journal_id) BETWEEN 1 AND 4096
    ),
    terminal_prepared_head_generation INTEGER NOT NULL CHECK (
        terminal_prepared_head_generation = 8
    ),
    terminal_prepared_head_digest TEXT NOT NULL UNIQUE CHECK (
        length(terminal_prepared_head_digest) = 64
        AND terminal_prepared_head_digest NOT GLOB '*[^0-9a-f]*'
    ),
    terminal_prepared_store_head_generation INTEGER NOT NULL CHECK (
        terminal_prepared_store_head_generation = resolution_store_head_generation
    ),
    terminal_prepared_store_head_digest TEXT NOT NULL CHECK (
        terminal_prepared_store_head_digest = resolution_store_head_digest
    ),
    terminal_prepared_at_unix_ms INTEGER NOT NULL CHECK (
        terminal_prepared_at_unix_ms > 0
    ),
    resolved_at_unix_ms INTEGER NOT NULL CHECK (
        resolved_at_unix_ms >= terminal_prepared_at_unix_ms
    ),
    layout_version INTEGER NOT NULL CHECK (layout_version = 1),
    contract_version INTEGER NOT NULL CHECK (contract_version > 0),
    clean_scan_resolution_receipt_json BLOB NOT NULL CHECK (
        length(clean_scan_resolution_receipt_json) > 0
        AND clean_scan_resolution_receipt_digest =
            grok_sensitive_output_clean_scan_resolution_v29_digest(
                clean_scan_resolution_receipt_json
            )
    ),
    FOREIGN KEY (capture_id, effect_id, intent_digest)
        REFERENCES command_output_capture_intents(capture_id, effect_id, intent_digest)
        ON DELETE RESTRICT,
    FOREIGN KEY (acquired_anchor_digest)
        REFERENCES command_output_capture_acquisitions(acquired_anchor_digest)
        ON DELETE RESTRICT,
    FOREIGN KEY (terminal_anchor_digest)
        REFERENCES command_output_capture_terminal_anchors(terminal_anchor_digest)
        ON DELETE RESTRICT,
    FOREIGN KEY (reconciliation_claim_id)
        REFERENCES command_output_capture_reconciliation_claims(claim_id)
        ON DELETE RESTRICT,
    FOREIGN KEY (resolution_anchor_digest)
        REFERENCES command_output_capture_reconciliation_resolutions(resolution_anchor_digest)
        ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED
) STRICT, WITHOUT ROWID;

CREATE TRIGGER command_output_clean_scan_resolution_no_backfill
BEFORE INSERT ON command_output_clean_scan_resolution_receipts_v29
WHEN EXISTS (
        SELECT 1 FROM command_output_capture_reconciliation_resolutions
        WHERE effect_id = NEW.effect_id OR capture_id = NEW.capture_id
     )
  OR EXISTS (
        SELECT 1 FROM command_output_clean_scan_publication_receipts_v29
        WHERE effect_id = NEW.effect_id OR capture_id = NEW.capture_id
     )
  OR EXISTS (
        SELECT 1 FROM command_output_sensitive_rejection_anchors_v29
        WHERE effect_id = NEW.effect_id OR capture_id = NEW.capture_id
     )
  OR EXISTS (
        SELECT 1 FROM pre_v29_sensitive_output_policy_exemptions
        WHERE effect_id = NEW.effect_id OR capture_id = NEW.capture_id
     )
BEGIN SELECT RAISE(ABORT, 'clean-scan resolution receipt must precede its resolution and cannot backfill'); END;

CREATE TRIGGER command_output_clean_scan_resolution_exact
BEFORE INSERT ON command_output_clean_scan_resolution_receipts_v29
WHEN NOT EXISTS (
    SELECT 1
    FROM command_output_capture_intents intent
    JOIN command_output_capture_acquisitions acquired
      ON acquired.capture_id = intent.capture_id
     AND acquired.effect_id = intent.effect_id
    JOIN command_output_capture_terminal_anchors terminal
      ON terminal.capture_id = intent.capture_id
     AND terminal.effect_id = intent.effect_id
     AND terminal.observation_id = NEW.observation_id
     AND terminal.terminal_anchor_digest = NEW.terminal_anchor_digest
     AND terminal.observation_class = 'Unknown'
     AND terminal.disposition = 'ReconciliationRequired'
     AND terminal.acquired_anchor_digest = acquired.acquired_anchor_digest
     AND terminal.artifact_manifest_digest IS NULL
     AND terminal.artifact_reference_json IS NULL
    JOIN command_output_capture_reconciliation_claims claim
      ON claim.claim_id = NEW.reconciliation_claim_id
     AND claim.capture_id = intent.capture_id
     AND claim.fencing_token = NEW.reconciliation_fencing_token
    JOIN command_output_sensitive_detection_policy_admissions_v29 policy
      ON policy.capture_id = intent.capture_id
     AND policy.effect_id = intent.effect_id
    WHERE intent.capture_id = NEW.capture_id
      AND intent.effect_id = NEW.effect_id
      AND intent.intent_digest = NEW.intent_digest
      AND acquired.acquired_anchor_digest = NEW.acquired_anchor_digest
      AND policy.policy_id = NEW.detector_policy_id
      AND policy.policy_version = NEW.detector_policy_version
      AND policy.policy_digest = NEW.detector_policy_digest
      AND claim.claim_epoch = (
          SELECT MAX(latest.claim_epoch)
          FROM command_output_capture_reconciliation_claims latest
          WHERE latest.capture_id = claim.capture_id
      )
      AND NOT EXISTS (
          SELECT 1 FROM command_output_capture_reconciliation_claim_releases release
          WHERE release.claim_id = claim.claim_id
      )
      AND NEW.resolved_at_unix_ms >= terminal.anchored_at_unix_ms
      AND NEW.resolved_at_unix_ms >= claim.acquired_at_unix_ms
      AND NEW.resolved_at_unix_ms < claim.expires_at_unix_ms
      AND NEW.resolution_store_head_generation > terminal.store_head_generation
      AND NEW.resolution_record_digest = NEW.resolution_store_head_digest
      AND intent.layout_version = NEW.layout_version
      AND intent.contract_version = NEW.contract_version
      AND acquired.contract_version = NEW.contract_version
      AND terminal.contract_version = NEW.contract_version
      AND claim.contract_version = NEW.contract_version
      AND policy.contract_version = NEW.contract_version
      AND json_extract(CAST(NEW.clean_scan_resolution_receipt_json AS TEXT),
                       '$.clean_scan_resolution_receipt_id') =
          NEW.clean_scan_resolution_receipt_id
      AND json_extract(CAST(NEW.clean_scan_resolution_receipt_json AS TEXT),
                       '$.intent.capture_id') = NEW.capture_id
      AND json_extract(CAST(NEW.clean_scan_resolution_receipt_json AS TEXT),
                       '$.intent.source.effect_id') = NEW.effect_id
      AND json_extract(CAST(NEW.clean_scan_resolution_receipt_json AS TEXT),
                       '$.intent.intent_digest') = NEW.intent_digest
      AND json_extract(CAST(NEW.clean_scan_resolution_receipt_json AS TEXT),
                       '$.acquired.acquired_anchor_digest') = NEW.acquired_anchor_digest
      AND json_extract(CAST(NEW.clean_scan_resolution_receipt_json AS TEXT),
                       '$.unknown_terminal.observation_id') = NEW.observation_id
      AND json_extract(CAST(NEW.clean_scan_resolution_receipt_json AS TEXT),
                       '$.unknown_terminal.terminal_anchor_digest') =
          NEW.terminal_anchor_digest
      AND json_extract(CAST(NEW.clean_scan_resolution_receipt_json AS TEXT),
                       '$.reconciliation_claim.claim_id') = NEW.reconciliation_claim_id
      AND json_extract(CAST(NEW.clean_scan_resolution_receipt_json AS TEXT),
                       '$.reconciliation_claim.fencing_token') =
          NEW.reconciliation_fencing_token
      AND json_extract(CAST(NEW.clean_scan_resolution_receipt_json AS TEXT),
                       '$.resolution.resolution_anchor_digest') =
          NEW.resolution_anchor_digest
      AND json_extract(CAST(NEW.clean_scan_resolution_receipt_json AS TEXT),
                       '$.resolution.artifact_reference.manifest_digest') =
          NEW.artifact_manifest_digest
      AND json_extract(CAST(NEW.clean_scan_resolution_receipt_json AS TEXT),
                       '$.resolution.store_head.generation') =
          NEW.resolution_store_head_generation
      AND json_extract(CAST(NEW.clean_scan_resolution_receipt_json AS TEXT),
                       '$.resolution.store_head.record_digest') =
          NEW.resolution_store_head_digest
      AND json_extract(CAST(NEW.clean_scan_resolution_receipt_json AS TEXT),
                       '$.resolution.resolution_record_digest') =
          NEW.resolution_record_digest
      AND json_extract(CAST(NEW.clean_scan_resolution_receipt_json AS TEXT),
                       '$.resolution.resolved_at_unix_ms') = NEW.resolved_at_unix_ms
      AND json_extract(CAST(NEW.clean_scan_resolution_receipt_json AS TEXT),
                       '$.detector_policy.policy_id') = NEW.detector_policy_id
      AND json_extract(CAST(NEW.clean_scan_resolution_receipt_json AS TEXT),
                       '$.detector_policy.policy_version') = NEW.detector_policy_version
      AND json_extract(CAST(NEW.clean_scan_resolution_receipt_json AS TEXT),
                       '$.detector_policy.policy_digest') = NEW.detector_policy_digest
      AND json_extract(CAST(NEW.clean_scan_resolution_receipt_json AS TEXT),
                       '$.clean_runner.journal_id') = NEW.runner_journal_id
      AND json_extract(CAST(NEW.clean_scan_resolution_receipt_json AS TEXT),
                       '$.clean_runner.terminal_prepared_journal_head.generation') =
          NEW.terminal_prepared_head_generation
      AND json_extract(CAST(NEW.clean_scan_resolution_receipt_json AS TEXT),
                       '$.clean_runner.terminal_prepared_journal_head.record_digest') =
          NEW.terminal_prepared_head_digest
      AND json_extract(CAST(NEW.clean_scan_resolution_receipt_json AS TEXT),
                       '$.clean_runner.terminal_prepared_store_head.generation') =
          NEW.terminal_prepared_store_head_generation
      AND json_extract(CAST(NEW.clean_scan_resolution_receipt_json AS TEXT),
                       '$.clean_runner.terminal_prepared_store_head.record_digest') =
          NEW.terminal_prepared_store_head_digest
      AND json_extract(CAST(NEW.clean_scan_resolution_receipt_json AS TEXT),
                       '$.clean_runner.terminal_prepared_at_unix_ms') =
          NEW.terminal_prepared_at_unix_ms
      AND json_extract(CAST(NEW.clean_scan_resolution_receipt_json AS TEXT),
                       '$.layout_version') = NEW.layout_version
      AND json_extract(CAST(NEW.clean_scan_resolution_receipt_json AS TEXT),
                       '$.contract_version') = NEW.contract_version
      AND json_extract(CAST(NEW.clean_scan_resolution_receipt_json AS TEXT),
                       '$.clean_scan_resolution_receipt_digest') =
          NEW.clean_scan_resolution_receipt_digest
      AND grok_sensitive_output_clean_scan_resolution_v29_digest(
              NEW.clean_scan_resolution_receipt_json
          ) = NEW.clean_scan_resolution_receipt_digest
)
BEGIN SELECT RAISE(ABORT, 'clean-scan resolution receipt must match exact current intent, acquisition, Unknown terminal, claim, policy, and Published resolution'); END;

CREATE TRIGGER command_output_clean_scan_resolution_no_update
BEFORE UPDATE ON command_output_clean_scan_resolution_receipts_v29
BEGIN SELECT RAISE(ABORT, 'clean-scan resolution receipts are immutable'); END;
CREATE TRIGGER command_output_clean_scan_resolution_no_delete
BEFORE DELETE ON command_output_clean_scan_resolution_receipts_v29
BEGIN SELECT RAISE(ABORT, 'clean-scan resolution receipts are immutable'); END;

CREATE TABLE command_output_sensitive_rejection_anchors_v29 (
    rejection_anchor_digest TEXT PRIMARY KEY NOT NULL CHECK (
        length(rejection_anchor_digest) = 64
        AND rejection_anchor_digest NOT GLOB '*[^0-9a-f]*'
    ),
    capture_id TEXT NOT NULL UNIQUE,
    effect_id TEXT NOT NULL UNIQUE,
    observation_id TEXT NOT NULL UNIQUE,
    dispatch_claim_id TEXT NOT NULL UNIQUE,
    intent_digest TEXT NOT NULL UNIQUE,
    acquired_anchor_digest TEXT NOT NULL UNIQUE,
    reason TEXT NOT NULL CHECK (reason = 'SensitiveOutputRejected'),
    detector_policy_id TEXT NOT NULL,
    detector_policy_version INTEGER NOT NULL CHECK (detector_policy_version > 0),
    detector_policy_digest TEXT NOT NULL,
    core_dump_schema_version INTEGER NOT NULL CHECK (core_dump_schema_version = 1),
    core_limit_current INTEGER NOT NULL CHECK (core_limit_current = 0),
    core_limit_maximum INTEGER NOT NULL CHECK (core_limit_maximum = 0),
    linux_dumpable_disabled INTEGER CHECK (linux_dumpable_disabled IS NULL OR linux_dumpable_disabled = 1),
    core_dump_profile_digest TEXT NOT NULL CHECK (
        length(core_dump_profile_digest) = 64
        AND core_dump_profile_digest NOT GLOB '*[^0-9a-f]*'
    ),
    staging_neutralization_receipt_digest TEXT NOT NULL CHECK (
        length(staging_neutralization_receipt_digest) = 64
        AND staging_neutralization_receipt_digest NOT GLOB '*[^0-9a-f]*'
    ),
    termination_kind TEXT NOT NULL CHECK (
        termination_kind IN ('Exited', 'Signaled', 'TimedOut', 'Canceled', 'OutputLimitExceeded')
    ),
    termination_code INTEGER,
    termination_signal INTEGER,
    runner_journal_id TEXT NOT NULL UNIQUE CHECK (length(runner_journal_id) BETWEEN 1 AND 4096),
    launch_intended_head_generation INTEGER NOT NULL CHECK (launch_intended_head_generation = 4),
    launch_intended_head_digest TEXT NOT NULL UNIQUE CHECK (
        length(launch_intended_head_digest) = 64
        AND launch_intended_head_digest NOT GLOB '*[^0-9a-f]*'
    ),
    rejected_terminal_head_generation INTEGER NOT NULL CHECK (
        rejected_terminal_head_generation = 8
    ),
    rejected_terminal_head_digest TEXT NOT NULL UNIQUE CHECK (
        length(rejected_terminal_head_digest) = 64
        AND rejected_terminal_head_digest NOT GLOB '*[^0-9a-f]*'
        AND rejected_terminal_head_digest != launch_intended_head_digest
    ),
    effect_evidence_digest TEXT NOT NULL UNIQUE CHECK (
        length(effect_evidence_digest) = 64
        AND effect_evidence_digest NOT GLOB '*[^0-9a-f]*'
    ),
    layout_version INTEGER NOT NULL CHECK (layout_version = 1),
    contract_version INTEGER NOT NULL CHECK (contract_version > 0),
    rejection_json BLOB NOT NULL CHECK (
        length(rejection_json) > 0
        AND rejection_anchor_digest =
            grok_sensitive_output_rejection_anchor_v29_digest(rejection_json)
        AND effect_evidence_digest = grok_sha256(rejection_json)
    ),
    CHECK (
        (termination_kind = 'Exited' AND termination_code >= 0 AND termination_signal IS NULL)
        OR (termination_kind = 'Signaled' AND termination_code IS NULL AND termination_signal > 0)
        OR (termination_kind IN ('TimedOut', 'Canceled', 'OutputLimitExceeded')
            AND termination_code IS NULL AND termination_signal IS NULL)
    ),
    FOREIGN KEY (capture_id, effect_id, intent_digest)
        REFERENCES command_output_capture_intents(capture_id, effect_id, intent_digest)
        ON DELETE RESTRICT,
    FOREIGN KEY (acquired_anchor_digest)
        REFERENCES command_output_capture_acquisitions(acquired_anchor_digest)
        ON DELETE RESTRICT,
    FOREIGN KEY (dispatch_claim_id)
        REFERENCES runner_effect_dispatch_claims(dispatch_claim_id) ON DELETE RESTRICT,
    FOREIGN KEY (observation_id)
        REFERENCES effect_observations(observation_id)
        ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED
) STRICT, WITHOUT ROWID;

CREATE TRIGGER command_output_sensitive_rejection_anchor_no_backfill
BEFORE INSERT ON command_output_sensitive_rejection_anchors_v29
WHEN EXISTS (SELECT 1 FROM effect_observations WHERE effect_id = NEW.effect_id)
   OR EXISTS (SELECT 1 FROM command_output_capture_terminal_anchors WHERE effect_id = NEW.effect_id)
   OR EXISTS (SELECT 1 FROM command_output_clean_scan_publication_receipts_v29 WHERE effect_id = NEW.effect_id)
   OR EXISTS (SELECT 1 FROM command_output_artifact_sets WHERE effect_id = NEW.effect_id)
   OR EXISTS (SELECT 1 FROM pre_v29_sensitive_output_policy_exemptions WHERE effect_id = NEW.effect_id)
BEGIN SELECT RAISE(ABORT, 'sensitive-output rejection must precede observation and cannot backfill'); END;

CREATE TRIGGER command_output_sensitive_rejection_anchor_exact
BEFORE INSERT ON command_output_sensitive_rejection_anchors_v29
WHEN NOT EXISTS (
    SELECT 1
    FROM command_output_capture_intents intent
    JOIN command_output_capture_acquisitions acquired
      ON acquired.capture_id = intent.capture_id AND acquired.effect_id = intent.effect_id
    JOIN runner_effect_dispatch_claims claim
      ON claim.dispatch_claim_id = acquired.dispatch_claim_id
     AND claim.effect_id = intent.effect_id
     AND claim.sprint_id = intent.sprint_id
     AND claim.launch_id = intent.runner_launch_id
     AND claim.session_id = intent.runner_session_id
     AND claim.request_digest = intent.request_digest
    JOIN command_output_sensitive_detection_policy_admissions_v29 policy
      ON policy.capture_id = intent.capture_id AND policy.effect_id = intent.effect_id
    WHERE intent.capture_id = NEW.capture_id
      AND intent.effect_id = NEW.effect_id
      AND intent.intent_digest = NEW.intent_digest
      AND acquired.acquired_anchor_digest = NEW.acquired_anchor_digest
      AND acquired.dispatch_claim_id = NEW.dispatch_claim_id
      AND acquired.contract_version = NEW.contract_version
      AND claim.contract_version = NEW.contract_version
      AND policy.policy_id = NEW.detector_policy_id
      AND policy.policy_version = NEW.detector_policy_version
      AND policy.policy_digest = NEW.detector_policy_digest
      AND policy.contract_version = NEW.contract_version
      AND NEW.linux_dumpable_disabled IS CASE
            WHEN json_extract(CAST(NEW.rejection_json AS TEXT), '$.core_dump_suppression.linux_dumpable_disabled') = 1 THEN 1
            ELSE NULL
          END
      AND json_extract(CAST(NEW.rejection_json AS TEXT), '$.capture_id') = NEW.capture_id
      AND json_extract(CAST(NEW.rejection_json AS TEXT), '$.effect_id') = NEW.effect_id
      AND json_extract(CAST(NEW.rejection_json AS TEXT), '$.observation_id') = NEW.observation_id
      AND json_extract(CAST(NEW.rejection_json AS TEXT), '$.dispatch_claim_id') = NEW.dispatch_claim_id
      AND json_extract(CAST(NEW.rejection_json AS TEXT), '$.intent_digest') = NEW.intent_digest
      AND json_extract(CAST(NEW.rejection_json AS TEXT), '$.acquired_anchor_digest') = NEW.acquired_anchor_digest
      AND json_extract(CAST(NEW.rejection_json AS TEXT), '$.reason') = 'sensitive_output_rejected'
      AND json_extract(CAST(NEW.rejection_json AS TEXT), '$.detector_policy.policy_id') = NEW.detector_policy_id
      AND json_extract(CAST(NEW.rejection_json AS TEXT), '$.detector_policy.policy_version') = NEW.detector_policy_version
      AND json_extract(CAST(NEW.rejection_json AS TEXT), '$.detector_policy.policy_digest') = NEW.detector_policy_digest
      AND json_extract(CAST(NEW.rejection_json AS TEXT), '$.core_dump_suppression.schema_version') = NEW.core_dump_schema_version
      AND json_extract(CAST(NEW.rejection_json AS TEXT), '$.core_dump_suppression.core_limit_current') = NEW.core_limit_current
      AND json_extract(CAST(NEW.rejection_json AS TEXT), '$.core_dump_suppression.core_limit_maximum') = NEW.core_limit_maximum
      AND json_extract(CAST(NEW.rejection_json AS TEXT), '$.core_dump_suppression.profile_digest') = NEW.core_dump_profile_digest
      AND json_extract(CAST(NEW.rejection_json AS TEXT), '$.staging_neutralization.receipt_digest') = NEW.staging_neutralization_receipt_digest
      AND json_extract(CAST(NEW.rejection_json AS TEXT), '$.staging_neutralization.capture_id') = NEW.capture_id
      AND json_extract(CAST(NEW.rejection_json AS TEXT), '$.staging_neutralization.acquired_anchor_digest') = NEW.acquired_anchor_digest
      AND json_extract(CAST(NEW.rejection_json AS TEXT), '$.staging_neutralization.aggregate_zero_length') = 0
      AND json_extract(CAST(NEW.rejection_json AS TEXT), '$.staging_neutralization.stdout.byte_length') = acquired.stdout_byte_length
      AND json_extract(CAST(NEW.rejection_json AS TEXT), '$.staging_neutralization.stderr.byte_length') = acquired.stderr_byte_length
      AND json_extract(CAST(NEW.rejection_json AS TEXT), '$.runner_cleanup.staging_neutralization.receipt_digest') = NEW.staging_neutralization_receipt_digest
      AND json_extract(CAST(NEW.rejection_json AS TEXT), '$.termination.kind') = CASE NEW.termination_kind
            WHEN 'Exited' THEN 'exited'
            WHEN 'Signaled' THEN 'signaled'
            WHEN 'TimedOut' THEN 'timed_out'
            WHEN 'Canceled' THEN 'canceled'
            WHEN 'OutputLimitExceeded' THEN 'output_limit_exceeded'
          END
      AND json_extract(CAST(NEW.rejection_json AS TEXT), '$.termination.code') IS NEW.termination_code
      AND json_extract(CAST(NEW.rejection_json AS TEXT), '$.termination.signal') IS NEW.termination_signal
      AND json_extract(CAST(NEW.rejection_json AS TEXT), '$.runner_journal_id') = NEW.runner_journal_id
      AND json_extract(CAST(NEW.rejection_json AS TEXT), '$.launch_intended_journal_head.generation') = NEW.launch_intended_head_generation
      AND json_extract(CAST(NEW.rejection_json AS TEXT), '$.launch_intended_journal_head.record_digest') = NEW.launch_intended_head_digest
      AND json_extract(CAST(NEW.rejection_json AS TEXT), '$.rejected_terminal_journal_head.generation') = NEW.rejected_terminal_head_generation
      AND json_extract(CAST(NEW.rejection_json AS TEXT), '$.rejected_terminal_journal_head.record_digest') = NEW.rejected_terminal_head_digest
      AND json_extract(CAST(NEW.rejection_json AS TEXT), '$.layout_version') = NEW.layout_version
      AND json_extract(CAST(NEW.rejection_json AS TEXT), '$.contract_version') = NEW.contract_version
      AND json_extract(CAST(NEW.rejection_json AS TEXT), '$.rejection_anchor_digest') = NEW.rejection_anchor_digest
)
BEGIN SELECT RAISE(ABORT, 'sensitive-output rejection must match exact pre-effect policy and acquisition'); END;

CREATE TABLE command_output_sensitive_rejection_cleanup_receipts_v29 (
    cleanup_receipt_digest TEXT PRIMARY KEY NOT NULL CHECK (
        length(cleanup_receipt_digest) = 64
        AND cleanup_receipt_digest NOT GLOB '*[^0-9a-f]*'
    ),
    cleanup_receipt_id TEXT NOT NULL UNIQUE CHECK (length(cleanup_receipt_id) BETWEEN 1 AND 4096),
    capture_id TEXT NOT NULL UNIQUE,
    effect_id TEXT NOT NULL UNIQUE,
    observation_id TEXT NOT NULL UNIQUE,
    rejection_anchor_digest TEXT NOT NULL UNIQUE,
    detector_policy_id TEXT NOT NULL,
    detector_policy_version INTEGER NOT NULL,
    detector_policy_digest TEXT NOT NULL,
    core_dump_schema_version INTEGER NOT NULL CHECK (core_dump_schema_version = 1),
    core_limit_current INTEGER NOT NULL CHECK (core_limit_current = 0),
    core_limit_maximum INTEGER NOT NULL CHECK (core_limit_maximum = 0),
    linux_dumpable_disabled INTEGER CHECK (linux_dumpable_disabled IS NULL OR linux_dumpable_disabled = 1),
    core_dump_profile_digest TEXT NOT NULL CHECK (
        length(core_dump_profile_digest) = 64
        AND core_dump_profile_digest NOT GLOB '*[^0-9a-f]*'
    ),
    staging_neutralization_receipt_digest TEXT NOT NULL CHECK (
        length(staging_neutralization_receipt_digest) = 64
        AND staging_neutralization_receipt_digest NOT GLOB '*[^0-9a-f]*'
    ),
    runner_journal_id TEXT NOT NULL UNIQUE CHECK (length(runner_journal_id) BETWEEN 1 AND 4096),
    launch_intended_head_generation INTEGER NOT NULL CHECK (launch_intended_head_generation = 4),
    launch_intended_head_digest TEXT NOT NULL UNIQUE CHECK (
        length(launch_intended_head_digest) = 64
        AND launch_intended_head_digest NOT GLOB '*[^0-9a-f]*'
    ),
    detected_head_generation INTEGER NOT NULL CHECK (detected_head_generation = 5),
    detected_head_digest TEXT NOT NULL UNIQUE CHECK (
        length(detected_head_digest) = 64
        AND detected_head_digest NOT GLOB '*[^0-9a-f]*'
        AND detected_head_digest != launch_intended_head_digest
    ),
    cleanup_intended_head_generation INTEGER NOT NULL CHECK (
        cleanup_intended_head_generation = 6
    ),
    cleanup_intended_head_digest TEXT NOT NULL UNIQUE CHECK (
        length(cleanup_intended_head_digest) = 64
        AND cleanup_intended_head_digest NOT GLOB '*[^0-9a-f]*'
        AND cleanup_intended_head_digest != detected_head_digest
    ),
    cleaned_head_generation INTEGER NOT NULL CHECK (cleaned_head_generation = 7),
    cleaned_head_digest TEXT NOT NULL UNIQUE CHECK (
        length(cleaned_head_digest) = 64
        AND cleaned_head_digest NOT GLOB '*[^0-9a-f]*'
        AND cleaned_head_digest != detected_head_digest
        AND cleaned_head_digest != cleanup_intended_head_digest
    ),
    rejected_terminal_head_generation INTEGER NOT NULL CHECK (rejected_terminal_head_generation = 8),
    rejected_terminal_head_digest TEXT NOT NULL UNIQUE CHECK (
        length(rejected_terminal_head_digest) = 64
        AND rejected_terminal_head_digest NOT GLOB '*[^0-9a-f]*'
        AND rejected_terminal_head_digest != cleaned_head_digest
        AND rejected_terminal_head_digest != detected_head_digest
        AND rejected_terminal_head_digest != cleanup_intended_head_digest
    ),
    runner_cleanup_receipt_id TEXT NOT NULL UNIQUE CHECK (
        length(runner_cleanup_receipt_id) BETWEEN 1 AND 4096
    ),
    runner_cleanup_receipt_digest TEXT NOT NULL UNIQUE CHECK (
        length(runner_cleanup_receipt_digest) = 64
        AND runner_cleanup_receipt_digest NOT GLOB '*[^0-9a-f]*'
    ),
    command_domain_cleanup_proof_id TEXT NOT NULL UNIQUE,
    layout_version INTEGER NOT NULL CHECK (layout_version = 1),
    contract_version INTEGER NOT NULL CHECK (contract_version > 0),
    cleanup_json BLOB NOT NULL CHECK (
        length(cleanup_json) > 0
        AND cleanup_receipt_digest =
            grok_sensitive_output_cleanup_v29_digest(cleanup_json)
    ),
    FOREIGN KEY (rejection_anchor_digest)
        REFERENCES command_output_sensitive_rejection_anchors_v29(rejection_anchor_digest)
        ON DELETE RESTRICT,
    FOREIGN KEY (command_domain_cleanup_proof_id)
        REFERENCES command_domain_cleanup_proofs(proof_id)
        ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED
) STRICT, WITHOUT ROWID;

CREATE TRIGGER command_output_sensitive_rejection_cleanup_exact
BEFORE INSERT ON command_output_sensitive_rejection_cleanup_receipts_v29
WHEN NOT EXISTS (
    SELECT 1 FROM command_output_sensitive_rejection_anchors_v29 anchor
    WHERE anchor.rejection_anchor_digest = NEW.rejection_anchor_digest
      AND anchor.capture_id = NEW.capture_id
      AND anchor.effect_id = NEW.effect_id
      AND anchor.observation_id = NEW.observation_id
      AND anchor.detector_policy_id = NEW.detector_policy_id
      AND anchor.detector_policy_version = NEW.detector_policy_version
      AND anchor.detector_policy_digest = NEW.detector_policy_digest
      AND anchor.core_dump_schema_version = NEW.core_dump_schema_version
      AND anchor.core_limit_current = NEW.core_limit_current
      AND anchor.core_limit_maximum = NEW.core_limit_maximum
      AND anchor.linux_dumpable_disabled IS NEW.linux_dumpable_disabled
      AND anchor.core_dump_profile_digest = NEW.core_dump_profile_digest
      AND anchor.staging_neutralization_receipt_digest = NEW.staging_neutralization_receipt_digest
      AND anchor.runner_journal_id = NEW.runner_journal_id
      AND anchor.launch_intended_head_generation = NEW.launch_intended_head_generation
      AND anchor.launch_intended_head_digest = NEW.launch_intended_head_digest
      AND anchor.rejected_terminal_head_generation = NEW.rejected_terminal_head_generation
      AND anchor.rejected_terminal_head_digest = NEW.rejected_terminal_head_digest
      AND anchor.layout_version = NEW.layout_version
      AND anchor.contract_version = NEW.contract_version
      AND json_extract(CAST(NEW.cleanup_json AS TEXT), '$.cleanup_receipt_id') = NEW.cleanup_receipt_id
      AND json_extract(CAST(NEW.cleanup_json AS TEXT), '$.capture_id') = NEW.capture_id
      AND json_extract(CAST(NEW.cleanup_json AS TEXT), '$.effect_id') = NEW.effect_id
      AND json_extract(CAST(NEW.cleanup_json AS TEXT), '$.observation_id') = NEW.observation_id
      AND json_extract(CAST(NEW.cleanup_json AS TEXT), '$.rejection_anchor_digest') = NEW.rejection_anchor_digest
      AND json_extract(CAST(NEW.cleanup_json AS TEXT), '$.runner_cleanup.journal_id') = NEW.runner_journal_id
      AND json_extract(CAST(NEW.cleanup_json AS TEXT), '$.runner_cleanup.launch_intended_journal_head.generation') = NEW.launch_intended_head_generation
      AND json_extract(CAST(NEW.cleanup_json AS TEXT), '$.runner_cleanup.launch_intended_journal_head.record_digest') = NEW.launch_intended_head_digest
      AND json_extract(CAST(NEW.cleanup_json AS TEXT), '$.runner_cleanup.core_dump_suppression.schema_version') = NEW.core_dump_schema_version
      AND json_extract(CAST(NEW.cleanup_json AS TEXT), '$.runner_cleanup.core_dump_suppression.core_limit_current') = NEW.core_limit_current
      AND json_extract(CAST(NEW.cleanup_json AS TEXT), '$.runner_cleanup.core_dump_suppression.core_limit_maximum') = NEW.core_limit_maximum
      AND json_extract(CAST(NEW.cleanup_json AS TEXT), '$.runner_cleanup.core_dump_suppression.linux_dumpable_disabled') IS NEW.linux_dumpable_disabled
      AND json_extract(CAST(NEW.cleanup_json AS TEXT), '$.runner_cleanup.core_dump_suppression.profile_digest') = NEW.core_dump_profile_digest
      AND json_extract(CAST(NEW.cleanup_json AS TEXT), '$.runner_cleanup.staging_neutralization.receipt_digest') = NEW.staging_neutralization_receipt_digest
      AND json_extract(CAST(NEW.cleanup_json AS TEXT), '$.runner_cleanup.staging_neutralization.capture_id') = NEW.capture_id
      AND json_extract(CAST(NEW.cleanup_json AS TEXT), '$.runner_cleanup.staging_neutralization.aggregate_zero_length') = 0
      AND json_extract(CAST(NEW.cleanup_json AS TEXT), '$.runner_cleanup.detected_journal_head.generation') = NEW.detected_head_generation
      AND json_extract(CAST(NEW.cleanup_json AS TEXT), '$.runner_cleanup.detected_journal_head.record_digest') = NEW.detected_head_digest
      AND json_extract(CAST(NEW.cleanup_json AS TEXT), '$.runner_cleanup.cleanup_intended_journal_head.generation') = NEW.cleanup_intended_head_generation
      AND json_extract(CAST(NEW.cleanup_json AS TEXT), '$.runner_cleanup.cleanup_intended_journal_head.record_digest') = NEW.cleanup_intended_head_digest
      AND json_extract(CAST(NEW.cleanup_json AS TEXT), '$.runner_cleanup.cleaned_journal_head.generation') = NEW.cleaned_head_generation
      AND json_extract(CAST(NEW.cleanup_json AS TEXT), '$.runner_cleanup.cleaned_journal_head.record_digest') = NEW.cleaned_head_digest
      AND json_extract(CAST(NEW.cleanup_json AS TEXT), '$.runner_cleanup.rejected_terminal_journal_head.generation') = NEW.rejected_terminal_head_generation
      AND json_extract(CAST(NEW.cleanup_json AS TEXT), '$.runner_cleanup.rejected_terminal_journal_head.record_digest') = NEW.rejected_terminal_head_digest
      AND json_extract(CAST(NEW.cleanup_json AS TEXT), '$.runner_cleanup.cleanup_receipt_id') = NEW.runner_cleanup_receipt_id
      AND json_extract(CAST(NEW.cleanup_json AS TEXT), '$.runner_cleanup.cleanup_receipt_digest') = NEW.runner_cleanup_receipt_digest
      AND json_extract(CAST(NEW.cleanup_json AS TEXT), '$.command_domain_cleanup_proof_id') = NEW.command_domain_cleanup_proof_id
      AND json_extract(CAST(NEW.cleanup_json AS TEXT), '$.cleanup_receipt_digest') = NEW.cleanup_receipt_digest
)
BEGIN SELECT RAISE(ABORT, 'sensitive-output cleanup must match exact rejection anchor'); END;

CREATE TABLE command_output_sensitive_rejection_closures_v29 (
    closure_digest TEXT PRIMARY KEY NOT NULL CHECK (
        length(closure_digest) = 64 AND closure_digest NOT GLOB '*[^0-9a-f]*'
    ),
    obligation_id TEXT NOT NULL UNIQUE,
    capture_id TEXT NOT NULL UNIQUE,
    effect_id TEXT NOT NULL UNIQUE,
    observation_id TEXT NOT NULL UNIQUE,
    rejection_anchor_digest TEXT NOT NULL UNIQUE,
    cleanup_receipt_digest TEXT NOT NULL UNIQUE,
    command_domain_cleanup_proof_id TEXT NOT NULL UNIQUE,
    reconciliation_claim_id TEXT UNIQUE,
    reconciliation_fencing_token TEXT UNIQUE,
    closed_at_unix_ms INTEGER NOT NULL CHECK (closed_at_unix_ms > 0),
    contract_version INTEGER NOT NULL CHECK (contract_version > 0),
    closure_json BLOB NOT NULL CHECK (
        length(closure_json) > 0
        AND closure_digest = grok_sensitive_output_closure_v29_digest(closure_json)
    ),
    CHECK ((reconciliation_claim_id IS NULL) = (reconciliation_fencing_token IS NULL)),
    FOREIGN KEY (obligation_id)
        REFERENCES command_output_capture_reconciliation_obligations(obligation_id)
        ON DELETE RESTRICT,
    FOREIGN KEY (rejection_anchor_digest)
        REFERENCES command_output_sensitive_rejection_anchors_v29(rejection_anchor_digest)
        ON DELETE RESTRICT,
    FOREIGN KEY (cleanup_receipt_digest)
        REFERENCES command_output_sensitive_rejection_cleanup_receipts_v29(cleanup_receipt_digest)
        ON DELETE RESTRICT,
    FOREIGN KEY (command_domain_cleanup_proof_id)
        REFERENCES command_domain_cleanup_proofs(proof_id)
        ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED,
    FOREIGN KEY (reconciliation_claim_id)
        REFERENCES command_output_capture_reconciliation_claims(claim_id) ON DELETE RESTRICT
) STRICT, WITHOUT ROWID;

CREATE TRIGGER command_output_sensitive_rejection_closure_exact
BEFORE INSERT ON command_output_sensitive_rejection_closures_v29
WHEN NOT EXISTS (
    SELECT 1
    FROM command_output_capture_reconciliation_obligations obligation
    JOIN command_output_sensitive_rejection_anchors_v29 anchor
      ON anchor.capture_id = obligation.capture_id AND anchor.effect_id = obligation.effect_id
    JOIN command_output_sensitive_rejection_cleanup_receipts_v29 cleanup
      ON cleanup.rejection_anchor_digest = anchor.rejection_anchor_digest
    WHERE obligation.obligation_id = NEW.obligation_id
      AND obligation.capture_id = NEW.capture_id
      AND obligation.effect_id = NEW.effect_id
      AND anchor.observation_id = NEW.observation_id
      AND anchor.rejection_anchor_digest = NEW.rejection_anchor_digest
      AND cleanup.cleanup_receipt_digest = NEW.cleanup_receipt_digest
      AND cleanup.command_domain_cleanup_proof_id = NEW.command_domain_cleanup_proof_id
      AND cleanup.contract_version = NEW.contract_version
      AND NOT EXISTS (
          SELECT 1 FROM command_output_capture_terminal_anchors
          WHERE capture_id = NEW.capture_id OR effect_id = NEW.effect_id
      )
      AND NOT EXISTS (
          SELECT 1 FROM command_output_capture_reconciliation_obligation_closures
          WHERE capture_id = NEW.capture_id OR effect_id = NEW.effect_id
      )
      AND NOT EXISTS (
          SELECT 1 FROM command_output_artifact_sets WHERE effect_id = NEW.effect_id
      )
      AND (
          (NEW.reconciliation_claim_id IS NULL AND NOT EXISTS (
              SELECT 1
              FROM command_output_capture_reconciliation_claims claim
              LEFT JOIN command_output_capture_reconciliation_claim_releases release
                ON release.claim_id = claim.claim_id
              WHERE claim.capture_id = NEW.capture_id AND release.claim_id IS NULL
          ))
          OR EXISTS (
              SELECT 1 FROM command_output_capture_reconciliation_claims claim
              LEFT JOIN command_output_capture_reconciliation_claim_releases release
                ON release.claim_id = claim.claim_id
              WHERE claim.claim_id = NEW.reconciliation_claim_id
                AND claim.capture_id = NEW.capture_id
                AND claim.fencing_token = NEW.reconciliation_fencing_token
                AND claim.contract_version = NEW.contract_version
                AND claim.claim_epoch = (
                    SELECT MAX(latest.claim_epoch)
                    FROM command_output_capture_reconciliation_claims latest
                    WHERE latest.capture_id = claim.capture_id
                )
                AND release.claim_id IS NULL
                AND claim.acquired_at_unix_ms <= NEW.closed_at_unix_ms
                AND NEW.closed_at_unix_ms < claim.expires_at_unix_ms
          )
      )
      AND json_extract(CAST(NEW.closure_json AS TEXT), '$.closure_digest') = NEW.closure_digest
      AND json_extract(CAST(NEW.closure_json AS TEXT), '$.obligation_id') = NEW.obligation_id
      AND json_extract(CAST(NEW.closure_json AS TEXT), '$.capture_id') = NEW.capture_id
      AND json_extract(CAST(NEW.closure_json AS TEXT), '$.effect_id') = NEW.effect_id
      AND json_extract(CAST(NEW.closure_json AS TEXT), '$.observation_id') = NEW.observation_id
      AND json_extract(CAST(NEW.closure_json AS TEXT), '$.rejection_anchor_digest') = NEW.rejection_anchor_digest
      AND json_extract(CAST(NEW.closure_json AS TEXT), '$.cleanup_receipt_digest') = NEW.cleanup_receipt_digest
      AND json_extract(CAST(NEW.closure_json AS TEXT), '$.command_domain_cleanup_proof_id') = NEW.command_domain_cleanup_proof_id
      AND json_extract(CAST(NEW.closure_json AS TEXT), '$.closed_at_unix_ms') = NEW.closed_at_unix_ms
      AND json_extract(CAST(NEW.closure_json AS TEXT), '$.contract_version') = NEW.contract_version
)
BEGIN SELECT RAISE(ABORT, 'sensitive-output closure must be exact and mutually exclusive'); END;

-- The existing v27 release table has a frozen FK to v27 terminal anchors.
-- Restart rejection therefore consumes its exact latest claim through this
-- additive, equally immutable release family bound to the final v29 head.
CREATE TABLE command_output_sensitive_rejection_claim_releases_v29 (
    claim_id TEXT PRIMARY KEY NOT NULL,
    capture_id TEXT NOT NULL,
    claim_epoch INTEGER NOT NULL CHECK (claim_epoch > 0),
    fencing_token TEXT NOT NULL UNIQUE,
    rejection_anchor_digest TEXT NOT NULL UNIQUE,
    closure_digest TEXT NOT NULL UNIQUE,
    released_at_unix_ms INTEGER NOT NULL CHECK (released_at_unix_ms > 0),
    contract_version INTEGER NOT NULL CHECK (contract_version > 0),
    FOREIGN KEY (claim_id)
        REFERENCES command_output_capture_reconciliation_claims(claim_id) ON DELETE RESTRICT,
    FOREIGN KEY (rejection_anchor_digest)
        REFERENCES command_output_sensitive_rejection_anchors_v29(rejection_anchor_digest)
        ON DELETE RESTRICT,
    FOREIGN KEY (closure_digest)
        REFERENCES command_output_sensitive_rejection_closures_v29(closure_digest)
        ON DELETE RESTRICT
) STRICT, WITHOUT ROWID;

CREATE TRIGGER command_output_sensitive_rejection_claim_release_exact
BEFORE INSERT ON command_output_sensitive_rejection_claim_releases_v29
WHEN NOT EXISTS (
    SELECT 1
    FROM command_output_capture_reconciliation_claims claim
    JOIN command_output_sensitive_rejection_closures_v29 closure
      ON closure.reconciliation_claim_id = claim.claim_id
     AND closure.reconciliation_fencing_token = claim.fencing_token
    JOIN command_output_sensitive_rejection_anchors_v29 anchor
      ON anchor.rejection_anchor_digest = closure.rejection_anchor_digest
    LEFT JOIN command_output_capture_reconciliation_claim_releases old_release
      ON old_release.claim_id = claim.claim_id
    WHERE claim.claim_id = NEW.claim_id
      AND claim.capture_id = NEW.capture_id
      AND claim.claim_epoch = NEW.claim_epoch
      AND claim.fencing_token = NEW.fencing_token
      AND claim.contract_version = NEW.contract_version
      AND claim.claim_epoch = (
          SELECT MAX(latest.claim_epoch)
          FROM command_output_capture_reconciliation_claims latest
          WHERE latest.capture_id = claim.capture_id
      )
      AND old_release.claim_id IS NULL
      AND closure.closure_digest = NEW.closure_digest
      AND closure.capture_id = NEW.capture_id
      AND closure.rejection_anchor_digest = NEW.rejection_anchor_digest
      AND closure.closed_at_unix_ms = NEW.released_at_unix_ms
      AND claim.acquired_at_unix_ms <= NEW.released_at_unix_ms
      AND NEW.released_at_unix_ms < claim.expires_at_unix_ms
)
BEGIN SELECT RAISE(ABORT, 'v29 claim release must consume exact latest claim and final head'); END;

CREATE TRIGGER command_output_capture_reconciliation_release_rejects_v29_sensitive_release
BEFORE INSERT ON command_output_capture_reconciliation_claim_releases
WHEN EXISTS (
    SELECT 1 FROM command_output_sensitive_rejection_claim_releases_v29
    WHERE claim_id = NEW.claim_id
)
BEGIN SELECT RAISE(ABORT, 'legacy and v29 claim releases are mutually exclusive'); END;

CREATE TRIGGER command_output_sensitive_rejection_claim_releases_no_update
BEFORE UPDATE ON command_output_sensitive_rejection_claim_releases_v29
BEGIN SELECT RAISE(ABORT, 'v29 sensitive rejection claim releases are immutable'); END;
CREATE TRIGGER command_output_sensitive_rejection_claim_releases_no_delete
BEFORE DELETE ON command_output_sensitive_rejection_claim_releases_v29
BEGIN SELECT RAISE(ABORT, 'v29 sensitive rejection claim releases are immutable'); END;

-- Preserve the v11 lifecycle check while admitting the repository-mandated
-- detection -> cleanup -> final rejection -> coordinator-observation ordering.
DROP TRIGGER command_domain_cleanup_proof_requires_exact_effect;
CREATE TRIGGER command_domain_cleanup_proof_requires_exact_effect_v29
BEFORE INSERT ON command_domain_cleanup_proofs
WHEN EXISTS (
    SELECT 1 FROM sprint_completion_proof_states WHERE sprint_id = NEW.sprint_id
) OR EXISTS (
    SELECT 1 FROM sprint_non_success_terminal_outcomes WHERE sprint_id = NEW.sprint_id
) OR EXISTS (
    SELECT 1 FROM sprint_terminal_states WHERE sprint_id = NEW.sprint_id
) OR NOT EXISTS (
    SELECT 1
    FROM effect_intents intent
    JOIN effect_request_payloads request
      ON request.effect_id = intent.effect_id AND request.sprint_id = intent.sprint_id
    JOIN effect_session_bindings binding
      ON binding.effect_id = intent.effect_id AND binding.sprint_id = intent.sprint_id
    JOIN runner_launch_intents launch
      ON launch.launch_id = binding.launch_id AND launch.sprint_id = binding.sprint_id
    JOIN runner_session_policies session
      ON session.session_id = binding.session_id
     AND session.sprint_id = binding.sprint_id
     AND session.launch_id = launch.launch_id
    LEFT JOIN effect_observations observation
      ON observation.effect_id = intent.effect_id AND observation.sprint_id = intent.sprint_id
    LEFT JOIN effect_evidence_payloads evidence
      ON evidence.effect_id = intent.effect_id AND evidence.sprint_id = intent.sprint_id
    WHERE intent.effect_id = NEW.effect_id
      AND intent.sprint_id = NEW.sprint_id
      AND intent.effect_kind = 'RunCommand'
      AND intent.request_digest = NEW.request_digest
      AND request.request_digest = NEW.request_digest
      AND binding.launch_id = NEW.launch_id
      AND binding.session_id = NEW.session_id
      AND launch.session_id = NEW.session_id
      AND session.purpose IN ('TaskWorker', 'FinalVerifier')
      AND NEW.observation_id IS observation.observation_id
      AND (observation.observation_id IS NULL
           OR (evidence.observation_id = observation.observation_id
               AND evidence.evidence_digest = observation.evidence_digest))
      AND (NEW.disposition = 'ReapedZeroSurvivors'
           OR (NEW.disposition = 'NoDomainCreatedBeforeEffect'
               AND observation.outcome IN ('FailedBeforeEffect', 'CancelledBeforeEffect')))
      AND (observation.outcome IS NULL
           OR observation.outcome IN (
               'Succeeded', 'FailedBeforeEffect', 'FailedAfterKnownEffect',
               'CancelledBeforeEffect', 'Unknown'
           ))
      AND session.registered_at_unix_ms <= NEW.cleaned_at_unix_ms
      AND intent.created_at_unix_ms <= NEW.cleaned_at_unix_ms
      AND (
          COALESCE(observation.observed_at_unix_ms, intent.created_at_unix_ms)
              <= NEW.cleaned_at_unix_ms
          OR EXISTS (
              SELECT 1
              FROM command_output_sensitive_rejection_cleanup_receipts_v29 cleanup
              JOIN command_output_sensitive_rejection_anchors_v29 anchor
                ON anchor.rejection_anchor_digest = cleanup.rejection_anchor_digest
              JOIN command_output_sensitive_rejection_closures_v29 closure
                ON closure.rejection_anchor_digest = anchor.rejection_anchor_digest
               AND closure.cleanup_receipt_digest = cleanup.cleanup_receipt_digest
              WHERE cleanup.command_domain_cleanup_proof_id = NEW.proof_id
                AND anchor.effect_id = intent.effect_id
                AND anchor.observation_id = observation.observation_id
                AND observation.outcome = 'FailedAfterKnownEffect'
                AND NEW.cleaned_at_unix_ms = closure.closed_at_unix_ms
                AND closure.closed_at_unix_ms <= observation.observed_at_unix_ms
          )
      )
)
BEGIN SELECT RAISE(ABORT, 'command-domain cleanup proof must bind one exact command lifecycle'); END;

-- The proof is inserted after the observation because its authority
-- trigger requires that observation. This reciprocal trigger closes the
-- deferred-FK ordering gap and requires exact post-effect emptiness.
CREATE TRIGGER command_domain_cleanup_proofs_exact_sensitive_rejection_v29
BEFORE INSERT ON command_domain_cleanup_proofs
WHEN EXISTS (
    SELECT 1 FROM command_output_sensitive_rejection_cleanup_receipts_v29 cleanup
    WHERE cleanup.command_domain_cleanup_proof_id = NEW.proof_id
) AND NOT EXISTS (
    SELECT 1
    FROM command_output_sensitive_rejection_cleanup_receipts_v29 cleanup
    JOIN command_output_sensitive_rejection_anchors_v29 anchor
      ON anchor.rejection_anchor_digest = cleanup.rejection_anchor_digest
    JOIN command_output_capture_intents intent
      ON intent.capture_id = anchor.capture_id AND intent.effect_id = anchor.effect_id
    JOIN command_output_sensitive_rejection_closures_v29 closure
      ON closure.rejection_anchor_digest = anchor.rejection_anchor_digest
     AND closure.cleanup_receipt_digest = cleanup.cleanup_receipt_digest
    WHERE cleanup.command_domain_cleanup_proof_id = NEW.proof_id
      AND NEW.sprint_id = intent.sprint_id
      AND NEW.launch_id = intent.runner_launch_id
      AND NEW.session_id = intent.runner_session_id
      AND NEW.effect_id = intent.effect_id
      AND NEW.observation_id = anchor.observation_id
      AND NEW.request_digest = intent.request_digest
      AND NEW.disposition = 'ReapedZeroSurvivors'
      AND NEW.surviving_processes = 0
      AND NEW.contract_version = intent.contract_version
      AND NEW.cleaned_at_unix_ms = closure.closed_at_unix_ms
)
BEGIN SELECT RAISE(ABORT, 'command cleanup must prove exact sensitive-rejection domain empty'); END;

CREATE TRIGGER command_domain_cleanup_proofs_exact_clean_scan_profile_v29
BEFORE INSERT ON command_domain_cleanup_proofs
WHEN EXISTS (
    SELECT 1
    FROM command_output_clean_scan_publication_receipts_v29 clean
    JOIN command_output_capture_terminal_validations validation
      ON validation.terminal_anchor_digest = clean.terminal_anchor_digest
    WHERE validation.command_domain_cleanup_proof_id = NEW.proof_id
) AND NOT EXISTS (
    SELECT 1
    FROM command_output_clean_scan_publication_receipts_v29 clean
    JOIN command_output_capture_terminal_validations validation
      ON validation.terminal_anchor_digest = clean.terminal_anchor_digest
     AND validation.capture_id = clean.capture_id
     AND validation.effect_id = clean.effect_id
     AND validation.observation_id = clean.observation_id
    WHERE validation.command_domain_cleanup_proof_id = NEW.proof_id
      AND NEW.effect_id = clean.effect_id
      AND NEW.observation_id = clean.observation_id
      AND NEW.surviving_processes = 0
      AND NEW.disposition = 'ReapedZeroSurvivors'
      AND (
          (NEW.backend = 'LinuxCgroupV2' AND clean.linux_dumpable_disabled = 1)
          OR (NEW.backend = 'MacOsDedicatedIdentity'
              AND clean.linux_dumpable_disabled IS NULL)
      )
)
BEGIN SELECT RAISE(ABORT, 'clean-scan core-dump profile must match command platform'); END;

-- Symmetric XOR: neither proof family can be attached after the other.
CREATE TRIGGER command_output_capture_terminal_rejects_v29_sensitive_rejection
BEFORE INSERT ON command_output_capture_terminal_anchors
WHEN EXISTS (
    SELECT 1 FROM command_output_sensitive_rejection_anchors_v29
    WHERE capture_id = NEW.capture_id OR effect_id = NEW.effect_id
)
BEGIN SELECT RAISE(ABORT, 'v27 terminal cannot coexist with v29 sensitive rejection'); END;

CREATE TRIGGER command_output_capture_published_requires_clean_scan_v29
BEFORE INSERT ON command_output_capture_terminal_anchors
WHEN EXISTS (
    SELECT 1 FROM command_output_sensitive_detection_policy_admissions_v29 policy
    WHERE policy.capture_id = NEW.capture_id AND policy.effect_id = NEW.effect_id
) AND (
    (NEW.disposition = 'Published' AND NOT EXISTS (
        SELECT 1
        FROM command_output_clean_scan_publication_receipts_v29 clean
        WHERE clean.capture_id = NEW.capture_id
          AND clean.effect_id = NEW.effect_id
          AND clean.observation_id = NEW.observation_id
          AND clean.intent_digest = NEW.intent_digest
          AND clean.acquired_anchor_digest = NEW.acquired_anchor_digest
          AND clean.terminal_prepared_store_head_generation = NEW.store_head_generation
          AND clean.terminal_prepared_store_head_digest = NEW.store_head_digest
          AND clean.terminal_record_digest = NEW.terminal_record_digest
          AND clean.terminal_anchor_digest = NEW.terminal_anchor_digest
          AND clean.terminal_prepared_at_unix_ms <= NEW.anchored_at_unix_ms
          AND clean.layout_version = NEW.layout_version
          AND clean.contract_version = NEW.contract_version
          AND grok_sensitive_output_clean_scan_v29_digest(clean.clean_scan_receipt_json) =
              clean.clean_scan_receipt_digest
    ))
    OR (NEW.disposition != 'Published' AND EXISTS (
        SELECT 1 FROM command_output_clean_scan_publication_receipts_v29 clean
        WHERE clean.capture_id = NEW.capture_id OR clean.effect_id = NEW.effect_id
    ))
)
BEGIN SELECT RAISE(ABORT, 'current-policy Published terminal requires exact clean-scan receipt'); END;

-- Current-policy Unknown resolution is symmetric with direct publication: a
-- Published row requires the exact staged resolution-specific clean receipt,
-- while an Abandoned row rejects any such receipt. Historical v27 captures
-- continue only through their immutable positive migration exemptions.
CREATE TRIGGER command_output_current_unknown_resolution_requires_clean_scan_v29
BEFORE INSERT ON command_output_capture_reconciliation_resolutions
WHEN EXISTS (
    SELECT 1
    FROM command_output_sensitive_detection_policy_admissions_v29 policy
    WHERE policy.capture_id = NEW.capture_id
      AND policy.effect_id = NEW.effect_id
 ) AND (
    (NEW.disposition = 'Published' AND NOT EXISTS (
        SELECT 1
        FROM command_output_clean_scan_resolution_receipts_v29 clean
        JOIN command_output_capture_restart_recovery_receipts physical
          ON physical.receipt_digest = NEW.physical_recovery_receipt_digest
         AND physical.capture_id = NEW.capture_id
         AND physical.effect_id = NEW.effect_id
         AND physical.reconciliation_claim_id = NEW.reconciliation_claim_id
         AND physical.reconciliation_fencing_token = NEW.reconciliation_fencing_token
         AND physical.observed_state = 'TerminalPrepared'
        WHERE clean.capture_id = NEW.capture_id
          AND clean.effect_id = NEW.effect_id
          AND clean.observation_id = NEW.observation_id
          AND clean.terminal_anchor_digest = NEW.terminal_anchor_digest
          AND clean.reconciliation_claim_id = NEW.reconciliation_claim_id
          AND clean.reconciliation_fencing_token = NEW.reconciliation_fencing_token
          AND clean.resolution_anchor_digest = NEW.resolution_anchor_digest
          AND clean.artifact_manifest_digest = NEW.artifact_manifest_digest
          AND clean.resolution_store_head_generation = NEW.store_head_generation
          AND clean.resolution_store_head_digest = NEW.store_head_digest
          AND clean.resolution_record_digest = NEW.resolution_record_digest
          AND clean.resolved_at_unix_ms = NEW.resolved_at_unix_ms
          AND clean.layout_version = NEW.layout_version
          AND clean.contract_version = NEW.contract_version
          AND json_extract(CAST(physical.receipt_json AS TEXT),
                           '$.lifecycle_history[1].store_head.generation') =
              json_extract(CAST(clean.clean_scan_resolution_receipt_json AS TEXT),
                           '$.clean_runner.acquired_store_head.generation')
          AND json_extract(CAST(physical.receipt_json AS TEXT),
                           '$.lifecycle_history[1].store_head.record_digest') =
              json_extract(CAST(clean.clean_scan_resolution_receipt_json AS TEXT),
                           '$.clean_runner.acquired_store_head.record_digest')
          AND json_extract(CAST(physical.receipt_json AS TEXT),
                           '$.lifecycle_history[2].store_head.generation') =
              json_extract(CAST(clean.clean_scan_resolution_receipt_json AS TEXT),
                           '$.clean_runner.writer_attached_store_head.generation')
          AND json_extract(CAST(physical.receipt_json AS TEXT),
                           '$.lifecycle_history[2].store_head.record_digest') =
              json_extract(CAST(clean.clean_scan_resolution_receipt_json AS TEXT),
                           '$.clean_runner.writer_attached_store_head.record_digest')
          AND json_extract(CAST(physical.receipt_json AS TEXT),
                           '$.lifecycle_history[3].store_head.generation') =
              json_extract(CAST(clean.clean_scan_resolution_receipt_json AS TEXT),
                           '$.clean_runner.launch_intended_store_head.generation')
          AND json_extract(CAST(physical.receipt_json AS TEXT),
                           '$.lifecycle_history[3].store_head.record_digest') =
              json_extract(CAST(clean.clean_scan_resolution_receipt_json AS TEXT),
                           '$.clean_runner.launch_intended_store_head.record_digest')
          AND json_extract(CAST(physical.receipt_json AS TEXT),
                           '$.lifecycle_history[4].store_head.generation') =
              json_extract(CAST(clean.clean_scan_resolution_receipt_json AS TEXT),
                           '$.clean_runner.finished_store_head.generation')
          AND json_extract(CAST(physical.receipt_json AS TEXT),
                           '$.lifecycle_history[4].store_head.record_digest') =
              json_extract(CAST(clean.clean_scan_resolution_receipt_json AS TEXT),
                           '$.clean_runner.finished_store_head.record_digest')
          AND json_extract(CAST(physical.receipt_json AS TEXT),
                           '$.lifecycle_history[5].store_head.generation') =
              json_extract(CAST(clean.clean_scan_resolution_receipt_json AS TEXT),
                           '$.clean_runner.published_store_head.generation')
          AND json_extract(CAST(physical.receipt_json AS TEXT),
                           '$.lifecycle_history[5].store_head.record_digest') =
              json_extract(CAST(clean.clean_scan_resolution_receipt_json AS TEXT),
                           '$.clean_runner.published_store_head.record_digest')
          AND json_extract(CAST(physical.receipt_json AS TEXT),
                           '$.lifecycle_history[6].store_head.generation') =
              clean.terminal_prepared_store_head_generation
          AND json_extract(CAST(physical.receipt_json AS TEXT),
                           '$.lifecycle_history[6].store_head.record_digest') =
              clean.terminal_prepared_store_head_digest
          AND grok_sensitive_output_clean_scan_resolution_v29_digest(
                  clean.clean_scan_resolution_receipt_json
              ) = clean.clean_scan_resolution_receipt_digest
    ))
    OR (NEW.disposition != 'Published' AND EXISTS (
        SELECT 1 FROM command_output_clean_scan_resolution_receipts_v29 clean
        WHERE clean.capture_id = NEW.capture_id OR clean.effect_id = NEW.effect_id
    ))
 )
BEGIN SELECT RAISE(ABORT, 'current-policy Unknown publication requires exact clean-scan resolution receipt'); END;

CREATE TRIGGER command_output_capture_closure_rejects_v29_sensitive_rejection
BEFORE INSERT ON command_output_capture_reconciliation_obligation_closures
WHEN EXISTS (
    SELECT 1 FROM command_output_sensitive_rejection_anchors_v29
    WHERE capture_id = NEW.capture_id OR effect_id = NEW.effect_id
)
BEGIN SELECT RAISE(ABORT, 'v27 closure cannot coexist with v29 sensitive rejection'); END;

CREATE TRIGGER command_output_artifact_sets_reject_v29_sensitive_rejection
BEFORE INSERT ON command_output_artifact_sets
WHEN EXISTS (
    SELECT 1 FROM command_output_sensitive_rejection_anchors_v29
    WHERE effect_id = NEW.effect_id
)
BEGIN SELECT RAISE(ABORT, 'sensitive-output rejection cannot retain an artifact'); END;

CREATE TRIGGER command_output_reconciliation_claims_reject_v29_closed_capture
BEFORE INSERT ON command_output_capture_reconciliation_claims
WHEN EXISTS (
    SELECT 1 FROM command_output_sensitive_rejection_closures_v29
    WHERE capture_id = NEW.capture_id
)
BEGIN SELECT RAISE(ABORT, 'closed sensitive-output capture cannot be reclaimed'); END;

CREATE TRIGGER command_output_sensitive_rejection_anchors_no_update
BEFORE UPDATE ON command_output_sensitive_rejection_anchors_v29
BEGIN SELECT RAISE(ABORT, 'sensitive-output rejection anchors are immutable'); END;
CREATE TRIGGER command_output_sensitive_rejection_anchors_no_delete
BEFORE DELETE ON command_output_sensitive_rejection_anchors_v29
BEGIN SELECT RAISE(ABORT, 'sensitive-output rejection anchors are immutable'); END;
CREATE TRIGGER command_output_sensitive_rejection_cleanup_no_update
BEFORE UPDATE ON command_output_sensitive_rejection_cleanup_receipts_v29
BEGIN SELECT RAISE(ABORT, 'sensitive-output cleanup receipts are immutable'); END;
CREATE TRIGGER command_output_sensitive_rejection_cleanup_no_delete
BEFORE DELETE ON command_output_sensitive_rejection_cleanup_receipts_v29
BEGIN SELECT RAISE(ABORT, 'sensitive-output cleanup receipts are immutable'); END;
CREATE TRIGGER command_output_sensitive_rejection_closures_no_update
BEFORE UPDATE ON command_output_sensitive_rejection_closures_v29
BEGIN SELECT RAISE(ABORT, 'sensitive-output rejection closures are immutable'); END;
CREATE TRIGGER command_output_sensitive_rejection_closures_no_delete
BEFORE DELETE ON command_output_sensitive_rejection_closures_v29
BEGIN SELECT RAISE(ABORT, 'sensitive-output rejection closures are immutable'); END;

-- Replace only the v27 observation gate. Its original branch is preserved
-- verbatim and a complete v29 branch is added; a partial rejection never lets
-- the observation commit.
DROP TRIGGER effect_observations_require_v27_capture_terminal;
CREATE TRIGGER effect_observations_require_current_capture_terminal
BEFORE INSERT ON effect_observations
WHEN EXISTS (
    SELECT 1 FROM command_output_capture_intents WHERE effect_id = NEW.effect_id
) AND NOT EXISTS (
    SELECT 1 FROM command_output_capture_terminal_anchors terminal
    JOIN command_output_capture_terminal_validations validation
      ON validation.terminal_anchor_digest = terminal.terminal_anchor_digest
    WHERE terminal.effect_id = NEW.effect_id
      AND terminal.observation_id = NEW.observation_id
      AND terminal.observation_class = NEW.outcome
      AND terminal.contract_version = NEW.contract_version
      AND (
          terminal.disposition != 'Published'
          OR EXISTS (
              SELECT 1
              FROM pre_v29_sensitive_output_policy_exemptions exemption
              WHERE exemption.capture_id = terminal.capture_id
                AND exemption.effect_id = terminal.effect_id
                AND exemption.intent_digest = terminal.intent_digest
          )
          OR EXISTS (
              SELECT 1
              FROM command_output_clean_scan_publication_receipts_v29 clean
              WHERE clean.capture_id = terminal.capture_id
                AND clean.effect_id = terminal.effect_id
                AND clean.observation_id = terminal.observation_id
                AND clean.terminal_anchor_digest = terminal.terminal_anchor_digest
                AND clean.terminal_prepared_store_head_generation = terminal.store_head_generation
                AND clean.terminal_prepared_store_head_digest = terminal.store_head_digest
                AND clean.terminal_record_digest = terminal.terminal_record_digest
          )
      )
      AND (
          validation.validation_kind != 'DirectClaimedUnresolved'
          OR (NEW.outcome = 'Unknown'
              AND terminal.terminal_record_digest = NEW.evidence_digest)
      )
) AND NOT EXISTS (
    SELECT 1
    FROM command_output_sensitive_rejection_anchors_v29 anchor
    JOIN command_output_sensitive_rejection_cleanup_receipts_v29 cleanup
      ON cleanup.rejection_anchor_digest = anchor.rejection_anchor_digest
    JOIN command_output_sensitive_rejection_closures_v29 closure
      ON closure.rejection_anchor_digest = anchor.rejection_anchor_digest
     AND closure.cleanup_receipt_digest = cleanup.cleanup_receipt_digest
    WHERE anchor.effect_id = NEW.effect_id
      AND anchor.observation_id = NEW.observation_id
      AND anchor.effect_evidence_digest = NEW.evidence_digest
      AND NEW.outcome = 'FailedAfterKnownEffect'
      AND NEW.observed_at_unix_ms >= closure.closed_at_unix_ms
      AND anchor.contract_version = NEW.contract_version
      AND cleanup.contract_version = NEW.contract_version
      AND closure.contract_version = NEW.contract_version
)
BEGIN SELECT RAISE(ABORT, 'RunCommand observation requires exact v27 terminal or v29 rejection'); END;

CREATE VIEW command_output_clean_scan_publication_exact_v29 AS
SELECT clean.effect_id,
       clean.capture_id,
       clean.observation_id,
       clean.clean_scan_receipt_digest,
       clean.terminal_anchor_digest,
       clean.contract_version
FROM command_output_clean_scan_publication_receipts_v29 clean
JOIN command_output_capture_intents intent
  ON intent.capture_id = clean.capture_id
 AND intent.effect_id = clean.effect_id
 AND intent.intent_digest = clean.intent_digest
 AND intent.runner_session_id = clean.runner_session_id
 AND intent.request_digest = clean.request_digest
JOIN command_output_capture_acquisitions acquired
  ON acquired.acquired_anchor_digest = clean.acquired_anchor_digest
 AND acquired.capture_id = clean.capture_id
 AND acquired.effect_id = clean.effect_id
 AND acquired.store_head_generation = clean.acquired_store_head_generation
 AND acquired.store_head_digest = clean.acquired_store_head_digest
JOIN command_output_sensitive_detection_policy_admissions_v29 policy
  ON policy.capture_id = clean.capture_id
 AND policy.effect_id = clean.effect_id
 AND policy.policy_id = clean.detector_policy_id
 AND policy.policy_version = clean.detector_policy_version
 AND policy.policy_digest = clean.detector_policy_digest
JOIN command_output_capture_terminal_anchors terminal
  ON terminal.terminal_anchor_digest = clean.terminal_anchor_digest
 AND terminal.capture_id = clean.capture_id
 AND terminal.effect_id = clean.effect_id
 AND terminal.observation_id = clean.observation_id
 AND terminal.intent_digest = clean.intent_digest
 AND terminal.acquired_anchor_digest = clean.acquired_anchor_digest
 AND terminal.disposition = 'Published'
 AND terminal.store_head_generation = clean.terminal_prepared_store_head_generation
 AND terminal.store_head_digest = clean.terminal_prepared_store_head_digest
 AND terminal.terminal_record_digest = clean.terminal_record_digest
 AND terminal.anchored_at_unix_ms >= clean.terminal_prepared_at_unix_ms
WHERE clean.contract_version = intent.contract_version
  AND clean.contract_version = acquired.contract_version
  AND clean.contract_version = policy.contract_version
  AND clean.contract_version = terminal.contract_version
  AND clean.layout_version = terminal.layout_version
  AND acquired.acquired_at_unix_ms <= clean.scanned_clean_at_unix_ms
  AND clean.scanned_clean_at_unix_ms <= clean.finished_at_unix_ms
  AND clean.finished_at_unix_ms <= clean.published_at_unix_ms
  AND clean.published_at_unix_ms <= clean.terminal_prepared_at_unix_ms
  AND grok_sensitive_output_policy_v29_canonical(policy.policy_json) = 'ok'
  AND grok_sensitive_output_clean_scan_v29_digest(clean.clean_scan_receipt_json) =
      clean.clean_scan_receipt_digest
  AND NOT EXISTS (
      SELECT 1 FROM pre_v29_sensitive_output_policy_exemptions exemption
      WHERE exemption.effect_id = clean.effect_id OR exemption.capture_id = clean.capture_id
  )
  AND NOT EXISTS (
      SELECT 1 FROM command_output_sensitive_rejection_anchors_v29 rejection
      WHERE rejection.effect_id = clean.effect_id OR rejection.capture_id = clean.capture_id
  );

CREATE VIEW command_output_clean_scan_resolution_exact_v29 AS
SELECT clean.effect_id,
       clean.capture_id,
       clean.observation_id,
       clean.clean_scan_resolution_receipt_digest,
       clean.terminal_anchor_digest,
       clean.resolution_anchor_digest,
       clean.contract_version
FROM command_output_clean_scan_resolution_receipts_v29 clean
JOIN command_output_capture_intents intent
  ON intent.capture_id = clean.capture_id
 AND intent.effect_id = clean.effect_id
 AND intent.intent_digest = clean.intent_digest
JOIN command_output_capture_acquisitions acquired
  ON acquired.acquired_anchor_digest = clean.acquired_anchor_digest
 AND acquired.capture_id = intent.capture_id
 AND acquired.effect_id = intent.effect_id
JOIN command_output_capture_terminal_anchors terminal
  ON terminal.terminal_anchor_digest = clean.terminal_anchor_digest
 AND terminal.capture_id = intent.capture_id
 AND terminal.effect_id = intent.effect_id
 AND terminal.observation_id = clean.observation_id
 AND terminal.observation_class = 'Unknown'
 AND terminal.disposition = 'ReconciliationRequired'
 AND terminal.acquired_anchor_digest = acquired.acquired_anchor_digest
 AND terminal.artifact_manifest_digest IS NULL
 AND terminal.artifact_reference_json IS NULL
JOIN command_output_capture_reconciliation_claims claim
  ON claim.claim_id = clean.reconciliation_claim_id
 AND claim.capture_id = intent.capture_id
 AND claim.fencing_token = clean.reconciliation_fencing_token
JOIN command_output_capture_reconciliation_resolutions resolution
  ON resolution.resolution_anchor_digest = clean.resolution_anchor_digest
 AND resolution.capture_id = intent.capture_id
 AND resolution.effect_id = intent.effect_id
 AND resolution.observation_id = terminal.observation_id
 AND resolution.terminal_anchor_digest = terminal.terminal_anchor_digest
 AND resolution.reconciliation_claim_id = claim.claim_id
 AND resolution.reconciliation_fencing_token = claim.fencing_token
 AND resolution.disposition = 'Published'
 AND resolution.artifact_manifest_digest = clean.artifact_manifest_digest
 AND resolution.store_head_generation = clean.resolution_store_head_generation
 AND resolution.store_head_digest = clean.resolution_store_head_digest
 AND resolution.resolution_record_digest = clean.resolution_record_digest
 AND resolution.resolved_at_unix_ms = clean.resolved_at_unix_ms
JOIN command_output_capture_restart_recovery_receipts physical
  ON physical.receipt_digest = resolution.physical_recovery_receipt_digest
 AND physical.capture_id = intent.capture_id
 AND physical.effect_id = intent.effect_id
 AND physical.reconciliation_claim_id = claim.claim_id
 AND physical.reconciliation_fencing_token = claim.fencing_token
 AND physical.observed_state = 'TerminalPrepared'
JOIN command_output_sensitive_detection_policy_admissions_v29 policy
  ON policy.capture_id = intent.capture_id
 AND policy.effect_id = intent.effect_id
 AND policy.policy_id = clean.detector_policy_id
 AND policy.policy_version = clean.detector_policy_version
 AND policy.policy_digest = clean.detector_policy_digest
WHERE clean.contract_version = intent.contract_version
  AND clean.contract_version = acquired.contract_version
  AND clean.contract_version = terminal.contract_version
  AND clean.contract_version = claim.contract_version
  AND clean.contract_version = resolution.contract_version
  AND clean.contract_version = policy.contract_version
  AND clean.layout_version = intent.layout_version
  AND clean.layout_version = terminal.layout_version
  AND clean.layout_version = resolution.layout_version
  AND clean.resolution_store_head_generation > terminal.store_head_generation
  AND clean.resolution_record_digest = clean.resolution_store_head_digest
  AND clean.terminal_prepared_store_head_generation = resolution.store_head_generation
  AND clean.terminal_prepared_store_head_digest = resolution.store_head_digest
  AND clean.terminal_prepared_at_unix_ms <= resolution.resolved_at_unix_ms
  AND json_extract(CAST(physical.receipt_json AS TEXT),
                   '$.lifecycle_history[1].store_head.generation') =
      json_extract(CAST(clean.clean_scan_resolution_receipt_json AS TEXT),
                   '$.clean_runner.acquired_store_head.generation')
  AND json_extract(CAST(physical.receipt_json AS TEXT),
                   '$.lifecycle_history[1].store_head.record_digest') =
      json_extract(CAST(clean.clean_scan_resolution_receipt_json AS TEXT),
                   '$.clean_runner.acquired_store_head.record_digest')
  AND json_extract(CAST(physical.receipt_json AS TEXT),
                   '$.lifecycle_history[2].store_head.generation') =
      json_extract(CAST(clean.clean_scan_resolution_receipt_json AS TEXT),
                   '$.clean_runner.writer_attached_store_head.generation')
  AND json_extract(CAST(physical.receipt_json AS TEXT),
                   '$.lifecycle_history[2].store_head.record_digest') =
      json_extract(CAST(clean.clean_scan_resolution_receipt_json AS TEXT),
                   '$.clean_runner.writer_attached_store_head.record_digest')
  AND json_extract(CAST(physical.receipt_json AS TEXT),
                   '$.lifecycle_history[3].store_head.generation') =
      json_extract(CAST(clean.clean_scan_resolution_receipt_json AS TEXT),
                   '$.clean_runner.launch_intended_store_head.generation')
  AND json_extract(CAST(physical.receipt_json AS TEXT),
                   '$.lifecycle_history[3].store_head.record_digest') =
      json_extract(CAST(clean.clean_scan_resolution_receipt_json AS TEXT),
                   '$.clean_runner.launch_intended_store_head.record_digest')
  AND json_extract(CAST(physical.receipt_json AS TEXT),
                   '$.lifecycle_history[4].store_head.generation') =
      json_extract(CAST(clean.clean_scan_resolution_receipt_json AS TEXT),
                   '$.clean_runner.finished_store_head.generation')
  AND json_extract(CAST(physical.receipt_json AS TEXT),
                   '$.lifecycle_history[4].store_head.record_digest') =
      json_extract(CAST(clean.clean_scan_resolution_receipt_json AS TEXT),
                   '$.clean_runner.finished_store_head.record_digest')
  AND json_extract(CAST(physical.receipt_json AS TEXT),
                   '$.lifecycle_history[5].store_head.generation') =
      json_extract(CAST(clean.clean_scan_resolution_receipt_json AS TEXT),
                   '$.clean_runner.published_store_head.generation')
  AND json_extract(CAST(physical.receipt_json AS TEXT),
                   '$.lifecycle_history[5].store_head.record_digest') =
      json_extract(CAST(clean.clean_scan_resolution_receipt_json AS TEXT),
                   '$.clean_runner.published_store_head.record_digest')
  AND json_extract(CAST(physical.receipt_json AS TEXT),
                   '$.lifecycle_history[6].store_head.generation') =
      clean.terminal_prepared_store_head_generation
  AND json_extract(CAST(physical.receipt_json AS TEXT),
                   '$.lifecycle_history[6].store_head.record_digest') =
      clean.terminal_prepared_store_head_digest
  AND grok_sensitive_output_policy_v29_canonical(policy.policy_json) = 'ok'
  AND grok_sensitive_output_clean_scan_resolution_v29_digest(
          clean.clean_scan_resolution_receipt_json
      ) = clean.clean_scan_resolution_receipt_digest
  AND NOT EXISTS (
      SELECT 1 FROM pre_v29_sensitive_output_policy_exemptions exemption
      WHERE exemption.effect_id = clean.effect_id OR exemption.capture_id = clean.capture_id
  )
  AND NOT EXISTS (
      SELECT 1 FROM command_output_clean_scan_publication_receipts_v29 direct
      WHERE direct.effect_id = clean.effect_id OR direct.capture_id = clean.capture_id
  )
  AND NOT EXISTS (
      SELECT 1 FROM command_output_sensitive_rejection_anchors_v29 rejection
      WHERE rejection.effect_id = clean.effect_id OR rejection.capture_id = clean.capture_id
  );

CREATE VIEW command_output_sensitive_rejection_exact_finishes_v29 AS
SELECT anchor.effect_id,
       anchor.contract_version,
       anchor.rejection_anchor_digest,
       cleanup.cleanup_receipt_digest,
       closure.closure_digest
FROM command_output_sensitive_rejection_anchors_v29 anchor
JOIN command_output_sensitive_rejection_cleanup_receipts_v29 cleanup
  ON cleanup.rejection_anchor_digest = anchor.rejection_anchor_digest
 AND cleanup.capture_id = anchor.capture_id
 AND cleanup.effect_id = anchor.effect_id
 AND cleanup.observation_id = anchor.observation_id
JOIN command_output_sensitive_rejection_closures_v29 closure
  ON closure.rejection_anchor_digest = anchor.rejection_anchor_digest
 AND closure.cleanup_receipt_digest = cleanup.cleanup_receipt_digest
 AND closure.command_domain_cleanup_proof_id = cleanup.command_domain_cleanup_proof_id
LEFT JOIN command_output_sensitive_rejection_claim_releases_v29 v29_release
  ON v29_release.claim_id = closure.reconciliation_claim_id
 AND v29_release.capture_id = closure.capture_id
 AND v29_release.fencing_token = closure.reconciliation_fencing_token
 AND v29_release.rejection_anchor_digest = anchor.rejection_anchor_digest
 AND v29_release.closure_digest = closure.closure_digest
 AND v29_release.released_at_unix_ms = closure.closed_at_unix_ms
JOIN command_output_capture_intents intent
  ON intent.capture_id = anchor.capture_id
 AND intent.effect_id = anchor.effect_id
 AND intent.intent_digest = anchor.intent_digest
JOIN command_output_sensitive_detection_policy_admissions_v29 policy
  ON policy.capture_id = intent.capture_id
 AND policy.effect_id = intent.effect_id
 AND policy.policy_id = anchor.detector_policy_id
 AND policy.policy_version = anchor.detector_policy_version
 AND policy.policy_digest = anchor.detector_policy_digest
JOIN command_output_capture_acquisitions acquired
  ON acquired.acquired_anchor_digest = anchor.acquired_anchor_digest
 AND acquired.capture_id = intent.capture_id
 AND acquired.effect_id = intent.effect_id
 AND acquired.dispatch_claim_id = anchor.dispatch_claim_id
JOIN effect_observations observation
  ON observation.effect_id = anchor.effect_id
 AND observation.observation_id = anchor.observation_id
 AND observation.outcome = 'FailedAfterKnownEffect'
 AND observation.evidence_digest = anchor.effect_evidence_digest
JOIN effect_evidence_payloads evidence
  ON evidence.effect_id = observation.effect_id
 AND evidence.observation_id = observation.observation_id
 AND evidence.evidence_digest = observation.evidence_digest
 AND evidence.evidence_bytes = anchor.rejection_json
JOIN command_domain_cleanup_proofs command_cleanup
  ON command_cleanup.proof_id = cleanup.command_domain_cleanup_proof_id
 AND command_cleanup.sprint_id = intent.sprint_id
 AND command_cleanup.launch_id = intent.runner_launch_id
 AND command_cleanup.session_id = intent.runner_session_id
 AND command_cleanup.effect_id = intent.effect_id
 AND command_cleanup.observation_id = observation.observation_id
 AND command_cleanup.request_digest = intent.request_digest
 AND command_cleanup.disposition = 'ReapedZeroSurvivors'
 AND command_cleanup.surviving_processes = 0
 AND command_cleanup.cleaned_at_unix_ms = closure.closed_at_unix_ms
WHERE closure.obligation_id = (
          SELECT obligation.obligation_id
          FROM command_output_capture_reconciliation_obligations obligation
          WHERE obligation.capture_id = intent.capture_id
            AND obligation.effect_id = intent.effect_id
      )
  AND closure.capture_id = intent.capture_id
  AND closure.effect_id = intent.effect_id
  AND closure.observation_id = observation.observation_id
  AND observation.observed_at_unix_ms >= closure.closed_at_unix_ms
  AND anchor.contract_version = intent.contract_version
  AND acquired.contract_version = intent.contract_version
  AND policy.contract_version = intent.contract_version
  AND cleanup.contract_version = intent.contract_version
  AND closure.contract_version = intent.contract_version
  AND observation.contract_version = intent.contract_version
  AND command_cleanup.contract_version = intent.contract_version
  AND grok_sensitive_output_policy_v29_canonical(policy.policy_json) = 'ok'
  AND grok_sensitive_output_rejection_anchor_v29_digest(anchor.rejection_json) =
      anchor.rejection_anchor_digest
  AND grok_sensitive_output_cleanup_v29_digest(cleanup.cleanup_json) =
      cleanup.cleanup_receipt_digest
  AND grok_sensitive_output_closure_v29_digest(closure.closure_json) =
      closure.closure_digest
  AND NOT EXISTS (SELECT 1 FROM command_output_capture_terminal_anchors terminal
                  WHERE terminal.capture_id = intent.capture_id)
  AND NOT EXISTS (SELECT 1 FROM command_output_capture_reconciliation_obligation_closures old
                  WHERE old.capture_id = intent.capture_id)
  AND NOT EXISTS (SELECT 1 FROM command_output_artifact_sets artifacts
                  WHERE artifacts.effect_id = intent.effect_id)
  AND NOT EXISTS (
      SELECT 1 FROM command_output_capture_reconciliation_claims claim
      LEFT JOIN command_output_capture_reconciliation_claim_releases release
        ON release.claim_id = claim.claim_id
      WHERE claim.capture_id = intent.capture_id
        AND release.claim_id IS NULL
        AND closure.reconciliation_claim_id IS NULL
  )
  AND (
      closure.reconciliation_claim_id IS NULL
      OR EXISTS (
          SELECT 1 FROM command_output_capture_reconciliation_claims claim
          WHERE claim.claim_id = closure.reconciliation_claim_id
            AND claim.capture_id = intent.capture_id
            AND claim.fencing_token = closure.reconciliation_fencing_token
            AND claim.claim_epoch = (
                SELECT MAX(latest.claim_epoch)
                FROM command_output_capture_reconciliation_claims latest
                WHERE latest.capture_id = claim.capture_id
            )
            AND v29_release.claim_id = claim.claim_id
      )
  );

CREATE VIEW command_output_exact_v27_finishes_v29 AS
SELECT terminal.effect_id, terminal.contract_version
FROM command_output_capture_terminal_anchors terminal
JOIN command_output_capture_exact_terminal_authorities_v27 exact_terminal
  ON exact_terminal.terminal_anchor_digest = terminal.terminal_anchor_digest
JOIN command_output_capture_reconciliation_obligations obligation
  ON obligation.capture_id = terminal.capture_id AND obligation.effect_id = terminal.effect_id
JOIN command_output_capture_reconciliation_obligation_closures closure
  ON closure.obligation_id = obligation.obligation_id
 AND closure.capture_id = terminal.capture_id
 AND closure.effect_id = terminal.effect_id
 AND closure.terminal_anchor_digest = terminal.terminal_anchor_digest
LEFT JOIN command_output_capture_reconciliation_resolutions resolution
  ON resolution.terminal_anchor_digest = terminal.terminal_anchor_digest
LEFT JOIN command_output_capture_exact_resolution_authorities_v27 exact_resolution
  ON exact_resolution.resolution_anchor_digest = resolution.resolution_anchor_digest
WHERE (
    (terminal.disposition IN ('Published', 'Abandoned')
     AND resolution.resolution_anchor_digest IS NULL
     AND closure.closed_at_unix_ms = terminal.anchored_at_unix_ms)
    OR (terminal.observation_class = 'Unknown'
        AND terminal.disposition = 'ReconciliationRequired'
        AND exact_resolution.resolution_anchor_digest IS NOT NULL
        AND closure.closed_at_unix_ms = resolution.resolved_at_unix_ms)
  )
  AND (
      COALESCE(resolution.disposition, terminal.disposition) != 'Published'
      OR EXISTS (
          SELECT 1 FROM pre_v29_sensitive_output_policy_exemptions exemption
          WHERE exemption.capture_id = terminal.capture_id
            AND exemption.effect_id = terminal.effect_id
            AND exemption.intent_digest = terminal.intent_digest
      )
      OR EXISTS (
          SELECT 1 FROM command_output_clean_scan_publication_exact_v29 clean
          WHERE clean.capture_id = terminal.capture_id
            AND clean.effect_id = terminal.effect_id
            AND clean.observation_id = terminal.observation_id
            AND clean.terminal_anchor_digest = terminal.terminal_anchor_digest
            AND resolution.resolution_anchor_digest IS NULL
      )
      OR EXISTS (
          SELECT 1 FROM command_output_clean_scan_resolution_exact_v29 clean_resolution
          WHERE clean_resolution.capture_id = terminal.capture_id
            AND clean_resolution.effect_id = terminal.effect_id
            AND clean_resolution.observation_id = terminal.observation_id
            AND clean_resolution.terminal_anchor_digest = terminal.terminal_anchor_digest
            AND clean_resolution.resolution_anchor_digest =
                resolution.resolution_anchor_digest
      )
  );

-- Preserve the complete v27 claim-release audit as an independent finish
-- predicate. A malformed release must not disappear merely because the
-- terminal/closure authority itself is otherwise exact.
CREATE VIEW command_output_exact_v27_claim_releases_v29 AS
SELECT release.claim_id
FROM command_output_capture_reconciliation_claim_releases release
JOIN command_output_capture_reconciliation_claims claim
  ON claim.claim_id = release.claim_id
 AND claim.capture_id = release.capture_id
 AND claim.claim_epoch = release.claim_epoch
 AND claim.fencing_token = release.fencing_token
 AND claim.contract_version = release.contract_version
WHERE release.released_at_unix_ms >= claim.acquired_at_unix_ms
  AND (
      (release.release_kind = 'Released'
       AND release.terminal_anchor_digest IS NULL
       AND release.successor_claim_id IS NULL
       AND release.successor_fencing_token IS NULL
       AND release.successor_claim_digest IS NULL)
      OR (release.release_kind = 'Expired'
          AND release.released_at_unix_ms >= claim.expires_at_unix_ms
          AND release.terminal_anchor_digest IS NULL
          AND release.successor_claim_id IS NULL
          AND release.successor_fencing_token IS NULL
          AND release.successor_claim_digest IS NULL)
      OR (release.release_kind = 'Superseded'
          AND release.released_at_unix_ms < claim.expires_at_unix_ms
          AND release.terminal_anchor_digest IS NULL
          AND EXISTS (
              SELECT 1
              FROM command_output_capture_reconciliation_claims successor
              WHERE successor.claim_id = release.successor_claim_id
                AND successor.capture_id = claim.capture_id
                AND successor.owner_id = claim.owner_id
                AND successor.claim_epoch = claim.claim_epoch + 1
                AND successor.previous_claim_id = claim.claim_id
                AND successor.fencing_token = release.successor_fencing_token
                AND successor.claim_digest = release.successor_claim_digest
                AND successor.acquired_at_unix_ms = release.released_at_unix_ms
                AND successor.contract_version = claim.contract_version
          ))
      OR (release.release_kind = 'ConsumedTerminal'
          AND release.released_at_unix_ms < claim.expires_at_unix_ms
          AND release.successor_claim_id IS NULL
          AND release.successor_fencing_token IS NULL
          AND release.successor_claim_digest IS NULL
          AND EXISTS (
              SELECT 1
              FROM command_output_capture_terminal_anchors terminal
              LEFT JOIN command_output_capture_terminal_validations validation
                ON validation.terminal_anchor_digest = terminal.terminal_anchor_digest
               AND validation.capture_id = terminal.capture_id
               AND validation.effect_id = terminal.effect_id
               AND validation.observation_id = terminal.observation_id
               AND validation.reconciliation_claim_id = claim.claim_id
               AND validation.reconciliation_fencing_token = claim.fencing_token
               AND validation.terminal_anchored_at_unix_ms =
                   release.released_at_unix_ms
               AND validation.contract_version = claim.contract_version
              WHERE terminal.terminal_anchor_digest = release.terminal_anchor_digest
                AND terminal.capture_id = claim.capture_id
                AND terminal.contract_version = claim.contract_version
                AND (
                    (terminal.observation_class = 'Unknown'
                     AND terminal.disposition = 'ReconciliationRequired'
                     AND terminal.anchored_at_unix_ms <= release.released_at_unix_ms)
                    OR (terminal.anchored_at_unix_ms = release.released_at_unix_ms
                        AND validation.validation_kind IN (
                            'RestartIntentAbandoned',
                            'RestartClaimedBeforeLaunchAbandoned',
                            'RestartClaimedUnresolved',
                            'RestartTerminalPreparedPublished',
                            'RestartReconciliation'
                        ))
                )
          ))
  );

CREATE VIEW command_output_exact_v29_claim_releases_v29 AS
SELECT release.claim_id
FROM command_output_sensitive_rejection_claim_releases_v29 release
JOIN command_output_capture_reconciliation_claims claim
  ON claim.claim_id = release.claim_id
 AND claim.capture_id = release.capture_id
 AND claim.claim_epoch = release.claim_epoch
 AND claim.fencing_token = release.fencing_token
 AND claim.contract_version = release.contract_version
JOIN command_output_sensitive_rejection_exact_finishes_v29 exact
  ON exact.rejection_anchor_digest = release.rejection_anchor_digest
JOIN command_output_sensitive_rejection_closures_v29 closure
  ON closure.closure_digest = release.closure_digest
 AND closure.rejection_anchor_digest = release.rejection_anchor_digest
 AND closure.reconciliation_claim_id = claim.claim_id
 AND closure.reconciliation_fencing_token = claim.fencing_token
 AND closure.closed_at_unix_ms = release.released_at_unix_ms
WHERE release.released_at_unix_ms >= claim.acquired_at_unix_ms
  AND release.released_at_unix_ms < claim.expires_at_unix_ms
  AND claim.claim_epoch = (
      SELECT MAX(latest.claim_epoch)
      FROM command_output_capture_reconciliation_claims latest
      WHERE latest.capture_id = claim.capture_id
  );

-- Rebuild the completion fence against the same exact v27 authorities plus
-- the additive v29 family. Pre-v27 exemptions remain historical only.
DROP TRIGGER command_output_capture_completion_obligation_fence;
CREATE TRIGGER command_output_capture_completion_obligation_fence_v29
BEFORE INSERT ON sprint_completion_proof_states
WHEN EXISTS (
    SELECT 1 FROM effect_intents effect
    WHERE effect.sprint_id = NEW.sprint_id
      AND effect.effect_kind = 'RunCommand'
      AND NOT EXISTS (
          SELECT 1 FROM pre_v27_command_output_capture_exemptions exemption
          WHERE exemption.effect_id = effect.effect_id
            AND exemption.sprint_id = effect.sprint_id
            AND exemption.request_digest = effect.request_digest
            AND exemption.created_at_unix_ms = effect.created_at_unix_ms
            AND exemption.contract_version = effect.contract_version
            AND exemption.intent_digest = grok_sha256(effect.intent_json)
      )
      AND NOT EXISTS (
          SELECT 1 FROM command_output_exact_v27_finishes_v29 old
          WHERE old.effect_id = effect.effect_id
            AND old.contract_version = NEW.contract_version
      )
      AND NOT EXISTS (
          SELECT 1 FROM command_output_sensitive_rejection_exact_finishes_v29 rejected
          WHERE rejected.effect_id = effect.effect_id
            AND rejected.contract_version = NEW.contract_version
      )
) OR EXISTS (
    SELECT 1
    FROM effect_intents effect
    JOIN pre_v27_command_output_capture_exemptions exemption
      ON exemption.effect_id = effect.effect_id
    JOIN command_output_capture_intents intent
      ON intent.effect_id = effect.effect_id
    WHERE effect.sprint_id = NEW.sprint_id
      AND effect.effect_kind = 'RunCommand'
) OR EXISTS (
    SELECT 1
    FROM effect_intents effect
    JOIN command_output_capture_intents intent
      ON intent.effect_id = effect.effect_id
    JOIN pre_v29_sensitive_output_policy_exemptions exemption
      ON exemption.effect_id = effect.effect_id
     AND exemption.capture_id = intent.capture_id
    JOIN command_output_sensitive_detection_policy_admissions_v29 policy
      ON policy.effect_id = effect.effect_id
     AND policy.capture_id = intent.capture_id
    WHERE effect.sprint_id = NEW.sprint_id
      AND effect.effect_kind = 'RunCommand'
) OR EXISTS (
    SELECT 1
    FROM effect_intents effect
    JOIN command_output_capture_intents intent
      ON intent.effect_id = effect.effect_id
    JOIN command_output_capture_reconciliation_claims claim
      ON claim.capture_id = intent.capture_id
      OR CASE WHEN json_valid(CAST(claim.claim_json AS TEXT))
              THEN json_extract(CAST(claim.claim_json AS TEXT), '$.capture_id') =
                   intent.capture_id
              ELSE 0 END
    LEFT JOIN command_output_capture_exact_reconciliation_claims_v27 exact_claim
      ON exact_claim.claim_id = claim.claim_id
    LEFT JOIN command_output_exact_v27_claim_releases_v29 old_release
      ON old_release.claim_id = claim.claim_id
    LEFT JOIN command_output_exact_v29_claim_releases_v29 v29_release
      ON v29_release.claim_id = claim.claim_id
    WHERE effect.sprint_id = NEW.sprint_id
      AND effect.effect_kind = 'RunCommand'
      AND (exact_claim.claim_id IS NULL
           OR (old_release.claim_id IS NULL AND v29_release.claim_id IS NULL))
)
BEGIN SELECT RAISE(ABORT, 'completion requires every capture obligation and claim closed'); END;
