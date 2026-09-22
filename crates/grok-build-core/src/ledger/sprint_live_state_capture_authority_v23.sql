-- Schema v23 adds descriptor-relative live-state capture without rebuilding
-- any of the closed v9/v17/v19 tables.  `LiveStateVerifier` is stored in the
-- old runner tables as `FinalVerifier`, and `CaptureWorkspaceState` is stored
-- in the old effect tables as taskless `ReadRelativeFile`.  The immutable
-- companions below are the sole semantic authority for those compatibility
-- storage classes.

CREATE TABLE sprint_live_state_capture_plans (
    plan_id TEXT PRIMARY KEY NOT NULL CHECK (length(plan_id) BETWEEN 1 AND 4096),
    sprint_id TEXT NOT NULL,
    branch TEXT NOT NULL CHECK (branch IN ('Applied', 'VerifiedNoOp')),
    final_verification_receipt_id TEXT NOT NULL
        CHECK (length(final_verification_receipt_id) BETWEEN 1 AND 4096),
    task_integration_receipt_id TEXT,
    application_receipt_id TEXT,
    rollback_reference_id TEXT,
    expected_snapshot TEXT NOT NULL CHECK (
        length(expected_snapshot) = 64
        AND expected_snapshot NOT GLOB '*[^0-9a-f]*'
    ),
    grant_hash TEXT NOT NULL CHECK (
        length(grant_hash) = 64 AND grant_hash NOT GLOB '*[^0-9a-f]*'
    ),
    policy_hash TEXT NOT NULL CHECK (
        length(policy_hash) = 64 AND policy_hash NOT GLOB '*[^0-9a-f]*'
    ),
    policy_version INTEGER NOT NULL CHECK (policy_version > 0),
    source_event_id TEXT NOT NULL CHECK (length(source_event_id) BETWEEN 1 AND 4096),
    source_event_sequence INTEGER NOT NULL CHECK (source_event_sequence > 0),
    required_cleanup_set_digest TEXT NOT NULL CHECK (
        length(required_cleanup_set_digest) = 64
        AND required_cleanup_set_digest NOT GLOB '*[^0-9a-f]*'
    ),
    required_cleanup_count INTEGER NOT NULL CHECK (required_cleanup_count >= 1),
    plan_digest TEXT NOT NULL UNIQUE CHECK (
        length(plan_digest) = 64 AND plan_digest NOT GLOB '*[^0-9a-f]*'
    ),
    contract_version INTEGER NOT NULL CHECK (contract_version > 0),
    planned_at_unix_ms INTEGER NOT NULL CHECK (planned_at_unix_ms > 0),
    plan_json BLOB NOT NULL CHECK (length(plan_json) BETWEEN 1 AND 1048576),
    execution_policy_json BLOB NOT NULL CHECK (
        length(execution_policy_json) BETWEEN 1 AND 1048576
    ),
    UNIQUE (sprint_id, plan_id),
    CHECK (
        (branch = 'Applied'
         AND task_integration_receipt_id IS NULL
         AND application_receipt_id IS NOT NULL
         AND rollback_reference_id IS NOT NULL)
        OR
        (branch = 'VerifiedNoOp'
         AND task_integration_receipt_id IS NOT NULL
         AND application_receipt_id IS NULL
         AND rollback_reference_id IS NULL)
    ),
    FOREIGN KEY (sprint_id) REFERENCES sprints(sprint_id) ON DELETE RESTRICT,
    FOREIGN KEY (sprint_id, final_verification_receipt_id)
        REFERENCES verification_receipts(sprint_id, receipt_id) ON DELETE RESTRICT,
    FOREIGN KEY (sprint_id, task_integration_receipt_id)
        REFERENCES task_integration_receipts(sprint_id, receipt_id) ON DELETE RESTRICT,
    FOREIGN KEY (sprint_id, application_receipt_id)
        REFERENCES application_receipts(sprint_id, receipt_id) ON DELETE RESTRICT,
    FOREIGN KEY (sprint_id, rollback_reference_id)
        REFERENCES rollback_references(sprint_id, reference_id) ON DELETE RESTRICT,
    FOREIGN KEY (source_event_id) REFERENCES agent_events(event_id) ON DELETE RESTRICT
) STRICT, WITHOUT ROWID;

-- Cleanup rows are inserted before their plan under deferred parent FKs.  The
-- plan's AFTER trigger below proves a complete contiguous set before any
-- launch can be admitted from it.
CREATE TABLE sprint_live_state_capture_plan_cleanups (
    plan_id TEXT NOT NULL,
    sprint_id TEXT NOT NULL,
    cleanup_ordinal INTEGER NOT NULL CHECK (cleanup_ordinal >= 0),
    cleanup_receipt_id TEXT NOT NULL CHECK (length(cleanup_receipt_id) BETWEEN 1 AND 4096),
    contract_version INTEGER NOT NULL CHECK (contract_version > 0),
    PRIMARY KEY (plan_id, cleanup_ordinal),
    UNIQUE (plan_id, cleanup_receipt_id),
    FOREIGN KEY (sprint_id, plan_id)
        REFERENCES sprint_live_state_capture_plans(sprint_id, plan_id)
        ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED,
    FOREIGN KEY (sprint_id, cleanup_receipt_id)
        REFERENCES worker_cleanup_receipts(sprint_id, receipt_id) ON DELETE RESTRICT
) STRICT, WITHOUT ROWID;

CREATE TABLE live_state_verifier_launch_purposes (
    launch_id TEXT PRIMARY KEY NOT NULL,
    sprint_id TEXT NOT NULL,
    session_id TEXT NOT NULL UNIQUE,
    plan_id TEXT NOT NULL UNIQUE,
    plan_digest TEXT NOT NULL CHECK (
        length(plan_digest) = 64 AND plan_digest NOT GLOB '*[^0-9a-f]*'
    ),
    semantic_purpose TEXT NOT NULL CHECK (semantic_purpose = 'LiveStateVerifier'),
    contract_version INTEGER NOT NULL CHECK (contract_version > 0),
    UNIQUE (sprint_id, launch_id),
    UNIQUE (sprint_id, session_id),
    FOREIGN KEY (sprint_id, plan_id)
        REFERENCES sprint_live_state_capture_plans(sprint_id, plan_id) ON DELETE RESTRICT,
    FOREIGN KEY (sprint_id, launch_id)
        REFERENCES runner_launch_intents(sprint_id, launch_id)
        ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED
) STRICT, WITHOUT ROWID;

CREATE TABLE live_state_verifier_session_purposes (
    session_id TEXT PRIMARY KEY NOT NULL,
    sprint_id TEXT NOT NULL,
    launch_id TEXT NOT NULL UNIQUE,
    plan_id TEXT NOT NULL UNIQUE,
    plan_digest TEXT NOT NULL CHECK (
        length(plan_digest) = 64 AND plan_digest NOT GLOB '*[^0-9a-f]*'
    ),
    semantic_purpose TEXT NOT NULL CHECK (semantic_purpose = 'LiveStateVerifier'),
    contract_version INTEGER NOT NULL CHECK (contract_version > 0),
    UNIQUE (sprint_id, session_id),
    UNIQUE (sprint_id, launch_id),
    FOREIGN KEY (sprint_id, plan_id)
        REFERENCES sprint_live_state_capture_plans(sprint_id, plan_id) ON DELETE RESTRICT,
    FOREIGN KEY (sprint_id, launch_id)
        REFERENCES live_state_verifier_launch_purposes(sprint_id, launch_id) ON DELETE RESTRICT,
    FOREIGN KEY (sprint_id, session_id)
        REFERENCES runner_session_policies(sprint_id, session_id)
        ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED
) STRICT, WITHOUT ROWID;

CREATE TABLE sprint_live_state_capture_admissions (
    admission_id TEXT PRIMARY KEY NOT NULL CHECK (length(admission_id) BETWEEN 1 AND 4096),
    sprint_id TEXT NOT NULL,
    plan_id TEXT NOT NULL UNIQUE,
    plan_digest TEXT NOT NULL CHECK (
        length(plan_digest) = 64 AND plan_digest NOT GLOB '*[^0-9a-f]*'
    ),
    effect_id TEXT NOT NULL UNIQUE,
    runner_launch_id TEXT NOT NULL UNIQUE,
    runner_session_id TEXT NOT NULL UNIQUE,
    request_digest TEXT NOT NULL CHECK (
        length(request_digest) = 64 AND request_digest NOT GLOB '*[^0-9a-f]*'
    ),
    expected_snapshot TEXT NOT NULL CHECK (
        length(expected_snapshot) = 64
        AND expected_snapshot NOT GLOB '*[^0-9a-f]*'
    ),
    grant_hash TEXT NOT NULL CHECK (
        length(grant_hash) = 64 AND grant_hash NOT GLOB '*[^0-9a-f]*'
    ),
    policy_hash TEXT NOT NULL CHECK (
        length(policy_hash) = 64 AND policy_hash NOT GLOB '*[^0-9a-f]*'
    ),
    policy_version INTEGER NOT NULL CHECK (policy_version > 0),
    contract_version INTEGER NOT NULL CHECK (contract_version > 0),
    admitted_at_unix_ms INTEGER NOT NULL CHECK (admitted_at_unix_ms > 0),
    admission_json BLOB NOT NULL CHECK (length(admission_json) BETWEEN 1 AND 1048576),
    UNIQUE (sprint_id, admission_id),
    FOREIGN KEY (sprint_id, plan_id)
        REFERENCES sprint_live_state_capture_plans(sprint_id, plan_id) ON DELETE RESTRICT,
    FOREIGN KEY (sprint_id, runner_launch_id)
        REFERENCES live_state_verifier_launch_purposes(sprint_id, launch_id) ON DELETE RESTRICT,
    FOREIGN KEY (sprint_id, runner_session_id)
        REFERENCES live_state_verifier_session_purposes(sprint_id, session_id) ON DELETE RESTRICT,
    FOREIGN KEY (sprint_id, effect_id)
        REFERENCES effect_intents(sprint_id, effect_id)
        ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED,
    FOREIGN KEY (sprint_id, expected_snapshot)
        REFERENCES workspace_snapshots(sprint_id, snapshot_id) ON DELETE RESTRICT
) STRICT, WITHOUT ROWID;

CREATE TABLE live_state_capture_effect_kinds (
    effect_id TEXT PRIMARY KEY NOT NULL,
    sprint_id TEXT NOT NULL,
    admission_id TEXT NOT NULL UNIQUE,
    semantic_kind TEXT NOT NULL CHECK (semantic_kind = 'CaptureWorkspaceState'),
    contract_version INTEGER NOT NULL CHECK (contract_version > 0),
    UNIQUE (sprint_id, effect_id),
    FOREIGN KEY (sprint_id, admission_id)
        REFERENCES sprint_live_state_capture_admissions(sprint_id, admission_id) ON DELETE RESTRICT,
    FOREIGN KEY (sprint_id, effect_id)
        REFERENCES effect_intents(sprint_id, effect_id)
        ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED
) STRICT, WITHOUT ROWID;

-- The v19 authority table has a closed CHECK. Capture claims therefore use an
-- authoritative supplemental companion and never forge one of its old phase
-- classes. `authority_json` is bounded even though core interprets it, so the
-- row can never become an unbounded opaque persistence channel.
CREATE TABLE live_state_capture_dispatch_claim_authorities (
    dispatch_claim_id TEXT PRIMARY KEY NOT NULL,
    sprint_id TEXT NOT NULL,
    admission_id TEXT NOT NULL UNIQUE,
    effect_id TEXT NOT NULL UNIQUE,
    authority_class TEXT NOT NULL CHECK (authority_class = 'SprintLiveStateCapture'),
    opaque_transport_request_digest TEXT NOT NULL CHECK (
        length(opaque_transport_request_digest) = 64
        AND opaque_transport_request_digest NOT GLOB '*[^0-9a-f]*'
    ),
    contract_version INTEGER NOT NULL CHECK (contract_version > 0),
    authority_json BLOB NOT NULL CHECK (length(authority_json) BETWEEN 1 AND 65536),
    UNIQUE (sprint_id, dispatch_claim_id),
    FOREIGN KEY (sprint_id, admission_id)
        REFERENCES sprint_live_state_capture_admissions(sprint_id, admission_id) ON DELETE RESTRICT,
    FOREIGN KEY (sprint_id, effect_id)
        REFERENCES live_state_capture_effect_kinds(sprint_id, effect_id) ON DELETE RESTRICT,
    FOREIGN KEY (dispatch_claim_id)
        REFERENCES runner_effect_dispatch_claims(dispatch_claim_id)
        ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED
) STRICT, WITHOUT ROWID;

-- `finish_receipt_ids.receipt_kind` is also closed, so capture receipts use a
-- separate identity registry with two-way collision triggers below.
CREATE TABLE live_state_capture_receipt_ids (
    receipt_id TEXT PRIMARY KEY NOT NULL CHECK (length(receipt_id) BETWEEN 1 AND 4096),
    sprint_id TEXT NOT NULL,
    receipt_kind TEXT NOT NULL CHECK (receipt_kind = 'LiveStateCapture'),
    contract_version INTEGER NOT NULL CHECK (contract_version > 0),
    FOREIGN KEY (sprint_id) REFERENCES sprints(sprint_id) ON DELETE RESTRICT
) STRICT, WITHOUT ROWID;

CREATE TABLE live_state_capture_receipts (
    receipt_id TEXT PRIMARY KEY NOT NULL,
    sprint_id TEXT NOT NULL,
    admission_id TEXT NOT NULL UNIQUE,
    plan_id TEXT NOT NULL,
    plan_digest TEXT NOT NULL CHECK (
        length(plan_digest) = 64 AND plan_digest NOT GLOB '*[^0-9a-f]*'
    ),
    effect_id TEXT NOT NULL UNIQUE,
    observation_id TEXT NOT NULL UNIQUE,
    dispatch_claim_id TEXT NOT NULL UNIQUE,
    request_digest TEXT NOT NULL CHECK (
        length(request_digest) = 64 AND request_digest NOT GLOB '*[^0-9a-f]*'
    ),
    runner_launch_id TEXT NOT NULL,
    runner_session_id TEXT NOT NULL,
    expected_snapshot TEXT NOT NULL CHECK (
        length(expected_snapshot) = 64
        AND expected_snapshot NOT GLOB '*[^0-9a-f]*'
    ),
    observed_snapshot TEXT NOT NULL CHECK (
        length(observed_snapshot) = 64
        AND observed_snapshot NOT GLOB '*[^0-9a-f]*'
    ),
    manifest_digest TEXT NOT NULL CHECK (
        length(manifest_digest) = 64
        AND manifest_digest NOT GLOB '*[^0-9a-f]*'
    ),
    manifest_entry_count INTEGER NOT NULL CHECK (manifest_entry_count BETWEEN 0 AND 65536),
    grant_hash TEXT NOT NULL CHECK (
        length(grant_hash) = 64 AND grant_hash NOT GLOB '*[^0-9a-f]*'
    ),
    policy_hash TEXT NOT NULL CHECK (
        length(policy_hash) = 64 AND policy_hash NOT GLOB '*[^0-9a-f]*'
    ),
    policy_version INTEGER NOT NULL CHECK (policy_version > 0),
    contract_version INTEGER NOT NULL CHECK (contract_version > 0),
    capture_started_at_unix_ms INTEGER NOT NULL CHECK (capture_started_at_unix_ms > 0),
    captured_at_unix_ms INTEGER NOT NULL CHECK (
        captured_at_unix_ms >= capture_started_at_unix_ms
    ),
    receipt_json BLOB NOT NULL CHECK (length(receipt_json) BETWEEN 1 AND 1048576),
    evidence_json BLOB NOT NULL CHECK (length(evidence_json) BETWEEN 1 AND 8323072),
    UNIQUE (sprint_id, receipt_id),
    UNIQUE (sprint_id),
    CHECK (observed_snapshot = manifest_digest),
    FOREIGN KEY (receipt_id)
        REFERENCES live_state_capture_receipt_ids(receipt_id)
        ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED,
    FOREIGN KEY (sprint_id, admission_id)
        REFERENCES sprint_live_state_capture_admissions(sprint_id, admission_id) ON DELETE RESTRICT,
    FOREIGN KEY (sprint_id, effect_id)
        REFERENCES live_state_capture_effect_kinds(sprint_id, effect_id) ON DELETE RESTRICT,
    FOREIGN KEY (observation_id)
        REFERENCES effect_observations(observation_id)
        ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED,
    FOREIGN KEY (dispatch_claim_id)
        REFERENCES runner_effect_dispatch_claims(dispatch_claim_id) ON DELETE RESTRICT,
    FOREIGN KEY (sprint_id, runner_launch_id)
        REFERENCES live_state_verifier_launch_purposes(sprint_id, launch_id) ON DELETE RESTRICT,
    FOREIGN KEY (sprint_id, runner_session_id)
        REFERENCES live_state_verifier_session_purposes(sprint_id, session_id) ON DELETE RESTRICT
) STRICT, WITHOUT ROWID;

-- Entry order is the manifest digest order. Paths use exact portable UTF-8
-- slash text and byte lengths/modes are bounded by the public contract.
CREATE TABLE live_state_capture_manifest_entries (
    receipt_id TEXT NOT NULL,
    entry_ordinal INTEGER NOT NULL CHECK (entry_ordinal >= 0),
    path TEXT NOT NULL CHECK (
        length(CAST(path AS BLOB)) BETWEEN 1 AND 4096
        AND substr(path, 1, 1) != '/'
        AND substr(path, -1, 1) != '/'
        AND instr(path, '\') = 0
        AND instr(path, '//') = 0
        AND path != '.'
        AND path != '..'
        AND instr('/' || path || '/', '/../') = 0
        AND instr('/' || path || '/', '/./') = 0
        AND instr('/' || lower(path) || '/', '/.git/') = 0
    ),
    content_digest TEXT NOT NULL CHECK (
        length(content_digest) = 64 AND content_digest NOT GLOB '*[^0-9a-f]*'
    ),
    byte_length INTEGER NOT NULL CHECK (byte_length >= 0),
    unix_mode INTEGER NOT NULL CHECK (unix_mode BETWEEN 0 AND 511),
    contract_version INTEGER NOT NULL CHECK (contract_version > 0),
    PRIMARY KEY (receipt_id, entry_ordinal),
    UNIQUE (receipt_id, path),
    FOREIGN KEY (receipt_id)
        REFERENCES live_state_capture_receipts(receipt_id)
        ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED
) STRICT, WITHOUT ROWID;

-- Every v23 authority row is immutable, and every pre-parent companion must
-- be inserted before its parent in the same transaction. These insertion
-- directions prevent post-hoc semantic relabeling and receipt backfill.
CREATE TRIGGER sprint_live_state_capture_plans_no_update
BEFORE UPDATE ON sprint_live_state_capture_plans
BEGIN SELECT RAISE(ABORT, 'live-state capture plans are immutable'); END;
CREATE TRIGGER sprint_live_state_capture_plans_no_delete
BEFORE DELETE ON sprint_live_state_capture_plans
BEGIN SELECT RAISE(ABORT, 'live-state capture plans are immutable'); END;
CREATE TRIGGER sprint_live_state_capture_plan_cleanups_no_existing_plan
BEFORE INSERT ON sprint_live_state_capture_plan_cleanups
WHEN EXISTS (SELECT 1 FROM sprint_live_state_capture_plans WHERE plan_id = NEW.plan_id)
BEGIN SELECT RAISE(ABORT, 'capture plan cleanup set must precede its new plan'); END;
CREATE TRIGGER sprint_live_state_capture_plan_cleanups_no_update
BEFORE UPDATE ON sprint_live_state_capture_plan_cleanups
BEGIN SELECT RAISE(ABORT, 'capture plan cleanup rows are immutable'); END;
CREATE TRIGGER sprint_live_state_capture_plan_cleanups_no_delete
BEFORE DELETE ON sprint_live_state_capture_plan_cleanups
BEGIN SELECT RAISE(ABORT, 'capture plan cleanup rows are immutable'); END;
CREATE TRIGGER live_state_verifier_launch_purposes_no_existing_launch
BEFORE INSERT ON live_state_verifier_launch_purposes
WHEN EXISTS (SELECT 1 FROM runner_launch_intents WHERE launch_id = NEW.launch_id)
BEGIN SELECT RAISE(ABORT, 'semantic launch companion must precede its new launch'); END;
CREATE TRIGGER live_state_verifier_launch_purposes_no_update
BEFORE UPDATE ON live_state_verifier_launch_purposes
BEGIN SELECT RAISE(ABORT, 'semantic launch purposes are immutable'); END;
CREATE TRIGGER live_state_verifier_launch_purposes_no_delete
BEFORE DELETE ON live_state_verifier_launch_purposes
BEGIN SELECT RAISE(ABORT, 'semantic launch purposes are immutable'); END;
CREATE TRIGGER live_state_verifier_session_purposes_no_existing_session
BEFORE INSERT ON live_state_verifier_session_purposes
WHEN EXISTS (SELECT 1 FROM runner_session_policies WHERE session_id = NEW.session_id)
BEGIN SELECT RAISE(ABORT, 'semantic session companion must precede its new session'); END;
CREATE TRIGGER live_state_verifier_session_purposes_no_update
BEFORE UPDATE ON live_state_verifier_session_purposes
BEGIN SELECT RAISE(ABORT, 'semantic session purposes are immutable'); END;
CREATE TRIGGER live_state_verifier_session_purposes_no_delete
BEFORE DELETE ON live_state_verifier_session_purposes
BEGIN SELECT RAISE(ABORT, 'semantic session purposes are immutable'); END;
CREATE TRIGGER sprint_live_state_capture_admissions_no_update
BEFORE UPDATE ON sprint_live_state_capture_admissions
BEGIN SELECT RAISE(ABORT, 'live-state capture admissions are immutable'); END;
CREATE TRIGGER sprint_live_state_capture_admissions_no_delete
BEFORE DELETE ON sprint_live_state_capture_admissions
BEGIN SELECT RAISE(ABORT, 'live-state capture admissions are immutable'); END;
CREATE TRIGGER live_state_capture_effect_kinds_no_existing_effect
BEFORE INSERT ON live_state_capture_effect_kinds
WHEN EXISTS (SELECT 1 FROM effect_intents WHERE effect_id = NEW.effect_id)
OR EXISTS (SELECT 1 FROM finish_effect_kinds WHERE effect_id = NEW.effect_id)
BEGIN SELECT RAISE(ABORT, 'capture subtype must precede its new effect'); END;
CREATE TRIGGER finish_effect_kinds_capture_exclusive
BEFORE INSERT ON finish_effect_kinds
WHEN EXISTS (
    SELECT 1 FROM live_state_capture_effect_kinds WHERE effect_id = NEW.effect_id
)
BEGIN SELECT RAISE(ABORT, 'effect may not carry crossed finish and capture subtypes'); END;
CREATE TRIGGER live_state_capture_effect_kinds_no_update
BEFORE UPDATE ON live_state_capture_effect_kinds
BEGIN SELECT RAISE(ABORT, 'capture effect subtypes are immutable'); END;
CREATE TRIGGER live_state_capture_effect_kinds_no_delete
BEFORE DELETE ON live_state_capture_effect_kinds
BEGIN SELECT RAISE(ABORT, 'capture effect subtypes are immutable'); END;
CREATE TRIGGER live_state_capture_dispatch_claim_authorities_no_existing_claim
BEFORE INSERT ON live_state_capture_dispatch_claim_authorities
WHEN EXISTS (
    SELECT 1 FROM runner_effect_dispatch_claims
    WHERE dispatch_claim_id = NEW.dispatch_claim_id
)
OR EXISTS (
    SELECT 1 FROM runner_effect_dispatch_claim_authorities
    WHERE dispatch_claim_id = NEW.dispatch_claim_id
)
BEGIN SELECT RAISE(ABORT, 'capture claim authority must precede its new claim'); END;
CREATE TRIGGER runner_effect_dispatch_claim_authorities_capture_exclusive
BEFORE INSERT ON runner_effect_dispatch_claim_authorities
WHEN EXISTS (
    SELECT 1 FROM live_state_capture_dispatch_claim_authorities
    WHERE dispatch_claim_id = NEW.dispatch_claim_id
)
BEGIN SELECT RAISE(ABORT, 'runner claim may not carry crossed old and capture authorities'); END;
CREATE TRIGGER live_state_capture_dispatch_claim_authorities_no_update
BEFORE UPDATE ON live_state_capture_dispatch_claim_authorities
BEGIN SELECT RAISE(ABORT, 'capture claim authorities are immutable'); END;
CREATE TRIGGER live_state_capture_dispatch_claim_authorities_no_delete
BEFORE DELETE ON live_state_capture_dispatch_claim_authorities
BEGIN SELECT RAISE(ABORT, 'capture claim authorities are immutable'); END;
CREATE TRIGGER live_state_capture_receipt_ids_no_update
BEFORE UPDATE ON live_state_capture_receipt_ids
BEGIN SELECT RAISE(ABORT, 'capture receipt identities are immutable'); END;
CREATE TRIGGER live_state_capture_receipt_ids_no_delete
BEFORE DELETE ON live_state_capture_receipt_ids
BEGIN SELECT RAISE(ABORT, 'capture receipt identities are immutable'); END;
CREATE TRIGGER live_state_capture_receipts_no_existing_parent
BEFORE INSERT ON live_state_capture_receipts
WHEN EXISTS (
    SELECT 1 FROM effect_observations WHERE observation_id = NEW.observation_id
)
OR EXISTS (
    SELECT 1 FROM live_state_capture_receipt_ids WHERE receipt_id = NEW.receipt_id
)
BEGIN SELECT RAISE(ABORT, 'capture receipt must precede its identity and observation'); END;
CREATE TRIGGER live_state_capture_receipts_no_update
BEFORE UPDATE ON live_state_capture_receipts
BEGIN SELECT RAISE(ABORT, 'capture receipts are immutable'); END;
CREATE TRIGGER live_state_capture_receipts_no_delete
BEFORE DELETE ON live_state_capture_receipts
BEGIN SELECT RAISE(ABORT, 'capture receipts are immutable'); END;
CREATE TRIGGER live_state_capture_manifest_entries_no_existing_receipt
BEFORE INSERT ON live_state_capture_manifest_entries
WHEN EXISTS (SELECT 1 FROM live_state_capture_receipts WHERE receipt_id = NEW.receipt_id)
BEGIN SELECT RAISE(ABORT, 'capture manifest entries must precede their new receipt'); END;
CREATE TRIGGER live_state_capture_manifest_entries_no_update
BEFORE UPDATE ON live_state_capture_manifest_entries
BEGIN SELECT RAISE(ABORT, 'capture manifest entries are immutable'); END;
CREATE TRIGGER live_state_capture_manifest_entries_no_delete
BEFORE DELETE ON live_state_capture_manifest_entries
BEGIN SELECT RAISE(ABORT, 'capture manifest entries are immutable'); END;

-- A later attempt is admissible only after every earlier capture is a
-- definite non-success and its exact verifier launch has a successful typed
-- zero-descendant cleanup ordered after that observation. Unknown is never a
-- retry source. The view is diagnostic and each authority boundary below
-- consumes it as an insertion-time fence.
CREATE VIEW sprint_live_state_capture_retry_blockers AS
SELECT admission.sprint_id, admission.admission_id
FROM sprint_live_state_capture_admissions admission
JOIN runner_launch_cleanup_admissions cleanup
  ON cleanup.sprint_id = admission.sprint_id
 AND cleanup.launch_id = admission.runner_launch_id
LEFT JOIN effect_observations capture
  ON capture.effect_id = admission.effect_id
 AND capture.sprint_id = admission.sprint_id
LEFT JOIN effect_observations cleanup_observation
  ON cleanup_observation.effect_id = cleanup.cleanup_effect_id
 AND cleanup_observation.sprint_id = cleanup.sprint_id
LEFT JOIN worker_cleanup_receipts cleanup_receipt
  ON cleanup_receipt.effect_id = cleanup.cleanup_effect_id
 AND cleanup_receipt.observation_id = cleanup_observation.observation_id
 AND cleanup_receipt.sprint_id = cleanup.sprint_id
 AND cleanup_receipt.launch_id = cleanup.launch_id
WHERE capture.effect_id IS NULL
   OR capture.outcome NOT IN (
       'FailedBeforeEffect', 'FailedAfterKnownEffect', 'CancelledBeforeEffect'
   )
   OR cleanup_observation.effect_id IS NULL
   OR cleanup_observation.outcome != 'Succeeded'
   OR cleanup_receipt.receipt_id IS NULL
   OR cleanup_observation.observed_at_unix_ms < capture.observed_at_unix_ms;

CREATE TRIGGER sprint_live_state_capture_plans_retry_gate
BEFORE INSERT ON sprint_live_state_capture_plans
WHEN EXISTS (
    SELECT 1 FROM live_state_capture_receipts success
    WHERE success.sprint_id = NEW.sprint_id
)
OR EXISTS (
    SELECT 1 FROM sprint_live_state_capture_retry_blockers blocker
    WHERE blocker.sprint_id = NEW.sprint_id
)
BEGIN SELECT RAISE(ABORT, 'capture plan requires no success and exact cleanup after every definite prior failure'); END;

CREATE TRIGGER live_state_verifier_launch_purposes_retry_gate
BEFORE INSERT ON live_state_verifier_launch_purposes
WHEN EXISTS (
    SELECT 1 FROM live_state_capture_receipts success
    WHERE success.sprint_id = NEW.sprint_id
)
OR EXISTS (
    SELECT 1 FROM sprint_live_state_capture_retry_blockers blocker
    WHERE blocker.sprint_id = NEW.sprint_id
)
BEGIN SELECT RAISE(ABORT, 'capture launch requires no success and exact cleanup after every definite prior failure'); END;

CREATE TRIGGER live_state_verifier_session_purposes_retry_gate
BEFORE INSERT ON live_state_verifier_session_purposes
WHEN EXISTS (
    SELECT 1 FROM live_state_capture_receipts success
    WHERE success.sprint_id = NEW.sprint_id
)
BEGIN SELECT RAISE(ABORT, 'capture session cannot initialize after a successful sprint capture'); END;

CREATE TRIGGER sprint_live_state_capture_admissions_retry_gate
BEFORE INSERT ON sprint_live_state_capture_admissions
WHEN EXISTS (
    SELECT 1 FROM live_state_capture_receipts success
    WHERE success.sprint_id = NEW.sprint_id
)
OR EXISTS (
    SELECT 1 FROM sprint_live_state_capture_retry_blockers blocker
    WHERE blocker.sprint_id = NEW.sprint_id
)
BEGIN SELECT RAISE(ABORT, 'capture admission requires no success and exact cleanup after every definite prior failure'); END;

CREATE TRIGGER live_state_capture_dispatch_claim_authorities_retry_gate
BEFORE INSERT ON live_state_capture_dispatch_claim_authorities
WHEN EXISTS (
    SELECT 1 FROM live_state_capture_receipts success
    WHERE success.sprint_id = NEW.sprint_id
)
OR EXISTS (
    SELECT 1 FROM sprint_live_state_capture_retry_blockers blocker
    WHERE blocker.sprint_id = NEW.sprint_id
      AND blocker.admission_id != NEW.admission_id
)
BEGIN SELECT RAISE(ABORT, 'capture claim requires no success and exact cleanup after every definite prior failure'); END;

-- Plans retain the exact latest event cut and a complete canonical cleanup
-- list. Hash equality is recomputed by Rust readback; SQL owns cardinality,
-- ordinal contiguity, source identity, and timestamp ordering.
CREATE TRIGGER sprint_live_state_capture_plans_exact_shape
AFTER INSERT ON sprint_live_state_capture_plans
WHEN NOT COALESCE((
    json_valid(CAST(NEW.plan_json AS TEXT))
    AND json_extract(CAST(NEW.plan_json AS TEXT), '$.contract_version') = NEW.contract_version
    AND json_extract(CAST(NEW.plan_json AS TEXT), '$.plan_id') = NEW.plan_id
    AND json_extract(CAST(NEW.plan_json AS TEXT), '$.sprint_id') = NEW.sprint_id
    AND json_extract(CAST(NEW.plan_json AS TEXT), '$.expected_snapshot') = NEW.expected_snapshot
    AND json_extract(CAST(NEW.plan_json AS TEXT), '$.grant_hash') = NEW.grant_hash
    AND json_extract(CAST(NEW.plan_json AS TEXT), '$.policy_hash') = NEW.policy_hash
    AND json_extract(CAST(NEW.plan_json AS TEXT), '$.policy_version') = NEW.policy_version
    AND json_extract(CAST(NEW.plan_json AS TEXT), '$.source_event_id') = NEW.source_event_id
    AND json_extract(CAST(NEW.plan_json AS TEXT), '$.source_event_sequence') = NEW.source_event_sequence
    AND json_extract(CAST(NEW.plan_json AS TEXT), '$.required_cleanup_set_digest') = NEW.required_cleanup_set_digest
    AND json_array_length(CAST(NEW.plan_json AS TEXT), '$.required_cleanup_receipt_ids') = NEW.required_cleanup_count
    AND json_extract(CAST(NEW.plan_json AS TEXT), '$.planned_at_unix_ms') = NEW.planned_at_unix_ms
    AND json_valid(CAST(NEW.execution_policy_json AS TEXT))
    AND json_extract(CAST(NEW.execution_policy_json AS TEXT), '$.policy_hash') = NEW.policy_hash
    AND json_extract(CAST(NEW.execution_policy_json AS TEXT), '$.grant_hash') = NEW.grant_hash
    AND json_extract(CAST(NEW.execution_policy_json AS TEXT), '$.mutation_mode') = 'ReadOnly'
    AND json_extract(CAST(NEW.execution_policy_json AS TEXT), '$.network') = 'None'
    AND json_type(CAST(NEW.execution_policy_json AS TEXT), '$.read_scopes') = 'array'
    AND json_array_length(CAST(NEW.execution_policy_json AS TEXT), '$.read_scopes') = 1
    AND json_extract(CAST(NEW.execution_policy_json AS TEXT), '$.read_scopes[0]') = 'Workspace'
    AND json_type(CAST(NEW.execution_policy_json AS TEXT), '$.write_scopes') = 'array'
    AND json_array_length(CAST(NEW.execution_policy_json AS TEXT), '$.write_scopes') = 0
    AND json_type(CAST(NEW.execution_policy_json AS TEXT), '$.approval_id') = 'null'
    AND (
        (NEW.branch = 'Applied'
         AND json_extract(CAST(NEW.plan_json AS TEXT), '$.branch.Applied.final_verification_receipt_id') = NEW.final_verification_receipt_id
         AND json_extract(CAST(NEW.plan_json AS TEXT), '$.branch.Applied.application_receipt_id') = NEW.application_receipt_id
         AND json_extract(CAST(NEW.plan_json AS TEXT), '$.branch.Applied.rollback_reference_id') = NEW.rollback_reference_id)
        OR
        (NEW.branch = 'VerifiedNoOp'
         AND json_extract(CAST(NEW.plan_json AS TEXT), '$.branch.VerifiedNoOp.final_verification_receipt_id') = NEW.final_verification_receipt_id
         AND json_extract(CAST(NEW.plan_json AS TEXT), '$.branch.VerifiedNoOp.task_integration_receipt_id') = NEW.task_integration_receipt_id)
    )
), 0)
OR NOT EXISTS (
    SELECT 1 FROM agent_events source
    WHERE source.event_id = NEW.source_event_id
      AND source.sprint_id = NEW.sprint_id
      AND source.sequence = NEW.source_event_sequence
      AND source.occurred_at_unix_ms <= NEW.planned_at_unix_ms
      AND source.sequence = (
          SELECT MAX(latest.sequence) FROM agent_events latest
          WHERE latest.sprint_id = NEW.sprint_id
      )
)
OR (SELECT COUNT(*) FROM sprint_live_state_capture_plan_cleanups
    WHERE plan_id = NEW.plan_id AND sprint_id = NEW.sprint_id) != NEW.required_cleanup_count
OR EXISTS (
    SELECT 1
    FROM sprint_live_state_capture_plan_cleanups cleanup
    WHERE cleanup.plan_id = NEW.plan_id
      AND cleanup.sprint_id = NEW.sprint_id
      AND cleanup.cleanup_ordinal >= NEW.required_cleanup_count
)
OR EXISTS (
    SELECT 1
    FROM sprint_live_state_capture_plan_cleanups cleanup
    JOIN worker_cleanup_receipts receipt
      ON receipt.receipt_id = cleanup.cleanup_receipt_id
     AND receipt.sprint_id = cleanup.sprint_id
    WHERE cleanup.plan_id = NEW.plan_id
      AND (cleanup.contract_version != NEW.contract_version
           OR receipt.cleaned_at_unix_ms > NEW.planned_at_unix_ms)
)
OR EXISTS (
    SELECT 1
    FROM sprint_live_state_capture_plan_cleanups cleanup
    WHERE cleanup.plan_id = NEW.plan_id
      AND (
          COALESCE(json_type(
              CAST(NEW.plan_json AS TEXT),
              '$.required_cleanup_receipt_ids[' || cleanup.cleanup_ordinal || ']'
          ), '') != 'text'
          OR COALESCE(json_extract(
              CAST(NEW.plan_json AS TEXT),
              '$.required_cleanup_receipt_ids[' || cleanup.cleanup_ordinal || ']'
          ), '') != cleanup.cleanup_receipt_id
      )
)
BEGIN SELECT RAISE(ABORT, 'capture plan requires exact source cut and complete prior cleanup set'); END;

-- Semantic runner envelopes are stored under the old FinalVerifier class only
-- when their pre-parent companion is exact. Ordinary FinalVerifier rows must
-- not acquire a semantic marker later.
CREATE TRIGGER runner_launch_intents_v23_semantic_purpose
AFTER INSERT ON runner_launch_intents
WHEN (
    COALESCE(json_extract(CAST(NEW.intent_json AS TEXT), '$.purpose'), '') = 'LiveStateVerifier'
    AND (
        NEW.purpose != 'FinalVerifier'
        OR NOT EXISTS (
            SELECT 1
            FROM live_state_verifier_launch_purposes marker
            JOIN sprint_live_state_capture_plans plan
              ON plan.plan_id = marker.plan_id AND plan.sprint_id = marker.sprint_id
            WHERE marker.launch_id = NEW.launch_id
              AND marker.sprint_id = NEW.sprint_id
              AND marker.session_id = NEW.session_id
              AND marker.plan_digest = plan.plan_digest
              AND marker.contract_version = NEW.contract_version
              AND plan.source_event_sequence = (
                  SELECT MAX(latest.sequence) FROM agent_events latest
                  WHERE latest.sprint_id = NEW.sprint_id
              )
        )
    )
)
OR (
    COALESCE(json_extract(CAST(NEW.intent_json AS TEXT), '$.purpose'), '') != 'LiveStateVerifier'
    AND EXISTS (
        SELECT 1 FROM live_state_verifier_launch_purposes marker
        WHERE marker.launch_id = NEW.launch_id
    )
)
BEGIN SELECT RAISE(ABORT, 'runner launch semantic purpose companion is missing or crossed'); END;

CREATE TRIGGER runner_session_policies_v23_semantic_purpose
AFTER INSERT ON runner_session_policies
WHEN (
    COALESCE(json_extract(CAST(NEW.record_json AS TEXT), '$.purpose'), '') = 'LiveStateVerifier'
    AND (
        NEW.purpose != 'FinalVerifier'
        OR NOT EXISTS (
            SELECT 1
            FROM live_state_verifier_session_purposes session_marker
            JOIN live_state_verifier_launch_purposes launch_marker
              ON launch_marker.launch_id = session_marker.launch_id
             AND launch_marker.sprint_id = session_marker.sprint_id
            WHERE session_marker.session_id = NEW.session_id
              AND session_marker.sprint_id = NEW.sprint_id
              AND session_marker.launch_id = NEW.launch_id
              AND session_marker.plan_id = launch_marker.plan_id
              AND session_marker.plan_digest = launch_marker.plan_digest
              AND session_marker.contract_version = NEW.contract_version
        )
    )
)
OR (
    COALESCE(json_extract(CAST(NEW.record_json AS TEXT), '$.purpose'), '') != 'LiveStateVerifier'
    AND EXISTS (
        SELECT 1 FROM live_state_verifier_session_purposes marker
        WHERE marker.session_id = NEW.session_id
    )
)
BEGIN SELECT RAISE(ABORT, 'runner session semantic purpose companion is missing or crossed'); END;

-- An admission must join one exact persisted plan, semantic runner lifecycle,
-- request, and pre-parent capture subtype. The current branch/source proof is
-- re-derived in Rust immediately before insert and again on every readback.
CREATE TRIGGER sprint_live_state_capture_admissions_exact_shape
BEFORE INSERT ON sprint_live_state_capture_admissions
WHEN NOT EXISTS (
    SELECT 1
    FROM sprint_live_state_capture_plans plan
    JOIN live_state_verifier_launch_purposes launch
      ON launch.plan_id = plan.plan_id AND launch.sprint_id = plan.sprint_id
    JOIN live_state_verifier_session_purposes session
      ON session.plan_id = plan.plan_id AND session.sprint_id = plan.sprint_id
     AND session.launch_id = launch.launch_id AND session.session_id = launch.session_id
    JOIN runner_launch_intents stored_launch
      ON stored_launch.launch_id = launch.launch_id
     AND stored_launch.sprint_id = launch.sprint_id
    JOIN runner_session_policies stored_session
      ON stored_session.session_id = session.session_id
     AND stored_session.sprint_id = session.sprint_id
     AND stored_session.launch_id = launch.launch_id
    JOIN runner_launch_cleanup_admissions cleanup
      ON cleanup.launch_id = launch.launch_id
     AND cleanup.sprint_id = launch.sprint_id
     AND cleanup.session_id = launch.session_id
    JOIN agent_events cleanup_event
      ON cleanup_event.event_id = cleanup.proposal_event_id
     AND cleanup_event.sprint_id = cleanup.sprint_id
    WHERE plan.plan_id = NEW.plan_id
      AND plan.sprint_id = NEW.sprint_id
      AND plan.plan_digest = NEW.plan_digest
      AND plan.expected_snapshot = NEW.expected_snapshot
      AND plan.grant_hash = NEW.grant_hash
      AND plan.policy_hash = NEW.policy_hash
      AND plan.policy_version = NEW.policy_version
      AND launch.launch_id = NEW.runner_launch_id
      AND session.session_id = NEW.runner_session_id
      AND launch.plan_digest = NEW.plan_digest
      AND session.plan_digest = NEW.plan_digest
      AND stored_launch.purpose = 'FinalVerifier'
      AND stored_session.purpose = 'FinalVerifier'
      AND stored_launch.worker_id IS NULL
      AND stored_session.worker_id IS NULL
      AND stored_launch.worker_lease_id IS NULL
      AND stored_session.worker_lease_id IS NULL
      AND stored_launch.policy_hash = NEW.policy_hash
      AND stored_session.policy_hash = NEW.policy_hash
      AND stored_launch.grant_hash = NEW.grant_hash
      AND stored_session.grant_hash = NEW.grant_hash
      AND stored_launch.policy_version = NEW.policy_version
      AND stored_session.policy_version = NEW.policy_version
      AND plan.planned_at_unix_ms <= stored_launch.created_at_unix_ms
      AND stored_launch.created_at_unix_ms <= stored_session.registered_at_unix_ms
      AND stored_session.registered_at_unix_ms <= NEW.admitted_at_unix_ms
      AND cleanup_event.sequence = plan.source_event_sequence + 1
      AND cleanup_event.sequence = (
          SELECT MAX(latest.sequence) FROM agent_events latest
          WHERE latest.sprint_id = NEW.sprint_id
      )
      AND NOT EXISTS (
          SELECT 1 FROM effect_observations cleanup_observation
          WHERE cleanup_observation.effect_id = cleanup.cleanup_effect_id
      )
      AND NOT EXISTS (
          SELECT 1
          FROM effect_intents unresolved
          LEFT JOIN effect_observations terminal
            ON terminal.effect_id = unresolved.effect_id
          WHERE unresolved.sprint_id = NEW.sprint_id
            AND unresolved.effect_id != cleanup.cleanup_effect_id
            AND (terminal.effect_id IS NULL OR terminal.outcome = 'Unknown')
      )
      AND (SELECT COUNT(*) FROM runner_launch_intents existing_launch
           WHERE existing_launch.sprint_id = NEW.sprint_id) = plan.required_cleanup_count + 1
      AND (
          (plan.branch = 'Applied'
           AND json_extract(CAST((
               SELECT phase.event_json
               FROM agent_events phase
               WHERE phase.sprint_id = NEW.sprint_id
                 AND json_type(CAST(phase.event_json AS TEXT), '$.payload.SprintStateChanged') = 'object'
               ORDER BY phase.sequence DESC LIMIT 1
           ) AS TEXT), '$.payload.SprintStateChanged.to') = 'Applying')
          OR
          (plan.branch = 'VerifiedNoOp'
           AND json_extract(CAST((
               SELECT phase.event_json
               FROM agent_events phase
               WHERE phase.sprint_id = NEW.sprint_id
                 AND json_type(CAST(phase.event_json AS TEXT), '$.payload.SprintStateChanged') = 'object'
               ORDER BY phase.sequence DESC LIMIT 1
           ) AS TEXT), '$.payload.SprintStateChanged.to') = 'FinalVerification')
      )
      AND plan.planned_at_unix_ms <= NEW.admitted_at_unix_ms
      AND plan.contract_version = NEW.contract_version
      AND launch.contract_version = NEW.contract_version
      AND session.contract_version = NEW.contract_version
      AND stored_launch.contract_version = NEW.contract_version
      AND stored_session.contract_version = NEW.contract_version
)
BEGIN SELECT RAISE(ABORT, 'capture admission crosses its plan or semantic runner authority'); END;

CREATE TRIGGER sprint_live_state_capture_admissions_json_matches
BEFORE INSERT ON sprint_live_state_capture_admissions
WHEN NOT COALESCE((
    json_valid(CAST(NEW.admission_json AS TEXT))
    AND grok_live_state_capture_admission_matches(
        NEW.admission_json, NEW.plan_digest, NEW.request_digest
    ) = 1
    AND json_type(CAST(NEW.admission_json AS TEXT), '$.contract_version') = 'integer'
    AND json_type(CAST(NEW.admission_json AS TEXT), '$.admission_id') = 'text'
    AND json_type(CAST(NEW.admission_json AS TEXT), '$.plan') = 'object'
    AND json_type(CAST(NEW.admission_json AS TEXT), '$.request') = 'object'
    AND json_type(CAST(NEW.admission_json AS TEXT), '$.effect_id') = 'text'
    AND json_type(CAST(NEW.admission_json AS TEXT), '$.runner_launch_id') = 'text'
    AND json_type(CAST(NEW.admission_json AS TEXT), '$.runner_session_id') = 'text'
    AND json_type(CAST(NEW.admission_json AS TEXT), '$.admitted_at_unix_ms') = 'integer'
    AND json_extract(CAST(NEW.admission_json AS TEXT), '$.contract_version') = NEW.contract_version
    AND json_extract(CAST(NEW.admission_json AS TEXT), '$.admission_id') = NEW.admission_id
    AND json_extract(CAST(NEW.admission_json AS TEXT), '$.plan.plan_id') = NEW.plan_id
    AND json_extract(CAST(NEW.admission_json AS TEXT), '$.plan.sprint_id') = NEW.sprint_id
    AND json_extract(CAST(NEW.admission_json AS TEXT), '$.plan.expected_snapshot') = NEW.expected_snapshot
    AND json_extract(CAST(NEW.admission_json AS TEXT), '$.plan.grant_hash') = NEW.grant_hash
    AND json_extract(CAST(NEW.admission_json AS TEXT), '$.plan.policy_hash') = NEW.policy_hash
    AND json_extract(CAST(NEW.admission_json AS TEXT), '$.plan.policy_version') = NEW.policy_version
    AND json_extract(CAST(NEW.admission_json AS TEXT), '$.request.contract_version') = NEW.contract_version
    AND json_extract(CAST(NEW.admission_json AS TEXT), '$.request.plan.plan_id') = NEW.plan_id
    AND json_extract(CAST(NEW.admission_json AS TEXT), '$.request.plan.sprint_id') = NEW.sprint_id
    AND json_extract(CAST(NEW.admission_json AS TEXT), '$.effect_id') = NEW.effect_id
    AND json_extract(CAST(NEW.admission_json AS TEXT), '$.runner_launch_id') = NEW.runner_launch_id
    AND json_extract(CAST(NEW.admission_json AS TEXT), '$.runner_session_id') = NEW.runner_session_id
    AND json_extract(CAST(NEW.admission_json AS TEXT), '$.admitted_at_unix_ms') = NEW.admitted_at_unix_ms
    AND EXISTS (
        SELECT 1 FROM sprint_live_state_capture_plans plan
        WHERE plan.plan_id = NEW.plan_id
          AND plan.sprint_id = NEW.sprint_id
          AND CAST(plan.plan_json AS TEXT)
              = json_extract(CAST(NEW.admission_json AS TEXT), '$.plan')
          AND CAST(plan.plan_json AS TEXT)
              = json_extract(CAST(NEW.admission_json AS TEXT), '$.request.plan')
    )
), 0)
BEGIN SELECT RAISE(ABORT, 'capture admission JSON must match indexed plan and lifecycle'); END;

-- Capture uses taskless ReadRelativeFile only as an indexed compatibility
-- class. Both directions are fenced so raw SQL cannot relabel an ordinary read
-- or omit the authoritative subtype.
CREATE TRIGGER effect_intents_v23_capture_subtype
AFTER INSERT ON effect_intents
WHEN (
    COALESCE(json_extract(CAST(NEW.intent_json AS TEXT), '$.kind'), '') = 'CaptureWorkspaceState'
    AND (
        NEW.effect_kind != 'ReadRelativeFile'
        OR NEW.task_id IS NOT NULL
        OR NEW.worker_id IS NOT NULL
        OR NEW.worker_lease_id IS NOT NULL
        OR NEW.worker_lease_epoch IS NOT NULL
        OR NOT EXISTS (
            SELECT 1
            FROM live_state_capture_effect_kinds subtype
            JOIN sprint_live_state_capture_admissions admission
              ON admission.admission_id = subtype.admission_id
             AND admission.sprint_id = subtype.sprint_id
            JOIN effect_session_bindings binding
              ON binding.effect_id = subtype.effect_id
             AND binding.sprint_id = subtype.sprint_id
            WHERE subtype.effect_id = NEW.effect_id
              AND subtype.sprint_id = NEW.sprint_id
              AND admission.effect_id = NEW.effect_id
              AND admission.runner_launch_id = binding.launch_id
              AND admission.runner_session_id = binding.session_id
              AND admission.request_digest = NEW.request_digest
              AND admission.expected_snapshot = NEW.input_snapshot
              AND admission.policy_hash = NEW.policy_hash
              AND admission.admitted_at_unix_ms = NEW.created_at_unix_ms
              AND subtype.contract_version = NEW.contract_version
              AND admission.contract_version = NEW.contract_version
              AND binding.contract_version = NEW.contract_version
        )
    )
)
OR (
    COALESCE(json_extract(CAST(NEW.intent_json AS TEXT), '$.kind'), '') != 'CaptureWorkspaceState'
    AND EXISTS (
        SELECT 1 FROM live_state_capture_effect_kinds subtype
        WHERE subtype.effect_id = NEW.effect_id
    )
)
BEGIN SELECT RAISE(ABORT, 'capture intent requires exact taskless compatibility subtype'); END;

CREATE TRIGGER effect_observations_v23_capture_subtype
BEFORE INSERT ON effect_observations
WHEN (
    EXISTS (
        SELECT 1 FROM live_state_capture_effect_kinds subtype
        WHERE subtype.effect_id = NEW.effect_id
    )
    AND (
        NEW.effect_kind != 'ReadRelativeFile'
        OR NEW.task_id IS NOT NULL
        OR NEW.worker_id IS NOT NULL
        OR NEW.worker_lease_id IS NOT NULL
        OR NEW.worker_lease_epoch IS NOT NULL
        OR (
            NEW.dispatch_claim_id IS NULL
            AND NEW.outcome NOT IN ('FailedBeforeEffect', 'CancelledBeforeEffect')
        )
        OR COALESCE(json_extract(CAST(NEW.observation_json AS TEXT), '$.kind'), '') != 'CaptureWorkspaceState'
    )
)
OR (
    COALESCE(json_extract(CAST(NEW.observation_json AS TEXT), '$.kind'), '') = 'CaptureWorkspaceState'
    AND NOT EXISTS (
        SELECT 1 FROM live_state_capture_effect_kinds subtype
        WHERE subtype.effect_id = NEW.effect_id
    )
)
BEGIN SELECT RAISE(ABORT, 'capture observation requires exact claimed semantic subtype'); END;

CREATE TRIGGER effect_observations_v23_capture_receipt_required
AFTER INSERT ON effect_observations
WHEN NEW.outcome = 'Succeeded'
 AND EXISTS (
     SELECT 1 FROM live_state_capture_effect_kinds subtype
     WHERE subtype.effect_id = NEW.effect_id
 )
 AND NOT EXISTS (
     SELECT 1
     FROM live_state_capture_receipts receipt
     JOIN effect_evidence_payloads payload
       ON payload.effect_id = receipt.effect_id
      AND payload.observation_id = receipt.observation_id
      AND payload.sprint_id = receipt.sprint_id
     WHERE receipt.effect_id = NEW.effect_id
       AND receipt.observation_id = NEW.observation_id
       AND receipt.sprint_id = NEW.sprint_id
       AND receipt.dispatch_claim_id = NEW.dispatch_claim_id
       AND receipt.policy_hash = NEW.policy_hash
       AND receipt.expected_snapshot = NEW.input_snapshot
       AND receipt.captured_at_unix_ms = NEW.observed_at_unix_ms
       AND receipt.contract_version = NEW.contract_version
       AND payload.contract_version = NEW.contract_version
       AND payload.evidence_bytes = receipt.evidence_json
       AND payload.evidence_digest = grok_sha256(receipt.evidence_json)
       AND payload.evidence_digest = NEW.evidence_digest
 )
BEGIN SELECT RAISE(ABORT, 'successful capture requires atomic typed manifest receipt'); END;

-- The manifest rows must be contiguous and strictly byte-lexicographic. The
-- prefix test rejects impossible regular-file trees such as both `a` and
-- `a/b`, without LIKE wildcard ambiguity.
CREATE TRIGGER live_state_capture_manifest_entries_ordered
BEFORE INSERT ON live_state_capture_manifest_entries
WHEN NEW.entry_ordinal != COALESCE((
    SELECT MAX(entry_ordinal) + 1
    FROM live_state_capture_manifest_entries
    WHERE receipt_id = NEW.receipt_id
), 0)
OR EXISTS (
    SELECT 1 FROM live_state_capture_manifest_entries prior
    WHERE prior.receipt_id = NEW.receipt_id
      AND prior.entry_ordinal = NEW.entry_ordinal - 1
      AND CAST(prior.path AS BLOB) >= CAST(NEW.path AS BLOB)
)
OR EXISTS (
    SELECT 1 FROM live_state_capture_manifest_entries existing
    WHERE existing.receipt_id = NEW.receipt_id
      AND (
          substr(NEW.path, 1, length(existing.path) + 1) = existing.path || '/'
          OR substr(existing.path, 1, length(NEW.path) + 1) = NEW.path || '/'
      )
)
BEGIN SELECT RAISE(ABORT, 'capture manifest entries must be contiguous, ordered, and prefix-safe'); END;

CREATE TRIGGER live_state_capture_receipts_json_matches
BEFORE INSERT ON live_state_capture_receipts
WHEN NOT COALESCE((
    json_valid(CAST(NEW.receipt_json AS TEXT))
    AND json_valid(CAST(NEW.evidence_json AS TEXT))
    AND grok_live_state_capture_manifest_digest(NEW.evidence_json) = NEW.manifest_digest
    AND json_type(CAST(NEW.receipt_json AS TEXT), '$.contract_version') = 'integer'
    AND json_type(CAST(NEW.receipt_json AS TEXT), '$.receipt_id') = 'text'
    AND json_type(CAST(NEW.receipt_json AS TEXT), '$.admission_id') = 'text'
    AND json_type(CAST(NEW.receipt_json AS TEXT), '$.effect_id') = 'text'
    AND json_type(CAST(NEW.receipt_json AS TEXT), '$.observation_id') = 'text'
    AND json_type(CAST(NEW.receipt_json AS TEXT), '$.dispatch_claim_id') = 'text'
    AND json_type(CAST(NEW.receipt_json AS TEXT), '$.sprint_id') = 'text'
    AND json_type(CAST(NEW.receipt_json AS TEXT), '$.plan_id') = 'text'
    AND json_type(CAST(NEW.receipt_json AS TEXT), '$.capture_started_at_unix_ms') = 'integer'
    AND json_type(CAST(NEW.receipt_json AS TEXT), '$.captured_at_unix_ms') = 'integer'
    AND json_type(CAST(NEW.evidence_json AS TEXT), '$.contract_version') = 'integer'
    AND json_type(CAST(NEW.evidence_json AS TEXT), '$.receipt') = 'object'
    AND json_type(CAST(NEW.evidence_json AS TEXT), '$.manifest') = 'object'
    AND json_type(CAST(NEW.evidence_json AS TEXT), '$.manifest.entries') = 'array'
    AND json_extract(CAST(NEW.receipt_json AS TEXT), '$.contract_version') = NEW.contract_version
    AND json_extract(CAST(NEW.receipt_json AS TEXT), '$.receipt_id') = NEW.receipt_id
    AND json_extract(CAST(NEW.receipt_json AS TEXT), '$.admission_id') = NEW.admission_id
    AND json_extract(CAST(NEW.receipt_json AS TEXT), '$.effect_id') = NEW.effect_id
    AND json_extract(CAST(NEW.receipt_json AS TEXT), '$.observation_id') = NEW.observation_id
    AND json_extract(CAST(NEW.receipt_json AS TEXT), '$.dispatch_claim_id') = NEW.dispatch_claim_id
    AND json_extract(CAST(NEW.receipt_json AS TEXT), '$.sprint_id') = NEW.sprint_id
    AND json_extract(CAST(NEW.receipt_json AS TEXT), '$.plan_id') = NEW.plan_id
    AND json_extract(CAST(NEW.receipt_json AS TEXT), '$.plan_digest') = NEW.plan_digest
    AND json_extract(CAST(NEW.receipt_json AS TEXT), '$.request_digest') = NEW.request_digest
    AND json_extract(CAST(NEW.receipt_json AS TEXT), '$.runner_launch_id') = NEW.runner_launch_id
    AND json_extract(CAST(NEW.receipt_json AS TEXT), '$.runner_session_id') = NEW.runner_session_id
    AND json_extract(CAST(NEW.receipt_json AS TEXT), '$.expected_snapshot') = NEW.expected_snapshot
    AND json_extract(CAST(NEW.receipt_json AS TEXT), '$.observed_snapshot') = NEW.observed_snapshot
    AND json_extract(CAST(NEW.receipt_json AS TEXT), '$.manifest_digest') = NEW.manifest_digest
    AND json_extract(CAST(NEW.receipt_json AS TEXT), '$.grant_hash') = NEW.grant_hash
    AND json_extract(CAST(NEW.receipt_json AS TEXT), '$.policy_hash') = NEW.policy_hash
    AND json_extract(CAST(NEW.receipt_json AS TEXT), '$.policy_version') = NEW.policy_version
    AND json_extract(CAST(NEW.receipt_json AS TEXT), '$.capture_started_at_unix_ms') = NEW.capture_started_at_unix_ms
    AND json_extract(CAST(NEW.receipt_json AS TEXT), '$.captured_at_unix_ms') = NEW.captured_at_unix_ms
    AND json_extract(CAST(NEW.evidence_json AS TEXT), '$.contract_version') = NEW.contract_version
    AND json_extract(CAST(NEW.evidence_json AS TEXT), '$.manifest.grant_hash') = NEW.grant_hash
    AND json_extract(CAST(NEW.evidence_json AS TEXT), '$.manifest.capture_started_at_unix_ms') = NEW.capture_started_at_unix_ms
    AND json_extract(CAST(NEW.evidence_json AS TEXT), '$.manifest.captured_at_unix_ms') = NEW.captured_at_unix_ms
    AND json_extract(CAST(NEW.evidence_json AS TEXT), '$.manifest.manifest_digest') = NEW.manifest_digest
    AND json_array_length(CAST(NEW.evidence_json AS TEXT), '$.manifest.entries') = NEW.manifest_entry_count
    AND CAST(NEW.receipt_json AS TEXT) = json_extract(CAST(NEW.evidence_json AS TEXT), '$.receipt')
    AND EXISTS (
        SELECT 1 FROM sprint_live_state_capture_plans plan
        WHERE plan.plan_id = NEW.plan_id
          AND plan.sprint_id = NEW.sprint_id
          AND json(json_extract(CAST(NEW.evidence_json AS TEXT), '$.receipt.branch'))
              = json(json_extract(CAST(plan.plan_json AS TEXT), '$.branch'))
    )
), 0)
BEGIN SELECT RAISE(ABORT, 'capture receipt and evidence JSON must match indexed canonical authority'); END;

CREATE TRIGGER live_state_capture_receipts_complete_manifest
AFTER INSERT ON live_state_capture_receipts
WHEN (SELECT COUNT(*) FROM live_state_capture_manifest_entries entry
      WHERE entry.receipt_id = NEW.receipt_id) != NEW.manifest_entry_count
OR EXISTS (
    SELECT 1 FROM live_state_capture_manifest_entries entry
    WHERE entry.receipt_id = NEW.receipt_id
      AND (entry.entry_ordinal >= NEW.manifest_entry_count
           OR entry.contract_version != NEW.contract_version
           OR COALESCE(json_type(
               CAST(NEW.evidence_json AS TEXT),
               '$.manifest.entries[' || entry.entry_ordinal || '].path'
           ), '') != 'text'
           OR COALESCE(json_extract(
               CAST(NEW.evidence_json AS TEXT),
               '$.manifest.entries[' || entry.entry_ordinal || '].path'
           ), '') != entry.path
           OR COALESCE(json_extract(
               CAST(NEW.evidence_json AS TEXT),
               '$.manifest.entries[' || entry.entry_ordinal || '].content_digest'
           ), '') != entry.content_digest
           OR COALESCE(json_extract(
               CAST(NEW.evidence_json AS TEXT),
               '$.manifest.entries[' || entry.entry_ordinal || '].byte_length'
           ), -1) != entry.byte_length
           OR COALESCE(json_extract(
               CAST(NEW.evidence_json AS TEXT),
               '$.manifest.entries[' || entry.entry_ordinal || '].unix_mode'
           ), -1) != entry.unix_mode)
)
OR NOT EXISTS (
    SELECT 1
    FROM sprint_live_state_capture_admissions admission
    JOIN live_state_capture_dispatch_claim_authorities authority
      ON authority.admission_id = admission.admission_id
     AND authority.sprint_id = admission.sprint_id
    WHERE admission.admission_id = NEW.admission_id
      AND admission.sprint_id = NEW.sprint_id
      AND admission.plan_id = NEW.plan_id
      AND admission.plan_digest = NEW.plan_digest
      AND admission.effect_id = NEW.effect_id
      AND admission.runner_launch_id = NEW.runner_launch_id
      AND admission.runner_session_id = NEW.runner_session_id
      AND admission.request_digest = NEW.request_digest
      AND admission.expected_snapshot = NEW.expected_snapshot
      AND admission.grant_hash = NEW.grant_hash
      AND admission.policy_hash = NEW.policy_hash
      AND admission.policy_version = NEW.policy_version
      AND authority.dispatch_claim_id = NEW.dispatch_claim_id
      AND authority.effect_id = NEW.effect_id
      AND admission.admitted_at_unix_ms <= NEW.capture_started_at_unix_ms
      AND admission.contract_version = NEW.contract_version
      AND authority.contract_version = NEW.contract_version
)
BEGIN SELECT RAISE(ABORT, 'capture receipt requires its complete exact manifest and authority'); END;

CREATE TRIGGER effect_evidence_payloads_v23_capture_receipt_binding
AFTER INSERT ON effect_evidence_payloads
WHEN EXISTS (
    SELECT 1 FROM live_state_capture_receipts receipt
    WHERE receipt.effect_id = NEW.effect_id
)
AND NOT EXISTS (
    SELECT 1 FROM live_state_capture_receipts receipt
    WHERE receipt.effect_id = NEW.effect_id
      AND receipt.observation_id = NEW.observation_id
      AND receipt.evidence_json = NEW.evidence_bytes
      AND NEW.evidence_digest = grok_sha256(NEW.evidence_bytes)
      AND receipt.manifest_digest = grok_live_state_capture_manifest_digest(NEW.evidence_bytes)
)
BEGIN SELECT RAISE(ABORT, 'capture effect evidence must equal its preinserted canonical typed receipt'); END;

-- Capture IDs participate in the existing global receipt namespace in both
-- directions. Existing triggers remain intact; these additive triggers close
-- collisions without rebuilding the old closed registry.
CREATE TRIGGER live_state_capture_receipt_ids_global_unique
BEFORE INSERT ON live_state_capture_receipt_ids
WHEN EXISTS (SELECT 1 FROM finish_receipt_ids WHERE receipt_id = NEW.receipt_id)
  OR EXISTS (SELECT 1 FROM verification_receipts WHERE receipt_id = NEW.receipt_id)
  OR EXISTS (SELECT 1 FROM acceptance_receipts WHERE receipt_id = NEW.receipt_id)
  OR EXISTS (SELECT 1 FROM completion_receipts WHERE receipt_id = NEW.receipt_id)
  OR EXISTS (SELECT 1 FROM v9_completion_receipts WHERE receipt_id = NEW.receipt_id)
BEGIN SELECT RAISE(ABORT, 'capture receipt identity must be globally unique'); END;
CREATE TRIGGER v9_completion_receipts_v23_capture_id_unique
BEFORE INSERT ON v9_completion_receipts
WHEN EXISTS (
    SELECT 1 FROM live_state_capture_receipt_ids capture
    WHERE capture.receipt_id = NEW.receipt_id
)
BEGIN SELECT RAISE(ABORT, 'completion receipt identity collides with live-state capture'); END;
CREATE TRIGGER live_state_capture_receipt_ids_complete
AFTER INSERT ON live_state_capture_receipt_ids
WHEN NOT EXISTS (
    SELECT 1 FROM live_state_capture_receipts receipt
    WHERE receipt.receipt_id = NEW.receipt_id
      AND receipt.sprint_id = NEW.sprint_id
      AND receipt.contract_version = NEW.contract_version
)
BEGIN SELECT RAISE(ABORT, 'capture receipt identity requires its new typed receipt'); END;
CREATE TRIGGER finish_receipt_ids_capture_id_unique
BEFORE INSERT ON finish_receipt_ids
WHEN EXISTS (
    SELECT 1 FROM live_state_capture_receipt_ids WHERE receipt_id = NEW.receipt_id
)
BEGIN SELECT RAISE(ABORT, 'finish receipt identity must be globally unique'); END;
CREATE TRIGGER verification_receipts_capture_id_unique
BEFORE INSERT ON verification_receipts
WHEN EXISTS (
    SELECT 1 FROM live_state_capture_receipt_ids WHERE receipt_id = NEW.receipt_id
)
BEGIN SELECT RAISE(ABORT, 'receipt identity must be globally unique'); END;
CREATE TRIGGER acceptance_receipts_capture_id_unique
BEFORE INSERT ON acceptance_receipts
WHEN EXISTS (
    SELECT 1 FROM live_state_capture_receipt_ids WHERE receipt_id = NEW.receipt_id
)
BEGIN SELECT RAISE(ABORT, 'receipt identity must be globally unique'); END;
CREATE TRIGGER completion_receipts_capture_id_unique
BEFORE INSERT ON completion_receipts
WHEN EXISTS (
    SELECT 1 FROM live_state_capture_receipt_ids WHERE receipt_id = NEW.receipt_id
)
BEGIN SELECT RAISE(ABORT, 'receipt identity must be globally unique'); END;

-- A claimed capture retains a bounded stable evidence interval and blocks
-- sprint movement until its truthful terminal observation exists. Capture
-- itself must run while the LSV cleanup effect is still open; once capture
-- terminalizes, that cleanup must follow the completed interval before any
-- v22 completion predicate can pass.
CREATE TRIGGER agent_events_v23_unobserved_capture_claim_phase_fence
BEFORE INSERT ON agent_events
WHEN json_type(CAST(NEW.event_json AS TEXT), '$.payload.SprintStateChanged') = 'object'
 AND EXISTS (
    SELECT 1
    FROM runner_effect_dispatch_claims claim
    JOIN live_state_capture_dispatch_claim_authorities authority
      ON authority.dispatch_claim_id = claim.dispatch_claim_id
    LEFT JOIN effect_observations observation ON observation.effect_id = claim.effect_id
    WHERE claim.sprint_id = NEW.sprint_id AND observation.effect_id IS NULL
 )
BEGIN SELECT RAISE(ABORT, 'unobserved live-state capture blocks sprint phase transition'); END;

CREATE TRIGGER effect_observations_v23_capture_before_lsv_cleanup
BEFORE INSERT ON effect_observations
WHEN EXISTS (
    SELECT 1
    FROM live_state_capture_effect_kinds subtype
    JOIN sprint_live_state_capture_admissions admission
      ON admission.effect_id = subtype.effect_id
     AND admission.sprint_id = subtype.sprint_id
    JOIN runner_launch_cleanup_admissions cleanup
      ON cleanup.launch_id = admission.runner_launch_id
     AND cleanup.sprint_id = admission.sprint_id
    JOIN effect_observations cleanup_observation
      ON cleanup_observation.effect_id = cleanup.cleanup_effect_id
    WHERE subtype.effect_id = NEW.effect_id
 )
BEGIN SELECT RAISE(ABORT, 'live-state capture must precede its verifier cleanup'); END;

CREATE TRIGGER effect_observations_v23_lsv_cleanup_after_capture
BEFORE INSERT ON effect_observations
WHEN EXISTS (
    SELECT 1
    FROM runner_launch_cleanup_admissions cleanup
    JOIN live_state_verifier_launch_purposes marker
      ON marker.launch_id = cleanup.launch_id AND marker.sprint_id = cleanup.sprint_id
    JOIN sprint_live_state_capture_admissions admission
      ON admission.runner_launch_id = marker.launch_id
     AND admission.sprint_id = marker.sprint_id
    JOIN live_state_capture_effect_kinds subtype
      ON subtype.effect_id = admission.effect_id
     AND subtype.sprint_id = admission.sprint_id
    LEFT JOIN effect_observations capture
      ON capture.effect_id = subtype.effect_id
    WHERE cleanup.cleanup_effect_id = NEW.effect_id
      AND (capture.effect_id IS NULL OR capture.observed_at_unix_ms > NEW.observed_at_unix_ms)
 )
BEGIN SELECT RAISE(ABORT, 'live-state verifier cleanup must follow the capture evidence interval'); END;

-- The v19 authority registry is closed, so the parent v17 claim accepts either
-- its exact historical v22 companion or the exact supplemental capture
-- companion. The old authority table and all historical rows remain unchanged.
DROP TRIGGER runner_effect_dispatch_claims_v22_companion_required;
CREATE TRIGGER runner_effect_dispatch_claims_v23_companion_required
BEFORE INSERT ON runner_effect_dispatch_claims
WHEN NOT EXISTS (
    SELECT 1 FROM runner_effect_dispatch_claim_authorities authority
    WHERE authority.dispatch_claim_id = NEW.dispatch_claim_id
      AND authority.contract_version = NEW.contract_version
      AND (
          (authority.authority_class = 'TaskRunning'
           AND authority.running_boundary_id = NEW.running_boundary_id)
          OR (authority.authority_class = 'TaskFormalCheck'
              AND NEW.running_boundary_id IS NULL
              AND EXISTS (
                  SELECT 1 FROM task_attempt_formal_check_admissions admission
                  WHERE admission.admission_id = authority.formal_check_admission_id
                    AND admission.effect_id = NEW.effect_id
                    AND admission.sprint_id = NEW.sprint_id
              ))
          OR (authority.authority_class = 'TaskIntegration'
              AND NEW.running_boundary_id IS NULL
              AND EXISTS (
                  SELECT 1 FROM task_attempt_integration_admissions admission
                  WHERE admission.admission_id = authority.integration_admission_id
                    AND admission.effect_id = NEW.effect_id
                    AND admission.sprint_id = NEW.sprint_id
              ))
          OR (authority.authority_class = 'SprintFinalVerification'
              AND NEW.running_boundary_id IS NULL
              AND EXISTS (
                  SELECT 1 FROM sprint_final_verification_admissions admission
                  WHERE admission.sprint_phase_event_id = authority.sprint_phase_event_id
                    AND admission.effect_id = NEW.effect_id
                    AND admission.sprint_id = NEW.sprint_id
              ))
          OR (authority.authority_class = 'SprintApplication'
              AND NEW.running_boundary_id IS NULL
              AND EXISTS (
                  SELECT 1 FROM sprint_application_admissions admission
                  WHERE admission.sprint_phase_event_id = authority.sprint_phase_event_id
                    AND admission.effect_id = NEW.effect_id
                    AND admission.sprint_id = NEW.sprint_id
              ))
      )
)
AND NOT EXISTS (
    SELECT 1
    FROM live_state_capture_dispatch_claim_authorities authority
    JOIN sprint_live_state_capture_admissions admission
      ON admission.admission_id = authority.admission_id
     AND admission.sprint_id = authority.sprint_id
    WHERE authority.dispatch_claim_id = NEW.dispatch_claim_id
      AND authority.effect_id = NEW.effect_id
      AND authority.sprint_id = NEW.sprint_id
      AND admission.effect_id = NEW.effect_id
      AND admission.runner_launch_id = NEW.launch_id
      AND admission.runner_session_id = NEW.session_id
      AND NEW.running_boundary_id IS NULL
      AND authority.contract_version = NEW.contract_version
      AND admission.contract_version = NEW.contract_version
)
BEGIN SELECT RAISE(ABORT, 'v23 runner dispatch claim requires exact implemented authority companion'); END;

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
                    AND json_extract(CAST(phase.event_json AS TEXT), '$.payload.SprintStateChanged.from') = 'Running'
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

CREATE TRIGGER live_state_capture_dispatch_claim_authorities_json_matches
BEFORE INSERT ON live_state_capture_dispatch_claim_authorities
WHEN NOT COALESCE((
    json_valid(CAST(NEW.authority_json AS TEXT))
    AND json_type(CAST(NEW.authority_json AS TEXT), '$.contract_version') = 'integer'
    AND json_type(CAST(NEW.authority_json AS TEXT), '$.dispatch_claim_id') = 'text'
    AND json_type(CAST(NEW.authority_json AS TEXT), '$.sprint_id') = 'text'
    AND json_type(CAST(NEW.authority_json AS TEXT), '$.admission_id') = 'text'
    AND json_type(CAST(NEW.authority_json AS TEXT), '$.effect_id') = 'text'
    AND json_type(CAST(NEW.authority_json AS TEXT), '$.opaque_transport_request_digest') = 'text'
    AND json_extract(CAST(NEW.authority_json AS TEXT), '$.contract_version') = NEW.contract_version
    AND json_extract(CAST(NEW.authority_json AS TEXT), '$.dispatch_claim_id') = NEW.dispatch_claim_id
    AND json_extract(CAST(NEW.authority_json AS TEXT), '$.sprint_id') = NEW.sprint_id
    AND json_extract(CAST(NEW.authority_json AS TEXT), '$.admission_id') = NEW.admission_id
    AND json_extract(CAST(NEW.authority_json AS TEXT), '$.effect_id') = NEW.effect_id
    AND json_extract(CAST(NEW.authority_json AS TEXT), '$.opaque_transport_request_digest') = NEW.opaque_transport_request_digest
), 0)
BEGIN SELECT RAISE(ABORT, 'capture claim authority JSON must match indexed identity'); END;

CREATE TRIGGER runner_effect_dispatch_claims_v23_capture_identity_match
BEFORE INSERT ON runner_effect_dispatch_claims
WHEN EXISTS (
    SELECT 1 FROM live_state_capture_dispatch_claim_authorities authority
    WHERE authority.dispatch_claim_id = NEW.dispatch_claim_id
)
AND NOT EXISTS (
    SELECT 1
    FROM live_state_capture_dispatch_claim_authorities authority
    JOIN sprint_live_state_capture_admissions admission
      ON admission.admission_id = authority.admission_id
     AND admission.sprint_id = authority.sprint_id
    JOIN sprint_live_state_capture_plans plan
      ON plan.plan_id = admission.plan_id
     AND plan.sprint_id = admission.sprint_id
    JOIN live_state_capture_effect_kinds subtype
      ON subtype.effect_id = admission.effect_id
     AND subtype.sprint_id = admission.sprint_id
    JOIN effect_intents intent
      ON intent.effect_id = subtype.effect_id
     AND intent.sprint_id = subtype.sprint_id
    JOIN effect_session_bindings binding
      ON binding.effect_id = intent.effect_id
     AND binding.sprint_id = intent.sprint_id
    JOIN runner_launch_intents launch
      ON launch.launch_id = binding.launch_id
     AND launch.sprint_id = binding.sprint_id
    JOIN runner_session_policies session
      ON session.session_id = binding.session_id
     AND session.sprint_id = binding.sprint_id
     AND session.launch_id = binding.launch_id
    JOIN live_state_verifier_launch_purposes launch_marker
      ON launch_marker.launch_id = launch.launch_id
     AND launch_marker.sprint_id = launch.sprint_id
    JOIN live_state_verifier_session_purposes session_marker
      ON session_marker.session_id = session.session_id
     AND session_marker.sprint_id = session.sprint_id
     AND session_marker.launch_id = launch.launch_id
    JOIN runner_launch_cleanup_admissions cleanup
      ON cleanup.launch_id = launch.launch_id
     AND cleanup.sprint_id = launch.sprint_id
     AND cleanup.session_id = session.session_id
    LEFT JOIN effect_observations cleanup_observation
      ON cleanup_observation.effect_id = cleanup.cleanup_effect_id
    WHERE authority.dispatch_claim_id = NEW.dispatch_claim_id
      AND authority.effect_id = NEW.effect_id
      AND authority.sprint_id = NEW.sprint_id
      AND admission.effect_id = NEW.effect_id
      AND admission.runner_launch_id = NEW.launch_id
      AND admission.runner_session_id = NEW.session_id
      AND admission.plan_id = plan.plan_id
      AND admission.plan_digest = plan.plan_digest
      AND admission.request_digest = NEW.request_digest
      AND authority.opaque_transport_request_digest = NEW.opaque_transport_request_digest
      AND admission.expected_snapshot = NEW.input_snapshot
      AND admission.policy_hash = NEW.policy_hash
      AND binding.launch_id = NEW.launch_id
      AND binding.session_id = NEW.session_id
      AND launch_marker.plan_id = plan.plan_id
      AND session_marker.plan_id = plan.plan_id
      AND launch_marker.plan_digest = plan.plan_digest
      AND session_marker.plan_digest = plan.plan_digest
      AND launch.purpose = 'FinalVerifier'
      AND session.purpose = 'FinalVerifier'
      AND json_extract(CAST(launch.intent_json AS TEXT), '$.purpose') = 'LiveStateVerifier'
      AND json_extract(CAST(session.record_json AS TEXT), '$.purpose') = 'LiveStateVerifier'
      AND intent.effect_kind = 'ReadRelativeFile'
      AND json_extract(CAST(intent.intent_json AS TEXT), '$.kind') = 'CaptureWorkspaceState'
      AND intent.task_id IS NULL
      AND intent.worker_id IS NULL
      AND intent.worker_lease_id IS NULL
      AND intent.worker_lease_epoch IS NULL
      AND launch.worker_id IS NULL
      AND session.worker_id IS NULL
      AND launch.worker_lease_id IS NULL
      AND session.worker_lease_id IS NULL
      AND NEW.running_boundary_id IS NULL
      AND intent.request_digest = NEW.request_digest
      AND intent.policy_hash = NEW.policy_hash
      AND intent.input_snapshot = NEW.input_snapshot
      AND intent.policy_hash = launch.policy_hash
      AND intent.policy_hash = session.policy_hash
      AND cleanup_observation.effect_id IS NULL
      AND NOT EXISTS (
          SELECT 1 FROM effect_observations observation
          WHERE observation.effect_id = NEW.effect_id
      )
      AND NOT EXISTS (
          SELECT 1 FROM sprint_terminal_states terminal
          WHERE terminal.sprint_id = NEW.sprint_id
      )
      AND NOT EXISTS (
          SELECT 1 FROM sprint_non_success_terminal_outcomes terminal
          WHERE terminal.sprint_id = NEW.sprint_id
      )
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
      AND (
          (plan.branch = 'Applied'
           AND json_extract(CAST((
               SELECT phase.event_json
               FROM agent_events phase
               WHERE phase.sprint_id = NEW.sprint_id
                 AND json_type(CAST(phase.event_json AS TEXT), '$.payload.SprintStateChanged') = 'object'
               ORDER BY phase.sequence DESC LIMIT 1
           ) AS TEXT), '$.payload.SprintStateChanged.to') = 'Applying')
          OR
          (plan.branch = 'VerifiedNoOp'
           AND json_extract(CAST((
               SELECT phase.event_json
               FROM agent_events phase
               WHERE phase.sprint_id = NEW.sprint_id
                 AND json_type(CAST(phase.event_json AS TEXT), '$.payload.SprintStateChanged') = 'object'
               ORDER BY phase.sequence DESC LIMIT 1
           ) AS TEXT), '$.payload.SprintStateChanged.to') = 'FinalVerification')
      )
      AND authority.contract_version = NEW.contract_version
      AND admission.contract_version = NEW.contract_version
      AND plan.contract_version = NEW.contract_version
      AND subtype.contract_version = NEW.contract_version
      AND binding.contract_version = NEW.contract_version
      AND launch.contract_version = NEW.contract_version
      AND session.contract_version = NEW.contract_version
      AND launch_marker.contract_version = NEW.contract_version
      AND session_marker.contract_version = NEW.contract_version
      AND intent.contract_version = NEW.contract_version
)
BEGIN SELECT RAISE(ABORT, 'capture dispatch claim must match exact plan, admission, runner, and pristine effect'); END;
