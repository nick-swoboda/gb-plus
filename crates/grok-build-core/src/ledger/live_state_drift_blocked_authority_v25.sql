-- Schema v25 adds one typed terminal authority for a successful descriptor-
-- relative capture whose observed manifest differs from its selected finish
-- snapshot. The closed v9 terminal_cleanup_proofs shape is not rebuilt or
-- overloaded: drift is an additive, mutually exclusive proof family.

-- Refuse to install the second proof family over an already-ambiguous v24
-- terminal image. Every historical terminal outcome must have exactly its old
-- proof row, and every old proof row must belong to a terminal outcome.
CREATE TEMP TABLE v25_terminal_proof_migration_guard (
    orphan_outcomes INTEGER NOT NULL CHECK (orphan_outcomes = 0),
    orphan_proofs INTEGER NOT NULL CHECK (orphan_proofs = 0)
) STRICT;

INSERT INTO v25_terminal_proof_migration_guard (orphan_outcomes, orphan_proofs)
SELECT
    (SELECT COUNT(*)
       FROM sprint_non_success_terminal_outcomes outcome
       LEFT JOIN terminal_cleanup_proofs proof ON proof.sprint_id = outcome.sprint_id
      WHERE proof.sprint_id IS NULL),
    (SELECT COUNT(*)
       FROM terminal_cleanup_proofs proof
       LEFT JOIN sprint_non_success_terminal_outcomes outcome
         ON outcome.sprint_id = proof.sprint_id
      WHERE outcome.sprint_id IS NULL);

DROP TABLE v25_terminal_proof_migration_guard;

CREATE TABLE sprint_live_state_drift_blocked_proofs (
    sprint_id TEXT PRIMARY KEY NOT NULL,
    terminal_record_id TEXT NOT NULL UNIQUE
        CHECK (length(terminal_record_id) BETWEEN 1 AND 4096),
    terminal_evidence_digest TEXT NOT NULL CHECK (
        length(terminal_evidence_digest) = 64
        AND terminal_evidence_digest NOT GLOB '*[^0-9a-f]*'
    ),
    branch TEXT NOT NULL CHECK (branch IN ('Applied', 'VerifiedNoOp')),
    final_verification_receipt_id TEXT NOT NULL
        CHECK (length(final_verification_receipt_id) BETWEEN 1 AND 4096),
    task_integration_receipt_id TEXT,
    application_receipt_id TEXT,
    rollback_reference_id TEXT,
    capture_receipt_id TEXT NOT NULL UNIQUE,
    capture_admission_id TEXT NOT NULL UNIQUE,
    capture_plan_id TEXT NOT NULL UNIQUE,
    capture_plan_digest TEXT NOT NULL CHECK (
        length(capture_plan_digest) = 64
        AND capture_plan_digest NOT GLOB '*[^0-9a-f]*'
    ),
    capture_effect_id TEXT NOT NULL UNIQUE,
    capture_observation_id TEXT NOT NULL UNIQUE,
    capture_dispatch_claim_id TEXT NOT NULL UNIQUE,
    runner_launch_id TEXT NOT NULL UNIQUE,
    runner_session_id TEXT NOT NULL UNIQUE,
    capture_evidence_digest TEXT NOT NULL CHECK (
        length(capture_evidence_digest) = 64
        AND capture_evidence_digest NOT GLOB '*[^0-9a-f]*'
    ),
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
    grant_hash TEXT NOT NULL CHECK (
        length(grant_hash) = 64 AND grant_hash NOT GLOB '*[^0-9a-f]*'
    ),
    policy_hash TEXT NOT NULL CHECK (
        length(policy_hash) = 64 AND policy_hash NOT GLOB '*[^0-9a-f]*'
    ),
    policy_version INTEGER NOT NULL CHECK (policy_version > 0),
    verifier_cleanup_receipt_id TEXT NOT NULL UNIQUE,
    required_cleanup_set_digest TEXT NOT NULL CHECK (
        length(required_cleanup_set_digest) = 64
        AND required_cleanup_set_digest NOT GLOB '*[^0-9a-f]*'
    ),
    capture_started_at_unix_ms INTEGER NOT NULL CHECK (
        capture_started_at_unix_ms > 0
    ),
    captured_at_unix_ms INTEGER NOT NULL CHECK (
        captured_at_unix_ms >= capture_started_at_unix_ms
    ),
    verifier_cleaned_at_unix_ms INTEGER NOT NULL CHECK (
        verifier_cleaned_at_unix_ms >= captured_at_unix_ms
    ),
    blocked_at_unix_ms INTEGER NOT NULL CHECK (
        blocked_at_unix_ms >= verifier_cleaned_at_unix_ms
    ),
    contract_version INTEGER NOT NULL CHECK (contract_version > 0),
    proof_json BLOB NOT NULL CHECK (length(proof_json) BETWEEN 1 AND 1048576),
    CHECK (observed_snapshot = manifest_digest AND observed_snapshot != expected_snapshot),
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
    FOREIGN KEY (terminal_record_id)
        REFERENCES sprint_non_success_terminal_outcomes(record_id)
        ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED,
    FOREIGN KEY (terminal_record_id)
        REFERENCES agent_events(event_id)
        ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED,
    FOREIGN KEY (sprint_id, final_verification_receipt_id)
        REFERENCES verification_receipts(sprint_id, receipt_id) ON DELETE RESTRICT,
    FOREIGN KEY (sprint_id, task_integration_receipt_id)
        REFERENCES task_integration_receipts(sprint_id, receipt_id) ON DELETE RESTRICT,
    FOREIGN KEY (sprint_id, application_receipt_id)
        REFERENCES application_receipts(sprint_id, receipt_id) ON DELETE RESTRICT,
    FOREIGN KEY (sprint_id, rollback_reference_id)
        REFERENCES rollback_references(sprint_id, reference_id) ON DELETE RESTRICT,
    FOREIGN KEY (sprint_id, capture_receipt_id)
        REFERENCES live_state_capture_receipts(sprint_id, receipt_id) ON DELETE RESTRICT,
    FOREIGN KEY (sprint_id, capture_admission_id)
        REFERENCES sprint_live_state_capture_admissions(sprint_id, admission_id)
        ON DELETE RESTRICT,
    FOREIGN KEY (sprint_id, capture_plan_id)
        REFERENCES sprint_live_state_capture_plans(sprint_id, plan_id) ON DELETE RESTRICT,
    FOREIGN KEY (sprint_id, capture_effect_id)
        REFERENCES live_state_capture_effect_kinds(sprint_id, effect_id) ON DELETE RESTRICT,
    FOREIGN KEY (capture_observation_id)
        REFERENCES effect_observations(observation_id) ON DELETE RESTRICT,
    FOREIGN KEY (capture_dispatch_claim_id)
        REFERENCES runner_effect_dispatch_claims(dispatch_claim_id) ON DELETE RESTRICT,
    FOREIGN KEY (sprint_id, runner_launch_id)
        REFERENCES live_state_verifier_launch_purposes(sprint_id, launch_id)
        ON DELETE RESTRICT,
    FOREIGN KEY (sprint_id, runner_session_id)
        REFERENCES live_state_verifier_session_purposes(sprint_id, session_id)
        ON DELETE RESTRICT,
    FOREIGN KEY (sprint_id, verifier_cleanup_receipt_id)
        REFERENCES worker_cleanup_receipts(sprint_id, receipt_id) ON DELETE RESTRICT
) STRICT, WITHOUT ROWID;

-- The canonical typed envelope authenticates every normalized column. The
-- deterministic scalar decodes, validates, and byte-reencodes the Rust
-- LiveStateDriftBlockedProof before returning one.
CREATE TRIGGER sprint_live_state_drift_blocked_proofs_canonical_envelope
BEFORE INSERT ON sprint_live_state_drift_blocked_proofs
WHEN grok_live_state_drift_blocked_proof_canonical(NEW.proof_json) != 1
 OR json_extract(CAST(NEW.proof_json AS TEXT), '$.contract_version') != NEW.contract_version
 OR json_extract(CAST(NEW.proof_json AS TEXT), '$.sprint_id') != NEW.sprint_id
 OR json_extract(CAST(NEW.proof_json AS TEXT), '$.terminal_record_id') != NEW.terminal_record_id
 OR json_extract(CAST(NEW.proof_json AS TEXT), '$.terminal_evidence_digest') != NEW.terminal_evidence_digest
 OR json_extract(CAST(NEW.proof_json AS TEXT), '$.capture_receipt_id') != NEW.capture_receipt_id
 OR json_extract(CAST(NEW.proof_json AS TEXT), '$.capture_admission_id') != NEW.capture_admission_id
 OR json_extract(CAST(NEW.proof_json AS TEXT), '$.capture_plan_id') != NEW.capture_plan_id
 OR json_extract(CAST(NEW.proof_json AS TEXT), '$.capture_plan_digest') != NEW.capture_plan_digest
 OR json_extract(CAST(NEW.proof_json AS TEXT), '$.capture_effect_id') != NEW.capture_effect_id
 OR json_extract(CAST(NEW.proof_json AS TEXT), '$.capture_observation_id') != NEW.capture_observation_id
 OR json_extract(CAST(NEW.proof_json AS TEXT), '$.capture_dispatch_claim_id') != NEW.capture_dispatch_claim_id
 OR json_extract(CAST(NEW.proof_json AS TEXT), '$.runner_launch_id') != NEW.runner_launch_id
 OR json_extract(CAST(NEW.proof_json AS TEXT), '$.runner_session_id') != NEW.runner_session_id
 OR json_extract(CAST(NEW.proof_json AS TEXT), '$.capture_evidence_digest') != NEW.capture_evidence_digest
 OR json_extract(CAST(NEW.proof_json AS TEXT), '$.expected_snapshot') != NEW.expected_snapshot
 OR json_extract(CAST(NEW.proof_json AS TEXT), '$.observed_snapshot') != NEW.observed_snapshot
 OR json_extract(CAST(NEW.proof_json AS TEXT), '$.manifest_digest') != NEW.manifest_digest
 OR json_extract(CAST(NEW.proof_json AS TEXT), '$.grant_hash') != NEW.grant_hash
 OR json_extract(CAST(NEW.proof_json AS TEXT), '$.policy_hash') != NEW.policy_hash
 OR json_extract(CAST(NEW.proof_json AS TEXT), '$.policy_version') != NEW.policy_version
 OR json_extract(CAST(NEW.proof_json AS TEXT), '$.verifier_cleanup_receipt_id') != NEW.verifier_cleanup_receipt_id
 OR json_extract(CAST(NEW.proof_json AS TEXT), '$.required_cleanup_set_digest') != NEW.required_cleanup_set_digest
 OR json_extract(CAST(NEW.proof_json AS TEXT), '$.capture_started_at_unix_ms') != NEW.capture_started_at_unix_ms
 OR json_extract(CAST(NEW.proof_json AS TEXT), '$.captured_at_unix_ms') != NEW.captured_at_unix_ms
 OR json_extract(CAST(NEW.proof_json AS TEXT), '$.verifier_cleaned_at_unix_ms') != NEW.verifier_cleaned_at_unix_ms
 OR json_extract(CAST(NEW.proof_json AS TEXT), '$.blocked_at_unix_ms') != NEW.blocked_at_unix_ms
 OR (
      NEW.branch = 'Applied'
      AND (
          json_type(CAST(NEW.proof_json AS TEXT), '$.branch.Applied') IS NOT 'object'
          OR json_type(CAST(NEW.proof_json AS TEXT), '$.branch.VerifiedNoOp') IS NOT NULL
          OR json_extract(CAST(NEW.proof_json AS TEXT), '$.branch.Applied.final_verification_receipt_id') IS NOT NEW.final_verification_receipt_id
          OR json_extract(CAST(NEW.proof_json AS TEXT), '$.branch.Applied.application_receipt_id') IS NOT NEW.application_receipt_id
          OR json_extract(CAST(NEW.proof_json AS TEXT), '$.branch.Applied.rollback_reference_id') IS NOT NEW.rollback_reference_id
      )
 )
 OR (
      NEW.branch = 'VerifiedNoOp'
      AND (
          json_type(CAST(NEW.proof_json AS TEXT), '$.branch.VerifiedNoOp') IS NOT 'object'
          OR json_type(CAST(NEW.proof_json AS TEXT), '$.branch.Applied') IS NOT NULL
          OR json_extract(CAST(NEW.proof_json AS TEXT), '$.branch.VerifiedNoOp.final_verification_receipt_id') IS NOT NEW.final_verification_receipt_id
          OR json_extract(CAST(NEW.proof_json AS TEXT), '$.branch.VerifiedNoOp.task_integration_receipt_id') IS NOT NEW.task_integration_receipt_id
      )
 )
BEGIN SELECT RAISE(ABORT, 'drift-blocked proof JSON is noncanonical or crossed'); END;

-- Capture-independent view used by both Rust and the insertion fence to reject
-- any authorized product mutation whose proposal, terminal event, or known
-- effect time crosses the selected stable-capture cut.
CREATE VIEW sprint_live_state_v25_post_capture_mutation_blockers AS
WITH semantic_effects AS (
    SELECT intent.sprint_id,
           intent.effect_id,
           COALESCE(kind.effect_kind, intent.effect_kind) AS semantic_kind,
           intent.proposed_event_id,
           observation.observation_id,
           observation.outcome,
           observation.observed_at_unix_ms,
           observation.terminal_event_id
    FROM effect_intents intent
    LEFT JOIN finish_effect_kinds kind
      ON kind.effect_id = intent.effect_id AND kind.sprint_id = intent.sprint_id
    LEFT JOIN effect_observations observation
      ON observation.effect_id = intent.effect_id AND observation.sprint_id = intent.sprint_id
)
SELECT capture.sprint_id,
       capture.receipt_id AS capture_receipt_id,
       mutation.effect_id,
       mutation.semantic_kind,
       COALESCE(mutation.outcome, 'Missing') AS outcome
FROM live_state_capture_receipts capture
JOIN effect_intents capture_intent
  ON capture_intent.effect_id = capture.effect_id
 AND capture_intent.sprint_id = capture.sprint_id
JOIN agent_events capture_proposed_event
  ON capture_proposed_event.event_id = capture_intent.proposed_event_id
 AND capture_proposed_event.sprint_id = capture.sprint_id
JOIN semantic_effects mutation ON mutation.sprint_id = capture.sprint_id
JOIN agent_events proposed_event ON proposed_event.event_id = mutation.proposed_event_id
LEFT JOIN agent_events terminal_event ON terminal_event.event_id = mutation.terminal_event_id
WHERE mutation.semantic_kind IN (
          'CreateRegularFile', 'ReplaceRegularFile', 'DeleteRegularFile',
          'IntegrateChangeSet', 'ApplyChangeSet', 'RollbackChangeSet'
      )
  AND (
      mutation.observation_id IS NULL
      OR mutation.outcome = 'Unknown'
      OR (
          mutation.outcome IN (
              'Succeeded', 'FailedAfterKnownEffect',
              'FailedBeforeEffect', 'CancelledBeforeEffect'
          )
          AND (
              proposed_event.sequence > capture_proposed_event.sequence
              OR terminal_event.sequence > capture_proposed_event.sequence
              OR mutation.observed_at_unix_ms > capture.capture_started_at_unix_ms
          )
      )
  );

-- The authority must be inserted only after the exact successful capture and
-- zero-survivor verifier cleanup, but before its terminal outcome/event parents.
CREATE TRIGGER sprint_live_state_drift_blocked_proofs_references_match
BEFORE INSERT ON sprint_live_state_drift_blocked_proofs
WHEN NOT EXISTS (
    SELECT 1
    FROM live_state_capture_receipts capture
    JOIN sprint_live_state_capture_admissions admission
      ON admission.admission_id = capture.admission_id
     AND admission.sprint_id = capture.sprint_id
    JOIN sprint_live_state_capture_plans plan
      ON plan.plan_id = capture.plan_id AND plan.sprint_id = capture.sprint_id
    JOIN live_state_capture_effect_kinds subtype
      ON subtype.effect_id = capture.effect_id AND subtype.sprint_id = capture.sprint_id
    JOIN effect_observations capture_observation
      ON capture_observation.observation_id = capture.observation_id
     AND capture_observation.effect_id = capture.effect_id
     AND capture_observation.sprint_id = capture.sprint_id
    JOIN effect_evidence_payloads capture_evidence
      ON capture_evidence.effect_id = capture.effect_id
     AND capture_evidence.observation_id = capture.observation_id
     AND capture_evidence.sprint_id = capture.sprint_id
    JOIN agent_events capture_event
      ON capture_event.event_id = capture_observation.terminal_event_id
     AND capture_event.sprint_id = capture.sprint_id
    JOIN runner_effect_dispatch_claims claim
      ON claim.dispatch_claim_id = capture.dispatch_claim_id
     AND claim.effect_id = capture.effect_id
     AND claim.sprint_id = capture.sprint_id
    JOIN live_state_verifier_launch_purposes launch_marker
      ON launch_marker.launch_id = capture.runner_launch_id
     AND launch_marker.sprint_id = capture.sprint_id
    JOIN live_state_verifier_session_purposes session_marker
      ON session_marker.session_id = capture.runner_session_id
     AND session_marker.sprint_id = capture.sprint_id
     AND session_marker.launch_id = capture.runner_launch_id
    JOIN runner_launch_cleanup_admissions cleanup_admission
      ON cleanup_admission.launch_id = capture.runner_launch_id
     AND cleanup_admission.session_id = capture.runner_session_id
     AND cleanup_admission.sprint_id = capture.sprint_id
    JOIN worker_cleanup_receipts cleanup
      ON cleanup.receipt_id = NEW.verifier_cleanup_receipt_id
     AND cleanup.sprint_id = capture.sprint_id
     AND cleanup.launch_id = capture.runner_launch_id
     AND cleanup.session_id = capture.runner_session_id
     AND cleanup.effect_id = cleanup_admission.cleanup_effect_id
    JOIN effect_observations cleanup_observation
      ON cleanup_observation.observation_id = cleanup.observation_id
     AND cleanup_observation.effect_id = cleanup.effect_id
     AND cleanup_observation.sprint_id = cleanup.sprint_id
    JOIN agent_events cleanup_event
      ON cleanup_event.event_id = cleanup_observation.terminal_event_id
     AND cleanup_event.sprint_id = cleanup.sprint_id
    JOIN finish_effect_kinds cleanup_kind
      ON cleanup_kind.effect_id = cleanup.effect_id
     AND cleanup_kind.sprint_id = cleanup.sprint_id
     AND cleanup_kind.effect_kind = 'CleanupWorkerDomain'
    WHERE capture.receipt_id = NEW.capture_receipt_id
      AND capture.sprint_id = NEW.sprint_id
      AND capture.admission_id = NEW.capture_admission_id
      AND capture.plan_id = NEW.capture_plan_id
      AND capture.plan_digest = NEW.capture_plan_digest
      AND capture.effect_id = NEW.capture_effect_id
      AND capture.observation_id = NEW.capture_observation_id
      AND capture.dispatch_claim_id = NEW.capture_dispatch_claim_id
      AND capture.runner_launch_id = NEW.runner_launch_id
      AND capture.runner_session_id = NEW.runner_session_id
      AND capture.expected_snapshot = NEW.expected_snapshot
      AND capture.observed_snapshot = NEW.observed_snapshot
      AND capture.manifest_digest = NEW.manifest_digest
      AND capture.grant_hash = NEW.grant_hash
      AND capture.policy_hash = NEW.policy_hash
      AND capture.policy_version = NEW.policy_version
      AND capture.capture_started_at_unix_ms = NEW.capture_started_at_unix_ms
      AND capture.captured_at_unix_ms = NEW.captured_at_unix_ms
      AND admission.plan_id = plan.plan_id
      AND admission.plan_digest = plan.plan_digest
      AND admission.effect_id = capture.effect_id
      AND admission.runner_launch_id = capture.runner_launch_id
      AND admission.runner_session_id = capture.runner_session_id
      AND launch_marker.plan_id = plan.plan_id
      AND launch_marker.plan_digest = plan.plan_digest
      AND session_marker.plan_id = plan.plan_id
      AND session_marker.plan_digest = plan.plan_digest
      AND subtype.admission_id = admission.admission_id
      AND capture_observation.outcome = 'Succeeded'
      AND capture_observation.dispatch_claim_id = capture.dispatch_claim_id
      AND capture_observation.observed_at_unix_ms = capture.captured_at_unix_ms
      AND capture_evidence.evidence_digest = NEW.capture_evidence_digest
      AND capture_evidence.evidence_digest = grok_sha256(capture_evidence.evidence_bytes)
      AND cleanup_observation.outcome = 'Succeeded'
      AND cleanup.surviving_processes = 0
      AND cleanup.policy_hash = NEW.policy_hash
      AND cleanup.grant_hash = NEW.grant_hash
      AND cleanup.policy_version = NEW.policy_version
      AND cleanup.cleaned_at_unix_ms = NEW.verifier_cleaned_at_unix_ms
      AND cleanup_observation.observed_at_unix_ms = NEW.verifier_cleaned_at_unix_ms
      AND capture_event.sequence < cleanup_event.sequence
      AND plan.expected_snapshot = NEW.expected_snapshot
      AND plan.final_verification_receipt_id = NEW.final_verification_receipt_id
      AND plan.required_cleanup_set_digest = NEW.required_cleanup_set_digest
      AND plan.planned_at_unix_ms <= NEW.capture_started_at_unix_ms
      AND NOT EXISTS (
          SELECT 1
          FROM sprint_live_state_capture_plan_cleanups prior
          JOIN worker_cleanup_receipts prior_receipt
            ON prior_receipt.receipt_id = prior.cleanup_receipt_id
           AND prior_receipt.sprint_id = prior.sprint_id
          WHERE prior.plan_id = plan.plan_id
            AND prior.sprint_id = plan.sprint_id
            AND prior_receipt.cleaned_at_unix_ms > NEW.capture_started_at_unix_ms
      )
      AND NOT EXISTS (
          SELECT 1 FROM sprint_live_state_capture_plan_cleanups prior
          WHERE prior.plan_id = plan.plan_id
            AND prior.sprint_id = plan.sprint_id
            AND prior.cleanup_receipt_id = NEW.verifier_cleanup_receipt_id
      )
      AND (SELECT COUNT(*) FROM runner_launch_intents launch
           WHERE launch.sprint_id = NEW.sprint_id) = plan.required_cleanup_count + 1
      AND (SELECT COUNT(*) FROM worker_cleanup_receipts receipt
           WHERE receipt.sprint_id = NEW.sprint_id) = plan.required_cleanup_count + 1
      AND NOT EXISTS (
          SELECT 1
          FROM runner_launch_intents launch
          LEFT JOIN worker_cleanup_receipts receipt
            ON receipt.sprint_id = launch.sprint_id AND receipt.launch_id = launch.launch_id
          WHERE launch.sprint_id = NEW.sprint_id AND receipt.receipt_id IS NULL
      )
      AND NOT EXISTS (
          SELECT 1
          FROM effect_session_bindings binding
          JOIN effect_intents command
            ON command.effect_id = binding.effect_id
           AND command.sprint_id = binding.sprint_id
          WHERE binding.sprint_id = NEW.sprint_id
            AND binding.launch_id = NEW.runner_launch_id
            AND binding.session_id = NEW.runner_session_id
            AND command.effect_kind = 'RunCommand'
      )
      AND NOT EXISTS (
          SELECT 1
          FROM effect_session_bindings binding
          JOIN effect_intents command
            ON command.effect_id = binding.effect_id
           AND command.sprint_id = binding.sprint_id
          JOIN runner_launch_intents launch
            ON launch.launch_id = binding.launch_id
           AND launch.sprint_id = binding.sprint_id
          JOIN worker_cleanup_receipts launch_cleanup
            ON launch_cleanup.launch_id = binding.launch_id
           AND launch_cleanup.sprint_id = binding.sprint_id
          LEFT JOIN effect_observations observation
            ON observation.effect_id = command.effect_id
           AND observation.sprint_id = command.sprint_id
          LEFT JOIN command_domain_cleanup_proofs command_cleanup
            ON command_cleanup.effect_id = command.effect_id
          WHERE binding.sprint_id = NEW.sprint_id
            AND launch.purpose IN ('TaskWorker', 'FinalVerifier')
            AND command.effect_kind = 'RunCommand'
            AND (
                observation.observation_id IS NULL
                OR observation.outcome = 'Unknown'
                OR command_cleanup.effect_id IS NULL
                OR command_cleanup.sprint_id IS NOT binding.sprint_id
                OR command_cleanup.launch_id IS NOT binding.launch_id
                OR command_cleanup.session_id IS NOT binding.session_id
                OR command_cleanup.observation_id IS NOT observation.observation_id
                OR command_cleanup.request_digest IS NOT command.request_digest
                OR command_cleanup.backend IS NOT launch_cleanup.platform_backend
                OR command_cleanup.contract_version != NEW.contract_version
            )
      )
      AND NOT EXISTS (SELECT 1 FROM rollback_receipts rollback
                      WHERE rollback.sprint_id = NEW.sprint_id)
      AND NOT EXISTS (SELECT 1 FROM live_conflict_receipts conflict
                      WHERE conflict.sprint_id = NEW.sprint_id)
      AND (
          (NEW.branch = 'Applied'
           AND plan.branch = 'Applied'
           AND plan.application_receipt_id = NEW.application_receipt_id
           AND plan.rollback_reference_id = NEW.rollback_reference_id
           AND EXISTS (
               SELECT 1 FROM application_receipts application
               WHERE application.receipt_id = NEW.application_receipt_id
                 AND application.sprint_id = NEW.sprint_id
                 AND application.result_snapshot = NEW.expected_snapshot
                 AND application.applied_at_unix_ms <= NEW.capture_started_at_unix_ms
           ))
          OR
          (NEW.branch = 'VerifiedNoOp'
           AND plan.branch = 'VerifiedNoOp'
           AND plan.task_integration_receipt_id = NEW.task_integration_receipt_id
           AND NOT EXISTS (
               SELECT 1 FROM finish_effect_kinds application
               WHERE application.sprint_id = NEW.sprint_id
                 AND application.effect_kind = 'ApplyChangeSet'
           ))
      )
      AND capture.contract_version = NEW.contract_version
      AND admission.contract_version = NEW.contract_version
      AND plan.contract_version = NEW.contract_version
      AND subtype.contract_version = NEW.contract_version
      AND claim.contract_version = NEW.contract_version
      AND launch_marker.contract_version = NEW.contract_version
      AND session_marker.contract_version = NEW.contract_version
      AND cleanup.contract_version = NEW.contract_version
)
OR EXISTS (
    SELECT 1 FROM sprint_live_state_v25_post_capture_mutation_blockers blocker
    WHERE blocker.sprint_id = NEW.sprint_id
      AND blocker.capture_receipt_id = NEW.capture_receipt_id
)
BEGIN SELECT RAISE(ABORT, 'drift-blocked proof crosses its capture, branch, cleanup, or mutation cut'); END;

-- The pre-parent proof and the closed old proof family are an exact XOR. A
-- raw terminal outcome cannot commit without exactly one typed proof family.
CREATE TRIGGER sprint_live_state_drift_blocked_proofs_no_existing_terminal
BEFORE INSERT ON sprint_live_state_drift_blocked_proofs
WHEN EXISTS (SELECT 1 FROM terminal_cleanup_proofs old WHERE old.sprint_id = NEW.sprint_id)
  OR EXISTS (SELECT 1 FROM sprint_non_success_terminal_outcomes terminal
             WHERE terminal.sprint_id = NEW.sprint_id)
  OR EXISTS (SELECT 1 FROM sprint_completion_live_state_capture_links link
             WHERE link.sprint_id = NEW.sprint_id)
  OR EXISTS (SELECT 1 FROM sprint_completion_proof_states proof
             WHERE proof.sprint_id = NEW.sprint_id)
  OR EXISTS (SELECT 1 FROM sprint_terminal_states terminal
             WHERE terminal.sprint_id = NEW.sprint_id)
BEGIN SELECT RAISE(ABORT, 'drift-blocked proof must precede one new non-success terminal'); END;

CREATE TRIGGER sprint_live_state_drift_blocked_proofs_no_active_lease
BEFORE INSERT ON sprint_live_state_drift_blocked_proofs
WHEN EXISTS (
    SELECT 1 FROM active_worker_leases active
    WHERE active.sprint_id = NEW.sprint_id
)
BEGIN SELECT RAISE(ABORT, 'drift-blocked proof requires every worker lease released'); END;

-- Once schema-v15 has frozen a sprint for Unknown terminalization, no later
-- proof family may reinterpret the same history as a known Blocked outcome.
CREATE TRIGGER sprint_live_state_drift_blocked_proofs_unknown_pending_fence
BEFORE INSERT ON sprint_live_state_drift_blocked_proofs
WHEN EXISTS (
    SELECT 1 FROM sprint_unknown_terminalization_pending pending
    LEFT JOIN sprint_unknown_terminalization_closures closure
      ON closure.marker_id = pending.marker_id AND closure.sprint_id = pending.sprint_id
    WHERE pending.sprint_id = NEW.sprint_id AND closure.marker_id IS NULL
)
BEGIN SELECT RAISE(ABORT, 'pending Unknown authority excludes drift-blocked proof'); END;

CREATE TRIGGER terminal_cleanup_proofs_v25_drift_exclusive
BEFORE INSERT ON terminal_cleanup_proofs
WHEN EXISTS (
    SELECT 1 FROM sprint_live_state_drift_blocked_proofs drift
    WHERE drift.sprint_id = NEW.sprint_id
)
BEGIN SELECT RAISE(ABORT, 'terminal outcome cannot carry old and drift proof families'); END;

DROP TRIGGER non_success_terminal_requires_cleanup_proof;
CREATE TRIGGER non_success_terminal_requires_cleanup_proof
AFTER INSERT ON sprint_non_success_terminal_outcomes
WHEN NOT EXISTS (
    SELECT 1 FROM terminal_cleanup_proofs proof
    WHERE proof.sprint_id = NEW.sprint_id
      AND (
          (NEW.terminal_state = 'Unknown'
           AND proof.proof_kind = 'UnknownNoProof')
          OR
          (NEW.terminal_state IN ('Failed', 'Canceled')
           AND proof.proof_kind IN ('LiveWorkspaceUnchanged', 'Rollback'))
          OR
          (NEW.terminal_state = 'Blocked'
           AND proof.proof_kind IN (
               'LiveWorkspaceUnchanged', 'Rollback', 'LiveConflict'
           ))
      )
)
AND NOT EXISTS (
    SELECT 1 FROM sprint_live_state_drift_blocked_proofs drift
    WHERE drift.sprint_id = NEW.sprint_id
      AND NEW.terminal_state = 'Blocked'
      AND drift.terminal_record_id = NEW.record_id
      AND drift.terminal_record_id = NEW.terminal_event_id
      AND drift.terminal_evidence_digest = NEW.evidence_digest
      AND drift.blocked_at_unix_ms = NEW.terminal_at_unix_ms
      AND drift.contract_version = NEW.contract_version
)
BEGIN SELECT RAISE(ABORT, 'terminal state requires its exact cleanup proof'); END;

CREATE TRIGGER sprint_non_success_terminal_outcomes_v25_exact_proof_xor
BEFORE INSERT ON sprint_non_success_terminal_outcomes
-- An unmet schema-v15 pending-Unknown closure remains owned by its older,
-- more specific fence. Once the exact deferred requirement exists, this
-- additive proof-family XOR applies without weakening that closure protocol.
WHEN NOT (
        NEW.terminal_state = 'Unknown'
        AND EXISTS (
            SELECT 1
            FROM sprint_unknown_terminalization_pending pending
            LEFT JOIN sprint_unknown_terminalization_closures closure
              ON closure.marker_id = pending.marker_id
            WHERE pending.sprint_id = NEW.sprint_id
              AND closure.marker_id IS NULL
        )
        AND NOT EXISTS (
            SELECT 1
            FROM sprint_unknown_terminalization_closure_requirements requirement
            JOIN sprint_unknown_terminalization_pending pending
              ON pending.marker_id = requirement.marker_id
            WHERE requirement.sprint_id = NEW.sprint_id
              AND requirement.terminal_evidence_id = NEW.record_id
              AND requirement.terminal_event_id = NEW.terminal_event_id
              AND requirement.contract_version = NEW.contract_version
              AND requirement.closed_at_unix_ms = NEW.terminal_at_unix_ms
              AND pending.sprint_id = NEW.sprint_id
        )
    )
 AND (
      (SELECT COUNT(*) FROM terminal_cleanup_proofs old
       WHERE old.sprint_id = NEW.sprint_id)
      + (SELECT COUNT(*) FROM sprint_live_state_drift_blocked_proofs drift
         WHERE drift.sprint_id = NEW.sprint_id) != 1
      OR EXISTS (
          SELECT 1 FROM sprint_live_state_drift_blocked_proofs drift
          WHERE drift.sprint_id = NEW.sprint_id
            AND (
                NEW.terminal_state != 'Blocked'
                OR drift.terminal_record_id != NEW.record_id
                OR drift.terminal_record_id != NEW.terminal_event_id
                OR drift.terminal_evidence_digest != NEW.evidence_digest
                OR drift.blocked_at_unix_ms != NEW.terminal_at_unix_ms
                OR drift.contract_version != NEW.contract_version
            )
      )
 )
BEGIN SELECT RAISE(ABORT, 'terminal outcome requires exactly one matching proof family'); END;

-- Completion and drift use pre-parent rows, so exclusivity must be symmetric
-- before either terminal parent exists.
CREATE TRIGGER sprint_completion_live_state_capture_links_v25_drift_exclusive
BEFORE INSERT ON sprint_completion_live_state_capture_links
WHEN EXISTS (
    SELECT 1 FROM sprint_live_state_drift_blocked_proofs drift
    WHERE drift.sprint_id = NEW.sprint_id
)
BEGIN SELECT RAISE(ABORT, 'sprint already has drift-blocked terminal authority'); END;

CREATE TRIGGER sprint_completion_proof_states_v25_drift_exclusive
BEFORE INSERT ON sprint_completion_proof_states
WHEN EXISTS (
    SELECT 1 FROM sprint_live_state_drift_blocked_proofs drift
    WHERE drift.sprint_id = NEW.sprint_id
)
BEGIN SELECT RAISE(ABORT, 'sprint already has drift-blocked terminal authority'); END;

CREATE TRIGGER sprint_terminal_states_v25_drift_exclusive
BEFORE INSERT ON sprint_terminal_states
WHEN EXISTS (
    SELECT 1 FROM sprint_live_state_drift_blocked_proofs drift
    WHERE drift.sprint_id = NEW.sprint_id
)
BEGIN SELECT RAISE(ABORT, 'sprint already has drift-blocked terminal authority'); END;

-- Once the pre-parent proof exists, only its exact terminal outcome/event may
-- be added. No effect or unrelated event can cross this terminal cut.
CREATE TRIGGER agent_events_v25_pending_drift_terminal_fence
BEFORE INSERT ON agent_events
WHEN EXISTS (
    SELECT 1 FROM sprint_live_state_drift_blocked_proofs drift
    WHERE drift.sprint_id = NEW.sprint_id
      AND drift.terminal_record_id != NEW.event_id
)
BEGIN SELECT RAISE(ABORT, 'pending drift-blocked authority accepts only its terminal event'); END;

CREATE TRIGGER effect_intents_v25_pending_drift_terminal_fence
BEFORE INSERT ON effect_intents
WHEN EXISTS (
    SELECT 1 FROM sprint_live_state_drift_blocked_proofs drift
    WHERE drift.sprint_id = NEW.sprint_id
)
BEGIN SELECT RAISE(ABORT, 'pending drift-blocked authority rejects new effects'); END;

CREATE TRIGGER effect_observations_v25_pending_drift_terminal_fence
BEFORE INSERT ON effect_observations
WHEN EXISTS (
    SELECT 1 FROM sprint_live_state_drift_blocked_proofs drift
    WHERE drift.sprint_id = NEW.sprint_id
)
BEGIN SELECT RAISE(ABORT, 'pending drift-blocked authority rejects new observations'); END;

CREATE TRIGGER agent_events_v25_drift_terminal_order
AFTER INSERT ON agent_events
WHEN EXISTS (
    SELECT 1
    FROM sprint_live_state_drift_blocked_proofs drift
    JOIN worker_cleanup_receipts cleanup
      ON cleanup.receipt_id = drift.verifier_cleanup_receipt_id
     AND cleanup.sprint_id = drift.sprint_id
    JOIN effect_observations cleanup_observation
      ON cleanup_observation.observation_id = cleanup.observation_id
     AND cleanup_observation.effect_id = cleanup.effect_id
    JOIN agent_events cleanup_event
      ON cleanup_event.event_id = cleanup_observation.terminal_event_id
     AND cleanup_event.sprint_id = cleanup.sprint_id
    WHERE drift.terminal_record_id = NEW.event_id
      AND (
          drift.sprint_id != NEW.sprint_id
          OR drift.blocked_at_unix_ms != NEW.occurred_at_unix_ms
          OR cleanup_event.sequence >= NEW.sequence
          OR cleanup.cleaned_at_unix_ms > NEW.occurred_at_unix_ms
      )
)
BEGIN SELECT RAISE(ABORT, 'drift terminal event must follow exact verifier cleanup'); END;

CREATE TRIGGER sprint_live_state_drift_blocked_proofs_no_update
BEFORE UPDATE ON sprint_live_state_drift_blocked_proofs
BEGIN SELECT RAISE(ABORT, 'drift-blocked proofs are immutable'); END;

CREATE TRIGGER sprint_live_state_drift_blocked_proofs_no_delete
BEFORE DELETE ON sprint_live_state_drift_blocked_proofs
BEGIN SELECT RAISE(ABORT, 'drift-blocked proofs are immutable'); END;
