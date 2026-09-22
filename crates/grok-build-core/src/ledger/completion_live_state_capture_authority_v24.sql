-- Schema v24 binds every newly proven completion to one exact successful
-- descriptor-relative capture without changing the closed v1 CompletionReceipt
-- envelope or rebuilding any v9/v16/v22/v23 table.

-- v23 introduced capture receipts after the v10 post-completion and v11
-- command-domain namespaces had closed. Reject a preexisting ambiguous image
-- before installing symmetric guards for every future insertion direction.
CREATE TEMP TABLE v24_capture_receipt_namespace_migration_guard (
    collision_count INTEGER NOT NULL CHECK (collision_count = 0)
) STRICT;

INSERT INTO v24_capture_receipt_namespace_migration_guard (collision_count)
SELECT
    (SELECT COUNT(*)
       FROM live_state_capture_receipt_ids capture
       JOIN command_domain_cleanup_proofs command_cleanup
         ON command_cleanup.proof_id = capture.receipt_id)
    +
    (SELECT COUNT(*)
       FROM live_state_capture_receipt_ids capture
       JOIN post_completion_rollback_receipt_ids post_completion
         ON post_completion.receipt_id = capture.receipt_id);

DROP TABLE v24_capture_receipt_namespace_migration_guard;

CREATE TRIGGER live_state_capture_receipt_ids_v24_extended_global_unique
BEFORE INSERT ON live_state_capture_receipt_ids
WHEN EXISTS (
        SELECT 1 FROM command_domain_cleanup_proofs
        WHERE proof_id = NEW.receipt_id
    )
 OR EXISTS (
        SELECT 1 FROM post_completion_rollback_receipt_ids
        WHERE receipt_id = NEW.receipt_id
    )
BEGIN SELECT RAISE(ABORT, 'capture receipt identity must be globally unique'); END;

CREATE TRIGGER command_domain_cleanup_proofs_v24_capture_id_unique
BEFORE INSERT ON command_domain_cleanup_proofs
WHEN EXISTS (
    SELECT 1 FROM live_state_capture_receipt_ids
    WHERE receipt_id = NEW.proof_id
)
BEGIN SELECT RAISE(ABORT, 'command-domain cleanup proof identity collides with live-state capture'); END;

CREATE TRIGGER post_completion_rollback_receipt_ids_v24_capture_id_unique
BEFORE INSERT ON post_completion_rollback_receipt_ids
WHEN EXISTS (
    SELECT 1 FROM live_state_capture_receipt_ids
    WHERE receipt_id = NEW.receipt_id
)
BEGIN SELECT RAISE(ABORT, 'post-completion receipt identity collides with live-state capture'); END;

-- Successful completions already durable before this migration retain their
-- historical authority. The digest authenticates the exact untouched v1 bytes.
CREATE TABLE pre_v24_completion_live_state_capture_exemptions (
    sprint_id TEXT PRIMARY KEY NOT NULL,
    completion_receipt_id TEXT NOT NULL UNIQUE,
    completion_event_id TEXT NOT NULL UNIQUE,
    completion_receipt_digest TEXT NOT NULL CHECK (
        length(completion_receipt_digest) = 64
        AND completion_receipt_digest NOT GLOB '*[^0-9a-f]*'
    ),
    terminal_at_unix_ms INTEGER NOT NULL CHECK (terminal_at_unix_ms > 0),
    contract_version INTEGER NOT NULL CHECK (contract_version > 0),
    marked_at_schema_version INTEGER NOT NULL CHECK (marked_at_schema_version = 24),
    FOREIGN KEY (sprint_id, completion_receipt_id)
        REFERENCES v9_completion_receipts(sprint_id, receipt_id) ON DELETE RESTRICT,
    FOREIGN KEY (completion_event_id)
        REFERENCES agent_events(event_id) ON DELETE RESTRICT
) STRICT, WITHOUT ROWID;

CREATE TEMP TABLE v24_completion_exemption_migration_guard (
    expected_count INTEGER NOT NULL,
    actual_count INTEGER NOT NULL,
    CHECK (expected_count = actual_count)
) STRICT;

INSERT INTO pre_v24_completion_live_state_capture_exemptions (
    sprint_id, completion_receipt_id, completion_event_id,
    completion_receipt_digest, terminal_at_unix_ms,
    contract_version, marked_at_schema_version
)
SELECT proof.sprint_id,
       proof.completion_receipt_id,
       proof.completion_event_id,
       grok_canonical_completion_receipt_digest(completion.receipt_json),
       proof.terminal_at_unix_ms,
       proof.contract_version,
       24
FROM sprint_completion_proof_states proof
JOIN v9_completion_receipts completion
  ON completion.sprint_id = proof.sprint_id
 AND completion.receipt_id = proof.completion_receipt_id
 AND completion.contract_version = proof.contract_version
 AND completion.completed_at_unix_ms = proof.terminal_at_unix_ms
JOIN agent_events event
  ON event.event_id = proof.completion_event_id
 AND event.sprint_id = proof.sprint_id
 AND event.contract_version = proof.contract_version
 AND event.occurred_at_unix_ms = proof.terminal_at_unix_ms
WHERE proof.proof_state = 'ProvenV9'
  AND json_extract(CAST(completion.receipt_json AS TEXT), '$.contract_version') IS completion.contract_version
  AND json_extract(CAST(completion.receipt_json AS TEXT), '$.receipt_id') IS completion.receipt_id
  AND json_extract(CAST(completion.receipt_json AS TEXT), '$.sprint_id') IS completion.sprint_id
  AND json_extract(CAST(completion.receipt_json AS TEXT), '$.final_snapshot') IS completion.final_snapshot
  AND json_extract(CAST(completion.receipt_json AS TEXT), '$.grant_hash') IS completion.grant_hash
  AND json_extract(CAST(completion.receipt_json AS TEXT), '$.policy_version') IS completion.policy_version
  AND json_extract(CAST(completion.receipt_json AS TEXT), '$.final_verification_receipt_id') IS completion.final_verification_receipt_id
  AND json_extract(CAST(completion.receipt_json AS TEXT), '$.application.kind') IS completion.application_kind
  AND json_extract(CAST(completion.receipt_json AS TEXT), '$.application.application_receipt_id') IS completion.application_receipt_id
  AND json_extract(CAST(completion.receipt_json AS TEXT), '$.application.rollback_reference_id') IS completion.rollback_reference_id
  AND json_extract(CAST(completion.receipt_json AS TEXT), '$.application.verified_no_op_receipt_id') IS completion.verified_no_op_receipt_id
  AND json_extract(CAST(completion.receipt_json AS TEXT), '$.final_report_id') IS completion.final_report_id
  AND json_extract(CAST(completion.receipt_json AS TEXT), '$.provider_backend') IS completion.provider_backend
  AND json_extract(CAST(completion.receipt_json AS TEXT), '$.provider_model') IS completion.provider_model
  AND json_extract(CAST(completion.receipt_json AS TEXT), '$.completed_at_unix_ms') IS completion.completed_at_unix_ms
  AND json_extract(CAST(event.event_json AS TEXT), '$.contract_version') IS event.contract_version
  AND json_extract(CAST(event.event_json AS TEXT), '$.sequence') IS event.sequence
  AND json_extract(CAST(event.event_json AS TEXT), '$.event_id') IS event.event_id
  AND json_extract(CAST(event.event_json AS TEXT), '$.sprint_id') IS event.sprint_id
  AND json_type(CAST(event.event_json AS TEXT), '$.task_id') = 'null'
  AND json_type(CAST(event.event_json AS TEXT), '$.worker_id') = 'null'
  AND json_type(CAST(event.event_json AS TEXT), '$.policy_hash') = 'null'
  AND json_extract(CAST(event.event_json AS TEXT), '$.occurred_at_unix_ms') IS event.occurred_at_unix_ms
  AND json_extract(CAST(event.event_json AS TEXT), '$.payload.CompletionRecorded') IS proof.completion_receipt_id;

INSERT INTO v24_completion_exemption_migration_guard (expected_count, actual_count)
SELECT (SELECT COUNT(*) FROM sprint_completion_proof_states WHERE proof_state = 'ProvenV9'),
       (SELECT COUNT(*) FROM pre_v24_completion_live_state_capture_exemptions);

DROP TABLE v24_completion_exemption_migration_guard;

CREATE TRIGGER pre_v24_completion_live_state_capture_exemptions_no_insert
BEFORE INSERT ON pre_v24_completion_live_state_capture_exemptions
BEGIN SELECT RAISE(ABORT, 'pre-v24 completion capture exemptions are migration-only'); END;
CREATE TRIGGER pre_v24_completion_live_state_capture_exemptions_no_update
BEFORE UPDATE ON pre_v24_completion_live_state_capture_exemptions
BEGIN SELECT RAISE(ABORT, 'pre-v24 completion capture exemptions are immutable'); END;
CREATE TRIGGER pre_v24_completion_live_state_capture_exemptions_no_delete
BEFORE DELETE ON pre_v24_completion_live_state_capture_exemptions
BEGIN SELECT RAISE(ABORT, 'pre-v24 completion capture exemptions are immutable'); END;

-- The link is inserted before both its completion parent and, for VerifiedNoOp,
-- its core-derived no-op parent. Both edges are deferred and commit atomically.
CREATE TABLE sprint_completion_live_state_capture_links (
    completion_receipt_id TEXT PRIMARY KEY NOT NULL
        CHECK (length(completion_receipt_id) BETWEEN 1 AND 4096),
    sprint_id TEXT NOT NULL UNIQUE,
    completion_receipt_digest TEXT NOT NULL CHECK (
        length(completion_receipt_digest) = 64
        AND completion_receipt_digest NOT GLOB '*[^0-9a-f]*'
    ),
    capture_receipt_id TEXT NOT NULL UNIQUE,
    capture_admission_id TEXT NOT NULL,
    capture_plan_id TEXT NOT NULL,
    capture_plan_digest TEXT NOT NULL CHECK (
        length(capture_plan_digest) = 64
        AND capture_plan_digest NOT GLOB '*[^0-9a-f]*'
    ),
    capture_effect_id TEXT NOT NULL UNIQUE,
    capture_observation_id TEXT NOT NULL UNIQUE,
    capture_dispatch_claim_id TEXT NOT NULL UNIQUE,
    runner_launch_id TEXT NOT NULL UNIQUE,
    runner_session_id TEXT NOT NULL UNIQUE,
    verifier_cleanup_receipt_id TEXT NOT NULL UNIQUE,
    final_snapshot TEXT NOT NULL CHECK (
        length(final_snapshot) = 64 AND final_snapshot NOT GLOB '*[^0-9a-f]*'
    ),
    expected_snapshot TEXT NOT NULL CHECK (
        length(expected_snapshot) = 64 AND expected_snapshot NOT GLOB '*[^0-9a-f]*'
    ),
    observed_snapshot TEXT NOT NULL CHECK (
        length(observed_snapshot) = 64 AND observed_snapshot NOT GLOB '*[^0-9a-f]*'
    ),
    manifest_digest TEXT NOT NULL CHECK (
        length(manifest_digest) = 64 AND manifest_digest NOT GLOB '*[^0-9a-f]*'
    ),
    grant_hash TEXT NOT NULL CHECK (
        length(grant_hash) = 64 AND grant_hash NOT GLOB '*[^0-9a-f]*'
    ),
    policy_hash TEXT NOT NULL CHECK (
        length(policy_hash) = 64 AND policy_hash NOT GLOB '*[^0-9a-f]*'
    ),
    policy_version INTEGER NOT NULL CHECK (policy_version > 0),
    final_verification_receipt_id TEXT NOT NULL,
    application_kind TEXT NOT NULL CHECK (application_kind IN ('Applied', 'VerifiedNoOp')),
    task_integration_receipt_id TEXT,
    application_receipt_id TEXT,
    rollback_reference_id TEXT,
    verified_no_op_receipt_id TEXT,
    capture_started_at_unix_ms INTEGER NOT NULL CHECK (capture_started_at_unix_ms > 0),
    captured_at_unix_ms INTEGER NOT NULL CHECK (
        captured_at_unix_ms >= capture_started_at_unix_ms
    ),
    verifier_cleaned_at_unix_ms INTEGER NOT NULL CHECK (
        verifier_cleaned_at_unix_ms >= captured_at_unix_ms
    ),
    completed_at_unix_ms INTEGER NOT NULL CHECK (
        completed_at_unix_ms >= verifier_cleaned_at_unix_ms
    ),
    contract_version INTEGER NOT NULL CHECK (contract_version > 0),
    link_json BLOB NOT NULL CHECK (length(link_json) BETWEEN 1 AND 1048576),
    UNIQUE (sprint_id, completion_receipt_id),
    CHECK (
        final_snapshot = expected_snapshot
        AND expected_snapshot = observed_snapshot
        AND observed_snapshot = manifest_digest
    ),
    CHECK (
        (application_kind = 'Applied'
         AND application_receipt_id IS NOT NULL
         AND rollback_reference_id IS NOT NULL
         AND verified_no_op_receipt_id IS NULL
         AND task_integration_receipt_id IS NULL)
        OR
        (application_kind = 'VerifiedNoOp'
         AND application_receipt_id IS NULL
         AND rollback_reference_id IS NULL
         AND verified_no_op_receipt_id IS NOT NULL
         AND task_integration_receipt_id IS NOT NULL)
    ),
    FOREIGN KEY (sprint_id, completion_receipt_id)
        REFERENCES v9_completion_receipts(sprint_id, receipt_id)
        ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED,
    FOREIGN KEY (sprint_id, capture_receipt_id)
        REFERENCES live_state_capture_receipts(sprint_id, receipt_id) ON DELETE RESTRICT,
    FOREIGN KEY (sprint_id, capture_admission_id)
        REFERENCES sprint_live_state_capture_admissions(sprint_id, admission_id) ON DELETE RESTRICT,
    FOREIGN KEY (sprint_id, capture_plan_id)
        REFERENCES sprint_live_state_capture_plans(sprint_id, plan_id) ON DELETE RESTRICT,
    FOREIGN KEY (sprint_id, capture_effect_id)
        REFERENCES live_state_capture_effect_kinds(sprint_id, effect_id) ON DELETE RESTRICT,
    FOREIGN KEY (capture_observation_id)
        REFERENCES effect_observations(observation_id) ON DELETE RESTRICT,
    FOREIGN KEY (capture_dispatch_claim_id)
        REFERENCES runner_effect_dispatch_claims(dispatch_claim_id) ON DELETE RESTRICT,
    FOREIGN KEY (sprint_id, runner_launch_id)
        REFERENCES live_state_verifier_launch_purposes(sprint_id, launch_id) ON DELETE RESTRICT,
    FOREIGN KEY (sprint_id, runner_session_id)
        REFERENCES live_state_verifier_session_purposes(sprint_id, session_id) ON DELETE RESTRICT,
    FOREIGN KEY (sprint_id, verifier_cleanup_receipt_id)
        REFERENCES worker_cleanup_receipts(sprint_id, receipt_id) ON DELETE RESTRICT,
    FOREIGN KEY (sprint_id, final_snapshot)
        REFERENCES workspace_snapshots(sprint_id, snapshot_id) ON DELETE RESTRICT,
    FOREIGN KEY (sprint_id, final_verification_receipt_id)
        REFERENCES verification_receipts(sprint_id, receipt_id) ON DELETE RESTRICT,
    FOREIGN KEY (sprint_id, task_integration_receipt_id)
        REFERENCES task_integration_receipts(sprint_id, receipt_id) ON DELETE RESTRICT,
    FOREIGN KEY (sprint_id, application_receipt_id)
        REFERENCES application_receipts(sprint_id, receipt_id) ON DELETE RESTRICT,
    FOREIGN KEY (sprint_id, rollback_reference_id)
        REFERENCES rollback_references(sprint_id, reference_id) ON DELETE RESTRICT,
    FOREIGN KEY (sprint_id, verified_no_op_receipt_id)
        REFERENCES verified_no_op_receipts(sprint_id, receipt_id)
        ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED
) STRICT, WITHOUT ROWID;

CREATE TRIGGER sprint_completion_live_state_capture_links_no_existing_parent
BEFORE INSERT ON sprint_completion_live_state_capture_links
WHEN EXISTS (SELECT 1 FROM finish_receipt_ids WHERE receipt_id = NEW.completion_receipt_id)
  OR EXISTS (SELECT 1 FROM v9_completion_receipts WHERE receipt_id = NEW.completion_receipt_id)
  OR (NEW.application_kind = 'VerifiedNoOp' AND EXISTS (
         SELECT 1 FROM finish_receipt_ids
         WHERE receipt_id = NEW.verified_no_op_receipt_id
     ))
  OR (NEW.application_kind = 'VerifiedNoOp' AND EXISTS (
         SELECT 1 FROM verified_no_op_receipts
         WHERE receipt_id = NEW.verified_no_op_receipt_id
     ))
  OR EXISTS (SELECT 1 FROM sprint_completion_proof_states WHERE sprint_id = NEW.sprint_id)
  OR EXISTS (SELECT 1 FROM sprint_non_success_terminal_outcomes WHERE sprint_id = NEW.sprint_id)
  OR EXISTS (SELECT 1 FROM sprint_terminal_states WHERE sprint_id = NEW.sprint_id)
BEGIN SELECT RAISE(ABORT, 'completion capture link must precede its new completion'); END;

CREATE TRIGGER sprint_completion_live_state_capture_links_canonical_envelope
BEFORE INSERT ON sprint_completion_live_state_capture_links
WHEN grok_completion_live_state_capture_link_canonical(NEW.link_json) != 1
 OR json_extract(CAST(NEW.link_json AS TEXT), '$.contract_version') != NEW.contract_version
 OR json_extract(CAST(NEW.link_json AS TEXT), '$.sprint_id') != NEW.sprint_id
 OR json_extract(CAST(NEW.link_json AS TEXT), '$.completion_receipt_id') != NEW.completion_receipt_id
 OR json_extract(CAST(NEW.link_json AS TEXT), '$.completion_receipt_digest') != NEW.completion_receipt_digest
 OR json_extract(CAST(NEW.link_json AS TEXT), '$.final_snapshot') != NEW.final_snapshot
 OR json_extract(CAST(NEW.link_json AS TEXT), '$.grant_hash') != NEW.grant_hash
 OR json_extract(CAST(NEW.link_json AS TEXT), '$.policy_hash') != NEW.policy_hash
 OR json_extract(CAST(NEW.link_json AS TEXT), '$.policy_version') != NEW.policy_version
 OR json_extract(CAST(NEW.link_json AS TEXT), '$.final_verification_receipt_id') != NEW.final_verification_receipt_id
 OR json_extract(CAST(NEW.link_json AS TEXT), '$.capture.capture_receipt_id') != NEW.capture_receipt_id
 OR json_extract(CAST(NEW.link_json AS TEXT), '$.capture.admission_id') != NEW.capture_admission_id
 OR json_extract(CAST(NEW.link_json AS TEXT), '$.capture.plan_id') != NEW.capture_plan_id
 OR json_extract(CAST(NEW.link_json AS TEXT), '$.capture.plan_digest') != NEW.capture_plan_digest
 OR json_extract(CAST(NEW.link_json AS TEXT), '$.capture.effect_id') != NEW.capture_effect_id
 OR json_extract(CAST(NEW.link_json AS TEXT), '$.capture.observation_id') != NEW.capture_observation_id
 OR json_extract(CAST(NEW.link_json AS TEXT), '$.capture.dispatch_claim_id') != NEW.capture_dispatch_claim_id
 OR json_extract(CAST(NEW.link_json AS TEXT), '$.capture.runner_launch_id') != NEW.runner_launch_id
 OR json_extract(CAST(NEW.link_json AS TEXT), '$.capture.runner_session_id') != NEW.runner_session_id
 OR json_extract(CAST(NEW.link_json AS TEXT), '$.capture.expected_snapshot') != NEW.expected_snapshot
 OR json_extract(CAST(NEW.link_json AS TEXT), '$.capture.observed_snapshot') != NEW.observed_snapshot
 OR json_extract(CAST(NEW.link_json AS TEXT), '$.capture.manifest_digest') != NEW.manifest_digest
 OR json_extract(CAST(NEW.link_json AS TEXT), '$.verifier_cleanup_receipt_id') != NEW.verifier_cleanup_receipt_id
 OR json_extract(CAST(NEW.link_json AS TEXT), '$.capture_started_at_unix_ms') != NEW.capture_started_at_unix_ms
 OR json_extract(CAST(NEW.link_json AS TEXT), '$.captured_at_unix_ms') != NEW.captured_at_unix_ms
 OR json_extract(CAST(NEW.link_json AS TEXT), '$.verifier_cleaned_at_unix_ms') != NEW.verifier_cleaned_at_unix_ms
 OR json_extract(CAST(NEW.link_json AS TEXT), '$.completed_at_unix_ms') != NEW.completed_at_unix_ms
 OR (
      NEW.application_kind = 'Applied'
      AND (
          json_type(CAST(NEW.link_json AS TEXT), '$.application.Applied') IS NOT 'object'
          OR json_type(CAST(NEW.link_json AS TEXT), '$.application.VerifiedNoOp') IS NOT NULL
          OR json_extract(CAST(NEW.link_json AS TEXT), '$.application.Applied.application_receipt_id') IS NOT NEW.application_receipt_id
          OR json_extract(CAST(NEW.link_json AS TEXT), '$.application.Applied.rollback_reference_id') IS NOT NEW.rollback_reference_id
      )
 )
 OR (
      NEW.application_kind = 'VerifiedNoOp'
      AND (
          json_type(CAST(NEW.link_json AS TEXT), '$.application.VerifiedNoOp') IS NOT 'object'
          OR json_type(CAST(NEW.link_json AS TEXT), '$.application.Applied') IS NOT NULL
          OR json_extract(CAST(NEW.link_json AS TEXT), '$.application.VerifiedNoOp.verified_no_op_receipt_id') IS NOT NEW.verified_no_op_receipt_id
          OR json_extract(CAST(NEW.link_json AS TEXT), '$.application.VerifiedNoOp.task_integration_receipt_id') IS NOT NEW.task_integration_receipt_id
      )
 )
BEGIN SELECT RAISE(ABORT, 'completion capture link JSON is noncanonical or crossed'); END;

CREATE TRIGGER sprint_completion_live_state_capture_links_references_match
BEFORE INSERT ON sprint_completion_live_state_capture_links
WHEN NOT EXISTS (
    SELECT 1
    FROM live_state_capture_receipts capture
    JOIN sprint_live_state_capture_admissions admission
      ON admission.admission_id = capture.admission_id
     AND admission.sprint_id = capture.sprint_id
    JOIN sprint_live_state_capture_plans plan
      ON plan.plan_id = capture.plan_id AND plan.sprint_id = capture.sprint_id
    JOIN effect_intents capture_intent
      ON capture_intent.effect_id = capture.effect_id
     AND capture_intent.sprint_id = capture.sprint_id
    JOIN effect_observations capture_observation
      ON capture_observation.observation_id = capture.observation_id
     AND capture_observation.effect_id = capture.effect_id
     AND capture_observation.sprint_id = capture.sprint_id
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
    JOIN worker_cleanup_receipts cleanup
      ON cleanup.receipt_id = NEW.verifier_cleanup_receipt_id
     AND cleanup.sprint_id = capture.sprint_id
     AND cleanup.launch_id = capture.runner_launch_id
     AND cleanup.session_id = capture.runner_session_id
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
      AND capture_observation.outcome = 'Succeeded'
      AND capture_observation.observed_at_unix_ms = capture.captured_at_unix_ms
      AND capture_observation.dispatch_claim_id = capture.dispatch_claim_id
      AND cleanup_observation.outcome = 'Succeeded'
      AND cleanup_observation.observed_at_unix_ms = NEW.verifier_cleaned_at_unix_ms
      AND cleanup.surviving_processes = 0
      AND cleanup.cleaned_at_unix_ms = NEW.verifier_cleaned_at_unix_ms
      AND cleanup_event.sequence > capture_event.sequence
      AND plan.expected_snapshot = NEW.final_snapshot
      AND plan.final_verification_receipt_id = NEW.final_verification_receipt_id
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
            AND prior.cleanup_receipt_id = NEW.verifier_cleanup_receipt_id
      )
      AND (
          (NEW.application_kind = 'Applied'
           AND plan.branch = 'Applied'
           AND plan.application_receipt_id = NEW.application_receipt_id
           AND plan.rollback_reference_id = NEW.rollback_reference_id
           AND EXISTS (
               SELECT 1 FROM application_receipts application
               WHERE application.receipt_id = NEW.application_receipt_id
                 AND application.sprint_id = NEW.sprint_id
                 AND application.result_snapshot = NEW.final_snapshot
                 AND application.applied_at_unix_ms <= NEW.capture_started_at_unix_ms
           ))
          OR
          (NEW.application_kind = 'VerifiedNoOp'
           AND plan.branch = 'VerifiedNoOp'
           AND plan.task_integration_receipt_id = NEW.task_integration_receipt_id)
      )
      AND capture.contract_version = NEW.contract_version
      AND plan.contract_version = NEW.contract_version
      AND cleanup.contract_version = NEW.contract_version
)
BEGIN SELECT RAISE(ABORT, 'completion capture link crosses its exact capture lifecycle'); END;

CREATE TRIGGER sprint_completion_live_state_capture_links_no_update
BEFORE UPDATE ON sprint_completion_live_state_capture_links
BEGIN SELECT RAISE(ABORT, 'completion capture links are immutable'); END;
CREATE TRIGGER sprint_completion_live_state_capture_links_no_delete
BEFORE DELETE ON sprint_completion_live_state_capture_links
BEGIN SELECT RAISE(ABORT, 'completion capture links are immutable'); END;

-- The specialized completion transaction derives and inserts the no-op only
-- after its pre-parent link. Standalone current-schema no-op insertion is inert.
CREATE TRIGGER verified_no_op_receipts_v24_capture_link_required
BEFORE INSERT ON verified_no_op_receipts
WHEN grok_verified_no_op_receipt_canonical(NEW.receipt_json) != 1
 OR json_extract(CAST(NEW.receipt_json AS TEXT), '$.contract_version') IS NOT NEW.contract_version
 OR json_extract(CAST(NEW.receipt_json AS TEXT), '$.receipt_id') IS NOT NEW.receipt_id
 OR json_extract(CAST(NEW.receipt_json AS TEXT), '$.sprint_id') IS NOT NEW.sprint_id
 OR json_extract(CAST(NEW.receipt_json AS TEXT), '$.final_verification_receipt_id') IS NOT NEW.final_verification_receipt_id
 OR json_extract(CAST(NEW.receipt_json AS TEXT), '$.base_snapshot') IS NOT NEW.base_snapshot
 OR json_extract(CAST(NEW.receipt_json AS TEXT), '$.live_manifest_digest') IS NOT NEW.live_manifest_digest
 OR json_extract(CAST(NEW.receipt_json AS TEXT), '$.grant_hash') IS NOT NEW.grant_hash
 OR json_extract(CAST(NEW.receipt_json AS TEXT), '$.policy_version') IS NOT NEW.policy_version
 OR json_extract(CAST(NEW.receipt_json AS TEXT), '$.observed_at_unix_ms') IS NOT NEW.observed_at_unix_ms
 OR NOT EXISTS (
    SELECT 1
    FROM sprint_completion_live_state_capture_links link
    JOIN live_state_capture_receipts capture
      ON capture.receipt_id = link.capture_receipt_id
     AND capture.sprint_id = link.sprint_id
    WHERE link.sprint_id = NEW.sprint_id
      AND link.application_kind = 'VerifiedNoOp'
      AND link.verified_no_op_receipt_id = NEW.receipt_id
      AND link.final_verification_receipt_id = NEW.final_verification_receipt_id
      AND link.final_snapshot = NEW.base_snapshot
      AND link.manifest_digest = NEW.live_manifest_digest
      AND link.grant_hash = NEW.grant_hash
      AND link.policy_version = NEW.policy_version
      AND link.captured_at_unix_ms = NEW.observed_at_unix_ms
      AND link.contract_version = NEW.contract_version
      AND capture.captured_at_unix_ms = NEW.observed_at_unix_ms
)
BEGIN SELECT RAISE(ABORT, 'current verified no-op requires its pre-parent completion capture link'); END;

CREATE TRIGGER finish_receipt_ids_v24_completion_link_required
BEFORE INSERT ON finish_receipt_ids
WHEN NEW.receipt_kind = 'Completion'
 AND NOT EXISTS (
    SELECT 1 FROM sprint_completion_live_state_capture_links link
    WHERE link.completion_receipt_id = NEW.receipt_id
      AND link.sprint_id = NEW.sprint_id
      AND link.contract_version = NEW.contract_version
 )
BEGIN SELECT RAISE(ABORT, 'current completion identity requires its pre-parent capture link'); END;

CREATE TRIGGER v9_completion_receipts_v24_link_required
BEFORE INSERT ON v9_completion_receipts
WHEN json_extract(CAST(NEW.receipt_json AS TEXT), '$.contract_version') IS NOT NEW.contract_version
 OR json_extract(CAST(NEW.receipt_json AS TEXT), '$.receipt_id') IS NOT NEW.receipt_id
 OR json_extract(CAST(NEW.receipt_json AS TEXT), '$.sprint_id') IS NOT NEW.sprint_id
 OR json_extract(CAST(NEW.receipt_json AS TEXT), '$.final_snapshot') IS NOT NEW.final_snapshot
 OR json_extract(CAST(NEW.receipt_json AS TEXT), '$.grant_hash') IS NOT NEW.grant_hash
 OR json_extract(CAST(NEW.receipt_json AS TEXT), '$.policy_version') IS NOT NEW.policy_version
 OR json_extract(CAST(NEW.receipt_json AS TEXT), '$.final_verification_receipt_id') IS NOT NEW.final_verification_receipt_id
 OR json_extract(CAST(NEW.receipt_json AS TEXT), '$.application.kind') IS NOT NEW.application_kind
 OR json_extract(CAST(NEW.receipt_json AS TEXT), '$.application.application_receipt_id') IS NOT NEW.application_receipt_id
 OR json_extract(CAST(NEW.receipt_json AS TEXT), '$.application.rollback_reference_id') IS NOT NEW.rollback_reference_id
 OR json_extract(CAST(NEW.receipt_json AS TEXT), '$.application.verified_no_op_receipt_id') IS NOT NEW.verified_no_op_receipt_id
 OR json_extract(CAST(NEW.receipt_json AS TEXT), '$.final_report_id') IS NOT NEW.final_report_id
 OR json_extract(CAST(NEW.receipt_json AS TEXT), '$.provider_backend') IS NOT NEW.provider_backend
 OR json_extract(CAST(NEW.receipt_json AS TEXT), '$.provider_model') IS NOT NEW.provider_model
 OR json_extract(CAST(NEW.receipt_json AS TEXT), '$.completed_at_unix_ms') IS NOT NEW.completed_at_unix_ms
 OR NOT EXISTS (
    SELECT 1
    FROM sprint_completion_live_state_capture_links link
    JOIN final_reports report
      ON report.report_id = NEW.final_report_id AND report.sprint_id = NEW.sprint_id
    WHERE link.completion_receipt_id = NEW.receipt_id
      AND link.sprint_id = NEW.sprint_id
      AND link.completion_receipt_digest = grok_canonical_completion_receipt_digest(NEW.receipt_json)
      AND link.final_snapshot = NEW.final_snapshot
      AND link.grant_hash = NEW.grant_hash
      AND link.policy_version = NEW.policy_version
      AND link.final_verification_receipt_id = NEW.final_verification_receipt_id
      AND link.application_kind = NEW.application_kind
      AND link.application_receipt_id IS NEW.application_receipt_id
      AND link.rollback_reference_id IS NEW.rollback_reference_id
      AND link.verified_no_op_receipt_id IS NEW.verified_no_op_receipt_id
      AND link.completed_at_unix_ms = NEW.completed_at_unix_ms
      AND link.contract_version = NEW.contract_version
      AND link.verifier_cleaned_at_unix_ms <= report.created_at_unix_ms
      AND report.created_at_unix_ms <= NEW.completed_at_unix_ms
      AND grok_final_report_canonical(report.report_json) = 1
      AND json_extract(CAST(report.report_json AS TEXT), '$.report_id') IS report.report_id
      AND json_extract(CAST(report.report_json AS TEXT), '$.sprint_id') IS report.sprint_id
      AND json_extract(CAST(report.report_json AS TEXT), '$.final_snapshot') IS report.final_snapshot
      AND json_extract(CAST(report.report_json AS TEXT), '$.content_digest') IS report.content_digest
      AND json_extract(CAST(report.report_json AS TEXT), '$.created_at_unix_ms') IS report.created_at_unix_ms
      AND report.contract_version = NEW.contract_version
      AND report.final_snapshot = NEW.final_snapshot
      AND (
          NEW.application_kind = 'Applied'
          OR EXISTS (
              SELECT 1 FROM verified_no_op_receipts no_op
              WHERE no_op.receipt_id = NEW.verified_no_op_receipt_id
                AND no_op.sprint_id = NEW.sprint_id
                AND no_op.observed_at_unix_ms = link.captured_at_unix_ms
                AND no_op.live_manifest_digest = link.manifest_digest
          )
      )
)
BEGIN SELECT RAISE(ABORT, 'current completion receipt requires its exact capture link'); END;

-- Semantic mutation blockers after the selected capture. Compatibility storage
-- classes for cleanup and capture are deliberately not interpreted as writes.
CREATE VIEW sprint_completion_v24_post_capture_mutation_blockers AS
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
SELECT link.sprint_id,
       mutation.effect_id,
       mutation.semantic_kind,
       COALESCE(mutation.outcome, 'Missing') AS outcome
FROM sprint_completion_live_state_capture_links link
JOIN live_state_capture_receipts capture
  ON capture.receipt_id = link.capture_receipt_id AND capture.sprint_id = link.sprint_id
JOIN effect_intents capture_intent
  ON capture_intent.effect_id = capture.effect_id
 AND capture_intent.sprint_id = capture.sprint_id
JOIN agent_events capture_proposed_event
  ON capture_proposed_event.event_id = capture_intent.proposed_event_id
 AND capture_proposed_event.sprint_id = capture.sprint_id
JOIN effect_observations capture_observation
  ON capture_observation.observation_id = capture.observation_id
JOIN agent_events capture_event
  ON capture_event.event_id = capture_observation.terminal_event_id
JOIN semantic_effects mutation ON mutation.sprint_id = link.sprint_id
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

CREATE TRIGGER sprint_completion_proof_states_v24_live_capture_required
BEFORE INSERT ON sprint_completion_proof_states
WHEN NEW.proof_state = 'ProvenV9' AND (
    (
      EXISTS (
          SELECT 1 FROM sprint_completion_live_state_capture_links link
          WHERE link.sprint_id = NEW.sprint_id
            AND link.completion_receipt_id = NEW.completion_receipt_id
      )
      + EXISTS (
          SELECT 1 FROM pre_v24_completion_live_state_capture_exemptions exemption
          WHERE exemption.sprint_id = NEW.sprint_id
            AND exemption.completion_receipt_id = NEW.completion_receipt_id
      )
    ) != 1
    OR EXISTS (
        SELECT 1
        FROM sprint_completion_live_state_capture_links link
        JOIN live_state_capture_receipts capture
          ON capture.receipt_id = link.capture_receipt_id
         AND capture.sprint_id = link.sprint_id
        JOIN effect_observations capture_observation
          ON capture_observation.observation_id = capture.observation_id
        JOIN agent_events capture_event
          ON capture_event.event_id = capture_observation.terminal_event_id
        JOIN worker_cleanup_receipts cleanup
          ON cleanup.receipt_id = link.verifier_cleanup_receipt_id
         AND cleanup.sprint_id = link.sprint_id
        JOIN effect_observations cleanup_observation
          ON cleanup_observation.observation_id = cleanup.observation_id
        JOIN agent_events cleanup_event
          ON cleanup_event.event_id = cleanup_observation.terminal_event_id
        JOIN agent_events completion_event
          ON completion_event.event_id = NEW.completion_event_id
         AND completion_event.sprint_id = NEW.sprint_id
        JOIN sprint_live_state_capture_plans plan
          ON plan.plan_id = capture.plan_id
         AND plan.sprint_id = capture.sprint_id
        WHERE link.sprint_id = NEW.sprint_id
          AND link.completion_receipt_id = NEW.completion_receipt_id
          AND (
              capture_event.sequence >= cleanup_event.sequence
              OR cleanup_event.sequence >= completion_event.sequence
              OR link.verifier_cleaned_at_unix_ms > NEW.terminal_at_unix_ms
              OR NOT EXISTS (
                  SELECT 1 FROM v9_completion_cleanup_receipts child
                  WHERE child.completion_receipt_id = NEW.completion_receipt_id
                    AND child.sprint_id = NEW.sprint_id
                    AND child.cleanup_receipt_id = link.verifier_cleanup_receipt_id
              )
              OR (SELECT COUNT(*) FROM v9_completion_cleanup_receipts child
                  WHERE child.completion_receipt_id = NEW.completion_receipt_id
                    AND child.sprint_id = NEW.sprint_id)
                    != plan.required_cleanup_count + 1
              OR EXISTS (
                  SELECT 1
                  FROM sprint_live_state_capture_plan_cleanups prior
                  WHERE prior.plan_id = plan.plan_id
                    AND prior.sprint_id = plan.sprint_id
                    AND NOT EXISTS (
                        SELECT 1 FROM v9_completion_cleanup_receipts child
                        WHERE child.completion_receipt_id = NEW.completion_receipt_id
                          AND child.sprint_id = NEW.sprint_id
                          AND child.cleanup_receipt_id = prior.cleanup_receipt_id
                    )
              )
              OR EXISTS (
                  SELECT 1 FROM v9_completion_cleanup_receipts child
                  WHERE child.completion_receipt_id = NEW.completion_receipt_id
                    AND child.sprint_id = NEW.sprint_id
                    AND child.cleanup_receipt_id != link.verifier_cleanup_receipt_id
                    AND NOT EXISTS (
                        SELECT 1 FROM sprint_live_state_capture_plan_cleanups prior
                        WHERE prior.plan_id = plan.plan_id
                          AND prior.sprint_id = plan.sprint_id
                          AND prior.cleanup_receipt_id = child.cleanup_receipt_id
                    )
              )
              OR NOT EXISTS (
                  SELECT 1 FROM v9_completion_verification_receipts child
                  WHERE child.completion_receipt_id = NEW.completion_receipt_id
                    AND child.sprint_id = NEW.sprint_id
                    AND child.verification_receipt_id = link.final_verification_receipt_id
              )
              OR (
                  link.application_kind = 'VerifiedNoOp'
                  AND NOT EXISTS (
                      SELECT 1 FROM v9_completion_task_integration_receipts child
                      WHERE child.completion_receipt_id = NEW.completion_receipt_id
                        AND child.sprint_id = NEW.sprint_id
                        AND child.integration_receipt_id = link.task_integration_receipt_id
                  )
              )
          )
    )
    OR EXISTS (
        SELECT 1 FROM sprint_completion_v24_post_capture_mutation_blockers blocker
        WHERE blocker.sprint_id = NEW.sprint_id
    )
    OR NOT EXISTS (
        SELECT 1
        FROM agent_events completion_event
        WHERE completion_event.event_id = NEW.completion_event_id
          AND completion_event.sprint_id = NEW.sprint_id
          AND completion_event.contract_version = NEW.contract_version
          AND completion_event.occurred_at_unix_ms = NEW.terminal_at_unix_ms
          AND grok_agent_event_canonical(completion_event.event_json) = 1
          AND json_extract(CAST(completion_event.event_json AS TEXT), '$.contract_version') IS completion_event.contract_version
          AND json_extract(CAST(completion_event.event_json AS TEXT), '$.sequence') IS completion_event.sequence
          AND json_extract(CAST(completion_event.event_json AS TEXT), '$.event_id') IS completion_event.event_id
          AND json_extract(CAST(completion_event.event_json AS TEXT), '$.sprint_id') IS completion_event.sprint_id
          AND json_type(CAST(completion_event.event_json AS TEXT), '$.task_id') = 'null'
          AND json_type(CAST(completion_event.event_json AS TEXT), '$.worker_id') = 'null'
          AND json_type(CAST(completion_event.event_json AS TEXT), '$.policy_hash') = 'null'
          AND json_extract(CAST(completion_event.event_json AS TEXT), '$.occurred_at_unix_ms') IS completion_event.occurred_at_unix_ms
          AND json_extract(CAST(completion_event.event_json AS TEXT), '$.payload.CompletionRecorded') IS NEW.completion_receipt_id
    )
    OR EXISTS (
        SELECT 1
        FROM v9_completion_receipts receipt
        WHERE receipt.receipt_id = NEW.completion_receipt_id
          AND receipt.sprint_id = NEW.sprint_id
          AND (
              (SELECT COUNT(*) FROM v9_completion_cleanup_receipts child
               WHERE child.completion_receipt_id = receipt.receipt_id)
                  != json_array_length(CAST(receipt.receipt_json AS TEXT), '$.worker_cleanup_receipt_ids')
              OR EXISTS (
                  SELECT 1 FROM v9_completion_cleanup_receipts child
                  WHERE child.completion_receipt_id = receipt.receipt_id
                    AND child.cleanup_receipt_id IS NOT json_extract(
                        CAST(receipt.receipt_json AS TEXT),
                        '$.worker_cleanup_receipt_ids[' || child.ordinal || ']'
                    )
              )
              OR COALESCE((
                  SELECT MAX(child.ordinal) FROM v9_completion_cleanup_receipts child
                  WHERE child.completion_receipt_id = receipt.receipt_id
              ), -1) != json_array_length(
                  CAST(receipt.receipt_json AS TEXT), '$.worker_cleanup_receipt_ids'
              ) - 1
              OR (SELECT COUNT(*) FROM v9_completion_verification_receipts child
                  WHERE child.completion_receipt_id = receipt.receipt_id)
                  != json_array_length(CAST(receipt.receipt_json AS TEXT), '$.verification_receipts')
              OR EXISTS (
                  SELECT 1 FROM v9_completion_verification_receipts child
                  WHERE child.completion_receipt_id = receipt.receipt_id
                    AND child.verification_receipt_id IS NOT json_extract(
                        CAST(receipt.receipt_json AS TEXT),
                        '$.verification_receipts[' || child.ordinal || ']'
                    )
              )
              OR COALESCE((
                  SELECT MAX(child.ordinal) FROM v9_completion_verification_receipts child
                  WHERE child.completion_receipt_id = receipt.receipt_id
              ), -1) != json_array_length(
                  CAST(receipt.receipt_json AS TEXT), '$.verification_receipts'
              ) - 1
              OR (SELECT COUNT(*) FROM v9_completion_task_integration_receipts child
                  WHERE child.completion_receipt_id = receipt.receipt_id)
                  != json_array_length(CAST(receipt.receipt_json AS TEXT), '$.task_integration_receipt_ids')
              OR EXISTS (
                  SELECT 1 FROM v9_completion_task_integration_receipts child
                  WHERE child.completion_receipt_id = receipt.receipt_id
                    AND child.integration_receipt_id IS NOT json_extract(
                        CAST(receipt.receipt_json AS TEXT),
                        '$.task_integration_receipt_ids[' || child.ordinal || ']'
                    )
              )
              OR COALESCE((
                  SELECT MAX(child.ordinal) FROM v9_completion_task_integration_receipts child
                  WHERE child.completion_receipt_id = receipt.receipt_id
              ), -1) != json_array_length(
                  CAST(receipt.receipt_json AS TEXT), '$.task_integration_receipt_ids'
              ) - 1
              OR (SELECT COUNT(*) FROM v9_completion_acceptance_receipts child
                  WHERE child.completion_receipt_id = receipt.receipt_id)
                  != json_array_length(CAST(receipt.receipt_json AS TEXT), '$.acceptance_receipts')
              OR EXISTS (
                  SELECT 1 FROM v9_completion_acceptance_receipts child
                  WHERE child.completion_receipt_id = receipt.receipt_id
                    AND child.acceptance_receipt_id IS NOT json_extract(
                        CAST(receipt.receipt_json AS TEXT),
                        '$.acceptance_receipts[' || child.ordinal || ']'
                    )
              )
              OR COALESCE((
                  SELECT MAX(child.ordinal) FROM v9_completion_acceptance_receipts child
                  WHERE child.completion_receipt_id = receipt.receipt_id
              ), -1) != json_array_length(
                  CAST(receipt.receipt_json AS TEXT), '$.acceptance_receipts'
              ) - 1
          )
    )
)
BEGIN SELECT RAISE(ABORT, 'proven completion requires exact v24 capture authority and child links'); END;
