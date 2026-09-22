-- Schema-v22 adds the first executable sprint application boundary. Every
-- row below is immutable provenance; exact replay can read it but can never
-- mint a fresh dispatch capability.

CREATE TABLE application_artifact_assemblies (
    assembly_id TEXT PRIMARY KEY NOT NULL,
    sprint_id TEXT NOT NULL,
    final_verification_receipt_id TEXT NOT NULL,
    change_set_id TEXT NOT NULL,
    base_snapshot TEXT NOT NULL,
    result_snapshot TEXT NOT NULL,
    artifact_format_version INTEGER NOT NULL CHECK (artifact_format_version > 0),
    artifact_digest TEXT NOT NULL,
    source_count INTEGER NOT NULL CHECK (source_count = 1),
    contract_version INTEGER NOT NULL CHECK (contract_version > 0),
    assembled_at_unix_ms INTEGER NOT NULL CHECK (assembled_at_unix_ms > 0),
    assembly_json BLOB NOT NULL CHECK (length(assembly_json) BETWEEN 1 AND 8388608),
    UNIQUE (sprint_id, assembly_id),
    FOREIGN KEY (sprint_id, change_set_id)
        REFERENCES change_sets(sprint_id, change_set_id) ON DELETE RESTRICT,
    FOREIGN KEY (sprint_id, final_verification_receipt_id)
        REFERENCES verification_receipts(sprint_id, receipt_id) ON DELETE RESTRICT,
    FOREIGN KEY (sprint_id, base_snapshot)
        REFERENCES workspace_snapshots(sprint_id, snapshot_id) ON DELETE RESTRICT,
    FOREIGN KEY (sprint_id, result_snapshot)
        REFERENCES workspace_snapshots(sprint_id, snapshot_id) ON DELETE RESTRICT
) STRICT, WITHOUT ROWID;

CREATE TABLE application_artifact_assembly_sources (
    assembly_id TEXT NOT NULL,
    sprint_id TEXT NOT NULL,
    source_ordinal INTEGER NOT NULL CHECK (source_ordinal = 0),
    task_id TEXT NOT NULL,
    task_integration_receipt_id TEXT NOT NULL,
    contract_version INTEGER NOT NULL CHECK (contract_version > 0),
    PRIMARY KEY (assembly_id, source_ordinal),
    UNIQUE (assembly_id, task_id),
    UNIQUE (assembly_id, task_integration_receipt_id),
    FOREIGN KEY (sprint_id, assembly_id)
        REFERENCES application_artifact_assemblies(sprint_id, assembly_id)
        ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED,
    FOREIGN KEY (sprint_id, task_integration_receipt_id)
        REFERENCES task_integration_receipts(sprint_id, receipt_id) ON DELETE RESTRICT
) STRICT, WITHOUT ROWID;

CREATE TABLE sprint_application_admissions (
    admission_id TEXT PRIMARY KEY NOT NULL,
    sprint_id TEXT NOT NULL,
    sprint_phase_event_id TEXT NOT NULL UNIQUE,
    final_verification_receipt_id TEXT NOT NULL,
    artifact_assembly_id TEXT NOT NULL UNIQUE,
    effect_id TEXT NOT NULL UNIQUE,
    runner_launch_id TEXT NOT NULL,
    runner_session_id TEXT NOT NULL,
    request_digest TEXT NOT NULL,
    base_snapshot TEXT NOT NULL,
    result_snapshot TEXT NOT NULL,
    contract_version INTEGER NOT NULL CHECK (contract_version > 0),
    admitted_at_unix_ms INTEGER NOT NULL CHECK (admitted_at_unix_ms > 0),
    admission_json BLOB NOT NULL CHECK (length(admission_json) BETWEEN 1 AND 8388608),
    UNIQUE (sprint_id, admission_id),
    FOREIGN KEY (sprint_phase_event_id)
        REFERENCES agent_events(event_id) ON DELETE RESTRICT,
    FOREIGN KEY (sprint_id, artifact_assembly_id)
        REFERENCES application_artifact_assemblies(sprint_id, assembly_id) ON DELETE RESTRICT,
    FOREIGN KEY (sprint_id, final_verification_receipt_id)
        REFERENCES verification_receipts(sprint_id, receipt_id) ON DELETE RESTRICT,
    FOREIGN KEY (sprint_id, runner_launch_id)
        REFERENCES runner_launch_intents(sprint_id, launch_id) ON DELETE RESTRICT,
    FOREIGN KEY (sprint_id, runner_session_id)
        REFERENCES runner_session_policies(sprint_id, session_id) ON DELETE RESTRICT,
    FOREIGN KEY (sprint_id, effect_id)
        REFERENCES effect_intents(sprint_id, effect_id)
        ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED
) STRICT, WITHOUT ROWID;

-- Only successful completions that were already durable before v22 retain the
-- old optional-integrated-no-op omission rule. Runtime inserts are forbidden.
CREATE TABLE pre_v22_completion_authority_exemptions (
    sprint_id TEXT PRIMARY KEY NOT NULL,
    completion_receipt_id TEXT NOT NULL UNIQUE,
    completion_event_id TEXT NOT NULL UNIQUE,
    marked_at_schema_version INTEGER NOT NULL CHECK (marked_at_schema_version = 22),
    FOREIGN KEY (sprint_id) REFERENCES sprints(sprint_id) ON DELETE RESTRICT
) STRICT, WITHOUT ROWID;

INSERT INTO pre_v22_completion_authority_exemptions (
    sprint_id, completion_receipt_id, completion_event_id, marked_at_schema_version
)
SELECT sprint_id, completion_receipt_id, completion_event_id, 22
FROM sprint_completion_proof_states
WHERE proof_state = 'ProvenV9';

CREATE TRIGGER application_artifact_assemblies_no_update
BEFORE UPDATE ON application_artifact_assemblies
BEGIN SELECT RAISE(ABORT, 'application artifact assemblies are immutable'); END;
CREATE TRIGGER application_artifact_assemblies_no_delete
BEFORE DELETE ON application_artifact_assemblies
BEGIN SELECT RAISE(ABORT, 'application artifact assemblies are immutable'); END;
CREATE TRIGGER application_artifact_assembly_sources_no_update
BEFORE UPDATE ON application_artifact_assembly_sources
BEGIN SELECT RAISE(ABORT, 'application artifact assembly sources are immutable'); END;
CREATE TRIGGER application_artifact_assembly_sources_no_delete
BEFORE DELETE ON application_artifact_assembly_sources
BEGIN SELECT RAISE(ABORT, 'application artifact assembly sources are immutable'); END;
CREATE TRIGGER sprint_application_admissions_no_update
BEFORE UPDATE ON sprint_application_admissions
BEGIN SELECT RAISE(ABORT, 'sprint application admissions are immutable'); END;
CREATE TRIGGER sprint_application_admissions_no_delete
BEFORE DELETE ON sprint_application_admissions
BEGIN SELECT RAISE(ABORT, 'sprint application admissions are immutable'); END;
CREATE TRIGGER pre_v22_completion_authority_exemptions_no_insert
BEFORE INSERT ON pre_v22_completion_authority_exemptions
BEGIN SELECT RAISE(ABORT, 'pre-v22 completion exemptions are migration-only'); END;
CREATE TRIGGER pre_v22_completion_authority_exemptions_no_update
BEFORE UPDATE ON pre_v22_completion_authority_exemptions
BEGIN SELECT RAISE(ABORT, 'pre-v22 completion exemptions are immutable'); END;
CREATE TRIGGER pre_v22_completion_authority_exemptions_no_delete
BEFORE DELETE ON pre_v22_completion_authority_exemptions
BEGIN SELECT RAISE(ABORT, 'pre-v22 completion exemptions are immutable'); END;

-- V18 allowed an integrated optional task to be omitted only when it was an
-- exact no-op. V22 instead makes every integrated graph task part of the
-- completion chain, regardless of required/optional or empty/nonempty result.
-- Unattempted optional tasks and safely terminal optional attempts remain
-- omittable. Recreate the complete predicate so the SQL writer fence mirrors
-- the v22 Rust validator rather than retaining the v18 optional branch.
DROP TRIGGER sprint_completion_task_attempt_predicate;
CREATE TRIGGER sprint_completion_task_attempt_predicate
BEFORE INSERT ON sprint_completion_proof_states
WHEN NEW.proof_state = 'ProvenV9'
 AND (
    EXISTS (
        SELECT 1 FROM active_worker_leases active
        WHERE active.sprint_id = NEW.sprint_id
    )
    OR EXISTS (
        SELECT 1
        FROM sprint_unknown_terminalization_pending pending
        LEFT JOIN sprint_unknown_terminalization_closures closure
          ON closure.marker_id = pending.marker_id
        WHERE pending.sprint_id = NEW.sprint_id
          AND closure.marker_id IS NULL
    )
    OR EXISTS (
        SELECT 1
        FROM task_attempts attempt
        LEFT JOIN task_attempt_dispositions disposition
          ON disposition.attempt_id = attempt.attempt_id
        WHERE attempt.sprint_id = NEW.sprint_id
          AND attempt.schema_generation = 15
          AND disposition.attempt_id IS NULL
    )
    OR EXISTS (
        SELECT 1
        FROM task_attempts attempt
        JOIN sprints sprint ON sprint.sprint_id = attempt.sprint_id
        WHERE attempt.sprint_id = NEW.sprint_id
          AND attempt.schema_generation = 15
        GROUP BY attempt.sprint_id, attempt.task_id
        HAVING COUNT(*) > json_extract(
            CAST(sprint.spec_json AS TEXT), '$.budget.max_attempts_per_task'
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
        WHERE attempt.sprint_id = NEW.sprint_id
          AND attempt.schema_generation = 15
          AND attempt.attempt_ordinal = (
              SELECT MAX(latest.attempt_ordinal)
              FROM task_attempts latest
              WHERE latest.sprint_id = attempt.sprint_id
                AND latest.task_id = attempt.task_id
                AND latest.schema_generation = 15
          )
          AND EXISTS (
              SELECT 1
              FROM sprint_task_graphs graph,
                   json_each(CAST(graph.graph_json AS TEXT), '$.tasks') graph_task
              WHERE graph.sprint_id = NEW.sprint_id
                AND json_extract(graph_task.value, '$.task_id') = attempt.task_id
                AND json_extract(graph_task.value, '$.required') = 1
          )
          AND (
              disposition.disposition_kind != 'Integrated'
              OR NOT EXISTS (
                  SELECT 1
                  FROM v9_completion_task_integration_receipts link
                  WHERE link.completion_receipt_id = NEW.completion_receipt_id
                    AND link.sprint_id = NEW.sprint_id
                    AND link.integration_receipt_id = disposition.integration_receipt_id
              )
          )
    )
    OR EXISTS (
        SELECT 1
        FROM task_attempts attempt
        WHERE attempt.sprint_id = NEW.sprint_id
          AND attempt.schema_generation = 15
          AND NOT EXISTS (
              SELECT 1
              FROM sprint_task_graphs graph,
                   json_each(CAST(graph.graph_json AS TEXT), '$.tasks') graph_task
              WHERE graph.sprint_id = NEW.sprint_id
                AND json_extract(graph_task.value, '$.task_id') = attempt.task_id
          )
    )
    OR EXISTS (
        SELECT 1
        FROM task_attempts attempt
        JOIN task_attempt_dispositions disposition
          ON disposition.attempt_id = attempt.attempt_id
        WHERE attempt.sprint_id = NEW.sprint_id
          AND attempt.schema_generation = 15
          AND attempt.attempt_ordinal = (
              SELECT MAX(latest.attempt_ordinal)
              FROM task_attempts latest
              WHERE latest.sprint_id = attempt.sprint_id
                AND latest.task_id = attempt.task_id
                AND latest.schema_generation = 15
          )
          AND EXISTS (
              SELECT 1
              FROM sprint_task_graphs graph,
                   json_each(CAST(graph.graph_json AS TEXT), '$.tasks') graph_task
              WHERE graph.sprint_id = NEW.sprint_id
                AND json_extract(graph_task.value, '$.task_id') = attempt.task_id
                AND json_extract(graph_task.value, '$.required') = 0
          )
          AND (
              disposition.disposition_kind NOT IN (
                  'Integrated', 'AttemptsExhausted', 'PermanentFailure',
                  'Blocked', 'Canceled'
              )
              OR (
                  disposition.disposition_kind = 'Integrated'
                  AND NOT EXISTS (
                      SELECT 1
                      FROM v9_completion_task_integration_receipts link
                      WHERE link.completion_receipt_id = NEW.completion_receipt_id
                        AND link.sprint_id = NEW.sprint_id
                        AND link.integration_receipt_id = disposition.integration_receipt_id
                  )
              )
              OR (
                  disposition.disposition_kind IN (
                      'AttemptsExhausted', 'PermanentFailure', 'Blocked', 'Canceled'
                  )
                  AND EXISTS (
                      SELECT 1
                      FROM v9_completion_task_integration_receipts link
                      JOIN task_integration_receipts integration
                        ON integration.sprint_id = link.sprint_id
                       AND integration.receipt_id = link.integration_receipt_id
                      WHERE link.completion_receipt_id = NEW.completion_receipt_id
                        AND link.sprint_id = NEW.sprint_id
                        AND integration.task_id = attempt.task_id
                  )
              )
          )
    )
    OR EXISTS (
        SELECT 1
        FROM task_attempts attempt
        LEFT JOIN task_attempt_legacy_classifications legacy
          ON legacy.attempt_id = attempt.attempt_id
        WHERE attempt.sprint_id = NEW.sprint_id
          AND attempt.schema_generation = 14
          AND (
              legacy.attempt_id IS NULL
              OR legacy.classification != 'LegacyIntegratedReleased'
              OR legacy.budget_classification != 'WithinBudget'
          )
    )
 )
BEGIN
    SELECT RAISE(ABORT, 'v22 completion requires every integrated TaskDone link and safe optional closure');
END;

-- Hard SQL mirror for assembly identity and the exact sole typed integration
-- source. Rust readback additionally verifies complete canonical bytes and
-- the full TaskDone conjunction.
CREATE TRIGGER application_artifact_assemblies_v22_validate
BEFORE INSERT ON application_artifact_assemblies
WHEN json_valid(CAST(NEW.assembly_json AS TEXT)) != 1
 OR json_extract(CAST(NEW.assembly_json AS TEXT), '$.contract_version') != NEW.contract_version
 OR json_extract(CAST(NEW.assembly_json AS TEXT), '$.assembly_id') != NEW.assembly_id
 OR json_extract(CAST(NEW.assembly_json AS TEXT), '$.sprint_id') != NEW.sprint_id
 OR json_extract(CAST(NEW.assembly_json AS TEXT), '$.final_verification_receipt_id') != NEW.final_verification_receipt_id
 OR json_extract(CAST(NEW.assembly_json AS TEXT), '$.change_set.change_set_id') != NEW.change_set_id
 OR json_extract(CAST(NEW.assembly_json AS TEXT), '$.change_set.base_snapshot') != NEW.base_snapshot
 OR json_extract(CAST(NEW.assembly_json AS TEXT), '$.change_set.result_snapshot') != NEW.result_snapshot
 OR json_extract(CAST(NEW.assembly_json AS TEXT), '$.artifact.format_version') != NEW.artifact_format_version
 OR json_extract(CAST(NEW.assembly_json AS TEXT), '$.artifact.artifact_digest') != NEW.artifact_digest
 OR json_array_length(CAST(NEW.assembly_json AS TEXT), '$.sources') != 1
 OR json_extract(CAST(NEW.assembly_json AS TEXT), '$.sources[0].source_ordinal') != 0
 OR json_extract(CAST(NEW.assembly_json AS TEXT), '$.assembled_at_unix_ms') != NEW.assembled_at_unix_ms
 OR NOT EXISTS (
    SELECT 1
    FROM change_sets change_set
    JOIN verification_receipts final
      ON final.sprint_id = change_set.sprint_id
     AND final.receipt_id = NEW.final_verification_receipt_id
    WHERE change_set.sprint_id = NEW.sprint_id
      AND change_set.change_set_id = NEW.change_set_id
      AND change_set.base_snapshot = NEW.base_snapshot
      AND change_set.result_snapshot = NEW.result_snapshot
      AND final.passed = 1
      AND final.snapshot_id = NEW.result_snapshot
      AND final.finished_at_unix_ms <= NEW.assembled_at_unix_ms
      AND change_set.contract_version = NEW.contract_version
      AND final.contract_version = NEW.contract_version
 )
BEGIN SELECT RAISE(ABORT, 'application assembly must mirror one exact change set and passing final receipt'); END;

CREATE TRIGGER application_artifact_assembly_sources_v22_validate
BEFORE INSERT ON application_artifact_assembly_sources
WHEN NOT EXISTS (
    SELECT 1
    FROM application_artifact_assemblies assembly
    JOIN task_integration_receipts receipt
      ON receipt.sprint_id = assembly.sprint_id
     AND receipt.receipt_id = NEW.task_integration_receipt_id
    JOIN effect_evidence_payloads evidence
      ON evidence.sprint_id = receipt.sprint_id
     AND evidence.effect_id = receipt.effect_id
     AND evidence.observation_id = receipt.observation_id
    WHERE assembly.assembly_id = NEW.assembly_id
      AND assembly.sprint_id = NEW.sprint_id
      AND NEW.source_ordinal = 0
      AND receipt.integration_ordinal = 0
      AND receipt.task_id = NEW.task_id
      AND receipt.change_set_id = assembly.change_set_id
      AND receipt.input_snapshot = assembly.base_snapshot
      AND receipt.result_snapshot = assembly.result_snapshot
      AND json_valid(CAST(evidence.evidence_bytes AS TEXT)) = 1
      AND json_extract(CAST(evidence.evidence_bytes AS TEXT), '$.receipt.receipt_id') = receipt.receipt_id
      AND json_extract(CAST(evidence.evidence_bytes AS TEXT), '$.artifact.format_version') = assembly.artifact_format_version
      AND json_extract(CAST(evidence.evidence_bytes AS TEXT), '$.artifact.artifact_digest') = assembly.artifact_digest
      AND json_extract(CAST(evidence.evidence_bytes AS TEXT), '$.artifact.change_set_id') = assembly.change_set_id
      AND json_extract(CAST(evidence.evidence_bytes AS TEXT), '$.artifact.base_snapshot') = assembly.base_snapshot
      AND json_extract(CAST(evidence.evidence_bytes AS TEXT), '$.artifact.result_snapshot') = assembly.result_snapshot
      AND receipt.contract_version = NEW.contract_version
      AND evidence.contract_version = NEW.contract_version
      AND assembly.contract_version = NEW.contract_version
 )
BEGIN SELECT RAISE(ABORT, 'application assembly source must be the exact ordinal-zero typed integration evidence'); END;

-- The phase row is inserted first; the exact application intent follows under
-- deferred foreign keys. This trigger proves the closed admission cut before
-- any effect can become durable.
CREATE TRIGGER sprint_application_admissions_v22_validate
BEFORE INSERT ON sprint_application_admissions
WHEN json_valid(CAST(NEW.admission_json AS TEXT)) != 1
 OR json_extract(CAST(NEW.admission_json AS TEXT), '$.contract_version') != NEW.contract_version
 OR json_extract(CAST(NEW.admission_json AS TEXT), '$.admission_id') != NEW.admission_id
 OR json_extract(CAST(NEW.admission_json AS TEXT), '$.sprint_id') != NEW.sprint_id
 OR json_extract(CAST(NEW.admission_json AS TEXT), '$.sprint_phase_event_id') != NEW.sprint_phase_event_id
 OR json_extract(CAST(NEW.admission_json AS TEXT), '$.final_verification_receipt_id') != NEW.final_verification_receipt_id
 OR json_extract(CAST(NEW.admission_json AS TEXT), '$.artifact_assembly_id') != NEW.artifact_assembly_id
 OR json_extract(CAST(NEW.admission_json AS TEXT), '$.effect_id') != NEW.effect_id
 OR json_extract(CAST(NEW.admission_json AS TEXT), '$.runner_launch_id') != NEW.runner_launch_id
 OR json_extract(CAST(NEW.admission_json AS TEXT), '$.runner_session_id') != NEW.runner_session_id
 OR json_extract(CAST(NEW.admission_json AS TEXT), '$.request.change_set.base_snapshot') != NEW.base_snapshot
 OR json_extract(CAST(NEW.admission_json AS TEXT), '$.request.change_set.result_snapshot') != NEW.result_snapshot
 OR json_extract(CAST(NEW.admission_json AS TEXT), '$.admitted_at_unix_ms') != NEW.admitted_at_unix_ms
 OR EXISTS (SELECT 1 FROM effect_intents WHERE effect_id = NEW.effect_id)
 OR EXISTS (SELECT 1 FROM active_worker_leases WHERE sprint_id = NEW.sprint_id)
 OR NOT EXISTS (
    SELECT 1
    FROM application_artifact_assemblies assembly
    JOIN application_artifact_assembly_sources source
      ON source.assembly_id = assembly.assembly_id
     AND source.sprint_id = assembly.sprint_id
     AND source.source_ordinal = 0
    JOIN agent_events phase
      ON phase.sprint_id = assembly.sprint_id
     AND phase.event_id = NEW.sprint_phase_event_id
    JOIN verification_receipts final
      ON final.sprint_id = assembly.sprint_id
     AND final.receipt_id = NEW.final_verification_receipt_id
    JOIN verification_effect_evidence final_evidence
      ON final_evidence.sprint_id = final.sprint_id
     AND final_evidence.verification_receipt_id = final.receipt_id
    JOIN sprint_final_verification_admissions final_admission
      ON final_admission.sprint_id = final.sprint_id
     AND final_admission.effect_id = final_evidence.effect_id
    JOIN effect_observations final_observation
      ON final_observation.effect_id = final_evidence.effect_id
     AND final_observation.observation_id = final_evidence.observation_id
    JOIN runner_effect_dispatch_claims final_claim
      ON final_claim.effect_id = final_evidence.effect_id
     AND final_claim.dispatch_claim_id = final_observation.dispatch_claim_id
    JOIN runner_effect_dispatch_claim_authorities final_authority
      ON final_authority.dispatch_claim_id = final_claim.dispatch_claim_id
     AND final_authority.authority_class = 'SprintFinalVerification'
     AND final_authority.sprint_phase_event_id = final_admission.sprint_phase_event_id
    JOIN worker_cleanup_receipts final_cleanup
      ON final_cleanup.sprint_id = final.sprint_id
     AND final_cleanup.launch_id = final_admission.runner_launch_id
     AND final_cleanup.session_id = final_admission.runner_session_id
    JOIN command_domain_cleanup_proofs command_cleanup
      ON command_cleanup.sprint_id = final.sprint_id
     AND command_cleanup.launch_id = final_admission.runner_launch_id
     AND command_cleanup.session_id = final_admission.runner_session_id
     AND command_cleanup.effect_id = final_evidence.effect_id
    JOIN runner_launch_intents launch
      ON launch.sprint_id = assembly.sprint_id
     AND launch.launch_id = NEW.runner_launch_id
    JOIN runner_session_policies session
      ON session.sprint_id = assembly.sprint_id
     AND session.session_id = NEW.runner_session_id
     AND session.launch_id = launch.launch_id
    JOIN runner_launch_cleanup_admissions cleanup
      ON cleanup.sprint_id = assembly.sprint_id
     AND cleanup.launch_id = launch.launch_id
     AND cleanup.session_id = session.session_id
    LEFT JOIN worker_cleanup_receipts application_cleanup
      ON application_cleanup.sprint_id = cleanup.sprint_id
     AND application_cleanup.launch_id = cleanup.launch_id
    WHERE assembly.assembly_id = NEW.artifact_assembly_id
      AND assembly.sprint_id = NEW.sprint_id
      AND assembly.final_verification_receipt_id = NEW.final_verification_receipt_id
      AND assembly.base_snapshot = NEW.base_snapshot
      AND assembly.result_snapshot = NEW.result_snapshot
      AND final.passed = 1
      AND final.snapshot_id = NEW.result_snapshot
      AND final_admission.final_snapshot = NEW.result_snapshot
      AND final_observation.outcome = 'Succeeded'
      AND phase.contract_version = NEW.contract_version
      AND json_extract(CAST(phase.event_json AS TEXT), '$.payload.SprintStateChanged.from') = 'FinalVerification'
      AND json_extract(CAST(phase.event_json AS TEXT), '$.payload.SprintStateChanged.to') = 'Applying'
      AND json_extract(CAST(phase.event_json AS TEXT), '$.causation_id') = final_observation.terminal_event_id
      AND phase.occurred_at_unix_ms >= final.finished_at_unix_ms
      AND phase.occurred_at_unix_ms >= final_cleanup.cleaned_at_unix_ms
      AND phase.occurred_at_unix_ms >= command_cleanup.cleaned_at_unix_ms
      AND NEW.admitted_at_unix_ms >= phase.occurred_at_unix_ms
      AND NEW.admitted_at_unix_ms >= final.finished_at_unix_ms
      AND NEW.admitted_at_unix_ms >= final_cleanup.cleaned_at_unix_ms
      AND NEW.admitted_at_unix_ms >= command_cleanup.cleaned_at_unix_ms
      AND launch.purpose = 'Applier'
      AND session.purpose = 'Applier'
      AND launch.worker_id IS NULL
      AND session.worker_id IS NULL
      AND launch.worker_lease_id IS NULL
      AND session.worker_lease_id IS NULL
      AND launch.policy_hash = session.policy_hash
      AND launch.policy_hash = json_extract(CAST(phase.event_json AS TEXT), '$.policy_hash')
      AND launch.created_at_unix_ms <= NEW.admitted_at_unix_ms
      AND session.registered_at_unix_ms <= NEW.admitted_at_unix_ms
      AND application_cleanup.receipt_id IS NULL
      AND assembly.contract_version = NEW.contract_version
      AND source.contract_version = NEW.contract_version
      AND final_evidence.contract_version = NEW.contract_version
      AND final_claim.contract_version = NEW.contract_version
      AND final_authority.contract_version = NEW.contract_version
      AND launch.contract_version = NEW.contract_version
      AND session.contract_version = NEW.contract_version
      AND cleanup.contract_version = NEW.contract_version
      AND NOT EXISTS (
          SELECT 1 FROM agent_events later
          WHERE later.sprint_id = NEW.sprint_id
            AND later.sequence > phase.sequence
            AND json_type(CAST(later.event_json AS TEXT), '$.payload.SprintStateChanged') = 'object'
      )
 )
 OR EXISTS (
    SELECT 1
    FROM effect_intents unresolved
    LEFT JOIN effect_observations observation
      ON observation.effect_id = unresolved.effect_id
    WHERE unresolved.sprint_id = NEW.sprint_id
      AND unresolved.effect_id != COALESCE((
          SELECT cleanup_effect_id FROM runner_launch_cleanup_admissions
          WHERE sprint_id = NEW.sprint_id AND launch_id = NEW.runner_launch_id
      ), '')
      AND (observation.effect_id IS NULL OR observation.outcome = 'Unknown')
 )
BEGIN SELECT RAISE(ABORT, 'application admission must match one exact cleaned claimed-final cut and open Applier authority'); END;

CREATE TRIGGER effect_intents_v22_application_admission_required
AFTER INSERT ON effect_intents
WHEN EXISTS (
       SELECT 1 FROM finish_effect_kinds kind
       WHERE kind.effect_id = NEW.effect_id AND kind.effect_kind = 'ApplyChangeSet'
     )
 AND NOT EXISTS (
    SELECT 1
    FROM sprint_application_admissions admission
    JOIN application_artifact_assemblies assembly
      ON assembly.assembly_id = admission.artifact_assembly_id
     AND assembly.sprint_id = admission.sprint_id
    JOIN effect_session_bindings binding
      ON binding.effect_id = NEW.effect_id AND binding.sprint_id = NEW.sprint_id
    JOIN effect_request_payloads request
      ON request.effect_id = NEW.effect_id AND request.sprint_id = NEW.sprint_id
    JOIN application_request_artifact_authorities artifact
      ON artifact.effect_id = NEW.effect_id AND artifact.sprint_id = NEW.sprint_id
    WHERE admission.effect_id = NEW.effect_id
      AND admission.sprint_id = NEW.sprint_id
      AND admission.runner_launch_id = binding.launch_id
      AND admission.runner_session_id = binding.session_id
      AND admission.request_digest = NEW.request_digest
      AND admission.request_digest = request.request_digest
      AND admission.request_digest = artifact.request_digest
      AND admission.base_snapshot = NEW.input_snapshot
      AND admission.base_snapshot = assembly.base_snapshot
      AND admission.result_snapshot = assembly.result_snapshot
      AND admission.sprint_phase_event_id = NEW.causation_event_id
      AND NEW.task_id IS NULL
      AND NEW.worker_id IS NULL
      AND NEW.worker_lease_id IS NULL
      AND NEW.worker_lease_epoch IS NULL
      AND NEW.effect_kind = 'ApplyChangeSet'
      AND NEW.created_at_unix_ms = admission.admitted_at_unix_ms
      AND admission.contract_version = NEW.contract_version
      AND binding.contract_version = NEW.contract_version
      AND request.contract_version = NEW.contract_version
      AND artifact.contract_version = NEW.contract_version
 )
BEGIN SELECT RAISE(ABORT, 'ApplyChangeSet intent requires exact current sprint application admission'); END;

DROP TRIGGER effect_observations_v21_phase_admission_claim_required;
CREATE TRIGGER effect_observations_v22_phase_admission_claim_required
BEFORE INSERT ON effect_observations
WHEN NEW.dispatch_claim_id IS NULL
 AND (
       EXISTS (SELECT 1 FROM sprint_final_verification_admissions WHERE effect_id = NEW.effect_id)
       OR EXISTS (SELECT 1 FROM sprint_application_admissions WHERE effect_id = NEW.effect_id)
       OR EXISTS (
           SELECT 1 FROM task_attempt_formal_check_admissions admission
           WHERE admission.effect_id = NEW.effect_id
             AND NOT EXISTS (
                 SELECT 1 FROM task_phase_claimless_legacy_exemptions legacy
                 WHERE legacy.authority_class = 'TaskFormalCheck'
                   AND legacy.admission_id = admission.admission_id
                   AND legacy.effect_id = admission.effect_id
                   AND legacy.admitted_contract_version = admission.contract_version
             )
       )
       OR EXISTS (
           SELECT 1 FROM task_attempt_integration_admissions admission
           WHERE admission.effect_id = NEW.effect_id
             AND NOT EXISTS (
                 SELECT 1 FROM task_phase_claimless_legacy_exemptions legacy
                 WHERE legacy.authority_class = 'TaskIntegration'
                   AND legacy.admission_id = admission.admission_id
                   AND legacy.effect_id = admission.effect_id
                   AND legacy.admitted_contract_version = admission.contract_version
             )
       )
 )
BEGIN SELECT RAISE(ABORT, 'current phase admission requires its exact runner dispatch claim'); END;

DROP TRIGGER agent_events_v21_unobserved_sprint_final_claim_phase_fence;
CREATE TRIGGER agent_events_v22_unobserved_sprint_claim_phase_fence
BEFORE INSERT ON agent_events
WHEN json_type(CAST(NEW.event_json AS TEXT), '$.payload.SprintStateChanged') = 'object'
 AND EXISTS (
    SELECT 1
    FROM runner_effect_dispatch_claims claim
    JOIN runner_effect_dispatch_claim_authorities authority
      ON authority.dispatch_claim_id = claim.dispatch_claim_id
    LEFT JOIN effect_observations observation ON observation.effect_id = claim.effect_id
    WHERE claim.sprint_id = NEW.sprint_id
      AND authority.authority_class IN ('SprintFinalVerification', 'SprintApplication')
      AND observation.effect_id IS NULL
 )
BEGIN SELECT RAISE(ABORT, 'unobserved sprint claim blocks every sprint phase transition'); END;

DROP TRIGGER runner_effect_dispatch_claim_authorities_v21_runtime_shape;
DROP TRIGGER runner_effect_dispatch_claims_v21_companion_required;
DROP TRIGGER runner_effect_dispatch_claims_identity_match;

CREATE TRIGGER runner_effect_dispatch_claim_authorities_v22_runtime_shape
BEFORE INSERT ON runner_effect_dispatch_claim_authorities
WHEN NEW.authority_class NOT IN (
       'TaskRunning', 'TaskFormalCheck', 'TaskIntegration',
       'SprintFinalVerification', 'SprintApplication'
     )
  OR EXISTS (
      SELECT 1 FROM runner_effect_dispatch_claims claim
      WHERE claim.dispatch_claim_id = NEW.dispatch_claim_id
  )
BEGIN SELECT RAISE(ABORT, 'v22 runtime companion must be pre-parent implemented phase authority'); END;

CREATE TRIGGER runner_effect_dispatch_claims_v22_companion_required
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
BEGIN SELECT RAISE(ABORT, 'v22 runner dispatch claim requires exact implemented phase companion'); END;
CREATE TRIGGER runner_effect_dispatch_claims_identity_match
BEFORE INSERT ON runner_effect_dispatch_claims
WHEN NOT EXISTS (
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
