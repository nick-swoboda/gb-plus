-- Schema v19 adds the phase authority beside, rather than inside, the
-- immutable v17 claim. Existing Running claims are projected for diagnostic
-- readback only; no migration path recreates an in-memory capability.
CREATE TABLE runner_effect_dispatch_claim_authorities (
    dispatch_claim_id TEXT PRIMARY KEY NOT NULL,
    authority_class TEXT NOT NULL CHECK (authority_class IN (
        'TaskRunning', 'TaskFormalCheck', 'TaskIntegration',
        'SprintFinalVerification', 'SprintApplication', 'SprintRollback'
    )),
    running_boundary_id TEXT,
    formal_check_admission_id TEXT,
    integration_admission_id TEXT,
    sprint_phase_event_id TEXT,
    rollback_reference_id TEXT,
    contract_version INTEGER NOT NULL CHECK (contract_version > 0),
    CHECK (
        (authority_class = 'TaskRunning'
         AND running_boundary_id IS NOT NULL
         AND formal_check_admission_id IS NULL
         AND integration_admission_id IS NULL
         AND sprint_phase_event_id IS NULL
         AND rollback_reference_id IS NULL)
        OR (authority_class = 'TaskFormalCheck'
            AND running_boundary_id IS NULL
            AND formal_check_admission_id IS NOT NULL
            AND integration_admission_id IS NULL
            AND sprint_phase_event_id IS NULL
            AND rollback_reference_id IS NULL)
        OR (authority_class = 'TaskIntegration'
            AND running_boundary_id IS NULL
            AND formal_check_admission_id IS NULL
            AND integration_admission_id IS NOT NULL
            AND sprint_phase_event_id IS NULL
            AND rollback_reference_id IS NULL)
        OR (authority_class IN ('SprintFinalVerification', 'SprintApplication')
            AND running_boundary_id IS NULL
            AND formal_check_admission_id IS NULL
            AND integration_admission_id IS NULL
            AND sprint_phase_event_id IS NOT NULL
            AND rollback_reference_id IS NULL)
        OR (authority_class = 'SprintRollback'
            AND running_boundary_id IS NULL
            AND formal_check_admission_id IS NULL
            AND integration_admission_id IS NULL
            AND sprint_phase_event_id IS NOT NULL
            AND rollback_reference_id IS NOT NULL)
    ),
    FOREIGN KEY (dispatch_claim_id)
        REFERENCES runner_effect_dispatch_claims(dispatch_claim_id)
        ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED,
    FOREIGN KEY (running_boundary_id)
        REFERENCES task_attempt_running_boundaries(boundary_id) ON DELETE RESTRICT,
    FOREIGN KEY (formal_check_admission_id)
        REFERENCES task_attempt_formal_check_admissions(admission_id) ON DELETE RESTRICT,
    FOREIGN KEY (integration_admission_id)
        REFERENCES task_attempt_integration_admissions(admission_id) ON DELETE RESTRICT,
    FOREIGN KEY (sprint_phase_event_id)
        REFERENCES agent_events(event_id) ON DELETE RESTRICT,
    FOREIGN KEY (rollback_reference_id)
        REFERENCES rollback_references(reference_id) ON DELETE RESTRICT
) STRICT, WITHOUT ROWID;

-- Project the sole safe historical shape. Claims without this row are explicit
-- legacy-unphased records and remain reconciliation-only.
INSERT INTO runner_effect_dispatch_claim_authorities (
    dispatch_claim_id, authority_class, running_boundary_id,
    formal_check_admission_id, integration_admission_id, sprint_phase_event_id,
    rollback_reference_id, contract_version
)
SELECT dispatch_claim_id, 'TaskRunning', running_boundary_id,
       NULL, NULL, NULL, NULL, contract_version
FROM runner_effect_dispatch_claims
WHERE running_boundary_id IS NOT NULL;

-- Migration backfill above is the sole exception. Runtime companions must be
-- inserted before their new parent claim in the same transaction, and this
-- TaskRunning-only tranche refuses every reserved future class outright.
CREATE TRIGGER runner_effect_dispatch_claim_authorities_v19_runtime_shape
BEFORE INSERT ON runner_effect_dispatch_claim_authorities
WHEN NEW.authority_class != 'TaskRunning'
  OR EXISTS (
      SELECT 1 FROM runner_effect_dispatch_claims claim
      WHERE claim.dispatch_claim_id = NEW.dispatch_claim_id
  )
BEGIN SELECT RAISE(ABORT, 'v19 runtime companion must be pre-parent exact TaskRunning authority'); END;

CREATE TRIGGER runner_effect_dispatch_claim_authorities_no_update
BEFORE UPDATE ON runner_effect_dispatch_claim_authorities
BEGIN SELECT RAISE(ABORT, 'runner dispatch claim authorities are immutable'); END;

CREATE TRIGGER runner_effect_dispatch_claim_authorities_no_delete
BEFORE DELETE ON runner_effect_dispatch_claim_authorities
BEGIN SELECT RAISE(ABORT, 'runner dispatch claim authorities are immutable'); END;

-- v19 runtime inserts must carry a normalized companion. TaskRunning is the
-- only branch admitted by this tranche; the other complete shapes are durable
-- schema reservations until their phase-specific admission paths exist.
CREATE TRIGGER runner_effect_dispatch_claims_v19_companion_required
BEFORE INSERT ON runner_effect_dispatch_claims
WHEN NOT EXISTS (
    SELECT 1 FROM runner_effect_dispatch_claim_authorities authority
    WHERE authority.dispatch_claim_id = NEW.dispatch_claim_id
      AND authority.authority_class = 'TaskRunning'
      AND authority.running_boundary_id = NEW.running_boundary_id
      AND authority.contract_version = NEW.contract_version
)
BEGIN SELECT RAISE(ABORT, 'v19 runner dispatch claim requires exact TaskRunning authority companion'); END;

-- A possibly started task Running claim blocks known task movement. Unknown is
-- intentionally exempt so the specialized truthful uncertainty path survives.
CREATE TRIGGER agent_events_v19_unobserved_running_claim_phase_fence
BEFORE INSERT ON agent_events
WHEN json_type(CAST(NEW.event_json AS TEXT), '$.payload.TaskStateChanged') = 'object'
 AND json_extract(CAST(NEW.event_json AS TEXT), '$.payload.TaskStateChanged.to') != 'Unknown'
 AND EXISTS (
    SELECT 1
    FROM runner_effect_dispatch_claims claim
    JOIN runner_effect_dispatch_claim_authorities authority
      ON authority.dispatch_claim_id = claim.dispatch_claim_id
     AND authority.authority_class = 'TaskRunning'
    JOIN effect_intents intent ON intent.effect_id = claim.effect_id
    LEFT JOIN effect_observations observation ON observation.effect_id = claim.effect_id
    WHERE claim.sprint_id = NEW.sprint_id
      AND intent.task_id = json_extract(CAST(NEW.event_json AS TEXT), '$.task_id')
      AND observation.effect_id IS NULL
 )
BEGIN SELECT RAISE(ABORT, 'unobserved TaskRunning claim blocks known task phase transition'); END;
