//! Schema-v14 worker-lease authority migration and durable projections.

use rusqlite::{Connection, OptionalExtension, Transaction, params};

use crate::{AgentEvent, AgentEventKind, PathScope, WorkerLease};

use super::{
    LedgerError, decode_stored, encode, load_event_by_id, load_sprint_inputs,
    load_sprint_inputs_for_recovery, reference_mismatch, sqlite_integer, unsigned_integer,
};

pub(super) const MIGRATION_V14: &str = r"
CREATE TABLE worker_lease_legacy_sprints (
    sprint_id TEXT PRIMARY KEY NOT NULL,
    reason TEXT NOT NULL CHECK (length(reason) > 0),
    FOREIGN KEY (sprint_id) REFERENCES sprints(sprint_id) ON DELETE RESTRICT
) STRICT, WITHOUT ROWID;

INSERT OR IGNORE INTO worker_lease_legacy_sprints (sprint_id, reason)
SELECT sprint_id, 'pre-v14 task-worker authority has no durable lease join'
FROM runner_launch_intents WHERE purpose = 'TaskWorker';
INSERT OR IGNORE INTO worker_lease_legacy_sprints (sprint_id, reason)
SELECT sprint_id, 'pre-v14 task-scoped effect has no durable lease join'
FROM effect_intents WHERE task_id IS NOT NULL;
INSERT OR IGNORE INTO worker_lease_legacy_sprints (sprint_id, reason)
SELECT sprint_id, 'pre-v14 task integration has no durable lease join'
FROM task_integration_receipts;

CREATE TABLE worker_lease_acquisitions (
    lease_id TEXT PRIMARY KEY NOT NULL,
    sprint_id TEXT NOT NULL,
    workspace_root TEXT NOT NULL CHECK (length(workspace_root) > 0),
    lease_epoch INTEGER NOT NULL CHECK (lease_epoch > 0),
    task_id TEXT NOT NULL,
    worker_id TEXT NOT NULL,
    acquired_at_unix_ms INTEGER NOT NULL CHECK (acquired_at_unix_ms > 0),
    acquisition_event_id TEXT NOT NULL UNIQUE,
    contract_version INTEGER NOT NULL CHECK (contract_version > 0),
    path_scopes_json BLOB NOT NULL CHECK (length(path_scopes_json) > 0),
    lease_json BLOB NOT NULL CHECK (length(lease_json) > 0),
    UNIQUE (sprint_id, lease_epoch),
    UNIQUE (sprint_id, lease_id),
    FOREIGN KEY (sprint_id) REFERENCES sprints(sprint_id) ON DELETE RESTRICT,
    FOREIGN KEY (acquisition_event_id) REFERENCES agent_events(event_id)
        ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED
) STRICT, WITHOUT ROWID;

CREATE TABLE worker_lease_releases (
    lease_id TEXT PRIMARY KEY NOT NULL,
    sprint_id TEXT NOT NULL,
    lease_epoch INTEGER NOT NULL CHECK (lease_epoch > 0),
    cleanup_receipt_id TEXT NOT NULL UNIQUE,
    cleanup_effect_id TEXT NOT NULL UNIQUE,
    cleanup_observation_id TEXT NOT NULL UNIQUE,
    released_at_unix_ms INTEGER NOT NULL CHECK (released_at_unix_ms > 0),
    contract_version INTEGER NOT NULL CHECK (contract_version > 0),
    UNIQUE (sprint_id, lease_epoch),
    FOREIGN KEY (lease_id) REFERENCES worker_lease_acquisitions(lease_id) ON DELETE RESTRICT,
    FOREIGN KEY (cleanup_receipt_id) REFERENCES worker_cleanup_receipts(receipt_id)
        ON DELETE RESTRICT,
    FOREIGN KEY (cleanup_effect_id) REFERENCES effect_intents(effect_id) ON DELETE RESTRICT,
    FOREIGN KEY (cleanup_observation_id) REFERENCES effect_observations(observation_id)
        ON DELETE RESTRICT
) STRICT, WITHOUT ROWID;

ALTER TABLE runner_launch_intents ADD COLUMN worker_lease_id TEXT
    REFERENCES worker_lease_acquisitions(lease_id) ON DELETE RESTRICT;
ALTER TABLE runner_launch_intents ADD COLUMN worker_lease_epoch INTEGER
    CHECK (worker_lease_epoch IS NULL OR worker_lease_epoch > 0);
ALTER TABLE runner_session_policies ADD COLUMN worker_lease_id TEXT
    REFERENCES worker_lease_acquisitions(lease_id) ON DELETE RESTRICT;
ALTER TABLE runner_session_policies ADD COLUMN worker_lease_epoch INTEGER
    CHECK (worker_lease_epoch IS NULL OR worker_lease_epoch > 0);
ALTER TABLE effect_intents ADD COLUMN worker_lease_id TEXT
    REFERENCES worker_lease_acquisitions(lease_id) ON DELETE RESTRICT;
ALTER TABLE effect_intents ADD COLUMN worker_lease_epoch INTEGER
    CHECK (worker_lease_epoch IS NULL OR worker_lease_epoch > 0);
ALTER TABLE effect_observations ADD COLUMN worker_lease_id TEXT
    REFERENCES worker_lease_acquisitions(lease_id) ON DELETE RESTRICT;
ALTER TABLE effect_observations ADD COLUMN worker_lease_epoch INTEGER
    CHECK (worker_lease_epoch IS NULL OR worker_lease_epoch > 0);
ALTER TABLE task_integration_receipts ADD COLUMN worker_lease_id TEXT
    REFERENCES worker_lease_acquisitions(lease_id) ON DELETE RESTRICT;
ALTER TABLE task_integration_receipts ADD COLUMN worker_lease_epoch INTEGER
    CHECK (worker_lease_epoch IS NULL OR worker_lease_epoch > 0);
ALTER TABLE worker_cleanup_receipts ADD COLUMN worker_lease_id TEXT
    REFERENCES worker_lease_acquisitions(lease_id) ON DELETE RESTRICT;
ALTER TABLE worker_cleanup_receipts ADD COLUMN worker_lease_epoch INTEGER
    CHECK (worker_lease_epoch IS NULL OR worker_lease_epoch > 0);

CREATE INDEX runner_launch_worker_lease_idx
ON runner_launch_intents (sprint_id, worker_lease_id, worker_lease_epoch);
CREATE UNIQUE INDEX runner_launch_one_per_worker_lease
ON runner_launch_intents (worker_lease_id) WHERE worker_lease_id IS NOT NULL;
CREATE INDEX runner_session_worker_lease_idx
ON runner_session_policies (sprint_id, worker_lease_id, worker_lease_epoch);
CREATE INDEX effect_intent_worker_lease_idx
ON effect_intents (sprint_id, worker_lease_id, worker_lease_epoch);
CREATE INDEX effect_observation_worker_lease_idx
ON effect_observations (sprint_id, worker_lease_id, worker_lease_epoch);
CREATE INDEX task_integration_worker_lease_idx
ON task_integration_receipts (sprint_id, worker_lease_id, worker_lease_epoch);
CREATE INDEX worker_cleanup_worker_lease_idx
ON worker_cleanup_receipts (sprint_id, worker_lease_id, worker_lease_epoch);

CREATE VIEW active_worker_leases AS
SELECT acquisition.*
FROM worker_lease_acquisitions acquisition
LEFT JOIN worker_lease_releases release ON release.lease_id = acquisition.lease_id
WHERE release.lease_id IS NULL;

CREATE TRIGGER worker_lease_legacy_sprints_no_update
BEFORE UPDATE ON worker_lease_legacy_sprints
BEGIN SELECT RAISE(ABORT, 'legacy worker-lease classifications are immutable'); END;
CREATE TRIGGER worker_lease_legacy_sprints_no_delete
BEFORE DELETE ON worker_lease_legacy_sprints
BEGIN SELECT RAISE(ABORT, 'legacy worker-lease classifications are immutable'); END;
CREATE TRIGGER worker_lease_legacy_sprints_no_insert
BEFORE INSERT ON worker_lease_legacy_sprints
BEGIN SELECT RAISE(ABORT, 'legacy worker-lease classifications are migration-only'); END;
CREATE TRIGGER worker_lease_acquisitions_no_update
BEFORE UPDATE ON worker_lease_acquisitions
BEGIN SELECT RAISE(ABORT, 'worker lease acquisitions are immutable'); END;
CREATE TRIGGER worker_lease_acquisitions_no_delete
BEFORE DELETE ON worker_lease_acquisitions
BEGIN SELECT RAISE(ABORT, 'worker lease acquisitions are immutable'); END;
CREATE TRIGGER worker_lease_releases_no_update
BEFORE UPDATE ON worker_lease_releases
BEGIN SELECT RAISE(ABORT, 'worker lease releases are immutable'); END;
CREATE TRIGGER worker_lease_releases_no_delete
BEFORE DELETE ON worker_lease_releases
BEGIN SELECT RAISE(ABORT, 'worker lease releases are immutable'); END;

CREATE TRIGGER worker_lease_acquisitions_validate
BEFORE INSERT ON worker_lease_acquisitions
WHEN EXISTS (
        SELECT 1 FROM worker_lease_legacy_sprints legacy
        WHERE legacy.sprint_id = NEW.sprint_id
    )
 OR NEW.lease_epoch != COALESCE((
        SELECT MAX(existing.lease_epoch) + 1
        FROM worker_lease_acquisitions existing
        WHERE existing.sprint_id = NEW.sprint_id
    ), 1)
 OR NEW.workspace_root != COALESCE((
        SELECT json_extract(
            CAST(sprint.spec_json AS TEXT),
            '$.workspace_grant.canonical_root'
        )
        FROM sprints sprint WHERE sprint.sprint_id = NEW.sprint_id
    ), '')
 OR (SELECT COUNT(*) FROM active_worker_leases active
     WHERE active.sprint_id = NEW.sprint_id) >= COALESCE((
        SELECT CAST(json_extract(
            CAST(sprint.spec_json AS TEXT), '$.max_workers'
        ) AS INTEGER)
        FROM sprints sprint WHERE sprint.sprint_id = NEW.sprint_id
    ), 0)
 OR EXISTS (
        SELECT 1 FROM active_worker_leases active
        WHERE active.sprint_id = NEW.sprint_id
          AND (active.task_id = NEW.task_id OR active.worker_id = NEW.worker_id)
    )
 OR COALESCE((
        SELECT json_extract(CAST(event_json AS TEXT), '$.payload.TaskStateChanged.to')
        FROM agent_events event
        WHERE event.sprint_id = NEW.sprint_id
          AND json_extract(CAST(event.event_json AS TEXT), '$.task_id') = NEW.task_id
          AND json_type(CAST(event.event_json AS TEXT), '$.payload.TaskStateChanged') = 'object'
        ORDER BY event.sequence DESC LIMIT 1
    ), '') != 'Ready'
 OR json_valid(CAST(NEW.lease_json AS TEXT)) = 0
 OR json_valid(CAST(NEW.path_scopes_json AS TEXT)) = 0
 OR json_type(CAST(NEW.path_scopes_json AS TEXT)) != 'array'
 OR json_array_length(CAST(NEW.path_scopes_json AS TEXT)) = 0
 OR EXISTS (
      SELECT 1 FROM json_each(CAST(NEW.path_scopes_json AS TEXT)) scope
      WHERE NOT (
          (scope.type = 'text' AND scope.atom = 'Workspace')
          OR (
              scope.type = 'object'
              AND json_type(scope.value, '$.Relative') = 'text'
              AND (SELECT COUNT(*) FROM json_each(scope.value)) = 1
          )
      )
    )
 OR json_extract(CAST(NEW.lease_json AS TEXT), '$.lease_id') IS NOT NEW.lease_id
 OR json_extract(CAST(NEW.lease_json AS TEXT), '$.sprint_id') IS NOT NEW.sprint_id
 OR json_extract(CAST(NEW.lease_json AS TEXT), '$.lease_epoch') IS NOT NEW.lease_epoch
 OR json_extract(CAST(NEW.lease_json AS TEXT), '$.task_id') IS NOT NEW.task_id
 OR json_extract(CAST(NEW.lease_json AS TEXT), '$.worker_id') IS NOT NEW.worker_id
 OR json_extract(CAST(NEW.lease_json AS TEXT), '$.acquired_at_unix_ms')
       IS NOT NEW.acquired_at_unix_ms
 OR json_extract(CAST(NEW.lease_json AS TEXT), '$.contract_version')
       IS NOT NEW.contract_version
 OR json(json_extract(CAST(NEW.lease_json AS TEXT), '$.path_scopes'))
       IS NOT json(CAST(NEW.path_scopes_json AS TEXT))
 OR json(CAST(NEW.path_scopes_json AS TEXT)) IS NOT COALESCE((
      SELECT json(json_extract(task.value, '$.path_scopes'))
      FROM sprint_task_graphs graph,
           json_each(CAST(graph.graph_json AS TEXT), '$.tasks') task
      WHERE graph.sprint_id = NEW.sprint_id
        AND json_extract(task.value, '$.task_id') = NEW.task_id
    ), '')
BEGIN SELECT RAISE(ABORT, 'invalid, stale, legacy, or duplicate worker lease acquisition'); END;

CREATE TRIGGER worker_lease_acquisitions_scope_exclusion
BEFORE INSERT ON worker_lease_acquisitions
WHEN EXISTS (
    SELECT 1
    FROM json_each(CAST(NEW.path_scopes_json AS TEXT)) proposed
    JOIN active_worker_leases active ON active.workspace_root = NEW.workspace_root
    JOIN json_each(CAST(active.path_scopes_json AS TEXT)) held
    WHERE (proposed.type = 'text' AND proposed.atom = 'Workspace')
       OR (held.type = 'text' AND held.atom = 'Workspace')
       OR (proposed.type = 'object'
           AND json_extract(proposed.value, '$.Relative') GLOB '*[^ -~]*')
       OR (held.type = 'object'
           AND json_extract(held.value, '$.Relative') GLOB '*[^ -~]*')
       OR (
            proposed.type = 'object' AND held.type = 'object'
        AND (
            lower(json_extract(proposed.value, '$.Relative'))
                = lower(json_extract(held.value, '$.Relative'))
         OR (
                substr(lower(json_extract(proposed.value, '$.Relative')), 1,
                       length(json_extract(held.value, '$.Relative')))
                    = lower(json_extract(held.value, '$.Relative'))
            AND substr(json_extract(proposed.value, '$.Relative'),
                       length(json_extract(held.value, '$.Relative')) + 1, 1) = '/'
            )
         OR (
                substr(lower(json_extract(held.value, '$.Relative')), 1,
                       length(json_extract(proposed.value, '$.Relative')))
                    = lower(json_extract(proposed.value, '$.Relative'))
            AND substr(json_extract(held.value, '$.Relative'),
                       length(json_extract(proposed.value, '$.Relative')) + 1, 1) = '/'
            )
        )
       )
)
BEGIN SELECT RAISE(ABORT, 'worker lease path scope conflicts with an active lease'); END;

CREATE TRIGGER agent_events_validate_task_transition
BEFORE INSERT ON agent_events
WHEN json_type(CAST(NEW.event_json AS TEXT), '$.payload.TaskStateChanged') = 'object'
 AND (
    json_type(CAST(NEW.event_json AS TEXT), '$.task_id') IS NOT 'text'
    OR json_type(CAST(NEW.event_json AS TEXT), '$.payload.TaskStateChanged.from') IS NOT 'text'
    OR json_type(CAST(NEW.event_json AS TEXT), '$.payload.TaskStateChanged.to') IS NOT 'text'
    OR NOT EXISTS (
        SELECT 1
        FROM sprint_task_graphs graph,
             json_each(CAST(graph.graph_json AS TEXT), '$.tasks') task
        WHERE graph.sprint_id = NEW.sprint_id
          AND json_extract(task.value, '$.task_id') =
              json_extract(CAST(NEW.event_json AS TEXT), '$.task_id')
    )
    OR json_extract(CAST(NEW.event_json AS TEXT), '$.payload.TaskStateChanged.from')
       IS NOT COALESCE((
          SELECT json_extract(CAST(event.event_json AS TEXT),
                              '$.payload.TaskStateChanged.to')
          FROM agent_events event
          WHERE event.sprint_id = NEW.sprint_id
            AND json_extract(CAST(event.event_json AS TEXT), '$.task_id') =
                json_extract(CAST(NEW.event_json AS TEXT), '$.task_id')
            AND json_type(CAST(event.event_json AS TEXT),
                          '$.payload.TaskStateChanged') = 'object'
          ORDER BY event.sequence DESC LIMIT 1
       ), 'Planned')
    OR NOT (
        (json_extract(CAST(NEW.event_json AS TEXT), '$.payload.TaskStateChanged.from')
             IN ('Planned', 'Leased')
         AND json_extract(CAST(NEW.event_json AS TEXT), '$.payload.TaskStateChanged.to') = 'Ready')
        OR (json_extract(CAST(NEW.event_json AS TEXT), '$.payload.TaskStateChanged.from') = 'Ready'
            AND json_extract(CAST(NEW.event_json AS TEXT), '$.payload.TaskStateChanged.to') = 'Leased')
        OR (json_extract(CAST(NEW.event_json AS TEXT), '$.payload.TaskStateChanged.from')
                IN ('Leased', 'Verifying', 'Candidate')
            AND json_extract(CAST(NEW.event_json AS TEXT), '$.payload.TaskStateChanged.to') = 'Running')
        OR (json_extract(CAST(NEW.event_json AS TEXT), '$.payload.TaskStateChanged.from') = 'Running'
            AND json_extract(CAST(NEW.event_json AS TEXT), '$.payload.TaskStateChanged.to') = 'Verifying')
        OR (json_extract(CAST(NEW.event_json AS TEXT), '$.payload.TaskStateChanged.from') = 'Verifying'
            AND json_extract(CAST(NEW.event_json AS TEXT), '$.payload.TaskStateChanged.to') = 'Candidate')
        OR (json_extract(CAST(NEW.event_json AS TEXT), '$.payload.TaskStateChanged.from') = 'Candidate'
            AND json_extract(CAST(NEW.event_json AS TEXT), '$.payload.TaskStateChanged.to') = 'Integrated')
        OR (
            json_extract(CAST(NEW.event_json AS TEXT), '$.payload.TaskStateChanged.from')
                IN ('Planned', 'Ready', 'Leased', 'Running', 'Verifying', 'Candidate')
            AND json_extract(CAST(NEW.event_json AS TEXT), '$.payload.TaskStateChanged.to')
                IN ('Blocked', 'Failed', 'Canceled', 'Unknown')
        )
    )
    OR (
       json_extract(CAST(NEW.event_json AS TEXT), '$.payload.TaskStateChanged.to') = 'Ready'
       AND EXISTS (
          SELECT 1 FROM active_worker_leases active
          WHERE active.sprint_id = NEW.sprint_id
            AND active.task_id =
                json_extract(CAST(NEW.event_json AS TEXT), '$.task_id')
       )
    )
    OR (
       json_extract(CAST(NEW.event_json AS TEXT), '$.payload.TaskStateChanged.to') = 'Ready'
       AND EXISTS (
          SELECT 1
          FROM sprint_task_graphs graph,
               json_each(CAST(graph.graph_json AS TEXT), '$.tasks') task,
               json_each(task.value, '$.dependencies') dependency
          WHERE graph.sprint_id = NEW.sprint_id
            AND json_extract(task.value, '$.task_id') =
                json_extract(CAST(NEW.event_json AS TEXT), '$.task_id')
            AND COALESCE((
                SELECT json_extract(CAST(event.event_json AS TEXT),
                                    '$.payload.TaskStateChanged.to')
                FROM agent_events event
                WHERE event.sprint_id = NEW.sprint_id
                  AND json_extract(CAST(event.event_json AS TEXT), '$.task_id') = dependency.value
                  AND json_type(CAST(event.event_json AS TEXT),
                                '$.payload.TaskStateChanged') = 'object'
                ORDER BY event.sequence DESC LIMIT 1
            ), 'Planned') != 'Integrated'
       )
    )
 )
BEGIN SELECT RAISE(ABORT, 'invalid, stale, or dependency-unready task transition'); END;

CREATE TRIGGER agent_events_known_terminal_requires_no_active_lease
BEFORE INSERT ON agent_events
WHEN json_extract(CAST(NEW.event_json AS TEXT), '$.payload.TaskStateChanged.to')
       IN ('Blocked', 'Failed', 'Canceled')
 AND EXISTS (
    SELECT 1 FROM active_worker_leases active
    WHERE active.sprint_id = NEW.sprint_id
      AND active.task_id = json_extract(CAST(NEW.event_json AS TEXT), '$.task_id')
 )
BEGIN SELECT RAISE(ABORT, 'known terminal task transition requires the task lease to be released'); END;

CREATE TRIGGER agent_events_require_worker_lease_acquisition
AFTER INSERT ON agent_events
WHEN json_extract(CAST(NEW.event_json AS TEXT), '$.payload.TaskStateChanged.from') = 'Ready'
 AND json_extract(CAST(NEW.event_json AS TEXT), '$.payload.TaskStateChanged.to') = 'Leased'
 AND NOT EXISTS (
    SELECT 1 FROM worker_lease_acquisitions acquisition
    WHERE acquisition.acquisition_event_id = NEW.event_id
      AND acquisition.sprint_id = NEW.sprint_id
      AND acquisition.task_id = json_extract(CAST(NEW.event_json AS TEXT), '$.task_id')
      AND acquisition.worker_id = json_extract(CAST(NEW.event_json AS TEXT), '$.worker_id')
      AND acquisition.acquired_at_unix_ms = NEW.occurred_at_unix_ms
 )
BEGIN SELECT RAISE(ABORT, 'Ready-to-Leased event requires exact atomic lease acquisition'); END;

CREATE TRIGGER worker_lease_bound_runner_launch
BEFORE INSERT ON runner_launch_intents
WHEN json_type(CAST(NEW.intent_json AS TEXT), '$.worker_lease') IS NULL
 OR (NEW.purpose = 'TaskWorker') != (NEW.worker_lease_id IS NOT NULL)
 OR (NEW.worker_lease_id IS NULL) != (NEW.worker_lease_epoch IS NULL)
 OR (NEW.worker_lease_id IS NOT NULL AND NOT EXISTS (
    SELECT 1 FROM active_worker_leases lease
    WHERE lease.lease_id = NEW.worker_lease_id
      AND lease.sprint_id = NEW.sprint_id
      AND lease.lease_epoch = NEW.worker_lease_epoch
      AND lease.worker_id = NEW.worker_id
 ))
 OR COALESCE(json_extract(CAST(NEW.intent_json AS TEXT), '$.worker_lease.lease_id'), '')
      != COALESCE(NEW.worker_lease_id, '')
 OR COALESCE(json_extract(CAST(NEW.intent_json AS TEXT), '$.worker_lease.lease_epoch'), 0)
      != COALESCE(NEW.worker_lease_epoch, 0)
BEGIN SELECT RAISE(ABORT, 'runner launch lacks its exact active worker lease'); END;

CREATE TRIGGER worker_lease_bound_runner_session
BEFORE INSERT ON runner_session_policies
WHEN json_type(CAST(NEW.record_json AS TEXT), '$.worker_lease') IS NULL
 OR (NEW.purpose = 'TaskWorker') != (NEW.worker_lease_id IS NOT NULL)
 OR (NEW.worker_lease_id IS NULL) != (NEW.worker_lease_epoch IS NULL)
 OR COALESCE(NEW.worker_lease_id, '') != COALESCE((
      SELECT launch.worker_lease_id FROM runner_launch_intents launch
      WHERE launch.launch_id = NEW.launch_id
    ), '')
 OR COALESCE(NEW.worker_lease_epoch, 0) != COALESCE((
      SELECT launch.worker_lease_epoch FROM runner_launch_intents launch
      WHERE launch.launch_id = NEW.launch_id
    ), 0)
 OR COALESCE(json_extract(CAST(NEW.record_json AS TEXT), '$.worker_lease.lease_id'), '')
      != COALESCE(NEW.worker_lease_id, '')
 OR COALESCE(json_extract(CAST(NEW.record_json AS TEXT), '$.worker_lease.lease_epoch'), 0)
      != COALESCE(NEW.worker_lease_epoch, 0)
 OR (NEW.worker_lease_id IS NOT NULL AND NOT EXISTS (
      SELECT 1 FROM active_worker_leases lease
      WHERE lease.lease_id = NEW.worker_lease_id
        AND lease.sprint_id = NEW.sprint_id
        AND lease.lease_epoch = NEW.worker_lease_epoch
        AND lease.worker_id = NEW.worker_id
    ))
BEGIN SELECT RAISE(ABORT, 'runner session lacks its launch active worker lease'); END;

CREATE TRIGGER worker_lease_bound_effect_intent
BEFORE INSERT ON effect_intents
WHEN json_type(CAST(NEW.intent_json AS TEXT), '$.worker_lease') IS NULL
 OR (NEW.worker_lease_id IS NULL) != (NEW.worker_lease_epoch IS NULL)
 OR (NEW.task_id IS NOT NULL AND NEW.worker_lease_id IS NULL)
 OR COALESCE(json_extract(CAST(NEW.intent_json AS TEXT), '$.worker_lease.lease_id'), '')
      != COALESCE(NEW.worker_lease_id, '')
 OR COALESCE(json_extract(CAST(NEW.intent_json AS TEXT), '$.worker_lease.lease_epoch'), 0)
      != COALESCE(NEW.worker_lease_epoch, 0)
 OR (NEW.worker_lease_id IS NOT NULL AND NOT EXISTS (
      SELECT 1 FROM active_worker_leases lease
      WHERE lease.lease_id = NEW.worker_lease_id
        AND lease.sprint_id = NEW.sprint_id
        AND lease.lease_epoch = NEW.worker_lease_epoch
        AND (NEW.task_id IS NULL OR lease.task_id = NEW.task_id)
        AND (NEW.worker_id IS NULL OR lease.worker_id = NEW.worker_id)
    ))
BEGIN SELECT RAISE(ABORT, 'effect intent lacks its exact active worker lease'); END;

CREATE TRIGGER worker_lease_bound_effect_observation
BEFORE INSERT ON effect_observations
WHEN json_type(CAST(NEW.observation_json AS TEXT), '$.worker_lease') IS NULL
 OR (NEW.worker_lease_id IS NULL) != (NEW.worker_lease_epoch IS NULL)
 OR COALESCE(NEW.worker_lease_id, '') != COALESCE((
      SELECT intent.worker_lease_id FROM effect_intents intent
      WHERE intent.effect_id = NEW.effect_id
    ), '')
 OR COALESCE(NEW.worker_lease_epoch, 0) != COALESCE((
      SELECT intent.worker_lease_epoch FROM effect_intents intent
      WHERE intent.effect_id = NEW.effect_id
    ), 0)
 OR COALESCE(json_extract(CAST(NEW.observation_json AS TEXT), '$.worker_lease.lease_id'), '')
      != COALESCE(NEW.worker_lease_id, '')
 OR COALESCE(json_extract(CAST(NEW.observation_json AS TEXT), '$.worker_lease.lease_epoch'), 0)
      != COALESCE(NEW.worker_lease_epoch, 0)
 OR (NEW.worker_lease_id IS NOT NULL AND NOT EXISTS (
      SELECT 1 FROM active_worker_leases lease
      WHERE lease.lease_id = NEW.worker_lease_id
        AND lease.sprint_id = NEW.sprint_id
        AND lease.lease_epoch = NEW.worker_lease_epoch
    ))
BEGIN SELECT RAISE(ABORT, 'effect observation lacks its exact active worker lease'); END;

CREATE TRIGGER worker_lease_bound_task_integration
BEFORE INSERT ON task_integration_receipts
WHEN json_type(CAST(NEW.receipt_json AS TEXT), '$.worker_lease') IS NULL
 OR NEW.worker_lease_id IS NULL OR NEW.worker_lease_epoch IS NULL
 OR NOT EXISTS (
      SELECT 1 FROM active_worker_leases lease
      JOIN effect_intents intent ON intent.effect_id = NEW.effect_id
      JOIN runner_launch_intents launch ON launch.launch_id = NEW.worker_launch_id
      JOIN runner_session_policies session ON session.session_id = NEW.worker_session_id
      WHERE lease.lease_id = NEW.worker_lease_id
        AND lease.sprint_id = NEW.sprint_id
        AND lease.lease_epoch = NEW.worker_lease_epoch
        AND lease.task_id = NEW.task_id
        AND lease.worker_id = NEW.worker_id
        AND intent.worker_lease_id = lease.lease_id
        AND intent.worker_lease_epoch = lease.lease_epoch
        AND launch.worker_lease_id = lease.lease_id
        AND launch.worker_lease_epoch = lease.lease_epoch
        AND session.worker_lease_id = lease.lease_id
        AND session.worker_lease_epoch = lease.lease_epoch
    )
 OR json_extract(CAST(NEW.receipt_json AS TEXT), '$.worker_lease.lease_id') != NEW.worker_lease_id
 OR json_extract(CAST(NEW.receipt_json AS TEXT), '$.worker_lease.lease_epoch') != NEW.worker_lease_epoch
BEGIN SELECT RAISE(ABORT, 'task integration lacks its exact active worker lease chain'); END;

CREATE TRIGGER worker_lease_bound_cleanup_receipt
BEFORE INSERT ON worker_cleanup_receipts
WHEN json_type(CAST(NEW.receipt_json AS TEXT), '$.worker_lease') IS NULL
 OR (NEW.worker_lease_id IS NULL) != (NEW.worker_lease_epoch IS NULL)
 OR COALESCE(NEW.worker_lease_id, '') != COALESCE((
      SELECT launch.worker_lease_id FROM runner_launch_intents launch
      WHERE launch.launch_id = NEW.launch_id
    ), '')
 OR COALESCE(NEW.worker_lease_epoch, 0) != COALESCE((
      SELECT launch.worker_lease_epoch FROM runner_launch_intents launch
      WHERE launch.launch_id = NEW.launch_id
    ), 0)
 OR COALESCE(NEW.worker_lease_id, '') != COALESCE((
      SELECT intent.worker_lease_id FROM effect_intents intent
      WHERE intent.effect_id = NEW.effect_id
    ), '')
 OR COALESCE(NEW.worker_lease_epoch, 0) != COALESCE((
      SELECT intent.worker_lease_epoch FROM effect_intents intent
      WHERE intent.effect_id = NEW.effect_id
    ), 0)
 OR COALESCE(json_extract(CAST(NEW.receipt_json AS TEXT), '$.worker_lease.lease_id'), '')
      != COALESCE(NEW.worker_lease_id, '')
 OR COALESCE(json_extract(CAST(NEW.receipt_json AS TEXT), '$.worker_lease.lease_epoch'), 0)
      != COALESCE(NEW.worker_lease_epoch, 0)
 OR (NEW.worker_lease_id IS NOT NULL AND NOT EXISTS (
      SELECT 1 FROM active_worker_leases lease
      WHERE lease.lease_id = NEW.worker_lease_id
        AND lease.sprint_id = NEW.sprint_id
        AND lease.lease_epoch = NEW.worker_lease_epoch
    ))
BEGIN SELECT RAISE(ABORT, 'cleanup receipt lacks its exact active worker lease'); END;

CREATE TRIGGER worker_lease_release_requires_cleanup
BEFORE INSERT ON worker_lease_releases
WHEN NOT EXISTS (
    SELECT 1
    FROM active_worker_leases lease
    JOIN worker_cleanup_receipts cleanup ON cleanup.receipt_id = NEW.cleanup_receipt_id
    WHERE lease.lease_id = NEW.lease_id
      AND lease.sprint_id = NEW.sprint_id
      AND lease.lease_epoch = NEW.lease_epoch
      AND cleanup.sprint_id = NEW.sprint_id
      AND cleanup.worker_lease_id = NEW.lease_id
      AND cleanup.worker_lease_epoch = NEW.lease_epoch
      AND cleanup.effect_id = NEW.cleanup_effect_id
      AND cleanup.observation_id = NEW.cleanup_observation_id
      AND cleanup.cleaned_at_unix_ms = NEW.released_at_unix_ms
      AND cleanup.surviving_processes = 0
 )
BEGIN SELECT RAISE(ABORT, 'worker lease release requires exact zero-survivor cleanup proof'); END;

CREATE TRIGGER worker_lease_release_requires_terminal_effects
BEFORE INSERT ON worker_lease_releases
WHEN EXISTS (
    SELECT 1
    FROM effect_intents intent
    LEFT JOIN effect_observations observation ON observation.effect_id = intent.effect_id
    WHERE intent.sprint_id = NEW.sprint_id
      AND intent.worker_lease_id = NEW.lease_id
      AND intent.worker_lease_epoch = NEW.lease_epoch
      AND observation.effect_id IS NULL
)
BEGIN SELECT RAISE(ABORT, 'worker lease release requires every lease-bound effect to be terminal'); END;

CREATE TRIGGER worker_lease_completion_requires_no_active
BEFORE INSERT ON sprint_completion_proof_states
WHEN NEW.proof_state = 'ProvenV9' AND EXISTS (
    SELECT 1 FROM active_worker_leases active
    WHERE active.sprint_id = NEW.sprint_id
)
BEGIN SELECT RAISE(ABORT, 'successful completion requires zero active worker leases'); END;

CREATE TRIGGER worker_lease_known_terminal_requires_no_active
BEFORE INSERT ON sprint_non_success_terminal_outcomes
WHEN NEW.terminal_state IN ('Blocked', 'Failed', 'Canceled')
 AND EXISTS (
    SELECT 1 FROM active_worker_leases active
    WHERE active.sprint_id = NEW.sprint_id
 )
BEGIN SELECT RAISE(ABORT, 'known terminal outcome requires zero active worker leases'); END;
";

pub(super) fn schema_is_installed(connection: &Connection) -> Result<bool, LedgerError> {
    Ok(connection
        .query_row(
            "SELECT 1 FROM sqlite_schema
             WHERE type = 'table' AND name = 'worker_lease_acquisitions'",
            [],
            |_| Ok(()),
        )
        .optional()?
        .is_some())
}

pub(super) fn is_legacy_sprint(
    connection: &Connection,
    sprint_id: &str,
) -> Result<bool, LedgerError> {
    Ok(connection
        .query_row(
            "SELECT 1 FROM worker_lease_legacy_sprints WHERE sprint_id = ?1",
            [sprint_id],
            |_| Ok(()),
        )
        .optional()?
        .is_some())
}

pub(super) fn reject_legacy_sprint(
    connection: &Connection,
    sprint_id: &str,
) -> Result<(), LedgerError> {
    if is_legacy_sprint(connection, sprint_id)? {
        Err(LedgerError::LegacyWorkerLeaseUnproven(sprint_id.to_owned()))
    } else {
        Ok(())
    }
}

pub(super) fn next_epoch(connection: &Connection, sprint_id: &str) -> Result<u64, LedgerError> {
    reject_legacy_sprint(connection, sprint_id)?;
    let maximum: Option<i64> = connection.query_row(
        "SELECT MAX(lease_epoch) FROM worker_lease_acquisitions WHERE sprint_id = ?1",
        [sprint_id],
        |row| row.get(0),
    )?;
    match maximum {
        Some(value) => unsigned_integer("worker_lease.next_epoch", value)?
            .checked_add(1)
            .ok_or(LedgerError::IntegerOutOfRange("worker_lease.next_epoch")),
        None => Ok(1),
    }
}

pub(super) fn insert_acquisition(
    transaction: &Transaction<'_>,
    lease: &WorkerLease,
    event: &AgentEvent,
) -> Result<(), LedgerError> {
    let (spec, _, _) = load_sprint_inputs(transaction, &lease.sprint_id)?;
    let workspace_root = spec
        .workspace_grant
        .canonical_root
        .to_str()
        .ok_or_else(|| reference_mismatch("worker lease", "workspace root is not UTF-8"))?;
    transaction.execute(
        "INSERT INTO worker_lease_acquisitions (
            lease_id, sprint_id, workspace_root, lease_epoch, task_id, worker_id,
            acquired_at_unix_ms, acquisition_event_id, contract_version,
            path_scopes_json, lease_json
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
        params![
            lease.lease_id,
            lease.sprint_id,
            workspace_root,
            sqlite_integer("worker_lease.lease_epoch", lease.lease_epoch)?,
            lease.task_id,
            lease.worker_id,
            sqlite_integer(
                "worker_lease.acquired_at_unix_ms",
                lease.acquired_at_unix_ms,
            )?,
            event.event_id,
            i64::from(lease.contract_version),
            encode("worker lease scopes", &lease.path_scopes)?,
            encode("worker lease", lease)?,
        ],
    )?;
    Ok(())
}

pub(super) fn load(
    connection: &Connection,
    lease_id: &str,
    require_active: bool,
) -> Result<WorkerLease, LedgerError> {
    load_inner(connection, lease_id, require_active, false)
}

pub(super) fn load_for_recovery(
    connection: &Connection,
    lease_id: &str,
    require_active: bool,
) -> Result<WorkerLease, LedgerError> {
    load_inner(connection, lease_id, require_active, true)
}

struct StoredWorkerLease {
    sprint_id: String,
    workspace_root: String,
    lease_epoch: i64,
    task_id: String,
    worker_id: String,
    acquired_at_unix_ms: i64,
    acquisition_event_id: String,
    contract_version: i64,
    path_scopes_json: Vec<u8>,
    lease_json: Vec<u8>,
    released: bool,
}

fn load_inner(
    connection: &Connection,
    lease_id: &str,
    require_active: bool,
    recovery_read: bool,
) -> Result<WorkerLease, LedgerError> {
    let stored = load_stored(connection, lease_id)?;
    if require_active && stored.released {
        return Err(reference_mismatch(
            "worker lease",
            "the exact lease has already been released",
        ));
    }
    reject_legacy_sprint(connection, &stored.sprint_id)?;
    let lease: WorkerLease = decode_stored("worker lease", &stored.lease_json)?;
    let path_scopes: Vec<PathScope> =
        decode_stored("worker lease scopes", &stored.path_scopes_json)?;
    validate_stored_lease(lease_id, &stored, &lease, &path_scopes)?;
    validate_acquisition_event(connection, &stored, &lease)?;
    validate_sprint_scope(connection, &stored, &lease, recovery_read)?;
    Ok(lease)
}

fn load_stored(connection: &Connection, lease_id: &str) -> Result<StoredWorkerLease, LedgerError> {
    connection
        .query_row(
            "SELECT sprint_id, workspace_root, lease_epoch, task_id, worker_id,
                    acquired_at_unix_ms, acquisition_event_id,
                    contract_version, path_scopes_json, lease_json,
                    EXISTS (SELECT 1 FROM worker_lease_releases release
                            WHERE release.lease_id = worker_lease_acquisitions.lease_id)
             FROM worker_lease_acquisitions WHERE lease_id = ?1",
            [lease_id],
            |row| {
                Ok(StoredWorkerLease {
                    sprint_id: row.get(0)?,
                    workspace_root: row.get(1)?,
                    lease_epoch: row.get(2)?,
                    task_id: row.get(3)?,
                    worker_id: row.get(4)?,
                    acquired_at_unix_ms: row.get(5)?,
                    acquisition_event_id: row.get(6)?,
                    contract_version: row.get(7)?,
                    path_scopes_json: row.get(8)?,
                    lease_json: row.get(9)?,
                    released: row.get(10)?,
                })
            },
        )
        .optional()?
        .ok_or_else(|| LedgerError::ArtifactNotFound {
            entity: "worker lease",
            id: lease_id.to_owned(),
        })
}

fn validate_stored_lease(
    lease_id: &str,
    stored: &StoredWorkerLease,
    lease: &WorkerLease,
    path_scopes: &[PathScope],
) -> Result<(), LedgerError> {
    lease.validate().map_err(|error| LedgerError::Corrupt {
        entity: "worker lease",
        detail: error.to_string(),
    })?;
    if encode("worker lease", lease)? != stored.lease_json
        || encode("worker lease scopes", &lease.path_scopes)? != stored.path_scopes_json
        || lease.path_scopes != path_scopes
        || lease.lease_id != lease_id
        || lease.sprint_id != stored.sprint_id
        || lease.lease_epoch != unsigned_integer("worker_lease.lease_epoch", stored.lease_epoch)?
        || lease.task_id != stored.task_id
        || lease.worker_id != stored.worker_id
        || lease.acquired_at_unix_ms
            != unsigned_integer(
                "worker_lease.acquired_at_unix_ms",
                stored.acquired_at_unix_ms,
            )?
        || i64::from(lease.contract_version) != stored.contract_version
    {
        return Err(LedgerError::Corrupt {
            entity: "worker lease",
            detail: "canonical lease disagrees with indexed acquisition columns".into(),
        });
    }
    Ok(())
}

fn validate_acquisition_event(
    connection: &Connection,
    stored: &StoredWorkerLease,
    lease: &WorkerLease,
) -> Result<(), LedgerError> {
    let event = load_event_by_id(connection, &stored.acquisition_event_id)?;
    let event_matches = matches!(
        event.payload,
        AgentEventKind::TaskStateChanged { ref from, ref to }
            if from == "Ready" && to == "Leased"
    );
    if event.sprint_id != lease.sprint_id
        || event.task_id.as_deref() != Some(lease.task_id.as_str())
        || event.worker_id.as_deref() != Some(lease.worker_id.as_str())
        || event.occurred_at_unix_ms != lease.acquired_at_unix_ms
        || !event_matches
    {
        return Err(LedgerError::Corrupt {
            entity: "worker lease",
            detail: "acquisition event does not prove the exact Ready-to-Leased transition".into(),
        });
    }
    Ok(())
}

fn validate_sprint_scope(
    connection: &Connection,
    stored: &StoredWorkerLease,
    lease: &WorkerLease,
    recovery_read: bool,
) -> Result<(), LedgerError> {
    let (spec, graph, _) = if recovery_read {
        load_sprint_inputs_for_recovery(connection, &lease.sprint_id)?
    } else {
        load_sprint_inputs(connection, &lease.sprint_id)?
    };
    if spec.workspace_grant.canonical_root.to_str() != Some(stored.workspace_root.as_str()) {
        return Err(LedgerError::Corrupt {
            entity: "worker lease",
            detail: "lease workspace root differs from its immutable sprint grant".into(),
        });
    }
    let task = graph
        .task(&lease.task_id)
        .ok_or_else(|| LedgerError::Corrupt {
            entity: "worker lease",
            detail: "lease task is absent from its immutable graph".into(),
        })?;
    if task.path_scopes != lease.path_scopes {
        return Err(LedgerError::Corrupt {
            entity: "worker lease",
            detail: "lease scopes differ from its immutable graph task".into(),
        });
    }
    Ok(())
}

pub(super) fn require_exact(
    connection: &Connection,
    expected: &WorkerLease,
    require_active: bool,
) -> Result<(), LedgerError> {
    let stored = load(connection, &expected.lease_id, require_active)?;
    if stored == *expected {
        Ok(())
    } else {
        Err(reference_mismatch(
            "worker lease",
            "supplied lease differs from its canonical durable acquisition",
        ))
    }
}

pub(super) fn require_exact_for_recovery(
    connection: &Connection,
    expected: &WorkerLease,
    require_active: bool,
) -> Result<(), LedgerError> {
    let stored = load_for_recovery(connection, &expected.lease_id, require_active)?;
    if stored == *expected {
        Ok(())
    } else {
        Err(reference_mismatch(
            "worker lease",
            "supplied lease differs from its canonical durable acquisition",
        ))
    }
}

pub(super) fn load_active(
    connection: &Connection,
    sprint_id: &str,
) -> Result<Vec<WorkerLease>, LedgerError> {
    reject_legacy_sprint(connection, sprint_id)?;
    let mut statement = connection.prepare(
        "SELECT lease_id FROM active_worker_leases
         WHERE sprint_id = ?1 ORDER BY lease_epoch ASC",
    )?;
    let ids = statement
        .query_map([sprint_id], |row| row.get::<_, String>(0))?
        .collect::<Result<Vec<_>, _>>()?;
    ids.iter().map(|id| load(connection, id, true)).collect()
}

pub(super) fn load_workspace_blocking(
    connection: &Connection,
    sprint_id: &str,
) -> Result<Vec<WorkerLease>, LedgerError> {
    reject_legacy_sprint(connection, sprint_id)?;
    let (spec, _, _) = load_sprint_inputs(connection, sprint_id)?;
    let workspace_root = spec
        .workspace_grant
        .canonical_root
        .to_str()
        .ok_or_else(|| reference_mismatch("worker lease", "workspace root is not UTF-8"))?;
    let mut statement = connection.prepare(
        "SELECT lease_id FROM active_worker_leases
         WHERE workspace_root = ?1 AND sprint_id != ?2
         ORDER BY sprint_id ASC, lease_epoch ASC",
    )?;
    let ids = statement
        .query_map(params![workspace_root, sprint_id], |row| {
            row.get::<_, String>(0)
        })?
        .collect::<Result<Vec<_>, _>>()?;
    ids.iter().map(|id| load(connection, id, true)).collect()
}

pub(super) fn require_no_active(
    connection: &Connection,
    sprint_id: &str,
) -> Result<(), LedgerError> {
    if !schema_is_installed(connection)? {
        return Ok(());
    }
    let active = connection
        .query_row(
            "SELECT lease_id FROM active_worker_leases
             WHERE sprint_id = ?1 ORDER BY lease_epoch ASC LIMIT 1",
            [sprint_id],
            |row| row.get::<_, String>(0),
        )
        .optional()?;
    if let Some(lease_id) = active {
        Err(reference_mismatch(
            "successful completion",
            format!("active worker lease `{lease_id}` has not been released"),
        ))
    } else {
        Ok(())
    }
}

pub(super) fn insert_release(
    transaction: &Transaction<'_>,
    lease: &WorkerLease,
    receipt_id: &str,
    effect_id: &str,
    observation_id: &str,
    released_at_unix_ms: u64,
) -> Result<(), LedgerError> {
    require_exact(transaction, lease, true)?;
    let unfinished_effect = transaction
        .query_row(
            "SELECT intent.effect_id
             FROM effect_intents intent
             LEFT JOIN effect_observations observation
               ON observation.effect_id = intent.effect_id
             WHERE intent.sprint_id = ?1
               AND intent.worker_lease_id = ?2
               AND intent.worker_lease_epoch = ?3
               AND observation.effect_id IS NULL
             ORDER BY intent.effect_id ASC LIMIT 1",
            params![
                lease.sprint_id,
                lease.lease_id,
                sqlite_integer("worker_lease_release.lease_epoch", lease.lease_epoch)?,
            ],
            |row| row.get::<_, String>(0),
        )
        .optional()?;
    if let Some(effect_id) = unfinished_effect {
        return Err(reference_mismatch(
            "worker lease release",
            format!("lease-bound effect `{effect_id}` has no terminal observation"),
        ));
    }
    transaction.execute(
        "INSERT INTO worker_lease_releases (
            lease_id, sprint_id, lease_epoch, cleanup_receipt_id,
            cleanup_effect_id, cleanup_observation_id,
            released_at_unix_ms, contract_version
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
        params![
            lease.lease_id,
            lease.sprint_id,
            sqlite_integer("worker_lease_release.lease_epoch", lease.lease_epoch)?,
            receipt_id,
            effect_id,
            observation_id,
            sqlite_integer(
                "worker_lease_release.released_at_unix_ms",
                released_at_unix_ms
            )?,
            i64::from(lease.contract_version),
        ],
    )?;
    Ok(())
}

pub(super) fn require_exact_release(
    connection: &Connection,
    lease: &WorkerLease,
    receipt_id: &str,
    effect_id: &str,
    observation_id: &str,
    released_at_unix_ms: u64,
) -> Result<(), LedgerError> {
    require_exact(connection, lease, false)?;
    let stored = connection
        .query_row(
            "SELECT sprint_id, lease_epoch, cleanup_receipt_id,
                    cleanup_effect_id, cleanup_observation_id,
                    released_at_unix_ms, contract_version
             FROM worker_lease_releases WHERE lease_id = ?1",
            [&lease.lease_id],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, i64>(5)?,
                    row.get::<_, i64>(6)?,
                ))
            },
        )
        .optional()?
        .ok_or_else(|| LedgerError::Corrupt {
            entity: "worker lease release",
            detail: "worker cleanup receipt has no exact durable lease release".into(),
        })?;
    if stored.0 != lease.sprint_id
        || unsigned_integer("worker_lease_release.lease_epoch", stored.1)? != lease.lease_epoch
        || stored.2 != receipt_id
        || stored.3 != effect_id
        || stored.4 != observation_id
        || unsigned_integer("worker_lease_release.released_at_unix_ms", stored.5)?
            != released_at_unix_ms
        || stored.6 != i64::from(lease.contract_version)
    {
        return Err(LedgerError::Corrupt {
            entity: "worker lease release",
            detail: "release columns disagree with the exact cleanup evidence".into(),
        });
    }
    Ok(())
}

pub(super) fn indexed_binding_matches(
    lease: Option<&WorkerLease>,
    stored_id: Option<&str>,
    stored_epoch: Option<i64>,
) -> Result<bool, LedgerError> {
    match (lease, stored_id, stored_epoch) {
        (None, None, None) => Ok(true),
        (Some(lease), Some(stored_id), Some(stored_epoch)) => Ok(lease.lease_id == stored_id
            && lease.lease_epoch
                == unsigned_integer("worker_lease_binding.lease_epoch", stored_epoch)?),
        _ => Ok(false),
    }
}
