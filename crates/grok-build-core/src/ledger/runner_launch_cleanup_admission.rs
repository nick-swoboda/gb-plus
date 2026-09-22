//! Atomic ordinary runner launch and cleanup admission.
//!
//! A new ordinary launch is executable only after its exact cleanup effect is
//! durable in the same transaction. Pre-v13 launches remain readable, but are
//! explicitly classified and may only acquire a launch-bound cleanup effect.

use rusqlite::{Connection, OptionalExtension, Transaction, params};
use serde::{Deserialize, Serialize};

use super::{
    LedgerError, PersistedEffect, PersistedFinishReceipt, decode_stored, encode,
    load_effect_from_with_receipts, load_effect_intent_row, load_effect_request_payload,
    load_event_by_id, load_runner_launch_intent_from, load_sprint_definition_raw,
    load_workspace_snapshot_from, reference_mismatch, require_contract_version, unsigned_integer,
    validate_draft_base_snapshot, validate_effect_for_sprint_phase,
    validate_effect_proposal_event_shape, validate_finish_effect_kind,
    validate_stored_event_causation, worker_lease_authority, worker_lease_encoding_matches,
};
use crate::{
    CONTRACT_VERSION, ContractError, Digest, EffectIntent, EffectKind, EffectOutcome,
    RunnerLaunchIntent, RunnerSessionPurpose, WorkerCleanupBackend, WorkerCleanupRequest,
};

/// Schema v13 makes the ordinary pre-spawn launch and its cleanup obligation
/// one immutable authority. It does not rewrite any v1-v12 row.
pub(super) const MIGRATION_V13: &str = r"
    CREATE TABLE legacy_runner_launch_cleanup_gaps (
        launch_id TEXT PRIMARY KEY NOT NULL,
        sprint_id TEXT NOT NULL,
        session_id TEXT NOT NULL,
        gap_kind TEXT NOT NULL CHECK (gap_kind = 'PreV13Unbound'),
        contract_version INTEGER NOT NULL CHECK (contract_version > 0),
        UNIQUE (sprint_id, launch_id),
        UNIQUE (sprint_id, session_id),
        FOREIGN KEY (sprint_id, launch_id)
            REFERENCES runner_launch_intents(sprint_id, launch_id)
            ON DELETE RESTRICT
    ) STRICT, WITHOUT ROWID;

    INSERT INTO legacy_runner_launch_cleanup_gaps (
        launch_id, sprint_id, session_id, gap_kind, contract_version
    )
    SELECT launch_id, sprint_id, session_id, 'PreV13Unbound', contract_version
    FROM runner_launch_intents;

    CREATE TRIGGER legacy_runner_launch_cleanup_gaps_no_insert
    BEFORE INSERT ON legacy_runner_launch_cleanup_gaps
    BEGIN SELECT RAISE(ABORT, 'legacy runner launch cleanup gaps are migration-only'); END;
    CREATE TRIGGER legacy_runner_launch_cleanup_gaps_no_update
    BEFORE UPDATE ON legacy_runner_launch_cleanup_gaps
    BEGIN SELECT RAISE(ABORT, 'legacy runner launch cleanup gaps are immutable'); END;
    CREATE TRIGGER legacy_runner_launch_cleanup_gaps_no_delete
    BEFORE DELETE ON legacy_runner_launch_cleanup_gaps
    BEGIN SELECT RAISE(ABORT, 'legacy runner launch cleanup gaps are immutable'); END;

    CREATE TABLE runner_launch_cleanup_admissions (
        launch_id TEXT PRIMARY KEY NOT NULL,
        sprint_id TEXT NOT NULL,
        session_id TEXT NOT NULL,
        cleanup_effect_id TEXT NOT NULL UNIQUE,
        proposal_event_id TEXT NOT NULL UNIQUE,
        request_digest TEXT NOT NULL,
        platform_backend TEXT NOT NULL CHECK (
            platform_backend IN (
                'MacOsDedicatedIdentity', 'LinuxCgroupV2',
                'TrustedApplierDirectChildWait'
            )
        ),
        contract_version INTEGER NOT NULL CHECK (contract_version > 0),
        admitted_at_unix_ms INTEGER NOT NULL CHECK (admitted_at_unix_ms > 0),
        admission_json BLOB NOT NULL CHECK (
            length(admission_json) BETWEEN 1 AND 65536
        ),
        UNIQUE (sprint_id, launch_id),
        UNIQUE (sprint_id, session_id),
        UNIQUE (sprint_id, cleanup_effect_id),
        FOREIGN KEY (sprint_id, launch_id)
            REFERENCES runner_launch_intents(sprint_id, launch_id)
            ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED,
        FOREIGN KEY (sprint_id, cleanup_effect_id)
            REFERENCES effect_intents(sprint_id, effect_id)
            ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED,
        FOREIGN KEY (proposal_event_id)
            REFERENCES agent_events(event_id)
            ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED
    ) STRICT, WITHOUT ROWID;

    CREATE INDEX runner_launch_cleanup_admissions_effect_idx
    ON runner_launch_cleanup_admissions (
        sprint_id, cleanup_effect_id, request_digest
    );

    CREATE TRIGGER runner_launch_cleanup_admissions_no_existing_insert
    BEFORE INSERT ON runner_launch_cleanup_admissions
    WHEN EXISTS (
        SELECT 1 FROM runner_launch_intents WHERE launch_id = NEW.launch_id
    ) OR EXISTS (
        SELECT 1 FROM effect_intents WHERE effect_id = NEW.cleanup_effect_id
    ) OR EXISTS (
        SELECT 1 FROM legacy_runner_launch_cleanup_gaps
        WHERE launch_id = NEW.launch_id
    )
    BEGIN SELECT RAISE(ABORT, 'runner launch cleanup admission must precede its new launch and effect'); END;
    CREATE TRIGGER runner_launch_cleanup_admissions_no_update
    BEFORE UPDATE ON runner_launch_cleanup_admissions
    BEGIN SELECT RAISE(ABORT, 'runner launch cleanup admissions are immutable'); END;
    CREATE TRIGGER runner_launch_cleanup_admissions_no_delete
    BEFORE DELETE ON runner_launch_cleanup_admissions
    BEGIN SELECT RAISE(ABORT, 'runner launch cleanup admissions are immutable'); END;

    CREATE TRIGGER runner_launch_cleanup_admissions_json_matches
    BEFORE INSERT ON runner_launch_cleanup_admissions
    WHEN NOT (
        json_valid(CAST(NEW.admission_json AS TEXT))
        AND json_type(CAST(NEW.admission_json AS TEXT), '$.contract_version') = 'integer'
        AND json_type(CAST(NEW.admission_json AS TEXT), '$.sprint_id') = 'text'
        AND json_type(CAST(NEW.admission_json AS TEXT), '$.launch_id') = 'text'
        AND json_type(CAST(NEW.admission_json AS TEXT), '$.session_id') = 'text'
        AND json_type(CAST(NEW.admission_json AS TEXT), '$.cleanup_effect_id') = 'text'
        AND json_type(CAST(NEW.admission_json AS TEXT), '$.proposal_event_id') = 'text'
        AND json_type(CAST(NEW.admission_json AS TEXT), '$.request_digest') = 'text'
        AND json_type(CAST(NEW.admission_json AS TEXT), '$.platform_backend') = 'text'
        AND json_type(CAST(NEW.admission_json AS TEXT), '$.admitted_at_unix_ms') = 'integer'
        AND json_extract(CAST(NEW.admission_json AS TEXT), '$.contract_version') = NEW.contract_version
        AND json_extract(CAST(NEW.admission_json AS TEXT), '$.sprint_id') = NEW.sprint_id
        AND json_extract(CAST(NEW.admission_json AS TEXT), '$.launch_id') = NEW.launch_id
        AND json_extract(CAST(NEW.admission_json AS TEXT), '$.session_id') = NEW.session_id
        AND json_extract(CAST(NEW.admission_json AS TEXT), '$.cleanup_effect_id') = NEW.cleanup_effect_id
        AND json_extract(CAST(NEW.admission_json AS TEXT), '$.proposal_event_id') = NEW.proposal_event_id
        AND json_extract(CAST(NEW.admission_json AS TEXT), '$.request_digest') = NEW.request_digest
        AND json_extract(CAST(NEW.admission_json AS TEXT), '$.platform_backend') = NEW.platform_backend
        AND json_extract(CAST(NEW.admission_json AS TEXT), '$.admitted_at_unix_ms') = NEW.admitted_at_unix_ms
    )
    BEGIN SELECT RAISE(ABORT, 'runner launch cleanup admission JSON must match indexed authority'); END;

    CREATE TRIGGER runner_launch_intents_require_cleanup_classification
    AFTER INSERT ON runner_launch_intents
    WHEN (
        (SELECT COUNT(*) FROM runner_launch_cleanup_admissions authority
         WHERE authority.launch_id = NEW.launch_id
           AND authority.sprint_id = NEW.sprint_id
           AND authority.session_id = NEW.session_id
           AND authority.contract_version = NEW.contract_version)
        +
        (SELECT COUNT(*) FROM legacy_runner_launch_cleanup_gaps gap
         WHERE gap.launch_id = NEW.launch_id
           AND gap.sprint_id = NEW.sprint_id
           AND gap.session_id = NEW.session_id
           AND gap.contract_version = NEW.contract_version)
    ) != 1
    BEGIN SELECT RAISE(ABORT, 'ordinary runner launch requires exactly one cleanup classification'); END;

    CREATE TRIGGER runner_launch_intents_v13_identity_unique
    BEFORE INSERT ON runner_launch_intents
    WHEN NEW.launch_id = NEW.session_id OR EXISTS (
        SELECT 1 FROM runner_launch_intents existing
        WHERE existing.launch_id IN (NEW.launch_id, NEW.session_id)
           OR existing.session_id IN (NEW.launch_id, NEW.session_id)
    )
    BEGIN SELECT RAISE(ABORT, 'runner launch and session identities must be globally unique'); END;

    CREATE TRIGGER runner_session_policies_require_cleanup_admission
    AFTER INSERT ON runner_session_policies
    WHEN NOT EXISTS (
        SELECT 1
        FROM runner_launch_cleanup_admissions authority
        WHERE authority.launch_id = NEW.launch_id
          AND authority.sprint_id = NEW.sprint_id
          AND authority.session_id = NEW.session_id
          AND authority.contract_version = NEW.contract_version
          AND NOT EXISTS (
              SELECT 1 FROM effect_observations observation
              WHERE observation.effect_id = authority.cleanup_effect_id
                AND observation.sprint_id = authority.sprint_id
          )
          AND NOT EXISTS (
              SELECT 1 FROM effect_evidence_payloads evidence
              WHERE evidence.effect_id = authority.cleanup_effect_id
                AND evidence.sprint_id = authority.sprint_id
          )
          AND NOT EXISTS (
              SELECT 1 FROM worker_cleanup_receipts receipt
              WHERE receipt.effect_id = authority.cleanup_effect_id
                AND receipt.sprint_id = authority.sprint_id
          )
    )
    BEGIN SELECT RAISE(ABORT, 'new runner session requires an open authoritative launch cleanup admission'); END;

    CREATE TRIGGER effect_session_bindings_require_cleanup_classification
    AFTER INSERT ON effect_session_bindings
    WHEN (
        NEW.session_id IS NOT NULL
        AND NOT EXISTS (
            SELECT 1 FROM runner_launch_cleanup_admissions authority
            WHERE authority.launch_id = NEW.launch_id
              AND authority.sprint_id = NEW.sprint_id
              AND authority.session_id = NEW.session_id
              AND authority.contract_version = NEW.contract_version
              AND NOT EXISTS (
                  SELECT 1 FROM effect_observations observation
                  WHERE observation.effect_id = authority.cleanup_effect_id
                    AND observation.sprint_id = authority.sprint_id
              )
              AND NOT EXISTS (
                  SELECT 1 FROM effect_evidence_payloads evidence
                  WHERE evidence.effect_id = authority.cleanup_effect_id
                    AND evidence.sprint_id = authority.sprint_id
              )
              AND NOT EXISTS (
                  SELECT 1 FROM worker_cleanup_receipts receipt
                  WHERE receipt.effect_id = authority.cleanup_effect_id
                    AND receipt.sprint_id = authority.sprint_id
              )
        )
    ) OR (
        NEW.session_id IS NULL
        AND NOT EXISTS (
            SELECT 1 FROM legacy_runner_launch_cleanup_gaps gap
            WHERE gap.launch_id = NEW.launch_id
              AND gap.sprint_id = NEW.sprint_id
              AND gap.contract_version = NEW.contract_version
        )
        AND NOT EXISTS (
            SELECT 1 FROM runner_launch_cleanup_admissions authority
            WHERE authority.launch_id = NEW.launch_id
              AND authority.sprint_id = NEW.sprint_id
              AND authority.cleanup_effect_id = NEW.effect_id
              AND authority.contract_version = NEW.contract_version
        )
    )
    BEGIN SELECT RAISE(ABORT, 'effect binding requires an open exact runner launch cleanup classification'); END;

    CREATE TRIGGER effect_intents_legacy_launch_cleanup_only
    AFTER INSERT ON effect_intents
    WHEN EXISTS (
        SELECT 1
        FROM effect_session_bindings binding
        JOIN legacy_runner_launch_cleanup_gaps gap
          ON gap.launch_id = binding.launch_id
         AND gap.sprint_id = binding.sprint_id
        WHERE binding.effect_id = NEW.effect_id
          AND binding.sprint_id = NEW.sprint_id
          AND binding.session_id IS NULL
    ) AND NOT EXISTS (
        SELECT 1 FROM finish_effect_kinds kind
        WHERE kind.effect_id = NEW.effect_id
          AND kind.sprint_id = NEW.sprint_id
          AND kind.effect_kind = 'CleanupWorkerDomain'
          AND kind.contract_version = NEW.contract_version
    )
    BEGIN SELECT RAISE(ABORT, 'legacy runner launch permits only launch-bound cleanup'); END;

    CREATE TRIGGER legacy_runner_launch_cleanup_retry_lifecycle
    AFTER INSERT ON effect_session_bindings
    WHEN NEW.session_id IS NULL
      AND EXISTS (
          SELECT 1 FROM legacy_runner_launch_cleanup_gaps gap
          WHERE gap.launch_id = NEW.launch_id
            AND gap.sprint_id = NEW.sprint_id
            AND gap.contract_version = NEW.contract_version
      )
      AND EXISTS (
          SELECT 1
          FROM effect_session_bindings prior_binding
          JOIN effect_intents prior_intent
            ON prior_intent.effect_id = prior_binding.effect_id
           AND prior_intent.sprint_id = prior_binding.sprint_id
          JOIN finish_effect_kinds prior_kind
            ON prior_kind.effect_id = prior_intent.effect_id
           AND prior_kind.sprint_id = prior_intent.sprint_id
          LEFT JOIN effect_observations prior_observation
            ON prior_observation.effect_id = prior_intent.effect_id
           AND prior_observation.sprint_id = prior_intent.sprint_id
          WHERE prior_binding.launch_id = NEW.launch_id
            AND prior_binding.sprint_id = NEW.sprint_id
            AND prior_binding.effect_id != NEW.effect_id
            AND prior_kind.effect_kind = 'CleanupWorkerDomain'
            AND (
                prior_observation.effect_id IS NULL
                OR prior_observation.outcome = 'Succeeded'
            )
      )
    BEGIN SELECT RAISE(ABORT, 'legacy runner launch cleanup retry requires every prior attempt to be terminal non-success'); END;

    -- Bindings precede their deferred effect rows. Recheck when the effect is
    -- inserted so one transaction cannot stage several bindings before any of
    -- their semantic cleanup kinds are visible to the binding-time trigger.
    CREATE TRIGGER effect_intents_legacy_launch_cleanup_retry_lifecycle
    AFTER INSERT ON effect_intents
    WHEN EXISTS (
        SELECT 1
        FROM effect_session_bindings current_binding
        JOIN legacy_runner_launch_cleanup_gaps gap
          ON gap.launch_id = current_binding.launch_id
         AND gap.sprint_id = current_binding.sprint_id
        WHERE current_binding.effect_id = NEW.effect_id
          AND current_binding.sprint_id = NEW.sprint_id
          AND current_binding.session_id IS NULL
    ) AND EXISTS (
        SELECT 1
        FROM effect_session_bindings current_binding
        JOIN effect_session_bindings prior_binding
          ON prior_binding.launch_id = current_binding.launch_id
         AND prior_binding.sprint_id = current_binding.sprint_id
         AND prior_binding.effect_id != current_binding.effect_id
        JOIN effect_intents prior_intent
          ON prior_intent.effect_id = prior_binding.effect_id
         AND prior_intent.sprint_id = prior_binding.sprint_id
        JOIN finish_effect_kinds prior_kind
          ON prior_kind.effect_id = prior_intent.effect_id
         AND prior_kind.sprint_id = prior_intent.sprint_id
        LEFT JOIN effect_observations prior_observation
          ON prior_observation.effect_id = prior_intent.effect_id
         AND prior_observation.sprint_id = prior_intent.sprint_id
        WHERE current_binding.effect_id = NEW.effect_id
          AND current_binding.sprint_id = NEW.sprint_id
          AND prior_kind.effect_kind = 'CleanupWorkerDomain'
          AND (
              prior_observation.effect_id IS NULL
              OR prior_observation.outcome = 'Succeeded'
          )
    )
    BEGIN SELECT RAISE(ABORT, 'legacy runner launch cleanup retry requires every prior attempt to be terminal non-success'); END;

    CREATE TRIGGER effect_intents_reject_session_bound_launch_cleanup
    AFTER INSERT ON effect_intents
    WHEN EXISTS (
        SELECT 1
        FROM finish_effect_kinds kind
        JOIN effect_session_bindings binding
          ON binding.effect_id = kind.effect_id
         AND binding.sprint_id = kind.sprint_id
        WHERE kind.effect_id = NEW.effect_id
          AND kind.sprint_id = NEW.sprint_id
          AND kind.effect_kind = 'CleanupWorkerDomain'
          AND binding.session_id IS NOT NULL
    )
    BEGIN SELECT RAISE(ABORT, 'ordinary cleanup must use its pre-spawn launch binding'); END;

    CREATE TRIGGER effect_request_payloads_require_exact_launch_cleanup_request
    AFTER INSERT ON effect_request_payloads
    WHEN EXISTS (
        SELECT 1 FROM runner_launch_cleanup_admissions authority
        WHERE authority.cleanup_effect_id = NEW.effect_id
          AND authority.sprint_id = NEW.sprint_id
    ) AND NOT EXISTS (
        SELECT 1
        FROM runner_launch_cleanup_admissions authority
        JOIN runner_launch_intents launch
          ON launch.launch_id = authority.launch_id
         AND launch.sprint_id = authority.sprint_id
        WHERE authority.cleanup_effect_id = NEW.effect_id
          AND authority.sprint_id = NEW.sprint_id
          AND authority.request_digest = NEW.request_digest
          AND authority.contract_version = NEW.contract_version
          AND json_valid(CAST(NEW.request_bytes AS TEXT))
          AND json_type(CAST(NEW.request_bytes AS TEXT), '$.contract_version') = 'integer'
          AND json_type(CAST(NEW.request_bytes AS TEXT), '$.sprint_id') = 'text'
          AND json_type(CAST(NEW.request_bytes AS TEXT), '$.launch_id') = 'text'
          AND json_type(CAST(NEW.request_bytes AS TEXT), '$.session_id') = 'text'
          AND json_type(CAST(NEW.request_bytes AS TEXT), '$.policy_hash') = 'text'
          AND json_type(CAST(NEW.request_bytes AS TEXT), '$.grant_hash') = 'text'
          AND json_type(CAST(NEW.request_bytes AS TEXT), '$.policy_version') = 'integer'
          AND json_type(CAST(NEW.request_bytes AS TEXT), '$.platform_backend') = 'text'
          AND json_extract(CAST(NEW.request_bytes AS TEXT), '$.contract_version') = authority.contract_version
          AND json_extract(CAST(NEW.request_bytes AS TEXT), '$.sprint_id') = authority.sprint_id
          AND json_extract(CAST(NEW.request_bytes AS TEXT), '$.launch_id') = authority.launch_id
          AND json_extract(CAST(NEW.request_bytes AS TEXT), '$.session_id') = authority.session_id
          AND json_extract(CAST(NEW.request_bytes AS TEXT), '$.policy_hash') = launch.policy_hash
          AND json_extract(CAST(NEW.request_bytes AS TEXT), '$.grant_hash') = launch.grant_hash
          AND json_extract(CAST(NEW.request_bytes AS TEXT), '$.policy_version') = launch.policy_version
          AND json_extract(CAST(NEW.request_bytes AS TEXT), '$.platform_backend') = authority.platform_backend
    )
    BEGIN SELECT RAISE(ABORT, 'cleanup request JSON must match exact launch authority'); END;

    -- Schema v3 deliberately normalizes CleanupWorkerDomain storage to
    -- ApplyChangeSet. finish_effect_kinds is the semantic subtype authority;
    -- both predicates are required here and must not be collapsed into one.
    CREATE TRIGGER effect_intents_require_exact_launch_cleanup_admission
    AFTER INSERT ON effect_intents
    WHEN EXISTS (
        SELECT 1 FROM runner_launch_cleanup_admissions authority
        WHERE authority.cleanup_effect_id = NEW.effect_id
    ) AND (
        NEW.effect_kind != 'ApplyChangeSet'
        OR NEW.task_id IS NOT NULL
        OR NEW.worker_id IS NOT NULL
        OR NOT EXISTS (
            SELECT 1
            FROM runner_launch_cleanup_admissions authority
            JOIN runner_launch_intents launch
              ON launch.launch_id = authority.launch_id
             AND launch.sprint_id = authority.sprint_id
            WHERE authority.cleanup_effect_id = NEW.effect_id
              AND authority.sprint_id = NEW.sprint_id
              AND authority.session_id = launch.session_id
              AND authority.proposal_event_id = NEW.proposed_event_id
              AND authority.request_digest = NEW.request_digest
              AND authority.contract_version = NEW.contract_version
              AND authority.admitted_at_unix_ms = NEW.created_at_unix_ms
              AND NEW.policy_hash = launch.policy_hash
        )
        OR NOT EXISTS (
            SELECT 1
            FROM runner_launch_cleanup_admissions authority
            JOIN effect_session_bindings binding
              ON binding.effect_id = authority.cleanup_effect_id
             AND binding.sprint_id = authority.sprint_id
            WHERE authority.cleanup_effect_id = NEW.effect_id
              AND binding.launch_id = authority.launch_id
              AND binding.session_id IS NULL
              AND binding.contract_version = authority.contract_version
        )
        OR NOT EXISTS (
            SELECT 1
            FROM runner_launch_cleanup_admissions authority
            JOIN effect_request_payloads request
              ON request.effect_id = authority.cleanup_effect_id
             AND request.sprint_id = authority.sprint_id
            WHERE authority.cleanup_effect_id = NEW.effect_id
              AND request.request_digest = authority.request_digest
              AND request.contract_version = authority.contract_version
        )
        OR NOT EXISTS (
            SELECT 1
            FROM runner_launch_cleanup_admissions authority
            JOIN agent_events event ON event.event_id = authority.proposal_event_id
            WHERE authority.cleanup_effect_id = NEW.effect_id
              AND event.sprint_id = authority.sprint_id
              AND event.occurred_at_unix_ms = authority.admitted_at_unix_ms
              AND event.contract_version = authority.contract_version
        )
        OR NOT EXISTS (
            SELECT 1
            FROM runner_launch_cleanup_admissions authority
            JOIN finish_effect_kinds kind
              ON kind.effect_id = authority.cleanup_effect_id
             AND kind.sprint_id = authority.sprint_id
            WHERE authority.cleanup_effect_id = NEW.effect_id
              AND kind.effect_kind = 'CleanupWorkerDomain'
              AND kind.contract_version = authority.contract_version
        )
    )
    BEGIN SELECT RAISE(ABORT, 'cleanup effect must match its exact atomic launch admission'); END;

    CREATE TABLE runner_launch_preparation_attempts (
        launch_id TEXT PRIMARY KEY NOT NULL,
        sprint_id TEXT NOT NULL,
        cleanup_effect_id TEXT NOT NULL UNIQUE,
        attempt_id TEXT NOT NULL UNIQUE,
        native_journal_id TEXT NOT NULL UNIQUE CHECK (
            length(native_journal_id) BETWEEN 1 AND 512
        ),
        expected_platform_binding_digest TEXT NOT NULL,
        contract_version INTEGER NOT NULL CHECK (contract_version > 0),
        claimed_at_unix_ms INTEGER NOT NULL CHECK (claimed_at_unix_ms > 0),
        attempt_json BLOB NOT NULL CHECK (
            length(attempt_json) BETWEEN 1 AND 65536
        ),
        UNIQUE (sprint_id, launch_id),
        UNIQUE (sprint_id, cleanup_effect_id),
        FOREIGN KEY (sprint_id, launch_id)
            REFERENCES runner_launch_cleanup_admissions(sprint_id, launch_id)
            ON DELETE RESTRICT,
        FOREIGN KEY (sprint_id, cleanup_effect_id)
            REFERENCES runner_launch_cleanup_admissions(sprint_id, cleanup_effect_id)
            ON DELETE RESTRICT
    ) STRICT, WITHOUT ROWID;

    CREATE TRIGGER runner_launch_preparation_attempts_no_update
    BEFORE UPDATE ON runner_launch_preparation_attempts
    BEGIN SELECT RAISE(ABORT, 'runner launch preparation attempts are immutable'); END;
    CREATE TRIGGER runner_launch_preparation_attempts_no_delete
    BEFORE DELETE ON runner_launch_preparation_attempts
    BEGIN SELECT RAISE(ABORT, 'runner launch preparation attempts are immutable'); END;
    CREATE TRIGGER runner_launch_preparation_attempts_exact_open_admission
    BEFORE INSERT ON runner_launch_preparation_attempts
    WHEN NOT EXISTS (
        SELECT 1
        FROM runner_launch_cleanup_admissions authority
        WHERE authority.launch_id = NEW.launch_id
          AND authority.sprint_id = NEW.sprint_id
          AND authority.cleanup_effect_id = NEW.cleanup_effect_id
          AND authority.contract_version = NEW.contract_version
          AND authority.admitted_at_unix_ms <= NEW.claimed_at_unix_ms
          AND NOT EXISTS (
              SELECT 1 FROM effect_observations observation
              WHERE observation.effect_id = authority.cleanup_effect_id
                AND observation.sprint_id = authority.sprint_id
          )
          AND NOT EXISTS (
              SELECT 1 FROM effect_evidence_payloads evidence
              WHERE evidence.effect_id = authority.cleanup_effect_id
                AND evidence.sprint_id = authority.sprint_id
          )
          AND NOT EXISTS (
              SELECT 1 FROM worker_cleanup_receipts receipt
              WHERE receipt.effect_id = authority.cleanup_effect_id
                AND receipt.sprint_id = authority.sprint_id
          )
    ) OR NOT (
        json_valid(CAST(NEW.attempt_json AS TEXT))
        AND json_type(CAST(NEW.attempt_json AS TEXT), '$.contract_version') = 'integer'
        AND json_type(CAST(NEW.attempt_json AS TEXT), '$.attempt_id') = 'text'
        AND json_type(CAST(NEW.attempt_json AS TEXT), '$.sprint_id') = 'text'
        AND json_type(CAST(NEW.attempt_json AS TEXT), '$.launch_id') = 'text'
        AND json_type(CAST(NEW.attempt_json AS TEXT), '$.cleanup_effect_id') = 'text'
        AND json_type(CAST(NEW.attempt_json AS TEXT), '$.native_journal_id') = 'text'
        AND json_type(CAST(NEW.attempt_json AS TEXT), '$.expected_platform_binding_digest') = 'text'
        AND json_type(CAST(NEW.attempt_json AS TEXT), '$.claimed_at_unix_ms') = 'integer'
        AND json_extract(CAST(NEW.attempt_json AS TEXT), '$.contract_version') = NEW.contract_version
        AND json_extract(CAST(NEW.attempt_json AS TEXT), '$.attempt_id') = NEW.attempt_id
        AND json_extract(CAST(NEW.attempt_json AS TEXT), '$.sprint_id') = NEW.sprint_id
        AND json_extract(CAST(NEW.attempt_json AS TEXT), '$.launch_id') = NEW.launch_id
        AND json_extract(CAST(NEW.attempt_json AS TEXT), '$.cleanup_effect_id') = NEW.cleanup_effect_id
        AND json_extract(CAST(NEW.attempt_json AS TEXT), '$.native_journal_id') = NEW.native_journal_id
        AND json_extract(CAST(NEW.attempt_json AS TEXT), '$.expected_platform_binding_digest') = NEW.expected_platform_binding_digest
        AND json_extract(CAST(NEW.attempt_json AS TEXT), '$.claimed_at_unix_ms') = NEW.claimed_at_unix_ms
    )
    BEGIN SELECT RAISE(ABORT, 'runner launch preparation attempt requires its exact open admission'); END;

    CREATE TABLE runner_launch_preparation_outcomes (
        attempt_id TEXT PRIMARY KEY NOT NULL,
        sprint_id TEXT NOT NULL,
        launch_id TEXT NOT NULL UNIQUE,
        cleanup_effect_id TEXT NOT NULL UNIQUE,
        native_journal_id TEXT NOT NULL UNIQUE,
        disposition TEXT NOT NULL CHECK (
            disposition IN (
                'HeldChildPrepared', 'RefusedBeforeNativeEffect',
                'NativeEffectUncertain'
            )
        ),
        native_evidence_digest TEXT NOT NULL,
        native_evidence_bytes BLOB NOT NULL CHECK (
            length(native_evidence_bytes) BETWEEN 1 AND 65536
        ),
        contract_version INTEGER NOT NULL CHECK (contract_version > 0),
        finished_at_unix_ms INTEGER NOT NULL CHECK (finished_at_unix_ms > 0),
        outcome_json BLOB NOT NULL CHECK (
            length(outcome_json) BETWEEN 1 AND 65536
        ),
        UNIQUE (sprint_id, launch_id),
        UNIQUE (sprint_id, cleanup_effect_id),
        FOREIGN KEY (attempt_id)
            REFERENCES runner_launch_preparation_attempts(attempt_id)
            ON DELETE RESTRICT,
        FOREIGN KEY (sprint_id, launch_id)
            REFERENCES runner_launch_preparation_attempts(sprint_id, launch_id)
            ON DELETE RESTRICT,
        FOREIGN KEY (sprint_id, cleanup_effect_id)
            REFERENCES runner_launch_preparation_attempts(sprint_id, cleanup_effect_id)
            ON DELETE RESTRICT
    ) STRICT, WITHOUT ROWID;

    CREATE TRIGGER runner_launch_preparation_outcomes_no_update
    BEFORE UPDATE ON runner_launch_preparation_outcomes
    BEGIN SELECT RAISE(ABORT, 'runner launch preparation outcomes are immutable'); END;
    CREATE TRIGGER runner_launch_preparation_outcomes_no_delete
    BEFORE DELETE ON runner_launch_preparation_outcomes
    BEGIN SELECT RAISE(ABORT, 'runner launch preparation outcomes are immutable'); END;
    CREATE TRIGGER runner_launch_preparation_outcomes_exact_attempt
    BEFORE INSERT ON runner_launch_preparation_outcomes
    WHEN NOT EXISTS (
        SELECT 1
        FROM runner_launch_preparation_attempts attempt
        WHERE attempt.attempt_id = NEW.attempt_id
          AND attempt.sprint_id = NEW.sprint_id
          AND attempt.launch_id = NEW.launch_id
          AND attempt.cleanup_effect_id = NEW.cleanup_effect_id
          AND attempt.native_journal_id = NEW.native_journal_id
          AND attempt.contract_version = NEW.contract_version
          AND attempt.claimed_at_unix_ms <= NEW.finished_at_unix_ms
    ) OR NOT (
        json_valid(CAST(NEW.outcome_json AS TEXT))
        AND json_type(CAST(NEW.outcome_json AS TEXT), '$.contract_version') = 'integer'
        AND json_type(CAST(NEW.outcome_json AS TEXT), '$.attempt_id') = 'text'
        AND json_type(CAST(NEW.outcome_json AS TEXT), '$.sprint_id') = 'text'
        AND json_type(CAST(NEW.outcome_json AS TEXT), '$.launch_id') = 'text'
        AND json_type(CAST(NEW.outcome_json AS TEXT), '$.cleanup_effect_id') = 'text'
        AND json_type(CAST(NEW.outcome_json AS TEXT), '$.native_journal_id') = 'text'
        AND json_type(CAST(NEW.outcome_json AS TEXT), '$.disposition') = 'text'
        AND json_type(CAST(NEW.outcome_json AS TEXT), '$.native_evidence_digest') = 'text'
        AND json_type(CAST(NEW.outcome_json AS TEXT), '$.finished_at_unix_ms') = 'integer'
        AND json_extract(CAST(NEW.outcome_json AS TEXT), '$.contract_version') = NEW.contract_version
        AND json_extract(CAST(NEW.outcome_json AS TEXT), '$.attempt_id') = NEW.attempt_id
        AND json_extract(CAST(NEW.outcome_json AS TEXT), '$.sprint_id') = NEW.sprint_id
        AND json_extract(CAST(NEW.outcome_json AS TEXT), '$.launch_id') = NEW.launch_id
        AND json_extract(CAST(NEW.outcome_json AS TEXT), '$.cleanup_effect_id') = NEW.cleanup_effect_id
        AND json_extract(CAST(NEW.outcome_json AS TEXT), '$.native_journal_id') = NEW.native_journal_id
        AND json_extract(CAST(NEW.outcome_json AS TEXT), '$.disposition') = NEW.disposition
        AND json_extract(CAST(NEW.outcome_json AS TEXT), '$.native_evidence_digest') = NEW.native_evidence_digest
        AND json_extract(CAST(NEW.outcome_json AS TEXT), '$.finished_at_unix_ms') = NEW.finished_at_unix_ms
    )
    BEGIN SELECT RAISE(ABORT, 'runner launch preparation outcome requires its exact attempt'); END;

    CREATE TRIGGER runner_session_policies_reject_nonprepared_attempt
    AFTER INSERT ON runner_session_policies
    WHEN EXISTS (
        SELECT 1 FROM runner_launch_preparation_attempts attempt
        WHERE attempt.launch_id = NEW.launch_id
          AND attempt.sprint_id = NEW.sprint_id
    ) AND NOT EXISTS (
        SELECT 1
        FROM runner_launch_preparation_attempts attempt
        JOIN runner_launch_preparation_outcomes outcome
          ON outcome.attempt_id = attempt.attempt_id
        WHERE attempt.launch_id = NEW.launch_id
          AND attempt.sprint_id = NEW.sprint_id
          AND outcome.disposition = 'HeldChildPrepared'
    )
    BEGIN SELECT RAISE(ABORT, 'failed or ambiguous preparation cannot initialize a runner session'); END;

    CREATE TRIGGER effect_session_bindings_reject_nonprepared_attempt
    AFTER INSERT ON effect_session_bindings
    WHEN NEW.session_id IS NOT NULL
      AND EXISTS (
          SELECT 1 FROM runner_launch_preparation_attempts attempt
          WHERE attempt.launch_id = NEW.launch_id
            AND attempt.sprint_id = NEW.sprint_id
      )
      AND NOT EXISTS (
          SELECT 1
          FROM runner_launch_preparation_attempts attempt
          JOIN runner_launch_preparation_outcomes outcome
            ON outcome.attempt_id = attempt.attempt_id
          WHERE attempt.launch_id = NEW.launch_id
            AND attempt.sprint_id = NEW.sprint_id
            AND outcome.disposition = 'HeldChildPrepared'
      )
    BEGIN SELECT RAISE(ABORT, 'failed or ambiguous preparation cannot admit runner work'); END;
";

/// Maximum retained opaque evidence emitted by the native preparation
/// service for one ordinary launch attempt.
pub const MAX_RUNNER_NATIVE_PREPARATION_EVIDENCE_BYTES: usize = 64 * 1024;
/// Maximum UTF-8 byte length of the service-owned durable native journal
/// identity bound before native preparation begins.
pub const MAX_RUNNER_NATIVE_JOURNAL_ID_BYTES: usize = 512;

/// Immutable one-attempt identity committed before native preparation begins.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RunnerLaunchPreparationAttempt {
    /// Contract version.
    pub contract_version: u32,
    /// Globally unique attempt identity.
    pub attempt_id: String,
    /// Owning sprint.
    pub sprint_id: String,
    /// Exact ordinary runner launch.
    pub launch_id: String,
    /// Pending cleanup obligation that recovers every ambiguous attempt.
    pub cleanup_effect_id: String,
    /// Durable service-owned journal identity used for reconciliation.
    pub native_journal_id: String,
    /// Digest of the expected platform launch binding; this is comparison
    /// state, not a permit.
    pub expected_platform_binding_digest: Digest,
    /// Claim timestamp.
    pub claimed_at_unix_ms: u64,
}

impl RunnerLaunchPreparationAttempt {
    /// Validates bounded identities and the current contract version.
    ///
    /// # Errors
    ///
    /// Returns a contract error for a blank, control-bearing, oversized, or
    /// otherwise invalid attempt.
    pub fn validate(&self) -> Result<(), ContractError> {
        if self.contract_version != CONTRACT_VERSION {
            return Err(ContractError::new(
                "runner_launch_preparation_attempt.contract_version",
                format!(
                    "expected version {CONTRACT_VERSION}, got {}",
                    self.contract_version
                ),
            ));
        }
        for (field, value) in [
            ("attempt_id", self.attempt_id.as_str()),
            ("sprint_id", self.sprint_id.as_str()),
            ("launch_id", self.launch_id.as_str()),
            ("cleanup_effect_id", self.cleanup_effect_id.as_str()),
            ("native_journal_id", self.native_journal_id.as_str()),
        ] {
            if value.trim().is_empty() || value.chars().any(char::is_control) {
                return Err(ContractError::new(
                    "runner_launch_preparation_attempt.identity",
                    format!("{field} must be nonblank and contain no control characters"),
                ));
            }
        }
        if self.native_journal_id.len() > MAX_RUNNER_NATIVE_JOURNAL_ID_BYTES {
            return Err(ContractError::new(
                "runner_launch_preparation_attempt.native_journal_id",
                format!("must not exceed {MAX_RUNNER_NATIVE_JOURNAL_ID_BYTES} UTF-8 bytes"),
            ));
        }
        if self.claimed_at_unix_ms == 0 {
            return Err(ContractError::new(
                "runner_launch_preparation_attempt.claimed_at_unix_ms",
                "must be greater than zero",
            ));
        }
        Ok(())
    }
}

/// Closed outcome of the single native preparation invocation.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum RunnerLaunchPreparationDisposition {
    /// The service durably owns the accounting domain and held child. This is
    /// not evidence that the child was released or containment is complete.
    HeldChildPrepared,
    /// Native preparation truthfully refused before creating native state.
    RefusedBeforeNativeEffect,
    /// Native state may have been created and only cleanup/reconciliation may
    /// continue.
    NativeEffectUncertain,
}

/// Bounded result returned by the one live native preparation callback.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RunnerLaunchPreparationOutcome {
    /// Closed native disposition.
    pub disposition: RunnerLaunchPreparationDisposition,
    /// Opaque service evidence, retained exactly for reconciliation.
    pub native_evidence_bytes: Vec<u8>,
    /// Native completion timestamp.
    pub finished_at_unix_ms: u64,
}

impl RunnerLaunchPreparationOutcome {
    pub(super) fn validate(&self, claimed_at_unix_ms: u64) -> Result<(), ContractError> {
        if self.native_evidence_bytes.is_empty()
            || self.native_evidence_bytes.len() > MAX_RUNNER_NATIVE_PREPARATION_EVIDENCE_BYTES
        {
            return Err(ContractError::new(
                "runner_launch_preparation_outcome.native_evidence_bytes",
                format!("must contain 1..={MAX_RUNNER_NATIVE_PREPARATION_EVIDENCE_BYTES} bytes"),
            ));
        }
        if self.finished_at_unix_ms < claimed_at_unix_ms {
            return Err(ContractError::new(
                "runner_launch_preparation_outcome.finished_at_unix_ms",
                "must not predate the durable preparation claim",
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct RunnerLaunchPreparationOutcomeRecord {
    contract_version: u32,
    attempt_id: String,
    sprint_id: String,
    launch_id: String,
    cleanup_effect_id: String,
    native_journal_id: String,
    disposition: RunnerLaunchPreparationDisposition,
    native_evidence_digest: Digest,
    finished_at_unix_ms: u64,
}

/// Fully validated durable state of the only native preparation attempt.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PersistedRunnerLaunchPreparation {
    /// Immutable one-attempt identity.
    pub attempt: RunnerLaunchPreparationAttempt,
    /// `None` only after a crash or operational failure between the durable
    /// claim and its outcome; that state is cleanup-only and never retryable.
    pub outcome: Option<RunnerLaunchPreparationOutcome>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RunnerLaunchCleanupAdmissionRecord {
    pub(super) contract_version: u32,
    pub(super) sprint_id: String,
    pub(super) launch_id: String,
    pub(super) session_id: String,
    pub(super) cleanup_effect_id: String,
    pub(super) proposal_event_id: String,
    pub(super) request_digest: Digest,
    pub(super) platform_backend: WorkerCleanupBackend,
    pub(super) admitted_at_unix_ms: u64,
}

impl RunnerLaunchCleanupAdmissionRecord {
    pub(super) fn validate(&self) -> Result<(), ContractError> {
        if self.contract_version != CONTRACT_VERSION {
            return Err(ContractError::new(
                "runner_launch_cleanup_admission.contract_version",
                format!(
                    "expected version {CONTRACT_VERSION}, got {}",
                    self.contract_version
                ),
            ));
        }
        for (field, value) in [
            ("sprint_id", self.sprint_id.as_str()),
            ("launch_id", self.launch_id.as_str()),
            ("session_id", self.session_id.as_str()),
            ("cleanup_effect_id", self.cleanup_effect_id.as_str()),
            ("proposal_event_id", self.proposal_event_id.as_str()),
        ] {
            if value.trim().is_empty() {
                return Err(ContractError::new(
                    "runner_launch_cleanup_admission.identity",
                    format!("{field} must not be blank"),
                ));
            }
        }
        if self.admitted_at_unix_ms == 0 {
            return Err(ContractError::new(
                "runner_launch_cleanup_admission.admitted_at_unix_ms",
                "must be greater than zero",
            ));
        }
        Ok(())
    }
}

/// Fully validated authoritative ordinary launch and its pre-spawn cleanup
/// effect.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PersistedRunnerLaunchCleanupAdmission {
    /// Exact immutable launch envelope.
    pub launch: RunnerLaunchIntent,
    /// Exact canonical cleanup request bound to the launch.
    pub cleanup_request: WorkerCleanupRequest,
    /// Complete durable cleanup effect lifecycle (normally still pending at
    /// admission time).
    pub cleanup_effect: PersistedEffect,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum RunnerLaunchCleanupClassification {
    Authoritative,
    LegacyPreV13,
}

pub(super) fn backend_name(backend: WorkerCleanupBackend) -> &'static str {
    match backend {
        WorkerCleanupBackend::MacOsDedicatedIdentity => "MacOsDedicatedIdentity",
        WorkerCleanupBackend::LinuxCgroupV2 => "LinuxCgroupV2",
        WorkerCleanupBackend::TrustedApplierDirectChildWait => "TrustedApplierDirectChildWait",
    }
}

pub(super) fn schema_is_installed(connection: &Connection) -> Result<bool, LedgerError> {
    connection
        .query_row(
            "SELECT 1 FROM sqlite_schema
             WHERE type = 'table' AND name = 'runner_launch_cleanup_admissions'",
            [],
            |_| Ok(()),
        )
        .optional()
        .map(|value| value.is_some())
        .map_err(Into::into)
}

pub(super) fn role_backend_matches(
    purpose: RunnerSessionPurpose,
    backend: WorkerCleanupBackend,
) -> bool {
    match purpose {
        RunnerSessionPurpose::TaskWorker
        | RunnerSessionPurpose::FinalVerifier
        | RunnerSessionPurpose::LiveStateVerifier => matches!(
            backend,
            WorkerCleanupBackend::MacOsDedicatedIdentity | WorkerCleanupBackend::LinuxCgroupV2
        ),
        RunnerSessionPurpose::Applier => {
            backend == WorkerCleanupBackend::TrustedApplierDirectChildWait
        }
    }
}

pub(super) fn validate_contract_join(
    launch: &RunnerLaunchIntent,
    cleanup_intent: &EffectIntent,
    cleanup_request: &WorkerCleanupRequest,
    proposal_event_id: &str,
) -> Result<RunnerLaunchCleanupAdmissionRecord, LedgerError> {
    cleanup_request.validate()?;
    if cleanup_intent.kind != EffectKind::CleanupWorkerDomain
        || cleanup_intent.task_id.is_some()
        || cleanup_intent.worker_id.is_some()
        || cleanup_intent.worker_lease != launch.worker_lease
        || cleanup_intent.sprint_id != launch.sprint_id
        || cleanup_intent.policy_hash != launch.policy_hash
        || cleanup_intent.created_at_unix_ms < launch.created_at_unix_ms
        || cleanup_request.sprint_id != launch.sprint_id
        || cleanup_request.launch_id != launch.launch_id
        || cleanup_request.session_id != launch.session_id
        || cleanup_request.policy_hash != launch.policy_hash
        || cleanup_request.grant_hash != launch.grant_hash
        || cleanup_request.policy_version != launch.policy_version
        || !role_backend_matches(launch.purpose, cleanup_request.platform_backend)
    {
        return Err(reference_mismatch(
            "runner launch cleanup admission",
            "cleanup intent, request, role, backend, policy, grant, or timestamp does not match the launch",
        ));
    }
    let record = RunnerLaunchCleanupAdmissionRecord {
        contract_version: launch.contract_version,
        sprint_id: launch.sprint_id.clone(),
        launch_id: launch.launch_id.clone(),
        session_id: launch.session_id.clone(),
        cleanup_effect_id: cleanup_intent.effect_id.clone(),
        proposal_event_id: proposal_event_id.to_owned(),
        request_digest: cleanup_intent.request_digest.clone(),
        platform_backend: cleanup_request.platform_backend,
        admitted_at_unix_ms: cleanup_intent.created_at_unix_ms,
    };
    record.validate()?;
    Ok(record)
}

pub(super) fn insert_admission(
    transaction: &Transaction<'_>,
    record: &RunnerLaunchCleanupAdmissionRecord,
) -> Result<(), LedgerError> {
    transaction.execute(
        "INSERT INTO runner_launch_cleanup_admissions (
            launch_id, sprint_id, session_id, cleanup_effect_id,
            proposal_event_id, request_digest, platform_backend,
            contract_version, admitted_at_unix_ms, admission_json
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
        params![
            record.launch_id,
            record.sprint_id,
            record.session_id,
            record.cleanup_effect_id,
            record.proposal_event_id,
            record.request_digest.as_str(),
            backend_name(record.platform_backend),
            i64::from(record.contract_version),
            super::sqlite_integer(
                "runner_launch_cleanup_admission.admitted_at_unix_ms",
                record.admitted_at_unix_ms,
            )?,
            encode("runner launch cleanup admission", record)?,
        ],
    )?;
    Ok(())
}

pub(super) fn load_classification(
    connection: &Connection,
    sprint_id: &str,
    launch_id: &str,
) -> Result<RunnerLaunchCleanupClassification, LedgerError> {
    let authority = connection
        .query_row(
            "SELECT session_id, contract_version
             FROM runner_launch_cleanup_admissions
             WHERE sprint_id = ?1 AND launch_id = ?2",
            params![sprint_id, launch_id],
            |row| Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?)),
        )
        .optional()?;
    let legacy = connection
        .query_row(
            "SELECT session_id, gap_kind, contract_version
             FROM legacy_runner_launch_cleanup_gaps
             WHERE sprint_id = ?1 AND launch_id = ?2",
            params![sprint_id, launch_id],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, i64>(2)?,
                ))
            },
        )
        .optional()?;
    match (authority, legacy) {
        (Some((session_id, contract_version)), None) => {
            let (launch, _) = load_runner_launch_intent_from(connection, sprint_id, launch_id)?;
            require_contract_version("runner launch cleanup admission", contract_version)?;
            if session_id != launch.session_id
                || contract_version != i64::from(launch.contract_version)
            {
                return Err(LedgerError::Corrupt {
                    entity: "runner launch cleanup classification",
                    detail: "authoritative classification disagrees with the exact launch".into(),
                });
            }
            Ok(RunnerLaunchCleanupClassification::Authoritative)
        }
        (None, Some((session_id, gap_kind, contract_version))) => {
            let (launch, _) = load_runner_launch_intent_from(connection, sprint_id, launch_id)?;
            require_contract_version("legacy runner launch cleanup gap", contract_version)?;
            if session_id != launch.session_id
                || gap_kind != "PreV13Unbound"
                || contract_version != i64::from(launch.contract_version)
            {
                return Err(LedgerError::Corrupt {
                    entity: "runner launch cleanup classification",
                    detail: "legacy classification disagrees with the exact launch".into(),
                });
            }
            Ok(RunnerLaunchCleanupClassification::LegacyPreV13)
        }
        _ => Err(LedgerError::Corrupt {
            entity: "runner launch cleanup classification",
            detail: "launch must have exactly one authoritative or legacy classification".into(),
        }),
    }
}

pub(super) fn require_authoritative(
    connection: &Connection,
    sprint_id: &str,
    launch_id: &str,
) -> Result<(), LedgerError> {
    match load_classification(connection, sprint_id, launch_id)? {
        RunnerLaunchCleanupClassification::Authoritative => Ok(()),
        RunnerLaunchCleanupClassification::LegacyPreV13 => Err(reference_mismatch(
            "runner launch cleanup admission",
            "pre-v13 launch may only be safely closed by a launch-bound cleanup effect",
        )),
    }
}

pub(super) fn require_open_authoritative(
    connection: &Connection,
    sprint_id: &str,
    launch_id: &str,
) -> Result<PersistedRunnerLaunchCleanupAdmission, LedgerError> {
    let admission = load_authoritative(connection, sprint_id, launch_id)?;
    if admission.cleanup_effect.observation.is_some()
        || admission.cleanup_effect.evidence_bytes.is_some()
        || admission.cleanup_effect.terminal_event.is_some()
        || admission.cleanup_effect.finish_receipt != PersistedFinishReceipt::NotRequired
    {
        return Err(reference_mismatch(
            "runner launch cleanup admission",
            "cleanup is already terminal; the launch cannot initialize a session or admit new runner work",
        ));
    }
    Ok(admission)
}

/// Once native preparation has been claimed, only its exact held-child
/// outcome may initialize a runner session or authorize session-bound work.
/// Absence remains admitted walking-skeleton state; production native launch
/// is separately fail-closed until it uses the live preparation API.
pub(super) fn require_preparation_allows_session_work(
    connection: &Connection,
    sprint_id: &str,
    launch_id: &str,
) -> Result<(), LedgerError> {
    let exists = connection
        .query_row(
            "SELECT 1 FROM runner_launch_preparation_attempts
             WHERE sprint_id = ?1 AND launch_id = ?2",
            params![sprint_id, launch_id],
            |_| Ok(()),
        )
        .optional()?
        .is_some();
    if !exists {
        return Ok(());
    }
    let preparation = load_preparation(connection, sprint_id, launch_id)?;
    if matches!(
        preparation.outcome,
        Some(RunnerLaunchPreparationOutcome {
            disposition: RunnerLaunchPreparationDisposition::HeldChildPrepared,
            ..
        })
    ) {
        Ok(())
    } else {
        Err(reference_mismatch(
            "runner launch preparation",
            "claimed preparation is incomplete, refused, or ambiguous and cannot authorize a session or runner work",
        ))
    }
}

/// Requires the only safe retry state for a migrated pre-v13 launch.
///
/// Historical rows remain untouched. A new launch-bound cleanup may be added
/// only when every earlier cleanup attempt for the launch is terminal and
/// non-successful. A pending attempt serializes retries, and any successful
/// zero-descendant receipt closes the launch permanently.
pub(super) fn require_legacy_cleanup_retry_admissible(
    connection: &Connection,
    sprint_id: &str,
    launch_id: &str,
) -> Result<(), LedgerError> {
    match load_classification(connection, sprint_id, launch_id)? {
        RunnerLaunchCleanupClassification::Authoritative => {
            return Err(reference_mismatch(
                "cleanup launch binding",
                "authoritative v13 launch cleanup was already admitted atomically",
            ));
        }
        RunnerLaunchCleanupClassification::LegacyPreV13 => {}
    }

    let prior_effect_ids = {
        let mut statement = connection.prepare(
            "SELECT binding.effect_id
             FROM effect_session_bindings binding
             JOIN effect_intents intent
               ON intent.effect_id = binding.effect_id
              AND intent.sprint_id = binding.sprint_id
             JOIN finish_effect_kinds kind
               ON kind.effect_id = intent.effect_id
              AND kind.sprint_id = intent.sprint_id
             WHERE binding.sprint_id = ?1
               AND binding.launch_id = ?2
               AND kind.effect_kind = 'CleanupWorkerDomain'
             ORDER BY binding.effect_id ASC",
        )?;
        statement
            .query_map(params![sprint_id, launch_id], |row| row.get::<_, String>(0))?
            .collect::<Result<Vec<_>, _>>()?
    };
    for effect_id in prior_effect_ids {
        let prior = load_effect_from_with_receipts(connection, &effect_id, true)?;
        match prior.observation.as_ref().map(|value| &value.outcome) {
            None => {
                return Err(reference_mismatch(
                    "cleanup launch binding",
                    format!("legacy launch cleanup attempt '{effect_id}' is still open"),
                ));
            }
            Some(EffectOutcome::Succeeded { .. }) => {
                return Err(reference_mismatch(
                    "cleanup launch binding",
                    format!("legacy launch cleanup attempt '{effect_id}' already succeeded"),
                ));
            }
            Some(
                EffectOutcome::FailedBeforeEffect { .. }
                | EffectOutcome::FailedAfterKnownEffect { .. }
                | EffectOutcome::CancelledBeforeEffect { .. }
                | EffectOutcome::Unknown { .. },
            ) => {}
        }
    }
    Ok(())
}

/// Loads only the immutable pre-effect authority that admitted one launch and
/// its cleanup obligation. This boundary deliberately excludes cleanup
/// observations, evidence, terminal events, and finish receipts: a historical
/// task Running boundary must remain readable without recursively reopening
/// later cleanup lifecycle state.
#[allow(clippy::too_many_lines)]
pub(super) fn load_static_authoritative_record(
    connection: &Connection,
    sprint_id: &str,
    launch_id: &str,
) -> Result<RunnerLaunchCleanupAdmissionRecord, LedgerError> {
    let legacy = connection
        .query_row(
            "SELECT 1 FROM legacy_runner_launch_cleanup_gaps
             WHERE sprint_id = ?1 AND launch_id = ?2",
            params![sprint_id, launch_id],
            |_| Ok(()),
        )
        .optional()?
        .is_some();
    let stored = connection
        .query_row(
            "SELECT session_id, cleanup_effect_id, proposal_event_id, request_digest,
                    platform_backend, contract_version, admitted_at_unix_ms,
                    admission_json
             FROM runner_launch_cleanup_admissions
             WHERE sprint_id = ?1 AND launch_id = ?2",
            params![sprint_id, launch_id],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, i64>(5)?,
                    row.get::<_, i64>(6)?,
                    row.get::<_, Vec<u8>>(7)?,
                ))
            },
        )
        .optional()?
        .ok_or_else(|| LedgerError::ArtifactNotFound {
            entity: "runner launch cleanup admission",
            id: format!("{sprint_id}/{launch_id}"),
        })?;
    if legacy {
        return Err(LedgerError::Corrupt {
            entity: "runner launch cleanup classification",
            detail: "launch carries both authoritative and legacy cleanup classifications".into(),
        });
    }
    require_contract_version("runner launch cleanup admission", stored.5)?;
    let record: RunnerLaunchCleanupAdmissionRecord =
        decode_stored("runner launch cleanup admission", &stored.7)?;
    record.validate().map_err(|error| LedgerError::Corrupt {
        entity: "runner launch cleanup admission",
        detail: error.to_string(),
    })?;
    if encode("runner launch cleanup admission", &record)? != stored.7
        || record.sprint_id != sprint_id
        || record.launch_id != launch_id
        || record.session_id != stored.0
        || record.cleanup_effect_id != stored.1
        || record.proposal_event_id != stored.2
        || record.request_digest.as_str() != stored.3
        || backend_name(record.platform_backend) != stored.4
        || i64::from(record.contract_version) != stored.5
        || record.admitted_at_unix_ms
            != unsigned_integer(
                "runner_launch_cleanup_admission.admitted_at_unix_ms",
                stored.6,
            )?
    {
        return Err(LedgerError::Corrupt {
            entity: "runner launch cleanup admission",
            detail: "admission envelope disagrees with indexed columns".into(),
        });
    }

    let (launch, _) = load_runner_launch_intent_from(connection, sprint_id, launch_id)?;
    let stored_effect = load_effect_intent_row(connection, &record.cleanup_effect_id)?;
    let intent = &stored_effect.intent;
    let stored_created_at = unsigned_integer(
        "effect_intent.created_at_unix_ms",
        stored_effect.created_at_unix_ms,
    )?;
    validate_finish_effect_kind(connection, intent, &stored_effect.effect_kind)?;
    if intent.effect_id != record.cleanup_effect_id
        || !worker_lease_encoding_matches(
            connection,
            &intent.sprint_id,
            "effect intent",
            intent,
            &stored_effect.intent_json,
        )?
        || intent.sprint_id != stored_effect.sprint_id
        || intent.task_id != stored_effect.task_id
        || intent.worker_id != stored_effect.worker_id
        || intent.causation_event_id != stored_effect.causation_event_id
        || intent.idempotency_key != stored_effect.idempotency_key
        || intent.correlation_id != stored_effect.correlation_id
        || intent.request_digest.as_str() != stored_effect.request_digest
        || intent.policy_hash.as_str() != stored_effect.policy_hash
        || intent.input_snapshot.as_str() != stored_effect.input_snapshot
        || intent.created_at_unix_ms != stored_created_at
        || !worker_lease_authority::indexed_binding_matches(
            intent.worker_lease.as_ref(),
            stored_effect.worker_lease_id.as_deref(),
            stored_effect.worker_lease_epoch,
        )?
    {
        return Err(LedgerError::Corrupt {
            entity: "runner launch cleanup admission",
            detail: "cleanup intent envelope disagrees with its immutable indexed fields".into(),
        });
    }
    if let Some(lease) = &intent.worker_lease {
        worker_lease_authority::require_exact(connection, lease, false)?;
    }
    let (spec, graph, sprint_created_at, _) =
        load_sprint_definition_raw(connection, &intent.sprint_id)?;
    if sprint_created_at > intent.created_at_unix_ms {
        return Err(LedgerError::Corrupt {
            entity: "runner launch cleanup admission",
            detail: "cleanup intent predates its sprint".into(),
        });
    }
    validate_effect_for_sprint_phase(&spec, graph.as_ref(), intent)?;
    let input_snapshot =
        load_workspace_snapshot_from(connection, &intent.sprint_id, &intent.input_snapshot)?;
    if graph.is_none() {
        validate_draft_base_snapshot(&spec, &input_snapshot, sprint_created_at)?;
    }
    if input_snapshot.created_at_unix_ms > intent.created_at_unix_ms {
        return Err(LedgerError::Corrupt {
            entity: "runner launch cleanup admission",
            detail: "cleanup intent predates its input snapshot".into(),
        });
    }

    let request_bytes = load_effect_request_payload(connection, intent)?;
    let request: WorkerCleanupRequest =
        super::decode_canonical_request("worker cleanup request", &request_bytes)?;
    let proposal = load_event_by_id(connection, &stored_effect.proposed_event_id)?;
    validate_effect_proposal_event_shape(intent, &proposal)?;
    validate_stored_event_causation(connection, &proposal)?;
    let binding = connection
        .query_row(
            "SELECT sprint_id, launch_id, session_id, contract_version
             FROM effect_session_bindings WHERE effect_id = ?1",
            [&intent.effect_id],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, Option<String>>(2)?,
                    row.get::<_, i64>(3)?,
                ))
            },
        )
        .optional()?
        .ok_or_else(|| LedgerError::Corrupt {
            entity: "runner launch cleanup admission",
            detail: "admitted cleanup intent lacks its immutable launch binding".into(),
        })?;
    require_contract_version("runner launch cleanup binding", binding.3)?;
    if binding.0 != record.sprint_id
        || binding.1 != record.launch_id
        || binding.2.is_some()
        || binding.3 != i64::from(record.contract_version)
    {
        return Err(LedgerError::Corrupt {
            entity: "runner launch cleanup admission",
            detail: "admitted cleanup intent binding is crossed or initialized".into(),
        });
    }
    let expected = validate_contract_join(&launch, intent, &request, &proposal.event_id)?;
    if expected != record
        || proposal.event_id != record.proposal_event_id
        || intent.request_digest != record.request_digest
    {
        return Err(LedgerError::Corrupt {
            entity: "runner launch cleanup admission",
            detail: "launch, cleanup intent, request, event, or admission join disagrees".into(),
        });
    }
    Ok(record)
}

#[allow(clippy::too_many_lines)]
pub(super) fn load_authoritative(
    connection: &Connection,
    sprint_id: &str,
    launch_id: &str,
) -> Result<PersistedRunnerLaunchCleanupAdmission, LedgerError> {
    require_authoritative(connection, sprint_id, launch_id)?;
    let stored = connection.query_row(
        "SELECT session_id, cleanup_effect_id, proposal_event_id, request_digest,
                platform_backend, contract_version, admitted_at_unix_ms,
                admission_json
         FROM runner_launch_cleanup_admissions
         WHERE sprint_id = ?1 AND launch_id = ?2",
        params![sprint_id, launch_id],
        |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, String>(4)?,
                row.get::<_, i64>(5)?,
                row.get::<_, i64>(6)?,
                row.get::<_, Vec<u8>>(7)?,
            ))
        },
    )?;
    require_contract_version("runner launch cleanup admission", stored.5)?;
    let record: RunnerLaunchCleanupAdmissionRecord =
        decode_stored("runner launch cleanup admission", &stored.7)?;
    record.validate().map_err(|error| LedgerError::Corrupt {
        entity: "runner launch cleanup admission",
        detail: error.to_string(),
    })?;
    if encode("runner launch cleanup admission", &record)? != stored.7
        || record.sprint_id != sprint_id
        || record.launch_id != launch_id
        || record.session_id != stored.0
        || record.cleanup_effect_id != stored.1
        || record.proposal_event_id != stored.2
        || record.request_digest.as_str() != stored.3
        || backend_name(record.platform_backend) != stored.4
        || i64::from(record.contract_version) != stored.5
        || record.admitted_at_unix_ms
            != super::unsigned_integer(
                "runner_launch_cleanup_admission.admitted_at_unix_ms",
                stored.6,
            )?
    {
        return Err(LedgerError::Corrupt {
            entity: "runner launch cleanup admission",
            detail: "admission envelope disagrees with indexed columns".into(),
        });
    }
    let (launch, _) = load_runner_launch_intent_from(connection, sprint_id, launch_id)?;
    let effect = load_effect_from_with_receipts(connection, &record.cleanup_effect_id, true)?;
    let binding = connection
        .query_row(
            "SELECT sprint_id, launch_id, session_id, contract_version
             FROM effect_session_bindings WHERE effect_id = ?1",
            [&record.cleanup_effect_id],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, Option<String>>(2)?,
                    row.get::<_, i64>(3)?,
                ))
            },
        )
        .optional()?
        .ok_or_else(|| LedgerError::Corrupt {
            entity: "runner launch cleanup admission",
            detail: "admitted cleanup effect lacks its immutable launch binding".into(),
        })?;
    require_contract_version("runner launch cleanup binding", binding.3)?;
    if binding.0 != record.sprint_id
        || binding.1 != record.launch_id
        || binding.2.is_some()
        || binding.3 != i64::from(record.contract_version)
    {
        return Err(LedgerError::Corrupt {
            entity: "runner launch cleanup admission",
            detail: "admitted cleanup effect binding is crossed or initialized".into(),
        });
    }
    let request: WorkerCleanupRequest =
        super::decode_canonical_request("worker cleanup request", &effect.request_bytes)?;
    let expected = validate_contract_join(
        &launch,
        &effect.intent,
        &request,
        &effect.proposed_event.event_id,
    )?;
    if expected != record
        || effect.proposed_event.event_id != record.proposal_event_id
        || effect.intent.request_digest != record.request_digest
    {
        return Err(LedgerError::Corrupt {
            entity: "runner launch cleanup admission",
            detail: "launch, cleanup effect, event, request, or admission join disagrees".into(),
        });
    }
    Ok(PersistedRunnerLaunchCleanupAdmission {
        launch,
        cleanup_request: request,
        cleanup_effect: effect,
    })
}

pub(super) fn insert_preparation_attempt(
    transaction: &Transaction<'_>,
    attempt: &RunnerLaunchPreparationAttempt,
) -> Result<(), LedgerError> {
    attempt.validate()?;
    transaction.execute(
        "INSERT INTO runner_launch_preparation_attempts (
            launch_id, sprint_id, cleanup_effect_id, attempt_id,
            native_journal_id, expected_platform_binding_digest,
            contract_version, claimed_at_unix_ms, attempt_json
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
        params![
            attempt.launch_id,
            attempt.sprint_id,
            attempt.cleanup_effect_id,
            attempt.attempt_id,
            attempt.native_journal_id,
            attempt.expected_platform_binding_digest.as_str(),
            i64::from(attempt.contract_version),
            super::sqlite_integer(
                "runner_launch_preparation_attempt.claimed_at_unix_ms",
                attempt.claimed_at_unix_ms,
            )?,
            encode("runner launch preparation attempt", attempt)?,
        ],
    )?;
    Ok(())
}

fn disposition_name(disposition: RunnerLaunchPreparationDisposition) -> &'static str {
    match disposition {
        RunnerLaunchPreparationDisposition::HeldChildPrepared => "HeldChildPrepared",
        RunnerLaunchPreparationDisposition::RefusedBeforeNativeEffect => {
            "RefusedBeforeNativeEffect"
        }
        RunnerLaunchPreparationDisposition::NativeEffectUncertain => "NativeEffectUncertain",
    }
}

pub(super) fn insert_preparation_outcome(
    transaction: &Transaction<'_>,
    attempt: &RunnerLaunchPreparationAttempt,
    outcome: &RunnerLaunchPreparationOutcome,
) -> Result<(), LedgerError> {
    outcome.validate(attempt.claimed_at_unix_ms)?;
    let native_evidence_digest = Digest::sha256(&outcome.native_evidence_bytes);
    let record = RunnerLaunchPreparationOutcomeRecord {
        contract_version: attempt.contract_version,
        attempt_id: attempt.attempt_id.clone(),
        sprint_id: attempt.sprint_id.clone(),
        launch_id: attempt.launch_id.clone(),
        cleanup_effect_id: attempt.cleanup_effect_id.clone(),
        native_journal_id: attempt.native_journal_id.clone(),
        disposition: outcome.disposition,
        native_evidence_digest: native_evidence_digest.clone(),
        finished_at_unix_ms: outcome.finished_at_unix_ms,
    };
    transaction.execute(
        "INSERT INTO runner_launch_preparation_outcomes (
            attempt_id, sprint_id, launch_id, cleanup_effect_id,
            native_journal_id, disposition, native_evidence_digest,
            native_evidence_bytes, contract_version, finished_at_unix_ms,
            outcome_json
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
        params![
            attempt.attempt_id,
            attempt.sprint_id,
            attempt.launch_id,
            attempt.cleanup_effect_id,
            attempt.native_journal_id,
            disposition_name(outcome.disposition),
            native_evidence_digest.as_str(),
            outcome.native_evidence_bytes,
            i64::from(attempt.contract_version),
            super::sqlite_integer(
                "runner_launch_preparation_outcome.finished_at_unix_ms",
                outcome.finished_at_unix_ms,
            )?,
            encode("runner launch preparation outcome", &record)?,
        ],
    )?;
    Ok(())
}

#[allow(clippy::too_many_lines)] // One exact attempt/outcome aggregate is validated end-to-end.
pub(super) fn load_preparation(
    connection: &Connection,
    sprint_id: &str,
    launch_id: &str,
) -> Result<PersistedRunnerLaunchPreparation, LedgerError> {
    let stored = connection
        .query_row(
            "SELECT cleanup_effect_id, attempt_id, native_journal_id,
                    expected_platform_binding_digest, contract_version,
                    claimed_at_unix_ms, attempt_json
             FROM runner_launch_preparation_attempts
             WHERE sprint_id = ?1 AND launch_id = ?2",
            params![sprint_id, launch_id],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, i64>(4)?,
                    row.get::<_, i64>(5)?,
                    row.get::<_, Vec<u8>>(6)?,
                ))
            },
        )
        .optional()?
        .ok_or_else(|| LedgerError::ArtifactNotFound {
            entity: "runner launch preparation",
            id: format!("{sprint_id}:{launch_id}"),
        })?;
    require_contract_version("runner launch preparation attempt", stored.4)?;
    let attempt: RunnerLaunchPreparationAttempt =
        decode_stored("runner launch preparation attempt", &stored.6)?;
    attempt.validate().map_err(|error| LedgerError::Corrupt {
        entity: "runner launch preparation attempt",
        detail: error.to_string(),
    })?;
    if encode("runner launch preparation attempt", &attempt)? != stored.6
        || attempt.sprint_id != sprint_id
        || attempt.launch_id != launch_id
        || attempt.cleanup_effect_id != stored.0
        || attempt.attempt_id != stored.1
        || attempt.native_journal_id != stored.2
        || attempt.expected_platform_binding_digest.as_str() != stored.3
        || i64::from(attempt.contract_version) != stored.4
        || attempt.claimed_at_unix_ms
            != super::unsigned_integer(
                "runner_launch_preparation_attempt.claimed_at_unix_ms",
                stored.5,
            )?
    {
        return Err(LedgerError::Corrupt {
            entity: "runner launch preparation attempt",
            detail: "attempt envelope disagrees with indexed columns".into(),
        });
    }
    let admission = load_authoritative(connection, sprint_id, launch_id)?;
    if attempt.cleanup_effect_id != admission.cleanup_effect.intent.effect_id
        || attempt.contract_version != admission.launch.contract_version
        || attempt.claimed_at_unix_ms < admission.cleanup_effect.intent.created_at_unix_ms
    {
        return Err(LedgerError::Corrupt {
            entity: "runner launch preparation attempt",
            detail: "attempt disagrees with its exact launch cleanup admission".into(),
        });
    }

    let outcome = connection
        .query_row(
            "SELECT sprint_id, launch_id, cleanup_effect_id, native_journal_id,
                    disposition, native_evidence_digest, native_evidence_bytes,
                    contract_version, finished_at_unix_ms, outcome_json
             FROM runner_launch_preparation_outcomes WHERE attempt_id = ?1",
            [&attempt.attempt_id],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, String>(5)?,
                    row.get::<_, Vec<u8>>(6)?,
                    row.get::<_, i64>(7)?,
                    row.get::<_, i64>(8)?,
                    row.get::<_, Vec<u8>>(9)?,
                ))
            },
        )
        .optional()?;
    let Some(stored_outcome) = outcome else {
        return Ok(PersistedRunnerLaunchPreparation {
            attempt,
            outcome: None,
        });
    };
    require_contract_version("runner launch preparation outcome", stored_outcome.7)?;
    let record: RunnerLaunchPreparationOutcomeRecord =
        decode_stored("runner launch preparation outcome", &stored_outcome.9)?;
    let native_evidence_digest = Digest::sha256(&stored_outcome.6);
    let outcome = RunnerLaunchPreparationOutcome {
        disposition: record.disposition,
        native_evidence_bytes: stored_outcome.6,
        finished_at_unix_ms: super::unsigned_integer(
            "runner_launch_preparation_outcome.finished_at_unix_ms",
            stored_outcome.8,
        )?,
    };
    outcome
        .validate(attempt.claimed_at_unix_ms)
        .map_err(|error| LedgerError::Corrupt {
            entity: "runner launch preparation outcome",
            detail: error.to_string(),
        })?;
    if encode("runner launch preparation outcome", &record)? != stored_outcome.9
        || record.contract_version != attempt.contract_version
        || record.attempt_id != attempt.attempt_id
        || record.sprint_id != attempt.sprint_id
        || record.launch_id != attempt.launch_id
        || record.cleanup_effect_id != attempt.cleanup_effect_id
        || record.native_journal_id != attempt.native_journal_id
        || record.native_evidence_digest != native_evidence_digest
        || record.finished_at_unix_ms != outcome.finished_at_unix_ms
        || stored_outcome.0 != attempt.sprint_id
        || stored_outcome.1 != attempt.launch_id
        || stored_outcome.2 != attempt.cleanup_effect_id
        || stored_outcome.3 != attempt.native_journal_id
        || stored_outcome.4 != disposition_name(record.disposition)
        || stored_outcome.5 != native_evidence_digest.as_str()
        || stored_outcome.7 != i64::from(attempt.contract_version)
    {
        return Err(LedgerError::Corrupt {
            entity: "runner launch preparation outcome",
            detail: "outcome envelope, evidence, or indexed columns disagree".into(),
        });
    }
    Ok(PersistedRunnerLaunchPreparation {
        attempt,
        outcome: Some(outcome),
    })
}
