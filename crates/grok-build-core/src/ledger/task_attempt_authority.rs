//! Schema-v15 task-attempt authority and exact durable projections.

use rusqlite::{Connection, OptionalExtension, Transaction, params};
use serde::Serialize;

use crate::{
    AgentEventKind, Digest, TaskAttempt, TaskAttemptAttemptsExhaustedDisposition,
    TaskAttemptBlockedDisposition, TaskAttemptCanceledDisposition, TaskAttemptCandidateBoundary,
    TaskAttemptCleanupRelease, TaskAttemptDisposition, TaskAttemptDispositionMetadata,
    TaskAttemptEvidence, TaskAttemptEvidenceKind, TaskAttemptFormalCheck,
    TaskAttemptKnownCleanupOutcome, TaskAttemptPermanentFailureDisposition,
    TaskAttemptReleaseProof, TaskAttemptRetryableCause, TaskAttemptRetryableDisposition,
    TaskAttemptRunningBoundary, TaskAttemptVerificationBoundary, WorkerCleanupReceipt, WorkerLease,
    WorkerLeaseNeverLaunchedRelease,
};

use super::{
    LedgerError, TaskAttemptFormalCheckAdmission, TaskAttemptIntegrationAdmission, decode_stored,
    encode, ensure_sprint_not_terminal, load_event_by_id, load_task_integration_receipt_from,
    load_worker_cleanup_evidence_from, reference_mismatch, runner_launch_cleanup_admission,
    sqlite_integer, unsigned_integer, worker_lease_authority,
};

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(super) enum KnownCleanupSourceKind {
    CandidateRejection,
    FormalVerificationFailure,
    LaunchRefusal,
    PolicyCause,
    SensitiveOutputRejection,
    WorkerExit,
}

impl KnownCleanupSourceKind {
    const fn as_str(self) -> &'static str {
        match self {
            Self::CandidateRejection => "CandidateRejection",
            Self::FormalVerificationFailure => "FormalVerificationFailure",
            Self::LaunchRefusal => "LaunchRefusal",
            Self::PolicyCause => "PolicyCause",
            Self::SensitiveOutputRejection => "SensitiveOutputRejection",
            Self::WorkerExit => "WorkerExit",
        }
    }

    fn parse(value: &str) -> Result<Self, LedgerError> {
        match value {
            "CandidateRejection" => Ok(Self::CandidateRejection),
            "FormalVerificationFailure" => Ok(Self::FormalVerificationFailure),
            "LaunchRefusal" => Ok(Self::LaunchRefusal),
            "PolicyCause" => Ok(Self::PolicyCause),
            "SensitiveOutputRejection" => Ok(Self::SensitiveOutputRejection),
            "WorkerExit" => Ok(Self::WorkerExit),
            other => Err(LedgerError::Corrupt {
                entity: "task attempt known-cleanup source",
                detail: format!("unsupported typed source kind `{other}`"),
            }),
        }
    }
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(super) struct KnownCleanupSourceKey {
    pub(super) outcome_rank: i64,
    pub(super) source_at_unix_ms: u64,
    pub(super) source_id: String,
    pub(super) source_kind: KnownCleanupSourceKind,
}

/// Schema-v15 task-attempt accounting, legacy classification, and SQL fences.
///
/// Migration statements intentionally backfill before installing current-row
/// triggers. A schema-v14 acquisition is evidence that an attempt was opened,
/// but never evidence of a current disposition.
pub(super) const MIGRATION_V15: &str = include_str!("task_attempt_authority_v15.sql");

pub(super) fn next_ordinal(
    connection: &Connection,
    sprint_id: &str,
    task_id: &str,
) -> Result<u32, LedgerError> {
    let maximum: Option<i64> = connection.query_row(
        "SELECT MAX(attempt_ordinal) FROM task_attempts
         WHERE sprint_id = ?1 AND task_id = ?2",
        params![sprint_id, task_id],
        |row| row.get(0),
    )?;
    match maximum {
        Some(value) => u32::try_from(unsigned_integer("task_attempt.next_ordinal", value)?)
            .map_err(|_| LedgerError::IntegerOutOfRange("task_attempt.next_ordinal"))?
            .checked_add(1)
            .ok_or(LedgerError::IntegerOutOfRange("task_attempt.next_ordinal")),
        None => Ok(1),
    }
}

pub(super) fn schema_is_installed(connection: &Connection) -> Result<bool, LedgerError> {
    connection
        .query_row(
            "SELECT 1 FROM sqlite_schema
             WHERE type = 'table' AND name = 'task_attempts'",
            [],
            |_| Ok(()),
        )
        .optional()
        .map(|row| row.is_some())
        .map_err(LedgerError::from)
}

const V14_ALL_ACQUISITIONS: &str = "SELECT * FROM worker_lease_acquisitions";
const V15_LEGACY_ACQUISITIONS: &str = r"SELECT acquisition.*
FROM worker_lease_acquisitions acquisition
JOIN task_attempts attempt ON attempt.worker_lease_id = acquisition.lease_id
WHERE attempt.schema_generation = 14";

const LEGACY_ATTEMPT_ADMISSION_BLOCKERS: &str = r"
WITH legacy_acquisitions AS (__LEGACY_ACQUISITIONS__),
legacy_sprints AS (
    SELECT DISTINCT sprint_id FROM legacy_acquisitions
),
blockers(priority, blocker, authority_id) AS (
    SELECT 0, 'pre-v14 worker-lease marker', marker.sprint_id
    FROM worker_lease_legacy_sprints marker
    UNION ALL
    SELECT 5, 'task-worker authority lacks acquisition', launch.launch_id
    FROM runner_launch_intents launch
    LEFT JOIN worker_lease_acquisitions acquisition
      ON acquisition.lease_id = launch.worker_lease_id
    WHERE launch.purpose = 'TaskWorker'
      AND (acquisition.lease_id IS NULL
           OR launch.worker_lease_epoch != acquisition.lease_epoch
           OR launch.sprint_id != acquisition.sprint_id
           OR launch.worker_id != acquisition.worker_id)
    UNION ALL
    SELECT 5, 'task-worker authority lacks acquisition', intent.effect_id
    FROM effect_intents intent
    LEFT JOIN worker_lease_acquisitions acquisition
      ON acquisition.lease_id = intent.worker_lease_id
    WHERE (intent.task_id IS NOT NULL OR intent.worker_id IS NOT NULL)
      AND (acquisition.lease_id IS NULL
           OR intent.worker_lease_epoch != acquisition.lease_epoch
           OR intent.sprint_id != acquisition.sprint_id
           OR intent.task_id != acquisition.task_id
           OR intent.worker_id != acquisition.worker_id)
    UNION ALL
    SELECT 5, 'task-worker authority lacks acquisition', integration.receipt_id
    FROM task_integration_receipts integration
    LEFT JOIN worker_lease_acquisitions acquisition
      ON acquisition.lease_id = integration.worker_lease_id
    WHERE acquisition.lease_id IS NULL
       OR integration.worker_lease_epoch != acquisition.lease_epoch
       OR integration.sprint_id != acquisition.sprint_id
       OR integration.task_id != acquisition.task_id
       OR integration.worker_id != acquisition.worker_id
    UNION ALL
    SELECT 5, 'task-worker authority lacks acquisition', session.session_id
    FROM runner_session_policies session
    LEFT JOIN worker_lease_acquisitions acquisition
      ON acquisition.lease_id = session.worker_lease_id
    WHERE session.purpose = 'TaskWorker'
      AND (acquisition.lease_id IS NULL
           OR session.worker_lease_epoch != acquisition.lease_epoch
           OR session.sprint_id != acquisition.sprint_id
           OR session.worker_id != acquisition.worker_id)
    UNION ALL
    SELECT 5, 'task-worker authority lacks acquisition', observation.observation_id
    FROM effect_observations observation
    LEFT JOIN worker_lease_acquisitions acquisition
      ON acquisition.lease_id = observation.worker_lease_id
    WHERE (observation.task_id IS NOT NULL OR observation.worker_id IS NOT NULL)
      AND (acquisition.lease_id IS NULL
           OR observation.worker_lease_epoch != acquisition.lease_epoch
           OR observation.sprint_id != acquisition.sprint_id
           OR observation.task_id != acquisition.task_id
           OR observation.worker_id != acquisition.worker_id)
    UNION ALL
    SELECT 5, 'task-worker authority lacks acquisition', cleanup.receipt_id
    FROM worker_cleanup_receipts cleanup
    LEFT JOIN worker_lease_acquisitions acquisition
      ON acquisition.lease_id = cleanup.worker_lease_id
    WHERE cleanup.worker_lease_id IS NOT NULL
      AND (acquisition.lease_id IS NULL
           OR cleanup.worker_lease_epoch != acquisition.lease_epoch
           OR cleanup.sprint_id != acquisition.sprint_id)
    UNION ALL
    SELECT 10, 'legacy attempt exceeds budget', acquisition.lease_id
    FROM legacy_acquisitions acquisition
    JOIN sprints sprint ON sprint.sprint_id = acquisition.sprint_id
    WHERE (
        SELECT COUNT(*) FROM legacy_acquisitions counted
        WHERE counted.sprint_id = acquisition.sprint_id
          AND counted.task_id = acquisition.task_id
    ) > COALESCE(
        CASE
          WHEN json_type(CAST(sprint.spec_json AS TEXT),
                         '$.budget.max_attempts_per_task') = 'integer'
          THEN json_extract(CAST(sprint.spec_json AS TEXT),
                            '$.budget.max_attempts_per_task')
        END,
        0
    )
    UNION ALL
    SELECT 20, 'legacy attempt is not integrated and released', acquisition.lease_id
    FROM legacy_acquisitions acquisition
    WHERE NOT EXISTS (
              SELECT 1 FROM task_integration_receipts integration
              WHERE integration.worker_lease_id = acquisition.lease_id
          )
       OR NOT EXISTS (
              SELECT 1 FROM worker_lease_releases release
              WHERE release.lease_id = acquisition.lease_id
          )
    UNION ALL
    SELECT 30, 'legacy task state is not Integrated', acquisition.lease_id
    FROM legacy_acquisitions acquisition
    WHERE COALESCE((
        SELECT json_extract(CAST(event.event_json AS TEXT),
                            '$.payload.TaskStateChanged.to')
        FROM agent_events event
        WHERE event.sprint_id = acquisition.sprint_id
          AND json_extract(CAST(event.event_json AS TEXT), '$.task_id') =
              acquisition.task_id
          AND json_type(CAST(event.event_json AS TEXT),
                        '$.payload.TaskStateChanged') = 'object'
        ORDER BY event.sequence DESC LIMIT 1
    ), '') != 'Integrated'
       OR COALESCE((
        SELECT json_extract(CAST(event.event_json AS TEXT), '$.worker_id')
        FROM agent_events event
        WHERE event.sprint_id = acquisition.sprint_id
          AND json_extract(CAST(event.event_json AS TEXT), '$.task_id') =
              acquisition.task_id
          AND json_type(CAST(event.event_json AS TEXT),
                        '$.payload.TaskStateChanged') = 'object'
        ORDER BY event.sequence DESC LIMIT 1
    ), '') != acquisition.worker_id
    UNION ALL
    SELECT 40, 'legacy graph coverage is not bijective',
           graph.sprint_id || '/' || json_extract(task.value, '$.task_id')
    FROM sprint_task_graphs graph,
         json_each(CAST(graph.graph_json AS TEXT), '$.tasks') task
    WHERE graph.sprint_id IN (SELECT sprint_id FROM legacy_sprints)
      AND (
          SELECT COUNT(*) FROM legacy_acquisitions acquisition
          WHERE acquisition.sprint_id = graph.sprint_id
            AND acquisition.task_id = json_extract(task.value, '$.task_id')
      ) != 1
    UNION ALL
    SELECT 40, 'legacy graph coverage is not bijective',
           acquisition.sprint_id || '/' || acquisition.task_id
    FROM legacy_acquisitions acquisition
    WHERE NOT EXISTS (
        SELECT 1
        FROM sprint_task_graphs graph,
             json_each(CAST(graph.graph_json AS TEXT), '$.tasks') task
        WHERE graph.sprint_id = acquisition.sprint_id
          AND json_extract(task.value, '$.task_id') = acquisition.task_id
    )
    UNION ALL
    SELECT 40, 'legacy graph coverage is not bijective', graph.sprint_id
    FROM sprint_task_graphs graph
    WHERE graph.sprint_id IN (SELECT sprint_id FROM legacy_sprints)
      AND json_array_length(CAST(graph.graph_json AS TEXT), '$.tasks') != (
          SELECT COUNT(DISTINCT json_extract(task.value, '$.task_id'))
          FROM json_each(CAST(graph.graph_json AS TEXT), '$.tasks') task
      )
    UNION ALL
    SELECT 50, 'legacy integration chain is not exact', acquisition.lease_id
    FROM legacy_acquisitions acquisition
    WHERE (
        SELECT COUNT(*) FROM task_integration_receipts integration
        WHERE integration.worker_lease_id = acquisition.lease_id
    ) != 1
       OR NOT EXISTS (
        SELECT 1
        FROM task_integration_receipts integration
        JOIN effect_intents intent ON intent.effect_id = integration.effect_id
        JOIN effect_observations observation
          ON observation.observation_id = integration.observation_id
         AND observation.effect_id = integration.effect_id
        JOIN finish_effect_kinds kind ON kind.effect_id = integration.effect_id
        JOIN runner_launch_intents launch
          ON launch.launch_id = integration.worker_launch_id
        JOIN runner_session_policies session
          ON session.session_id = integration.worker_session_id
        JOIN effect_session_bindings binding ON binding.effect_id = integration.effect_id
        WHERE integration.worker_lease_id = acquisition.lease_id
          AND integration.worker_lease_epoch = acquisition.lease_epoch
          AND integration.sprint_id = acquisition.sprint_id
          AND integration.task_id = acquisition.task_id
          AND integration.worker_id = acquisition.worker_id
          AND integration.contract_version = acquisition.contract_version
          AND integration.integrated_at_unix_ms >= acquisition.acquired_at_unix_ms
          AND launch.sprint_id = acquisition.sprint_id
          AND launch.purpose = 'TaskWorker'
          AND launch.worker_id = acquisition.worker_id
          AND launch.worker_lease_id = acquisition.lease_id
          AND launch.worker_lease_epoch = acquisition.lease_epoch
          AND session.sprint_id = acquisition.sprint_id
          AND session.launch_id = launch.launch_id
          AND session.purpose = 'TaskWorker'
          AND session.worker_id = acquisition.worker_id
          AND session.worker_lease_id = acquisition.lease_id
          AND session.worker_lease_epoch = acquisition.lease_epoch
          AND binding.sprint_id = acquisition.sprint_id
          AND binding.launch_id = launch.launch_id
          AND binding.session_id = session.session_id
          AND integration.worker_policy_hash = launch.policy_hash
          AND intent.sprint_id = acquisition.sprint_id
          AND intent.task_id = acquisition.task_id
          AND intent.worker_id = acquisition.worker_id
          AND intent.worker_lease_id = acquisition.lease_id
          AND intent.worker_lease_epoch = acquisition.lease_epoch
          AND intent.effect_kind = 'IntegrateChangeSet'
          AND observation.sprint_id = acquisition.sprint_id
          AND observation.task_id = acquisition.task_id
          AND observation.worker_id = acquisition.worker_id
          AND observation.worker_lease_id = acquisition.lease_id
          AND observation.worker_lease_epoch = acquisition.lease_epoch
          AND observation.effect_kind = 'IntegrateChangeSet'
          AND observation.outcome = 'Succeeded'
          AND observation.observed_at_unix_ms = integration.integrated_at_unix_ms
          AND kind.sprint_id = acquisition.sprint_id
          AND kind.effect_kind = 'IntegrateChangeSet'
          AND kind.contract_version = acquisition.contract_version
    )
    UNION ALL
    SELECT 60, 'legacy release and cleanup chain is not exact', acquisition.lease_id
    FROM legacy_acquisitions acquisition
    WHERE NOT EXISTS (
        SELECT 1
        FROM worker_lease_releases release
        JOIN worker_cleanup_receipts cleanup
          ON cleanup.receipt_id = release.cleanup_receipt_id
         AND cleanup.effect_id = release.cleanup_effect_id
         AND cleanup.observation_id = release.cleanup_observation_id
        JOIN effect_intents intent ON intent.effect_id = cleanup.effect_id
        JOIN effect_observations observation
          ON observation.observation_id = cleanup.observation_id
         AND observation.effect_id = cleanup.effect_id
        JOIN finish_effect_kinds kind ON kind.effect_id = cleanup.effect_id
        JOIN runner_launch_intents launch ON launch.launch_id = cleanup.launch_id
        JOIN runner_session_policies session
          ON session.session_id = cleanup.session_id
        JOIN runner_launch_cleanup_admissions admission
          ON admission.launch_id = cleanup.launch_id
         AND admission.cleanup_effect_id = cleanup.effect_id
        JOIN effect_session_bindings binding ON binding.effect_id = cleanup.effect_id
        WHERE release.lease_id = acquisition.lease_id
          AND release.sprint_id = acquisition.sprint_id
          AND release.lease_epoch = acquisition.lease_epoch
          AND release.contract_version = acquisition.contract_version
          AND release.released_at_unix_ms >= acquisition.acquired_at_unix_ms
          AND cleanup.sprint_id = acquisition.sprint_id
          AND cleanup.worker_lease_id = acquisition.lease_id
          AND cleanup.worker_lease_epoch = acquisition.lease_epoch
          AND cleanup.contract_version = acquisition.contract_version
          AND cleanup.cleaned_at_unix_ms = release.released_at_unix_ms
          AND cleanup.cleaned_at_unix_ms = observation.observed_at_unix_ms
          AND cleanup.cleaned_at_unix_ms >= (
              SELECT integration.integrated_at_unix_ms
              FROM task_integration_receipts integration
              WHERE integration.worker_lease_id = acquisition.lease_id
          )
          AND launch.sprint_id = acquisition.sprint_id
          AND launch.purpose = 'TaskWorker'
          AND launch.worker_id = acquisition.worker_id
          AND launch.worker_lease_id = acquisition.lease_id
          AND launch.worker_lease_epoch = acquisition.lease_epoch
          AND session.sprint_id = acquisition.sprint_id
          AND session.launch_id = launch.launch_id
          AND session.purpose = 'TaskWorker'
          AND session.worker_id = acquisition.worker_id
          AND session.worker_lease_id = acquisition.lease_id
          AND session.worker_lease_epoch = acquisition.lease_epoch
          AND cleanup.policy_hash = launch.policy_hash
          AND cleanup.grant_hash = launch.grant_hash
          AND cleanup.policy_version = launch.policy_version
          AND admission.sprint_id = acquisition.sprint_id
          AND admission.session_id = cleanup.session_id
          AND admission.contract_version = acquisition.contract_version
          AND binding.sprint_id = acquisition.sprint_id
          AND binding.launch_id = launch.launch_id
          AND binding.session_id IS NULL
          AND intent.sprint_id = acquisition.sprint_id
          AND intent.worker_lease_id = acquisition.lease_id
          AND intent.worker_lease_epoch = acquisition.lease_epoch
          AND intent.task_id IS NULL
          AND intent.worker_id IS NULL
          AND intent.effect_kind = 'ApplyChangeSet'
          AND observation.sprint_id = acquisition.sprint_id
          AND observation.worker_lease_id = acquisition.lease_id
          AND observation.worker_lease_epoch = acquisition.lease_epoch
          AND observation.task_id IS NULL
          AND observation.worker_id IS NULL
          AND observation.effect_kind = 'ApplyChangeSet'
          AND observation.outcome = 'Succeeded'
          AND kind.sprint_id = acquisition.sprint_id
          AND kind.effect_kind = 'CleanupWorkerDomain'
          AND kind.contract_version = acquisition.contract_version
    )
       OR (
        SELECT COUNT(*) FROM worker_cleanup_receipts cleanup
        WHERE cleanup.worker_lease_id = acquisition.lease_id
    ) != 1
    UNION ALL
    SELECT 70, 'legacy sprint has unresolved effect', intent.effect_id
    FROM effect_intents intent
    LEFT JOIN effect_observations observation ON observation.effect_id = intent.effect_id
    WHERE intent.sprint_id IN (SELECT sprint_id FROM legacy_sprints)
      AND (observation.effect_id IS NULL OR observation.outcome = 'Unknown')
    UNION ALL
    SELECT 80, 'legacy sprint has unresolved mutation', unresolved.effect_id
    FROM unresolved_mutation_effects unresolved
    WHERE unresolved.sprint_id IN (SELECT sprint_id FROM legacy_sprints)
    UNION ALL
    SELECT 90, 'legacy sprint has unresolved runner preparation', preparation.attempt_id
    FROM runner_launch_preparation_attempts preparation
    LEFT JOIN runner_launch_preparation_outcomes outcome
      ON outcome.attempt_id = preparation.attempt_id
    WHERE preparation.sprint_id IN (SELECT sprint_id FROM legacy_sprints)
      AND (
          outcome.attempt_id IS NULL
          OR outcome.disposition = 'NativeEffectUncertain'
          OR (
              outcome.disposition = 'RefusedBeforeNativeEffect'
              AND EXISTS (
                  SELECT 1 FROM runner_session_policies session
                  WHERE session.sprint_id = preparation.sprint_id
                    AND session.launch_id = preparation.launch_id
              )
          )
          OR (
              outcome.disposition = 'HeldChildPrepared'
              AND NOT EXISTS (
                  SELECT 1 FROM runner_session_policies session
                  WHERE session.sprint_id = preparation.sprint_id
                    AND session.launch_id = preparation.launch_id
              )
          )
      )
    UNION ALL
    SELECT 100, 'legacy sprint has effect payload gap', gap.effect_id
    FROM legacy_effect_payload_gaps gap
    WHERE gap.sprint_id IN (SELECT sprint_id FROM legacy_sprints)
    UNION ALL
    SELECT 110, 'legacy sprint has finish receipt gap', gap.effect_id
    FROM legacy_finish_receipt_gaps gap
    WHERE gap.sprint_id IN (SELECT sprint_id FROM legacy_sprints)
    UNION ALL
    SELECT 115, 'legacy sprint has dynamic finish receipt gap', kind.effect_id
    FROM finish_effect_kinds kind
    JOIN effect_observations observation ON observation.effect_id = kind.effect_id
    WHERE kind.sprint_id IN (SELECT sprint_id FROM legacy_sprints)
      AND observation.outcome = 'Succeeded'
      AND NOT (
          (kind.effect_kind = 'IntegrateChangeSet' AND EXISTS (
              SELECT 1 FROM task_integration_receipts receipt
              WHERE receipt.effect_id = kind.effect_id
                AND receipt.observation_id = observation.observation_id
                AND receipt.sprint_id = kind.sprint_id
          ))
          OR (kind.effect_kind = 'ApplyChangeSet' AND EXISTS (
              SELECT 1 FROM application_receipts receipt
              WHERE receipt.effect_id = kind.effect_id
                AND receipt.observation_id = observation.observation_id
                AND receipt.sprint_id = kind.sprint_id
          ))
          OR (kind.effect_kind = 'CleanupWorkerDomain' AND EXISTS (
              SELECT 1 FROM worker_cleanup_receipts receipt
              WHERE receipt.effect_id = kind.effect_id
                AND receipt.observation_id = observation.observation_id
                AND receipt.sprint_id = kind.sprint_id
          ))
          OR (kind.effect_kind = 'RollbackChangeSet' AND EXISTS (
              SELECT 1 FROM rollback_receipts receipt
              WHERE receipt.effect_id = kind.effect_id
                AND receipt.observation_id = observation.observation_id
                AND receipt.sprint_id = kind.sprint_id
          ))
      )
    UNION ALL
    SELECT 120, 'legacy sprint has open cleanup admission', admission.launch_id
    FROM runner_launch_cleanup_admissions admission
    LEFT JOIN effect_observations observation
      ON observation.effect_id = admission.cleanup_effect_id
    WHERE admission.sprint_id IN (SELECT sprint_id FROM legacy_sprints)
      AND (
          observation.effect_id IS NULL
          OR (
              observation.outcome = 'Succeeded'
              AND NOT EXISTS (
              SELECT 1 FROM worker_cleanup_receipts cleanup
              WHERE cleanup.sprint_id = admission.sprint_id
                AND cleanup.launch_id = admission.launch_id
                AND cleanup.session_id = admission.session_id
                AND cleanup.effect_id = admission.cleanup_effect_id
                AND cleanup.observation_id = observation.observation_id
              )
          )
          OR (
              observation.outcome IN ('FailedBeforeEffect', 'CancelledBeforeEffect')
              AND NOT EXISTS (
                  SELECT 1
                  FROM runner_launch_preparation_attempts preparation
                  JOIN runner_launch_preparation_outcomes outcome
                    ON outcome.attempt_id = preparation.attempt_id
                  WHERE preparation.sprint_id = admission.sprint_id
                    AND preparation.launch_id = admission.launch_id
                    AND preparation.cleanup_effect_id = admission.cleanup_effect_id
                    AND outcome.disposition = 'RefusedBeforeNativeEffect'
                    AND NOT EXISTS (
                        SELECT 1 FROM runner_session_policies session
                        WHERE session.sprint_id = preparation.sprint_id
                          AND session.launch_id = preparation.launch_id
                    )
              )
          )
          OR observation.outcome NOT IN (
              'Succeeded', 'FailedBeforeEffect', 'CancelledBeforeEffect'
          )
      )
    UNION ALL
    SELECT 125, 'legacy sprint has incomplete effect payload', intent.effect_id
    FROM effect_intents intent
    WHERE intent.sprint_id IN (SELECT sprint_id FROM legacy_sprints)
      AND (
          NOT EXISTS (
              SELECT 1 FROM effect_request_payloads request
              WHERE request.effect_id = intent.effect_id
                AND request.sprint_id = intent.sprint_id
                AND request.request_digest = intent.request_digest
                AND request.contract_version = intent.contract_version
          )
          OR EXISTS (
              SELECT 1 FROM effect_observations observation
              WHERE observation.effect_id = intent.effect_id
                AND NOT EXISTS (
                    SELECT 1 FROM effect_evidence_payloads evidence
                    WHERE evidence.effect_id = observation.effect_id
                      AND evidence.observation_id = observation.observation_id
                      AND evidence.sprint_id = observation.sprint_id
                      AND evidence.evidence_digest = observation.evidence_digest
                      AND evidence.contract_version = observation.contract_version
                )
          )
      )
    UNION ALL
    SELECT 127, 'legacy sprint has incompatible terminal authority', terminal.sprint_id
    FROM (
        SELECT sprint_id FROM sprint_non_success_terminal_outcomes
        UNION ALL
        SELECT sprint_id FROM sprint_terminal_states
        WHERE terminal_state != 'Completed'
    ) terminal
    WHERE terminal.sprint_id IN (SELECT sprint_id FROM legacy_sprints)
)
SELECT blocker, substr(MIN(authority_id), 1, 256),
       COUNT(DISTINCT authority_id)
FROM blockers
GROUP BY priority, blocker
ORDER BY priority ASC
LIMIT 1";

const V15_DERIVED_LEGACY_BLOCKERS: &str = r"
WITH legacy_attempts AS (
    SELECT * FROM task_attempts WHERE schema_generation = 14
),
blockers(priority, blocker, authority_id) AS (
    SELECT 130, 'legacy attempt row does not match acquisition', attempt.attempt_id
    FROM legacy_attempts attempt
    LEFT JOIN worker_lease_acquisitions acquisition
      ON acquisition.lease_id = attempt.worker_lease_id
    WHERE acquisition.lease_id IS NULL
       OR attempt.attempt_id != acquisition.lease_id
       OR attempt.sprint_id != acquisition.sprint_id
       OR attempt.task_id != acquisition.task_id
       OR attempt.worker_id != acquisition.worker_id
       OR attempt.lease_epoch != acquisition.lease_epoch
       OR attempt.opening_event_id != acquisition.acquisition_event_id
       OR attempt.opened_at_unix_ms != acquisition.acquired_at_unix_ms
       OR attempt.contract_version != acquisition.contract_version
       OR attempt.attempt_ordinal != 1
       OR attempt.attempt_json != CAST(json_object(
           'contract_version', acquisition.contract_version,
           'attempt_id', acquisition.lease_id,
           'worker_lease', json(CAST(acquisition.lease_json AS TEXT)),
           'attempt_ordinal', 1,
           'opening_event_id', acquisition.acquisition_event_id,
           'opened_at_unix_ms', acquisition.acquired_at_unix_ms
       ) AS BLOB)
    UNION ALL
    SELECT 135, 'legacy acquisition lacks exact attempt row', acquisition.lease_id
    FROM worker_lease_acquisitions acquisition
    WHERE (
          SELECT COUNT(*) FROM task_attempts attempt
          WHERE attempt.worker_lease_id = acquisition.lease_id
            AND attempt.sprint_id = acquisition.sprint_id
            AND attempt.task_id = acquisition.task_id
            AND attempt.worker_id = acquisition.worker_id
            AND attempt.lease_epoch = acquisition.lease_epoch
            AND attempt.opening_event_id = acquisition.acquisition_event_id
            AND attempt.opened_at_unix_ms = acquisition.acquired_at_unix_ms
            AND attempt.contract_version = acquisition.contract_version
      ) != 1
    UNION ALL
    SELECT 137, 'current attempt lacks active or disposed authority', attempt.attempt_id
    FROM task_attempts attempt
    WHERE attempt.schema_generation = 15
      AND NOT EXISTS (
          SELECT 1 FROM active_worker_leases active
          WHERE active.lease_id = attempt.worker_lease_id
            AND active.sprint_id = attempt.sprint_id
            AND active.task_id = attempt.task_id
            AND active.worker_id = attempt.worker_id
            AND active.lease_epoch = attempt.lease_epoch
      )
      AND NOT EXISTS (
          SELECT 1 FROM task_attempt_dispositions disposition
          WHERE disposition.attempt_id = attempt.attempt_id
            AND disposition.sprint_id = attempt.sprint_id
            AND disposition.task_id = attempt.task_id
            AND disposition.worker_id = attempt.worker_id
            AND disposition.worker_lease_id = attempt.worker_lease_id
            AND disposition.lease_epoch = attempt.lease_epoch
            AND disposition.attempt_ordinal = attempt.attempt_ordinal
            AND disposition.contract_version = attempt.contract_version
      )
    UNION ALL
    SELECT 140, 'legacy classification is not exact safe authority', attempt.attempt_id
    FROM legacy_attempts attempt
    WHERE (
        SELECT COUNT(*) FROM task_attempt_legacy_classifications classification
        WHERE classification.attempt_id = attempt.attempt_id
          AND classification.sprint_id = attempt.sprint_id
          AND classification.task_id = attempt.task_id
          AND classification.attempt_ordinal = attempt.attempt_ordinal
          AND classification.classification = 'LegacyIntegratedReleased'
          AND classification.budget_classification = 'WithinBudget'
          AND classification.classified_at_schema = 15
    ) != 1
    UNION ALL
    SELECT 150, 'legacy attempt has current disposition', disposition.attempt_id
    FROM task_attempt_dispositions disposition
    JOIN legacy_attempts attempt ON attempt.attempt_id = disposition.attempt_id
    UNION ALL
    SELECT 160, 'legacy sprint has Unknown terminalization authority', pending.sprint_id
    FROM sprint_unknown_terminalization_pending pending
    WHERE pending.sprint_id IN (SELECT sprint_id FROM legacy_attempts)
    UNION ALL
    SELECT 170, 'legacy sprint has completion invalidation', invalidation.sprint_id
    FROM task_attempt_legacy_completion_invalidations invalidation
    WHERE invalidation.sprint_id IN (SELECT sprint_id FROM legacy_attempts)
    UNION ALL
    SELECT 180, 'legacy task is mixed with schema-v15 attempts', current.attempt_id
    FROM task_attempts current
    WHERE current.schema_generation = 15
      AND EXISTS (
          SELECT 1 FROM legacy_attempts legacy
          WHERE legacy.sprint_id = current.sprint_id
            AND legacy.task_id = current.task_id
      )
    UNION ALL
    SELECT 190, 'legacy classification is attached to current attempt',
           classification.attempt_id
    FROM task_attempt_legacy_classifications classification
    JOIN task_attempts attempt ON attempt.attempt_id = classification.attempt_id
    WHERE attempt.schema_generation != 14
)
SELECT blocker, substr(MIN(authority_id), 1, 256),
       COUNT(DISTINCT authority_id)
FROM blockers
GROUP BY priority, blocker
ORDER BY priority ASC
LIMIT 1";

fn admission_blocker(
    connection: &Connection,
    query: &str,
) -> Result<Option<(&'static str, String, u64)>, LedgerError> {
    let blocker = connection
        .query_row(query, [], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, i64>(2)?,
            ))
        })
        .optional()?;
    blocker
        .map(|(label, authority_id, count)| {
            let label = migration_blocker_label(&label)?;
            Ok((
                label,
                authority_id,
                unsigned_integer("migration blocker count", count)?,
            ))
        })
        .transpose()
}

fn migration_blocker_label(label: &str) -> Result<&'static str, LedgerError> {
    match label {
        "pre-v14 worker-lease marker" => Ok("pre-v14 worker-lease marker"),
        "task-worker authority lacks acquisition" => Ok("task-worker authority lacks acquisition"),
        "legacy attempt exceeds budget" => Ok("legacy attempt exceeds budget"),
        "legacy attempt is not integrated and released" => {
            Ok("legacy attempt is not integrated and released")
        }
        "legacy task state is not Integrated" => Ok("legacy task state is not Integrated"),
        "legacy graph coverage is not bijective" => Ok("legacy graph coverage is not bijective"),
        "legacy integration chain is not exact" => Ok("legacy integration chain is not exact"),
        "legacy release and cleanup chain is not exact" => {
            Ok("legacy release and cleanup chain is not exact")
        }
        "legacy sprint has unresolved effect" => Ok("legacy sprint has unresolved effect"),
        "legacy sprint has unresolved mutation" => Ok("legacy sprint has unresolved mutation"),
        "legacy sprint has unresolved runner preparation" => {
            Ok("legacy sprint has unresolved runner preparation")
        }
        "legacy sprint has effect payload gap" => Ok("legacy sprint has effect payload gap"),
        "legacy sprint has finish receipt gap" => Ok("legacy sprint has finish receipt gap"),
        "legacy sprint has dynamic finish receipt gap" => {
            Ok("legacy sprint has dynamic finish receipt gap")
        }
        "legacy sprint has open cleanup admission" => {
            Ok("legacy sprint has open cleanup admission")
        }
        "legacy sprint has incomplete effect payload" => {
            Ok("legacy sprint has incomplete effect payload")
        }
        "legacy sprint has incompatible terminal authority" => {
            Ok("legacy sprint has incompatible terminal authority")
        }
        "legacy attempt row does not match acquisition" => {
            Ok("legacy attempt row does not match acquisition")
        }
        "legacy acquisition lacks exact attempt row" => {
            Ok("legacy acquisition lacks exact attempt row")
        }
        "current attempt lacks active or disposed authority" => {
            Ok("current attempt lacks active or disposed authority")
        }
        "legacy classification is not exact safe authority" => {
            Ok("legacy classification is not exact safe authority")
        }
        "legacy attempt has current disposition" => Ok("legacy attempt has current disposition"),
        "legacy sprint has Unknown terminalization authority" => {
            Ok("legacy sprint has Unknown terminalization authority")
        }
        "legacy sprint has completion invalidation" => {
            Ok("legacy sprint has completion invalidation")
        }
        "legacy task is mixed with schema-v15 attempts" => {
            Ok("legacy task is mixed with schema-v15 attempts")
        }
        "legacy classification is attached to current attempt" => {
            Ok("legacy classification is attached to current attempt")
        }
        _ => Err(LedgerError::Corrupt {
            entity: "schema-v14 task-attempt migration admission",
            detail: "blocker query returned an unsupported category".into(),
        }),
    }
}

fn refuse_unsafe_v14_migration(
    blocker: Option<(&'static str, String, u64)>,
) -> Result<(), LedgerError> {
    if let Some((first_blocker, first_authority_id, blocker_count)) = blocker {
        Err(LedgerError::UnsafeV14TaskAttemptMigration {
            first_blocker,
            first_authority_id,
            blocker_count,
        })
    } else {
        Ok(())
    }
}

pub(super) fn validate_v14_task_attempt_migration_admission(
    connection: &Connection,
) -> Result<(), LedgerError> {
    let query =
        LEGACY_ATTEMPT_ADMISSION_BLOCKERS.replace("__LEGACY_ACQUISITIONS__", V14_ALL_ACQUISITIONS);
    refuse_unsafe_v14_migration(admission_blocker(connection, &query)?)
}

pub(super) fn validate_v15_legacy_task_attempt_admission(
    connection: &Connection,
) -> Result<(), LedgerError> {
    connection.execute_batch("SAVEPOINT validate_v15_legacy_task_attempt_admission")?;
    let raw_query = LEGACY_ATTEMPT_ADMISSION_BLOCKERS
        .replace("__LEGACY_ACQUISITIONS__", V15_LEGACY_ACQUISITIONS);
    let validation = (|| {
        refuse_unsafe_v14_migration(admission_blocker(connection, &raw_query)?)?;
        refuse_unsafe_v14_migration(admission_blocker(connection, V15_DERIVED_LEGACY_BLOCKERS)?)
    })();
    if validation.is_ok() {
        connection.execute_batch("RELEASE validate_v15_legacy_task_attempt_admission")?;
    } else {
        connection.execute_batch(
            "ROLLBACK TO validate_v15_legacy_task_attempt_admission;
             RELEASE validate_v15_legacy_task_attempt_admission;",
        )?;
    }
    validation
}

pub(super) fn require_unknown_unresolved_authority_coverage(
    connection: &Connection,
    sprint_id: &str,
    entity: &'static str,
) -> Result<(), LedgerError> {
    let uncovered = connection
        .query_row(
            "SELECT authority_kind, authority_reference_id
             FROM task_attempt_uncovered_uncertain_authorities
             WHERE sprint_id = ?1
             ORDER BY worker_lease_id ASC, lease_epoch ASC,
                      authority_kind ASC, authority_reference_id ASC
             LIMIT 1",
            [sprint_id],
            |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
        )
        .optional()?;
    if let Some((kind, authority_id)) = uncovered {
        Err(reference_mismatch(
            entity,
            format!(
                "unresolved {kind} authority `{authority_id}` is not covered by its owning Unknown disposition"
            ),
        ))
    } else {
        Ok(())
    }
}

pub(super) fn require_exact_unknown_quarantine_authority_set(
    connection: &Connection,
    attempt: &TaskAttempt,
    supplied: &[String],
) -> Result<(), LedgerError> {
    let mut statement = connection.prepare(
        "SELECT authority_reference_id
         FROM task_attempt_canonical_unresolved_authorities
         WHERE worker_lease_id = ?1 AND lease_epoch = ?2
         ORDER BY authority_reference_id ASC",
    )?;
    let expected = statement
        .query_map(
            params![
                attempt.worker_lease.lease_id,
                sqlite_integer(
                    "task_attempt_unknown_quarantine.lease_epoch",
                    attempt.worker_lease.lease_epoch,
                )?,
            ],
            |row| row.get::<_, String>(0),
        )?
        .collect::<Result<Vec<_>, _>>()?;
    if expected == supplied {
        Ok(())
    } else {
        Err(reference_mismatch(
            "task attempt unknown quarantine",
            "uncertain authority references differ from the complete canonical unresolved set",
        ))
    }
}

pub(super) fn reject_legacy_history(
    connection: &Connection,
    sprint_id: &str,
) -> Result<(), LedgerError> {
    let exists = connection
        .query_row(
            "SELECT 1 FROM task_attempt_legacy_classifications
             WHERE sprint_id = ?1 LIMIT 1",
            [sprint_id],
            |_| Ok(()),
        )
        .optional()?
        .is_some();
    if exists {
        Err(reference_mismatch(
            "task attempt acquisition",
            "schema-v14 classified attempt history cannot authorize new current work",
        ))
    } else {
        Ok(())
    }
}

pub(super) fn insert(
    transaction: &Transaction<'_>,
    attempt: &TaskAttempt,
) -> Result<(), LedgerError> {
    let lease = &attempt.worker_lease;
    transaction.execute(
        "INSERT INTO task_attempts (
            attempt_id, sprint_id, task_id, worker_id, worker_lease_id,
            lease_epoch, attempt_ordinal, opening_event_id, opened_at_unix_ms,
            contract_version, schema_generation, attempt_json
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, 15, ?11)",
        params![
            attempt.attempt_id,
            lease.sprint_id,
            lease.task_id,
            lease.worker_id,
            lease.lease_id,
            sqlite_integer("task_attempt.lease_epoch", lease.lease_epoch)?,
            i64::from(attempt.attempt_ordinal),
            attempt.opening_event_id,
            sqlite_integer("task_attempt.opened_at_unix_ms", attempt.opened_at_unix_ms)?,
            i64::from(attempt.contract_version),
            encode("task attempt", attempt)?,
        ],
    )?;
    Ok(())
}

pub(super) fn computed_never_launched_disposition(
    metadata: TaskAttemptDispositionMetadata,
    release: WorkerLeaseNeverLaunchedRelease,
    max_attempts_per_task: u8,
) -> Result<TaskAttemptDisposition, LedgerError> {
    if metadata.attempt != release.attempt {
        return Err(reference_mismatch(
            "never-launched disposition",
            "metadata and release must carry the exact same attempt",
        ));
    }
    let cause = TaskAttemptRetryableCause::NeverLaunched {
        evidence: release.absence_evidence.clone(),
    };
    let release_proof = TaskAttemptReleaseProof::NeverLaunched(release);
    let disposition = if metadata.attempt.attempt_ordinal < u32::from(max_attempts_per_task) {
        TaskAttemptDisposition::Retryable(TaskAttemptRetryableDisposition {
            metadata,
            cause,
            release_proof,
        })
    } else {
        TaskAttemptDisposition::AttemptsExhausted(TaskAttemptAttemptsExhaustedDisposition {
            metadata,
            cause,
            release_proof,
        })
    };
    disposition
        .validate_for_budget(max_attempts_per_task)
        .map_err(LedgerError::Contract)?;
    Ok(disposition)
}

pub(super) fn computed_cleanup_disposition(
    metadata: TaskAttemptDispositionMetadata,
    outcome: TaskAttemptKnownCleanupOutcome,
    release: TaskAttemptCleanupRelease,
    max_attempts_per_task: u8,
) -> Result<TaskAttemptDisposition, LedgerError> {
    if metadata.attempt != release.attempt {
        return Err(reference_mismatch(
            "task attempt cleanup disposition",
            "metadata and cleanup release must carry the exact same attempt",
        ));
    }
    let release_proof = TaskAttemptReleaseProof::Cleanup(release);
    let disposition = match outcome {
        TaskAttemptKnownCleanupOutcome::Retryable(cause)
            if metadata.attempt.attempt_ordinal < u32::from(max_attempts_per_task) =>
        {
            TaskAttemptDisposition::Retryable(TaskAttemptRetryableDisposition {
                metadata,
                cause,
                release_proof,
            })
        }
        TaskAttemptKnownCleanupOutcome::Retryable(cause) => {
            TaskAttemptDisposition::AttemptsExhausted(TaskAttemptAttemptsExhaustedDisposition {
                metadata,
                cause,
                release_proof,
            })
        }
        TaskAttemptKnownCleanupOutcome::PermanentFailure(cause) => {
            TaskAttemptDisposition::PermanentFailure(TaskAttemptPermanentFailureDisposition {
                metadata,
                cause,
                release_proof,
            })
        }
        TaskAttemptKnownCleanupOutcome::Blocked(cause) => {
            TaskAttemptDisposition::Blocked(TaskAttemptBlockedDisposition {
                metadata,
                cause,
                release_proof,
            })
        }
        TaskAttemptKnownCleanupOutcome::Canceled(cause) => {
            TaskAttemptDisposition::Canceled(TaskAttemptCanceledDisposition {
                metadata,
                cause,
                release_proof,
            })
        }
    };
    disposition
        .validate_for_budget(max_attempts_per_task)
        .map_err(LedgerError::Contract)?;
    Ok(disposition)
}

pub(super) fn insert_never_launched_release(
    transaction: &Transaction<'_>,
    release: &WorkerLeaseNeverLaunchedRelease,
    disposition_id: &str,
) -> Result<(), LedgerError> {
    release.validate()?;
    let attempt = &release.attempt;
    let lease = &attempt.worker_lease;
    transaction.execute(
        "INSERT INTO worker_lease_never_launched_releases (
            release_id, disposition_id, attempt_id, sprint_id, task_id, worker_id,
            worker_lease_id, lease_epoch, absence_evidence_id,
            absence_evidence_digest, absence_evidence_bytes, contract_version,
            released_at_unix_ms, release_json
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14)",
        params![
            release.release_id,
            disposition_id,
            attempt.attempt_id,
            lease.sprint_id,
            lease.task_id,
            lease.worker_id,
            lease.lease_id,
            sqlite_integer("never_launched_release.lease_epoch", lease.lease_epoch)?,
            release.absence_evidence.evidence_id,
            release.absence_evidence.digest.as_str(),
            release.absence_evidence.canonical_bytes,
            i64::from(release.contract_version),
            sqlite_integer(
                "never_launched_release.released_at_unix_ms",
                release.released_at_unix_ms,
            )?,
            encode("worker lease never-launched release", release)?,
        ],
    )?;
    Ok(())
}

pub(super) fn insert_running_boundary(
    transaction: &Transaction<'_>,
    boundary: &TaskAttemptRunningBoundary,
) -> Result<(), LedgerError> {
    let attempt = &boundary.attempt;
    let lease = &attempt.worker_lease;
    transaction.execute(
        "INSERT INTO task_attempt_running_boundaries (
            boundary_id, attempt_id, sprint_id, task_id, worker_id, worker_lease_id,
            lease_epoch, runner_launch_id, runner_session_id,
            transition_event_id, contract_version, started_at_unix_ms, boundary_json
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)",
        params![
            boundary.boundary_id,
            attempt.attempt_id,
            lease.sprint_id,
            lease.task_id,
            lease.worker_id,
            lease.lease_id,
            sqlite_integer("task_attempt_running.lease_epoch", lease.lease_epoch)?,
            boundary.runner_launch_id,
            boundary.runner_session_id,
            boundary.transition_event_id,
            i64::from(boundary.contract_version),
            sqlite_integer(
                "task_attempt_running.started_at_unix_ms",
                boundary.started_at_unix_ms
            )?,
            encode("task attempt Running boundary", boundary)?,
        ],
    )?;
    Ok(())
}

pub(super) fn load_running_boundary(
    connection: &Connection,
    boundary_id: &str,
) -> Result<TaskAttemptRunningBoundary, LedgerError> {
    load_running_boundary_inner(connection, boundary_id, false)
}

pub(super) fn load_running_boundary_for_recovery(
    connection: &Connection,
    boundary_id: &str,
) -> Result<TaskAttemptRunningBoundary, LedgerError> {
    load_running_boundary_inner(connection, boundary_id, true)
}

fn load_running_boundary_inner(
    connection: &Connection,
    boundary_id: &str,
    recovery_read: bool,
) -> Result<TaskAttemptRunningBoundary, LedgerError> {
    let stored = connection
        .query_row(
            "SELECT attempt_id, sprint_id, task_id, worker_id, worker_lease_id,
                    lease_epoch, runner_launch_id, runner_session_id,
                    transition_event_id, contract_version, started_at_unix_ms,
                    boundary_json
             FROM task_attempt_running_boundaries
             WHERE boundary_id = ?1",
            [boundary_id],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, i64>(5)?,
                    row.get::<_, String>(6)?,
                    row.get::<_, String>(7)?,
                    row.get::<_, String>(8)?,
                    row.get::<_, i64>(9)?,
                    row.get::<_, i64>(10)?,
                    row.get::<_, Vec<u8>>(11)?,
                ))
            },
        )
        .optional()?
        .ok_or_else(|| LedgerError::ArtifactNotFound {
            entity: "task attempt Running boundary",
            id: boundary_id.to_owned(),
        })?;
    let boundary: TaskAttemptRunningBoundary =
        decode_stored("task attempt Running boundary", &stored.11)?;
    boundary.validate().map_err(|error| LedgerError::Corrupt {
        entity: "task attempt Running boundary",
        detail: error.to_string(),
    })?;
    let attempt = if recovery_read {
        load_for_recovery(connection, &stored.0)?
    } else {
        load(connection, &stored.0)?
    };
    let lease = &attempt.worker_lease;
    if encode("task attempt Running boundary", &boundary)? != stored.11
        || boundary.boundary_id != boundary_id
        || boundary.attempt != attempt
        || lease.sprint_id != stored.1
        || lease.task_id != stored.2
        || lease.worker_id != stored.3
        || lease.lease_id != stored.4
        || lease.lease_epoch != unsigned_integer("task_attempt_running.lease_epoch", stored.5)?
        || boundary.runner_launch_id != stored.6
        || boundary.runner_session_id != stored.7
        || boundary.transition_event_id != stored.8
        || i64::from(boundary.contract_version) != stored.9
        || boundary.started_at_unix_ms
            != unsigned_integer("task_attempt_running.started_at_unix_ms", stored.10)?
    {
        return Err(LedgerError::Corrupt {
            entity: "task attempt Running boundary",
            detail: "canonical Running boundary disagrees with indexed authority".into(),
        });
    }
    Ok(boundary)
}

pub(super) fn insert_verification_boundary(
    transaction: &Transaction<'_>,
    boundary: &TaskAttemptVerificationBoundary,
) -> Result<(), LedgerError> {
    let attempt = &boundary.attempt;
    let lease = &attempt.worker_lease;
    transaction.execute(
        "INSERT INTO task_attempt_verification_boundaries (
            boundary_id, attempt_id, sprint_id, task_id, worker_lease_id,
            lease_epoch, worker_launch_id, worker_session_id, change_set_id,
            sealed_snapshot_id, transition_event_id, terminal_effect_count,
            contract_version, sealed_at_unix_ms, boundary_json
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12,
                   ?13, ?14, ?15)",
        params![
            boundary.boundary_id,
            attempt.attempt_id,
            lease.sprint_id,
            lease.task_id,
            lease.lease_id,
            sqlite_integer("task_attempt_verification.lease_epoch", lease.lease_epoch)?,
            boundary.runner_launch_id,
            boundary.runner_session_id,
            boundary.change_set_id,
            boundary.sealed_snapshot.as_str(),
            boundary.transition_event_id,
            i64::try_from(boundary.terminal_non_cleanup_effects.len()).map_err(|_| {
                LedgerError::IntegerOutOfRange("verification terminal-effect count")
            })?,
            i64::from(boundary.contract_version),
            sqlite_integer(
                "task_attempt_verification.sealed_at_unix_ms",
                boundary.sealed_at_unix_ms,
            )?,
            encode("task attempt verification boundary", boundary)?,
        ],
    )?;
    for (ordinal, terminal) in boundary.terminal_non_cleanup_effects.iter().enumerate() {
        transaction.execute(
            "INSERT INTO task_attempt_verification_terminal_effects (
                verification_boundary_id, sprint_id, ordinal, effect_id,
                observation_id
             ) VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                boundary.boundary_id,
                lease.sprint_id,
                i64::try_from(ordinal).map_err(|_| {
                    LedgerError::IntegerOutOfRange("verification terminal-effect ordinal")
                })?,
                terminal.effect_id,
                terminal.observation_id,
            ],
        )?;
    }
    Ok(())
}

#[allow(clippy::too_many_lines)]
pub(super) fn load_verification_boundary(
    connection: &Connection,
    boundary_id: &str,
) -> Result<TaskAttemptVerificationBoundary, LedgerError> {
    let stored = connection
        .query_row(
            "SELECT attempt_id, sprint_id, task_id, worker_lease_id, lease_epoch,
                    worker_launch_id, worker_session_id, change_set_id,
                    sealed_snapshot_id, transition_event_id, terminal_effect_count,
                    contract_version, sealed_at_unix_ms, boundary_json
             FROM task_attempt_verification_boundaries WHERE boundary_id = ?1",
            [boundary_id],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, i64>(4)?,
                    row.get::<_, String>(5)?,
                    row.get::<_, String>(6)?,
                    row.get::<_, String>(7)?,
                    row.get::<_, String>(8)?,
                    row.get::<_, String>(9)?,
                    row.get::<_, i64>(10)?,
                    row.get::<_, i64>(11)?,
                    row.get::<_, i64>(12)?,
                    row.get::<_, Vec<u8>>(13)?,
                ))
            },
        )
        .optional()?
        .ok_or_else(|| LedgerError::ArtifactNotFound {
            entity: "task attempt verification boundary",
            id: boundary_id.to_owned(),
        })?;
    let boundary: TaskAttemptVerificationBoundary =
        decode_stored("task attempt verification boundary", &stored.13)?;
    boundary.validate().map_err(|error| LedgerError::Corrupt {
        entity: "task attempt verification boundary",
        detail: error.to_string(),
    })?;
    let attempt = load(connection, &stored.0)?;
    let lease = &attempt.worker_lease;
    let linked = connection
        .prepare(
            "SELECT ordinal, sprint_id, effect_id, observation_id
             FROM task_attempt_verification_terminal_effects
             WHERE verification_boundary_id = ?1 ORDER BY ordinal ASC",
        )?
        .query_map([boundary_id], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
            ))
        })?
        .collect::<Result<Vec<_>, _>>()?;
    if encode("task attempt verification boundary", &boundary)? != stored.13
        || boundary.boundary_id != boundary_id
        || boundary.attempt != attempt
        || lease.sprint_id != stored.1
        || lease.task_id != stored.2
        || lease.lease_id != stored.3
        || lease.lease_epoch != unsigned_integer("task_attempt_verification.lease_epoch", stored.4)?
        || boundary.runner_launch_id != stored.5
        || boundary.runner_session_id != stored.6
        || boundary.change_set_id != stored.7
        || boundary.sealed_snapshot.as_str() != stored.8
        || boundary.transition_event_id != stored.9
        || i64::try_from(boundary.terminal_non_cleanup_effects.len()).ok() != Some(stored.10)
        || i64::from(boundary.contract_version) != stored.11
        || boundary.sealed_at_unix_ms
            != unsigned_integer("task_attempt_verification.sealed_at_unix_ms", stored.12)?
        || linked.len() != boundary.terminal_non_cleanup_effects.len()
        || linked.iter().enumerate().any(|(ordinal, stored_link)| {
            i64::try_from(ordinal).ok() != Some(stored_link.0)
                || stored_link.1 != lease.sprint_id
                || stored_link.2 != boundary.terminal_non_cleanup_effects[ordinal].effect_id
                || stored_link.3 != boundary.terminal_non_cleanup_effects[ordinal].observation_id
        })
    {
        return Err(LedgerError::Corrupt {
            entity: "task attempt verification boundary",
            detail: "canonical boundary disagrees with indexed or ordered authority".into(),
        });
    }
    Ok(boundary)
}

pub(super) fn insert_formal_check_admission(
    transaction: &Transaction<'_>,
    admission: &TaskAttemptFormalCheckAdmission,
) -> Result<(), LedgerError> {
    let lease = &admission.attempt.worker_lease;
    transaction.execute(
        "INSERT INTO task_attempt_formal_check_admissions (
            admission_id, attempt_id, sprint_id, task_id, criterion_id,
            criterion_ordinal, effect_id, worker_session_id, sealed_snapshot_id,
            command_spec_json, contract_version, admitted_at_unix_ms,
            admission_json
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12,
                   ?13)",
        params![
            admission.admission_id,
            admission.attempt.attempt_id,
            lease.sprint_id,
            lease.task_id,
            admission.criterion_id,
            i64::from(admission.criterion_ordinal),
            admission.effect_id,
            admission.runner_session_id,
            admission.sealed_snapshot.as_str(),
            encode("formal-check command", &admission.command)?,
            i64::from(admission.contract_version),
            sqlite_integer(
                "task_attempt_formal_admission.admitted_at_unix_ms",
                admission.admitted_at_unix_ms,
            )?,
            encode("task attempt formal-check admission", admission)?,
        ],
    )?;
    Ok(())
}

#[allow(clippy::too_many_lines)]
pub(super) fn load_formal_check_admission(
    connection: &Connection,
    admission_id: &str,
) -> Result<TaskAttemptFormalCheckAdmission, LedgerError> {
    let stored = connection
        .query_row(
            "SELECT attempt_id, sprint_id, task_id, criterion_id,
                    criterion_ordinal, effect_id, worker_session_id,
                    sealed_snapshot_id, command_spec_json, contract_version,
                    admitted_at_unix_ms, admission_json
             FROM task_attempt_formal_check_admissions WHERE admission_id = ?1",
            [admission_id],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, i64>(4)?,
                    row.get::<_, String>(5)?,
                    row.get::<_, String>(6)?,
                    row.get::<_, String>(7)?,
                    row.get::<_, Vec<u8>>(8)?,
                    row.get::<_, i64>(9)?,
                    row.get::<_, i64>(10)?,
                    row.get::<_, Vec<u8>>(11)?,
                ))
            },
        )
        .optional()?
        .ok_or_else(|| LedgerError::ArtifactNotFound {
            entity: "task attempt formal-check admission",
            id: admission_id.to_owned(),
        })?;
    let admission: TaskAttemptFormalCheckAdmission =
        decode_stored("task attempt formal-check admission", &stored.11)?;
    admission.validate().map_err(|error| LedgerError::Corrupt {
        entity: "task attempt formal-check admission",
        detail: error.to_string(),
    })?;
    let attempt = load(connection, &stored.0)?;
    let lease = &attempt.worker_lease;
    if encode("task attempt formal-check admission", &admission)? != stored.11
        || encode("formal-check command", &admission.command)? != stored.8
        || admission.admission_id != admission_id
        || admission.attempt != attempt
        || lease.sprint_id != stored.1
        || lease.task_id != stored.2
        || admission.criterion_id != stored.3
        || i64::from(admission.criterion_ordinal) != stored.4
        || admission.effect_id != stored.5
        || admission.runner_session_id != stored.6
        || admission.sealed_snapshot.as_str() != stored.7
        || i64::from(admission.contract_version) != stored.9
        || admission.admitted_at_unix_ms
            != unsigned_integer(
                "task_attempt_formal_admission.admitted_at_unix_ms",
                stored.10,
            )?
    {
        return Err(LedgerError::Corrupt {
            entity: "task attempt formal-check admission",
            detail: "canonical admission disagrees with indexed authority".into(),
        });
    }
    Ok(admission)
}

pub(super) fn insert_formal_check(
    transaction: &Transaction<'_>,
    admission_id: &str,
    check: &TaskAttemptFormalCheck,
) -> Result<(), LedgerError> {
    let lease = &check.attempt.worker_lease;
    transaction.execute(
        "INSERT INTO task_attempt_formal_checks (
            formal_check_id, admission_id, attempt_id, sprint_id, task_id,
            criterion_id, criterion_ordinal, effect_id, observation_id,
            verification_receipt_id, worker_session_id, sealed_snapshot_id,
            passed, contract_version, checked_at_unix_ms, formal_check_json
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12,
                   ?13, ?14, ?15, ?16)",
        params![
            check.formal_check_id,
            admission_id,
            check.attempt.attempt_id,
            lease.sprint_id,
            lease.task_id,
            check.criterion_id,
            i64::from(check.criterion_ordinal),
            check.effect_id,
            check.observation_id,
            check.verification_receipt.receipt_id,
            check.runner_session_id,
            check.sealed_snapshot.as_str(),
            i64::from(check.verification_receipt.passed()),
            i64::from(check.contract_version),
            sqlite_integer(
                "task_attempt_formal_check.checked_at_unix_ms",
                check.verification_receipt.finished_at_unix_ms,
            )?,
            encode("task attempt formal check", check)?,
        ],
    )?;
    Ok(())
}

pub(super) fn load_formal_check(
    connection: &Connection,
    formal_check_id: &str,
) -> Result<TaskAttemptFormalCheck, LedgerError> {
    let stored = connection
        .query_row(
            "SELECT admission_id, attempt_id, sprint_id, task_id, criterion_id,
                    criterion_ordinal, effect_id, observation_id,
                    verification_receipt_id, worker_session_id,
                    sealed_snapshot_id, passed, contract_version,
                    checked_at_unix_ms, formal_check_json
             FROM task_attempt_formal_checks WHERE formal_check_id = ?1",
            [formal_check_id],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, i64>(5)?,
                    row.get::<_, String>(6)?,
                    row.get::<_, String>(7)?,
                    row.get::<_, String>(8)?,
                    row.get::<_, String>(9)?,
                    row.get::<_, String>(10)?,
                    row.get::<_, i64>(11)?,
                    row.get::<_, i64>(12)?,
                    row.get::<_, i64>(13)?,
                    row.get::<_, Vec<u8>>(14)?,
                ))
            },
        )
        .optional()?
        .ok_or_else(|| LedgerError::ArtifactNotFound {
            entity: "task attempt formal check",
            id: formal_check_id.to_owned(),
        })?;
    let check: TaskAttemptFormalCheck = decode_stored("task attempt formal check", &stored.14)?;
    check.validate().map_err(|error| LedgerError::Corrupt {
        entity: "task attempt formal check",
        detail: error.to_string(),
    })?;
    let admission = load_formal_check_admission(connection, &stored.0)?;
    let attempt = load(connection, &stored.1)?;
    let lease = &attempt.worker_lease;
    if encode("task attempt formal check", &check)? != stored.14
        || check.formal_check_id != formal_check_id
        || check.attempt != attempt
        || admission.attempt != attempt
        || admission.criterion_id != check.criterion_id
        || admission.criterion_ordinal != check.criterion_ordinal
        || admission.effect_id != check.effect_id
        || admission.runner_session_id != check.runner_session_id
        || admission.sealed_snapshot != check.sealed_snapshot
        || lease.sprint_id != stored.2
        || lease.task_id != stored.3
        || check.criterion_id != stored.4
        || i64::from(check.criterion_ordinal) != stored.5
        || check.effect_id != stored.6
        || check.observation_id != stored.7
        || check.verification_receipt.receipt_id != stored.8
        || check.runner_session_id != stored.9
        || check.sealed_snapshot.as_str() != stored.10
        || i64::from(check.verification_receipt.passed()) != stored.11
        || i64::from(check.contract_version) != stored.12
        || check.verification_receipt.finished_at_unix_ms
            != unsigned_integer("task_attempt_formal_check.checked_at_unix_ms", stored.13)?
    {
        return Err(LedgerError::Corrupt {
            entity: "task attempt formal check",
            detail: "canonical formal check disagrees with admission or indexed authority".into(),
        });
    }
    Ok(check)
}

pub(super) fn insert_candidate_boundary(
    transaction: &Transaction<'_>,
    boundary: &TaskAttemptCandidateBoundary,
) -> Result<(), LedgerError> {
    let attempt = &boundary.attempt;
    let lease = &attempt.worker_lease;
    transaction.execute(
        "INSERT INTO task_attempt_candidate_boundaries (
            boundary_id, attempt_id, sprint_id, task_id, worker_lease_id,
            lease_epoch, verification_boundary_id, change_set_id,
            sealed_snapshot_id, transition_event_id, formal_check_count,
            contract_version, admitted_at_unix_ms, boundary_json
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12,
                   ?13, ?14)",
        params![
            boundary.boundary_id,
            attempt.attempt_id,
            lease.sprint_id,
            lease.task_id,
            lease.lease_id,
            sqlite_integer("task_attempt_candidate.lease_epoch", lease.lease_epoch)?,
            boundary.verification_boundary_id,
            boundary.change_set_id,
            boundary.sealed_snapshot.as_str(),
            boundary.transition_event_id,
            i64::try_from(boundary.formal_check_ids.len())
                .map_err(|_| LedgerError::IntegerOutOfRange("candidate formal-check count"))?,
            i64::from(boundary.contract_version),
            sqlite_integer(
                "task_attempt_candidate.admitted_at_unix_ms",
                boundary.admitted_at_unix_ms,
            )?,
            encode("task attempt candidate boundary", boundary)?,
        ],
    )?;
    for (ordinal, (formal_check_id, verification_receipt_id)) in boundary
        .formal_check_ids
        .iter()
        .zip(&boundary.verification_receipt_ids)
        .enumerate()
    {
        let formal = load_formal_check(transaction, formal_check_id)?;
        transaction.execute(
            "INSERT INTO task_attempt_candidate_formal_checks (
                candidate_boundary_id, sprint_id, ordinal, formal_check_id,
                criterion_id, verification_receipt_id
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                boundary.boundary_id,
                lease.sprint_id,
                i64::try_from(ordinal).map_err(|_| {
                    LedgerError::IntegerOutOfRange("candidate formal-check ordinal")
                })?,
                formal_check_id,
                formal.criterion_id,
                verification_receipt_id,
            ],
        )?;
    }
    Ok(())
}

#[allow(clippy::too_many_lines)]
pub(super) fn load_candidate_boundary(
    connection: &Connection,
    boundary_id: &str,
) -> Result<TaskAttemptCandidateBoundary, LedgerError> {
    let stored = connection
        .query_row(
            "SELECT attempt_id, sprint_id, task_id, worker_lease_id, lease_epoch,
                    verification_boundary_id, change_set_id, sealed_snapshot_id,
                    transition_event_id, formal_check_count, contract_version,
                    admitted_at_unix_ms, boundary_json
             FROM task_attempt_candidate_boundaries WHERE boundary_id = ?1",
            [boundary_id],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, i64>(4)?,
                    row.get::<_, String>(5)?,
                    row.get::<_, String>(6)?,
                    row.get::<_, String>(7)?,
                    row.get::<_, String>(8)?,
                    row.get::<_, i64>(9)?,
                    row.get::<_, i64>(10)?,
                    row.get::<_, i64>(11)?,
                    row.get::<_, Vec<u8>>(12)?,
                ))
            },
        )
        .optional()?
        .ok_or_else(|| LedgerError::ArtifactNotFound {
            entity: "task attempt candidate boundary",
            id: boundary_id.to_owned(),
        })?;
    let boundary: TaskAttemptCandidateBoundary =
        decode_stored("task attempt candidate boundary", &stored.12)?;
    boundary.validate().map_err(|error| LedgerError::Corrupt {
        entity: "task attempt candidate boundary",
        detail: error.to_string(),
    })?;
    let attempt = load(connection, &stored.0)?;
    let verification = load_verification_boundary(connection, &stored.5)?;
    let lease = &attempt.worker_lease;
    let linked = connection
        .prepare(
            "SELECT ordinal, sprint_id, formal_check_id, criterion_id,
                    verification_receipt_id
             FROM task_attempt_candidate_formal_checks
             WHERE candidate_boundary_id = ?1 ORDER BY ordinal ASC",
        )?
        .query_map([boundary_id], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, String>(4)?,
            ))
        })?
        .collect::<Result<Vec<_>, _>>()?;
    if encode("task attempt candidate boundary", &boundary)? != stored.12
        || boundary.boundary_id != boundary_id
        || boundary.attempt != attempt
        || verification.attempt != attempt
        || boundary.verification_boundary_id != verification.boundary_id
        || boundary.change_set_id != verification.change_set_id
        || boundary.sealed_snapshot != verification.sealed_snapshot
        || lease.sprint_id != stored.1
        || lease.task_id != stored.2
        || lease.lease_id != stored.3
        || lease.lease_epoch != unsigned_integer("task_attempt_candidate.lease_epoch", stored.4)?
        || boundary.verification_boundary_id != stored.5
        || boundary.change_set_id != stored.6
        || boundary.sealed_snapshot.as_str() != stored.7
        || boundary.transition_event_id != stored.8
        || i64::try_from(boundary.formal_check_ids.len()).ok() != Some(stored.9)
        || i64::from(boundary.contract_version) != stored.10
        || boundary.admitted_at_unix_ms
            != unsigned_integer("task_attempt_candidate.admitted_at_unix_ms", stored.11)?
        || linked.len() != boundary.formal_check_ids.len()
        || linked.iter().enumerate().any(|(ordinal, link)| {
            let formal = load_formal_check(connection, &link.2);
            i64::try_from(ordinal).ok() != Some(link.0)
                || link.1 != lease.sprint_id
                || link.2 != boundary.formal_check_ids[ordinal]
                || link.4 != boundary.verification_receipt_ids[ordinal]
                || formal.is_err()
                || formal.is_ok_and(|value| {
                    value.criterion_id != link.3 || value.verification_receipt.receipt_id != link.4
                })
        })
    {
        return Err(LedgerError::Corrupt {
            entity: "task attempt candidate boundary",
            detail: "canonical candidate disagrees with phase or ordered check authority".into(),
        });
    }
    Ok(boundary)
}

pub(super) fn insert_integration_admission(
    transaction: &Transaction<'_>,
    admission: &TaskAttemptIntegrationAdmission,
    request_json: &[u8],
) -> Result<(), LedgerError> {
    let candidate = &admission.candidate_boundary;
    let attempt = &candidate.attempt;
    let lease = &attempt.worker_lease;
    transaction.execute(
        "INSERT INTO task_attempt_integration_admissions (
            admission_id, attempt_id, candidate_boundary_id, sprint_id,
            task_id, worker_id, worker_lease_id, lease_epoch, effect_id,
            worker_launch_id, worker_session_id, input_snapshot_id,
            result_snapshot_id, contract_version, admitted_at_unix_ms,
            request_json, admission_json
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12,
                   ?13, ?14, ?15, ?16, ?17)",
        params![
            admission.admission_id,
            attempt.attempt_id,
            candidate.boundary_id,
            lease.sprint_id,
            lease.task_id,
            lease.worker_id,
            lease.lease_id,
            sqlite_integer("task_attempt_integration.lease_epoch", lease.lease_epoch)?,
            admission.effect_id,
            admission.runner_launch_id,
            admission.runner_session_id,
            admission.input_snapshot.as_str(),
            admission.result_snapshot.as_str(),
            i64::from(admission.contract_version),
            sqlite_integer(
                "task_attempt_integration.admitted_at_unix_ms",
                admission.admitted_at_unix_ms,
            )?,
            request_json,
            encode("task attempt integration admission", admission)?,
        ],
    )?;
    Ok(())
}

#[allow(clippy::too_many_lines)]
pub(super) fn load_integration_admission(
    connection: &Connection,
    admission_id: &str,
) -> Result<TaskAttemptIntegrationAdmission, LedgerError> {
    let stored = connection
        .query_row(
            "SELECT attempt_id, candidate_boundary_id, sprint_id, task_id,
                    worker_id, worker_lease_id, lease_epoch, effect_id,
                    worker_launch_id, worker_session_id, input_snapshot_id,
                    result_snapshot_id, contract_version, admitted_at_unix_ms,
                    request_json, admission_json
             FROM task_attempt_integration_admissions WHERE admission_id = ?1",
            [admission_id],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, String>(5)?,
                    row.get::<_, i64>(6)?,
                    row.get::<_, String>(7)?,
                    row.get::<_, String>(8)?,
                    row.get::<_, String>(9)?,
                    row.get::<_, String>(10)?,
                    row.get::<_, String>(11)?,
                    row.get::<_, i64>(12)?,
                    row.get::<_, i64>(13)?,
                    row.get::<_, Vec<u8>>(14)?,
                    row.get::<_, Vec<u8>>(15)?,
                ))
            },
        )
        .optional()?
        .ok_or_else(|| LedgerError::ArtifactNotFound {
            entity: "task attempt integration admission",
            id: admission_id.to_owned(),
        })?;
    let admission: TaskAttemptIntegrationAdmission =
        decode_stored("task attempt integration admission", &stored.15)?;
    admission.validate().map_err(|error| LedgerError::Corrupt {
        entity: "task attempt integration admission",
        detail: error.to_string(),
    })?;
    let candidate = load_candidate_boundary(connection, &stored.1)?;
    let attempt = load(connection, &stored.0)?;
    let lease = &attempt.worker_lease;
    if encode("task attempt integration admission", &admission)? != stored.15
        || admission.admission_id != admission_id
        || admission.candidate_boundary != candidate
        || candidate.attempt != attempt
        || lease.sprint_id != stored.2
        || lease.task_id != stored.3
        || lease.worker_id != stored.4
        || lease.lease_id != stored.5
        || lease.lease_epoch != unsigned_integer("task_attempt_integration.lease_epoch", stored.6)?
        || admission.effect_id != stored.7
        || admission.runner_launch_id != stored.8
        || admission.runner_session_id != stored.9
        || admission.input_snapshot.as_str() != stored.10
        || admission.result_snapshot.as_str() != stored.11
        || i64::from(admission.contract_version) != stored.12
        || admission.admitted_at_unix_ms
            != unsigned_integer("task_attempt_integration.admitted_at_unix_ms", stored.13)?
    {
        return Err(LedgerError::Corrupt {
            entity: "task attempt integration admission",
            detail: "canonical integration admission disagrees with indexed authority".into(),
        });
    }
    Ok(admission)
}

pub(super) fn load_integration_admission_request(
    connection: &Connection,
    admission_id: &str,
) -> Result<Vec<u8>, LedgerError> {
    connection
        .query_row(
            "SELECT request_json FROM task_attempt_integration_admissions
             WHERE admission_id = ?1",
            [admission_id],
            |row| row.get::<_, Vec<u8>>(0),
        )
        .optional()?
        .ok_or_else(|| LedgerError::ArtifactNotFound {
            entity: "task attempt integration admission request",
            id: admission_id.to_owned(),
        })
}

pub(super) fn insert_integrated_result_coverage(
    transaction: &Transaction<'_>,
    disposition_id: &str,
    receipt_id: &str,
    admission_id: &str,
    attempt_id: &str,
) -> Result<(), LedgerError> {
    transaction.execute(
        "INSERT INTO task_attempt_integrated_result_coverage (
            disposition_id, receipt_id, admission_id, attempt_id
         ) VALUES (?1, ?2, ?3, ?4)",
        params![disposition_id, receipt_id, admission_id, attempt_id],
    )?;
    Ok(())
}

pub(super) fn require_exact_integrated_result_coverage(
    connection: &Connection,
    disposition_id: &str,
    receipt_id: &str,
    admission_id: &str,
    attempt_id: &str,
) -> Result<(), LedgerError> {
    let (related_count, exact_count) = connection.query_row(
        "SELECT COUNT(*),
                COALESCE(SUM(
                    disposition_id = ?1 AND receipt_id = ?2
                    AND admission_id = ?3 AND attempt_id = ?4
                ), 0)
         FROM task_attempt_integrated_result_coverage
         WHERE disposition_id = ?1 OR receipt_id = ?2
            OR admission_id = ?3 OR attempt_id = ?4",
        params![disposition_id, receipt_id, admission_id, attempt_id],
        |row| Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?)),
    )?;
    if related_count != 1 || exact_count != 1 {
        return Err(LedgerError::Corrupt {
            entity: "task attempt integrated-result coverage",
            detail: "coverage is absent, crossed, or duplicated".into(),
        });
    }
    Ok(())
}

pub(super) fn insert_cleanup_result_coverage(
    transaction: &Transaction<'_>,
    disposition_id: &str,
    attempt: &TaskAttempt,
    receipt: &WorkerCleanupReceipt,
) -> Result<(), LedgerError> {
    let lease = &attempt.worker_lease;
    transaction.execute(
        "INSERT INTO task_attempt_cleanup_result_coverage (
            cleanup_receipt_id, disposition_id, attempt_id, sprint_id,
            worker_lease_id, lease_epoch, cleanup_effect_id, contract_version
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
        params![
            receipt.receipt_id,
            disposition_id,
            attempt.attempt_id,
            lease.sprint_id,
            lease.lease_id,
            sqlite_integer(
                "task_attempt_cleanup_coverage.lease_epoch",
                lease.lease_epoch,
            )?,
            receipt.effect_id,
            i64::from(attempt.contract_version),
        ],
    )?;
    Ok(())
}

pub(super) fn require_exact_cleanup_result_coverage(
    connection: &Connection,
    cleanup_receipt_id: &str,
    disposition_id: &str,
    attempt: &TaskAttempt,
    cleanup_effect_id: &str,
) -> Result<(), LedgerError> {
    let lease = &attempt.worker_lease;
    let (related_count, exact_count) = connection.query_row(
        "SELECT COUNT(*),
                COALESCE(SUM(
                    cleanup_receipt_id = ?1 AND disposition_id = ?2
                    AND attempt_id = ?3 AND sprint_id = ?4
                    AND worker_lease_id = ?5 AND lease_epoch = ?6
                    AND cleanup_effect_id = ?7 AND contract_version = ?8
                ), 0)
         FROM task_attempt_cleanup_result_coverage
         WHERE cleanup_receipt_id = ?1 OR disposition_id = ?2
            OR attempt_id = ?3 OR worker_lease_id = ?5
            OR cleanup_effect_id = ?7",
        params![
            cleanup_receipt_id,
            disposition_id,
            attempt.attempt_id,
            lease.sprint_id,
            lease.lease_id,
            sqlite_integer(
                "task_attempt_cleanup_coverage.lease_epoch",
                lease.lease_epoch,
            )?,
            cleanup_effect_id,
            i64::from(attempt.contract_version),
        ],
        |row| Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?)),
    )?;
    if related_count != 1 || exact_count != 1 {
        return Err(LedgerError::Corrupt {
            entity: "task attempt cleanup-result coverage",
            detail: "coverage is absent, crossed, or duplicated".into(),
        });
    }
    Ok(())
}

struct DispositionStorage<'a> {
    kind: &'static str,
    cause_kind: Option<&'static str>,
    cause_launch_id: Option<&'a str>,
    cause_session_id: Option<&'a str>,
    cause_formal_check_id: Option<&'a str>,
    cause_candidate_boundary_id: Option<&'a str>,
    cause_effect_id: Option<&'a str>,
    cause_observation_id: Option<&'a str>,
    cause_authority_id: Option<&'a str>,
    uncertainty_id: Option<&'a str>,
    uncertain_authority_ids: &'a [String],
    candidate_boundary_id: Option<&'a str>,
    integration_receipt_id: Option<&'a str>,
    cleanup_receipt_id: Option<&'a str>,
    never_launched_release_id: Option<&'a str>,
    release_id: Option<&'a str>,
    evidence: &'a TaskAttemptEvidence,
}

#[derive(Serialize)]
struct DispositionSqlIndex<'a> {
    contract_version: u32,
    disposition_id: &'a str,
    attempt_id: &'a str,
    sprint_id: &'a str,
    task_id: &'a str,
    worker_id: &'a str,
    worker_lease_id: &'a str,
    lease_epoch: u64,
    attempt_ordinal: u32,
    from_state: String,
    transition_event_id: &'a str,
    disposed_at_unix_ms: u64,
    disposition_kind: &'static str,
    cause_kind: Option<&'static str>,
    cause_launch_id: Option<&'a str>,
    cause_session_id: Option<&'a str>,
    cause_formal_check_id: Option<&'a str>,
    cause_candidate_boundary_id: Option<&'a str>,
    cause_effect_id: Option<&'a str>,
    cause_observation_id: Option<&'a str>,
    cause_authority_id: Option<&'a str>,
    cause_subject_id: Option<&'a str>,
    uncertainty_id: Option<&'a str>,
    uncertain_authority_ids: &'a [String],
    candidate_boundary_id: Option<&'a str>,
    candidate_boundary_digest: Option<String>,
    integration_receipt_id: Option<&'a str>,
    integration_receipt_digest: Option<String>,
    cleanup_receipt_id: Option<&'a str>,
    cleanup_receipt_digest: Option<String>,
    never_launched_release_id: Option<&'a str>,
    never_launched_release_digest: Option<String>,
    release_id: Option<&'a str>,
    evidence_id: &'a str,
    evidence_kind: &'static str,
    evidence_digest: &'a str,
}

fn evidence_kind_name(kind: TaskAttemptEvidenceKind) -> &'static str {
    match kind {
        TaskAttemptEvidenceKind::Integrated => "Integrated",
        TaskAttemptEvidenceKind::NeverLaunched => "NeverLaunched",
        TaskAttemptEvidenceKind::LaunchRefusedBeforeNativeEffect => {
            "LaunchRefusedBeforeNativeEffect"
        }
        TaskAttemptEvidenceKind::KnownWorkerExit => "KnownWorkerExit",
        TaskAttemptEvidenceKind::FormalVerificationFailed => "FormalVerificationFailed",
        TaskAttemptEvidenceKind::CandidateRejectedKnown => "CandidateRejectedKnown",
        TaskAttemptEvidenceKind::SensitiveOutputRejected => "SensitiveOutputRejected",
        TaskAttemptEvidenceKind::PermanentContractViolation => "PermanentContractViolation",
        TaskAttemptEvidenceKind::CriterionProvenUnsatisfiable => "CriterionProvenUnsatisfiable",
        TaskAttemptEvidenceKind::AuthorityExpansionRequired => "AuthorityExpansionRequired",
        TaskAttemptEvidenceKind::VerifiedDependencyUnavailable => "VerifiedDependencyUnavailable",
        TaskAttemptEvidenceKind::OperatorCanceled => "OperatorCanceled",
        TaskAttemptEvidenceKind::UnknownTerminalEffect => "UnknownTerminalEffect",
        TaskAttemptEvidenceKind::UncertainAuthority => "UncertainAuthority",
    }
}

#[allow(clippy::type_complexity)] // Closed tuple mirrors the normalized cause reference columns.
fn retryable_cause_storage(
    cause: &TaskAttemptRetryableCause,
) -> (
    &'static str,
    Option<&str>,
    Option<&str>,
    Option<&str>,
    Option<&str>,
    Option<&str>,
    Option<&str>,
    &TaskAttemptEvidence,
) {
    match cause {
        TaskAttemptRetryableCause::NeverLaunched { evidence } => (
            "NeverLaunched",
            None,
            None,
            None,
            None,
            None,
            None,
            evidence,
        ),
        TaskAttemptRetryableCause::LaunchRefusedBeforeNativeEffect {
            launch_id,
            evidence,
        } => (
            "LaunchRefusedBeforeNativeEffect",
            Some(launch_id),
            None,
            None,
            None,
            None,
            None,
            evidence,
        ),
        TaskAttemptRetryableCause::KnownWorkerExit {
            launch_id,
            session_id,
            evidence,
        } => (
            "KnownWorkerExit",
            Some(launch_id),
            Some(session_id),
            None,
            None,
            None,
            None,
            evidence,
        ),
        TaskAttemptRetryableCause::FormalVerificationFailed {
            formal_check_id,
            evidence,
        } => (
            "FormalVerificationFailed",
            None,
            None,
            Some(formal_check_id),
            None,
            None,
            None,
            evidence,
        ),
        TaskAttemptRetryableCause::CandidateRejectedKnown {
            candidate_boundary_id,
            evidence,
        } => (
            "CandidateRejectedKnown",
            None,
            None,
            None,
            Some(candidate_boundary_id),
            None,
            None,
            evidence,
        ),
        TaskAttemptRetryableCause::SensitiveOutputRejected {
            effect_id,
            evidence,
        } => (
            "SensitiveOutputRejected",
            None,
            None,
            None,
            None,
            Some(effect_id),
            Some(evidence.evidence_id.as_str()),
            evidence,
        ),
    }
}

fn release_storage(release: &TaskAttemptReleaseProof) -> (Option<&str>, Option<&str>, &str) {
    match release {
        TaskAttemptReleaseProof::Cleanup(value) => (
            Some(value.cleanup_receipt.receipt_id.as_str()),
            None,
            value.release_id.as_str(),
        ),
        TaskAttemptReleaseProof::NeverLaunched(value) => (
            None,
            Some(value.release_id.as_str()),
            value.release_id.as_str(),
        ),
    }
}

#[allow(clippy::too_many_lines)]
fn disposition_storage(disposition: &TaskAttemptDisposition) -> DispositionStorage<'_> {
    match disposition {
        TaskAttemptDisposition::Integrated(value) => DispositionStorage {
            kind: "Integrated",
            cause_kind: None,
            cause_launch_id: None,
            cause_session_id: None,
            cause_formal_check_id: None,
            cause_candidate_boundary_id: None,
            cause_effect_id: None,
            cause_observation_id: None,
            cause_authority_id: None,
            uncertainty_id: None,
            uncertain_authority_ids: &[],
            candidate_boundary_id: Some(value.candidate_boundary.boundary_id.as_str()),
            integration_receipt_id: Some(value.integration_receipt.receipt_id.as_str()),
            cleanup_receipt_id: None,
            never_launched_release_id: None,
            release_id: None,
            evidence: &value.evidence,
        },
        TaskAttemptDisposition::Retryable(value) => {
            known_disposition_storage("Retryable", &value.cause, &value.release_proof)
        }
        TaskAttemptDisposition::AttemptsExhausted(value) => {
            known_disposition_storage("AttemptsExhausted", &value.cause, &value.release_proof)
        }
        TaskAttemptDisposition::PermanentFailure(value) => {
            let (cause_kind, authority_id, evidence) = match &value.cause {
                crate::TaskAttemptPermanentFailureCause::PermanentContractViolation {
                    evidence,
                    ..
                } => (
                    "PermanentContractViolation",
                    evidence.evidence_id.as_str(),
                    evidence,
                ),
                crate::TaskAttemptPermanentFailureCause::CriterionProvenUnsatisfiable {
                    evidence,
                    ..
                } => (
                    "CriterionProvenUnsatisfiable",
                    evidence.evidence_id.as_str(),
                    evidence,
                ),
            };
            nonretryable_release_storage(
                "PermanentFailure",
                cause_kind,
                authority_id,
                evidence,
                &value.release_proof,
            )
        }
        TaskAttemptDisposition::Blocked(value) => {
            let (cause_kind, authority_id, evidence) = match &value.cause {
                crate::TaskAttemptBlockedCause::AuthorityExpansionRequired { evidence, .. } => (
                    "AuthorityExpansionRequired",
                    evidence.evidence_id.as_str(),
                    evidence,
                ),
                crate::TaskAttemptBlockedCause::VerifiedDependencyUnavailable {
                    evidence, ..
                } => (
                    "VerifiedDependencyUnavailable",
                    evidence.evidence_id.as_str(),
                    evidence,
                ),
            };
            nonretryable_release_storage(
                "Blocked",
                cause_kind,
                authority_id,
                evidence,
                &value.release_proof,
            )
        }
        TaskAttemptDisposition::Canceled(value) => nonretryable_release_storage(
            "Canceled",
            "OperatorCanceled",
            value.cause.evidence.evidence_id.as_str(),
            &value.cause.evidence,
            &value.release_proof,
        ),
        TaskAttemptDisposition::UnknownCleaned(value) => DispositionStorage {
            kind: "UnknownCleaned",
            cause_kind: None,
            cause_launch_id: None,
            cause_session_id: None,
            cause_formal_check_id: None,
            cause_candidate_boundary_id: None,
            cause_effect_id: Some(value.unknown_evidence.effect_id.as_str()),
            cause_observation_id: Some(value.unknown_evidence.observation_id.as_str()),
            cause_authority_id: None,
            uncertainty_id: None,
            uncertain_authority_ids: &[],
            candidate_boundary_id: None,
            integration_receipt_id: None,
            cleanup_receipt_id: Some(value.cleanup_release.cleanup_receipt.receipt_id.as_str()),
            never_launched_release_id: None,
            release_id: Some(value.cleanup_release.release_id.as_str()),
            evidence: &value.unknown_evidence.evidence,
        },
        TaskAttemptDisposition::UnknownQuarantined(value) => DispositionStorage {
            kind: "UnknownQuarantined",
            cause_kind: None,
            cause_launch_id: None,
            cause_session_id: None,
            cause_formal_check_id: None,
            cause_candidate_boundary_id: None,
            cause_effect_id: None,
            cause_observation_id: None,
            cause_authority_id: None,
            uncertainty_id: Some(value.uncertain_evidence.uncertainty_id.as_str()),
            uncertain_authority_ids: &value.uncertain_evidence.authority_reference_ids,
            candidate_boundary_id: None,
            integration_receipt_id: None,
            cleanup_receipt_id: None,
            never_launched_release_id: None,
            release_id: None,
            evidence: &value.uncertain_evidence.evidence,
        },
    }
}

fn known_disposition_storage<'a>(
    kind: &'static str,
    cause: &'a TaskAttemptRetryableCause,
    release: &'a TaskAttemptReleaseProof,
) -> DispositionStorage<'a> {
    let (
        cause_kind,
        launch_id,
        session_id,
        formal_id,
        candidate_id,
        effect_id,
        observation_id,
        evidence,
    ) = retryable_cause_storage(cause);
    let (cleanup_id, no_launch_id, release_id) = release_storage(release);
    DispositionStorage {
        kind,
        cause_kind: Some(cause_kind),
        cause_launch_id: launch_id,
        cause_session_id: session_id,
        cause_formal_check_id: formal_id,
        cause_candidate_boundary_id: candidate_id,
        cause_effect_id: effect_id,
        cause_observation_id: observation_id,
        cause_authority_id: matches!(
            cause,
            TaskAttemptRetryableCause::KnownWorkerExit { .. }
                | TaskAttemptRetryableCause::CandidateRejectedKnown { .. }
        )
        .then_some(evidence.evidence_id.as_str()),
        uncertainty_id: None,
        uncertain_authority_ids: &[],
        candidate_boundary_id: None,
        integration_receipt_id: None,
        cleanup_receipt_id: cleanup_id,
        never_launched_release_id: no_launch_id,
        release_id: Some(release_id),
        evidence,
    }
}

fn nonretryable_release_storage<'a>(
    kind: &'static str,
    cause_kind: &'static str,
    authority_id: &'a str,
    evidence: &'a TaskAttemptEvidence,
    release: &'a TaskAttemptReleaseProof,
) -> DispositionStorage<'a> {
    let (cleanup_id, no_launch_id, release_id) = release_storage(release);
    DispositionStorage {
        kind,
        cause_kind: Some(cause_kind),
        cause_launch_id: None,
        cause_session_id: None,
        cause_formal_check_id: None,
        cause_candidate_boundary_id: None,
        cause_effect_id: None,
        cause_observation_id: None,
        cause_authority_id: Some(authority_id),
        uncertainty_id: None,
        uncertain_authority_ids: &[],
        candidate_boundary_id: None,
        integration_receipt_id: None,
        cleanup_receipt_id: cleanup_id,
        never_launched_release_id: no_launch_id,
        release_id: Some(release_id),
        evidence,
    }
}

fn cause_subject_id(disposition: &TaskAttemptDisposition) -> Option<&str> {
    match disposition {
        TaskAttemptDisposition::PermanentFailure(value) => match &value.cause {
            crate::TaskAttemptPermanentFailureCause::PermanentContractViolation {
                violation_id,
                ..
            } => Some(violation_id),
            crate::TaskAttemptPermanentFailureCause::CriterionProvenUnsatisfiable {
                criterion_id,
                ..
            } => Some(criterion_id),
        },
        TaskAttemptDisposition::Blocked(value) => match &value.cause {
            crate::TaskAttemptBlockedCause::AuthorityExpansionRequired {
                authority_request_id,
                ..
            } => Some(authority_request_id),
            crate::TaskAttemptBlockedCause::VerifiedDependencyUnavailable {
                dependency_task_id,
                ..
            } => Some(dependency_task_id),
        },
        TaskAttemptDisposition::Canceled(value) => Some(&value.cause.cancellation_id),
        _ => None,
    }
}

fn canonical_digest<T: Serialize>(value: &T) -> Result<String, String> {
    serde_json::to_vec(value)
        .map(|bytes| crate::Digest::sha256(&bytes).as_str().to_owned())
        .map_err(|error| error.to_string())
}

pub(super) fn disposition_sql_index(
    disposition_bytes: &[u8],
    max_attempts_per_task: u8,
) -> Result<String, String> {
    let disposition: TaskAttemptDisposition =
        serde_json::from_slice(disposition_bytes).map_err(|error| error.to_string())?;
    disposition
        .validate_for_budget(max_attempts_per_task)
        .map_err(|error| error.to_string())?;
    if serde_json::to_vec(&disposition).map_err(|error| error.to_string())? != disposition_bytes {
        return Err("disposition bytes are not the exact canonical typed encoding".into());
    }
    let metadata = disposition.metadata();
    let attempt = &metadata.attempt;
    let lease = &attempt.worker_lease;
    let storage = disposition_storage(&disposition);
    let (candidate_boundary_digest, integration_receipt_digest) = match &disposition {
        TaskAttemptDisposition::Integrated(value) => (
            Some(canonical_digest(&value.candidate_boundary)?),
            Some(canonical_digest(&value.integration_receipt)?),
        ),
        _ => (None, None),
    };
    let release = disposition.release_proof();
    let cleanup_receipt_digest = match release {
        Some(TaskAttemptReleaseProof::Cleanup(value)) => {
            Some(canonical_digest(&value.cleanup_receipt)?)
        }
        _ => match &disposition {
            TaskAttemptDisposition::UnknownCleaned(value) => {
                Some(canonical_digest(&value.cleanup_release.cleanup_receipt)?)
            }
            _ => None,
        },
    };
    let never_launched_release_digest = match release {
        Some(TaskAttemptReleaseProof::NeverLaunched(value)) => Some(canonical_digest(value)?),
        _ => None,
    };
    let projection = DispositionSqlIndex {
        contract_version: metadata.contract_version,
        disposition_id: &metadata.disposition_id,
        attempt_id: &attempt.attempt_id,
        sprint_id: &lease.sprint_id,
        task_id: &lease.task_id,
        worker_id: &lease.worker_id,
        worker_lease_id: &lease.lease_id,
        lease_epoch: lease.lease_epoch,
        attempt_ordinal: attempt.attempt_ordinal,
        from_state: format!("{:?}", metadata.from_state),
        transition_event_id: &metadata.state_transition_event_id,
        disposed_at_unix_ms: metadata.disposed_at_unix_ms,
        disposition_kind: storage.kind,
        cause_kind: storage.cause_kind,
        cause_launch_id: storage.cause_launch_id,
        cause_session_id: storage.cause_session_id,
        cause_formal_check_id: storage.cause_formal_check_id,
        cause_candidate_boundary_id: storage.cause_candidate_boundary_id,
        cause_effect_id: storage.cause_effect_id,
        cause_observation_id: storage.cause_observation_id,
        cause_authority_id: storage.cause_authority_id,
        cause_subject_id: cause_subject_id(&disposition),
        uncertainty_id: storage.uncertainty_id,
        uncertain_authority_ids: storage.uncertain_authority_ids,
        candidate_boundary_id: storage.candidate_boundary_id,
        candidate_boundary_digest,
        integration_receipt_id: storage.integration_receipt_id,
        integration_receipt_digest,
        cleanup_receipt_id: storage.cleanup_receipt_id,
        cleanup_receipt_digest,
        never_launched_release_id: storage.never_launched_release_id,
        never_launched_release_digest,
        release_id: storage.release_id,
        evidence_id: &storage.evidence.evidence_id,
        evidence_kind: evidence_kind_name(storage.evidence.kind),
        evidence_digest: storage.evidence.digest.as_str(),
    };
    serde_json::to_string(&projection).map_err(|error| error.to_string())
}

#[derive(Serialize)]
struct WorkerExitAuthorityEnvelope<'a> {
    authority_id: &'a str,
    attempt_id: &'a str,
    launch_id: &'a str,
    session_id: &'a str,
    evidence_id: &'a str,
    evidence_digest: &'a str,
    observed_at_unix_ms: u64,
}

#[derive(Serialize)]
struct CandidateRejectionAuthorityEnvelope<'a> {
    authority_id: &'a str,
    attempt_id: &'a str,
    candidate_boundary_id: &'a str,
    evidence_id: &'a str,
    evidence_digest: &'a str,
    rejected_at_unix_ms: u64,
}

#[derive(Serialize)]
struct PolicyCauseAuthorityEnvelope<'a> {
    authority_id: &'a str,
    attempt_id: &'a str,
    cause_kind: &'static str,
    subject_id: &'a str,
    evidence_id: &'a str,
    evidence_digest: &'a str,
    decided_at_unix_ms: u64,
}

/// Persists one typed source authority independently from any later cleanup
/// disposition. Exact replay is a no-op; every crossed identity conflicts.
#[allow(clippy::too_many_lines)] // Three closed source variants retain separate normalized uniqueness domains.
pub(super) fn record_external_cleanup_outcome_authority(
    transaction: &Connection,
    attempt: &TaskAttempt,
    outcome: &TaskAttemptKnownCleanupOutcome,
    recorded_at_unix_ms: u64,
    insert_if_missing: bool,
) -> Result<(), LedgerError> {
    outcome.validate()?;
    require_exact(transaction, attempt)?;
    if recorded_at_unix_ms < attempt.opened_at_unix_ms {
        return Err(reference_mismatch(
            "task attempt cleanup outcome authority",
            "source authority timestamp precedes attempt opening",
        ));
    }
    let lease = &attempt.worker_lease;
    match outcome {
        TaskAttemptKnownCleanupOutcome::Retryable(TaskAttemptRetryableCause::KnownWorkerExit {
            launch_id,
            session_id,
            evidence,
        }) => {
            let envelope = WorkerExitAuthorityEnvelope {
                authority_id: &evidence.evidence_id,
                attempt_id: &attempt.attempt_id,
                launch_id,
                session_id,
                evidence_id: &evidence.evidence_id,
                evidence_digest: evidence.digest.as_str(),
                observed_at_unix_ms: recorded_at_unix_ms,
            };
            let authority_json = encode("task attempt worker-exit authority", &envelope)?;
            if let Some(exact) = transaction
                .query_row(
                    "SELECT authority_id = ?1 AND attempt_id = ?2
                            AND sprint_id = ?3 AND worker_lease_id = ?4
                            AND lease_epoch = ?5 AND launch_id = ?6
                            AND session_id = ?7 AND evidence_id = ?8
                            AND evidence_digest = ?9 AND evidence_bytes = ?10
                            AND contract_version = ?11 AND observed_at_unix_ms = ?12
                            AND authority_json = ?13
                     FROM task_attempt_worker_exit_authorities
                     WHERE authority_id = ?1 OR attempt_id = ?2
                        OR worker_lease_id = ?4 OR launch_id = ?6
                        OR session_id = ?7 OR evidence_id = ?8",
                    params![
                        evidence.evidence_id,
                        attempt.attempt_id,
                        lease.sprint_id,
                        lease.lease_id,
                        sqlite_integer("task_attempt_worker_exit.lease_epoch", lease.lease_epoch)?,
                        launch_id,
                        session_id,
                        evidence.evidence_id,
                        evidence.digest.as_str(),
                        evidence.canonical_bytes,
                        i64::from(attempt.contract_version),
                        sqlite_integer(
                            "task_attempt_worker_exit.observed_at_unix_ms",
                            recorded_at_unix_ms,
                        )?,
                        authority_json,
                    ],
                    |row| row.get::<_, bool>(0),
                )
                .optional()?
            {
                return if exact {
                    Ok(())
                } else {
                    Err(reference_mismatch(
                        "task attempt worker-exit authority",
                        "authority identity is already bound differently",
                    ))
                };
            }
            if !insert_if_missing {
                return Err(LedgerError::ArtifactNotFound {
                    entity: "task attempt worker-exit authority",
                    id: evidence.evidence_id.clone(),
                });
            }
            require_exact_open_task_attempt_launch_cleanup_authority(transaction, attempt)?;
            transaction.execute(
                "INSERT INTO task_attempt_worker_exit_authorities (
                    authority_id, attempt_id, sprint_id, worker_lease_id,
                    lease_epoch, launch_id, session_id, evidence_id,
                    evidence_digest, evidence_bytes, contract_version,
                    observed_at_unix_ms, authority_json
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10,
                           ?11, ?12, ?13)",
                params![
                    evidence.evidence_id,
                    attempt.attempt_id,
                    lease.sprint_id,
                    lease.lease_id,
                    sqlite_integer("task_attempt_worker_exit.lease_epoch", lease.lease_epoch)?,
                    launch_id,
                    session_id,
                    evidence.evidence_id,
                    evidence.digest.as_str(),
                    evidence.canonical_bytes,
                    i64::from(attempt.contract_version),
                    sqlite_integer(
                        "task_attempt_worker_exit.observed_at_unix_ms",
                        recorded_at_unix_ms,
                    )?,
                    authority_json,
                ],
            )?;
        }
        TaskAttemptKnownCleanupOutcome::Retryable(
            TaskAttemptRetryableCause::CandidateRejectedKnown {
                candidate_boundary_id,
                evidence,
            },
        ) => {
            let envelope = CandidateRejectionAuthorityEnvelope {
                authority_id: &evidence.evidence_id,
                attempt_id: &attempt.attempt_id,
                candidate_boundary_id,
                evidence_id: &evidence.evidence_id,
                evidence_digest: evidence.digest.as_str(),
                rejected_at_unix_ms: recorded_at_unix_ms,
            };
            let authority_json = encode("task attempt candidate-rejection authority", &envelope)?;
            if let Some(exact) = transaction
                .query_row(
                    "SELECT authority_id = ?1 AND attempt_id = ?2
                            AND sprint_id = ?3 AND candidate_boundary_id = ?4
                            AND evidence_id = ?5 AND evidence_digest = ?6
                            AND evidence_bytes = ?7 AND contract_version = ?8
                            AND rejected_at_unix_ms = ?9 AND authority_json = ?10
                     FROM task_attempt_candidate_rejection_authorities
                     WHERE authority_id = ?1 OR attempt_id = ?2
                        OR candidate_boundary_id = ?4 OR evidence_id = ?5",
                    params![
                        evidence.evidence_id,
                        attempt.attempt_id,
                        lease.sprint_id,
                        candidate_boundary_id,
                        evidence.evidence_id,
                        evidence.digest.as_str(),
                        evidence.canonical_bytes,
                        i64::from(attempt.contract_version),
                        sqlite_integer(
                            "task_attempt_candidate_rejection.rejected_at_unix_ms",
                            recorded_at_unix_ms,
                        )?,
                        authority_json,
                    ],
                    |row| row.get::<_, bool>(0),
                )
                .optional()?
            {
                return if exact {
                    Ok(())
                } else {
                    Err(reference_mismatch(
                        "task attempt candidate-rejection authority",
                        "authority identity is already bound differently",
                    ))
                };
            }
            if !insert_if_missing {
                return Err(LedgerError::ArtifactNotFound {
                    entity: "task attempt candidate-rejection authority",
                    id: evidence.evidence_id.clone(),
                });
            }
            require_exact_open_task_attempt_launch_cleanup_authority(transaction, attempt)?;
            transaction.execute(
                "INSERT INTO task_attempt_candidate_rejection_authorities (
                    authority_id, attempt_id, sprint_id, candidate_boundary_id,
                    evidence_id, evidence_digest, evidence_bytes, contract_version,
                    rejected_at_unix_ms, authority_json
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
                params![
                    evidence.evidence_id,
                    attempt.attempt_id,
                    lease.sprint_id,
                    candidate_boundary_id,
                    evidence.evidence_id,
                    evidence.digest.as_str(),
                    evidence.canonical_bytes,
                    i64::from(attempt.contract_version),
                    sqlite_integer(
                        "task_attempt_candidate_rejection.rejected_at_unix_ms",
                        recorded_at_unix_ms,
                    )?,
                    authority_json,
                ],
            )?;
        }
        TaskAttemptKnownCleanupOutcome::PermanentFailure(_)
        | TaskAttemptKnownCleanupOutcome::Blocked(_)
        | TaskAttemptKnownCleanupOutcome::Canceled(_) => {
            let (cause_kind, subject_id, evidence) = policy_cleanup_outcome_storage(outcome)
                .expect("closed policy outcome has normalized source storage");
            let envelope = PolicyCauseAuthorityEnvelope {
                authority_id: &evidence.evidence_id,
                attempt_id: &attempt.attempt_id,
                cause_kind,
                subject_id,
                evidence_id: &evidence.evidence_id,
                evidence_digest: evidence.digest.as_str(),
                decided_at_unix_ms: recorded_at_unix_ms,
            };
            let authority_json = encode("task attempt policy-cause authority", &envelope)?;
            if let Some(exact) = transaction
                .query_row(
                    "SELECT authority_id = ?1 AND attempt_id = ?2
                            AND sprint_id = ?3 AND task_id = ?4 AND cause_kind = ?5
                            AND subject_id = ?6 AND evidence_id = ?7
                            AND evidence_digest = ?8 AND evidence_bytes = ?9
                            AND contract_version = ?10 AND decided_at_unix_ms = ?11
                            AND authority_json = ?12
                     FROM task_attempt_policy_cause_authorities
                     WHERE authority_id = ?1 OR evidence_id = ?7
                        OR (attempt_id = ?2 AND cause_kind = ?5)",
                    params![
                        evidence.evidence_id,
                        attempt.attempt_id,
                        lease.sprint_id,
                        lease.task_id,
                        cause_kind,
                        subject_id,
                        evidence.evidence_id,
                        evidence.digest.as_str(),
                        evidence.canonical_bytes,
                        i64::from(attempt.contract_version),
                        sqlite_integer(
                            "task_attempt_policy_cause.decided_at_unix_ms",
                            recorded_at_unix_ms,
                        )?,
                        authority_json,
                    ],
                    |row| row.get::<_, bool>(0),
                )
                .optional()?
            {
                return if exact {
                    Ok(())
                } else {
                    Err(reference_mismatch(
                        "task attempt policy-cause authority",
                        "authority identity is already bound differently",
                    ))
                };
            }
            if !insert_if_missing {
                return Err(LedgerError::ArtifactNotFound {
                    entity: "task attempt policy-cause authority",
                    id: evidence.evidence_id.clone(),
                });
            }
            require_exact_open_task_attempt_launch_cleanup_authority(transaction, attempt)?;
            transaction.execute(
                "INSERT INTO task_attempt_policy_cause_authorities (
                    authority_id, attempt_id, sprint_id, task_id, cause_kind,
                    subject_id, evidence_id, evidence_digest, evidence_bytes,
                    contract_version, decided_at_unix_ms, authority_json
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
                params![
                    evidence.evidence_id,
                    attempt.attempt_id,
                    lease.sprint_id,
                    lease.task_id,
                    cause_kind,
                    subject_id,
                    evidence.evidence_id,
                    evidence.digest.as_str(),
                    evidence.canonical_bytes,
                    i64::from(attempt.contract_version),
                    sqlite_integer(
                        "task_attempt_policy_cause.decided_at_unix_ms",
                        recorded_at_unix_ms,
                    )?,
                    authority_json,
                ],
            )?;
        }
        TaskAttemptKnownCleanupOutcome::Retryable(_) => {
            return Err(reference_mismatch(
                "task attempt cleanup outcome authority",
                "launch refusal and formal failure already require their native preparation or formal-check source; this API does not normalize them",
            ));
        }
    }
    Ok(())
}
fn require_exact_open_task_attempt_launch_cleanup_authority(
    connection: &Connection,
    attempt: &TaskAttempt,
) -> Result<(), LedgerError> {
    let lease = &attempt.worker_lease;
    worker_lease_authority::require_exact(connection, lease, true)?;
    ensure_sprint_not_terminal(connection, &lease.sprint_id)?;
    let has_open_unknown_marker = connection
        .query_row(
            "SELECT 1
             FROM sprint_unknown_terminalization_pending pending
             LEFT JOIN sprint_unknown_terminalization_closures closure
               ON closure.marker_id = pending.marker_id
             WHERE pending.sprint_id = ?1 AND closure.marker_id IS NULL",
            [&lease.sprint_id],
            |_| Ok(()),
        )
        .optional()?
        .is_some();
    if has_open_unknown_marker {
        return Err(reference_mismatch(
            "task attempt cleanup outcome authority",
            "open sprint Unknown terminalization rejects new known-cleanup source authority",
        ));
    }
    let already_disposed = connection
        .query_row(
            "SELECT 1 FROM task_attempt_dispositions WHERE attempt_id = ?1",
            [&attempt.attempt_id],
            |_| Ok(()),
        )
        .optional()?
        .is_some();
    if already_disposed {
        return Err(reference_mismatch(
            "task attempt cleanup outcome authority",
            "disposed or quarantined attempts reject new known-cleanup source authority",
        ));
    }
    let launch_id = connection
        .query_row(
            "SELECT launch_id FROM runner_launch_intents
             WHERE sprint_id = ?1 AND worker_lease_id = ?2
               AND worker_lease_epoch = ?3",
            params![
                lease.sprint_id,
                lease.lease_id,
                sqlite_integer(
                    "task_attempt_cleanup_outcome.lease_epoch",
                    lease.lease_epoch,
                )?,
            ],
            |row| row.get::<_, String>(0),
        )
        .optional()?
        .ok_or_else(|| {
            reference_mismatch(
                "task attempt cleanup outcome authority",
                "non-NeverLaunched cause requires exact open task-worker launch cleanup authority",
            )
        })?;
    let admission = runner_launch_cleanup_admission::require_open_authoritative(
        connection,
        &lease.sprint_id,
        &launch_id,
    )?;
    if admission.launch.purpose != crate::RunnerSessionPurpose::TaskWorker
        || admission.launch.worker_lease.as_ref() != Some(lease)
        || admission.launch.worker_id.as_deref() != Some(lease.worker_id.as_str())
    {
        return Err(reference_mismatch(
            "task attempt cleanup outcome authority",
            "launch cleanup authority crosses the attempt role, worker, or lease",
        ));
    }
    Ok(())
}

fn policy_cleanup_outcome_storage(
    outcome: &TaskAttemptKnownCleanupOutcome,
) -> Option<(&'static str, &str, &TaskAttemptEvidence)> {
    match outcome {
        TaskAttemptKnownCleanupOutcome::PermanentFailure(cause) => match cause {
            crate::TaskAttemptPermanentFailureCause::PermanentContractViolation {
                violation_id,
                evidence,
            } => Some(("PermanentContractViolation", violation_id, evidence)),
            crate::TaskAttemptPermanentFailureCause::CriterionProvenUnsatisfiable {
                criterion_id,
                evidence,
            } => Some(("CriterionProvenUnsatisfiable", criterion_id, evidence)),
        },
        TaskAttemptKnownCleanupOutcome::Blocked(cause) => match cause {
            crate::TaskAttemptBlockedCause::AuthorityExpansionRequired {
                authority_request_id,
                evidence,
            } => Some(("AuthorityExpansionRequired", authority_request_id, evidence)),
            crate::TaskAttemptBlockedCause::VerifiedDependencyUnavailable {
                dependency_task_id,
                evidence,
            } => Some((
                "VerifiedDependencyUnavailable",
                dependency_task_id,
                evidence,
            )),
        },
        TaskAttemptKnownCleanupOutcome::Canceled(cause) => {
            Some(("OperatorCanceled", &cause.cancellation_id, &cause.evidence))
        }
        TaskAttemptKnownCleanupOutcome::Retryable(_) => None,
    }
}

fn known_cleanup_outcome_identity(
    outcome: &TaskAttemptKnownCleanupOutcome,
) -> Result<(i64, &str, KnownCleanupSourceKind), LedgerError> {
    match outcome {
        TaskAttemptKnownCleanupOutcome::PermanentFailure(cause) => {
            let evidence = match cause {
                crate::TaskAttemptPermanentFailureCause::PermanentContractViolation {
                    evidence,
                    ..
                }
                | crate::TaskAttemptPermanentFailureCause::CriterionProvenUnsatisfiable {
                    evidence,
                    ..
                } => evidence,
            };
            Ok((
                0,
                &evidence.evidence_id,
                KnownCleanupSourceKind::PolicyCause,
            ))
        }
        TaskAttemptKnownCleanupOutcome::Canceled(cause) => Ok((
            1,
            &cause.evidence.evidence_id,
            KnownCleanupSourceKind::PolicyCause,
        )),
        TaskAttemptKnownCleanupOutcome::Blocked(cause) => {
            let evidence = match cause {
                crate::TaskAttemptBlockedCause::AuthorityExpansionRequired { evidence, .. }
                | crate::TaskAttemptBlockedCause::VerifiedDependencyUnavailable {
                    evidence, ..
                } => evidence,
            };
            Ok((
                2,
                &evidence.evidence_id,
                KnownCleanupSourceKind::PolicyCause,
            ))
        }
        TaskAttemptKnownCleanupOutcome::Retryable(cause) => {
            let (evidence, source_kind) = match cause {
                TaskAttemptRetryableCause::LaunchRefusedBeforeNativeEffect { evidence, .. } => {
                    (evidence, KnownCleanupSourceKind::LaunchRefusal)
                }
                TaskAttemptRetryableCause::KnownWorkerExit { evidence, .. } => {
                    (evidence, KnownCleanupSourceKind::WorkerExit)
                }
                TaskAttemptRetryableCause::FormalVerificationFailed { evidence, .. } => {
                    (evidence, KnownCleanupSourceKind::FormalVerificationFailure)
                }
                TaskAttemptRetryableCause::CandidateRejectedKnown { evidence, .. } => {
                    (evidence, KnownCleanupSourceKind::CandidateRejection)
                }
                TaskAttemptRetryableCause::SensitiveOutputRejected { evidence, .. } => {
                    (evidence, KnownCleanupSourceKind::SensitiveOutputRejection)
                }
                TaskAttemptRetryableCause::NeverLaunched { .. } => {
                    return Err(reference_mismatch(
                        "task attempt cleanup source precedence",
                        "NeverLaunched has no launched known-cleanup source",
                    ));
                }
            };
            Ok((3, &evidence.evidence_id, source_kind))
        }
    }
}

pub(super) fn preferred_known_cleanup_source(
    connection: &Connection,
    attempt: &TaskAttempt,
) -> Result<Option<KnownCleanupSourceKey>, LedgerError> {
    let stored = connection
        .query_row(
            "SELECT outcome_rank, source_at_unix_ms, source_id, source_kind
             FROM task_attempt_known_cleanup_sources
             WHERE attempt_id = ?1
             ORDER BY outcome_rank ASC, source_at_unix_ms ASC,
                      source_id ASC, source_kind ASC
             LIMIT 1",
            [&attempt.attempt_id],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                ))
            },
        )
        .optional()?;
    stored
        .map(|(outcome_rank, source_at, source_id, source_kind)| {
            Ok(KnownCleanupSourceKey {
                outcome_rank,
                source_at_unix_ms: unsigned_integer(
                    "task_attempt_known_cleanup_source.source_at_unix_ms",
                    source_at,
                )?,
                source_id,
                source_kind: KnownCleanupSourceKind::parse(&source_kind)?,
            })
        })
        .transpose()
}

fn known_cleanup_source_key_for_outcome(
    connection: &Connection,
    attempt: &TaskAttempt,
    outcome: &TaskAttemptKnownCleanupOutcome,
) -> Result<KnownCleanupSourceKey, LedgerError> {
    let (expected_rank, source_id, source_kind) = known_cleanup_outcome_identity(outcome)?;
    let stored = connection
        .query_row(
            "SELECT outcome_rank, source_at_unix_ms
             FROM task_attempt_known_cleanup_sources
             WHERE attempt_id = ?1 AND source_id = ?2 AND source_kind = ?3",
            params![attempt.attempt_id, source_id, source_kind.as_str()],
            |row| Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?)),
        )
        .optional()?
        .ok_or_else(|| LedgerError::ArtifactNotFound {
            entity: "task attempt known-cleanup source",
            id: source_id.to_owned(),
        })?;
    if stored.0 != expected_rank {
        return Err(LedgerError::Corrupt {
            entity: "task attempt known-cleanup source",
            detail: "typed source outcome rank disagrees with its public contract".into(),
        });
    }
    Ok(KnownCleanupSourceKey {
        outcome_rank: stored.0,
        source_at_unix_ms: unsigned_integer(
            "task_attempt_known_cleanup_source.source_at_unix_ms",
            stored.1,
        )?,
        source_id: source_id.to_owned(),
        source_kind,
    })
}

/// Returns the earliest timestamp at which the selected source can authorize
/// a disposition. Sensitive-output ordering deliberately uses physical v29
/// closure time for rank-3 source precedence, while disposition cannot precede
/// the later atomic effect observation that made that closure durable.
pub(super) fn known_cleanup_outcome_minimum_disposition_time(
    connection: &Connection,
    attempt: &TaskAttempt,
    outcome: &TaskAttemptKnownCleanupOutcome,
) -> Result<u64, LedgerError> {
    let source = known_cleanup_source_key_for_outcome(connection, attempt, outcome)?;
    let TaskAttemptKnownCleanupOutcome::Retryable(
        TaskAttemptRetryableCause::SensitiveOutputRejected {
            effect_id,
            evidence,
        },
    ) = outcome
    else {
        return Ok(source.source_at_unix_ms);
    };
    let observed_at = connection
        .query_row(
            "SELECT observation.observed_at_unix_ms
               FROM command_output_sensitive_rejection_exact_finishes_v29 finish
               JOIN command_output_sensitive_rejection_anchors_v29 anchor
                 ON anchor.effect_id = finish.effect_id
                AND anchor.rejection_anchor_digest = finish.rejection_anchor_digest
               JOIN effect_intents intent ON intent.effect_id = anchor.effect_id
               JOIN effect_observations observation
                 ON observation.effect_id = anchor.effect_id
                AND observation.observation_id = anchor.observation_id
              WHERE anchor.effect_id = ?1
                AND anchor.observation_id = ?2
                AND intent.worker_lease_id = ?3
                AND intent.worker_lease_epoch = ?4",
            params![
                effect_id,
                evidence.evidence_id,
                attempt.worker_lease.lease_id,
                sqlite_integer(
                    "task_attempt_sensitive_output_rejection.lease_epoch",
                    attempt.worker_lease.lease_epoch,
                )?,
            ],
            |row| row.get::<_, i64>(0),
        )
        .optional()?
        .ok_or_else(|| LedgerError::ArtifactNotFound {
            entity: "task attempt sensitive-output-rejection authority",
            id: effect_id.clone(),
        })?;
    Ok(source.source_at_unix_ms.max(unsigned_integer(
        "task_attempt_sensitive_output_rejection.observed_at_unix_ms",
        observed_at,
    )?))
}

pub(super) fn require_preferred_known_cleanup_outcome_authority(
    connection: &Connection,
    metadata: &TaskAttemptDispositionMetadata,
    outcome: &TaskAttemptKnownCleanupOutcome,
) -> Result<(), LedgerError> {
    require_known_cleanup_outcome_authority(connection, metadata, outcome)?;
    require_preferred_known_cleanup_outcome(connection, &metadata.attempt, outcome)
}

pub(super) fn require_preferred_current_known_cleanup_outcome_authority(
    connection: &Connection,
    attempt: &TaskAttempt,
    outcome: &TaskAttemptKnownCleanupOutcome,
) -> Result<(), LedgerError> {
    require_current_known_cleanup_outcome_authority(connection, attempt, outcome)?;
    require_preferred_known_cleanup_outcome(connection, attempt, outcome)
}

fn require_preferred_known_cleanup_outcome(
    connection: &Connection,
    attempt: &TaskAttempt,
    outcome: &TaskAttemptKnownCleanupOutcome,
) -> Result<(), LedgerError> {
    let supplied = known_cleanup_source_key_for_outcome(connection, attempt, outcome)?;
    let preferred = preferred_known_cleanup_source(connection, attempt)?.ok_or_else(|| {
        reference_mismatch(
            "task attempt cleanup source precedence",
            "attempt has no durable known-cleanup source",
        )
    })?;
    if supplied != preferred {
        return Err(reference_mismatch(
            "task attempt cleanup source precedence",
            format!(
                "source `{}` ({}) is not canonical winner `{}` ({})",
                supplied.source_id,
                supplied.source_kind.as_str(),
                preferred.source_id,
                preferred.source_kind.as_str(),
            ),
        ));
    }
    Ok(())
}

/// Requires the independent, append-only source authority behind a known
/// cleanup outcome before any irreversible native cleanup callback runs.
#[allow(clippy::too_many_lines)] // The closed cause matrix must rejoin every variant beside its shared transaction.
pub(super) fn require_known_cleanup_outcome_authority(
    transaction: &Connection,
    metadata: &TaskAttemptDispositionMetadata,
    outcome: &TaskAttemptKnownCleanupOutcome,
) -> Result<(), LedgerError> {
    require_known_cleanup_outcome_authority_at(
        transaction,
        &metadata.attempt,
        metadata.contract_version,
        metadata.disposed_at_unix_ms,
        outcome,
    )
}

/// Reopens current source authority without manufacturing disposition fields.
pub(super) fn require_current_known_cleanup_outcome_authority(
    transaction: &Connection,
    attempt: &TaskAttempt,
    outcome: &TaskAttemptKnownCleanupOutcome,
) -> Result<(), LedgerError> {
    require_known_cleanup_outcome_authority_at(
        transaction,
        attempt,
        crate::CONTRACT_VERSION,
        i64::MAX as u64,
        outcome,
    )
}

#[allow(clippy::too_many_lines)] // The closed cause matrix must rejoin every variant beside its shared transaction.
fn require_known_cleanup_outcome_authority_at(
    transaction: &Connection,
    attempt: &TaskAttempt,
    contract_version: u32,
    authority_cutoff_unix_ms: u64,
    outcome: &TaskAttemptKnownCleanupOutcome,
) -> Result<(), LedgerError> {
    outcome.validate()?;
    require_exact(transaction, attempt)?;
    let lease = &attempt.worker_lease;
    match outcome {
        TaskAttemptKnownCleanupOutcome::Retryable(cause) => match cause {
            TaskAttemptRetryableCause::KnownWorkerExit {
                launch_id,
                session_id,
                evidence,
            } => {
                let (authority_json, observed_at_unix_ms) = transaction
                    .query_row(
                        "SELECT authority_json, observed_at_unix_ms
                             FROM task_attempt_worker_exit_authorities
                             WHERE authority_id = ?1 AND attempt_id = ?2
                               AND sprint_id = ?3 AND worker_lease_id = ?4
                               AND lease_epoch = ?5 AND launch_id = ?6
                               AND session_id = ?7 AND evidence_id = ?8
                               AND evidence_digest = ?9 AND evidence_bytes = ?10
                               AND contract_version = ?11",
                        params![
                            evidence.evidence_id,
                            attempt.attempt_id,
                            lease.sprint_id,
                            lease.lease_id,
                            sqlite_integer(
                                "task_attempt_worker_exit.lease_epoch",
                                lease.lease_epoch
                            )?,
                            launch_id,
                            session_id,
                            evidence.evidence_id,
                            evidence.digest.as_str(),
                            evidence.canonical_bytes,
                            i64::from(contract_version),
                        ],
                        |row| Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, i64>(1)?)),
                    )
                    .optional()?
                    .ok_or_else(|| LedgerError::ArtifactNotFound {
                        entity: "task attempt worker-exit authority",
                        id: evidence.evidence_id.clone(),
                    })?;
                let observed_at_unix_ms = unsigned_integer(
                    "task_attempt_worker_exit.observed_at_unix_ms",
                    observed_at_unix_ms,
                )?;
                let envelope = WorkerExitAuthorityEnvelope {
                    authority_id: &evidence.evidence_id,
                    attempt_id: &attempt.attempt_id,
                    launch_id,
                    session_id,
                    evidence_id: &evidence.evidence_id,
                    evidence_digest: evidence.digest.as_str(),
                    observed_at_unix_ms,
                };
                if authority_json != encode("task attempt worker-exit authority", &envelope)?
                    || observed_at_unix_ms > authority_cutoff_unix_ms
                {
                    return Err(LedgerError::Corrupt {
                        entity: "task attempt worker-exit authority",
                        detail: "canonical authority bytes disagree with indexed source evidence"
                            .into(),
                    });
                }
            }
            TaskAttemptRetryableCause::CandidateRejectedKnown {
                candidate_boundary_id,
                evidence,
            } => {
                let (authority_json, rejected_at_unix_ms) = transaction
                    .query_row(
                        "SELECT authority_json, rejected_at_unix_ms
                             FROM task_attempt_candidate_rejection_authorities
                             WHERE authority_id = ?1 AND attempt_id = ?2
                               AND sprint_id = ?3 AND candidate_boundary_id = ?4
                               AND evidence_id = ?5 AND evidence_digest = ?6
                               AND evidence_bytes = ?7 AND contract_version = ?8",
                        params![
                            evidence.evidence_id,
                            attempt.attempt_id,
                            lease.sprint_id,
                            candidate_boundary_id,
                            evidence.evidence_id,
                            evidence.digest.as_str(),
                            evidence.canonical_bytes,
                            i64::from(contract_version),
                        ],
                        |row| Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, i64>(1)?)),
                    )
                    .optional()?
                    .ok_or_else(|| LedgerError::ArtifactNotFound {
                        entity: "task attempt candidate-rejection authority",
                        id: evidence.evidence_id.clone(),
                    })?;
                let rejected_at_unix_ms = unsigned_integer(
                    "task_attempt_candidate_rejection.rejected_at_unix_ms",
                    rejected_at_unix_ms,
                )?;
                let envelope = CandidateRejectionAuthorityEnvelope {
                    authority_id: &evidence.evidence_id,
                    attempt_id: &attempt.attempt_id,
                    candidate_boundary_id,
                    evidence_id: &evidence.evidence_id,
                    evidence_digest: evidence.digest.as_str(),
                    rejected_at_unix_ms,
                };
                if authority_json
                    != encode("task attempt candidate-rejection authority", &envelope)?
                    || rejected_at_unix_ms > authority_cutoff_unix_ms
                {
                    return Err(LedgerError::Corrupt {
                        entity: "task attempt candidate-rejection authority",
                        detail: "canonical authority bytes disagree with indexed source evidence"
                            .into(),
                    });
                }
            }
            TaskAttemptRetryableCause::LaunchRefusedBeforeNativeEffect {
                launch_id,
                evidence,
            } => {
                let preparation = runner_launch_cleanup_admission::load_preparation(
                    transaction,
                    &lease.sprint_id,
                    launch_id,
                )?;
                if preparation.attempt.attempt_id != evidence.evidence_id
                    || preparation.outcome.as_ref().is_none_or(|outcome| {
                        outcome.disposition
                            != super::RunnerLaunchPreparationDisposition::RefusedBeforeNativeEffect
                            || outcome.native_evidence_bytes != evidence.canonical_bytes
                    })
                {
                    return Err(reference_mismatch(
                        "task attempt launch-refusal authority",
                        "cause must name the exact canonical refused preparation aggregate",
                    ));
                }
                let exact = transaction
                    .query_row(
                        "SELECT 1
                             FROM runner_launch_intents launch
                             JOIN runner_launch_preparation_attempts preparation
                               ON preparation.launch_id = launch.launch_id
                             JOIN runner_launch_preparation_outcomes prepared
                               ON prepared.attempt_id = preparation.attempt_id
                             WHERE launch.launch_id = ?1
                               AND launch.worker_lease_id = ?2
                               AND launch.worker_lease_epoch = ?3
                               AND preparation.attempt_id = ?4
                               AND prepared.disposition = 'RefusedBeforeNativeEffect'
                               AND prepared.native_evidence_digest = ?5
                               AND prepared.native_evidence_bytes = ?6
                               AND prepared.finished_at_unix_ms <= ?7",
                        params![
                            launch_id,
                            lease.lease_id,
                            sqlite_integer(
                                "task_attempt_launch_refusal.lease_epoch",
                                lease.lease_epoch,
                            )?,
                            evidence.evidence_id,
                            evidence.digest.as_str(),
                            evidence.canonical_bytes,
                            sqlite_integer(
                                "task_attempt_disposition.disposed_at_unix_ms",
                                authority_cutoff_unix_ms,
                            )?,
                        ],
                        |_| Ok(()),
                    )
                    .optional()?
                    .is_some();
                if !exact {
                    return Err(reference_mismatch(
                        "task attempt launch-refusal authority",
                        "cause lacks its exact prior refused preparation evidence",
                    ));
                }
            }
            TaskAttemptRetryableCause::FormalVerificationFailed {
                formal_check_id,
                evidence,
            } => {
                let formal = load_formal_check(transaction, formal_check_id)?;
                if formal.attempt != *attempt
                    || formal.verification_receipt.passed()
                    || formal.observation_id != evidence.evidence_id
                {
                    return Err(reference_mismatch(
                        "task attempt formal-failure authority",
                        "cause must name the exact canonical failed formal-check observation",
                    ));
                }
                let exact = transaction
                    .query_row(
                        "SELECT 1
                             FROM task_attempt_formal_checks formal
                             JOIN effect_evidence_payloads payload
                               ON payload.observation_id = formal.observation_id
                             WHERE formal.formal_check_id = ?1
                               AND formal.attempt_id = ?2 AND formal.passed = 0
                               AND formal.observation_id = ?3
                               AND payload.evidence_digest = ?4
                               AND payload.evidence_bytes = ?5
                               AND formal.checked_at_unix_ms <= ?6",
                        params![
                            formal_check_id,
                            attempt.attempt_id,
                            evidence.evidence_id,
                            evidence.digest.as_str(),
                            evidence.canonical_bytes,
                            sqlite_integer(
                                "task_attempt_disposition.disposed_at_unix_ms",
                                authority_cutoff_unix_ms,
                            )?,
                        ],
                        |_| Ok(()),
                    )
                    .optional()?
                    .is_some();
                if !exact {
                    return Err(reference_mismatch(
                        "task attempt formal-failure authority",
                        "cause lacks its exact failed-check effect evidence",
                    ));
                }
            }
            TaskAttemptRetryableCause::SensitiveOutputRejected {
                effect_id,
                evidence,
            } => {
                let rejection =
                    super::sensitive_output_rejection::load_for_effect(transaction, effect_id)?
                        .ok_or_else(|| LedgerError::ArtifactNotFound {
                            entity: "task attempt sensitive-output-rejection authority",
                            id: effect_id.clone(),
                        })?;
                let canonical_bytes = rejection.anchor.canonical_evidence_bytes()?;
                let exact = transaction.query_row(
                    "SELECT EXISTS (
                         SELECT 1
                           FROM command_output_sensitive_rejection_exact_finishes_v29 finish
                           JOIN command_output_sensitive_rejection_anchors_v29 anchor
                             ON anchor.effect_id = finish.effect_id
                            AND anchor.rejection_anchor_digest = finish.rejection_anchor_digest
                           JOIN command_output_sensitive_rejection_closures_v29 closure
                             ON closure.closure_digest = finish.closure_digest
                            AND closure.effect_id = anchor.effect_id
                            AND closure.observation_id = anchor.observation_id
                           JOIN effect_intents intent ON intent.effect_id = anchor.effect_id
                           JOIN effect_observations observation
                             ON observation.effect_id = anchor.effect_id
                            AND observation.observation_id = anchor.observation_id
                          WHERE finish.effect_id = ?1
                            AND anchor.observation_id = ?2
                            AND anchor.rejection_json = ?3
                            AND anchor.effect_evidence_digest = ?4
                            AND anchor.contract_version = ?5
                            AND intent.worker_lease_id = ?6
                            AND intent.worker_lease_epoch = ?7
                            AND closure.closed_at_unix_ms <= ?8
                            AND observation.observed_at_unix_ms <= ?8
                     )",
                    params![
                        effect_id,
                        evidence.evidence_id,
                        evidence.canonical_bytes,
                        evidence.digest.as_str(),
                        i64::from(contract_version),
                        lease.lease_id,
                        sqlite_integer(
                            "task_attempt_sensitive_output_rejection.lease_epoch",
                            lease.lease_epoch,
                        )?,
                        sqlite_integer(
                            "task_attempt_disposition.disposed_at_unix_ms",
                            authority_cutoff_unix_ms,
                        )?,
                    ],
                    |row| row.get::<_, bool>(0),
                )?;
                if !exact
                    || rejection.anchor.observation_id != evidence.evidence_id
                    || canonical_bytes != evidence.canonical_bytes
                    || Digest::sha256(&canonical_bytes) != evidence.digest
                {
                    return Err(reference_mismatch(
                        "task attempt sensitive-output-rejection authority",
                        "cause must name the exact complete secret-free v29 rejection anchor for this attempt lease",
                    ));
                }
            }
            TaskAttemptRetryableCause::NeverLaunched { .. } => {
                return Err(reference_mismatch(
                    "task attempt cleanup outcome authority",
                    "NeverLaunched must use the separate no-launch closure",
                ));
            }
        },
        TaskAttemptKnownCleanupOutcome::PermanentFailure(_)
        | TaskAttemptKnownCleanupOutcome::Blocked(_)
        | TaskAttemptKnownCleanupOutcome::Canceled(_) => {
            let (cause_kind, subject_id, evidence) = policy_cleanup_outcome_storage(outcome)
                .expect("closed policy outcome has normalized source storage");
            let authority_id = evidence.evidence_id.as_str();
            let (authority_json, decided_at_unix_ms) = transaction
                .query_row(
                    "SELECT authority_json, decided_at_unix_ms
                     FROM task_attempt_policy_cause_authorities
                     WHERE authority_id = ?1 AND attempt_id = ?2
                       AND sprint_id = ?3 AND task_id = ?4 AND cause_kind = ?5
                       AND subject_id = ?6 AND evidence_id = ?7
                       AND evidence_digest = ?8 AND evidence_bytes = ?9
                       AND contract_version = ?10",
                    params![
                        authority_id,
                        attempt.attempt_id,
                        lease.sprint_id,
                        lease.task_id,
                        cause_kind,
                        subject_id,
                        evidence.evidence_id,
                        evidence.digest.as_str(),
                        evidence.canonical_bytes,
                        i64::from(contract_version),
                    ],
                    |row| Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, i64>(1)?)),
                )
                .optional()?
                .ok_or_else(|| LedgerError::ArtifactNotFound {
                    entity: "task attempt policy-cause authority",
                    id: authority_id.to_owned(),
                })?;
            let decided_at_unix_ms = unsigned_integer(
                "task_attempt_policy_cause.decided_at_unix_ms",
                decided_at_unix_ms,
            )?;
            let envelope = PolicyCauseAuthorityEnvelope {
                authority_id,
                attempt_id: &attempt.attempt_id,
                cause_kind,
                subject_id,
                evidence_id: &evidence.evidence_id,
                evidence_digest: evidence.digest.as_str(),
                decided_at_unix_ms,
            };
            if authority_json != encode("task attempt policy-cause authority", &envelope)?
                || decided_at_unix_ms > authority_cutoff_unix_ms
            {
                return Err(LedgerError::Corrupt {
                    entity: "task attempt policy-cause authority",
                    detail: "canonical authority bytes disagree with indexed source evidence"
                        .into(),
                });
            }
        }
    }
    Ok(())
}

pub(super) fn require_disposition_cause_authority(
    transaction: &Connection,
    disposition: &TaskAttemptDisposition,
) -> Result<(), LedgerError> {
    let outcome = match disposition {
        // Never-launched authority is the exact release proof itself. The
        // disposition readback validates that proof through the dedicated
        // no-launch table instead of the launched-cleanup authority tables.
        TaskAttemptDisposition::Retryable(value)
            if matches!(
                &value.cause,
                TaskAttemptRetryableCause::NeverLaunched { .. }
            ) =>
        {
            return Ok(());
        }
        TaskAttemptDisposition::AttemptsExhausted(value)
            if matches!(
                &value.cause,
                TaskAttemptRetryableCause::NeverLaunched { .. }
            ) =>
        {
            return Ok(());
        }
        TaskAttemptDisposition::Retryable(value) => {
            TaskAttemptKnownCleanupOutcome::Retryable(value.cause.clone())
        }
        TaskAttemptDisposition::AttemptsExhausted(value) => {
            TaskAttemptKnownCleanupOutcome::Retryable(value.cause.clone())
        }
        TaskAttemptDisposition::PermanentFailure(value) => {
            TaskAttemptKnownCleanupOutcome::PermanentFailure(value.cause.clone())
        }
        TaskAttemptDisposition::Blocked(value) => {
            TaskAttemptKnownCleanupOutcome::Blocked(value.cause.clone())
        }
        TaskAttemptDisposition::Canceled(value) => {
            TaskAttemptKnownCleanupOutcome::Canceled(value.cause.clone())
        }
        TaskAttemptDisposition::Integrated(_)
        | TaskAttemptDisposition::UnknownCleaned(_)
        | TaskAttemptDisposition::UnknownQuarantined(_) => return Ok(()),
    };
    require_known_cleanup_outcome_authority(transaction, disposition.metadata(), &outcome)
}

pub(super) fn insert_disposition(
    transaction: &Transaction<'_>,
    disposition: &TaskAttemptDisposition,
) -> Result<(), LedgerError> {
    let metadata = disposition.metadata();
    let attempt = &metadata.attempt;
    let lease = &attempt.worker_lease;
    let stored = disposition_storage(disposition);
    transaction.execute(
        "INSERT INTO task_attempt_dispositions (
            disposition_id, attempt_id, sprint_id, task_id, worker_id,
            worker_lease_id, lease_epoch, attempt_ordinal, from_state,
            disposition_kind, cause_kind, cause_launch_id, cause_session_id,
            cause_formal_check_id, cause_candidate_boundary_id, cause_effect_id,
            cause_observation_id, cause_authority_id, uncertainty_id,
            uncertain_authority_count, candidate_boundary_id,
            integration_receipt_id, cleanup_receipt_id,
            never_launched_release_id, release_id, transition_event_id,
            evidence_id, evidence_kind, evidence_digest, evidence_bytes,
            contract_version, disposed_at_unix_ms, disposition_json
         ) VALUES (
            ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13,
            ?14, ?15, ?16, ?17, ?18, ?19, ?20, ?21, ?22, ?23, ?24, ?25,
            ?26, ?27, ?28, ?29, ?30, ?31, ?32, ?33
         )",
        params![
            metadata.disposition_id,
            attempt.attempt_id,
            lease.sprint_id,
            lease.task_id,
            lease.worker_id,
            lease.lease_id,
            sqlite_integer("task_attempt_disposition.lease_epoch", lease.lease_epoch)?,
            i64::from(attempt.attempt_ordinal),
            format!("{:?}", metadata.from_state),
            stored.kind,
            stored.cause_kind,
            stored.cause_launch_id,
            stored.cause_session_id,
            stored.cause_formal_check_id,
            stored.cause_candidate_boundary_id,
            stored.cause_effect_id,
            stored.cause_observation_id,
            stored.cause_authority_id,
            stored.uncertainty_id,
            i64::try_from(stored.uncertain_authority_ids.len())
                .map_err(|_| LedgerError::IntegerOutOfRange("uncertain authority count"))?,
            stored.candidate_boundary_id,
            stored.integration_receipt_id,
            stored.cleanup_receipt_id,
            stored.never_launched_release_id,
            stored.release_id,
            metadata.state_transition_event_id,
            stored.evidence.evidence_id,
            evidence_kind_name(stored.evidence.kind),
            stored.evidence.digest.as_str(),
            stored.evidence.canonical_bytes,
            i64::from(metadata.contract_version),
            sqlite_integer(
                "task_attempt_disposition.disposed_at_unix_ms",
                metadata.disposed_at_unix_ms,
            )?,
            encode("task attempt disposition", disposition)?,
        ],
    )?;
    for (ordinal, authority_id) in stored.uncertain_authority_ids.iter().enumerate() {
        transaction.execute(
            "INSERT INTO task_attempt_disposition_uncertain_authorities (
                disposition_id, ordinal, authority_reference_id
             ) VALUES (?1, ?2, ?3)",
            params![
                metadata.disposition_id,
                i64::try_from(ordinal).map_err(|_| {
                    LedgerError::IntegerOutOfRange("uncertain authority ordinal")
                })?,
                authority_id,
            ],
        )?;
    }
    Ok(())
}

pub(super) fn load_disposition(
    connection: &Connection,
    disposition_id: &str,
    max_attempts_per_task: u8,
) -> Result<TaskAttemptDisposition, LedgerError> {
    let (attempt_id, disposition_bytes) = connection
        .query_row(
            "SELECT attempt_id, disposition_json
             FROM task_attempt_dispositions WHERE disposition_id = ?1",
            [disposition_id],
            |row| Ok((row.get::<_, String>(0)?, row.get::<_, Vec<u8>>(1)?)),
        )
        .optional()?
        .ok_or_else(|| LedgerError::ArtifactNotFound {
            entity: "task attempt disposition",
            id: disposition_id.to_owned(),
        })?;
    let disposition: TaskAttemptDisposition =
        decode_stored("task attempt disposition", &disposition_bytes)?;
    disposition
        .validate_for_budget(max_attempts_per_task)
        .map_err(|error| LedgerError::Corrupt {
            entity: "task attempt disposition",
            detail: error.to_string(),
        })?;
    let metadata = disposition.metadata();
    let attempt = load(connection, &attempt_id)?;
    let projection =
        disposition_sql_index(&disposition_bytes, max_attempts_per_task).map_err(|detail| {
            LedgerError::Corrupt {
                entity: "task attempt disposition",
                detail,
            }
        })?;
    let evidence_bytes = &disposition_storage(&disposition).evidence.canonical_bytes;
    let exact_index = connection.query_row(
        "SELECT
             json_extract(?2, '$.contract_version') IS contract_version
         AND json_extract(?2, '$.disposition_id') IS disposition_id
         AND json_extract(?2, '$.attempt_id') IS attempt_id
         AND json_extract(?2, '$.sprint_id') IS sprint_id
         AND json_extract(?2, '$.task_id') IS task_id
         AND json_extract(?2, '$.worker_id') IS worker_id
         AND json_extract(?2, '$.worker_lease_id') IS worker_lease_id
         AND json_extract(?2, '$.lease_epoch') IS lease_epoch
         AND json_extract(?2, '$.attempt_ordinal') IS attempt_ordinal
         AND json_extract(?2, '$.from_state') IS from_state
         AND json_extract(?2, '$.transition_event_id') IS transition_event_id
         AND json_extract(?2, '$.disposed_at_unix_ms') IS disposed_at_unix_ms
         AND json_extract(?2, '$.disposition_kind') IS disposition_kind
         AND json_extract(?2, '$.cause_kind') IS cause_kind
         AND json_extract(?2, '$.cause_launch_id') IS cause_launch_id
         AND json_extract(?2, '$.cause_session_id') IS cause_session_id
         AND json_extract(?2, '$.cause_formal_check_id') IS cause_formal_check_id
         AND json_extract(?2, '$.cause_candidate_boundary_id') IS cause_candidate_boundary_id
         AND json_extract(?2, '$.cause_effect_id') IS cause_effect_id
         AND json_extract(?2, '$.cause_observation_id') IS cause_observation_id
         AND json_extract(?2, '$.cause_authority_id') IS cause_authority_id
         AND json_extract(?2, '$.uncertainty_id') IS uncertainty_id
         AND json_array_length(?2, '$.uncertain_authority_ids') IS uncertain_authority_count
         AND json_extract(?2, '$.candidate_boundary_id') IS candidate_boundary_id
         AND json_extract(?2, '$.integration_receipt_id') IS integration_receipt_id
         AND json_extract(?2, '$.cleanup_receipt_id') IS cleanup_receipt_id
         AND json_extract(?2, '$.never_launched_release_id') IS never_launched_release_id
         AND json_extract(?2, '$.release_id') IS release_id
         AND json_extract(?2, '$.evidence_id') IS evidence_id
         AND json_extract(?2, '$.evidence_kind') IS evidence_kind
         AND json_extract(?2, '$.evidence_digest') IS evidence_digest
         AND evidence_bytes = ?3
         AND disposition_json = ?4
         FROM task_attempt_dispositions
         WHERE disposition_id = ?1",
        params![
            disposition_id,
            projection,
            evidence_bytes,
            disposition_bytes,
        ],
        |row| row.get::<_, bool>(0),
    )?;
    if metadata.attempt != attempt || !exact_index {
        return Err(LedgerError::Corrupt {
            entity: "task attempt disposition",
            detail: "canonical disposition disagrees with its indexed authority".into(),
        });
    }
    validate_disposition_readback(connection, &disposition)?;
    Ok(disposition)
}

#[allow(clippy::too_many_lines)] // Every tagged variant reopens its independent source, release, and transition authority.
fn validate_disposition_readback(
    connection: &Connection,
    disposition: &TaskAttemptDisposition,
) -> Result<(), LedgerError> {
    let metadata = disposition.metadata();
    let attempt = &metadata.attempt;
    let lease = &attempt.worker_lease;
    let event = load_event_by_id(connection, &metadata.state_transition_event_id)?;
    let expected_to = format!("{:?}", disposition.resulting_task_state());
    let exact_transition = matches!(
        &event.payload,
        AgentEventKind::TaskStateChanged { from, to }
            if from == &format!("{:?}", metadata.from_state) && to == &expected_to
    );
    if event.event_id != metadata.state_transition_event_id
        || event.sprint_id != lease.sprint_id
        || event.task_id.as_deref() != Some(lease.task_id.as_str())
        || event.worker_id.as_deref() != Some(lease.worker_id.as_str())
        || event.occurred_at_unix_ms != metadata.disposed_at_unix_ms
        || !exact_transition
    {
        return Err(LedgerError::Corrupt {
            entity: "task attempt disposition",
            detail: "transition event does not prove the exact disposition state change".into(),
        });
    }
    require_disposition_cause_authority(connection, disposition)?;
    match disposition {
        TaskAttemptDisposition::Integrated(value) => {
            if load_candidate_boundary(connection, &value.candidate_boundary.boundary_id)?
                != value.candidate_boundary
                || load_task_integration_receipt_from(
                    connection,
                    &value.integration_receipt.receipt_id,
                )? != value.integration_receipt
            {
                return Err(LedgerError::Corrupt {
                    entity: "task attempt integrated disposition",
                    detail: "candidate or integration receipt readback differs".into(),
                });
            }
            let admission_id = connection
                .query_row(
                    "SELECT admission_id FROM task_attempt_integration_admissions
                     WHERE attempt_id = ?1 AND candidate_boundary_id = ?2
                       AND effect_id = ?3",
                    params![
                        attempt.attempt_id,
                        value.candidate_boundary.boundary_id,
                        value.integration_receipt.effect_id,
                    ],
                    |row| row.get::<_, String>(0),
                )
                .optional()?
                .ok_or_else(|| LedgerError::Corrupt {
                    entity: "task attempt integrated disposition",
                    detail: "integration receipt lacks its exact prior admission".into(),
                })?;
            require_exact_integrated_result_coverage(
                connection,
                &metadata.disposition_id,
                &value.integration_receipt.receipt_id,
                &admission_id,
                &attempt.attempt_id,
            )?;
            require_disposition_evidence_payload(
                connection,
                &value.integration_receipt.effect_id,
                &value.integration_receipt.observation_id,
                &value.evidence,
            )?;
        }
        TaskAttemptDisposition::Retryable(value) => {
            validate_release_proof_readback(
                connection,
                &metadata.disposition_id,
                &value.release_proof,
            )?;
        }
        TaskAttemptDisposition::AttemptsExhausted(value) => {
            validate_release_proof_readback(
                connection,
                &metadata.disposition_id,
                &value.release_proof,
            )?;
        }
        TaskAttemptDisposition::PermanentFailure(value) => {
            validate_release_proof_readback(
                connection,
                &metadata.disposition_id,
                &value.release_proof,
            )?;
        }
        TaskAttemptDisposition::Blocked(value) => {
            validate_release_proof_readback(
                connection,
                &metadata.disposition_id,
                &value.release_proof,
            )?;
        }
        TaskAttemptDisposition::Canceled(value) => {
            validate_release_proof_readback(
                connection,
                &metadata.disposition_id,
                &value.release_proof,
            )?;
        }
        TaskAttemptDisposition::UnknownCleaned(value) => {
            validate_cleanup_release_readback(
                connection,
                &metadata.disposition_id,
                &value.cleanup_release,
            )?;
            require_disposition_evidence_payload(
                connection,
                &value.unknown_evidence.effect_id,
                &value.unknown_evidence.observation_id,
                &value.unknown_evidence.evidence,
            )?;
            let outcome: String = connection.query_row(
                "SELECT outcome FROM effect_observations WHERE observation_id = ?1",
                [&value.unknown_evidence.observation_id],
                |row| row.get(0),
            )?;
            if outcome != "Unknown" {
                return Err(LedgerError::Corrupt {
                    entity: "task attempt unknown-cleaned disposition",
                    detail: "source effect observation is not Unknown".into(),
                });
            }
        }
        TaskAttemptDisposition::UnknownQuarantined(value) => {
            let mut statement = connection.prepare(
                "SELECT authority_reference_id
                 FROM task_attempt_disposition_uncertain_authorities
                 WHERE disposition_id = ?1 ORDER BY ordinal ASC",
            )?;
            let stored = statement
                .query_map([&metadata.disposition_id], |row| row.get::<_, String>(0))?
                .collect::<Result<Vec<_>, _>>()?;
            if stored != value.uncertain_evidence.authority_reference_ids {
                return Err(LedgerError::Corrupt {
                    entity: "task attempt unknown-quarantined disposition",
                    detail: "uncertain authority reference readback differs".into(),
                });
            }
        }
    }
    Ok(())
}

fn validate_release_proof_readback(
    connection: &Connection,
    disposition_id: &str,
    release: &TaskAttemptReleaseProof,
) -> Result<(), LedgerError> {
    match release {
        TaskAttemptReleaseProof::Cleanup(release) => {
            validate_cleanup_release_readback(connection, disposition_id, release)
        }
        TaskAttemptReleaseProof::NeverLaunched(release) => {
            if load_never_launched_release(connection, &release.release_id)? != *release {
                return Err(LedgerError::Corrupt {
                    entity: "never-launched release",
                    detail: "release readback differs from disposition proof".into(),
                });
            }
            Ok(())
        }
    }
}

fn validate_cleanup_release_readback(
    connection: &Connection,
    disposition_id: &str,
    release: &TaskAttemptCleanupRelease,
) -> Result<(), LedgerError> {
    let receipt_id = &release.cleanup_receipt.receipt_id;
    let evidence = load_worker_cleanup_evidence_from(connection, receipt_id)?;
    if evidence.receipt != release.cleanup_receipt {
        return Err(LedgerError::Corrupt {
            entity: "task attempt cleanup release",
            detail: "cleanup receipt readback differs from disposition proof".into(),
        });
    }
    require_exact_cleanup_result_coverage(
        connection,
        receipt_id,
        disposition_id,
        &release.attempt,
        &release.cleanup_receipt.effect_id,
    )?;
    worker_lease_authority::require_exact_release(
        connection,
        &release.attempt.worker_lease,
        receipt_id,
        &release.cleanup_receipt.effect_id,
        &release.cleanup_receipt.observation_id,
        release.released_at_unix_ms,
    )
}

fn require_disposition_evidence_payload(
    connection: &Connection,
    effect_id: &str,
    observation_id: &str,
    evidence: &TaskAttemptEvidence,
) -> Result<(), LedgerError> {
    let exact = connection
        .query_row(
            "SELECT 1 FROM effect_evidence_payloads
             WHERE effect_id = ?1 AND observation_id = ?2
               AND evidence_digest = ?3 AND evidence_bytes = ?4",
            params![
                effect_id,
                observation_id,
                evidence.digest.as_str(),
                evidence.canonical_bytes,
            ],
            |_| Ok(()),
        )
        .optional()?
        .is_some();
    if exact {
        Ok(())
    } else {
        Err(LedgerError::Corrupt {
            entity: "task attempt disposition evidence",
            detail: "retained evidence does not rejoin its exact effect payload".into(),
        })
    }
}

pub(super) fn load_never_launched_release(
    connection: &Connection,
    release_id: &str,
) -> Result<WorkerLeaseNeverLaunchedRelease, LedgerError> {
    let (attempt_id, disposition_id, bytes) = connection
        .query_row(
            "SELECT attempt_id, disposition_id, release_json
             FROM worker_lease_never_launched_releases WHERE release_id = ?1",
            [release_id],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, Vec<u8>>(2)?,
                ))
            },
        )
        .optional()?
        .ok_or_else(|| LedgerError::ArtifactNotFound {
            entity: "worker lease never-launched release",
            id: release_id.to_owned(),
        })?;
    let release: WorkerLeaseNeverLaunchedRelease =
        decode_stored("worker lease never-launched release", &bytes)?;
    release.validate().map_err(|error| LedgerError::Corrupt {
        entity: "worker lease never-launched release",
        detail: error.to_string(),
    })?;
    if encode("worker lease never-launched release", &release)? != bytes
        || release.release_id != release_id
        || release.attempt.attempt_id != attempt_id
        || disposition_id.is_empty()
        || load(connection, &attempt_id)? != release.attempt
    {
        return Err(LedgerError::Corrupt {
            entity: "worker lease never-launched release",
            detail: "canonical no-launch release disagrees with indexed authority".into(),
        });
    }
    Ok(release)
}

pub(super) fn load(connection: &Connection, attempt_id: &str) -> Result<TaskAttempt, LedgerError> {
    load_inner(connection, attempt_id, false)
}

pub(super) fn load_for_recovery(
    connection: &Connection,
    attempt_id: &str,
) -> Result<TaskAttempt, LedgerError> {
    load_inner(connection, attempt_id, true)
}

fn load_inner(
    connection: &Connection,
    attempt_id: &str,
    recovery_read: bool,
) -> Result<TaskAttempt, LedgerError> {
    let stored = connection
        .query_row(
            "SELECT sprint_id, task_id, worker_id, worker_lease_id, lease_epoch,
                    attempt_ordinal, opening_event_id, opened_at_unix_ms,
                    contract_version, attempt_json
             FROM task_attempts WHERE attempt_id = ?1",
            [attempt_id],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, i64>(4)?,
                    row.get::<_, i64>(5)?,
                    row.get::<_, String>(6)?,
                    row.get::<_, i64>(7)?,
                    row.get::<_, i64>(8)?,
                    row.get::<_, Vec<u8>>(9)?,
                ))
            },
        )
        .optional()?
        .ok_or_else(|| LedgerError::ArtifactNotFound {
            entity: "task attempt",
            id: attempt_id.to_owned(),
        })?;

    let attempt: TaskAttempt = decode_stored("task attempt", &stored.9)?;
    attempt.validate().map_err(|error| LedgerError::Corrupt {
        entity: "task attempt",
        detail: error.to_string(),
    })?;
    let lease: WorkerLease = if recovery_read {
        worker_lease_authority::load_for_recovery(connection, &stored.3, false)?
    } else {
        worker_lease_authority::load(connection, &stored.3, false)?
    };
    if encode("task attempt", &attempt)? != stored.9
        || attempt.attempt_id != attempt_id
        || attempt.worker_lease != lease
        || lease.sprint_id != stored.0
        || lease.task_id != stored.1
        || lease.worker_id != stored.2
        || lease.lease_id != stored.3
        || lease.lease_epoch != unsigned_integer("task_attempt.lease_epoch", stored.4)?
        || u64::from(attempt.attempt_ordinal)
            != unsigned_integer("task_attempt.attempt_ordinal", stored.5)?
        || attempt.opening_event_id != stored.6
        || attempt.opened_at_unix_ms
            != unsigned_integer("task_attempt.opened_at_unix_ms", stored.7)?
        || i64::from(attempt.contract_version) != stored.8
    {
        return Err(LedgerError::Corrupt {
            entity: "task attempt",
            detail: "canonical attempt disagrees with indexed identity columns".into(),
        });
    }
    let event = load_event_by_id(connection, &attempt.opening_event_id)?;
    let event_matches = matches!(
        event.payload,
        AgentEventKind::TaskStateChanged { ref from, ref to }
            if from == "Ready" && to == "Leased"
    );
    if event.sprint_id != lease.sprint_id
        || event.task_id.as_deref() != Some(lease.task_id.as_str())
        || event.worker_id.as_deref() != Some(lease.worker_id.as_str())
        || event.occurred_at_unix_ms != attempt.opened_at_unix_ms
        || !event_matches
    {
        return Err(LedgerError::Corrupt {
            entity: "task attempt",
            detail: "opening event does not prove the exact attempt acquisition".into(),
        });
    }
    Ok(attempt)
}

pub(super) fn require_exact(
    connection: &Connection,
    expected: &TaskAttempt,
) -> Result<(), LedgerError> {
    let stored = load(connection, &expected.attempt_id)?;
    if stored == *expected {
        Ok(())
    } else {
        Err(reference_mismatch(
            "task attempt",
            "supplied attempt differs from canonical durable authority",
        ))
    }
}

pub(super) fn require_exact_for_recovery(
    connection: &Connection,
    expected: &TaskAttempt,
) -> Result<(), LedgerError> {
    let stored = load_for_recovery(connection, &expected.attempt_id)?;
    if stored == *expected {
        Ok(())
    } else {
        Err(reference_mismatch(
            "task attempt",
            "supplied attempt differs from canonical durable authority",
        ))
    }
}

#[allow(clippy::too_many_arguments)] // Exact observation/event identity crosses the pending marker atomically.
pub(super) fn admit_pending_observation_if_required(
    transaction: &Transaction<'_>,
    observation_id: &str,
    effect_id: &str,
    sprint_id: &str,
    worker_lease_id: Option<&str>,
    terminal_event_id: &str,
    contract_version: u32,
    admitted_at_unix_ms: u64,
) -> Result<(), LedgerError> {
    let schema_installed = transaction
        .query_row(
            "SELECT 1 FROM sqlite_schema
             WHERE type = 'table' AND name = 'sprint_unknown_terminalization_pending'",
            [],
            |_| Ok(()),
        )
        .optional()?
        .is_some();
    if !schema_installed {
        return Ok(());
    }
    let pending = transaction
        .query_row(
            "SELECT 1
             FROM sprint_unknown_terminalization_pending pending
             LEFT JOIN sprint_unknown_terminalization_closures closure
                    ON closure.marker_id = pending.marker_id
             WHERE pending.sprint_id = ?1 AND closure.marker_id IS NULL",
            [sprint_id],
            |_| Ok(()),
        )
        .optional()?
        .is_some();
    if !pending {
        return Ok(());
    }
    let attempt_id = worker_lease_id
        .map(|lease_id| {
            transaction
                .query_row(
                    "SELECT attempt_id FROM task_attempts WHERE worker_lease_id = ?1",
                    [lease_id],
                    |row| row.get::<_, String>(0),
                )
                .optional()
        })
        .transpose()?
        .flatten();
    if worker_lease_id.is_some() && attempt_id.is_none() {
        return Err(reference_mismatch(
            "pending effect observation",
            "lease-bound effect lacks its exact task attempt",
        ));
    }
    transaction.execute(
        "INSERT INTO sprint_unknown_pending_observation_admissions (
            observation_id, effect_id, sprint_id, attempt_id, worker_lease_id,
            terminal_event_id, contract_version, admitted_at_unix_ms
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
        params![
            observation_id,
            effect_id,
            sprint_id,
            attempt_id,
            worker_lease_id,
            terminal_event_id,
            i64::from(contract_version),
            sqlite_integer(
                "pending_observation.admitted_at_unix_ms",
                admitted_at_unix_ms,
            )?,
        ],
    )?;
    Ok(())
}

#[allow(clippy::too_many_arguments)] // Readback must compare every normalized admission column to its effect lifecycle.
pub(super) fn require_exact_pending_observation_admission(
    connection: &Connection,
    observation_id: &str,
    effect_id: &str,
    sprint_id: &str,
    worker_lease_id: Option<&str>,
    terminal_event_id: &str,
    contract_version: u32,
    admitted_at_unix_ms: u64,
) -> Result<(), LedgerError> {
    if !schema_is_installed(connection)? {
        return Ok(());
    }

    let observation_event = load_event_by_id(connection, terminal_event_id)?;
    if observation_event.sprint_id != sprint_id {
        return Err(LedgerError::Corrupt {
            entity: "pending effect observation admission",
            detail: "terminal event belongs to another sprint".into(),
        });
    }

    let admission_required =
        pending_observation_admission_required(connection, sprint_id, observation_event.sequence)?;

    let related_count: i64 = connection.query_row(
        "SELECT COUNT(*)
         FROM sprint_unknown_pending_observation_admissions
         WHERE observation_id = ?1 OR effect_id = ?2 OR terminal_event_id = ?3",
        params![observation_id, effect_id, terminal_event_id],
        |row| row.get(0),
    )?;
    if !admission_required {
        if related_count != 0 {
            return Err(LedgerError::Corrupt {
                entity: "pending effect observation admission",
                detail: "admission exists for an observation outside the pending-marker window"
                    .into(),
            });
        }
        return Ok(());
    }

    let attempt_id = worker_lease_id
        .map(|lease_id| {
            connection
                .query_row(
                    "SELECT attempt_id FROM task_attempts WHERE worker_lease_id = ?1",
                    [lease_id],
                    |row| row.get::<_, String>(0),
                )
                .optional()
        })
        .transpose()?
        .flatten();
    if worker_lease_id.is_some() && attempt_id.is_none() {
        return Err(LedgerError::Corrupt {
            entity: "pending effect observation admission",
            detail: "lease-bound admission lacks its exact task attempt".into(),
        });
    }
    let exact_count: i64 = connection.query_row(
        "SELECT COUNT(*)
         FROM sprint_unknown_pending_observation_admissions
         WHERE observation_id = ?1 AND effect_id = ?2 AND sprint_id = ?3
           AND attempt_id IS ?4 AND worker_lease_id IS ?5
           AND terminal_event_id = ?6 AND contract_version = ?7
           AND admitted_at_unix_ms = ?8",
        params![
            observation_id,
            effect_id,
            sprint_id,
            attempt_id,
            worker_lease_id,
            terminal_event_id,
            i64::from(contract_version),
            sqlite_integer(
                "pending_observation.admitted_at_unix_ms",
                admitted_at_unix_ms,
            )?,
        ],
        |row| row.get(0),
    )?;
    if related_count != 1 || exact_count != 1 {
        return Err(LedgerError::Corrupt {
            entity: "pending effect observation admission",
            detail: "required admission is absent, crossed, or duplicated".into(),
        });
    }
    Ok(())
}

fn pending_observation_admission_required(
    connection: &Connection,
    sprint_id: &str,
    observation_sequence: u64,
) -> Result<bool, LedgerError> {
    let pending = connection
        .query_row(
            "SELECT marker_id, first_disposition_id
             FROM sprint_unknown_terminalization_pending
             WHERE sprint_id = ?1",
            [sprint_id],
            |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
        )
        .optional()?;
    let Some((marker_id, first_disposition_id)) = pending else {
        return Ok(false);
    };
    let marker_event_id = connection
        .query_row(
            "SELECT transition_event_id FROM task_attempt_dispositions
             WHERE disposition_id = ?1 AND sprint_id = ?2",
            params![first_disposition_id, sprint_id],
            |row| row.get::<_, String>(0),
        )
        .optional()?
        .ok_or_else(|| LedgerError::Corrupt {
            entity: "pending effect observation admission",
            detail: "pending marker lacks its first disposition event".into(),
        })?;
    let marker_event = load_event_by_id(connection, &marker_event_id)?;
    if marker_event.sprint_id != sprint_id {
        return Err(LedgerError::Corrupt {
            entity: "pending effect observation admission",
            detail: "pending marker event belongs to another sprint".into(),
        });
    }
    let closure_event_id = connection
        .query_row(
            "SELECT terminal_event_id
             FROM sprint_unknown_terminalization_closures
             WHERE marker_id = ?1 AND sprint_id = ?2",
            params![marker_id, sprint_id],
            |row| row.get::<_, String>(0),
        )
        .optional()?;
    let closure_sequence = closure_event_id
        .as_deref()
        .map(|event_id| load_event_by_id(connection, event_id))
        .transpose()?
        .map(|event| {
            if event.sprint_id != sprint_id {
                return Err(LedgerError::Corrupt {
                    entity: "pending effect observation admission",
                    detail: "pending-marker closure event belongs to another sprint".into(),
                });
            }
            Ok(event.sequence)
        })
        .transpose()?;
    if closure_sequence.is_some_and(|sequence| {
        sequence <= marker_event.sequence || observation_sequence >= sequence
    }) {
        return Err(LedgerError::Corrupt {
            entity: "pending effect observation admission",
            detail: "effect observation falls outside the durable pending-marker timeline".into(),
        });
    }
    Ok(marker_event.sequence < observation_sequence)
}
