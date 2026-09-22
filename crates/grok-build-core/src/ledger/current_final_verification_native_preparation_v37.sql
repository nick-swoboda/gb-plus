-- Schema v37 records one current-only native-preparation attempt and its
-- still-pending cleanup obligation before any authenticated native callback
-- can run. It deliberately does not claim native cleanup ownership, advance
-- the schema-v34 event frontier beyond CaptureAcquired, or reuse the legacy
-- schema-v13 preparation tables.

CREATE TABLE current_final_verification_native_preparation_attempts_v37 (
    preparation_attempt_id TEXT PRIMARY KEY NOT NULL CHECK (length(preparation_attempt_id) = 64),
    preparation_version INTEGER NOT NULL CHECK (preparation_version = 1),
    sprint_id TEXT NOT NULL CHECK (length(CAST(sprint_id AS BLOB)) BETWEEN 1 AND 256),
    attempt_id TEXT NOT NULL UNIQUE CHECK (length(CAST(attempt_id AS BLOB)) BETWEEN 1 AND 256),
    launch_authority_digest TEXT NOT NULL UNIQUE CHECK (length(launch_authority_digest) = 64),
    capture_authority_digest TEXT NOT NULL UNIQUE CHECK (length(capture_authority_digest) = 64),
    acquired_anchor_digest TEXT NOT NULL UNIQUE CHECK (length(acquired_anchor_digest) = 64),
    native_journal_id TEXT NOT NULL UNIQUE CHECK (length(native_journal_id) = 64),
    cleanup_effect_id TEXT NOT NULL UNIQUE CHECK (length(cleanup_effect_id) = 64),
    preparation_receipt_id TEXT NOT NULL UNIQUE CHECK (length(preparation_receipt_id) = 64),
    target_id TEXT NOT NULL CHECK (
        target_id IN (
            'macos-15-apple-silicon',
            'ubuntu-26.04-x86_64',
            'fedora-44-x86_64'
        )
    ),
    target_identity_digest TEXT NOT NULL CHECK (length(target_identity_digest) = 64),
    native_policy_digest TEXT NOT NULL CHECK (length(native_policy_digest) = 64),
    runner_binary_digest TEXT NOT NULL CHECK (length(runner_binary_digest) = 64),
    runner_binary_size_bytes INTEGER NOT NULL CHECK (runner_binary_size_bytes > 0),
    runner_protocol_version INTEGER NOT NULL CHECK (runner_protocol_version = 13),
    runner_protocol_digest TEXT NOT NULL CHECK (length(runner_protocol_digest) = 64),
    private_state_id TEXT NOT NULL
        CHECK (length(CAST(private_state_id AS BLOB)) BETWEEN 1 AND 256),
    private_state_digest TEXT NOT NULL CHECK (length(private_state_digest) = 64),
    workspace_grant_hash TEXT NOT NULL CHECK (length(workspace_grant_hash) = 64),
    execution_policy_digest TEXT NOT NULL CHECK (length(execution_policy_digest) = 64),
    expected_source_identity_digest TEXT NOT NULL CHECK (length(expected_source_identity_digest) = 64),
    expected_service_protocol_version INTEGER NOT NULL
        CHECK (expected_service_protocol_version > 0),
    expected_service_protocol_digest TEXT NOT NULL
        CHECK (length(expected_service_protocol_digest) = 64),
    expected_service_manifest_digest TEXT NOT NULL
        CHECK (length(expected_service_manifest_digest) = 64),
    platform_expectation_digest TEXT NOT NULL
        CHECK (length(platform_expectation_digest) = 64),
    ledger_database_identity_digest TEXT NOT NULL
        CHECK (length(ledger_database_identity_digest) = 64),
    state_root_identity_digest TEXT NOT NULL
        CHECK (length(state_root_identity_digest) = 64),
    launch_cleanup_lock_identity_digest TEXT NOT NULL
        CHECK (length(launch_cleanup_lock_identity_digest) = 64),
    claimed_at_unix_ms INTEGER NOT NULL CHECK (claimed_at_unix_ms > 0),
    attempt_digest TEXT NOT NULL UNIQUE CHECK (length(attempt_digest) = 64),
    attempt_json BLOB NOT NULL CHECK (length(attempt_json) BETWEEN 1 AND 1048576),
    UNIQUE (sprint_id, attempt_id),
    UNIQUE (cleanup_effect_id, preparation_attempt_id),
    FOREIGN KEY (attempt_id)
        REFERENCES current_final_verification_capture_acquisitions_v36(attempt_id)
        ON DELETE RESTRICT,
    FOREIGN KEY (sprint_id, attempt_id)
        REFERENCES current_final_verification_capture_acquisitions_v36(sprint_id, attempt_id)
        ON DELETE RESTRICT,
    FOREIGN KEY (launch_authority_digest)
        REFERENCES current_final_verification_capture_acquisitions_v36(launch_authority_digest)
        ON DELETE RESTRICT,
    FOREIGN KEY (capture_authority_digest)
        REFERENCES current_final_verification_capture_acquisitions_v36(capture_authority_digest)
        ON DELETE RESTRICT,
    -- This reverse link makes the attempt and its obligation one indivisible
    -- committed prefix. Both rows are inserted in one deferred transaction.
    FOREIGN KEY (cleanup_effect_id, preparation_attempt_id)
        REFERENCES current_final_verification_native_cleanup_obligations_v37(
            cleanup_effect_id, preparation_attempt_id
        )
        ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED,
    CHECK (
        grok_current_final_verification_native_preparation_attempt_v37_canonical(attempt_json) = 1
    ),
    CHECK (
        grok_current_final_verification_native_preparation_attempt_v37_digest(attempt_json)
        = attempt_digest
    ),
    CHECK (
        grok_current_final_verification_native_preparation_attempt_v37_matches(
            attempt_json,
            preparation_attempt_id,
            preparation_version,
            sprint_id,
            attempt_id,
            launch_authority_digest,
            capture_authority_digest,
            acquired_anchor_digest,
            native_journal_id,
            cleanup_effect_id,
            preparation_receipt_id,
            target_id,
            target_identity_digest,
            native_policy_digest,
            runner_binary_digest,
            runner_binary_size_bytes,
            runner_protocol_version,
            runner_protocol_digest,
            private_state_id,
            private_state_digest,
            workspace_grant_hash,
            execution_policy_digest,
            expected_source_identity_digest,
            expected_service_protocol_version,
            expected_service_protocol_digest,
            expected_service_manifest_digest,
            platform_expectation_digest,
            ledger_database_identity_digest,
            state_root_identity_digest,
            launch_cleanup_lock_identity_digest,
            claimed_at_unix_ms
        ) = 1
    )
) STRICT, WITHOUT ROWID;

CREATE TABLE current_final_verification_native_cleanup_obligations_v37 (
    cleanup_effect_id TEXT PRIMARY KEY NOT NULL CHECK (length(cleanup_effect_id) = 64),
    preparation_attempt_id TEXT NOT NULL UNIQUE CHECK (length(preparation_attempt_id) = 64),
    sprint_id TEXT NOT NULL CHECK (length(CAST(sprint_id AS BLOB)) BETWEEN 1 AND 256),
    attempt_id TEXT NOT NULL UNIQUE CHECK (length(CAST(attempt_id AS BLOB)) BETWEEN 1 AND 256),
    native_journal_id TEXT NOT NULL UNIQUE CHECK (length(native_journal_id) = 64),
    state TEXT NOT NULL CHECK (state = 'Pending'),
    obligation_digest TEXT NOT NULL UNIQUE CHECK (length(obligation_digest) = 64),
    obligation_json BLOB NOT NULL CHECK (length(obligation_json) BETWEEN 1 AND 1048576),
    UNIQUE (cleanup_effect_id, preparation_attempt_id),
    FOREIGN KEY (preparation_attempt_id)
        REFERENCES current_final_verification_native_preparation_attempts_v37(preparation_attempt_id)
        ON DELETE RESTRICT,
    FOREIGN KEY (sprint_id, attempt_id)
        REFERENCES current_final_verification_native_preparation_attempts_v37(sprint_id, attempt_id)
        ON DELETE RESTRICT,
    CHECK (
        grok_current_final_verification_native_cleanup_obligation_v37_canonical(obligation_json) = 1
    ),
    CHECK (
        grok_current_final_verification_native_cleanup_obligation_v37_digest(obligation_json)
        = obligation_digest
    ),
    CHECK (
        grok_current_final_verification_native_cleanup_obligation_v37_matches(
            obligation_json,
            cleanup_effect_id,
            preparation_attempt_id,
            sprint_id,
            attempt_id,
            native_journal_id,
            state
        ) = 1
    )
) STRICT, WITHOUT ROWID;

CREATE TABLE current_final_verification_native_source_consumptions_v37 (
    source_consumption_id TEXT PRIMARY KEY NOT NULL CHECK (length(source_consumption_id) = 64),
    preparation_attempt_id TEXT NOT NULL UNIQUE CHECK (length(preparation_attempt_id) = 64),
    sprint_id TEXT NOT NULL CHECK (length(CAST(sprint_id AS BLOB)) BETWEEN 1 AND 256),
    attempt_id TEXT NOT NULL UNIQUE CHECK (length(CAST(attempt_id AS BLOB)) BETWEEN 1 AND 256),
    operation_domain TEXT NOT NULL CHECK (operation_domain = 'NativePreparationV1'),
    authenticated_source_identity_digest TEXT NOT NULL
        CHECK (length(authenticated_source_identity_digest) = 64),
    source_session_identity_digest TEXT NOT NULL
        CHECK (length(source_session_identity_digest) = 64),
    operation_sequence TEXT NOT NULL
        CHECK (length(operation_sequence) BETWEEN 1 AND 20),
    payload_digest TEXT NOT NULL CHECK (length(payload_digest) = 64),
    payload_length INTEGER NOT NULL CHECK (payload_length >= 0),
    disposition TEXT NOT NULL CHECK (disposition IN ('Accepted', 'SourceRejected')),
    rejection_reason TEXT,
    accepted_payload_json BLOB,
    accepted_preparation_receipt_id TEXT,
    consumed_at_unix_ms INTEGER NOT NULL CHECK (consumed_at_unix_ms > 0),
    consumption_digest TEXT NOT NULL UNIQUE CHECK (length(consumption_digest) = 64),
    consumption_json BLOB NOT NULL CHECK (length(consumption_json) BETWEEN 1 AND 1048576),
    UNIQUE (
        operation_domain,
        authenticated_source_identity_digest,
        source_session_identity_digest,
        operation_sequence
    ),
    UNIQUE (accepted_preparation_receipt_id, source_consumption_id),
    FOREIGN KEY (preparation_attempt_id)
        REFERENCES current_final_verification_native_preparation_attempts_v37(preparation_attempt_id)
        ON DELETE RESTRICT,
    FOREIGN KEY (sprint_id, attempt_id)
        REFERENCES current_final_verification_native_preparation_attempts_v37(sprint_id, attempt_id)
        ON DELETE RESTRICT,
    -- An accepted source and its exact derived outcome must commit together.
    -- The nullable receipt keeps SourceRejected terminal without an outcome.
    FOREIGN KEY (accepted_preparation_receipt_id, source_consumption_id)
        REFERENCES current_final_verification_native_preparation_outcomes_v37(
            preparation_receipt_id, source_consumption_id
        )
        ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED,
    CHECK (
        (disposition = 'Accepted'
            AND rejection_reason IS NULL
            AND accepted_payload_json IS NOT NULL
            AND accepted_preparation_receipt_id IS NOT NULL
            AND payload_length = length(accepted_payload_json)
            AND payload_length BETWEEN 1 AND 1048576)
        OR
        (disposition = 'SourceRejected'
            AND rejection_reason IS NOT NULL
            AND rejection_reason IN (
                'Oversized', 'Malformed', 'NonCanonical', 'CrossedIdentity',
                'TimeInvalid', 'EvidenceInvalid', 'SourceIdentityMismatch'
            )
            AND (
                rejection_reason = 'SourceIdentityMismatch'
                OR (rejection_reason = 'Oversized' AND payload_length > 1048576)
                OR (
                    rejection_reason NOT IN ('SourceIdentityMismatch', 'Oversized')
                    AND payload_length <= 1048576
                )
            )
            AND accepted_payload_json IS NULL
            AND accepted_preparation_receipt_id IS NULL)
    ),
    CHECK (
        grok_current_final_verification_native_operation_sequence_v37_canonical(
            operation_sequence
        ) = 1
    ),
    CHECK (
        CASE
            WHEN accepted_payload_json IS NULL THEN 1
            ELSE
                grok_current_final_verification_native_source_payload_v37_canonical(
                    accepted_payload_json
                ) = 1
                AND grok_current_final_verification_native_source_payload_v37_digest(
                    accepted_payload_json
                ) = payload_digest
        END = 1
    ),
    CHECK (
        grok_current_final_verification_native_source_consumption_v37_canonical(consumption_json) = 1
    ),
    CHECK (
        grok_current_final_verification_native_source_consumption_v37_digest(consumption_json)
        = consumption_digest
    ),
    CHECK (
        grok_current_final_verification_native_source_consumption_v37_matches(
            consumption_json,
            source_consumption_id,
            preparation_attempt_id,
            sprint_id,
            attempt_id,
            operation_domain,
            authenticated_source_identity_digest,
            source_session_identity_digest,
            operation_sequence,
            payload_digest,
            payload_length,
            disposition,
            rejection_reason,
            accepted_preparation_receipt_id,
            consumed_at_unix_ms
        ) = 1
    )
) STRICT, WITHOUT ROWID;

CREATE TABLE current_final_verification_native_preparation_outcomes_v37 (
    preparation_receipt_id TEXT PRIMARY KEY NOT NULL CHECK (length(preparation_receipt_id) = 64),
    preparation_attempt_id TEXT NOT NULL UNIQUE CHECK (length(preparation_attempt_id) = 64),
    source_consumption_id TEXT NOT NULL UNIQUE CHECK (length(source_consumption_id) = 64),
    sprint_id TEXT NOT NULL CHECK (length(CAST(sprint_id AS BLOB)) BETWEEN 1 AND 256),
    attempt_id TEXT NOT NULL UNIQUE CHECK (length(CAST(attempt_id AS BLOB)) BETWEEN 1 AND 256),
    native_journal_id TEXT NOT NULL UNIQUE CHECK (length(native_journal_id) = 64),
    cleanup_effect_id TEXT NOT NULL UNIQUE CHECK (length(cleanup_effect_id) = 64),
    disposition TEXT NOT NULL CHECK (
        disposition IN (
            'HeldChildPrepared',
            'RefusedBeforeNativeEffect',
            'NativeEffectUncertain'
        )
    ),
    native_evidence_digest TEXT NOT NULL CHECK (length(native_evidence_digest) = 64),
    native_evidence_bytes BLOB NOT NULL
        CHECK (length(native_evidence_bytes) BETWEEN 1 AND 65536),
    finished_at_unix_ms INTEGER NOT NULL CHECK (finished_at_unix_ms > 0),
    outcome_digest TEXT NOT NULL UNIQUE CHECK (length(outcome_digest) = 64),
    outcome_json BLOB NOT NULL CHECK (length(outcome_json) BETWEEN 1 AND 1048576),
    UNIQUE (preparation_receipt_id, source_consumption_id),
    FOREIGN KEY (preparation_attempt_id)
        REFERENCES current_final_verification_native_preparation_attempts_v37(preparation_attempt_id)
        ON DELETE RESTRICT,
    FOREIGN KEY (source_consumption_id)
        REFERENCES current_final_verification_native_source_consumptions_v37(source_consumption_id)
        ON DELETE RESTRICT,
    FOREIGN KEY (sprint_id, attempt_id)
        REFERENCES current_final_verification_native_preparation_attempts_v37(sprint_id, attempt_id)
        ON DELETE RESTRICT,
    FOREIGN KEY (cleanup_effect_id)
        REFERENCES current_final_verification_native_cleanup_obligations_v37(cleanup_effect_id)
        ON DELETE RESTRICT,
    CHECK (
        grok_current_final_verification_native_preparation_outcome_v37_canonical(outcome_json) = 1
    ),
    CHECK (
        grok_current_final_verification_native_preparation_outcome_v37_digest(outcome_json)
        = outcome_digest
    ),
    CHECK (
        grok_current_final_verification_native_evidence_v37_digest(native_evidence_bytes)
        = native_evidence_digest
    ),
    CHECK (
        grok_current_final_verification_native_preparation_outcome_v37_matches(
            outcome_json,
            preparation_receipt_id,
            preparation_attempt_id,
            source_consumption_id,
            sprint_id,
            attempt_id,
            native_journal_id,
            cleanup_effect_id,
            disposition,
            native_evidence_digest,
            native_evidence_bytes,
            finished_at_unix_ms
        ) = 1
    )
) STRICT, WITHOUT ROWID;

CREATE TRIGGER current_final_verification_native_preparation_attempts_v37_validate_insert
BEFORE INSERT ON current_final_verification_native_preparation_attempts_v37
WHEN grok_current_final_verification_native_preparation_write_admitted_v37(
         'attempt', NEW.preparation_attempt_id, NEW.attempt_digest
     ) != 1
  OR NOT EXISTS (
      SELECT 1
      FROM current_final_verification_capture_acquisitions_v36 capture
      JOIN current_final_verification_launches_v35 launch
        ON launch.attempt_id = capture.attempt_id
      WHERE capture.attempt_id = NEW.attempt_id
        AND capture.sprint_id = NEW.sprint_id
        AND capture.launch_authority_digest = NEW.launch_authority_digest
        AND capture.capture_authority_digest = NEW.capture_authority_digest
        AND capture.acquired_anchor_digest = NEW.acquired_anchor_digest
        AND capture.acquired_at_unix_ms <= NEW.claimed_at_unix_ms
        AND launch.target_identity_digest = NEW.target_identity_digest
        AND launch.native_policy_digest = NEW.native_policy_digest
        AND launch.runner_binary_digest = NEW.runner_binary_digest
        AND launch.runner_binary_size_bytes = NEW.runner_binary_size_bytes
        AND launch.runner_protocol_version = NEW.runner_protocol_version
        AND launch.runner_protocol_digest = NEW.runner_protocol_digest
        AND launch.private_state_id = NEW.private_state_id
        AND launch.private_state_digest = NEW.private_state_digest
        AND launch.workspace_grant_hash = NEW.workspace_grant_hash
        AND launch.execution_policy_digest = NEW.execution_policy_digest
        AND grok_current_final_verification_native_attempt_v37_matches_parent(
            NEW.attempt_json,
            launch.launch_authority_json,
            capture.capture_authority_json
        ) = 1
        AND EXISTS (
            SELECT 1 FROM current_final_verification_lifecycle_reservations_v35 reservation
            WHERE reservation.attempt_id = NEW.attempt_id
              AND reservation.reservation_role = 'native_launch_preparation_attempt_id'
              AND reservation.reserved_id = NEW.preparation_attempt_id
        )
        AND EXISTS (
            SELECT 1 FROM current_final_verification_lifecycle_reservations_v35 reservation
            WHERE reservation.attempt_id = NEW.attempt_id
              AND reservation.reservation_role = 'native_launch_journal_id'
              AND reservation.reserved_id = NEW.native_journal_id
        )
        AND EXISTS (
            SELECT 1 FROM current_final_verification_lifecycle_reservations_v35 reservation
            WHERE reservation.attempt_id = NEW.attempt_id
              AND reservation.reservation_role = 'native_launch_cleanup_effect_id'
              AND reservation.reserved_id = NEW.cleanup_effect_id
        )
        AND EXISTS (
            SELECT 1 FROM current_final_verification_lifecycle_reservations_v35 reservation
            WHERE reservation.attempt_id = NEW.attempt_id
              AND reservation.reservation_role = 'native_launch_preparation_receipt_id'
              AND reservation.reserved_id = NEW.preparation_receipt_id
        )
        AND NOT EXISTS (
            SELECT 1 FROM current_final_verification_events_v34 later
            WHERE later.attempt_id = NEW.attempt_id
              AND later.event_kind NOT IN (
                  'AttemptAdmitted', 'LaunchCommitted', 'CaptureAcquired'
              )
        )
  )
BEGIN SELECT RAISE(ABORT, 'current native preparation attempt crosses exact v36 authority, time, or event frontier'); END;

CREATE TRIGGER current_final_verification_native_cleanup_obligations_v37_validate_insert
BEFORE INSERT ON current_final_verification_native_cleanup_obligations_v37
WHEN grok_current_final_verification_native_preparation_write_admitted_v37(
         'cleanup', NEW.cleanup_effect_id, NEW.obligation_digest
     ) != 1
  OR NOT EXISTS (
      SELECT 1 FROM current_final_verification_native_preparation_attempts_v37 attempt
      WHERE attempt.preparation_attempt_id = NEW.preparation_attempt_id
        AND attempt.sprint_id = NEW.sprint_id
        AND attempt.attempt_id = NEW.attempt_id
        AND attempt.native_journal_id = NEW.native_journal_id
        AND attempt.cleanup_effect_id = NEW.cleanup_effect_id
  )
BEGIN SELECT RAISE(ABORT, 'current native cleanup obligation requires its exact preparation attempt'); END;

CREATE TRIGGER current_final_verification_native_source_consumptions_v37_validate_insert
BEFORE INSERT ON current_final_verification_native_source_consumptions_v37
WHEN grok_current_final_verification_native_preparation_write_admitted_v37(
         'source', NEW.source_consumption_id, NEW.consumption_digest
     ) != 1
  OR NOT EXISTS (
      SELECT 1 FROM current_final_verification_native_preparation_attempts_v37 attempt
      JOIN current_final_verification_native_cleanup_obligations_v37 cleanup
        ON cleanup.preparation_attempt_id = attempt.preparation_attempt_id
      WHERE attempt.preparation_attempt_id = NEW.preparation_attempt_id
        AND attempt.sprint_id = NEW.sprint_id
        AND attempt.attempt_id = NEW.attempt_id
        AND (
            (
                NEW.disposition = 'Accepted'
                AND attempt.expected_source_identity_digest
                    = NEW.authenticated_source_identity_digest
            )
            OR (
                NEW.disposition = 'SourceRejected'
                AND (
                    (
                        NEW.rejection_reason = 'SourceIdentityMismatch'
                        AND attempt.expected_source_identity_digest
                            <> NEW.authenticated_source_identity_digest
                    )
                    OR (
                        NEW.rejection_reason <> 'SourceIdentityMismatch'
                        AND attempt.expected_source_identity_digest
                            = NEW.authenticated_source_identity_digest
                    )
                )
            )
        )
        AND attempt.claimed_at_unix_ms <= NEW.consumed_at_unix_ms
        AND cleanup.cleanup_effect_id = attempt.cleanup_effect_id
        AND cleanup.native_journal_id = attempt.native_journal_id
        AND cleanup.state = 'Pending'
        AND CASE
            WHEN NEW.disposition = 'SourceRejected' THEN 1
            WHEN NEW.disposition = 'Accepted'
                AND NEW.accepted_payload_json IS NOT NULL
            THEN grok_current_final_verification_native_source_payload_v37_matches_attempt(
                NEW.accepted_payload_json,
                attempt.attempt_json,
                cleanup.obligation_json,
                NEW.authenticated_source_identity_digest,
                NEW.source_session_identity_digest,
                NEW.operation_sequence,
                NEW.consumed_at_unix_ms
            )
            ELSE 0
        END = 1
  )
BEGIN SELECT RAISE(ABORT, 'current native source consumption crosses its exact authenticated source, pending obligation, parent, or time'); END;

CREATE TRIGGER current_final_verification_native_preparation_outcomes_v37_validate_insert
BEFORE INSERT ON current_final_verification_native_preparation_outcomes_v37
WHEN grok_current_final_verification_native_preparation_write_admitted_v37(
         'outcome', NEW.preparation_receipt_id, NEW.outcome_digest
     ) != 1
  OR NOT EXISTS (
      SELECT 1
      FROM current_final_verification_native_preparation_attempts_v37 attempt
      JOIN current_final_verification_native_cleanup_obligations_v37 cleanup
        ON cleanup.preparation_attempt_id = attempt.preparation_attempt_id
      JOIN current_final_verification_native_source_consumptions_v37 source
        ON source.preparation_attempt_id = attempt.preparation_attempt_id
      WHERE attempt.preparation_attempt_id = NEW.preparation_attempt_id
        AND attempt.preparation_receipt_id = NEW.preparation_receipt_id
        AND attempt.sprint_id = NEW.sprint_id
        AND attempt.attempt_id = NEW.attempt_id
        AND attempt.native_journal_id = NEW.native_journal_id
        AND attempt.claimed_at_unix_ms <= NEW.finished_at_unix_ms
        AND cleanup.cleanup_effect_id = NEW.cleanup_effect_id
        AND cleanup.state = 'Pending'
        AND source.source_consumption_id = NEW.source_consumption_id
        AND source.accepted_preparation_receipt_id = NEW.preparation_receipt_id
        AND NEW.finished_at_unix_ms <= source.consumed_at_unix_ms
        AND CASE
            WHEN source.disposition = 'Accepted'
                AND source.accepted_payload_json IS NOT NULL
            THEN grok_current_final_verification_native_outcome_v37_matches_source(
                NEW.outcome_json,
                source.accepted_payload_json,
                source.consumption_json,
                attempt.attempt_json,
                cleanup.obligation_json
            )
            ELSE 0
        END = 1
  )
BEGIN SELECT RAISE(ABORT, 'current native preparation outcome does not derive from its exact accepted source and pending obligation'); END;

CREATE TRIGGER current_final_verification_native_preparation_attempts_v37_no_update
BEFORE UPDATE ON current_final_verification_native_preparation_attempts_v37
BEGIN SELECT RAISE(ABORT, 'current native preparation attempts are immutable'); END;
CREATE TRIGGER current_final_verification_native_preparation_attempts_v37_no_delete
BEFORE DELETE ON current_final_verification_native_preparation_attempts_v37
BEGIN SELECT RAISE(ABORT, 'current native preparation attempts are immutable'); END;
CREATE TRIGGER current_final_verification_native_preparation_attempts_v37_no_replace
BEFORE INSERT ON current_final_verification_native_preparation_attempts_v37
WHEN EXISTS (
    SELECT 1 FROM current_final_verification_native_preparation_attempts_v37 existing
    WHERE existing.preparation_attempt_id = NEW.preparation_attempt_id
       OR existing.attempt_id = NEW.attempt_id
       OR existing.launch_authority_digest = NEW.launch_authority_digest
       OR existing.capture_authority_digest = NEW.capture_authority_digest
       OR existing.acquired_anchor_digest = NEW.acquired_anchor_digest
       OR existing.native_journal_id = NEW.native_journal_id
       OR existing.cleanup_effect_id = NEW.cleanup_effect_id
       OR existing.preparation_receipt_id = NEW.preparation_receipt_id
       OR existing.attempt_digest = NEW.attempt_digest
)
BEGIN SELECT RAISE(ABORT, 'current native preparation attempt identity already exists'); END;

CREATE TRIGGER current_final_verification_native_cleanup_obligations_v37_no_update
BEFORE UPDATE ON current_final_verification_native_cleanup_obligations_v37
BEGIN SELECT RAISE(ABORT, 'current native cleanup obligations are immutable'); END;
CREATE TRIGGER current_final_verification_native_cleanup_obligations_v37_no_delete
BEFORE DELETE ON current_final_verification_native_cleanup_obligations_v37
BEGIN SELECT RAISE(ABORT, 'current native cleanup obligations are immutable'); END;
CREATE TRIGGER current_final_verification_native_cleanup_obligations_v37_no_replace
BEFORE INSERT ON current_final_verification_native_cleanup_obligations_v37
WHEN EXISTS (
    SELECT 1 FROM current_final_verification_native_cleanup_obligations_v37 existing
    WHERE existing.cleanup_effect_id = NEW.cleanup_effect_id
       OR existing.preparation_attempt_id = NEW.preparation_attempt_id
       OR existing.attempt_id = NEW.attempt_id
       OR existing.native_journal_id = NEW.native_journal_id
       OR existing.obligation_digest = NEW.obligation_digest
)
BEGIN SELECT RAISE(ABORT, 'current native cleanup obligation identity already exists'); END;

CREATE TRIGGER current_final_verification_native_source_consumptions_v37_no_update
BEFORE UPDATE ON current_final_verification_native_source_consumptions_v37
BEGIN SELECT RAISE(ABORT, 'current native source consumptions are immutable'); END;
CREATE TRIGGER current_final_verification_native_source_consumptions_v37_no_delete
BEFORE DELETE ON current_final_verification_native_source_consumptions_v37
BEGIN SELECT RAISE(ABORT, 'current native source consumptions are immutable'); END;
CREATE TRIGGER current_final_verification_native_source_consumptions_v37_no_replace
BEFORE INSERT ON current_final_verification_native_source_consumptions_v37
WHEN EXISTS (
    SELECT 1 FROM current_final_verification_native_source_consumptions_v37 existing
    WHERE existing.source_consumption_id = NEW.source_consumption_id
       OR existing.preparation_attempt_id = NEW.preparation_attempt_id
       OR existing.attempt_id = NEW.attempt_id
       OR (
           existing.operation_domain = NEW.operation_domain
           AND existing.authenticated_source_identity_digest
               = NEW.authenticated_source_identity_digest
           AND existing.source_session_identity_digest
               = NEW.source_session_identity_digest
           AND existing.operation_sequence = NEW.operation_sequence
       )
       OR existing.consumption_digest = NEW.consumption_digest
)
BEGIN SELECT RAISE(ABORT, 'current native source consumption identity already exists'); END;

CREATE TRIGGER current_final_verification_native_preparation_outcomes_v37_no_update
BEFORE UPDATE ON current_final_verification_native_preparation_outcomes_v37
BEGIN SELECT RAISE(ABORT, 'current native preparation outcomes are immutable'); END;
CREATE TRIGGER current_final_verification_native_preparation_outcomes_v37_no_delete
BEFORE DELETE ON current_final_verification_native_preparation_outcomes_v37
BEGIN SELECT RAISE(ABORT, 'current native preparation outcomes are immutable'); END;
CREATE TRIGGER current_final_verification_native_preparation_outcomes_v37_no_replace
BEFORE INSERT ON current_final_verification_native_preparation_outcomes_v37
WHEN EXISTS (
    SELECT 1 FROM current_final_verification_native_preparation_outcomes_v37 existing
    WHERE existing.preparation_receipt_id = NEW.preparation_receipt_id
       OR existing.preparation_attempt_id = NEW.preparation_attempt_id
       OR existing.source_consumption_id = NEW.source_consumption_id
       OR existing.attempt_id = NEW.attempt_id
       OR existing.native_journal_id = NEW.native_journal_id
       OR existing.cleanup_effect_id = NEW.cleanup_effect_id
       OR existing.outcome_digest = NEW.outcome_digest
)
BEGIN SELECT RAISE(ABORT, 'current native preparation outcome identity already exists'); END;
