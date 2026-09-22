-- Schema v27 makes raw command-output custody a prerequisite of every new
-- RunCommand effect and transport claim. Existing v26 rows remain readable;
-- no migration row is backfilled and no historical effect can acquire v27
-- dispatch authority.

CREATE TABLE command_output_capture_intents (
    capture_id TEXT PRIMARY KEY NOT NULL CHECK (
        length(capture_id) = 64 AND capture_id NOT GLOB '*[^0-9a-f]*'
    ),
    effect_id TEXT NOT NULL UNIQUE,
    sprint_id TEXT NOT NULL,
    runner_launch_id TEXT NOT NULL,
    runner_session_id TEXT NOT NULL,
    request_digest TEXT NOT NULL CHECK (
        length(request_digest) = 64 AND request_digest NOT GLOB '*[^0-9a-f]*'
    ),
    private_state_digest TEXT NOT NULL CHECK (
        length(private_state_digest) = 64
        AND private_state_digest NOT GLOB '*[^0-9a-f]*'
    ),
    max_aggregate_output_bytes INTEGER NOT NULL
        CHECK (max_aggregate_output_bytes BETWEEN 1 AND 134217728),
    layout_version INTEGER NOT NULL CHECK (layout_version = 1),
    created_at_unix_ms INTEGER NOT NULL CHECK (created_at_unix_ms > 0),
    intent_digest TEXT NOT NULL UNIQUE CHECK (
        length(intent_digest) = 64 AND intent_digest NOT GLOB '*[^0-9a-f]*'
    ),
    contract_version INTEGER NOT NULL CHECK (contract_version > 0),
    intent_json BLOB NOT NULL CHECK (
        length(intent_json) > 0
        AND intent_digest = grok_command_output_capture_intent_digest(intent_json)
    ),
    UNIQUE (capture_id, effect_id),
    UNIQUE (sprint_id, effect_id),
    UNIQUE (capture_id, effect_id, intent_digest),
    FOREIGN KEY (effect_id) REFERENCES effect_intents(effect_id)
        ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED,
    FOREIGN KEY (sprint_id, runner_launch_id)
        REFERENCES runner_launch_intents(sprint_id, launch_id) ON DELETE RESTRICT,
    FOREIGN KEY (sprint_id, runner_session_id)
        REFERENCES runner_session_policies(sprint_id, session_id) ON DELETE RESTRICT
) STRICT, WITHOUT ROWID;

CREATE INDEX command_output_capture_intents_source_idx
ON command_output_capture_intents (
    sprint_id, runner_launch_id, runner_session_id, effect_id, request_digest
);

CREATE TABLE command_output_capture_reconciliation_obligations (
    obligation_id TEXT PRIMARY KEY NOT NULL CHECK (
        length(obligation_id) = 64 AND obligation_id NOT GLOB '*[^0-9a-f]*'
    ),
    capture_id TEXT NOT NULL UNIQUE,
    effect_id TEXT NOT NULL UNIQUE,
    intent_digest TEXT NOT NULL UNIQUE,
    contract_version INTEGER NOT NULL CHECK (contract_version > 0),
    FOREIGN KEY (capture_id, effect_id, intent_digest)
        REFERENCES command_output_capture_intents(capture_id, effect_id, intent_digest)
        ON DELETE RESTRICT
) STRICT, WITHOUT ROWID;

-- A migrated pre-v27 RunCommand could never have acquired capture authority:
-- the intent must precede the effect row and migration never fabricates that
-- authority.  Preserve that historical cut explicitly so an absent current
-- capture cannot be confused with either a deleted/crossed v27 capture or a
-- genuinely historical effect.  This row means only "capture obligation was
-- not applicable"; all pre-existing effect, command-domain, runner-domain,
-- lease, and terminal requirements remain independently mandatory.
CREATE TABLE pre_v27_command_output_capture_exemptions (
    effect_id TEXT PRIMARY KEY NOT NULL,
    sprint_id TEXT NOT NULL,
    request_digest TEXT NOT NULL CHECK (
        length(request_digest) = 64 AND request_digest NOT GLOB '*[^0-9a-f]*'
    ),
    created_at_unix_ms INTEGER NOT NULL CHECK (created_at_unix_ms > 0),
    contract_version INTEGER NOT NULL CHECK (contract_version > 0),
    intent_digest TEXT NOT NULL CHECK (
        length(intent_digest) = 64 AND intent_digest NOT GLOB '*[^0-9a-f]*'
    ),
    UNIQUE (effect_id, sprint_id, request_digest),
    FOREIGN KEY (effect_id) REFERENCES effect_intents(effect_id)
        ON DELETE RESTRICT
) STRICT, WITHOUT ROWID;

INSERT INTO pre_v27_command_output_capture_exemptions (
    effect_id, sprint_id, request_digest, created_at_unix_ms,
    contract_version, intent_digest
)
SELECT effect_id, sprint_id, request_digest, created_at_unix_ms,
       contract_version, grok_sha256(intent_json)
FROM effect_intents
WHERE effect_kind = 'RunCommand';

CREATE TRIGGER pre_v27_command_output_capture_exemptions_no_insert
BEFORE INSERT ON pre_v27_command_output_capture_exemptions
BEGIN SELECT RAISE(ABORT, 'pre-v27 command output capture exemptions are migration-only'); END;
CREATE TRIGGER pre_v27_command_output_capture_exemptions_no_update
BEFORE UPDATE ON pre_v27_command_output_capture_exemptions
BEGIN SELECT RAISE(ABORT, 'pre-v27 command output capture exemptions are immutable'); END;
CREATE TRIGGER pre_v27_command_output_capture_exemptions_no_delete
BEFORE DELETE ON pre_v27_command_output_capture_exemptions
BEGIN SELECT RAISE(ABORT, 'pre-v27 command output capture exemptions are immutable'); END;

CREATE TRIGGER command_output_capture_intents_no_backfill
BEFORE INSERT ON command_output_capture_intents
WHEN EXISTS (SELECT 1 FROM effect_intents WHERE effect_id = NEW.effect_id)
   OR EXISTS (
       SELECT 1 FROM command_output_capture_intents
       WHERE capture_id = NEW.capture_id OR effect_id = NEW.effect_id
   )
BEGIN SELECT RAISE(ABORT, 'command output capture intents cannot be backfilled'); END;

CREATE TRIGGER command_output_capture_intents_exact_source
BEFORE INSERT ON command_output_capture_intents
WHEN NOT EXISTS (
    SELECT 1
    FROM effect_session_bindings binding
    JOIN runner_launch_intents launch
      ON launch.sprint_id = binding.sprint_id
     AND launch.launch_id = binding.launch_id
    JOIN runner_session_policies session
      ON session.sprint_id = binding.sprint_id
     AND session.session_id = binding.session_id
     AND session.launch_id = launch.launch_id
    WHERE binding.effect_id = NEW.effect_id
      AND binding.sprint_id = NEW.sprint_id
      AND binding.launch_id = NEW.runner_launch_id
      AND binding.session_id = NEW.runner_session_id
      AND launch.private_state_digest = NEW.private_state_digest
      AND session.private_state_digest = NEW.private_state_digest
      AND session.purpose IN ('TaskWorker', 'FinalVerifier')
      AND binding.contract_version = NEW.contract_version
      AND launch.contract_version = NEW.contract_version
      AND session.contract_version = NEW.contract_version
      AND json_extract(CAST(NEW.intent_json AS TEXT), '$.capture_id') = NEW.capture_id
      AND json_extract(CAST(NEW.intent_json AS TEXT), '$.source.effect_id') = NEW.effect_id
      AND json_extract(CAST(NEW.intent_json AS TEXT), '$.source.sprint_id') = NEW.sprint_id
      AND json_extract(CAST(NEW.intent_json AS TEXT), '$.source.runner_launch_id') = NEW.runner_launch_id
      AND json_extract(CAST(NEW.intent_json AS TEXT), '$.source.runner_session_id') = NEW.runner_session_id
      AND json_extract(CAST(NEW.intent_json AS TEXT), '$.source.request_digest') = NEW.request_digest
      AND json_extract(CAST(NEW.intent_json AS TEXT), '$.private_state_digest') = NEW.private_state_digest
      AND json_extract(CAST(NEW.intent_json AS TEXT), '$.max_aggregate_output_bytes') = NEW.max_aggregate_output_bytes
      AND json_extract(CAST(NEW.intent_json AS TEXT), '$.layout_version') = NEW.layout_version
      AND json_extract(CAST(NEW.intent_json AS TEXT), '$.created_at_unix_ms') = NEW.created_at_unix_ms
      AND json_extract(CAST(NEW.intent_json AS TEXT), '$.intent_digest') = NEW.intent_digest
      AND json_extract(CAST(NEW.intent_json AS TEXT), '$.contract_version') = NEW.contract_version
)
BEGIN SELECT RAISE(ABORT, 'command output capture intent must match one exact runner source'); END;

CREATE TRIGGER effect_intents_require_v27_command_output_capture
BEFORE INSERT ON effect_intents
WHEN NEW.effect_kind = 'RunCommand' AND NOT EXISTS (
    SELECT 1
    FROM command_output_capture_intents capture
    JOIN command_output_capture_reconciliation_obligations obligation
      ON obligation.capture_id = capture.capture_id
     AND obligation.effect_id = capture.effect_id
     AND obligation.intent_digest = capture.intent_digest
    WHERE capture.effect_id = NEW.effect_id
      AND capture.sprint_id = NEW.sprint_id
      AND capture.request_digest = NEW.request_digest
      AND capture.created_at_unix_ms = NEW.created_at_unix_ms
      AND capture.contract_version = NEW.contract_version
      AND obligation.contract_version = NEW.contract_version
)
BEGIN SELECT RAISE(ABORT, 'new RunCommand intent requires atomic v27 output capture authority'); END;

CREATE TRIGGER command_output_capture_intents_terminal_fence
BEFORE INSERT ON command_output_capture_intents
WHEN EXISTS (SELECT 1 FROM sprint_completion_proof_states WHERE sprint_id = NEW.sprint_id)
  OR EXISTS (SELECT 1 FROM sprint_non_success_terminal_outcomes WHERE sprint_id = NEW.sprint_id)
  OR EXISTS (SELECT 1 FROM sprint_terminal_states WHERE sprint_id = NEW.sprint_id)
BEGIN SELECT RAISE(ABORT, 'terminal sprints reject output capture intents'); END;

CREATE TRIGGER command_output_capture_intents_no_update
BEFORE UPDATE ON command_output_capture_intents
BEGIN SELECT RAISE(ABORT, 'command output capture intents are immutable'); END;
CREATE TRIGGER command_output_capture_intents_no_delete
BEFORE DELETE ON command_output_capture_intents
BEGIN SELECT RAISE(ABORT, 'command output capture intents are immutable'); END;
CREATE TRIGGER command_output_capture_obligations_no_update
BEFORE UPDATE ON command_output_capture_reconciliation_obligations
BEGIN SELECT RAISE(ABORT, 'command output capture obligations are immutable'); END;
CREATE TRIGGER command_output_capture_obligations_no_delete
BEFORE DELETE ON command_output_capture_reconciliation_obligations
BEGIN SELECT RAISE(ABORT, 'command output capture obligations are immutable'); END;

CREATE TABLE command_output_capture_acquisitions (
    capture_id TEXT PRIMARY KEY NOT NULL,
    effect_id TEXT NOT NULL UNIQUE,
    sprint_id TEXT NOT NULL,
    runner_launch_id TEXT NOT NULL,
    runner_session_id TEXT NOT NULL,
    request_digest TEXT NOT NULL,
    private_state_digest TEXT NOT NULL,
    max_aggregate_output_bytes INTEGER NOT NULL
        CHECK (max_aggregate_output_bytes BETWEEN 1 AND 134217728),
    intent_digest TEXT NOT NULL UNIQUE,
    dispatch_claim_id TEXT NOT NULL UNIQUE,
    store_head_generation INTEGER NOT NULL CHECK (store_head_generation > 0),
    store_head_digest TEXT NOT NULL CHECK (
        length(store_head_digest) = 64 AND store_head_digest NOT GLOB '*[^0-9a-f]*'
    ),
    working_device_id INTEGER NOT NULL CHECK (working_device_id >= 0),
    working_inode INTEGER NOT NULL CHECK (working_inode > 0),
    working_owner_uid INTEGER NOT NULL CHECK (working_owner_uid >= 0),
    working_mode INTEGER NOT NULL CHECK (working_mode = 448),
    working_link_count INTEGER NOT NULL CHECK (working_link_count > 0),
    stdout_device_id INTEGER NOT NULL CHECK (stdout_device_id >= 0),
    stdout_inode INTEGER NOT NULL CHECK (stdout_inode > 0),
    stdout_owner_uid INTEGER NOT NULL CHECK (stdout_owner_uid >= 0),
    stdout_mode INTEGER NOT NULL CHECK (stdout_mode = 384),
    stdout_link_count INTEGER NOT NULL CHECK (stdout_link_count = 1),
    stdout_byte_length INTEGER NOT NULL CHECK (stdout_byte_length = 0),
    stderr_device_id INTEGER NOT NULL CHECK (stderr_device_id >= 0),
    stderr_inode INTEGER NOT NULL CHECK (stderr_inode > 0),
    stderr_owner_uid INTEGER NOT NULL CHECK (stderr_owner_uid >= 0),
    stderr_mode INTEGER NOT NULL CHECK (stderr_mode = 384),
    stderr_link_count INTEGER NOT NULL CHECK (stderr_link_count = 1),
    stderr_byte_length INTEGER NOT NULL CHECK (stderr_byte_length = 0),
    acquired_at_unix_ms INTEGER NOT NULL CHECK (acquired_at_unix_ms > 0),
    acquired_anchor_digest TEXT NOT NULL UNIQUE CHECK (
        length(acquired_anchor_digest) = 64
        AND acquired_anchor_digest NOT GLOB '*[^0-9a-f]*'
    ),
    layout_version INTEGER NOT NULL CHECK (layout_version = 1),
    contract_version INTEGER NOT NULL CHECK (contract_version > 0),
    acquired_json BLOB NOT NULL CHECK (
        length(acquired_json) > 0
        AND acquired_anchor_digest = grok_command_output_capture_acquired_digest(acquired_json)
    ),
    CHECK (working_owner_uid = stdout_owner_uid AND working_owner_uid = stderr_owner_uid),
    CHECK (stdout_device_id != stderr_device_id OR stdout_inode != stderr_inode),
    UNIQUE (capture_id, effect_id, acquired_anchor_digest),
    FOREIGN KEY (capture_id, effect_id, intent_digest)
        REFERENCES command_output_capture_intents(capture_id, effect_id, intent_digest)
        ON DELETE RESTRICT,
    FOREIGN KEY (dispatch_claim_id)
        REFERENCES runner_effect_dispatch_claims(dispatch_claim_id)
        ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED
) STRICT, WITHOUT ROWID;

CREATE TRIGGER command_output_capture_acquisitions_no_backfill
BEFORE INSERT ON command_output_capture_acquisitions
WHEN EXISTS (SELECT 1 FROM runner_effect_dispatch_claims WHERE effect_id = NEW.effect_id)
   OR EXISTS (SELECT 1 FROM effect_observations WHERE effect_id = NEW.effect_id)
BEGIN SELECT RAISE(ABORT, 'capture acquisition must precede a new dispatch claim'); END;

CREATE TRIGGER command_output_capture_acquisitions_exact_intent
BEFORE INSERT ON command_output_capture_acquisitions
WHEN NOT EXISTS (
    SELECT 1 FROM command_output_capture_intents intent
    WHERE intent.capture_id = NEW.capture_id
      AND intent.effect_id = NEW.effect_id
      AND intent.sprint_id = NEW.sprint_id
      AND intent.runner_launch_id = NEW.runner_launch_id
      AND intent.runner_session_id = NEW.runner_session_id
      AND intent.request_digest = NEW.request_digest
      AND intent.private_state_digest = NEW.private_state_digest
      AND intent.max_aggregate_output_bytes = NEW.max_aggregate_output_bytes
      AND intent.intent_digest = NEW.intent_digest
      AND intent.layout_version = NEW.layout_version
      AND intent.contract_version = NEW.contract_version
      AND intent.created_at_unix_ms <= NEW.acquired_at_unix_ms
      AND json_extract(CAST(NEW.acquired_json AS TEXT), '$.capture_id') = NEW.capture_id
      AND json_extract(CAST(NEW.acquired_json AS TEXT), '$.source.effect_id') = NEW.effect_id
      AND json_extract(CAST(NEW.acquired_json AS TEXT), '$.source.sprint_id') = NEW.sprint_id
      AND json_extract(CAST(NEW.acquired_json AS TEXT), '$.source.runner_launch_id') = NEW.runner_launch_id
      AND json_extract(CAST(NEW.acquired_json AS TEXT), '$.source.runner_session_id') = NEW.runner_session_id
      AND json_extract(CAST(NEW.acquired_json AS TEXT), '$.source.request_digest') = NEW.request_digest
      AND json_extract(CAST(NEW.acquired_json AS TEXT), '$.dispatch_claim_id') = NEW.dispatch_claim_id
      AND json_extract(CAST(NEW.acquired_json AS TEXT), '$.acquired_anchor_digest') = NEW.acquired_anchor_digest
)
BEGIN SELECT RAISE(ABORT, 'capture acquisition must copy its exact immutable intent'); END;

CREATE TRIGGER runner_effect_dispatch_claims_require_v27_capture_acquisition
BEFORE INSERT ON runner_effect_dispatch_claims
WHEN EXISTS (
    SELECT 1 FROM effect_intents
    WHERE effect_id = NEW.effect_id AND effect_kind = 'RunCommand'
) AND NOT EXISTS (
    SELECT 1 FROM command_output_capture_acquisitions acquired
    WHERE acquired.effect_id = NEW.effect_id
      AND acquired.sprint_id = NEW.sprint_id
      AND acquired.runner_launch_id = NEW.launch_id
      AND acquired.runner_session_id = NEW.session_id
      AND acquired.request_digest = NEW.request_digest
      AND acquired.dispatch_claim_id = NEW.dispatch_claim_id
      AND acquired.contract_version = NEW.contract_version
)
BEGIN SELECT RAISE(ABORT, 'RunCommand dispatch requires exact v27 capture acquisition'); END;

CREATE TRIGGER command_output_capture_acquisitions_no_update
BEFORE UPDATE ON command_output_capture_acquisitions
BEGIN SELECT RAISE(ABORT, 'command output capture acquisitions are immutable'); END;
CREATE TRIGGER command_output_capture_acquisitions_no_delete
BEFORE DELETE ON command_output_capture_acquisitions
BEGIN SELECT RAISE(ABORT, 'command output capture acquisitions are immutable'); END;

CREATE TABLE command_output_capture_reconciliation_claims (
    claim_id TEXT PRIMARY KEY NOT NULL CHECK (
        length(claim_id) = 64 AND claim_id NOT GLOB '*[^0-9a-f]*'
    ),
    capture_id TEXT NOT NULL,
    owner_id TEXT NOT NULL CHECK (length(owner_id) BETWEEN 1 AND 256),
    claim_epoch INTEGER NOT NULL CHECK (claim_epoch > 0),
    previous_claim_id TEXT UNIQUE,
    fencing_token TEXT NOT NULL UNIQUE CHECK (
        length(fencing_token) = 64 AND fencing_token NOT GLOB '*[^0-9a-f]*'
    ),
    acquired_at_unix_ms INTEGER NOT NULL CHECK (acquired_at_unix_ms > 0),
    expires_at_unix_ms INTEGER NOT NULL CHECK (
        expires_at_unix_ms > acquired_at_unix_ms
        AND expires_at_unix_ms - acquired_at_unix_ms <= 300000
    ),
    claim_digest TEXT NOT NULL UNIQUE CHECK (
        length(claim_digest) = 64 AND claim_digest NOT GLOB '*[^0-9a-f]*'
    ),
    contract_version INTEGER NOT NULL CHECK (contract_version > 0),
    claim_json BLOB NOT NULL CHECK (
        length(claim_json) > 0
        AND claim_digest = grok_command_output_capture_reconciliation_claim_digest(claim_json)
    ),
    UNIQUE (capture_id, claim_epoch),
    FOREIGN KEY (capture_id) REFERENCES command_output_capture_intents(capture_id)
        ON DELETE RESTRICT,
    FOREIGN KEY (previous_claim_id)
        REFERENCES command_output_capture_reconciliation_claims(claim_id) ON DELETE RESTRICT
) STRICT, WITHOUT ROWID;

CREATE TABLE command_output_capture_reconciliation_claim_releases (
    claim_id TEXT PRIMARY KEY NOT NULL,
    capture_id TEXT NOT NULL,
    claim_epoch INTEGER NOT NULL CHECK (claim_epoch > 0),
    fencing_token TEXT NOT NULL UNIQUE,
    release_kind TEXT NOT NULL CHECK (
        release_kind IN ('Released', 'Expired', 'Superseded', 'ConsumedTerminal')
    ),
    released_at_unix_ms INTEGER NOT NULL CHECK (released_at_unix_ms > 0),
    terminal_anchor_digest TEXT,
    successor_claim_id TEXT UNIQUE,
    successor_fencing_token TEXT UNIQUE,
    successor_claim_digest TEXT UNIQUE,
    contract_version INTEGER NOT NULL CHECK (contract_version > 0),
    CHECK (
        (release_kind = 'ConsumedTerminal'
         AND terminal_anchor_digest IS NOT NULL
         AND successor_claim_id IS NULL
         AND successor_fencing_token IS NULL
         AND successor_claim_digest IS NULL)
        OR (release_kind = 'Superseded'
            AND terminal_anchor_digest IS NULL
            AND successor_claim_id IS NOT NULL
            AND successor_fencing_token IS NOT NULL
            AND successor_claim_digest IS NOT NULL)
        OR (release_kind IN ('Released', 'Expired')
            AND terminal_anchor_digest IS NULL
            AND successor_claim_id IS NULL
            AND successor_fencing_token IS NULL
            AND successor_claim_digest IS NULL)
    ),
    FOREIGN KEY (claim_id) REFERENCES command_output_capture_reconciliation_claims(claim_id)
        ON DELETE RESTRICT,
    FOREIGN KEY (terminal_anchor_digest)
        REFERENCES command_output_capture_terminal_anchors(terminal_anchor_digest)
        ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED,
    FOREIGN KEY (successor_claim_id)
        REFERENCES command_output_capture_reconciliation_claims(claim_id)
        ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED
) STRICT, WITHOUT ROWID;

CREATE TRIGGER command_output_capture_reconciliation_claims_exact_epoch
BEFORE INSERT ON command_output_capture_reconciliation_claims
WHEN EXISTS (
    SELECT 1 FROM command_output_capture_terminal_anchors
    WHERE capture_id = NEW.capture_id
      AND disposition IN ('Published', 'Abandoned')
) OR EXISTS (
    SELECT 1 FROM command_output_capture_reconciliation_obligation_closures
    WHERE capture_id = NEW.capture_id
) OR (
    NEW.claim_epoch != COALESCE((
        SELECT MAX(claim_epoch) + 1
        FROM command_output_capture_reconciliation_claims
        WHERE capture_id = NEW.capture_id
    ), 1)
) OR (
    (NEW.claim_epoch = 1 AND NEW.previous_claim_id IS NOT NULL)
    OR (NEW.claim_epoch > 1 AND NOT EXISTS (
        SELECT 1
        FROM command_output_capture_reconciliation_claims previous
        JOIN command_output_capture_reconciliation_claim_releases release
          ON release.claim_id = previous.claim_id
         AND release.capture_id = previous.capture_id
         AND release.claim_epoch = previous.claim_epoch
         AND release.fencing_token = previous.fencing_token
         AND release.contract_version = previous.contract_version
        WHERE previous.capture_id = NEW.capture_id
          AND previous.claim_epoch = NEW.claim_epoch - 1
          AND previous.claim_id = NEW.previous_claim_id
          AND (
              (release.release_kind = 'Released'
               AND release.released_at_unix_ms <= NEW.acquired_at_unix_ms)
              OR (release.release_kind = 'Expired'
                  AND release.released_at_unix_ms = NEW.acquired_at_unix_ms
                  AND previous.expires_at_unix_ms <= NEW.acquired_at_unix_ms)
              OR (release.release_kind = 'Superseded'
                  AND previous.owner_id = NEW.owner_id
                  AND release.released_at_unix_ms = NEW.acquired_at_unix_ms
                  AND release.successor_claim_id = NEW.claim_id
                  AND release.successor_fencing_token = NEW.fencing_token
                  AND release.successor_claim_digest = NEW.claim_digest)
              OR (release.release_kind = 'ConsumedTerminal'
                  AND release.released_at_unix_ms <= NEW.acquired_at_unix_ms
                  AND EXISTS (
                      SELECT 1
                      FROM command_output_capture_terminal_anchors terminal
                      JOIN command_output_capture_reconciliation_obligations obligation
                        ON obligation.capture_id = terminal.capture_id
                       AND obligation.effect_id = terminal.effect_id
                      LEFT JOIN command_output_capture_reconciliation_obligation_closures closure
                        ON closure.obligation_id = obligation.obligation_id
                      LEFT JOIN command_output_capture_reconciliation_resolutions resolution
                        ON resolution.terminal_anchor_digest = terminal.terminal_anchor_digest
                      WHERE terminal.terminal_anchor_digest =
                                release.terminal_anchor_digest
                        AND terminal.capture_id = previous.capture_id
                        AND terminal.observation_class = 'Unknown'
                        AND terminal.disposition = 'ReconciliationRequired'
                        AND closure.obligation_id IS NULL
                        AND resolution.resolution_anchor_digest IS NULL
                  ))
          )
    ))
    OR json_extract(CAST(NEW.claim_json AS TEXT), '$.claim_id') != NEW.claim_id
    OR json_extract(CAST(NEW.claim_json AS TEXT), '$.capture_id') != NEW.capture_id
    OR json_extract(CAST(NEW.claim_json AS TEXT), '$.owner_id') != NEW.owner_id
    OR json_extract(CAST(NEW.claim_json AS TEXT), '$.claim_epoch') != NEW.claim_epoch
    OR json_extract(CAST(NEW.claim_json AS TEXT), '$.previous_claim_id')
       IS NOT NEW.previous_claim_id
    OR json_extract(CAST(NEW.claim_json AS TEXT), '$.fencing_token') != NEW.fencing_token
    OR json_extract(CAST(NEW.claim_json AS TEXT), '$.acquired_at_unix_ms')
       != NEW.acquired_at_unix_ms
    OR json_extract(CAST(NEW.claim_json AS TEXT), '$.expires_at_unix_ms')
       != NEW.expires_at_unix_ms
    OR json_extract(CAST(NEW.claim_json AS TEXT), '$.claim_digest') != NEW.claim_digest
    OR json_extract(CAST(NEW.claim_json AS TEXT), '$.contract_version')
       != NEW.contract_version
)
BEGIN SELECT RAISE(ABORT, 'capture reconciliation claim must CAS the closed prior epoch'); END;

CREATE TRIGGER command_output_capture_reconciliation_releases_exact_claim
BEFORE INSERT ON command_output_capture_reconciliation_claim_releases
WHEN NOT EXISTS (
    SELECT 1 FROM command_output_capture_reconciliation_claims claim
    WHERE claim.claim_id = NEW.claim_id
      AND claim.capture_id = NEW.capture_id
      AND claim.claim_epoch = NEW.claim_epoch
      AND claim.fencing_token = NEW.fencing_token
      AND claim.contract_version = NEW.contract_version
      AND claim.acquired_at_unix_ms <= NEW.released_at_unix_ms
      AND (
          NEW.release_kind = 'Released'
          OR (NEW.release_kind = 'Expired'
              AND NEW.released_at_unix_ms >= claim.expires_at_unix_ms)
          OR (NEW.release_kind = 'Superseded'
              AND NEW.released_at_unix_ms < claim.expires_at_unix_ms
              AND (
                  NOT EXISTS (
                      SELECT 1
                      FROM command_output_capture_reconciliation_claims successor
                      WHERE successor.claim_id = NEW.successor_claim_id
                  )
                  OR EXISTS (
                      SELECT 1
                      FROM command_output_capture_reconciliation_claims successor
                      WHERE successor.claim_id = NEW.successor_claim_id
                        AND successor.capture_id = claim.capture_id
                        AND successor.owner_id = claim.owner_id
                        AND successor.claim_epoch = claim.claim_epoch + 1
                        AND successor.previous_claim_id = claim.claim_id
                        AND successor.fencing_token = NEW.successor_fencing_token
                        AND successor.claim_digest = NEW.successor_claim_digest
                        AND successor.acquired_at_unix_ms =
                            NEW.released_at_unix_ms
                  )
              ))
          OR (NEW.release_kind = 'ConsumedTerminal'
              AND NEW.released_at_unix_ms < claim.expires_at_unix_ms
              AND (
                  EXISTS (
                      SELECT 1
                      FROM command_output_capture_intents intent
                      JOIN command_output_capture_terminal_anchors terminal
                        ON terminal.capture_id = intent.capture_id
                       AND terminal.effect_id = intent.effect_id
                       AND terminal.terminal_anchor_digest =
                           NEW.terminal_anchor_digest
                      WHERE intent.capture_id = claim.capture_id
                        AND terminal.observation_class = 'Unknown'
                        AND terminal.disposition = 'ReconciliationRequired'
                        AND terminal.anchored_at_unix_ms <=
                            NEW.released_at_unix_ms
                        AND terminal.contract_version = claim.contract_version
                  )
                  OR EXISTS (
                      SELECT 1
                      FROM command_output_capture_intents intent
                      JOIN command_output_capture_terminal_validations validation
                        ON validation.terminal_anchor_digest =
                           NEW.terminal_anchor_digest
                       AND validation.capture_id = intent.capture_id
                       AND validation.effect_id = intent.effect_id
                       AND validation.reconciliation_claim_id = claim.claim_id
                       AND validation.reconciliation_fencing_token =
                           claim.fencing_token
                       AND validation.terminal_anchored_at_unix_ms =
                           NEW.released_at_unix_ms
                       AND validation.contract_version = claim.contract_version
                      LEFT JOIN command_output_capture_restart_recovery_receipts recovery
                        ON recovery.receipt_digest =
                           validation.restart_recovery_receipt_digest
                       AND recovery.capture_id = intent.capture_id
                       AND recovery.effect_id = intent.effect_id
                       AND recovery.reconciliation_claim_id = claim.claim_id
                       AND recovery.reconciliation_fencing_token =
                           claim.fencing_token
                      WHERE intent.capture_id = claim.capture_id
                        AND (
                            (validation.validation_kind IN (
                                 'RestartIntentAbandoned',
                                 'RestartClaimedBeforeLaunchAbandoned',
                                 'RestartClaimedUnresolved',
                                 'RestartTerminalPreparedPublished'
                             )
                             AND recovery.receipt_digest =
                                 validation.restart_recovery_receipt_digest
                             AND recovery.recovered_at_unix_ms =
                                 NEW.released_at_unix_ms)
                            OR (validation.validation_kind =
                                    'RestartReconciliation'
                                AND validation.restart_recovery_receipt_digest
                                    IS NULL)
                        )
                  )
              ))
      )
)
BEGIN SELECT RAISE(ABORT, 'capture reconciliation release must consume one exact fencing token'); END;

CREATE TRIGGER command_output_capture_reconciliation_claims_no_update
BEFORE UPDATE ON command_output_capture_reconciliation_claims
BEGIN SELECT RAISE(ABORT, 'capture reconciliation claims are immutable'); END;
CREATE TRIGGER command_output_capture_reconciliation_claims_no_delete
BEFORE DELETE ON command_output_capture_reconciliation_claims
BEGIN SELECT RAISE(ABORT, 'capture reconciliation claims are immutable'); END;
CREATE TRIGGER command_output_capture_reconciliation_releases_no_update
BEFORE UPDATE ON command_output_capture_reconciliation_claim_releases
BEGIN SELECT RAISE(ABORT, 'capture reconciliation releases are immutable'); END;
CREATE TRIGGER command_output_capture_reconciliation_releases_no_delete
BEFORE DELETE ON command_output_capture_reconciliation_claim_releases
BEGIN SELECT RAISE(ABORT, 'capture reconciliation releases are immutable'); END;

-- Any durable restart claim permanently wins the race against a stale live
-- dispatcher. Release, expiry, or supersession closes ownership; it never
-- recreates fresh acquisition authority for the same physical capture ID.
CREATE TRIGGER command_output_capture_acquisitions_reject_reconciliation_history
BEFORE INSERT ON command_output_capture_acquisitions
WHEN EXISTS (
    SELECT 1 FROM command_output_capture_reconciliation_claims claim
    WHERE claim.capture_id = NEW.capture_id
)
BEGIN SELECT RAISE(ABORT, 'capture acquisition is permanently fenced by reconciliation history'); END;

-- Canonical bridge from the runner-owned physical journal into core-owned
-- restart terminalization. The chained store-head digest commits to the full
-- journal history; exact launch bytes are retained whenever launch crossed the
-- physical boundary. This table confers no execution authority.
CREATE TABLE command_output_capture_restart_recovery_receipts (
    receipt_digest TEXT PRIMARY KEY NOT NULL CHECK (
        length(receipt_digest) = 64 AND receipt_digest NOT GLOB '*[^0-9a-f]*'
    ),
    capture_id TEXT NOT NULL,
    effect_id TEXT NOT NULL,
    intent_digest TEXT NOT NULL,
    reconciliation_claim_id TEXT NOT NULL UNIQUE,
    reconciliation_fencing_token TEXT NOT NULL UNIQUE,
    recovery_fence_claim_digest TEXT NOT NULL UNIQUE,
    physical_fence_chain_length INTEGER NOT NULL CHECK (physical_fence_chain_length > 0),
    physical_fence_digest TEXT NOT NULL UNIQUE CHECK (
        length(physical_fence_digest) = 64
        AND physical_fence_digest NOT GLOB '*[^0-9a-f]*'
    ),
    observed_state TEXT NOT NULL CHECK (observed_state IN (
        'Intent', 'Acquired', 'WriterAttached', 'LaunchIntended', 'Finished',
        'Published', 'TerminalPrepared', 'CleanupIntended', 'Cleaned'
    )),
    resolution_action TEXT NOT NULL CHECK (resolution_action IN (
        'IntentTombstoned', 'PreAcquisitionCleaned', 'WorkingSetCleaned',
        'FinishedPublicationRecovered', 'TerminalPreparedRecovered',
        'TerminalReadback'
    )),
    store_head_generation INTEGER NOT NULL CHECK (store_head_generation > 0),
    store_head_digest TEXT NOT NULL CHECK (
        length(store_head_digest) = 64 AND store_head_digest NOT GLOB '*[^0-9a-f]*'
    ),
    journal_history_digest TEXT NOT NULL CHECK (
        length(journal_history_digest) = 64
        AND journal_history_digest NOT GLOB '*[^0-9a-f]*'
    ),
    acquired_anchor_digest TEXT,
    launch_schema TEXT,
    launch_canonical_bytes BLOB,
    launch_canonical_bytes_digest TEXT,
    launch_store_head_generation INTEGER,
    launch_store_head_digest TEXT,
    cleaned_record_digest TEXT,
    pending_record_present INTEGER NOT NULL CHECK (pending_record_present = 0),
    recovered_at_unix_ms INTEGER NOT NULL CHECK (recovered_at_unix_ms > 0),
    layout_version INTEGER NOT NULL CHECK (layout_version = 1),
    contract_version INTEGER NOT NULL CHECK (contract_version > 0),
    receipt_json BLOB NOT NULL CHECK (
        length(receipt_json) > 0
        AND receipt_digest =
            grok_command_output_capture_restart_recovery_receipt_digest(receipt_json)
    ),
    CHECK (
        (launch_schema IS NULL
         AND launch_canonical_bytes IS NULL
         AND launch_canonical_bytes_digest IS NULL
         AND launch_store_head_generation IS NULL
         AND launch_store_head_digest IS NULL)
        OR (launch_schema IS NOT NULL
            AND launch_canonical_bytes IS NOT NULL
            AND launch_canonical_bytes_digest IS NOT NULL
            AND launch_store_head_generation IS NOT NULL
            AND launch_store_head_digest IS NOT NULL)
    ),
    CHECK (
        (observed_state = 'Cleaned' AND cleaned_record_digest = store_head_digest)
        OR (observed_state != 'Cleaned' AND cleaned_record_digest IS NULL)
    ),
    UNIQUE (capture_id, effect_id, reconciliation_claim_id),
    FOREIGN KEY (capture_id, effect_id, intent_digest)
        REFERENCES command_output_capture_intents(capture_id, effect_id, intent_digest)
        ON DELETE RESTRICT,
    FOREIGN KEY (reconciliation_claim_id)
        REFERENCES command_output_capture_reconciliation_claims(claim_id)
        ON DELETE RESTRICT
) STRICT, WITHOUT ROWID;

CREATE TRIGGER command_output_capture_restart_recovery_receipts_exact
BEFORE INSERT ON command_output_capture_restart_recovery_receipts
WHEN NOT EXISTS (
    SELECT 1
    FROM command_output_capture_intents intent
    JOIN command_output_capture_reconciliation_claims claim
      ON claim.claim_id = NEW.reconciliation_claim_id
     AND claim.capture_id = intent.capture_id
     AND claim.fencing_token = NEW.reconciliation_fencing_token
     AND claim.claim_digest = NEW.recovery_fence_claim_digest
    WHERE intent.capture_id = NEW.capture_id
      AND intent.effect_id = NEW.effect_id
      AND intent.intent_digest = NEW.intent_digest
      AND intent.layout_version = NEW.layout_version
      AND intent.contract_version = NEW.contract_version
      AND NEW.recovered_at_unix_ms >= claim.acquired_at_unix_ms
      AND NEW.recovered_at_unix_ms < claim.expires_at_unix_ms
      AND NEW.pending_record_present = 0
      AND (
          (NOT EXISTS (
               SELECT 1
               FROM command_output_capture_restart_recovery_receipts previous
               WHERE previous.capture_id = NEW.capture_id
           )
           AND ((NEW.physical_fence_chain_length = 1
                 AND json_type(
                       CAST(NEW.receipt_json AS TEXT),
                       '$.predecessor_fence_digest'
                     ) = 'null')
                OR (NEW.physical_fence_chain_length > 1
                    AND json_type(
                          CAST(NEW.receipt_json AS TEXT),
                          '$.predecessor_fence_digest'
                        ) = 'text')))
          OR (EXISTS (
                  SELECT 1
                  FROM command_output_capture_restart_recovery_receipts previous
                  WHERE previous.capture_id = NEW.capture_id
              )
              AND NEW.physical_fence_chain_length > (
                  SELECT MAX(previous.physical_fence_chain_length)
                  FROM command_output_capture_restart_recovery_receipts previous
                  WHERE previous.capture_id = NEW.capture_id
              )
              AND json_type(
                    CAST(NEW.receipt_json AS TEXT),
                    '$.predecessor_fence_digest'
                  ) = 'text')
      )
      AND (
          (NEW.launch_schema IS NULL
           AND NEW.observed_state NOT IN (
               'LaunchIntended', 'Finished', 'Published', 'TerminalPrepared'
           ))
          OR (NEW.launch_schema IS NOT NULL
              AND NEW.acquired_anchor_digest IS NOT NULL
              AND NEW.launch_store_head_generation <= NEW.store_head_generation
              AND NEW.observed_state IN (
                  'LaunchIntended', 'Finished', 'Published', 'TerminalPrepared',
                  'CleanupIntended', 'Cleaned'
              ))
      )
      AND json_extract(CAST(NEW.receipt_json AS TEXT), '$.capture_id') = NEW.capture_id
      AND json_extract(CAST(NEW.receipt_json AS TEXT), '$.effect_id') = NEW.effect_id
      AND json_extract(CAST(NEW.receipt_json AS TEXT), '$.intent_digest') = NEW.intent_digest
      AND json_extract(CAST(NEW.receipt_json AS TEXT), '$.reconciliation_claim.claim_id') = NEW.reconciliation_claim_id
      AND json_extract(CAST(NEW.receipt_json AS TEXT), '$.reconciliation_claim.fencing_token') = NEW.reconciliation_fencing_token
      AND json_extract(CAST(NEW.receipt_json AS TEXT), '$.reconciliation_claim.claim_digest') = NEW.recovery_fence_claim_digest
      AND json_extract(CAST(NEW.receipt_json AS TEXT), '$.physical_fence_chain_length') = NEW.physical_fence_chain_length
      AND json_extract(CAST(NEW.receipt_json AS TEXT), '$.physical_fence_digest') = NEW.physical_fence_digest
      AND json_extract(CAST(NEW.receipt_json AS TEXT), '$.final_state') =
          CASE NEW.observed_state
            WHEN 'Intent' THEN 'intent'
            WHEN 'Acquired' THEN 'acquired'
            WHEN 'WriterAttached' THEN 'writer_attached'
            WHEN 'LaunchIntended' THEN 'launch_intended'
            WHEN 'Finished' THEN 'finished'
            WHEN 'Published' THEN 'published'
            WHEN 'TerminalPrepared' THEN 'terminal_prepared'
            WHEN 'CleanupIntended' THEN 'cleanup_intended'
            WHEN 'Cleaned' THEN 'cleaned'
          END
      AND json_extract(CAST(NEW.receipt_json AS TEXT), '$.resolution_action') =
          CASE NEW.resolution_action
            WHEN 'IntentTombstoned' THEN 'intent_tombstoned'
            WHEN 'PreAcquisitionCleaned' THEN 'pre_acquisition_cleaned'
            WHEN 'WorkingSetCleaned' THEN 'working_set_cleaned'
            WHEN 'FinishedPublicationRecovered' THEN 'finished_publication_recovered'
            WHEN 'TerminalPreparedRecovered' THEN 'terminal_prepared_recovered'
            WHEN 'TerminalReadback' THEN 'terminal_readback'
          END
      AND json_extract(CAST(NEW.receipt_json AS TEXT), '$.final_store_head.generation') = NEW.store_head_generation
      AND json_extract(CAST(NEW.receipt_json AS TEXT), '$.final_store_head.record_digest') = NEW.store_head_digest
      AND json_extract(CAST(NEW.receipt_json AS TEXT), '$.lifecycle_history_digest') = NEW.journal_history_digest
      AND json_extract(
            CAST(NEW.receipt_json AS TEXT),
            '$.physical_acquired.acquired_anchor_digest'
          ) IS NEW.acquired_anchor_digest
      AND (
          (NEW.launch_schema IS NULL
           AND json_extract(
                 CAST(NEW.receipt_json AS TEXT),
                 '$.launch_history.classification'
               ) = 'none_before_launch')
          OR (NEW.launch_schema IS NOT NULL
              AND json_extract(
                    CAST(NEW.receipt_json AS TEXT),
                    '$.launch_history.classification'
                  ) = 'exact_launch_evidence'
              AND json_extract(
                    CAST(NEW.receipt_json AS TEXT),
                    '$.launch_history.evidence.schema'
                  ) = NEW.launch_schema
              AND json_extract(
                    CAST(NEW.receipt_json AS TEXT),
                    '$.launch_history.evidence.canonical_bytes_digest'
                  ) = NEW.launch_canonical_bytes_digest
              AND grok_sha256(NEW.launch_canonical_bytes) =
                  NEW.launch_canonical_bytes_digest
              AND json_extract(
                    CAST(NEW.receipt_json AS TEXT),
                    '$.launch_history.evidence.store_head.generation'
                  ) = NEW.launch_store_head_generation
              AND json_extract(
                    CAST(NEW.receipt_json AS TEXT),
                    '$.launch_history.evidence.store_head.record_digest'
                  ) = NEW.launch_store_head_digest)
      )
      AND json_extract(
            CAST(NEW.receipt_json AS TEXT),
            '$.cleaned_store_head.record_digest'
          ) IS NEW.cleaned_record_digest
      AND json_extract(CAST(NEW.receipt_json AS TEXT), '$.reconciliation_digest') = NEW.receipt_digest
      AND json_extract(CAST(NEW.receipt_json AS TEXT), '$.reconciled_at_unix_ms') = NEW.recovered_at_unix_ms
)
BEGIN SELECT RAISE(ABORT, 'restart recovery receipt must bind exact intent, claim fence, and journal history'); END;

CREATE TRIGGER command_output_capture_restart_recovery_receipts_no_update
BEFORE UPDATE ON command_output_capture_restart_recovery_receipts
BEGIN SELECT RAISE(ABORT, 'capture restart recovery receipts are immutable'); END;
CREATE TRIGGER command_output_capture_restart_recovery_receipts_no_delete
BEFORE DELETE ON command_output_capture_restart_recovery_receipts
BEGIN SELECT RAISE(ABORT, 'capture restart recovery receipts are immutable'); END;

-- A terminal anchor is never sufficient authority by itself. This immutable
-- companion records which live/recovery capability and which independent
-- cleanup evidence authorize the atomic observation.
CREATE TABLE command_output_capture_terminal_validations (
    terminal_anchor_digest TEXT PRIMARY KEY NOT NULL,
    capture_id TEXT NOT NULL UNIQUE,
    effect_id TEXT NOT NULL UNIQUE,
    observation_id TEXT NOT NULL UNIQUE,
    validation_kind TEXT NOT NULL CHECK (validation_kind IN (
        'DirectClaimed', 'DirectClaimedUnresolved', 'PreDispatchAbandoned',
        'RestartIntentAbandoned', 'RestartClaimedBeforeLaunchAbandoned',
        'RestartClaimedUnresolved', 'RestartTerminalPreparedPublished',
        'RestartReconciliation'
    )),
    command_domain_cleanup_proof_id TEXT UNIQUE,
    reconciliation_claim_id TEXT UNIQUE,
    reconciliation_fencing_token TEXT UNIQUE,
    runner_cleanup_receipt_id TEXT UNIQUE,
    restart_recovery_receipt_digest TEXT UNIQUE,
    terminal_anchored_at_unix_ms INTEGER NOT NULL CHECK (
        terminal_anchored_at_unix_ms > 0
    ),
    sprint_id TEXT NOT NULL,
    contract_version INTEGER NOT NULL CHECK (contract_version > 0),
    CHECK (
        (validation_kind = 'DirectClaimed'
         AND command_domain_cleanup_proof_id IS NOT NULL
         AND reconciliation_claim_id IS NULL
         AND reconciliation_fencing_token IS NULL
         AND runner_cleanup_receipt_id IS NULL
         AND restart_recovery_receipt_digest IS NULL)
        OR (validation_kind = 'DirectClaimedUnresolved'
            AND command_domain_cleanup_proof_id IS NULL
            AND reconciliation_claim_id IS NULL
            AND reconciliation_fencing_token IS NULL
            AND runner_cleanup_receipt_id IS NULL
            AND restart_recovery_receipt_digest IS NULL)
        OR (validation_kind = 'PreDispatchAbandoned'
            AND command_domain_cleanup_proof_id IS NULL
            AND reconciliation_claim_id IS NULL
            AND reconciliation_fencing_token IS NULL
            AND runner_cleanup_receipt_id IS NULL
            AND restart_recovery_receipt_digest IS NULL)
        OR (validation_kind = 'RestartClaimedUnresolved'
            AND command_domain_cleanup_proof_id IS NULL
            AND reconciliation_claim_id IS NOT NULL
            AND reconciliation_fencing_token IS NOT NULL
            AND runner_cleanup_receipt_id IS NULL
            AND restart_recovery_receipt_digest IS NOT NULL)
        OR (validation_kind IN (
                'RestartIntentAbandoned', 'RestartClaimedBeforeLaunchAbandoned',
                'RestartTerminalPreparedPublished'
            )
            AND command_domain_cleanup_proof_id IS NOT NULL
            AND reconciliation_claim_id IS NOT NULL
            AND reconciliation_fencing_token IS NOT NULL
            AND runner_cleanup_receipt_id IS NULL
            AND restart_recovery_receipt_digest IS NOT NULL)
        OR (validation_kind = 'RestartReconciliation'
            AND command_domain_cleanup_proof_id IS NOT NULL
            AND reconciliation_claim_id IS NOT NULL
            AND reconciliation_fencing_token IS NOT NULL
            AND runner_cleanup_receipt_id IS NOT NULL
            AND restart_recovery_receipt_digest IS NULL)
    ),
    FOREIGN KEY (capture_id, effect_id)
        REFERENCES command_output_capture_intents(capture_id, effect_id)
        ON DELETE RESTRICT,
    FOREIGN KEY (terminal_anchor_digest)
        REFERENCES command_output_capture_terminal_anchors(terminal_anchor_digest)
        ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED,
    FOREIGN KEY (command_domain_cleanup_proof_id)
        REFERENCES command_domain_cleanup_proofs(proof_id)
        ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED,
    FOREIGN KEY (reconciliation_claim_id)
        REFERENCES command_output_capture_reconciliation_claims(claim_id)
        ON DELETE RESTRICT,
    FOREIGN KEY (restart_recovery_receipt_digest)
        REFERENCES command_output_capture_restart_recovery_receipts(receipt_digest)
        ON DELETE RESTRICT,
    FOREIGN KEY (sprint_id, runner_cleanup_receipt_id)
        REFERENCES worker_cleanup_receipts(sprint_id, receipt_id)
        ON DELETE RESTRICT
) STRICT, WITHOUT ROWID;

CREATE TRIGGER command_output_capture_terminal_validations_exact
BEFORE INSERT ON command_output_capture_terminal_validations
WHEN NOT EXISTS (
    SELECT 1 FROM command_output_capture_intents intent
    LEFT JOIN command_output_capture_reconciliation_claims claim
      ON claim.claim_id = NEW.reconciliation_claim_id
     AND claim.capture_id = intent.capture_id
    LEFT JOIN command_output_capture_acquisitions acquired
      ON acquired.capture_id = intent.capture_id
     AND acquired.effect_id = intent.effect_id
    LEFT JOIN command_domain_cleanup_proofs command_cleanup
      ON command_cleanup.proof_id = NEW.command_domain_cleanup_proof_id
    LEFT JOIN worker_cleanup_receipts cleanup
      ON cleanup.sprint_id = intent.sprint_id
     AND cleanup.receipt_id = NEW.runner_cleanup_receipt_id
     AND cleanup.launch_id = intent.runner_launch_id
     AND cleanup.session_id = intent.runner_session_id
    LEFT JOIN command_output_capture_restart_recovery_receipts recovery
      ON recovery.receipt_digest = NEW.restart_recovery_receipt_digest
     AND recovery.capture_id = intent.capture_id
     AND recovery.effect_id = intent.effect_id
     AND recovery.reconciliation_claim_id = claim.claim_id
     AND recovery.reconciliation_fencing_token = claim.fencing_token
    WHERE intent.capture_id = NEW.capture_id
      AND intent.effect_id = NEW.effect_id
      AND intent.sprint_id = NEW.sprint_id
      AND intent.contract_version = NEW.contract_version
      AND (
          NEW.reconciliation_claim_id IS NULL
          OR (NEW.terminal_anchored_at_unix_ms >= claim.acquired_at_unix_ms
              AND NEW.terminal_anchored_at_unix_ms < claim.expires_at_unix_ms)
      )
      AND (
          NEW.reconciliation_claim_id IS NULL
          OR claim.claim_epoch = (
              SELECT MAX(latest.claim_epoch)
              FROM command_output_capture_reconciliation_claims latest
              WHERE latest.capture_id = claim.capture_id
          )
      )
      AND (
          (NEW.validation_kind = 'DirectClaimed'
           AND NEW.reconciliation_claim_id IS NULL
           AND (
               command_cleanup.proof_id IS NULL
               OR (command_cleanup.sprint_id = intent.sprint_id
                   AND command_cleanup.launch_id = intent.runner_launch_id
                   AND command_cleanup.session_id = intent.runner_session_id
                   AND command_cleanup.effect_id = intent.effect_id
                   AND command_cleanup.observation_id = NEW.observation_id
                   AND command_cleanup.request_digest = intent.request_digest
                   AND command_cleanup.surviving_processes = 0)
           ))
          OR (NEW.validation_kind IN (
                  'DirectClaimedUnresolved', 'PreDispatchAbandoned'
              )
              AND NEW.reconciliation_claim_id IS NULL)
          OR (NEW.validation_kind IN (
                 'RestartIntentAbandoned', 'RestartClaimedBeforeLaunchAbandoned',
                 'RestartClaimedUnresolved', 'RestartTerminalPreparedPublished'
              )
              AND claim.fencing_token = NEW.reconciliation_fencing_token
              AND recovery.receipt_digest = NEW.restart_recovery_receipt_digest
              AND recovery.recovered_at_unix_ms =
                  NEW.terminal_anchored_at_unix_ms
              AND recovery.recovered_at_unix_ms >= claim.acquired_at_unix_ms
              AND recovery.recovered_at_unix_ms < claim.expires_at_unix_ms
              AND (
                  (NEW.validation_kind = 'RestartIntentAbandoned'
                   AND acquired.acquired_anchor_digest IS NULL
                   AND recovery.observed_state = 'Cleaned'
                   AND recovery.launch_schema IS NULL
                   AND json_type(
                         CAST(recovery.receipt_json AS TEXT),
                         '$.requested_store_head'
                       ) = 'null'
                   AND json_type(
                         CAST(recovery.receipt_json AS TEXT),
                         '$.artifact_reference'
                       ) = 'null'
                   AND json_type(
                         CAST(recovery.receipt_json AS TEXT),
                         '$.terminal_prepared'
                       ) = 'null'
                   AND json_type(
                         CAST(recovery.receipt_json AS TEXT),
                         '$.cleanup_completion_proof_digest'
                       ) = 'text'
                   AND (
                       (recovery.acquired_anchor_digest IS NULL
                        AND (
                            recovery.resolution_action IN (
                                'IntentTombstoned', 'PreAcquisitionCleaned'
                            )
                            OR (recovery.resolution_action = 'TerminalReadback'
                                AND json_extract(
                                      CAST(recovery.receipt_json AS TEXT),
                                      '$.initial_state'
                                    ) = 'cleaned'
                                AND json_extract(
                                      CAST(recovery.receipt_json AS TEXT),
                                      '$.initial_store_head.generation'
                                    ) = recovery.store_head_generation
                                AND json_extract(
                                      CAST(recovery.receipt_json AS TEXT),
                                      '$.initial_store_head.record_digest'
                                    ) = recovery.store_head_digest))
                       )
                       OR (recovery.acquired_anchor_digest IS NOT NULL
                           AND (
                               recovery.resolution_action = 'WorkingSetCleaned'
                               OR (recovery.resolution_action = 'TerminalReadback'
                                   AND json_extract(
                                         CAST(recovery.receipt_json AS TEXT),
                                         '$.initial_state'
                                       ) = 'cleaned'
                                   AND json_extract(
                                         CAST(recovery.receipt_json AS TEXT),
                                         '$.initial_store_head.generation'
                                       ) = recovery.store_head_generation
                                   AND json_extract(
                                         CAST(recovery.receipt_json AS TEXT),
                                         '$.initial_store_head.record_digest'
                                       ) = recovery.store_head_digest)
                           )
                           AND NOT EXISTS (
                               SELECT 1
                               FROM json_each(
                                   CAST(recovery.receipt_json AS TEXT),
                                   '$.lifecycle_history'
                               ) history
                               WHERE json_extract(history.value, '$.state') IN (
                                   'writer_attached', 'launch_intended', 'finished',
                                   'published', 'terminal_prepared'
                               )
                           ))
                   )
                   AND (
                       command_cleanup.proof_id IS NULL
                       OR (command_cleanup.sprint_id = intent.sprint_id
                           AND command_cleanup.launch_id = intent.runner_launch_id
                           AND command_cleanup.session_id = intent.runner_session_id
                           AND command_cleanup.effect_id = intent.effect_id
                           AND command_cleanup.observation_id = NEW.observation_id
                           AND command_cleanup.request_digest = intent.request_digest
                           AND command_cleanup.disposition = 'NoDomainCreatedBeforeEffect'
                           AND command_cleanup.surviving_processes = 0
                           AND command_cleanup.cleaned_at_unix_ms <=
                               recovery.recovered_at_unix_ms)
                   ))
                  OR (NEW.validation_kind = 'RestartClaimedBeforeLaunchAbandoned'
                      AND acquired.acquired_anchor_digest IS NOT NULL
                      AND recovery.acquired_anchor_digest = acquired.acquired_anchor_digest
                      AND recovery.observed_state = 'Cleaned'
                      AND recovery.launch_schema IS NULL
                      AND json_extract(
                            CAST(recovery.receipt_json AS TEXT),
                            '$.requested_store_head.generation'
                          ) = acquired.store_head_generation
                      AND json_extract(
                            CAST(recovery.receipt_json AS TEXT),
                            '$.requested_store_head.record_digest'
                          ) = acquired.store_head_digest
                      AND json_type(
                            CAST(recovery.receipt_json AS TEXT),
                            '$.artifact_reference'
                          ) = 'null'
                      AND json_type(
                            CAST(recovery.receipt_json AS TEXT),
                            '$.terminal_prepared'
                          ) = 'null'
                      AND json_type(
                            CAST(recovery.receipt_json AS TEXT),
                            '$.cleanup_completion_proof_digest'
                          ) = 'text'
                      AND (
                          recovery.resolution_action = 'WorkingSetCleaned'
                          OR (recovery.resolution_action = 'TerminalReadback'
                              AND json_extract(
                                    CAST(recovery.receipt_json AS TEXT),
                                    '$.initial_state'
                                  ) = 'cleaned'
                              AND json_extract(
                                    CAST(recovery.receipt_json AS TEXT),
                                    '$.initial_store_head.generation'
                                  ) = recovery.store_head_generation
                              AND json_extract(
                                    CAST(recovery.receipt_json AS TEXT),
                                    '$.initial_store_head.record_digest'
                                  ) = recovery.store_head_digest)
                      )
                      AND NOT EXISTS (
                          SELECT 1
                          FROM json_each(
                              CAST(recovery.receipt_json AS TEXT),
                              '$.lifecycle_history'
                          ) history
                          WHERE json_extract(history.value, '$.state') IN (
                              'launch_intended', 'finished', 'published',
                              'terminal_prepared'
                          )
                      )
                      AND (
                          command_cleanup.proof_id IS NULL
                          OR (command_cleanup.sprint_id = intent.sprint_id
                              AND command_cleanup.launch_id = intent.runner_launch_id
                              AND command_cleanup.session_id = intent.runner_session_id
                              AND command_cleanup.effect_id = intent.effect_id
                              AND command_cleanup.observation_id = NEW.observation_id
                              AND command_cleanup.request_digest = intent.request_digest
                              AND command_cleanup.disposition = 'NoDomainCreatedBeforeEffect'
                              AND command_cleanup.surviving_processes = 0
                              AND command_cleanup.cleaned_at_unix_ms <=
                                  recovery.recovered_at_unix_ms)
                      ))
                  OR (NEW.validation_kind = 'RestartClaimedUnresolved'
                      AND acquired.acquired_anchor_digest IS NOT NULL
                      AND recovery.acquired_anchor_digest = acquired.acquired_anchor_digest
                      AND recovery.launch_schema IS NOT NULL
                      AND recovery.observed_state IN (
                          'LaunchIntended', 'Finished', 'Published',
                          'TerminalPrepared', 'CleanupIntended', 'Cleaned'
                      )
                      AND json_extract(
                            CAST(recovery.receipt_json AS TEXT),
                            '$.requested_store_head.generation'
                          ) = acquired.store_head_generation
                      AND json_extract(
                            CAST(recovery.receipt_json AS TEXT),
                            '$.requested_store_head.record_digest'
                          ) = acquired.store_head_digest
                      AND NEW.command_domain_cleanup_proof_id IS NULL)
                  OR (NEW.validation_kind = 'RestartTerminalPreparedPublished'
                      AND acquired.acquired_anchor_digest IS NOT NULL
                      AND recovery.acquired_anchor_digest = acquired.acquired_anchor_digest
                      AND recovery.observed_state = 'TerminalPrepared'
                      AND recovery.resolution_action IN (
                          'TerminalReadback', 'TerminalPreparedRecovered'
                      )
                      AND recovery.launch_schema IS NOT NULL
                      AND json_extract(
                            CAST(recovery.receipt_json AS TEXT),
                            '$.requested_store_head.generation'
                          ) = acquired.store_head_generation
                      AND json_extract(
                            CAST(recovery.receipt_json AS TEXT),
                            '$.requested_store_head.record_digest'
                          ) = acquired.store_head_digest
                      AND json_type(
                            CAST(recovery.receipt_json AS TEXT),
                            '$.finished_store_head'
                          ) = 'object'
                      AND json_type(
                            CAST(recovery.receipt_json AS TEXT),
                            '$.published_store_head'
                          ) = 'object'
                      AND json_type(
                            CAST(recovery.receipt_json AS TEXT),
                            '$.artifact_reference'
                          ) = 'object'
                      AND json_type(
                            CAST(recovery.receipt_json AS TEXT),
                            '$.terminal_prepared'
                          ) = 'object'
                      AND json_extract(
                            CAST(recovery.receipt_json AS TEXT),
                            '$.terminal_prepared.store_head.generation'
                          ) = recovery.store_head_generation
                      AND json_extract(
                            CAST(recovery.receipt_json AS TEXT),
                            '$.terminal_prepared.store_head.record_digest'
                          ) = recovery.store_head_digest
                      AND json_type(
                            CAST(recovery.receipt_json AS TEXT),
                            '$.cleaned_store_head'
                          ) = 'null'
                      AND json_type(
                            CAST(recovery.receipt_json AS TEXT),
                            '$.cleanup_completion_proof_digest'
                          ) = 'null'
                      AND (
                          command_cleanup.proof_id IS NULL
                          OR (command_cleanup.sprint_id = intent.sprint_id
                              AND command_cleanup.launch_id = intent.runner_launch_id
                              AND command_cleanup.session_id = intent.runner_session_id
                              AND command_cleanup.effect_id = intent.effect_id
                              AND command_cleanup.observation_id = NEW.observation_id
                              AND command_cleanup.request_digest = intent.request_digest
                              AND command_cleanup.disposition = 'ReapedZeroSurvivors'
                              AND command_cleanup.surviving_processes = 0
                              AND command_cleanup.cleaned_at_unix_ms <=
                                  recovery.recovered_at_unix_ms)
                      ))
              ))
          OR (NEW.validation_kind = 'RestartReconciliation'
              AND claim.fencing_token = NEW.reconciliation_fencing_token
              AND cleanup.surviving_processes = 0
              AND cleanup.cleaned_at_unix_ms >= claim.acquired_at_unix_ms
              AND cleanup.cleaned_at_unix_ms <=
                  NEW.terminal_anchored_at_unix_ms
              AND (
                  command_cleanup.proof_id IS NULL
                  OR (command_cleanup.sprint_id = intent.sprint_id
                      AND command_cleanup.launch_id = intent.runner_launch_id
                      AND command_cleanup.session_id = intent.runner_session_id
                      AND command_cleanup.effect_id = intent.effect_id
                      AND command_cleanup.observation_id = NEW.observation_id
                      AND command_cleanup.request_digest = intent.request_digest
                      AND command_cleanup.surviving_processes = 0)
              ))
      )
)
BEGIN SELECT RAISE(ABORT, 'capture terminal validation must bind exact live or recovery authority'); END;

-- Cleanup rows are staged after their observation inside the owning atomic
-- terminal transaction. This reciprocal trigger closes the deferred-FK gap:
-- a validation may name an absent proof, but that proof can only arrive with
-- the exact family, effect, observation, runner binding, and recovery time.
CREATE TRIGGER command_domain_cleanup_proofs_exact_capture_restart_validation
BEFORE INSERT ON command_domain_cleanup_proofs
WHEN EXISTS (
    SELECT 1
    FROM command_output_capture_terminal_validations validation
    WHERE validation.command_domain_cleanup_proof_id = NEW.proof_id
      AND validation.validation_kind IN (
          'DirectClaimed',
          'RestartIntentAbandoned', 'RestartClaimedBeforeLaunchAbandoned',
          'RestartTerminalPreparedPublished', 'RestartReconciliation'
      )
) AND NOT EXISTS (
    SELECT 1
    FROM command_output_capture_terminal_validations validation
    JOIN command_output_capture_intents intent
      ON intent.capture_id = validation.capture_id
     AND intent.effect_id = validation.effect_id
     AND intent.sprint_id = validation.sprint_id
    LEFT JOIN command_output_capture_restart_recovery_receipts recovery
      ON recovery.receipt_digest = validation.restart_recovery_receipt_digest
     AND recovery.capture_id = intent.capture_id
     AND recovery.effect_id = intent.effect_id
    JOIN command_output_capture_terminal_anchors terminal
      ON terminal.terminal_anchor_digest = validation.terminal_anchor_digest
     AND terminal.capture_id = intent.capture_id
     AND terminal.effect_id = intent.effect_id
     AND terminal.observation_id = validation.observation_id
    WHERE validation.command_domain_cleanup_proof_id = NEW.proof_id
      AND NEW.sprint_id = intent.sprint_id
      AND NEW.launch_id = intent.runner_launch_id
      AND NEW.session_id = intent.runner_session_id
      AND NEW.effect_id = intent.effect_id
      AND NEW.observation_id = validation.observation_id
      AND NEW.request_digest = intent.request_digest
      AND NEW.surviving_processes = 0
      AND NEW.cleaned_at_unix_ms <= terminal.anchored_at_unix_ms
      AND (
          (validation.validation_kind IN (
               'RestartIntentAbandoned', 'RestartClaimedBeforeLaunchAbandoned'
           )
           AND NEW.disposition = 'NoDomainCreatedBeforeEffect'
           AND NEW.cleaned_at_unix_ms <= recovery.recovered_at_unix_ms)
          OR (validation.validation_kind = 'RestartTerminalPreparedPublished'
              AND NEW.disposition = 'ReapedZeroSurvivors'
              AND NEW.cleaned_at_unix_ms <= recovery.recovered_at_unix_ms)
          OR validation.validation_kind IN ('DirectClaimed', 'RestartReconciliation')
      )
)
BEGIN SELECT RAISE(ABORT, 'command cleanup proof must match its exact capture restart validation'); END;

CREATE TRIGGER command_output_capture_terminal_validations_no_update
BEFORE UPDATE ON command_output_capture_terminal_validations
BEGIN SELECT RAISE(ABORT, 'capture terminal validations are immutable'); END;
CREATE TRIGGER command_output_capture_terminal_validations_no_delete
BEFORE DELETE ON command_output_capture_terminal_validations
BEGIN SELECT RAISE(ABORT, 'capture terminal validations are immutable'); END;

CREATE TABLE command_output_capture_terminal_anchors (
    capture_id TEXT PRIMARY KEY NOT NULL,
    effect_id TEXT NOT NULL UNIQUE,
    observation_id TEXT NOT NULL UNIQUE,
    dispatch_claim_id TEXT,
    intent_digest TEXT NOT NULL,
    acquired_anchor_digest TEXT,
    observation_class TEXT NOT NULL CHECK (observation_class IN (
        'Succeeded', 'FailedBeforeEffect', 'FailedAfterKnownEffect',
        'CancelledBeforeEffect', 'Unknown'
    )),
    disposition TEXT NOT NULL CHECK (disposition IN (
        'Published', 'Abandoned', 'ReconciliationRequired'
    )),
    store_head_generation INTEGER NOT NULL CHECK (store_head_generation > 0),
    store_head_digest TEXT NOT NULL,
    terminal_record_digest TEXT NOT NULL,
    artifact_manifest_digest TEXT,
    artifact_reference_json BLOB,
    anchored_at_unix_ms INTEGER NOT NULL CHECK (anchored_at_unix_ms > 0),
    terminal_anchor_digest TEXT NOT NULL UNIQUE CHECK (
        length(terminal_anchor_digest) = 64
        AND terminal_anchor_digest NOT GLOB '*[^0-9a-f]*'
    ),
    layout_version INTEGER NOT NULL CHECK (layout_version = 1),
    contract_version INTEGER NOT NULL CHECK (contract_version > 0),
    terminal_anchor_json BLOB NOT NULL CHECK (
        length(terminal_anchor_json) > 0
        AND terminal_anchor_digest = grok_command_output_capture_terminal_digest(terminal_anchor_json)
    ),
    CHECK (
        (observation_class IN ('Succeeded', 'FailedAfterKnownEffect')
         AND disposition = 'Published'
         AND dispatch_claim_id IS NOT NULL
         AND acquired_anchor_digest IS NOT NULL
         AND artifact_manifest_digest IS NOT NULL
         AND artifact_reference_json IS NOT NULL)
        OR (observation_class IN ('FailedBeforeEffect', 'CancelledBeforeEffect')
            AND disposition = 'Abandoned'
            AND artifact_manifest_digest IS NULL
            AND artifact_reference_json IS NULL)
        OR (observation_class = 'Unknown'
            AND disposition = 'ReconciliationRequired'
            AND dispatch_claim_id IS NOT NULL
            AND acquired_anchor_digest IS NOT NULL
            AND artifact_manifest_digest IS NULL
            AND artifact_reference_json IS NULL)
    ),
    FOREIGN KEY (capture_id, effect_id, intent_digest)
        REFERENCES command_output_capture_intents(capture_id, effect_id, intent_digest)
        ON DELETE RESTRICT,
    FOREIGN KEY (dispatch_claim_id)
        REFERENCES runner_effect_dispatch_claims(dispatch_claim_id) ON DELETE RESTRICT,
    FOREIGN KEY (acquired_anchor_digest)
        REFERENCES command_output_capture_acquisitions(acquired_anchor_digest) ON DELETE RESTRICT,
    FOREIGN KEY (observation_id) REFERENCES effect_observations(observation_id)
        ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED
) STRICT, WITHOUT ROWID;

-- An Unknown observation and its ReconciliationRequired terminal are immutable.
-- Later recovery appends exactly one fenced resolution after both execution
-- domains are proven clean; it never rewrites the effect or terminal history.
CREATE TABLE command_output_capture_reconciliation_resolutions (
    resolution_anchor_digest TEXT PRIMARY KEY NOT NULL CHECK (
        length(resolution_anchor_digest) = 64
        AND resolution_anchor_digest NOT GLOB '*[^0-9a-f]*'
    ),
    capture_id TEXT NOT NULL UNIQUE,
    effect_id TEXT NOT NULL UNIQUE,
    observation_id TEXT NOT NULL UNIQUE,
    terminal_anchor_digest TEXT NOT NULL UNIQUE,
    reconciliation_claim_id TEXT NOT NULL UNIQUE,
    reconciliation_fencing_token TEXT NOT NULL UNIQUE,
    disposition TEXT NOT NULL CHECK (disposition IN ('Published', 'Abandoned')),
    store_head_generation INTEGER NOT NULL CHECK (store_head_generation > 0),
    store_head_digest TEXT NOT NULL CHECK (
        length(store_head_digest) = 64
        AND store_head_digest NOT GLOB '*[^0-9a-f]*'
    ),
    resolution_record_digest TEXT NOT NULL CHECK (
        length(resolution_record_digest) = 64
        AND resolution_record_digest NOT GLOB '*[^0-9a-f]*'
    ),
    artifact_manifest_digest TEXT,
    artifact_reference_json BLOB,
    command_domain_cleanup_proof_id TEXT NOT NULL UNIQUE,
    runner_cleanup_receipt_id TEXT NOT NULL UNIQUE,
    physical_recovery_receipt_digest TEXT NOT NULL UNIQUE,
    resolved_at_unix_ms INTEGER NOT NULL CHECK (resolved_at_unix_ms > 0),
    layout_version INTEGER NOT NULL CHECK (layout_version = 1),
    contract_version INTEGER NOT NULL CHECK (contract_version > 0),
    resolution_json BLOB NOT NULL CHECK (
        length(resolution_json) > 0
        AND resolution_anchor_digest =
            grok_command_output_capture_reconciliation_resolution_digest(resolution_json)
    ),
    CHECK (
        (disposition = 'Published'
         AND artifact_manifest_digest IS NOT NULL
         AND artifact_reference_json IS NOT NULL)
        OR (disposition = 'Abandoned'
            AND artifact_manifest_digest IS NULL
            AND artifact_reference_json IS NULL)
    ),
    FOREIGN KEY (capture_id, effect_id)
        REFERENCES command_output_capture_intents(capture_id, effect_id)
        ON DELETE RESTRICT,
    FOREIGN KEY (terminal_anchor_digest)
        REFERENCES command_output_capture_terminal_anchors(terminal_anchor_digest)
        ON DELETE RESTRICT,
    FOREIGN KEY (reconciliation_claim_id)
        REFERENCES command_output_capture_reconciliation_claims(claim_id)
        ON DELETE RESTRICT,
    FOREIGN KEY (command_domain_cleanup_proof_id)
        REFERENCES command_domain_cleanup_proofs(proof_id)
        ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED,
    FOREIGN KEY (runner_cleanup_receipt_id)
        REFERENCES worker_cleanup_receipts(receipt_id)
        ON DELETE RESTRICT,
    FOREIGN KEY (physical_recovery_receipt_digest)
        REFERENCES command_output_capture_restart_recovery_receipts(receipt_digest)
        ON DELETE RESTRICT
) STRICT, WITHOUT ROWID;

CREATE TRIGGER command_output_capture_reconciliation_resolutions_exact
BEFORE INSERT ON command_output_capture_reconciliation_resolutions
WHEN NOT EXISTS (
    SELECT 1
    FROM command_output_capture_intents intent
    JOIN effect_intents effect_intent
      ON effect_intent.effect_id = intent.effect_id
     AND effect_intent.sprint_id = intent.sprint_id
    JOIN command_output_capture_terminal_anchors terminal
      ON terminal.capture_id = intent.capture_id
     AND terminal.effect_id = intent.effect_id
     AND terminal.observation_id = NEW.observation_id
     AND terminal.terminal_anchor_digest = NEW.terminal_anchor_digest
     AND terminal.observation_class = 'Unknown'
     AND terminal.disposition = 'ReconciliationRequired'
    JOIN command_output_capture_reconciliation_claims claim
      ON claim.claim_id = NEW.reconciliation_claim_id
     AND claim.capture_id = intent.capture_id
     AND claim.fencing_token = NEW.reconciliation_fencing_token
    JOIN command_output_capture_reconciliation_claim_releases release
      ON release.claim_id = claim.claim_id
     AND release.capture_id = claim.capture_id
     AND release.claim_epoch = claim.claim_epoch
     AND release.fencing_token = claim.fencing_token
     AND release.contract_version = claim.contract_version
     AND release.release_kind = 'ConsumedTerminal'
     AND release.terminal_anchor_digest = terminal.terminal_anchor_digest
     AND release.released_at_unix_ms = NEW.resolved_at_unix_ms
    JOIN worker_cleanup_receipts runner_cleanup
      ON runner_cleanup.sprint_id = intent.sprint_id
     AND runner_cleanup.receipt_id = NEW.runner_cleanup_receipt_id
     AND runner_cleanup.launch_id = intent.runner_launch_id
     AND runner_cleanup.session_id = intent.runner_session_id
     AND runner_cleanup.worker_lease_id IS effect_intent.worker_lease_id
     AND runner_cleanup.worker_lease_epoch IS effect_intent.worker_lease_epoch
     AND runner_cleanup.surviving_processes = 0
     AND runner_cleanup.contract_version = intent.contract_version
    LEFT JOIN command_domain_cleanup_proofs command_cleanup
      ON command_cleanup.proof_id = NEW.command_domain_cleanup_proof_id
    JOIN command_output_capture_restart_recovery_receipts physical
      ON physical.receipt_digest = NEW.physical_recovery_receipt_digest
     AND physical.capture_id = intent.capture_id
     AND physical.effect_id = intent.effect_id
    WHERE intent.capture_id = NEW.capture_id
      AND intent.effect_id = NEW.effect_id
      AND intent.layout_version = NEW.layout_version
      AND intent.contract_version = NEW.contract_version
      AND claim.claim_epoch = (
          SELECT MAX(latest.claim_epoch)
          FROM command_output_capture_reconciliation_claims latest
          WHERE latest.capture_id = claim.capture_id
      )
      AND (
          command_cleanup.proof_id IS NULL
          OR (command_cleanup.sprint_id = intent.sprint_id
              AND command_cleanup.launch_id = intent.runner_launch_id
              AND command_cleanup.session_id = intent.runner_session_id
              AND command_cleanup.effect_id = intent.effect_id
              AND command_cleanup.observation_id = terminal.observation_id
              AND command_cleanup.request_digest = intent.request_digest
              AND command_cleanup.disposition = 'ReapedZeroSurvivors'
              AND command_cleanup.surviving_processes = 0
              AND command_cleanup.contract_version = intent.contract_version
              AND command_cleanup.cleaned_at_unix_ms >= terminal.anchored_at_unix_ms
              AND command_cleanup.cleaned_at_unix_ms <= NEW.resolved_at_unix_ms)
      )
      AND (
          (NEW.store_head_generation > terminal.store_head_generation
           AND physical.reconciliation_claim_id = claim.claim_id
           AND physical.reconciliation_fencing_token = claim.fencing_token
           AND physical.acquired_anchor_digest = terminal.acquired_anchor_digest
           AND physical.store_head_generation = NEW.store_head_generation
           AND physical.store_head_digest = NEW.store_head_digest
           AND NEW.resolution_record_digest = physical.store_head_digest
           AND physical.recovered_at_unix_ms = NEW.resolved_at_unix_ms
           AND json_extract(
                 CAST(physical.receipt_json AS TEXT),
                 '$.requested_store_head.generation'
               ) = terminal.store_head_generation
           AND json_extract(
                 CAST(physical.receipt_json AS TEXT),
                 '$.requested_store_head.record_digest'
               ) = terminal.store_head_digest
           AND json_extract(
                 CAST(physical.receipt_json AS TEXT),
                 '$.initial_store_head.generation'
               ) BETWEEN terminal.store_head_generation
                     AND physical.store_head_generation
           AND (
               (physical.observed_state = 'Cleaned'
                AND NEW.disposition = 'Abandoned'
                AND json_type(
                      CAST(physical.receipt_json AS TEXT),
                      '$.artifact_reference'
                    ) = 'null'
                AND json_type(
                      CAST(physical.receipt_json AS TEXT),
                      '$.cleanup_completion_proof_digest'
                    ) = 'text')
               OR (physical.observed_state IN ('Published', 'TerminalPrepared')
                   AND NEW.disposition = 'Published'
                   AND NEW.artifact_manifest_digest = json_extract(
                         CAST(physical.receipt_json AS TEXT),
                         '$.artifact_reference.manifest_digest'
                       )
                   AND CAST(NEW.artifact_reference_json AS TEXT) = json_extract(
                         CAST(physical.receipt_json AS TEXT),
                         '$.artifact_reference'
                       )
                   AND json_extract(
                         CAST(physical.receipt_json AS TEXT),
                         '$.artifact_reference.source.sprint_id'
                       ) = intent.sprint_id
                   AND json_extract(
                         CAST(physical.receipt_json AS TEXT),
                         '$.artifact_reference.source.runner_launch_id'
                       ) = intent.runner_launch_id
                   AND json_extract(
                         CAST(physical.receipt_json AS TEXT),
                         '$.artifact_reference.source.runner_session_id'
                       ) = intent.runner_session_id
                   AND json_extract(
                         CAST(physical.receipt_json AS TEXT),
                         '$.artifact_reference.source.effect_id'
                       ) = intent.effect_id
                   AND json_extract(
                         CAST(physical.receipt_json AS TEXT),
                         '$.artifact_reference.source.request_digest'
                       ) = intent.request_digest))
           )
          OR (NEW.store_head_generation = terminal.store_head_generation
              AND NEW.store_head_digest = terminal.store_head_digest
              AND NEW.resolution_record_digest = terminal.terminal_record_digest
              AND EXISTS (
                  SELECT 1
                  FROM command_output_capture_terminal_validations validation
                  JOIN command_output_capture_restart_recovery_receipts recovery
                    ON recovery.receipt_digest = validation.restart_recovery_receipt_digest
                   AND recovery.receipt_digest = physical.receipt_digest
                   AND recovery.capture_id = terminal.capture_id
                   AND recovery.effect_id = terminal.effect_id
                   AND recovery.store_head_generation = terminal.store_head_generation
                   AND recovery.store_head_digest = terminal.store_head_digest
                   AND recovery.receipt_digest = terminal.terminal_record_digest
                  WHERE validation.terminal_anchor_digest = terminal.terminal_anchor_digest
                    AND validation.validation_kind = 'RestartClaimedUnresolved'
                    AND ((recovery.observed_state = 'Cleaned'
                          AND NEW.disposition = 'Abandoned')
                         OR (recovery.observed_state IN ('Published', 'TerminalPrepared')
                             AND NEW.disposition = 'Published'
                             AND NEW.artifact_manifest_digest = json_extract(
                                   CAST(recovery.receipt_json AS TEXT),
                                   '$.artifact_reference.manifest_digest'
                                 )
                             AND CAST(NEW.artifact_reference_json AS TEXT) =
                                 json_extract(
                                     CAST(recovery.receipt_json AS TEXT),
                                     '$.artifact_reference'
                                 )
                             AND json_extract(
                                   CAST(recovery.receipt_json AS TEXT),
                                   '$.artifact_reference.source.sprint_id'
                                 ) = intent.sprint_id
                             AND json_extract(
                                   CAST(recovery.receipt_json AS TEXT),
                                   '$.artifact_reference.source.runner_launch_id'
                                 ) = intent.runner_launch_id
                             AND json_extract(
                                   CAST(recovery.receipt_json AS TEXT),
                                   '$.artifact_reference.source.runner_session_id'
                                 ) = intent.runner_session_id
                             AND json_extract(
                                   CAST(recovery.receipt_json AS TEXT),
                                   '$.artifact_reference.source.effect_id'
                                 ) = intent.effect_id
                             AND json_extract(
                                   CAST(recovery.receipt_json AS TEXT),
                                   '$.artifact_reference.source.request_digest'
                                 ) = intent.request_digest))
              ))
      )
      AND NEW.resolved_at_unix_ms >= terminal.anchored_at_unix_ms
      AND NEW.resolved_at_unix_ms >= claim.acquired_at_unix_ms
      AND NEW.resolved_at_unix_ms < claim.expires_at_unix_ms
      AND runner_cleanup.cleaned_at_unix_ms >= terminal.anchored_at_unix_ms
      AND runner_cleanup.cleaned_at_unix_ms <= NEW.resolved_at_unix_ms
      AND json_extract(CAST(NEW.resolution_json AS TEXT), '$.capture_id') = NEW.capture_id
      AND json_extract(CAST(NEW.resolution_json AS TEXT), '$.effect_id') = NEW.effect_id
      AND json_extract(CAST(NEW.resolution_json AS TEXT), '$.observation_id') = NEW.observation_id
      AND json_extract(CAST(NEW.resolution_json AS TEXT), '$.terminal_anchor_digest') = NEW.terminal_anchor_digest
      AND json_extract(CAST(NEW.resolution_json AS TEXT), '$.reconciliation_claim_id') = NEW.reconciliation_claim_id
      AND json_extract(CAST(NEW.resolution_json AS TEXT), '$.reconciliation_fencing_token') = NEW.reconciliation_fencing_token
      AND json_extract(CAST(NEW.resolution_json AS TEXT), '$.resolution_anchor_digest') = NEW.resolution_anchor_digest
      AND json_extract(CAST(NEW.resolution_json AS TEXT), '$.disposition') = CASE NEW.disposition
            WHEN 'Published' THEN 'published'
            WHEN 'Abandoned' THEN 'abandoned'
          END
      AND json_extract(
            CAST(NEW.resolution_json AS TEXT),
            '$.store_head.generation'
          ) = NEW.store_head_generation
      AND json_extract(
            CAST(NEW.resolution_json AS TEXT),
            '$.store_head.record_digest'
          ) = NEW.store_head_digest
      AND json_extract(
            CAST(NEW.resolution_json AS TEXT),
            '$.resolution_record_digest'
          ) = NEW.resolution_record_digest
      AND json_extract(
            CAST(NEW.resolution_json AS TEXT),
            '$.artifact_reference.manifest_digest'
          ) IS NEW.artifact_manifest_digest
      AND (
          (NEW.artifact_reference_json IS NULL
           AND json_type(
                 CAST(NEW.resolution_json AS TEXT),
                 '$.artifact_reference'
               ) = 'null')
          OR (NEW.artifact_reference_json IS NOT NULL
              AND CAST(NEW.artifact_reference_json AS TEXT) = json_extract(
                    CAST(NEW.resolution_json AS TEXT),
                    '$.artifact_reference'
                  ))
      )
      AND json_extract(
            CAST(NEW.resolution_json AS TEXT),
            '$.resolved_at_unix_ms'
          ) = NEW.resolved_at_unix_ms
      AND json_extract(CAST(NEW.resolution_json AS TEXT), '$.layout_version') =
          NEW.layout_version
      AND json_extract(CAST(NEW.resolution_json AS TEXT), '$.contract_version') =
          NEW.contract_version
)
BEGIN SELECT RAISE(ABORT, 'capture resolution must bind exact Unknown, claim, and runner cleanup'); END;

-- The resolution may be staged before its deferred command-domain proof in
-- the same transaction. Close that ordering gap from the reciprocal side so
-- a later proof cannot satisfy the FK with crossed command or time authority.
CREATE TRIGGER command_domain_cleanup_proofs_exact_capture_resolution
BEFORE INSERT ON command_domain_cleanup_proofs
WHEN EXISTS (
    SELECT 1
    FROM command_output_capture_reconciliation_resolutions resolution
    WHERE resolution.command_domain_cleanup_proof_id = NEW.proof_id
) AND NOT EXISTS (
    SELECT 1
    FROM command_output_capture_reconciliation_resolutions resolution
    JOIN command_output_capture_intents intent
      ON intent.capture_id = resolution.capture_id
     AND intent.effect_id = resolution.effect_id
    JOIN command_output_capture_terminal_anchors terminal
      ON terminal.terminal_anchor_digest = resolution.terminal_anchor_digest
     AND terminal.capture_id = intent.capture_id
     AND terminal.effect_id = intent.effect_id
     AND terminal.observation_id = resolution.observation_id
    WHERE resolution.command_domain_cleanup_proof_id = NEW.proof_id
      AND NEW.sprint_id = intent.sprint_id
      AND NEW.launch_id = intent.runner_launch_id
      AND NEW.session_id = intent.runner_session_id
      AND NEW.effect_id = intent.effect_id
      AND NEW.observation_id = terminal.observation_id
      AND NEW.request_digest = intent.request_digest
      AND NEW.disposition = 'ReapedZeroSurvivors'
      AND NEW.surviving_processes = 0
      AND NEW.contract_version = intent.contract_version
      AND NEW.cleaned_at_unix_ms >= terminal.anchored_at_unix_ms
      AND NEW.cleaned_at_unix_ms <= resolution.resolved_at_unix_ms
)
BEGIN SELECT RAISE(ABORT, 'command cleanup proof must match its exact capture resolution'); END;

CREATE TRIGGER command_output_capture_reconciliation_resolutions_no_update
BEFORE UPDATE ON command_output_capture_reconciliation_resolutions
BEGIN SELECT RAISE(ABORT, 'command output capture resolutions are immutable'); END;
CREATE TRIGGER command_output_capture_reconciliation_resolutions_no_delete
BEFORE DELETE ON command_output_capture_reconciliation_resolutions
BEGIN SELECT RAISE(ABORT, 'command output capture resolutions are immutable'); END;

CREATE TABLE command_output_capture_reconciliation_obligation_closures (
    obligation_id TEXT PRIMARY KEY NOT NULL,
    capture_id TEXT NOT NULL UNIQUE,
    effect_id TEXT NOT NULL UNIQUE,
    terminal_anchor_digest TEXT NOT NULL UNIQUE,
    closed_at_unix_ms INTEGER NOT NULL CHECK (closed_at_unix_ms > 0),
    contract_version INTEGER NOT NULL CHECK (contract_version > 0),
    FOREIGN KEY (obligation_id)
        REFERENCES command_output_capture_reconciliation_obligations(obligation_id)
        ON DELETE RESTRICT,
    FOREIGN KEY (terminal_anchor_digest)
        REFERENCES command_output_capture_terminal_anchors(terminal_anchor_digest)
        ON DELETE RESTRICT
) STRICT, WITHOUT ROWID;

CREATE TRIGGER command_output_capture_terminal_no_backfill
BEFORE INSERT ON command_output_capture_terminal_anchors
WHEN EXISTS (SELECT 1 FROM effect_observations WHERE effect_id = NEW.effect_id)
BEGIN SELECT RAISE(ABORT, 'capture terminal anchor must precede its new observation'); END;

CREATE TRIGGER command_output_capture_terminal_exact_authority
BEFORE INSERT ON command_output_capture_terminal_anchors
WHEN NOT EXISTS (
    SELECT 1
    FROM command_output_capture_intents intent
    JOIN command_output_capture_exact_runner_sources_v27 exact_source
      ON exact_source.capture_id = intent.capture_id
    LEFT JOIN command_output_capture_acquisitions acquired
      ON acquired.capture_id = intent.capture_id
    LEFT JOIN command_output_capture_exact_acquisitions_v27 exact_acquired
      ON exact_acquired.acquired_anchor_digest = acquired.acquired_anchor_digest
    LEFT JOIN runner_effect_dispatch_claims claim
      ON claim.effect_id = intent.effect_id
    LEFT JOIN command_output_capture_exact_dispatch_authorities_v27 exact_dispatch
      ON exact_dispatch.capture_id = intent.capture_id
     AND exact_dispatch.dispatch_claim_id = claim.dispatch_claim_id
    JOIN command_output_capture_terminal_validations validation
      ON validation.terminal_anchor_digest = NEW.terminal_anchor_digest
     AND validation.capture_id = intent.capture_id
     AND validation.effect_id = intent.effect_id
     AND validation.observation_id = NEW.observation_id
     AND validation.terminal_anchored_at_unix_ms = NEW.anchored_at_unix_ms
    LEFT JOIN command_output_capture_reconciliation_claims reconciliation_claim
      ON reconciliation_claim.claim_id = validation.reconciliation_claim_id
     AND reconciliation_claim.capture_id = intent.capture_id
     AND reconciliation_claim.fencing_token = validation.reconciliation_fencing_token
    LEFT JOIN command_output_capture_restart_recovery_receipts recovery
      ON recovery.receipt_digest = validation.restart_recovery_receipt_digest
     AND recovery.capture_id = intent.capture_id
     AND recovery.effect_id = intent.effect_id
     AND recovery.reconciliation_claim_id = validation.reconciliation_claim_id
     AND recovery.reconciliation_fencing_token =
         validation.reconciliation_fencing_token
    LEFT JOIN command_output_capture_reconciliation_claim_releases recovery_release
      ON recovery_release.claim_id = validation.reconciliation_claim_id
     AND recovery_release.capture_id = intent.capture_id
     AND recovery_release.claim_epoch = reconciliation_claim.claim_epoch
     AND recovery_release.fencing_token = validation.reconciliation_fencing_token
     AND recovery_release.contract_version = reconciliation_claim.contract_version
     AND recovery_release.release_kind = 'ConsumedTerminal'
     AND recovery_release.terminal_anchor_digest = NEW.terminal_anchor_digest
    WHERE intent.capture_id = NEW.capture_id
      AND intent.effect_id = NEW.effect_id
      AND intent.intent_digest = NEW.intent_digest
      AND NEW.dispatch_claim_id IS claim.dispatch_claim_id
      AND NEW.acquired_anchor_digest IS acquired.acquired_anchor_digest
      AND (
          (NEW.dispatch_claim_id IS NULL
           AND NEW.acquired_anchor_digest IS NULL
           AND claim.dispatch_claim_id IS NULL
           AND acquired.acquired_anchor_digest IS NULL)
          OR (NEW.dispatch_claim_id IS NOT NULL
              AND NEW.acquired_anchor_digest IS NOT NULL
              AND exact_acquired.acquired_anchor_digest IS NOT NULL
              AND exact_dispatch.dispatch_claim_id = NEW.dispatch_claim_id)
      )
      AND (
          (validation.validation_kind = 'DirectClaimed'
           AND NEW.dispatch_claim_id IS NOT NULL
           AND NEW.acquired_anchor_digest IS NOT NULL
           AND NEW.disposition IN ('Published', 'Abandoned'))
          OR (validation.validation_kind = 'DirectClaimedUnresolved'
              AND NEW.observation_class = 'Unknown'
              AND NEW.disposition = 'ReconciliationRequired'
              AND NEW.dispatch_claim_id IS NOT NULL
              AND NEW.acquired_anchor_digest IS NOT NULL
              AND NEW.store_head_generation = acquired.store_head_generation
              AND NEW.store_head_digest = acquired.store_head_digest)
          OR (validation.validation_kind = 'PreDispatchAbandoned'
              AND NEW.observation_class IN (
                  'FailedBeforeEffect', 'CancelledBeforeEffect'
              )
              AND NEW.disposition = 'Abandoned'
              AND NEW.dispatch_claim_id IS NULL
              AND NEW.acquired_anchor_digest IS NULL)
          OR (validation.validation_kind = 'RestartIntentAbandoned'
              AND NEW.observation_class = 'FailedBeforeEffect'
              AND NEW.disposition = 'Abandoned'
              AND NEW.dispatch_claim_id IS NULL
              AND NEW.acquired_anchor_digest IS NULL
              AND recovery.receipt_digest = validation.restart_recovery_receipt_digest
              AND NEW.store_head_generation = recovery.store_head_generation
              AND NEW.store_head_digest = recovery.store_head_digest
              AND NEW.terminal_record_digest = recovery.receipt_digest
              AND NEW.anchored_at_unix_ms = recovery.recovered_at_unix_ms
              AND recovery_release.released_at_unix_ms =
                  recovery.recovered_at_unix_ms)
          OR (validation.validation_kind = 'RestartClaimedBeforeLaunchAbandoned'
              AND NEW.observation_class = 'FailedBeforeEffect'
              AND NEW.disposition = 'Abandoned'
              AND NEW.dispatch_claim_id IS NOT NULL
              AND NEW.acquired_anchor_digest IS NOT NULL
              AND recovery.receipt_digest = validation.restart_recovery_receipt_digest
              AND NEW.store_head_generation = recovery.store_head_generation
              AND NEW.store_head_digest = recovery.store_head_digest
              AND NEW.terminal_record_digest = recovery.receipt_digest
              AND NEW.anchored_at_unix_ms = recovery.recovered_at_unix_ms
              AND recovery_release.released_at_unix_ms =
                  recovery.recovered_at_unix_ms)
          OR (validation.validation_kind = 'RestartClaimedUnresolved'
              AND NEW.observation_class = 'Unknown'
              AND NEW.disposition = 'ReconciliationRequired'
              AND NEW.dispatch_claim_id IS NOT NULL
              AND NEW.acquired_anchor_digest IS NOT NULL
              AND recovery.receipt_digest = validation.restart_recovery_receipt_digest
              AND NEW.store_head_generation = recovery.store_head_generation
              AND NEW.store_head_digest = recovery.store_head_digest
              AND NEW.terminal_record_digest = recovery.receipt_digest
              AND NEW.anchored_at_unix_ms = recovery.recovered_at_unix_ms
              AND recovery_release.released_at_unix_ms =
                  recovery.recovered_at_unix_ms)
          OR (validation.validation_kind = 'RestartTerminalPreparedPublished'
              AND NEW.observation_class = 'Succeeded'
              AND NEW.disposition = 'Published'
              AND NEW.dispatch_claim_id IS NOT NULL
              AND NEW.acquired_anchor_digest IS NOT NULL
              AND recovery.receipt_digest = validation.restart_recovery_receipt_digest
              AND NEW.store_head_generation = recovery.store_head_generation
              AND NEW.store_head_digest = recovery.store_head_digest
              AND NEW.terminal_record_digest = json_extract(
                    CAST(recovery.receipt_json AS TEXT),
                    '$.terminal_prepared.canonical_bytes_digest'
                  )
              AND NEW.artifact_manifest_digest = json_extract(
                    CAST(recovery.receipt_json AS TEXT),
                    '$.artifact_reference.manifest_digest'
                  )
              AND CAST(NEW.artifact_reference_json AS TEXT) = json_extract(
                    CAST(recovery.receipt_json AS TEXT),
                    '$.artifact_reference'
                  )
              AND NEW.anchored_at_unix_ms = recovery.recovered_at_unix_ms
              AND recovery_release.released_at_unix_ms =
                  recovery.recovered_at_unix_ms)
          OR (validation.validation_kind = 'RestartReconciliation'
              AND NEW.dispatch_claim_id IS NOT NULL
              AND NEW.acquired_anchor_digest IS NOT NULL
              AND recovery_release.released_at_unix_ms =
                  NEW.anchored_at_unix_ms)
      )
      AND NEW.anchored_at_unix_ms >= intent.created_at_unix_ms
      AND json_extract(CAST(NEW.terminal_anchor_json AS TEXT), '$.capture_id') = NEW.capture_id
      AND json_extract(CAST(NEW.terminal_anchor_json AS TEXT), '$.effect_id') = NEW.effect_id
      AND json_extract(CAST(NEW.terminal_anchor_json AS TEXT), '$.observation_id') = NEW.observation_id
      AND json_extract(CAST(NEW.terminal_anchor_json AS TEXT), '$.dispatch_claim_id')
          IS NEW.dispatch_claim_id
      AND json_extract(CAST(NEW.terminal_anchor_json AS TEXT), '$.intent_digest') =
          NEW.intent_digest
      AND json_extract(
            CAST(NEW.terminal_anchor_json AS TEXT),
            '$.acquired_anchor_digest'
          ) IS NEW.acquired_anchor_digest
      AND json_extract(CAST(NEW.terminal_anchor_json AS TEXT), '$.terminal_anchor_digest') = NEW.terminal_anchor_digest
      AND json_extract(CAST(NEW.terminal_anchor_json AS TEXT), '$.observation_class') = CASE NEW.observation_class
            WHEN 'Succeeded' THEN 'succeeded'
            WHEN 'FailedBeforeEffect' THEN 'failed_before_effect'
            WHEN 'FailedAfterKnownEffect' THEN 'failed_after_known_effect'
            WHEN 'CancelledBeforeEffect' THEN 'cancelled_before_effect'
            WHEN 'Unknown' THEN 'unknown'
          END
      AND json_extract(CAST(NEW.terminal_anchor_json AS TEXT), '$.disposition') = CASE NEW.disposition
            WHEN 'Published' THEN 'published'
            WHEN 'Abandoned' THEN 'abandoned'
            WHEN 'ReconciliationRequired' THEN 'reconciliation_required'
          END
      AND json_extract(
            CAST(NEW.terminal_anchor_json AS TEXT),
            '$.store_head.generation'
          ) = NEW.store_head_generation
      AND json_extract(
            CAST(NEW.terminal_anchor_json AS TEXT),
            '$.store_head.record_digest'
          ) = NEW.store_head_digest
      AND json_extract(
            CAST(NEW.terminal_anchor_json AS TEXT),
            '$.terminal_record_digest'
          ) = NEW.terminal_record_digest
      AND json_extract(
            CAST(NEW.terminal_anchor_json AS TEXT),
            '$.artifact_reference.manifest_digest'
          ) IS NEW.artifact_manifest_digest
      AND (
          (NEW.artifact_reference_json IS NULL
           AND json_type(
                 CAST(NEW.terminal_anchor_json AS TEXT),
                 '$.artifact_reference'
               ) = 'null')
          OR (NEW.artifact_reference_json IS NOT NULL
              AND CAST(NEW.artifact_reference_json AS TEXT) = json_extract(
                    CAST(NEW.terminal_anchor_json AS TEXT),
                    '$.artifact_reference'
                  ))
      )
      AND json_extract(
            CAST(NEW.terminal_anchor_json AS TEXT),
            '$.anchored_at_unix_ms'
          ) = NEW.anchored_at_unix_ms
      AND json_extract(CAST(NEW.terminal_anchor_json AS TEXT), '$.layout_version') =
          NEW.layout_version
      AND json_extract(CAST(NEW.terminal_anchor_json AS TEXT), '$.contract_version') =
          NEW.contract_version
)
BEGIN SELECT RAISE(ABORT, 'capture terminal anchor must match exact intent/acquisition/claim'); END;

CREATE TRIGGER command_output_capture_terminal_rejects_active_claim
BEFORE INSERT ON command_output_capture_terminal_anchors
WHEN EXISTS (
    SELECT 1
    FROM command_output_capture_reconciliation_claims claim
    LEFT JOIN command_output_capture_reconciliation_claim_releases release
      ON release.claim_id = claim.claim_id
     AND release.capture_id = claim.capture_id
     AND release.claim_epoch = claim.claim_epoch
     AND release.fencing_token = claim.fencing_token
     AND release.contract_version = claim.contract_version
    WHERE claim.capture_id = NEW.capture_id AND release.claim_id IS NULL
      AND NOT EXISTS (
          SELECT 1
          FROM command_output_capture_terminal_validations validation
          JOIN command_output_capture_reconciliation_claim_releases consumed
            ON consumed.claim_id = validation.reconciliation_claim_id
           AND consumed.release_kind = 'ConsumedTerminal'
           AND consumed.terminal_anchor_digest = NEW.terminal_anchor_digest
           AND consumed.released_at_unix_ms = NEW.anchored_at_unix_ms
          WHERE validation.terminal_anchor_digest = NEW.terminal_anchor_digest
            AND validation.validation_kind IN (
                'RestartIntentAbandoned', 'RestartClaimedBeforeLaunchAbandoned',
                'RestartClaimedUnresolved', 'RestartTerminalPreparedPublished',
                'RestartReconciliation'
            )
            AND validation.reconciliation_claim_id = claim.claim_id
            AND validation.reconciliation_fencing_token = claim.fencing_token
            AND consumed.capture_id = claim.capture_id
            AND consumed.claim_epoch = claim.claim_epoch
            AND consumed.fencing_token = claim.fencing_token
            AND consumed.contract_version = claim.contract_version
      )
)
BEGIN SELECT RAISE(ABORT, 'capture terminal must consume or exclude active reconciliation claim'); END;

CREATE TRIGGER effect_observations_require_v27_capture_terminal
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
          validation.validation_kind != 'DirectClaimedUnresolved'
          OR (NEW.outcome = 'Unknown'
              AND terminal.terminal_record_digest = NEW.evidence_digest)
      )
)
BEGIN SELECT RAISE(ABORT, 'v27 RunCommand observation requires atomic capture terminal anchor'); END;

-- These three restart dispositions use the complete physical reconciliation
-- receipt as their effect evidence.  The payload is staged before the
-- observation (its FK is deferred), so the observation boundary can bind the
-- exact immutable receipt bytes instead of accepting any payload that merely
-- shares a caller-supplied digest.  TerminalPrepared publication deliberately
-- remains outside this rule because it retains provider evidence separately.
CREATE TRIGGER effect_observations_require_v27_physical_recovery_evidence
BEFORE INSERT ON effect_observations
WHEN EXISTS (
    SELECT 1
    FROM command_output_capture_terminal_anchors terminal
    JOIN command_output_capture_terminal_validations validation
      ON validation.terminal_anchor_digest = terminal.terminal_anchor_digest
     AND validation.capture_id = terminal.capture_id
     AND validation.effect_id = terminal.effect_id
     AND validation.observation_id = terminal.observation_id
     AND validation.validation_kind IN (
         'RestartIntentAbandoned', 'RestartClaimedBeforeLaunchAbandoned',
         'RestartClaimedUnresolved'
     )
    WHERE terminal.effect_id = NEW.effect_id
      AND terminal.observation_id = NEW.observation_id
) AND NOT EXISTS (
    SELECT 1
    FROM command_output_capture_terminal_anchors terminal
    JOIN command_output_capture_terminal_validations validation
      ON validation.terminal_anchor_digest = terminal.terminal_anchor_digest
     AND validation.capture_id = terminal.capture_id
     AND validation.effect_id = terminal.effect_id
     AND validation.observation_id = terminal.observation_id
     AND validation.validation_kind IN (
         'RestartIntentAbandoned', 'RestartClaimedBeforeLaunchAbandoned',
         'RestartClaimedUnresolved'
     )
    JOIN command_output_capture_intents intent
      ON intent.capture_id = terminal.capture_id
     AND intent.effect_id = terminal.effect_id
     AND intent.sprint_id = validation.sprint_id
     AND intent.contract_version = validation.contract_version
    JOIN command_output_capture_restart_recovery_receipts recovery
      ON recovery.receipt_digest = validation.restart_recovery_receipt_digest
     AND recovery.capture_id = intent.capture_id
     AND recovery.effect_id = intent.effect_id
     AND recovery.reconciliation_claim_id = validation.reconciliation_claim_id
     AND recovery.reconciliation_fencing_token =
         validation.reconciliation_fencing_token
     AND recovery.recovered_at_unix_ms = terminal.anchored_at_unix_ms
     AND recovery.contract_version = terminal.contract_version
    JOIN effect_evidence_payloads payload
      ON payload.effect_id = NEW.effect_id
     AND payload.observation_id = NEW.observation_id
     AND payload.sprint_id = NEW.sprint_id
     AND payload.evidence_digest = NEW.evidence_digest
     AND payload.evidence_bytes = recovery.receipt_json
     AND payload.contract_version = NEW.contract_version
    WHERE terminal.effect_id = NEW.effect_id
      AND terminal.observation_id = NEW.observation_id
      AND terminal.observation_class = NEW.outcome
      AND terminal.contract_version = NEW.contract_version
      AND validation.terminal_anchored_at_unix_ms = terminal.anchored_at_unix_ms
      AND validation.contract_version = NEW.contract_version
      AND validation.sprint_id = NEW.sprint_id
      AND NEW.evidence_digest = grok_sha256(recovery.receipt_json)
)
BEGIN SELECT RAISE(ABORT, 'restart capture observation requires exact physical receipt evidence'); END;

CREATE TRIGGER command_output_artifact_sets_require_v27_terminal
BEFORE INSERT ON command_output_artifact_sets
WHEN EXISTS (
    SELECT 1 FROM command_output_capture_intents WHERE effect_id = NEW.effect_id
) AND NOT EXISTS (
    SELECT 1 FROM command_output_capture_terminal_anchors terminal
    WHERE terminal.effect_id = NEW.effect_id
      AND terminal.observation_id = NEW.observation_id
      AND terminal.disposition = 'Published'
      AND terminal.artifact_manifest_digest = NEW.manifest_digest
      AND terminal.artifact_reference_json = NEW.reference_json
)
BEGIN SELECT RAISE(ABORT, 'v27 output artifacts require exact terminal publication anchor'); END;

CREATE TRIGGER command_output_capture_obligation_closure_exact_terminal
BEFORE INSERT ON command_output_capture_reconciliation_obligation_closures
WHEN NOT EXISTS (
    SELECT 1
    FROM command_output_capture_reconciliation_obligations obligation
    JOIN command_output_capture_terminal_anchors terminal
      ON terminal.capture_id = obligation.capture_id
     AND terminal.effect_id = obligation.effect_id
    WHERE obligation.obligation_id = NEW.obligation_id
      AND obligation.capture_id = NEW.capture_id
      AND obligation.effect_id = NEW.effect_id
      AND terminal.terminal_anchor_digest = NEW.terminal_anchor_digest
      AND (
          (terminal.disposition IN ('Published', 'Abandoned')
           AND terminal.anchored_at_unix_ms = NEW.closed_at_unix_ms)
          OR (terminal.observation_class = 'Unknown'
              AND terminal.disposition = 'ReconciliationRequired'
              AND EXISTS (
                  SELECT 1
                  FROM command_output_capture_reconciliation_resolutions resolution
                  JOIN command_output_capture_reconciliation_claims claim
                    ON claim.claim_id = resolution.reconciliation_claim_id
                   AND claim.capture_id = resolution.capture_id
                   AND claim.fencing_token = resolution.reconciliation_fencing_token
                  JOIN command_output_capture_reconciliation_claim_releases release
                    ON release.claim_id = claim.claim_id
                   AND release.capture_id = claim.capture_id
                   AND release.claim_epoch = claim.claim_epoch
                   AND release.fencing_token = claim.fencing_token
                   AND release.contract_version = claim.contract_version
                   AND release.release_kind = 'ConsumedTerminal'
                   AND release.terminal_anchor_digest = terminal.terminal_anchor_digest
                   AND release.released_at_unix_ms = resolution.resolved_at_unix_ms
                  WHERE resolution.capture_id = terminal.capture_id
                    AND resolution.effect_id = terminal.effect_id
                    AND resolution.observation_id = terminal.observation_id
                    AND resolution.terminal_anchor_digest = terminal.terminal_anchor_digest
                    AND resolution.resolved_at_unix_ms = NEW.closed_at_unix_ms
                    AND resolution.contract_version = NEW.contract_version
                    AND claim.claim_epoch = (
                        SELECT MAX(latest.claim_epoch)
                        FROM command_output_capture_reconciliation_claims latest
                        WHERE latest.capture_id = claim.capture_id
                    )
              ))
      )
      AND terminal.contract_version = NEW.contract_version
) OR EXISTS (
    SELECT 1
    FROM command_output_capture_reconciliation_claims claim
    LEFT JOIN command_output_capture_reconciliation_claim_releases release
      ON release.claim_id = claim.claim_id
     AND release.capture_id = claim.capture_id
     AND release.claim_epoch = claim.claim_epoch
     AND release.fencing_token = claim.fencing_token
     AND release.contract_version = claim.contract_version
    WHERE claim.capture_id = NEW.capture_id AND release.claim_id IS NULL
)
BEGIN SELECT RAISE(ABORT, 'capture obligation closes only with exact terminal/resolution and no active claim'); END;

CREATE TRIGGER command_output_capture_terminal_no_update
BEFORE UPDATE ON command_output_capture_terminal_anchors
BEGIN SELECT RAISE(ABORT, 'command output capture terminal anchors are immutable'); END;
CREATE TRIGGER command_output_capture_terminal_no_delete
BEFORE DELETE ON command_output_capture_terminal_anchors
BEGIN SELECT RAISE(ABORT, 'command output capture terminal anchors are immutable'); END;
CREATE TRIGGER command_output_capture_obligation_closures_no_update
BEFORE UPDATE ON command_output_capture_reconciliation_obligation_closures
BEGIN SELECT RAISE(ABORT, 'command output capture obligation closures are immutable'); END;
CREATE TRIGGER command_output_capture_obligation_closures_no_delete
BEFORE DELETE ON command_output_capture_reconciliation_obligation_closures
BEGIN SELECT RAISE(ABORT, 'command output capture obligation closures are immutable'); END;

-- Reusable completion/readback authority for a durable core acquisition.  The
-- acquired digest authenticates the JSON object, but the redundant columns are
-- independently queryable selectors and therefore must be rebound both to the
-- canonical bytes and to the current immutable intent/dispatch rows.
CREATE VIEW command_output_capture_exact_runner_sources_v27 AS
SELECT capture.capture_id,
       effect.effect_id,
       effect.sprint_id,
       binding.launch_id,
       binding.session_id,
       effect.request_digest,
       effect.policy_hash,
       effect.input_snapshot,
       effect.task_id,
       effect.worker_id,
       effect.worker_lease_id,
       effect.worker_lease_epoch,
       session.purpose,
       effect.created_at_unix_ms,
       effect.contract_version
FROM command_output_capture_intents capture
JOIN effect_intents effect
  ON effect.effect_id = capture.effect_id
 AND effect.sprint_id = capture.sprint_id
 AND effect.effect_kind = 'RunCommand'
 AND effect.request_digest = capture.request_digest
 AND effect.created_at_unix_ms = capture.created_at_unix_ms
 AND effect.contract_version = capture.contract_version
JOIN effect_request_payloads request
  ON request.effect_id = effect.effect_id
 AND request.sprint_id = effect.sprint_id
 AND request.request_digest = effect.request_digest
 AND request.contract_version = effect.contract_version
JOIN agent_events proposal
  ON proposal.event_id = effect.proposed_event_id
 AND proposal.sprint_id = effect.sprint_id
 AND proposal.contract_version = effect.contract_version
 AND proposal.occurred_at_unix_ms = effect.created_at_unix_ms
JOIN effect_session_bindings binding
  ON binding.effect_id = effect.effect_id
 AND binding.sprint_id = effect.sprint_id
 AND binding.launch_id = capture.runner_launch_id
 AND binding.session_id = capture.runner_session_id
 AND binding.contract_version = effect.contract_version
JOIN runner_launch_intents launch
  ON launch.sprint_id = binding.sprint_id
 AND launch.launch_id = binding.launch_id
JOIN runner_session_policies session
  ON session.sprint_id = binding.sprint_id
 AND session.session_id = binding.session_id
 AND session.launch_id = launch.launch_id
JOIN workspace_snapshots snapshot
  ON snapshot.sprint_id = effect.sprint_id
 AND snapshot.snapshot_id = effect.input_snapshot
JOIN sprints sprint ON sprint.sprint_id = effect.sprint_id
WHERE grok_sprint_spec_v27_canonical(sprint.spec_json) = 1
  AND json_extract(CAST(sprint.spec_json AS TEXT), '$.sprint_id') = sprint.sprint_id
  AND sprint.contract_version = effect.contract_version
  AND sprint.created_at_unix_ms <= launch.created_at_unix_ms
  AND grok_effect_intent_v27_canonical(effect.intent_json) = 1
  AND grok_effect_proposal_v27_canonical(
        effect.intent_json, proposal.event_json
      ) = 1
  AND grok_runner_launch_v27_canonical(
        launch.intent_json, launch.execution_policy_json
      ) = 1
  AND grok_runner_session_v27_canonical(
        session.record_json, session.execution_policy_json
      ) = 1
  AND grok_agent_event_v27_canonical(proposal.event_json) = 1
  AND grok_sha256(request.request_bytes) = effect.request_digest
  AND launch.execution_policy_json = session.execution_policy_json
  AND json_extract(CAST(effect.intent_json AS TEXT), '$.contract_version') =
      effect.contract_version
  AND json_extract(CAST(effect.intent_json AS TEXT), '$.effect_id') = effect.effect_id
  AND json_extract(CAST(effect.intent_json AS TEXT), '$.idempotency_key') =
      effect.idempotency_key
  AND json_extract(CAST(effect.intent_json AS TEXT), '$.sprint_id') = effect.sprint_id
  AND json_extract(CAST(effect.intent_json AS TEXT), '$.task_id') IS effect.task_id
  AND json_extract(CAST(effect.intent_json AS TEXT), '$.worker_id') IS effect.worker_id
  AND json_extract(
        CAST(effect.intent_json AS TEXT), '$.worker_lease.lease_id'
      ) IS effect.worker_lease_id
  AND json_extract(
        CAST(effect.intent_json AS TEXT), '$.worker_lease.lease_epoch'
      ) IS effect.worker_lease_epoch
  AND json_extract(CAST(effect.intent_json AS TEXT), '$.causation_event_id') IS
      effect.causation_event_id
  AND json_extract(CAST(effect.intent_json AS TEXT), '$.correlation_id') =
      effect.correlation_id
  AND json_extract(CAST(effect.intent_json AS TEXT), '$.kind') = 'RunCommand'
  AND json_extract(CAST(effect.intent_json AS TEXT), '$.request_digest') =
      effect.request_digest
  AND json_extract(CAST(effect.intent_json AS TEXT), '$.policy_hash') = effect.policy_hash
  AND json_extract(CAST(effect.intent_json AS TEXT), '$.input_snapshot') =
      effect.input_snapshot
  AND json_extract(CAST(effect.intent_json AS TEXT), '$.created_at_unix_ms') =
      effect.created_at_unix_ms
  AND json_extract(CAST(proposal.event_json AS TEXT), '$.contract_version') =
      proposal.contract_version
  AND json_extract(CAST(proposal.event_json AS TEXT), '$.sequence') = proposal.sequence
  AND json_extract(CAST(proposal.event_json AS TEXT), '$.event_id') = proposal.event_id
  AND json_extract(CAST(proposal.event_json AS TEXT), '$.sprint_id') = proposal.sprint_id
  AND json_extract(CAST(proposal.event_json AS TEXT), '$.occurred_at_unix_ms') =
      proposal.occurred_at_unix_ms
  AND (
      effect.causation_event_id IS NULL
      OR EXISTS (
          SELECT 1 FROM agent_events cause
          WHERE cause.event_id = effect.causation_event_id
            AND cause.sprint_id = effect.sprint_id
            AND cause.sequence < proposal.sequence
      )
  )
  AND json_extract(CAST(launch.intent_json AS TEXT), '$.contract_version') =
      launch.contract_version
  AND json_extract(CAST(launch.intent_json AS TEXT), '$.launch_id') = launch.launch_id
  AND json_extract(CAST(launch.intent_json AS TEXT), '$.sprint_id') = launch.sprint_id
  AND json_extract(CAST(launch.intent_json AS TEXT), '$.session_id') = launch.session_id
  AND json_extract(CAST(launch.intent_json AS TEXT), '$.purpose') = launch.purpose
  AND json_extract(CAST(launch.intent_json AS TEXT), '$.worker_id') IS launch.worker_id
  AND json_extract(
        CAST(launch.intent_json AS TEXT), '$.worker_lease.lease_id'
      ) IS launch.worker_lease_id
  AND json_extract(
        CAST(launch.intent_json AS TEXT), '$.worker_lease.lease_epoch'
      ) IS launch.worker_lease_epoch
  AND json_extract(CAST(launch.intent_json AS TEXT), '$.policy_hash') = launch.policy_hash
  AND json_extract(CAST(launch.intent_json AS TEXT), '$.runner_binary_digest') =
      launch.runner_binary_digest
  AND json_extract(CAST(launch.intent_json AS TEXT), '$.protocol_digest') =
      launch.protocol_digest
  AND json_extract(CAST(launch.intent_json AS TEXT), '$.private_state_digest') =
      launch.private_state_digest
  AND json_extract(CAST(launch.intent_json AS TEXT), '$.grant_hash') = launch.grant_hash
  AND json_extract(CAST(launch.intent_json AS TEXT), '$.policy_version') =
      launch.policy_version
  AND json_extract(CAST(launch.intent_json AS TEXT), '$.created_at_unix_ms') =
      launch.created_at_unix_ms
  AND json_extract(CAST(session.record_json AS TEXT), '$.contract_version') =
      session.contract_version
  AND json_extract(CAST(session.record_json AS TEXT), '$.sprint_id') = session.sprint_id
  AND json_extract(CAST(session.record_json AS TEXT), '$.launch_id') = session.launch_id
  AND json_extract(CAST(session.record_json AS TEXT), '$.session_id') = session.session_id
  AND json_extract(CAST(session.record_json AS TEXT), '$.purpose') = session.purpose
  AND json_extract(CAST(session.record_json AS TEXT), '$.worker_id') IS session.worker_id
  AND json_extract(
        CAST(session.record_json AS TEXT), '$.worker_lease.lease_id'
      ) IS session.worker_lease_id
  AND json_extract(
        CAST(session.record_json AS TEXT), '$.worker_lease.lease_epoch'
      ) IS session.worker_lease_epoch
  AND json_extract(CAST(session.record_json AS TEXT), '$.policy_hash') = session.policy_hash
  AND json_extract(CAST(session.record_json AS TEXT), '$.session_nonce') =
      session.session_nonce
  AND json_extract(CAST(session.record_json AS TEXT), '$.runner_binary_digest') =
      session.runner_binary_digest
  AND json_extract(CAST(session.record_json AS TEXT), '$.protocol_digest') =
      session.protocol_digest
  AND json_extract(CAST(session.record_json AS TEXT), '$.private_state_digest') =
      session.private_state_digest
  AND json_extract(CAST(session.record_json AS TEXT), '$.grant_hash') = session.grant_hash
  AND json_extract(CAST(session.record_json AS TEXT), '$.policy_version') =
      session.policy_version
  AND json_extract(CAST(session.record_json AS TEXT), '$.registered_at_unix_ms') =
      session.registered_at_unix_ms
  AND launch.session_id = session.session_id
  AND launch.purpose = session.purpose
  AND launch.worker_id IS session.worker_id
  AND launch.worker_lease_id IS session.worker_lease_id
  AND launch.worker_lease_epoch IS session.worker_lease_epoch
  AND launch.policy_hash = session.policy_hash
  AND launch.runner_binary_digest = session.runner_binary_digest
  AND launch.protocol_digest = session.protocol_digest
  AND launch.private_state_digest = session.private_state_digest
  AND launch.grant_hash = session.grant_hash
  AND launch.policy_version = session.policy_version
  AND launch.contract_version = session.contract_version
  AND effect.policy_hash = launch.policy_hash
  AND capture.private_state_digest = launch.private_state_digest
  AND session.registered_at_unix_ms >= launch.created_at_unix_ms
  AND session.registered_at_unix_ms <= effect.created_at_unix_ms
  AND snapshot.created_at_unix_ms <= effect.created_at_unix_ms
  AND json_extract(
        CAST(sprint.spec_json AS TEXT), '$.workspace_grant.grant_hash'
      ) = launch.grant_hash
  AND json_extract(
        CAST(sprint.spec_json AS TEXT), '$.workspace_grant.policy_version'
      ) = launch.policy_version
  AND json_extract(
        CAST(sprint.spec_json AS TEXT), '$.workspace_grant.canonical_root'
      ) = json_extract(
        CAST(launch.execution_policy_json AS TEXT), '$.workspace_root'
      )
  AND json_extract(CAST(launch.execution_policy_json AS TEXT), '$.policy_hash') =
      launch.policy_hash
  AND json_extract(CAST(launch.execution_policy_json AS TEXT), '$.grant_hash') =
      launch.grant_hash
  AND NOT EXISTS (
      SELECT 1 FROM live_state_verifier_launch_purposes marker
      WHERE marker.launch_id = launch.launch_id
  )
  AND NOT EXISTS (
      SELECT 1 FROM live_state_verifier_session_purposes marker
      WHERE marker.session_id = session.session_id
  )
  AND (
      (session.purpose = 'TaskWorker'
       AND effect.task_id IS NOT NULL
       AND effect.worker_id = session.worker_id
       AND effect.worker_lease_id = launch.worker_lease_id
       AND effect.worker_lease_id = session.worker_lease_id
       AND effect.worker_lease_epoch = launch.worker_lease_epoch
       AND effect.worker_lease_epoch = session.worker_lease_epoch
       AND EXISTS (
           SELECT 1
           FROM task_attempt_running_boundaries running
           JOIN task_attempts attempt ON attempt.attempt_id = running.attempt_id
           WHERE running.sprint_id = effect.sprint_id
             AND running.task_id = effect.task_id
             AND running.worker_id = effect.worker_id
             AND running.runner_launch_id = launch.launch_id
             AND running.runner_session_id = session.session_id
             AND running.worker_lease_id = effect.worker_lease_id
             AND running.lease_epoch = effect.worker_lease_epoch
             AND running.contract_version = effect.contract_version
             AND attempt.sprint_id = effect.sprint_id
             AND attempt.task_id = effect.task_id
             AND attempt.worker_id = effect.worker_id
             AND attempt.worker_lease_id = effect.worker_lease_id
             AND attempt.lease_epoch = effect.worker_lease_epoch
             AND attempt.schema_generation = 15
             AND attempt.contract_version = effect.contract_version
             AND grok_task_running_authority_v27_canonical(
                   attempt.attempt_json, running.boundary_json
                 ) = 1
       ))
      OR
      (session.purpose = 'FinalVerifier'
       AND effect.task_id IS NULL
       AND effect.worker_id IS NULL
       AND effect.worker_lease_id IS NULL
       AND effect.worker_lease_epoch IS NULL
       AND launch.worker_id IS NULL
       AND launch.worker_lease_id IS NULL
       AND launch.worker_lease_epoch IS NULL
       AND session.worker_id IS NULL
       AND session.worker_lease_id IS NULL
       AND session.worker_lease_epoch IS NULL
       AND EXISTS (
           SELECT 1
           FROM sprint_final_verification_admissions admission
           JOIN agent_events phase
             ON phase.event_id = admission.sprint_phase_event_id
            AND phase.sprint_id = admission.sprint_id
           WHERE admission.effect_id = effect.effect_id
             AND admission.sprint_id = effect.sprint_id
             AND admission.runner_launch_id = launch.launch_id
             AND admission.runner_session_id = session.session_id
             AND admission.final_snapshot = effect.input_snapshot
             AND admission.contract_version = effect.contract_version
             AND admission.admitted_at_unix_ms = effect.created_at_unix_ms
             AND admission.command_digest = effect.request_digest
             AND admission.command_digest = grok_sha256(admission.command_bytes)
             AND grok_final_verification_admission_v27_canonical(
                   admission.admission_json, admission.command_bytes
                 ) = 1
             AND json_extract(
                   CAST(admission.admission_json AS TEXT), '$.contract_version'
                 ) = admission.contract_version
             AND json_extract(
                   CAST(admission.admission_json AS TEXT), '$.admission_id'
                 ) = admission.admission_id
             AND json_extract(
                   CAST(admission.admission_json AS TEXT), '$.sprint_id'
                 ) = admission.sprint_id
             AND json_extract(
                   CAST(admission.admission_json AS TEXT),
                   '$.sprint_phase_event_id'
                 ) = admission.sprint_phase_event_id
             AND json_extract(
                   CAST(admission.admission_json AS TEXT), '$.final_snapshot'
                 ) = admission.final_snapshot
             AND json_extract(
                   CAST(admission.admission_json AS TEXT), '$.effect_id'
                 ) = admission.effect_id
             AND json_extract(
                   CAST(admission.admission_json AS TEXT), '$.runner_launch_id'
                 ) = admission.runner_launch_id
             AND json_extract(
                   CAST(admission.admission_json AS TEXT), '$.runner_session_id'
                 ) = admission.runner_session_id
             AND json_extract(
                   CAST(admission.admission_json AS TEXT), '$.admitted_at_unix_ms'
                 ) = admission.admitted_at_unix_ms
             AND grok_agent_event_v27_canonical(phase.event_json) = 1
             AND json_extract(CAST(phase.event_json AS TEXT), '$.event_id') =
                 phase.event_id
             AND json_extract(CAST(phase.event_json AS TEXT), '$.sequence') =
                 phase.sequence
             AND json_extract(CAST(phase.event_json AS TEXT), '$.sprint_id') =
                 phase.sprint_id
             AND json_extract(CAST(phase.event_json AS TEXT), '$.task_id') IS NULL
             AND json_extract(CAST(phase.event_json AS TEXT), '$.worker_id') IS NULL
             AND json_extract(CAST(phase.event_json AS TEXT), '$.policy_hash') =
                 effect.policy_hash
             AND json_extract(
                   CAST(phase.event_json AS TEXT),
                   '$.payload.SprintStateChanged.from'
                 ) = 'Running'
             AND json_extract(
                   CAST(phase.event_json AS TEXT),
                   '$.payload.SprintStateChanged.to'
                 ) = 'FinalVerification'
             AND phase.contract_version = admission.contract_version
             AND phase.occurred_at_unix_ms <= admission.admitted_at_unix_ms
             AND phase.sequence < proposal.sequence
       ))
  );

CREATE VIEW command_output_capture_exact_dispatch_authorities_v27 AS
SELECT source.capture_id, claim.dispatch_claim_id
FROM command_output_capture_exact_runner_sources_v27 source
JOIN runner_effect_dispatch_claims claim
  ON claim.effect_id = source.effect_id
 AND claim.sprint_id = source.sprint_id
 AND claim.launch_id = source.launch_id
 AND claim.session_id = source.session_id
 AND claim.request_digest = source.request_digest
 AND claim.policy_hash = source.policy_hash
 AND claim.input_snapshot = source.input_snapshot
 AND claim.contract_version = source.contract_version
JOIN runner_effect_dispatch_claim_authorities authority
  ON authority.dispatch_claim_id = claim.dispatch_claim_id
 AND authority.contract_version = claim.contract_version
WHERE NOT EXISTS (
    SELECT 1 FROM live_state_capture_dispatch_claim_authorities live
    WHERE live.dispatch_claim_id = claim.dispatch_claim_id
)
AND (
    (authority.authority_class = 'TaskRunning'
     AND source.purpose = 'TaskWorker'
     AND claim.running_boundary_id = authority.running_boundary_id
     AND authority.running_boundary_id IS NOT NULL
     AND authority.formal_check_admission_id IS NULL
     AND authority.integration_admission_id IS NULL
     AND authority.sprint_phase_event_id IS NULL
     AND authority.rollback_reference_id IS NULL
     AND EXISTS (
         SELECT 1
         FROM task_attempt_running_boundaries running
         JOIN task_attempts attempt ON attempt.attempt_id = running.attempt_id
         WHERE running.boundary_id = claim.running_boundary_id
           AND running.sprint_id = source.sprint_id
           AND running.runner_launch_id = source.launch_id
           AND running.runner_session_id = source.session_id
           AND running.task_id = source.task_id
           AND running.worker_id = source.worker_id
           AND running.worker_lease_id = source.worker_lease_id
           AND running.lease_epoch = source.worker_lease_epoch
           AND running.contract_version = source.contract_version
           AND attempt.sprint_id = source.sprint_id
           AND attempt.task_id = source.task_id
           AND attempt.worker_id = source.worker_id
           AND attempt.worker_lease_id = source.worker_lease_id
           AND attempt.lease_epoch = source.worker_lease_epoch
           AND attempt.schema_generation = 15
           AND attempt.contract_version = source.contract_version
           AND grok_task_running_authority_v27_canonical(
                 attempt.attempt_json, running.boundary_json
               ) = 1
     ))
    OR
    (authority.authority_class = 'TaskFormalCheck'
     AND source.purpose = 'TaskWorker'
     AND claim.running_boundary_id IS NULL
     AND authority.running_boundary_id IS NULL
     AND authority.formal_check_admission_id IS NOT NULL
     AND authority.integration_admission_id IS NULL
     AND authority.sprint_phase_event_id IS NULL
     AND authority.rollback_reference_id IS NULL
     AND EXISTS (
         SELECT 1
         FROM task_attempt_formal_check_admissions admission
         JOIN task_attempts attempt ON attempt.attempt_id = admission.attempt_id
         WHERE admission.admission_id = authority.formal_check_admission_id
           AND admission.effect_id = source.effect_id
           AND admission.sprint_id = source.sprint_id
           AND admission.task_id = source.task_id
           AND admission.worker_session_id = source.session_id
           AND admission.sealed_snapshot_id = source.input_snapshot
           AND admission.contract_version = source.contract_version
           AND admission.admitted_at_unix_ms = source.created_at_unix_ms
           AND attempt.sprint_id = source.sprint_id
           AND attempt.task_id = source.task_id
           AND attempt.worker_id = source.worker_id
           AND attempt.worker_lease_id = source.worker_lease_id
           AND attempt.lease_epoch = source.worker_lease_epoch
           AND attempt.schema_generation = 15
           AND attempt.contract_version = source.contract_version
           AND grok_formal_check_admission_v27_canonical(
                 admission.admission_json, admission.command_spec_json
               ) = 1
           AND json_extract(
                 CAST(admission.admission_json AS TEXT), '$.contract_version'
               ) = admission.contract_version
           AND json_extract(
                 CAST(admission.admission_json AS TEXT), '$.admission_id'
               ) = admission.admission_id
           AND json_extract(
                 CAST(admission.admission_json AS TEXT), '$.attempt.attempt_id'
               ) = admission.attempt_id
           AND json_extract(
                 CAST(admission.admission_json AS TEXT),
                 '$.attempt.worker_lease.sprint_id'
               ) = admission.sprint_id
           AND json_extract(
                 CAST(admission.admission_json AS TEXT),
                 '$.attempt.worker_lease.task_id'
               ) = admission.task_id
           AND json_extract(
                 CAST(admission.admission_json AS TEXT), '$.criterion_id'
               ) = admission.criterion_id
           AND json_extract(
                 CAST(admission.admission_json AS TEXT), '$.criterion_ordinal'
               ) = admission.criterion_ordinal
           AND json_extract(
                 CAST(admission.admission_json AS TEXT), '$.effect_id'
               ) = admission.effect_id
           AND json_extract(
                 CAST(admission.admission_json AS TEXT), '$.runner_session_id'
               ) = admission.worker_session_id
           AND json_extract(
                 CAST(admission.admission_json AS TEXT), '$.sealed_snapshot'
               ) = admission.sealed_snapshot_id
           AND json_extract(
                 CAST(admission.admission_json AS TEXT), '$.admitted_at_unix_ms'
               ) = admission.admitted_at_unix_ms
           AND grok_sha256(admission.command_spec_json) = source.request_digest
     ))
    OR
    (authority.authority_class = 'SprintFinalVerification'
     AND source.purpose = 'FinalVerifier'
     AND claim.running_boundary_id IS NULL
     AND authority.running_boundary_id IS NULL
     AND authority.formal_check_admission_id IS NULL
     AND authority.integration_admission_id IS NULL
     AND authority.sprint_phase_event_id IS NOT NULL
     AND authority.rollback_reference_id IS NULL
     AND EXISTS (
         SELECT 1
         FROM sprint_final_verification_admissions admission
         JOIN agent_events phase
           ON phase.event_id = admission.sprint_phase_event_id
          AND phase.sprint_id = admission.sprint_id
         JOIN workspace_snapshots snapshot
           ON snapshot.sprint_id = admission.sprint_id
          AND snapshot.snapshot_id = admission.final_snapshot
         WHERE admission.sprint_phase_event_id = authority.sprint_phase_event_id
           AND admission.effect_id = source.effect_id
           AND admission.sprint_id = source.sprint_id
           AND admission.runner_launch_id = source.launch_id
           AND admission.runner_session_id = source.session_id
           AND admission.final_snapshot = source.input_snapshot
           AND admission.contract_version = source.contract_version
           AND admission.admitted_at_unix_ms = source.created_at_unix_ms
           AND admission.command_digest = source.request_digest
           AND admission.command_digest = grok_sha256(admission.command_bytes)
           AND grok_final_verification_admission_v27_canonical(
                 admission.admission_json, admission.command_bytes
               ) = 1
           AND json_extract(
                 CAST(admission.admission_json AS TEXT), '$.contract_version'
               ) = admission.contract_version
           AND json_extract(
                 CAST(admission.admission_json AS TEXT), '$.admission_id'
               ) = admission.admission_id
           AND json_extract(
                 CAST(admission.admission_json AS TEXT), '$.sprint_id'
               ) = admission.sprint_id
           AND json_extract(
                 CAST(admission.admission_json AS TEXT),
                 '$.sprint_phase_event_id'
               ) = admission.sprint_phase_event_id
           AND json_extract(
                 CAST(admission.admission_json AS TEXT), '$.final_snapshot'
               ) = admission.final_snapshot
           AND json_extract(
                 CAST(admission.admission_json AS TEXT), '$.effect_id'
               ) = admission.effect_id
           AND json_extract(
                 CAST(admission.admission_json AS TEXT), '$.runner_launch_id'
               ) = admission.runner_launch_id
           AND json_extract(
                 CAST(admission.admission_json AS TEXT), '$.runner_session_id'
               ) = admission.runner_session_id
           AND json_extract(
                 CAST(admission.admission_json AS TEXT), '$.admitted_at_unix_ms'
               ) = admission.admitted_at_unix_ms
           AND grok_agent_event_v27_canonical(phase.event_json) = 1
           AND json_extract(CAST(phase.event_json AS TEXT), '$.event_id') =
               phase.event_id
           AND json_extract(CAST(phase.event_json AS TEXT), '$.sequence') =
               phase.sequence
           AND json_extract(CAST(phase.event_json AS TEXT), '$.sprint_id') =
               phase.sprint_id
           AND json_extract(CAST(phase.event_json AS TEXT), '$.task_id') IS NULL
           AND json_extract(CAST(phase.event_json AS TEXT), '$.worker_id') IS NULL
           AND json_extract(CAST(phase.event_json AS TEXT), '$.policy_hash') =
               source.policy_hash
           AND json_extract(
                 CAST(phase.event_json AS TEXT),
                 '$.payload.SprintStateChanged.from'
               ) = 'Running'
           AND json_extract(
                 CAST(phase.event_json AS TEXT),
                 '$.payload.SprintStateChanged.to'
               ) = 'FinalVerification'
           AND phase.contract_version = admission.contract_version
           AND phase.occurred_at_unix_ms <= admission.admitted_at_unix_ms
           AND snapshot.created_at_unix_ms <= admission.admitted_at_unix_ms
     ))
);

CREATE VIEW command_output_capture_exact_acquisitions_v27 AS
SELECT acquired.acquired_anchor_digest
FROM command_output_capture_acquisitions acquired
JOIN command_output_capture_intents intent
  ON intent.capture_id = acquired.capture_id
 AND intent.effect_id = acquired.effect_id
 AND intent.sprint_id = acquired.sprint_id
 AND intent.runner_launch_id = acquired.runner_launch_id
 AND intent.runner_session_id = acquired.runner_session_id
 AND intent.request_digest = acquired.request_digest
 AND intent.private_state_digest = acquired.private_state_digest
 AND intent.max_aggregate_output_bytes = acquired.max_aggregate_output_bytes
 AND intent.intent_digest = acquired.intent_digest
 AND intent.layout_version = acquired.layout_version
 AND intent.contract_version = acquired.contract_version
JOIN command_output_capture_exact_dispatch_authorities_v27 dispatch
  ON dispatch.capture_id = acquired.capture_id
 AND dispatch.dispatch_claim_id = acquired.dispatch_claim_id
WHERE acquired.acquired_at_unix_ms >= intent.created_at_unix_ms
  AND acquired.acquired_anchor_digest =
      grok_command_output_capture_acquired_digest(acquired.acquired_json)
  AND json_extract(
        CAST(acquired.acquired_json AS TEXT), '$.capture_id'
      ) = acquired.capture_id
  AND json_extract(
        CAST(acquired.acquired_json AS TEXT), '$.source.effect_id'
      ) = acquired.effect_id
  AND json_extract(
        CAST(acquired.acquired_json AS TEXT), '$.source.sprint_id'
      ) = acquired.sprint_id
  AND json_extract(
        CAST(acquired.acquired_json AS TEXT), '$.source.runner_launch_id'
      ) = acquired.runner_launch_id
  AND json_extract(
        CAST(acquired.acquired_json AS TEXT), '$.source.runner_session_id'
      ) = acquired.runner_session_id
  AND json_extract(
        CAST(acquired.acquired_json AS TEXT), '$.source.request_digest'
      ) = acquired.request_digest
  AND json_extract(
        CAST(acquired.acquired_json AS TEXT), '$.private_state_digest'
      ) = acquired.private_state_digest
  AND json_extract(
        CAST(acquired.acquired_json AS TEXT), '$.max_aggregate_output_bytes'
      ) = acquired.max_aggregate_output_bytes
  AND json_extract(
        CAST(acquired.acquired_json AS TEXT), '$.intent_digest'
      ) = acquired.intent_digest
  AND json_extract(
        CAST(acquired.acquired_json AS TEXT), '$.dispatch_claim_id'
      ) = acquired.dispatch_claim_id
  AND json_extract(
        CAST(acquired.acquired_json AS TEXT), '$.store_head.generation'
      ) = acquired.store_head_generation
  AND json_extract(
        CAST(acquired.acquired_json AS TEXT), '$.store_head.record_digest'
      ) = acquired.store_head_digest
  AND json_extract(
        CAST(acquired.acquired_json AS TEXT), '$.working_directory.device_id'
      ) = acquired.working_device_id
  AND json_extract(
        CAST(acquired.acquired_json AS TEXT), '$.working_directory.inode'
      ) = acquired.working_inode
  AND json_extract(
        CAST(acquired.acquired_json AS TEXT), '$.working_directory.owner_uid'
      ) = acquired.working_owner_uid
  AND json_extract(
        CAST(acquired.acquired_json AS TEXT), '$.working_directory.mode'
      ) = acquired.working_mode
  AND json_extract(
        CAST(acquired.acquired_json AS TEXT), '$.working_directory.link_count'
      ) = acquired.working_link_count
  AND json_extract(
        CAST(acquired.acquired_json AS TEXT), '$.stdout.device_id'
      ) = acquired.stdout_device_id
  AND json_extract(
        CAST(acquired.acquired_json AS TEXT), '$.stdout.inode'
      ) = acquired.stdout_inode
  AND json_extract(
        CAST(acquired.acquired_json AS TEXT), '$.stdout.owner_uid'
      ) = acquired.stdout_owner_uid
  AND json_extract(
        CAST(acquired.acquired_json AS TEXT), '$.stdout.mode'
      ) = acquired.stdout_mode
  AND json_extract(
        CAST(acquired.acquired_json AS TEXT), '$.stdout.link_count'
      ) = acquired.stdout_link_count
  AND json_extract(
        CAST(acquired.acquired_json AS TEXT), '$.stdout.byte_length'
      ) = acquired.stdout_byte_length
  AND json_extract(
        CAST(acquired.acquired_json AS TEXT), '$.stderr.device_id'
      ) = acquired.stderr_device_id
  AND json_extract(
        CAST(acquired.acquired_json AS TEXT), '$.stderr.inode'
      ) = acquired.stderr_inode
  AND json_extract(
        CAST(acquired.acquired_json AS TEXT), '$.stderr.owner_uid'
      ) = acquired.stderr_owner_uid
  AND json_extract(
        CAST(acquired.acquired_json AS TEXT), '$.stderr.mode'
      ) = acquired.stderr_mode
  AND json_extract(
        CAST(acquired.acquired_json AS TEXT), '$.stderr.link_count'
      ) = acquired.stderr_link_count
  AND json_extract(
        CAST(acquired.acquired_json AS TEXT), '$.stderr.byte_length'
      ) = acquired.stderr_byte_length
  AND json_extract(
        CAST(acquired.acquired_json AS TEXT), '$.acquired_at_unix_ms'
      ) = acquired.acquired_at_unix_ms
  AND json_extract(
        CAST(acquired.acquired_json AS TEXT), '$.acquired_anchor_digest'
      ) = acquired.acquired_anchor_digest
  AND json_extract(
        CAST(acquired.acquired_json AS TEXT), '$.layout_version'
      ) = acquired.layout_version
  AND json_extract(
        CAST(acquired.acquired_json AS TEXT), '$.contract_version'
      ) = acquired.contract_version;

-- Every claim row is canonical and every non-initial epoch repeats the exact
-- predecessor-release edge that admitted it.  Completion applies this view to
-- every historical claim, not only the claim named by the terminal row.
CREATE VIEW command_output_capture_exact_reconciliation_claims_v27 AS
SELECT claim.claim_id
FROM command_output_capture_reconciliation_claims claim
JOIN command_output_capture_intents intent
  ON intent.capture_id = claim.capture_id
 AND intent.contract_version = claim.contract_version
WHERE claim.claim_digest =
      grok_command_output_capture_reconciliation_claim_digest(claim.claim_json)
  AND json_extract(CAST(claim.claim_json AS TEXT), '$.claim_id') = claim.claim_id
  AND json_extract(CAST(claim.claim_json AS TEXT), '$.capture_id') = claim.capture_id
  AND json_extract(CAST(claim.claim_json AS TEXT), '$.owner_id') = claim.owner_id
  AND json_extract(CAST(claim.claim_json AS TEXT), '$.claim_epoch') = claim.claim_epoch
  AND json_extract(CAST(claim.claim_json AS TEXT), '$.previous_claim_id')
      IS claim.previous_claim_id
  AND json_extract(CAST(claim.claim_json AS TEXT), '$.fencing_token') =
      claim.fencing_token
  AND json_extract(CAST(claim.claim_json AS TEXT), '$.acquired_at_unix_ms') =
      claim.acquired_at_unix_ms
  AND json_extract(CAST(claim.claim_json AS TEXT), '$.expires_at_unix_ms') =
      claim.expires_at_unix_ms
  AND json_extract(CAST(claim.claim_json AS TEXT), '$.claim_digest') =
      claim.claim_digest
  AND json_extract(CAST(claim.claim_json AS TEXT), '$.contract_version') =
      claim.contract_version
  AND (
      (claim.claim_epoch = 1 AND claim.previous_claim_id IS NULL)
      OR (claim.claim_epoch > 1 AND EXISTS (
          SELECT 1
          FROM command_output_capture_reconciliation_claims previous
          JOIN command_output_capture_reconciliation_claim_releases release
            ON release.claim_id = previous.claim_id
           AND release.capture_id = previous.capture_id
           AND release.claim_epoch = previous.claim_epoch
           AND release.fencing_token = previous.fencing_token
           AND release.contract_version = previous.contract_version
          WHERE previous.claim_id = claim.previous_claim_id
            AND previous.capture_id = claim.capture_id
            AND previous.claim_epoch = claim.claim_epoch - 1
            AND previous.contract_version = claim.contract_version
            AND (
                (release.release_kind = 'Released'
                 AND release.released_at_unix_ms <= claim.acquired_at_unix_ms)
                OR (release.release_kind = 'Expired'
                    AND release.released_at_unix_ms = claim.acquired_at_unix_ms
                    AND previous.expires_at_unix_ms <= claim.acquired_at_unix_ms)
                OR (release.release_kind = 'Superseded'
                    AND previous.owner_id = claim.owner_id
                    AND release.released_at_unix_ms = claim.acquired_at_unix_ms
                    AND release.successor_claim_id = claim.claim_id
                    AND release.successor_fencing_token = claim.fencing_token
                    AND release.successor_claim_digest = claim.claim_digest)
                OR (release.release_kind = 'ConsumedTerminal'
                    AND release.released_at_unix_ms <= claim.acquired_at_unix_ms
                    AND EXISTS (
                        SELECT 1
                        FROM command_output_capture_terminal_anchors terminal
                        WHERE terminal.terminal_anchor_digest =
                                  release.terminal_anchor_digest
                          AND terminal.capture_id = claim.capture_id
                          AND terminal.observation_class = 'Unknown'
                          AND terminal.disposition = 'ReconciliationRequired'
                          AND terminal.anchored_at_unix_ms <=
                              release.released_at_unix_ms
                          AND terminal.contract_version = claim.contract_version
                    ))
            )
      ))
  );

CREATE VIEW command_output_capture_exact_restart_recovery_receipts_v27 AS
SELECT recovery.receipt_digest
FROM command_output_capture_restart_recovery_receipts recovery
JOIN command_output_capture_intents intent
  ON intent.capture_id = recovery.capture_id
 AND intent.effect_id = recovery.effect_id
 AND intent.intent_digest = recovery.intent_digest
 AND intent.layout_version = recovery.layout_version
 AND intent.contract_version = recovery.contract_version
JOIN command_output_capture_reconciliation_claims claim
  ON claim.claim_id = recovery.reconciliation_claim_id
 AND claim.capture_id = recovery.capture_id
 AND claim.fencing_token = recovery.reconciliation_fencing_token
 AND claim.claim_digest = recovery.recovery_fence_claim_digest
 AND claim.contract_version = recovery.contract_version
JOIN command_output_capture_exact_reconciliation_claims_v27 exact_claim
  ON exact_claim.claim_id = claim.claim_id
WHERE recovery.recovered_at_unix_ms >= claim.acquired_at_unix_ms
  AND recovery.recovered_at_unix_ms < claim.expires_at_unix_ms
  AND recovery.pending_record_present = 0
  AND recovery.receipt_digest =
      grok_command_output_capture_restart_recovery_receipt_digest(
          recovery.receipt_json
      )
  AND json_extract(
        CAST(recovery.receipt_json AS TEXT), '$.capture_id'
      ) = recovery.capture_id
  AND json_extract(
        CAST(recovery.receipt_json AS TEXT), '$.effect_id'
      ) = recovery.effect_id
  AND json_extract(
        CAST(recovery.receipt_json AS TEXT), '$.intent_digest'
      ) = recovery.intent_digest
  AND json_extract(
        CAST(recovery.receipt_json AS TEXT),
        '$.reconciliation_claim.claim_id'
      ) = recovery.reconciliation_claim_id
  AND json_extract(
        CAST(recovery.receipt_json AS TEXT),
        '$.reconciliation_claim.fencing_token'
      ) = recovery.reconciliation_fencing_token
  AND json_extract(
        CAST(recovery.receipt_json AS TEXT),
        '$.reconciliation_claim.claim_digest'
      ) = recovery.recovery_fence_claim_digest
  AND json_extract(
        CAST(recovery.receipt_json AS TEXT), '$.physical_fence_chain_length'
      ) = recovery.physical_fence_chain_length
  AND json_extract(
        CAST(recovery.receipt_json AS TEXT), '$.physical_fence_digest'
      ) = recovery.physical_fence_digest
  AND json_extract(
        CAST(recovery.receipt_json AS TEXT), '$.final_state'
      ) = CASE recovery.observed_state
            WHEN 'Intent' THEN 'intent'
            WHEN 'Acquired' THEN 'acquired'
            WHEN 'WriterAttached' THEN 'writer_attached'
            WHEN 'LaunchIntended' THEN 'launch_intended'
            WHEN 'Finished' THEN 'finished'
            WHEN 'Published' THEN 'published'
            WHEN 'TerminalPrepared' THEN 'terminal_prepared'
            WHEN 'CleanupIntended' THEN 'cleanup_intended'
            WHEN 'Cleaned' THEN 'cleaned'
          END
  AND json_extract(
        CAST(recovery.receipt_json AS TEXT), '$.resolution_action'
      ) = CASE recovery.resolution_action
            WHEN 'IntentTombstoned' THEN 'intent_tombstoned'
            WHEN 'PreAcquisitionCleaned' THEN 'pre_acquisition_cleaned'
            WHEN 'WorkingSetCleaned' THEN 'working_set_cleaned'
            WHEN 'FinishedPublicationRecovered' THEN
                'finished_publication_recovered'
            WHEN 'TerminalPreparedRecovered' THEN
                'terminal_prepared_recovered'
            WHEN 'TerminalReadback' THEN 'terminal_readback'
          END
  AND json_extract(
        CAST(recovery.receipt_json AS TEXT), '$.final_store_head.generation'
      ) = recovery.store_head_generation
  AND json_extract(
        CAST(recovery.receipt_json AS TEXT),
        '$.final_store_head.record_digest'
      ) = recovery.store_head_digest
  AND json_extract(
        CAST(recovery.receipt_json AS TEXT), '$.lifecycle_history_digest'
      ) = recovery.journal_history_digest
  AND json_extract(
        CAST(recovery.receipt_json AS TEXT),
        '$.physical_acquired.acquired_anchor_digest'
      ) IS recovery.acquired_anchor_digest
  AND (
      (recovery.acquired_anchor_digest IS NULL
       AND json_type(
             CAST(recovery.receipt_json AS TEXT), '$.physical_acquired'
           ) = 'null')
      OR (recovery.acquired_anchor_digest IS NOT NULL
          AND json_type(
                CAST(recovery.receipt_json AS TEXT), '$.physical_acquired'
              ) = 'object'
          AND json_extract(
                CAST(recovery.receipt_json AS TEXT),
                '$.physical_acquired.capture_id'
              ) = intent.capture_id
          AND json_extract(
                CAST(recovery.receipt_json AS TEXT),
                '$.physical_acquired.source.effect_id'
              ) = intent.effect_id
          AND json_extract(
                CAST(recovery.receipt_json AS TEXT),
                '$.physical_acquired.source.sprint_id'
              ) = intent.sprint_id
          AND json_extract(
                CAST(recovery.receipt_json AS TEXT),
                '$.physical_acquired.source.runner_launch_id'
              ) = intent.runner_launch_id
          AND json_extract(
                CAST(recovery.receipt_json AS TEXT),
                '$.physical_acquired.source.runner_session_id'
              ) = intent.runner_session_id
          AND json_extract(
                CAST(recovery.receipt_json AS TEXT),
                '$.physical_acquired.source.request_digest'
              ) = intent.request_digest
          AND json_extract(
                CAST(recovery.receipt_json AS TEXT),
                '$.physical_acquired.private_state_digest'
              ) = intent.private_state_digest
          AND json_extract(
                CAST(recovery.receipt_json AS TEXT),
                '$.physical_acquired.max_aggregate_output_bytes'
              ) = intent.max_aggregate_output_bytes
          AND json_extract(
                CAST(recovery.receipt_json AS TEXT),
                '$.physical_acquired.intent_digest'
              ) = intent.intent_digest
          AND json_extract(
                CAST(recovery.receipt_json AS TEXT),
                '$.physical_acquired.acquired_at_unix_ms'
              ) >= intent.created_at_unix_ms
          AND json_extract(
                CAST(recovery.receipt_json AS TEXT),
                '$.physical_acquired.layout_version'
              ) = intent.layout_version
          AND json_extract(
                CAST(recovery.receipt_json AS TEXT),
                '$.physical_acquired.contract_version'
              ) = intent.contract_version)
  )
  AND (
      (recovery.launch_schema IS NULL
       AND recovery.launch_canonical_bytes IS NULL
       AND recovery.launch_canonical_bytes_digest IS NULL
       AND recovery.launch_store_head_generation IS NULL
       AND recovery.launch_store_head_digest IS NULL
       AND json_extract(
             CAST(recovery.receipt_json AS TEXT),
             '$.launch_history.classification'
           ) = 'none_before_launch')
      OR (recovery.launch_schema IS NOT NULL
          AND recovery.launch_canonical_bytes IS NOT NULL
          AND recovery.launch_canonical_bytes_digest IS NOT NULL
          AND recovery.launch_store_head_generation IS NOT NULL
          AND recovery.launch_store_head_digest IS NOT NULL
          AND json_extract(
                CAST(recovery.receipt_json AS TEXT),
                '$.launch_history.classification'
              ) = 'exact_launch_evidence'
          AND json_extract(
                CAST(recovery.receipt_json AS TEXT),
                '$.launch_history.evidence.schema'
              ) = recovery.launch_schema
          AND json_extract(
                CAST(recovery.receipt_json AS TEXT),
                '$.launch_history.evidence.canonical_bytes_digest'
              ) = recovery.launch_canonical_bytes_digest
          AND grok_sha256(recovery.launch_canonical_bytes) =
              recovery.launch_canonical_bytes_digest
          AND json_extract(
                CAST(recovery.receipt_json AS TEXT),
                '$.launch_history.evidence.store_head.generation'
              ) = recovery.launch_store_head_generation
          AND json_extract(
                CAST(recovery.receipt_json AS TEXT),
                '$.launch_history.evidence.store_head.record_digest'
              ) = recovery.launch_store_head_digest)
  )
  AND json_extract(
        CAST(recovery.receipt_json AS TEXT),
        '$.cleaned_store_head.record_digest'
      ) IS recovery.cleaned_record_digest
  AND json_extract(
        CAST(recovery.receipt_json AS TEXT), '$.reconciliation_digest'
      ) = recovery.receipt_digest
  AND json_extract(
        CAST(recovery.receipt_json AS TEXT), '$.reconciled_at_unix_ms'
      ) = recovery.recovered_at_unix_ms;

-- Resolution JSON authenticates the semantic result; the cleanup receipts and
-- physical recovery receipt are deliberately external authority selectors.
-- This view rebinds both halves so completion cannot accept a CHECK/FK-valid
-- selector substitution after the original insert.
CREATE VIEW command_output_capture_exact_resolution_authorities_v27 AS
SELECT resolution.resolution_anchor_digest
FROM command_output_capture_reconciliation_resolutions resolution
JOIN command_output_capture_intents intent
  ON intent.capture_id = resolution.capture_id
 AND intent.effect_id = resolution.effect_id
 AND intent.layout_version = resolution.layout_version
 AND intent.contract_version = resolution.contract_version
JOIN effect_intents effect_intent
  ON effect_intent.effect_id = intent.effect_id
 AND effect_intent.sprint_id = intent.sprint_id
 AND effect_intent.request_digest = intent.request_digest
 AND effect_intent.contract_version = intent.contract_version
JOIN command_output_capture_terminal_anchors terminal
  ON terminal.capture_id = intent.capture_id
 AND terminal.effect_id = intent.effect_id
 AND terminal.observation_id = resolution.observation_id
 AND terminal.terminal_anchor_digest = resolution.terminal_anchor_digest
 AND terminal.observation_class = 'Unknown'
 AND terminal.disposition = 'ReconciliationRequired'
 AND terminal.contract_version = intent.contract_version
JOIN command_output_capture_acquisitions acquired
  ON acquired.acquired_anchor_digest = terminal.acquired_anchor_digest
 AND acquired.capture_id = intent.capture_id
 AND acquired.effect_id = intent.effect_id
 AND acquired.contract_version = intent.contract_version
JOIN command_output_capture_exact_acquisitions_v27 exact_acquired
  ON exact_acquired.acquired_anchor_digest = acquired.acquired_anchor_digest
JOIN command_output_capture_reconciliation_claims claim
  ON claim.claim_id = resolution.reconciliation_claim_id
 AND claim.capture_id = intent.capture_id
 AND claim.fencing_token = resolution.reconciliation_fencing_token
 AND claim.contract_version = intent.contract_version
JOIN command_output_capture_exact_reconciliation_claims_v27 exact_claim
  ON exact_claim.claim_id = claim.claim_id
JOIN command_output_capture_reconciliation_claim_releases release
  ON release.claim_id = claim.claim_id
 AND release.capture_id = claim.capture_id
 AND release.claim_epoch = claim.claim_epoch
 AND release.fencing_token = claim.fencing_token
 AND release.contract_version = claim.contract_version
 AND release.release_kind = 'ConsumedTerminal'
 AND release.terminal_anchor_digest = terminal.terminal_anchor_digest
 AND release.released_at_unix_ms = resolution.resolved_at_unix_ms
JOIN command_domain_cleanup_proofs command_cleanup
  ON command_cleanup.proof_id = resolution.command_domain_cleanup_proof_id
 AND command_cleanup.sprint_id = intent.sprint_id
 AND command_cleanup.launch_id = intent.runner_launch_id
 AND command_cleanup.session_id = intent.runner_session_id
 AND command_cleanup.effect_id = intent.effect_id
 AND command_cleanup.observation_id = terminal.observation_id
 AND command_cleanup.request_digest = intent.request_digest
 AND command_cleanup.disposition = 'ReapedZeroSurvivors'
 AND command_cleanup.surviving_processes = 0
 AND command_cleanup.contract_version = intent.contract_version
 AND command_cleanup.cleaned_at_unix_ms >= terminal.anchored_at_unix_ms
 AND command_cleanup.cleaned_at_unix_ms <= resolution.resolved_at_unix_ms
JOIN worker_cleanup_receipts runner_cleanup
  ON runner_cleanup.sprint_id = intent.sprint_id
 AND runner_cleanup.receipt_id = resolution.runner_cleanup_receipt_id
 AND runner_cleanup.launch_id = intent.runner_launch_id
 AND runner_cleanup.session_id = intent.runner_session_id
 AND runner_cleanup.worker_lease_id IS effect_intent.worker_lease_id
 AND runner_cleanup.worker_lease_epoch IS effect_intent.worker_lease_epoch
 AND runner_cleanup.surviving_processes = 0
 AND runner_cleanup.contract_version = intent.contract_version
 AND runner_cleanup.cleaned_at_unix_ms >= terminal.anchored_at_unix_ms
 AND runner_cleanup.cleaned_at_unix_ms <= resolution.resolved_at_unix_ms
JOIN command_output_capture_restart_recovery_receipts physical
  ON physical.receipt_digest = resolution.physical_recovery_receipt_digest
 AND physical.capture_id = intent.capture_id
 AND physical.effect_id = intent.effect_id
 AND physical.contract_version = intent.contract_version
JOIN command_output_capture_exact_restart_recovery_receipts_v27 exact_physical
  ON exact_physical.receipt_digest = physical.receipt_digest
WHERE resolution.resolved_at_unix_ms >= terminal.anchored_at_unix_ms
  AND resolution.resolved_at_unix_ms >= claim.acquired_at_unix_ms
  AND resolution.resolved_at_unix_ms < claim.expires_at_unix_ms
  AND claim.claim_epoch = (
      SELECT MAX(latest.claim_epoch)
      FROM command_output_capture_reconciliation_claims latest
      WHERE latest.capture_id = claim.capture_id
  )
  AND (
      (resolution.store_head_generation > terminal.store_head_generation
       AND physical.reconciliation_claim_id = claim.claim_id
       AND physical.reconciliation_fencing_token = claim.fencing_token
       AND physical.acquired_anchor_digest = terminal.acquired_anchor_digest
       AND physical.store_head_generation = resolution.store_head_generation
       AND physical.store_head_digest = resolution.store_head_digest
       AND resolution.resolution_record_digest = physical.store_head_digest
       AND physical.recovered_at_unix_ms = resolution.resolved_at_unix_ms
       AND json_extract(
             CAST(physical.receipt_json AS TEXT),
             '$.requested_store_head.generation'
           ) = terminal.store_head_generation
       AND json_extract(
             CAST(physical.receipt_json AS TEXT),
             '$.requested_store_head.record_digest'
           ) = terminal.store_head_digest
       AND json_extract(
             CAST(physical.receipt_json AS TEXT),
             '$.initial_store_head.generation'
           ) BETWEEN terminal.store_head_generation
                 AND physical.store_head_generation
       AND (
           (physical.observed_state = 'Cleaned'
            AND resolution.disposition = 'Abandoned'
            AND json_type(
                  CAST(physical.receipt_json AS TEXT), '$.artifact_reference'
                ) = 'null'
            AND json_type(
                  CAST(physical.receipt_json AS TEXT),
                  '$.cleanup_completion_proof_digest'
                ) = 'text')
           OR (physical.observed_state IN ('Published', 'TerminalPrepared')
               AND resolution.disposition = 'Published'
               AND resolution.artifact_manifest_digest = json_extract(
                     CAST(physical.receipt_json AS TEXT),
                     '$.artifact_reference.manifest_digest'
                   )
               AND CAST(resolution.artifact_reference_json AS TEXT) =
                   json_extract(
                       CAST(physical.receipt_json AS TEXT), '$.artifact_reference'
                   )
               AND json_extract(
                     CAST(physical.receipt_json AS TEXT),
                     '$.artifact_reference.source.sprint_id'
                   ) = intent.sprint_id
               AND json_extract(
                     CAST(physical.receipt_json AS TEXT),
                     '$.artifact_reference.source.runner_launch_id'
                   ) = intent.runner_launch_id
               AND json_extract(
                     CAST(physical.receipt_json AS TEXT),
                     '$.artifact_reference.source.runner_session_id'
                   ) = intent.runner_session_id
               AND json_extract(
                     CAST(physical.receipt_json AS TEXT),
                     '$.artifact_reference.source.effect_id'
                   ) = intent.effect_id
               AND json_extract(
                     CAST(physical.receipt_json AS TEXT),
                     '$.artifact_reference.source.request_digest'
                   ) = intent.request_digest)
       ))
      OR
      (resolution.store_head_generation = terminal.store_head_generation
       AND resolution.store_head_digest = terminal.store_head_digest
       AND resolution.resolution_record_digest = terminal.terminal_record_digest
       AND EXISTS (
           SELECT 1
           FROM command_output_capture_terminal_validations original_validation
           JOIN command_output_capture_restart_recovery_receipts original_recovery
             ON original_recovery.receipt_digest =
                original_validation.restart_recovery_receipt_digest
            AND original_recovery.receipt_digest = physical.receipt_digest
            AND original_recovery.capture_id = terminal.capture_id
            AND original_recovery.effect_id = terminal.effect_id
            AND original_recovery.store_head_generation =
                terminal.store_head_generation
            AND original_recovery.store_head_digest = terminal.store_head_digest
            AND original_recovery.receipt_digest = terminal.terminal_record_digest
           WHERE original_validation.terminal_anchor_digest =
                     terminal.terminal_anchor_digest
             AND original_validation.validation_kind =
                 'RestartClaimedUnresolved'
             AND ((original_recovery.observed_state = 'Cleaned'
                   AND resolution.disposition = 'Abandoned')
                  OR (original_recovery.observed_state IN (
                          'Published', 'TerminalPrepared'
                      )
                      AND resolution.disposition = 'Published'
                      AND resolution.artifact_manifest_digest = json_extract(
                            CAST(original_recovery.receipt_json AS TEXT),
                            '$.artifact_reference.manifest_digest'
                          )
                      AND CAST(resolution.artifact_reference_json AS TEXT) =
                          json_extract(
                              CAST(original_recovery.receipt_json AS TEXT),
                              '$.artifact_reference'
                          )
                      AND json_extract(
                            CAST(original_recovery.receipt_json AS TEXT),
                            '$.artifact_reference.source.sprint_id'
                          ) = intent.sprint_id
                      AND json_extract(
                            CAST(original_recovery.receipt_json AS TEXT),
                            '$.artifact_reference.source.runner_launch_id'
                          ) = intent.runner_launch_id
                      AND json_extract(
                            CAST(original_recovery.receipt_json AS TEXT),
                            '$.artifact_reference.source.runner_session_id'
                          ) = intent.runner_session_id
                      AND json_extract(
                            CAST(original_recovery.receipt_json AS TEXT),
                            '$.artifact_reference.source.effect_id'
                          ) = intent.effect_id
                      AND json_extract(
                            CAST(original_recovery.receipt_json AS TEXT),
                            '$.artifact_reference.source.request_digest'
                          ) = intent.request_digest))
       ))
  )
  AND json_extract(
        CAST(resolution.resolution_json AS TEXT), '$.capture_id'
      ) = resolution.capture_id
  AND json_extract(
        CAST(resolution.resolution_json AS TEXT), '$.effect_id'
      ) = resolution.effect_id
  AND json_extract(
        CAST(resolution.resolution_json AS TEXT), '$.observation_id'
      ) = resolution.observation_id
  AND json_extract(
        CAST(resolution.resolution_json AS TEXT), '$.terminal_anchor_digest'
      ) = resolution.terminal_anchor_digest
  AND json_extract(
        CAST(resolution.resolution_json AS TEXT), '$.reconciliation_claim_id'
      ) = resolution.reconciliation_claim_id
  AND json_extract(
        CAST(resolution.resolution_json AS TEXT),
        '$.reconciliation_fencing_token'
      ) = resolution.reconciliation_fencing_token
  AND json_extract(
        CAST(resolution.resolution_json AS TEXT), '$.resolution_anchor_digest'
      ) = resolution.resolution_anchor_digest
  AND json_extract(
        CAST(resolution.resolution_json AS TEXT), '$.disposition'
      ) = CASE resolution.disposition
            WHEN 'Published' THEN 'published'
            WHEN 'Abandoned' THEN 'abandoned'
          END
  AND json_extract(
        CAST(resolution.resolution_json AS TEXT), '$.store_head.generation'
      ) = resolution.store_head_generation
  AND json_extract(
        CAST(resolution.resolution_json AS TEXT), '$.store_head.record_digest'
      ) = resolution.store_head_digest
  AND json_extract(
        CAST(resolution.resolution_json AS TEXT), '$.resolution_record_digest'
      ) = resolution.resolution_record_digest
  AND json_extract(
        CAST(resolution.resolution_json AS TEXT),
        '$.artifact_reference.manifest_digest'
      ) IS resolution.artifact_manifest_digest
  AND (
      (resolution.artifact_reference_json IS NULL
       AND json_type(
             CAST(resolution.resolution_json AS TEXT), '$.artifact_reference'
           ) = 'null')
      OR (resolution.artifact_reference_json IS NOT NULL
          AND CAST(resolution.artifact_reference_json AS TEXT) = json_extract(
                CAST(resolution.resolution_json AS TEXT), '$.artifact_reference'
              ))
  )
  AND json_extract(
        CAST(resolution.resolution_json AS TEXT), '$.resolved_at_unix_ms'
      ) = resolution.resolved_at_unix_ms
  AND json_extract(
        CAST(resolution.resolution_json AS TEXT), '$.layout_version'
      ) = resolution.layout_version
  AND json_extract(
        CAST(resolution.resolution_json AS TEXT), '$.contract_version'
      ) = resolution.contract_version;

-- Completion re-evaluates terminal authority from the immutable source rows;
-- it does not trust that a validation row merely passed its insert trigger in
-- the past.  Keeping the closed branch union in one view makes validation-kind
-- shape, cleanup, recovery, and consumed-claim semantics reusable at the final
-- fence and fail closed under rollback-only corruption tests.
CREATE VIEW command_output_capture_exact_terminal_authorities_v27 AS
SELECT terminal.terminal_anchor_digest
FROM command_output_capture_terminal_anchors terminal
JOIN command_output_capture_intents intent
  ON intent.capture_id = terminal.capture_id
 AND intent.effect_id = terminal.effect_id
 AND intent.intent_digest = terminal.intent_digest
 AND intent.contract_version = terminal.contract_version
JOIN command_output_capture_exact_runner_sources_v27 exact_source
  ON exact_source.capture_id = intent.capture_id
JOIN command_output_capture_terminal_validations validation
  ON validation.terminal_anchor_digest = terminal.terminal_anchor_digest
 AND validation.capture_id = terminal.capture_id
 AND validation.effect_id = terminal.effect_id
 AND validation.observation_id = terminal.observation_id
 AND validation.terminal_anchored_at_unix_ms = terminal.anchored_at_unix_ms
 AND validation.sprint_id = intent.sprint_id
 AND validation.contract_version = terminal.contract_version
JOIN effect_observations observation
  ON observation.effect_id = terminal.effect_id
 AND observation.observation_id = terminal.observation_id
 AND observation.sprint_id = intent.sprint_id
 AND observation.outcome = terminal.observation_class
 AND observation.contract_version = terminal.contract_version
LEFT JOIN effect_evidence_payloads payload
  ON payload.effect_id = observation.effect_id
 AND payload.observation_id = observation.observation_id
 AND payload.sprint_id = observation.sprint_id
 AND payload.evidence_digest = observation.evidence_digest
 AND payload.contract_version = observation.contract_version
LEFT JOIN command_output_capture_acquisitions acquired
  ON acquired.capture_id = terminal.capture_id
 AND acquired.effect_id = terminal.effect_id
 AND acquired.contract_version = terminal.contract_version
LEFT JOIN command_output_capture_exact_acquisitions_v27 exact_acquired
  ON exact_acquired.acquired_anchor_digest = acquired.acquired_anchor_digest
LEFT JOIN runner_effect_dispatch_claims dispatch
  ON dispatch.effect_id = terminal.effect_id
LEFT JOIN command_output_capture_exact_dispatch_authorities_v27 exact_dispatch
  ON exact_dispatch.capture_id = terminal.capture_id
 AND exact_dispatch.dispatch_claim_id = dispatch.dispatch_claim_id
LEFT JOIN command_domain_cleanup_proofs command_cleanup
  ON command_cleanup.proof_id = validation.command_domain_cleanup_proof_id
LEFT JOIN command_output_capture_reconciliation_claims recovery_claim
  ON recovery_claim.claim_id = validation.reconciliation_claim_id
 AND recovery_claim.capture_id = terminal.capture_id
 AND recovery_claim.fencing_token = validation.reconciliation_fencing_token
 AND recovery_claim.contract_version = terminal.contract_version
LEFT JOIN command_output_capture_exact_reconciliation_claims_v27 exact_recovery_claim
  ON exact_recovery_claim.claim_id = recovery_claim.claim_id
LEFT JOIN command_output_capture_reconciliation_claim_releases recovery_release
  ON recovery_release.claim_id = recovery_claim.claim_id
 AND recovery_release.capture_id = recovery_claim.capture_id
 AND recovery_release.claim_epoch = recovery_claim.claim_epoch
 AND recovery_release.fencing_token = recovery_claim.fencing_token
 AND recovery_release.contract_version = recovery_claim.contract_version
 AND recovery_release.release_kind = 'ConsumedTerminal'
 AND recovery_release.terminal_anchor_digest = terminal.terminal_anchor_digest
 AND recovery_release.released_at_unix_ms = terminal.anchored_at_unix_ms
LEFT JOIN command_output_capture_restart_recovery_receipts recovery
  ON recovery.receipt_digest = validation.restart_recovery_receipt_digest
 AND recovery.capture_id = terminal.capture_id
 AND recovery.effect_id = terminal.effect_id
 AND recovery.intent_digest = terminal.intent_digest
 AND recovery.reconciliation_claim_id = recovery_claim.claim_id
 AND recovery.reconciliation_fencing_token = recovery_claim.fencing_token
 AND recovery.contract_version = terminal.contract_version
LEFT JOIN command_output_capture_exact_restart_recovery_receipts_v27 exact_recovery
  ON exact_recovery.receipt_digest = recovery.receipt_digest
LEFT JOIN effect_intents effect_intent
  ON effect_intent.effect_id = terminal.effect_id
 AND effect_intent.sprint_id = intent.sprint_id
 AND effect_intent.request_digest = intent.request_digest
 AND effect_intent.contract_version = intent.contract_version
LEFT JOIN worker_cleanup_receipts runner_cleanup
  ON runner_cleanup.sprint_id = intent.sprint_id
 AND runner_cleanup.receipt_id = validation.runner_cleanup_receipt_id
 AND runner_cleanup.launch_id = intent.runner_launch_id
 AND runner_cleanup.session_id = intent.runner_session_id
 AND runner_cleanup.worker_lease_id IS effect_intent.worker_lease_id
 AND runner_cleanup.worker_lease_epoch IS effect_intent.worker_lease_epoch
 AND runner_cleanup.contract_version = intent.contract_version
WHERE terminal.anchored_at_unix_ms >= intent.created_at_unix_ms
  AND (
      (acquired.acquired_anchor_digest IS NULL
       AND terminal.acquired_anchor_digest IS NULL
       AND terminal.dispatch_claim_id IS NULL
       AND dispatch.dispatch_claim_id IS NULL)
      OR (exact_acquired.acquired_anchor_digest IS NOT NULL
          AND exact_dispatch.dispatch_claim_id IS NOT NULL
          AND terminal.acquired_anchor_digest = acquired.acquired_anchor_digest
          AND terminal.dispatch_claim_id = acquired.dispatch_claim_id
          AND dispatch.dispatch_claim_id = acquired.dispatch_claim_id
          AND dispatch.sprint_id = intent.sprint_id
          AND dispatch.launch_id = intent.runner_launch_id
          AND dispatch.session_id = intent.runner_session_id
          AND dispatch.request_digest = intent.request_digest
          AND dispatch.contract_version = intent.contract_version)
  )
  AND (
      validation.reconciliation_claim_id IS NULL
      OR exact_recovery_claim.claim_id IS NOT NULL
  )
  AND (
      (validation.validation_kind = 'PreDispatchAbandoned'
       AND validation.command_domain_cleanup_proof_id IS NULL
       AND validation.reconciliation_claim_id IS NULL
       AND validation.reconciliation_fencing_token IS NULL
       AND validation.runner_cleanup_receipt_id IS NULL
       AND validation.restart_recovery_receipt_digest IS NULL
       AND terminal.dispatch_claim_id IS NULL
       AND terminal.acquired_anchor_digest IS NULL
       AND acquired.acquired_anchor_digest IS NULL
       AND dispatch.dispatch_claim_id IS NULL
       AND terminal.observation_class IN (
           'FailedBeforeEffect', 'CancelledBeforeEffect'
       )
       AND terminal.disposition = 'Abandoned')
      OR
      (validation.validation_kind = 'DirectClaimed'
       AND validation.command_domain_cleanup_proof_id IS NOT NULL
       AND validation.reconciliation_claim_id IS NULL
       AND validation.reconciliation_fencing_token IS NULL
       AND validation.runner_cleanup_receipt_id IS NULL
       AND validation.restart_recovery_receipt_digest IS NULL
       AND acquired.acquired_anchor_digest IS NOT NULL
       AND dispatch.dispatch_claim_id IS NOT NULL
       AND acquired.dispatch_claim_id = dispatch.dispatch_claim_id
       AND acquired.runner_launch_id = intent.runner_launch_id
       AND acquired.runner_session_id = intent.runner_session_id
       AND acquired.request_digest = intent.request_digest
       AND acquired.private_state_digest = intent.private_state_digest
       AND terminal.disposition IN ('Published', 'Abandoned')
       AND command_cleanup.proof_id IS NOT NULL
       AND command_cleanup.sprint_id = intent.sprint_id
       AND command_cleanup.launch_id = intent.runner_launch_id
       AND command_cleanup.session_id = intent.runner_session_id
       AND command_cleanup.effect_id = intent.effect_id
       AND command_cleanup.observation_id = terminal.observation_id
       AND command_cleanup.request_digest = intent.request_digest
       AND command_cleanup.surviving_processes = 0
       AND command_cleanup.contract_version = intent.contract_version
       AND command_cleanup.cleaned_at_unix_ms >= observation.observed_at_unix_ms
       AND command_cleanup.cleaned_at_unix_ms <= terminal.anchored_at_unix_ms
       AND (
           command_cleanup.disposition = 'ReapedZeroSurvivors'
           OR (terminal.observation_class IN (
                   'FailedBeforeEffect', 'CancelledBeforeEffect'
               )
               AND command_cleanup.disposition = 'NoDomainCreatedBeforeEffect')
       ))
      OR
      (validation.validation_kind = 'DirectClaimedUnresolved'
       AND validation.command_domain_cleanup_proof_id IS NULL
       AND validation.reconciliation_claim_id IS NULL
       AND validation.reconciliation_fencing_token IS NULL
       AND validation.runner_cleanup_receipt_id IS NULL
       AND validation.restart_recovery_receipt_digest IS NULL
       AND acquired.acquired_anchor_digest IS NOT NULL
       AND dispatch.dispatch_claim_id IS NOT NULL
       AND acquired.dispatch_claim_id = dispatch.dispatch_claim_id
       AND terminal.observation_class = 'Unknown'
       AND terminal.disposition = 'ReconciliationRequired'
       AND terminal.store_head_generation = acquired.store_head_generation
       AND terminal.store_head_digest = acquired.store_head_digest
       AND terminal.terminal_record_digest = observation.evidence_digest)
      OR
      (validation.validation_kind IN (
           'RestartIntentAbandoned', 'RestartClaimedBeforeLaunchAbandoned',
           'RestartClaimedUnresolved', 'RestartTerminalPreparedPublished'
       )
       AND validation.reconciliation_claim_id IS NOT NULL
       AND validation.reconciliation_fencing_token IS NOT NULL
       AND validation.runner_cleanup_receipt_id IS NULL
       AND validation.restart_recovery_receipt_digest IS NOT NULL
       AND recovery_claim.claim_id IS NOT NULL
       AND recovery_release.claim_id IS NOT NULL
       AND terminal.anchored_at_unix_ms >= recovery_claim.acquired_at_unix_ms
       AND terminal.anchored_at_unix_ms < recovery_claim.expires_at_unix_ms
       AND recovery.receipt_digest IS NOT NULL
       AND exact_recovery.receipt_digest IS NOT NULL
       AND recovery.recovered_at_unix_ms = terminal.anchored_at_unix_ms
       AND recovery.store_head_generation = terminal.store_head_generation
       AND recovery.store_head_digest = terminal.store_head_digest
       AND recovery.receipt_digest = grok_command_output_capture_restart_recovery_receipt_digest(
           recovery.receipt_json
       )
       AND json_extract(
             CAST(recovery.receipt_json AS TEXT), '$.capture_id'
           ) = terminal.capture_id
       AND json_extract(
             CAST(recovery.receipt_json AS TEXT), '$.effect_id'
           ) = terminal.effect_id
       AND json_extract(
             CAST(recovery.receipt_json AS TEXT), '$.intent_digest'
           ) = terminal.intent_digest
       AND json_extract(
             CAST(recovery.receipt_json AS TEXT),
             '$.reconciliation_claim.claim_id'
           ) = recovery_claim.claim_id
       AND json_extract(
             CAST(recovery.receipt_json AS TEXT),
             '$.reconciliation_claim.fencing_token'
           ) = recovery_claim.fencing_token
       AND json_extract(
             CAST(recovery.receipt_json AS TEXT), '$.final_store_head.generation'
           ) = terminal.store_head_generation
       AND json_extract(
             CAST(recovery.receipt_json AS TEXT),
             '$.final_store_head.record_digest'
           ) = terminal.store_head_digest
       AND json_extract(
             CAST(recovery.receipt_json AS TEXT), '$.reconciliation_digest'
           ) = recovery.receipt_digest
       AND json_extract(
             CAST(recovery.receipt_json AS TEXT), '$.reconciled_at_unix_ms'
           ) = terminal.anchored_at_unix_ms
       AND (
           (validation.validation_kind = 'RestartIntentAbandoned'
            AND validation.command_domain_cleanup_proof_id IS NOT NULL
            AND acquired.acquired_anchor_digest IS NULL
            AND terminal.dispatch_claim_id IS NULL
            AND terminal.acquired_anchor_digest IS NULL
            AND terminal.observation_class = 'FailedBeforeEffect'
            AND terminal.disposition = 'Abandoned'
            AND terminal.terminal_record_digest = recovery.receipt_digest
            AND recovery.observed_state = 'Cleaned'
            AND recovery.launch_schema IS NULL
            AND json_type(
                  CAST(recovery.receipt_json AS TEXT), '$.requested_store_head'
                ) = 'null'
            AND json_type(
                  CAST(recovery.receipt_json AS TEXT), '$.artifact_reference'
                ) = 'null'
            AND json_type(
                  CAST(recovery.receipt_json AS TEXT), '$.terminal_prepared'
                ) = 'null'
            AND json_type(
                  CAST(recovery.receipt_json AS TEXT),
                  '$.cleanup_completion_proof_digest'
                ) = 'text'
            AND (
                (recovery.acquired_anchor_digest IS NULL
                 AND (recovery.resolution_action IN (
                          'IntentTombstoned', 'PreAcquisitionCleaned'
                      )
                      OR (recovery.resolution_action = 'TerminalReadback'
                          AND json_extract(
                                CAST(recovery.receipt_json AS TEXT),
                                '$.initial_state'
                              ) = 'cleaned'
                          AND json_extract(
                                CAST(recovery.receipt_json AS TEXT),
                                '$.initial_store_head.generation'
                              ) = recovery.store_head_generation
                          AND json_extract(
                                CAST(recovery.receipt_json AS TEXT),
                                '$.initial_store_head.record_digest'
                              ) = recovery.store_head_digest)))
                OR (recovery.acquired_anchor_digest IS NOT NULL
                    AND (recovery.resolution_action = 'WorkingSetCleaned'
                         OR (recovery.resolution_action = 'TerminalReadback'
                             AND json_extract(
                                   CAST(recovery.receipt_json AS TEXT),
                                   '$.initial_state'
                                 ) = 'cleaned'
                             AND json_extract(
                                   CAST(recovery.receipt_json AS TEXT),
                                   '$.initial_store_head.generation'
                                 ) = recovery.store_head_generation
                             AND json_extract(
                                   CAST(recovery.receipt_json AS TEXT),
                                   '$.initial_store_head.record_digest'
                                 ) = recovery.store_head_digest))
                    AND NOT EXISTS (
                        SELECT 1
                        FROM json_each(
                            CAST(recovery.receipt_json AS TEXT),
                            '$.lifecycle_history'
                        ) history
                        WHERE json_extract(history.value, '$.state') IN (
                            'writer_attached', 'launch_intended', 'finished',
                            'published', 'terminal_prepared'
                        )
                    ))
            )
            AND command_cleanup.proof_id IS NOT NULL
            AND command_cleanup.sprint_id = intent.sprint_id
            AND command_cleanup.launch_id = intent.runner_launch_id
            AND command_cleanup.session_id = intent.runner_session_id
            AND command_cleanup.effect_id = intent.effect_id
            AND command_cleanup.observation_id = terminal.observation_id
            AND command_cleanup.request_digest = intent.request_digest
            AND command_cleanup.disposition = 'NoDomainCreatedBeforeEffect'
            AND command_cleanup.surviving_processes = 0
            AND command_cleanup.contract_version = intent.contract_version
            AND command_cleanup.cleaned_at_unix_ms >=
                observation.observed_at_unix_ms
            AND command_cleanup.cleaned_at_unix_ms <= terminal.anchored_at_unix_ms
            AND observation.evidence_digest = grok_sha256(recovery.receipt_json)
            AND payload.evidence_bytes = recovery.receipt_json)
           OR
           (validation.validation_kind = 'RestartClaimedBeforeLaunchAbandoned'
            AND validation.command_domain_cleanup_proof_id IS NOT NULL
            AND acquired.acquired_anchor_digest IS NOT NULL
            AND dispatch.dispatch_claim_id IS NOT NULL
            AND acquired.dispatch_claim_id = dispatch.dispatch_claim_id
            AND recovery.acquired_anchor_digest = acquired.acquired_anchor_digest
            AND terminal.observation_class = 'FailedBeforeEffect'
            AND terminal.disposition = 'Abandoned'
            AND terminal.terminal_record_digest = recovery.receipt_digest
            AND recovery.observed_state = 'Cleaned'
            AND recovery.launch_schema IS NULL
            AND json_extract(
                  CAST(recovery.receipt_json AS TEXT),
                  '$.requested_store_head.generation'
                ) = acquired.store_head_generation
            AND json_extract(
                  CAST(recovery.receipt_json AS TEXT),
                  '$.requested_store_head.record_digest'
                ) = acquired.store_head_digest
            AND json_type(
                  CAST(recovery.receipt_json AS TEXT), '$.artifact_reference'
                ) = 'null'
            AND json_type(
                  CAST(recovery.receipt_json AS TEXT), '$.terminal_prepared'
                ) = 'null'
            AND json_type(
                  CAST(recovery.receipt_json AS TEXT),
                  '$.cleanup_completion_proof_digest'
                ) = 'text'
            AND (recovery.resolution_action = 'WorkingSetCleaned'
                 OR (recovery.resolution_action = 'TerminalReadback'
                     AND json_extract(
                           CAST(recovery.receipt_json AS TEXT), '$.initial_state'
                         ) = 'cleaned'
                     AND json_extract(
                           CAST(recovery.receipt_json AS TEXT),
                           '$.initial_store_head.generation'
                         ) = recovery.store_head_generation
                     AND json_extract(
                           CAST(recovery.receipt_json AS TEXT),
                           '$.initial_store_head.record_digest'
                         ) = recovery.store_head_digest))
            AND NOT EXISTS (
                SELECT 1
                FROM json_each(
                    CAST(recovery.receipt_json AS TEXT), '$.lifecycle_history'
                ) history
                WHERE json_extract(history.value, '$.state') IN (
                    'launch_intended', 'finished', 'published',
                    'terminal_prepared'
                )
            )
            AND command_cleanup.proof_id IS NOT NULL
            AND command_cleanup.sprint_id = intent.sprint_id
            AND command_cleanup.launch_id = intent.runner_launch_id
            AND command_cleanup.session_id = intent.runner_session_id
            AND command_cleanup.effect_id = intent.effect_id
            AND command_cleanup.observation_id = terminal.observation_id
            AND command_cleanup.request_digest = intent.request_digest
            AND command_cleanup.disposition = 'NoDomainCreatedBeforeEffect'
            AND command_cleanup.surviving_processes = 0
            AND command_cleanup.contract_version = intent.contract_version
            AND command_cleanup.cleaned_at_unix_ms >=
                observation.observed_at_unix_ms
            AND command_cleanup.cleaned_at_unix_ms <= terminal.anchored_at_unix_ms
            AND observation.evidence_digest = grok_sha256(recovery.receipt_json)
            AND payload.evidence_bytes = recovery.receipt_json)
           OR
           (validation.validation_kind = 'RestartClaimedUnresolved'
            AND validation.command_domain_cleanup_proof_id IS NULL
            AND acquired.acquired_anchor_digest IS NOT NULL
            AND dispatch.dispatch_claim_id IS NOT NULL
            AND acquired.dispatch_claim_id = dispatch.dispatch_claim_id
            AND recovery.acquired_anchor_digest = acquired.acquired_anchor_digest
            AND terminal.observation_class = 'Unknown'
            AND terminal.disposition = 'ReconciliationRequired'
            AND terminal.terminal_record_digest = recovery.receipt_digest
            AND recovery.launch_schema IS NOT NULL
            AND recovery.observed_state IN (
                'LaunchIntended', 'Finished', 'Published', 'TerminalPrepared',
                'CleanupIntended', 'Cleaned'
            )
            AND json_extract(
                  CAST(recovery.receipt_json AS TEXT),
                  '$.requested_store_head.generation'
                ) = acquired.store_head_generation
            AND json_extract(
                  CAST(recovery.receipt_json AS TEXT),
                  '$.requested_store_head.record_digest'
                ) = acquired.store_head_digest
            AND observation.evidence_digest = grok_sha256(recovery.receipt_json)
            AND payload.evidence_bytes = recovery.receipt_json)
           OR
           (validation.validation_kind = 'RestartTerminalPreparedPublished'
            AND validation.command_domain_cleanup_proof_id IS NOT NULL
            AND acquired.acquired_anchor_digest IS NOT NULL
            AND dispatch.dispatch_claim_id IS NOT NULL
            AND acquired.dispatch_claim_id = dispatch.dispatch_claim_id
            AND recovery.acquired_anchor_digest = acquired.acquired_anchor_digest
            AND terminal.observation_class = 'Succeeded'
            AND terminal.disposition = 'Published'
            AND recovery.observed_state = 'TerminalPrepared'
            AND recovery.resolution_action IN (
                'TerminalReadback', 'TerminalPreparedRecovered'
            )
            AND recovery.launch_schema IS NOT NULL
            AND json_extract(
                  CAST(recovery.receipt_json AS TEXT),
                  '$.requested_store_head.generation'
                ) = acquired.store_head_generation
            AND json_extract(
                  CAST(recovery.receipt_json AS TEXT),
                  '$.requested_store_head.record_digest'
                ) = acquired.store_head_digest
            AND json_type(
                  CAST(recovery.receipt_json AS TEXT), '$.finished_store_head'
                ) = 'object'
            AND json_type(
                  CAST(recovery.receipt_json AS TEXT), '$.published_store_head'
                ) = 'object'
            AND json_type(
                  CAST(recovery.receipt_json AS TEXT), '$.artifact_reference'
                ) = 'object'
            AND json_type(
                  CAST(recovery.receipt_json AS TEXT), '$.terminal_prepared'
                ) = 'object'
            AND json_extract(
                  CAST(recovery.receipt_json AS TEXT),
                  '$.terminal_prepared.store_head.generation'
                ) = recovery.store_head_generation
            AND json_extract(
                  CAST(recovery.receipt_json AS TEXT),
                  '$.terminal_prepared.store_head.record_digest'
                ) = recovery.store_head_digest
            AND json_type(
                  CAST(recovery.receipt_json AS TEXT), '$.cleaned_store_head'
                ) = 'null'
            AND json_type(
                  CAST(recovery.receipt_json AS TEXT),
                  '$.cleanup_completion_proof_digest'
                ) = 'null'
            AND terminal.terminal_record_digest = json_extract(
                  CAST(recovery.receipt_json AS TEXT),
                  '$.terminal_prepared.canonical_bytes_digest'
                )
            AND terminal.artifact_manifest_digest = json_extract(
                  CAST(recovery.receipt_json AS TEXT),
                  '$.artifact_reference.manifest_digest'
                )
            AND CAST(terminal.artifact_reference_json AS TEXT) = json_extract(
                  CAST(recovery.receipt_json AS TEXT), '$.artifact_reference'
                )
            AND command_cleanup.proof_id IS NOT NULL
            AND command_cleanup.sprint_id = intent.sprint_id
            AND command_cleanup.launch_id = intent.runner_launch_id
            AND command_cleanup.session_id = intent.runner_session_id
            AND command_cleanup.effect_id = intent.effect_id
            AND command_cleanup.observation_id = terminal.observation_id
            AND command_cleanup.request_digest = intent.request_digest
            AND command_cleanup.disposition = 'ReapedZeroSurvivors'
            AND command_cleanup.surviving_processes = 0
            AND command_cleanup.contract_version = intent.contract_version
            AND command_cleanup.cleaned_at_unix_ms >=
                observation.observed_at_unix_ms
            AND command_cleanup.cleaned_at_unix_ms <= terminal.anchored_at_unix_ms)
       ))
      OR
      (validation.validation_kind = 'RestartReconciliation'
       AND validation.command_domain_cleanup_proof_id IS NOT NULL
       AND validation.reconciliation_claim_id IS NOT NULL
       AND validation.reconciliation_fencing_token IS NOT NULL
       AND validation.runner_cleanup_receipt_id IS NOT NULL
       AND validation.restart_recovery_receipt_digest IS NULL
       AND acquired.acquired_anchor_digest IS NOT NULL
       AND dispatch.dispatch_claim_id IS NOT NULL
       AND acquired.dispatch_claim_id = dispatch.dispatch_claim_id
       AND recovery_claim.claim_id IS NOT NULL
       AND recovery_release.claim_id IS NOT NULL
       AND terminal.anchored_at_unix_ms >= recovery_claim.acquired_at_unix_ms
       AND terminal.anchored_at_unix_ms < recovery_claim.expires_at_unix_ms
       AND recovery_claim.claim_epoch = (
           SELECT MAX(latest.claim_epoch)
           FROM command_output_capture_reconciliation_claims latest
           WHERE latest.capture_id = recovery_claim.capture_id
       )
       AND runner_cleanup.receipt_id IS NOT NULL
       AND runner_cleanup.surviving_processes = 0
       AND runner_cleanup.cleaned_at_unix_ms >= recovery_claim.acquired_at_unix_ms
       AND runner_cleanup.cleaned_at_unix_ms <= terminal.anchored_at_unix_ms
       AND command_cleanup.proof_id IS NOT NULL
       AND command_cleanup.sprint_id = intent.sprint_id
       AND command_cleanup.launch_id = intent.runner_launch_id
       AND command_cleanup.session_id = intent.runner_session_id
       AND command_cleanup.effect_id = intent.effect_id
       AND command_cleanup.observation_id = terminal.observation_id
       AND command_cleanup.request_digest = intent.request_digest
       AND command_cleanup.surviving_processes = 0
       AND command_cleanup.contract_version = intent.contract_version
       AND command_cleanup.cleaned_at_unix_ms >= observation.observed_at_unix_ms
       AND command_cleanup.cleaned_at_unix_ms <= terminal.anchored_at_unix_ms
       AND (
           command_cleanup.disposition = 'ReapedZeroSurvivors'
           OR (terminal.observation_class IN (
                   'FailedBeforeEffect', 'CancelledBeforeEffect'
               )
               AND command_cleanup.disposition = 'NoDomainCreatedBeforeEffect')
       ))
  );

-- Successful completion remains impossible while any capture obligation or
-- restart-reconciliation claim is unresolved, even if other effect rows look
-- terminal through direct SQL.
CREATE TRIGGER command_output_capture_completion_obligation_fence
BEFORE INSERT ON sprint_completion_proof_states
WHEN EXISTS (
    SELECT 1
    FROM effect_intents effect_intent
    LEFT JOIN pre_v27_command_output_capture_exemptions exemption
      ON exemption.effect_id = effect_intent.effect_id
     AND exemption.sprint_id = effect_intent.sprint_id
     AND exemption.request_digest = effect_intent.request_digest
     AND exemption.created_at_unix_ms = effect_intent.created_at_unix_ms
     AND exemption.contract_version = effect_intent.contract_version
     AND exemption.intent_digest = grok_sha256(effect_intent.intent_json)
    LEFT JOIN effect_session_bindings binding
      ON binding.effect_id = effect_intent.effect_id
     AND binding.sprint_id = effect_intent.sprint_id
    LEFT JOIN runner_launch_intents launch
      ON launch.sprint_id = binding.sprint_id
     AND launch.launch_id = binding.launch_id
    LEFT JOIN runner_session_policies session
      ON session.sprint_id = binding.sprint_id
     AND session.session_id = binding.session_id
     AND session.launch_id = launch.launch_id
    LEFT JOIN command_output_capture_intents intent
      ON intent.effect_id = effect_intent.effect_id
    LEFT JOIN command_output_capture_exact_runner_sources_v27 exact_source
      ON exact_source.capture_id = intent.capture_id
    LEFT JOIN command_output_capture_acquisitions acquired
      ON acquired.capture_id = intent.capture_id
     AND acquired.effect_id = intent.effect_id
     AND acquired.contract_version = intent.contract_version
    LEFT JOIN command_output_capture_exact_acquisitions_v27 exact_acquired
      ON exact_acquired.acquired_anchor_digest = acquired.acquired_anchor_digest
    LEFT JOIN runner_effect_dispatch_claims raw_dispatch
      ON raw_dispatch.effect_id = intent.effect_id
    LEFT JOIN command_output_capture_exact_dispatch_authorities_v27 exact_dispatch
      ON exact_dispatch.capture_id = intent.capture_id
     AND exact_dispatch.dispatch_claim_id = raw_dispatch.dispatch_claim_id
    LEFT JOIN command_output_capture_reconciliation_obligations obligation
      ON obligation.capture_id = intent.capture_id
    LEFT JOIN command_output_capture_terminal_anchors terminal
      ON terminal.capture_id = intent.capture_id
     AND terminal.effect_id = intent.effect_id
     AND terminal.intent_digest = intent.intent_digest
     AND terminal.contract_version = intent.contract_version
    LEFT JOIN command_output_capture_terminal_validations validation
      ON validation.terminal_anchor_digest = terminal.terminal_anchor_digest
     AND validation.capture_id = terminal.capture_id
     AND validation.effect_id = terminal.effect_id
     AND validation.observation_id = terminal.observation_id
     AND validation.terminal_anchored_at_unix_ms = terminal.anchored_at_unix_ms
     AND validation.sprint_id = intent.sprint_id
     AND validation.contract_version = terminal.contract_version
    LEFT JOIN command_output_capture_exact_terminal_authorities_v27 exact_terminal
      ON exact_terminal.terminal_anchor_digest = terminal.terminal_anchor_digest
    LEFT JOIN command_output_capture_reconciliation_resolutions resolution
      ON resolution.capture_id = terminal.capture_id
     AND resolution.effect_id = terminal.effect_id
     AND resolution.observation_id = terminal.observation_id
     AND resolution.terminal_anchor_digest = terminal.terminal_anchor_digest
     AND resolution.contract_version = terminal.contract_version
    LEFT JOIN command_output_capture_exact_resolution_authorities_v27 exact_resolution
      ON exact_resolution.resolution_anchor_digest =
         resolution.resolution_anchor_digest
    LEFT JOIN command_output_capture_reconciliation_obligation_closures closure
      ON closure.obligation_id = obligation.obligation_id
     AND closure.capture_id = intent.capture_id
     AND closure.effect_id = intent.effect_id
     AND closure.terminal_anchor_digest = terminal.terminal_anchor_digest
     AND closure.contract_version = intent.contract_version
     AND closure.contract_version = NEW.contract_version
    WHERE effect_intent.sprint_id = NEW.sprint_id
      AND effect_intent.effect_kind = 'RunCommand'
      AND (
          (exemption.effect_id IS NOT NULL AND intent.capture_id IS NOT NULL)
          OR (exemption.effect_id IS NULL AND (
              intent.capture_id IS NULL
              OR exact_source.capture_id IS NULL
              OR binding.effect_id IS NULL
              OR launch.launch_id IS NULL
              OR session.session_id IS NULL
              OR intent.sprint_id IS NOT effect_intent.sprint_id
              OR intent.request_digest IS NOT effect_intent.request_digest
              OR intent.created_at_unix_ms IS NOT effect_intent.created_at_unix_ms
              OR intent.contract_version IS NOT effect_intent.contract_version
              OR intent.contract_version IS NOT NEW.contract_version
              OR intent.runner_launch_id IS NOT binding.launch_id
              OR intent.runner_session_id IS NOT binding.session_id
              OR intent.private_state_digest IS NOT launch.private_state_digest
              OR intent.private_state_digest IS NOT session.private_state_digest
              OR binding.contract_version IS NOT intent.contract_version
              OR launch.contract_version IS NOT intent.contract_version
              OR session.contract_version IS NOT intent.contract_version
              OR session.purpose NOT IN ('TaskWorker', 'FinalVerifier')
              OR json_extract(CAST(intent.intent_json AS TEXT), '$.capture_id')
                    IS NOT intent.capture_id
              OR json_extract(CAST(intent.intent_json AS TEXT), '$.source.effect_id')
                    IS NOT intent.effect_id
              OR json_extract(CAST(intent.intent_json AS TEXT), '$.source.sprint_id')
                    IS NOT intent.sprint_id
              OR json_extract(CAST(intent.intent_json AS TEXT), '$.source.runner_launch_id')
                    IS NOT intent.runner_launch_id
              OR json_extract(CAST(intent.intent_json AS TEXT), '$.source.runner_session_id')
                    IS NOT intent.runner_session_id
              OR json_extract(CAST(intent.intent_json AS TEXT), '$.source.request_digest')
                    IS NOT intent.request_digest
              OR json_extract(CAST(intent.intent_json AS TEXT), '$.private_state_digest')
                    IS NOT intent.private_state_digest
              OR json_extract(CAST(intent.intent_json AS TEXT), '$.max_aggregate_output_bytes')
                    IS NOT intent.max_aggregate_output_bytes
              OR json_extract(CAST(intent.intent_json AS TEXT), '$.layout_version')
                    IS NOT intent.layout_version
              OR json_extract(CAST(intent.intent_json AS TEXT), '$.created_at_unix_ms')
                    IS NOT intent.created_at_unix_ms
              OR json_extract(CAST(intent.intent_json AS TEXT), '$.intent_digest')
                    IS NOT intent.intent_digest
              OR json_extract(CAST(intent.intent_json AS TEXT), '$.contract_version')
                    IS NOT intent.contract_version
              OR obligation.obligation_id IS NULL
              OR obligation.capture_id IS NOT intent.capture_id
              OR obligation.effect_id IS NOT intent.effect_id
              OR obligation.intent_digest IS NOT intent.intent_digest
              OR obligation.contract_version IS NOT intent.contract_version
              OR (acquired.acquired_anchor_digest IS NULL
                  AND raw_dispatch.dispatch_claim_id IS NOT NULL)
              OR (acquired.acquired_anchor_digest IS NOT NULL
                  AND (exact_acquired.acquired_anchor_digest IS NULL
                       OR exact_dispatch.dispatch_claim_id IS NULL
                       OR exact_dispatch.dispatch_claim_id IS NOT
                          acquired.dispatch_claim_id))
              OR terminal.capture_id IS NULL
              OR validation.terminal_anchor_digest IS NULL
              OR exact_terminal.terminal_anchor_digest IS NULL
              OR json_extract(
                    CAST(terminal.terminal_anchor_json AS TEXT), '$.capture_id'
                 ) IS NOT terminal.capture_id
              OR json_extract(
                    CAST(terminal.terminal_anchor_json AS TEXT), '$.effect_id'
                 ) IS NOT terminal.effect_id
              OR json_extract(
                    CAST(terminal.terminal_anchor_json AS TEXT), '$.observation_id'
                 ) IS NOT terminal.observation_id
              OR json_extract(
                    CAST(terminal.terminal_anchor_json AS TEXT), '$.dispatch_claim_id'
                 ) IS NOT terminal.dispatch_claim_id
              OR json_extract(
                    CAST(terminal.terminal_anchor_json AS TEXT), '$.intent_digest'
                 ) IS NOT terminal.intent_digest
              OR json_extract(
                    CAST(terminal.terminal_anchor_json AS TEXT),
                    '$.acquired_anchor_digest'
                 ) IS NOT terminal.acquired_anchor_digest
              OR json_extract(
                    CAST(terminal.terminal_anchor_json AS TEXT), '$.observation_class'
                 ) IS NOT CASE terminal.observation_class
                       WHEN 'Succeeded' THEN 'succeeded'
                       WHEN 'FailedBeforeEffect' THEN 'failed_before_effect'
                       WHEN 'FailedAfterKnownEffect' THEN 'failed_after_known_effect'
                       WHEN 'CancelledBeforeEffect' THEN 'cancelled_before_effect'
                       WHEN 'Unknown' THEN 'unknown'
                     END
              OR json_extract(
                    CAST(terminal.terminal_anchor_json AS TEXT), '$.disposition'
                 ) IS NOT CASE terminal.disposition
                       WHEN 'Published' THEN 'published'
                       WHEN 'Abandoned' THEN 'abandoned'
                       WHEN 'ReconciliationRequired' THEN
                           'reconciliation_required'
                     END
              OR json_extract(
                    CAST(terminal.terminal_anchor_json AS TEXT),
                    '$.store_head.generation'
                 ) IS NOT terminal.store_head_generation
              OR json_extract(
                    CAST(terminal.terminal_anchor_json AS TEXT),
                    '$.store_head.record_digest'
                 ) IS NOT terminal.store_head_digest
              OR json_extract(
                    CAST(terminal.terminal_anchor_json AS TEXT),
                    '$.terminal_record_digest'
                 ) IS NOT terminal.terminal_record_digest
              OR json_extract(
                    CAST(terminal.terminal_anchor_json AS TEXT),
                    '$.artifact_reference.manifest_digest'
                 ) IS NOT terminal.artifact_manifest_digest
              OR NOT (
                  (terminal.artifact_reference_json IS NULL
                   AND json_type(
                         CAST(terminal.terminal_anchor_json AS TEXT),
                         '$.artifact_reference'
                       ) = 'null')
                  OR (terminal.artifact_reference_json IS NOT NULL
                      AND CAST(terminal.artifact_reference_json AS TEXT) =
                          json_extract(
                              CAST(terminal.terminal_anchor_json AS TEXT),
                              '$.artifact_reference'
                          ))
              )
              OR json_extract(
                    CAST(terminal.terminal_anchor_json AS TEXT),
                    '$.anchored_at_unix_ms'
                 ) IS NOT terminal.anchored_at_unix_ms
              OR json_extract(
                    CAST(terminal.terminal_anchor_json AS TEXT), '$.layout_version'
                 ) IS NOT terminal.layout_version
              OR json_extract(
                    CAST(terminal.terminal_anchor_json AS TEXT), '$.contract_version'
                 ) IS NOT terminal.contract_version
              OR json_extract(
                    CAST(terminal.terminal_anchor_json AS TEXT),
                    '$.terminal_anchor_digest'
                 ) IS NOT terminal.terminal_anchor_digest
              OR closure.obligation_id IS NULL
              OR NOT (
                  (terminal.disposition IN ('Published', 'Abandoned')
                   AND resolution.resolution_anchor_digest IS NULL
                   AND closure.closed_at_unix_ms = terminal.anchored_at_unix_ms)
                  OR (terminal.observation_class = 'Unknown'
                      AND terminal.disposition = 'ReconciliationRequired'
                      AND resolution.resolution_anchor_digest IS NOT NULL
                      AND exact_resolution.resolution_anchor_digest IS NOT NULL
                      AND json_extract(
                            CAST(resolution.resolution_json AS TEXT), '$.capture_id'
                          ) IS resolution.capture_id
                      AND json_extract(
                            CAST(resolution.resolution_json AS TEXT), '$.effect_id'
                          ) IS resolution.effect_id
                      AND json_extract(
                            CAST(resolution.resolution_json AS TEXT), '$.observation_id'
                          ) IS resolution.observation_id
                      AND json_extract(
                            CAST(resolution.resolution_json AS TEXT),
                            '$.terminal_anchor_digest'
                          ) IS resolution.terminal_anchor_digest
                      AND json_extract(
                            CAST(resolution.resolution_json AS TEXT),
                            '$.reconciliation_claim_id'
                          ) IS resolution.reconciliation_claim_id
                      AND json_extract(
                            CAST(resolution.resolution_json AS TEXT),
                            '$.reconciliation_fencing_token'
                          ) IS resolution.reconciliation_fencing_token
                      AND json_extract(
                            CAST(resolution.resolution_json AS TEXT), '$.disposition'
                          ) IS CASE resolution.disposition
                                WHEN 'Published' THEN 'published'
                                WHEN 'Abandoned' THEN 'abandoned'
                              END
                      AND json_extract(
                            CAST(resolution.resolution_json AS TEXT),
                            '$.store_head.generation'
                          ) IS resolution.store_head_generation
                      AND json_extract(
                            CAST(resolution.resolution_json AS TEXT),
                            '$.store_head.record_digest'
                          ) IS resolution.store_head_digest
                      AND json_extract(
                            CAST(resolution.resolution_json AS TEXT),
                            '$.resolution_record_digest'
                          ) IS resolution.resolution_record_digest
                      AND json_extract(
                            CAST(resolution.resolution_json AS TEXT),
                            '$.artifact_reference.manifest_digest'
                          ) IS resolution.artifact_manifest_digest
                      AND (
                          (resolution.artifact_reference_json IS NULL
                           AND json_type(
                                 CAST(resolution.resolution_json AS TEXT),
                                 '$.artifact_reference'
                               ) = 'null')
                          OR (resolution.artifact_reference_json IS NOT NULL
                              AND CAST(resolution.artifact_reference_json AS TEXT) =
                                  json_extract(
                                      CAST(resolution.resolution_json AS TEXT),
                                      '$.artifact_reference'
                                  ))
                      )
                      AND json_extract(
                            CAST(resolution.resolution_json AS TEXT),
                            '$.resolution_anchor_digest'
                          ) IS resolution.resolution_anchor_digest
                      AND json_extract(
                            CAST(resolution.resolution_json AS TEXT),
                            '$.resolved_at_unix_ms'
                          ) IS resolution.resolved_at_unix_ms
                      AND json_extract(
                            CAST(resolution.resolution_json AS TEXT), '$.layout_version'
                          ) IS resolution.layout_version
                      AND json_extract(
                            CAST(resolution.resolution_json AS TEXT), '$.contract_version'
                          ) IS resolution.contract_version
                      AND closure.closed_at_unix_ms = resolution.resolved_at_unix_ms)
              )
          ))
      )
) OR EXISTS (
    SELECT 1
    FROM effect_intents effect_intent
    JOIN command_output_capture_intents intent
      ON intent.effect_id = effect_intent.effect_id
    JOIN command_output_capture_reconciliation_claims claim
      ON claim.capture_id = intent.capture_id
      OR CASE WHEN json_valid(CAST(claim.claim_json AS TEXT))
              THEN json_extract(CAST(claim.claim_json AS TEXT), '$.capture_id') =
                   intent.capture_id
              ELSE 0 END
    LEFT JOIN command_output_capture_exact_reconciliation_claims_v27 exact_claim
      ON exact_claim.claim_id = claim.claim_id
    LEFT JOIN command_output_capture_reconciliation_claim_releases release
      ON release.claim_id = claim.claim_id
     AND release.capture_id = claim.capture_id
     AND release.claim_epoch = claim.claim_epoch
     AND release.fencing_token = claim.fencing_token
     AND release.contract_version = claim.contract_version
     AND release.released_at_unix_ms >= claim.acquired_at_unix_ms
     AND (
         release.release_kind = 'Released'
         OR (release.release_kind = 'Expired'
             AND release.released_at_unix_ms >= claim.expires_at_unix_ms)
         OR (release.release_kind = 'Superseded'
             AND release.released_at_unix_ms < claim.expires_at_unix_ms
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
             AND EXISTS (
                 SELECT 1
                 FROM command_output_capture_terminal_anchors consumed_terminal
                 LEFT JOIN command_output_capture_terminal_validations consumed_validation
                   ON consumed_validation.terminal_anchor_digest =
                      consumed_terminal.terminal_anchor_digest
                  AND consumed_validation.capture_id = consumed_terminal.capture_id
                  AND consumed_validation.effect_id = consumed_terminal.effect_id
                  AND consumed_validation.observation_id =
                      consumed_terminal.observation_id
                  AND consumed_validation.reconciliation_claim_id = claim.claim_id
                  AND consumed_validation.reconciliation_fencing_token =
                      claim.fencing_token
                  AND consumed_validation.terminal_anchored_at_unix_ms =
                      release.released_at_unix_ms
                  AND consumed_validation.contract_version = claim.contract_version
                 WHERE consumed_terminal.terminal_anchor_digest =
                           release.terminal_anchor_digest
                   AND consumed_terminal.capture_id = claim.capture_id
                   AND consumed_terminal.contract_version = claim.contract_version
                   AND (
                       (consumed_terminal.observation_class = 'Unknown'
                        AND consumed_terminal.disposition =
                            'ReconciliationRequired'
                        AND consumed_terminal.anchored_at_unix_ms <=
                            release.released_at_unix_ms)
                       OR (consumed_terminal.anchored_at_unix_ms =
                               release.released_at_unix_ms
                           AND consumed_validation.validation_kind IN (
                               'RestartIntentAbandoned',
                               'RestartClaimedBeforeLaunchAbandoned',
                               'RestartClaimedUnresolved',
                               'RestartTerminalPreparedPublished',
                               'RestartReconciliation'
                           ))
                   )
             ))
     )
    WHERE effect_intent.sprint_id = NEW.sprint_id
      AND effect_intent.effect_kind = 'RunCommand'
      AND (exact_claim.claim_id IS NULL OR release.claim_id IS NULL)
)
BEGIN SELECT RAISE(ABORT, 'completion requires every capture obligation and claim closed'); END;
