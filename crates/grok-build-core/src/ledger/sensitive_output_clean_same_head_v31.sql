-- Schema v31 admits a current-policy clean Published resolution at the exact
-- immutable Unknown terminal head only when the clean receipt embeds the
-- exact restart physical receipt that originally produced that terminal.
-- The ordinary advancing branch remains byte- and semantics-identical: its
-- optional embedded restart field is absent and its new fenced physical
-- receipt must advance the store generation exactly as before.

DROP TRIGGER command_output_clean_scan_resolution_exact;
CREATE TRIGGER command_output_clean_scan_resolution_exact
BEFORE INSERT ON command_output_clean_scan_resolution_receipts_v29
WHEN NOT EXISTS (
    SELECT 1
    FROM command_output_capture_intents intent
    JOIN command_output_capture_acquisitions acquired
      ON acquired.capture_id = intent.capture_id
     AND acquired.effect_id = intent.effect_id
    JOIN command_output_capture_terminal_anchors terminal
      ON terminal.capture_id = intent.capture_id
     AND terminal.effect_id = intent.effect_id
     AND terminal.observation_id = NEW.observation_id
     AND terminal.terminal_anchor_digest = NEW.terminal_anchor_digest
     AND terminal.observation_class = 'Unknown'
     AND terminal.disposition = 'ReconciliationRequired'
     AND terminal.acquired_anchor_digest = acquired.acquired_anchor_digest
     AND terminal.artifact_manifest_digest IS NULL
     AND terminal.artifact_reference_json IS NULL
    JOIN command_output_capture_reconciliation_claims claim
      ON claim.claim_id = NEW.reconciliation_claim_id
     AND claim.capture_id = intent.capture_id
     AND claim.fencing_token = NEW.reconciliation_fencing_token
    JOIN command_output_sensitive_detection_policy_admissions_v29 policy
      ON policy.capture_id = intent.capture_id
     AND policy.effect_id = intent.effect_id
    WHERE intent.capture_id = NEW.capture_id
      AND intent.effect_id = NEW.effect_id
      AND intent.intent_digest = NEW.intent_digest
      AND acquired.acquired_anchor_digest = NEW.acquired_anchor_digest
      AND policy.policy_id = NEW.detector_policy_id
      AND policy.policy_version = NEW.detector_policy_version
      AND policy.policy_digest = NEW.detector_policy_digest
      AND claim.claim_epoch = (
          SELECT MAX(latest.claim_epoch)
          FROM command_output_capture_reconciliation_claims latest
          WHERE latest.capture_id = claim.capture_id
      )
      AND NOT EXISTS (
          SELECT 1 FROM command_output_capture_reconciliation_claim_releases release
          WHERE release.claim_id = claim.claim_id
      )
      AND NEW.resolved_at_unix_ms >= terminal.anchored_at_unix_ms
      AND NEW.resolved_at_unix_ms >= claim.acquired_at_unix_ms
      AND NEW.resolved_at_unix_ms < claim.expires_at_unix_ms
      AND (
          (NEW.resolution_store_head_generation > terminal.store_head_generation
           AND NEW.resolution_record_digest = NEW.resolution_store_head_digest
           AND json_type(
                 CAST(NEW.clean_scan_resolution_receipt_json AS TEXT),
                 '$.restart_same_head_receipt'
               ) IS NULL)
          OR
          (NEW.resolution_store_head_generation = terminal.store_head_generation
           AND NEW.resolution_store_head_digest = terminal.store_head_digest
           AND NEW.resolution_record_digest = terminal.terminal_record_digest
           AND json_type(
                 CAST(NEW.clean_scan_resolution_receipt_json AS TEXT),
                 '$.restart_same_head_receipt'
               ) = 'object'
           AND EXISTS (
               SELECT 1
               FROM command_output_capture_restart_recovery_receipts physical
               WHERE physical.receipt_digest = NEW.resolution_record_digest
                 AND physical.receipt_digest = json_extract(
                       CAST(NEW.clean_scan_resolution_receipt_json AS TEXT),
                       '$.restart_same_head_receipt.reconciliation_digest'
                     )
                 AND physical.capture_id = NEW.capture_id
                 AND physical.effect_id = NEW.effect_id
                 AND physical.intent_digest = NEW.intent_digest
                 AND physical.acquired_anchor_digest = NEW.acquired_anchor_digest
                 AND physical.observed_state = 'TerminalPrepared'
                 AND physical.store_head_generation = terminal.store_head_generation
                 AND physical.store_head_digest = terminal.store_head_digest
                 AND physical.recovered_at_unix_ms = terminal.anchored_at_unix_ms
                 AND physical.contract_version = NEW.contract_version
                 AND physical.layout_version = NEW.layout_version
           ))
      )
      AND intent.layout_version = NEW.layout_version
      AND intent.contract_version = NEW.contract_version
      AND acquired.contract_version = NEW.contract_version
      AND terminal.contract_version = NEW.contract_version
      AND claim.contract_version = NEW.contract_version
      AND policy.contract_version = NEW.contract_version
      AND json_extract(CAST(NEW.clean_scan_resolution_receipt_json AS TEXT),
                       '$.clean_scan_resolution_receipt_id') =
          NEW.clean_scan_resolution_receipt_id
      AND json_extract(CAST(NEW.clean_scan_resolution_receipt_json AS TEXT),
                       '$.intent.capture_id') = NEW.capture_id
      AND json_extract(CAST(NEW.clean_scan_resolution_receipt_json AS TEXT),
                       '$.intent.source.effect_id') = NEW.effect_id
      AND json_extract(CAST(NEW.clean_scan_resolution_receipt_json AS TEXT),
                       '$.intent.intent_digest') = NEW.intent_digest
      AND json_extract(CAST(NEW.clean_scan_resolution_receipt_json AS TEXT),
                       '$.acquired.acquired_anchor_digest') = NEW.acquired_anchor_digest
      AND json_extract(CAST(NEW.clean_scan_resolution_receipt_json AS TEXT),
                       '$.unknown_terminal.observation_id') = NEW.observation_id
      AND json_extract(CAST(NEW.clean_scan_resolution_receipt_json AS TEXT),
                       '$.unknown_terminal.terminal_anchor_digest') =
          NEW.terminal_anchor_digest
      AND json_extract(CAST(NEW.clean_scan_resolution_receipt_json AS TEXT),
                       '$.reconciliation_claim.claim_id') = NEW.reconciliation_claim_id
      AND json_extract(CAST(NEW.clean_scan_resolution_receipt_json AS TEXT),
                       '$.reconciliation_claim.fencing_token') =
          NEW.reconciliation_fencing_token
      AND json_extract(CAST(NEW.clean_scan_resolution_receipt_json AS TEXT),
                       '$.resolution.resolution_anchor_digest') =
          NEW.resolution_anchor_digest
      AND json_extract(CAST(NEW.clean_scan_resolution_receipt_json AS TEXT),
                       '$.resolution.artifact_reference.manifest_digest') =
          NEW.artifact_manifest_digest
      AND json_extract(CAST(NEW.clean_scan_resolution_receipt_json AS TEXT),
                       '$.resolution.store_head.generation') =
          NEW.resolution_store_head_generation
      AND json_extract(CAST(NEW.clean_scan_resolution_receipt_json AS TEXT),
                       '$.resolution.store_head.record_digest') =
          NEW.resolution_store_head_digest
      AND json_extract(CAST(NEW.clean_scan_resolution_receipt_json AS TEXT),
                       '$.resolution.resolution_record_digest') =
          NEW.resolution_record_digest
      AND json_extract(CAST(NEW.clean_scan_resolution_receipt_json AS TEXT),
                       '$.resolution.resolved_at_unix_ms') = NEW.resolved_at_unix_ms
      AND json_extract(CAST(NEW.clean_scan_resolution_receipt_json AS TEXT),
                       '$.detector_policy.policy_id') = NEW.detector_policy_id
      AND json_extract(CAST(NEW.clean_scan_resolution_receipt_json AS TEXT),
                       '$.detector_policy.policy_version') = NEW.detector_policy_version
      AND json_extract(CAST(NEW.clean_scan_resolution_receipt_json AS TEXT),
                       '$.detector_policy.policy_digest') = NEW.detector_policy_digest
      AND json_extract(CAST(NEW.clean_scan_resolution_receipt_json AS TEXT),
                       '$.clean_runner.journal_id') = NEW.runner_journal_id
      AND json_extract(CAST(NEW.clean_scan_resolution_receipt_json AS TEXT),
                       '$.clean_runner.terminal_prepared_journal_head.generation') =
          NEW.terminal_prepared_head_generation
      AND json_extract(CAST(NEW.clean_scan_resolution_receipt_json AS TEXT),
                       '$.clean_runner.terminal_prepared_journal_head.record_digest') =
          NEW.terminal_prepared_head_digest
      AND json_extract(CAST(NEW.clean_scan_resolution_receipt_json AS TEXT),
                       '$.clean_runner.terminal_prepared_store_head.generation') =
          NEW.terminal_prepared_store_head_generation
      AND json_extract(CAST(NEW.clean_scan_resolution_receipt_json AS TEXT),
                       '$.clean_runner.terminal_prepared_store_head.record_digest') =
          NEW.terminal_prepared_store_head_digest
      AND json_extract(CAST(NEW.clean_scan_resolution_receipt_json AS TEXT),
                       '$.clean_runner.terminal_prepared_at_unix_ms') =
          NEW.terminal_prepared_at_unix_ms
      AND json_extract(CAST(NEW.clean_scan_resolution_receipt_json AS TEXT),
                       '$.layout_version') = NEW.layout_version
      AND json_extract(CAST(NEW.clean_scan_resolution_receipt_json AS TEXT),
                       '$.contract_version') = NEW.contract_version
      AND json_extract(CAST(NEW.clean_scan_resolution_receipt_json AS TEXT),
                       '$.clean_scan_resolution_receipt_digest') =
          NEW.clean_scan_resolution_receipt_digest
      AND grok_sensitive_output_clean_scan_resolution_v29_digest(
              NEW.clean_scan_resolution_receipt_json
          ) = NEW.clean_scan_resolution_receipt_digest
)
BEGIN SELECT RAISE(ABORT, 'clean-scan resolution receipt must match exact current intent, acquisition, Unknown terminal, claim, policy, and typed physical branch'); END;

DROP TRIGGER command_output_current_unknown_resolution_requires_clean_scan_v29;
CREATE TRIGGER command_output_current_unknown_resolution_requires_clean_scan_v29
BEFORE INSERT ON command_output_capture_reconciliation_resolutions
WHEN EXISTS (
    SELECT 1
    FROM command_output_sensitive_detection_policy_admissions_v29 policy
    WHERE policy.capture_id = NEW.capture_id
      AND policy.effect_id = NEW.effect_id
) AND (
    (NEW.disposition = 'Published' AND NOT EXISTS (
        SELECT 1
        FROM command_output_clean_scan_resolution_receipts_v29 clean
        JOIN command_output_capture_terminal_anchors terminal
          ON terminal.terminal_anchor_digest = NEW.terminal_anchor_digest
         AND terminal.capture_id = NEW.capture_id
         AND terminal.effect_id = NEW.effect_id
         AND terminal.observation_id = NEW.observation_id
         AND terminal.observation_class = 'Unknown'
         AND terminal.disposition = 'ReconciliationRequired'
        JOIN command_output_capture_restart_recovery_receipts physical
          ON physical.receipt_digest = NEW.physical_recovery_receipt_digest
         AND physical.capture_id = NEW.capture_id
         AND physical.effect_id = NEW.effect_id
         AND physical.observed_state = 'TerminalPrepared'
        WHERE clean.capture_id = NEW.capture_id
          AND clean.effect_id = NEW.effect_id
          AND clean.observation_id = NEW.observation_id
          AND clean.terminal_anchor_digest = NEW.terminal_anchor_digest
          AND clean.reconciliation_claim_id = NEW.reconciliation_claim_id
          AND clean.reconciliation_fencing_token = NEW.reconciliation_fencing_token
          AND clean.resolution_anchor_digest = NEW.resolution_anchor_digest
          AND clean.artifact_manifest_digest = NEW.artifact_manifest_digest
          AND clean.resolution_store_head_generation = NEW.store_head_generation
          AND clean.resolution_store_head_digest = NEW.store_head_digest
          AND clean.resolution_record_digest = NEW.resolution_record_digest
          AND clean.resolved_at_unix_ms = NEW.resolved_at_unix_ms
          AND clean.layout_version = NEW.layout_version
          AND clean.contract_version = NEW.contract_version
          AND (
              (NEW.store_head_generation > terminal.store_head_generation
               AND physical.reconciliation_claim_id = NEW.reconciliation_claim_id
               AND physical.reconciliation_fencing_token =
                   NEW.reconciliation_fencing_token
               AND json_type(
                     CAST(clean.clean_scan_resolution_receipt_json AS TEXT),
                     '$.restart_same_head_receipt'
                   ) IS NULL)
              OR
              (NEW.store_head_generation = terminal.store_head_generation
               AND NEW.store_head_digest = terminal.store_head_digest
               AND NEW.resolution_record_digest = terminal.terminal_record_digest
               AND physical.receipt_digest = NEW.resolution_record_digest
               AND physical.receipt_digest = json_extract(
                     CAST(clean.clean_scan_resolution_receipt_json AS TEXT),
                     '$.restart_same_head_receipt.reconciliation_digest'
                   )
               AND physical.store_head_generation = terminal.store_head_generation
               AND physical.store_head_digest = terminal.store_head_digest
               AND physical.recovered_at_unix_ms = terminal.anchored_at_unix_ms
               AND json_type(
                     CAST(clean.clean_scan_resolution_receipt_json AS TEXT),
                     '$.restart_same_head_receipt'
                   ) = 'object')
          )
          AND json_extract(CAST(physical.receipt_json AS TEXT),
                           '$.lifecycle_history[1].store_head.generation') =
              json_extract(CAST(clean.clean_scan_resolution_receipt_json AS TEXT),
                           '$.clean_runner.acquired_store_head.generation')
          AND json_extract(CAST(physical.receipt_json AS TEXT),
                           '$.lifecycle_history[1].store_head.record_digest') =
              json_extract(CAST(clean.clean_scan_resolution_receipt_json AS TEXT),
                           '$.clean_runner.acquired_store_head.record_digest')
          AND json_extract(CAST(physical.receipt_json AS TEXT),
                           '$.lifecycle_history[2].store_head.generation') =
              json_extract(CAST(clean.clean_scan_resolution_receipt_json AS TEXT),
                           '$.clean_runner.writer_attached_store_head.generation')
          AND json_extract(CAST(physical.receipt_json AS TEXT),
                           '$.lifecycle_history[2].store_head.record_digest') =
              json_extract(CAST(clean.clean_scan_resolution_receipt_json AS TEXT),
                           '$.clean_runner.writer_attached_store_head.record_digest')
          AND json_extract(CAST(physical.receipt_json AS TEXT),
                           '$.lifecycle_history[3].store_head.generation') =
              json_extract(CAST(clean.clean_scan_resolution_receipt_json AS TEXT),
                           '$.clean_runner.launch_intended_store_head.generation')
          AND json_extract(CAST(physical.receipt_json AS TEXT),
                           '$.lifecycle_history[3].store_head.record_digest') =
              json_extract(CAST(clean.clean_scan_resolution_receipt_json AS TEXT),
                           '$.clean_runner.launch_intended_store_head.record_digest')
          AND json_extract(CAST(physical.receipt_json AS TEXT),
                           '$.lifecycle_history[4].store_head.generation') =
              json_extract(CAST(clean.clean_scan_resolution_receipt_json AS TEXT),
                           '$.clean_runner.finished_store_head.generation')
          AND json_extract(CAST(physical.receipt_json AS TEXT),
                           '$.lifecycle_history[4].store_head.record_digest') =
              json_extract(CAST(clean.clean_scan_resolution_receipt_json AS TEXT),
                           '$.clean_runner.finished_store_head.record_digest')
          AND json_extract(CAST(physical.receipt_json AS TEXT),
                           '$.lifecycle_history[5].store_head.generation') =
              json_extract(CAST(clean.clean_scan_resolution_receipt_json AS TEXT),
                           '$.clean_runner.published_store_head.generation')
          AND json_extract(CAST(physical.receipt_json AS TEXT),
                           '$.lifecycle_history[5].store_head.record_digest') =
              json_extract(CAST(clean.clean_scan_resolution_receipt_json AS TEXT),
                           '$.clean_runner.published_store_head.record_digest')
          AND json_extract(CAST(physical.receipt_json AS TEXT),
                           '$.lifecycle_history[6].store_head.generation') =
              clean.terminal_prepared_store_head_generation
          AND json_extract(CAST(physical.receipt_json AS TEXT),
                           '$.lifecycle_history[6].store_head.record_digest') =
              clean.terminal_prepared_store_head_digest
          AND grok_sensitive_output_clean_scan_resolution_v29_digest(
                  clean.clean_scan_resolution_receipt_json
              ) = clean.clean_scan_resolution_receipt_digest
    ))
    OR (NEW.disposition != 'Published' AND EXISTS (
        SELECT 1 FROM command_output_clean_scan_resolution_receipts_v29 clean
        WHERE clean.capture_id = NEW.capture_id OR clean.effect_id = NEW.effect_id
    ))
)
BEGIN SELECT RAISE(ABORT, 'current-policy Unknown publication requires exact clean-scan resolution receipt'); END;

DROP VIEW command_output_clean_scan_resolution_exact_v29;
CREATE VIEW command_output_clean_scan_resolution_exact_v29 AS
SELECT clean.effect_id,
       clean.capture_id,
       clean.observation_id,
       clean.clean_scan_resolution_receipt_digest,
       clean.terminal_anchor_digest,
       clean.resolution_anchor_digest,
       clean.contract_version
FROM command_output_clean_scan_resolution_receipts_v29 clean
JOIN command_output_capture_intents intent
  ON intent.capture_id = clean.capture_id
 AND intent.effect_id = clean.effect_id
 AND intent.intent_digest = clean.intent_digest
JOIN command_output_capture_acquisitions acquired
  ON acquired.acquired_anchor_digest = clean.acquired_anchor_digest
 AND acquired.capture_id = intent.capture_id
 AND acquired.effect_id = intent.effect_id
JOIN command_output_capture_terminal_anchors terminal
  ON terminal.terminal_anchor_digest = clean.terminal_anchor_digest
 AND terminal.capture_id = intent.capture_id
 AND terminal.effect_id = intent.effect_id
 AND terminal.observation_id = clean.observation_id
 AND terminal.observation_class = 'Unknown'
 AND terminal.disposition = 'ReconciliationRequired'
 AND terminal.acquired_anchor_digest = acquired.acquired_anchor_digest
 AND terminal.artifact_manifest_digest IS NULL
 AND terminal.artifact_reference_json IS NULL
JOIN command_output_capture_reconciliation_claims claim
  ON claim.claim_id = clean.reconciliation_claim_id
 AND claim.capture_id = intent.capture_id
 AND claim.fencing_token = clean.reconciliation_fencing_token
JOIN command_output_capture_reconciliation_resolutions resolution
  ON resolution.resolution_anchor_digest = clean.resolution_anchor_digest
 AND resolution.capture_id = intent.capture_id
 AND resolution.effect_id = intent.effect_id
 AND resolution.observation_id = terminal.observation_id
 AND resolution.terminal_anchor_digest = terminal.terminal_anchor_digest
 AND resolution.reconciliation_claim_id = claim.claim_id
 AND resolution.reconciliation_fencing_token = claim.fencing_token
 AND resolution.disposition = 'Published'
 AND resolution.artifact_manifest_digest = clean.artifact_manifest_digest
 AND resolution.store_head_generation = clean.resolution_store_head_generation
 AND resolution.store_head_digest = clean.resolution_store_head_digest
 AND resolution.resolution_record_digest = clean.resolution_record_digest
 AND resolution.resolved_at_unix_ms = clean.resolved_at_unix_ms
JOIN command_output_capture_restart_recovery_receipts physical
  ON physical.receipt_digest = resolution.physical_recovery_receipt_digest
 AND physical.capture_id = intent.capture_id
 AND physical.effect_id = intent.effect_id
 AND physical.observed_state = 'TerminalPrepared'
JOIN command_output_sensitive_detection_policy_admissions_v29 policy
  ON policy.capture_id = intent.capture_id
 AND policy.effect_id = intent.effect_id
 AND policy.policy_id = clean.detector_policy_id
 AND policy.policy_version = clean.detector_policy_version
 AND policy.policy_digest = clean.detector_policy_digest
WHERE clean.contract_version = intent.contract_version
  AND clean.contract_version = acquired.contract_version
  AND clean.contract_version = terminal.contract_version
  AND clean.contract_version = claim.contract_version
  AND clean.contract_version = resolution.contract_version
  AND clean.contract_version = physical.contract_version
  AND clean.contract_version = policy.contract_version
  AND clean.layout_version = intent.layout_version
  AND clean.layout_version = terminal.layout_version
  AND clean.layout_version = resolution.layout_version
  AND clean.layout_version = physical.layout_version
  AND (
      (clean.resolution_store_head_generation > terminal.store_head_generation
       AND clean.resolution_record_digest = clean.resolution_store_head_digest
       AND physical.reconciliation_claim_id = claim.claim_id
       AND physical.reconciliation_fencing_token = claim.fencing_token
       AND json_type(
             CAST(clean.clean_scan_resolution_receipt_json AS TEXT),
             '$.restart_same_head_receipt'
           ) IS NULL)
      OR
      (clean.resolution_store_head_generation = terminal.store_head_generation
       AND clean.resolution_store_head_digest = terminal.store_head_digest
       AND clean.resolution_record_digest = terminal.terminal_record_digest
       AND physical.receipt_digest = clean.resolution_record_digest
       AND physical.receipt_digest = json_extract(
             CAST(clean.clean_scan_resolution_receipt_json AS TEXT),
             '$.restart_same_head_receipt.reconciliation_digest'
           )
       AND physical.store_head_generation = terminal.store_head_generation
       AND physical.store_head_digest = terminal.store_head_digest
       AND physical.recovered_at_unix_ms = terminal.anchored_at_unix_ms
       AND json_type(
             CAST(clean.clean_scan_resolution_receipt_json AS TEXT),
             '$.restart_same_head_receipt'
           ) = 'object')
  )
  AND clean.terminal_prepared_store_head_generation = resolution.store_head_generation
  AND clean.terminal_prepared_store_head_digest = resolution.store_head_digest
  AND clean.terminal_prepared_at_unix_ms <= resolution.resolved_at_unix_ms
  AND json_extract(CAST(physical.receipt_json AS TEXT),
                   '$.lifecycle_history[1].store_head.generation') =
      json_extract(CAST(clean.clean_scan_resolution_receipt_json AS TEXT),
                   '$.clean_runner.acquired_store_head.generation')
  AND json_extract(CAST(physical.receipt_json AS TEXT),
                   '$.lifecycle_history[1].store_head.record_digest') =
      json_extract(CAST(clean.clean_scan_resolution_receipt_json AS TEXT),
                   '$.clean_runner.acquired_store_head.record_digest')
  AND json_extract(CAST(physical.receipt_json AS TEXT),
                   '$.lifecycle_history[2].store_head.generation') =
      json_extract(CAST(clean.clean_scan_resolution_receipt_json AS TEXT),
                   '$.clean_runner.writer_attached_store_head.generation')
  AND json_extract(CAST(physical.receipt_json AS TEXT),
                   '$.lifecycle_history[2].store_head.record_digest') =
      json_extract(CAST(clean.clean_scan_resolution_receipt_json AS TEXT),
                   '$.clean_runner.writer_attached_store_head.record_digest')
  AND json_extract(CAST(physical.receipt_json AS TEXT),
                   '$.lifecycle_history[3].store_head.generation') =
      json_extract(CAST(clean.clean_scan_resolution_receipt_json AS TEXT),
                   '$.clean_runner.launch_intended_store_head.generation')
  AND json_extract(CAST(physical.receipt_json AS TEXT),
                   '$.lifecycle_history[3].store_head.record_digest') =
      json_extract(CAST(clean.clean_scan_resolution_receipt_json AS TEXT),
                   '$.clean_runner.launch_intended_store_head.record_digest')
  AND json_extract(CAST(physical.receipt_json AS TEXT),
                   '$.lifecycle_history[4].store_head.generation') =
      json_extract(CAST(clean.clean_scan_resolution_receipt_json AS TEXT),
                   '$.clean_runner.finished_store_head.generation')
  AND json_extract(CAST(physical.receipt_json AS TEXT),
                   '$.lifecycle_history[4].store_head.record_digest') =
      json_extract(CAST(clean.clean_scan_resolution_receipt_json AS TEXT),
                   '$.clean_runner.finished_store_head.record_digest')
  AND json_extract(CAST(physical.receipt_json AS TEXT),
                   '$.lifecycle_history[5].store_head.generation') =
      json_extract(CAST(clean.clean_scan_resolution_receipt_json AS TEXT),
                   '$.clean_runner.published_store_head.generation')
  AND json_extract(CAST(physical.receipt_json AS TEXT),
                   '$.lifecycle_history[5].store_head.record_digest') =
      json_extract(CAST(clean.clean_scan_resolution_receipt_json AS TEXT),
                   '$.clean_runner.published_store_head.record_digest')
  AND json_extract(CAST(physical.receipt_json AS TEXT),
                   '$.lifecycle_history[6].store_head.generation') =
      clean.terminal_prepared_store_head_generation
  AND json_extract(CAST(physical.receipt_json AS TEXT),
                   '$.lifecycle_history[6].store_head.record_digest') =
      clean.terminal_prepared_store_head_digest
  AND grok_sensitive_output_policy_v29_canonical(policy.policy_json) = 'ok'
  AND grok_sensitive_output_clean_scan_resolution_v29_digest(
          clean.clean_scan_resolution_receipt_json
      ) = clean.clean_scan_resolution_receipt_digest
  AND NOT EXISTS (
      SELECT 1 FROM pre_v29_sensitive_output_policy_exemptions exemption
      WHERE exemption.effect_id = clean.effect_id OR exemption.capture_id = clean.capture_id
  )
  AND NOT EXISTS (
      SELECT 1 FROM command_output_clean_scan_publication_receipts_v29 direct
      WHERE direct.effect_id = clean.effect_id OR direct.capture_id = clean.capture_id
  )
  AND NOT EXISTS (
      SELECT 1 FROM command_output_sensitive_rejection_anchors_v29 rejection
      WHERE rejection.effect_id = clean.effect_id OR rejection.capture_id = clean.capture_id
  );
