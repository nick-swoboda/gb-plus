pub(super) fn sprint_exists(connection: &Connection, sprint_id: &str) -> rusqlite::Result<bool> {
    connection
        .query_row(
            "SELECT 1 FROM sprints WHERE sprint_id = ?1",
            [sprint_id],
            |_| Ok(()),
        )
        .optional()
        .map(|value| value.is_some())
}

pub(super) fn ensure_new_sprint(
    connection: &Connection,
    sprint_id: &str,
) -> Result<(), LedgerError> {
    if sprint_exists(connection, sprint_id)? {
        Err(LedgerError::SprintAlreadyExists(sprint_id.to_owned()))
    } else {
        Ok(())
    }
}

pub(super) fn validate_draft_base_snapshot(
    spec: &SprintSpec,
    base_snapshot: &WorkspaceSnapshot,
    created_at_unix_ms: u64,
) -> Result<(), LedgerError> {
    if created_at_unix_ms == 0 {
        return Err(LedgerError::InvalidTimestamp("created_at_unix_ms"));
    }
    if base_snapshot.snapshot_id != spec.base_snapshot {
        return Err(reference_mismatch(
            "draft sprint",
            "workspace snapshot does not match sprint.base_snapshot",
        ));
    }
    if base_snapshot.grant_hash != spec.workspace_grant.grant_hash {
        return Err(reference_mismatch(
            "draft sprint",
            "workspace snapshot grant does not match the sprint grant",
        ));
    }
    if base_snapshot.created_at_unix_ms > created_at_unix_ms {
        return Err(reference_mismatch(
            "draft sprint",
            "workspace snapshot was created after the sprint",
        ));
    }
    Ok(())
}

pub(super) fn insert_sprint_definition(
    transaction: &Transaction<'_>,
    spec: &SprintSpec,
    created_at_unix_ms: u64,
) -> Result<(), LedgerError> {
    transaction.execute(
        "INSERT INTO sprints (
            sprint_id, contract_version, spec_json, graph_json, created_at_unix_ms
         ) VALUES (?1, ?2, ?3, ?4, ?5)",
        params![
            spec.sprint_id,
            i64::from(CONTRACT_VERSION),
            encode("sprint specification", spec)?,
            Vec::<u8>::new(),
            sqlite_integer("created_at_unix_ms", created_at_unix_ms)?
        ],
    )?;
    Ok(())
}

pub(super) fn insert_sprint_planning_state(
    transaction: &Transaction<'_>,
    spec: &SprintSpec,
) -> Result<(), LedgerError> {
    transaction.execute(
        "INSERT INTO sprint_planning_states (
            sprint_id, base_snapshot, contract_version
         ) VALUES (?1, ?2, ?3)",
        params![
            spec.sprint_id,
            spec.base_snapshot.as_str(),
            i64::from(CONTRACT_VERSION)
        ],
    )?;
    Ok(())
}

pub(super) fn insert_direct_graph_provenance(
    transaction: &Transaction<'_>,
    sprint_id: &str,
) -> Result<(), LedgerError> {
    transaction.execute(
        "INSERT INTO sprint_graph_provenance (
            sprint_id, provenance_kind, effect_id, observation_id,
            response_digest, contract_version
         ) VALUES (?1, 'DirectTrusted', NULL, NULL, NULL, ?2)",
        params![sprint_id, i64::from(CONTRACT_VERSION)],
    )?;
    Ok(())
}

pub(super) fn persisted_or_current_completion_receipt_digest(
    connection: &Connection,
    receipt: &CompletionReceipt,
) -> Result<Digest, LedgerError> {
    let stored = connection
        .query_row(
            "SELECT receipt_json FROM v9_completion_receipts
             WHERE receipt_id = ?1 AND sprint_id = ?2",
            params![receipt.receipt_id, receipt.sprint_id],
            |row| row.get::<_, Vec<u8>>(0),
        )
        .optional()?;
    let Some(stored) = stored else {
        // Eligibility and link derivation run before the parent receipt is
        // inserted. Current ledgers author the v28 vocabulary; exact historical
        // test ledgers must reproduce the vocabulary and digest their schema
        // generation actually authored.
        return if human_acceptance_claim_schema_is_installed(connection)? {
            Ok(receipt.receipt_digest()?)
        } else {
            Ok(Digest::sha256(&encode_legacy_completion_receipt(receipt)?))
        };
    };
    canonical_stored_completion_receipt_digest(receipt, &stored)?.ok_or_else(|| {
        LedgerError::Corrupt {
            entity: "completion receipt",
            detail: "stored receipt bytes are not either canonical completion encoding".into(),
        }
    })
}

pub(super) fn insert_completion_live_state_capture_link(
    transaction: &Transaction<'_>,
    link: &CompletionLiveStateCaptureLink,
) -> Result<(), LedgerError> {
    link.validate()?;
    let (application_kind, integration_id, application_id, rollback_id, no_op_id) =
        match &link.application {
            CompletionLiveStateApplicationLink::Applied {
                application_receipt_id,
                rollback_reference_id,
            } => (
                "Applied",
                None,
                Some(application_receipt_id.as_str()),
                Some(rollback_reference_id.as_str()),
                None,
            ),
            CompletionLiveStateApplicationLink::VerifiedNoOp {
                verified_no_op_receipt_id,
                task_integration_receipt_id,
            } => (
                "VerifiedNoOp",
                Some(task_integration_receipt_id.as_str()),
                None,
                None,
                Some(verified_no_op_receipt_id.as_str()),
            ),
        };
    transaction.execute(
        "INSERT INTO sprint_completion_live_state_capture_links (
            completion_receipt_id, sprint_id, completion_receipt_digest,
            capture_receipt_id, capture_admission_id, capture_plan_id,
            capture_plan_digest, capture_effect_id, capture_observation_id,
            capture_dispatch_claim_id, runner_launch_id, runner_session_id,
            verifier_cleanup_receipt_id, final_snapshot, expected_snapshot,
            observed_snapshot, manifest_digest, grant_hash, policy_hash,
            policy_version, final_verification_receipt_id, application_kind,
            task_integration_receipt_id, application_receipt_id,
            rollback_reference_id, verified_no_op_receipt_id,
            capture_started_at_unix_ms, captured_at_unix_ms,
            verifier_cleaned_at_unix_ms, completed_at_unix_ms,
            contract_version, link_json
         ) VALUES (
            ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12,
            ?13, ?14, ?15, ?16, ?17, ?18, ?19, ?20, ?21, ?22, ?23,
            ?24, ?25, ?26, ?27, ?28, ?29, ?30, ?31, ?32
         )",
        params![
            link.completion_receipt_id,
            link.sprint_id,
            link.completion_receipt_digest.as_str(),
            link.capture.capture_receipt_id,
            link.capture.admission_id,
            link.capture.plan_id,
            link.capture.plan_digest.as_str(),
            link.capture.effect_id,
            link.capture.observation_id,
            link.capture.dispatch_claim_id,
            link.capture.runner_launch_id,
            link.capture.runner_session_id,
            link.verifier_cleanup_receipt_id,
            link.final_snapshot.as_str(),
            link.capture.expected_snapshot.as_str(),
            link.capture.observed_snapshot.as_str(),
            link.capture.manifest_digest.as_str(),
            link.grant_hash.as_str(),
            link.policy_hash.as_str(),
            i64::from(link.policy_version),
            link.final_verification_receipt_id,
            application_kind,
            integration_id,
            application_id,
            rollback_id,
            no_op_id,
            sqlite_integer(
                "completion_capture_link.capture_started_at_unix_ms",
                link.capture_started_at_unix_ms,
            )?,
            sqlite_integer(
                "completion_capture_link.captured_at_unix_ms",
                link.captured_at_unix_ms,
            )?,
            sqlite_integer(
                "completion_capture_link.verifier_cleaned_at_unix_ms",
                link.verifier_cleaned_at_unix_ms,
            )?,
            sqlite_integer(
                "completion_capture_link.completed_at_unix_ms",
                link.completed_at_unix_ms,
            )?,
            i64::from(link.contract_version),
            encode("completion live-state capture link", link)?,
        ],
    )?;
    Ok(())
}

pub(super) fn insert_successful_completion_parent_children_and_terminal(
    transaction: &Transaction<'_>,
    receipt: &CompletionReceipt,
    event: &AgentEvent,
) -> Result<(), LedgerError> {
    insert_completion_receipt(transaction, receipt)?;
    for (ordinal, cleanup_receipt_id) in receipt.worker_cleanup_receipt_ids.iter().enumerate() {
        transaction.execute(
            "INSERT INTO v9_completion_cleanup_receipts (
                completion_receipt_id, sprint_id, ordinal, cleanup_receipt_id
             ) VALUES (?1, ?2, ?3, ?4)",
            params![
                receipt.receipt_id,
                receipt.sprint_id,
                i64::try_from(ordinal)
                    .map_err(|_| LedgerError::IntegerOutOfRange("cleanup ordinal"))?,
                cleanup_receipt_id,
            ],
        )?;
    }
    for (ordinal, verification_receipt_id) in receipt.verification_receipts.iter().enumerate() {
        transaction.execute(
            "INSERT INTO v9_completion_verification_receipts (
                completion_receipt_id, sprint_id, ordinal, verification_receipt_id
             ) VALUES (?1, ?2, ?3, ?4)",
            params![
                receipt.receipt_id,
                receipt.sprint_id,
                i64::try_from(ordinal)
                    .map_err(|_| LedgerError::IntegerOutOfRange("verification ordinal"))?,
                verification_receipt_id,
            ],
        )?;
    }
    for (ordinal, integration_receipt_id) in receipt.task_integration_receipt_ids.iter().enumerate()
    {
        transaction.execute(
            "INSERT INTO v9_completion_task_integration_receipts (
                completion_receipt_id, sprint_id, ordinal, integration_receipt_id
             ) VALUES (?1, ?2, ?3, ?4)",
            params![
                receipt.receipt_id,
                receipt.sprint_id,
                i64::try_from(ordinal)
                    .map_err(|_| LedgerError::IntegerOutOfRange("task integration ordinal"))?,
                integration_receipt_id,
            ],
        )?;
    }
    for (ordinal, criterion_evidence_receipt_id) in
        receipt.criterion_evidence_receipt_ids.iter().enumerate()
    {
        let ordinal = i64::try_from(ordinal)
            .map_err(|_| LedgerError::IntegerOutOfRange("criterion evidence ordinal"))?;
        if human_acceptance_claim_schema_is_installed(transaction)? {
            transaction.execute(
                "INSERT INTO v28_completion_criterion_evidence_receipts (
                    completion_receipt_id, sprint_id, ordinal,
                    criterion_evidence_receipt_id
                 ) VALUES (?1, ?2, ?3, ?4)",
                params![
                    receipt.receipt_id,
                    receipt.sprint_id,
                    ordinal,
                    criterion_evidence_receipt_id,
                ],
            )?;
        } else {
            transaction.execute(
                "INSERT INTO v9_completion_acceptance_receipts (
                    completion_receipt_id, sprint_id, ordinal,
                    acceptance_receipt_id
                 ) VALUES (?1, ?2, ?3, ?4)",
                params![
                    receipt.receipt_id,
                    receipt.sprint_id,
                    ordinal,
                    criterion_evidence_receipt_id,
                ],
            )?;
        }
    }
    insert_agent_event(transaction, event)?;
    transaction.execute(
        "INSERT INTO sprint_completion_proof_states (
            sprint_id, proof_state, completion_receipt_id,
            completion_event_id, contract_version, terminal_at_unix_ms
         ) VALUES (?1, 'ProvenV9', ?2, ?3, ?4, ?5)",
        params![
            receipt.sprint_id,
            receipt.receipt_id,
            event.event_id,
            i64::from(CONTRACT_VERSION),
            sqlite_integer(
                "completion_receipt.completed_at_unix_ms",
                receipt.completed_at_unix_ms,
            )?,
        ],
    )?;
    Ok(())
}

#[allow(clippy::too_many_lines)] // Indexed columns and the full envelope are compared together.
pub(super) fn load_completion_receipt_envelope_from(
    connection: &Connection,
    receipt_id: &str,
) -> Result<CompletionReceipt, LedgerError> {
    let stored = connection
        .query_row(
            "SELECT sprint_id, final_snapshot, grant_hash, policy_version,
                    final_verification_receipt_id, application_kind,
                    application_receipt_id, rollback_reference_id,
                    verified_no_op_receipt_id, final_report_id,
                    provider_backend, provider_model,
                    contract_version, completed_at_unix_ms, receipt_json
             FROM v9_completion_receipts WHERE receipt_id = ?1",
            [receipt_id],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, String>(5)?,
                    row.get::<_, Option<String>>(6)?,
                    row.get::<_, Option<String>>(7)?,
                    row.get::<_, Option<String>>(8)?,
                    row.get::<_, String>(9)?,
                    row.get::<_, String>(10)?,
                    row.get::<_, String>(11)?,
                    row.get::<_, i64>(12)?,
                    row.get::<_, i64>(13)?,
                    row.get::<_, Vec<u8>>(14)?,
                ))
            },
        )
        .optional()?
        .ok_or_else(|| LedgerError::ArtifactNotFound {
            entity: "completion receipt",
            id: receipt_id.to_owned(),
        })?;
    require_contract_version("completion receipt", stored.12)?;
    let receipt: CompletionReceipt = decode_stored("completion receipt", &stored.14)?;
    receipt.validate().map_err(|error| LedgerError::Corrupt {
        entity: "completion receipt",
        detail: error.to_string(),
    })?;
    let stored_completed = unsigned_integer("completion_receipt.completed_at_unix_ms", stored.13)?;
    let application_columns_match = match &receipt.application {
        CompletionApplication::Applied {
            application_receipt_id,
            rollback_reference_id,
        } => {
            stored.5 == "Applied"
                && stored.6.as_deref() == Some(application_receipt_id)
                && stored.7.as_deref() == Some(rollback_reference_id)
                && stored.8.is_none()
        }
        CompletionApplication::VerifiedNoOp {
            verified_no_op_receipt_id,
        } => {
            stored.5 == "VerifiedNoOp"
                && stored.6.is_none()
                && stored.7.is_none()
                && stored.8.as_deref() == Some(verified_no_op_receipt_id)
        }
    };
    if canonical_stored_completion_receipt_digest(&receipt, &stored.14)?.is_none()
        || receipt.receipt_id != receipt_id
        || receipt.sprint_id != stored.0
        || receipt.final_snapshot.as_str() != stored.1
        || receipt.grant_hash.as_str() != stored.2
        || i64::from(receipt.policy_version) != stored.3
        || receipt.final_verification_receipt_id != stored.4
        || !application_columns_match
        || receipt.final_report_id != stored.9
        || receipt.provider_backend != stored.10
        || receipt.provider_model != stored.11
        || receipt.completed_at_unix_ms != stored_completed
    {
        return Err(LedgerError::Corrupt {
            entity: "completion receipt",
            detail: "receipt envelope disagrees with indexed columns".into(),
        });
    }
    Ok(receipt)
}

#[allow(clippy::too_many_lines)] // Child links and all referenced evidence are revalidated together.
pub(super) fn load_completion_receipt_from(
    connection: &Connection,
    receipt_id: &str,
) -> Result<CompletionReceipt, LedgerError> {
    let receipt = load_completion_receipt_envelope_from(connection, receipt_id)?;
    let linked_cleanup = load_ordered_completion_links(
        connection,
        "SELECT ordinal, sprint_id, cleanup_receipt_id
         FROM v9_completion_cleanup_receipts
         WHERE completion_receipt_id = ?1
         ORDER BY ordinal ASC",
        receipt_id,
        &receipt.sprint_id,
        "completion cleanup links",
    )?;
    if linked_cleanup != receipt.worker_cleanup_receipt_ids {
        return Err(LedgerError::Corrupt {
            entity: "completion receipt",
            detail: "ordered cleanup links disagree with the receipt envelope".into(),
        });
    }

    let linked_verifications = load_ordered_completion_links(
        connection,
        "SELECT ordinal, sprint_id, verification_receipt_id
         FROM v9_completion_verification_receipts
         WHERE completion_receipt_id = ?1
         ORDER BY ordinal ASC",
        receipt_id,
        &receipt.sprint_id,
        "completion verification links",
    )?;
    if linked_verifications != receipt.verification_receipts {
        return Err(LedgerError::Corrupt {
            entity: "completion receipt",
            detail: "ordered verification links disagree with the receipt envelope".into(),
        });
    }

    let linked_integrations = load_ordered_completion_links(
        connection,
        "SELECT ordinal, sprint_id, integration_receipt_id
         FROM v9_completion_task_integration_receipts
         WHERE completion_receipt_id = ?1
         ORDER BY ordinal ASC",
        receipt_id,
        &receipt.sprint_id,
        "completion task-integration links",
    )?;
    if linked_integrations != receipt.task_integration_receipt_ids {
        return Err(LedgerError::Corrupt {
            entity: "completion receipt",
            detail: "ordered task-integration links disagree with the receipt envelope".into(),
        });
    }

    let legacy_acceptance = completion_uses_legacy_acceptance_links(connection, receipt_id)?;
    if human_acceptance_claim_schema_is_installed(connection)? {
        let crossed_link_family = if legacy_acceptance {
            connection
                .query_row(
                    "SELECT 1 FROM v28_completion_criterion_evidence_receipts
                     WHERE completion_receipt_id = ?1 LIMIT 1",
                    [receipt_id],
                    |_| Ok(()),
                )
                .optional()?
                .is_some()
        } else {
            connection
                .query_row(
                    "SELECT 1 FROM v9_completion_acceptance_receipts
                     WHERE completion_receipt_id = ?1 LIMIT 1",
                    [receipt_id],
                    |_| Ok(()),
                )
                .optional()?
                .is_some()
        };
        if crossed_link_family {
            return Err(LedgerError::Corrupt {
                entity: "completion receipt",
                detail: "legacy and current criterion-evidence link families are crossed".into(),
            });
        }
    }
    let linked_criterion_evidence = if legacy_acceptance {
        load_ordered_completion_links(
            connection,
            "SELECT ordinal, sprint_id, acceptance_receipt_id
             FROM v9_completion_acceptance_receipts
             WHERE completion_receipt_id = ?1
             ORDER BY ordinal ASC",
            receipt_id,
            &receipt.sprint_id,
            "legacy completion acceptance links",
        )?
    } else {
        load_ordered_completion_links(
            connection,
            "SELECT ordinal, sprint_id, criterion_evidence_receipt_id
             FROM v28_completion_criterion_evidence_receipts
             WHERE completion_receipt_id = ?1
             ORDER BY ordinal ASC",
            receipt_id,
            &receipt.sprint_id,
            "completion criterion-evidence links",
        )?
    };
    if linked_criterion_evidence != receipt.criterion_evidence_receipt_ids {
        return Err(LedgerError::Corrupt {
            entity: "completion receipt",
            detail: "ordered criterion-evidence links disagree with the receipt envelope".into(),
        });
    }
    let report = load_final_report_from(connection, &receipt.final_report_id)?;
    validate_completion_evidence(connection, &report, &receipt)?;
    validate_finish_receipt_registry(
        connection,
        receipt_id,
        &receipt.sprint_id,
        "Completion",
        receipt.contract_version,
    )?;
    Ok(receipt)
}

pub(super) fn human_acceptance_claim_schema_is_installed(
    connection: &Connection,
) -> Result<bool, LedgerError> {
    Ok(connection
        .query_row(
            "SELECT 1 FROM sqlite_schema
             WHERE type = 'table'
               AND name = 'criterion_evidence_receipts_v2'",
            [],
            |_| Ok(()),
        )
        .optional()?
        .is_some())
}

pub(super) fn completion_uses_legacy_acceptance_links(
    connection: &Connection,
    completion_receipt_id: &str,
) -> Result<bool, LedgerError> {
    if !human_acceptance_claim_schema_is_installed(connection)? {
        return Ok(true);
    }
    Ok(connection
        .query_row(
            "SELECT 1 FROM v28_legacy_completion_acceptance_sets
             WHERE completion_receipt_id = ?1",
            [completion_receipt_id],
            |_| Ok(()),
        )
        .optional()?
        .is_some())
}

pub(super) fn completion_live_state_capture_authority_schema_is_installed(
    connection: &Connection,
) -> Result<bool, LedgerError> {
    Ok(connection
        .query_row(
            "SELECT 1 FROM sqlite_schema
             WHERE type = 'table'
               AND name = 'sprint_completion_live_state_capture_links'",
            [],
            |_| Ok(()),
        )
        .optional()?
        .is_some())
}

pub(super) fn command_output_artifact_set_schema_is_installed(
    connection: &Connection,
) -> Result<bool, LedgerError> {
    Ok(connection
        .query_row(
            "SELECT 1 FROM sqlite_schema
             WHERE type = 'table' AND name = 'command_output_artifact_sets'",
            [],
            |_| Ok(()),
        )
        .optional()?
        .is_some())
}

pub(super) fn validate_verification_evidence_write_contract(
    connection: &Connection,
    evidence: &VerificationEffectEvidence,
) -> Result<(), LedgerError> {
    if command_output_artifact_set_schema_is_installed(connection)? {
        evidence.validate_current()?;
    } else {
        evidence.validate()?;
        if evidence.output_artifacts.is_some() {
            return Err(reference_mismatch(
                "verification effect evidence",
                "pre-v26 schemas cannot persist an unindexed command output artifact reference",
            ));
        }
    }
    Ok(())
}

#[allow(clippy::too_many_lines)] // Every normalized link column is authenticated here.
pub(super) fn load_completion_live_state_capture_link_envelope_from(
    connection: &Connection,
    completion_receipt_id: &str,
) -> Result<Option<CompletionLiveStateCaptureLink>, LedgerError> {
    let bytes = connection
        .query_row(
            "SELECT link_json FROM sprint_completion_live_state_capture_links
             WHERE completion_receipt_id = ?1",
            [completion_receipt_id],
            |row| row.get::<_, Vec<u8>>(0),
        )
        .optional()?;
    let Some(bytes) = bytes else {
        return Ok(None);
    };
    let link: CompletionLiveStateCaptureLink =
        decode_stored("completion live-state capture link", &bytes)?;
    link.validate().map_err(|error| LedgerError::Corrupt {
        entity: "completion live-state capture link",
        detail: error.to_string(),
    })?;
    if encode("completion live-state capture link", &link)? != bytes {
        return Err(LedgerError::Corrupt {
            entity: "completion live-state capture link",
            detail: "stored link JSON is not the exact canonical envelope".into(),
        });
    }
    let (application_kind, integration_id, application_id, rollback_id, no_op_id) =
        match &link.application {
            CompletionLiveStateApplicationLink::Applied {
                application_receipt_id,
                rollback_reference_id,
            } => (
                "Applied",
                None,
                Some(application_receipt_id.as_str()),
                Some(rollback_reference_id.as_str()),
                None,
            ),
            CompletionLiveStateApplicationLink::VerifiedNoOp {
                verified_no_op_receipt_id,
                task_integration_receipt_id,
            } => (
                "VerifiedNoOp",
                Some(task_integration_receipt_id.as_str()),
                None,
                None,
                Some(verified_no_op_receipt_id.as_str()),
            ),
        };
    let exact = connection
        .query_row(
            "SELECT 1 FROM sprint_completion_live_state_capture_links
             WHERE completion_receipt_id = ?1
               AND sprint_id = ?2
               AND completion_receipt_digest = ?3
               AND capture_receipt_id = ?4
               AND capture_admission_id = ?5
               AND capture_plan_id = ?6
               AND capture_plan_digest = ?7
               AND capture_effect_id = ?8
               AND capture_observation_id = ?9
               AND capture_dispatch_claim_id = ?10
               AND runner_launch_id = ?11
               AND runner_session_id = ?12
               AND verifier_cleanup_receipt_id = ?13
               AND final_snapshot = ?14
               AND expected_snapshot = ?15
               AND observed_snapshot = ?16
               AND manifest_digest = ?17
               AND grant_hash = ?18
               AND policy_hash = ?19
               AND policy_version = ?20
               AND final_verification_receipt_id = ?21
               AND application_kind = ?22
               AND task_integration_receipt_id IS ?23
               AND application_receipt_id IS ?24
               AND rollback_reference_id IS ?25
               AND verified_no_op_receipt_id IS ?26
               AND capture_started_at_unix_ms = ?27
               AND captured_at_unix_ms = ?28
               AND verifier_cleaned_at_unix_ms = ?29
               AND completed_at_unix_ms = ?30
               AND contract_version = ?31",
            params![
                link.completion_receipt_id,
                link.sprint_id,
                link.completion_receipt_digest.as_str(),
                link.capture.capture_receipt_id,
                link.capture.admission_id,
                link.capture.plan_id,
                link.capture.plan_digest.as_str(),
                link.capture.effect_id,
                link.capture.observation_id,
                link.capture.dispatch_claim_id,
                link.capture.runner_launch_id,
                link.capture.runner_session_id,
                link.verifier_cleanup_receipt_id,
                link.final_snapshot.as_str(),
                link.capture.expected_snapshot.as_str(),
                link.capture.observed_snapshot.as_str(),
                link.capture.manifest_digest.as_str(),
                link.grant_hash.as_str(),
                link.policy_hash.as_str(),
                i64::from(link.policy_version),
                link.final_verification_receipt_id,
                application_kind,
                integration_id,
                application_id,
                rollback_id,
                no_op_id,
                sqlite_integer(
                    "completion_capture_link.capture_started_at_unix_ms",
                    link.capture_started_at_unix_ms,
                )?,
                sqlite_integer(
                    "completion_capture_link.captured_at_unix_ms",
                    link.captured_at_unix_ms,
                )?,
                sqlite_integer(
                    "completion_capture_link.verifier_cleaned_at_unix_ms",
                    link.verifier_cleaned_at_unix_ms,
                )?,
                sqlite_integer(
                    "completion_capture_link.completed_at_unix_ms",
                    link.completed_at_unix_ms,
                )?,
                i64::from(link.contract_version),
            ],
            |_| Ok(()),
        )
        .optional()?
        .is_some();
    if !exact || link.completion_receipt_id != completion_receipt_id {
        return Err(LedgerError::Corrupt {
            entity: "completion live-state capture link",
            detail: "canonical link disagrees with one or more normalized columns".into(),
        });
    }
    Ok(Some(link))
}

pub(super) fn load_pre_v24_completion_live_state_capture_exemption_from(
    connection: &Connection,
    receipt: &CompletionReceipt,
) -> Result<Option<PreV24CompletionLiveStateCaptureExemption>, LedgerError> {
    let stored = connection
        .query_row(
            "SELECT completion_event_id, completion_receipt_digest,
                    terminal_at_unix_ms, contract_version,
                    marked_at_schema_version
             FROM pre_v24_completion_live_state_capture_exemptions
             WHERE sprint_id = ?1 AND completion_receipt_id = ?2",
            params![receipt.sprint_id, receipt.receipt_id],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, i64>(4)?,
                ))
            },
        )
        .optional()?;
    let Some(stored) = stored else {
        return Ok(None);
    };
    require_contract_version("pre-v24 completion capture exemption", stored.3)?;
    let exemption = PreV24CompletionLiveStateCaptureExemption {
        sprint_id: receipt.sprint_id.clone(),
        completion_receipt_id: receipt.receipt_id.clone(),
        completion_event_id: stored.0,
        completion_receipt_digest: Digest::parse(stored.1).map_err(|error| {
            LedgerError::Corrupt {
                entity: "pre-v24 completion capture exemption",
                detail: error.to_string(),
            }
        })?,
        terminal_at_unix_ms: unsigned_integer(
            "pre_v24_completion_capture_exemption.terminal_at_unix_ms",
            stored.2,
        )?,
        contract_version: u32::try_from(stored.3)
            .map_err(|_| LedgerError::IntegerOutOfRange("pre-v24 exemption version"))?,
        marked_at_schema_version: u32::try_from(stored.4)
            .map_err(|_| LedgerError::IntegerOutOfRange("pre-v24 marked schema version"))?,
    };
    let event = load_event_by_id(connection, &exemption.completion_event_id)?;
    validate_completion_event_shape(&event, receipt)?;
    let proof_matches = connection
        .query_row(
            "SELECT 1 FROM sprint_completion_proof_states
             WHERE sprint_id = ?1 AND proof_state = 'ProvenV9'
               AND completion_receipt_id = ?2
               AND completion_event_id = ?3
               AND terminal_at_unix_ms = ?4
               AND contract_version = ?5",
            params![
                exemption.sprint_id,
                exemption.completion_receipt_id,
                exemption.completion_event_id,
                sqlite_integer(
                    "pre_v24_completion_capture_exemption.terminal_at_unix_ms",
                    exemption.terminal_at_unix_ms,
                )?,
                i64::from(exemption.contract_version),
            ],
            |_| Ok(()),
        )
        .optional()?
        .is_some();
    if exemption.marked_at_schema_version != 24
        || exemption.completion_receipt_digest
            != persisted_or_current_completion_receipt_digest(connection, receipt)?
        || exemption.terminal_at_unix_ms != receipt.completed_at_unix_ms
        || exemption.contract_version != receipt.contract_version
        || !proof_matches
    {
        return Err(LedgerError::Corrupt {
            entity: "pre-v24 completion capture exemption",
            detail: "migration exemption disagrees with the exact receipt, event, or proof state"
                .into(),
        });
    }
    Ok(Some(exemption))
}

pub(super) fn load_selected_live_state_verifier_cleanup_from(
    connection: &Connection,
    capture: &LiveStateCaptureEvidence,
) -> Result<WorkerCleanupEvidence, LedgerError> {
    let receipt_id = connection
        .query_row(
            "SELECT receipt_id FROM worker_cleanup_receipts
             WHERE sprint_id = ?1 AND launch_id = ?2 AND session_id = ?3",
            params![
                capture.receipt.sprint_id,
                capture.receipt.runner_launch_id,
                capture.receipt.runner_session_id,
            ],
            |row| row.get::<_, String>(0),
        )
        .optional()?
        .ok_or_else(|| LedgerError::ArtifactNotFound {
            entity: "selected live-state verifier cleanup",
            id: capture.receipt.runner_launch_id.clone(),
        })?;
    load_worker_cleanup_evidence_from(connection, &receipt_id)
}

pub(super) fn effect_terminal_event_sequence(
    connection: &Connection,
    sprint_id: &str,
    effect_id: &str,
    observation_id: &str,
) -> Result<u64, LedgerError> {
    let sequence = connection
        .query_row(
            "SELECT event.sequence
             FROM effect_observations observation
             JOIN agent_events event
               ON event.event_id = observation.terminal_event_id
              AND event.sprint_id = observation.sprint_id
             WHERE observation.sprint_id = ?1
               AND observation.effect_id = ?2
               AND observation.observation_id = ?3",
            params![sprint_id, effect_id, observation_id],
            |row| row.get::<_, i64>(0),
        )
        .optional()?
        .ok_or_else(|| LedgerError::Corrupt {
            entity: "completion live-state event order",
            detail: format!("effect '{effect_id}' lacks its exact terminal event"),
        })?;
    unsigned_integer("completion_live_state_event.sequence", sequence)
}

pub(super) fn validate_linked_completion_event_order(
    connection: &Connection,
    authority: &PersistedCompletionLiveStateAuthority,
    completion_event: &AgentEvent,
) -> Result<(), LedgerError> {
    let PersistedCompletionLiveStateAuthority::Linked {
        link,
        capture_evidence,
        verifier_cleanup_evidence,
    } = authority
    else {
        return Ok(());
    };
    let capture_sequence = effect_terminal_event_sequence(
        connection,
        &link.sprint_id,
        &capture_evidence.receipt.effect_id,
        &capture_evidence.receipt.observation_id,
    )?;
    let cleanup_sequence = effect_terminal_event_sequence(
        connection,
        &link.sprint_id,
        &verifier_cleanup_evidence.receipt.effect_id,
        &verifier_cleanup_evidence.receipt.observation_id,
    )?;
    if capture_sequence >= cleanup_sequence || cleanup_sequence >= completion_event.sequence {
        return Err(reference_mismatch(
            "completion live-state event order",
            "capture terminal must precede verifier-cleanup terminal, which must precede completion",
        ));
    }
    Ok(())
}

pub(super) fn validate_no_authorized_mutation_after_capture(
    connection: &Connection,
    capture: &LiveStateCaptureReceipt,
) -> Result<(), LedgerError> {
    let blocked: i64 = connection.query_row(
        "WITH semantic_effects AS (
             SELECT intent.sprint_id, intent.effect_id,
                    COALESCE(kind.effect_kind, intent.effect_kind) AS semantic_kind,
                    intent.proposed_event_id, observation.observation_id,
                    observation.outcome, observation.observed_at_unix_ms,
                    observation.terminal_event_id
             FROM effect_intents intent
             LEFT JOIN finish_effect_kinds kind
               ON kind.effect_id = intent.effect_id AND kind.sprint_id = intent.sprint_id
             LEFT JOIN effect_observations observation
               ON observation.effect_id = intent.effect_id
              AND observation.sprint_id = intent.sprint_id
         )
         SELECT EXISTS (
             SELECT 1
             FROM effect_intents capture_intent
             JOIN agent_events capture_proposed_event
               ON capture_proposed_event.event_id = capture_intent.proposed_event_id
              AND capture_proposed_event.sprint_id = capture_intent.sprint_id
             JOIN semantic_effects mutation
               ON mutation.sprint_id = capture_intent.sprint_id
             JOIN agent_events proposed_event
               ON proposed_event.event_id = mutation.proposed_event_id
             LEFT JOIN agent_events terminal_event
               ON terminal_event.event_id = mutation.terminal_event_id
             WHERE capture_intent.effect_id = ?1
               AND capture_intent.sprint_id = ?2
               AND mutation.semantic_kind IN (
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
                           OR mutation.observed_at_unix_ms > ?3
                       )
                   )
               )
         )",
        params![
            capture.effect_id,
            capture.sprint_id,
            sqlite_integer(
                "live_state_capture_receipt.capture_started_at_unix_ms",
                capture.capture_started_at_unix_ms,
            )?,
        ],
        |row| row.get(0),
    )?;
    if blocked != 0 {
        return Err(reference_mismatch(
            "completion live-state capture link",
            "an unresolved, unknown, or authorized workspace mutation crosses the selected capture cut",
        ));
    }
    Ok(())
}

pub(super) fn derive_completion_live_state_capture_link_from(
    connection: &Connection,
    receipt: &CompletionReceipt,
    capture_receipt_id: &str,
) -> Result<CompletionLiveStateCaptureLink, LedgerError> {
    let capture = load_live_state_capture_evidence_from(connection, capture_receipt_id)?;
    let verifier_cleanup = load_selected_live_state_verifier_cleanup_from(connection, &capture)?;
    derive_completion_live_state_capture_link_from_evidence(
        connection,
        receipt,
        &capture,
        &verifier_cleanup,
    )
}

#[allow(clippy::too_many_lines)] // The v24 cut is intentionally rederived in one closed join.
pub(super) fn derive_completion_live_state_capture_link_from_evidence(
    connection: &Connection,
    receipt: &CompletionReceipt,
    capture: &LiveStateCaptureEvidence,
    verifier_cleanup: &WorkerCleanupEvidence,
) -> Result<CompletionLiveStateCaptureLink, LedgerError> {
    receipt.validate()?;
    capture.validate()?;
    verifier_cleanup.validate()?;
    let capture_receipt = &capture.receipt;
    let cleanup_receipt = &verifier_cleanup.receipt;
    let plan = load_sprint_live_state_capture_plan_from(connection, &capture_receipt.plan_id)?;
    let plan_final_verification_receipt_id = match &plan.branch {
        LiveStateCaptureBranch::Applied {
            final_verification_receipt_id,
            ..
        }
        | LiveStateCaptureBranch::VerifiedNoOp {
            final_verification_receipt_id,
            ..
        } => final_verification_receipt_id,
        LiveStateCaptureBranch::KnownPreApplicationTerminal { .. } => {
            return Err(LedgerError::Corrupt {
                entity: "completion live-state capture link",
                detail: "reserved terminal capture branch cannot authorize completion".into(),
            });
        }
    };
    if receipt.sprint_id != capture_receipt.sprint_id
        || receipt.sprint_id != plan.sprint_id
        || receipt.final_snapshot != plan.expected_snapshot
        || receipt.final_snapshot != capture_receipt.expected_snapshot
        || receipt.final_snapshot != capture_receipt.observed_snapshot
        || receipt.final_snapshot != capture_receipt.manifest_digest
        || receipt.grant_hash != plan.grant_hash
        || receipt.grant_hash != capture_receipt.grant_hash
        || receipt.policy_version != plan.policy_version
        || receipt.policy_version != capture_receipt.policy_version
        || capture_receipt.policy_hash != plan.policy_hash
        || receipt.final_verification_receipt_id.as_str()
            != plan_final_verification_receipt_id.as_str()
        || cleanup_receipt.sprint_id != receipt.sprint_id
        || cleanup_receipt.launch_id != capture_receipt.runner_launch_id
        || cleanup_receipt.session_id != capture_receipt.runner_session_id
        || cleanup_receipt.grant_hash != receipt.grant_hash
        || cleanup_receipt.policy_hash != capture_receipt.policy_hash
        || cleanup_receipt.policy_version != receipt.policy_version
        || cleanup_receipt.surviving_processes != 0
        || cleanup_receipt.cleaned_at_unix_ms < capture_receipt.captured_at_unix_ms
        || cleanup_receipt.cleaned_at_unix_ms > receipt.completed_at_unix_ms
    {
        return Err(reference_mismatch(
            "completion live-state capture link",
            "capture, plan, cleanup, snapshot, grant, policy, verification, or time differs",
        ));
    }
    let mut expected_cleanup_ids = plan
        .required_cleanup_receipt_ids
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>();
    if !expected_cleanup_ids.insert(cleanup_receipt.receipt_id.clone())
        || expected_cleanup_ids
            != receipt
                .worker_cleanup_receipt_ids
                .iter()
                .cloned()
                .collect::<BTreeSet<_>>()
        || expected_cleanup_ids.len() != receipt.worker_cleanup_receipt_ids.len()
    {
        return Err(reference_mismatch(
            "completion live-state capture link",
            "completion cleanup links are not exactly the plan-prior set plus selected verifier cleanup",
        ));
    }
    for cleanup_id in &plan.required_cleanup_receipt_ids {
        let cleanup = load_worker_cleanup_evidence_from(connection, cleanup_id)?;
        if cleanup.receipt.cleaned_at_unix_ms > capture_receipt.capture_started_at_unix_ms {
            return Err(reference_mismatch(
                "completion live-state capture link",
                "a plan-prior cleanup occurs after descriptor capture began",
            ));
        }
    }
    let application = match (&receipt.application, &plan.branch) {
        (
            CompletionApplication::Applied {
                application_receipt_id,
                rollback_reference_id,
            },
            LiveStateCaptureBranch::Applied {
                application_receipt_id: plan_application_id,
                rollback_reference_id: plan_rollback_id,
                ..
            },
        ) if application_receipt_id == plan_application_id
            && rollback_reference_id == plan_rollback_id =>
        {
            let application = load_application_evidence_from(connection, application_receipt_id)?;
            if application.receipt.result_snapshot != receipt.final_snapshot
                || application.receipt.applied_at_unix_ms
                    > capture_receipt.capture_started_at_unix_ms
            {
                return Err(reference_mismatch(
                    "completion live-state capture link",
                    "selected application result or application/capture ordering differs",
                ));
            }
            CompletionLiveStateApplicationLink::Applied {
                application_receipt_id: application_receipt_id.clone(),
                rollback_reference_id: rollback_reference_id.clone(),
            }
        }
        (
            CompletionApplication::VerifiedNoOp {
                verified_no_op_receipt_id,
            },
            LiveStateCaptureBranch::VerifiedNoOp {
                task_integration_receipt_id,
                ..
            },
        ) => {
            if !receipt
                .task_integration_receipt_ids
                .iter()
                .any(|id| id == task_integration_receipt_id)
            {
                return Err(reference_mismatch(
                    "completion live-state capture link",
                    "verified no-op completion omits the plan's exact TaskDone integration",
                ));
            }
            CompletionLiveStateApplicationLink::VerifiedNoOp {
                verified_no_op_receipt_id: verified_no_op_receipt_id.clone(),
                task_integration_receipt_id: task_integration_receipt_id.clone(),
            }
        }
        _ => {
            return Err(reference_mismatch(
                "completion live-state capture link",
                "completion branch differs from the selected capture plan branch",
            ));
        }
    };
    let capture_terminal_sequence = effect_terminal_event_sequence(
        connection,
        &receipt.sprint_id,
        &capture_receipt.effect_id,
        &capture_receipt.observation_id,
    )?;
    let cleanup_terminal_sequence = effect_terminal_event_sequence(
        connection,
        &receipt.sprint_id,
        &cleanup_receipt.effect_id,
        &cleanup_receipt.observation_id,
    )?;
    if capture_terminal_sequence >= cleanup_terminal_sequence {
        return Err(reference_mismatch(
            "completion live-state event order",
            "capture terminal event must precede selected verifier-cleanup terminal event",
        ));
    }
    validate_no_authorized_mutation_after_capture(connection, capture_receipt)?;
    let link = CompletionLiveStateCaptureLink {
        contract_version: CONTRACT_VERSION,
        sprint_id: receipt.sprint_id.clone(),
        completion_receipt_id: receipt.receipt_id.clone(),
        completion_receipt_digest: persisted_or_current_completion_receipt_digest(
            connection, receipt,
        )?,
        final_snapshot: receipt.final_snapshot.clone(),
        grant_hash: receipt.grant_hash.clone(),
        policy_hash: capture_receipt.policy_hash.clone(),
        policy_version: receipt.policy_version,
        final_verification_receipt_id: receipt.final_verification_receipt_id.clone(),
        application,
        capture: CompletionLiveStateCaptureAuthority {
            capture_receipt_id: capture_receipt.receipt_id.clone(),
            admission_id: capture_receipt.admission_id.clone(),
            plan_id: capture_receipt.plan_id.clone(),
            plan_digest: capture_receipt.plan_digest.clone(),
            effect_id: capture_receipt.effect_id.clone(),
            observation_id: capture_receipt.observation_id.clone(),
            dispatch_claim_id: capture_receipt.dispatch_claim_id.clone(),
            runner_launch_id: capture_receipt.runner_launch_id.clone(),
            runner_session_id: capture_receipt.runner_session_id.clone(),
            expected_snapshot: capture_receipt.expected_snapshot.clone(),
            observed_snapshot: capture_receipt.observed_snapshot.clone(),
            manifest_digest: capture_receipt.manifest_digest.clone(),
        },
        verifier_cleanup_receipt_id: cleanup_receipt.receipt_id.clone(),
        capture_started_at_unix_ms: capture_receipt.capture_started_at_unix_ms,
        captured_at_unix_ms: capture_receipt.captured_at_unix_ms,
        verifier_cleaned_at_unix_ms: cleanup_receipt.cleaned_at_unix_ms,
        completed_at_unix_ms: receipt.completed_at_unix_ms,
    };
    link.validate()?;
    Ok(link)
}

pub(super) fn classify_completion_live_state_authority(
    connection: &Connection,
    receipt: &CompletionReceipt,
) -> Result<PersistedCompletionLiveStateAuthority, LedgerError> {
    if !completion_live_state_capture_authority_schema_is_installed(connection)? {
        return Err(LedgerError::Corrupt {
            entity: "completion live-state authority",
            detail: "schema-v24 completion authority tables are absent".into(),
        });
    }
    let link =
        load_completion_live_state_capture_link_envelope_from(connection, &receipt.receipt_id)?;
    let exemption = load_pre_v24_completion_live_state_capture_exemption_from(connection, receipt)?;
    match (link, exemption) {
        (Some(link), None) => {
            let capture = load_live_state_capture_evidence_from(
                connection,
                &link.capture.capture_receipt_id,
            )?;
            let cleanup =
                load_worker_cleanup_evidence_from(connection, &link.verifier_cleanup_receipt_id)?;
            let derived = derive_completion_live_state_capture_link_from_evidence(
                connection, receipt, &capture, &cleanup,
            )?;
            if derived != link {
                return Err(LedgerError::Corrupt {
                    entity: "completion live-state capture link",
                    detail: "stored link differs from exact durable rederivation".into(),
                });
            }
            let authority = PersistedCompletionLiveStateAuthority::Linked {
                link,
                capture_evidence: capture,
                verifier_cleanup_evidence: cleanup,
            };
            let completion_event_id = connection
                .query_row(
                    "SELECT completion_event_id FROM sprint_completion_proof_states
                     WHERE sprint_id = ?1 AND proof_state = 'ProvenV9'
                       AND completion_receipt_id = ?2",
                    params![receipt.sprint_id, receipt.receipt_id],
                    |row| row.get::<_, String>(0),
                )
                .optional()?
                .ok_or_else(|| LedgerError::Corrupt {
                    entity: "completion live-state event order",
                    detail: "linked completion lacks its exact proof-state event".into(),
                })?;
            let completion_event = load_event_by_id(connection, &completion_event_id)?;
            validate_completion_event_shape(&completion_event, receipt)?;
            validate_linked_completion_event_order(connection, &authority, &completion_event)?;
            Ok(authority)
        }
        (None, Some(exemption)) => {
            Ok(PersistedCompletionLiveStateAuthority::PreV24MigrationExemption(exemption))
        }
        (Some(_), Some(_)) => Err(LedgerError::Corrupt {
            entity: "completion live-state authority",
            detail: "completion has both current link and pre-v24 exemption authority".into(),
        }),
        (None, None) => Err(LedgerError::Corrupt {
            entity: "completion live-state authority",
            detail: "completion has neither current link nor pre-v24 exemption authority".into(),
        }),
    }
}

pub(super) fn load_ordered_completion_links(
    connection: &Connection,
    sql: &str,
    completion_receipt_id: &str,
    expected_sprint_id: &str,
    entity: &'static str,
) -> Result<Vec<String>, LedgerError> {
    let mut statement = connection.prepare(sql)?;
    let mut rows = statement.query([completion_receipt_id])?;
    let mut linked = Vec::new();
    let mut expected_ordinal = 0_i64;
    while let Some(row) = rows.next()? {
        let ordinal: i64 = row.get(0)?;
        let linked_sprint: String = row.get(1)?;
        let linked_id: String = row.get(2)?;
        if ordinal != expected_ordinal {
            return Err(LedgerError::Corrupt {
                entity,
                detail: "link ordinals are not contiguous from zero".into(),
            });
        }
        if linked_sprint != expected_sprint_id {
            return Err(LedgerError::Corrupt {
                entity,
                detail: "link sprint disagrees with the completion receipt".into(),
            });
        }
        linked.push(linked_id);
        expected_ordinal = expected_ordinal
            .checked_add(1)
            .ok_or(LedgerError::IntegerOutOfRange("completion link ordinal"))?;
    }
    Ok(linked)
}

pub(super) fn require_current_completion_verification_evidence(
    connection: &Connection,
    receipt: &CompletionReceipt,
) -> Result<(), LedgerError> {
    for receipt_id in &receipt.verification_receipts {
        let evidence = load_verification_effect_evidence_from(connection, receipt_id)?;
        evidence.validate_current().map_err(|error| {
            reference_mismatch(
                "successful completion writer",
                format!(
                    "verification evidence '{receipt_id}' cannot mint current completion authority: {error}"
                ),
            )
        })?;
    }
    Ok(())
}

pub(super) fn validate_completion_evidence(
    connection: &Connection,
    report: &FinalReport,
    receipt: &CompletionReceipt,
) -> Result<(), LedgerError> {
    if completion_live_state_capture_authority_schema_is_installed(connection)? {
        let authority = classify_completion_live_state_authority(connection, receipt)?;
        validate_completion_evidence_with_authority(
            connection,
            report,
            receipt,
            Some(&authority),
            None,
        )
    } else {
        validate_completion_evidence_with_authority(connection, report, receipt, None, None)
    }
}

#[allow(
    clippy::too_many_lines,
    reason = "completion validation deliberately retains the complete conjunction in one authority-aware audit boundary"
)]
pub(super) fn validate_completion_evidence_with_authority(
    connection: &Connection,
    report: &FinalReport,
    receipt: &CompletionReceipt,
    authority: Option<&PersistedCompletionLiveStateAuthority>,
    supplied_linked_no_op: Option<&VerifiedNoOpReceipt>,
) -> Result<(), LedgerError> {
    worker_lease_authority::require_no_active(connection, &receipt.sprint_id)?;
    validate_task_attempt_completion_predicate(connection, receipt)?;
    let (spec, graph, _) = load_sprint_inputs(connection, &receipt.sprint_id)?;
    if report.sprint_id != receipt.sprint_id
        || report.report_id != receipt.final_report_id
        || report.final_snapshot != receipt.final_snapshot
    {
        return Err(reference_mismatch(
            "completion receipt",
            "final report identity, sprint, or snapshot does not match",
        ));
    }
    if report.created_at_unix_ms > receipt.completed_at_unix_ms {
        return Err(reference_mismatch(
            "completion receipt",
            "final report was created after the completion timestamp",
        ));
    }
    if receipt.provider_backend != spec.provider.backend_id
        || receipt.provider_model != spec.provider.model_id
        || receipt.grant_hash != spec.workspace_grant.grant_hash
        || receipt.policy_version != spec.workspace_grant.policy_version
    {
        return Err(reference_mismatch(
            "completion receipt",
            "provider backend or model does not match the sprint specification",
        ));
    }
    load_workspace_snapshot_from(connection, &receipt.sprint_id, &receipt.final_snapshot)?;

    let final_verification =
        load_verification_effect_evidence_from(connection, &receipt.final_verification_receipt_id)?
            .verification;
    if final_verification.sprint_id != receipt.sprint_id
        || final_verification.task_id.is_some()
        || !final_verification.passed()
        || final_verification.snapshot_id != receipt.final_snapshot
    {
        return Err(reference_mismatch(
            "completion receipt",
            "final verification does not pass on the exact completion snapshot",
        ));
    }
    let final_session =
        load_verification_session_binding(connection, &receipt.sprint_id, &final_verification)?;
    if final_session.purpose != RunnerSessionPurpose::FinalVerifier {
        return Err(reference_mismatch(
            "completion receipt",
            "final verification is not bound to a final-verifier runner session",
        ));
    }
    let cleanup = validate_completion_cleanup_set(connection, receipt)?;
    let requires_v16_evidence = completion_requires_v16_evidence(connection, receipt)?;
    if requires_v16_evidence && command_domain_cleanup::schema_is_installed(connection)? {
        validate_completion_command_domain_cleanup(connection, receipt, &cleanup)?;
    }
    match authority {
        None | Some(PersistedCompletionLiveStateAuthority::PreV24MigrationExemption(_)) => {
            if supplied_linked_no_op.is_some() {
                return Err(reference_mismatch(
                    "completion receipt",
                    "migration-exempt completion cannot carry current linked no-op evidence",
                ));
            }
            validate_completion_application(
                connection,
                &spec,
                receipt,
                &final_verification,
                &cleanup,
            )?;
        }
        Some(PersistedCompletionLiveStateAuthority::Linked {
            link,
            capture_evidence,
            verifier_cleanup_evidence,
        }) => {
            if link.verifier_cleaned_at_unix_ms > report.created_at_unix_ms
                || report.created_at_unix_ms > receipt.completed_at_unix_ms
            {
                return Err(reference_mismatch(
                    "completion receipt",
                    "current final report must follow selected verifier cleanup and precede completion",
                ));
            }
            validate_linked_completion_application(
                connection,
                &spec,
                receipt,
                &final_verification,
                &cleanup,
                link,
                capture_evidence,
                verifier_cleanup_evidence,
                supplied_linked_no_op,
            )?;
        }
    }
    let rollback_exists = connection
        .query_row(
            "SELECT 1 FROM rollback_receipts WHERE sprint_id = ?1 LIMIT 1",
            [&receipt.sprint_id],
            |_| Ok(()),
        )
        .optional()?
        .is_some();
    let conflict_exists = connection
        .query_row(
            "SELECT 1 FROM live_conflict_receipts WHERE sprint_id = ?1 LIMIT 1",
            [&receipt.sprint_id],
            |_| Ok(()),
        )
        .optional()?
        .is_some();
    if rollback_exists || conflict_exists {
        return Err(reference_mismatch(
            "completion receipt",
            "a rolled-back or live-conflicted application cannot complete",
        ));
    }

    if requires_v16_evidence && task_attempt_authority::schema_is_installed(connection)? {
        validate_completion_task_done_closure(connection, receipt, &graph)?;
    }

    validate_completion_acceptance(connection, &spec, receipt)?;
    validate_completion_tasks(connection, &spec, &graph, receipt, &final_verification)?;
    validate_completion_verifications(connection, receipt)
}

/// Recomputes the task-graph part of `CompletionEligible` from exact durable
/// task proofs. Integration identity alone is not finish authority: each
/// required receipt must be the winner named by `TaskDone`. An unattempted
/// optional task is irrelevant to finish. An attempted optional task must have
/// a safe terminal latest disposition and all global effect, launch, cleanup,
/// release, and lease predicates checked by the surrounding completion
/// validator. Optional integration is admissible outside the required-task
/// chain only when its exact `TaskDone` winner is a represented no-op.
pub(super) fn validate_completion_task_done_closure(
    connection: &Connection,
    receipt: &CompletionReceipt,
    graph: &TaskGraph,
) -> Result<(), LedgerError> {
    let strict_v22 = completion_requires_v22_task_links(connection, receipt)?;
    if strict_v22 {
        return validate_completion_task_done_closure_v22(connection, receipt, graph);
    }

    let mut integration_by_task = BTreeMap::new();
    for integration_receipt_id in &receipt.task_integration_receipt_ids {
        let integration = load_task_integration_receipt_from(connection, integration_receipt_id)?;
        if integration_by_task
            .insert(integration.task_id.clone(), integration.receipt_id)
            .is_some()
        {
            return Err(reference_mismatch(
                "completion receipt",
                "multiple integration receipts claim one graph task",
            ));
        }
    }

    for task in &graph.tasks {
        let history =
            load_task_attempt_history_from(connection, &receipt.sprint_id, &task.task_id)?;
        if task.required {
            let assessment =
                task_done::assess_task_done_from(connection, &receipt.sprint_id, &task.task_id)?;
            let proof = assessment
                .proof
                .as_ref()
                .filter(|_| assessment.is_done())
                .ok_or_else(|| {
                    reference_mismatch(
                        "completion receipt",
                        format!(
                            "required task '{}' is not TaskDone: {:?}",
                            task.task_id, assessment.unmet_requirements
                        ),
                    )
                })?;
            if integration_by_task.get(&task.task_id) != Some(&proof.integration_receipt.receipt_id)
            {
                return Err(reference_mismatch(
                    "completion receipt",
                    format!(
                        "required task '{}' completion link is not its exact TaskDone winner",
                        task.task_id
                    ),
                ));
            }
        } else if !history.attempts.is_empty() {
            validate_attempted_optional_task_closure(
                connection,
                &receipt.sprint_id,
                &task.task_id,
                &history,
            )?;
        }
    }
    Ok(())
}

pub(super) fn completion_requires_v22_task_links(
    connection: &Connection,
    receipt: &CompletionReceipt,
) -> Result<bool, LedgerError> {
    let schema_v22 = connection
        .query_row(
            "SELECT 1 FROM sqlite_schema
             WHERE type = 'table' AND name = 'pre_v22_completion_authority_exemptions'",
            [],
            |_| Ok(()),
        )
        .optional()?
        .is_some();
    if !schema_v22 {
        return Ok(false);
    }
    Ok(connection
        .query_row(
            "SELECT 1 FROM pre_v22_completion_authority_exemptions
             WHERE sprint_id = ?1 AND completion_receipt_id = ?2",
            params![receipt.sprint_id, receipt.receipt_id],
            |_| Ok(()),
        )
        .optional()?
        .is_none())
}

/// Schema-v22 completion authority: every integrated graph task, required or
/// optional and including represented no-ops, must link its exact `TaskDone`
/// winner. The linked receipts themselves must be the complete contiguous
/// ordinal/snapshot chain from sprint base to completion final snapshot.
pub(super) fn validate_completion_task_done_closure_v22(
    connection: &Connection,
    receipt: &CompletionReceipt,
    graph: &TaskGraph,
) -> Result<(), LedgerError> {
    let (spec, _, _) = load_sprint_inputs(connection, &receipt.sprint_id)?;
    let mut integration_by_task = BTreeMap::new();
    let mut ordered_integrations = Vec::new();
    for (expected_ordinal, integration_receipt_id) in
        receipt.task_integration_receipt_ids.iter().enumerate()
    {
        let integration = load_task_integration_receipt_from(connection, integration_receipt_id)?;
        if graph.task(&integration.task_id).is_none()
            || usize::try_from(integration.integration_ordinal).ok() != Some(expected_ordinal)
            || integration_by_task
                .insert(integration.task_id.clone(), integration.receipt_id.clone())
                .is_some()
        {
            return Err(reference_mismatch(
                "completion receipt",
                "v22 task links must be unique graph tasks in contiguous integration-ordinal order",
            ));
        }
        let expected_base = ordered_integrations
            .last()
            .map_or(&spec.base_snapshot, |prior: &TaskIntegrationReceipt| {
                &prior.result_snapshot
            });
        if &integration.input_snapshot != expected_base {
            return Err(reference_mismatch(
                "completion receipt",
                "v22 integration links do not form one contiguous chain from sprint base",
            ));
        }
        ordered_integrations.push(integration);
    }

    let mut integrated_task_count = 0_usize;
    for task in &graph.tasks {
        let history =
            load_task_attempt_history_from(connection, &receipt.sprint_id, &task.task_id)?;
        if history.task_state == TaskState::Integrated {
            integrated_task_count = integrated_task_count
                .checked_add(1)
                .ok_or(LedgerError::IntegerOutOfRange("v22 integrated task count"))?;
            let assessment =
                task_done::assess_task_done_from(connection, &receipt.sprint_id, &task.task_id)?;
            let proof = assessment
                .proof
                .as_ref()
                .filter(|_| assessment.is_done())
                .ok_or_else(|| {
                    reference_mismatch(
                        "completion receipt",
                        format!(
                            "integrated task '{}' is not TaskDone: {:?}",
                            task.task_id, assessment.unmet_requirements
                        ),
                    )
                })?;
            if integration_by_task.get(&task.task_id) != Some(&proof.integration_receipt.receipt_id)
            {
                return Err(reference_mismatch(
                    "completion receipt",
                    format!(
                        "integrated task '{}' is not linked to its exact TaskDone winner",
                        task.task_id
                    ),
                ));
            }
        } else if task.required {
            return Err(reference_mismatch(
                "completion receipt",
                format!("required task '{}' is not integrated", task.task_id),
            ));
        } else if !history.attempts.is_empty() {
            validate_attempted_optional_task_closure(
                connection,
                &receipt.sprint_id,
                &task.task_id,
                &history,
            )?;
        }
    }
    if integration_by_task.len() != integrated_task_count {
        return Err(reference_mismatch(
            "completion receipt",
            "v22 completion must link every and only integrated graph task",
        ));
    }
    let chain_result = ordered_integrations
        .last()
        .map_or(&spec.base_snapshot, |integration| {
            &integration.result_snapshot
        });
    if chain_result != &receipt.final_snapshot {
        return Err(reference_mismatch(
            "completion receipt",
            "v22 complete integration chain does not end at the completion final snapshot",
        ));
    }
    Ok(())
}

pub(super) fn validate_attempted_optional_task_closure(
    connection: &Connection,
    sprint_id: &str,
    task_id: &str,
    history: &TaskAttemptHistory,
) -> Result<(), LedgerError> {
    if history
        .attempts
        .iter()
        .any(|entry| entry.disposition.is_none())
    {
        return Err(reference_mismatch(
            "attempted optional task closure",
            format!("attempted optional task '{task_id}' has an undisposed attempt"),
        ));
    }
    if history
        .attempts
        .iter()
        .take(history.attempts.len().saturating_sub(1))
        .any(|entry| {
            !matches!(
                entry.disposition,
                Some(TaskAttemptDisposition::Retryable(_))
            )
        })
    {
        return Err(reference_mismatch(
            "attempted optional task closure",
            format!(
                "attempted optional task '{task_id}' has a non-retryable disposition before its latest attempt"
            ),
        ));
    }
    let latest = history
        .attempts
        .last()
        .and_then(|entry| entry.disposition.as_ref())
        .ok_or_else(|| {
            reference_mismatch(
                "attempted optional task closure",
                format!("attempted optional task '{task_id}' lacks a latest disposition"),
            )
        })?;

    let safely_terminal = matches!(
        (history.task_state, latest),
        (
            TaskState::Failed,
            TaskAttemptDisposition::AttemptsExhausted(_)
                | TaskAttemptDisposition::PermanentFailure(_)
        ) | (TaskState::Blocked, TaskAttemptDisposition::Blocked(_))
            | (TaskState::Canceled, TaskAttemptDisposition::Canceled(_))
    );
    if safely_terminal {
        return Ok(());
    }

    if history.task_state == TaskState::Integrated
        && matches!(latest, TaskAttemptDisposition::Integrated(_))
    {
        let assessment = task_done::assess_task_done_from(connection, sprint_id, task_id)?;
        let proof = assessment
            .proof
            .as_ref()
            .filter(|_| assessment.is_done())
            .ok_or_else(|| {
                reference_mismatch(
                    "attempted optional task closure",
                    format!(
                        "integrated optional task '{task_id}' is not globally closed TaskDone: {:?}",
                        assessment.unmet_requirements
                    ),
                )
            })?;
        if !proof.change_set.operations.is_empty()
            || proof.change_set.base_snapshot != proof.change_set.result_snapshot
            || proof.integration_receipt.input_snapshot != proof.integration_receipt.result_snapshot
        {
            return Err(reference_mismatch(
                "attempted optional task closure",
                format!(
                    "integrated optional task '{task_id}' may be omitted only as an exact represented no-op"
                ),
            ));
        }
        return Ok(());
    }

    Err(reference_mismatch(
        "attempted optional task closure",
        format!(
            "attempted optional task '{task_id}' is not safely terminal: state {:?}, disposition {latest:?}",
            history.task_state
        ),
    ))
}

pub(super) fn require_all_task_scoped_effects_terminal_known(
    connection: &Connection,
    sprint_id: &str,
) -> Result<(), LedgerError> {
    for effect in load_effects_from(connection, sprint_id, false)? {
        let task_runner_bound = connection.query_row(
            "SELECT EXISTS(
                 SELECT 1
                 FROM effect_session_bindings binding
                 JOIN runner_launch_intents launch
                   ON launch.sprint_id = binding.sprint_id
                  AND launch.launch_id = binding.launch_id
                 WHERE binding.effect_id = ?1
                   AND binding.sprint_id = ?2
                   AND launch.purpose = 'TaskWorker'
             )",
            params![effect.intent.effect_id, sprint_id],
            |row| row.get::<_, bool>(0),
        )?;
        let task_scoped = effect.intent.task_id.is_some()
            || effect.intent.worker_lease.is_some()
            || task_runner_bound;
        if task_scoped
            && !effect.observation.as_ref().is_some_and(|observation| {
                !matches!(observation.outcome, EffectOutcome::Unknown { .. })
            })
        {
            return Err(reference_mismatch(
                "sprint final-verification admission",
                format!(
                    "task-scoped effect '{}' is unfinished or Unknown",
                    effect.intent.effect_id
                ),
            ));
        }
    }
    Ok(())
}

#[allow(clippy::too_many_lines)] // The derived snapshot gate enumerates every task-closure class before returning authority.
pub(super) fn derive_sprint_final_verification_snapshot(
    connection: &Connection,
    sprint_id: &str,
) -> Result<Digest, LedgerError> {
    let (spec, graph, _) = load_sprint_inputs(connection, sprint_id)?;
    worker_lease_authority::require_no_active(connection, sprint_id)?;
    require_all_task_scoped_effects_terminal_known(connection, sprint_id)?;

    let mut integrations = Vec::new();
    for task in &graph.tasks {
        let history = load_task_attempt_history_from(connection, sprint_id, &task.task_id)?;
        if task.required || history.task_state == TaskState::Integrated {
            let assessment =
                task_done::assess_task_done_from(connection, sprint_id, &task.task_id)?;
            if !assessment.is_done() {
                return Err(reference_mismatch(
                    "sprint final-verification admission",
                    format!(
                        "integrated task '{}' is not TaskDone: {:?}",
                        task.task_id, assessment.unmet_requirements
                    ),
                ));
            }
            let proof = assessment
                .proof
                .expect("TaskDone assessment with no unmet requirements carries proof");
            integrations.push(proof.integration_receipt);
        } else if !history.attempts.is_empty() {
            validate_attempted_optional_task_closure(
                connection,
                sprint_id,
                &task.task_id,
                &history,
            )?;
        }
    }

    for launch in load_runner_launches_for_sprint(connection, sprint_id)?
        .into_iter()
        .filter(|launch| launch.purpose == RunnerSessionPurpose::TaskWorker)
    {
        let receipt_id = connection
            .query_row(
                "SELECT receipt_id FROM worker_cleanup_receipts
                 WHERE sprint_id = ?1 AND launch_id = ?2",
                params![sprint_id, launch.launch_id],
                |row| row.get::<_, String>(0),
            )
            .optional()?
            .ok_or_else(|| {
                reference_mismatch(
                    "sprint final-verification admission",
                    format!(
                        "task-worker launch '{}' lacks exact zero-survivor cleanup",
                        launch.launch_id
                    ),
                )
            })?;
        let cleanup = load_worker_cleanup_evidence_from(connection, &receipt_id)?;
        validate_cleanup_after_launch_activity(connection, &launch, &cleanup)?;
        let backend = match cleanup.receipt.platform_backend {
            crate::WorkerCleanupBackend::MacOsDedicatedIdentity => {
                CommandDomainBackend::MacOsDedicatedIdentity
            }
            crate::WorkerCleanupBackend::LinuxCgroupV2 => CommandDomainBackend::LinuxCgroupV2,
            crate::WorkerCleanupBackend::TrustedApplierDirectChildWait => {
                return Err(reference_mismatch(
                    "sprint final-verification admission",
                    "task-worker cleanup cannot use the trusted-applier backend",
                ));
            }
        };
        match command_domain_cleanup::load_command_domain_cleanup_completeness_from(
            connection,
            sprint_id,
            &launch.launch_id,
            &launch.session_id,
            backend,
        )? {
            CommandDomainCleanupCompleteness::Complete(_) => {}
            CommandDomainCleanupCompleteness::Incomplete(reason) => {
                return Err(reference_mismatch(
                    "sprint final-verification admission",
                    format!(
                        "task-worker launch '{}' has incomplete command cleanup: {reason:?}",
                        launch.launch_id
                    ),
                ));
            }
        }
    }

    integrations.sort_by_key(|receipt| receipt.integration_ordinal);
    let mut seen_tasks = BTreeSet::new();
    let mut expected_input = spec.base_snapshot.clone();
    for (ordinal, receipt) in integrations.iter().enumerate() {
        let ordinal = u32::try_from(ordinal)
            .map_err(|_| LedgerError::IntegerOutOfRange("final integration ordinal"))?;
        if receipt.integration_ordinal != ordinal
            || receipt.input_snapshot != expected_input
            || !seen_tasks.insert(receipt.task_id.clone())
        {
            return Err(reference_mismatch(
                "sprint final-verification admission",
                "all integrated TaskDone tasks are not one contiguous snapshot chain",
            ));
        }
        expected_input.clone_from(&receipt.result_snapshot);
    }
    load_workspace_snapshot_from(connection, sprint_id, &expected_input)?;
    Ok(expected_input)
}

/// Returns whether a completion was created under the current proof contract.
///
/// A reader temporarily opened at an exact pre-v16 schema (migration tests and
/// recovery tooling) must preserve the historical contract. During v16
/// migration, every already-durable completion is captured in an immutable
/// exemption table; completions created after migration can never enter it.
pub(super) fn completion_requires_v16_evidence(
    connection: &Connection,
    receipt: &CompletionReceipt,
) -> Result<bool, LedgerError> {
    let v16_installed = connection.query_row(
        "SELECT EXISTS(
             SELECT 1 FROM sqlite_schema
             WHERE type = 'table'
               AND name = 'pre_v16_completion_evidence_exemptions'
         )",
        [],
        |row| row.get::<_, bool>(0),
    )?;
    if !v16_installed {
        return Ok(false);
    }
    let exempt = connection
        .query_row(
            "SELECT recorded_schema_ceiling
             FROM pre_v16_completion_evidence_exemptions
             WHERE sprint_id = ?1 AND completion_receipt_id = ?2",
            params![receipt.sprint_id, receipt.receipt_id],
            |row| row.get::<_, i64>(0),
        )
        .optional()?;
    match exempt {
        None => Ok(true),
        Some(15) => Ok(false),
        Some(other) => Err(LedgerError::Corrupt {
            entity: "pre-v16 completion evidence exemption",
            detail: format!("invalid recorded schema ceiling {other}"),
        }),
    }
}

#[allow(clippy::too_many_lines)] // Rust mirrors the complete SQL completion conjunction field-for-field.
pub(super) fn validate_task_attempt_completion_predicate(
    connection: &Connection,
    receipt: &CompletionReceipt,
) -> Result<(), LedgerError> {
    if !task_attempt_authority::schema_is_installed(connection)? {
        return Ok(());
    }
    let invalid: i64 = connection.query_row(
        "SELECT
            EXISTS (
                SELECT 1
                FROM sprint_unknown_terminalization_pending pending
                LEFT JOIN sprint_unknown_terminalization_closures closure
                  ON closure.marker_id = pending.marker_id
                WHERE pending.sprint_id = ?1
                  AND closure.marker_id IS NULL
            )
            OR EXISTS (
                SELECT 1
                FROM task_attempts attempt
                LEFT JOIN task_attempt_dispositions disposition
                  ON disposition.attempt_id = attempt.attempt_id
                WHERE attempt.sprint_id = ?1
                  AND attempt.schema_generation = 15
                  AND disposition.attempt_id IS NULL
            )
            OR EXISTS (
                SELECT 1
                FROM task_attempts attempt
                JOIN sprints sprint ON sprint.sprint_id = attempt.sprint_id
                WHERE attempt.sprint_id = ?1
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
                WHERE attempt.sprint_id = ?1
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
                LEFT JOIN task_attempt_legacy_classifications legacy
                  ON legacy.attempt_id = attempt.attempt_id
                WHERE attempt.sprint_id = ?1
                  AND attempt.schema_generation = 14
                  AND (
                      legacy.attempt_id IS NULL
                      OR legacy.classification != 'LegacyIntegratedReleased'
                      OR legacy.budget_classification != 'WithinBudget'
                  )
            )",
        [&receipt.sprint_id],
        |row| row.get(0),
    )?;
    if invalid != 0 {
        return Err(reference_mismatch(
            "completion receipt",
            "completion requires every attempt disposed, every earlier attempt Retryable, no unsafe legacy or over-budget history, and no pending Unknown authority",
        ));
    }

    let latest_required_v15_integrations = {
        let mut statement = connection.prepare(
            "SELECT disposition.integration_receipt_id
             FROM task_attempts attempt
             JOIN task_attempt_dispositions disposition
               ON disposition.attempt_id = attempt.attempt_id
             JOIN sprint_task_graphs graph ON graph.sprint_id = attempt.sprint_id
             JOIN json_each(CAST(graph.graph_json AS TEXT), '$.tasks') graph_task
               ON json_extract(graph_task.value, '$.task_id') = attempt.task_id
             WHERE attempt.sprint_id = ?1
               AND attempt.schema_generation = 15
               AND json_extract(graph_task.value, '$.required') = 1
               AND attempt.attempt_ordinal = (
                   SELECT MAX(latest.attempt_ordinal)
                   FROM task_attempts latest
                   WHERE latest.sprint_id = attempt.sprint_id
                     AND latest.task_id = attempt.task_id
                     AND latest.schema_generation = 15
               )
               AND disposition.disposition_kind = 'Integrated'
             ORDER BY attempt.task_id ASC",
        )?;
        let rows = statement.query_map([&receipt.sprint_id], |row| row.get::<_, String>(0))?;
        rows.collect::<Result<BTreeSet<_>, _>>()?
    };
    let completion_integrations: BTreeSet<&str> = receipt
        .task_integration_receipt_ids
        .iter()
        .map(String::as_str)
        .collect();
    if latest_required_v15_integrations
        .iter()
        .any(|integration| !completion_integrations.contains(integration.as_str()))
    {
        return Err(reference_mismatch(
            "completion receipt",
            "completion integration links omit or substitute a required task's latest v15 Integrated disposition",
        ));
    }
    Ok(())
}

pub(super) fn load_verification_session_binding(
    connection: &Connection,
    sprint_id: &str,
    verification: &VerificationReceipt,
) -> Result<RunnerSessionPolicyRecord, LedgerError> {
    let session_id = connection
        .query_row(
            "SELECT session_id FROM verification_session_bindings
             WHERE sprint_id = ?1 AND verification_receipt_id = ?2",
            params![sprint_id, verification.receipt_id],
            |row| row.get::<_, String>(0),
        )
        .optional()?
        .ok_or_else(|| LedgerError::ArtifactNotFound {
            entity: "verification session binding",
            id: verification.receipt_id.clone(),
        })?;
    let (session, _) = load_runner_session_policy_from(connection, sprint_id, &session_id)?;
    if verification.sprint_id != sprint_id
        || session.policy_hash != verification.policy_hash
        || session.registered_at_unix_ms > verification.finished_at_unix_ms
        || (verification.task_id.is_none()
            && session.purpose != RunnerSessionPurpose::FinalVerifier)
        || (verification.task_id.is_some() && session.purpose != RunnerSessionPurpose::TaskWorker)
    {
        return Err(reference_mismatch(
            "verification session binding",
            "verification scope, policy, or timestamp differs from its registered session",
        ));
    }
    Ok(session)
}

pub(super) fn load_runner_sessions_for_sprint(
    connection: &Connection,
    sprint_id: &str,
) -> Result<Vec<RunnerSessionPolicyRecord>, LedgerError> {
    let mut statement = connection.prepare(
        "SELECT session_id FROM runner_session_policies
         WHERE sprint_id = ?1 ORDER BY session_id ASC",
    )?;
    let session_ids = statement
        .query_map([sprint_id], |row| row.get::<_, String>(0))?
        .collect::<Result<Vec<_>, _>>()?;
    session_ids
        .iter()
        .map(|session_id| {
            load_runner_session_policy_from(connection, sprint_id, session_id)
                .map(|(record, _)| record)
        })
        .collect()
}

pub(super) fn load_runner_launches_for_sprint(
    connection: &Connection,
    sprint_id: &str,
) -> Result<Vec<RunnerLaunchIntent>, LedgerError> {
    let cleanup_classification_installed =
        runner_launch_cleanup_admission::schema_is_installed(connection)?;
    let mut statement = connection.prepare(
        "SELECT launch_id FROM runner_launch_intents
         WHERE sprint_id = ?1 ORDER BY launch_id ASC",
    )?;
    let launch_ids = statement
        .query_map([sprint_id], |row| row.get::<_, String>(0))?
        .collect::<Result<Vec<_>, _>>()?;
    launch_ids
        .iter()
        .map(|launch_id| {
            if !cleanup_classification_installed {
                return load_runner_launch_intent_from(connection, sprint_id, launch_id)
                    .map(|(intent, _)| intent);
            }
            match runner_launch_cleanup_admission::load_classification(
                connection,
                sprint_id,
                launch_id,
            )? {
                runner_launch_cleanup_admission::RunnerLaunchCleanupClassification::Authoritative => {
                    runner_launch_cleanup_admission::load_authoritative(
                        connection,
                        sprint_id,
                        launch_id,
                    )
                    .map(|admission| admission.launch)
                }
                runner_launch_cleanup_admission::RunnerLaunchCleanupClassification::LegacyPreV13 => {
                    load_runner_launch_intent_from(connection, sprint_id, launch_id)
                        .map(|(intent, _)| intent)
                }
            }
        })
        .collect()
}

pub(super) fn validate_completion_cleanup_set(
    connection: &Connection,
    receipt: &CompletionReceipt,
) -> Result<BTreeMap<String, WorkerCleanupEvidence>, LedgerError> {
    validate_all_session_cleanups(
        connection,
        &receipt.sprint_id,
        Some(&receipt.worker_cleanup_receipt_ids),
    )
}

/// Requires the complete canonical runner and command-domain cleanup set before
/// a known unsuccessful sprint terminal. A sprint that never launched a runner
/// has an exactly empty cleanup obligation; unlike successful completion, that
/// valid pre-launch case does not require manufacturing a cleanup receipt.
pub(super) fn validate_known_terminal_cleanup_set(
    connection: &Connection,
    sprint_id: &str,
) -> Result<(), LedgerError> {
    if load_runner_launches_for_sprint(connection, sprint_id)?.is_empty() {
        return Ok(());
    }
    let cleanup_by_launch = validate_all_session_cleanups(connection, sprint_id, None)?;
    validate_command_domain_cleanup_set(connection, sprint_id, &cleanup_by_launch)
}

pub(super) fn validate_completion_command_domain_cleanup(
    connection: &Connection,
    receipt: &CompletionReceipt,
    cleanup_by_launch: &BTreeMap<String, WorkerCleanupEvidence>,
) -> Result<(), LedgerError> {
    validate_command_domain_cleanup_set(connection, &receipt.sprint_id, cleanup_by_launch)
}

pub(super) fn validate_command_domain_cleanup_set(
    connection: &Connection,
    sprint_id: &str,
    cleanup_by_launch: &BTreeMap<String, WorkerCleanupEvidence>,
) -> Result<(), LedgerError> {
    for launch in load_runner_launches_for_sprint(connection, sprint_id)? {
        if !matches!(
            launch.purpose,
            RunnerSessionPurpose::TaskWorker
                | RunnerSessionPurpose::FinalVerifier
                | RunnerSessionPurpose::LiveStateVerifier
        ) {
            continue;
        }
        let cleanup = cleanup_by_launch.get(&launch.launch_id).ok_or_else(|| {
            reference_mismatch(
                "command-domain cleanup set",
                format!(
                    "ordinary runner launch '{}' lacks cleanup",
                    launch.launch_id
                ),
            )
        })?;
        let stored_session = connection
            .query_row(
                "SELECT sprint_id, launch_id FROM runner_session_policies
                 WHERE session_id = ?1",
                [&launch.session_id],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
            )
            .optional()?;
        if let Some((session_sprint_id, session_launch_id)) = stored_session.as_ref()
            && (session_sprint_id != sprint_id || session_launch_id != &launch.launch_id)
        {
            return Err(LedgerError::Corrupt {
                entity: "command-domain runner lifecycle",
                detail: "runner session identity is crossed to another sprint or launch".into(),
            });
        }
        if stored_session.is_none() {
            let command_bindings: i64 = connection.query_row(
                "SELECT COUNT(*)
                 FROM effect_session_bindings binding
                 JOIN effect_intents intent ON intent.effect_id = binding.effect_id
                 WHERE binding.sprint_id = ?1 AND binding.launch_id = ?2
                   AND intent.effect_kind = 'RunCommand'",
                params![sprint_id, launch.launch_id],
                |row| row.get(0),
            )?;
            let command_proofs: i64 = connection.query_row(
                "SELECT COUNT(*) FROM command_domain_cleanup_proofs
                 WHERE sprint_id = ?1 AND (launch_id = ?2 OR session_id = ?3)",
                params![sprint_id, launch.launch_id, launch.session_id],
                |row| row.get(0),
            )?;
            if cleanup.receipt.surviving_processes != 0 {
                return Err(LedgerError::Corrupt {
                    entity: "command-domain cleanup set",
                    detail: "pre-session runner cleanup has surviving processes".into(),
                });
            }
            if command_bindings == 0 && command_proofs == 0 {
                continue;
            }
            return Err(LedgerError::Corrupt {
                entity: "command-domain cleanup set",
                detail: "pre-session runner launch retains command bindings or cleanup proofs"
                    .into(),
            });
        }
        let backend = match cleanup.receipt.platform_backend {
            crate::WorkerCleanupBackend::MacOsDedicatedIdentity => {
                CommandDomainBackend::MacOsDedicatedIdentity
            }
            crate::WorkerCleanupBackend::LinuxCgroupV2 => CommandDomainBackend::LinuxCgroupV2,
            crate::WorkerCleanupBackend::TrustedApplierDirectChildWait => {
                return Err(reference_mismatch(
                    "command-domain cleanup set",
                    "ordinary runner cleanup cannot use the trusted-applier backend",
                ));
            }
        };
        match command_domain_cleanup::load_command_domain_cleanup_completeness_from(
            connection,
            sprint_id,
            &launch.launch_id,
            &launch.session_id,
            backend,
        )? {
            CommandDomainCleanupCompleteness::Complete(_) => {}
            CommandDomainCleanupCompleteness::Incomplete(reason) => {
                return Err(reference_mismatch(
                    "command-domain cleanup set",
                    format!(
                        "ordinary runner launch '{}' has incomplete cleanup: {reason:?}",
                        launch.launch_id
                    ),
                ));
            }
        }
    }
    Ok(())
}

pub(super) fn validate_all_session_cleanups(
    connection: &Connection,
    sprint_id: &str,
    expected_receipt_ids: Option<&[String]>,
) -> Result<BTreeMap<String, WorkerCleanupEvidence>, LedgerError> {
    let launches = load_runner_launches_for_sprint(connection, sprint_id)?;
    if launches.is_empty() {
        return Err(reference_mismatch(
            "worker cleanup set",
            "completion requires at least one registered runner session",
        ));
    }
    let unmapped_runner_effect = connection
        .query_row(
            "SELECT intent.effect_id
             FROM effect_intents intent
             LEFT JOIN finish_effect_kinds finish ON finish.effect_id = intent.effect_id
             LEFT JOIN effect_session_bindings binding ON binding.effect_id = intent.effect_id
             WHERE intent.sprint_id = ?1
               AND (
                   intent.effect_kind IN (
                       'ReadRelativeFile', 'SearchLiteral', 'RunCommand',
                       'CreateRegularFile', 'ReplaceRegularFile', 'DeleteRegularFile'
                   )
                   OR finish.effect_id IS NOT NULL
               )
               AND binding.effect_id IS NULL
             LIMIT 1",
            [sprint_id],
            |row| row.get::<_, String>(0),
        )
        .optional()?;
    if let Some(effect_id) = unmapped_runner_effect {
        return Err(reference_mismatch(
            "worker cleanup set",
            format!("runner effect '{effect_id}' lacks its exact session-policy registration"),
        ));
    }
    let mut binding_statement = connection.prepare(
        "SELECT effect_id FROM effect_session_bindings
         WHERE sprint_id = ?1 ORDER BY effect_id ASC",
    )?;
    let bound_effect_ids = binding_statement
        .query_map([sprint_id], |row| row.get::<_, String>(0))?
        .collect::<Result<Vec<_>, _>>()?;
    for effect_id in bound_effect_ids {
        let effect = load_effect_from_with_receipts(connection, &effect_id, false)?;
        load_effect_runner_binding(connection, &effect.intent)?;
    }

    let mut receipt_ids = Vec::new();
    let mut cleanup_by_launch = BTreeMap::new();
    let mut statement = connection.prepare(
        "SELECT receipt_id FROM worker_cleanup_receipts
         WHERE sprint_id = ?1 ORDER BY receipt_id ASC",
    )?;
    let stored_ids = statement
        .query_map([sprint_id], |row| row.get::<_, String>(0))?
        .collect::<Result<Vec<_>, _>>()?;
    for receipt_id in stored_ids {
        let evidence = load_worker_cleanup_evidence_from(connection, &receipt_id)?;
        receipt_ids.push(receipt_id);
        if cleanup_by_launch
            .insert(evidence.receipt.launch_id.clone(), evidence)
            .is_some()
        {
            return Err(LedgerError::Corrupt {
                entity: "worker cleanup set",
                detail: "multiple cleanup receipts claim one runner launch attempt".into(),
            });
        }
    }
    if expected_receipt_ids.is_some_and(|expected| expected != receipt_ids)
        || cleanup_by_launch.len() != launches.len()
    {
        return Err(reference_mismatch(
            "worker cleanup set",
            "cleanup receipt IDs are not the canonical exact registered-session set",
        ));
    }
    for launch in launches {
        let cleanup = cleanup_by_launch.get(&launch.launch_id).ok_or_else(|| {
            reference_mismatch(
                "worker cleanup set",
                format!(
                    "runner launch '{}' has no cleanup receipt",
                    launch.launch_id
                ),
            )
        })?;
        validate_cleanup_after_launch_activity(connection, &launch, cleanup)?;
    }
    Ok(cleanup_by_launch)
}

pub(super) fn validate_cleanup_after_launch_activity(
    connection: &Connection,
    launch: &RunnerLaunchIntent,
    cleanup: &WorkerCleanupEvidence,
) -> Result<(), LedgerError> {
    let receipt = &cleanup.receipt;
    let latest_effect_at: Option<i64> = connection.query_row(
        "SELECT MAX(COALESCE(observation.observed_at_unix_ms,
                                 intent.created_at_unix_ms))
             FROM effect_session_bindings binding
             JOIN effect_intents intent ON intent.effect_id = binding.effect_id
             LEFT JOIN effect_observations observation
               ON observation.effect_id = intent.effect_id
             WHERE binding.sprint_id = ?1 AND binding.launch_id = ?2",
        params![launch.sprint_id, launch.launch_id],
        |row| row.get(0),
    )?;
    let latest_verification_at: Option<i64> = connection.query_row(
        "SELECT MAX(receipt.finished_at_unix_ms)
         FROM verification_session_bindings binding
         JOIN verification_receipts receipt
           ON receipt.receipt_id = binding.verification_receipt_id
         WHERE binding.sprint_id = ?1 AND binding.session_id = ?2",
        params![launch.sprint_id, launch.session_id],
        |row| row.get(0),
    )?;
    let cleaned_at = receipt.cleaned_at_unix_ms;
    for activity_at in [latest_effect_at, latest_verification_at]
        .into_iter()
        .flatten()
    {
        if cleaned_at < unsigned_integer("runner session activity timestamp", activity_at)? {
            return Err(reference_mismatch(
                "worker cleanup set",
                format!(
                    "cleanup for session '{}' predates its last durable activity",
                    launch.session_id
                ),
            ));
        }
    }
    Ok(())
}

pub(super) fn derive_linked_verified_no_op_receipt(
    receipt: &CompletionReceipt,
    link: &CompletionLiveStateCaptureLink,
) -> Result<VerifiedNoOpReceipt, LedgerError> {
    let (
        CompletionApplication::VerifiedNoOp {
            verified_no_op_receipt_id,
        },
        CompletionLiveStateApplicationLink::VerifiedNoOp {
            verified_no_op_receipt_id: linked_no_op_id,
            ..
        },
    ) = (&receipt.application, &link.application)
    else {
        return Err(reference_mismatch(
            "verified no-op receipt",
            "current no-op derivation requires matching completion and capture-link branches",
        ));
    };
    if verified_no_op_receipt_id != linked_no_op_id {
        return Err(reference_mismatch(
            "verified no-op receipt",
            "completion and capture link select different no-op identities",
        ));
    }
    let no_op = VerifiedNoOpReceipt {
        contract_version: CONTRACT_VERSION,
        receipt_id: verified_no_op_receipt_id.clone(),
        sprint_id: receipt.sprint_id.clone(),
        final_verification_receipt_id: receipt.final_verification_receipt_id.clone(),
        base_snapshot: receipt.final_snapshot.clone(),
        live_manifest_digest: link.capture.manifest_digest.clone(),
        grant_hash: receipt.grant_hash.clone(),
        policy_version: receipt.policy_version,
        observed_at_unix_ms: link.captured_at_unix_ms,
    };
    no_op.validate()?;
    Ok(no_op)
}

#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
pub(super) fn validate_linked_completion_application(
    connection: &Connection,
    spec: &SprintSpec,
    receipt: &CompletionReceipt,
    final_verification: &VerificationReceipt,
    cleanup: &BTreeMap<String, WorkerCleanupEvidence>,
    link: &CompletionLiveStateCaptureLink,
    capture: &LiveStateCaptureEvidence,
    verifier_cleanup: &WorkerCleanupEvidence,
    supplied_no_op: Option<&VerifiedNoOpReceipt>,
) -> Result<(), LedgerError> {
    if link.sprint_id != receipt.sprint_id
        || link.completion_receipt_id != receipt.receipt_id
        || link.completion_receipt_digest
            != persisted_or_current_completion_receipt_digest(connection, receipt)?
        || link.final_snapshot != receipt.final_snapshot
        || link.final_verification_receipt_id != receipt.final_verification_receipt_id
        || link.capture.capture_receipt_id != capture.receipt.receipt_id
        || link.verifier_cleanup_receipt_id != verifier_cleanup.receipt.receipt_id
    {
        return Err(reference_mismatch(
            "completion live-state capture link",
            "linked completion, capture, cleanup, verification, snapshot, or digest differs",
        ));
    }
    match &receipt.application {
        CompletionApplication::Applied {
            application_receipt_id,
            rollback_reference_id,
        } => {
            if supplied_no_op.is_some() {
                return Err(reference_mismatch(
                    "completion receipt",
                    "Applied completion cannot carry supplied no-op evidence",
                ));
            }
            validate_linked_applied_completion(
                connection,
                spec,
                receipt,
                final_verification,
                cleanup,
                link,
                application_receipt_id,
                rollback_reference_id,
            )
        }
        CompletionApplication::VerifiedNoOp { .. } => validate_linked_verified_no_op_completion(
            connection,
            spec,
            receipt,
            final_verification,
            cleanup,
            link,
            supplied_no_op,
        ),
    }
}

#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
pub(super) fn validate_linked_applied_completion(
    connection: &Connection,
    spec: &SprintSpec,
    receipt: &CompletionReceipt,
    final_verification: &VerificationReceipt,
    cleanup: &BTreeMap<String, WorkerCleanupEvidence>,
    link: &CompletionLiveStateCaptureLink,
    application_receipt_id: &str,
    rollback_reference_id: &str,
) -> Result<(), LedgerError> {
    if link.application
        != (CompletionLiveStateApplicationLink::Applied {
            application_receipt_id: application_receipt_id.to_owned(),
            rollback_reference_id: rollback_reference_id.to_owned(),
        })
    {
        return Err(reference_mismatch(
            "completion receipt",
            "Applied completion differs from its live-state capture link",
        ));
    }
    let application_evidence = load_application_evidence_from(connection, application_receipt_id)?;
    let application = &application_evidence.receipt;
    let rollback = load_rollback_reference_evidence_from(connection, rollback_reference_id)?;
    let change_set =
        load_change_set_from(connection, &receipt.sprint_id, &application.change_set_id)?;
    let launches = load_runner_launches_for_sprint(connection, &receipt.sprint_id)?;
    let (applier, _) = load_runner_session_policy_from(
        connection,
        &receipt.sprint_id,
        &application.applier_session_id,
    )?;
    let (validator, _) = load_runner_session_policy_from(
        connection,
        &receipt.sprint_id,
        &application_evidence.validation.runner_session_id,
    )?;
    if applier.purpose != RunnerSessionPurpose::Applier
        || application.sprint_id != receipt.sprint_id
        || application.base_snapshot != spec.base_snapshot
        || application.result_snapshot != receipt.final_snapshot
        || application.grant_hash != receipt.grant_hash
        || application.policy_version != receipt.policy_version
        || change_set.base_snapshot != spec.base_snapshot
        || change_set.result_snapshot != receipt.final_snapshot
        || rollback.reference.sprint_id != receipt.sprint_id
        || rollback.reference.application_receipt_id != application.receipt_id
        || rollback.reference.transaction_id != application.transaction_id
        || rollback.reference.base_snapshot != spec.base_snapshot
        || final_verification.finished_at_unix_ms > application.applied_at_unix_ms
        || application.applied_at_unix_ms > link.capture_started_at_unix_ms
        || rollback.reference.validated_at_unix_ms > link.capture_started_at_unix_ms
    {
        return Err(reference_mismatch(
            "completion receipt",
            "linked application, rollback, grant, snapshot, applier, or capture ordering differs",
        ));
    }
    let plan = load_sprint_live_state_capture_plan_from(connection, &link.capture.plan_id)?;
    let prior_cleanup_ids = plan
        .required_cleanup_receipt_ids
        .iter()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    for launch in launches {
        let cleanup_evidence = cleanup
            .get(&launch.launch_id)
            .expect("cleanup/launch bijection validated");
        let cleanup_receipt = &cleanup_evidence.receipt;
        let cleaned_at = cleanup_receipt.cleaned_at_unix_ms;
        let ordered = match launch.purpose {
            RunnerSessionPurpose::TaskWorker | RunnerSessionPurpose::FinalVerifier => {
                cleaned_at <= application.applied_at_unix_ms
            }
            RunnerSessionPurpose::LiveStateVerifier => {
                if launch.launch_id == link.capture.runner_launch_id {
                    cleanup_receipt.receipt_id == link.verifier_cleanup_receipt_id
                        && link.captured_at_unix_ms <= cleaned_at
                        && cleaned_at <= receipt.completed_at_unix_ms
                } else {
                    prior_cleanup_ids.contains(cleanup_receipt.receipt_id.as_str())
                        && application.applied_at_unix_ms <= cleaned_at
                        && cleaned_at <= link.capture_started_at_unix_ms
                }
            }
            RunnerSessionPurpose::Applier => {
                if launch.launch_id == validator.launch_id {
                    application.applied_at_unix_ms <= cleaned_at
                        && rollback.reference.validated_at_unix_ms <= cleaned_at
                        && cleaned_at <= link.capture_started_at_unix_ms
                } else if launch.launch_id == applier.launch_id {
                    application.applied_at_unix_ms <= cleaned_at
                        && cleaned_at <= link.capture_started_at_unix_ms
                } else {
                    cleaned_at <= application.applied_at_unix_ms
                }
            }
        };
        if !ordered {
            return Err(reference_mismatch(
                "completion receipt",
                "current Applied cleanup ordering does not match the pre-capture cut and selected verifier cleanup",
            ));
        }
    }
    Ok(())
}

pub(super) fn validate_linked_verified_no_op_completion(
    connection: &Connection,
    spec: &SprintSpec,
    receipt: &CompletionReceipt,
    final_verification: &VerificationReceipt,
    cleanup: &BTreeMap<String, WorkerCleanupEvidence>,
    link: &CompletionLiveStateCaptureLink,
    supplied_no_op: Option<&VerifiedNoOpReceipt>,
) -> Result<(), LedgerError> {
    let expected = derive_linked_verified_no_op_receipt(receipt, link)?;
    let stored;
    let actual = if let Some(no_op) = supplied_no_op {
        no_op.validate()?;
        no_op
    } else {
        stored = load_verified_no_op_receipt_envelope_from(connection, &expected.receipt_id)?;
        &stored
    };
    if actual != &expected
        || final_verification.sprint_id != receipt.sprint_id
        || final_verification.task_id.is_some()
        || !final_verification.passed()
        || final_verification.snapshot_id != spec.base_snapshot
        || final_verification.finished_at_unix_ms > link.capture_started_at_unix_ms
        || receipt.final_snapshot != spec.base_snapshot
    {
        return Err(reference_mismatch(
            "verified no-op receipt",
            "core-derived no-op, final verification, base snapshot, or capture ordering differs",
        ));
    }
    let application_intents: i64 = connection.query_row(
        "SELECT COUNT(*) FROM finish_effect_kinds
         WHERE sprint_id = ?1 AND effect_kind = 'ApplyChangeSet'",
        [&receipt.sprint_id],
        |row| row.get(0),
    )?;
    if application_intents != 0 {
        return Err(reference_mismatch(
            "verified no-op receipt",
            "current linked no-op requires zero application intents",
        ));
    }
    let plan = load_sprint_live_state_capture_plan_from(connection, &link.capture.plan_id)?;
    let prior_cleanup_ids = plan
        .required_cleanup_receipt_ids
        .iter()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    for evidence in cleanup.values() {
        let cleanup_receipt = &evidence.receipt;
        let cleanup_effect = load_effect_from(connection, &cleanup_receipt.effect_id)?;
        if cleanup_effect.intent.input_snapshot != spec.base_snapshot {
            return Err(reference_mismatch(
                "verified no-op receipt",
                "every no-op cleanup effect must be admitted on the unchanged sprint base",
            ));
        }
        if cleanup_receipt.receipt_id == link.verifier_cleanup_receipt_id {
            if cleanup_receipt.launch_id != link.capture.runner_launch_id
                || cleanup_receipt.session_id != link.capture.runner_session_id
                || cleanup_receipt.cleaned_at_unix_ms < link.captured_at_unix_ms
                || cleanup_receipt.cleaned_at_unix_ms > receipt.completed_at_unix_ms
            {
                return Err(reference_mismatch(
                    "verified no-op receipt",
                    "selected verifier cleanup does not follow the exact capture interval",
                ));
            }
        } else if !prior_cleanup_ids.contains(cleanup_receipt.receipt_id.as_str())
            || cleanup_receipt.cleaned_at_unix_ms > link.capture_started_at_unix_ms
        {
            return Err(reference_mismatch(
                "verified no-op receipt",
                "plan-prior cleanup is absent from the cut or follows capture start",
            ));
        }
    }
    Ok(())
}

pub(super) fn validate_completion_application(
    connection: &Connection,
    spec: &SprintSpec,
    receipt: &CompletionReceipt,
    final_verification: &VerificationReceipt,
    cleanup: &BTreeMap<String, WorkerCleanupEvidence>,
) -> Result<(), LedgerError> {
    match &receipt.application {
        CompletionApplication::Applied {
            application_receipt_id,
            rollback_reference_id,
        } => validate_applied_completion(
            connection,
            spec,
            receipt,
            final_verification,
            cleanup,
            application_receipt_id,
            rollback_reference_id,
        ),
        CompletionApplication::VerifiedNoOp {
            verified_no_op_receipt_id,
        } => {
            let no_op = load_verified_no_op_receipt_from(connection, verified_no_op_receipt_id)?;
            if no_op.sprint_id != receipt.sprint_id
                || no_op.final_verification_receipt_id != final_verification.receipt_id
                || no_op.base_snapshot != receipt.final_snapshot
                || no_op.observed_at_unix_ms > receipt.completed_at_unix_ms
            {
                return Err(reference_mismatch(
                    "completion receipt",
                    "verified no-op does not match the final verification, snapshot, or ordering",
                ));
            }
            validate_verified_no_op_live_manifest_capture_authority(connection, receipt, &no_op)?;
            Ok(())
        }
    }
}

pub(super) fn validate_verified_no_op_live_manifest_capture_authority(
    connection: &Connection,
    receipt: &CompletionReceipt,
    no_op: &VerifiedNoOpReceipt,
) -> Result<(), LedgerError> {
    if !completion_requires_v22_task_links(connection, receipt)? {
        return Ok(());
    }
    Err(reference_mismatch(
        "verified no-op live-manifest capture authority",
        format!(
            "current-schema VerifiedNoOp '{}' lacks a typed runner/session/effect-bound descriptor-relative live-manifest capture",
            no_op.receipt_id
        ),
    ))
}
