#[allow(
    clippy::too_many_lines,
    reason = "one exact fixture constructs the complete independently timed rejection authority"
)]
fn v29_sensitive_rejection_fixture(
    label: &str,
) -> (
    FreshDispatchInputFixture,
    CommandOutputCaptureIntentV1,
    CommandOutputCaptureAcquiredV1,
    RunnerEffectObservationAuthority,
    EffectObservation,
    AgentEvent,
    CommandOutputSensitiveRejectionAnchorV1,
    CommandOutputSensitiveRejectionCleanupReceiptV1,
    CommandDomainCleanupProof,
) {
    let (mut fixture, capture, permit, acquired) = v27_prepare_stale_capture_permit(label);
    let (_, transport) = fixture
        .ledger
        .claim_command_output_capture_dispatch(
            permit,
            acquired.clone(),
            OPAQUE_RUNNER_TRANSPORT_REQUEST_BYTES,
        )
        .expect("claim exact sensitive-output command dispatch");
    let authority = transport
        .validate_transport_request(
            &fixture.intent,
            EFFECT_REQUEST_BYTES,
            &fixture.launch,
            &fixture.session,
            Some(&fixture.running),
            OPAQUE_RUNNER_TRANSPORT_REQUEST_BYTES,
        )
        .expect("validate exact sensitive-output transport request");
    let policy = fixture
        .ledger
        .load_sensitive_output_detection_policy_for_effect(&fixture.intent.effect_id)
        .expect("load exact pre-dispatch detector policy");
    assert_eq!(policy, SensitiveOutputDetectionPolicyReferenceV1::core_v1());

    let observation_id = format!("v29-sensitive-observation-{label}");
    let command_cleanup_id = format!("v29-sensitive-command-cleanup-{label}");
    let journal_head = |generation, state: &str| SensitiveOutputJournalHeadV1 {
        generation,
        record_digest: Digest::sha256(
            format!("v29-sensitive-journal:{label}:{state}:{generation}").as_bytes(),
        ),
    };
    let store_head = |generation, state: &str| CommandOutputCaptureStoreHeadV1 {
        generation,
        record_digest: Digest::sha256(
            format!("v29-sensitive-store:{label}:{state}:{generation}").as_bytes(),
        ),
    };
    let core_dump_suppression = SensitiveOutputCoreDumpSuppressionV1::macos();
    let staging_neutralization = SensitiveOutputStagingNeutralizationReceiptV1::try_new(&acquired)
        .expect("construct exact zero-only staging neutralization receipt");
    let mut runner_cleanup = SensitiveOutputRejectionRunnerReferenceV1 {
        journal_id: format!("runner-v12-sensitive-journal-{label}"),
        capture_id: capture.capture_id.clone(),
        runner_session_id: capture.source.runner_session_id.clone(),
        effect_id: capture.source.effect_id.clone(),
        request_digest: capture.source.request_digest.clone(),
        intent_digest: capture.intent_digest.clone(),
        acquired: acquired.clone(),
        acquired_anchor_digest: acquired.acquired_anchor_digest.clone(),
        acquired_store_head: acquired.store_head.clone(),
        writer_attached_store_head: store_head(
            acquired.store_head.generation + 1,
            "writer-attached",
        ),
        launch_intended_store_head: store_head(
            acquired.store_head.generation + 2,
            "launch-intended",
        ),
        core_dump_suppression,
        detector_policy: policy,
        intent_bound_journal_head: journal_head(1, "intent-bound"),
        acquired_bound_journal_head: journal_head(2, "acquired-bound"),
        writer_attached_journal_head: journal_head(3, "writer-attached"),
        launch_intended_journal_head: journal_head(4, "launch-intended"),
        detected_journal_head: journal_head(5, "detected"),
        cleanup_intended_journal_head: journal_head(6, "cleanup-intended"),
        cleaned_journal_head: journal_head(7, "cleaned"),
        rejected_terminal_journal_head: journal_head(8, "rejected"),
        v1_cleaned_store_head: store_head(acquired.store_head.generation + 3, "cleaned"),
        command_domain_cleanup_proof_id: command_cleanup_id.clone(),
        staging_neutralization,
        termination: CommandTerminationV1::Exited { code: 1 },
        cleanup_receipt_id: format!("runner-v12-sensitive-cleanup-{label}"),
        cleanup_receipt_digest: Digest::sha256(b"pending-runner-cleanup-receipt"),
    };
    runner_cleanup
        .canonicalize_journal_heads_for_test()
        .expect("compute exact rejection journal chain");
    runner_cleanup
        .validate()
        .expect("validate exact rejection journal chain");
    let anchor = CommandOutputSensitiveRejectionAnchorV1::try_new(
        &capture,
        &acquired,
        observation_id.clone(),
        runner_cleanup.clone(),
    )
    .expect("construct secret-free sensitive-output rejection anchor");
    let cleanup = CommandOutputSensitiveRejectionCleanupReceiptV1::try_new(
        &anchor,
        format!("v29-sensitive-cleanup-{label}"),
        runner_cleanup,
        command_cleanup_id.clone(),
    )
    .expect("construct exact sensitive-output cleanup receipt");
    let evidence = anchor
        .canonical_evidence_bytes()
        .expect("encode secret-free rejection evidence");
    let observation = effect_observation(
        &fixture.intent,
        &observation_id,
        EffectOutcome::FailedAfterKnownEffect {
            evidence_digest: Digest::sha256(&evidence),
        },
        1_290,
    );
    let event = effect_terminal_event(
        &fixture.intent,
        &fixture.proposal.event_id,
        &observation,
        fixture
            .ledger
            .next_sequence(&fixture.intent.sprint_id)
            .expect("sensitive rejection event sequence"),
        &format!("v29-sensitive-terminal-event-{label}"),
    );
    let platform_proof_bytes = format!("v29-sensitive-domain-empty:{label}").into_bytes();
    let command_cleanup = CommandDomainCleanupProof {
        contract_version: CONTRACT_VERSION,
        proof_id: command_cleanup_id,
        sprint_id: fixture.intent.sprint_id.clone(),
        launch_id: fixture.launch.launch_id.clone(),
        session_id: fixture.session.session_id.clone(),
        effect_id: fixture.intent.effect_id.clone(),
        observation_id: Some(observation.observation_id.clone()),
        request_digest: fixture.intent.request_digest.clone(),
        backend: CommandDomainBackend::MacOsDedicatedIdentity,
        disposition: CommandDomainCleanupDisposition::ReapedZeroSurvivors,
        surviving_processes: 0,
        platform_proof_digest: Digest::sha256(&platform_proof_bytes),
        platform_proof_bytes,
        cleaned_at_unix_ms: 1_265,
    };
    (
        fixture,
        capture,
        acquired,
        authority,
        observation,
        event,
        anchor,
        cleanup,
        command_cleanup,
    )
}

struct V29UnknownCleanResolutionFixture {
    fixture: FreshDispatchInputFixture,
    capture: CommandOutputCaptureIntentV1,
    acquired: CommandOutputCaptureAcquiredV1,
    terminal: CommandOutputCaptureTerminalAnchorV1,
    permit: Option<CommandOutputCaptureReconciliationPermit>,
    claim: CommandOutputCaptureReconciliationClaimV1,
    physical: CommandOutputCapturePhysicalReconciliationV1,
    resolution: CommandOutputCaptureReconciliationResolutionV1,
    receipt: CommandOutputCleanScanResolutionReceiptV1,
    command_cleanup: CommandDomainCleanupProof,
    runner_cleanup_receipt_id: String,
}

#[allow(
    clippy::too_many_lines,
    reason = "one fixture constructs every independent live, cleanup, fence, v1 physical, and runner-v2 clean authority"
)]
fn v29_unknown_clean_resolution_fixture(label: &str) -> V29UnknownCleanResolutionFixture {
    let (mut fixture, capture, permit, _) = v27_prepare_stale_capture_permit(label);
    let acquired = v27_test_capture_acquired_at_generation(
        &capture,
        permit
            .expected_output_capture_dispatch_claim_id()
            .expect("current Unknown fixture has exact dispatch identity"),
        label,
        2,
        1_250,
    );
    let (_, transport) = fixture
        .ledger
        .claim_command_output_capture_dispatch(
            permit,
            acquired.clone(),
            OPAQUE_RUNNER_TRANSPORT_REQUEST_BYTES,
        )
        .expect("claim current Unknown command dispatch");
    let authority = transport
        .validate_transport_request(
            &fixture.intent,
            EFFECT_REQUEST_BYTES,
            &fixture.launch,
            &fixture.session,
            Some(&fixture.running),
            OPAQUE_RUNNER_TRANSPORT_REQUEST_BYTES,
        )
        .expect("validate current Unknown transport request");
    let observation = effect_observation(
        &fixture.intent,
        &format!("v29-unknown-observation-{label}"),
        EffectOutcome::Unknown {
            evidence_digest: effect_evidence_digest(),
        },
        1_300,
    );
    let event = effect_terminal_event(
        &fixture.intent,
        &fixture.proposal.event_id,
        &observation,
        fixture
            .ledger
            .next_sequence(&fixture.intent.sprint_id)
            .expect("current Unknown terminal sequence"),
        &format!("v29-unknown-terminal-event-{label}"),
    );
    let terminal = CommandOutputCaptureTerminalAnchorV1::try_new(
        &capture,
        Some(&acquired),
        &observation,
        CommandOutputCaptureTerminalDispositionV1::ReconciliationRequired,
        acquired.store_head.clone(),
        observation.outcome.evidence_digest().clone(),
        None,
        1_310,
    )
    .expect("construct immutable current Unknown terminal");
    fixture
        .ledger
        .record_claimed_command_unknown_with_capture_reconciliation_required(
            authority,
            &observation,
            EFFECT_EVIDENCE_BYTES,
            &event,
            &terminal,
        )
        .expect("commit current Unknown terminal");

    let platform_proof_bytes = format!("v29-clean-resolution-domain-empty:{label}").into_bytes();
    let command_cleanup = CommandDomainCleanupProof {
        contract_version: CONTRACT_VERSION,
        proof_id: format!("v29-clean-resolution-command-cleanup-{label}"),
        sprint_id: fixture.intent.sprint_id.clone(),
        launch_id: fixture.launch.launch_id.clone(),
        session_id: fixture.session.session_id.clone(),
        effect_id: fixture.intent.effect_id.clone(),
        observation_id: Some(observation.observation_id.clone()),
        request_digest: fixture.intent.request_digest.clone(),
        backend: CommandDomainBackend::LinuxCgroupV2,
        disposition: CommandDomainCleanupDisposition::ReapedZeroSurvivors,
        surviving_processes: 0,
        platform_proof_digest: Digest::sha256(&platform_proof_bytes),
        platform_proof_bytes,
        cleaned_at_unix_ms: 1_320,
    };
    fixture
        .ledger
        .record_command_domain_cleanup_proof(&command_cleanup)
        .expect("persist current Unknown command cleanup");
    let unknown_evidence = crate::TaskAttemptUnknownEvidence {
        effect_id: fixture.intent.effect_id.clone(),
        observation_id: observation.observation_id.clone(),
        evidence: crate::TaskAttemptEvidence::new(
            format!("v29-clean-resolution-unknown-evidence-{label}"),
            crate::TaskAttemptEvidenceKind::UnknownTerminalEffect,
            EFFECT_EVIDENCE_BYTES.to_vec(),
        )
        .expect("construct current Unknown task evidence"),
    };
    let disposition = fixture
        .ledger
        .with_task_command_unknown_cleaned_disposition_derived_timestamps(
            &command_cleanup,
            &fixture.running.attempt,
            TaskState::Running,
            &format!("v29-clean-resolution-disposition-{label}"),
            &unknown_evidence,
            &format!("v29-clean-resolution-release-{label}"),
            &format!("v29-clean-resolution-marker-{label}"),
            &format!("v29-clean-resolution-transition-{label}"),
            1_330,
            |claim| {
                Ok(cleanup_terminal_from_live_claim(
                    claim,
                    &format!("v29-clean-resolution-runner-cleanup-{label}"),
                    1_400,
                ))
            },
        )
        .expect("close current Unknown attempt and runner domain");
    let runner_cleanup_receipt_id = match disposition {
        TaskAttemptDisposition::UnknownCleaned(value) => {
            value.cleanup_release.cleanup_receipt.receipt_id
        }
        other => panic!("expected UnknownCleaned disposition, got {other:?}"),
    };

    let (permit, claim) = match fixture
        .ledger
        .claim_command_output_capture_reconciliation(
            &capture.capture_id,
            Digest::sha256(format!("v29-clean-resolution-claim-{label}").as_bytes()).as_str(),
            &format!("v29-clean-resolution-owner-{label}"),
            1_410,
            1_900,
        )
        .expect("claim current Unknown reconciliation")
    {
        CommandOutputCaptureReconciliationAdmission::Fresh { claim, permit } => (permit, claim),
        other => panic!("expected fresh current Unknown claim, got {other:?}"),
    };
    let artifacts = v27_test_artifact_reference(&capture, label);
    let terminal_prepared_store_head = CommandOutputCaptureStoreHeadV1 {
        generation: 7,
        record_digest: Digest::sha256(
            format!("v29-clean-resolution-terminal-head:{label}").as_bytes(),
        ),
    };
    let terminal_record_digest =
        Digest::sha256(format!("v29-clean-resolution-terminal-record:{label}").as_bytes());
    let clean_runner = v29_test_clean_runner_reference(
        &capture,
        &acquired,
        &terminal_prepared_store_head,
        &terminal_record_digest,
        CommandTerminationV1::Exited { code: 0 },
        CommandDomainBackend::LinuxCgroupV2,
        label,
        1_490,
    );
    let lifecycle_history = vec![
        CommandOutputCapturePhysicalHistoryEntryV1 {
            state: CommandOutputCaptureRestartStateV1::Intent,
            store_head: CommandOutputCaptureStoreHeadV1 {
                generation: 1,
                record_digest: Digest::sha256(
                    format!("v29-clean-resolution-intent-head:{label}").as_bytes(),
                ),
            },
        },
        CommandOutputCapturePhysicalHistoryEntryV1 {
            state: CommandOutputCaptureRestartStateV1::Acquired,
            store_head: clean_runner.acquired_store_head.clone(),
        },
        CommandOutputCapturePhysicalHistoryEntryV1 {
            state: CommandOutputCaptureRestartStateV1::WriterAttached,
            store_head: clean_runner.writer_attached_store_head.clone(),
        },
        CommandOutputCapturePhysicalHistoryEntryV1 {
            state: CommandOutputCaptureRestartStateV1::LaunchIntended,
            store_head: clean_runner.launch_intended_store_head.clone(),
        },
        CommandOutputCapturePhysicalHistoryEntryV1 {
            state: CommandOutputCaptureRestartStateV1::Finished,
            store_head: clean_runner.finished_store_head.clone(),
        },
        CommandOutputCapturePhysicalHistoryEntryV1 {
            state: CommandOutputCaptureRestartStateV1::Published,
            store_head: clean_runner.published_store_head.clone(),
        },
        CommandOutputCapturePhysicalHistoryEntryV1 {
            state: CommandOutputCaptureRestartStateV1::TerminalPrepared,
            store_head: clean_runner.terminal_prepared_store_head.clone(),
        },
    ];
    let launch_evidence = CommandOutputCaptureRestartLaunchEvidenceV1::try_new(
        "runner-launch-binding/v1",
        format!("{{\"launch\":\"{label}\"}}").into_bytes(),
        clean_runner.launch_intended_store_head.clone(),
    )
    .expect("construct exact clean-resolution launch evidence");
    let physical_terminal = CommandOutputCapturePhysicalTerminalEvidenceV1 {
        schema: "runner-terminal-record/v1".into(),
        canonical_bytes_digest: terminal_record_digest,
        store_head: clean_runner.terminal_prepared_store_head.clone(),
    };
    let physical = CommandOutputCapturePhysicalReconciliationV1::try_new(
        &capture,
        &claim,
        None,
        1,
        Some(terminal.store_head.clone()),
        Some(CommandOutputCaptureRestartStateV1::Published),
        Some(clean_runner.published_store_head.clone()),
        CommandOutputCapturePendingResolutionV1::RolledForward {
            sequence: clean_runner.terminal_prepared_store_head.generation,
            state: CommandOutputCaptureRestartStateV1::TerminalPrepared,
            record_digest: clean_runner
                .terminal_prepared_store_head
                .record_digest
                .clone(),
        },
        CommandOutputCapturePhysicalResolutionActionV1::TerminalPreparedRecovered,
        lifecycle_history,
        Some(acquired.clone()),
        CommandOutputCaptureLaunchHistoryV1::ExactLaunchEvidence {
            evidence: launch_evidence,
        },
        Some(artifacts.clone()),
        Some(physical_terminal),
        None,
        1_500,
    )
    .expect("construct exact current clean physical reconciliation");
    let resolution = CommandOutputCaptureReconciliationResolutionV1::try_new(
        &capture,
        &terminal,
        &claim,
        CommandOutputCaptureTerminalDispositionV1::Published,
        physical.final_store_head.clone(),
        physical.final_store_head.record_digest.clone(),
        Some(artifacts),
        physical.reconciled_at_unix_ms,
    )
    .expect("construct exact current clean Published resolution");
    let receipt = CommandOutputCleanScanResolutionReceiptV1::try_new_from_runner_reference(
        &capture,
        &acquired,
        &terminal,
        &claim,
        &resolution,
        None,
        SensitiveOutputDetectionPolicyReferenceV1::core_v1(),
        &clean_runner,
    )
    .expect("construct exact current clean-scan resolution receipt");
    V29UnknownCleanResolutionFixture {
        fixture,
        capture,
        acquired,
        terminal,
        permit: Some(permit),
        claim,
        physical,
        resolution,
        receipt,
        command_cleanup,
        runner_cleanup_receipt_id,
    }
}

fn open_v28_sensitive_output_test_ledger(database: &TestDatabase) -> EventLedger {
    schema_template::install_exact_database_at(28, &database.path);
    let connection = Connection::open(&database.path).expect("create v28 test database");
    register_schema_functions(&connection).expect("register v28 schema functions");
    connection
        .execute_batch(
            "PRAGMA foreign_keys = ON;
             PRAGMA synchronous = FULL;
             PRAGMA journal_mode = WAL;",
        )
        .expect("configure v28 test database");
    EventLedger {
        connection,
        database_path: database.path.clone(),
        read_only: false,
        instance_id: next_event_ledger_instance_id(),
    }
}

fn assert_v29_clean_terminal_write_set_empty(ledger: &EventLedger, terminal_event_id: &str) {
    for table in [
        "command_output_clean_scan_publication_receipts_v29",
        "command_output_capture_terminal_anchors",
        "command_output_capture_terminal_validations",
        "command_output_artifact_sets",
        "command_domain_cleanup_proofs",
        "verification_receipts",
        "verification_session_bindings",
        "verification_effect_evidence",
        "effect_evidence_payloads",
        "effect_observations",
        "task_attempt_formal_checks",
    ] {
        assert_eq!(
            row_count(ledger, table),
            0,
            "failed clean terminal leaked a row in {table}"
        );
    }
    assert!(
        !ledger
            .connection
            .query_row(
                "SELECT EXISTS (SELECT 1 FROM agent_events WHERE event_id = ?1)",
                [terminal_event_id],
                |row| row.get::<_, bool>(0),
            )
            .expect("query rejected clean terminal event"),
        "failed clean terminal leaked its terminal event"
    );
}

#[test]
fn v29_current_clean_verification_requires_exact_clean_receipt_before_any_write() {
    let mut fixture = prepare_claimed_formal_terminal_fixture(true);
    let failure = fixture
        .ledger
        .complete_claimed_task_attempt_formal_check(
            fixture.authority.take().expect("take clean authority"),
            &fixture.check,
            &fixture.observation,
            &fixture.terminal,
            &fixture.evidence,
        )
        .expect_err("current clean verification cannot omit its typed clean receipt");
    assert!(failure.has_retry_authority());
    assert_v29_clean_terminal_write_set_empty(&fixture.ledger, &fixture.terminal.event_id);

    let (_, retry_authority) = failure.into_parts();
    fixture
        .ledger
        .complete_claimed_task_attempt_formal_check_with_output_capture(
            retry_authority.expect("missing-receipt failure returns exact authority"),
            &fixture.check,
            &fixture.observation,
            &fixture.terminal,
            &fixture.evidence,
            fixture
                .capture_terminal
                .as_ref()
                .expect("exact clean terminal"),
            fixture
                .clean_scan_receipt
                .as_ref()
                .expect("exact clean-scan receipt"),
            fixture
                .command_cleanup
                .as_ref()
                .expect("exact command cleanup"),
        )
        .expect("exact clean receipt authorizes the atomic verification write");
    assert_eq!(
        fixture
            .ledger
            .load_command_output_clean_scan_publication_receipt_for_effect(
                &fixture.intent.effect_id,
            )
            .expect("read exact persisted clean receipt"),
        fixture
            .clean_scan_receipt
            .clone()
            .expect("fixture clean receipt")
    );
}

#[test]
#[allow(
    clippy::too_many_lines,
    reason = "one negative proof exercises task and sprint finish against the same deliberately incomplete clean-publication authority"
)]
fn v29_missing_current_clean_receipt_cannot_prove_task_or_sprint_finish() {
    let mut fixture = prepare_claimed_formal_terminal_fixture(true);
    fixture
        .ledger
        .complete_claimed_task_attempt_formal_check_with_output_capture(
            fixture.authority.take().expect("take clean authority"),
            &fixture.check,
            &fixture.observation,
            &fixture.terminal,
            &fixture.evidence,
            fixture
                .capture_terminal
                .as_ref()
                .expect("exact clean terminal"),
            fixture
                .clean_scan_receipt
                .as_ref()
                .expect("exact clean-scan receipt"),
            fixture
                .command_cleanup
                .as_ref()
                .expect("exact command cleanup"),
        )
        .expect("commit exact current clean publication");
    assert!(
        command_output_capture_authority::finish_is_proven_for_effect(
            &fixture.ledger.connection,
            &fixture.intent.effect_id,
        )
        .expect("current clean finish is initially exact")
    );
    assert!(matches!(
        fixture
            .ledger
            .load_command_output_publication_authority_for_effect(&fixture.intent.effect_id)
            .expect("load exact current publication authority"),
        CommandOutputPublicationAuthorityV1::CurrentPolicy { .. }
    ));
    fixture
        .ledger
        .load_verification_effect_evidence(&fixture.evidence.verification.receipt_id)
        .expect("current verification evidence initially has exact output custody");

    fixture
        .ledger
        .connection
        .execute_batch(
            "DROP TRIGGER command_output_clean_scan_publication_no_delete;
             DELETE FROM command_output_clean_scan_publication_receipts_v29;",
        )
        .expect("inject a missing clean receipt below the immutable SQL boundary");

    assert!(
        !command_output_capture_authority::finish_is_proven_for_effect(
            &fixture.ledger.connection,
            &fixture.intent.effect_id,
        )
        .expect("missing current receipt is an unproven task finish")
    );
    assert!(
        !command_output_capture_authority::sprint_finish_is_proven(
            &fixture.ledger.connection,
            &fixture.intent.sprint_id,
        )
        .expect("missing current receipt is an unproven sprint finish")
    );
    assert!(matches!(
        fixture
            .ledger
            .load_command_output_publication_authority_for_effect(&fixture.intent.effect_id),
        Err(LedgerError::Corrupt {
            entity: "command output publication authority",
            ..
        })
    ));
    assert!(matches!(
        fixture
            .ledger
            .load_verification_effect_evidence(&fixture.evidence.verification.receipt_id),
        Err(LedgerError::Corrupt {
            entity: "verification effect evidence",
            ..
        })
    ));
    assert!(matches!(
        fixture
            .ledger
            .classify_command_output_capture_recovery(
                fixture
                    .capture_terminal
                    .as_ref()
                    .expect("fixture capture terminal")
                    .capture_id
                    .as_str(),
            )
            .expect("classify missing-receipt current publication"),
        CommandOutputCaptureRecovery::ReconciliationRequired(_)
    ));
    let exact_finish_rows = fixture
        .ledger
        .connection
        .query_row(
            "SELECT COUNT(*) FROM command_output_exact_v27_finishes_v29
             WHERE effect_id = ?1",
            [&fixture.intent.effect_id],
            |row| row.get::<_, i64>(0),
        )
        .expect("query exact finish projection after receipt loss");
    assert_eq!(exact_finish_rows, 0);
}

#[test]
#[allow(
    clippy::too_many_lines,
    reason = "one adversarial acceptance test proves raw-SQL/API parity, retry custody, exact atomic readback, and Unknown precedence"
)]
fn v29_current_unknown_publication_requires_exact_clean_resolution_receipt() {
    let mut exact = v29_unknown_clean_resolution_fixture("exact");

    let raw = exact
        .fixture
        .ledger
        .connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .expect("start v1-only current resolution probe");
    v27_insert_raw_restart_receipt(&raw, &exact.physical, None)
        .expect("stage exact legacy physical receipt");
    v27_insert_raw_consumed_reconciliation_release(
        &raw,
        &exact.claim,
        &exact.terminal.terminal_anchor_digest,
        exact.resolution.resolved_at_unix_ms,
    )
    .expect("stage exact consumed claim for v1-only probe");
    let raw_error = v27_insert_raw_reconciliation_resolution(
        &raw,
        &exact.resolution,
        &exact.physical.reconciliation_digest,
        &exact.command_cleanup.proof_id,
        &exact.runner_cleanup_receipt_id,
    )
    .expect_err("v1 physical authority alone cannot publish current-policy output");
    assert!(
        raw_error.to_string().contains(
            "current-policy Unknown publication requires exact clean-scan resolution receipt"
        ),
        "unexpected v1-only raw rejection: {raw_error}"
    );
    raw.rollback().expect("roll back v1-only probe");

    let missing = exact
        .fixture
        .ledger
        .resolve_claimed_command_output_capture_unknown(
            exact.permit.take().expect("take exact permit"),
            &exact.resolution,
            Some(&exact.physical),
            None,
            &exact.command_cleanup,
            &exact.runner_cleanup_receipt_id,
        )
        .expect_err("Rust API rejects a missing clean-resolution receipt");
    assert!(missing.has_retry_permit());
    let (_, retry_permit) = missing.into_parts();
    exact.permit = retry_permit;

    let crossed = v29_unknown_clean_resolution_fixture("crossed");
    let crossed_failure = exact
        .fixture
        .ledger
        .resolve_claimed_command_output_capture_unknown(
            exact.permit.take().expect("take retry permit"),
            &exact.resolution,
            Some(&exact.physical),
            Some(&crossed.receipt),
            &exact.command_cleanup,
            &exact.runner_cleanup_receipt_id,
        )
        .expect_err("crossed clean-resolution receipt cannot authorize another capture");
    assert!(crossed_failure.has_retry_permit());
    let (_, retry_permit) = crossed_failure.into_parts();
    exact.permit = retry_permit;
    assert_eq!(
        row_count(
            &exact.fixture.ledger,
            "command_output_clean_scan_resolution_receipts_v29"
        ),
        0
    );
    assert_eq!(
        row_count(
            &exact.fixture.ledger,
            "command_output_capture_reconciliation_resolutions"
        ),
        0
    );

    let resolved = exact
        .fixture
        .ledger
        .resolve_claimed_command_output_capture_unknown(
            exact.permit.take().expect("take exact retry permit"),
            &exact.resolution,
            Some(&exact.physical),
            Some(&exact.receipt),
            &exact.command_cleanup,
            &exact.runner_cleanup_receipt_id,
        )
        .expect("exact current clean-resolution authority commits atomically");
    assert_eq!(resolved.intent, exact.capture);
    assert_eq!(resolved.acquired.as_ref(), Some(&exact.acquired));
    assert_eq!(resolved.terminal.as_ref(), Some(&exact.terminal));
    assert_eq!(
        resolved.reconciliation_resolution.as_ref(),
        Some(&exact.resolution)
    );
    assert_eq!(
        exact
            .fixture
            .ledger
            .load_command_output_clean_scan_resolution_receipt_for_effect(
                &exact.fixture.intent.effect_id,
            )
            .expect("read exact current clean-resolution receipt"),
        exact.receipt
    );
    assert!(matches!(
        exact
            .fixture
            .ledger
            .load_command_output_publication_authority_for_effect(
                &exact.fixture.intent.effect_id,
            )
            .expect("load exact resolution publication authority"),
        CommandOutputPublicationAuthorityV1::CurrentPolicyResolution {
            clean_scan_resolution_receipt,
            ..
        } if *clean_scan_resolution_receipt == exact.receipt
    ));
    assert!(
        command_output_capture_authority::finish_is_proven_for_effect(
            &exact.fixture.ledger.connection,
            &exact.fixture.intent.effect_id,
        )
        .expect("clean Published resolution closes output custody")
    );
    assert_eq!(
        exact
            .fixture
            .ledger
            .connection
            .query_row(
                "SELECT COUNT(*) FROM command_output_clean_scan_resolution_exact_v29
                 WHERE effect_id = ?1",
                [&exact.fixture.intent.effect_id],
                |row| row.get::<_, i64>(0),
            )
            .expect("query exact clean-resolution view"),
        1
    );
    assert_eq!(
        exact
            .fixture
            .ledger
            .connection
            .query_row(
                "SELECT COUNT(*) FROM command_output_exact_v27_finishes_v29
                 WHERE effect_id = ?1",
                [&exact.fixture.intent.effect_id],
                |row| row.get::<_, i64>(0),
            )
            .expect("query exact current Published finish"),
        1
    );

    let persisted_effect = exact
        .fixture
        .ledger
        .load_effect(&exact.fixture.intent.effect_id)
        .expect("reload immutable Unknown effect");
    assert!(matches!(
        persisted_effect
            .observation
            .as_ref()
            .map(|value| &value.outcome),
        Some(EffectOutcome::Unknown { .. })
    ));
    assert!(
        !exact
            .fixture
            .ledger
            .assess_task_done(&exact.fixture.intent.sprint_id, "task-1")
            .expect("assess TaskDone with immutable Unknown effect")
            .is_done(),
        "clean storage resolution must not upgrade an Unknown effect to verified task success"
    );
    assert_eq!(
        row_count(&exact.fixture.ledger, "verification_effect_evidence"),
        0,
        "clean resolution cannot mint verification evidence"
    );

    let database_path = exact.fixture.database.path.clone();
    drop(exact.fixture.ledger);
    let reopened = EventLedger::open(&database_path).expect("reopen clean-resolution ledger");
    assert_eq!(
        reopened
            .load_command_output_clean_scan_resolution_receipt_for_effect(
                &exact.fixture.intent.effect_id,
            )
            .expect("restart readback keeps exact clean-resolution authority"),
        exact.receipt
    );
    assert!(matches!(
        reopened
            .classify_command_output_capture_recovery(&exact.capture.capture_id)
            .expect("restart classifies exact resolution terminal"),
        CommandOutputCaptureRecovery::Terminal(_)
    ));
}

#[test]
fn v29_missing_committed_clean_resolution_receipt_revokes_publication_finish() {
    let mut fixture = v29_unknown_clean_resolution_fixture("missing-after-commit");
    fixture
        .fixture
        .ledger
        .resolve_claimed_command_output_capture_unknown(
            fixture.permit.take().expect("take clean-resolution permit"),
            &fixture.resolution,
            Some(&fixture.physical),
            Some(&fixture.receipt),
            &fixture.command_cleanup,
            &fixture.runner_cleanup_receipt_id,
        )
        .expect("commit exact clean-resolution authority");
    fixture
        .fixture
        .ledger
        .connection
        .execute_batch(
            "DROP TRIGGER command_output_clean_scan_resolution_no_delete;
             DELETE FROM command_output_clean_scan_resolution_receipts_v29;",
        )
        .expect("inject missing resolution receipt below immutable storage boundary");
    assert!(
        !command_output_capture_authority::finish_is_proven_for_effect(
            &fixture.fixture.ledger.connection,
            &fixture.fixture.intent.effect_id,
        )
        .expect("missing current resolution receipt is unproven")
    );
    assert!(matches!(
        fixture
            .fixture
            .ledger
            .load_command_output_publication_authority_for_effect(
                &fixture.fixture.intent.effect_id,
            ),
        Err(LedgerError::Corrupt {
            entity: "command output publication authority",
            ..
        })
    ));
    assert_eq!(
        fixture
            .fixture
            .ledger
            .connection
            .query_row(
                "SELECT COUNT(*) FROM command_output_exact_v27_finishes_v29
                 WHERE effect_id = ?1",
                [&fixture.fixture.intent.effect_id],
                |row| row.get::<_, i64>(0),
            )
            .expect("query finish after receipt loss"),
        0
    );
}

#[test]
#[allow(
    clippy::too_many_lines,
    reason = "all eight journal heads plus platform and terminal crossings share one retry-custody proof"
)]
fn v29_clean_runner_full_chain_profile_and_terminal_crossings_fail_atomically() {
    let mut fixture = prepare_claimed_formal_terminal_fixture(true);
    let valid_receipt = fixture
        .clean_scan_receipt
        .clone()
        .expect("fixture clean-scan receipt");
    let mut authority = fixture.authority.take().expect("take clean authority");

    for generation in 1_u64..=8 {
        let mut crossed = valid_receipt.clone();
        let head = match generation {
            1 => &mut crossed.intent_bound_journal_head,
            2 => &mut crossed.acquired_bound_journal_head,
            3 => &mut crossed.writer_attached_journal_head,
            4 => &mut crossed.launch_intended_journal_head,
            5 => &mut crossed.scanned_clean_journal_head,
            6 => &mut crossed.finished_journal_head,
            7 => &mut crossed.published_journal_head,
            8 => &mut crossed.terminal_prepared_journal_head,
            _ => unreachable!("closed generation set"),
        };
        head.record_digest =
            Digest::sha256(format!("crossed-v29-clean-journal-generation-{generation}").as_bytes());
        let failure = fixture
            .ledger
            .complete_claimed_task_attempt_formal_check_with_output_capture(
                authority,
                &fixture.check,
                &fixture.observation,
                &fixture.terminal,
                &fixture.evidence,
                fixture
                    .capture_terminal
                    .as_ref()
                    .expect("exact clean terminal"),
                &crossed,
                fixture
                    .command_cleanup
                    .as_ref()
                    .expect("exact command cleanup"),
            )
            .expect_err("every crossed clean journal head must fail before commit");
        assert!(failure.has_retry_authority());
        assert_v29_clean_terminal_write_set_empty(&fixture.ledger, &fixture.terminal.event_id);
        authority = failure
            .into_parts()
            .1
            .expect("journal-head rejection preserves exact retry authority");
    }

    let mut crossed_backend = fixture
        .command_cleanup
        .clone()
        .expect("fixture command cleanup");
    crossed_backend.backend = CommandDomainBackend::MacOsDedicatedIdentity;
    let failure = fixture
        .ledger
        .complete_claimed_task_attempt_formal_check_with_output_capture(
            authority,
            &fixture.check,
            &fixture.observation,
            &fixture.terminal,
            &fixture.evidence,
            fixture
                .capture_terminal
                .as_ref()
                .expect("exact clean terminal"),
            &valid_receipt,
            &crossed_backend,
        )
        .expect_err("Linux zero-dump profile cannot cross a macOS cleanup backend");
    assert!(failure.has_retry_authority());
    assert_v29_clean_terminal_write_set_empty(&fixture.ledger, &fixture.terminal.event_id);
    authority = failure
        .into_parts()
        .1
        .expect("profile/backend rejection preserves retry authority");

    let capture = fixture
        .ledger
        .load_command_output_capture_for_effect(&fixture.intent.effect_id)
        .expect("load pristine current capture");
    let crossed_terminal = v27_test_published_capture_terminal(
        &capture.intent,
        capture.acquired.as_ref().expect("pristine acquisition"),
        &fixture.observation,
        fixture
            .evidence
            .output_artifacts
            .clone()
            .expect("exact output artifacts"),
        "v29-crossed-clean-terminal",
        fixture
            .capture_terminal
            .as_ref()
            .expect("fixture clean terminal")
            .anchored_at_unix_ms,
    );
    assert_ne!(
        crossed_terminal.terminal_anchor_digest,
        valid_receipt.terminal_anchor_digest
    );
    let failure = fixture
        .ledger
        .complete_claimed_task_attempt_formal_check_with_output_capture(
            authority,
            &fixture.check,
            &fixture.observation,
            &fixture.terminal,
            &fixture.evidence,
            &crossed_terminal,
            &valid_receipt,
            fixture
                .command_cleanup
                .as_ref()
                .expect("exact command cleanup"),
        )
        .expect_err("clean receipt cannot authorize a different valid terminal");
    assert!(failure.has_retry_authority());
    assert_v29_clean_terminal_write_set_empty(&fixture.ledger, &fixture.terminal.event_id);
    authority = failure
        .into_parts()
        .1
        .expect("terminal crossing preserves retry authority");

    fixture
        .ledger
        .complete_claimed_task_attempt_formal_check_with_output_capture(
            authority,
            &fixture.check,
            &fixture.observation,
            &fixture.terminal,
            &fixture.evidence,
            fixture
                .capture_terminal
                .as_ref()
                .expect("exact clean terminal"),
            &valid_receipt,
            fixture
                .command_cleanup
                .as_ref()
                .expect("exact command cleanup"),
        )
        .expect("uncrossed full clean chain commits atomically");
}

#[test]
#[allow(
    clippy::too_many_lines,
    reason = "one acceptance test audits the full atomic write, exact readback, TaskDone projection, and no-artifact invariants"
)]
fn v29_claimed_sensitive_output_rejection_is_atomic_exact_and_artifact_free() {
    let (
        mut fixture,
        capture,
        acquired,
        authority,
        observation,
        event,
        anchor,
        cleanup,
        command_cleanup,
    ) = v29_sensitive_rejection_fixture("fresh");
    let persisted = fixture
        .ledger
        .record_claimed_command_sensitive_output_rejection(
            authority,
            &observation,
            &event,
            &anchor,
            &cleanup,
            &command_cleanup,
        )
        .expect("commit exact claimed sensitive-output rejection");
    assert_eq!(persisted.observation.as_ref(), Some(&observation));
    assert_eq!(
        persisted.evidence_bytes.as_deref(),
        Some(anchor.canonical_evidence_bytes().unwrap().as_slice())
    );

    let rejection = fixture
        .ledger
        .load_command_output_sensitive_rejection_for_effect(&fixture.intent.effect_id)
        .expect("read back exact sensitive-output rejection");
    assert_eq!(rejection.anchor, anchor);
    assert_eq!(rejection.cleanup, cleanup);
    assert_eq!(
        rejection.closure.closed_at_unix_ms,
        command_cleanup.cleaned_at_unix_ms
    );
    let capture_readback = fixture
        .ledger
        .load_command_output_capture_for_effect(&fixture.intent.effect_id)
        .expect("read back exact underlying capture");
    assert_eq!(capture_readback.intent, capture);
    assert_eq!(capture_readback.acquired.as_ref(), Some(&acquired));
    assert!(capture_readback.terminal.is_none());
    assert!(capture_readback.reconciliation_obligation_closure.is_none());
    assert!(matches!(
        fixture
            .ledger
            .classify_command_output_capture_recovery(&capture.capture_id)
            .expect("classify exact sensitive rejection"),
        CommandOutputCaptureRecovery::SensitiveOutputRejected {
            capture: recovered_capture,
            rejection: recovered_rejection,
        } if recovered_capture == capture_readback && *recovered_rejection == rejection
    ));
    assert!(
        command_output_capture_authority::finish_is_proven_for_effect(
            &fixture.ledger.connection,
            &fixture.intent.effect_id,
        )
        .expect("v29 exact finish query")
    );
    assert_eq!(
        row_count(&fixture.ledger, "command_output_artifact_sets"),
        0
    );
    assert_eq!(
        row_count(&fixture.ledger, "command_output_capture_terminal_anchors"),
        0
    );
    assert_eq!(
        row_count(
            &fixture.ledger,
            "command_output_sensitive_rejection_anchors_v29"
        ),
        1
    );
    assert_eq!(
        row_count(
            &fixture.ledger,
            "command_output_sensitive_rejection_cleanup_receipts_v29"
        ),
        1
    );
    assert_eq!(
        row_count(
            &fixture.ledger,
            "command_output_sensitive_rejection_closures_v29"
        ),
        1
    );
    let task_done = fixture
        .ledger
        .assess_task_done(&fixture.intent.sprint_id, "task-1")
        .expect("assess task finish after sensitive rejection");
    assert!(!task_done.is_done());
    assert!(
        !task_done
            .unmet_requirements
            .contains(&TaskDoneRequirement::CommandOutputCaptureTerminalExact)
    );
    assert!(
        task_done
            .unmet_requirements
            .contains(&TaskDoneRequirement::RequiredTaskChecksPassedOnResultSnapshot)
    );

    let admission = fixture
        .ledger
        .claim_command_output_capture_reconciliation(
            &capture.capture_id,
            "claim-after-sensitive-rejection",
            "desktop-after-sensitive-rejection",
            1_300,
            1_400,
        )
        .expect("closed rejection returns terminal admission");
    assert!(matches!(
        admission,
        CommandOutputCaptureReconciliationAdmission::Terminal(_)
    ));
}

#[test]
fn v29_migration_projects_existing_v28_capture_to_exact_policy_exemption_only() {
    let database = TestDatabase::new();
    let (effect_id, capture_id, intent_digest) = {
        let mut ledger = open_v28_sensitive_output_test_ledger(&database);
        let (_policy, launch, session) = prepare_command_domain_session(&mut ledger);
        let running = load_runner_effect_dispatch_running_boundary(&ledger.connection, &session)
            .expect("load v28 running boundary")
            .expect("v28 task worker is running");
        let lease = launch.worker_lease.as_ref().expect("v28 worker lease");
        let mut intent = effect_intent(
            "v28-sensitive-migration-effect",
            "v28-sensitive-migration-key",
            1_200,
        );
        intent.kind = EffectKind::RunCommand;
        intent.task_id = Some(lease.task_id.clone());
        intent.worker_id = Some(lease.worker_id.clone());
        intent.worker_lease = Some(lease.clone());
        intent.causation_event_id = Some(running.transition_event_id.clone());
        intent.correlation_id = "v28-sensitive-migration-correlation".into();
        intent.policy_hash = launch.policy_hash.clone();
        let proposal = effect_proposal_event(
            &intent,
            ledger
                .next_sequence(&intent.sprint_id)
                .expect("v28 migration proposal sequence"),
            "v28-sensitive-migration-proposal",
        );
        let capture = v27_test_capture_intent(&intent, &launch, &session, "v28-migration");
        let admission = ledger
            .admit_runner_command_output_capture_intent_for_dispatch(
                &intent,
                EFFECT_REQUEST_BYTES,
                &proposal,
                &session.session_id,
                &capture,
            )
            .expect("admit v28 capture before migration");
        assert!(matches!(
            admission,
            CommandOutputCaptureIntentAdmission::Fresh { .. }
        ));
        (intent.effect_id, capture.capture_id, capture.intent_digest)
    };

    let migrated = EventLedger::open(&database.path).expect("migrate exact v28 capture to v29");
    let exemption: (String, String) = migrated
        .connection
        .query_row(
            "SELECT capture_id, intent_digest
             FROM pre_v29_sensitive_output_policy_exemptions WHERE effect_id = ?1",
            [&effect_id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .expect("load exact pre-v29 policy exemption");
    assert_eq!(exemption.0, capture_id);
    assert_eq!(exemption.1, intent_digest.as_str());
    assert_eq!(
        row_count(
            &migrated,
            "command_output_sensitive_detection_policy_admissions_v29"
        ),
        0
    );
    let restored = migrated
        .load_command_output_capture_for_effect(&effect_id)
        .expect("read exact migrated capture");
    assert_eq!(restored.intent.capture_id, capture_id);
    assert!(matches!(
        migrated.load_sensitive_output_detection_policy_for_effect(&effect_id),
        Err(LedgerError::ArtifactNotFound { .. })
    ));
}

#[test]
#[allow(
    clippy::too_many_lines,
    reason = "the migration fixture and both raw SQL authority probes form one exact exemption fence"
)]
fn v29_pre_migration_exemption_cannot_acquire_output_or_dispatch_after_upgrade() {
    let database = TestDatabase::new();
    let (intent, capture, launch, session, running) = {
        let mut ledger = open_v28_sensitive_output_test_ledger(&database);
        let (_policy, launch, session) = prepare_command_domain_session(&mut ledger);
        let running = load_runner_effect_dispatch_running_boundary(&ledger.connection, &session)
            .expect("load pre-v29 running boundary")
            .expect("pre-v29 task worker is running");
        let lease = launch.worker_lease.as_ref().expect("pre-v29 worker lease");
        let mut intent = effect_intent(
            "v29-exempt-dispatch-fence-effect",
            "v29-exempt-dispatch-fence-key",
            1_200,
        );
        intent.kind = EffectKind::RunCommand;
        intent.task_id = Some(lease.task_id.clone());
        intent.worker_id = Some(lease.worker_id.clone());
        intent.worker_lease = Some(lease.clone());
        intent.causation_event_id = Some(running.transition_event_id.clone());
        intent.correlation_id = "v29-exempt-dispatch-fence-correlation".into();
        intent.policy_hash = launch.policy_hash.clone();
        let proposal = effect_proposal_event(
            &intent,
            ledger
                .next_sequence(&intent.sprint_id)
                .expect("pre-v29 fence proposal sequence"),
            "v29-exempt-dispatch-fence-proposal",
        );
        let capture =
            v27_test_capture_intent(&intent, &launch, &session, "v29-exempt-dispatch-fence");
        assert!(matches!(
            ledger
                .admit_runner_command_output_capture_intent_for_dispatch(
                    &intent,
                    EFFECT_REQUEST_BYTES,
                    &proposal,
                    &session.session_id,
                    &capture,
                )
                .expect("admit exact pre-v29 capture"),
            CommandOutputCaptureIntentAdmission::Fresh { .. }
        ));
        (intent, capture, launch, session, running)
    };

    let mut migrated = EventLedger::open(&database.path).expect("upgrade exemption fixture to v29");
    let transaction = migrated
        .connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .expect("start exact pre-v29 exemption probes");
    let dispatch_claim_id = runner_effect_dispatch_claim_id(&intent.effect_id);
    let acquired = v27_test_capture_acquired(
        &capture,
        dispatch_claim_id.clone(),
        "v29-exempt-dispatch-fence",
        1_250,
    );
    let acquisition_error =
        command_output_capture_authority::insert_acquired(&transaction, &capture, &acquired)
            .expect_err("pre-v29 exemption cannot reacquire output custody");
    assert!(
        acquisition_error
            .to_string()
            .contains("pre-v29 exempt command cannot acquire new output custody")
    );

    let claim = PersistedRunnerEffectDispatchClaim {
        dispatch_claim_id,
        effect_id: intent.effect_id.clone(),
        sprint_id: intent.sprint_id.clone(),
        launch_id: launch.launch_id.clone(),
        session_id: session.session_id.clone(),
        running_boundary_id: Some(running.boundary_id.clone()),
        authority: RunnerEffectRequestAuthority::TaskRunning {
            running_boundary_id: running.boundary_id,
        },
        request_digest: intent.request_digest.clone(),
        opaque_transport_request_digest: Digest::sha256(OPAQUE_RUNNER_TRANSPORT_REQUEST_BYTES),
        policy_hash: intent.policy_hash.clone(),
        input_snapshot: intent.input_snapshot.clone(),
        contract_version: intent.contract_version,
    };
    insert_runner_effect_dispatch_claim_authority(&transaction, &claim)
        .expect("stage exact dispatch authority companion");
    let dispatch_error = insert_runner_effect_dispatch_claim(&transaction, &claim)
        .expect_err("pre-v29 exemption cannot regain dispatch authority");
    assert!(
        dispatch_error
            .to_string()
            .contains("pre-v29 exempt command cannot acquire new dispatch authority")
    );
    transaction
        .rollback()
        .expect("roll back exemption fence probes");
    assert_eq!(
        row_count(&migrated, "command_output_capture_acquisitions"),
        0
    );
    assert_eq!(row_count(&migrated, "runner_effect_dispatch_claims"), 0);
    assert_eq!(
        row_count(&migrated, "runner_effect_dispatch_claim_authorities"),
        0
    );
}

#[test]
fn v29_fresh_dispatch_rejects_persisted_detector_policy_tamper_without_claim_or_acquisition() {
    let (mut fixture, _capture, permit, acquired) =
        v27_prepare_stale_capture_permit("v29-policy-tamper");
    assert_eq!(
        permit.sensitive_output_detection_policy(),
        Some(&SensitiveOutputDetectionPolicyReferenceV1::core_v1())
    );
    fixture
        .ledger
        .connection
        .execute_batch("DROP TRIGGER command_output_sensitive_policy_no_update;")
        .expect("open only the detector-policy immutability fence for corruption injection");
    fixture
        .ledger
        .connection
        .execute(
            "UPDATE command_output_sensitive_detection_policy_admissions_v29
             SET policy_digest = ?1 WHERE effect_id = ?2",
            params![
                Digest::sha256(b"crossed-persisted-detector-policy").as_str(),
                fixture.intent.effect_id,
            ],
        )
        .expect("inject normalized detector-policy crossing");

    assert!(matches!(
        fixture.ledger.claim_command_output_capture_dispatch(
            permit,
            acquired,
            OPAQUE_RUNNER_TRANSPORT_REQUEST_BYTES,
        ),
        Err(LedgerError::Corrupt {
            entity: "sensitive output detection policy",
            ..
        })
    ));
    assert_eq!(
        row_count(&fixture.ledger, "command_output_capture_acquisitions"),
        0
    );
    assert_eq!(
        row_count(&fixture.ledger, "runner_effect_dispatch_claims"),
        0
    );
}

#[test]
fn v29_policy_loader_rejects_self_consistent_non_repository_policy_bytes() {
    let (fixture, _capture, _permit, _acquired) =
        v27_prepare_stale_capture_permit("v29-policy-json-tamper");
    let substituted = SensitiveOutputDetectionPolicyReferenceV1 {
        policy_id: "substituted.detector.policy.v1".into(),
        policy_version: 1,
        policy_digest: Digest::sha256(b"self-consistent-but-not-repository-policy"),
    };
    let substituted_json =
        encode("substituted sensitive-output policy", &substituted).expect("encode substitution");
    fixture
        .ledger
        .connection
        .execute_batch(
            "DROP TRIGGER command_output_sensitive_policy_no_update;
             PRAGMA ignore_check_constraints = ON;",
        )
        .expect("open test-only below-boundary policy corruption path");
    fixture
        .ledger
        .connection
        .execute(
            "UPDATE command_output_sensitive_detection_policy_admissions_v29
             SET policy_id = ?1, policy_version = ?2, policy_digest = ?3,
                 policy_json = ?4
             WHERE effect_id = ?5",
            params![
                substituted.policy_id,
                i64::from(substituted.policy_version),
                substituted.policy_digest.as_str(),
                substituted_json,
                fixture.intent.effect_id,
            ],
        )
        .expect("inject canonical self-consistent but non-repository policy");
    fixture
        .ledger
        .connection
        .pragma_update(None, "ignore_check_constraints", false)
        .expect("restore check constraints after corruption injection");
    assert!(matches!(
        fixture
            .ledger
            .load_sensitive_output_detection_policy_for_effect(&fixture.intent.effect_id),
        Err(LedgerError::Corrupt {
            entity: "sensitive output detection policy",
            ..
        })
    ));
}

#[test]
fn v29_sensitive_rejection_rejects_crossed_cleanup_without_partial_rows() {
    let (
        mut fixture,
        _capture,
        _acquired,
        authority,
        observation,
        event,
        anchor,
        cleanup,
        mut command_cleanup,
    ) = v29_sensitive_rejection_fixture("crossed");
    command_cleanup.proof_id = "crossed-command-cleanup-proof".into();
    let failure = fixture
        .ledger
        .record_claimed_command_sensitive_output_rejection(
            authority,
            &observation,
            &event,
            &anchor,
            &cleanup,
            &command_cleanup,
        )
        .expect_err("crossed command cleanup identity must fail precommit");
    let (error, retry) = failure.into_parts();
    assert!(matches!(error, LedgerError::ReferenceMismatch { .. }));
    assert!(retry.is_some());
    assert_eq!(row_count(&fixture.ledger, "effect_observations"), 0);
    assert_eq!(
        row_count(&fixture.ledger, "command_domain_cleanup_proofs"),
        0
    );
    assert_eq!(
        row_count(
            &fixture.ledger,
            "command_output_sensitive_rejection_anchors_v29"
        ),
        0
    );
    assert_eq!(
        row_count(
            &fixture.ledger,
            "command_output_sensitive_rejection_cleanup_receipts_v29"
        ),
        0
    );
    assert_eq!(
        row_count(
            &fixture.ledger,
            "command_output_sensitive_rejection_closures_v29"
        ),
        0
    );
}

#[test]
#[allow(
    clippy::too_many_lines,
    reason = "one restart test keeps claim consumption, release readback, XOR corruption, and replay fencing together"
)]
fn v29_restart_rejection_consumes_and_reads_back_exact_latest_claim() {
    let (
        mut fixture,
        capture,
        _acquired,
        authority,
        observation,
        event,
        anchor,
        cleanup,
        command_cleanup,
    ) = v29_sensitive_rejection_fixture("restart");
    drop(authority);
    let (claim, permit) = match fixture
        .ledger
        .claim_command_output_capture_reconciliation(
            &capture.capture_id,
            Digest::sha256(b"v29-sensitive-restart-claim").as_str(),
            "desktop-v29-sensitive-restart",
            1_255,
            1_400,
        )
        .expect("claim exact restart reconciliation")
    {
        CommandOutputCaptureReconciliationAdmission::Fresh { claim, permit } => (claim, permit),
        other => panic!("fresh v29 reconciliation returned {other:?}"),
    };
    fixture
        .ledger
        .record_reconciled_command_sensitive_output_rejection(
            permit,
            &observation,
            &event,
            &anchor,
            &cleanup,
            &command_cleanup,
        )
        .expect("commit exact restart-sensitive rejection");
    let release = command_output_capture_authority::load_reconciliation_claim_release(
        &fixture.ledger.connection,
        &claim,
    )
    .expect("load exact additive v29 claim release")
    .expect("restart rejection must release its claim");
    assert_eq!(release.0, "ConsumedTerminal");
    assert_eq!(release.1, command_cleanup.cleaned_at_unix_ms);
    assert_eq!(release.2.as_ref(), Some(&anchor.rejection_anchor_digest));
    assert_eq!(
        row_count(
            &fixture.ledger,
            "command_output_sensitive_rejection_claim_releases_v29"
        ),
        1
    );
    let release_xor_probe = fixture
        .ledger
        .connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .expect("start rollback-only dual-release probe");
    release_xor_probe
        .execute_batch(
            "DROP TRIGGER
             command_output_capture_reconciliation_release_rejects_v29_sensitive_release;",
        )
        .expect("open rollback-only dual-release insertion");
    release_xor_probe
        .execute(
            "INSERT INTO command_output_capture_reconciliation_claim_releases (
                claim_id, capture_id, claim_epoch, fencing_token, release_kind,
                released_at_unix_ms, terminal_anchor_digest, successor_claim_id,
                successor_fencing_token, successor_claim_digest, contract_version
             ) VALUES (?1, ?2, ?3, ?4, 'Released', ?5, NULL, NULL, NULL, NULL, ?6)",
            params![
                claim.claim_id,
                claim.capture_id,
                sqlite_integer("dual-release claim epoch", claim.claim_epoch)
                    .expect("claim epoch fits SQLite"),
                claim.fencing_token.as_str(),
                sqlite_integer("dual-release time", command_cleanup.cleaned_at_unix_ms + 1)
                    .expect("dual-release time fits SQLite"),
                i64::from(claim.contract_version),
            ],
        )
        .expect("inject individually valid legacy release beside v29 release");
    let xor_error = command_output_capture_authority::load_reconciliation_claim_release(
        &release_xor_probe,
        &claim,
    )
    .expect_err("exact readback must reject dual release families");
    assert!(matches!(xor_error, LedgerError::Corrupt { .. }));
    drop(release_xor_probe);
    assert!(matches!(
        fixture
            .ledger
            .classify_command_output_capture_recovery(&capture.capture_id)
            .expect("restart readback classifies exact rejection"),
        CommandOutputCaptureRecovery::SensitiveOutputRejected { .. }
    ));
    assert!(matches!(
        fixture
            .ledger
            .claim_command_output_capture_reconciliation(
                &capture.capture_id,
                "claim-after-reconciled-rejection",
                "desktop-after-reconciled-rejection",
                1_300,
                1_400,
            )
            .expect("closed restart rejection returns terminal"),
        CommandOutputCaptureReconciliationAdmission::Terminal(_)
    ));
}

#[test]
fn v29_multiple_current_commands_share_one_exact_policy_without_exemption() {
    let mut fixture = prepare_fresh_command_dispatch_input("same-policy-one");
    let first_capture = v27_test_capture_intent(
        &fixture.intent,
        &fixture.launch,
        &fixture.session,
        "same-policy-one",
    );
    let first = fixture
        .ledger
        .admit_runner_command_output_capture_intent_for_dispatch(
            &fixture.intent,
            EFFECT_REQUEST_BYTES,
            &fixture.proposal,
            &fixture.session.session_id,
            &first_capture,
        )
        .expect("admit first current command");
    assert!(matches!(
        first,
        CommandOutputCaptureIntentAdmission::Fresh { .. }
    ));

    let lease = fixture.launch.worker_lease.as_ref().expect("worker lease");
    let mut second_intent = effect_intent(
        "fresh-dispatch-effect-same-policy-two",
        "fresh-dispatch-key-same-policy-two",
        1_300,
    );
    second_intent.kind = EffectKind::RunCommand;
    second_intent.task_id = Some(lease.task_id.clone());
    second_intent.worker_id = Some(lease.worker_id.clone());
    second_intent.worker_lease = Some(lease.clone());
    second_intent.causation_event_id = Some(fixture.running.transition_event_id.clone());
    second_intent.correlation_id = "fresh-dispatch-correlation-same-policy-two".into();
    second_intent.policy_hash = fixture.launch.policy_hash.clone();
    let second_proposal = effect_proposal_event(
        &second_intent,
        fixture
            .ledger
            .next_sequence(&second_intent.sprint_id)
            .expect("second policy proposal sequence"),
        "fresh-dispatch-proposal-same-policy-two",
    );
    let second_capture = v27_test_capture_intent(
        &second_intent,
        &fixture.launch,
        &fixture.session,
        "same-policy-two",
    );
    let second = fixture
        .ledger
        .admit_runner_command_output_capture_intent_for_dispatch(
            &second_intent,
            EFFECT_REQUEST_BYTES,
            &second_proposal,
            &fixture.session.session_id,
            &second_capture,
        )
        .expect("admit second current command under the same policy");
    assert!(matches!(
        second,
        CommandOutputCaptureIntentAdmission::Fresh { .. }
    ));
    let first_policy = fixture
        .ledger
        .load_sensitive_output_detection_policy_for_effect(&fixture.intent.effect_id)
        .expect("load first policy");
    let second_policy = fixture
        .ledger
        .load_sensitive_output_detection_policy_for_effect(&second_intent.effect_id)
        .expect("load second policy");
    assert_eq!(first_policy, second_policy);
    assert_eq!(
        first_policy,
        SensitiveOutputDetectionPolicyReferenceV1::core_v1()
    );
    assert_eq!(
        row_count(
            &fixture.ledger,
            "command_output_sensitive_detection_policy_admissions_v29"
        ),
        2
    );
    assert_eq!(
        row_count(
            &fixture.ledger,
            "pre_v29_sensitive_output_policy_exemptions"
        ),
        0
    );
}

#[test]
fn v29_missing_current_policy_row_is_corruption_not_a_historical_exemption() {
    let (fixture, _capture, _permit, _acquired) =
        v27_prepare_stale_capture_permit("missing-current-policy-row");
    fixture
        .ledger
        .connection
        .execute_batch(
            "DROP TRIGGER command_output_sensitive_policy_no_delete;
             DELETE FROM command_output_sensitive_detection_policy_admissions_v29;",
        )
        .expect("inject a missing current-policy row below the immutable SQL boundary");

    assert!(matches!(
        fixture
            .ledger
            .load_sensitive_output_detection_policy_for_effect(&fixture.intent.effect_id),
        Err(LedgerError::Corrupt {
            entity: "sensitive output policy admission",
            ..
        })
    ));
}

#[test]
fn v29_current_capture_cannot_gain_pre_v27_or_pre_v29_exemption() {
    let mut fixture = prepare_fresh_command_dispatch_input("no-current-exemption");
    let capture = v27_test_capture_intent(
        &fixture.intent,
        &fixture.launch,
        &fixture.session,
        "no-current-exemption",
    );
    let admission = fixture
        .ledger
        .admit_runner_command_output_capture_intent_for_dispatch(
            &fixture.intent,
            EFFECT_REQUEST_BYTES,
            &fixture.proposal,
            &fixture.session.session_id,
            &capture,
        )
        .expect("admit exact current capture");
    assert!(matches!(
        admission,
        CommandOutputCaptureIntentAdmission::Fresh { .. }
    ));

    let pre_v27 = fixture
        .ledger
        .connection
        .execute(
            "INSERT INTO pre_v27_command_output_capture_exemptions (
                effect_id, sprint_id, request_digest, created_at_unix_ms,
                contract_version, intent_digest
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                fixture.intent.effect_id,
                fixture.intent.sprint_id,
                fixture.intent.request_digest.as_str(),
                sqlite_integer(
                    "test current command time",
                    fixture.intent.created_at_unix_ms
                )
                .expect("current command time fits SQLite"),
                i64::from(CONTRACT_VERSION),
                Digest::sha256(&encode("current effect", &fixture.intent).unwrap()).as_str(),
            ],
        )
        .expect_err("pre-v27 exemption remains migration-only");
    assert!(pre_v27.to_string().contains("migration-only"));
    let pre_v29 = fixture
        .ledger
        .connection
        .execute(
            "INSERT INTO pre_v29_sensitive_output_policy_exemptions (
                effect_id, capture_id, intent_digest, contract_version
             ) VALUES (?1, ?2, ?3, ?4)",
            params![
                fixture.intent.effect_id,
                capture.capture_id,
                capture.intent_digest.as_str(),
                i64::from(CONTRACT_VERSION),
            ],
        )
        .expect_err("pre-v29 exemption remains migration-only");
    assert!(pre_v29.to_string().contains("migration-only"));
    assert_eq!(
        row_count(&fixture.ledger, "pre_v27_command_output_capture_exemptions"),
        0
    );
    assert_eq!(
        row_count(
            &fixture.ledger,
            "pre_v29_sensitive_output_policy_exemptions"
        ),
        0
    );
}

#[test]
fn v29_completion_fence_rejects_cross_version_sensitive_finish() {
    let (
        mut fixture,
        _capture,
        _acquired,
        authority,
        observation,
        event,
        anchor,
        cleanup,
        command_cleanup,
    ) = v29_sensitive_rejection_fixture("cross-version");
    fixture
        .ledger
        .record_claimed_command_sensitive_output_rejection(
            authority,
            &observation,
            &event,
            &anchor,
            &cleanup,
            &command_cleanup,
        )
        .expect("finish exact v29 rejection before cross-version probe");
    let transaction = fixture
        .ledger
        .connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .expect("start rollback-only cross-version completion probe");
    isolate_v27_completion_fence(&transaction);
    let error = transaction
        .execute(
            "INSERT INTO sprint_completion_proof_states (
                sprint_id, proof_state, completion_receipt_id,
                completion_event_id, contract_version, terminal_at_unix_ms
             ) VALUES (?1, 'ProvenV9', ?2, ?3, ?4, ?5)",
            params![
                fixture.intent.sprint_id,
                "v29-cross-version-completion",
                event.event_id,
                i64::from(CONTRACT_VERSION + 1),
                sqlite_integer("test completion time", event.occurred_at_unix_ms)
                    .expect("completion time fits SQLite"),
            ],
        )
        .expect_err("cross-version exact finish cannot admit completion");
    assert!(
        error
            .to_string()
            .contains("completion requires every capture obligation and claim closed")
    );
}

#[test]
fn v29_rust_and_sql_both_enforce_detection_cleanup_rejection_observation_order() {
    let (
        mut fixture,
        _capture,
        _acquired,
        authority,
        observation,
        event,
        anchor,
        cleanup,
        command_cleanup,
    ) = v29_sensitive_rejection_fixture("time-order");
    assert!(
        CommandOutputSensitiveRejectionCleanupReceiptV1::try_new(
            &anchor,
            "v29-late-cleanup",
            cleanup.runner_cleanup.clone(),
            "v29-late-command-cleanup",
        )
        .is_err()
    );

    fixture
        .ledger
        .record_claimed_command_sensitive_output_rejection(
            authority,
            &observation,
            &event,
            &anchor,
            &cleanup,
            &command_cleanup,
        )
        .expect("commit exact ordered rejection");
    let exact_rows: i64 = fixture
        .ledger
        .connection
        .query_row(
            "SELECT COUNT(*) FROM command_output_sensitive_rejection_exact_finishes_v29
             WHERE effect_id = ?1",
            [&fixture.intent.effect_id],
            |row| row.get(0),
        )
        .expect("count exact ordered finish");
    assert_eq!(exact_rows, 1);

    let transaction = fixture
        .ledger
        .connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .expect("start rollback-only time corruption");
    transaction
        .execute_batch("DROP TRIGGER effect_observations_no_update;")
        .expect("open rollback-only observation-time mutation");
    transaction
        .execute(
            "UPDATE effect_observations SET observed_at_unix_ms = ?1
             WHERE effect_id = ?2",
            params![
                sqlite_integer(
                    "test crossed observation time",
                    command_cleanup.cleaned_at_unix_ms - 1,
                )
                .expect("crossed observation time fits SQLite"),
                fixture.intent.effect_id,
            ],
        )
        .expect("cross normalized observation time inside rollback");
    let crossed_rows: i64 = transaction
        .query_row(
            "SELECT COUNT(*) FROM command_output_sensitive_rejection_exact_finishes_v29
             WHERE effect_id = ?1",
            [&fixture.intent.effect_id],
            |row| row.get(0),
        )
        .expect("count crossed ordered finish");
    assert_eq!(crossed_rows, 0);
}

#[test]
#[allow(
    clippy::too_many_lines,
    reason = "two rollback-only corruptions share one exact completed rejection fixture"
)]
fn v29_completion_fence_rejects_injected_historical_exemption_and_unreleased_claim() {
    let (
        mut fixture,
        capture,
        _acquired,
        authority,
        observation,
        event,
        anchor,
        cleanup,
        command_cleanup,
    ) = v29_sensitive_rejection_fixture("completion-parity");
    fixture
        .ledger
        .record_claimed_command_sensitive_output_rejection(
            authority,
            &observation,
            &event,
            &anchor,
            &cleanup,
            &command_cleanup,
        )
        .expect("finish exact v29 rejection before parity probes");

    let exemption_probe = fixture
        .ledger
        .connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .expect("start rollback-only exemption coexistence probe");
    isolate_v27_completion_fence(&exemption_probe);
    exemption_probe
        .execute_batch("DROP TRIGGER pre_v27_command_output_capture_exemptions_no_insert;")
        .expect("open rollback-only historical exemption insertion");
    exemption_probe
        .execute(
            "INSERT INTO pre_v27_command_output_capture_exemptions (
                effect_id, sprint_id, request_digest, created_at_unix_ms,
                contract_version, intent_digest
             )
             SELECT effect_id, sprint_id, request_digest, created_at_unix_ms,
                    contract_version, grok_sha256(intent_json)
             FROM effect_intents WHERE effect_id = ?1",
            [&fixture.intent.effect_id],
        )
        .expect("inject exact-looking historical exemption beside current capture");
    let exemption_error = exemption_probe
        .execute(
            "INSERT INTO sprint_completion_proof_states (
                sprint_id, proof_state, completion_receipt_id,
                completion_event_id, contract_version, terminal_at_unix_ms
             ) VALUES (?1, 'ProvenV9', ?2, ?3, ?4, ?5)",
            params![
                fixture.intent.sprint_id,
                "v29-exemption-coexistence-completion",
                event.event_id,
                i64::from(CONTRACT_VERSION),
                sqlite_integer("test completion time", event.occurred_at_unix_ms)
                    .expect("completion time fits SQLite"),
            ],
        )
        .expect_err("current capture plus historical exemption must not complete");
    assert!(
        exemption_error
            .to_string()
            .contains("completion requires every capture obligation and claim closed")
    );
    drop(exemption_probe);

    let claim_probe = fixture
        .ledger
        .connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .expect("start rollback-only unreleased claim probe");
    isolate_v27_completion_fence(&claim_probe);
    claim_probe
        .execute_batch(
            "DROP TRIGGER command_output_reconciliation_claims_reject_v29_closed_capture;",
        )
        .expect("open rollback-only post-close claim insertion");
    let claim = command_output_capture_authority::reconciliation_claim_for_test(
        Digest::sha256(b"v29-unreleased-parity-claim").as_str(),
        &capture.capture_id,
        "v29-unreleased-parity-owner",
        1,
        None,
        1_300,
        1_400,
    )
    .expect("construct exact unreleased parity claim");
    claim_probe
        .execute(
            "INSERT INTO command_output_capture_reconciliation_claims (
                claim_id, capture_id, owner_id, claim_epoch, previous_claim_id,
                fencing_token, acquired_at_unix_ms, expires_at_unix_ms,
                claim_digest, contract_version, claim_json
             ) VALUES (?1, ?2, ?3, ?4, NULL, ?5, ?6, ?7, ?8, ?9, ?10)",
            params![
                claim.claim_id,
                claim.capture_id,
                claim.owner_id,
                sqlite_integer("test claim epoch", claim.claim_epoch)
                    .expect("claim epoch fits SQLite"),
                claim.fencing_token.as_str(),
                sqlite_integer("test claim acquisition", claim.acquired_at_unix_ms)
                    .expect("claim acquisition fits SQLite"),
                sqlite_integer("test claim expiry", claim.expires_at_unix_ms)
                    .expect("claim expiry fits SQLite"),
                claim.claim_digest.as_str(),
                i64::from(claim.contract_version),
                encode("test unreleased claim", &claim).expect("encode exact unreleased claim"),
            ],
        )
        .expect("inject exact but unreleased claim after closure");
    let claim_error = claim_probe
        .execute(
            "INSERT INTO sprint_completion_proof_states (
                sprint_id, proof_state, completion_receipt_id,
                completion_event_id, contract_version, terminal_at_unix_ms
             ) VALUES (?1, 'ProvenV9', ?2, ?3, ?4, ?5)",
            params![
                fixture.intent.sprint_id,
                "v29-unreleased-claim-completion",
                event.event_id,
                i64::from(CONTRACT_VERSION),
                sqlite_integer("test completion time", event.occurred_at_unix_ms)
                    .expect("completion time fits SQLite"),
            ],
        )
        .expect_err("extra unreleased claim must not complete");
    assert!(
        claim_error
            .to_string()
            .contains("completion requires every capture obligation and claim closed")
    );
}
