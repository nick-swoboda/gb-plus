#[allow(
    clippy::type_complexity,
    clippy::too_many_lines,
    reason = "the fixture builds the exact task lease, command dispatch, and eight-record rejection proof without synthetic authority"
)]
fn v30_sensitive_rejection_fixture(
    label: &str,
    max_attempts_per_task: u8,
) -> (
    FreshDispatchInputFixture,
    RunnerEffectObservationAuthority,
    EffectObservation,
    AgentEvent,
    CommandOutputSensitiveRejectionAnchorV1,
    CommandOutputSensitiveRejectionCleanupReceiptV1,
    CommandDomainCleanupProof,
) {
    assert!(max_attempts_per_task > 0);
    let database = TestDatabase::new();
    let mut ledger = EventLedger::open(&database.path).expect("open v30 rejection ledger");
    let (mut spec, graph) = sprint_fixture();
    spec.budget.max_attempts_per_task = max_attempts_per_task;
    ledger
        .create_sprint(&spec, &graph, 1_000)
        .expect("persist v30 rejection sprint");
    let (base, _, _, _, _, _, _, _) = completion_artifacts();
    ledger
        .persist_workspace_snapshot(&spec.sprint_id, &base)
        .expect("persist v30 rejection base snapshot");

    let policy = compiled_shadow_test_policy(&format!("v30-sensitive-policy-{label}"));
    let launch = runner_launch(
        &format!("v30-sensitive-launch-{label}"),
        &format!("v30-sensitive-session-{label}"),
        RunnerSessionPurpose::TaskWorker,
        Some("worker-1"),
        &policy,
        1_100,
    );
    admit_test_runner_launch(&mut ledger, &launch, &policy);
    let session = runner_session(&launch, 1_150);
    ledger
        .register_runner_session(&session, &policy)
        .expect("register v30 rejection session");
    let running = enter_test_task_attempt_running(&mut ledger, &launch, 1_160);
    let lease = launch
        .worker_lease
        .as_ref()
        .expect("v30 rejection launch carries task lease");
    let mut intent = effect_intent(
        &format!("v30-sensitive-effect-{label}"),
        &format!("v30-sensitive-key-{label}"),
        1_200,
    );
    intent.kind = EffectKind::RunCommand;
    intent.task_id = Some(lease.task_id.clone());
    intent.worker_id = Some(lease.worker_id.clone());
    intent.worker_lease = Some(lease.clone());
    intent.causation_event_id = Some(running.transition_event_id.clone());
    intent.correlation_id = format!("v30-sensitive-correlation-{label}");
    intent.policy_hash = launch.policy_hash.clone();
    let proposal = effect_proposal_event(
        &intent,
        ledger
            .next_sequence(&intent.sprint_id)
            .expect("v30 rejection proposal sequence"),
        &format!("v30-sensitive-proposal-{label}"),
    );
    let mut fixture = FreshDispatchInputFixture {
        database,
        ledger,
        launch,
        session,
        running,
        intent,
        proposal,
    };

    let capture =
        v27_test_capture_intent(&fixture.intent, &fixture.launch, &fixture.session, label);
    let permit = match fixture
        .ledger
        .admit_runner_command_output_capture_intent_for_dispatch(
            &fixture.intent,
            EFFECT_REQUEST_BYTES,
            &fixture.proposal,
            &fixture.session.session_id,
            &capture,
        )
        .expect("admit v30 rejection command")
    {
        CommandOutputCaptureIntentAdmission::Fresh { permit, .. } => permit,
        other => panic!("fresh v30 rejection admission returned {other:?}"),
    };
    let acquired = v27_test_capture_acquired(
        &capture,
        permit
            .expected_output_capture_dispatch_claim_id()
            .expect("v30 rejection dispatch identity"),
        label,
        1_250,
    );
    let (_, transport) = fixture
        .ledger
        .claim_command_output_capture_dispatch(
            permit,
            acquired.clone(),
            OPAQUE_RUNNER_TRANSPORT_REQUEST_BYTES,
        )
        .expect("claim v30 rejection dispatch");
    let authority = transport
        .validate_transport_request(
            &fixture.intent,
            EFFECT_REQUEST_BYTES,
            &fixture.launch,
            &fixture.session,
            Some(&fixture.running),
            OPAQUE_RUNNER_TRANSPORT_REQUEST_BYTES,
        )
        .expect("validate v30 rejection transport");
    let detector_policy = fixture
        .ledger
        .load_sensitive_output_detection_policy_for_effect(&fixture.intent.effect_id)
        .expect("load v30 detector policy");
    let observation_id = format!("v30-sensitive-observation-{label}");
    let command_cleanup_id = format!("v30-sensitive-command-cleanup-{label}");
    let journal_head = |generation, state: &str| SensitiveOutputJournalHeadV1 {
        generation,
        record_digest: Digest::sha256(
            format!("v30-sensitive-journal:{label}:{state}:{generation}").as_bytes(),
        ),
    };
    let store_head = |generation, state: &str| CommandOutputCaptureStoreHeadV1 {
        generation,
        record_digest: Digest::sha256(
            format!("v30-sensitive-store:{label}:{state}:{generation}").as_bytes(),
        ),
    };
    let core_dump_suppression = SensitiveOutputCoreDumpSuppressionV1::macos();
    let staging_neutralization = SensitiveOutputStagingNeutralizationReceiptV1::try_new(&acquired)
        .expect("construct v30 zero-only neutralization");
    let mut runner_cleanup = SensitiveOutputRejectionRunnerReferenceV1 {
        journal_id: format!("v30-sensitive-journal-{label}"),
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
        detector_policy,
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
        cleanup_receipt_id: format!("v30-sensitive-cleanup-{label}"),
        cleanup_receipt_digest: Digest::sha256(b"pending-v30-runner-cleanup-receipt"),
    };
    runner_cleanup
        .canonicalize_journal_heads_for_test()
        .expect("compute exact v30 rejection journal chain");
    runner_cleanup
        .validate()
        .expect("validate exact v30 rejection journal chain");
    let anchor = CommandOutputSensitiveRejectionAnchorV1::try_new(
        &capture,
        &acquired,
        observation_id.clone(),
        runner_cleanup.clone(),
    )
    .expect("construct v30 secret-free rejection anchor");
    let cleanup = CommandOutputSensitiveRejectionCleanupReceiptV1::try_new(
        &anchor,
        format!("v30-sensitive-core-cleanup-{label}"),
        runner_cleanup,
        command_cleanup_id.clone(),
    )
    .expect("construct v30 rejection cleanup receipt");
    let evidence = anchor
        .canonical_evidence_bytes()
        .expect("encode v30 secret-free rejection anchor");
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
            .expect("v30 rejection terminal sequence"),
        &format!("v30-sensitive-terminal-{label}"),
    );
    let platform_proof_bytes = format!("v30-sensitive-domain-empty:{label}").into_bytes();
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
        authority,
        observation,
        event,
        anchor,
        cleanup,
        command_cleanup,
    )
}

#[cfg(unix)]
#[test]
#[allow(
    clippy::too_many_lines,
    reason = "one restart proof covers all six atomic cuts, exact replanning, closure, lease release, and replay readback"
)]
fn v30_complete_sensitive_rejection_retries_then_replays_across_restart() {
    let (mut fixture, authority, observation, event, anchor, cleanup, command_cleanup) =
        v30_sensitive_rejection_fixture("retry", 2);
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
        .expect("commit complete v30 retry source");
    let attempt = fixture.running.attempt.clone();
    let database_path = fixture.database.path.clone();
    drop(fixture.ledger);

    let mut reopened = EventLedger::open(&database_path).expect("reopen rejection before cleanup");
    let plan = reopened
        .plan_task_attempt_cleanup_disposition(&attempt)
        .expect("derive rejection repair plan after restart");
    let expected_bytes = anchor
        .canonical_evidence_bytes()
        .expect("encode expected rejection evidence");
    assert_eq!(plan.resulting_task_state, TaskState::Ready);
    assert_eq!(
        plan.minimum_terminal_at_unix_ms(),
        observation.observed_at_unix_ms
    );
    assert!(matches!(
        &plan.outcome,
        TaskAttemptKnownCleanupOutcome::Retryable(
            crate::TaskAttemptRetryableCause::SensitiveOutputRejected {
                effect_id,
                evidence,
            }
        ) if effect_id == &anchor.effect_id
            && evidence.evidence_id == anchor.observation_id
            && evidence.kind == crate::TaskAttemptEvidenceKind::SensitiveOutputRejected
            && evidence.canonical_bytes == expected_bytes
            && evidence.digest == Digest::sha256(&expected_bytes)
    ));
    let cut_suffix = "v30-sensitive-retry";
    let baseline = v15_finish_matrix_counts(&reopened);
    for (table, identity_column, identity) in [
        (
            "task_attempt_cleanup_result_coverage",
            "disposition_id",
            plan.disposition_id.clone(),
        ),
        (
            "worker_cleanup_receipts",
            "receipt_id",
            format!("excluded-cleanup-receipt-{cut_suffix}"),
        ),
        (
            "agent_events",
            "event_id",
            format!("excluded-cleanup-finished-{cut_suffix}"),
        ),
        (
            "task_attempt_dispositions",
            "disposition_id",
            plan.disposition_id.clone(),
        ),
        (
            "worker_lease_releases",
            "lease_id",
            attempt.worker_lease.lease_id.clone(),
        ),
        ("agent_events", "event_id", plan.transition_event_id.clone()),
    ] {
        let cut_plan = plan.clone();
        v15_assert_statement_cut_rolls_back(
            &mut reopened,
            table,
            identity_column,
            &identity,
            baseline,
            move |ledger| {
                ledger.with_planned_task_attempt_cleanup_disposition_exclusion(&cut_plan, |claim| {
                    Ok(cleanup_terminal_from_live_claim(
                        claim,
                        cut_suffix,
                        observation.observed_at_unix_ms + 10,
                    ))
                })
            },
        );
        assert_eq!(
            reopened
                .plan_task_attempt_cleanup_disposition(&attempt)
                .expect("rederive exact rejection repair plan after statement cut"),
            plan
        );
    }
    let stored = reopened
        .with_planned_task_attempt_cleanup_disposition_exclusion(&plan, |claim| {
            Ok(cleanup_terminal_from_live_claim(
                claim,
                "v30-sensitive-retry",
                observation.observed_at_unix_ms + 10,
            ))
        })
        .expect("atomically close rejected attempt for retry");
    assert!(matches!(stored, TaskAttemptDisposition::Retryable(_)));
    assert_eq!(stored.resulting_task_state(), TaskState::Ready);
    assert!(
        reopened
            .load_active_worker_leases(&attempt.worker_lease.sprint_id)
            .expect("load active leases after repair closure")
            .is_empty()
    );
    drop(reopened);

    let mut replay = EventLedger::open(&database_path).expect("reopen repaired attempt");
    let replay_plan = replay
        .plan_task_attempt_cleanup_disposition(&attempt)
        .expect("rederive exact repair plan");
    assert_eq!(replay_plan, plan);
    let replayed = replay
        .with_planned_task_attempt_cleanup_disposition_exclusion(&replay_plan, |_| {
            panic!("exact replay must not invoke native cleanup")
        })
        .expect("read back exact repaired disposition");
    assert_eq!(replayed, stored);
    assert_eq!(row_count(&replay, "task_attempt_dispositions"), 1);
    assert_eq!(row_count(&replay, "worker_lease_releases"), 1);
}

#[cfg(unix)]
#[test]
fn v30_complete_sensitive_rejection_exhausts_at_exact_budget() {
    let (mut fixture, authority, observation, event, anchor, cleanup, command_cleanup) =
        v30_sensitive_rejection_fixture("exhausted", 1);
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
        .expect("commit complete v30 exhausted source");
    let attempt = fixture.running.attempt.clone();
    let plan = fixture
        .ledger
        .plan_task_attempt_cleanup_disposition(&attempt)
        .expect("derive exhausted rejection cleanup plan");
    assert_eq!(plan.resulting_task_state, TaskState::Failed);
    let stored = fixture
        .ledger
        .with_planned_task_attempt_cleanup_disposition_exclusion(&plan, |claim| {
            Ok(cleanup_terminal_from_live_claim(
                claim,
                "v30-sensitive-exhausted",
                observation.observed_at_unix_ms + 10,
            ))
        })
        .expect("atomically exhaust rejected attempt");
    assert!(matches!(
        stored,
        TaskAttemptDisposition::AttemptsExhausted(_)
    ));
    assert_eq!(stored.resulting_task_state(), TaskState::Failed);
    assert!(
        fixture
            .ledger
            .load_active_worker_leases(&attempt.worker_lease.sprint_id)
            .expect("load active leases after exhaustion")
            .is_empty()
    );
}

#[test]
fn v30_crossed_and_partial_sensitive_rejection_cannot_become_cleanup_authority() {
    let (mut fixture, authority, observation, event, anchor, cleanup, command_cleanup) =
        v30_sensitive_rejection_fixture("crossed", 2);
    let attempt = fixture.running.attempt.clone();
    assert!(
        fixture
            .ledger
            .plan_task_attempt_cleanup_disposition(&attempt)
            .is_err(),
        "an admitted capture without complete rejection is not cleanup authority"
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
        .expect("commit exact source before crossed probes");
    let exact_bytes = anchor
        .canonical_evidence_bytes()
        .expect("encode exact anchor");
    let crossed = TaskAttemptKnownCleanupOutcome::Retryable(
        crate::TaskAttemptRetryableCause::SensitiveOutputRejected {
            effect_id: "crossed-sensitive-effect".into(),
            evidence: crate::TaskAttemptEvidence::new(
                anchor.observation_id.clone(),
                crate::TaskAttemptEvidenceKind::SensitiveOutputRejected,
                exact_bytes.clone(),
            )
            .expect("construct structurally valid crossed evidence"),
        },
    );
    assert!(
        task_attempt_authority::require_preferred_current_known_cleanup_outcome_authority(
            &fixture.ledger.connection,
            &attempt,
            &crossed,
        )
        .is_err()
    );
    let partial = TaskAttemptKnownCleanupOutcome::Retryable(
        crate::TaskAttemptRetryableCause::SensitiveOutputRejected {
            effect_id: anchor.effect_id.clone(),
            evidence: crate::TaskAttemptEvidence::new(
                anchor.observation_id.clone(),
                crate::TaskAttemptEvidenceKind::SensitiveOutputRejected,
                b"structurally valid but noncanonical rejection anchor".to_vec(),
            )
            .expect("construct structurally valid partial evidence"),
        },
    );
    assert!(
        task_attempt_authority::require_preferred_current_known_cleanup_outcome_authority(
            &fixture.ledger.connection,
            &attempt,
            &partial,
        )
        .is_err()
    );
    for aliased_kind in [
        crate::TaskAttemptEvidenceKind::KnownWorkerExit,
        crate::TaskAttemptEvidenceKind::FormalVerificationFailed,
    ] {
        let aliased = TaskAttemptKnownCleanupOutcome::Retryable(
            crate::TaskAttemptRetryableCause::SensitiveOutputRejected {
                effect_id: anchor.effect_id.clone(),
                evidence: crate::TaskAttemptEvidence::new(
                    anchor.observation_id.clone(),
                    aliased_kind,
                    exact_bytes.clone(),
                )
                .expect("construct structurally valid aliased evidence"),
            },
        );
        assert!(
            aliased.validate().is_err(),
            "sensitive-output rejection must not alias worker-exit or formal-verification evidence"
        );
    }
    assert_eq!(row_count(&fixture.ledger, "task_attempt_dispositions"), 0);
    assert_eq!(row_count(&fixture.ledger, "worker_lease_releases"), 0);
}

fn v30_open_exact_v29_database(database: &TestDatabase) -> EventLedger {
    schema_template::install_exact_database_at(29, &database.path);
    let connection = Connection::open(&database.path).expect("create exact schema-v29 database");
    register_schema_functions(&connection).expect("register schema-v29 functions");
    connection
        .execute_batch(
            "PRAGMA foreign_keys = ON;
             PRAGMA synchronous = FULL;
             PRAGMA journal_mode = WAL;
             PRAGMA temp_store = MEMORY;
             PRAGMA trusted_schema = OFF;",
        )
        .expect("configure exact schema-v29 database");
    EventLedger {
        connection,
        database_path: database.path.clone(),
        read_only: false,
        instance_id: next_event_ledger_instance_id(),
    }
}

fn v30_assert_database_checks(connection: &Connection) {
    let quick_check: String = connection
        .query_row("PRAGMA quick_check(1)", [], |row| row.get(0))
        .expect("run schema-v30 quick check");
    assert_eq!(quick_check, "ok");

    let mut statement = connection
        .prepare("PRAGMA foreign_key_check")
        .expect("prepare schema-v30 foreign-key check");
    let mut rows = statement
        .query([])
        .expect("run schema-v30 foreign-key check");
    assert!(
        rows.next()
            .expect("read schema-v30 foreign-key check")
            .is_none(),
        "schema-v30 migration must preserve every foreign-key relation"
    );
}

fn v30_copy_disposition_to_check_probe(
    connection: &Connection,
    cause_kind: Option<&str>,
    evidence_kind: Option<&str>,
) -> rusqlite::Result<usize> {
    let columns = {
        let mut statement = connection.prepare("PRAGMA table_info(task_attempt_dispositions)")?;
        statement
            .query_map([], |row| row.get::<_, String>(1))?
            .collect::<Result<Vec<_>, _>>()?
    };
    let quoted_columns = columns
        .iter()
        .map(|column| format!("\"{}\"", column.replace('"', "\"\"")))
        .collect::<Vec<_>>();
    let selected_columns = columns
        .iter()
        .zip(&quoted_columns)
        .map(|(column, quoted)| match column.as_str() {
            "cause_kind" => cause_kind.map_or_else(|| quoted.clone(), |value| format!("'{value}'")),
            "evidence_kind" => {
                evidence_kind.map_or_else(|| quoted.clone(), |value| format!("'{value}'"))
            }
            _ => quoted.clone(),
        })
        .collect::<Vec<_>>();
    connection.execute(
        &format!(
            "INSERT INTO task_attempt_dispositions_v30_check_probe ({})
             SELECT {} FROM task_attempt_dispositions LIMIT 1",
            quoted_columns.join(", "),
            selected_columns.join(", ")
        ),
        [],
    )
}

fn v30_assert_disposition_check_token_matrix(connection: &Connection) {
    let table_sql: String = connection
        .query_row(
            "SELECT sql FROM sqlite_schema
             WHERE type = 'table' AND name = 'task_attempt_dispositions'",
            [],
            |row| row.get(0),
        )
        .expect("load widened task-attempt disposition DDL");
    assert_eq!(table_sql.matches("'SensitiveOutputRejected'").count(), 2);
    let probe_sql = table_sql.replacen(
        "CREATE TABLE task_attempt_dispositions",
        "CREATE TABLE task_attempt_dispositions_v30_check_probe",
        1,
    );
    connection
        .execute_batch(&probe_sql)
        .expect("create isolated schema-v30 CHECK probe");

    v30_copy_disposition_to_check_probe(connection, None, None)
        .expect("the exact old cause/evidence token pair remains admitted");
    connection
        .execute("DELETE FROM task_attempt_dispositions_v30_check_probe", [])
        .expect("clear old-token probe row");
    v30_copy_disposition_to_check_probe(
        connection,
        Some("SensitiveOutputRejected"),
        Some("SensitiveOutputRejected"),
    )
    .expect("the exact new cause/evidence token pair is admitted by both widened checks");
    connection
        .execute("DELETE FROM task_attempt_dispositions_v30_check_probe", [])
        .expect("clear new-token probe row");
    assert!(
        v30_copy_disposition_to_check_probe(connection, Some("UnknownV30Cause"), None).is_err(),
        "an unknown cause token must remain outside the closed CHECK set"
    );
    assert!(
        v30_copy_disposition_to_check_probe(connection, None, Some("UnknownV30Evidence")).is_err(),
        "an unknown evidence token must remain outside the closed CHECK set"
    );
    connection
        .execute_batch("DROP TABLE task_attempt_dispositions_v30_check_probe;")
        .expect("drop isolated schema-v30 CHECK probe");
}

struct V30LegacyDispositionFixture {
    database: TestDatabase,
    ledger: EventLedger,
    disposition: TaskAttemptDisposition,
    max_attempts_per_task: u8,
}

fn v30_v29_refusal_disposition_fixture(
    label: &str,
    max_attempts_per_task: u8,
) -> V30LegacyDispositionFixture {
    let database = TestDatabase::new();
    let mut ledger = v30_open_exact_v29_database(&database);
    let attempt = prepare_planned_refused_task_attempt(&mut ledger, label, max_attempts_per_task);
    let plan = ledger
        .plan_task_attempt_cleanup_disposition(&attempt)
        .expect("derive genuine schema-v29 launch-refusal disposition");
    let disposition = ledger
        .with_planned_task_attempt_cleanup_disposition_exclusion(&plan, |claim| {
            Ok(cleanup_terminal_from_live_claim(
                claim,
                label,
                plan.minimum_terminal_at_unix_ms() + 1,
            ))
        })
        .expect("persist genuine schema-v29 launch-refusal disposition");
    V30LegacyDispositionFixture {
        database,
        ledger,
        disposition,
        max_attempts_per_task,
    }
}

fn v30_v29_known_cleanup_disposition_fixture(
    kind: V15KnownCleanupKind,
) -> V30LegacyDispositionFixture {
    let database = TestDatabase::new();
    let mut ledger = v30_open_exact_v29_database(&database);
    let (_policy, launch, _session) = prepare_command_domain_session(&mut ledger);
    let attempt = ledger
        .load_task_attempt(
            &launch
                .worker_lease
                .as_ref()
                .expect("schema-v29 known-cleanup launch lease")
                .lease_id,
        )
        .expect("load schema-v29 known-cleanup attempt");
    let outcome = v15_known_cleanup_outcome(kind, &launch);
    ledger
        .record_task_attempt_cleanup_outcome_authority(&attempt, &outcome, 1_200)
        .expect("record genuine schema-v29 known-cleanup source");
    let suffix = format!("v30-v29-{}", kind.suffix());
    let terminal = cleanup_terminal_record(&ledger, &launch, &suffix, 1_300);
    let metadata = TaskAttemptDispositionMetadata {
        contract_version: CONTRACT_VERSION,
        disposition_id: format!("{suffix}-disposition"),
        attempt: attempt.clone(),
        from_state: TaskState::Running,
        state_transition_event_id: format!("{suffix}-transition"),
        disposed_at_unix_ms: 1_350,
    };
    let transition = AgentEvent {
        contract_version: CONTRACT_VERSION,
        sequence: terminal.event.sequence + 1,
        event_id: metadata.state_transition_event_id.clone(),
        sprint_id: attempt.worker_lease.sprint_id.clone(),
        task_id: Some(attempt.worker_lease.task_id.clone()),
        worker_id: Some(attempt.worker_lease.worker_id.clone()),
        causation_id: Some(attempt.opening_event_id.clone()),
        correlation_id: format!("{suffix}-lifecycle"),
        policy_hash: Some(launch.policy_hash.clone()),
        occurred_at_unix_ms: metadata.disposed_at_unix_ms,
        payload: AgentEventKind::TaskStateChanged {
            from: "Running".into(),
            to: format!("{:?}", kind.resulting_state()),
        },
    };
    let disposition = ledger
        .with_task_attempt_cleanup_disposition_exclusion(
            &metadata,
            &outcome,
            &format!("{suffix}-release"),
            &transition,
            |_| Ok(terminal),
        )
        .expect("persist genuine schema-v29 known-cleanup disposition");
    assert!(kind.matches(&disposition));
    V30LegacyDispositionFixture {
        database,
        ledger,
        disposition,
        max_attempts_per_task: 2,
    }
}

fn v30_v29_integrated_disposition_fixture() -> V30LegacyDispositionFixture {
    let database = TestDatabase::new();
    let mut ledger = v30_open_exact_v29_database(&database);
    let mut pending = prepare_pending_task_integration(&mut ledger);
    let (expected, transition) = pending_integration_disposition(&pending);
    let disposition =
        integrate_pending_task_attempt(&mut ledger, &mut pending, &expected, &transition)
            .expect("persist genuine schema-v29 Integrated disposition");
    assert_eq!(disposition, expected);
    V30LegacyDispositionFixture {
        database,
        ledger,
        disposition,
        max_attempts_per_task: 2,
    }
}

fn v30_v29_unknown_cleaned_disposition_fixture() -> V30LegacyDispositionFixture {
    let database = TestDatabase::new();
    let mut ledger = v30_open_exact_v29_database(&database);
    let (_policy, launch, _session) = prepare_command_domain_session(&mut ledger);
    let attempt = ledger
        .load_task_attempt(
            &launch
                .worker_lease
                .as_ref()
                .expect("schema-v29 UnknownCleaned launch lease")
                .lease_id,
        )
        .expect("load schema-v29 UnknownCleaned attempt");
    let (intent, proposal, permit) =
        persist_command_domain_intent(&mut ledger, &launch, "v30-v29-unknown-cleaned", 1_200);
    let observation = persist_command_domain_observation(
        &mut ledger,
        &intent,
        &proposal,
        permit,
        EffectOutcome::Unknown {
            evidence_digest: effect_evidence_digest(),
        },
        1_250,
    );
    let unknown = crate::TaskAttemptUnknownEvidence {
        effect_id: intent.effect_id.clone(),
        observation_id: observation.observation_id,
        evidence: crate::TaskAttemptEvidence::new(
            "v30-v29-unknown-cleaned-evidence".into(),
            crate::TaskAttemptEvidenceKind::UnknownTerminalEffect,
            EFFECT_EVIDENCE_BYTES.to_vec(),
        )
        .expect("construct genuine schema-v29 UnknownCleaned evidence"),
    };
    let terminal =
        cleanup_terminal_record(&ledger, &launch, "v30-v29-unknown-cleaned-cleanup", 1_300);
    let (metadata, mut transition) = v15_unknown_metadata(
        &ledger,
        &attempt,
        "v30-v29-unknown-cleaned-disposition",
        "v30-v29-unknown-cleaned-transition",
        1_350,
    );
    transition.sequence = terminal.event.sequence + 1;
    let marker = v15_unknown_marker(&metadata);
    let disposition = ledger
        .with_task_attempt_unknown_cleaned_disposition_exclusion(
            &metadata,
            &unknown,
            "v30-v29-unknown-cleaned-release",
            &marker,
            &transition,
            |_| Ok(terminal),
        )
        .expect("persist genuine schema-v29 UnknownCleaned disposition");
    assert!(matches!(
        disposition,
        TaskAttemptDisposition::UnknownCleaned(_)
    ));
    V30LegacyDispositionFixture {
        database,
        ledger,
        disposition,
        max_attempts_per_task: 2,
    }
}

fn v30_v29_unknown_quarantined_disposition_fixture() -> V30LegacyDispositionFixture {
    let database = TestDatabase::new();
    let mut ledger = v30_open_exact_v29_database(&database);
    let (_policy, launch, _session) = prepare_command_domain_session(&mut ledger);
    let attempt = ledger
        .load_task_attempt(
            &launch
                .worker_lease
                .as_ref()
                .expect("schema-v29 UnknownQuarantined launch lease")
                .lease_id,
        )
        .expect("load schema-v29 UnknownQuarantined attempt");
    let (intent, proposal, permit) =
        persist_command_domain_intent(&mut ledger, &launch, "v30-v29-unknown-quarantine", 1_200);
    let observation = persist_command_domain_observation(
        &mut ledger,
        &intent,
        &proposal,
        permit,
        EffectOutcome::Unknown {
            evidence_digest: effect_evidence_digest(),
        },
        1_250,
    );
    let (metadata, transition) = v15_unknown_metadata(
        &ledger,
        &attempt,
        "v30-v29-unknown-quarantine-disposition",
        "v30-v29-unknown-quarantine-transition",
        1_300,
    );
    let marker = v15_unknown_marker(&metadata);
    let uncertain = crate::TaskAttemptUncertainEvidence {
        uncertainty_id: "v30-v29-unknown-quarantine-authority".into(),
        authority_reference_ids: vec![observation.observation_id],
        evidence: crate::TaskAttemptEvidence::new(
            "v30-v29-unknown-quarantine-evidence".into(),
            crate::TaskAttemptEvidenceKind::UncertainAuthority,
            b"schema-v29 native survival remains uncertain".to_vec(),
        )
        .expect("construct genuine schema-v29 UnknownQuarantined evidence"),
    };
    let disposition = ledger
        .quarantine_task_attempt_unknown(&metadata, &uncertain, &marker, &transition)
        .expect("persist genuine schema-v29 UnknownQuarantined disposition");
    assert!(matches!(
        disposition,
        TaskAttemptDisposition::UnknownQuarantined(_)
    ));
    V30LegacyDispositionFixture {
        database,
        ledger,
        disposition,
        max_attempts_per_task: 2,
    }
}

fn v30_disposition_bytes_and_sql_index(
    ledger: &EventLedger,
    disposition_id: &str,
    max_attempts_per_task: u8,
) -> (Vec<u8>, String) {
    let (bytes, sql_index) = ledger
        .connection
        .query_row(
            "SELECT disposition_json,
                    grok_task_attempt_disposition_index(disposition_json, ?2)
             FROM task_attempt_dispositions WHERE disposition_id = ?1",
            params![disposition_id, i64::from(max_attempts_per_task)],
            |row| Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, String>(1)?)),
        )
        .expect("load canonical disposition bytes and SQL index");
    assert_eq!(
        sql_index,
        task_attempt_authority::disposition_sql_index(&bytes, max_attempts_per_task)
            .expect("derive matching Rust disposition index")
    );
    (bytes, sql_index)
}

fn v30_capture_historical_rows(connection: &Connection) -> Vec<(String, Vec<Vec<String>>)> {
    capture_all_historical_rows(connection)
}

fn v30_capture_matching_historical_rows(
    connection: &Connection,
    baseline: &[(String, Vec<Vec<String>>)],
) -> Vec<(String, Vec<Vec<String>>)> {
    let historical_tables = baseline
        .iter()
        .map(|(table, _)| table.as_str())
        .collect::<std::collections::BTreeSet<_>>();
    capture_all_historical_rows(connection)
        .into_iter()
        .filter(|(table, _)| historical_tables.contains(table.as_str()))
        .collect()
}

fn v30_assert_legacy_disposition_migrates_byte_exact(
    expected_kind: &str,
    fixture: V30LegacyDispositionFixture,
) {
    let V30LegacyDispositionFixture {
        database,
        ledger,
        disposition,
        max_attempts_per_task,
    } = fixture;
    let disposition_id = disposition.metadata().disposition_id.clone();
    let stored_kind: String = ledger
        .connection
        .query_row(
            "SELECT disposition_kind FROM task_attempt_dispositions
             WHERE disposition_id = ?1",
            [&disposition_id],
            |row| row.get(0),
        )
        .expect("load genuine schema-v29 disposition kind");
    assert_eq!(stored_kind, expected_kind);
    assert_eq!(
        ledger
            .load_task_attempt_disposition(&disposition_id)
            .expect("read genuine schema-v29 disposition"),
        disposition
    );
    let bytes_and_index =
        v30_disposition_bytes_and_sql_index(&ledger, &disposition_id, max_attempts_per_task);
    let all_rows = v30_capture_historical_rows(&ledger.connection);
    drop(ledger);

    let migrated = EventLedger::open(&database.path)
        .unwrap_or_else(|error| panic!("migrate genuine v29 {expected_kind}: {error}"));
    assert_eq!(
        v30_capture_matching_historical_rows(&migrated.connection, &all_rows),
        all_rows
    );
    assert_eq!(
        migrated
            .load_task_attempt_disposition(&disposition_id)
            .expect("read migrated legacy disposition"),
        disposition
    );
    assert_eq!(
        v30_disposition_bytes_and_sql_index(&migrated, &disposition_id, max_attempts_per_task,),
        bytes_and_index
    );
    v30_assert_database_checks(&migrated.connection);
    drop(migrated);

    let read_only = EventLedger::open_read_only(&database.path)
        .unwrap_or_else(|error| panic!("read-only reopen migrated {expected_kind}: {error}"));
    assert_eq!(
        read_only
            .load_task_attempt_disposition(&disposition_id)
            .expect("read exact legacy disposition after read-only reopen"),
        disposition
    );
    assert_eq!(
        v30_disposition_bytes_and_sql_index(&read_only, &disposition_id, max_attempts_per_task,),
        bytes_and_index
    );
}

#[cfg(unix)]
#[test]
#[allow(
    clippy::too_many_lines,
    reason = "all eight closed schema-v29 variants must independently survive the exceptional schema-text widening"
)]
fn v30_all_eight_legacy_disposition_variants_migrate_byte_exact() {
    v30_assert_legacy_disposition_migrates_byte_exact(
        "Integrated",
        v30_v29_integrated_disposition_fixture(),
    );
    v30_assert_legacy_disposition_migrates_byte_exact(
        "Retryable",
        v30_v29_known_cleanup_disposition_fixture(V15KnownCleanupKind::Retryable),
    );
    v30_assert_legacy_disposition_migrates_byte_exact(
        "AttemptsExhausted",
        v30_v29_refusal_disposition_fixture("v30-v29-attempts-exhausted", 1),
    );
    v30_assert_legacy_disposition_migrates_byte_exact(
        "PermanentFailure",
        v30_v29_known_cleanup_disposition_fixture(V15KnownCleanupKind::PermanentFailure),
    );
    v30_assert_legacy_disposition_migrates_byte_exact(
        "Blocked",
        v30_v29_known_cleanup_disposition_fixture(V15KnownCleanupKind::Blocked),
    );
    v30_assert_legacy_disposition_migrates_byte_exact(
        "Canceled",
        v30_v29_known_cleanup_disposition_fixture(V15KnownCleanupKind::Canceled),
    );
    v30_assert_legacy_disposition_migrates_byte_exact(
        "UnknownCleaned",
        v30_v29_unknown_cleaned_disposition_fixture(),
    );
    v30_assert_legacy_disposition_migrates_byte_exact(
        "UnknownQuarantined",
        v30_v29_unknown_quarantined_disposition_fixture(),
    );
}

#[cfg(unix)]
#[test]
#[allow(
    clippy::too_many_lines,
    reason = "one migration proof binds populated v29 byte custody, all referring rows, checks, and both reopen modes"
)]
fn v30_populated_v29_migrates_byte_exact_and_reopens_read_write_and_read_only() {
    let database = TestDatabase::new();
    let mut v29 = v30_open_exact_v29_database(&database);
    let attempt = prepare_planned_refused_task_attempt(&mut v29, "v30-migration-old-row", 2);
    let plan = v29
        .plan_task_attempt_cleanup_disposition(&attempt)
        .expect("derive an old schema-v29 retry disposition");
    let old_disposition = v29
        .with_planned_task_attempt_cleanup_disposition_exclusion(&plan, |claim| {
            Ok(cleanup_terminal_from_live_claim(
                claim,
                "v30-migration-old-row",
                plan.minimum_terminal_at_unix_ms() + 1,
            ))
        })
        .expect("persist an old schema-v29 retry disposition");
    assert!(matches!(
        old_disposition,
        TaskAttemptDisposition::Retryable(_)
    ));
    for table in [
        "task_attempt_dispositions",
        "task_attempt_cleanup_result_coverage",
        "worker_cleanup_receipts",
        "worker_lease_releases",
        "agent_events",
    ] {
        assert!(
            row_count(&v29, table) > 0,
            "the populated migration fixture must exercise referring family {table}"
        );
    }
    let v29_rows = v30_capture_historical_rows(&v29.connection);
    let version: i64 = v29
        .connection
        .pragma_query_value(None, "user_version", |row| row.get(0))
        .expect("read exact v29 version");
    assert_eq!(version, 29);
    drop(v29);

    let migrated =
        EventLedger::open(&database.path).expect("migrate populated v29 to current schema");
    assert_eq!(
        v30_capture_matching_historical_rows(&migrated.connection, &v29_rows),
        v29_rows
    );
    v30_assert_database_checks(&migrated.connection);
    v30_assert_disposition_check_token_matrix(&migrated.connection);
    drop(migrated);

    let writable = EventLedger::open(&database.path).expect("reopen current schema read-write");
    assert_eq!(
        v30_capture_matching_historical_rows(&writable.connection, &v29_rows),
        v29_rows
    );
    v30_assert_database_checks(&writable.connection);
    drop(writable);

    let read_only =
        EventLedger::open_read_only(&database.path).expect("reopen current schema read-only");
    assert_eq!(
        v30_capture_matching_historical_rows(&read_only.connection, &v29_rows),
        v29_rows
    );
    v30_assert_database_checks(&read_only.connection);
}

#[test]
fn v30_divergent_v29_schema_refuses_before_any_migration_write() {
    let database = TestDatabase::new();
    let v29 = v30_open_exact_v29_database(&database);
    let rows_before = capture_all_historical_rows(&v29.connection);
    v29.connection
        .execute_batch(
            "PRAGMA writable_schema = ON;
             UPDATE sqlite_schema SET sql = sql || ' '
              WHERE type = 'table' AND name = 'sprints';
             PRAGMA schema_version = 290029;
             PRAGMA writable_schema = OFF;",
        )
        .expect("create a valid but noncanonical v29 source schema");
    let divergent_schema = capture_schema_definition(&v29.connection);
    drop(v29);

    assert!(matches!(
        EventLedger::open(&database.path),
        Err(LedgerError::Corrupt {
            entity: "ledger schema migration source",
            ..
        })
    ));
    let unchanged = Connection::open(&database.path).expect("inspect refused v29 source");
    let version: i64 = unchanged
        .pragma_query_value(None, "user_version", |row| row.get(0))
        .expect("read refused v29 user version");
    assert_eq!(version, 29);
    assert_eq!(capture_schema_definition(&unchanged), divergent_schema);
    assert_eq!(capture_all_historical_rows(&unchanged), rows_before);
    let disposition_sql: String = unchanged
        .query_row(
            "SELECT sql FROM sqlite_schema
             WHERE type = 'table' AND name = 'task_attempt_dispositions'",
            [],
            |row| row.get(0),
        )
        .expect("load refused v29 disposition DDL");
    assert!(!disposition_sql.contains("SensitiveOutputRejected"));
}
