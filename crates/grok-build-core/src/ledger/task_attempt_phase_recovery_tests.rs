// Dedicated schema-v15 phase and recovery adversarial regressions.

struct PhaseRecoveryFixture {
    database: TestDatabase,
    ledger: EventLedger,
    spec: SprintSpec,
    result_snapshot: WorkspaceSnapshot,
    change_set: ChangeSet,
    policy: CompiledExecutionPolicy,
    launch: RunnerLaunchIntent,
    attempt: TaskAttempt,
}

fn open_v20_phase_recovery_ledger(database: &TestDatabase) -> EventLedger {
    schema_template::install_exact_database_at(20, &database.path);
    let connection = Connection::open(&database.path).expect("create schema-v20 phase database");
    register_schema_functions(&connection).expect("register schema functions for v20 fixture");
    connection
        .execute_batch(
            "PRAGMA foreign_keys = ON;
             PRAGMA synchronous = FULL;
             PRAGMA journal_mode = WAL;",
        )
        .expect("configure schema-v20 phase database");
    EventLedger {
        connection,
        database_path: database.path.clone(),
        read_only: false,
        instance_id: next_event_ledger_instance_id(),
    }
}

fn prepare_phase_recovery_fixture() -> PhaseRecoveryFixture {
    prepare_phase_recovery_fixture_with_order(false, false, false)
}

fn prepare_v26_phase_recovery_fixture() -> PhaseRecoveryFixture {
    prepare_phase_recovery_fixture_with_order(false, false, true)
}

fn prepare_phase_recovery_fixture_with_order(
    schema_v20: bool,
    legacy_task_spec_order: bool,
    schema_v26: bool,
) -> PhaseRecoveryFixture {
    assert!(!(schema_v20 && schema_v26));
    let database = TestDatabase::new();
    let mut ledger = if schema_v20 {
        open_v20_phase_recovery_ledger(&database)
    } else if schema_v26 {
        open_v26_test_ledger(&database)
    } else {
        EventLedger::open(&database.path).expect("open phase-recovery ledger")
    };
    let (mut spec, mut graph) = sprint_fixture();
    spec.acceptance_criteria.push(AcceptanceCriterion {
        criterion_id: "lint".into(),
        description: "Focused lint passes".into(),
        kind: AcceptanceKind::Automated(CommandSpec {
            program: "cargo".into(),
            arguments: vec!["clippy".into(), "--locked".into()],
            working_directory: PathBuf::new(),
        }),
    });
    graph.tasks[0].acceptance_checks.push("lint".into());
    if legacy_task_spec_order {
        graph.tasks[0].acceptance_checks.reverse();
    }
    ledger
        .create_sprint(&spec, &graph, 1_000)
        .expect("persist two-criterion phase sprint");
    let (base, result_snapshot, change_set, _, _, _, _, _) = completion_artifacts();
    ledger
        .persist_workspace_snapshot(&spec.sprint_id, &base)
        .expect("persist phase base snapshot");
    ledger
        .persist_workspace_snapshot(&spec.sprint_id, &result_snapshot)
        .expect("persist phase result snapshot");
    ledger
        .persist_change_set(&spec.sprint_id, &change_set)
        .expect("persist phase change set");
    let policy = compiled_shadow_test_policy("phase-recovery-worker-policy");
    let launch = runner_launch(
        "launch-phase-recovery",
        "session-phase-recovery",
        RunnerSessionPurpose::TaskWorker,
        Some("worker-1"),
        &policy,
        1_210,
    );
    admit_test_runner_launch(&mut ledger, &launch, &policy);
    let attempt = ledger
        .load_task_attempt(&launch.worker_lease.as_ref().unwrap().lease_id)
        .expect("load phase task attempt");
    PhaseRecoveryFixture {
        database,
        ledger,
        spec,
        result_snapshot,
        change_set,
        policy,
        launch,
        attempt,
    }
}

fn assert_phase_recovery_reopens(
    fixture: &PhaseRecoveryFixture,
    expected: &LedgerTaskAttemptRecoveryProjection,
) {
    assert_recovery_projection_reopens(
        &fixture.ledger,
        &fixture.database,
        &fixture.spec.sprint_id,
        &fixture.attempt.worker_lease.task_id,
        &fixture.attempt.attempt_id,
        expected,
    );
}

fn assert_recovery_projection_reopens(
    ledger: &EventLedger,
    database: &TestDatabase,
    sprint_id: &str,
    task_id: &str,
    attempt_id: &str,
    expected: &LedgerTaskAttemptRecoveryProjection,
) {
    assert_eq!(
        ledger
            .load_task_attempt_recovery_projection(sprint_id, task_id, attempt_id)
            .expect("derive phase recovery projection"),
        *expected
    );
    let reopened =
        EventLedger::open_read_only(&database.path).expect("reopen phase recovery read-only");
    assert_eq!(
        reopened
            .load_task_attempt_recovery_projection(sprint_id, task_id, attempt_id)
            .expect("rederive phase recovery after reopen"),
        *expected
    );
}

fn phase_current_projection(
    launch: &RunnerLaunchIntent,
    session_id: Option<String>,
) -> LedgerTaskAttemptRecoveryProjection {
    LedgerTaskAttemptRecoveryProjection {
        facts: TaskAttemptRecoveryFacts::CurrentAuthority {
            launch_id: launch.launch_id.clone(),
            session_id,
        },
        decision: TaskAttemptRecoveryDecision::ContinueActive,
    }
}

fn phase_verification_contract(
    fixture: &PhaseRecoveryFixture,
    running: &TaskAttemptRunningBoundary,
    terminal_non_cleanup_effects: Vec<crate::TaskAttemptTerminalEffect>,
    sealed_snapshot: Digest,
    suffix: &str,
    sealed_at_unix_ms: u64,
) -> (TaskAttemptVerificationBoundary, AgentEvent) {
    let event = AgentEvent {
        contract_version: CONTRACT_VERSION,
        sequence: fixture
            .ledger
            .next_sequence(&fixture.spec.sprint_id)
            .expect("phase Verifying sequence"),
        event_id: format!("phase-verifying-{suffix}"),
        sprint_id: fixture.spec.sprint_id.clone(),
        task_id: Some(fixture.attempt.worker_lease.task_id.clone()),
        worker_id: Some(fixture.attempt.worker_lease.worker_id.clone()),
        causation_id: Some(running.transition_event_id.clone()),
        correlation_id: "phase-recovery-attempt".into(),
        policy_hash: Some(fixture.launch.policy_hash.clone()),
        occurred_at_unix_ms: sealed_at_unix_ms,
        payload: AgentEventKind::TaskStateChanged {
            from: "Running".into(),
            to: "Verifying".into(),
        },
    };
    let boundary = TaskAttemptVerificationBoundary {
        contract_version: CONTRACT_VERSION,
        boundary_id: format!("phase-verification-boundary-{suffix}"),
        attempt: fixture.attempt.clone(),
        runner_launch_id: fixture.launch.launch_id.clone(),
        runner_session_id: fixture.launch.session_id.clone(),
        change_set_id: fixture.change_set.change_set_id.clone(),
        sealed_snapshot,
        transition_event_id: event.event_id.clone(),
        terminal_non_cleanup_effects,
        sealed_at_unix_ms,
    };
    (boundary, event)
}

struct PhaseFormalContracts {
    admission: TaskAttemptFormalCheckAdmission,
    intent: EffectIntent,
    proposed_event: AgentEvent,
    check: TaskAttemptFormalCheck,
    observation: EffectObservation,
    terminal_event: AgentEvent,
    evidence: VerificationEffectEvidence,
}

#[allow(
    clippy::too_many_lines,
    reason = "the fixture keeps one formal-check lifecycle visible end to end"
)]
fn phase_formal_contracts(
    fixture: &PhaseRecoveryFixture,
    verification: &TaskAttemptVerificationBoundary,
    criterion: (u32, &str, &CommandSpec),
    passed: bool,
    suffix: &str,
    admitted_at_unix_ms: u64,
) -> PhaseFormalContracts {
    let (criterion_ordinal, criterion_id, command) = criterion;
    let command_bytes = encode("phase formal-check command", command).expect("encode command");
    let intent = EffectIntent {
        contract_version: CONTRACT_VERSION,
        effect_id: format!("phase-formal-effect-{suffix}"),
        idempotency_key: format!("phase-formal-key-{suffix}"),
        sprint_id: fixture.spec.sprint_id.clone(),
        task_id: Some(fixture.attempt.worker_lease.task_id.clone()),
        worker_id: Some(fixture.attempt.worker_lease.worker_id.clone()),
        worker_lease: Some(fixture.attempt.worker_lease.clone()),
        causation_event_id: Some(verification.transition_event_id.clone()),
        correlation_id: format!("phase-formal-{suffix}"),
        kind: EffectKind::RunCommand,
        request_digest: Digest::sha256(&command_bytes),
        policy_hash: fixture.launch.policy_hash.clone(),
        input_snapshot: verification.sealed_snapshot.clone(),
        created_at_unix_ms: admitted_at_unix_ms,
    };
    let proposed_event = effect_proposal_event(
        &intent,
        fixture
            .ledger
            .next_sequence(&fixture.spec.sprint_id)
            .expect("phase formal proposal sequence"),
        &format!("phase-formal-proposed-{suffix}"),
    );
    let admission = TaskAttemptFormalCheckAdmission {
        contract_version: CONTRACT_VERSION,
        admission_id: format!("phase-formal-admission-{suffix}"),
        attempt: fixture.attempt.clone(),
        criterion_ordinal,
        criterion_id: criterion_id.into(),
        effect_id: intent.effect_id.clone(),
        runner_session_id: fixture.launch.session_id.clone(),
        sealed_snapshot: verification.sealed_snapshot.clone(),
        command: command.clone(),
        admitted_at_unix_ms,
    };
    let output = format!("phase formal output {suffix}").into_bytes();
    let mut receipt = VerificationReceipt {
        receipt_id: format!("phase-formal-receipt-{suffix}"),
        sprint_id: fixture.spec.sprint_id.clone(),
        task_id: Some(fixture.attempt.worker_lease.task_id.clone()),
        snapshot_id: verification.sealed_snapshot.clone(),
        command: command.clone(),
        policy_hash: fixture.launch.policy_hash.clone(),
        exit_status: Some(i32::from(!passed)),
        termination: Some(CommandTerminationV1::Exited {
            code: i32::from(!passed),
        }),
        output_digest: Digest::sha256(&output),
        duration_ms: 10,
        finished_at_unix_ms: admitted_at_unix_ms + 10,
    };
    let (output_artifacts, output_evidence_bytes) = bind_complete_output_artifacts(
        &fixture.ledger,
        &mut receipt,
        &intent.effect_id,
        &fixture.launch.launch_id,
        &fixture.launch.session_id,
        output,
    );
    let evidence = VerificationEffectEvidence {
        contract_version: CONTRACT_VERSION,
        effect_id: intent.effect_id.clone(),
        observation_id: format!("phase-formal-observation-{suffix}"),
        runner_launch_id: fixture.launch.launch_id.clone(),
        runner_session_id: fixture.launch.session_id.clone(),
        verification: receipt.clone(),
        output_artifacts,
        output_evidence_bytes,
    };
    let evidence_bytes =
        encode("phase formal verification evidence", &evidence).expect("encode formal evidence");
    let observation = effect_observation(
        &intent,
        &evidence.observation_id,
        EffectOutcome::Succeeded {
            evidence_digest: Digest::sha256(&evidence_bytes),
        },
        receipt.finished_at_unix_ms,
    );
    let terminal_event = effect_terminal_event(
        &intent,
        &proposed_event.event_id,
        &observation,
        proposed_event.sequence + 1,
        &format!("phase-formal-finished-{suffix}"),
    );
    let check = TaskAttemptFormalCheck {
        contract_version: CONTRACT_VERSION,
        formal_check_id: format!("phase-formal-check-{suffix}"),
        attempt: fixture.attempt.clone(),
        criterion_ordinal,
        criterion_id: criterion_id.into(),
        effect_id: intent.effect_id.clone(),
        observation_id: observation.observation_id.clone(),
        verification_receipt: receipt,
        runner_session_id: fixture.launch.session_id.clone(),
        sealed_snapshot: verification.sealed_snapshot.clone(),
    };
    PhaseFormalContracts {
        admission,
        intent,
        proposed_event,
        check,
        observation,
        terminal_event,
        evidence,
    }
}

#[allow(clippy::too_many_lines)]
fn persist_phase_formal(
    fixture: &mut PhaseRecoveryFixture,
    contracts: &PhaseFormalContracts,
) -> TaskAttemptFormalCheck {
    let session = fixture
        .ledger
        .load_runner_session(&fixture.spec.sprint_id, &fixture.launch.session_id)
        .expect("load phase formal runner session");
    let capture = command_output_capture_authority::schema_is_installed(&fixture.ledger.connection)
        .expect("inspect phase formal capture schema")
        .then(|| {
            v27_test_capture_intent(
                &contracts.intent,
                &fixture.launch,
                &session,
                &contracts.check.formal_check_id,
            )
        });
    let admission = match capture.as_ref() {
        Some(capture) => fixture
            .ledger
            .admit_task_attempt_formal_check_with_output_capture_for_dispatch(
                &contracts.admission,
                &contracts.intent,
                &contracts.proposed_event,
                capture,
            ),
        None => fixture.ledger.admit_task_attempt_formal_check_for_dispatch(
            &contracts.admission,
            &contracts.intent,
            &contracts.proposed_event,
        ),
    }
    .expect("admit serialized phase formal check for dispatch");
    let permit = match admission {
        TaskFormalCheckDispatchAdmission::Fresh { permit, .. } => permit,
        TaskFormalCheckDispatchAdmission::Existing { .. } => {
            panic!("new serialized phase formal check must be Fresh")
        }
    };
    let command_bytes =
        encode("formal-check command", &contracts.admission.command).expect("encode command");
    let dispatch_permit = FreshRunnerEffectDispatchPermit::TaskFormalCheck(permit);
    let (transport, acquired) = if let Some(capture) = capture.as_ref() {
        let acquired = v27_test_capture_acquired(
            capture,
            dispatch_permit
                .expected_output_capture_dispatch_claim_id()
                .expect("phase formal capture claim identity"),
            &contracts.check.formal_check_id,
            contracts.intent.created_at_unix_ms + 1,
        );
        let (_, transport) = fixture
            .ledger
            .claim_command_output_capture_dispatch(
                dispatch_permit,
                acquired.clone(),
                OPAQUE_RUNNER_TRANSPORT_REQUEST_BYTES,
            )
            .expect("claim serialized phase formal capture dispatch");
        (transport, Some(acquired))
    } else {
        let (_, transport) = fixture
            .ledger
            .claim_runner_effect_dispatch(dispatch_permit, OPAQUE_RUNNER_TRANSPORT_REQUEST_BYTES)
            .expect("claim historical serialized phase formal dispatch");
        (transport, None)
    };
    let authority = transport
        .validate_transport_request(
            &contracts.intent,
            &command_bytes,
            &fixture.launch,
            &session,
            None,
            OPAQUE_RUNNER_TRANSPORT_REQUEST_BYTES,
        )
        .expect("validate serialized phase formal transport");
    if let (Some(capture), Some(acquired)) = (capture.as_ref(), acquired.as_ref()) {
        let capture_terminal = v27_test_published_capture_terminal(
            capture,
            acquired,
            &contracts.observation,
            contracts
                .evidence
                .output_artifacts
                .clone()
                .expect("current phase formal evidence carries output artifacts"),
            &contracts.check.formal_check_id,
            contracts.observation.observed_at_unix_ms + 2,
        );
        let cleanup = v27_test_command_cleanup(
            &contracts.intent,
            &contracts.observation,
            &fixture.launch,
            &session,
            &contracts.check.formal_check_id,
            contracts.observation.observed_at_unix_ms + 1,
        );
        let clean_scan = v29_test_clean_scan_receipt(
            capture,
            acquired,
            &capture_terminal,
            contracts
                .evidence
                .verification
                .termination
                .expect("current phase receipt has typed termination"),
            &contracts.check.formal_check_id,
        );
        fixture
            .ledger
            .complete_claimed_task_attempt_formal_check_with_output_capture(
                authority,
                &contracts.check,
                &contracts.observation,
                &contracts.terminal_event,
                &contracts.evidence,
                &capture_terminal,
                &clean_scan,
                &cleanup,
            )
            .expect("complete serialized phase formal check with v27 capture")
    } else {
        fixture
            .ledger
            .complete_claimed_task_attempt_formal_check(
                authority,
                &contracts.check,
                &contracts.observation,
                &contracts.terminal_event,
                &contracts.evidence,
            )
            .expect("complete historical serialized phase formal check")
    }
}

fn phase_candidate_contract(
    fixture: &PhaseRecoveryFixture,
    verification: &TaskAttemptVerificationBoundary,
    checks: &[TaskAttemptFormalCheck],
    suffix: &str,
    admitted_at_unix_ms: u64,
) -> (TaskAttemptCandidateBoundary, AgentEvent) {
    let event = AgentEvent {
        contract_version: CONTRACT_VERSION,
        sequence: fixture
            .ledger
            .next_sequence(&fixture.spec.sprint_id)
            .expect("phase Candidate sequence"),
        event_id: format!("phase-candidate-{suffix}"),
        sprint_id: fixture.spec.sprint_id.clone(),
        task_id: Some(fixture.attempt.worker_lease.task_id.clone()),
        worker_id: Some(fixture.attempt.worker_lease.worker_id.clone()),
        causation_id: Some(verification.transition_event_id.clone()),
        correlation_id: format!("phase-candidate-{suffix}"),
        policy_hash: Some(fixture.launch.policy_hash.clone()),
        occurred_at_unix_ms: admitted_at_unix_ms,
        payload: AgentEventKind::TaskStateChanged {
            from: "Verifying".into(),
            to: "Candidate".into(),
        },
    };
    let boundary = TaskAttemptCandidateBoundary {
        contract_version: CONTRACT_VERSION,
        boundary_id: format!("phase-candidate-boundary-{suffix}"),
        attempt: fixture.attempt.clone(),
        verification_boundary_id: verification.boundary_id.clone(),
        change_set_id: fixture.change_set.change_set_id.clone(),
        sealed_snapshot: verification.sealed_snapshot.clone(),
        formal_check_ids: checks
            .iter()
            .map(|check| check.formal_check_id.clone())
            .collect(),
        verification_receipt_ids: checks
            .iter()
            .map(|check| check.verification_receipt.receipt_id.clone())
            .collect(),
        transition_event_id: event.event_id.clone(),
        admitted_at_unix_ms,
    };
    (boundary, event)
}

fn enter_clean_phase_verifying(
    fixture: &mut PhaseRecoveryFixture,
    suffix: &str,
) -> (TaskAttemptRunningBoundary, TaskAttemptVerificationBoundary) {
    fixture
        .ledger
        .register_runner_session(&runner_session(&fixture.launch, 1_220), &fixture.policy)
        .expect("register phase worker session");
    let running = enter_test_task_attempt_running(&mut fixture.ledger, &fixture.launch, 1_230);
    let (verification, event) = phase_verification_contract(
        fixture,
        &running,
        Vec::new(),
        fixture.result_snapshot.snapshot_id.clone(),
        suffix,
        1_240,
    );
    fixture
        .ledger
        .transition_task_attempt_to_verifying(&verification, &event)
        .expect("enter clean phase Verifying");
    (running, verification)
}

fn phase_provider_intent(
    attempt: &TaskAttempt,
    launch: &RunnerLaunchIntent,
    effect_id: &str,
    input_snapshot: Digest,
    causation_event_id: &str,
    created_at_unix_ms: u64,
) -> EffectIntent {
    EffectIntent {
        contract_version: CONTRACT_VERSION,
        effect_id: effect_id.into(),
        idempotency_key: format!("{effect_id}-key"),
        sprint_id: attempt.worker_lease.sprint_id.clone(),
        task_id: Some(attempt.worker_lease.task_id.clone()),
        worker_id: Some(attempt.worker_lease.worker_id.clone()),
        worker_lease: Some(attempt.worker_lease.clone()),
        causation_event_id: Some(causation_event_id.into()),
        correlation_id: format!("{effect_id}-correlation"),
        kind: EffectKind::ProviderRequest,
        request_digest: Digest::sha256(EFFECT_REQUEST_BYTES),
        policy_hash: launch.policy_hash.clone(),
        input_snapshot,
        created_at_unix_ms,
    }
}

fn assert_provider_rejected_by_api_and_sql(
    ledger: &mut EventLedger,
    intent: &EffectIntent,
    proposed_event_id: &str,
    expect_phase_fence: bool,
) {
    let proposal = effect_proposal_event(
        intent,
        ledger
            .next_sequence(&intent.sprint_id)
            .expect("provider phase proposal sequence"),
        proposed_event_id,
    );
    let baseline = (
        row_count(ledger, "agent_events"),
        row_count(ledger, "effect_request_payloads"),
        row_count(ledger, "effect_intents"),
    );
    assert!(
        ledger
            .record_effect_intent(intent, EFFECT_REQUEST_BYTES, &proposal)
            .is_err(),
        "ordinary API must reject a provider request outside exact Running authority"
    );
    assert_eq!(
        (
            row_count(ledger, "agent_events"),
            row_count(ledger, "effect_request_payloads"),
            row_count(ledger, "effect_intents"),
        ),
        baseline
    );

    let transaction = ledger
        .connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .expect("open provider phase SQL bypass");
    insert_agent_event(&transaction, &proposal).expect("stage provider proposal");
    insert_effect_request_payload(&transaction, intent, EFFECT_REQUEST_BYTES)
        .expect("stage provider request bytes");
    let error = insert_effect_intent(&transaction, intent, &proposal.event_id)
        .expect_err("direct SQL must reject provider request outside exact Running authority");
    if expect_phase_fence {
        assert!(
            error
                .to_string()
                .contains("task effect is not admitted by the exact current attempt phase"),
            "unexpected provider phase SQL fence: {error}"
        );
    }
    transaction
        .rollback()
        .expect("roll back provider phase SQL bypass");
    assert_eq!(
        (
            row_count(ledger, "agent_events"),
            row_count(ledger, "effect_request_payloads"),
            row_count(ledger, "effect_intents"),
        ),
        baseline
    );
}

#[test]
#[allow(clippy::too_many_lines)] // Migration classification and the fresh/mixed rejection matrix are one ordering proof.
fn populated_v20_legacy_formal_order_migrates_without_authorizing_new_or_mixed_order() {
    let mut legacy = prepare_phase_recovery_fixture_with_order(true, true, false);
    let (_, legacy_verification) = enter_clean_phase_verifying(&mut legacy, "v20-legacy-order");
    let legacy_criteria = legacy
        .spec
        .acceptance_criteria
        .iter()
        .map(|criterion| {
            let AcceptanceKind::Automated(command) = &criterion.kind else {
                unreachable!("legacy phase fixture has only automated criteria")
            };
            (criterion.criterion_id.clone(), command.clone())
        })
        .collect::<Vec<_>>();
    let legacy_lint = phase_formal_contracts(
        &legacy,
        &legacy_verification,
        (0, &legacy_criteria[1].0, &legacy_criteria[1].1),
        true,
        "v20-legacy-lint",
        1_250,
    );
    let legacy_lint = persist_phase_formal(&mut legacy, &legacy_lint);
    let legacy_tests = phase_formal_contracts(
        &legacy,
        &legacy_verification,
        (1, &legacy_criteria[0].0, &legacy_criteria[0].1),
        true,
        "v20-legacy-tests",
        1_270,
    );
    let legacy_tests = persist_phase_formal(&mut legacy, &legacy_tests);
    assert_eq!(
        [
            legacy_lint.criterion_id.as_str(),
            legacy_tests.criterion_id.as_str()
        ],
        ["lint", "tests"]
    );

    let migrated = EventLedger::open(&legacy.database.path)
        .expect("migrate populated legacy-order database through v21");
    legacy.ledger = migrated;
    assert_eq!(
        legacy
            .ledger
            .connection
            .query_row(
                "SELECT COUNT(*) FROM task_formal_order_legacy_exemptions
                 WHERE attempt_id = ?1 AND sprint_id = ?2 AND task_id = ?3
                   AND formal_check_count = 2 AND marked_at_schema_version = 21",
                params![
                    legacy.attempt.attempt_id,
                    legacy.attempt.worker_lease.sprint_id,
                    legacy.attempt.worker_lease.task_id,
                ],
                |row| row.get::<_, i64>(0),
            )
            .expect("count exact migrated legacy-order exemption"),
        1
    );
    assert!(
        legacy
            .ledger
            .connection
            .execute(
                "INSERT INTO task_formal_order_legacy_exemptions (
                    attempt_id, sprint_id, task_id, formal_check_count,
                    marked_at_schema_version
                 ) VALUES ('forged-attempt', 'sprint-1', 'task-1', 2, 21)",
                [],
            )
            .is_err(),
        "runtime cannot mint a legacy-order exemption"
    );
    let legacy_checks = vec![legacy_lint, legacy_tests];
    let (legacy_candidate, legacy_candidate_event) = phase_candidate_contract(
        &legacy,
        &legacy_verification,
        &legacy_checks,
        "migrated-v20-legacy-order",
        1_290,
    );
    legacy
        .ledger
        .transition_task_attempt_to_candidate(&legacy_candidate, &legacy_candidate_event)
        .expect("migrated complete v20 legacy order may close Candidate exactly once");

    let mut fresh = prepare_phase_recovery_fixture_with_order(false, true, false);
    let (_, fresh_verification) = enter_clean_phase_verifying(&mut fresh, "v21-fresh-order");
    let fresh_criteria = fresh
        .spec
        .acceptance_criteria
        .iter()
        .map(|criterion| {
            let AcceptanceKind::Automated(command) = &criterion.kind else {
                unreachable!("fresh phase fixture has only automated criteria")
            };
            (criterion.criterion_id.clone(), command.clone())
        })
        .collect::<Vec<_>>();
    let forbidden_legacy_first = phase_formal_contracts(
        &fresh,
        &fresh_verification,
        (0, &fresh_criteria[1].0, &fresh_criteria[1].1),
        true,
        "v21-forbidden-legacy-first",
        1_250,
    );
    assert!(
        fresh
            .ledger
            .admit_task_attempt_formal_check_for_dispatch(
                &forbidden_legacy_first.admission,
                &forbidden_legacy_first.intent,
                &forbidden_legacy_first.proposed_event,
            )
            .is_err(),
        "fresh v21 attempt cannot begin in legacy TaskSpec order"
    );
    assert_eq!(
        row_count(&fresh.ledger, "task_formal_order_legacy_exemptions"),
        0
    );

    let canonical_tests = phase_formal_contracts(
        &fresh,
        &fresh_verification,
        (0, &fresh_criteria[0].0, &fresh_criteria[0].1),
        true,
        "v21-canonical-tests",
        1_250,
    );
    let canonical_tests = persist_phase_formal(&mut fresh, &canonical_tests);
    let forbidden_mixed_second = phase_formal_contracts(
        &fresh,
        &fresh_verification,
        (1, &fresh_criteria[0].0, &fresh_criteria[0].1),
        true,
        "v21-forbidden-mixed-second",
        1_270,
    );
    assert!(
        fresh
            .ledger
            .admit_task_attempt_formal_check_for_dispatch(
                &forbidden_mixed_second.admission,
                &forbidden_mixed_second.intent,
                &forbidden_mixed_second.proposed_event,
            )
            .is_err(),
        "fresh history cannot switch to the legacy sequence after a canonical prefix"
    );
    let canonical_lint = phase_formal_contracts(
        &fresh,
        &fresh_verification,
        (1, &fresh_criteria[1].0, &fresh_criteria[1].1),
        true,
        "v21-canonical-lint",
        1_270,
    );
    let canonical_lint = persist_phase_formal(&mut fresh, &canonical_lint);
    let canonical_checks = vec![canonical_tests, canonical_lint];
    let (canonical_candidate, canonical_candidate_event) = phase_candidate_contract(
        &fresh,
        &fresh_verification,
        &canonical_checks,
        "v21-canonical-order",
        1_290,
    );
    fresh
        .ledger
        .transition_task_attempt_to_candidate(&canonical_candidate, &canonical_candidate_event)
        .expect("fresh v21 canonical SprintSpec order closes Candidate");
}

#[test]
#[allow(clippy::too_many_lines)] // Four phases plus the no-session and substituted-lease cuts form one closed fence matrix.
fn v15_task_provider_requests_require_exact_running_attempt_without_runner_binding() {
    let mut leased = prepare_phase_recovery_fixture();
    let leased_intent = phase_provider_intent(
        &leased.attempt,
        &leased.launch,
        "phase-provider-leased",
        leased.spec.base_snapshot.clone(),
        &leased.attempt.opening_event_id,
        1_220,
    );
    assert_provider_rejected_by_api_and_sql(
        &mut leased.ledger,
        &leased_intent,
        "phase-provider-leased-proposed",
        true,
    );

    let mut running = prepare_phase_recovery_fixture();
    running
        .ledger
        .register_runner_session(&runner_session(&running.launch, 1_220), &running.policy)
        .expect("register provider-phase worker session");
    let running_boundary =
        enter_test_task_attempt_running(&mut running.ledger, &running.launch, 1_230);
    let running_intent = phase_provider_intent(
        &running.attempt,
        &running.launch,
        "phase-provider-running",
        running.spec.base_snapshot.clone(),
        &running_boundary.transition_event_id,
        1_240,
    );
    let running_proposal = effect_proposal_event(
        &running_intent,
        running
            .ledger
            .next_sequence(&running.spec.sprint_id)
            .expect("Running provider proposal sequence"),
        "phase-provider-running-proposed",
    );
    let persisted = running
        .ledger
        .record_effect_intent(&running_intent, EFFECT_REQUEST_BYTES, &running_proposal)
        .expect("exact task-scoped Running provider request must persist");
    assert_eq!(persisted.intent, running_intent);
    assert_eq!(
        running
            .ledger
            .connection
            .query_row(
                "SELECT COUNT(*) FROM effect_session_bindings WHERE effect_id = ?1",
                [&running_intent.effect_id],
                |row| row.get::<_, i64>(0),
            )
            .expect("count provider runner bindings"),
        0,
        "provider ownership must not invent a runner-session binding"
    );

    let bound_intent = phase_provider_intent(
        &running.attempt,
        &running.launch,
        "phase-provider-bound",
        running.spec.base_snapshot.clone(),
        &running_boundary.transition_event_id,
        1_250,
    );
    let bound_proposal = effect_proposal_event(
        &bound_intent,
        running
            .ledger
            .next_sequence(&running.spec.sprint_id)
            .expect("bound provider proposal sequence"),
        "phase-provider-bound-proposed",
    );
    let transaction = running
        .ledger
        .connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .expect("open bound-provider SQL bypass");
    insert_agent_event(&transaction, &bound_proposal).expect("stage bound provider proposal");
    insert_effect_request_payload(&transaction, &bound_intent, EFFECT_REQUEST_BYTES)
        .expect("stage bound provider request bytes");
    transaction
        .execute(
            "INSERT INTO effect_session_bindings (
                effect_id, sprint_id, launch_id, session_id, contract_version
             ) VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                bound_intent.effect_id,
                bound_intent.sprint_id,
                running.launch.launch_id,
                running.launch.session_id,
                i64::from(CONTRACT_VERSION),
            ],
        )
        .expect("stage forbidden provider runner binding");
    assert!(
        insert_effect_intent(&transaction, &bound_intent, &bound_proposal.event_id).is_err(),
        "provider request must reject a substituted runner-session binding"
    );
    transaction
        .rollback()
        .expect("roll back bound-provider SQL bypass");

    let mut substituted = phase_provider_intent(
        &running.attempt,
        &running.launch,
        "phase-provider-substituted-lease",
        running.spec.base_snapshot.clone(),
        &running_boundary.transition_event_id,
        1_260,
    );
    let lease = &running.attempt.worker_lease;
    substituted.worker_lease = Some(
        WorkerLease::new(
            lease.sprint_id.clone(),
            lease.lease_epoch + 1,
            lease.task_id.clone(),
            lease.worker_id.clone(),
            lease.path_scopes.clone(),
            lease.acquired_at_unix_ms,
        )
        .expect("construct canonical substituted lease"),
    );
    assert_provider_rejected_by_api_and_sql(
        &mut running.ledger,
        &substituted,
        "phase-provider-substituted-lease-proposed",
        false,
    );

    let mut verifying = prepare_phase_recovery_fixture();
    let (_, verification) = enter_clean_phase_verifying(&mut verifying, "provider-fence");
    let verifying_intent = phase_provider_intent(
        &verifying.attempt,
        &verifying.launch,
        "phase-provider-verifying",
        verifying.result_snapshot.snapshot_id.clone(),
        &verification.transition_event_id,
        1_250,
    );
    assert_provider_rejected_by_api_and_sql(
        &mut verifying.ledger,
        &verifying_intent,
        "phase-provider-verifying-proposed",
        true,
    );

    let mut candidate = prepare_v15_candidate_fixture(false);
    let candidate_intent = phase_provider_intent(
        &candidate.attempt,
        &candidate.launch,
        "phase-provider-candidate",
        candidate.result_snapshot.snapshot_id.clone(),
        &candidate.candidate.transition_event_id,
        1_260,
    );
    assert_provider_rejected_by_api_and_sql(
        &mut candidate.ledger,
        &candidate_intent,
        "phase-provider-candidate-proposed",
        true,
    );
}

#[test]
#[allow(clippy::too_many_lines)] // Every durable phase and its restart projection form one lifecycle proof.
fn v15_recovery_projects_every_current_and_integrated_phase_across_reopen() {
    let mut fixture = prepare_phase_recovery_fixture();
    assert_phase_recovery_reopens(&fixture, &phase_current_projection(&fixture.launch, None));

    fixture
        .ledger
        .register_runner_session(&runner_session(&fixture.launch, 1_220), &fixture.policy)
        .expect("register phase worker session");
    let running = enter_test_task_attempt_running(&mut fixture.ledger, &fixture.launch, 1_230);
    let current =
        phase_current_projection(&fixture.launch, Some(fixture.launch.session_id.clone()));
    assert_phase_recovery_reopens(&fixture, &current);

    let ordinary_intent = EffectIntent {
        contract_version: CONTRACT_VERSION,
        effect_id: "phase-terminal-effect".into(),
        idempotency_key: "phase-terminal-key".into(),
        sprint_id: fixture.spec.sprint_id.clone(),
        task_id: Some(fixture.attempt.worker_lease.task_id.clone()),
        worker_id: Some(fixture.attempt.worker_lease.worker_id.clone()),
        worker_lease: Some(fixture.attempt.worker_lease.clone()),
        causation_event_id: Some(running.transition_event_id.clone()),
        correlation_id: "phase-terminal-effect".into(),
        kind: EffectKind::SearchLiteral,
        request_digest: Digest::sha256(EFFECT_REQUEST_BYTES),
        policy_hash: fixture.launch.policy_hash.clone(),
        input_snapshot: fixture.spec.base_snapshot.clone(),
        created_at_unix_ms: 1_240,
    };
    let ordinary_proposal = effect_proposal_event(
        &ordinary_intent,
        fixture.ledger.next_sequence("sprint-1").unwrap(),
        "phase-terminal-effect-proposed",
    );
    fixture
        .ledger
        .record_runner_effect_intent(
            &ordinary_intent,
            EFFECT_REQUEST_BYTES,
            &ordinary_proposal,
            &fixture.launch.session_id,
        )
        .expect("pre-admit ordinary phase effect");
    let expected_terminal = crate::TaskAttemptTerminalEffect {
        effect_id: ordinary_intent.effect_id.clone(),
        observation_id: "phase-terminal-effect-observed".into(),
    };
    let before_unfinished = (
        row_count(&fixture.ledger, "task_attempt_verification_boundaries"),
        row_count(&fixture.ledger, "agent_events"),
    );
    let (unfinished_boundary, unfinished_event) = phase_verification_contract(
        &fixture,
        &running,
        vec![expected_terminal.clone()],
        fixture.result_snapshot.snapshot_id.clone(),
        "unfinished-effect",
        1_250,
    );
    assert!(
        fixture
            .ledger
            .transition_task_attempt_to_verifying(&unfinished_boundary, &unfinished_event)
            .is_err(),
        "Verifying must reject an unfinished pre-admitted effect"
    );
    assert_eq!(
        (
            row_count(&fixture.ledger, "task_attempt_verification_boundaries"),
            row_count(&fixture.ledger, "agent_events"),
        ),
        before_unfinished
    );

    let ordinary_observation = effect_observation(
        &ordinary_intent,
        &expected_terminal.observation_id,
        EffectOutcome::Succeeded {
            evidence_digest: effect_evidence_digest(),
        },
        1_250,
    );
    let ordinary_terminal_event = effect_terminal_event(
        &ordinary_intent,
        &ordinary_proposal.event_id,
        &ordinary_observation,
        fixture.ledger.next_sequence("sprint-1").unwrap(),
        "phase-terminal-effect-finished",
    );
    fixture
        .ledger
        .record_effect_observation(
            &ordinary_observation,
            EFFECT_EVIDENCE_BYTES,
            &ordinary_terminal_event,
        )
        .expect("terminalize ordinary phase effect");

    let before_crossed = (
        row_count(&fixture.ledger, "task_attempt_verification_boundaries"),
        row_count(
            &fixture.ledger,
            "task_attempt_verification_terminal_effects",
        ),
        row_count(&fixture.ledger, "agent_events"),
    );
    let (omitted_boundary, omitted_event) = phase_verification_contract(
        &fixture,
        &running,
        Vec::new(),
        fixture.result_snapshot.snapshot_id.clone(),
        "omitted-effect",
        1_260,
    );
    assert!(
        fixture
            .ledger
            .transition_task_attempt_to_verifying(&omitted_boundary, &omitted_event)
            .is_err(),
        "sealed boundary must enumerate every exact earlier effect"
    );
    let (wrong_snapshot, wrong_snapshot_event) = phase_verification_contract(
        &fixture,
        &running,
        vec![expected_terminal.clone()],
        digest('e'),
        "wrong-snapshot",
        1_260,
    );
    assert!(
        fixture
            .ledger
            .transition_task_attempt_to_verifying(&wrong_snapshot, &wrong_snapshot_event)
            .is_err(),
        "Verifying must seal the exact persisted change-set result snapshot"
    );
    assert_eq!(
        (
            row_count(&fixture.ledger, "task_attempt_verification_boundaries"),
            row_count(
                &fixture.ledger,
                "task_attempt_verification_terminal_effects",
            ),
            row_count(&fixture.ledger, "agent_events"),
        ),
        before_crossed
    );
    let (verification, verification_event) = phase_verification_contract(
        &fixture,
        &running,
        vec![expected_terminal],
        fixture.result_snapshot.snapshot_id.clone(),
        "exact",
        1_260,
    );
    fixture
        .ledger
        .transition_task_attempt_to_verifying(&verification, &verification_event)
        .expect("enter exact phase Verifying");
    assert_phase_recovery_reopens(&fixture, &current);

    let criteria = fixture
        .spec
        .acceptance_criteria
        .iter()
        .map(|criterion| {
            let AcceptanceKind::Automated(command) = &criterion.kind else {
                unreachable!("phase fixture has only automated criteria")
            };
            (criterion.criterion_id.clone(), command.clone())
        })
        .collect::<Vec<_>>();
    let premature = phase_formal_contracts(
        &fixture,
        &verification,
        (1, &criteria[1].0, &criteria[1].1),
        true,
        "premature-second",
        1_270,
    );
    let before_premature = (
        row_count(&fixture.ledger, "task_attempt_formal_check_admissions"),
        row_count(&fixture.ledger, "effect_intents"),
        row_count(&fixture.ledger, "agent_events"),
    );
    assert!(
        fixture
            .ledger
            .admit_task_attempt_formal_check(
                &premature.admission,
                &premature.intent,
                &premature.proposed_event,
            )
            .is_err(),
        "ordinal one cannot bypass ordinal zero"
    );
    assert_eq!(
        (
            row_count(&fixture.ledger, "task_attempt_formal_check_admissions"),
            row_count(&fixture.ledger, "effect_intents"),
            row_count(&fixture.ledger, "agent_events"),
        ),
        before_premature
    );

    let formal_zero = phase_formal_contracts(
        &fixture,
        &verification,
        (0, &criteria[0].0, &criteria[0].1),
        true,
        "zero",
        1_270,
    );
    let check_zero = persist_phase_formal(&mut fixture, &formal_zero);
    let formal_one = phase_formal_contracts(
        &fixture,
        &verification,
        (1, &criteria[1].0, &criteria[1].1),
        true,
        "one",
        1_290,
    );
    let check_one = persist_phase_formal(&mut fixture, &formal_one);
    assert_eq!(
        [check_zero.criterion_ordinal, check_one.criterion_ordinal],
        [0, 1]
    );
    let checks = vec![check_zero, check_one];
    let (candidate, candidate_event) =
        phase_candidate_contract(&fixture, &verification, &checks, "exact", 1_310);
    fixture
        .ledger
        .transition_task_attempt_to_candidate(&candidate, &candidate_event)
        .expect("enter exact phase Candidate");
    assert_eq!(
        candidate.formal_check_ids,
        checks
            .iter()
            .map(|check| check.formal_check_id.clone())
            .collect::<Vec<_>>()
    );
    assert_phase_recovery_reopens(&fixture, &current);

    let PhaseRecoveryFixture {
        database,
        ledger,
        spec,
        result_snapshot,
        change_set,
        policy: _,
        launch,
        attempt,
    } = fixture;
    let mut integrated_fixture = V15CandidateFixture {
        database,
        ledger,
        spec,
        result_snapshot,
        change_set,
        launch,
        attempt,
        running,
        verification,
        formal_checks: checks,
        candidate,
        prior_attempt: None,
        prior_disposition: None,
        prior_launch: None,
        candidate_required: true,
    };
    let (_, _, disposition) =
        integrate_v15_candidate(&mut integrated_fixture, "phase-recovery", false);
    let cleanup_pending = LedgerTaskAttemptRecoveryProjection {
        facts: TaskAttemptRecoveryFacts::DurableHistoryOnly,
        decision: TaskAttemptRecoveryDecision::IntegratedCleanupPending,
    };
    assert_recovery_projection_reopens(
        &integrated_fixture.ledger,
        &integrated_fixture.database,
        &integrated_fixture.spec.sprint_id,
        &integrated_fixture.attempt.worker_lease.task_id,
        &integrated_fixture.attempt.attempt_id,
        &cleanup_pending,
    );
    let cleanup = cleanup_terminal_record(
        &integrated_fixture.ledger,
        &integrated_fixture.launch,
        "phase-recovery-cleanup",
        1_500,
    );
    integrated_fixture
        .ledger
        .with_integrated_task_attempt_cleanup_exclusion(
            &disposition.metadata().disposition_id,
            |_| Ok(cleanup),
        )
        .expect("release exact Integrated cleanup authority");
    let released = LedgerTaskAttemptRecoveryProjection {
        facts: TaskAttemptRecoveryFacts::DurableHistoryOnly,
        decision: TaskAttemptRecoveryDecision::AlreadyDisposed,
    };
    assert_recovery_projection_reopens(
        &integrated_fixture.ledger,
        &integrated_fixture.database,
        &integrated_fixture.spec.sprint_id,
        &integrated_fixture.attempt.worker_lease.task_id,
        &integrated_fixture.attempt.attempt_id,
        &released,
    );
}

#[test]
#[allow(clippy::too_many_lines)] // Failure, both admission cuts, Candidate fence, source identity, and replay are one invariant.
fn v15_failed_formal_check_permanently_fences_later_work_and_rejects_forged_source() {
    let mut fixture = prepare_phase_recovery_fixture();
    let (_, verification) = enter_clean_phase_verifying(&mut fixture, "failed-formal");
    let criteria = fixture
        .spec
        .acceptance_criteria
        .iter()
        .map(|criterion| {
            let AcceptanceKind::Automated(command) = &criterion.kind else {
                unreachable!("phase fixture has only automated criteria")
            };
            (criterion.criterion_id.clone(), command.clone())
        })
        .collect::<Vec<_>>();
    let failed = phase_formal_contracts(
        &fixture,
        &verification,
        (0, &criteria[0].0, &criteria[0].1),
        false,
        "failed",
        1_250,
    );
    let failed_check = persist_phase_formal(&mut fixture, &failed);
    assert!(!failed_check.verification_receipt.passed());
    assert_eq!(
        fixture
            .ledger
            .load_task_attempt_formal_check(&failed_check.formal_check_id)
            .expect("failed formal-check exact readback remains readable"),
        failed_check
    );
    assert_eq!(
        fixture
            .ledger
            .load_task_attempt_formal_check(&failed_check.formal_check_id)
            .expect("reload exact failed formal check"),
        failed_check
    );

    let later = phase_formal_contracts(
        &fixture,
        &verification,
        (1, &criteria[1].0, &criteria[1].1),
        true,
        "forbidden-after-failure",
        1_270,
    );
    let baseline = (
        row_count(&fixture.ledger, "task_attempt_formal_check_admissions"),
        row_count(&fixture.ledger, "task_attempt_formal_checks"),
        row_count(&fixture.ledger, "effect_intents"),
        row_count(&fixture.ledger, "agent_events"),
    );
    let api_error = fixture
        .ledger
        .admit_task_attempt_formal_check(&later.admission, &later.intent, &later.proposed_event)
        .expect_err("a failed check permanently fences later API admission");
    assert!(
        api_error.to_string().contains(
            "formal-check admission must be the next SprintSpec-ordered automated criterion"
        ),
        "unexpected failed-check API fence: {api_error}"
    );
    assert_eq!(
        (
            row_count(&fixture.ledger, "task_attempt_formal_check_admissions"),
            row_count(&fixture.ledger, "task_attempt_formal_checks"),
            row_count(&fixture.ledger, "effect_intents"),
            row_count(&fixture.ledger, "agent_events"),
        ),
        baseline
    );

    let transaction = fixture
        .ledger
        .connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .expect("open failed-check raw admission transaction");
    let sql_error =
        task_attempt_authority::insert_formal_check_admission(&transaction, &later.admission)
            .expect_err("a failed check permanently fences later SQL admission");
    assert!(
        sql_error.to_string().contains(
            "formal-check admission must be the next SprintSpec-ordered automated criterion"
        ),
        "unexpected failed-check SQL fence: {sql_error}"
    );
    transaction
        .rollback()
        .expect("roll back failed-check raw admission");
    assert_eq!(
        (
            row_count(&fixture.ledger, "task_attempt_formal_check_admissions"),
            row_count(&fixture.ledger, "task_attempt_formal_checks"),
            row_count(&fixture.ledger, "effect_intents"),
            row_count(&fixture.ledger, "agent_events"),
        ),
        baseline
    );

    let (candidate, candidate_event) = phase_candidate_contract(
        &fixture,
        &verification,
        std::slice::from_ref(&failed_check),
        "failed",
        1_280,
    );
    let candidate_baseline = (
        row_count(&fixture.ledger, "task_attempt_candidate_boundaries"),
        row_count(&fixture.ledger, "agent_events"),
    );
    assert!(
        fixture
            .ledger
            .transition_task_attempt_to_candidate(&candidate, &candidate_event)
            .is_err(),
        "a failed check permanently fences Candidate"
    );
    assert_eq!(
        (
            row_count(&fixture.ledger, "task_attempt_candidate_boundaries"),
            row_count(&fixture.ledger, "agent_events"),
        ),
        candidate_baseline
    );

    let projection = fixture
        .ledger
        .load_task_attempt_recovery_projection(
            &fixture.spec.sprint_id,
            &fixture.attempt.worker_lease.task_id,
            &fixture.attempt.attempt_id,
        )
        .expect("derive failed-formal cleanup projection");
    assert_eq!(
        projection.decision,
        TaskAttemptRecoveryDecision::CleanupThenRetry
    );
    let TaskAttemptRecoveryFacts::KnownCleanupRequired {
        launch_id,
        session_id,
        outcome:
            TaskAttemptKnownCleanupOutcome::Retryable(
                crate::TaskAttemptRetryableCause::FormalVerificationFailed {
                    formal_check_id,
                    evidence,
                },
            ),
    } = &projection.facts
    else {
        panic!("failed formal check must derive its exact known-cleanup source")
    };
    assert_eq!(launch_id, &fixture.launch.launch_id);
    assert_eq!(
        session_id.as_deref(),
        Some(fixture.launch.session_id.as_str())
    );
    assert_eq!(formal_check_id, &failed_check.formal_check_id);
    assert_eq!(evidence.evidence_id, failed_check.observation_id);
    assert_phase_recovery_reopens(&fixture, &projection);

    let forged_evidence = crate::TaskAttemptEvidence::new(
        "forged-formal-observation".into(),
        crate::TaskAttemptEvidenceKind::FormalVerificationFailed,
        evidence.canonical_bytes.clone(),
    )
    .expect("construct byte-exact forged formal source");
    let forged_outcome = TaskAttemptKnownCleanupOutcome::Retryable(
        crate::TaskAttemptRetryableCause::FormalVerificationFailed {
            formal_check_id: formal_check_id.clone(),
            evidence: forged_evidence,
        },
    );
    let forged = TaskAttemptRecoveryFacts::KnownCleanupRequired {
        launch_id: launch_id.clone(),
        session_id: session_id.clone(),
        outcome: forged_outcome.clone(),
    };
    assert!(
        task_attempt_authority::require_current_known_cleanup_outcome_authority(
            &fixture.ledger.connection,
            &fixture.attempt,
            &forged_outcome,
        )
        .is_err(),
        "shared source validator must reject a forged formal observation identity"
    );
    assert!(
        fixture
            .ledger
            .project_task_attempt_recovery_decision(
                &fixture.spec.sprint_id,
                &fixture.attempt.worker_lease.task_id,
                &fixture.attempt.attempt_id,
                &forged,
            )
            .is_err(),
        "ledger recovery must reject exact bytes under a forged formal source ID"
    );
}

#[test]
#[allow(clippy::too_many_lines)] // Direct SQL staging, rollback proof, and restart readback form one atomicity regression.
fn v15_formal_check_sql_rejects_failed_effect_observation_without_partial_authority() {
    // Preserve the standalone v15 formal-authority SQL cut on the last schema
    // where command observations were not atomically joined to v27 capture.
    let mut fixture = prepare_v26_phase_recovery_fixture();
    let (_, verification) = enter_clean_phase_verifying(&mut fixture, "failed-effect-sql");
    let criterion = &fixture.spec.acceptance_criteria[0];
    let AcceptanceKind::Automated(command) = &criterion.kind else {
        unreachable!("phase fixture starts with an automated criterion")
    };
    let contracts = phase_formal_contracts(
        &fixture,
        &verification,
        (0, &criterion.criterion_id, command),
        true,
        "failed-effect-sql",
        1_250,
    );
    let permit = match fixture
        .ledger
        .admit_task_attempt_formal_check_for_dispatch(
            &contracts.admission,
            &contracts.intent,
            &contracts.proposed_event,
        )
        .expect("admit SQL-bypass formal effect for dispatch")
    {
        TaskFormalCheckDispatchAdmission::Fresh { permit, .. } => permit,
        TaskFormalCheckDispatchAdmission::Existing { .. } => {
            panic!("SQL-bypass formal admission must be Fresh")
        }
    };
    let session = fixture
        .ledger
        .load_runner_session(&fixture.spec.sprint_id, &fixture.launch.session_id)
        .expect("load SQL-bypass formal session");
    let command_bytes =
        encode("formal-check command", &contracts.admission.command).expect("encode command");
    let (claimed, transport) = fixture
        .ledger
        .claim_runner_effect_dispatch(
            FreshRunnerEffectDispatchPermit::TaskFormalCheck(permit),
            OPAQUE_RUNNER_TRANSPORT_REQUEST_BYTES,
        )
        .expect("claim SQL-bypass formal dispatch");
    let claim_id = claimed
        .dispatch_claim
        .as_ref()
        .expect("claimed SQL-bypass formal effect")
        .dispatch_claim_id
        .clone();
    let authority = transport
        .validate_transport_request(
            &contracts.intent,
            &command_bytes,
            &fixture.launch,
            &session,
            None,
            OPAQUE_RUNNER_TRANSPORT_REQUEST_BYTES,
        )
        .expect("validate SQL-bypass formal transport");
    let evidence_bytes = encode("verification effect evidence", &contracts.evidence)
        .expect("encode canonical failed-effect evidence");
    let mut failed_observation = contracts.observation.clone();
    failed_observation.outcome = EffectOutcome::FailedBeforeEffect {
        evidence_digest: Digest::sha256(&evidence_bytes),
    };
    let failed_terminal = effect_terminal_event(
        &contracts.intent,
        &contracts.proposed_event.event_id,
        &failed_observation,
        fixture
            .ledger
            .next_sequence(&fixture.spec.sprint_id)
            .expect("failed effect terminal sequence"),
        "phase-formal-failed-effect-terminal",
    );
    let baseline = (
        row_count(&fixture.ledger, "verification_receipts"),
        row_count(&fixture.ledger, "verification_effect_evidence"),
        row_count(&fixture.ledger, "effect_observations"),
        row_count(&fixture.ledger, "task_attempt_formal_checks"),
        row_count(&fixture.ledger, "task_attempt_candidate_boundaries"),
    );
    let transaction = fixture
        .ledger
        .connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .expect("open failed-observation SQL transaction");
    insert_verification_receipt(&transaction, &contracts.evidence.verification)
        .expect("stage forged passing receipt");
    transaction
        .execute(
            "INSERT INTO verification_session_bindings (
                verification_receipt_id, sprint_id, session_id, contract_version
             ) VALUES (?1, ?2, ?3, ?4)",
            params![
                contracts.evidence.verification.receipt_id,
                contracts.evidence.verification.sprint_id,
                contracts.evidence.runner_session_id,
                i64::from(CONTRACT_VERSION),
            ],
        )
        .expect("stage forged passing session binding");
    insert_verification_effect_evidence(&transaction, &contracts.evidence, &evidence_bytes)
        .expect("stage forged passing verification evidence");
    insert_agent_event(&transaction, &failed_terminal).expect("stage failed terminal event");
    insert_effect_evidence_payload(&transaction, &failed_observation, &evidence_bytes)
        .expect("stage failed effect evidence");
    let observation_result = insert_claimed_effect_observation(
        &transaction,
        &failed_observation,
        &failed_terminal.event_id,
        &claim_id,
    );
    let error = match observation_result {
        Err(error) => error,
        Ok(()) => task_attempt_authority::insert_formal_check(
            &transaction,
            &contracts.admission.admission_id,
            &contracts.check,
        )
        .expect_err("failed command observation cannot authorize a passing formal check"),
    };
    assert!(
        error.to_string().contains(
            "formal check requires exact attempt, effect, observation, receipt, session, and sealed snapshot"
        ) || error
            .to_string()
            .contains("command output artifacts require their exact successful RunCommand observation"),
        "unexpected formal SQL outcome fence: {error}"
    );
    transaction
        .rollback()
        .expect("roll back failed-observation SQL cut");
    assert_eq!(
        (
            row_count(&fixture.ledger, "verification_receipts"),
            row_count(&fixture.ledger, "verification_effect_evidence"),
            row_count(&fixture.ledger, "effect_observations"),
            row_count(&fixture.ledger, "task_attempt_formal_checks"),
            row_count(&fixture.ledger, "task_attempt_candidate_boundaries"),
        ),
        baseline
    );
    fixture
        .ledger
        .record_claimed_effect_observation(
            authority,
            &failed_observation,
            &evidence_bytes,
            &failed_terminal,
        )
        .expect("persist known failed command observation after rejected forged transaction");
    drop(fixture.ledger);
    let reopened = reopen_test_legacy_ledger(&fixture.database);
    assert_eq!(row_count(&reopened, "task_attempt_formal_checks"), 0);
    assert_eq!(row_count(&reopened, "task_attempt_candidate_boundaries"), 0);
    assert_eq!(
        reopened
            .load_effect(&contracts.intent.effect_id)
            .expect("reload failed formal effect")
            .observation,
        Some(failed_observation)
    );
}

#[test]
#[allow(clippy::too_many_lines)] // Commit-uncertain recovery requires both persisted-row and restart projection assertions.
fn v15_failed_after_known_mutation_projects_uncertain_across_reopen() {
    let database = TestDatabase::new();
    let mut ledger = EventLedger::open(&database.path).expect("open mutation recovery ledger");
    let (_policy, launch, _session) = prepare_command_domain_session(&mut ledger);
    let attempt = ledger
        .load_task_attempt(&launch.worker_lease.as_ref().unwrap().lease_id)
        .expect("load mutation recovery attempt");
    let intent = EffectIntent {
        contract_version: CONTRACT_VERSION,
        effect_id: "recovery-unresolved-mutation".into(),
        idempotency_key: "recovery-unresolved-mutation-key".into(),
        sprint_id: launch.sprint_id.clone(),
        task_id: Some(attempt.worker_lease.task_id.clone()),
        worker_id: Some(attempt.worker_lease.worker_id.clone()),
        worker_lease: Some(attempt.worker_lease.clone()),
        causation_event_id: None,
        correlation_id: "recovery-unresolved-mutation".into(),
        kind: EffectKind::ReplaceRegularFile,
        request_digest: Digest::sha256(EFFECT_REQUEST_BYTES),
        policy_hash: launch.policy_hash.clone(),
        input_snapshot: digest('b'),
        created_at_unix_ms: 1_200,
    };
    let proposal = effect_proposal_event(
        &intent,
        ledger.next_sequence("sprint-1").unwrap(),
        "recovery-unresolved-mutation-proposed",
    );
    ledger
        .record_runner_effect_intent(&intent, EFFECT_REQUEST_BYTES, &proposal, &launch.session_id)
        .expect("pre-admit mutation effect");
    let observation = effect_observation(
        &intent,
        "recovery-unresolved-mutation-observed",
        EffectOutcome::FailedAfterKnownEffect {
            evidence_digest: effect_evidence_digest(),
        },
        1_250,
    );
    let terminal = effect_terminal_event(
        &intent,
        &proposal.event_id,
        &observation,
        ledger.next_sequence("sprint-1").unwrap(),
        "recovery-unresolved-mutation-finished",
    );
    assert!(matches!(
        ledger.record_effect_observation(&observation, EFFECT_EVIDENCE_BYTES, &terminal),
        Err(LedgerError::PostCommitStateUncertain {
            recovery_id,
            ..
        }) if recovery_id == intent.effect_id
    ));
    assert_eq!(
        ledger
            .connection
            .query_row(
                "SELECT COUNT(*) FROM effect_observations WHERE observation_id = ?1",
                [&observation.observation_id],
                |row| row.get::<_, i64>(0),
            )
            .expect("reload committed unresolved mutation observation"),
        1
    );
    assert_eq!(
        ledger
            .connection
            .query_row(
                "SELECT COUNT(*) FROM unresolved_mutation_effects WHERE effect_id = ?1",
                [&intent.effect_id],
                |row| row.get::<_, i64>(0),
            )
            .expect("count unresolved mutation authority"),
        1
    );
    load_sprint_inputs_for_recovery(&ledger.connection, "sprint-1")
        .expect("recovery input read bypasses the continuation fence");
    load_task_attempt_history_for_recovery(&ledger.connection, "sprint-1", "task-1")
        .expect("recovery history read bypasses the continuation fence");
    assert_eq!(
        task_attempt_recovery::derive_recovery_facts(
            &ledger.connection,
            "sprint-1",
            "task-1",
            &attempt.attempt_id,
        )
        .expect("derive unresolved mutation recovery facts"),
        TaskAttemptRecoveryFacts::UncertainAuthority {
            evidence_id: intent.effect_id.clone(),
        }
    );
    let expected = LedgerTaskAttemptRecoveryProjection {
        facts: TaskAttemptRecoveryFacts::UncertainAuthority {
            evidence_id: intent.effect_id.clone(),
        },
        decision: TaskAttemptRecoveryDecision::TerminalizeUnknown,
    };
    assert_recovery_projection_reopens(
        &ledger,
        &database,
        "sprint-1",
        "task-1",
        &attempt.attempt_id,
        &expected,
    );
}

#[derive(Clone, serde::Serialize)]
#[serde(deny_unknown_fields)]
struct ExpectedRecoveryMatrixPreimage {
    contract_version: u32,
    marker: SprintUnknownTerminalizationPending,
    tasks: Vec<ExpectedRecoveryMatrixTask>,
}

#[derive(Clone, serde::Serialize)]
#[serde(deny_unknown_fields)]
struct ExpectedRecoveryMatrixTask {
    task_id: String,
    attempts: Vec<ExpectedRecoveryMatrixAttempt>,
}

#[derive(Clone, serde::Serialize)]
#[serde(deny_unknown_fields)]
struct ExpectedRecoveryMatrixAttempt {
    attempt: TaskAttempt,
    disposition: Option<TaskAttemptDisposition>,
    legacy_classification: Option<LegacyTaskAttemptClassification>,
    lease_state: TaskAttemptLeaseState,
}

fn expected_recovery_matrix_id(
    marker: &SprintUnknownTerminalizationPending,
    tasks: Vec<ExpectedRecoveryMatrixTask>,
) -> String {
    let canonical = encode(
        "expected task attempt recovery matrix",
        &ExpectedRecoveryMatrixPreimage {
            contract_version: CONTRACT_VERSION,
            marker: marker.clone(),
            tasks,
        },
    )
    .expect("encode expected recovery matrix");
    let mut preimage = b"grok-build/task-attempt-recovery-matrix/v1\0".to_vec();
    preimage.extend_from_slice(&canonical);
    format!("recovery-matrix-{}", Digest::sha256(&preimage))
}

fn expected_recovery_matrix_task(
    ledger: &EventLedger,
    task_id: &str,
) -> ExpectedRecoveryMatrixTask {
    let history = ledger
        .load_task_attempt_history("sprint-1", task_id)
        .expect("load expected matrix task history");
    ExpectedRecoveryMatrixTask {
        task_id: task_id.into(),
        attempts: history
            .attempts
            .into_iter()
            .map(|entry| ExpectedRecoveryMatrixAttempt {
                attempt: entry.attempt,
                disposition: entry.disposition,
                legacy_classification: entry.legacy_classification,
                lease_state: entry.lease_state,
            })
            .collect(),
    }
}

#[test]
#[allow(clippy::too_many_lines)] // Two attempts, two readiness cuts, canonical ordering, and restart are one matrix proof.
fn v15_multi_task_recovery_matrix_requires_effect_readiness_and_sorts_by_task_id() {
    let database = TestDatabase::new();
    // Preserve the cleanup-unavailable v15 quarantine matrix, then verify the
    // resulting RunCommands acquire only migration exemptions in v27.
    let mut ledger = open_v26_test_ledger(&database);
    let [(launch_a, attempt_a), (launch_b, attempt_b)] =
        v15_prepare_two_running_attempts(&mut ledger);
    let (uncertain_a, proposal_a, permit_a) =
        persist_command_domain_intent(&mut ledger, &launch_a, "matrix-order-a", 1_170);
    let observation_a = persist_command_domain_observation(
        &mut ledger,
        &uncertain_a,
        &proposal_a,
        permit_a,
        EffectOutcome::Unknown {
            evidence_digest: effect_evidence_digest(),
        },
        1_180,
    );
    let (uncertain_b, proposal_b, permit_b) =
        persist_command_domain_intent(&mut ledger, &launch_b, "matrix-order-b", 1_190);
    let observation_b = persist_command_domain_observation(
        &mut ledger,
        &uncertain_b,
        &proposal_b,
        permit_b,
        EffectOutcome::Unknown {
            evidence_digest: effect_evidence_digest(),
        },
        1_200,
    );
    let (pending_b, _pending_proposal_b, _pending_permit_b) =
        persist_command_domain_intent(&mut ledger, &launch_b, "matrix-pending-b", 1_210);

    let (metadata_a, transition_a) = v15_unknown_metadata(
        &ledger,
        &attempt_a,
        "matrix-order-disposition-a",
        "matrix-order-transition-a",
        1_300,
    );
    let marker = v15_unknown_marker(&metadata_a);
    let uncertainty_a = crate::TaskAttemptUncertainEvidence {
        uncertainty_id: "matrix-order-authority-a".into(),
        authority_reference_ids: vec![observation_a.observation_id],
        evidence: crate::TaskAttemptEvidence::new(
            "matrix-order-evidence-a".into(),
            crate::TaskAttemptEvidenceKind::UncertainAuthority,
            b"task A authority remains uncertain".to_vec(),
        )
        .expect("construct matrix task A evidence"),
    };
    ledger
        .quarantine_task_attempt_unknown(&metadata_a, &uncertainty_a, &marker, &transition_a)
        .expect("quarantine matrix task A");
    assert!(
        ledger
            .load_task_attempt_recovery_matrix_evidence_id("sprint-1")
            .is_err(),
        "an undisposed active task must keep the recovery matrix unready"
    );

    let (metadata_b, transition_b) = v15_unknown_metadata(
        &ledger,
        &attempt_b,
        "matrix-order-disposition-b",
        "matrix-order-transition-b",
        1_320,
    );
    let incomplete_uncertainty_b = crate::TaskAttemptUncertainEvidence {
        uncertainty_id: "matrix-order-authority-b".into(),
        authority_reference_ids: vec![observation_b.observation_id.clone()],
        evidence: crate::TaskAttemptEvidence::new(
            "matrix-order-evidence-b".into(),
            crate::TaskAttemptEvidenceKind::UncertainAuthority,
            b"task B authority remains uncertain".to_vec(),
        )
        .expect("construct matrix task B evidence"),
    };
    let subset_baseline = (
        row_count(&ledger, "task_attempt_dispositions"),
        row_count(&ledger, "sprint_unknown_terminalization_pending"),
        row_count(&ledger, "agent_events"),
    );
    assert!(
        ledger
            .quarantine_task_attempt_unknown(
                &metadata_b,
                &incomplete_uncertainty_b,
                &marker,
                &transition_b,
            )
            .is_err(),
        "an immutable quarantine must reject an unresolved-authority subset"
    );
    assert_eq!(
        (
            row_count(&ledger, "task_attempt_dispositions"),
            row_count(&ledger, "sprint_unknown_terminalization_pending"),
            row_count(&ledger, "agent_events"),
        ),
        subset_baseline
    );
    let incomplete_disposition = TaskAttemptDisposition::UnknownQuarantined(
        crate::TaskAttemptUnknownQuarantinedDisposition {
            metadata: metadata_b.clone(),
            uncertain_evidence: incomplete_uncertainty_b,
        },
    );
    let transaction = ledger
        .connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .expect("open direct subset-quarantine transaction");
    let sql_error =
        task_attempt_authority::insert_disposition(&transaction, &incomplete_disposition)
            .expect_err("SQL must reject the same incomplete canonical set");
    assert!(
        sql_error.to_string().contains(
            "UnknownQuarantined requires the complete canonical attempt-scoped uncertain-authority set"
        ),
        "unexpected direct subset fence: {sql_error}"
    );
    transaction.rollback().expect("roll back direct subset cut");
    assert_eq!(
        (
            row_count(&ledger, "task_attempt_dispositions"),
            row_count(&ledger, "sprint_unknown_terminalization_pending"),
            row_count(&ledger, "agent_events"),
        ),
        subset_baseline
    );

    let mut complete_authorities = vec![observation_b.observation_id, pending_b.effect_id.clone()];
    complete_authorities.sort();
    let uncertainty_b = crate::TaskAttemptUncertainEvidence {
        uncertainty_id: "matrix-order-authority-b-complete".into(),
        authority_reference_ids: complete_authorities,
        evidence: crate::TaskAttemptEvidence::new(
            "matrix-order-evidence-b-complete".into(),
            crate::TaskAttemptEvidenceKind::UncertainAuthority,
            b"all task B uncertain authorities are retained".to_vec(),
        )
        .expect("construct complete matrix task B evidence"),
    };
    ledger
        .quarantine_task_attempt_unknown(&metadata_b, &uncertainty_b, &marker, &transition_b)
        .expect("complete canonical task B quarantine succeeds");
    let matrix_id = ledger
        .load_task_attempt_recovery_matrix_evidence_id("sprint-1")
        .expect("derive ready two-task recovery matrix");
    let task_a = expected_recovery_matrix_task(&ledger, "task-1");
    let task_b = expected_recovery_matrix_task(&ledger, "task-2");
    assert_eq!(
        matrix_id,
        expected_recovery_matrix_id(&marker, vec![task_a.clone(), task_b.clone()]),
        "matrix preimage must use task-id order independent of lease acquisition identity"
    );
    assert_ne!(
        matrix_id,
        expected_recovery_matrix_id(&marker, vec![task_b, task_a]),
        "reversing task order must produce a different canonical preimage"
    );
    for (task_id, attempt) in [("task-1", &attempt_a), ("task-2", &attempt_b)] {
        assert_eq!(
            ledger
                .load_task_attempt_recovery_projection("sprint-1", task_id, &attempt.attempt_id)
                .expect("derive all-domain matrix projection"),
            LedgerTaskAttemptRecoveryProjection {
                facts: TaskAttemptRecoveryFacts::AllDomainsUnknownTerminalReady {
                    marker_id: marker.marker_id.clone(),
                    evidence_id: matrix_id.clone(),
                },
                decision: TaskAttemptRecoveryDecision::TerminalizeSprintUnknown,
            }
        );
    }
    drop(ledger);
    drop(EventLedger::open(&database.path).expect("migrate ordered matrix to current schema"));
    let reopened = EventLedger::open_read_only(&database.path).expect("reopen ordered matrix");
    assert_eq!(
        reopened
            .load_task_attempt_recovery_matrix_evidence_id("sprint-1")
            .expect("rederive ordered matrix after reopen"),
        matrix_id
    );
}

#[test]
fn v15_active_legacy_unknown_quarantine_is_refused_before_recovery_projection() {
    let database = TestDatabase::new();
    let (attempt, _) =
        prepare_v14_classification_fixture(&database, V14AttemptFixtureKind::UnknownQuarantine);
    assert!(matches!(
        EventLedger::open(&database.path),
        Err(LedgerError::UnsafeV14TaskAttemptMigration {
            first_blocker: "legacy attempt is not integrated and released",
            first_authority_id,
            blocker_count: 1,
        }) if first_authority_id == attempt.attempt_id
    ));
}
