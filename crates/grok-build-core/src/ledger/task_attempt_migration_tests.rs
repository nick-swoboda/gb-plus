#[derive(Clone, Copy, Debug)]
enum V14AttemptFixtureKind {
    Released,
    Open,
    IntegratedCleanupPending,
    IntegratedReleased,
    ReleasedActiveState,
    UnknownQuarantine,
}

fn open_v14_fixture(database: &TestDatabase) -> EventLedger {
    schema_template::install_exact_database_at(14, &database.path);
    let connection = Connection::open(&database.path).expect("create schema-v14 database");
    register_schema_functions(&connection).expect("register schema functions for v14 fixture");
    connection
        .execute_batch(
            "PRAGMA foreign_keys = ON;
             PRAGMA synchronous = FULL;
             PRAGMA journal_mode = WAL;",
        )
        .expect("configure schema-v14 database");
    EventLedger {
        connection,
        database_path: database.path.clone(),
        read_only: false,
        instance_id: next_event_ledger_instance_id(),
    }
}

fn append_historical_v14_task_transition(
    ledger: &mut EventLedger,
    from: TaskState,
    to: TaskState,
    occurred_at_unix_ms: u64,
) -> AgentEvent {
    let sequence = ledger
        .next_sequence("sprint-1")
        .expect("historical transition sequence");
    let event = AgentEvent {
        contract_version: CONTRACT_VERSION,
        sequence,
        event_id: format!("v14-task-transition-{from:?}-{to:?}-{sequence}"),
        sprint_id: "sprint-1".into(),
        task_id: Some("task-1".into()),
        worker_id: Some("worker-1".into()),
        causation_id: None,
        correlation_id: "v14-task-transition".into(),
        policy_hash: None,
        occurred_at_unix_ms,
        payload: AgentEventKind::TaskStateChanged {
            from: format!("{from:?}"),
            to: format!("{to:?}"),
        },
    };
    event.validate().expect("valid historical task transition");
    let transaction = ledger
        .connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .expect("begin historical transition");
    validate_new_event(&transaction, &event).expect("validate historical event identity");
    // This intentionally replays bytes accepted by schema v14. The current
    // state machine rejects the old in-lease repair transitions, which is why
    // migration coverage must not route these fixtures through the v15 API.
    insert_agent_event(&transaction, &event).expect("insert historical transition");
    transaction.commit().expect("commit historical transition");
    event
}

fn prepare_v14_worker_attempt(
    ledger: &mut EventLedger,
) -> (CompiledExecutionPolicy, RunnerLaunchIntent, TaskAttempt) {
    let (spec, graph) = sprint_fixture();
    ledger
        .create_sprint(&spec, &graph, 1_000)
        .expect("persist v14 sprint");
    let (base, _, _, _, _, _, _, _) = completion_artifacts();
    ledger
        .persist_workspace_snapshot("sprint-1", &base)
        .expect("persist v14 base snapshot");
    let policy = compiled_shadow_test_policy("v14-migration-worker-policy");
    let launch = runner_launch(
        "v14-migration-launch",
        "v14-migration-session",
        RunnerSessionPurpose::TaskWorker,
        Some("worker-1"),
        &policy,
        1_210,
    );
    admit_test_runner_launch(ledger, &launch, &policy);
    ledger
        .register_runner_session(&runner_session(&launch, 1_300), &policy)
        .expect("persist v14 worker session");
    let lease = launch.worker_lease.clone().expect("v14 worker lease");
    let attempt = TaskAttempt::new(lease, 1, format!("{}-lease-acquired", launch.launch_id))
        .expect("derive expected v14 backfill attempt");
    (policy, launch, attempt)
}

#[allow(clippy::too_many_lines)] // The exact historical integration preimage is the migration subject.
fn persist_v14_task_integration(
    ledger: &mut EventLedger,
    launch: &RunnerLaunchIntent,
    policy: &CompiledExecutionPolicy,
) {
    let (base, result, change_set, verification, _, _, _, _) = completion_artifacts();
    ledger
        .persist_workspace_snapshot("sprint-1", &result)
        .expect("persist v14 integration result snapshot");
    ledger
        .persist_change_set("sprint-1", &change_set)
        .expect("persist v14 integration change set");
    persist_verification_evidence(
        ledger,
        launch,
        VerificationReceipt {
            receipt_id: "v14-migration-verification".into(),
            sprint_id: "sprint-1".into(),
            task_id: Some("task-1".into()),
            snapshot_id: result.snapshot_id.clone(),
            command: verification.command,
            policy_hash: policy.contract().policy_hash.clone(),
            exit_status: Some(0),
            termination: Some(CommandTerminationV1::Exited { code: 0 }),
            output_digest: digest('0'),
            duration_ms: 25,
            finished_at_unix_ms: 1_400,
        },
        b"v14 migration verification output".to_vec(),
        1_350,
    );

    let artifact = TaskIntegrationArtifactReference {
        format_version: 1,
        artifact_digest: Digest::sha256(b"v14-migration-stage-bundle"),
        change_set_id: change_set.change_set_id.clone(),
        base_snapshot: base.snapshot_id.clone(),
        result_snapshot: result.snapshot_id.clone(),
    };
    let request = TaskIntegrationRequest {
        contract_version: CONTRACT_VERSION,
        change_set: change_set.clone(),
        artifact: artifact.clone(),
    };
    let request_bytes =
        encode("v14 task integration request", &request).expect("encode v14 integration request");
    let intent = EffectIntent {
        contract_version: CONTRACT_VERSION,
        effect_id: "v14-migration-integration-effect".into(),
        idempotency_key: "v14-migration-integration-key".into(),
        sprint_id: "sprint-1".into(),
        task_id: Some("task-1".into()),
        worker_id: Some("worker-1".into()),
        worker_lease: launch.worker_lease.clone(),
        causation_event_id: None,
        correlation_id: "v14-migration-integration".into(),
        kind: EffectKind::IntegrateChangeSet,
        request_digest: Digest::sha256(&request_bytes),
        policy_hash: policy.contract().policy_hash.clone(),
        input_snapshot: base.snapshot_id.clone(),
        created_at_unix_ms: 1_410,
    };
    let proposal = effect_proposal_event(
        &intent,
        ledger
            .next_sequence("sprint-1")
            .expect("v14 integration proposal sequence"),
        "v14-migration-integration-proposed",
    );
    ledger
        .record_runner_effect_intent(&intent, &request_bytes, &proposal, &launch.session_id)
        .expect("persist v14 integration intent");
    let receipt = TaskIntegrationReceipt {
        contract_version: CONTRACT_VERSION,
        receipt_id: "v14-migration-integration-receipt".into(),
        sprint_id: "sprint-1".into(),
        task_id: "task-1".into(),
        worker_id: "worker-1".into(),
        worker_lease: launch.worker_lease.clone(),
        worker_launch_id: launch.launch_id.clone(),
        worker_session_id: launch.session_id.clone(),
        worker_policy_hash: policy.contract().policy_hash.clone(),
        effect_id: intent.effect_id.clone(),
        observation_id: "v14-migration-integration-observed".into(),
        change_set_id: change_set.change_set_id,
        input_snapshot: base.snapshot_id,
        result_snapshot: result.snapshot_id,
        task_verification_receipt_ids: vec!["v14-migration-verification".into()],
        integration_ordinal: 0,
        integrated_at_unix_ms: 1_450,
    };
    let evidence = TaskIntegrationEvidence {
        contract_version: CONTRACT_VERSION,
        artifact,
        validation: crate::TaskIntegrationValidationEvidence {
            mode: TaskIntegrationValidationMode::WorkerPublication,
            runner_launch_id: launch.launch_id.clone(),
            runner_session_id: launch.session_id.clone(),
            policy_hash: launch.policy_hash.clone(),
            grant_hash: launch.grant_hash.clone(),
            private_state_digest: launch.private_state_digest.clone(),
        },
        receipt,
    };
    let evidence_bytes =
        encode("v14 task integration evidence", &evidence).expect("encode v14 integration");
    let observation = effect_observation(
        &intent,
        &evidence.receipt.observation_id,
        EffectOutcome::Succeeded {
            evidence_digest: Digest::sha256(&evidence_bytes),
        },
        evidence.receipt.integrated_at_unix_ms,
    );
    let terminal = effect_terminal_event(
        &intent,
        &proposal.event_id,
        &observation,
        ledger
            .next_sequence("sprint-1")
            .expect("v14 integration terminal sequence"),
        "v14-migration-integration-finished",
    );
    ledger
        .record_task_integration_effect_observation(&observation, &terminal, &evidence)
        .expect("persist v14 integration evidence");

    for (from, to, timestamp) in [
        (TaskState::Leased, TaskState::Running, 1_460),
        (TaskState::Running, TaskState::Verifying, 1_470),
        (TaskState::Verifying, TaskState::Candidate, 1_480),
        (TaskState::Candidate, TaskState::Integrated, 1_490),
    ] {
        append_historical_v14_task_transition(ledger, from, to, timestamp);
    }
}

fn capture_historical_task_attempt_bytes(connection: &Connection) -> Vec<(String, Vec<u8>)> {
    let mut statement = connection
        .prepare(
            "SELECT label, bytes FROM (
                 SELECT 'sprint/spec/' || sprint_id AS label, spec_json AS bytes
                 FROM sprints WHERE sprint_id = 'sprint-1'
                 UNION ALL SELECT 'graph/' || sprint_id, graph_json
                 FROM sprint_task_graphs WHERE sprint_id = 'sprint-1'
                 UNION ALL SELECT 'event/' || event_id, event_json
                 FROM agent_events WHERE sprint_id = 'sprint-1'
                 UNION ALL SELECT 'snapshot/' || snapshot_id, snapshot_json
                 FROM workspace_snapshots WHERE sprint_id = 'sprint-1'
                 UNION ALL SELECT 'change-set/' || change_set_id, change_set_json
                 FROM change_sets WHERE sprint_id = 'sprint-1'
                 UNION ALL SELECT 'lease/scopes/' || lease_id, path_scopes_json
                 FROM worker_lease_acquisitions WHERE sprint_id = 'sprint-1'
                 UNION ALL SELECT 'lease/envelope/' || lease_id, lease_json
                 FROM worker_lease_acquisitions WHERE sprint_id = 'sprint-1'
                 UNION ALL SELECT 'launch/' || launch_id, intent_json
                 FROM runner_launch_intents WHERE sprint_id = 'sprint-1'
                 UNION ALL SELECT 'launch-policy/' || launch_id, execution_policy_json
                 FROM runner_launch_intents WHERE sprint_id = 'sprint-1'
                 UNION ALL SELECT 'session/' || session_id, record_json
                 FROM runner_session_policies WHERE sprint_id = 'sprint-1'
                 UNION ALL SELECT 'session-policy/' || session_id, execution_policy_json
                 FROM runner_session_policies WHERE sprint_id = 'sprint-1'
                 UNION ALL SELECT 'effect-intent/' || effect_id, intent_json
                 FROM effect_intents WHERE sprint_id = 'sprint-1'
                 UNION ALL SELECT 'effect-request/' || effect_id, request_bytes
                 FROM effect_request_payloads WHERE sprint_id = 'sprint-1'
                 UNION ALL SELECT 'effect-observation/' || observation_id, observation_json
                 FROM effect_observations WHERE sprint_id = 'sprint-1'
                 UNION ALL SELECT 'effect-evidence/' || effect_id, evidence_bytes
                 FROM effect_evidence_payloads WHERE sprint_id = 'sprint-1'
                 UNION ALL SELECT 'integration/' || receipt_id, receipt_json
                 FROM task_integration_receipts WHERE sprint_id = 'sprint-1'
                 UNION ALL SELECT 'cleanup-receipt/' || receipt_id, receipt_json
                 FROM worker_cleanup_receipts WHERE sprint_id = 'sprint-1'
                 UNION ALL SELECT 'cleanup-evidence/' || receipt_id, evidence_json
                 FROM worker_cleanup_receipts WHERE sprint_id = 'sprint-1'
                 UNION ALL SELECT 'cleanup-os/' || receipt_id, os_evidence_bytes
                 FROM worker_cleanup_receipts WHERE sprint_id = 'sprint-1'
                 UNION ALL SELECT 'terminal/' || record_id, evidence_json
                 FROM sprint_non_success_terminal_outcomes WHERE sprint_id = 'sprint-1'
                 UNION ALL SELECT 'completion/' || receipt_id, receipt_json
                 FROM v9_completion_receipts WHERE sprint_id = 'sprint-1'
             ) ORDER BY label ASC",
        )
        .expect("prepare historical byte capture");
    statement
        .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
        .expect("query historical bytes")
        .collect::<Result<Vec<_>, _>>()
        .expect("collect historical bytes")
}

fn prepare_v14_classification_fixture(
    database: &TestDatabase,
    kind: V14AttemptFixtureKind,
) -> (TaskAttempt, Vec<(String, Vec<u8>)>) {
    let mut ledger = open_v14_fixture(database);
    let (policy, launch, attempt) = prepare_v14_worker_attempt(&mut ledger);
    match kind {
        V14AttemptFixtureKind::Released => {
            persist_cleanup_evidence(
                &mut ledger,
                &launch,
                &digest('b'),
                "v14-migration-cleanup",
                WorkerCleanupBackend::LinuxCgroupV2,
                1_350,
                1_400,
            );
            append_historical_v14_task_transition(
                &mut ledger,
                TaskState::Leased,
                TaskState::Ready,
                1_410,
            );
        }
        V14AttemptFixtureKind::Open => {}
        V14AttemptFixtureKind::IntegratedCleanupPending => {
            persist_v14_task_integration(&mut ledger, &launch, &policy);
        }
        V14AttemptFixtureKind::IntegratedReleased => {
            persist_v14_task_integration(&mut ledger, &launch, &policy);
            persist_cleanup_evidence(
                &mut ledger,
                &launch,
                &digest('b'),
                "v14-migration-cleanup",
                WorkerCleanupBackend::LinuxCgroupV2,
                1_500,
                1_520,
            );
        }
        V14AttemptFixtureKind::ReleasedActiveState => {
            persist_cleanup_evidence(
                &mut ledger,
                &launch,
                &digest('b'),
                "v14-migration-cleanup",
                WorkerCleanupBackend::LinuxCgroupV2,
                1_350,
                1_400,
            );
        }
        V14AttemptFixtureKind::UnknownQuarantine => {
            append_historical_v14_task_transition(
                &mut ledger,
                TaskState::Leased,
                TaskState::Unknown,
                1_400,
            );
            let evidence =
                terminal_evidence("v14-migration-unknown", NonSuccessTerminalState::Unknown);
            let evidence_bytes =
                encode("historical v14 terminal evidence", &evidence).expect("encode Unknown");
            let evidence_digest = Digest::sha256(&evidence_bytes);
            let event = normalized_terminal_event(
                &evidence,
                evidence_digest.clone(),
                ledger
                    .next_sequence("sprint-1")
                    .expect("historical Unknown event sequence"),
            );
            let transaction = ledger
                .connection
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .expect("begin historical Unknown transaction");
            insert_terminal_proof(
                &transaction,
                &evidence,
                &evidence_digest,
                &event,
                TerminalProofAdmission::Unknown,
            )
                .expect("insert historical Unknown proof marker");
            insert_non_success_terminal_outcome(
                &transaction,
                &evidence,
                &evidence_bytes,
                &evidence_digest,
            )
            .expect("insert historical Unknown evidence");
            insert_agent_event(&transaction, &event).expect("insert historical Unknown event");
            transaction
                .commit()
                .expect("commit historical Unknown authority");
        }
    }
    let bytes = capture_historical_task_attempt_bytes(&ledger.connection);
    assert!(!bytes.is_empty());
    (attempt, bytes)
}

fn capture_schema_definition(connection: &Connection) -> Vec<(String, String, String, String)> {
    let mut statement = connection
        .prepare(
            "SELECT type, name, tbl_name, sql FROM sqlite_schema
             WHERE sql IS NOT NULL AND name NOT LIKE 'sqlite_%'
             ORDER BY type, name, tbl_name",
        )
        .expect("prepare schema definition capture");
    statement
        .query_map([], |row| {
            Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?))
        })
        .expect("query schema definition")
        .collect::<Result<Vec<_>, _>>()
        .expect("collect schema definition")
}

type HistoricalDatabaseRows = Vec<(String, Vec<Vec<String>>)>;

#[allow(clippy::too_many_lines)] // Generic all-table capture keeps refusal evidence exhaustive.
fn capture_all_historical_rows(connection: &Connection) -> HistoricalDatabaseRows {
    let tables = {
        let mut statement = connection
            .prepare(
                "SELECT name FROM sqlite_schema
                 WHERE type = 'table' AND name NOT LIKE 'sqlite_%'
                 ORDER BY name",
            )
            .expect("prepare historical table list");
        statement
            .query_map([], |row| row.get::<_, String>(0))
            .expect("query historical table list")
            .collect::<Result<Vec<_>, _>>()
            .expect("collect historical table list")
    };
    tables
        .into_iter()
        .map(|table| {
            let quoted_table = table.replace('"', "\"\"");
            let columns = {
                let mut statement = connection
                    .prepare(&format!("PRAGMA main.table_info(\"{quoted_table}\")"))
                    .expect("prepare historical column list");
                statement
                    .query_map([], |row| row.get::<_, String>(1))
                    .expect("query historical column list")
                    .collect::<Result<Vec<_>, _>>()
                    .expect("collect historical column list")
            };
            let quoted_columns = columns
                .iter()
                .map(|column| format!("\"{}\"", column.replace('"', "\"\"")))
                .collect::<Vec<_>>();
            let projection = quoted_columns
                .iter()
                .map(|column| format!("quote({column})"))
                .collect::<Vec<_>>()
                .join(", ");
            let order = quoted_columns.join(", ");
            let mut statement = connection
                .prepare(&format!(
                    "SELECT {projection} FROM main.\"{quoted_table}\" ORDER BY {order}"
                ))
                .expect("prepare exhaustive historical row capture");
            let column_count = columns.len();
            let rows = statement
                .query_map([], |row| {
                    (0..column_count)
                        .map(|index| row.get::<_, String>(index))
                        .collect::<Result<Vec<_>, _>>()
                })
                .expect("query exhaustive historical rows")
                .collect::<Result<Vec<_>, _>>()
                .expect("collect exhaustive historical rows");
            (table, rows)
        })
        .collect()
}

fn assert_v14_refusal_is_repeatable_and_byte_exact(
    database: &TestDatabase,
    historical_bytes: &[(String, Vec<u8>)],
    expected_authority_id: &str,
    expected_blocker: &'static str,
    expected_count: u64,
) {
    let before = Connection::open(&database.path).expect("open v14 before refusal");
    let schema = capture_schema_definition(&before);
    let all_rows = capture_all_historical_rows(&before);
    drop(before);
    for _ in 0..2 {
        assert!(matches!(
            EventLedger::open(&database.path),
            Err(LedgerError::UnsafeV14TaskAttemptMigration {
                first_blocker,
                first_authority_id,
                blocker_count,
            }) if first_blocker == expected_blocker
                && first_authority_id == expected_authority_id
                && blocker_count == expected_count
        ));
        let unchanged = Connection::open(&database.path).expect("inspect refused v14 image");
        let version: i64 = unchanged
            .pragma_query_value(None, "user_version", |row| row.get(0))
            .expect("read refused schema version");
        assert_eq!(version, 14);
        assert_eq!(capture_schema_definition(&unchanged), schema);
        assert_eq!(capture_all_historical_rows(&unchanged), all_rows);
        assert_eq!(
            capture_historical_task_attempt_bytes(&unchanged),
            historical_bytes
        );
        assert!(
            !task_attempt_authority::schema_is_installed(&unchanged)
                .expect("inspect v15 attempt table")
        );
    }
}

#[test]
fn v14_all_five_unsafe_classifications_refuse_repeatedly_without_writes() {
    for kind in [
        V14AttemptFixtureKind::Released,
        V14AttemptFixtureKind::Open,
        V14AttemptFixtureKind::IntegratedCleanupPending,
        V14AttemptFixtureKind::ReleasedActiveState,
        V14AttemptFixtureKind::UnknownQuarantine,
    ] {
        let database = TestDatabase::new();
        let (expected_attempt, historical_bytes) =
            prepare_v14_classification_fixture(&database, kind);
        assert_v14_refusal_is_repeatable_and_byte_exact(
            &database,
            &historical_bytes,
            &expected_attempt.attempt_id,
            "legacy attempt is not integrated and released",
            1,
        );
    }
}

#[test]
fn v14_direct_sql_migration_guard_runs_before_persistent_v15_ddl() {
    let database = TestDatabase::new();
    let (_, historical_bytes) =
        prepare_v14_classification_fixture(&database, V14AttemptFixtureKind::Released);
    let connection = Connection::open(&database.path).expect("open direct-guard fixture");
    register_schema_functions(&connection).expect("register direct-guard schema functions");
    let schema = capture_schema_definition(&connection);
    let all_rows = capture_all_historical_rows(&connection);
    let error = connection
        .execute_batch(task_attempt_authority::MIGRATION_V15)
        .expect_err("raw unsafe v14 migration must hit its first-statement guard");
    assert!(error.to_string().contains("safe = 1"));
    drop(connection);
    let connection = Connection::open(&database.path).expect("reopen direct-guard fixture");
    assert_eq!(capture_schema_definition(&connection), schema);
    assert_eq!(capture_all_historical_rows(&connection), all_rows);
    assert_eq!(
        capture_historical_task_attempt_bytes(&connection),
        historical_bytes
    );
    let version: i64 = connection
        .pragma_query_value(None, "user_version", |row| row.get(0))
        .expect("read direct-guard schema version");
    assert_eq!(version, 14);
}

#[test]
fn v14_cleanup_success_without_release_refuses_as_incomplete_attempt() {
    let database = TestDatabase::new();
    let (attempt, _) =
        prepare_v14_classification_fixture(&database, V14AttemptFixtureKind::IntegratedReleased);
    let connection = Connection::open(&database.path).expect("open release-gap fixture");
    let trigger_sql: String = connection
        .query_row(
            "SELECT sql FROM sqlite_schema
             WHERE type = 'trigger' AND name = 'worker_lease_releases_no_delete'",
            [],
            |row| row.get(0),
        )
        .expect("capture release immutability trigger");
    connection
        .execute_batch("DROP TRIGGER worker_lease_releases_no_delete")
        .expect("open historical release-gap fixture");
    connection
        .execute(
            "DELETE FROM worker_lease_releases WHERE lease_id = ?1",
            [&attempt.worker_lease.lease_id],
        )
        .expect("remove historical release only");
    connection
        .execute_batch(&trigger_sql)
        .expect("restore release immutability trigger");
    let historical_bytes = capture_historical_task_attempt_bytes(&connection);
    drop(connection);
    assert_v14_refusal_is_repeatable_and_byte_exact(
        &database,
        &historical_bytes,
        &attempt.attempt_id,
        "legacy attempt is not integrated and released",
        1,
    );
}

fn acquire_additional_v14_worker_attempt(
    ledger: &mut EventLedger,
    lease_epoch: u64,
    suffix: &str,
    acquired_at_unix_ms: u64,
) -> (RunnerLaunchIntent, String) {
    let lease = WorkerLease::new(
        "sprint-1".into(),
        lease_epoch,
        "task-1".into(),
        "worker-1".into(),
        vec![PathScope::Workspace],
        acquired_at_unix_ms,
    )
    .expect("construct additional historical lease");
    let acquisition_event = AgentEvent {
        contract_version: CONTRACT_VERSION,
        sequence: ledger
            .next_sequence("sprint-1")
            .expect("additional acquisition sequence"),
        event_id: format!("v14-over-budget-acquired-{suffix}"),
        sprint_id: "sprint-1".into(),
        task_id: Some("task-1".into()),
        worker_id: Some("worker-1".into()),
        causation_id: None,
        correlation_id: format!("v14-over-budget-{suffix}"),
        policy_hash: None,
        occurred_at_unix_ms: acquired_at_unix_ms,
        payload: AgentEventKind::TaskStateChanged {
            from: "Ready".into(),
            to: "Leased".into(),
        },
    };
    let transaction = ledger
        .connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .expect("begin additional v14 acquisition");
    worker_lease_authority::insert_acquisition(&transaction, &lease, &acquisition_event)
        .expect("insert additional v14 lease");
    insert_agent_event(&transaction, &acquisition_event)
        .expect("insert additional acquisition event");
    transaction
        .commit()
        .expect("commit additional v14 acquisition");

    let policy = compiled_shadow_test_policy(&format!("v14-over-budget-policy-{suffix}"));
    let mut launch = runner_launch(
        &format!("v14-over-budget-launch-{suffix}"),
        &format!("v14-over-budget-session-{suffix}"),
        RunnerSessionPurpose::TaskWorker,
        Some("worker-1"),
        &policy,
        acquired_at_unix_ms + 1,
    );
    launch.worker_lease = Some(lease);
    admit_test_runner_launch(ledger, &launch, &policy);
    ledger
        .register_runner_session(&runner_session(&launch, acquired_at_unix_ms + 2), &policy)
        .expect("persist additional historical worker session");
    let receipt_id = format!("v14-over-budget-cleanup-{suffix}");
    persist_cleanup_evidence(
        ledger,
        &launch,
        &digest('b'),
        &receipt_id,
        WorkerCleanupBackend::LinuxCgroupV2,
        acquired_at_unix_ms + 3,
        acquired_at_unix_ms + 20,
    );
    (launch, receipt_id)
}

#[test]
#[allow(clippy::too_many_lines)] // Completion, three acquisitions, migration, and exact diagnostic bytes are one invariant.
fn v14_over_budget_completion_refuses_repeatedly_without_writes() {
    let database = TestDatabase::new();
    let (
        expected_completion,
        historical_completion_bytes,
        historical_bytes,
        original_completion_receipt,
    ) = {
        let mut legacy = open_v14_fixture(&database);
        let (report, mut receipt, mut event) = prepare_completion_evidence(&mut legacy);

        append_historical_v14_task_transition(
            &mut legacy,
            TaskState::Leased,
            TaskState::Ready,
            1_545,
        );
        let (_, second_cleanup_id) =
            acquire_additional_v14_worker_attempt(&mut legacy, 2, "second", 1_550);
        append_historical_v14_task_transition(
            &mut legacy,
            TaskState::Leased,
            TaskState::Ready,
            1_575,
        );
        let (_, third_cleanup_id) =
            acquire_additional_v14_worker_attempt(&mut legacy, 3, "third", 1_580);
        receipt.worker_cleanup_receipt_ids.push(second_cleanup_id);
        receipt.worker_cleanup_receipt_ids.push(third_cleanup_id);
        receipt.worker_cleanup_receipt_ids.sort();
        event.sequence = legacy
            .next_sequence("sprint-1")
            .expect("over-budget completion event sequence");
        let completion =
            record_pre_v24_successful_completion_for_test(&mut legacy, &report, &receipt, &event)
                .expect("schema v14 accepts the historical completion");
        let completion_bytes = legacy
            .connection
            .query_row(
                "SELECT receipt_json FROM v9_completion_receipts
                 WHERE sprint_id = 'sprint-1'",
                [],
                |row| row.get::<_, Vec<u8>>(0),
            )
            .expect("capture exact historical completion receipt");
        (
            completion,
            completion_bytes,
            capture_historical_task_attempt_bytes(&legacy.connection),
            receipt,
        )
    };

    assert_eq!(expected_completion.receipt, original_completion_receipt);
    assert_eq!(
        expected_completion.receipt.receipt_id,
        decode_stored::<CompletionReceipt>(
            "historical over-budget completion",
            &historical_completion_bytes,
        )
        .expect("decode unchanged historical completion")
        .receipt_id
    );
    let inspection = Connection::open(&database.path).expect("inspect over-budget v14 image");
    let first_lease: String = inspection
        .query_row(
            "SELECT MIN(lease_id) FROM worker_lease_acquisitions",
            [],
            |row| row.get(0),
        )
        .expect("load first over-budget lease identity");
    drop(inspection);
    assert_v14_refusal_is_repeatable_and_byte_exact(
        &database,
        &historical_bytes,
        &first_lease,
        "legacy attempt exceeds budget",
        3,
    );
}

#[test]
fn v14_integrated_released_completion_is_the_only_safe_current_substitution() {
    let database = TestDatabase::new();
    let (expected_completion, historical_bytes) = prepare_safe_v14_completion(&database);

    let ledger =
        EventLedger::open(&database.path).expect("migrate safe integrated/released completion");
    let completion = load_migrated_pre_v24_completion(&ledger, &expected_completion);
    assert_eq!(
        capture_historical_task_attempt_bytes(&ledger.connection),
        historical_bytes
    );
    assert_eq!(
        ledger
            .load_legacy_task_attempt_completion_invalidation("sprint-1")
            .expect("load safe completion invalidation projection"),
        None
    );
    assert_eq!(
        ledger
            .load_completion("sprint-1")
            .expect("load safe current completion"),
        Some(completion.clone())
    );
    let history = ledger
        .load_task_attempt_history("sprint-1", "task-1")
        .expect("load safe migrated attempt history");
    assert_eq!(history.attempts.len(), 1);
    assert_eq!(
        history.attempts[0].legacy_classification,
        Some(LegacyTaskAttemptClassification::LegacyIntegratedReleased)
    );
    assert!(!history.attempts[0].lease_state.is_active());
    assert_eq!(
        history.budget_classification,
        TaskAttemptBudgetClassification::WithinBudget
    );
    drop(ledger);

    let reopened =
        EventLedger::open_read_only(&database.path).expect("reopen safe legacy completion");
    assert_eq!(
        reopened
            .load_completion("sprint-1")
            .expect("reload safe current completion"),
        Some(completion)
    );
    assert_eq!(
        capture_historical_task_attempt_bytes(&reopened.connection),
        historical_bytes
    );
}

fn prepare_safe_v14_completion(
    database: &TestDatabase,
) -> (PreV24CompletionProjection, Vec<(String, Vec<u8>)>) {
    let mut legacy = open_v14_fixture(database);
    let (report, receipt, mut event) = prepare_completion_evidence(&mut legacy);
    for (from, to, timestamp) in [
        (TaskState::Leased, TaskState::Running, 1_810),
        (TaskState::Running, TaskState::Verifying, 1_820),
        (TaskState::Verifying, TaskState::Candidate, 1_830),
        (TaskState::Candidate, TaskState::Integrated, 1_840),
    ] {
        append_historical_v14_task_transition(&mut legacy, from, to, timestamp);
    }
    event.sequence = legacy
        .next_sequence("sprint-1")
        .expect("safe legacy completion event sequence");
    let completion =
        record_pre_v24_successful_completion_for_test(&mut legacy, &report, &receipt, &event)
            .expect("record safe schema-v14 completion");
    (
        completion,
        capture_historical_task_attempt_bytes(&legacy.connection),
    )
}

#[test]
fn unsafe_already_v15_legacy_chain_fails_writable_and_read_only_open() {
    let database = TestDatabase::new();
    prepare_safe_v14_completion(&database);
    let ledger = EventLedger::open(&database.path).expect("install safe v15 legacy image");
    let attempt_id: String = ledger
        .connection
        .query_row(
            "SELECT attempt_id FROM task_attempts WHERE schema_generation = 14",
            [],
            |row| row.get(0),
        )
        .expect("load migrated legacy attempt identity");
    let trigger_sql: String = ledger
        .connection
        .query_row(
            "SELECT sql FROM sqlite_schema
             WHERE type = 'trigger' AND name = 'task_integration_receipts_no_update'",
            [],
            |row| row.get(0),
        )
        .expect("capture integration immutability trigger");
    ledger
        .connection
        .execute_batch("DROP TRIGGER task_integration_receipts_no_update")
        .expect("open unsafe-v15 fixture");
    ledger
        .connection
        .execute(
            "UPDATE task_integration_receipts
             SET worker_policy_hash = ?2
             WHERE worker_lease_id = ?1",
            params![attempt_id, digest('c').as_str()],
        )
        .expect("cross normalized legacy integration policy identity");
    ledger
        .connection
        .execute_batch(&trigger_sql)
        .expect("restore exact integration immutability trigger");
    drop(ledger);

    for result in [
        EventLedger::open_read_only(&database.path),
        EventLedger::open(&database.path),
    ] {
        let Err(error) = result else {
            panic!("unsafe existing v15 image must refuse open");
        };
        assert!(
            matches!(
                error,
                LedgerError::UnsafeV14TaskAttemptMigration {
                    first_blocker: "legacy integration chain is not exact",
                    ref first_authority_id,
                    blocker_count: 1,
                } if first_authority_id == &attempt_id
            ),
            "unexpected unsafe-v15 error: {error:?}"
        );
    }
}

#[test]
fn unsafe_already_v15_deleted_legacy_attempt_fails_both_open_modes() {
    let database = TestDatabase::new();
    prepare_safe_v14_completion(&database);
    let ledger = EventLedger::open(&database.path).expect("install deletable v15 legacy image");
    let attempt_id: String = ledger
        .connection
        .query_row(
            "SELECT attempt_id FROM task_attempts WHERE schema_generation = 14",
            [],
            |row| row.get(0),
        )
        .expect("load deletable legacy attempt identity");
    let trigger_names = [
        "task_attempt_legacy_classifications_no_delete",
        "task_attempts_no_delete",
    ];
    let trigger_sql = trigger_names
        .iter()
        .map(|name| {
            ledger
                .connection
                .query_row(
                    "SELECT sql FROM sqlite_schema WHERE type = 'trigger' AND name = ?1",
                    [name],
                    |row| row.get::<_, String>(0),
                )
                .expect("capture deleted-attempt fixture trigger")
        })
        .collect::<Vec<_>>();
    ledger
        .connection
        .execute_batch("PRAGMA foreign_keys = OFF")
        .expect("disable fixture foreign keys");
    for name in trigger_names {
        ledger
            .connection
            .execute_batch(&format!("DROP TRIGGER \"{name}\""))
            .expect("open deleted-attempt fixture");
    }
    ledger
        .connection
        .execute(
            "DELETE FROM task_attempt_legacy_classifications WHERE attempt_id = ?1",
            [&attempt_id],
        )
        .expect("delete derived legacy classification");
    ledger
        .connection
        .execute(
            "DELETE FROM task_attempts WHERE attempt_id = ?1",
            [&attempt_id],
        )
        .expect("delete derived legacy attempt");
    for sql in trigger_sql {
        ledger
            .connection
            .execute_batch(&sql)
            .expect("restore deleted-attempt fixture trigger");
    }
    ledger
        .connection
        .execute_batch("PRAGMA foreign_keys = ON")
        .expect("restore fixture foreign keys");
    drop(ledger);

    for result in [
        EventLedger::open_read_only(&database.path),
        EventLedger::open(&database.path),
    ] {
        assert!(matches!(
            result,
            Err(LedgerError::UnsafeV14TaskAttemptMigration {
                first_blocker: "legacy acquisition lacks exact attempt row",
                first_authority_id,
                blocker_count: 1,
            }) if first_authority_id == attempt_id
        ));
    }
}

#[test]
fn unsafe_already_v15_generation_flip_and_deleted_classification_fails_both_open_modes() {
    let database = TestDatabase::new();
    prepare_safe_v14_completion(&database);
    let ledger = EventLedger::open(&database.path).expect("install mutable v15 legacy image");
    let attempt_id: String = ledger
        .connection
        .query_row(
            "SELECT attempt_id FROM task_attempts WHERE schema_generation = 14",
            [],
            |row| row.get(0),
        )
        .expect("load migrated attempt identity");
    let trigger_names = [
        "task_attempts_no_update",
        "task_attempt_legacy_classifications_no_delete",
    ];
    let trigger_sql = trigger_names
        .iter()
        .map(|name| {
            ledger
                .connection
                .query_row(
                    "SELECT sql FROM sqlite_schema WHERE type = 'trigger' AND name = ?1",
                    [name],
                    |row| row.get::<_, String>(0),
                )
                .expect("capture generation-tamper fixture trigger")
        })
        .collect::<Vec<_>>();
    ledger
        .connection
        .execute_batch("PRAGMA foreign_keys = OFF")
        .expect("disable fixture foreign keys");
    for name in trigger_names {
        ledger
            .connection
            .execute_batch(&format!("DROP TRIGGER \"{name}\""))
            .expect("open generation-tamper fixture");
    }
    ledger
        .connection
        .execute(
            "UPDATE task_attempts SET schema_generation = 15 WHERE attempt_id = ?1",
            [&attempt_id],
        )
        .expect("forge current schema generation");
    ledger
        .connection
        .execute(
            "DELETE FROM task_attempt_legacy_classifications WHERE attempt_id = ?1",
            [&attempt_id],
        )
        .expect("delete migrated classification");
    for sql in trigger_sql {
        ledger
            .connection
            .execute_batch(&sql)
            .expect("restore generation-tamper fixture trigger");
    }
    ledger
        .connection
        .execute_batch("PRAGMA foreign_keys = ON")
        .expect("restore fixture foreign keys");
    drop(ledger);

    for result in [
        EventLedger::open_read_only(&database.path),
        EventLedger::open(&database.path),
    ] {
        assert!(matches!(
            result,
            Err(LedgerError::UnsafeV14TaskAttemptMigration {
                first_blocker: "current attempt lacks active or disposed authority",
                first_authority_id,
                blocker_count: 1,
            }) if first_authority_id == attempt_id
        ));
    }
}

#[test]
#[allow(clippy::too_many_lines)] // Two role branches prove the same native-child safety boundary.
fn v14_held_native_child_with_failed_cleanup_refuses_for_task_and_non_task_launches() {
    for (purpose_predicate, expected_blocker) in [
        (
            "launch.purpose = 'TaskWorker'",
            "legacy release and cleanup chain is not exact",
        ),
        (
            "launch.purpose != 'TaskWorker'",
            "legacy sprint has open cleanup admission",
        ),
    ] {
        let database = TestDatabase::new();
        prepare_safe_v14_completion(&database);
        let connection = Connection::open(&database.path).expect("open held-child fixture");
        register_schema_functions(&connection).expect("register held-child schema functions");
        let selection = format!(
            "SELECT admission.launch_id, admission.sprint_id,
                    admission.cleanup_effect_id, admission.contract_version,
                    admission.admitted_at_unix_ms, observation.observation_id,
                    COALESCE(launch.worker_lease_id, admission.launch_id)
             FROM runner_launch_cleanup_admissions admission
             JOIN runner_launch_intents launch ON launch.launch_id = admission.launch_id
             JOIN effect_observations observation
               ON observation.effect_id = admission.cleanup_effect_id
             WHERE {purpose_predicate}
             ORDER BY admission.launch_id LIMIT 1"
        );
        let (
            launch_id,
            sprint_id,
            cleanup_effect_id,
            contract_version,
            admitted_at,
            observation_id,
            authority_id,
        ): (String, String, String, i64, i64, String, String) = connection
            .query_row(&selection, [], |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                    row.get(6)?,
                ))
            })
            .expect("select exact cleanup admission branch");
        let trigger_names = [
            "runner_launch_preparation_attempts_exact_open_admission",
            "runner_launch_preparation_outcomes_exact_attempt",
            "effect_observations_no_update",
        ];
        let trigger_sql = trigger_names
            .iter()
            .map(|name| {
                connection
                    .query_row(
                        "SELECT sql FROM sqlite_schema
                         WHERE type = 'trigger' AND name = ?1",
                        [name],
                        |row| row.get::<_, String>(0),
                    )
                    .expect("capture fixture trigger")
            })
            .collect::<Vec<_>>();
        for name in trigger_names {
            connection
                .execute_batch(&format!("DROP TRIGGER \"{name}\""))
                .expect("open held-child corruption fixture");
        }
        let preparation_id = format!("held-child-preparation-{launch_id}");
        let native_journal_id = format!("held-child-journal-{launch_id}");
        connection
            .execute(
                "INSERT INTO runner_launch_preparation_attempts (
                    launch_id, sprint_id, cleanup_effect_id, attempt_id,
                    native_journal_id, expected_platform_binding_digest,
                    contract_version, claimed_at_unix_ms, attempt_json
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, X'01')",
                params![
                    launch_id,
                    sprint_id,
                    cleanup_effect_id,
                    preparation_id,
                    native_journal_id,
                    digest('a').as_str(),
                    contract_version,
                    admitted_at + 1,
                ],
            )
            .expect("inject held-child preparation attempt");
        connection
            .execute(
                "INSERT INTO runner_launch_preparation_outcomes (
                    attempt_id, sprint_id, launch_id, cleanup_effect_id,
                    native_journal_id, disposition, native_evidence_digest,
                    native_evidence_bytes, contract_version, finished_at_unix_ms,
                    outcome_json
                 ) VALUES (?1, ?2, ?3, ?4, ?5, 'HeldChildPrepared', ?6,
                           X'01', ?7, ?8, X'01')",
                params![
                    preparation_id,
                    sprint_id,
                    launch_id,
                    cleanup_effect_id,
                    native_journal_id,
                    digest('b').as_str(),
                    contract_version,
                    admitted_at + 2,
                ],
            )
            .expect("inject held-child preparation outcome");
        connection
            .execute(
                "UPDATE effect_observations SET outcome = 'FailedBeforeEffect'
                 WHERE observation_id = ?1",
                [&observation_id],
            )
            .expect("replace cleanup success with failed-before-effect index");
        for sql in trigger_sql {
            connection
                .execute_batch(&sql)
                .expect("restore exact fixture trigger");
        }
        let schema = capture_schema_definition(&connection);
        let rows = capture_all_historical_rows(&connection);
        let direct_error = connection
            .execute_batch(task_attempt_authority::MIGRATION_V15)
            .expect_err("first-statement SQL guard must reject held child");
        assert!(direct_error.to_string().contains("safe = 1"));
        drop(connection);
        let unchanged = Connection::open(&database.path).expect("reopen held-child v14 image");
        assert_eq!(capture_schema_definition(&unchanged), schema);
        assert_eq!(capture_all_historical_rows(&unchanged), rows);
        drop(unchanged);
        assert!(matches!(
            EventLedger::open(&database.path),
            Err(LedgerError::UnsafeV14TaskAttemptMigration {
                first_blocker,
                first_authority_id,
                blocker_count: 1,
            }) if first_blocker == expected_blocker && first_authority_id == authority_id
        ));
    }
}

#[test]
fn v14_cleanup_release_before_integration_refuses_in_rust_and_sql() {
    let database = TestDatabase::new();
    prepare_safe_v14_completion(&database);
    let connection = Connection::open(&database.path).expect("open inverted timeline fixture");
    register_schema_functions(&connection).expect("register inverted timeline functions");
    let attempt_id: String = connection
        .query_row(
            "SELECT lease_id FROM worker_lease_acquisitions",
            [],
            |row| row.get(0),
        )
        .expect("load timeline attempt identity");
    let trigger_names = [
        "worker_lease_releases_no_update",
        "worker_cleanup_receipts_no_update",
        "effect_observations_no_update",
    ];
    let trigger_sql = trigger_names
        .iter()
        .map(|name| {
            connection
                .query_row(
                    "SELECT sql FROM sqlite_schema WHERE type = 'trigger' AND name = ?1",
                    [name],
                    |row| row.get::<_, String>(0),
                )
                .expect("capture timeline fixture trigger")
        })
        .collect::<Vec<_>>();
    for name in trigger_names {
        connection
            .execute_batch(&format!("DROP TRIGGER \"{name}\""))
            .expect("open timeline corruption fixture");
    }
    let integration_time: i64 = connection
        .query_row(
            "SELECT integrated_at_unix_ms FROM task_integration_receipts
             WHERE worker_lease_id = ?1",
            [&attempt_id],
            |row| row.get(0),
        )
        .expect("load integration time");
    let inverted_time = integration_time - 1;
    connection
        .execute(
            "UPDATE worker_lease_releases SET released_at_unix_ms = ?2
             WHERE lease_id = ?1",
            params![attempt_id, inverted_time],
        )
        .expect("invert release time");
    connection
        .execute(
            "UPDATE worker_cleanup_receipts SET cleaned_at_unix_ms = ?2
             WHERE worker_lease_id = ?1",
            params![attempt_id, inverted_time],
        )
        .expect("invert cleanup time");
    connection
        .execute(
            "UPDATE effect_observations SET observed_at_unix_ms = ?2
             WHERE effect_id = (
                 SELECT cleanup_effect_id FROM worker_lease_releases WHERE lease_id = ?1
             )",
            params![attempt_id, inverted_time],
        )
        .expect("invert cleanup observation time");
    for sql in trigger_sql {
        connection
            .execute_batch(&sql)
            .expect("restore timeline fixture trigger");
    }
    let direct_error = connection
        .execute_batch(task_attempt_authority::MIGRATION_V15)
        .expect_err("SQL guard must reject cleanup before integration");
    assert!(direct_error.to_string().contains("safe = 1"));
    drop(connection);
    assert!(matches!(
        EventLedger::open(&database.path),
        Err(LedgerError::UnsafeV14TaskAttemptMigration {
            first_blocker: "legacy release and cleanup chain is not exact",
            first_authority_id,
            blocker_count: 1,
        }) if first_authority_id == attempt_id
    ));
}

#[test]
fn v14_direct_guard_rejects_crossed_contract_and_effect_kind_fields() {
    for (trigger_name, mutation, expected_blocker) in [
        (
            "worker_lease_releases_no_update",
            "UPDATE worker_lease_releases
             SET contract_version = contract_version + 1",
            "legacy release and cleanup chain is not exact",
        ),
        (
            "effect_observations_no_update",
            "UPDATE effect_observations SET effect_kind = 'RunCommand'
             WHERE effect_id = (SELECT effect_id FROM task_integration_receipts)",
            "legacy integration chain is not exact",
        ),
    ] {
        let database = TestDatabase::new();
        prepare_safe_v14_completion(&database);
        let connection = Connection::open(&database.path).expect("open crossed-field fixture");
        register_schema_functions(&connection).expect("register crossed-field functions");
        let attempt_id: String = connection
            .query_row(
                "SELECT lease_id FROM worker_lease_acquisitions",
                [],
                |row| row.get(0),
            )
            .expect("load crossed-field attempt identity");
        let trigger_sql: String = connection
            .query_row(
                "SELECT sql FROM sqlite_schema WHERE type = 'trigger' AND name = ?1",
                [trigger_name],
                |row| row.get(0),
            )
            .expect("capture crossed-field trigger");
        connection
            .execute_batch(&format!("DROP TRIGGER \"{trigger_name}\""))
            .expect("open crossed-field fixture");
        connection
            .execute_batch(mutation)
            .expect("cross normalized v14 field");
        connection
            .execute_batch(&trigger_sql)
            .expect("restore crossed-field trigger");
        let schema = capture_schema_definition(&connection);
        let rows = capture_all_historical_rows(&connection);
        let direct_error = connection
            .execute_batch(task_attempt_authority::MIGRATION_V15)
            .expect_err("direct SQL guard must reject crossed normalized field");
        assert!(direct_error.to_string().contains("safe = 1"));
        drop(connection);
        let unchanged = Connection::open(&database.path).expect("reopen crossed-field image");
        assert_eq!(capture_schema_definition(&unchanged), schema);
        assert_eq!(capture_all_historical_rows(&unchanged), rows);
        drop(unchanged);
        assert!(matches!(
            EventLedger::open(&database.path),
            Err(LedgerError::UnsafeV14TaskAttemptMigration {
                first_blocker,
                first_authority_id,
                blocker_count: 1,
            }) if first_blocker == expected_blocker && first_authority_id == attempt_id
        ));
    }
}

#[test]
#[allow(clippy::too_many_lines)] // One table proves raw/Rust parity across independent blockers.
fn v14_raw_and_rust_guard_parity_matrix_refuses_without_writes() {
    let cases = [
        (
            "crossed-release-ids",
            "worker_lease_releases_no_update",
            "UPDATE worker_lease_releases
             SET cleanup_effect_id = (SELECT effect_id FROM task_integration_receipts),
                 cleanup_observation_id = (
                     SELECT observation_id FROM task_integration_receipts
                 )",
            "legacy release and cleanup chain is not exact",
            "SELECT lease_id FROM worker_lease_acquisitions",
        ),
        (
            "non-integrated-latest-state",
            "agent_events_no_update",
            "UPDATE agent_events
             SET event_json = CAST(json_set(
                 CAST(event_json AS TEXT),
                 '$.payload.TaskStateChanged.to', 'Candidate'
             ) AS BLOB)
             WHERE event_id = (
                 SELECT event_id FROM agent_events
                 WHERE json_extract(CAST(event_json AS TEXT), '$.task_id') = 'task-1'
                   AND json_type(CAST(event_json AS TEXT),
                                 '$.payload.TaskStateChanged') = 'object'
                 ORDER BY sequence DESC LIMIT 1
             )",
            "legacy task state is not Integrated",
            "SELECT lease_id FROM worker_lease_acquisitions",
        ),
        (
            "uncovered-graph-task",
            "sprint_task_graphs_no_update",
            "UPDATE sprint_task_graphs
             SET graph_json = CAST(json_insert(
                 CAST(graph_json AS TEXT), '$.tasks[#]',
                 json('{\"task_id\":\"uncovered\"}')
             ) AS BLOB)",
            "legacy graph coverage is not bijective",
            "SELECT 'sprint-1/uncovered'",
        ),
        (
            "unobserved-effect",
            "effect_observations_no_delete",
            "DELETE FROM effect_observations
             WHERE effect_id = (
                 SELECT effect_id FROM effect_intents
                 WHERE effect_kind = 'RunCommand' AND task_id IS NOT NULL
                 ORDER BY effect_id LIMIT 1
             )",
            "legacy sprint has unresolved effect",
            "SELECT effect_id FROM effect_intents
             WHERE effect_kind = 'RunCommand' AND task_id IS NOT NULL
             ORDER BY effect_id LIMIT 1",
        ),
        (
            "unresolved-mutation",
            "effect_observations_no_update",
            "UPDATE effect_observations
             SET effect_kind = 'CreateRegularFile', outcome = 'FailedAfterKnownEffect'
             WHERE effect_id = (
                 SELECT effect_id FROM effect_intents
                 WHERE effect_kind = 'RunCommand' AND task_id IS NOT NULL
                 ORDER BY effect_id LIMIT 1
             )",
            "legacy sprint has unresolved mutation",
            "SELECT effect_id FROM effect_intents
             WHERE effect_kind = 'RunCommand' AND task_id IS NOT NULL
             ORDER BY effect_id LIMIT 1",
        ),
        (
            "missing-evidence-payload",
            "effect_evidence_payloads_no_delete",
            "DELETE FROM effect_evidence_payloads
             WHERE effect_id = (
                 SELECT effect_id FROM effect_intents
                 WHERE effect_kind = 'RunCommand' AND task_id IS NOT NULL
                 ORDER BY effect_id LIMIT 1
             )",
            "legacy sprint has incomplete effect payload",
            "SELECT effect_id FROM effect_intents
             WHERE effect_kind = 'RunCommand' AND task_id IS NOT NULL
             ORDER BY effect_id LIMIT 1",
        ),
        (
            "dynamic-finish-gap",
            "application_receipts_no_delete",
            "DELETE FROM application_receipts",
            "legacy sprint has dynamic finish receipt gap",
            "SELECT effect_id FROM application_receipts LIMIT 1",
        ),
    ];
    for (case, trigger_name, mutation, expected_blocker, authority_query) in cases {
        let database = TestDatabase::new();
        let (_, _) = prepare_safe_v14_completion(&database);
        let connection = Connection::open(&database.path).expect("open guard-parity fixture");
        register_schema_functions(&connection).expect("register guard-parity functions");
        let authority_id: String = connection
            .query_row(authority_query, [], |row| row.get(0))
            .unwrap_or_else(|error| panic!("load {case} authority: {error}"));
        let trigger_sql: String = connection
            .query_row(
                "SELECT sql FROM sqlite_schema WHERE type = 'trigger' AND name = ?1",
                [trigger_name],
                |row| row.get(0),
            )
            .unwrap_or_else(|error| panic!("capture {case} trigger: {error}"));
        connection
            .execute_batch("PRAGMA foreign_keys = OFF")
            .expect("disable parity-fixture foreign keys");
        connection
            .execute_batch(&format!("DROP TRIGGER \"{trigger_name}\""))
            .unwrap_or_else(|error| panic!("open {case} fixture: {error}"));
        connection
            .execute_batch(mutation)
            .unwrap_or_else(|error| panic!("apply {case} mutation: {error}"));
        connection
            .execute_batch(&trigger_sql)
            .unwrap_or_else(|error| panic!("restore {case} trigger: {error}"));
        connection
            .execute_batch("PRAGMA foreign_keys = ON")
            .expect("restore parity-fixture foreign keys");
        let schema = capture_schema_definition(&connection);
        let rows = capture_all_historical_rows(&connection);
        let historical_bytes = capture_historical_task_attempt_bytes(&connection);
        let direct_error = connection
            .execute_batch(task_attempt_authority::MIGRATION_V15)
            .unwrap_err();
        assert!(direct_error.to_string().contains("safe = 1"), "case {case}");
        drop(connection);
        let unchanged = Connection::open(&database.path).expect("reopen parity fixture");
        assert_eq!(capture_schema_definition(&unchanged), schema, "case {case}");
        assert_eq!(capture_all_historical_rows(&unchanged), rows, "case {case}");
        drop(unchanged);
        assert_v14_refusal_is_repeatable_and_byte_exact(
            &database,
            &historical_bytes,
            &authority_id,
            expected_blocker,
            1,
        );
    }
}

fn prepare_v14_unsafe_completed_history(
    database: &TestDatabase,
) -> (CompletionReceipt, Vec<u8>, HistoricalMigrationBytes) {
    let mut legacy = open_v14_fixture(database);
    let (report, mut receipt, mut event) = prepare_completion_evidence(&mut legacy);
    append_historical_v14_task_transition(&mut legacy, TaskState::Leased, TaskState::Ready, 1_545);
    let (_, cleanup_id) =
        acquire_additional_v14_worker_attempt(&mut legacy, 2, "unsafe-second", 1_550);
    receipt.worker_cleanup_receipt_ids.push(cleanup_id);
    receipt.worker_cleanup_receipt_ids.sort();
    event.sequence = legacy
        .next_sequence("sprint-1")
        .expect("unsafe-history completion event sequence");
    record_pre_v24_successful_completion_for_test(&mut legacy, &report, &receipt, &event)
        .expect("schema v14 accepts completion with unsafe within-budget history");
    let completion_bytes = legacy
        .connection
        .query_row(
            "SELECT receipt_json FROM v9_completion_receipts
             WHERE sprint_id = 'sprint-1'",
            [],
            |row| row.get::<_, Vec<u8>>(0),
        )
        .expect("capture unsafe historical completion bytes");
    let historical_bytes = capture_historical_task_attempt_bytes(&legacy.connection);
    (receipt, completion_bytes, historical_bytes)
}

#[test]
fn v14_unsafe_within_budget_completion_refuses_without_derived_invalidation() {
    let database = TestDatabase::new();
    let (receipt, completion_bytes, historical_bytes) =
        prepare_v14_unsafe_completed_history(&database);
    assert_eq!(
        decode_stored::<CompletionReceipt>("unsafe v14 completion", &completion_bytes)
            .expect("decode unchanged unsafe completion"),
        receipt
    );
    let inspection = Connection::open(&database.path).expect("inspect unsafe v14 image");
    let first_unsafe_lease: String = inspection
        .query_row(
            "SELECT MIN(acquisition.lease_id)
             FROM worker_lease_acquisitions acquisition
             WHERE NOT EXISTS (
                 SELECT 1 FROM task_integration_receipts integration
                 WHERE integration.worker_lease_id = acquisition.lease_id
             ) OR NOT EXISTS (
                 SELECT 1 FROM worker_lease_releases release
                 WHERE release.lease_id = acquisition.lease_id
             )",
            [],
            |row| row.get(0),
        )
        .expect("load first unsafe legacy lease");
    drop(inspection);
    assert_v14_refusal_is_repeatable_and_byte_exact(
        &database,
        &historical_bytes,
        &first_unsafe_lease,
        "legacy attempt is not integrated and released",
        1,
    );
}

type HistoricalMigrationBytes = Vec<(String, Vec<u8>)>;

fn capture_pre_v14_worker_bytes(connection: &Connection) -> HistoricalMigrationBytes {
    let mut statement = connection
        .prepare(
            "SELECT label, bytes FROM (
                 SELECT 'sprint/spec/' || sprint_id AS label, spec_json AS bytes
                 FROM sprints WHERE sprint_id = 'sprint-1'
                 UNION ALL SELECT 'graph/' || sprint_id, graph_json
                 FROM sprint_task_graphs WHERE sprint_id = 'sprint-1'
                 UNION ALL SELECT 'event/' || event_id, event_json
                 FROM agent_events WHERE sprint_id = 'sprint-1'
                 UNION ALL SELECT 'snapshot/' || snapshot_id, snapshot_json
                 FROM workspace_snapshots WHERE sprint_id = 'sprint-1'
                 UNION ALL SELECT 'launch/' || launch_id, intent_json
                 FROM runner_launch_intents WHERE sprint_id = 'sprint-1'
                 UNION ALL SELECT 'launch-policy/' || launch_id, execution_policy_json
                 FROM runner_launch_intents WHERE sprint_id = 'sprint-1'
                 UNION ALL SELECT 'session/' || session_id, record_json
                 FROM runner_session_policies WHERE sprint_id = 'sprint-1'
                 UNION ALL SELECT 'session-policy/' || session_id, execution_policy_json
                 FROM runner_session_policies WHERE sprint_id = 'sprint-1'
             ) ORDER BY label ASC",
        )
        .expect("prepare pre-v14 byte capture");
    statement
        .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
        .expect("query pre-v14 bytes")
        .collect::<Result<Vec<_>, _>>()
        .expect("collect pre-v14 bytes")
}

#[test]
#[allow(clippy::too_many_lines)] // Pre-v14 setup and two-stage migration refusal are one compatibility invariant.
fn pre_v14_task_worker_authority_refuses_at_v15_and_remains_byte_exact() {
    let database = TestDatabase::new();
    let historical_bytes = {
        schema_template::install_exact_database_at(12, &database.path);
        let connection = Connection::open(&database.path).expect("create schema-v12 database");
        register_schema_functions(&connection)
            .expect("register schema functions for pre-v14 fixture");
        connection
            .execute_batch(
                "PRAGMA foreign_keys = ON;
                 PRAGMA synchronous = FULL;
                 PRAGMA journal_mode = WAL;",
            )
            .expect("configure schema-v12 database");
        let mut legacy = EventLedger {
            connection,
            database_path: database.path.clone(),
            read_only: false,
            instance_id: next_event_ledger_instance_id(),
        };
        let (spec, graph) = sprint_fixture();
        legacy
            .create_sprint(&spec, &graph, 1_000)
            .expect("persist pre-v14 sprint");
        let (base, _, _, _, _, _, _, _) = completion_artifacts();
        legacy
            .persist_workspace_snapshot("sprint-1", &base)
            .expect("persist pre-v14 base snapshot");
        let policy = compiled_shadow_test_policy("pre-v14-worker-policy");
        let launch = runner_launch(
            "pre-v14-worker-launch",
            "pre-v14-worker-session",
            RunnerSessionPurpose::TaskWorker,
            Some("worker-1"),
            &policy,
            1_200,
        );
        legacy
            .record_runner_launch_intent(&launch, &policy)
            .expect("persist schema-v12 task-worker launch");
        legacy
            .register_runner_session(&runner_session(&launch, 1_250), &policy)
            .expect("persist schema-v12 task-worker session");
        capture_pre_v14_worker_bytes(&legacy.connection)
    };

    assert!(matches!(
        EventLedger::open(&database.path),
        Err(LedgerError::UnsafeV14TaskAttemptMigration {
            first_blocker: "pre-v14 worker-lease marker",
            first_authority_id,
            blocker_count: 1,
        }) if first_authority_id == "sprint-1"
    ));
    let v14 = Connection::open(&database.path).expect("inspect migrated-through-v14 refusal");
    let version: i64 = v14
        .pragma_query_value(None, "user_version", |row| row.get(0))
        .expect("read v14 refusal version");
    assert_eq!(version, 14);
    assert_eq!(capture_pre_v14_worker_bytes(&v14), historical_bytes);
    let refused_schema = capture_schema_definition(&v14);
    let refused_rows = capture_all_historical_rows(&v14);
    drop(v14);
    assert!(matches!(
        EventLedger::open(&database.path),
        Err(LedgerError::UnsafeV14TaskAttemptMigration {
            first_blocker: "pre-v14 worker-lease marker",
            first_authority_id,
            blocker_count: 1,
        }) if first_authority_id == "sprint-1"
    ));
    let unchanged = Connection::open(&database.path).expect("reinspect refused v14 image");
    assert_eq!(capture_pre_v14_worker_bytes(&unchanged), historical_bytes);
    assert_eq!(capture_schema_definition(&unchanged), refused_schema);
    assert_eq!(capture_all_historical_rows(&unchanged), refused_rows);
}
