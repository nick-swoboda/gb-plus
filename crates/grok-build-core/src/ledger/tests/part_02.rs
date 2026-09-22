    fn try_admit_test_runner_launch(
        ledger: &mut EventLedger,
        launch: &RunnerLaunchIntent,
        policy: &CompiledExecutionPolicy,
    ) -> Result<(), LedgerError> {
        if !runner_launch_cleanup_admission::schema_is_installed(&ledger.connection)? {
            return ledger.record_runner_launch_intent(launch, policy);
        }
        if launch.purpose == RunnerSessionPurpose::TaskWorker
            && runner_role_policy_matches(launch.purpose, policy.contract())
        {
            acquire_test_launch_lease(ledger, launch)?;
        }
        let backend = match launch.purpose {
            RunnerSessionPurpose::TaskWorker
            | RunnerSessionPurpose::FinalVerifier
            | RunnerSessionPurpose::LiveStateVerifier => WorkerCleanupBackend::LinuxCgroupV2,
            RunnerSessionPurpose::Applier => WorkerCleanupBackend::TrustedApplierDirectChildWait,
        };
        let (intent, _, request_bytes, event) =
            test_runner_launch_cleanup_contracts(ledger, launch, backend)?;
        ledger
            .admit_runner_launch_with_cleanup(launch, policy, &intent, &request_bytes, &event)
            .map(|_| ())
    }

    fn acquire_test_launch_lease(
        ledger: &mut EventLedger,
        launch: &RunnerLaunchIntent,
    ) -> Result<(), LedgerError> {
        let lease = launch.worker_lease.as_ref().ok_or_else(|| {
            reference_mismatch("test runner launch", "task-worker fixture lacks a lease")
        })?;
        let active = ledger.load_active_worker_leases(&launch.sprint_id)?;
        if active.iter().any(|stored| stored == lease) {
            return Ok(());
        }
        if !active.is_empty() {
            return Err(reference_mismatch(
                "test runner launch",
                "fixture sprint already owns a different active lease",
            ));
        }
        let ready = AgentEvent {
            contract_version: CONTRACT_VERSION,
            sequence: ledger.next_sequence(&launch.sprint_id)?,
            event_id: format!("{}-task-ready", launch.launch_id),
            sprint_id: launch.sprint_id.clone(),
            task_id: Some(lease.task_id.clone()),
            worker_id: None,
            causation_id: None,
            correlation_id: format!("{}-lease", launch.launch_id),
            policy_hash: None,
            occurred_at_unix_ms: lease.acquired_at_unix_ms.saturating_sub(1).max(1),
            payload: AgentEventKind::TaskStateChanged {
                from: "Planned".into(),
                to: "Ready".into(),
            },
        };
        ledger.append_event(&ready)?;
        let acquired = AgentEvent {
            contract_version: CONTRACT_VERSION,
            sequence: ledger.next_sequence(&launch.sprint_id)?,
            event_id: format!("{}-lease-acquired", launch.launch_id),
            sprint_id: launch.sprint_id.clone(),
            task_id: Some(lease.task_id.clone()),
            worker_id: Some(lease.worker_id.clone()),
            causation_id: Some(ready.event_id),
            correlation_id: format!("{}-lease", launch.launch_id),
            policy_hash: Some(launch.policy_hash.clone()),
            occurred_at_unix_ms: lease.acquired_at_unix_ms,
            payload: AgentEventKind::TaskStateChanged {
                from: "Ready".into(),
                to: "Leased".into(),
            },
        };
        if task_attempt_authority::schema_is_installed(&ledger.connection)? {
            ledger.acquire_task_attempt(lease, &acquired).map(|_| ())
        } else {
            let transaction = ledger
                .connection
                .transaction_with_behavior(TransactionBehavior::Immediate)?;
            worker_lease_authority::insert_acquisition(&transaction, lease, &acquired)?;
            insert_agent_event(&transaction, &acquired)?;
            transaction.commit()?;
            Ok(())
        }
    }

    fn test_runner_launch_cleanup_contracts(
        ledger: &EventLedger,
        launch: &RunnerLaunchIntent,
        backend: WorkerCleanupBackend,
    ) -> Result<(EffectIntent, WorkerCleanupRequest, Vec<u8>, AgentEvent), LedgerError> {
        let sprint = ledger.load_sprint(&launch.sprint_id)?;
        let input_snapshot = sprint.spec.base_snapshot;
        let snapshot = ledger.load_workspace_snapshot(&launch.sprint_id, &input_snapshot)?;
        let admitted_at_unix_ms = launch.created_at_unix_ms.max(snapshot.created_at_unix_ms);
        let request = WorkerCleanupRequest {
            contract_version: CONTRACT_VERSION,
            sprint_id: launch.sprint_id.clone(),
            launch_id: launch.launch_id.clone(),
            session_id: launch.session_id.clone(),
            policy_hash: launch.policy_hash.clone(),
            grant_hash: launch.grant_hash.clone(),
            policy_version: launch.policy_version,
            platform_backend: backend,
        };
        let request_bytes = encode("worker cleanup request", &request)?;
        let intent = EffectIntent {
            contract_version: CONTRACT_VERSION,
            effect_id: format!("cleanup-admission-effect-{}", launch.launch_id),
            idempotency_key: format!("cleanup-admission-key-{}", launch.launch_id),
            sprint_id: launch.sprint_id.clone(),
            task_id: None,
            worker_id: None,
            worker_lease: launch.worker_lease.clone(),
            causation_event_id: None,
            correlation_id: format!("cleanup-admission-correlation-{}", launch.launch_id),
            kind: EffectKind::CleanupWorkerDomain,
            request_digest: Digest::sha256(&request_bytes),
            policy_hash: launch.policy_hash.clone(),
            input_snapshot,
            created_at_unix_ms: admitted_at_unix_ms,
        };
        let event = effect_proposal_event(
            &intent,
            ledger.next_sequence(&launch.sprint_id)?,
            &format!("cleanup-admission-event-{}", launch.launch_id),
        );
        Ok((intent, request, request_bytes, event))
    }

    fn admit_test_runner_launch(
        ledger: &mut EventLedger,
        launch: &RunnerLaunchIntent,
        policy: &CompiledExecutionPolicy,
    ) {
        try_admit_test_runner_launch(ledger, launch, policy)
            .expect("atomically admit runner launch and cleanup");
    }

    fn prepare_test_launch_admission(
        ledger: &mut EventLedger,
        suffix: &str,
        purpose: RunnerSessionPurpose,
        worker_id: Option<&str>,
        backend: WorkerCleanupBackend,
    ) -> (
        CompiledExecutionPolicy,
        RunnerLaunchIntent,
        EffectIntent,
        WorkerCleanupRequest,
        Vec<u8>,
        AgentEvent,
    ) {
        prepare_effect_input(ledger);
        let policy = if purpose == RunnerSessionPurpose::TaskWorker {
            compiled_shadow_test_policy(&format!("atomic-launch-policy-{suffix}"))
        } else {
            compiled_test_policy(&format!("atomic-launch-policy-{suffix}"))
        };
        let launch = runner_launch(
            &format!("atomic-launch-{suffix}"),
            &format!("atomic-session-{suffix}"),
            purpose,
            worker_id,
            &policy,
            1_100,
        );
        if purpose == RunnerSessionPurpose::TaskWorker {
            acquire_test_launch_lease(ledger, &launch)
                .expect("acquire atomic task-worker fixture lease");
        }
        let (intent, request, request_bytes, event) =
            test_runner_launch_cleanup_contracts(ledger, &launch, backend)
                .expect("build atomic launch cleanup contracts");
        (policy, launch, intent, request, request_bytes, event)
    }

    fn test_launch_preparation_attempt(
        admission: &PersistedRunnerLaunchCleanupAdmission,
        suffix: &str,
        claimed_at_unix_ms: u64,
    ) -> RunnerLaunchPreparationAttempt {
        RunnerLaunchPreparationAttempt {
            contract_version: CONTRACT_VERSION,
            attempt_id: format!("preparation-attempt-{suffix}"),
            sprint_id: admission.launch.sprint_id.clone(),
            launch_id: admission.launch.launch_id.clone(),
            cleanup_effect_id: admission.cleanup_effect.intent.effect_id.clone(),
            native_journal_id: format!("native-journal-{suffix}"),
            expected_platform_binding_digest: Digest::sha256(
                format!("expected-platform-binding:{suffix}").as_bytes(),
            ),
            claimed_at_unix_ms,
        }
    }

    fn held_child_preparation_outcome(
        suffix: &str,
        finished_at_unix_ms: u64,
    ) -> RunnerLaunchPreparationOutcome {
        RunnerLaunchPreparationOutcome {
            disposition: RunnerLaunchPreparationDisposition::HeldChildPrepared,
            native_evidence_bytes: format!("service-owned held-child journal:{suffix}")
                .into_bytes(),
            finished_at_unix_ms,
        }
    }

    fn cleanup_terminal_from_live_claim(
        claim: &LiveRunnerCleanupClaim<'_>,
        suffix: &str,
        cleaned_at_unix_ms: u64,
    ) -> RunnerCleanupTerminalRecord {
        cleanup_terminal_for_admission(
            claim.admission(),
            claim.next_event_sequence(),
            suffix,
            cleaned_at_unix_ms,
        )
    }

    fn cleanup_terminal_for_admission(
        admission: &PersistedRunnerLaunchCleanupAdmission,
        next_event_sequence: u64,
        suffix: &str,
        cleaned_at_unix_ms: u64,
    ) -> RunnerCleanupTerminalRecord {
        let intent = &admission.cleanup_effect.intent;
        let os_evidence_bytes = format!("zero descendants under exclusion:{suffix}").into_bytes();
        let evidence = WorkerCleanupEvidence {
            receipt: WorkerCleanupReceipt {
                contract_version: CONTRACT_VERSION,
                receipt_id: format!("excluded-cleanup-receipt-{suffix}"),
                sprint_id: admission.launch.sprint_id.clone(),
                launch_id: admission.launch.launch_id.clone(),
                effect_id: intent.effect_id.clone(),
                observation_id: format!("excluded-cleanup-observation-{suffix}"),
                session_id: admission.launch.session_id.clone(),
                worker_lease: admission.launch.worker_lease.clone(),
                policy_hash: admission.launch.policy_hash.clone(),
                grant_hash: admission.launch.grant_hash.clone(),
                policy_version: admission.launch.policy_version,
                platform_backend: admission.cleanup_request.platform_backend,
                os_evidence_digest: Digest::sha256(&os_evidence_bytes),
                surviving_processes: 0,
                cleaned_at_unix_ms,
            },
            os_evidence_bytes,
        };
        let evidence_bytes =
            encode("worker cleanup evidence", &evidence).expect("encode excluded cleanup");
        let observation = effect_observation(
            intent,
            &evidence.receipt.observation_id,
            EffectOutcome::Succeeded {
                evidence_digest: Digest::sha256(&evidence_bytes),
            },
            cleaned_at_unix_ms,
        );
        let event = effect_terminal_event(
            intent,
            &admission.cleanup_effect.proposed_event.event_id,
            &observation,
            next_event_sequence,
            &format!("excluded-cleanup-finished-{suffix}"),
        );
        RunnerCleanupTerminalRecord {
            observation,
            event,
            evidence,
        }
    }

    fn prepare_planned_refused_task_attempt(
        ledger: &mut EventLedger,
        suffix: &str,
        max_attempts_per_task: u8,
    ) -> TaskAttempt {
        assert!(max_attempts_per_task > 0);
        let (mut spec, graph) = sprint_fixture();
        spec.budget.max_attempts_per_task = max_attempts_per_task;
        ledger
            .create_sprint(&spec, &graph, 1_000)
            .expect("persist planned-cleanup sprint");
        let (base, _, _, _, _, _, _, _) = completion_artifacts();
        ledger
            .persist_workspace_snapshot(&spec.sprint_id, &base)
            .expect("persist planned-cleanup input snapshot");

        let policy = compiled_shadow_test_policy(&format!("planned-cleanup-policy-{suffix}"));
        let launch = runner_launch(
            &format!("planned-cleanup-launch-{suffix}"),
            &format!("planned-cleanup-session-{suffix}"),
            RunnerSessionPurpose::TaskWorker,
            Some("worker-1"),
            &policy,
            1_100,
        );
        acquire_test_launch_lease(ledger, &launch)
            .expect("acquire planned-cleanup task-worker lease");
        let (intent, _, request_bytes, proposal) = test_runner_launch_cleanup_contracts(
            ledger,
            &launch,
            WorkerCleanupBackend::LinuxCgroupV2,
        )
        .expect("build planned-cleanup admission contracts");
        let admission = ledger
            .admit_runner_launch_with_cleanup(&launch, &policy, &intent, &request_bytes, &proposal)
            .expect("admit planned-cleanup launch");
        let preparation_attempt = test_launch_preparation_attempt(&admission, suffix, 1_150);
        ledger
            .with_runner_launch_preparation_claim(&admission, &preparation_attempt, |_| {
                RunnerLaunchPreparationOutcome {
                    disposition: RunnerLaunchPreparationDisposition::RefusedBeforeNativeEffect,
                    native_evidence_bytes: format!(
                        "planned cleanup refused before native effect:{suffix}"
                    )
                    .into_bytes(),
                    finished_at_unix_ms: 1_200,
                }
            })
            .expect("persist planned-cleanup refusal authority");
        task_attempt_authority::load(
            &ledger.connection,
            &launch
                .worker_lease
                .as_ref()
                .expect("planned-cleanup launch lease")
                .lease_id,
        )
        .expect("load planned-cleanup task attempt")
    }

    fn migrate_test_v12_legacy_launch(
        database: &TestDatabase,
        suffix: &str,
    ) -> (EventLedger, CompiledExecutionPolicy, RunnerLaunchIntent) {
        schema_template::install_exact_database_at(12, &database.path);
        let connection = Connection::open(&database.path).expect("create v12 legacy database");
        connection
            .execute_batch(
                "PRAGMA foreign_keys = ON;
                 PRAGMA synchronous = FULL;
                 PRAGMA journal_mode = WAL;",
            )
            .expect("configure v12 legacy database");
        connection
            .pragma_update(None, "user_version", 12_i64)
            .expect("mark v12 legacy schema");
        let mut v12 = EventLedger {
            connection,
            database_path: database.path.clone(),
            read_only: false,
            instance_id: next_event_ledger_instance_id(),
        };
        prepare_effect_input(&mut v12);
        let policy = compiled_shadow_test_policy(&format!("legacy-retry-policy-{suffix}"));
        let launch = runner_launch(
            &format!("legacy-retry-launch-{suffix}"),
            &format!("legacy-retry-session-{suffix}"),
            RunnerSessionPurpose::TaskWorker,
            Some("worker-1"),
            &policy,
            1_100,
        );
        v12.record_runner_launch_intent(&launch, &policy)
            .expect("persist v12 legacy launch");
        drop(v12);
        let connection = Connection::open(&database.path).expect("reopen v12 legacy launch");
        register_schema_functions(&connection).expect("register v13 schema functions");
        connection
            .execute_batch("PRAGMA foreign_keys = ON; PRAGMA trusted_schema = OFF;")
            .expect("configure v13 legacy-launch connection");
        connection
            .execute_batch(MIGRATIONS[12])
            .expect("install runner-cleanup migration v13");
        connection
            .pragma_update(None, "user_version", 13_i64)
            .expect("mark v13 legacy-launch schema");
        (
            EventLedger {
                connection,
                database_path: database.path.clone(),
                read_only: false,
                instance_id: next_event_ledger_instance_id(),
            },
            policy,
            launch,
        )
    }

    fn reopen_test_legacy_ledger(database: &TestDatabase) -> EventLedger {
        let connection = Connection::open(&database.path).expect("reopen historical test ledger");
        register_schema_functions(&connection).expect("register historical schema functions");
        connection
            .busy_timeout(BUSY_TIMEOUT)
            .expect("configure historical busy timeout");
        connection
            .execute_batch("PRAGMA foreign_keys = ON; PRAGMA trusted_schema = OFF;")
            .expect("configure historical test connection");
        EventLedger {
            connection,
            database_path: database.path.clone(),
            read_only: false,
            instance_id: next_event_ledger_instance_id(),
        }
    }

    fn legacy_launch_cleanup_contracts(
        ledger: &EventLedger,
        launch: &RunnerLaunchIntent,
        suffix: &str,
        created_at_unix_ms: u64,
    ) -> (EffectIntent, Vec<u8>, AgentEvent) {
        let request = WorkerCleanupRequest {
            contract_version: CONTRACT_VERSION,
            sprint_id: launch.sprint_id.clone(),
            launch_id: launch.launch_id.clone(),
            session_id: launch.session_id.clone(),
            policy_hash: launch.policy_hash.clone(),
            grant_hash: launch.grant_hash.clone(),
            policy_version: launch.policy_version,
            platform_backend: WorkerCleanupBackend::LinuxCgroupV2,
        };
        let request_bytes =
            encode("worker cleanup request", &request).expect("encode legacy cleanup request");
        let intent = EffectIntent {
            contract_version: CONTRACT_VERSION,
            effect_id: format!("legacy-retry-effect-{suffix}"),
            idempotency_key: format!("legacy-retry-key-{suffix}"),
            sprint_id: launch.sprint_id.clone(),
            task_id: None,
            worker_id: None,
            // The authoritative launch row was written by v12, before worker
            // leases existed, so cleanup retains the explicit legacy gap.
            worker_lease: None,
            causation_event_id: None,
            correlation_id: format!("legacy-retry-correlation-{suffix}"),
            kind: EffectKind::CleanupWorkerDomain,
            request_digest: Digest::sha256(&request_bytes),
            policy_hash: launch.policy_hash.clone(),
            input_snapshot: ledger
                .load_sprint(&launch.sprint_id)
                .expect("load legacy cleanup sprint")
                .spec
                .base_snapshot,
            created_at_unix_ms,
        };
        let event = effect_proposal_event(
            &intent,
            ledger
                .next_sequence(&launch.sprint_id)
                .expect("legacy cleanup proposal sequence"),
            &format!("legacy-retry-event-{suffix}"),
        );
        (intent, request_bytes, event)
    }

    fn record_legacy_launch_cleanup_success(
        ledger: &mut EventLedger,
        launch: &RunnerLaunchIntent,
        intent: &EffectIntent,
        proposal: &AgentEvent,
        suffix: &str,
        cleaned_at_unix_ms: u64,
    ) {
        let os_evidence_bytes = format!("legacy zero descendants:{suffix}").into_bytes();
        let evidence = WorkerCleanupEvidence {
            receipt: WorkerCleanupReceipt {
                contract_version: CONTRACT_VERSION,
                receipt_id: format!("legacy-retry-receipt-{suffix}"),
                sprint_id: launch.sprint_id.clone(),
                launch_id: launch.launch_id.clone(),
                effect_id: intent.effect_id.clone(),
                observation_id: format!("legacy-retry-observation-{suffix}"),
                session_id: launch.session_id.clone(),
                worker_lease: None,
                policy_hash: launch.policy_hash.clone(),
                grant_hash: launch.grant_hash.clone(),
                policy_version: launch.policy_version,
                platform_backend: WorkerCleanupBackend::LinuxCgroupV2,
                os_evidence_digest: Digest::sha256(&os_evidence_bytes),
                surviving_processes: 0,
                cleaned_at_unix_ms,
            },
            os_evidence_bytes,
        };
        let evidence_bytes =
            encode("worker cleanup evidence", &evidence).expect("encode legacy cleanup success");
        let observation = effect_observation(
            intent,
            &evidence.receipt.observation_id,
            EffectOutcome::Succeeded {
                evidence_digest: Digest::sha256(&evidence_bytes),
            },
            cleaned_at_unix_ms,
        );
        let terminal = effect_terminal_event(
            intent,
            &proposal.event_id,
            &observation,
            ledger
                .next_sequence(&launch.sprint_id)
                .expect("legacy cleanup success sequence"),
            &format!("legacy-retry-finished-{suffix}"),
        );
        ledger
            .record_worker_cleanup_effect_observation(&observation, &terminal, &evidence)
            .expect("record legacy cleanup success");
    }

    fn inject_runner_launch_cleanup_authority_corruption(ledger: &EventLedger, corruption: &str) {
        let (launch_id, sprint_id, session_id, contract_version) = ledger
            .connection
            .query_row(
                "SELECT launch_id, sprint_id, session_id, contract_version
                 FROM runner_launch_cleanup_admissions
                 ORDER BY launch_id ASC LIMIT 1",
                [],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, i64>(3)?,
                    ))
                },
            )
            .expect("select authoritative launch for corruption");
        match corruption {
            "both" => {
                ledger
                    .connection
                    .execute_batch("DROP TRIGGER legacy_runner_launch_cleanup_gaps_no_insert;")
                    .expect("open doubled-classification corruption");
                ledger
                    .connection
                    .execute(
                        "INSERT INTO legacy_runner_launch_cleanup_gaps (
                            launch_id, sprint_id, session_id, gap_kind, contract_version
                         ) VALUES (?1, ?2, ?3, 'PreV13Unbound', ?4)",
                        params![launch_id, sprint_id, session_id, contract_version],
                    )
                    .expect("inject doubled launch cleanup classification");
            }
            "neither" => {
                ledger
                    .connection
                    .execute_batch(
                        "DROP TRIGGER runner_launch_cleanup_admissions_no_delete;
                         PRAGMA foreign_keys = OFF;",
                    )
                    .expect("open missing-classification corruption");
                ledger
                    .connection
                    .execute(
                        "DELETE FROM runner_launch_cleanup_admissions
                         WHERE sprint_id = ?1 AND launch_id = ?2",
                        params![sprint_id, launch_id],
                    )
                    .expect("delete both launch cleanup classifications");
            }
            "crossed" => {
                ledger
                    .connection
                    .execute_batch("DROP TRIGGER runner_launch_cleanup_admissions_no_update;")
                    .expect("open crossed-authority corruption");
                ledger
                    .connection
                    .execute(
                        "UPDATE runner_launch_cleanup_admissions
                         SET session_id = ?1
                         WHERE sprint_id = ?2 AND launch_id = ?3",
                        params![format!("crossed-{session_id}"), sprint_id, launch_id,],
                    )
                    .expect("cross launch cleanup authority session");
            }
            _ => unreachable!("closed launch cleanup corruption matrix"),
        }
    }

    fn enter_test_task_attempt_running(
        ledger: &mut EventLedger,
        launch: &RunnerLaunchIntent,
        started_at_unix_ms: u64,
    ) -> TaskAttemptRunningBoundary {
        let lease = launch.worker_lease.as_ref().expect("task-worker lease");
        let attempt = ledger
            .load_task_attempt(&lease.lease_id)
            .expect("load test task attempt");
        if current_task_state(&ledger.connection, &lease.sprint_id, &lease.task_id)
            .expect("load test task state")
            == TaskState::Running
        {
            let boundary_id = ledger
                .connection
                .query_row(
                    "SELECT boundary_id FROM task_attempt_running_boundaries
                     WHERE attempt_id = ?1",
                    [&attempt.attempt_id],
                    |row| row.get::<_, String>(0),
                )
                .expect("load existing Running boundary identity");
            return ledger
                .load_task_attempt_running_boundary(&boundary_id)
                .expect("load existing Running boundary");
        }
        let event = AgentEvent {
            contract_version: CONTRACT_VERSION,
            sequence: ledger
                .next_sequence(&lease.sprint_id)
                .expect("Running sequence"),
            event_id: format!("{}-test-running", launch.launch_id),
            sprint_id: lease.sprint_id.clone(),
            task_id: Some(lease.task_id.clone()),
            worker_id: Some(lease.worker_id.clone()),
            causation_id: Some(attempt.opening_event_id.clone()),
            correlation_id: format!("{}-test-attempt", launch.launch_id),
            policy_hash: Some(launch.policy_hash.clone()),
            occurred_at_unix_ms: started_at_unix_ms,
            payload: AgentEventKind::TaskStateChanged {
                from: "Leased".into(),
                to: "Running".into(),
            },
        };
        let boundary = TaskAttemptRunningBoundary {
            contract_version: CONTRACT_VERSION,
            boundary_id: format!("{}-test-running-boundary", launch.launch_id),
            attempt,
            runner_launch_id: launch.launch_id.clone(),
            runner_session_id: launch.session_id.clone(),
            transition_event_id: event.event_id.clone(),
            started_at_unix_ms,
        };
        ledger
            .start_task_attempt(&boundary, &event)
            .expect("enter test task attempt Running");
        boundary
    }

    fn prepare_command_domain_session(
        ledger: &mut EventLedger,
    ) -> (
        CompiledExecutionPolicy,
        RunnerLaunchIntent,
        RunnerSessionPolicyRecord,
    ) {
        prepare_effect_input(ledger);
        let policy = compiled_shadow_test_policy("command-domain-worker-policy");
        let launch = runner_launch(
            "launch-command-domain",
            "session-command-domain",
            RunnerSessionPurpose::TaskWorker,
            Some("worker-1"),
            &policy,
            1_100,
        );
        admit_test_runner_launch(ledger, &launch, &policy);
        let session = runner_session(&launch, 1_150);
        ledger
            .register_runner_session(&session, &policy)
            .expect("register command-domain session");
        enter_test_task_attempt_running(ledger, &launch, 1_160);
        (policy, launch, session)
    }

    struct FreshDispatchInputFixture {
        database: TestDatabase,
        ledger: EventLedger,
        launch: RunnerLaunchIntent,
        session: RunnerSessionPolicyRecord,
        running: TaskAttemptRunningBoundary,
        intent: EffectIntent,
        proposal: AgentEvent,
    }

    fn prepare_fresh_dispatch_input(suffix: &str) -> FreshDispatchInputFixture {
        let database = TestDatabase::new();
        let mut ledger = EventLedger::open(&database.path).expect("open fresh-dispatch ledger");
        let (_policy, launch, session) = prepare_command_domain_session(&mut ledger);
        let running = load_runner_effect_dispatch_running_boundary(&ledger.connection, &session)
            .expect("load fresh-dispatch Running boundary")
            .expect("task-worker dispatch has a Running boundary");
        let lease = launch
            .worker_lease
            .as_ref()
            .expect("fresh dispatch launch carries a lease");
        let mut intent = effect_intent(
            &format!("fresh-dispatch-effect-{suffix}"),
            &format!("fresh-dispatch-key-{suffix}"),
            1_200,
        );
        intent.task_id = Some(lease.task_id.clone());
        intent.worker_id = Some(lease.worker_id.clone());
        intent.worker_lease = Some(lease.clone());
        intent.causation_event_id = Some(running.transition_event_id.clone());
        intent.correlation_id = format!("fresh-dispatch-correlation-{suffix}");
        intent.policy_hash = launch.policy_hash.clone();
        let proposal = effect_proposal_event(
            &intent,
            ledger
                .next_sequence(&intent.sprint_id)
                .expect("fresh dispatch proposal sequence"),
            &format!("fresh-dispatch-proposal-{suffix}"),
        );
        FreshDispatchInputFixture {
            database,
            ledger,
            launch,
            session,
            running,
            intent,
            proposal,
        }
    }

    fn prepare_fresh_command_dispatch_input(suffix: &str) -> FreshDispatchInputFixture {
        let mut fixture = prepare_fresh_dispatch_input(suffix);
        fixture.intent.kind = EffectKind::RunCommand;
        fixture.proposal = effect_proposal_event(
            &fixture.intent,
            fixture.proposal.sequence,
            &fixture.proposal.event_id,
        );
        fixture
    }

    fn v27_prepare_stale_capture_permit(
        label: &str,
    ) -> (
        FreshDispatchInputFixture,
        CommandOutputCaptureIntentV1,
        FreshRunnerEffectDispatchPermit,
        CommandOutputCaptureAcquiredV1,
    ) {
        let mut fixture = prepare_fresh_command_dispatch_input(label);
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
            .expect("admit stale-capture fixture")
        {
            CommandOutputCaptureIntentAdmission::Fresh { permit, .. } => permit,
            other => panic!("fresh stale-capture admission returned {other:?}"),
        };
        let acquired = v27_test_capture_acquired(
            &capture,
            permit
                .expected_output_capture_dispatch_claim_id()
                .expect("stale-capture dispatch identity"),
            label,
            1_250,
        );
        (fixture, capture, permit, acquired)
    }

    pub(crate) fn seeded_v27_and_v36_capture_counts_for_test(label: &str) -> (i64, i64) {
        let (mut fixture, _capture, permit, acquired) = v27_prepare_stale_capture_permit(label);
        let (_effect, transport_permit) = fixture
            .ledger
            .claim_command_output_capture_dispatch(
                permit,
                acquired,
                OPAQUE_RUNNER_TRANSPORT_REQUEST_BYTES,
            )
            .expect("seed one exact legacy v27 capture acquisition");
        // The proof concerns durable v27 acquisition identity only; deliberately
        // surrender the unrelated transport capability without executing it.
        drop(transport_permit);
        fixture
            .ledger
            .connection
            .query_row(
                "SELECT
                    (SELECT COUNT(*) FROM command_output_capture_acquisitions),
                    (SELECT COUNT(*) FROM current_final_verification_capture_acquisitions_v36)",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .expect("count seeded v27 and unpromoted v36 acquisitions")
    }

    #[test]
    #[allow(clippy::too_many_lines)] // Exact historical coverage and the fresh-current counterexample form one migration cut.
    fn v27_migration_exactly_exempts_every_historical_command_but_never_a_fresh_command() {
        let database = TestDatabase::new();
        let historical = {
            let mut v26 = open_v26_test_ledger(&database);
            let (_policy, launch, _session) = prepare_command_domain_session(&mut v26);
            let (succeeded, succeeded_proposal, succeeded_permit) =
                persist_command_domain_intent(&mut v26, &launch, "v27-exempt-succeeded", 1_200);
            persist_command_domain_observation(
                &mut v26,
                &succeeded,
                &succeeded_proposal,
                succeeded_permit,
                EffectOutcome::Succeeded {
                    evidence_digest: effect_evidence_digest(),
                },
                1_250,
            );
            let (unfinished, _, _) =
                persist_command_domain_intent(&mut v26, &launch, "v27-exempt-unfinished", 1_300);
            let (unknown, unknown_proposal, unknown_permit) =
                persist_command_domain_intent(&mut v26, &launch, "v27-exempt-unknown", 1_400);
            persist_command_domain_observation(
                &mut v26,
                &unknown,
                &unknown_proposal,
                unknown_permit,
                EffectOutcome::Unknown {
                    evidence_digest: effect_evidence_digest(),
                },
                1_450,
            );
            [succeeded, unfinished, unknown]
        };

        let migrated = EventLedger::open(&database.path).expect("migrate v26 commands to v27");
        assert_eq!(
            row_count(&migrated, "pre_v27_command_output_capture_exemptions"),
            i64::try_from(historical.len()).expect("historical exemption count fits SQLite")
        );
        for intent in &historical {
            let stored: (String, String, i64, i64, String) = migrated
                .connection
                .query_row(
                    "SELECT sprint_id, request_digest, created_at_unix_ms,
                            contract_version, intent_digest
                     FROM pre_v27_command_output_capture_exemptions
                     WHERE effect_id = ?1",
                    [&intent.effect_id],
                    |row| {
                        Ok((
                            row.get(0)?,
                            row.get(1)?,
                            row.get(2)?,
                            row.get(3)?,
                            row.get(4)?,
                        ))
                    },
                )
                .expect("load exact migrated command exemption");
            assert_eq!(stored.0, intent.sprint_id);
            assert_eq!(stored.1, intent.request_digest.as_str());
            assert_eq!(
                stored.2,
                i64::try_from(intent.created_at_unix_ms)
                    .expect("historical command timestamp fits SQLite")
            );
            assert_eq!(stored.3, i64::from(intent.contract_version));
            assert_eq!(
                stored.4,
                Digest::sha256(
                    &encode("historical command intent", intent)
                        .expect("encode historical command intent")
                )
                .as_str()
            );
            assert!(
                command_output_capture_authority::finish_is_proven_for_effect(
                    &migrated.connection,
                    &intent.effect_id,
                )
                .expect("validate exact historical capture exemption")
            );
        }

        let mut fresh = prepare_fresh_command_dispatch_input("v27-never-exempt");
        let capture = v27_test_capture_intent(
            &fresh.intent,
            &fresh.launch,
            &fresh.session,
            "v27-never-exempt",
        );
        let admission = fresh
            .ledger
            .admit_runner_command_output_capture_intent_for_dispatch(
                &fresh.intent,
                EFFECT_REQUEST_BYTES,
                &fresh.proposal,
                &fresh.session.session_id,
                &capture,
            )
            .expect("admit fresh v27 command capture");
        assert!(matches!(
            admission,
            CommandOutputCaptureIntentAdmission::Fresh { .. }
        ));
        assert_eq!(
            fresh
                .ledger
                .connection
                .query_row(
                    "SELECT COUNT(*) FROM pre_v27_command_output_capture_exemptions
                     WHERE effect_id = ?1",
                    [&fresh.intent.effect_id],
                    |row| row.get::<_, i64>(0),
                )
                .expect("count fresh-command exemptions"),
            0
        );
        assert!(
            !command_output_capture_authority::finish_is_proven_for_effect(
                &fresh.ledger.connection,
                &fresh.intent.effect_id,
            )
            .expect("fresh incomplete capture is not terminal")
        );
    }

    #[test]
    #[allow(clippy::too_many_lines)] // Immutability and injected corruption exercise one migration-only authority.
    fn v27_historical_command_exemptions_reject_mutation_crossing_and_capture_coexistence() {
        let database = TestDatabase::new();
        let historical = {
            let mut v26 = open_v26_test_ledger(&database);
            let (_policy, launch, _session) = prepare_command_domain_session(&mut v26);
            persist_command_domain_intent(&mut v26, &launch, "v27-exemption-corruption", 1_200).0
        };
        let migrated = EventLedger::open(&database.path).expect("migrate exemption fixture");

        let insert_error = migrated
            .connection
            .execute(
                "INSERT INTO pre_v27_command_output_capture_exemptions (
                    effect_id, sprint_id, request_digest, created_at_unix_ms,
                    contract_version, intent_digest
                 ) VALUES ('forged-effect', 'sprint-1', ?1, 1, 1, ?2)",
                params![digest('a').as_str(), digest('b').as_str()],
            )
            .expect_err("post-migration exemption insertion must fail");
        assert!(insert_error.to_string().contains("migration-only"));
        let update_error = migrated
            .connection
            .execute(
                "UPDATE pre_v27_command_output_capture_exemptions
                 SET sprint_id = sprint_id WHERE effect_id = ?1",
                [&historical.effect_id],
            )
            .expect_err("historical exemption update must fail");
        assert!(update_error.to_string().contains("immutable"));
        let delete_error = migrated
            .connection
            .execute(
                "DELETE FROM pre_v27_command_output_capture_exemptions WHERE effect_id = ?1",
                [&historical.effect_id],
            )
            .expect_err("historical exemption deletion must fail");
        assert!(delete_error.to_string().contains("immutable"));

        migrated
            .connection
            .execute_batch("DROP TRIGGER pre_v27_command_output_capture_exemptions_no_update;")
            .expect("open adversarial exemption-update bypass");
        migrated
            .connection
            .execute(
                "UPDATE pre_v27_command_output_capture_exemptions
                 SET sprint_id = 'crossed-sprint' WHERE effect_id = ?1",
                [&historical.effect_id],
            )
            .expect("cross exemption redundancy");
        assert!(matches!(
            command_output_capture_authority::finish_is_proven_for_effect(
                &migrated.connection,
                &historical.effect_id,
            ),
            Err(LedgerError::Corrupt {
                entity: "pre-v27 command output capture exemption",
                ..
            })
        ));
        migrated
            .connection
            .execute(
                "UPDATE pre_v27_command_output_capture_exemptions
                 SET sprint_id = ?1, intent_digest = ?2 WHERE effect_id = ?3",
                params![
                    historical.sprint_id,
                    digest('f').as_str(),
                    historical.effect_id
                ],
            )
            .expect("inject crossed exemption digest");
        assert!(matches!(
            command_output_capture_authority::finish_is_proven_for_effect(
                &migrated.connection,
                &historical.effect_id,
            ),
            Err(LedgerError::Corrupt {
                entity: "pre-v27 command output capture exemption",
                ..
            })
        ));

        let mut fresh = prepare_fresh_command_dispatch_input("v27-coexisting-exemption");
        let capture = v27_test_capture_intent(
            &fresh.intent,
            &fresh.launch,
            &fresh.session,
            "v27-coexisting-exemption",
        );
        let admission = fresh
            .ledger
            .admit_runner_command_output_capture_intent_for_dispatch(
                &fresh.intent,
                EFFECT_REQUEST_BYTES,
                &fresh.proposal,
                &fresh.session.session_id,
                &capture,
            )
            .expect("admit coexisting-authority fixture");
        assert!(matches!(
            admission,
            CommandOutputCaptureIntentAdmission::Fresh { .. }
        ));
        fresh
            .ledger
            .connection
            .execute_batch("DROP TRIGGER pre_v27_command_output_capture_exemptions_no_insert;")
            .expect("open adversarial exemption-insert bypass");
        fresh
            .ledger
            .connection
            .execute(
                "INSERT INTO pre_v27_command_output_capture_exemptions (
                    effect_id, sprint_id, request_digest, created_at_unix_ms,
                    contract_version, intent_digest
                 )
                 SELECT effect_id, sprint_id, request_digest, created_at_unix_ms,
                        contract_version, grok_sha256(intent_json)
                 FROM effect_intents WHERE effect_id = ?1",
                [&fresh.intent.effect_id],
            )
            .expect("inject capture/exemption coexistence");
        assert!(matches!(
            fresh
                .ledger
                .load_command_output_capture_for_effect(&fresh.intent.effect_id),
            Err(LedgerError::Corrupt {
                entity: "command output capture authority",
                ..
            })
        ));
    }

    #[test]
    fn v27_historical_exemption_does_not_finish_unobserved_or_unknown_commands() {
        let database = TestDatabase::new();
        let (unfinished, unknown) = {
            let mut v26 = open_v26_test_ledger(&database);
            let (_policy, launch, _session) = prepare_command_domain_session(&mut v26);
            let unfinished = persist_command_domain_intent(
                &mut v26,
                &launch,
                "v27-exempt-but-unfinished",
                1_200,
            )
            .0;
            let (unknown, unknown_proposal, unknown_permit) =
                persist_command_domain_intent(&mut v26, &launch, "v27-exempt-but-unknown", 1_300);
            persist_command_domain_observation(
                &mut v26,
                &unknown,
                &unknown_proposal,
                unknown_permit,
                EffectOutcome::Unknown {
                    evidence_digest: effect_evidence_digest(),
                },
                1_350,
            );
            (unfinished, unknown)
        };
        let migrated = EventLedger::open(&database.path).expect("migrate unfinished commands");

        for intent in [&unfinished, &unknown] {
            assert!(
                command_output_capture_authority::finish_is_proven_for_effect(
                    &migrated.connection,
                    &intent.effect_id,
                )
                .expect("historical exemption closes only capture applicability")
            );
        }
        assert!(matches!(
            ensure_no_unresolved_effects(&migrated.connection, "sprint-1"),
            Err(LedgerError::ReferenceMismatch { .. })
        ));
        let assessment = migrated
            .assess_task_done("sprint-1", "task-1")
            .expect("assess migrated unresolved task");
        assert!(
            assessment
                .unmet_requirements
                .contains(&TaskDoneRequirement::EveryTaskEffectTerminalNonUnknown)
        );
        assert!(
            !assessment
                .unmet_requirements
                .contains(&TaskDoneRequirement::CommandOutputCaptureTerminalExact),
            "the narrow migration exemption must close capture applicability without closing the effect"
        );
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn v27_reconciliation_history_permanently_fences_stale_acquisition_in_every_claim_state() {
        let (mut active, active_capture, active_dispatch, active_acquired) =
            v27_prepare_stale_capture_permit("v27-fence-active");
        let active_reconciliation = match active
            .ledger
            .claim_command_output_capture_reconciliation(
                &active_capture.capture_id,
                Digest::sha256(b"v27-fence-active-claim").as_str(),
                "desktop-owner",
                1_300,
                1_600,
            )
            .expect("create active reconciliation history")
        {
            CommandOutputCaptureReconciliationAdmission::Fresh { permit, .. } => permit,
            other => panic!("active reconciliation returned {other:?}"),
        };
        drop(active_reconciliation);
        assert!(matches!(
            active.ledger.claim_command_output_capture_dispatch(
                active_dispatch,
                active_acquired,
                OPAQUE_RUNNER_TRANSPORT_REQUEST_BYTES,
            ),
            Err(LedgerError::ReferenceMismatch { .. })
        ));

        let (mut released, released_capture, released_dispatch, released_acquired) =
            v27_prepare_stale_capture_permit("v27-fence-released");
        let released_reconciliation = match released
            .ledger
            .claim_command_output_capture_reconciliation(
                &released_capture.capture_id,
                Digest::sha256(b"v27-fence-released-claim").as_str(),
                "desktop-owner",
                1_300,
                1_600,
            )
            .expect("create released reconciliation history")
        {
            CommandOutputCaptureReconciliationAdmission::Fresh { permit, .. } => permit,
            other => panic!("released reconciliation returned {other:?}"),
        };
        let released_claim = released
            .ledger
            .release_command_output_capture_reconciliation(released_reconciliation, 1_310)
            .expect("release exact reconciliation claim");
        assert!(matches!(
            released.ledger.claim_command_output_capture_dispatch(
                released_dispatch,
                released_acquired,
                OPAQUE_RUNNER_TRANSPORT_REQUEST_BYTES,
            ),
            Err(LedgerError::ReferenceMismatch { .. })
        ));
        assert_eq!(
            released
                .ledger
                .connection
                .query_row(
                    "SELECT release_kind
                     FROM command_output_capture_reconciliation_claim_releases
                     WHERE claim_id = ?1",
                    [&released_claim.claim_id],
                    |row| row.get::<_, String>(0),
                )
                .expect("read released claim state"),
            "Released"
        );

        let (mut expired, expired_capture, expired_dispatch, expired_acquired) =
            v27_prepare_stale_capture_permit("v27-fence-expired");
        let expired_claim = match expired
            .ledger
            .claim_command_output_capture_reconciliation(
                &expired_capture.capture_id,
                Digest::sha256(b"v27-fence-expired-claim-one").as_str(),
                "desktop-owner",
                1_300,
                1_310,
            )
            .expect("create expiring reconciliation history")
        {
            CommandOutputCaptureReconciliationAdmission::Fresh { claim, permit } => {
                drop(permit);
                claim
            }
            other => panic!("expiring reconciliation returned {other:?}"),
        };
        let replacement = match expired
            .ledger
            .claim_command_output_capture_reconciliation(
                &expired_capture.capture_id,
                Digest::sha256(b"v27-fence-expired-claim-two").as_str(),
                "desktop-owner",
                1_320,
                1_600,
            )
            .expect("expire and replace exact reconciliation claim")
        {
            CommandOutputCaptureReconciliationAdmission::Fresh { permit, .. } => permit,
            other => panic!("replacement reconciliation returned {other:?}"),
        };
        expired
            .ledger
            .release_command_output_capture_reconciliation(replacement, 1_330)
            .expect("release replacement reconciliation claim");
        assert!(matches!(
            expired.ledger.claim_command_output_capture_dispatch(
                expired_dispatch,
                expired_acquired,
                OPAQUE_RUNNER_TRANSPORT_REQUEST_BYTES,
            ),
            Err(LedgerError::ReferenceMismatch { .. })
        ));
        assert_eq!(
            expired
                .ledger
                .connection
                .query_row(
                    "SELECT release_kind
                     FROM command_output_capture_reconciliation_claim_releases
                     WHERE claim_id = ?1",
                    [&expired_claim.claim_id],
                    |row| row.get::<_, String>(0),
                )
                .expect("read expired claim state"),
            "Expired"
        );

        let (mut superseded, superseded_capture, superseded_dispatch, superseded_acquired) =
            v27_prepare_stale_capture_permit("v27-fence-superseded");
        let (superseded_claim_id, superseded_reconciliation) = match superseded
            .ledger
            .claim_command_output_capture_reconciliation(
                &superseded_capture.capture_id,
                Digest::sha256(b"v27-fence-superseded-claim-one").as_str(),
                "desktop-owner",
                1_300,
                1_600,
            )
            .expect("create superseded reconciliation history")
        {
            CommandOutputCaptureReconciliationAdmission::Fresh { claim, permit } => {
                (claim.claim_id, permit)
            }
            other => panic!("superseded reconciliation returned {other:?}"),
        };
        let renewed = superseded
            .ledger
            .renew_command_output_capture_reconciliation(
                superseded_reconciliation,
                Digest::sha256(b"v27-fence-superseded-claim-two").as_str(),
                1_310,
                1_700,
            )
            .expect("supersede exact reconciliation claim");
        superseded
            .ledger
            .release_command_output_capture_reconciliation(renewed, 1_320)
            .expect("release renewed reconciliation claim");
        assert!(matches!(
            superseded.ledger.claim_command_output_capture_dispatch(
                superseded_dispatch,
                superseded_acquired,
                OPAQUE_RUNNER_TRANSPORT_REQUEST_BYTES,
            ),
            Err(LedgerError::ReferenceMismatch { .. })
        ));
        assert_eq!(
            superseded
                .ledger
                .connection
                .query_row(
                    "SELECT release_kind
                     FROM command_output_capture_reconciliation_claim_releases
                     WHERE claim_id = ?1",
                    [&superseded_claim_id],
                    |row| row.get::<_, String>(0),
                )
                .expect("read superseded claim state"),
            "Superseded"
        );

        for ledger in [
            &active.ledger,
            &released.ledger,
            &expired.ledger,
            &superseded.ledger,
        ] {
            assert_eq!(row_count(ledger, "runner_effect_dispatch_claims"), 0);
            assert_eq!(row_count(ledger, "command_output_capture_acquisitions"), 0);
        }
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn v27_sql_claim_release_custody_rejects_early_expiry_and_raw_renewal_theft() {
        let (mut fixture, capture, _dispatch_permit, _acquired) =
            v27_prepare_stale_capture_permit("v27-raw-claim-custody");
        let (old_claim, old_permit) = match fixture
            .ledger
            .claim_command_output_capture_reconciliation(
                &capture.capture_id,
                Digest::sha256(b"v27-raw-claim-custody-old").as_str(),
                "desktop-owner",
                1_300,
                1_600,
            )
            .expect("claim raw-custody fixture")
        {
            CommandOutputCaptureReconciliationAdmission::Fresh { claim, permit } => (claim, permit),
            other => panic!("fresh raw-custody claim returned {other:?}"),
        };

        let early_expiry = v27_insert_raw_reconciliation_release(
            &fixture.ledger.connection,
            &old_claim,
            "Expired",
            1_400,
            None,
        )
        .expect_err("raw SQL cannot expire a live claim");
        assert!(
            early_expiry
                .to_string()
                .contains("must consume one exact fencing token")
        );

        let exact_successor = command_output_capture_authority::reconciliation_claim_for_test(
            Digest::sha256(b"v27-raw-claim-custody-exact-successor").as_str(),
            &capture.capture_id,
            &old_claim.owner_id,
            2,
            Some(old_claim.claim_id.clone()),
            1_410,
            1_700,
        )
        .expect("construct exact raw successor");
        let orphan_transaction = fixture
            .ledger
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .expect("start orphan supersession transaction");
        v27_insert_raw_reconciliation_release(
            &orphan_transaction,
            &old_claim,
            "Superseded",
            1_410,
            Some(&exact_successor),
        )
        .expect("stage supersession bound to a future exact successor");
        assert!(
            orphan_transaction.commit().is_err(),
            "deferred successor custody must reject an orphan Superseded release"
        );

        let stolen_successor = command_output_capture_authority::reconciliation_claim_for_test(
            Digest::sha256(b"v27-raw-claim-custody-stolen-successor").as_str(),
            &capture.capture_id,
            "attacker-owner",
            2,
            Some(old_claim.claim_id.clone()),
            1_420,
            1_700,
        )
        .expect("construct canonical changed-owner successor");
        let stolen_transaction = fixture
            .ledger
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .expect("start changed-owner supersession transaction");
        v27_insert_raw_reconciliation_release(
            &stolen_transaction,
            &old_claim,
            "Superseded",
            1_420,
            Some(&stolen_successor),
        )
        .expect("stage raw changed-owner supersession marker");
        let stolen_error =
            v27_insert_raw_reconciliation_claim(&stolen_transaction, &stolen_successor)
                .expect_err("raw next epoch cannot change the renewal owner");
        assert!(
            stolen_error
                .to_string()
                .contains("must CAS the closed prior epoch")
        );
        drop(stolen_transaction);

        let wrong_time_successor = command_output_capture_authority::reconciliation_claim_for_test(
            Digest::sha256(b"v27-raw-claim-custody-wrong-time").as_str(),
            &capture.capture_id,
            &old_claim.owner_id,
            2,
            Some(old_claim.claim_id.clone()),
            1_431,
            1_700,
        )
        .expect("construct canonical mismatched-time successor");
        let wrong_time_transaction = fixture
            .ledger
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .expect("start mismatched-time supersession transaction");
        v27_insert_raw_reconciliation_release(
            &wrong_time_transaction,
            &old_claim,
            "Superseded",
            1_430,
            Some(&wrong_time_successor),
        )
        .expect("stage raw mismatched-time supersession marker");
        assert!(
            v27_insert_raw_reconciliation_claim(&wrong_time_transaction, &wrong_time_successor,)
                .is_err(),
            "renewal acquisition must exactly equal the Superseded release time"
        );
        drop(wrong_time_transaction);

        let renewed = fixture
            .ledger
            .renew_command_output_capture_reconciliation(
                old_permit,
                Digest::sha256(b"v27-raw-claim-custody-valid-renewal").as_str(),
                1_440,
                1_700,
            )
            .expect("typed exact same-owner renewal remains admitted");
        assert_eq!(renewed.claim().owner_id, old_claim.owner_id);
        assert_eq!(renewed.claim().claim_epoch, 2);
        fixture
            .ledger
            .release_command_output_capture_reconciliation(renewed, 1_450)
            .expect("release exact renewed claim");
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn v27_restart_closes_core_unacquired_physical_acquired_orphan_and_permanently_fences_dispatch()
    {
        let mut fixture = prepare_fresh_command_dispatch_input("v27-restart-orphan-acquired");
        let capture_intent = v27_test_capture_intent(
            &fixture.intent,
            &fixture.launch,
            &fixture.session,
            "v27-restart-orphan-acquired",
        );
        let stale_dispatch_permit = match fixture
            .ledger
            .admit_runner_command_output_capture_intent_for_dispatch(
                &fixture.intent,
                EFFECT_REQUEST_BYTES,
                &fixture.proposal,
                &fixture.session.session_id,
                &capture_intent,
            )
            .expect("admit orphan-acquired capture intent")
        {
            CommandOutputCaptureIntentAdmission::Fresh { permit, .. } => permit,
            other => panic!("fresh orphan-acquired admission returned {other:?}"),
        };
        let physical_acquired = v27_test_capture_acquired_at_generation(
            &capture_intent,
            stale_dispatch_permit
                .expected_output_capture_dispatch_claim_id()
                .expect("deterministic stale dispatch identity"),
            "v27-restart-orphan-acquired",
            2,
            1_250,
        );
        let (reconciliation_permit, reconciliation_claim) = match fixture
            .ledger
            .claim_command_output_capture_reconciliation(
                &capture_intent.capture_id,
                Digest::sha256(b"v27-restart-orphan-acquired-claim").as_str(),
                "desktop-restart-owner",
                1_300,
                1_600,
            )
            .expect("claim core-unacquired orphan")
        {
            CommandOutputCaptureReconciliationAdmission::Fresh { claim, permit } => (permit, claim),
            other => panic!("fresh orphan reconciliation returned {other:?}"),
        };

        let raw = fixture
            .ledger
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .expect("start adversarial raw acquisition");
        let raw_error = command_output_capture_authority::insert_acquired_without_rust_reconciliation_fence_for_test(
            &raw,
            &physical_acquired,
        )
        .expect_err("SQL trigger must independently reject acquisition after claim history");
        assert!(
            raw_error
                .to_string()
                .contains("permanently fenced by reconciliation history")
        );
        drop(raw);

        let states = [
            CommandOutputCaptureRestartStateV1::Intent,
            CommandOutputCaptureRestartStateV1::Acquired,
            CommandOutputCaptureRestartStateV1::CleanupIntended,
            CommandOutputCaptureRestartStateV1::Cleaned,
        ];
        let original_physical_cleanup = v27_test_physical_reconciliation(
            &capture_intent,
            &reconciliation_claim,
            "v27-restart-orphan-acquired",
            &states,
            None,
            Some(CommandOutputCaptureRestartStateV1::Acquired),
            CommandOutputCapturePendingResolutionV1::None,
            CommandOutputCapturePhysicalResolutionActionV1::WorkingSetCleaned,
            Some(physical_acquired.clone()),
            CommandOutputCaptureLaunchHistoryV1::NoneBeforeLaunch,
            None,
            None,
            1_400,
        )
        .expect("construct orphan-acquired physical reconciliation");
        assert_eq!(
            original_physical_cleanup.resolution_action,
            CommandOutputCapturePhysicalResolutionActionV1::WorkingSetCleaned
        );

        let crossed_capture_intent = CommandOutputCaptureIntentV1::try_new(
            Digest::sha256(b"v27-crossed-orphan-physical-capture").as_str(),
            capture_intent.source.clone(),
            capture_intent.private_state_digest.clone(),
            capture_intent.max_aggregate_output_bytes,
            capture_intent.created_at_unix_ms,
        )
        .expect("construct distinct self-canonical orphan capture intent");
        let crossed_physical_acquired = CommandOutputCaptureAcquiredV1::try_new(
            &crossed_capture_intent,
            physical_acquired.dispatch_claim_id.clone(),
            physical_acquired.store_head.clone(),
            physical_acquired.working_directory.clone(),
            physical_acquired.stdout.clone(),
            physical_acquired.stderr.clone(),
            physical_acquired.acquired_at_unix_ms,
        )
        .expect("construct distinct self-canonical orphan acquisition");
        let crossed_physical_cleanup = command_output_capture_authority::physical_reconciliation_with_physical_acquired_for_test(
            &original_physical_cleanup,
            crossed_physical_acquired,
        )
        .expect("construct self-canonical receipt with crossed physical acquisition");
        assert!(
            crossed_physical_cleanup
                .validate_against(&capture_intent, &reconciliation_claim, None)
                .is_err(),
            "typed authority must reject a physical acquisition from another capture"
        );
        let crossed_physical_transaction = fixture
            .ledger
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .expect("start crossed orphan physical-acquisition transaction");
        v27_insert_raw_restart_receipt(
            &crossed_physical_transaction,
            &crossed_physical_cleanup,
            None,
        )
        .expect("raw receipt remains self-canonical before external source readback");
        assert!(
            !crossed_physical_transaction
                .query_row(
                    "SELECT EXISTS (
                         SELECT 1
                         FROM command_output_capture_exact_restart_recovery_receipts_v27
                         WHERE receipt_digest = ?1
                     )",
                    [crossed_physical_cleanup.reconciliation_digest.as_str()],
                    |row| row.get::<_, bool>(0),
                )
                .expect("query exact crossed orphan recovery authority"),
            "exact restart authority must reject a nested acquisition from another capture"
        );
        drop(crossed_physical_transaction);

        fixture
            .ledger
            .release_command_output_capture_reconciliation(reconciliation_permit, 1_401)
            .expect("model precommit loss after physical orphan cleanup");
        assert_eq!(
            row_count(
                &fixture.ledger,
                "command_output_capture_restart_recovery_receipts"
            ),
            0
        );
        let (replay_permit, replay_claim) = match fixture
            .ledger
            .claim_command_output_capture_reconciliation(
                &capture_intent.capture_id,
                Digest::sha256(b"v27-restart-orphan-acquired-replay-claim").as_str(),
                "desktop-restart-owner",
                1_410,
                1_700,
            )
            .expect("reclaim physically cleaned orphan")
        {
            CommandOutputCaptureReconciliationAdmission::Fresh { claim, permit } => (permit, claim),
            other => panic!("fresh cleaned-orphan replay claim returned {other:?}"),
        };
        let physical = v27_test_physical_reconciliation(
            &capture_intent,
            &replay_claim,
            "v27-restart-orphan-acquired-cleaned-readback",
            &states,
            None,
            Some(CommandOutputCaptureRestartStateV1::Cleaned),
            CommandOutputCapturePendingResolutionV1::None,
            CommandOutputCapturePhysicalResolutionActionV1::TerminalReadback,
            Some(physical_acquired.clone()),
            CommandOutputCaptureLaunchHistoryV1::NoneBeforeLaunch,
            None,
            None,
            1_500,
        )
        .expect("construct exact higher-claim Cleaned orphan readback");
        let mut crossed = physical.clone();
        crossed.reconciliation_claim = reconciliation_claim;
        assert!(crossed.validate().is_err());
        let observation = effect_observation(
            &fixture.intent,
            "v27-restart-orphan-acquired-observation",
            EffectOutcome::FailedBeforeEffect {
                evidence_digest: physical
                    .effect_evidence_digest()
                    .expect("physical evidence digest"),
            },
            1_480,
        );
        let event = effect_terminal_event(
            &fixture.intent,
            &fixture.proposal.event_id,
            &observation,
            fixture
                .ledger
                .next_sequence(&fixture.intent.sprint_id)
                .expect("orphan-acquired terminal sequence"),
            "v27-restart-orphan-acquired-event",
        );
        let mut cleanup = v27_test_command_cleanup(
            &fixture.intent,
            &observation,
            &fixture.launch,
            &fixture.session,
            "v27-restart-orphan-acquired",
            1_490,
        );
        cleanup.disposition = CommandDomainCleanupDisposition::NoDomainCreatedBeforeEffect;
        let persisted = fixture
            .ledger
            .reconcile_unacquired_command_output_capture_before_dispatch(
                replay_permit,
                &observation,
                &event,
                &cleanup,
                &physical,
            )
            .expect("atomically abandon core-unacquired physical orphan");
        assert_eq!(persisted.observation.as_ref(), Some(&observation));
        let capture = fixture
            .ledger
            .load_command_output_capture(&capture_intent.capture_id)
            .expect("load terminal orphan capture");
        assert!(capture.acquired.is_none());
        let terminal = capture.terminal.as_ref().expect("orphan terminal");
        assert_eq!(
            terminal.disposition,
            CommandOutputCaptureTerminalDispositionV1::Abandoned
        );
        assert_eq!(
            capture.reconciliation_obligation_closure.as_ref(),
            Some(&terminal.terminal_anchor_digest)
        );
        assert_eq!(
            row_count(&fixture.ledger, "runner_effect_dispatch_claims"),
            0
        );
        assert_eq!(
            row_count(&fixture.ledger, "command_output_capture_acquisitions"),
            0
        );
        assert_eq!(
            row_count(&fixture.ledger, "command_domain_cleanup_proofs"),
            1
        );
        assert_v27_capture_loader_rejects_transactional_corruption(
            &mut fixture.ledger,
            &capture_intent.capture_id,
            "DROP TRIGGER effect_evidence_payloads_no_update;",
            |transaction| {
                transaction
                    .execute(
                        "UPDATE effect_evidence_payloads
                         SET evidence_bytes = ?1 WHERE effect_id = ?2",
                        params![
                            b"crossed-unacquired-restart-evidence".as_slice(),
                            fixture.intent.effect_id,
                        ],
                    )
                    .expect("cross unacquired restart physical evidence bytes");
            },
        );

        assert!(matches!(
            fixture.ledger.claim_command_output_capture_dispatch(
                stale_dispatch_permit,
                physical_acquired,
                OPAQUE_RUNNER_TRANSPORT_REQUEST_BYTES,
            ),
            Err(LedgerError::ReferenceMismatch { .. })
        ));
        assert_eq!(
            row_count(&fixture.ledger, "runner_effect_dispatch_claims"),
            0
        );
        assert!(matches!(
            fixture
                .ledger
                .claim_command_output_capture_reconciliation(
                    &capture_intent.capture_id,
                    Digest::sha256(b"v27-restart-orphan-replay").as_str(),
                    "desktop-replay-owner",
                    1_510,
                    1_600,
                )
                .expect("classify terminal replay"),
            CommandOutputCaptureReconciliationAdmission::Terminal(replay)
                if replay == capture
        ));
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn v27_restart_claimed_prelaunch_abandonment_is_atomic_and_rejects_action_substitution() {
        let mut fixture = prepare_fresh_command_dispatch_input("v27-restart-claimed-prelaunch");
        let capture_intent = v27_test_capture_intent(
            &fixture.intent,
            &fixture.launch,
            &fixture.session,
            "v27-restart-claimed-prelaunch",
        );
        let dispatch_permit = match fixture
            .ledger
            .admit_runner_command_output_capture_intent_for_dispatch(
                &fixture.intent,
                EFFECT_REQUEST_BYTES,
                &fixture.proposal,
                &fixture.session.session_id,
                &capture_intent,
            )
            .expect("admit claimed-prelaunch capture")
        {
            CommandOutputCaptureIntentAdmission::Fresh { permit, .. } => permit,
            other => panic!("fresh claimed-prelaunch admission returned {other:?}"),
        };
        let acquired = v27_test_capture_acquired_at_generation(
            &capture_intent,
            dispatch_permit
                .expected_output_capture_dispatch_claim_id()
                .expect("claimed-prelaunch dispatch identity"),
            "v27-restart-claimed-prelaunch",
            2,
            1_240,
        );
        let (_, transport) = fixture
            .ledger
            .claim_command_output_capture_dispatch(
                dispatch_permit,
                acquired.clone(),
                OPAQUE_RUNNER_TRANSPORT_REQUEST_BYTES,
            )
            .expect("commit claimed-prelaunch acquisition and dispatch");
        drop(transport);
        let (reconciliation_permit, reconciliation_claim) = match fixture
            .ledger
            .claim_command_output_capture_reconciliation(
                &capture_intent.capture_id,
                Digest::sha256(b"v27-restart-claimed-prelaunch-claim").as_str(),
                "desktop-restart-owner",
                1_300,
                1_600,
            )
            .expect("claim claimed-prelaunch capture")
        {
            CommandOutputCaptureReconciliationAdmission::Fresh { claim, permit } => (permit, claim),
            other => panic!("fresh claimed-prelaunch reconciliation returned {other:?}"),
        };
        let states = [
            CommandOutputCaptureRestartStateV1::Intent,
            CommandOutputCaptureRestartStateV1::Acquired,
            CommandOutputCaptureRestartStateV1::WriterAttached,
            CommandOutputCaptureRestartStateV1::CleanupIntended,
            CommandOutputCaptureRestartStateV1::Cleaned,
        ];
        let original_physical_cleanup = v27_test_physical_reconciliation(
            &capture_intent,
            &reconciliation_claim,
            "v27-restart-claimed-prelaunch",
            &states,
            Some(acquired.store_head.clone()),
            Some(CommandOutputCaptureRestartStateV1::WriterAttached),
            CommandOutputCapturePendingResolutionV1::None,
            CommandOutputCapturePhysicalResolutionActionV1::WorkingSetCleaned,
            Some(acquired.clone()),
            CommandOutputCaptureLaunchHistoryV1::NoneBeforeLaunch,
            None,
            None,
            1_400,
        )
        .expect("construct claimed-prelaunch physical reconciliation");
        assert_eq!(
            original_physical_cleanup.resolution_action,
            CommandOutputCapturePhysicalResolutionActionV1::WorkingSetCleaned
        );
        fixture
            .ledger
            .release_command_output_capture_reconciliation(reconciliation_permit, 1_401)
            .expect("model precommit loss after claimed prelaunch cleanup");
        let (replay_permit, replay_claim) = match fixture
            .ledger
            .claim_command_output_capture_reconciliation(
                &capture_intent.capture_id,
                Digest::sha256(b"v27-restart-claimed-prelaunch-replay-claim").as_str(),
                "desktop-restart-owner",
                1_410,
                1_700,
            )
            .expect("reclaim physically cleaned claimed-prelaunch capture")
        {
            CommandOutputCaptureReconciliationAdmission::Fresh { claim, permit } => (permit, claim),
            other => panic!("fresh claimed-prelaunch replay claim returned {other:?}"),
        };
        let physical = v27_test_physical_reconciliation(
            &capture_intent,
            &replay_claim,
            "v27-restart-claimed-prelaunch-cleaned-readback",
            &states,
            Some(acquired.store_head.clone()),
            Some(CommandOutputCaptureRestartStateV1::Cleaned),
            CommandOutputCapturePendingResolutionV1::None,
            CommandOutputCapturePhysicalResolutionActionV1::TerminalReadback,
            Some(acquired.clone()),
            CommandOutputCaptureLaunchHistoryV1::NoneBeforeLaunch,
            None,
            None,
            1_500,
        )
        .expect("construct exact higher-claim claimed-prelaunch Cleaned readback");
        let mut substituted = physical.clone();
        substituted.resolution_action =
            CommandOutputCapturePhysicalResolutionActionV1::PreAcquisitionCleaned;
        assert!(substituted.validate().is_err());
        let mut crossed = physical.clone();
        crossed.reconciliation_claim = reconciliation_claim;
        assert!(crossed.validate().is_err());

        let observation = effect_observation(
            &fixture.intent,
            "v27-restart-claimed-prelaunch-observation",
            EffectOutcome::FailedBeforeEffect {
                evidence_digest: physical
                    .effect_evidence_digest()
                    .expect("claimed-prelaunch evidence digest"),
            },
            1_480,
        );
        let event = effect_terminal_event(
            &fixture.intent,
            &fixture.proposal.event_id,
            &observation,
            fixture
                .ledger
                .next_sequence(&fixture.intent.sprint_id)
                .expect("claimed-prelaunch terminal sequence"),
            "v27-restart-claimed-prelaunch-event",
        );
        let mut cleanup = v27_test_command_cleanup(
            &fixture.intent,
            &observation,
            &fixture.launch,
            &fixture.session,
            "v27-restart-claimed-prelaunch",
            1_490,
        );
        cleanup.disposition = CommandDomainCleanupDisposition::NoDomainCreatedBeforeEffect;
        fixture
            .ledger
            .reconcile_claimed_prelaunch_command_output_capture_before_effect(
                replay_permit,
                &observation,
                &event,
                &cleanup,
                &physical,
            )
            .expect("atomically abandon exact claimed prelaunch capture");
        let capture = fixture
            .ledger
            .load_command_output_capture(&capture_intent.capture_id)
            .expect("load claimed-prelaunch terminal capture");
        assert_eq!(capture.acquired.as_ref(), Some(&acquired));
        let terminal = capture
            .terminal
            .as_ref()
            .expect("claimed-prelaunch terminal");
        assert_eq!(
            terminal.observation_class,
            CommandOutputCaptureObservationClassV1::FailedBeforeEffect
        );
        assert_eq!(
            capture.reconciliation_obligation_closure.as_ref(),
            Some(&terminal.terminal_anchor_digest)
        );
        assert_eq!(
            fixture
                .ledger
                .load_command_domain_cleanup_proof(&fixture.intent.effect_id)
                .expect("load exact no-domain cleanup")
                .proof,
            cleanup
        );
        assert_v27_capture_loader_rejects_transactional_corruption(
            &mut fixture.ledger,
            &capture_intent.capture_id,
            "DROP TRIGGER effect_evidence_payloads_no_update;",
            |transaction| {
                transaction
                    .execute(
                        "UPDATE effect_evidence_payloads
                         SET evidence_bytes = ?1 WHERE effect_id = ?2",
                        params![
                            b"crossed-prelaunch-restart-evidence".as_slice(),
                            fixture.intent.effect_id,
                        ],
                    )
                    .expect("cross prelaunch restart physical evidence bytes");
            },
        );
        assert!(matches!(
            fixture
                .ledger
                .classify_command_output_capture_recovery(&capture_intent.capture_id)
                .expect("classify claimed-prelaunch terminal"),
            CommandOutputCaptureRecovery::Terminal(replay) if replay == capture
        ));
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn v27_restart_postlaunch_unknown_consumes_claim_but_keeps_obligation_open_without_cleanup() {
        let mut fixture = prepare_fresh_command_dispatch_input("v27-restart-postlaunch-unknown");
        let capture_intent = v27_test_capture_intent(
            &fixture.intent,
            &fixture.launch,
            &fixture.session,
            "v27-restart-postlaunch-unknown",
        );
        let dispatch_permit = match fixture
            .ledger
            .admit_runner_command_output_capture_intent_for_dispatch(
                &fixture.intent,
                EFFECT_REQUEST_BYTES,
                &fixture.proposal,
                &fixture.session.session_id,
                &capture_intent,
            )
            .expect("admit postlaunch-Unknown capture")
        {
            CommandOutputCaptureIntentAdmission::Fresh { permit, .. } => permit,
            other => panic!("fresh postlaunch-Unknown admission returned {other:?}"),
        };
        let acquired = v27_test_capture_acquired_at_generation(
            &capture_intent,
            dispatch_permit
                .expected_output_capture_dispatch_claim_id()
                .expect("postlaunch-Unknown dispatch identity"),
            "v27-restart-postlaunch-unknown",
            2,
            1_240,
        );
        let (_, transport) = fixture
            .ledger
            .claim_command_output_capture_dispatch(
                dispatch_permit,
                acquired.clone(),
                OPAQUE_RUNNER_TRANSPORT_REQUEST_BYTES,
            )
            .expect("commit postlaunch-Unknown acquisition and dispatch");
        drop(transport);
        let (reconciliation_permit, reconciliation_claim) = match fixture
            .ledger
            .claim_command_output_capture_reconciliation(
                &capture_intent.capture_id,
                Digest::sha256(b"v27-restart-postlaunch-unknown-claim").as_str(),
                "desktop-restart-owner",
                1_300,
                1_600,
            )
            .expect("claim postlaunch-Unknown capture")
        {
            CommandOutputCaptureReconciliationAdmission::Fresh { claim, permit } => (permit, claim),
            other => panic!("fresh postlaunch-Unknown reconciliation returned {other:?}"),
        };
        let launch = CommandOutputCaptureRestartLaunchEvidenceV1::try_new(
            "runner-launch-binding/v1",
            br#"{"pid":4242,"launch":"exact"}"#.to_vec(),
            CommandOutputCaptureStoreHeadV1 {
                generation: 4,
                record_digest: Digest::sha256(b"v27-restart-postlaunch-unknown-launch"),
            },
        )
        .expect("construct exact postlaunch evidence");
        let states = [
            CommandOutputCaptureRestartStateV1::Intent,
            CommandOutputCaptureRestartStateV1::Acquired,
            CommandOutputCaptureRestartStateV1::WriterAttached,
            CommandOutputCaptureRestartStateV1::LaunchIntended,
            CommandOutputCaptureRestartStateV1::CleanupIntended,
            CommandOutputCaptureRestartStateV1::Cleaned,
        ];
        let physical = v27_test_physical_reconciliation(
            &capture_intent,
            &reconciliation_claim,
            "v27-restart-postlaunch-unknown",
            &states,
            Some(acquired.store_head.clone()),
            Some(CommandOutputCaptureRestartStateV1::LaunchIntended),
            CommandOutputCapturePendingResolutionV1::None,
            CommandOutputCapturePhysicalResolutionActionV1::WorkingSetCleaned,
            Some(acquired.clone()),
            CommandOutputCaptureLaunchHistoryV1::ExactLaunchEvidence { evidence: launch },
            None,
            None,
            1_400,
        )
        .expect("construct postlaunch-Unknown physical reconciliation");
        let observation = effect_observation(
            &fixture.intent,
            "v27-restart-postlaunch-unknown-observation",
            EffectOutcome::Unknown {
                evidence_digest: physical
                    .effect_evidence_digest()
                    .expect("postlaunch-Unknown evidence digest"),
            },
            1_390,
        );
        let event = effect_terminal_event(
            &fixture.intent,
            &fixture.proposal.event_id,
            &observation,
            fixture
                .ledger
                .next_sequence(&fixture.intent.sprint_id)
                .expect("postlaunch-Unknown terminal sequence"),
            "v27-restart-postlaunch-unknown-event",
        );

        let raw_terminal = CommandOutputCaptureTerminalAnchorV1::try_new(
            &capture_intent,
            Some(&acquired),
            &observation,
            CommandOutputCaptureTerminalDispositionV1::ReconciliationRequired,
            physical.final_store_head.clone(),
            physical.reconciliation_digest.clone(),
            None,
            physical.reconciled_at_unix_ms,
        )
        .expect("construct raw restart-Unknown terminal evidence fixture");
        let raw_evidence = fixture
            .ledger
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .expect("start raw restart-Unknown evidence substitution");
        command_output_capture_authority::insert_restart_claimed_unresolved_terminal_validation(
            &raw_evidence,
            &capture_intent,
            &acquired,
            &raw_terminal,
            &reconciliation_claim,
            &physical,
        )
        .expect("stage exact raw restart-Unknown validation");
        command_output_capture_authority::insert_terminal(
            &raw_evidence,
            &raw_terminal,
            &observation,
        )
        .expect("stage exact raw restart-Unknown terminal");
        insert_agent_event(&raw_evidence, &event).expect("stage raw restart-Unknown event");
        insert_effect_evidence_payload(
            &raw_evidence,
            &observation,
            b"not-the-canonical-physical-reconciliation-receipt",
        )
        .expect("stage digest-labelled but byte-substituted effect evidence");
        let raw_evidence_error = insert_claimed_effect_observation(
            &raw_evidence,
            &observation,
            &event.event_id,
            &acquired.dispatch_claim_id,
        )
        .expect_err("raw restart disposition cannot substitute physical evidence bytes");
        assert!(
            raw_evidence_error
                .to_string()
                .contains("restart capture observation requires exact physical receipt evidence"),
            "unexpected raw physical-evidence rejection: {raw_evidence_error}"
        );
        drop(raw_evidence);

        fixture
            .ledger
            .record_reconciled_claimed_command_output_capture_unknown(
                reconciliation_permit,
                &observation,
                &event,
                &physical,
            )
            .expect("atomically record exact restart Unknown");
        let capture = fixture
            .ledger
            .load_command_output_capture(&capture_intent.capture_id)
            .expect("load restart Unknown capture");
        let terminal = capture.terminal.as_ref().expect("restart Unknown terminal");
        assert_eq!(
            terminal.disposition,
            CommandOutputCaptureTerminalDispositionV1::ReconciliationRequired
        );
        assert!(capture.reconciliation_obligation_closure.is_none());
        assert_eq!(
            row_count(&fixture.ledger, "command_domain_cleanup_proofs"),
            0
        );
        assert_eq!(row_count(&fixture.ledger, "worker_cleanup_receipts"), 0);
        assert_eq!(
            fixture
                .ledger
                .connection
                .query_row(
                    "SELECT release_kind
                     FROM command_output_capture_reconciliation_claim_releases
                     WHERE claim_id = ?1",
                    [&reconciliation_claim.claim_id],
                    |row| row.get::<_, String>(0),
                )
                .expect("load consumed restart-Unknown claim"),
            "ConsumedTerminal"
        );
        assert_v27_capture_loader_rejects_transactional_corruption(
            &mut fixture.ledger,
            &capture_intent.capture_id,
            "DROP TRIGGER effect_evidence_payloads_no_update;",
            |transaction| {
                transaction
                    .execute(
                        "UPDATE effect_evidence_payloads
                         SET evidence_bytes = ?1 WHERE effect_id = ?2",
                        params![
                            b"crossed-restart-physical-evidence".as_slice(),
                            fixture.intent.effect_id,
                        ],
                    )
                    .expect("cross stored restart physical evidence bytes");
            },
        );
        assert!(matches!(
            fixture
                .ledger
                .classify_command_output_capture_recovery(&capture_intent.capture_id)
                .expect("classify restart Unknown"),
            CommandOutputCaptureRecovery::ReconciliationRequired(replay) if replay == capture
        ));
        let restart_receipt =
            command_output_capture_authority::load_restart_claimed_unresolved_receipt_for_terminal(
                &fixture.ledger.connection,
                &terminal.terminal_anchor_digest,
            )
            .expect("load typed restart-Unknown receipt")
            .expect("restart-Unknown terminal retains physical receipt");
        let (same_head_permit, same_head_claim) = match fixture
            .ledger
            .claim_command_output_capture_reconciliation(
                &capture_intent.capture_id,
                Digest::sha256(b"v27-restart-postlaunch-same-head-claim").as_str(),
                "desktop-resolution-owner",
                1_410,
                1_700,
            )
            .expect("claim restart Unknown for same-head resolution")
        {
            CommandOutputCaptureReconciliationAdmission::Fresh { claim, permit } => (permit, claim),
            other => panic!("fresh same-head resolution claim returned {other:?}"),
        };
        let same_head = CommandOutputCaptureReconciliationResolutionV1::try_new_restart_same_head(
            &capture_intent,
            &acquired,
            terminal,
            &same_head_claim,
            &restart_receipt,
            CommandOutputCaptureTerminalDispositionV1::Abandoned,
            1_420,
        )
        .expect("construct typed restart-only same-head resolution");
        assert_eq!(same_head.store_head, terminal.store_head);
        assert!(
            same_head
                .validate_against(&capture_intent, terminal, &same_head_claim)
                .is_err(),
            "the ordinary live Unknown path must remain strict-advance"
        );
        drop(same_head_permit);
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn v27_restart_terminal_prepared_publishes_exact_provider_evidence_and_cleanup_atomically() {
        let mut fixture = prepare_fresh_command_dispatch_input("v27-restart-terminal-prepared");
        let capture_intent = v27_test_capture_intent(
            &fixture.intent,
            &fixture.launch,
            &fixture.session,
            "v27-restart-terminal-prepared",
        );
        let dispatch_permit = match fixture
            .ledger
            .admit_runner_command_output_capture_intent_for_dispatch(
                &fixture.intent,
                EFFECT_REQUEST_BYTES,
                &fixture.proposal,
                &fixture.session.session_id,
                &capture_intent,
            )
            .expect("admit TerminalPrepared capture")
        {
            CommandOutputCaptureIntentAdmission::Fresh { permit, .. } => permit,
            other => panic!("fresh TerminalPrepared admission returned {other:?}"),
        };
        let acquired = v27_test_capture_acquired_at_generation(
            &capture_intent,
            dispatch_permit
                .expected_output_capture_dispatch_claim_id()
                .expect("TerminalPrepared dispatch identity"),
            "v27-restart-terminal-prepared",
            2,
            1_240,
        );
        let (_, transport) = fixture
            .ledger
            .claim_command_output_capture_dispatch(
                dispatch_permit,
                acquired.clone(),
                OPAQUE_RUNNER_TRANSPORT_REQUEST_BYTES,
            )
            .expect("commit TerminalPrepared acquisition and dispatch");
        drop(transport);
        let (reconciliation_permit, reconciliation_claim) = match fixture
            .ledger
            .claim_command_output_capture_reconciliation(
                &capture_intent.capture_id,
                Digest::sha256(b"v27-restart-terminal-prepared-claim").as_str(),
                "desktop-restart-owner",
                1_300,
                1_700,
            )
            .expect("claim TerminalPrepared capture")
        {
            CommandOutputCaptureReconciliationAdmission::Fresh { claim, permit } => (permit, claim),
            other => panic!("fresh TerminalPrepared reconciliation returned {other:?}"),
        };
        let launch = CommandOutputCaptureRestartLaunchEvidenceV1::try_new(
            "runner-launch-binding/v1",
            br#"{"pid":5150,"launch":"terminal-prepared"}"#.to_vec(),
            CommandOutputCaptureStoreHeadV1 {
                generation: 4,
                record_digest: Digest::sha256(b"v27-restart-terminal-prepared-launch"),
            },
        )
        .expect("construct TerminalPrepared launch evidence");
        let retained_terminal_bytes =
            br#"{"runner_wire_terminal":{"exit_code":0,"capture":"complete"}}"#;
        let terminal_prepared = CommandOutputCapturePhysicalTerminalEvidenceV1 {
            schema: "runner-terminal-record/v1".into(),
            canonical_bytes_digest: Digest::sha256(retained_terminal_bytes),
            store_head: CommandOutputCaptureStoreHeadV1 {
                generation: 7,
                record_digest: Digest::sha256(b"v27-restart-terminal-prepared-head"),
            },
        };
        let artifacts =
            v27_test_artifact_reference(&capture_intent, "v27-restart-terminal-prepared");
        let states = [
            CommandOutputCaptureRestartStateV1::Intent,
            CommandOutputCaptureRestartStateV1::Acquired,
            CommandOutputCaptureRestartStateV1::WriterAttached,
            CommandOutputCaptureRestartStateV1::LaunchIntended,
            CommandOutputCaptureRestartStateV1::Finished,
            CommandOutputCaptureRestartStateV1::Published,
            CommandOutputCaptureRestartStateV1::TerminalPrepared,
        ];
        let physical = v27_test_physical_reconciliation(
            &capture_intent,
            &reconciliation_claim,
            "v27-restart-terminal-prepared",
            &states,
            Some(acquired.store_head.clone()),
            Some(CommandOutputCaptureRestartStateV1::TerminalPrepared),
            CommandOutputCapturePendingResolutionV1::None,
            CommandOutputCapturePhysicalResolutionActionV1::TerminalReadback,
            Some(acquired.clone()),
            CommandOutputCaptureLaunchHistoryV1::ExactLaunchEvidence { evidence: launch },
            Some(artifacts.clone()),
            Some(terminal_prepared.clone()),
            1_500,
        )
        .expect("construct TerminalPrepared physical reconciliation");
        let mut substituted = physical.clone();
        substituted.resolution_action =
            CommandOutputCapturePhysicalResolutionActionV1::FinishedPublicationRecovered;
        assert!(substituted.validate().is_err());

        let provider_evidence =
            br#"{"provider_tool_result":{"status":"success","content":"done"}}"#;
        let observation = effect_observation(
            &fixture.intent,
            "v27-restart-terminal-prepared-observation",
            EffectOutcome::Succeeded {
                evidence_digest: Digest::sha256(provider_evidence),
            },
            1_470,
        );
        let event = effect_terminal_event(
            &fixture.intent,
            &fixture.proposal.event_id,
            &observation,
            fixture
                .ledger
                .next_sequence(&fixture.intent.sprint_id)
                .expect("TerminalPrepared terminal sequence"),
            "v27-restart-terminal-prepared-event",
        );
        let cleanup = v27_test_command_cleanup(
            &fixture.intent,
            &observation,
            &fixture.launch,
            &fixture.session,
            "v27-restart-terminal-prepared",
            1_490,
        );
        let clean_runner = v29_test_clean_runner_reference(
            &capture_intent,
            &acquired,
            &physical.final_store_head,
            &terminal_prepared.canonical_bytes_digest,
            CommandTerminationV1::Exited { code: 0 },
            cleanup.backend,
            "v27-restart-terminal-prepared",
            1_499,
        );
        let persisted = fixture
            .ledger
            .record_reconciled_terminal_prepared_command_output_capture_success(
                reconciliation_permit,
                &observation,
                provider_evidence,
                retained_terminal_bytes,
                &event,
                &cleanup,
                &physical,
                &clean_runner,
            )
            .expect("atomically publish exact TerminalPrepared restart success");
        assert_eq!(
            persisted.evidence_bytes.as_deref(),
            Some(provider_evidence.as_slice())
        );
        let capture = fixture
            .ledger
            .load_command_output_capture(&capture_intent.capture_id)
            .expect("load published TerminalPrepared capture");
        let terminal = capture
            .terminal
            .as_ref()
            .expect("published restart terminal");
        assert_eq!(
            terminal.disposition,
            CommandOutputCaptureTerminalDispositionV1::Published
        );
        assert_eq!(terminal.artifact_reference.as_ref(), Some(&artifacts));
        assert_eq!(
            terminal.terminal_record_digest,
            terminal_prepared.canonical_bytes_digest
        );
        assert_eq!(
            capture.reconciliation_obligation_closure.as_ref(),
            Some(&terminal.terminal_anchor_digest)
        );
        assert_eq!(
            fixture
                .ledger
                .load_command_domain_cleanup_proof(&fixture.intent.effect_id)
                .expect("load TerminalPrepared zero-survivor cleanup")
                .proof,
            cleanup
        );
        assert!(matches!(
            fixture
                .ledger
                .claim_command_output_capture_reconciliation(
                    &capture_intent.capture_id,
                    Digest::sha256(b"v27-restart-terminal-prepared-replay").as_str(),
                    "desktop-replay-owner",
                    1_510,
                    1_600,
                )
                .expect("classify TerminalPrepared replay"),
            CommandOutputCaptureReconciliationAdmission::Terminal(replay)
                if replay == capture
        ));
    }

