    #[allow(clippy::too_many_lines)] // The fixture builds one complete typed verification/effect authority chain.
    fn persist_verification_evidence(
        ledger: &mut EventLedger,
        launch: &RunnerLaunchIntent,
        mut verification: VerificationReceipt,
        output_evidence_bytes: Vec<u8>,
        created_at_unix_ms: u64,
    ) -> VerificationEffectEvidence {
        let request_bytes =
            encode("verification command request", &verification.command).expect("encode command");
        let capture_schema = ledger
            .connection
            .pragma_query_value(None, "user_version", |row| row.get::<_, i64>(0))
            .expect("inspect capture schema for verification fixture")
            >= 27;
        let current_attempt_schema =
            task_attempt_authority::schema_is_installed(&ledger.connection)
                .expect("inspect task-attempt schema for verification fixture");
        let formal_authority = verification
            .task_id
            .as_ref()
            .filter(|_| current_attempt_schema)
            .map(|task_id| {
                let running = enter_test_task_attempt_running(
                    ledger,
                    launch,
                    created_at_unix_ms.saturating_sub(2),
                );
                let change_set_id = ledger
                    .connection
                    .query_row(
                        "SELECT change_set_id FROM change_sets
                     WHERE sprint_id = ?1 AND result_snapshot = ?2",
                        params![verification.sprint_id, verification.snapshot_id.as_str()],
                        |row| row.get::<_, String>(0),
                    )
                    .expect("task verification snapshot has one candidate change set");
                let boundary_event = AgentEvent {
                    contract_version: CONTRACT_VERSION,
                    sequence: ledger
                        .next_sequence(&verification.sprint_id)
                        .expect("test verification boundary sequence"),
                    event_id: format!("event-{}-verifying", verification.receipt_id),
                    sprint_id: verification.sprint_id.clone(),
                    task_id: Some(task_id.clone()),
                    worker_id: launch.worker_id.clone(),
                    causation_id: Some(running.transition_event_id.clone()),
                    correlation_id: format!("correlation-{}", verification.receipt_id),
                    policy_hash: Some(launch.policy_hash.clone()),
                    occurred_at_unix_ms: created_at_unix_ms.saturating_sub(1),
                    payload: AgentEventKind::TaskStateChanged {
                        from: "Running".into(),
                        to: "Verifying".into(),
                    },
                };
                let boundary = TaskAttemptVerificationBoundary {
                    contract_version: CONTRACT_VERSION,
                    boundary_id: format!("boundary-{}-verifying", verification.receipt_id),
                    attempt: running.attempt.clone(),
                    runner_launch_id: launch.launch_id.clone(),
                    runner_session_id: launch.session_id.clone(),
                    change_set_id,
                    sealed_snapshot: verification.snapshot_id.clone(),
                    transition_event_id: boundary_event.event_id.clone(),
                    terminal_non_cleanup_effects: Vec::new(),
                    sealed_at_unix_ms: boundary_event.occurred_at_unix_ms,
                };
                ledger
                    .transition_task_attempt_to_verifying(&boundary, &boundary_event)
                    .expect("enter formal Verifying phase");
                (running.attempt, boundary)
            });
        let final_phase_event = (verification.task_id.is_none() && capture_schema).then(|| {
            let sequence = ledger
                .next_sequence(&verification.sprint_id)
                .expect("final-verification phase sequence");
            AgentEvent {
                contract_version: CONTRACT_VERSION,
                sequence,
                event_id: format!("event-{}-phase", verification.receipt_id),
                sprint_id: verification.sprint_id.clone(),
                task_id: None,
                worker_id: None,
                causation_id: None,
                correlation_id: format!("correlation-{}", verification.receipt_id),
                policy_hash: Some(launch.policy_hash.clone()),
                occurred_at_unix_ms: created_at_unix_ms.saturating_sub(1),
                payload: AgentEventKind::SprintStateChanged {
                    from: "Running".into(),
                    to: "FinalVerification".into(),
                },
            }
        });
        let intent = EffectIntent {
            contract_version: CONTRACT_VERSION,
            effect_id: format!("effect-{}", verification.receipt_id),
            idempotency_key: format!("key-{}", verification.receipt_id),
            sprint_id: verification.sprint_id.clone(),
            task_id: verification.task_id.clone(),
            worker_id: verification
                .task_id
                .as_ref()
                .map(|_| launch.worker_id.clone().expect("task worker identity")),
            worker_lease: verification.task_id.as_ref().map(|_| {
                launch
                    .worker_lease
                    .clone()
                    .expect("task worker lease identity")
            }),
            causation_event_id: formal_authority
                .as_ref()
                .map(|(_, boundary)| boundary.transition_event_id.clone())
                .or_else(|| {
                    final_phase_event
                        .as_ref()
                        .map(|event| event.event_id.clone())
                }),
            correlation_id: format!("correlation-{}", verification.receipt_id),
            kind: EffectKind::RunCommand,
            request_digest: Digest::sha256(&request_bytes),
            policy_hash: launch.policy_hash.clone(),
            input_snapshot: verification.snapshot_id.clone(),
            created_at_unix_ms,
        };
        let proposal = effect_proposal_event(
            &intent,
            final_phase_event.as_ref().map_or_else(
                || {
                    ledger
                        .next_sequence("sprint-1")
                        .expect("verification proposal sequence")
                },
                |event| event.sequence + 1,
            ),
            &format!("event-{}-proposed", verification.receipt_id),
        );
        let claimed_dispatch_schema =
            runner_effect_dispatch_claim_schema_is_installed(&ledger.connection)
                .expect("inspect runner dispatch claim schema for verification fixture");
        let formal_dispatch = formal_authority.as_ref().map(|(attempt, _)| {
            let admission = TaskAttemptFormalCheckAdmission {
                contract_version: CONTRACT_VERSION,
                admission_id: format!("admission-{}", verification.receipt_id),
                attempt: attempt.clone(),
                criterion_ordinal: 0,
                criterion_id: "tests".into(),
                effect_id: intent.effect_id.clone(),
                runner_session_id: launch.session_id.clone(),
                sealed_snapshot: verification.snapshot_id.clone(),
                command: verification.command.clone(),
                admitted_at_unix_ms: created_at_unix_ms,
            };
            let capture_intent = capture_schema.then(|| {
                v27_test_capture_intent(
                    &intent,
                    launch,
                    &runner_session(launch, 1_300),
                    &verification.receipt_id,
                )
            });
            let permit = if let Some(capture) = capture_intent.as_ref() {
                Some(
                    match ledger
                        .admit_task_attempt_formal_check_with_output_capture_for_dispatch(
                            &admission, &intent, &proposal, capture,
                        )
                        .expect("persist current formal verification capture admission")
                    {
                        TaskFormalCheckDispatchAdmission::Fresh { permit, .. } => permit,
                        TaskFormalCheckDispatchAdmission::Existing { .. } => {
                            panic!("new formal verification admission must be Fresh")
                        }
                    },
                )
            } else if claimed_dispatch_schema {
                Some(
                    match ledger
                        .admit_task_attempt_formal_check_for_dispatch(
                            &admission, &intent, &proposal,
                        )
                        .expect("persist historical formal verification dispatch admission")
                    {
                        TaskFormalCheckDispatchAdmission::Fresh { permit, .. } => permit,
                        TaskFormalCheckDispatchAdmission::Existing { .. } => {
                            panic!("new formal verification admission must be Fresh")
                        }
                    },
                )
            } else {
                ledger
                    .admit_task_attempt_formal_check(&admission, &intent, &proposal)
                    .expect("persist historical claimless formal verification admission");
                None
            };
            (admission, permit, capture_intent)
        });
        let final_dispatch = final_phase_event.as_ref().map(|phase_event| {
            let session = ledger
                .load_runner_session(&intent.sprint_id, &launch.session_id)
                .expect("load final-verification session");
            let admission = SprintFinalVerificationAdmission {
                contract_version: CONTRACT_VERSION,
                admission_id: format!("admission-{}", verification.receipt_id),
                sprint_id: intent.sprint_id.clone(),
                sprint_phase_event_id: phase_event.event_id.clone(),
                final_snapshot: verification.snapshot_id.clone(),
                effect_id: intent.effect_id.clone(),
                runner_launch_id: launch.launch_id.clone(),
                runner_session_id: launch.session_id.clone(),
                command: verification.command.clone(),
                admitted_at_unix_ms: intent.created_at_unix_ms,
            };
            let capture =
                v27_test_capture_intent(&intent, launch, &session, &verification.receipt_id);
            let permit = match ledger
                .admit_sprint_final_verification_with_output_capture_for_dispatch(
                    &admission,
                    phase_event,
                    &intent,
                    &proposal,
                    &capture,
                )
                .expect("persist current final-verification capture admission")
            {
                SprintFinalVerificationDispatchAdmission::Fresh { permit, .. } => permit,
                SprintFinalVerificationDispatchAdmission::Existing { .. } => {
                    panic!("new final-verification admission must be Fresh")
                }
            };
            (permit, capture)
        });
        if formal_dispatch.is_none() && final_dispatch.is_none() {
            ledger
                .record_runner_effect_intent(&intent, &request_bytes, &proposal, &launch.session_id)
                .expect("persist verification intent");
        }
        let (output_artifacts, output_evidence_bytes) = bind_complete_output_artifacts(
            ledger,
            &mut verification,
            &intent.effect_id,
            &launch.launch_id,
            &launch.session_id,
            output_evidence_bytes,
        );
        let evidence = VerificationEffectEvidence {
            contract_version: CONTRACT_VERSION,
            effect_id: intent.effect_id.clone(),
            observation_id: format!("observation-{}", verification.receipt_id),
            runner_launch_id: launch.launch_id.clone(),
            runner_session_id: launch.session_id.clone(),
            verification,
            output_artifacts,
            output_evidence_bytes,
        };
        let evidence_bytes =
            encode("verification effect evidence", &evidence).expect("encode verification");
        let observation = effect_observation(
            &intent,
            &evidence.observation_id,
            EffectOutcome::Succeeded {
                evidence_digest: Digest::sha256(&evidence_bytes),
            },
            evidence.verification.finished_at_unix_ms,
        );
        let terminal = effect_terminal_event(
            &intent,
            &proposal.event_id,
            &observation,
            ledger
                .next_sequence("sprint-1")
                .expect("verification terminal sequence"),
            &format!("event-{}-finished", evidence.verification.receipt_id),
        );
        if let (Some((admission, permit, capture_intent)), Some((attempt, boundary))) =
            (formal_dispatch, formal_authority)
        {
            let check = TaskAttemptFormalCheck {
                contract_version: CONTRACT_VERSION,
                formal_check_id: format!("formal-check-{}", evidence.verification.receipt_id),
                attempt: attempt.clone(),
                criterion_ordinal: admission.criterion_ordinal,
                criterion_id: admission.criterion_id,
                effect_id: evidence.effect_id.clone(),
                observation_id: evidence.observation_id.clone(),
                verification_receipt: evidence.verification.clone(),
                runner_session_id: launch.session_id.clone(),
                sealed_snapshot: evidence.verification.snapshot_id.clone(),
            };
            if let Some(permit) = permit {
                let session = ledger
                    .load_runner_session(&intent.sprint_id, &launch.session_id)
                    .expect("load formal verification runner session");
                let dispatch_permit = FreshRunnerEffectDispatchPermit::TaskFormalCheck(permit);
                let (transport, capture_acquired) = if let Some(capture) = capture_intent.as_ref() {
                    let acquired = v27_test_capture_acquired(
                        capture,
                        dispatch_permit
                            .expected_output_capture_dispatch_claim_id()
                            .expect("fresh fixture capture claim identity"),
                        &evidence.verification.receipt_id,
                        intent.created_at_unix_ms + 1,
                    );
                    let (_, transport) = ledger
                        .claim_command_output_capture_dispatch(
                            dispatch_permit,
                            acquired.clone(),
                            OPAQUE_RUNNER_TRANSPORT_REQUEST_BYTES,
                        )
                        .expect("claim formal verification capture dispatch");
                    (transport, Some(acquired))
                } else {
                    let (_, transport) = ledger
                        .claim_runner_effect_dispatch(
                            dispatch_permit,
                            OPAQUE_RUNNER_TRANSPORT_REQUEST_BYTES,
                        )
                        .expect("claim historical formal verification dispatch");
                    (transport, None)
                };
                let authority = transport
                    .validate_transport_request(
                        &intent,
                        &request_bytes,
                        launch,
                        &session,
                        None,
                        OPAQUE_RUNNER_TRANSPORT_REQUEST_BYTES,
                    )
                    .expect("validate formal verification transport");
                if let (Some(capture), Some(acquired)) =
                    (capture_intent.as_ref(), capture_acquired.as_ref())
                {
                    let capture_terminal = v27_test_published_capture_terminal(
                        capture,
                        acquired,
                        &observation,
                        evidence
                            .output_artifacts
                            .clone()
                            .expect("current formal evidence carries output artifacts"),
                        &evidence.verification.receipt_id,
                        evidence.verification.finished_at_unix_ms + 2,
                    );
                    let cleanup = v27_test_command_cleanup(
                        &intent,
                        &observation,
                        launch,
                        &session,
                        &evidence.verification.receipt_id,
                        evidence.verification.finished_at_unix_ms + 1,
                    );
                    let clean_scan = v29_test_clean_scan_receipt(
                        capture,
                        acquired,
                        &capture_terminal,
                        evidence
                            .verification
                            .termination
                            .expect("current formal receipt has typed termination"),
                        &evidence.verification.receipt_id,
                    );
                    ledger
                        .complete_claimed_task_attempt_formal_check_with_output_capture(
                            authority,
                            &check,
                            &observation,
                            &terminal,
                            &evidence,
                            &capture_terminal,
                            &clean_scan,
                            &cleanup,
                        )
                        .expect("persist claimed v27 formal verification evidence");
                } else {
                    ledger
                        .complete_claimed_task_attempt_formal_check(
                            authority,
                            &check,
                            &observation,
                            &terminal,
                            &evidence,
                        )
                        .expect("persist claimed historical formal verification evidence");
                }
            } else {
                ledger
                    .complete_task_attempt_formal_check(&check, &observation, &terminal, &evidence)
                    .expect("persist historical claimless formal verification evidence");
            }
            let candidate_event = AgentEvent {
                contract_version: CONTRACT_VERSION,
                sequence: ledger
                    .next_sequence(&evidence.verification.sprint_id)
                    .expect("test candidate sequence"),
                event_id: format!("event-{}-candidate", evidence.verification.receipt_id),
                sprint_id: evidence.verification.sprint_id.clone(),
                task_id: evidence.verification.task_id.clone(),
                worker_id: launch.worker_id.clone(),
                causation_id: Some(terminal.event_id.clone()),
                correlation_id: format!("correlation-{}", evidence.verification.receipt_id),
                policy_hash: Some(launch.policy_hash.clone()),
                occurred_at_unix_ms: evidence.verification.finished_at_unix_ms + 1,
                payload: AgentEventKind::TaskStateChanged {
                    from: "Verifying".into(),
                    to: "Candidate".into(),
                },
            };
            let candidate = TaskAttemptCandidateBoundary {
                contract_version: CONTRACT_VERSION,
                boundary_id: format!("boundary-{}-candidate", evidence.verification.receipt_id),
                attempt,
                verification_boundary_id: boundary.boundary_id,
                change_set_id: boundary.change_set_id,
                sealed_snapshot: boundary.sealed_snapshot,
                formal_check_ids: vec![check.formal_check_id],
                verification_receipt_ids: vec![evidence.verification.receipt_id.clone()],
                transition_event_id: candidate_event.event_id.clone(),
                admitted_at_unix_ms: candidate_event.occurred_at_unix_ms,
            };
            ledger
                .transition_task_attempt_to_candidate(&candidate, &candidate_event)
                .expect("enter test Candidate phase");
        } else if let Some((permit, capture)) = final_dispatch {
            let session = ledger
                .load_runner_session(&intent.sprint_id, &launch.session_id)
                .expect("load claimed final-verification session");
            let dispatch_permit = FreshRunnerEffectDispatchPermit::SprintFinalVerification(permit);
            let acquired = v27_test_capture_acquired(
                &capture,
                dispatch_permit
                    .expected_output_capture_dispatch_claim_id()
                    .expect("fresh final capture claim identity"),
                &evidence.verification.receipt_id,
                intent.created_at_unix_ms + 1,
            );
            let (_, transport) = ledger
                .claim_command_output_capture_dispatch(
                    dispatch_permit,
                    acquired.clone(),
                    OPAQUE_RUNNER_TRANSPORT_REQUEST_BYTES,
                )
                .expect("claim final-verification capture dispatch");
            let authority = transport
                .validate_transport_request(
                    &intent,
                    &request_bytes,
                    launch,
                    &session,
                    None,
                    OPAQUE_RUNNER_TRANSPORT_REQUEST_BYTES,
                )
                .expect("validate final-verification transport");
            let capture_terminal = v27_test_published_capture_terminal(
                &capture,
                &acquired,
                &observation,
                evidence
                    .output_artifacts
                    .clone()
                    .expect("current final evidence carries output artifacts"),
                &evidence.verification.receipt_id,
                evidence.verification.finished_at_unix_ms + 2,
            );
            let cleanup = v27_test_command_cleanup(
                &intent,
                &observation,
                launch,
                &session,
                &evidence.verification.receipt_id,
                evidence.verification.finished_at_unix_ms + 1,
            );
            let clean_scan = v29_test_clean_scan_receipt(
                &capture,
                &acquired,
                &capture_terminal,
                evidence
                    .verification
                    .termination
                    .expect("current final receipt has typed termination"),
                &evidence.verification.receipt_id,
            );
            ledger
                .complete_claimed_sprint_final_verification_with_output_capture(
                    authority,
                    &observation,
                    &terminal,
                    &evidence,
                    &capture_terminal,
                    &clean_scan,
                    &cleanup,
                )
                .expect("persist claimed v27 final-verification evidence");
        } else {
            ledger
                .record_verification_effect_observation(&observation, &terminal, &evidence)
                .expect("persist authoritative verification evidence");
        }
        evidence
    }

    struct PendingTaskIntegrationFixture {
        worker_launch: RunnerLaunchIntent,
        candidate: TaskAttemptCandidateBoundary,
        evidence: TaskIntegrationEvidence,
        observation: EffectObservation,
        terminal: AgentEvent,
        observation_authority: Option<RunnerEffectObservationAuthority>,
    }

    fn open_v12_test_ledger(database: &TestDatabase) -> EventLedger {
        schema_template::install_exact_database_at(12, &database.path);
        let connection = Connection::open(&database.path).expect("create v12 test database");
        register_schema_functions(&connection).expect("register v12 schema functions");
        connection
            .execute_batch(
                "PRAGMA foreign_keys = ON;
                 PRAGMA synchronous = FULL;
                 PRAGMA journal_mode = WAL;",
            )
            .expect("configure v12 test database");
        EventLedger {
            connection,
            database_path: database.path.clone(),
            read_only: false,
            instance_id: next_event_ledger_instance_id(),
        }
    }

    fn open_v16_test_ledger(database: &TestDatabase) -> EventLedger {
        schema_template::install_exact_database_at(16, &database.path);
        let connection = Connection::open(&database.path).expect("create v16 test database");
        register_schema_functions(&connection).expect("register v16 schema functions");
        connection
            .execute_batch(
                "PRAGMA foreign_keys = ON;
                 PRAGMA synchronous = FULL;
                 PRAGMA journal_mode = WAL;",
            )
            .expect("configure v16 test database");
        EventLedger {
            connection,
            database_path: database.path.clone(),
            read_only: false,
            instance_id: next_event_ledger_instance_id(),
        }
    }

    fn open_v21_test_ledger(database: &TestDatabase) -> EventLedger {
        if !database.path.exists() {
            schema_template::install_exact_database_at(21, &database.path);
        }
        let connection = Connection::open(&database.path).expect("create v21 test database");
        register_schema_functions(&connection).expect("register v21 schema functions");
        connection
            .execute_batch(
                "PRAGMA foreign_keys = ON;
                 PRAGMA synchronous = FULL;
                 PRAGMA journal_mode = WAL;",
            )
            .expect("configure v21 test database");
        let schema_version = connection
            .pragma_query_value(None, "user_version", |row| row.get::<_, u32>(0))
            .expect("read v21 test schema version");
        assert_eq!(schema_version, 21, "historical helper only reopens v21");
        EventLedger {
            connection,
            database_path: database.path.clone(),
            read_only: false,
            instance_id: next_event_ledger_instance_id(),
        }
    }

    fn open_v23_test_ledger(database: &TestDatabase) -> EventLedger {
        if !database.path.exists() {
            schema_template::install_exact_database_at(23, &database.path);
        }
        let connection = Connection::open(&database.path).expect("create v23 test database");
        register_schema_functions(&connection).expect("register v23 schema functions");
        connection
            .execute_batch(
                "PRAGMA foreign_keys = ON;
                 PRAGMA synchronous = FULL;
                 PRAGMA journal_mode = WAL;",
            )
            .expect("configure v23 test database");
        let schema_version = connection
            .pragma_query_value(None, "user_version", |row| row.get::<_, u32>(0))
            .expect("read v23 test schema version");
        assert_eq!(schema_version, 23, "historical helper only reopens v23");
        EventLedger {
            connection,
            database_path: database.path.clone(),
            read_only: false,
            instance_id: next_event_ledger_instance_id(),
        }
    }

    fn open_v25_test_ledger(database: &TestDatabase) -> EventLedger {
        schema_template::install_exact_database_at(25, &database.path);
        let connection = Connection::open(&database.path).expect("create v25 test database");
        register_schema_functions(&connection).expect("register v25 schema functions");
        connection
            .execute_batch(
                "PRAGMA foreign_keys = ON;
                 PRAGMA synchronous = FULL;
                 PRAGMA journal_mode = WAL;",
            )
            .expect("configure v25 test database");
        EventLedger {
            connection,
            database_path: database.path.clone(),
            read_only: false,
            instance_id: next_event_ledger_instance_id(),
        }
    }

    fn open_v26_test_ledger(database: &TestDatabase) -> EventLedger {
        schema_template::install_exact_database_at(26, &database.path);
        let connection = Connection::open(&database.path).expect("create v26 test database");
        register_schema_functions(&connection).expect("register v26 schema functions");
        connection
            .execute_batch(
                "PRAGMA foreign_keys = ON;
                 PRAGMA synchronous = FULL;
                 PRAGMA journal_mode = WAL;",
            )
            .expect("configure v26 test database");
        EventLedger {
            connection,
            database_path: database.path.clone(),
            read_only: false,
            instance_id: next_event_ledger_instance_id(),
        }
    }

    #[allow(clippy::too_many_lines)] // Keeps each adversarial test on one valid evidence chain.
    fn prepare_pending_task_integration(ledger: &mut EventLedger) -> PendingTaskIntegrationFixture {
        let (spec, graph) = sprint_fixture();
        ledger
            .create_sprint(&spec, &graph, 1_000)
            .expect("persist integration sprint");
        let (base, result, change_set, verification, _, _, _, _) = completion_artifacts();
        ledger
            .persist_workspace_snapshot(&spec.sprint_id, &base)
            .expect("persist integration input");
        ledger
            .persist_workspace_snapshot(&spec.sprint_id, &result)
            .expect("persist integration result");
        ledger
            .persist_change_set(&spec.sprint_id, &change_set)
            .expect("persist integration change set");

        let worker_policy = compiled_shadow_test_policy("pending-integration-worker-policy");
        let worker_launch = runner_launch(
            "launch-pending-integration-worker",
            "session-pending-integration-worker",
            RunnerSessionPurpose::TaskWorker,
            Some("worker-1"),
            &worker_policy,
            1_210,
        );
        admit_test_runner_launch(ledger, &worker_launch, &worker_policy);
        ledger
            .register_runner_session(&runner_session(&worker_launch, 1_300), &worker_policy)
            .expect("persist integration worker session");

        persist_verification_evidence(
            ledger,
            &worker_launch,
            VerificationReceipt {
                receipt_id: "verify-pending-integration-task".into(),
                sprint_id: spec.sprint_id.clone(),
                task_id: Some("task-1".into()),
                snapshot_id: result.snapshot_id.clone(),
                command: verification.command,
                policy_hash: worker_policy.contract().policy_hash.clone(),
                exit_status: Some(0),
                termination: Some(CommandTerminationV1::Exited { code: 0 }),
                output_digest: digest('0'),
                duration_ms: 25,
                finished_at_unix_ms: 1_400,
            },
            b"pending integration task verification passed".to_vec(),
            1_350,
        );

        let artifact = crate::TaskIntegrationArtifactReference {
            format_version: 1,
            artifact_digest: Digest::sha256(b"pending-integration-stage-bundle"),
            change_set_id: change_set.change_set_id.clone(),
            base_snapshot: base.snapshot_id.clone(),
            result_snapshot: result.snapshot_id.clone(),
        };
        let request = TaskIntegrationRequest {
            contract_version: CONTRACT_VERSION,
            change_set: change_set.clone(),
            artifact: artifact.clone(),
        };
        let request_bytes = encode("task integration request", &request)
            .expect("encode pending integration request");
        let attempt = ledger
            .load_task_attempt(
                &worker_launch
                    .worker_lease
                    .as_ref()
                    .expect("pending integration lease")
                    .lease_id,
            )
            .expect("load pending integration attempt");
        let candidate_id = ledger
            .connection
            .query_row(
                "SELECT boundary_id FROM task_attempt_candidate_boundaries
                 WHERE attempt_id = ?1",
                [&attempt.attempt_id],
                |row| row.get::<_, String>(0),
            )
            .expect("load pending candidate boundary identity");
        let candidate = ledger
            .load_task_attempt_candidate_boundary(&candidate_id)
            .expect("load pending candidate boundary");
        let intent = EffectIntent {
            contract_version: CONTRACT_VERSION,
            effect_id: "effect-pending-integration".into(),
            idempotency_key: "key-pending-integration".into(),
            sprint_id: spec.sprint_id,
            task_id: Some("task-1".into()),
            worker_id: Some("worker-1".into()),
            worker_lease: worker_launch.worker_lease.clone(),
            causation_event_id: Some(candidate.transition_event_id.clone()),
            correlation_id: "correlation-pending-integration".into(),
            kind: EffectKind::IntegrateChangeSet,
            request_digest: Digest::sha256(&request_bytes),
            policy_hash: worker_policy.contract().policy_hash.clone(),
            input_snapshot: base.snapshot_id.clone(),
            created_at_unix_ms: 1_410,
        };
        let proposal = effect_proposal_event(
            &intent,
            ledger
                .next_sequence(&intent.sprint_id)
                .expect("integration proposal sequence"),
            "event-pending-integration-proposed",
        );
        let admission = TaskAttemptIntegrationAdmission {
            contract_version: CONTRACT_VERSION,
            admission_id: "admission-pending-integration".into(),
            candidate_boundary: candidate.clone(),
            effect_id: intent.effect_id.clone(),
            runner_launch_id: worker_launch.launch_id.clone(),
            runner_session_id: worker_launch.session_id.clone(),
            input_snapshot: base.snapshot_id.clone(),
            result_snapshot: result.snapshot_id.clone(),
            admitted_at_unix_ms: intent.created_at_unix_ms,
        };
        let observation_authority =
            if runner_effect_dispatch_claim_schema_is_installed(&ledger.connection)
                .expect("inspect pending integration dispatch claim schema")
            {
                let permit = match ledger
                    .admit_task_attempt_integration_for_dispatch(
                        &admission, &intent, &request, &proposal,
                    )
                    .expect("persist pending integration dispatch admission")
                {
                    TaskIntegrationDispatchAdmission::Fresh { permit, .. } => permit,
                    TaskIntegrationDispatchAdmission::Existing { .. } => {
                        panic!("new pending integration admission must be Fresh")
                    }
                };
                let session = ledger
                    .load_runner_session(&intent.sprint_id, &worker_launch.session_id)
                    .expect("load pending integration worker session");
                let (_, transport) = ledger
                    .claim_task_attempt_integration_dispatch(
                        permit,
                        OPAQUE_RUNNER_TRANSPORT_REQUEST_BYTES,
                    )
                    .expect("claim pending integration dispatch");
                Some(
                    transport
                        .validate_transport_request(
                            &intent,
                            &request_bytes,
                            &worker_launch,
                            &session,
                            None,
                            OPAQUE_RUNNER_TRANSPORT_REQUEST_BYTES,
                        )
                        .expect("validate pending integration transport"),
                )
            } else {
                ledger
                    .admit_task_attempt_integration(&admission, &intent, &request, &proposal)
                    .expect("persist historical pending integration intent");
                None
            };
        let receipt = TaskIntegrationReceipt {
            contract_version: CONTRACT_VERSION,
            receipt_id: "receipt-pending-integration".into(),
            sprint_id: intent.sprint_id.clone(),
            task_id: "task-1".into(),
            worker_id: "worker-1".into(),
            worker_lease: worker_launch.worker_lease.clone(),
            worker_launch_id: worker_launch.launch_id.clone(),
            worker_session_id: worker_launch.session_id.clone(),
            worker_policy_hash: worker_launch.policy_hash.clone(),
            effect_id: intent.effect_id.clone(),
            observation_id: "observation-pending-integration".into(),
            change_set_id: change_set.change_set_id,
            input_snapshot: base.snapshot_id,
            result_snapshot: result.snapshot_id,
            task_verification_receipt_ids: vec!["verify-pending-integration-task".into()],
            integration_ordinal: 0,
            integrated_at_unix_ms: 1_450,
        };
        let evidence = TaskIntegrationEvidence {
            contract_version: CONTRACT_VERSION,
            artifact,
            validation: crate::TaskIntegrationValidationEvidence {
                mode: TaskIntegrationValidationMode::WorkerPublication,
                runner_launch_id: worker_launch.launch_id.clone(),
                runner_session_id: worker_launch.session_id.clone(),
                policy_hash: worker_launch.policy_hash.clone(),
                grant_hash: worker_launch.grant_hash.clone(),
                private_state_digest: worker_launch.private_state_digest.clone(),
            },
            receipt,
        };
        let evidence_bytes =
            encode("task integration evidence", &evidence).expect("encode integration evidence");
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
                .next_sequence(&intent.sprint_id)
                .expect("integration terminal sequence"),
            "event-pending-integration-finished",
        );
        PendingTaskIntegrationFixture {
            worker_launch,
            candidate,
            evidence,
            observation,
            terminal,
            observation_authority,
        }
    }

    fn integrate_pending_task_attempt(
        ledger: &mut EventLedger,
        pending: &mut PendingTaskIntegrationFixture,
        disposition: &TaskAttemptDisposition,
        transition_event: &AgentEvent,
    ) -> Result<TaskAttemptDisposition, LedgerError> {
        let Some(authority) = pending.observation_authority.take() else {
            return ledger.integrate_task_attempt(
                disposition,
                &pending.observation,
                &pending.terminal,
                &pending.evidence,
                transition_event,
            );
        };
        match ledger.integrate_claimed_task_attempt(
            authority,
            disposition,
            &pending.observation,
            &pending.terminal,
            &pending.evidence,
            transition_event,
        ) {
            Ok(stored) => Ok(stored),
            Err(failure) => {
                let (error, retry_authority) = failure.into_parts();
                pending.observation_authority = retry_authority;
                Err(error)
            }
        }
    }

    fn prepare_migrated_v16_pending_task_integration(
        database: &TestDatabase,
    ) -> (EventLedger, PendingTaskIntegrationFixture) {
        let pending = {
            let mut legacy = open_v16_test_ledger(database);
            let pending = prepare_pending_task_integration(&mut legacy);
            assert!(pending.observation_authority.is_none());
            pending
        };
        let ledger = EventLedger::open(&database.path).expect("migrate pending v16 integration");
        assert_eq!(
            ledger
                .connection
                .query_row(
                    "SELECT COUNT(*) FROM task_phase_claimless_legacy_exemptions
                     WHERE effect_id = ?1 AND authority_class = 'TaskIntegration'",
                    [&pending.evidence.receipt.effect_id],
                    |row| row.get::<_, i64>(0),
                )
                .expect("load migrated task-integration exemption"),
            1
        );
        (ledger, pending)
    }

    fn refresh_pending_integration_digest(
        ledger: &EventLedger,
        pending: &mut PendingTaskIntegrationFixture,
    ) {
        let evidence_bytes = encode("task integration evidence", &pending.evidence)
            .expect("encode modified integration evidence");
        pending.observation.outcome = EffectOutcome::Succeeded {
            evidence_digest: Digest::sha256(&evidence_bytes),
        };
        pending.terminal.sequence = ledger
            .next_sequence(&pending.observation.sprint_id)
            .expect("refresh integration terminal sequence");
    }

    fn pending_integration_disposition(
        pending: &PendingTaskIntegrationFixture,
    ) -> (TaskAttemptDisposition, AgentEvent) {
        let disposed_at_unix_ms = pending.evidence.receipt.integrated_at_unix_ms + 10;
        let transition_event = AgentEvent {
            contract_version: CONTRACT_VERSION,
            sequence: pending.terminal.sequence + 1,
            event_id: "event-pending-integration-integrated".into(),
            sprint_id: pending.evidence.receipt.sprint_id.clone(),
            task_id: Some(pending.evidence.receipt.task_id.clone()),
            worker_id: Some(pending.evidence.receipt.worker_id.clone()),
            causation_id: Some(pending.terminal.event_id.clone()),
            correlation_id: "correlation-pending-integration".into(),
            policy_hash: Some(pending.worker_launch.policy_hash.clone()),
            occurred_at_unix_ms: disposed_at_unix_ms,
            payload: AgentEventKind::TaskStateChanged {
                from: "Candidate".into(),
                to: "Integrated".into(),
            },
        };
        let evidence_bytes = encode("task integration evidence", &pending.evidence)
            .expect("encode pending integration disposition evidence");
        let disposition =
            TaskAttemptDisposition::Integrated(crate::TaskAttemptIntegratedDisposition {
                metadata: TaskAttemptDispositionMetadata {
                    contract_version: CONTRACT_VERSION,
                    disposition_id: "disposition-pending-integration".into(),
                    attempt: pending.candidate.attempt.clone(),
                    from_state: TaskState::Candidate,
                    state_transition_event_id: transition_event.event_id.clone(),
                    disposed_at_unix_ms,
                },
                candidate_boundary: pending.candidate.clone(),
                integration_receipt: pending.evidence.receipt.clone(),
                evidence: crate::TaskAttemptEvidence::new(
                    "evidence-pending-integration-disposition".into(),
                    crate::TaskAttemptEvidenceKind::Integrated,
                    evidence_bytes,
                )
                .expect("construct pending integration disposition evidence"),
            });
        (disposition, transition_event)
    }

    fn register_integration_validator(
        ledger: &mut EventLedger,
        launch_id: &str,
        session_id: &str,
        purpose: RunnerSessionPurpose,
        policy: &CompiledExecutionPolicy,
        private_state_digest: Digest,
        registered_at_unix_ms: u64,
    ) -> RunnerLaunchIntent {
        let mut launch = runner_launch(launch_id, session_id, purpose, None, policy, 1_420);
        launch.private_state_digest = private_state_digest;
        admit_test_runner_launch(ledger, &launch, policy);
        ledger
            .register_runner_session(&runner_session(&launch, registered_at_unix_ms), policy)
            .expect("persist validation session");
        launch
    }

    fn bind_recovery_validation(
        pending: &mut PendingTaskIntegrationFixture,
        launch: &RunnerLaunchIntent,
    ) {
        pending.evidence.validation = crate::TaskIntegrationValidationEvidence {
            mode: TaskIntegrationValidationMode::RecoveryApplierReconciliation,
            runner_launch_id: launch.launch_id.clone(),
            runner_session_id: launch.session_id.clone(),
            policy_hash: launch.policy_hash.clone(),
            grant_hash: launch.grant_hash.clone(),
            private_state_digest: launch.private_state_digest.clone(),
        };
    }

    fn rejected_pending_integration(
        configure: impl FnOnce(&mut EventLedger, &mut PendingTaskIntegrationFixture),
    ) -> LedgerError {
        let database = TestDatabase::new();
        let (mut ledger, mut pending) = prepare_migrated_v16_pending_task_integration(&database);
        configure(&mut ledger, &mut pending);
        refresh_pending_integration_digest(&ledger, &mut pending);
        let (disposition, transition_event) = pending_integration_disposition(&pending);
        let error = integrate_pending_task_attempt(
            &mut ledger,
            &mut pending,
            &disposition,
            &transition_event,
        )
        .expect_err("invalid validation authority must be rejected");
        assert_eq!(row_count(&ledger, "task_integration_receipts"), 0);
        assert!(
            ledger
                .load_effect(&pending.evidence.receipt.effect_id)
                .expect("load still-pending integration")
                .observation
                .is_none()
        );
        error
    }

    struct PendingApplicationFixture {
        executor_launch: RunnerLaunchIntent,
        applier_policy: CompiledExecutionPolicy,
        change_set: ChangeSet,
        artifact: TaskIntegrationArtifactReference,
        request: ApplicationRequest,
        request_bytes: Vec<u8>,
        intent: EffectIntent,
        proposal: AgentEvent,
        evidence: ApplicationEvidence,
        rollback_reference: RollbackReferenceEvidence,
        observation: EffectObservation,
        terminal: AgentEvent,
    }

    #[allow(clippy::too_many_lines)] // The exact application/journal chain is intentionally visible.
    fn prepare_pending_application(ledger: &mut EventLedger) -> PendingApplicationFixture {
        let (spec, graph) = sprint_fixture();
        ledger
            .create_sprint(&spec, &graph, 1_000)
            .expect("persist application sprint");
        let (base, result, change_set, _, _, _, _, _) = completion_artifacts();
        ledger
            .persist_workspace_snapshot(&spec.sprint_id, &base)
            .expect("persist application base");
        ledger
            .persist_workspace_snapshot(&spec.sprint_id, &result)
            .expect("persist application result");
        ledger
            .persist_change_set(&spec.sprint_id, &change_set)
            .expect("persist application change set");

        let applier_policy = compiled_test_policy("pending-application-applier-policy");
        let executor_launch = runner_launch(
            "launch-pending-application-executor",
            "session-pending-application-executor",
            RunnerSessionPurpose::Applier,
            None,
            &applier_policy,
            1_210,
        );
        admit_test_runner_launch(ledger, &executor_launch, &applier_policy);
        ledger
            .register_runner_session(&runner_session(&executor_launch, 1_250), &applier_policy)
            .expect("persist application executor session");

        let artifact = test_application_artifact(&change_set, "pending-application");
        let request = ApplicationRequest {
            contract_version: CONTRACT_VERSION,
            change_set: change_set.clone(),
            artifact: artifact.clone(),
        };
        let request_bytes = application_request_bytes(ledger, &change_set, &artifact);
        let intent = EffectIntent {
            contract_version: CONTRACT_VERSION,
            effect_id: "effect-pending-application".into(),
            idempotency_key: "key-pending-application".into(),
            sprint_id: spec.sprint_id,
            task_id: None,
            worker_id: None,
            worker_lease: None,
            causation_event_id: None,
            correlation_id: "correlation-pending-application".into(),
            kind: EffectKind::ApplyChangeSet,
            request_digest: Digest::sha256(&request_bytes),
            policy_hash: applier_policy.contract().policy_hash.clone(),
            input_snapshot: base.snapshot_id.clone(),
            created_at_unix_ms: 1_300,
        };
        let proposal = effect_proposal_event(
            &intent,
            ledger
                .next_sequence(&intent.sprint_id)
                .expect("application proposal sequence"),
            "event-pending-application-proposed",
        );
        ledger
            .record_runner_effect_intent(
                &intent,
                &request_bytes,
                &proposal,
                &executor_launch.session_id,
            )
            .expect("persist pending application intent");
        let receipt = ApplicationReceipt {
            contract_version: CONTRACT_VERSION,
            receipt_id: "receipt-pending-application".into(),
            sprint_id: intent.sprint_id.clone(),
            effect_id: intent.effect_id.clone(),
            observation_id: "observation-pending-application".into(),
            applier_session_id: executor_launch.session_id.clone(),
            transaction_id: "transaction-pending-application".into(),
            change_set_id: change_set.change_set_id.clone(),
            base_snapshot: base.snapshot_id.clone(),
            result_snapshot: result.snapshot_id.clone(),
            policy_hash: executor_launch.policy_hash.clone(),
            grant_hash: executor_launch.grant_hash.clone(),
            policy_version: executor_launch.policy_version,
            applied_operations_digest: change_set
                .applied_operations_digest()
                .expect("digest application operations"),
            touched_path_endpoints_digest: change_set
                .touched_path_endpoints_digest()
                .expect("digest application endpoints"),
            live_manifest_digest: digest('9'),
            applied_at_unix_ms: 1_450,
        };
        let evidence = ApplicationEvidence {
            contract_version: CONTRACT_VERSION,
            validation: crate::ApplicationValidationEvidence {
                mode: ApplicationValidationMode::DirectEffectResponse,
                runner_launch_id: executor_launch.launch_id.clone(),
                runner_session_id: executor_launch.session_id.clone(),
                policy_hash: executor_launch.policy_hash.clone(),
                grant_hash: executor_launch.grant_hash.clone(),
                policy_version: executor_launch.policy_version,
                private_state_digest: executor_launch.private_state_digest.clone(),
            },
            receipt,
        };
        let evidence_bytes =
            encode("application evidence", &evidence).expect("encode application evidence");
        let observation = effect_observation(
            &intent,
            &evidence.receipt.observation_id,
            EffectOutcome::Succeeded {
                evidence_digest: Digest::sha256(&evidence_bytes),
            },
            evidence.receipt.applied_at_unix_ms,
        );
        let terminal = effect_terminal_event(
            &intent,
            &proposal.event_id,
            &observation,
            ledger
                .next_sequence(&intent.sprint_id)
                .expect("application terminal sequence"),
            "event-pending-application-finished",
        );
        let reopened_artifacts_bytes = b"pending application rollback artifacts".to_vec();
        let rollback_reference = RollbackReferenceEvidence {
            reference: RollbackReference {
                contract_version: CONTRACT_VERSION,
                reference_id: "reference-pending-application".into(),
                sprint_id: evidence.receipt.sprint_id.clone(),
                application_receipt_id: evidence.receipt.receipt_id.clone(),
                transaction_id: evidence.receipt.transaction_id.clone(),
                journal_binding_digest: evidence
                    .receipt
                    .journal_binding_digest()
                    .expect("digest application journal binding"),
                base_snapshot: base.snapshot_id,
                touched_target_set_digest: change_set
                    .touched_target_set_digest()
                    .expect("digest application target set"),
                reopened_artifacts_digest: Digest::sha256(&reopened_artifacts_bytes),
                validated_at_unix_ms: 1_460,
            },
            reopened_artifacts_bytes,
        };
        PendingApplicationFixture {
            executor_launch,
            applier_policy,
            change_set,
            artifact,
            request,
            request_bytes,
            intent,
            proposal,
            evidence,
            rollback_reference,
            observation,
            terminal,
        }
    }

    #[allow(clippy::too_many_arguments)] // Recovery tests keep each authority dimension explicit.
    fn register_validation_runner(
        ledger: &mut EventLedger,
        baseline: &RunnerLaunchIntent,
        launch_id: &str,
        session_id: &str,
        purpose: RunnerSessionPurpose,
        policy: &CompiledExecutionPolicy,
        private_state_digest: Digest,
        created_at_unix_ms: u64,
        registered_at_unix_ms: u64,
    ) -> RunnerLaunchIntent {
        let mut launch = runner_launch(
            launch_id,
            session_id,
            purpose,
            None,
            policy,
            created_at_unix_ms,
        );
        launch.private_state_digest = private_state_digest;
        launch.runner_binary_digest = baseline.runner_binary_digest.clone();
        launch.protocol_digest = baseline.protocol_digest.clone();
        admit_test_runner_launch(ledger, &launch, policy);
        ledger
            .register_runner_session(&runner_session(&launch, registered_at_unix_ms), policy)
            .expect("persist validation session");
        launch
    }

    fn register_other_sprint_validator(
        ledger: &mut EventLedger,
        baseline: &RunnerLaunchIntent,
        policy: &CompiledExecutionPolicy,
        suffix: &str,
        created_at_unix_ms: u64,
        registered_at_unix_ms: u64,
    ) -> RunnerLaunchIntent {
        let (mut spec, mut graph) = sprint_fixture();
        spec.sprint_id = format!("sprint-{suffix}");
        spec.workspace_grant.grant_id = format!("grant-{suffix}");
        graph.graph_id = format!("graph-{suffix}");
        ledger
            .create_sprint(&spec, &graph, 1_000)
            .expect("persist validation's unrelated sprint");
        let (base, _, _, _, _, _, _, _) = completion_artifacts();
        ledger
            .persist_workspace_snapshot(&spec.sprint_id, &base)
            .expect("persist validation's unrelated base snapshot");
        let mut launch = runner_launch(
            &format!("launch-{suffix}"),
            &format!("session-{suffix}"),
            RunnerSessionPurpose::Applier,
            None,
            policy,
            created_at_unix_ms,
        );
        launch.sprint_id = spec.sprint_id;
        launch.private_state_digest = baseline.private_state_digest.clone();
        launch.runner_binary_digest = baseline.runner_binary_digest.clone();
        launch.protocol_digest = baseline.protocol_digest.clone();
        admit_test_runner_launch(ledger, &launch, policy);
        ledger
            .register_runner_session(&runner_session(&launch, registered_at_unix_ms), policy)
            .expect("persist unrelated-sprint validation session");
        launch
    }

    fn bind_application_recovery(
        pending: &mut PendingApplicationFixture,
        launch: &RunnerLaunchIntent,
    ) {
        pending.evidence.validation = crate::ApplicationValidationEvidence {
            mode: ApplicationValidationMode::RecoveryApplierReconciliation,
            runner_launch_id: launch.launch_id.clone(),
            runner_session_id: launch.session_id.clone(),
            policy_hash: launch.policy_hash.clone(),
            grant_hash: launch.grant_hash.clone(),
            policy_version: launch.policy_version,
            private_state_digest: launch.private_state_digest.clone(),
        };
    }

    fn matching_application_recovery(
        ledger: &mut EventLedger,
        pending: &PendingApplicationFixture,
        suffix: &str,
        created_at_unix_ms: u64,
        registered_at_unix_ms: u64,
    ) -> RunnerLaunchIntent {
        register_validation_runner(
            ledger,
            &pending.executor_launch,
            &format!("launch-application-{suffix}"),
            &format!("session-application-{suffix}"),
            RunnerSessionPurpose::Applier,
            &pending.applier_policy,
            pending.executor_launch.private_state_digest.clone(),
            created_at_unix_ms,
            registered_at_unix_ms,
        )
    }

    fn refresh_pending_application_digest(
        ledger: &EventLedger,
        pending: &mut PendingApplicationFixture,
    ) {
        let bytes = encode("application evidence", &pending.evidence)
            .expect("encode modified application evidence");
        pending.observation.outcome = EffectOutcome::Succeeded {
            evidence_digest: Digest::sha256(&bytes),
        };
        pending.terminal.sequence = ledger
            .next_sequence(&pending.observation.sprint_id)
            .expect("refresh application terminal sequence");
    }

    fn rejected_pending_application(
        configure: impl FnOnce(&mut EventLedger, &mut PendingApplicationFixture),
    ) -> LedgerError {
        let database = TestDatabase::new();
        let mut ledger = open_v21_test_ledger(&database);
        let mut pending = prepare_pending_application(&mut ledger);
        configure(&mut ledger, &mut pending);
        refresh_pending_application_digest(&ledger, &mut pending);
        let error = ledger
            .record_application_effect_observation_with_rollback(
                &pending.observation,
                &pending.terminal,
                &pending.evidence,
                &pending.rollback_reference,
            )
            .expect_err("invalid application validator must be rejected");
        assert_eq!(row_count(&ledger, "application_receipts"), 0);
        assert_eq!(row_count(&ledger, "rollback_references"), 0);
        assert!(
            ledger
                .load_effect(&pending.evidence.receipt.effect_id)
                .expect("load still-pending application")
                .observation
                .is_none()
        );
        error
    }

    struct PendingRollbackFixture {
        executor_launch: RunnerLaunchIntent,
        applier_policy: CompiledExecutionPolicy,
        evidence: RollbackEvidence,
        observation: EffectObservation,
        terminal: AgentEvent,
    }

    #[allow(clippy::too_many_lines)] // The application-to-rollback chain is intentionally visible.
    fn prepare_pending_rollback(ledger: &mut EventLedger) -> PendingRollbackFixture {
        let application = prepare_pending_application(ledger);
        ledger
            .record_application_effect_observation_with_rollback(
                &application.observation,
                &application.terminal,
                &application.evidence,
                &application.rollback_reference,
            )
            .expect("persist rollback test application");
        let application_receipt = &application.evidence.receipt;
        let request = RollbackRequest {
            contract_version: CONTRACT_VERSION,
            sprint_id: application_receipt.sprint_id.clone(),
            application_receipt_id: application_receipt.receipt_id.clone(),
            application_transaction_id: application_receipt.transaction_id.clone(),
            rollback_reference_id: application
                .rollback_reference
                .reference
                .reference_id
                .clone(),
        };
        let request_bytes = encode("rollback request", &request).expect("encode rollback request");
        let intent = EffectIntent {
            contract_version: CONTRACT_VERSION,
            effect_id: "effect-pending-rollback".into(),
            idempotency_key: "key-pending-rollback".into(),
            sprint_id: application_receipt.sprint_id.clone(),
            task_id: None,
            worker_id: None,
            worker_lease: None,
            causation_event_id: None,
            correlation_id: "correlation-pending-rollback".into(),
            kind: EffectKind::RollbackChangeSet,
            request_digest: Digest::sha256(&request_bytes),
            policy_hash: application.executor_launch.policy_hash.clone(),
            input_snapshot: application_receipt.result_snapshot.clone(),
            created_at_unix_ms: 1_500,
        };
        let proposal = effect_proposal_event(
            &intent,
            ledger
                .next_sequence(&intent.sprint_id)
                .expect("rollback proposal sequence"),
            "event-pending-rollback-proposed",
        );
        ledger
            .record_runner_effect_intent(
                &intent,
                &request_bytes,
                &proposal,
                &application.executor_launch.session_id,
            )
            .expect("persist pending rollback intent");
        let receipt = RollbackReceipt {
            contract_version: CONTRACT_VERSION,
            receipt_id: "receipt-pending-rollback".into(),
            sprint_id: intent.sprint_id.clone(),
            effect_id: intent.effect_id.clone(),
            observation_id: "observation-pending-rollback".into(),
            application_receipt_id: application_receipt.receipt_id.clone(),
            application_transaction_id: application_receipt.transaction_id.clone(),
            restored_base_snapshot: application_receipt.base_snapshot.clone(),
            restored_endpoints_digest: application
                .change_set
                .restored_base_endpoints_digest()
                .expect("digest restored endpoints"),
            live_manifest_digest: digest('8'),
            unresolved_conflicts: 0,
            completed_at_unix_ms: 1_600,
        };
        let evidence = RollbackEvidence {
            contract_version: CONTRACT_VERSION,
            validation: crate::RollbackValidationEvidence {
                mode: RollbackValidationMode::DirectEffectResponse,
                runner_launch_id: application.executor_launch.launch_id.clone(),
                runner_session_id: application.executor_launch.session_id.clone(),
                policy_hash: application.executor_launch.policy_hash.clone(),
                grant_hash: application.executor_launch.grant_hash.clone(),
                policy_version: application.executor_launch.policy_version,
                private_state_digest: application.executor_launch.private_state_digest.clone(),
            },
            receipt,
        };
        let evidence_bytes =
            encode("rollback evidence", &evidence).expect("encode rollback evidence");
        let observation = effect_observation(
            &intent,
            &evidence.receipt.observation_id,
            EffectOutcome::Succeeded {
                evidence_digest: Digest::sha256(&evidence_bytes),
            },
            evidence.receipt.completed_at_unix_ms,
        );
        let terminal = effect_terminal_event(
            &intent,
            &proposal.event_id,
            &observation,
            ledger
                .next_sequence(&intent.sprint_id)
                .expect("rollback terminal sequence"),
            "event-pending-rollback-finished",
        );
        PendingRollbackFixture {
            executor_launch: application.executor_launch,
            applier_policy: application.applier_policy,
            evidence,
            observation,
            terminal,
        }
    }

    fn bind_rollback_recovery(pending: &mut PendingRollbackFixture, launch: &RunnerLaunchIntent) {
        pending.evidence.validation = crate::RollbackValidationEvidence {
            mode: RollbackValidationMode::RecoveryApplierReconciliation,
            runner_launch_id: launch.launch_id.clone(),
            runner_session_id: launch.session_id.clone(),
            policy_hash: launch.policy_hash.clone(),
            grant_hash: launch.grant_hash.clone(),
            policy_version: launch.policy_version,
            private_state_digest: launch.private_state_digest.clone(),
        };
    }

    fn matching_rollback_recovery(
        ledger: &mut EventLedger,
        pending: &PendingRollbackFixture,
        suffix: &str,
        created_at_unix_ms: u64,
        registered_at_unix_ms: u64,
    ) -> RunnerLaunchIntent {
        register_validation_runner(
            ledger,
            &pending.executor_launch,
            &format!("launch-rollback-{suffix}"),
            &format!("session-rollback-{suffix}"),
            RunnerSessionPurpose::Applier,
            &pending.applier_policy,
            pending.executor_launch.private_state_digest.clone(),
            created_at_unix_ms,
            registered_at_unix_ms,
        )
    }

    fn refresh_pending_rollback_digest(ledger: &EventLedger, pending: &mut PendingRollbackFixture) {
        let bytes = encode("rollback evidence", &pending.evidence)
            .expect("encode modified rollback evidence");
        pending.observation.outcome = EffectOutcome::Succeeded {
            evidence_digest: Digest::sha256(&bytes),
        };
        pending.terminal.sequence = ledger
            .next_sequence(&pending.observation.sprint_id)
            .expect("refresh rollback terminal sequence");
    }

    fn rejected_pending_rollback(
        configure: impl FnOnce(&mut EventLedger, &mut PendingRollbackFixture),
    ) -> LedgerError {
        let database = TestDatabase::new();
        let mut ledger = open_v21_test_ledger(&database);
        let mut pending = prepare_pending_rollback(&mut ledger);
        configure(&mut ledger, &mut pending);
        refresh_pending_rollback_digest(&ledger, &mut pending);
        let error = ledger
            .record_rollback_effect_observation(
                &pending.observation,
                &pending.terminal,
                &pending.evidence,
            )
            .expect_err("invalid rollback validator must be rejected");
        assert_eq!(row_count(&ledger, "rollback_receipts"), 0);
        assert!(
            ledger
                .load_effect(&pending.evidence.receipt.effect_id)
                .expect("load still-pending rollback")
                .observation
                .is_none()
        );
        error
    }

    fn prepare_completion_evidence(
        ledger: &mut EventLedger,
    ) -> (FinalReport, CompletionReceipt, AgentEvent) {
        prepare_completion_evidence_with_recovery(ledger, false)
    }

    fn prepare_recovery_completion_evidence(
        ledger: &mut EventLedger,
    ) -> (FinalReport, CompletionReceipt, AgentEvent) {
        prepare_completion_evidence_with_recovery(ledger, true)
    }

    #[allow(clippy::too_many_lines)] // The end-to-end receipt chain is deliberately visible.
    fn prepare_completion_evidence_with_recovery(
        ledger: &mut EventLedger,
        use_recovery_validator: bool,
    ) -> (FinalReport, CompletionReceipt, AgentEvent) {
        let (spec, graph) = sprint_fixture();
        ledger
            .create_sprint(&spec, &graph, 1_000)
            .expect("persist sprint");
        let (
            base,
            final_snapshot,
            change_set,
            mut verification,
            acceptance,
            report,
            mut receipt,
            mut event,
        ) = completion_artifacts();
        ledger
            .persist_workspace_snapshot("sprint-1", &base)
            .expect("persist rollback snapshot");
        ledger
            .persist_workspace_snapshot("sprint-1", &final_snapshot)
            .expect("persist final snapshot");
        ledger
            .persist_change_set("sprint-1", &change_set)
            .expect("persist change set");

        let worker_policy = compiled_shadow_test_policy("policy-worker");
        let final_policy = compiled_test_policy("policy-final");
        let applier_policy = compiled_test_policy("policy-applier");
        let command_domain_cleanup_installed = ledger
            .connection
            .query_row(
                "SELECT EXISTS(
                     SELECT 1 FROM sqlite_schema
                     WHERE type = 'table' AND name = 'command_domain_cleanup_proofs'
                 )",
                [],
                |row| row.get::<_, bool>(0),
            )
            .expect("inspect command-domain cleanup schema");
        let worker_launch = runner_launch(
            "launch-worker",
            "session-worker",
            RunnerSessionPurpose::TaskWorker,
            Some("worker-1"),
            &worker_policy,
            1_210,
        );
        let final_launch = runner_launch(
            "launch-final",
            "session-final",
            RunnerSessionPurpose::FinalVerifier,
            None,
            &final_policy,
            1_220,
        );
        let applier_launch = runner_launch(
            "launch-applier",
            "session-applier",
            RunnerSessionPurpose::Applier,
            None,
            &applier_policy,
            1_230,
        );
        for (launch, policy) in [
            (&worker_launch, &worker_policy),
            (&final_launch, &final_policy),
            (&applier_launch, &applier_policy),
        ] {
            admit_test_runner_launch(ledger, launch, policy);
            ledger
                .register_runner_session(&runner_session(launch, 1_300), policy)
                .expect("persist initialized session");
        }

        let task_verification = VerificationReceipt {
            receipt_id: "verify-task-1".into(),
            sprint_id: "sprint-1".into(),
            task_id: Some("task-1".into()),
            snapshot_id: final_snapshot.snapshot_id.clone(),
            command: verification.command.clone(),
            policy_hash: worker_policy.contract().policy_hash.clone(),
            exit_status: Some(0),
            termination: Some(CommandTerminationV1::Exited { code: 0 }),
            output_digest: digest('0'),
            duration_ms: 25,
            finished_at_unix_ms: 1_400,
        };
        let task_verification_evidence = persist_verification_evidence(
            ledger,
            &worker_launch,
            task_verification,
            b"task verification passed".to_vec(),
            1_350,
        );
        if command_domain_cleanup_installed {
            let task_command_binding = ledger
                .load_command_domain_effect_bindings(
                    &worker_launch.sprint_id,
                    &worker_launch.launch_id,
                    &worker_launch.session_id,
                )
                .expect("load completion task command binding")
                .into_iter()
                .find(|binding| binding.effect_id == task_verification_evidence.effect_id)
                .expect("find completion task command binding");
            if ledger
                .connection
                .pragma_query_value(None, "user_version", |row| row.get::<_, i64>(0))
                .expect("inspect completion capture schema")
                >= 27
            {
                ledger
                    .load_command_domain_cleanup_proof(&task_command_binding.effect_id)
                    .expect("v27 formal terminal already committed command cleanup");
            } else {
                ledger
                    .record_command_domain_cleanup_proof(&command_domain_proof(
                        &task_command_binding,
                        "command-cleanup-task-1",
                        CommandDomainBackend::LinuxCgroupV2,
                        CommandDomainCleanupDisposition::ReapedZeroSurvivors,
                        1_510,
                    ))
                    .expect("persist historical completion task command cleanup");
            }
        }

        let integration_artifact = crate::TaskIntegrationArtifactReference {
            format_version: 1,
            artifact_digest: Digest::sha256(b"stage-bundle-task-1"),
            change_set_id: change_set.change_set_id.clone(),
            base_snapshot: base.snapshot_id.clone(),
            result_snapshot: final_snapshot.snapshot_id.clone(),
        };
        let integration_request = TaskIntegrationRequest {
            contract_version: CONTRACT_VERSION,
            change_set: change_set.clone(),
            artifact: integration_artifact.clone(),
        };
        let integration_request_bytes = encode("task integration request", &integration_request)
            .expect("encode integration request");
        let current_attempt_authority =
            task_attempt_authority::schema_is_installed(&ledger.connection)
                .expect("inspect completion task-attempt schema")
                .then(|| {
                    let attempt = ledger
                        .load_task_attempt(
                            &worker_launch
                                .worker_lease
                                .as_ref()
                                .expect("completion worker lease")
                                .lease_id,
                        )
                        .expect("load completion task attempt");
                    let candidate_id = ledger
                        .connection
                        .query_row(
                            "SELECT boundary_id FROM task_attempt_candidate_boundaries
                             WHERE attempt_id = ?1",
                            [&attempt.attempt_id],
                            |row| row.get::<_, String>(0),
                        )
                        .expect("load completion candidate boundary identity");
                    let candidate = ledger
                        .load_task_attempt_candidate_boundary(&candidate_id)
                        .expect("load completion candidate boundary");
                    (attempt, candidate)
                });
        let integration_intent = EffectIntent {
            contract_version: CONTRACT_VERSION,
            effect_id: "effect-integration-task-1".into(),
            idempotency_key: "key-integration-task-1".into(),
            sprint_id: "sprint-1".into(),
            task_id: Some("task-1".into()),
            worker_id: Some("worker-1".into()),
            worker_lease: worker_launch.worker_lease.clone(),
            causation_event_id: current_attempt_authority
                .as_ref()
                .map(|(_, candidate)| candidate.transition_event_id.clone()),
            correlation_id: "correlation-integration-task-1".into(),
            kind: EffectKind::IntegrateChangeSet,
            request_digest: Digest::sha256(&integration_request_bytes),
            policy_hash: worker_policy.contract().policy_hash.clone(),
            input_snapshot: base.snapshot_id.clone(),
            created_at_unix_ms: 1_410,
        };
        let integration_proposal = effect_proposal_event(
            &integration_intent,
            ledger
                .next_sequence("sprint-1")
                .expect("integration proposal sequence"),
            "event-integration-task-1-proposed",
        );
        let claimed_dispatch_schema =
            runner_effect_dispatch_claim_schema_is_installed(&ledger.connection)
                .expect("inspect runner dispatch claim schema for completion fixture");
        let integration_permit = if let Some((_, candidate)) = &current_attempt_authority {
            let integration_admission = TaskAttemptIntegrationAdmission {
                contract_version: CONTRACT_VERSION,
                admission_id: "admission-integration-task-1".into(),
                candidate_boundary: candidate.clone(),
                effect_id: integration_intent.effect_id.clone(),
                runner_launch_id: worker_launch.launch_id.clone(),
                runner_session_id: worker_launch.session_id.clone(),
                input_snapshot: base.snapshot_id.clone(),
                result_snapshot: final_snapshot.snapshot_id.clone(),
                admitted_at_unix_ms: integration_intent.created_at_unix_ms,
            };
            if claimed_dispatch_schema {
                let permit = match ledger
                    .admit_task_attempt_integration_for_dispatch(
                        &integration_admission,
                        &integration_intent,
                        &integration_request,
                        &integration_proposal,
                    )
                    .expect("persist current task integration dispatch admission")
                {
                    TaskIntegrationDispatchAdmission::Fresh { permit, .. } => permit,
                    TaskIntegrationDispatchAdmission::Existing { .. } => {
                        panic!("new completion integration admission must be Fresh")
                    }
                };
                Some(permit)
            } else {
                ledger
                    .admit_task_attempt_integration(
                        &integration_admission,
                        &integration_intent,
                        &integration_request,
                        &integration_proposal,
                    )
                    .expect("persist historical task integration admission");
                None
            }
        } else {
            ledger
                .record_runner_effect_intent(
                    &integration_intent,
                    &integration_request_bytes,
                    &integration_proposal,
                    &worker_launch.session_id,
                )
                .expect("persist historical task integration intent");
            None
        };
        let integration_receipt = TaskIntegrationReceipt {
            contract_version: CONTRACT_VERSION,
            receipt_id: "integration-task-1".into(),
            sprint_id: "sprint-1".into(),
            task_id: "task-1".into(),
            worker_id: "worker-1".into(),
            worker_lease: worker_launch.worker_lease.clone(),
            worker_launch_id: worker_launch.launch_id.clone(),
            worker_session_id: worker_launch.session_id.clone(),
            worker_policy_hash: worker_policy.contract().policy_hash.clone(),
            effect_id: integration_intent.effect_id.clone(),
            observation_id: "observation-integration-task-1".into(),
            change_set_id: change_set.change_set_id.clone(),
            input_snapshot: base.snapshot_id.clone(),
            result_snapshot: final_snapshot.snapshot_id.clone(),
            task_verification_receipt_ids: vec!["verify-task-1".into()],
            integration_ordinal: 0,
            integrated_at_unix_ms: 1_450,
        };
        let integration_evidence = TaskIntegrationEvidence {
            contract_version: CONTRACT_VERSION,
            artifact: integration_artifact.clone(),
            validation: crate::TaskIntegrationValidationEvidence {
                mode: TaskIntegrationValidationMode::WorkerPublication,
                runner_launch_id: worker_launch.launch_id.clone(),
                runner_session_id: worker_launch.session_id.clone(),
                policy_hash: worker_launch.policy_hash.clone(),
                grant_hash: worker_launch.grant_hash.clone(),
                private_state_digest: worker_launch.private_state_digest.clone(),
            },
            receipt: integration_receipt.clone(),
        };
        let integration_evidence_bytes = encode("task integration evidence", &integration_evidence)
            .expect("encode integration evidence");
        let integration_observation = effect_observation(
            &integration_intent,
            &integration_receipt.observation_id,
            EffectOutcome::Succeeded {
                evidence_digest: Digest::sha256(&integration_evidence_bytes),
            },
            integration_receipt.integrated_at_unix_ms,
        );
        let integration_terminal = effect_terminal_event(
            &integration_intent,
            &integration_proposal.event_id,
            &integration_observation,
            ledger
                .next_sequence("sprint-1")
                .expect("integration terminal sequence"),
            "event-integration-task-1-finished",
        );
        let integration_attempt_authority =
            current_attempt_authority.map(|(attempt, candidate)| {
                let integration_disposed_at_unix_ms =
                    integration_receipt.integrated_at_unix_ms + 10;
                let integration_transition = AgentEvent {
                    contract_version: CONTRACT_VERSION,
                    sequence: integration_terminal.sequence + 1,
                    event_id: "event-integration-task-1-integrated".into(),
                    sprint_id: integration_receipt.sprint_id.clone(),
                    task_id: Some(integration_receipt.task_id.clone()),
                    worker_id: Some(integration_receipt.worker_id.clone()),
                    causation_id: Some(integration_terminal.event_id.clone()),
                    correlation_id: integration_intent.correlation_id.clone(),
                    policy_hash: Some(worker_launch.policy_hash.clone()),
                    occurred_at_unix_ms: integration_disposed_at_unix_ms,
                    payload: AgentEventKind::TaskStateChanged {
                        from: "Candidate".into(),
                        to: "Integrated".into(),
                    },
                };
                let integration_disposition =
                    TaskAttemptDisposition::Integrated(crate::TaskAttemptIntegratedDisposition {
                        metadata: TaskAttemptDispositionMetadata {
                            contract_version: CONTRACT_VERSION,
                            disposition_id: "disposition-integration-task-1".into(),
                            attempt,
                            from_state: TaskState::Candidate,
                            state_transition_event_id: integration_transition.event_id.clone(),
                            disposed_at_unix_ms: integration_disposed_at_unix_ms,
                        },
                        candidate_boundary: candidate,
                        integration_receipt: integration_receipt.clone(),
                        evidence: crate::TaskAttemptEvidence::new(
                            "evidence-disposition-integration-task-1".into(),
                            crate::TaskAttemptEvidenceKind::Integrated,
                            integration_evidence_bytes.clone(),
                        )
                        .expect("construct completion integration disposition evidence"),
                    });
                (integration_disposition, integration_transition)
            });
        match (&integration_attempt_authority, integration_permit) {
            (Some((integration_disposition, integration_transition)), Some(permit)) => {
                let session = ledger
                    .load_runner_session(&integration_intent.sprint_id, &worker_launch.session_id)
                    .expect("load completion integration runner session");
                let (_, transport) = ledger
                    .claim_runner_effect_dispatch(
                        FreshRunnerEffectDispatchPermit::TaskIntegration(permit),
                        OPAQUE_RUNNER_TRANSPORT_REQUEST_BYTES,
                    )
                    .expect("claim completion integration dispatch");
                let authority = transport
                    .validate_transport_request(
                        &integration_intent,
                        &integration_request_bytes,
                        &worker_launch,
                        &session,
                        None,
                        OPAQUE_RUNNER_TRANSPORT_REQUEST_BYTES,
                    )
                    .expect("validate completion integration transport");
                ledger
                    .integrate_claimed_task_attempt(
                        authority,
                        integration_disposition,
                        &integration_observation,
                        &integration_terminal,
                        &integration_evidence,
                        integration_transition,
                    )
                    .expect("persist claimed current task integration proof");
            }
            (Some((integration_disposition, integration_transition)), None) => {
                ledger
                    .integrate_task_attempt(
                        integration_disposition,
                        &integration_observation,
                        &integration_terminal,
                        &integration_evidence,
                        integration_transition,
                    )
                    .expect("persist historical task integration proof");
            }
            (None, None) => {
                ledger
                    .record_task_integration_effect_observation(
                        &integration_observation,
                        &integration_terminal,
                        &integration_evidence,
                    )
                    .expect("persist historical task integration proof");
            }
            (None, Some(_)) => panic!("integration permit requires task-attempt authority"),
        }

        // Current final-verification admission is derived from the complete
        // TaskDone chain, including zero-survivor worker cleanup. Close that
        // authority before entering the sprint phase instead of manufacturing
        // a legacy session-bound command while the task remains live.
        if let Some((integration_disposition, _)) = &integration_attempt_authority {
            let worker_cleanup =
                cleanup_terminal_record(ledger, &worker_launch, "cleanup-worker", 1_465);
            ledger
                .with_integrated_task_attempt_cleanup_exclusion(
                    &integration_disposition.metadata().disposition_id,
                    |claim| {
                        assert_eq!(claim.next_event_sequence(), worker_cleanup.event.sequence);
                        Ok(worker_cleanup)
                    },
                )
                .expect("persist Integrated task-attempt cleanup and release");
        } else {
            persist_cleanup_evidence(
                ledger,
                &worker_launch,
                &final_snapshot.snapshot_id,
                "cleanup-worker",
                WorkerCleanupBackend::LinuxCgroupV2,
                1_460,
                1_465,
            );
        }

        verification.policy_hash = final_policy.contract().policy_hash.clone();
        let final_verification_evidence = persist_verification_evidence(
            ledger,
            &final_launch,
            verification,
            b"final verification passed".to_vec(),
            1_470,
        );
        if command_domain_cleanup_installed {
            let final_command_binding = ledger
                .load_command_domain_effect_bindings(
                    &final_launch.sprint_id,
                    &final_launch.launch_id,
                    &final_launch.session_id,
                )
                .expect("load completion final command binding")
                .into_iter()
                .find(|binding| binding.effect_id == final_verification_evidence.effect_id)
                .expect("find completion final command binding");
            if ledger
                .connection
                .pragma_query_value(None, "user_version", |row| row.get::<_, i64>(0))
                .expect("inspect completion final capture schema")
                >= 27
            {
                ledger
                    .load_command_domain_cleanup_proof(&final_command_binding.effect_id)
                    .expect("v27 final terminal already committed command cleanup");
            } else {
                ledger
                    .record_command_domain_cleanup_proof(&command_domain_proof(
                        &final_command_binding,
                        "command-cleanup-final",
                        CommandDomainBackend::LinuxCgroupV2,
                        CommandDomainCleanupDisposition::ReapedZeroSurvivors,
                        1_530,
                    ))
                    .expect("persist historical completion final command cleanup");
            }
        }
        let verification = final_verification_evidence.verification;
        assert_eq!(verification.receipt_id, "verify-final");
        ledger
            .persist_acceptance_receipt(&acceptance)
            .expect("persist acceptance");

        persist_cleanup_evidence(
            ledger,
            &final_launch,
            &final_snapshot.snapshot_id,
            "cleanup-final",
            WorkerCleanupBackend::LinuxCgroupV2,
            1_530,
            1_540,
        );

        let application_request =
            application_request_bytes(ledger, &change_set, &integration_artifact);
        let application_intent = EffectIntent {
            contract_version: CONTRACT_VERSION,
            effect_id: "effect-application".into(),
            idempotency_key: "key-application".into(),
            sprint_id: "sprint-1".into(),
            task_id: None,
            worker_id: None,
            worker_lease: None,
            causation_event_id: None,
            correlation_id: "correlation-application".into(),
            kind: EffectKind::ApplyChangeSet,
            request_digest: Digest::sha256(&application_request),
            policy_hash: applier_policy.contract().policy_hash.clone(),
            input_snapshot: base.snapshot_id.clone(),
            created_at_unix_ms: 1_650,
        };
        let application_proposal = effect_proposal_event(
            &application_intent,
            ledger
                .next_sequence("sprint-1")
                .expect("application proposal sequence"),
            "event-application-proposed",
        );
        ledger
            .record_runner_effect_intent(
                &application_intent,
                &application_request,
                &application_proposal,
                &applier_launch.session_id,
            )
            .expect("persist application intent");
        let recovery_launch = use_recovery_validator.then(|| {
            register_validation_runner(
                ledger,
                &applier_launch,
                "launch-application-recovery-completion",
                "session-application-recovery-completion",
                RunnerSessionPurpose::Applier,
                &applier_policy,
                applier_launch.private_state_digest.clone(),
                1_660,
                1_680,
            )
        });
        let application_receipt = ApplicationReceipt {
            contract_version: CONTRACT_VERSION,
            receipt_id: "application-1".into(),
            sprint_id: "sprint-1".into(),
            effect_id: application_intent.effect_id.clone(),
            observation_id: "observation-application".into(),
            applier_session_id: applier_launch.session_id.clone(),
            transaction_id: "transaction-application".into(),
            change_set_id: change_set.change_set_id.clone(),
            base_snapshot: base.snapshot_id.clone(),
            result_snapshot: final_snapshot.snapshot_id.clone(),
            policy_hash: applier_policy.contract().policy_hash.clone(),
            grant_hash: digest('a'),
            policy_version: 1,
            applied_operations_digest: change_set
                .applied_operations_digest()
                .expect("digest applied operations"),
            touched_path_endpoints_digest: change_set
                .touched_path_endpoints_digest()
                .expect("digest touched endpoints"),
            live_manifest_digest: digest('9'),
            applied_at_unix_ms: 1_700,
        };
        let validation_launch = recovery_launch.as_ref().unwrap_or(&applier_launch);
        let application_evidence = ApplicationEvidence {
            contract_version: CONTRACT_VERSION,
            validation: crate::ApplicationValidationEvidence {
                mode: if use_recovery_validator {
                    ApplicationValidationMode::RecoveryApplierReconciliation
                } else {
                    ApplicationValidationMode::DirectEffectResponse
                },
                runner_launch_id: validation_launch.launch_id.clone(),
                runner_session_id: validation_launch.session_id.clone(),
                policy_hash: validation_launch.policy_hash.clone(),
                grant_hash: validation_launch.grant_hash.clone(),
                policy_version: validation_launch.policy_version,
                private_state_digest: validation_launch.private_state_digest.clone(),
            },
            receipt: application_receipt.clone(),
        };
        let application_evidence_bytes = encode("application evidence", &application_evidence)
            .expect("encode application evidence");
        let application_observation = effect_observation(
            &application_intent,
            &application_receipt.observation_id,
            EffectOutcome::Succeeded {
                evidence_digest: Digest::sha256(&application_evidence_bytes),
            },
            application_receipt.applied_at_unix_ms,
        );
        let application_terminal = effect_terminal_event(
            &application_intent,
            &application_proposal.event_id,
            &application_observation,
            ledger
                .next_sequence("sprint-1")
                .expect("application terminal sequence"),
            "event-application-finished",
        );
        let reopened_artifacts_bytes = b"canonical reopened rollback artifacts".to_vec();
        let rollback_reference = RollbackReferenceEvidence {
            reference: RollbackReference {
                contract_version: CONTRACT_VERSION,
                reference_id: "rollback-reference-1".into(),
                sprint_id: "sprint-1".into(),
                application_receipt_id: application_receipt.receipt_id.clone(),
                transaction_id: application_receipt.transaction_id.clone(),
                journal_binding_digest: application_receipt
                    .journal_binding_digest()
                    .expect("digest journal binding"),
                base_snapshot: base.snapshot_id.clone(),
                touched_target_set_digest: change_set
                    .touched_target_set_digest()
                    .expect("digest touched target set"),
                reopened_artifacts_digest: Digest::sha256(&reopened_artifacts_bytes),
                validated_at_unix_ms: 1_750,
            },
            reopened_artifacts_bytes,
        };
        ledger
            .record_application_effect_observation_with_rollback(
                &application_observation,
                &application_terminal,
                &application_evidence,
                &rollback_reference,
            )
            .expect("atomically persist application and reopened rollback artifacts");

        persist_cleanup_evidence(
            ledger,
            &applier_launch,
            &final_snapshot.snapshot_id,
            "cleanup-applier",
            WorkerCleanupBackend::TrustedApplierDirectChildWait,
            1_760,
            1_800,
        );
        if let Some(recovery_launch) = &recovery_launch {
            persist_cleanup_evidence(
                ledger,
                recovery_launch,
                &final_snapshot.snapshot_id,
                "cleanup-application-recovery",
                WorkerCleanupBackend::TrustedApplierDirectChildWait,
                1_810,
                1_850,
            );
            receipt
                .worker_cleanup_receipt_ids
                .push("cleanup-application-recovery".into());
            receipt.worker_cleanup_receipt_ids.sort();
        }
        event.sequence = ledger
            .next_sequence("sprint-1")
            .expect("completion event sequence");
        (report, receipt, event)
    }

    struct V21FinalVerificationFixture {
        admission: SprintFinalVerificationAdmission,
        phase_event: AgentEvent,
        intent: EffectIntent,
        proposed_event: AgentEvent,
        launch: RunnerLaunchIntent,
        session: RunnerSessionPolicyRecord,
        command_bytes: Vec<u8>,
        capture_intent: CommandOutputCaptureIntentV1,
    }

    fn prepare_v21_final_verification_fixture(
        ledger: &mut EventLedger,
    ) -> V21FinalVerificationFixture {
        let _ = prepare_completion_evidence(ledger);
        build_v21_final_verification_fixture(ledger, digest('c'))
    }

    fn build_v21_final_verification_fixture(
        ledger: &mut EventLedger,
        final_snapshot: Digest,
    ) -> V21FinalVerificationFixture {
        build_v21_final_verification_fixture_with_session(ledger, final_snapshot, true)
    }

    #[allow(
        clippy::too_many_lines,
        reason = "the v21 fixture keeps launch, cleanup, preparation, optional session, and phase contracts contiguous"
    )]
    fn build_v21_final_verification_fixture_with_session(
        ledger: &mut EventLedger,
        final_snapshot: Digest,
        register_session: bool,
    ) -> V21FinalVerificationFixture {
        let policy = compiled_test_policy("policy-v21-final");
        let launch = runner_launch(
            "launch-v21-final",
            "session-v21-final",
            RunnerSessionPurpose::FinalVerifier,
            None,
            &policy,
            2_100,
        );
        let (mut cleanup_intent, _, cleanup_request_bytes, cleanup_event) =
            test_runner_launch_cleanup_contracts(
                ledger,
                &launch,
                WorkerCleanupBackend::LinuxCgroupV2,
            )
            .expect("build v21 final-verifier cleanup contracts");
        cleanup_intent.input_snapshot = final_snapshot.clone();
        let cleanup_event = effect_proposal_event(
            &cleanup_intent,
            cleanup_event.sequence,
            &cleanup_event.event_id,
        );
        ledger
            .admit_runner_launch_with_cleanup(
                &launch,
                &policy,
                &cleanup_intent,
                &cleanup_request_bytes,
                &cleanup_event,
            )
            .expect("admit v21 final-verifier launch and exact-snapshot cleanup");
        let session = runner_session(&launch, 2_120);
        if register_session {
            ledger
                .register_runner_session(&session, &policy)
                .expect("register v21 final-verifier session");
        }
        let command = CommandSpec {
            program: "cargo".into(),
            arguments: vec!["test".into(), "--locked".into()],
            working_directory: PathBuf::new(),
        };
        let command_bytes = encode("v21 final-verification command", &command)
            .expect("encode v21 final-verification command");
        let phase_sequence = ledger
            .next_sequence("sprint-1")
            .expect("v21 final phase sequence");
        let phase_event = AgentEvent {
            contract_version: CONTRACT_VERSION,
            sequence: phase_sequence,
            event_id: "event-v21-final-phase".into(),
            sprint_id: "sprint-1".into(),
            task_id: None,
            worker_id: None,
            causation_id: None,
            correlation_id: "correlation-v21-final".into(),
            policy_hash: Some(launch.policy_hash.clone()),
            occurred_at_unix_ms: 2_190,
            payload: AgentEventKind::SprintStateChanged {
                from: "Running".into(),
                to: "FinalVerification".into(),
            },
        };
        let intent = EffectIntent {
            contract_version: CONTRACT_VERSION,
            effect_id: "effect-v21-final".into(),
            idempotency_key: "key-v21-final".into(),
            sprint_id: "sprint-1".into(),
            task_id: None,
            worker_id: None,
            worker_lease: None,
            causation_event_id: Some(phase_event.event_id.clone()),
            correlation_id: phase_event.correlation_id.clone(),
            kind: EffectKind::RunCommand,
            request_digest: Digest::sha256(&command_bytes),
            policy_hash: launch.policy_hash.clone(),
            input_snapshot: final_snapshot,
            created_at_unix_ms: 2_200,
        };
        let proposed_event =
            effect_proposal_event(&intent, phase_sequence + 1, "event-v21-final-proposed");
        let admission = SprintFinalVerificationAdmission {
            contract_version: CONTRACT_VERSION,
            admission_id: "admission-v21-final".into(),
            sprint_id: intent.sprint_id.clone(),
            sprint_phase_event_id: phase_event.event_id.clone(),
            final_snapshot: intent.input_snapshot.clone(),
            effect_id: intent.effect_id.clone(),
            runner_launch_id: launch.launch_id.clone(),
            runner_session_id: session.session_id.clone(),
            command,
            admitted_at_unix_ms: intent.created_at_unix_ms,
        };
        let capture_intent =
            v27_test_capture_intent(&intent, &launch, &session, "v21-final-verification");
        V21FinalVerificationFixture {
            admission,
            phase_event,
            intent,
            proposed_event,
            launch,
            session,
            command_bytes,
            capture_intent,
        }
    }

    fn prepare_current_unadmitted_final_verifier_fixture(
        register_session: bool,
        cleanup_snapshot: Digest,
    ) -> (V15CandidateFixture, V21FinalVerificationFixture) {
        prepare_current_unadmitted_final_verifier_fixture_with_task_done(
            register_session,
            cleanup_snapshot,
            true,
        )
    }

    fn prepare_current_unadmitted_final_verifier_fixture_with_task_done(
        register_session: bool,
        cleanup_snapshot: Digest,
        close_task_done: bool,
    ) -> (V15CandidateFixture, V21FinalVerificationFixture) {
        prepare_current_unadmitted_final_verifier_fixture_with_task_done_and_result(
            register_session,
            cleanup_snapshot,
            close_task_done,
            true,
        )
    }

    fn prepare_current_unadmitted_final_verifier_fixture_with_task_done_and_result(
        register_session: bool,
        cleanup_snapshot: Digest,
        close_task_done: bool,
        verified_no_op: bool,
    ) -> (V15CandidateFixture, V21FinalVerificationFixture) {
        let mut candidate = prepare_v15_candidate_fixture_with_result(true, verified_no_op);
        let (_, _, disposition) =
            integrate_v15_candidate(&mut candidate, "unadmitted-final", false);
        let command = candidate
            .ledger
            .load_command_domain_effect_bindings(
                &candidate.spec.sprint_id,
                &candidate.launch.launch_id,
                &candidate.launch.session_id,
            )
            .expect("load unadmitted-final task command binding")
            .into_iter()
            .find(|binding| binding.effect_id == "effect-v15-formal")
            .expect("find unadmitted-final task command binding");
        ensure_test_command_domain_cleanup(
            &mut candidate.ledger,
            &command,
            "command-cleanup-unadmitted-final-task",
            CommandDomainBackend::LinuxCgroupV2,
            CommandDomainCleanupDisposition::ReapedZeroSurvivors,
            1_400,
        );
        if close_task_done {
            let task_cleanup = cleanup_terminal_record(
                &candidate.ledger,
                &candidate.launch,
                "cleanup-unadmitted-final-task",
                1_450,
            );
            candidate
                .ledger
                .with_integrated_task_attempt_cleanup_exclusion(
                    &disposition.metadata().disposition_id,
                    |_| Ok(task_cleanup),
                )
                .expect("close unadmitted-final TaskDone worker");
            assert!(
                candidate
                    .ledger
                    .assess_task_done(&candidate.spec.sprint_id, "task-1")
                    .expect("assess unadmitted-final TaskDone")
                    .is_done()
            );
        }
        if cleanup_snapshot != candidate.spec.base_snapshot
            && cleanup_snapshot != candidate.result_snapshot.snapshot_id
        {
            candidate
                .ledger
                .persist_workspace_snapshot(
                    &candidate.spec.sprint_id,
                    &WorkspaceSnapshot {
                        snapshot_id: cleanup_snapshot.clone(),
                        grant_hash: candidate.spec.workspace_grant.grant_hash.clone(),
                        created_at_unix_ms: 1_490,
                    },
                )
                .expect("persist crossed final-verifier cleanup snapshot");
        }
        let final_fixture = build_v21_final_verification_fixture_with_session(
            &mut candidate.ledger,
            cleanup_snapshot,
            register_session,
        );
        (candidate, final_fixture)
    }

    fn bind_v21_final_fixture_command(
        fixture: &mut V21FinalVerificationFixture,
        command: CommandSpec,
    ) {
        fixture.admission.command = command;
        fixture.command_bytes =
            encode("v21 final-verification command", &fixture.admission.command)
                .expect("encode rebound v21 final-verification command");
        fixture.intent.request_digest = Digest::sha256(&fixture.command_bytes);
        fixture.proposed_event = effect_proposal_event(
            &fixture.intent,
            fixture.proposed_event.sequence,
            &fixture.proposed_event.event_id,
        );
        fixture.capture_intent = v27_test_capture_intent(
            &fixture.intent,
            &fixture.launch,
            &fixture.session,
            "v21-final-verification",
        );
    }

    fn admit_test_final_verification(
        ledger: &mut EventLedger,
        fixture: &V21FinalVerificationFixture,
    ) -> FreshRunnerEffectDispatchPermit {
        let capture_schema =
            command_output_capture_authority::schema_is_installed(&ledger.connection)
                .expect("inspect final-verification capture schema");
        let admission = if capture_schema {
            ledger.admit_sprint_final_verification_with_output_capture_for_dispatch(
                &fixture.admission,
                &fixture.phase_event,
                &fixture.intent,
                &fixture.proposed_event,
                &fixture.capture_intent,
            )
        } else {
            ledger.admit_sprint_final_verification_for_dispatch(
                &fixture.admission,
                &fixture.phase_event,
                &fixture.intent,
                &fixture.proposed_event,
            )
        }
        .expect("admit exact test final verification");
        match admission {
            SprintFinalVerificationDispatchAdmission::Fresh { permit, .. } => {
                FreshRunnerEffectDispatchPermit::SprintFinalVerification(permit)
            }
            SprintFinalVerificationDispatchAdmission::Existing { .. } => {
                panic!("new test final-verification admission must be Fresh")
            }
        }
    }

    fn claim_test_final_verification(
        ledger: &mut EventLedger,
        fixture: &V21FinalVerificationFixture,
        permit: FreshRunnerEffectDispatchPermit,
    ) -> (
        RunnerEffectObservationAuthority,
        Option<CommandOutputCaptureAcquiredV1>,
    ) {
        let acquired = permit.output_capture_intent().map(|capture| {
            v27_test_capture_acquired(
                capture,
                permit
                    .expected_output_capture_dispatch_claim_id()
                    .expect("fresh final capture claim identity"),
                &fixture.intent.effect_id,
                fixture.intent.created_at_unix_ms + 1,
            )
        });
        let (_, transport) = if let Some(acquired) = acquired.as_ref() {
            ledger.claim_command_output_capture_dispatch(
                permit,
                acquired.clone(),
                OPAQUE_RUNNER_TRANSPORT_REQUEST_BYTES,
            )
        } else {
            ledger.claim_runner_effect_dispatch(permit, OPAQUE_RUNNER_TRANSPORT_REQUEST_BYTES)
        }
        .expect("claim exact test final verification");
        let authority = transport
            .validate_transport_request(
                &fixture.intent,
                &fixture.command_bytes,
                &fixture.launch,
                &fixture.session,
                None,
                OPAQUE_RUNNER_TRANSPORT_REQUEST_BYTES,
            )
            .expect("validate exact test final-verification transport");
        (authority, acquired)
    }

    fn complete_test_final_verification(
        ledger: &mut EventLedger,
        fixture: &V21FinalVerificationFixture,
        authority: RunnerEffectObservationAuthority,
        acquired: Option<&CommandOutputCaptureAcquiredV1>,
        observation: &EffectObservation,
        event: &AgentEvent,
        evidence: &VerificationEffectEvidence,
    ) {
        if let Some(acquired) = acquired {
            let capture_terminal = v27_test_published_capture_terminal(
                &fixture.capture_intent,
                acquired,
                observation,
                evidence
                    .output_artifacts
                    .clone()
                    .expect("current final-verification evidence carries output artifacts"),
                &fixture.intent.effect_id,
                evidence.verification.finished_at_unix_ms + 2,
            );
            let cleanup = v27_test_command_cleanup(
                &fixture.intent,
                observation,
                &fixture.launch,
                &fixture.session,
                &fixture.intent.effect_id,
                evidence.verification.finished_at_unix_ms + 1,
            );
            let clean_scan = v29_test_clean_scan_receipt(
                &fixture.capture_intent,
                acquired,
                &capture_terminal,
                evidence
                    .verification
                    .termination
                    .expect("current final receipt has typed termination"),
                &fixture.intent.effect_id,
            );
            ledger
                .complete_claimed_sprint_final_verification_with_output_capture(
                    authority,
                    observation,
                    event,
                    evidence,
                    &capture_terminal,
                    &clean_scan,
                    &cleanup,
                )
                .expect("persist exact v27 test final verification");
        } else {
            ledger
                .record_claimed_final_verification_effect_observation(
                    authority,
                    observation,
                    event,
                    evidence,
                )
                .expect("persist exact historical test final verification");
        }
    }

    fn v21_final_verification_terminal(
        ledger: &EventLedger,
        fixture: &V21FinalVerificationFixture,
    ) -> (EffectObservation, AgentEvent, VerificationEffectEvidence) {
        let output = b"v21 final verification passed".to_vec();
        let mut receipt = VerificationReceipt {
            receipt_id: "receipt-v21-final".into(),
            sprint_id: fixture.intent.sprint_id.clone(),
            task_id: None,
            snapshot_id: fixture.admission.final_snapshot.clone(),
            command: fixture.admission.command.clone(),
            policy_hash: fixture.intent.policy_hash.clone(),
            exit_status: Some(0),
            termination: Some(CommandTerminationV1::Exited { code: 0 }),
            output_digest: Digest::sha256(&output),
            duration_ms: 25,
            finished_at_unix_ms: 2_300,
        };
        let (output_artifacts, output_evidence_bytes) = bind_complete_output_artifacts(
            ledger,
            &mut receipt,
            &fixture.intent.effect_id,
            &fixture.launch.launch_id,
            &fixture.session.session_id,
            output,
        );
        let evidence = VerificationEffectEvidence {
            contract_version: CONTRACT_VERSION,
            verification: receipt,
            effect_id: fixture.intent.effect_id.clone(),
            observation_id: "observation-v21-final".into(),
            runner_launch_id: fixture.launch.launch_id.clone(),
            runner_session_id: fixture.session.session_id.clone(),
            output_artifacts,
            output_evidence_bytes,
        };
        let evidence_bytes =
            encode("verification effect evidence", &evidence).expect("encode v21 final evidence");
        let observation = effect_observation(
            &fixture.intent,
            &evidence.observation_id,
            EffectOutcome::Succeeded {
                evidence_digest: Digest::sha256(&evidence_bytes),
            },
            evidence.verification.finished_at_unix_ms,
        );
        let event = effect_terminal_event(
            &fixture.intent,
            &fixture.proposed_event.event_id,
            &observation,
            ledger
                .next_sequence(&fixture.intent.sprint_id)
                .expect("v21 final terminal sequence"),
            "event-v21-final-finished",
        );
        (observation, event, evidence)
    }

    #[test]
    fn unadmitted_final_verifier_cleanup_accepts_exact_registered_session_and_closes_phase() {
        let (mut candidate, fixture) =
            prepare_current_unadmitted_final_verifier_fixture(true, digest('b'));
        let ledger = &mut candidate.ledger;
        let callback_invoked = Arc::new(AtomicBool::new(false));
        let callback_flag = Arc::clone(&callback_invoked);
        let expected_launch = fixture.launch.clone();
        let expected_session = fixture.session.clone();
        let persisted = ledger
            .with_unadmitted_final_verifier_launch_cleanup_exclusion(
                &fixture.launch.sprint_id,
                &fixture.launch.launch_id,
                move |claim| {
                    callback_flag.store(true, Ordering::SeqCst);
                    assert_eq!(claim.admission().launch, expected_launch);
                    assert_eq!(claim.registered_session(), Some(&expected_session));
                    assert_eq!(
                        claim.minimum_terminal_at_unix_ms(),
                        runner_cleanup_minimum_terminal_time(
                            claim.admission(),
                            claim.preparation(),
                        )
                        .max(expected_session.registered_at_unix_ms)
                    );
                    Ok(cleanup_terminal_from_live_claim(
                        claim,
                        "unadmitted-final-session-present",
                        2_300,
                    ))
                },
            )
            .expect("clean exact unadmitted final-verifier launch");
        assert!(callback_invoked.load(Ordering::SeqCst));
        assert!(matches!(
            persisted.finish_receipt,
            PersistedFinishReceipt::WorkerCleanup(_)
        ));

        let mut post_cleanup_phase = fixture.phase_event.clone();
        post_cleanup_phase.sequence = ledger
            .next_sequence(&fixture.launch.sprint_id)
            .expect("post-cleanup phase sequence");
        post_cleanup_phase.occurred_at_unix_ms = 2_400;
        let mut post_cleanup_intent = fixture.intent.clone();
        post_cleanup_intent.created_at_unix_ms = 2_410;
        let post_cleanup_proposal = effect_proposal_event(
            &post_cleanup_intent,
            post_cleanup_phase.sequence + 1,
            &fixture.proposed_event.event_id,
        );
        let mut post_cleanup_admission = fixture.admission.clone();
        post_cleanup_admission.admitted_at_unix_ms = post_cleanup_intent.created_at_unix_ms;
        let phase_error = ledger
            .admit_sprint_final_verification_for_dispatch(
                &post_cleanup_admission,
                &post_cleanup_phase,
                &post_cleanup_intent,
                &post_cleanup_proposal,
            )
            .expect_err("cleaned launch cannot later acquire final-verification authority");
        assert!(
            matches!(
                &phase_error,
                LedgerError::ReferenceMismatch {
                    entity: "runner launch cleanup admission",
                    ..
                }
            ),
            "unexpected post-cleanup phase rejection: {phase_error:?}"
        );
        assert_eq!(row_count(ledger, "sprint_final_verification_admissions"), 0);
    }

