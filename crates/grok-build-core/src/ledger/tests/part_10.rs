    #[allow(clippy::too_many_arguments)]
    fn assert_v27_source_dispatch_corruption_blocks_completion<F>(
        ledger: &mut EventLedger,
        capture_id: &str,
        effect_id: &str,
        sprint_id: &str,
        completion_event_id: &str,
        terminal_at_unix_ms: u64,
        drop_immutable_trigger_sql: &str,
        mutate: F,
        expected_source_rows: i64,
        expected_dispatch_rows: i64,
    ) where
        F: FnOnce(&Transaction<'_>),
    {
        for (view, expected) in [
            ("command_output_capture_exact_runner_sources_v27", 1_i64),
            (
                "command_output_capture_exact_dispatch_authorities_v27",
                1_i64,
            ),
        ] {
            let rows = ledger
                .connection
                .query_row(
                    &format!("SELECT COUNT(*) FROM {view} WHERE capture_id = ?1"),
                    [capture_id],
                    |row| row.get::<_, i64>(0),
                )
                .expect("count pristine v27 exact authority view");
            assert_eq!(rows, expected, "pristine fixture missing from {view}");
        }
        let transaction = ledger
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .expect("start rollback-only exact source/dispatch corruption");
        isolate_v27_completion_fence(&transaction);
        transaction
            .execute_batch(drop_immutable_trigger_sql)
            .expect("drop exact source/dispatch immutability guard");
        mutate(&transaction);
        let error = command_output_capture_authority::load_from_id(&transaction, capture_id)
            .expect_err("typed capture readback must reject source/dispatch corruption");
        assert!(matches!(error, LedgerError::Corrupt { .. }), "{error:?}");
        for (view, expected) in [
            (
                "command_output_capture_exact_runner_sources_v27",
                expected_source_rows,
            ),
            (
                "command_output_capture_exact_dispatch_authorities_v27",
                expected_dispatch_rows,
            ),
        ] {
            let rows = transaction
                .query_row(
                    &format!("SELECT COUNT(*) FROM {view} WHERE capture_id = ?1"),
                    [capture_id],
                    |row| row.get::<_, i64>(0),
                )
                .expect("count corrupted v27 exact authority view");
            assert_eq!(rows, expected, "unexpected corrupted row count in {view}");
        }
        let completion_error = transaction
            .execute(
                "INSERT INTO sprint_completion_proof_states (
                    sprint_id, proof_state, completion_receipt_id,
                    completion_event_id, contract_version, terminal_at_unix_ms
                 ) VALUES (?1, 'ProvenV9', ?2, ?3, ?4, ?5)",
                params![
                    sprint_id,
                    format!("v27-corrupt-source-completion-{effect_id}"),
                    completion_event_id,
                    i64::from(CONTRACT_VERSION),
                    sqlite_integer("v27 source corruption completion time", terminal_at_unix_ms)
                        .expect("completion time fits SQLite"),
                ],
            )
            .expect_err("corrupt source/dispatch authority cannot admit raw completion");
        assert!(
            completion_error
                .to_string()
                .contains("completion requires every capture obligation and claim closed"),
            "unexpected exact source/dispatch completion error: {completion_error}"
        );
        drop(transaction);
    }

    fn isolate_v27_completion_fence(transaction: &Transaction<'_>) {
        transaction
            .execute_batch(
                "DROP TRIGGER sprint_completion_proof_states_v28_current_criterion_evidence_required;",
            )
            .expect("isolate the v27 completion fence inside a rollback-only test transaction");
    }

    fn assert_no_completion_writes(ledger: &EventLedger) {
        assert_eq!(row_count(ledger, "final_reports"), 0);
        assert_eq!(row_count(ledger, "v9_completion_receipts"), 0);
        assert_eq!(row_count(ledger, "v9_completion_cleanup_receipts"), 0);
        assert_eq!(row_count(ledger, "v9_completion_verification_receipts"), 0);
        assert_eq!(
            row_count(ledger, "v9_completion_task_integration_receipts"),
            0
        );
        assert_eq!(row_count(ledger, "v9_completion_acceptance_receipts"), 0);
        assert_eq!(row_count(ledger, "sprint_completion_proof_states"), 0);
        let completion_events: i64 = ledger
            .connection
            .query_row(
                "SELECT COUNT(*) FROM agent_events
                 WHERE event_json LIKE '%CompletionRecorded%'",
                [],
                |row| row.get(0),
            )
            .expect("count completion events");
        assert_eq!(completion_events, 0);
    }

    #[test]
    fn restart_restores_spec_graph_and_exact_event_order() {
        let database = TestDatabase::new();
        let (spec, graph) = sprint_fixture();
        let first = event(1, "event-1", None);
        let second = event(2, "event-2", Some("event-1"));

        {
            let mut ledger = EventLedger::open(&database.path).expect("open ledger");
            ledger
                .create_sprint(&spec, &graph, 1_000)
                .expect("persist sprint");
            assert_eq!(ledger.next_sequence("sprint-1").expect("next sequence"), 1);
            ledger.append_event(&first).expect("append first event");
            ledger.append_event(&second).expect("append second event");
            assert_eq!(ledger.next_sequence("sprint-1").expect("next sequence"), 3);
        }

        let ledger = EventLedger::open(&database.path).expect("reopen ledger");
        let restored = ledger.load_sprint("sprint-1").expect("restore sprint");
        assert_eq!(restored.spec, spec);
        assert_eq!(restored.graph, Some(graph));
        assert_eq!(
            restored.graph_provenance,
            TaskGraphProvenance::DirectTrusted
        );
        assert_eq!(restored.created_at_unix_ms, 1_000);
        assert_eq!(restored.events, vec![first, second]);
        assert_eq!(ledger.next_sequence("sprint-1").expect("next sequence"), 3);
    }

    #[test]
    fn draft_provider_planning_survives_crash_read_only_reopen_and_attach() {
        let database = TestDatabase::new();
        let (spec, graph) = sprint_fixture();
        let base = draft_base_snapshot();
        let intent = planning_effect_intent("planning-effect", "planning-key", 1_100);
        let proposal = effect_proposal_event(&intent, 1, "planning-proposal");

        {
            let mut ledger = EventLedger::open(&database.path).expect("open draft ledger");
            ledger
                .create_draft_sprint(&spec, &base, 1_000)
                .expect("atomically create draft and base snapshot");
            let draft = ledger.load_sprint("sprint-1").expect("load draft");
            assert_eq!(draft.graph, None);
            assert_eq!(
                ledger
                    .load_workspace_snapshot("sprint-1", &spec.base_snapshot)
                    .expect("load authenticated base"),
                base
            );
            record_test_effect_intent(&mut ledger, &intent, &proposal)
                .expect("persist planning request before execution");
        }

        {
            let ledger = EventLedger::open_read_only(&database.path).expect("reopen read-only");
            let draft = ledger.load_sprint("sprint-1").expect("restore draft");
            assert_eq!(draft.graph, None);
            assert_eq!(draft.effects.len(), 1);
            assert_eq!(draft.effects[0].request_bytes, EFFECT_REQUEST_BYTES);
            assert_eq!(
                ledger
                    .load_unfinished_effects("sprint-1")
                    .expect("recover unfinished planning request")
                    .len(),
                1
            );
            assert!(matches!(
                ledger.load_completion("sprint-1"),
                Err(LedgerError::SprintGraphNotAttached(id)) if id == "sprint-1"
            ));
        }

        let response_bytes = planning_response_bytes(&spec, &graph);
        let observation = effect_observation(
            &intent,
            "planning-observation",
            EffectOutcome::Succeeded {
                evidence_digest: Digest::sha256(&response_bytes),
            },
            1_200,
        );
        let terminal = effect_terminal_event(
            &intent,
            "planning-proposal",
            &observation,
            2,
            "planning-finished",
        );
        {
            let mut ledger = EventLedger::open(&database.path).expect("reopen writable");
            ledger
                .record_effect_observation(&observation, &response_bytes, &terminal)
                .expect("persist planning result");
            ledger
                .attach_task_graph_from_effect("sprint-1", &intent.effect_id, &graph)
                .expect("attach immutable graph");
        }

        let ledger = EventLedger::open_read_only(&database.path).expect("inspect planned sprint");
        let restored = ledger
            .load_sprint("sprint-1")
            .expect("restore planned sprint");
        assert_eq!(restored.graph, Some(graph));
        assert_eq!(
            restored.graph_provenance,
            TaskGraphProvenance::ProviderEffect {
                effect_id: intent.effect_id.clone(),
                observation_id: observation.observation_id.clone(),
                response_digest: Digest::sha256(&response_bytes),
            }
        );
        assert_eq!(restored.effects[0].observation, Some(observation));
        assert_eq!(
            restored.effects[0].evidence_bytes.as_deref(),
            Some(response_bytes.as_slice())
        );
    }

    #[test]
    fn draft_effects_are_only_sprint_scoped_base_bound_provider_requests() {
        let database = TestDatabase::new();
        let (spec, _) = sprint_fixture();
        let mut ledger = EventLedger::open(&database.path).expect("open ledger");
        ledger
            .create_draft_sprint(&spec, &draft_base_snapshot(), 1_000)
            .expect("create draft");

        let mut wrong_kind = planning_effect_intent("wrong-kind", "key-1", 1_100);
        // Use a non-command tool so this draft-scope test reaches the draft
        // lifecycle gate instead of the independent v27 capture prerequisite.
        wrong_kind.kind = EffectKind::SearchLiteral;
        let event = effect_proposal_event(&wrong_kind, 1, "wrong-kind-event");
        assert!(matches!(
            record_test_effect_intent(&mut ledger, &wrong_kind, &event),
            Err(LedgerError::ReferenceMismatch {
                entity: "effect intent",
                ..
            })
        ));

        let mut task_scoped = planning_effect_intent("task-scoped", "key-2", 1_100);
        task_scoped.task_id = Some("task-1".into());
        task_scoped.worker_id = Some("worker-1".into());
        task_scoped.worker_lease = Some(test_worker_lease_for("worker-1", 1_099));
        let event = effect_proposal_event(&task_scoped, 1, "task-scoped-event");
        assert!(matches!(
            record_test_effect_intent(&mut ledger, &task_scoped, &event),
            Err(LedgerError::ReferenceMismatch {
                entity: "task or worker effect intent",
                ..
            })
        ));

        let mut stale_base = planning_effect_intent("stale-base", "key-3", 1_100);
        stale_base.input_snapshot = digest('c');
        let event = effect_proposal_event(&stale_base, 1, "stale-base-event");
        assert!(matches!(
            record_test_effect_intent(&mut ledger, &stale_base, &event),
            Err(LedgerError::ReferenceMismatch {
                entity: "effect intent",
                ..
            })
        ));
        assert_eq!(row_count(&ledger, "effect_intents"), 0);
        assert_eq!(row_count(&ledger, "agent_events"), 0);
        assert_eq!(row_count(&ledger, "effect_request_payloads"), 0);
    }

    #[test]
    fn graph_attach_rejects_stale_cross_sprint_and_second_graph_then_unlocks_work() {
        let database = TestDatabase::new();
        let (spec, graph) = sprint_fixture();
        let mut ledger = EventLedger::open(&database.path).expect("open ledger");
        ledger
            .create_draft_sprint(&spec, &draft_base_snapshot(), 1_000)
            .expect("create draft");
        let (planning_intent, _, _) = persist_successful_planning_effect(
            &mut ledger,
            &spec,
            &graph,
            "planning-effect",
            "planning-key",
            1_100,
            1_200,
        );

        assert!(matches!(
            ledger.attach_task_graph("sprint-1", &graph),
            Err(LedgerError::PlanningProvenanceRequired(id)) if id == "sprint-1"
        ));

        let mut stale = graph.clone();
        stale.tasks[0].base_snapshot = digest('c');
        assert!(matches!(
            ledger.attach_task_graph_from_effect(
                "sprint-1",
                &planning_intent.effect_id,
                &stale
            ),
            Err(LedgerError::Contract(error)) if error.field() == "task.base_snapshot"
        ));
        let mut cross_sprint = graph.clone();
        cross_sprint.tasks[0].acceptance_checks = vec!["other-sprint-check".into()];
        assert!(matches!(
            ledger.attach_task_graph_from_effect(
                "sprint-1",
                &planning_intent.effect_id,
                &cross_sprint
            ),
            Err(LedgerError::Contract(error)) if error.field() == "task.acceptance_checks"
        ));
        assert_eq!(row_count(&ledger, "sprint_task_graphs"), 0);

        ledger
            .attach_task_graph_from_effect("sprint-1", &planning_intent.effect_id, &graph)
            .expect("attach valid graph");
        assert!(matches!(
            ledger.attach_task_graph_from_effect("sprint-1", &planning_intent.effect_id, &graph),
            Err(LedgerError::ArtifactAlreadyExists {
                entity: "task graph",
                ..
            })
        ));
        assert!(
            ledger
                .connection
                .execute(
                    "UPDATE sprint_task_graphs SET graph_id = 'replacement'
                     WHERE sprint_id = 'sprint-1'",
                    [],
                )
                .is_err()
        );
        assert!(
            ledger
                .connection
                .execute(
                    "DELETE FROM sprint_task_graphs WHERE sprint_id = 'sprint-1'",
                    [],
                )
                .is_err()
        );
        let intent = effect_intent("task-effect", "task-key", 1_300);
        let proposal = effect_proposal_event(&intent, 3, "task-proposal");
        record_test_effect_intent(&mut ledger, &intent, &proposal)
            .expect("normal task effect works after graph attach");
    }

    #[test]
    fn graph_provenance_requires_success_and_the_exact_response_graph() {
        let database = TestDatabase::new();
        let (spec, graph) = sprint_fixture();
        let mut ledger = EventLedger::open(&database.path).expect("open ledger");
        ledger
            .create_draft_sprint(&spec, &draft_base_snapshot(), 1_000)
            .expect("create draft");

        let failed_intent = planning_effect_intent("failed-plan", "failed-key", 1_100);
        let failed_proposal = effect_proposal_event(&failed_intent, 1, "failed-plan-proposed");
        record_test_effect_intent(&mut ledger, &failed_intent, &failed_proposal)
            .expect("persist failed planning intent");
        let failed_observation = effect_observation(
            &failed_intent,
            "failed-plan-observed",
            EffectOutcome::FailedAfterKnownEffect {
                evidence_digest: effect_evidence_digest(),
            },
            1_200,
        );
        let failed_terminal = effect_terminal_event(
            &failed_intent,
            &failed_proposal.event_id,
            &failed_observation,
            2,
            "failed-plan-finished",
        );
        record_test_effect_observation(&mut ledger, &failed_observation, &failed_terminal)
            .expect("persist failed outcome");
        assert!(matches!(
            ledger.attach_task_graph_from_effect("sprint-1", &failed_intent.effect_id, &graph),
            Err(LedgerError::ReferenceMismatch {
                entity: "task graph provenance",
                ..
            })
        ));

        let (successful_intent, _, _) = persist_successful_planning_effect(
            &mut ledger,
            &spec,
            &graph,
            "successful-plan",
            "successful-key",
            1_300,
            1_400,
        );
        let mut other_graph = graph.clone();
        other_graph.graph_id = "other-valid-graph".into();
        assert!(matches!(
            ledger.attach_task_graph_from_effect(
                "sprint-1",
                &successful_intent.effect_id,
                &other_graph
            ),
            Err(LedgerError::ReferenceMismatch {
                entity: "task graph provenance",
                ..
            })
        ));
        assert_eq!(row_count(&ledger, "sprint_task_graphs"), 0);
        assert_eq!(row_count(&ledger, "sprint_graph_provenance"), 0);
    }

    #[test]
    fn graph_provenance_rejects_noncanonical_and_cross_sprint_evidence() {
        let database = TestDatabase::new();
        let (spec, graph) = sprint_fixture();
        let mut ledger = EventLedger::open(&database.path).expect("open ledger");
        ledger
            .create_draft_sprint(&spec, &draft_base_snapshot(), 1_000)
            .expect("create first draft");
        let response = ProviderResponse {
            contract_version: CONTRACT_VERSION,
            sprint_id: spec.sprint_id.clone(),
            result: ProviderResponseResult::PlanningComplete {
                task_graph: graph.clone(),
            },
        };
        let noncanonical = serde_json::to_vec_pretty(&response).expect("encode pretty response");
        let intent = planning_effect_intent("pretty-plan", "pretty-key", 1_100);
        let proposal = effect_proposal_event(&intent, 1, "pretty-plan-proposed");
        record_test_effect_intent(&mut ledger, &intent, &proposal).expect("persist intent");
        let observation = effect_observation(
            &intent,
            "pretty-plan-observed",
            EffectOutcome::Succeeded {
                evidence_digest: Digest::sha256(&noncanonical),
            },
            1_200,
        );
        let terminal = effect_terminal_event(
            &intent,
            &proposal.event_id,
            &observation,
            2,
            "pretty-plan-finished",
        );
        ledger
            .record_effect_observation(&observation, &noncanonical, &terminal)
            .expect("persist noncanonical response evidence");
        assert!(matches!(
            ledger.attach_task_graph_from_effect("sprint-1", &intent.effect_id, &graph),
            Err(LedgerError::ReferenceMismatch {
                entity: "task graph provenance",
                ..
            })
        ));

        let mut second_spec = spec;
        second_spec.sprint_id = "sprint-2".into();
        ledger
            .create_draft_sprint(&second_spec, &draft_base_snapshot(), 1_000)
            .expect("create second draft");
        assert!(matches!(
            ledger.attach_task_graph_from_effect("sprint-2", &intent.effect_id, &graph),
            Err(LedgerError::ReferenceMismatch {
                entity: "task graph provenance",
                ..
            })
        ));
    }

    #[test]
    fn provenance_double_bind_and_direct_corruption_fail_closed() {
        let database = TestDatabase::new();
        let (spec, graph) = sprint_fixture();
        let mut ledger = EventLedger::open(&database.path).expect("open ledger");
        ledger
            .create_draft_sprint(&spec, &draft_base_snapshot(), 1_000)
            .expect("create first draft");
        let (intent, observation, _) = persist_successful_planning_effect(
            &mut ledger,
            &spec,
            &graph,
            "bound-plan",
            "bound-key",
            1_100,
            1_200,
        );
        ledger
            .attach_task_graph_from_effect("sprint-1", &intent.effect_id, &graph)
            .expect("bind first graph");

        let mut second_spec = spec;
        second_spec.sprint_id = "sprint-2".into();
        ledger
            .create_draft_sprint(&second_spec, &draft_base_snapshot(), 1_000)
            .expect("create second draft");
        assert!(matches!(
            ledger.attach_task_graph_from_effect("sprint-2", &intent.effect_id, &graph),
            Err(LedgerError::ReferenceMismatch {
                entity: "task graph provenance",
                ..
            })
        ));
        let direct_second_bind = ledger.connection.execute(
            "INSERT INTO sprint_graph_provenance (
                sprint_id, provenance_kind, effect_id, observation_id,
                response_digest, contract_version
             ) VALUES (?1, 'ProviderEffect', ?2, ?3, ?4, ?5)",
            params![
                "sprint-2",
                intent.effect_id,
                observation.observation_id,
                observation.outcome.evidence_digest().as_str(),
                i64::from(CONTRACT_VERSION)
            ],
        );
        assert!(
            direct_second_bind.is_err(),
            "effect identity must be unique across graph provenance"
        );

        let response_digest = observation.outcome.evidence_digest().clone();
        ledger
            .connection
            .execute_batch("DROP TRIGGER sprint_graph_provenance_no_update;")
            .expect("allow corruption injection");
        ledger
            .connection
            .execute(
                "UPDATE sprint_graph_provenance SET response_digest = ?1
                 WHERE sprint_id = 'sprint-1'",
                [digest('f').as_str()],
            )
            .expect("corrupt response digest");
        assert!(matches!(
            ledger.load_sprint("sprint-1"),
            Err(LedgerError::Corrupt {
                entity: "task graph provenance",
                ..
            })
        ));
        ledger
            .connection
            .execute(
                "UPDATE sprint_graph_provenance SET response_digest = ?1
                 WHERE sprint_id = 'sprint-1'",
                [response_digest.as_str()],
            )
            .expect("restore response digest");
        ledger
            .connection
            .execute_batch("DROP TRIGGER effect_evidence_payloads_no_update;")
            .expect("allow evidence corruption injection");
        ledger
            .connection
            .execute(
                "UPDATE effect_evidence_payloads SET evidence_bytes = x'00'
                 WHERE effect_id = ?1",
                [&intent.effect_id],
            )
            .expect("corrupt response preimage");
        assert!(matches!(
            ledger.load_sprint("sprint-1"),
            Err(LedgerError::Corrupt {
                entity: "effect evidence payload",
                ..
            })
        ));
    }

    #[test]
    fn graph_provenance_rehashes_the_planning_request_preimage() {
        let database = TestDatabase::new();
        let (spec, graph) = sprint_fixture();
        let mut ledger = EventLedger::open(&database.path).expect("open ledger");
        ledger
            .create_draft_sprint(&spec, &draft_base_snapshot(), 1_000)
            .expect("create draft");
        let (intent, _, _) = persist_successful_planning_effect(
            &mut ledger,
            &spec,
            &graph,
            "corrupt-request-plan",
            "corrupt-request-key",
            1_100,
            1_200,
        );
        ledger
            .connection
            .execute_batch("DROP TRIGGER effect_request_payloads_no_update;")
            .expect("allow request corruption injection");
        ledger
            .connection
            .execute(
                "UPDATE effect_request_payloads SET request_bytes = x'00'
                 WHERE effect_id = ?1",
                [&intent.effect_id],
            )
            .expect("corrupt request preimage");
        assert!(matches!(
            ledger.attach_task_graph_from_effect("sprint-1", &intent.effect_id, &graph),
            Err(LedgerError::Corrupt {
                entity: "effect request payload",
                ..
            })
        ));
        assert_eq!(row_count(&ledger, "sprint_task_graphs"), 0);
        assert_eq!(row_count(&ledger, "sprint_graph_provenance"), 0);
    }

    #[test]
    fn draft_creation_is_atomic_and_rejects_mismatched_base_evidence() {
        let database = TestDatabase::new();
        let (spec, _) = sprint_fixture();
        let mut ledger = EventLedger::open(&database.path).expect("open ledger");

        let mut wrong_snapshot = draft_base_snapshot();
        wrong_snapshot.snapshot_id = digest('c');
        assert!(matches!(
            ledger.create_draft_sprint(&spec, &wrong_snapshot, 1_000),
            Err(LedgerError::ReferenceMismatch {
                entity: "draft sprint",
                ..
            })
        ));
        let mut wrong_grant = draft_base_snapshot();
        wrong_grant.grant_hash = digest('d');
        assert!(
            ledger
                .create_draft_sprint(&spec, &wrong_grant, 1_000)
                .is_err()
        );
        let mut future_snapshot = draft_base_snapshot();
        future_snapshot.created_at_unix_ms = 1_001;
        assert!(
            ledger
                .create_draft_sprint(&spec, &future_snapshot, 1_000)
                .is_err()
        );

        ledger
            .connection
            .execute_batch(
                "CREATE TRIGGER test_draft_late_failure
                 BEFORE INSERT ON workspace_snapshots
                 BEGIN SELECT RAISE(ABORT, 'injected late failure'); END;",
            )
            .expect("install late failure");
        assert!(
            ledger
                .create_draft_sprint(&spec, &draft_base_snapshot(), 1_000)
                .is_err()
        );
        assert_eq!(row_count(&ledger, "sprints"), 0);
        assert_eq!(row_count(&ledger, "sprint_planning_states"), 0);
        assert_eq!(row_count(&ledger, "workspace_snapshots"), 0);
    }

    #[test]
    fn draft_rejects_task_artifacts_events_and_completion_until_planned() {
        let database = TestDatabase::new();
        let (spec, _) = sprint_fixture();
        let mut ledger = EventLedger::open(&database.path).expect("open ledger");
        ledger
            .create_draft_sprint(&spec, &draft_base_snapshot(), 1_000)
            .expect("create draft");
        let (
            _,
            final_snapshot,
            change_set,
            verification,
            acceptance,
            report,
            receipt,
            completion_event,
        ) = completion_artifacts();

        assert!(matches!(
            ledger.persist_workspace_snapshot("sprint-1", &final_snapshot),
            Err(LedgerError::SprintGraphNotAttached(_))
        ));
        assert!(matches!(
            ledger.persist_change_set("sprint-1", &change_set),
            Err(LedgerError::SprintGraphNotAttached(_))
        ));
        assert!(matches!(
            ledger.persist_verification_receipt(&verification),
            Err(LedgerError::SprintGraphNotAttached(_))
        ));
        assert!(matches!(
            ledger.persist_acceptance_receipt(&acceptance),
            Err(LedgerError::SprintGraphNotAttached(_))
        ));
        assert!(matches!(
            ledger.persist_final_report(&report),
            Err(LedgerError::SprintGraphNotAttached(_))
        ));
        assert!(matches!(
            ledger.record_successful_completion_from_live_state_capture(
                &report,
                &receipt,
                "missing-draft-live-state-capture",
                &completion_event,
            ),
            Err(LedgerError::ArtifactNotFound {
                entity: "live-state capture evidence",
                id,
            }) if id == "missing-draft-live-state-capture"
        ));
        assert!(matches!(
            ledger.load_completion("sprint-1"),
            Err(LedgerError::SprintGraphNotAttached(_))
        ));

        let task_event = AgentEvent {
            task_id: Some("task-1".into()),
            worker_id: Some("worker-1".into()),
            payload: AgentEventKind::TaskStateChanged {
                from: "Queued".into(),
                to: "Running".into(),
            },
            ..event(1, "task-event", None)
        };
        assert!(matches!(
            ledger.append_event(&task_event),
            Err(LedgerError::ReferenceMismatch {
                entity: "agent event",
                ..
            })
        ));
        assert_eq!(row_count(&ledger, "agent_events"), 0);
        assert_no_completion_writes(&ledger);

        let mut source = event(1, "draft-capture-source", None);
        source.occurred_at_unix_ms = 1_100;
        ledger
            .append_event(&source)
            .expect("append non-task draft diagnostic source");
        let cut = SprintLiveStateCapturePlanCut {
            plan_id: "draft-capture-plan".into(),
            source_event_id: source.event_id,
            source_event_sequence: source.sequence,
            planned_at_unix_ms: 1_110,
        };
        assert!(matches!(
            ledger.derive_verified_no_op_live_state_capture_plan(
                cut,
                &compiled_test_policy("policy-draft-capture"),
                "sprint-1",
                "missing-draft-final-verification",
                "missing-draft-integration",
            ),
            Err(LedgerError::SprintGraphNotAttached(id)) if id == "sprint-1"
        ));
        assert_eq!(row_count(&ledger, "sprint_live_state_capture_plans"), 0);
        assert_no_completion_writes(&ledger);
    }

    #[test]
    fn draft_schema_triggers_reject_bypassed_effect_and_artifact() {
        let database = TestDatabase::new();
        let (spec, _) = sprint_fixture();
        let mut ledger = EventLedger::open(&database.path).expect("open ledger");
        ledger
            .create_draft_sprint(&spec, &draft_base_snapshot(), 1_000)
            .expect("create draft");

        let direct_change = ledger.connection.execute(
            "INSERT INTO change_sets (
                sprint_id, change_set_id, base_snapshot, result_snapshot,
                contract_version, change_set_json
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                "sprint-1",
                "direct-change",
                digest('b').as_str(),
                digest('b').as_str(),
                i64::from(CONTRACT_VERSION),
                b"{}"
            ],
        );
        assert!(direct_change.is_err(), "schema must fence draft artifacts");

        let mut wrong_kind = planning_effect_intent("direct-effect", "direct-key", 1_100);
        wrong_kind.kind = EffectKind::RunCommand;
        let proposal = effect_proposal_event(&wrong_kind, 1, "direct-proposal");
        {
            let transaction = ledger
                .connection
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .expect("start bypass transaction");
            insert_agent_event(&transaction, &proposal).expect("insert proposal directly");
            insert_effect_request_payload(&transaction, &wrong_kind, EFFECT_REQUEST_BYTES)
                .expect("insert request directly");
            assert!(
                insert_effect_intent(&transaction, &wrong_kind, &proposal.event_id).is_err(),
                "schema must enforce draft effect kind"
            );
            transaction.rollback().expect("rollback bypass writes");
        }

        assert_eq!(row_count(&ledger, "change_sets"), 0);
        assert_eq!(row_count(&ledger, "effect_intents"), 0);
    }

    #[test]
    fn draft_schema_triggers_reject_stale_or_unproven_graph() {
        let database = TestDatabase::new();
        let (spec, graph) = sprint_fixture();
        let mut ledger = EventLedger::open(&database.path).expect("open ledger");
        ledger
            .create_draft_sprint(&spec, &draft_base_snapshot(), 1_000)
            .expect("create draft");

        let mut stale_graph = graph.clone();
        stale_graph.tasks[0].base_snapshot = digest('c');
        let direct_graph = ledger.connection.execute(
            "INSERT INTO sprint_task_graphs (
                sprint_id, graph_id, base_snapshot, contract_version, graph_json
             ) VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                "sprint-1",
                stale_graph.graph_id,
                spec.base_snapshot.as_str(),
                i64::from(CONTRACT_VERSION),
                encode("task graph", &stale_graph).expect("encode stale graph")
            ],
        );
        assert!(direct_graph.is_err(), "schema must reject stale task bases");
        let missing_tasks = ledger.connection.execute(
            "INSERT INTO sprint_task_graphs (
                sprint_id, graph_id, base_snapshot, contract_version, graph_json
             ) VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                "sprint-1",
                "missing-tasks",
                spec.base_snapshot.as_str(),
                i64::from(CONTRACT_VERSION),
                br#"{"graph_id":"missing-tasks"}"#.as_slice()
            ],
        );
        assert!(
            missing_tasks.is_err(),
            "schema must require a nonempty task array"
        );
        let missing_provenance = ledger.connection.execute(
            "INSERT INTO sprint_task_graphs (
                sprint_id, graph_id, base_snapshot, contract_version, graph_json
             ) VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                "sprint-1",
                graph.graph_id,
                spec.base_snapshot.as_str(),
                i64::from(CONTRACT_VERSION),
                encode("task graph", &graph).expect("encode valid graph")
            ],
        );
        assert!(
            missing_provenance.is_err(),
            "schema must reject a graph without provenance"
        );
        let fabricated_provenance = ledger.connection.execute(
            "INSERT INTO sprint_graph_provenance (
                sprint_id, provenance_kind, effect_id, observation_id,
                response_digest, contract_version
             ) VALUES (?1, 'ProviderEffect', ?2, ?3, ?4, ?5)",
            params![
                "sprint-1",
                "fabricated-effect",
                "fabricated-observation",
                digest('f').as_str(),
                i64::from(CONTRACT_VERSION)
            ],
        );
        assert!(
            fabricated_provenance.is_err(),
            "schema must reject fabricated provider provenance"
        );
        assert_eq!(row_count(&ledger, "sprint_task_graphs"), 0);
    }

    #[test]
    fn tool_events_require_atomic_effect_lifecycles_and_orphans_fail_readback() {
        let database = TestDatabase::new();
        let (spec, graph) = sprint_fixture();
        let mut ledger = EventLedger::open(&database.path).expect("open ledger");
        ledger
            .create_sprint(&spec, &graph, 1_000)
            .expect("create planned sprint");
        let intent = planning_effect_intent("orphan-effect", "orphan-key", 1_100);
        let proposal = effect_proposal_event(&intent, 1, "orphan-proposal");

        assert!(matches!(
            ledger.append_event(&proposal),
            Err(LedgerError::ReferenceMismatch {
                entity: "agent event",
                ..
            })
        ));
        assert_eq!(row_count(&ledger, "agent_events"), 0);

        let transaction = ledger
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .expect("start direct event transaction");
        insert_agent_event(&transaction, &proposal).expect("bypass public event API");
        transaction.commit().expect("commit orphan tool event");
        assert!(matches!(
            ledger.load_sprint("sprint-1"),
            Err(LedgerError::Corrupt {
                entity: "effect event relationship",
                ..
            })
        ));
    }

    #[test]
    fn effect_lifecycle_round_trips_with_exact_events_across_restart() {
        let database = TestDatabase::new();
        let (intent, proposal, observation, terminal, expected) = {
            let mut ledger = EventLedger::open(&database.path).expect("open ledger");
            prepare_effect_input(&mut ledger);
            let intent = effect_intent("effect-1", "key-1", 1_200);
            let proposal = effect_proposal_event(&intent, 1, "event-proposed-1");
            let unfinished = record_test_effect_intent(&mut ledger, &intent, &proposal)
                .expect("atomically record intent and proposal");
            assert_eq!(
                unfinished.reconciliation(),
                EffectReconciliation::EvidenceRequired
            );
            assert_eq!(row_count(&ledger, "effect_intents"), 1);
            assert_eq!(row_count(&ledger, "legacy_effect_payload_gaps"), 0);
            assert_eq!(row_count(&ledger, "agent_events"), 1);

            let observation = effect_observation(
                &intent,
                "observation-1",
                EffectOutcome::Succeeded {
                    evidence_digest: effect_evidence_digest(),
                },
                1_300,
            );
            let terminal = effect_terminal_event(
                &intent,
                &proposal.event_id,
                &observation,
                2,
                "event-terminal-1",
            );
            let completed = record_test_effect_observation(&mut ledger, &observation, &terminal)
                .expect("atomically record observation and terminal event");
            assert_eq!(
                completed.reconciliation(),
                EffectReconciliation::TerminalKnown
            );
            (intent, proposal, observation, terminal, completed)
        };

        let ledger = EventLedger::open_read_only(&database.path).expect("reopen read-only");
        assert_eq!(
            ledger.load_effect("effect-1").expect("load effect"),
            expected
        );
        assert_eq!(expected.request_bytes, EFFECT_REQUEST_BYTES);
        assert_eq!(
            expected.evidence_bytes.as_deref(),
            Some(EFFECT_EVIDENCE_BYTES)
        );
        assert_eq!(
            ledger
                .load_effect_by_idempotency_key("sprint-1", "key-1")
                .expect("deduplicate by durable key"),
            Some(expected.clone())
        );
        assert_eq!(
            ledger
                .load_effect_by_idempotency_key("sprint-1", "absent-key")
                .expect("look up absent key"),
            None
        );
        assert_eq!(
            ledger
                .load_effects("sprint-1")
                .expect("load sprint effects"),
            vec![expected.clone()]
        );
        assert!(
            ledger
                .load_unfinished_effects("sprint-1")
                .expect("enumerate unfinished")
                .is_empty()
        );
        let sprint = ledger.load_sprint("sprint-1").expect("restore sprint");
        assert_eq!(sprint.effects, vec![expected]);
        assert_eq!(sprint.events, vec![proposal, terminal]);
        assert_eq!(sprint.effects[0].intent, intent);
        assert_eq!(sprint.effects[0].observation.as_ref(), Some(&observation));
    }

    #[test]
    fn unfinished_restart_is_evidence_required_not_replay_authority() {
        let database = TestDatabase::new();
        let intent = effect_intent("effect-unfinished", "key-unfinished", 1_200);
        let proposal = effect_proposal_event(&intent, 1, "event-unfinished");
        {
            let mut ledger = EventLedger::open(&database.path).expect("open ledger");
            prepare_effect_input(&mut ledger);
            record_test_effect_intent(&mut ledger, &intent, &proposal)
                .expect("commit intent before simulated crash");
        }

        let ledger = EventLedger::open_read_only(&database.path).expect("restart read-only");
        let unfinished = ledger
            .load_unfinished_effects("sprint-1")
            .expect("enumerate unfinished intent");
        assert_eq!(unfinished.len(), 1);
        assert_eq!(unfinished[0].intent, intent);
        assert_eq!(unfinished[0].request_bytes, EFFECT_REQUEST_BYTES);
        assert_eq!(unfinished[0].proposed_event, proposal);
        assert!(unfinished[0].observation.is_none());
        assert!(unfinished[0].evidence_bytes.is_none());
        assert!(unfinished[0].terminal_event.is_none());
        assert_eq!(
            unfinished[0].reconciliation(),
            EffectReconciliation::EvidenceRequired
        );
    }

    #[test]
    fn reconciliation_classification_requires_new_identity_after_proven_no_start() {
        let intent = effect_intent("effect-classify", "key-classify", 1_200);
        let proposal = effect_proposal_event(&intent, 1, "event-classify");
        let mut persisted = PersistedEffect {
            intent: intent.clone(),
            request_bytes: EFFECT_REQUEST_BYTES.to_vec(),
            proposed_event: proposal,
            dispatch_claim: None,
            observation: None,
            evidence_bytes: None,
            terminal_event: None,
            mutation_artifact: PersistedMutationArtifact::NotRequired,
            finish_receipt: PersistedFinishReceipt::NotRequired,
        };
        assert_eq!(
            persisted.reconciliation(),
            EffectReconciliation::EvidenceRequired
        );

        for outcome in [
            EffectOutcome::FailedBeforeEffect {
                evidence_digest: digest('1'),
            },
            EffectOutcome::CancelledBeforeEffect {
                evidence_digest: digest('2'),
            },
        ] {
            persisted.observation = Some(effect_observation(
                &intent,
                "observation-no-start",
                outcome,
                1_300,
            ));
            persisted.evidence_bytes = Some(EFFECT_EVIDENCE_BYTES.to_vec());
            assert_eq!(
                persisted.reconciliation(),
                EffectReconciliation::NewIntentRequired
            );
        }

        for outcome in [
            EffectOutcome::Succeeded {
                evidence_digest: digest('3'),
            },
            EffectOutcome::FailedAfterKnownEffect {
                evidence_digest: digest('4'),
            },
        ] {
            persisted.observation = Some(effect_observation(
                &intent,
                "observation-known",
                outcome,
                1_300,
            ));
            persisted.evidence_bytes = Some(EFFECT_EVIDENCE_BYTES.to_vec());
            assert_eq!(
                persisted.reconciliation(),
                EffectReconciliation::TerminalKnown
            );
        }

        persisted.observation = Some(effect_observation(
            &intent,
            "observation-unknown",
            EffectOutcome::Unknown {
                evidence_digest: digest('5'),
            },
            1_300,
        ));
        persisted.evidence_bytes = Some(EFFECT_EVIDENCE_BYTES.to_vec());
        assert_eq!(
            persisted.reconciliation(),
            EffectReconciliation::EvidenceRequired
        );
    }

    #[test]
    fn effect_atomic_transactions_roll_back_after_late_failures() {
        let database = TestDatabase::new();
        let mut ledger = EventLedger::open(&database.path).expect("open ledger");
        prepare_effect_input(&mut ledger);
        let intent = effect_intent("effect-atomic", "key-atomic", 1_200);
        let proposal = effect_proposal_event(&intent, 1, "event-atomic-proposal");
        ledger
            .connection
            .execute_batch(
                "CREATE TRIGGER test_abort_effect_intent
                 BEFORE INSERT ON effect_intents
                 BEGIN SELECT RAISE(ABORT, 'injected intent failure'); END;",
            )
            .expect("install intent failure injection");
        assert!(matches!(
            record_test_effect_intent(&mut ledger, &intent, &proposal),
            Err(LedgerError::Sql(_))
        ));
        assert_eq!(row_count(&ledger, "effect_intents"), 0);
        assert_eq!(row_count(&ledger, "effect_request_payloads"), 0);
        assert_eq!(row_count(&ledger, "agent_events"), 0);
        ledger
            .connection
            .execute_batch("DROP TRIGGER test_abort_effect_intent;")
            .expect("remove intent failure injection");
        record_test_effect_intent(&mut ledger, &intent, &proposal)
            .expect("retry intent transaction");

        let observation = effect_observation(
            &intent,
            "observation-atomic",
            EffectOutcome::FailedAfterKnownEffect {
                evidence_digest: effect_evidence_digest(),
            },
            1_300,
        );
        let terminal = effect_terminal_event(
            &intent,
            &proposal.event_id,
            &observation,
            2,
            "event-atomic-terminal",
        );
        ledger
            .connection
            .execute_batch(
                "CREATE TRIGGER test_abort_effect_observation
                 BEFORE INSERT ON effect_observations
                 BEGIN SELECT RAISE(ABORT, 'injected observation failure'); END;",
            )
            .expect("install observation failure injection");
        assert!(matches!(
            record_test_effect_observation(&mut ledger, &observation, &terminal),
            Err(LedgerError::Sql(_))
        ));
        assert_eq!(row_count(&ledger, "effect_observations"), 0);
        assert_eq!(row_count(&ledger, "effect_evidence_payloads"), 0);
        assert_eq!(row_count(&ledger, "agent_events"), 1);
        assert_eq!(ledger.next_sequence("sprint-1").expect("next sequence"), 2);
        ledger
            .connection
            .execute_batch("DROP TRIGGER test_abort_effect_observation;")
            .expect("remove observation failure injection");
        record_test_effect_observation(&mut ledger, &observation, &terminal)
            .expect("retry observation transaction");
        assert_eq!(row_count(&ledger, "effect_observations"), 1);
        assert_eq!(row_count(&ledger, "agent_events"), 2);
    }

    #[test]
    fn effect_payloads_reject_mismatch_empty_and_oversize_without_writes() {
        let database = TestDatabase::new();
        let mut ledger = EventLedger::open(&database.path).expect("open ledger");
        prepare_effect_input(&mut ledger);
        let intent = effect_intent("effect-payload", "key-payload", 1_200);
        let proposal = effect_proposal_event(&intent, 1, "event-payload-proposal");

        assert!(matches!(
            ledger.record_effect_intent(&intent, b"different request", &proposal),
            Err(LedgerError::EffectDigestMismatch {
                entity: "effect request",
                ..
            })
        ));
        assert!(matches!(
            ledger.record_effect_intent(&intent, &[], &proposal),
            Err(LedgerError::EffectPayloadSize {
                entity: "effect request",
                actual_bytes: 0,
                ..
            })
        ));
        let oversized_request = vec![b'x'; MAX_EFFECT_REQUEST_BYTES + 1];
        assert!(matches!(
            ledger.record_effect_intent(&intent, &oversized_request, &proposal),
            Err(LedgerError::EffectPayloadSize {
                entity: "effect request",
                ..
            })
        ));
        for table in ["effect_intents", "effect_request_payloads", "agent_events"] {
            assert_eq!(row_count(&ledger, table), 0, "partial row in {table}");
        }

        record_test_effect_intent(&mut ledger, &intent, &proposal)
            .expect("record exact request preimage");
        let observation = effect_observation(
            &intent,
            "observation-payload",
            EffectOutcome::Succeeded {
                evidence_digest: effect_evidence_digest(),
            },
            1_300,
        );
        let terminal = effect_terminal_event(
            &intent,
            &proposal.event_id,
            &observation,
            2,
            "event-payload-terminal",
        );
        assert!(matches!(
            ledger.record_effect_observation(&observation, b"different evidence", &terminal),
            Err(LedgerError::EffectDigestMismatch {
                entity: "effect evidence",
                ..
            })
        ));
        assert!(matches!(
            ledger.record_effect_observation(&observation, &[], &terminal),
            Err(LedgerError::EffectPayloadSize {
                entity: "effect evidence",
                actual_bytes: 0,
                ..
            })
        ));
        let oversized_evidence = vec![b'y'; MAX_EFFECT_EVIDENCE_BYTES + 1];
        assert!(matches!(
            ledger.record_effect_observation(&observation, &oversized_evidence, &terminal),
            Err(LedgerError::EffectPayloadSize {
                entity: "effect evidence",
                ..
            })
        ));
        assert_eq!(row_count(&ledger, "effect_observations"), 0);
        assert_eq!(row_count(&ledger, "effect_evidence_payloads"), 0);
        assert_eq!(row_count(&ledger, "agent_events"), 1);
    }

    #[test]
    fn schema_rejects_digest_only_effect_rows_without_preimages() {
        let database = TestDatabase::new();
        let mut ledger = EventLedger::open(&database.path).expect("open ledger");
        prepare_effect_input(&mut ledger);
        let intent = effect_intent("effect-no-preimage", "key-no-preimage", 1_200);
        let proposal = effect_proposal_event(&intent, 1, "event-no-preimage");
        let transaction = ledger
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .expect("start direct effect transaction");
        insert_agent_event(&transaction, &proposal).expect("insert proposal directly");
        assert!(insert_effect_intent(&transaction, &intent, &proposal.event_id).is_err());
        drop(transaction);
        assert_eq!(row_count(&ledger, "effect_intents"), 0);
        assert_eq!(row_count(&ledger, "effect_request_payloads"), 0);
        assert_eq!(row_count(&ledger, "agent_events"), 0);
    }

    #[test]
    fn effect_protocol_rejects_proposal_mismatch_and_duplicate_identities() {
        let database = TestDatabase::new();
        let mut ledger = EventLedger::open(&database.path).expect("open ledger");
        prepare_effect_input(&mut ledger);

        let intent = effect_intent("effect-context", "key-context", 1_200);
        let mut bad_proposal = effect_proposal_event(&intent, 1, "event-bad-proposal");
        bad_proposal.policy_hash = Some(digest('9'));
        assert!(matches!(
            record_test_effect_intent(&mut ledger, &intent, &bad_proposal),
            Err(LedgerError::ReferenceMismatch {
                entity: "effect proposal event",
                ..
            })
        ));
        assert_eq!(row_count(&ledger, "effect_intents"), 0);
        assert_eq!(row_count(&ledger, "agent_events"), 0);

        let proposal = effect_proposal_event(&intent, 1, "event-context-proposal");
        record_test_effect_intent(&mut ledger, &intent, &proposal)
            .expect("record canonical intent");

        let duplicate_effect = EffectIntent {
            idempotency_key: "key-different".into(),
            created_at_unix_ms: 1_250,
            ..intent.clone()
        };
        let duplicate_effect_event =
            effect_proposal_event(&duplicate_effect, 2, "event-duplicate-effect");
        assert!(matches!(
            record_test_effect_intent(&mut ledger, &duplicate_effect, &duplicate_effect_event),
            Err(LedgerError::ArtifactAlreadyExists {
                entity: "effect intent",
                ..
            })
        ));

        let duplicate_key = EffectIntent {
            effect_id: "effect-different".into(),
            created_at_unix_ms: 1_250,
            ..intent.clone()
        };
        let duplicate_key_event = effect_proposal_event(&duplicate_key, 2, "event-duplicate-key");
        assert!(matches!(
            record_test_effect_intent(&mut ledger, &duplicate_key, &duplicate_key_event),
            Err(LedgerError::ArtifactAlreadyExists {
                entity: "effect idempotency key",
                ..
            })
        ));
        assert_eq!(row_count(&ledger, "effect_intents"), 1);
        assert_eq!(row_count(&ledger, "agent_events"), 1);
    }

    #[test]
    fn effect_protocol_rejects_observation_and_terminal_event_mismatches() {
        let database = TestDatabase::new();
        let mut ledger = EventLedger::open(&database.path).expect("open ledger");
        prepare_effect_input(&mut ledger);
        let intent = effect_intent("effect-context", "key-context", 1_200);
        let proposal = effect_proposal_event(&intent, 1, "event-context-proposal");
        record_test_effect_intent(&mut ledger, &intent, &proposal)
            .expect("record canonical intent");

        let mut mismatched_observation = effect_observation(
            &intent,
            "observation-mismatch",
            EffectOutcome::Succeeded {
                evidence_digest: effect_evidence_digest(),
            },
            1_300,
        );
        mismatched_observation.request_digest = digest('8');
        let mismatched_event = effect_terminal_event(
            &intent,
            &proposal.event_id,
            &mismatched_observation,
            2,
            "event-mismatched-observation",
        );
        assert!(matches!(
            record_test_effect_observation(&mut ledger, &mismatched_observation, &mismatched_event),
            Err(LedgerError::Contract(_))
        ));
        assert_eq!(row_count(&ledger, "effect_observations"), 0);
        assert_eq!(row_count(&ledger, "agent_events"), 1);

        let observation = effect_observation(
            &intent,
            "observation-context",
            EffectOutcome::Succeeded {
                evidence_digest: effect_evidence_digest(),
            },
            1_300,
        );
        let mut bad_terminal = effect_terminal_event(
            &intent,
            &proposal.event_id,
            &observation,
            2,
            "event-bad-terminal",
        );
        bad_terminal.causation_id = None;
        assert!(matches!(
            record_test_effect_observation(&mut ledger, &observation, &bad_terminal),
            Err(LedgerError::ReferenceMismatch {
                entity: "effect terminal event",
                ..
            })
        ));
        assert_eq!(row_count(&ledger, "effect_observations"), 0);
        assert_eq!(row_count(&ledger, "agent_events"), 1);

        let terminal = effect_terminal_event(
            &intent,
            &proposal.event_id,
            &observation,
            2,
            "event-context-terminal",
        );
        record_test_effect_observation(&mut ledger, &observation, &terminal)
            .expect("record canonical terminal evidence");

        let duplicate_observation = EffectObservation {
            observation_id: "observation-duplicate".into(),
            observed_at_unix_ms: 1_400,
            ..observation
        };
        let duplicate_terminal = effect_terminal_event(
            &intent,
            &proposal.event_id,
            &duplicate_observation,
            3,
            "event-duplicate-terminal",
        );
        assert!(matches!(
            record_test_effect_observation(
                &mut ledger,
                &duplicate_observation,
                &duplicate_terminal
            ),
            Err(LedgerError::ArtifactAlreadyExists {
                entity: "effect observation",
                ..
            })
        ));
        assert_eq!(row_count(&ledger, "effect_observations"), 1);
        assert_eq!(row_count(&ledger, "agent_events"), 2);
    }

    #[test]
    fn effect_observation_cannot_exist_without_its_intent() {
        let database = TestDatabase::new();
        let mut ledger = EventLedger::open(&database.path).expect("open ledger");
        prepare_effect_input(&mut ledger);
        let standalone = event(1, "standalone-event", None);
        ledger
            .append_event(&standalone)
            .expect("persist standalone event");

        let result = ledger.connection.execute(
            "INSERT INTO effect_observations (
                observation_id, effect_id, sprint_id, idempotency_key, task_id,
                worker_id, correlation_id, effect_kind, request_digest,
                policy_hash, input_snapshot, outcome, evidence_digest,
                terminal_event_id, contract_version, observed_at_unix_ms,
                observation_json
             ) VALUES (
                'orphan-observation', 'missing-effect', 'sprint-1', 'orphan-key',
                'task-1', 'worker-1', 'orphan-correlation', 'RunCommand', ?1,
                ?2, ?3, 'Unknown', ?4, 'standalone-event', ?5, 1300, X'7B7D'
             )",
            params![
                digest('1').as_str(),
                digest('2').as_str(),
                digest('b').as_str(),
                digest('3').as_str(),
                i64::from(CONTRACT_VERSION)
            ],
        );
        assert!(result.is_err());
        assert_eq!(row_count(&ledger, "effect_observations"), 0);
    }

    #[test]
    fn append_rejects_gaps_duplicates_and_unknown_causation() {
        let database = TestDatabase::new();
        let (spec, graph) = sprint_fixture();
        let mut ledger = EventLedger::open(&database.path).expect("open ledger");
        ledger
            .create_sprint(&spec, &graph, 1_000)
            .expect("persist sprint");

        assert!(matches!(
            ledger.append_event(&event(2, "event-2", None)),
            Err(LedgerError::SequenceMismatch {
                expected: 1,
                actual: 2,
                ..
            })
        ));
        ledger
            .append_event(&event(1, "event-1", None))
            .expect("append first event");
        assert!(matches!(
            ledger.append_event(&event(2, "event-1", None)),
            Err(LedgerError::EventAlreadyExists(event_id)) if event_id == "event-1"
        ));
        assert!(matches!(
            ledger.append_event(&event(1, "event-repeat-sequence", None)),
            Err(LedgerError::SequenceMismatch {
                expected: 2,
                actual: 1,
                ..
            })
        ));
        assert!(matches!(
            ledger.append_event(&event(2, "event-2", Some("missing"))),
            Err(LedgerError::CausationNotFound(event_id)) if event_id == "missing"
        ));
        assert!(matches!(
            ledger.append_event(&event(3, "event-3", Some("event-1"))),
            Err(LedgerError::SequenceMismatch {
                expected: 2,
                actual: 3,
                ..
            })
        ));
        assert_eq!(ledger.next_sequence("sprint-1").expect("next sequence"), 2);
    }

    #[test]
    fn schema_triggers_reject_event_mutation() {
        let database = TestDatabase::new();
        let (spec, graph) = sprint_fixture();
        let mut ledger = EventLedger::open(&database.path).expect("open ledger");
        ledger
            .create_sprint(&spec, &graph, 1_000)
            .expect("persist sprint");
        ledger
            .append_event(&event(1, "event-1", None))
            .expect("append first event");

        let update = ledger.connection.execute(
            "UPDATE agent_events SET event_id = 'rewritten' WHERE event_id = 'event-1'",
            [],
        );
        let delete = ledger
            .connection
            .execute("DELETE FROM agent_events WHERE event_id = 'event-1'", []);
        assert!(update.is_err());
        assert!(delete.is_err());
        assert_eq!(
            ledger
                .load_sprint("sprint-1")
                .expect("load unchanged sprint")
                .events,
            vec![event(1, "event-1", None)]
        );
    }

    #[cfg(unix)]
    #[test]
    fn database_and_live_sidecars_are_user_only() {
        use std::os::unix::fs::PermissionsExt;

        let database = TestDatabase::new();
        let (spec, graph) = sprint_fixture();
        let mut ledger = EventLedger::open(&database.path).expect("open ledger");
        ledger
            .create_sprint(&spec, &graph, 1_000)
            .expect("persist sprint");
        ledger
            .append_event(&event(1, "event-1", None))
            .expect("append event");

        let mut checked = 0;
        for path in [&database.path, &database.path.with_extension("sqlite3-wal")] {
            if path.exists() {
                let mode = fs::metadata(path).expect("read mode").permissions().mode() & 0o777;
                assert_eq!(mode, 0o600, "unexpected permissions for {}", path.display());
                checked += 1;
            }
        }
        assert!(checked >= 1);
    }

    #[test]
    fn historical_worker_lease_key_detection_is_structural_not_textual() {
        let connection = Connection::open_in_memory().expect("open in-memory connection");
        let mut intent = effect_intent("historical-key-literal", "historical-key", 1_200);
        intent.correlation_id = r#"a string containing "worker_lease" is not a JSON key"#.into();
        let historical = encode_pre_v14_without_worker_lease("effect intent", &intent)
            .expect("encode historical effect intent");
        assert!(
            worker_lease_encoding_matches(
                &connection,
                &intent.sprint_id,
                "effect intent",
                &intent,
                &historical,
            )
            .expect("classify exact historical encoding")
        );

        let current = encode("effect intent", &intent).expect("encode current effect intent");
        assert!(json_contains_worker_lease_key(
            "effect intent",
            &serde_json::from_slice(&current).expect("decode current envelope")
        ));
        assert!(!json_contains_worker_lease_key(
            "effect intent",
            &serde_json::json!({"nested": {"worker_lease": null}}),
        ));
    }

    #[test]
    fn schema_version_and_wal_survive_reopen() {
        let database = TestDatabase::new();
        let ledger = EventLedger::open(&database.path).expect("open ledger");
        let schema: i64 = ledger
            .connection
            .pragma_query_value(None, "user_version", |row| row.get(0))
            .expect("read schema version");
        let journal: String = ledger
            .connection
            .pragma_query_value(None, "journal_mode", |row| row.get(0))
            .expect("read journal mode");
        assert_eq!(schema, SCHEMA_VERSION);
        assert_eq!(journal.to_ascii_lowercase(), "wal");
    }

    #[test]
    fn populated_v16_effects_migrate_to_v17_unclaimed_without_retroactive_authority() {
        let database = TestDatabase::new();
        let (intent, observation) = {
            schema_template::install_exact_database_at(16, &database.path);
            let connection = Connection::open(&database.path).expect("create v16 database");
            register_schema_functions(&connection).expect("register v16 schema functions");
            connection
                .execute_batch(
                    "PRAGMA foreign_keys = ON;
                     PRAGMA synchronous = FULL;
                     PRAGMA journal_mode = WAL;
                     PRAGMA trusted_schema = OFF;",
                )
                .expect("configure v16 database");
            let mut v16 = EventLedger {
                connection,
                database_path: database.path.clone(),
                read_only: false,
                instance_id: next_event_ledger_instance_id(),
            };
            prepare_effect_input(&mut v16);
            let intent = effect_intent("pre-v17-effect", "pre-v17-key", 1_200);
            let proposal = effect_proposal_event(&intent, 1, "pre-v17-proposal");
            record_test_effect_intent(&mut v16, &intent, &proposal).expect("persist v16 effect");
            let observation = effect_observation(
                &intent,
                "pre-v17-observation",
                EffectOutcome::FailedBeforeEffect {
                    evidence_digest: effect_evidence_digest(),
                },
                1_300,
            );
            let terminal = effect_terminal_event(
                &intent,
                &proposal.event_id,
                &observation,
                2,
                "pre-v17-finished",
            );
            v16.record_effect_observation(&observation, EFFECT_EVIDENCE_BYTES, &terminal)
                .expect("persist v16 terminal effect");
            (intent, observation)
        };

        let ledger = EventLedger::open(&database.path).expect("upgrade populated v16 database");
        let version: i64 = ledger
            .connection
            .pragma_query_value(None, "user_version", |row| row.get(0))
            .expect("read v17 schema version");
        assert_eq!(version, SCHEMA_VERSION);
        verify_exact_schema(&ledger.connection).expect("schema exactly matches v17");
        assert_eq!(row_count(&ledger, "runner_effect_dispatch_claims"), 0);
        let dispatch_column_count: i64 = ledger
            .connection
            .query_row(
                "SELECT COUNT(*) FROM pragma_table_info('effect_observations')
                 WHERE name = 'dispatch_claim_id'",
                [],
                |row| row.get(0),
            )
            .expect("inspect v17 observation claim column");
        assert_eq!(dispatch_column_count, 1);
        let migrated = ledger
            .load_effect(&intent.effect_id)
            .expect("load migrated terminal effect");
        assert!(migrated.dispatch_claim.is_none());
        assert_eq!(migrated.observation, Some(observation));
        let migrated_claim_id: Option<String> = ledger
            .connection
            .query_row(
                "SELECT dispatch_claim_id FROM effect_observations WHERE effect_id = ?1",
                [&intent.effect_id],
                |row| row.get(0),
            )
            .expect("load migrated nullable claim binding");
        assert!(migrated_claim_id.is_none());
    }

    #[test]
    fn populated_v17_running_claim_migrates_to_v19_normalized_readback_without_authority_remint() {
        let database = TestDatabase::new();
        let (intent, claim) = {
            schema_template::install_exact_database_at(17, &database.path);
            let connection = Connection::open(&database.path).expect("create v17 database");
            register_schema_functions(&connection).expect("register v17 schema functions");
            connection
                .execute_batch(
                    "PRAGMA foreign_keys = ON;
                     PRAGMA synchronous = FULL;
                     PRAGMA journal_mode = WAL;
                     PRAGMA trusted_schema = OFF;",
                )
                .expect("configure v17 database");
            let mut v17 = EventLedger {
                connection,
                database_path: database.path.clone(),
                read_only: false,
                instance_id: next_event_ledger_instance_id(),
            };
            let (_policy, launch, session) = prepare_command_domain_session(&mut v17);
            let running = load_runner_effect_dispatch_running_boundary(&v17.connection, &session)
                .expect("load v17 dispatch Running boundary")
                .expect("v17 task runner has a Running boundary");
            let lease = launch
                .worker_lease
                .as_ref()
                .expect("v17 dispatch launch carries a lease");
            let mut intent = effect_intent("pre-v18-claimed-effect", "pre-v18-claimed-key", 1_200);
            intent.task_id = Some(lease.task_id.clone());
            intent.worker_id = Some(lease.worker_id.clone());
            intent.worker_lease = Some(lease.clone());
            intent.causation_event_id = Some(running.transition_event_id);
            intent.correlation_id = "pre-v18-claimed-dispatch".into();
            intent.policy_hash = launch.policy_hash;
            let proposal = effect_proposal_event(
                &intent,
                v17.next_sequence(&intent.sprint_id)
                    .expect("v17 dispatch proposal sequence"),
                "pre-v18-claimed-proposal",
            );
            let (_, permit) = v17
                .record_runner_effect_intent_for_dispatch(
                    &intent,
                    EFFECT_REQUEST_BYTES,
                    &proposal,
                    &session.session_id,
                )
                .expect("mint v17 dispatch permit");
            let (claimed, transport) = v17
                .claim_runner_effect_dispatch(permit, OPAQUE_RUNNER_TRANSPORT_REQUEST_BYTES)
                .expect("persist populated v17 dispatch claim");
            drop(transport);
            let claim = claimed
                .dispatch_claim
                .expect("v17 effect carries durable dispatch claim");
            assert_eq!(row_count(&v17, "runner_effect_dispatch_claims"), 1);
            (intent, claim)
        };

        let ledger = EventLedger::open(&database.path).expect("upgrade populated v17 database");
        let version: i64 = ledger
            .connection
            .pragma_query_value(None, "user_version", |row| row.get(0))
            .expect("read v19 schema version");
        assert_eq!(version, SCHEMA_VERSION);
        verify_exact_schema(&ledger.connection).expect("schema exactly matches v19");
        assert_eq!(row_count(&ledger, "runner_effect_dispatch_claims"), 1);
        assert_eq!(
            row_count(&ledger, "runner_effect_dispatch_claim_authorities"),
            1
        );
        let migrated = ledger
            .load_effect(&intent.effect_id)
            .expect("load v19 migrated claimed effect");
        assert_eq!(migrated.dispatch_claim, Some(claim));
        assert!(migrated.observation.is_none());
    }

    #[test]
    fn runner_session_nonces_are_globally_single_use() {
        let database = TestDatabase::new();
        let mut ledger = EventLedger::open(&database.path).expect("open ledger");
        prepare_effect_input(&mut ledger);
        let policy = compiled_test_policy("nonce-policy");
        let first_launch = runner_launch(
            "nonce-launch-1",
            "nonce-session-1",
            RunnerSessionPurpose::FinalVerifier,
            None,
            &policy,
            1_100,
        );
        let second_launch = runner_launch(
            "nonce-launch-2",
            "nonce-session-2",
            RunnerSessionPurpose::FinalVerifier,
            None,
            &policy,
            1_101,
        );
        admit_test_runner_launch(&mut ledger, &first_launch, &policy);
        admit_test_runner_launch(&mut ledger, &second_launch, &policy);

        let first = runner_session(&first_launch, 1_200);
        let mut replay = runner_session(&second_launch, 1_201);
        replay.session_nonce = first.session_nonce.clone();
        ledger
            .register_runner_session(&first, &policy)
            .expect("register first nonce");
        assert!(matches!(
            ledger.register_runner_session(&replay, &policy),
            Err(LedgerError::ArtifactAlreadyExists {
                entity: "runner session nonce",
                ..
            })
        ));
        assert_eq!(row_count(&ledger, "runner_session_policies"), 1);
    }

    #[test]
    #[allow(clippy::too_many_lines)] // Atomic authority, bypass fences, and restart share one fixture.
    fn runner_launch_cleanup_admission_is_atomic_unique_and_restart_safe() {
        let database = TestDatabase::new();
        let (launch, request, cleanup_effect) = {
            let mut ledger = EventLedger::open(&database.path).expect("open launch ledger");
            let (policy, launch, intent, request, request_bytes, event) =
                prepare_test_launch_admission(
                    &mut ledger,
                    "round-trip",
                    RunnerSessionPurpose::Applier,
                    None,
                    WorkerCleanupBackend::TrustedApplierDirectChildWait,
                );
            let admitted = ledger
                .admit_runner_launch_with_cleanup(&launch, &policy, &intent, &request_bytes, &event)
                .expect("atomically admit launch and cleanup");
            assert_eq!(admitted.launch, launch);
            assert_eq!(admitted.cleanup_request, request);
            assert_eq!(admitted.cleanup_effect.intent, intent);
            assert_eq!(admitted.cleanup_effect.request_bytes, request_bytes);
            assert_eq!(admitted.cleanup_effect.proposed_event, event);
            assert_eq!(
                ledger
                    .load_runner_launch_intent("sprint-1", &launch.launch_id)
                    .expect("load exact launch-only contract"),
                launch
            );
            assert_eq!(row_count(&ledger, "runner_launch_intents"), 1);
            assert_eq!(row_count(&ledger, "runner_launch_cleanup_admissions"), 1);
            assert_eq!(row_count(&ledger, "legacy_runner_launch_cleanup_gaps"), 0);
            assert_eq!(row_count(&ledger, "effect_intents"), 1);
            assert_eq!(row_count(&ledger, "effect_request_payloads"), 1);
            assert_eq!(row_count(&ledger, "effect_session_bindings"), 1);
            assert_eq!(row_count(&ledger, "finish_effect_kinds"), 1);
            assert_eq!(row_count(&ledger, "agent_events"), 1);

            assert!(matches!(
                ledger.record_runner_launch_intent(&launch, &policy),
                Err(LedgerError::ReferenceMismatch {
                    entity: "runner launch intent",
                    ..
                })
            ));

            ledger
                .register_runner_session(&runner_session(&launch, 1_150), &policy)
                .expect("register admitted runner session");
            let mut duplicate_intent = intent.clone();
            duplicate_intent.effect_id = "duplicate-session-cleanup".into();
            duplicate_intent.idempotency_key = "duplicate-session-cleanup-key".into();
            duplicate_intent.correlation_id = "duplicate-session-cleanup-correlation".into();
            duplicate_intent.created_at_unix_ms = 1_200;
            let duplicate_event = effect_proposal_event(
                &duplicate_intent,
                ledger
                    .next_sequence("sprint-1")
                    .expect("duplicate sequence"),
                "duplicate-session-cleanup-event",
            );
            let counts_before = (
                row_count(&ledger, "effect_intents"),
                row_count(&ledger, "agent_events"),
                row_count(&ledger, "effect_session_bindings"),
            );
            assert!(matches!(
                ledger.record_runner_effect_intent(
                    &duplicate_intent,
                    &request_bytes,
                    &duplicate_event,
                    &launch.session_id,
                ),
                Err(LedgerError::EffectDigestMismatch { .. }
                    | LedgerError::ReferenceMismatch {
                        entity: "cleanup launch binding",
                        ..
                    })
            ));
            assert_eq!(
                (
                    row_count(&ledger, "effect_intents"),
                    row_count(&ledger, "agent_events"),
                    row_count(&ledger, "effect_session_bindings"),
                ),
                counts_before
            );
            for statement in [
                "UPDATE runner_launch_cleanup_admissions SET request_digest = request_digest",
                "DELETE FROM runner_launch_cleanup_admissions",
            ] {
                assert!(
                    ledger.connection.execute_batch(statement).is_err(),
                    "admission mutation unexpectedly succeeded: {statement}"
                );
            }
            (launch, request, intent)
        };

        let ledger = EventLedger::open_read_only(&database.path)
            .expect("reopen atomic launch ledger read-only");
        assert_eq!(
            ledger
                .load_runner_launch_cleanup_admission("sprint-1", &launch.launch_id)
                .expect("reload exact launch cleanup admission"),
            PersistedRunnerLaunchCleanupAdmission {
                launch,
                cleanup_request: request,
                cleanup_effect: ledger
                    .load_effect(&cleanup_effect.effect_id)
                    .expect("reload admitted cleanup effect"),
            }
        );
    }

    #[cfg(unix)]
    #[test]
    fn live_preparation_claim_serializes_cleanup_callback_across_two_ledgers() {
        let database = TestDatabase::new();
        let mut launch_ledger = EventLedger::open(&database.path).expect("open launch ledger");
        let (policy, launch, intent, _, request_bytes, event) = prepare_test_launch_admission(
            &mut launch_ledger,
            "live-claim-barrier",
            RunnerSessionPurpose::FinalVerifier,
            None,
            WorkerCleanupBackend::LinuxCgroupV2,
        );
        let admission = launch_ledger
            .admit_runner_launch_with_cleanup(&launch, &policy, &intent, &request_bytes, &event)
            .expect("admit launch before barrier");
        let attempt = test_launch_preparation_attempt(&admission, "live-claim-barrier", 1_150);
        let mut cleanup_ledger =
            EventLedger::open(&database.path).expect("open competing cleanup ledger");
        let cleanup_sprint_id = launch.sprint_id.clone();
        let cleanup_launch_id = launch.launch_id.clone();

        let (preparation_entered_tx, preparation_entered_rx) = mpsc::channel();
        let (release_preparation_tx, release_preparation_rx) = mpsc::channel();
        let preparation = std::thread::spawn(move || {
            launch_ledger.with_runner_launch_preparation_claim(&admission, &attempt, |_| {
                preparation_entered_tx
                    .send(())
                    .expect("signal live preparation callback");
                release_preparation_rx
                    .recv()
                    .expect("release live preparation callback");
                held_child_preparation_outcome("live-claim-barrier", 1_200)
            })
        });
        preparation_entered_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("preparation callback entered");

        let (cleanup_attempting_tx, cleanup_attempting_rx) = mpsc::channel();
        let (cleanup_entered_tx, cleanup_entered_rx) = mpsc::channel();
        let cleanup = std::thread::spawn(move || {
            cleanup_attempting_tx
                .send(())
                .expect("signal cleanup is attempting exclusion");
            cleanup_ledger.with_runner_launch_cleanup_exclusion(
                &cleanup_sprint_id,
                &cleanup_launch_id,
                |claim| {
                    cleanup_entered_tx
                        .send(())
                        .expect("signal cleanup callback entry");
                    Ok(cleanup_terminal_from_live_claim(
                        claim,
                        "live-claim-barrier",
                        1_300,
                    ))
                },
            )
        });
        cleanup_attempting_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("cleanup thread reached exclusion call");
        assert!(matches!(
            cleanup_entered_rx.recv_timeout(Duration::from_millis(100)),
            Err(mpsc::RecvTimeoutError::Timeout)
        ));
        release_preparation_tx
            .send(())
            .expect("release preparation exclusion");
        let prepared = preparation
            .join()
            .expect("join preparation thread")
            .expect("persist preparation outcome");
        assert!(matches!(
            prepared.outcome,
            Some(RunnerLaunchPreparationOutcome {
                disposition: RunnerLaunchPreparationDisposition::HeldChildPrepared,
                ..
            })
        ));
        cleanup_entered_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("cleanup callback enters only after preparation releases");
        let cleaned = cleanup
            .join()
            .expect("join cleanup thread")
            .expect("persist serialized cleanup");
        assert!(cleaned.observation.is_some());
    }

    #[cfg(unix)]
    #[test]
    fn live_release_claim_serializes_cleanup_and_uses_fresh_held_readback() {
        let database = TestDatabase::new();
        let mut release_ledger = EventLedger::open(&database.path).expect("open release ledger");
        let (policy, launch, intent, _, request_bytes, event) = prepare_test_launch_admission(
            &mut release_ledger,
            "live-release-barrier",
            RunnerSessionPurpose::FinalVerifier,
            None,
            WorkerCleanupBackend::LinuxCgroupV2,
        );
        let admission = release_ledger
            .admit_runner_launch_with_cleanup(&launch, &policy, &intent, &request_bytes, &event)
            .expect("admit launch before release barrier");
        let attempt = test_launch_preparation_attempt(&admission, "live-release-barrier", 1_150);
        let preparation = release_ledger
            .with_runner_launch_preparation_claim(&admission, &attempt, |_| {
                held_child_preparation_outcome("live-release-barrier", 1_200)
            })
            .expect("persist held preparation before release");
        let mut cleanup_ledger =
            EventLedger::open(&database.path).expect("open competing cleanup ledger");
        let cleanup_sprint_id = launch.sprint_id.clone();
        let cleanup_launch_id = launch.launch_id.clone();

        let (release_entered_tx, release_entered_rx) = mpsc::channel();
        let (finish_release_tx, finish_release_rx) = mpsc::channel();
        let release = std::thread::spawn(move || {
            release_ledger.with_runner_launch_release_exclusion(&admission, &preparation, |claim| {
                assert_eq!(claim.admission(), &admission);
                assert_eq!(claim.preparation(), &preparation);
                release_entered_tx
                    .send(())
                    .expect("signal live release callback");
                finish_release_rx
                    .recv()
                    .expect("finish live release callback");
                "released"
            })
        });
        release_entered_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("release callback entered");

        let (cleanup_attempting_tx, cleanup_attempting_rx) = mpsc::channel();
        let (cleanup_entered_tx, cleanup_entered_rx) = mpsc::channel();
        let cleanup = std::thread::spawn(move || {
            cleanup_attempting_tx
                .send(())
                .expect("signal cleanup is attempting release exclusion");
            cleanup_ledger.with_runner_launch_cleanup_exclusion(
                &cleanup_sprint_id,
                &cleanup_launch_id,
                |claim| {
                    cleanup_entered_tx
                        .send(())
                        .expect("signal serialized cleanup callback");
                    Ok(cleanup_terminal_from_live_claim(
                        claim,
                        "live-release-barrier",
                        1_300,
                    ))
                },
            )
        });
        cleanup_attempting_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("cleanup reached exclusion call");
        assert!(matches!(
            cleanup_entered_rx.recv_timeout(Duration::from_millis(100)),
            Err(mpsc::RecvTimeoutError::Timeout)
        ));
        finish_release_tx
            .send(())
            .expect("finish release exclusion");
        assert_eq!(
            release
                .join()
                .expect("join release thread")
                .expect("release exclusion succeeds"),
            "released"
        );
        cleanup_entered_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("cleanup enters only after release returns");
        assert!(
            cleanup
                .join()
                .expect("join cleanup thread")
                .expect("terminalize cleanup after release")
                .observation
                .is_some()
        );
    }

    #[cfg(unix)]
    #[test]
    fn terminal_cleanup_wins_before_stale_release_and_callback_never_runs() {
        let database = TestDatabase::new();
        let mut stale_ledger =
            EventLedger::open(&database.path).expect("open stale release ledger");
        let (policy, launch, intent, _, request_bytes, event) = prepare_test_launch_admission(
            &mut stale_ledger,
            "cleanup-wins-release",
            RunnerSessionPurpose::FinalVerifier,
            None,
            WorkerCleanupBackend::LinuxCgroupV2,
        );
        let stale_admission = stale_ledger
            .admit_runner_launch_with_cleanup(&launch, &policy, &intent, &request_bytes, &event)
            .expect("admit stale release candidate");
        let attempt =
            test_launch_preparation_attempt(&stale_admission, "cleanup-wins-release", 1_150);
        let stale_preparation = stale_ledger
            .with_runner_launch_preparation_claim(&stale_admission, &attempt, |_| {
                held_child_preparation_outcome("cleanup-wins-release", 1_200)
            })
            .expect("persist stale held preparation");
        let mut cleanup_ledger =
            EventLedger::open(&database.path).expect("open cleanup winner ledger");
        cleanup_ledger
            .with_runner_launch_cleanup_exclusion(&launch.sprint_id, &launch.launch_id, |claim| {
                Ok(cleanup_terminal_from_live_claim(
                    claim,
                    "cleanup-wins-release",
                    1_250,
                ))
            })
            .expect("cleanup terminalizes before release");

        let invoked = Arc::new(AtomicBool::new(false));
        let callback_invoked = Arc::clone(&invoked);
        assert!(matches!(
            stale_ledger.with_runner_launch_release_exclusion(
                &stale_admission,
                &stale_preparation,
                move |_| {
                    callback_invoked.store(true, Ordering::SeqCst);
                },
            ),
            Err(LedgerError::ReferenceMismatch {
                entity: "runner launch cleanup admission",
                ..
            })
        ));
        assert!(!invoked.load(Ordering::SeqCst));
    }

    #[cfg(unix)]
    #[test]
    fn refused_preparation_cannot_enter_release_callback() {
        let database = TestDatabase::new();
        let mut ledger = EventLedger::open(&database.path).expect("open refused release ledger");
        let (policy, launch, intent, _, request_bytes, event) = prepare_test_launch_admission(
            &mut ledger,
            "refused-release",
            RunnerSessionPurpose::TaskWorker,
            Some("worker-1"),
            WorkerCleanupBackend::LinuxCgroupV2,
        );
        let admission = ledger
            .admit_runner_launch_with_cleanup(&launch, &policy, &intent, &request_bytes, &event)
            .expect("admit refused release candidate");
        let attempt = test_launch_preparation_attempt(&admission, "refused-release", 1_150);
        let preparation = ledger
            .with_runner_launch_preparation_claim(&admission, &attempt, |_| {
                RunnerLaunchPreparationOutcome {
                    disposition: RunnerLaunchPreparationDisposition::RefusedBeforeNativeEffect,
                    native_evidence_bytes: b"refused before native effect".to_vec(),
                    finished_at_unix_ms: 1_200,
                }
            })
            .expect("persist refused preparation");
        let invoked = Arc::new(AtomicBool::new(false));
        let callback_invoked = Arc::clone(&invoked);
        assert!(matches!(
            ledger.with_runner_launch_release_exclusion(&admission, &preparation, move |_| {
                callback_invoked.store(true, Ordering::SeqCst);
            },),
            Err(LedgerError::ReferenceMismatch {
                entity: "runner launch release exclusion",
                ..
            })
        ));
        assert!(!invoked.load(Ordering::SeqCst));
    }

    #[cfg(unix)]
    #[test]
    #[allow(clippy::too_many_lines)] // One lifecycle exercises validation-before-effect, replay, and crossed-source cases.
    fn v15_launched_disposition_validates_before_cleanup_and_replays_without_callback() {
        let database = TestDatabase::new();
        let mut ledger =
            EventLedger::open(&database.path).expect("open launched disposition ledger");
        let (policy, launch, intent, _, request_bytes, proposal) = prepare_test_launch_admission(
            &mut ledger,
            "v15-launched-disposition",
            RunnerSessionPurpose::TaskWorker,
            Some("worker-1"),
            WorkerCleanupBackend::LinuxCgroupV2,
        );
        let admission = ledger
            .admit_runner_launch_with_cleanup(&launch, &policy, &intent, &request_bytes, &proposal)
            .expect("admit launched disposition cleanup");
        let preparation_attempt =
            test_launch_preparation_attempt(&admission, "v15-launched-disposition", 1_150);
        let refusal_bytes = b"v15 refused before native effect".to_vec();
        ledger
            .with_runner_launch_preparation_claim(&admission, &preparation_attempt, |_| {
                RunnerLaunchPreparationOutcome {
                    disposition: RunnerLaunchPreparationDisposition::RefusedBeforeNativeEffect,
                    native_evidence_bytes: refusal_bytes.clone(),
                    finished_at_unix_ms: 1_200,
                }
            })
            .expect("record independent launch-refusal authority");
        let attempt = task_attempt_authority::load(
            &ledger.connection,
            &launch
                .worker_lease
                .as_ref()
                .expect("task launch lease")
                .lease_id,
        )
        .expect("load current task attempt");
        let metadata = TaskAttemptDispositionMetadata {
            contract_version: CONTRACT_VERSION,
            disposition_id: "v15-launched-disposition-result".into(),
            attempt: attempt.clone(),
            from_state: TaskState::Leased,
            state_transition_event_id: "v15-launched-disposition-transition".into(),
            disposed_at_unix_ms: 1_300,
        };
        let next_sequence = ledger
            .next_sequence(&launch.sprint_id)
            .expect("cleanup terminal sequence");
        let transition = AgentEvent {
            contract_version: CONTRACT_VERSION,
            sequence: next_sequence + 1,
            event_id: metadata.state_transition_event_id.clone(),
            sprint_id: launch.sprint_id.clone(),
            task_id: Some(attempt.worker_lease.task_id.clone()),
            worker_id: Some(attempt.worker_lease.worker_id.clone()),
            causation_id: Some(attempt.opening_event_id.clone()),
            correlation_id: "v15-launched-disposition-correlation".into(),
            policy_hash: Some(launch.policy_hash.clone()),
            occurred_at_unix_ms: metadata.disposed_at_unix_ms,
            payload: AgentEventKind::TaskStateChanged {
                from: "Leased".into(),
                to: "Ready".into(),
            },
        };
        let missing_source = TaskAttemptKnownCleanupOutcome::Retryable(
            crate::TaskAttemptRetryableCause::KnownWorkerExit {
                launch_id: launch.launch_id.clone(),
                session_id: launch.session_id.clone(),
                evidence: crate::TaskAttemptEvidence::new(
                    "v15-missing-worker-exit-source".into(),
                    crate::TaskAttemptEvidenceKind::KnownWorkerExit,
                    b"missing independent worker exit source".to_vec(),
                )
                .expect("valid missing source evidence"),
            },
        );
        let invoked = Arc::new(AtomicBool::new(false));
        let invalid_invoked = Arc::clone(&invoked);
        assert!(
            ledger
                .with_task_attempt_cleanup_disposition_exclusion(
                    &metadata,
                    &missing_source,
                    "v15-launched-release",
                    &transition,
                    move |_| {
                        invalid_invoked.store(true, Ordering::SeqCst);
                        panic!("missing source must reject before native cleanup")
                    },
                )
                .is_err()
        );
        assert!(!invoked.load(Ordering::SeqCst));
        assert_eq!(row_count(&ledger, "worker_cleanup_receipts"), 0);
        assert_eq!(row_count(&ledger, "task_attempt_dispositions"), 0);

        let cancellation_evidence = crate::TaskAttemptEvidence::new(
            "v15-independent-cancellation-source".into(),
            crate::TaskAttemptEvidenceKind::OperatorCanceled,
            b"operator cancellation source recorded before cleanup".to_vec(),
        )
        .expect("valid cancellation evidence");
        let cancellation =
            TaskAttemptKnownCleanupOutcome::Canceled(crate::TaskAttemptCanceledCause {
                cancellation_id: "v15-independent-cancellation".into(),
                evidence: cancellation_evidence.clone(),
            });
        assert_eq!(
            ledger
                .record_task_attempt_cleanup_outcome_authority(&attempt, &cancellation, 1_210)
                .expect("record independent cancellation source"),
            cancellation
        );
        assert_eq!(
            ledger
                .record_task_attempt_cleanup_outcome_authority(&attempt, &cancellation, 1_210)
                .expect("exact source replay before cleanup"),
            cancellation
        );

        let refusal = TaskAttemptKnownCleanupOutcome::Retryable(
            crate::TaskAttemptRetryableCause::LaunchRefusedBeforeNativeEffect {
                launch_id: launch.launch_id.clone(),
                evidence: crate::TaskAttemptEvidence::new(
                    preparation_attempt.attempt_id.clone(),
                    crate::TaskAttemptEvidenceKind::LaunchRefusedBeforeNativeEffect,
                    refusal_bytes,
                )
                .expect("valid launch refusal evidence"),
            },
        );
        let mut wrong_transition = transition.clone();
        wrong_transition.payload = AgentEventKind::TaskStateChanged {
            from: "Running".into(),
            to: "Ready".into(),
        };
        let invoked = Arc::new(AtomicBool::new(false));
        let invalid_invoked = Arc::clone(&invoked);
        assert!(
            ledger
                .with_task_attempt_cleanup_disposition_exclusion(
                    &metadata,
                    &refusal,
                    "v15-launched-release",
                    &wrong_transition,
                    move |_| {
                        invalid_invoked.store(true, Ordering::SeqCst);
                        panic!("crossed event must reject before native cleanup")
                    },
                )
                .is_err()
        );
        assert!(!invoked.load(Ordering::SeqCst));

        let cancellation_metadata = TaskAttemptDispositionMetadata {
            contract_version: metadata.contract_version,
            disposition_id: metadata.disposition_id.clone(),
            attempt: attempt.clone(),
            from_state: metadata.from_state,
            state_transition_event_id: metadata.state_transition_event_id.clone(),
            disposed_at_unix_ms: metadata.disposed_at_unix_ms,
        };
        let mut cancellation_transition = transition.clone();
        cancellation_transition.payload = AgentEventKind::TaskStateChanged {
            from: "Leased".into(),
            to: "Canceled".into(),
        };
        let invoked = Arc::new(AtomicBool::new(false));
        let loser_invoked = Arc::clone(&invoked);
        assert!(matches!(
            ledger.with_task_attempt_cleanup_disposition_exclusion(
                &metadata,
                &refusal,
                "v15-launched-release",
                &transition,
                move |_| {
                    loser_invoked.store(true, Ordering::SeqCst);
                    panic!("noncanonical cleanup source must reject before native cleanup")
                },
            ),
            Err(LedgerError::ReferenceMismatch {
                entity: "task attempt cleanup source precedence",
                ..
            })
        ));
        assert!(!invoked.load(Ordering::SeqCst));

        let stored = ledger
            .with_task_attempt_cleanup_disposition_exclusion(
                &cancellation_metadata,
                &cancellation,
                "v15-launched-release",
                &cancellation_transition,
                |claim| {
                    Ok(cleanup_terminal_from_live_claim(
                        claim,
                        "v15-launched-disposition",
                        1_250,
                    ))
                },
            )
            .expect("atomically close launched attempt with canonical cancellation");
        assert!(matches!(stored, TaskAttemptDisposition::Canceled(_)));
        let cleanup_release = match &stored {
            TaskAttemptDisposition::Canceled(value) => match &value.release_proof {
                crate::TaskAttemptReleaseProof::Cleanup(release) => release.clone(),
                crate::TaskAttemptReleaseProof::NeverLaunched(_) => {
                    unreachable!("launched cancellation uses cleanup release")
                }
            },
            _ => unreachable!("canonical cancellation was asserted above"),
        };
        let mut direct_loser_metadata = metadata.clone();
        direct_loser_metadata.disposition_id = "v15-direct-noncanonical-disposition".into();
        direct_loser_metadata.state_transition_event_id =
            "v15-direct-noncanonical-transition".into();
        let (spec, _, _) = load_sprint_inputs(&ledger.connection, &launch.sprint_id)
            .expect("load source-precedence sprint budget");
        let direct_loser = task_attempt_authority::computed_cleanup_disposition(
            direct_loser_metadata,
            refusal.clone(),
            cleanup_release,
            spec.budget.max_attempts_per_task,
        )
        .expect("construct valid loser disposition envelope");
        let transaction = ledger
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .expect("start direct noncanonical disposition attempt");
        let sql_error = task_attempt_authority::insert_disposition(&transaction, &direct_loser)
            .expect_err("SQL independently rejects noncanonical source winner");
        assert!(
            sql_error
                .to_string()
                .contains("not the canonical known-cleanup source winner"),
            "unexpected canonical source SQL rejection: {sql_error}"
        );
        transaction
            .rollback()
            .expect("rollback direct noncanonical disposition");
        let replay = ledger
            .with_task_attempt_cleanup_disposition_exclusion(
                &cancellation_metadata,
                &cancellation,
                "v15-launched-release",
                &cancellation_transition,
                |_| panic!("exact replay must not invoke native cleanup"),
            )
            .expect("exact launched disposition replay");
        assert_eq!(replay, stored);
        assert_eq!(row_count(&ledger, "worker_cleanup_receipts"), 1);
        assert_eq!(row_count(&ledger, "task_attempt_dispositions"), 1);
        assert_eq!(row_count(&ledger, "worker_lease_releases"), 1);
        drop(ledger);
        let mut reopened =
            EventLedger::open(&database.path).expect("reopen disposed source ledger");
        assert_eq!(
            reopened
                .record_task_attempt_cleanup_outcome_authority(&attempt, &cancellation, 1_210)
                .expect("exact source replay after release and reopen"),
            cancellation
        );
        let crossed = TaskAttemptKnownCleanupOutcome::Canceled(crate::TaskAttemptCanceledCause {
            cancellation_id: "v15-crossed-cancellation".into(),
            evidence: cancellation_evidence,
        });
        assert!(
            reopened
                .record_task_attempt_cleanup_outcome_authority(&attempt, &crossed, 1_210)
                .is_err()
        );
        assert_eq!(
            row_count(&reopened, "task_attempt_policy_cause_authorities"),
            1
        );
    }

    #[cfg(unix)]
    #[test]
    fn planned_task_attempt_cleanup_retry_is_core_derived_and_receipt_timed() {
        let database = TestDatabase::new();
        let mut ledger = EventLedger::open(&database.path).expect("open planned retry ledger");
        let attempt = prepare_planned_refused_task_attempt(&mut ledger, "planned-retry", 2);
        let plan = ledger
            .plan_task_attempt_cleanup_disposition(&attempt)
            .expect("derive planned retry cleanup");
        assert_eq!(plan.contract_version, CONTRACT_VERSION);
        assert_eq!(plan.attempt, attempt);
        assert_eq!(plan.from_state, TaskState::Leased);
        assert_eq!(plan.resulting_task_state, TaskState::Ready);
        assert_eq!(plan.minimum_terminal_at_unix_ms(), 1_200);
        assert!(matches!(
            plan.outcome,
            TaskAttemptKnownCleanupOutcome::Retryable(
                crate::TaskAttemptRetryableCause::LaunchRefusedBeforeNativeEffect { .. }
            )
        ));

        let cleanup_sequence = ledger
            .next_sequence(&attempt.worker_lease.sprint_id)
            .expect("planned retry cleanup sequence");
        let cleaned_at_unix_ms = plan.minimum_terminal_at_unix_ms() + 37;
        let stored = ledger
            .with_planned_task_attempt_cleanup_disposition_exclusion(&plan, |claim| {
                assert_eq!(
                    claim.minimum_terminal_at_unix_ms(),
                    plan.minimum_terminal_at_unix_ms()
                );
                Ok(cleanup_terminal_from_live_claim(
                    claim,
                    "planned-retry",
                    cleaned_at_unix_ms,
                ))
            })
            .expect("commit planned retry cleanup");
        assert!(matches!(stored, TaskAttemptDisposition::Retryable(_)));
        assert_eq!(stored.resulting_task_state(), TaskState::Ready);
        assert_eq!(stored.metadata().disposition_id, plan.disposition_id);
        assert_eq!(
            stored.metadata().state_transition_event_id,
            plan.transition_event_id
        );
        assert_eq!(stored.metadata().disposed_at_unix_ms, cleaned_at_unix_ms);
        let release = match stored.release_proof().expect("planned retry release") {
            crate::TaskAttemptReleaseProof::Cleanup(release) => release,
            crate::TaskAttemptReleaseProof::NeverLaunched(_) => {
                panic!("launched planned cleanup requires a cleanup release")
            }
        };
        assert_eq!(release.release_id, plan.release_id);
        assert_eq!(release.released_at_unix_ms, cleaned_at_unix_ms);
        assert_eq!(
            release.cleanup_receipt.cleaned_at_unix_ms,
            cleaned_at_unix_ms
        );
        let cleanup_effect =
            load_effect_from(&ledger.connection, &release.cleanup_receipt.effect_id)
                .expect("load planned retry cleanup effect");
        let cleanup_event = cleanup_effect
            .terminal_event
            .expect("planned retry cleanup terminal event");
        let transition = load_event_by_id(&ledger.connection, &plan.transition_event_id)
            .expect("load planned retry transition");
        assert_eq!(cleanup_event.sequence, cleanup_sequence);
        assert_eq!(transition.sequence, cleanup_sequence + 1);
        assert_eq!(
            transition.causation_id.as_deref(),
            Some(cleanup_event.event_id.as_str())
        );
        assert_eq!(transition.occurred_at_unix_ms, cleaned_at_unix_ms);
        assert_eq!(
            current_task_state(
                &ledger.connection,
                &attempt.worker_lease.sprint_id,
                &attempt.worker_lease.task_id,
            )
            .expect("load planned retry state"),
            TaskState::Ready
        );
        assert_eq!(
            row_count(&ledger, "task_attempt_cleanup_result_coverage"),
            1
        );
        assert_eq!(row_count(&ledger, "worker_cleanup_receipts"), 1);
        assert_eq!(row_count(&ledger, "task_attempt_dispositions"), 1);
        assert_eq!(row_count(&ledger, "worker_lease_releases"), 1);
    }

    #[cfg(unix)]
    #[test]
    fn planned_task_attempt_cleanup_exhaustion_is_core_derived() {
        let database = TestDatabase::new();
        let mut ledger = EventLedger::open(&database.path).expect("open planned exhaustion ledger");
        let attempt = prepare_planned_refused_task_attempt(&mut ledger, "planned-exhaustion", 1);
        let plan = ledger
            .plan_task_attempt_cleanup_disposition(&attempt)
            .expect("derive planned exhausted cleanup");
        assert_eq!(attempt.attempt_ordinal, 1);
        assert_eq!(plan.resulting_task_state, TaskState::Failed);
        let cleaned_at_unix_ms = plan.minimum_terminal_at_unix_ms();
        let stored = ledger
            .with_planned_task_attempt_cleanup_disposition_exclusion(&plan, |claim| {
                Ok(cleanup_terminal_from_live_claim(
                    claim,
                    "planned-exhaustion",
                    cleaned_at_unix_ms,
                ))
            })
            .expect("commit planned exhausted cleanup");
        assert!(matches!(
            stored,
            TaskAttemptDisposition::AttemptsExhausted(_)
        ));
        assert_eq!(stored.resulting_task_state(), TaskState::Failed);
        assert_eq!(
            current_task_state(
                &ledger.connection,
                &attempt.worker_lease.sprint_id,
                &attempt.worker_lease.task_id,
            )
            .expect("load planned exhausted state"),
            TaskState::Failed
        );
    }

    #[cfg(unix)]
    #[test]
    fn planned_task_attempt_cleanup_crossed_plan_rejects_before_callback() {
        let database = TestDatabase::new();
        let mut ledger =
            EventLedger::open(&database.path).expect("open crossed planned-cleanup ledger");
        let attempt = prepare_planned_refused_task_attempt(&mut ledger, "planned-crossed", 2);
        let stale_plan = ledger
            .plan_task_attempt_cleanup_disposition(&attempt)
            .expect("derive plan before preferred-source race");
        let cancellation =
            TaskAttemptKnownCleanupOutcome::Canceled(crate::TaskAttemptCanceledCause {
                cancellation_id: "planned-crossed-cancellation".into(),
                evidence: crate::TaskAttemptEvidence::new(
                    "planned-crossed-cancellation-evidence".into(),
                    crate::TaskAttemptEvidenceKind::OperatorCanceled,
                    b"operator cancellation crossed the retained cleanup plan".to_vec(),
                )
                .expect("valid crossed cancellation evidence"),
            });
        ledger
            .record_task_attempt_cleanup_outcome_authority(&attempt, &cancellation, 1_210)
            .expect("record preferred cancellation after plan derivation");

        let invoked = Arc::new(AtomicBool::new(false));
        let callback_invoked = Arc::clone(&invoked);
        assert!(matches!(
            ledger.with_planned_task_attempt_cleanup_disposition_exclusion(
                &stale_plan,
                move |_| {
                    callback_invoked.store(true, Ordering::SeqCst);
                    panic!("crossed plan must reject before native cleanup")
                },
            ),
            Err(LedgerError::ReferenceMismatch {
                entity: "planned task attempt cleanup disposition",
                ..
            })
        ));
        assert!(!invoked.load(Ordering::SeqCst));
        assert_eq!(row_count(&ledger, "worker_cleanup_receipts"), 0);
        assert_eq!(row_count(&ledger, "task_attempt_dispositions"), 0);
        assert_eq!(row_count(&ledger, "worker_lease_releases"), 0);
        assert_eq!(
            row_count(&ledger, "task_attempt_cleanup_result_coverage"),
            0
        );

        let current_plan = ledger
            .plan_task_attempt_cleanup_disposition(&attempt)
            .expect("derive replacement preferred-source plan");
        assert_ne!(current_plan, stale_plan);
        assert!(matches!(
            current_plan.outcome,
            TaskAttemptKnownCleanupOutcome::Canceled(_)
        ));
        assert_eq!(current_plan.resulting_task_state, TaskState::Canceled);
        assert_eq!(current_plan.minimum_terminal_at_unix_ms(), 1_210);
    }

    #[cfg(unix)]
    #[test]
    fn planned_task_attempt_cleanup_below_minimum_rolls_back() {
        let database = TestDatabase::new();
        let mut ledger =
            EventLedger::open(&database.path).expect("open below-minimum planned-cleanup ledger");
        let attempt = prepare_planned_refused_task_attempt(&mut ledger, "planned-below-minimum", 2);
        let plan = ledger
            .plan_task_attempt_cleanup_disposition(&attempt)
            .expect("derive below-minimum cleanup plan");
        let below_minimum = plan
            .minimum_terminal_at_unix_ms()
            .checked_sub(1)
            .expect("fixture cleanup minimum is nonzero");
        let invoked = Arc::new(AtomicBool::new(false));
        let callback_invoked = Arc::clone(&invoked);
        assert!(matches!(
            ledger.with_planned_task_attempt_cleanup_disposition_exclusion(&plan, move |claim| {
                callback_invoked.store(true, Ordering::SeqCst);
                Ok(cleanup_terminal_from_live_claim(
                    claim,
                    "planned-below-minimum",
                    below_minimum,
                ))
            },),
            Err(LedgerError::ReferenceMismatch {
                entity: "planned task attempt cleanup disposition",
                ..
            })
        ));
        assert!(invoked.load(Ordering::SeqCst));
        assert_eq!(row_count(&ledger, "worker_cleanup_receipts"), 0);
        assert_eq!(row_count(&ledger, "task_attempt_dispositions"), 0);
        assert_eq!(row_count(&ledger, "worker_lease_releases"), 0);
        assert_eq!(
            row_count(&ledger, "task_attempt_cleanup_result_coverage"),
            0
        );
        assert_eq!(row_count(&ledger, "active_worker_leases"), 1);
        assert!(
            !event_exists(&ledger.connection, &plan.transition_event_id)
                .expect("check rolled-back transition identity")
        );
        assert_eq!(
            ledger
                .plan_task_attempt_cleanup_disposition(&attempt)
                .expect("rederive plan after timestamp rollback"),
            plan
        );
    }

