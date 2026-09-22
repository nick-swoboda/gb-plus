    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "the restart regression exact-compares the complete migrated completion image"
    )]
    fn completion_artifacts_round_trip_across_read_only_restart() {
        let database = TestDatabase::new();
        let (projection, legacy_receipt_bytes, legacy_receipt_digest) = {
            let mut ledger = open_v21_test_ledger(&database);
            let (report, receipt, event) = prepare_completion_evidence(&mut ledger);
            let expected = record_pre_v24_successful_completion_for_test(
                &mut ledger,
                &report,
                &receipt,
                &event,
            )
            .expect("record atomic completion");
            let stored_receipt_bytes = ledger
                .connection
                .query_row(
                    "SELECT receipt_json FROM v9_completion_receipts
                     WHERE receipt_id = ?1",
                    [&receipt.receipt_id],
                    |row| row.get::<_, Vec<u8>>(0),
                )
                .expect("load genuine pre-v28 completion bytes");
            assert_eq!(
                stored_receipt_bytes,
                encode_legacy_completion_receipt(&receipt)
                    .expect("encode expected pre-v28 completion wire image")
            );
            assert_ne!(
                stored_receipt_bytes,
                encode("current completion receipt", &receipt)
                    .expect("encode current completion wire image"),
                "historical fixture must not manufacture v28 field names"
            );
            let stored_receipt_digest = Digest::sha256(&stored_receipt_bytes);
            assert_eq!(
                ledger
                    .load_final_report(&report.report_id)
                    .expect("read report"),
                report
            );
            assert_eq!(
                ledger
                    .load_completion_receipt(&receipt.receipt_id)
                    .expect("read completion receipt"),
                receipt
            );
            let integration = ledger
                .load_task_integration_evidence("integration-task-1")
                .expect("read exact integration artifact evidence");
            assert_eq!(integration.receipt.change_set_id, "change-1");
            assert_eq!(integration.artifact.format_version, 1);
            assert_eq!(
                integration.artifact.change_set_id,
                integration.receipt.change_set_id
            );
            assert_eq!(
                integration.validation.mode,
                TaskIntegrationValidationMode::WorkerPublication
            );
            assert_eq!(
                integration.validation.runner_session_id,
                integration.receipt.worker_session_id
            );
            assert!(matches!(
                ledger.append_event(&AgentEvent {
                    sequence: 2,
                    event_id: "after-terminal".into(),
                    occurred_at_unix_ms: 2_100,
                    payload: AgentEventKind::Diagnostic("must fail".into()),
                    ..event
                }),
                Err(LedgerError::SprintAlreadyTerminal(sprint_id))
                    if sprint_id == "sprint-1"
            ));
            (expected, stored_receipt_bytes, stored_receipt_digest)
        };

        let ledger =
            EventLedger::open(&database.path).expect("migrate historical completion for readback");
        let migrated_receipt_bytes = ledger
            .connection
            .query_row(
                "SELECT receipt_json FROM v9_completion_receipts
                 WHERE receipt_id = ?1",
                [&projection.receipt.receipt_id],
                |row| row.get::<_, Vec<u8>>(0),
            )
            .expect("load migrated completion bytes");
        assert_eq!(
            migrated_receipt_bytes, legacy_receipt_bytes,
            "v28 migration must retain the exact historical receipt bytes"
        );
        let exemption_digest: String = ledger
            .connection
            .query_row(
                "SELECT completion_receipt_digest
                 FROM pre_v24_completion_live_state_capture_exemptions
                 WHERE completion_receipt_id = ?1",
                [&projection.receipt.receipt_id],
                |row| row.get(0),
            )
            .expect("load exact pre-v24 receipt digest");
        assert_eq!(exemption_digest, legacy_receipt_digest.as_str());
        let legacy_marker_count: i64 = ledger
            .connection
            .query_row(
                "SELECT COUNT(*) FROM v28_legacy_completion_acceptance_sets
                 WHERE completion_receipt_id = ?1",
                [&projection.receipt.receipt_id],
                |row| row.get(0),
            )
            .expect("count migrated legacy completion marker");
        assert_eq!(legacy_marker_count, 1);
        let typed_link_count: i64 = ledger
            .connection
            .query_row(
                "SELECT COUNT(*) FROM v28_completion_criterion_evidence_receipts
                 WHERE completion_receipt_id = ?1",
                [&projection.receipt.receipt_id],
                |row| row.get(0),
            )
            .expect("count forbidden typed backfill links");
        assert_eq!(
            typed_link_count, 0,
            "migration must not recast legacy evidence"
        );
        let expected = load_migrated_pre_v24_completion(&ledger, &projection);
        let restored = ledger
            .load_sprint("sprint-1")
            .expect("restore complete sprint");
        assert_eq!(restored.completion, Some(expected.clone()));
        assert_eq!(restored.terminal_outcome, None);
        assert_eq!(restored.events.len(), 21);
        let attempt_phase_events = restored
            .events
            .iter()
            .map(|event| event.event_id.as_str())
            .filter(|event_id| {
                matches!(
                    *event_id,
                    "launch-worker-test-running"
                        | "event-verify-task-1-verifying"
                        | "event-verify-task-1-candidate"
                        | "event-integration-task-1-integrated"
                )
            })
            .collect::<Vec<_>>();
        assert_eq!(
            attempt_phase_events,
            [
                "launch-worker-test-running",
                "event-verify-task-1-verifying",
                "event-verify-task-1-candidate",
                "event-integration-task-1-integrated",
            ]
        );
        assert_eq!(restored.events.last(), Some(&expected.event));
        let integration = ledger
            .load_task_integration_evidence("integration-task-1")
            .expect("restore exact integration artifact evidence");
        assert_eq!(
            integration.artifact.result_snapshot,
            integration.receipt.result_snapshot
        );
        assert_eq!(
            integration.validation.runner_launch_id,
            integration.receipt.worker_launch_id
        );
        assert_eq!(
            ledger.load_completion("sprint-1").expect("load completion"),
            Some(expected.clone())
        );
        drop(ledger);
        let read_only = EventLedger::open_read_only(&database.path)
            .expect("restart migrated historical completion read-only");
        let restarted = read_only
            .load_completion("sprint-1")
            .expect("read historical completion after read-only restart")
            .expect("historical completion remains present after restart");
        assert_eq!(restarted, expected);
        assert_eq!(
            restarted.completion_receipt_wire_digest,
            legacy_receipt_digest
        );
    }

    #[test]
    fn v28_migration_rejects_a_completion_parent_without_legacy_criterion_links() {
        let database = TestDatabase::new();
        {
            let mut ledger = open_v21_test_ledger(&database);
            let (report, receipt, event) = prepare_completion_evidence(&mut ledger);
            record_pre_v24_successful_completion_for_test(&mut ledger, &report, &receipt, &event)
                .expect("record historical completion before tearing its link set");
            ledger
                .connection
                .execute_batch(
                    "DROP TRIGGER v9_completion_acceptance_no_delete;
                     DELETE FROM v9_completion_acceptance_receipts
                     WHERE completion_receipt_id = 'completion-1';",
                )
                .expect("tear historical criterion links for migration refusal");
        }

        let Err(error) = EventLedger::open(&database.path) else {
            panic!("v28 migration accepted a completion with no historical criterion links");
        };
        assert!(matches!(error, LedgerError::Sql(_)));
        let connection = Connection::open(&database.path).expect("inspect refused v28 migration");
        let version: i64 = connection
            .pragma_query_value(None, "user_version", |row| row.get(0))
            .expect("read version after refused v28 migration");
        assert_eq!(
            version, 27,
            "the failing v28 migration must roll back atomically"
        );
        let v28_table_exists: bool = connection
            .query_row(
                "SELECT EXISTS(
                     SELECT 1 FROM sqlite_schema
                     WHERE type = 'table'
                       AND name = 'v28_legacy_completion_acceptance_sets'
                 )",
                [],
                |row| row.get(0),
            )
            .expect("inspect rolled-back v28 schema");
        assert!(!v28_table_exists);
    }

    #[test]
    fn task_done_proof_is_exact_and_reopens_read_only() {
        let database = TestDatabase::new();
        let expected = {
            let mut ledger = open_v21_test_ledger(&database);
            let _ = prepare_completion_evidence(&mut ledger);
            let assessment = ledger
                .assess_task_done("sprint-1", "task-1")
                .expect("compute exact task done proof");
            assert!(assessment.is_done());
            assert!(assessment.unmet_requirements.is_empty());
            let proof = assessment.proof.as_ref().expect("complete proof");
            assert_eq!(
                proof.attempt.worker_lease.lease_id,
                proof.attempt.attempt_id
            );
            assert_eq!(
                proof.integration_disposition_id,
                "disposition-integration-task-1"
            );
            assert_eq!(proof.change_set.change_set_id, "change-1");
            assert_eq!(
                proof.integration_receipt.result_snapshot,
                proof.change_set.result_snapshot
            );
            assert_eq!(proof.formal_check_ids, ["formal-check-verify-task-1"]);
            assert_eq!(proof.command_domain_cleanup.entries.len(), 1);
            assert_eq!(proof.runner_cleanup.receipt.surviving_processes, 0);
            assert!(matches!(
                proof.lease_release,
                TaskAttemptLeaseState::Released { .. }
            ));
            assessment
        };

        let reader = EventLedger::open(&database.path)
            .expect("migrate historical task-done ledger for readback");
        assert_eq!(
            reader
                .assess_task_done("sprint-1", "task-1")
                .expect("recompute task done after restart"),
            expected
        );
    }

    #[test]
    fn task_done_static_command_readback_rehashes_request_after_prior_full_validation() {
        let database = TestDatabase::new();
        let mut ledger = open_v21_test_ledger(&database);
        let _ = prepare_completion_evidence(&mut ledger);
        let command_effect_id = ledger
            .connection
            .query_row(
                "SELECT effect_id FROM effect_intents
                 WHERE sprint_id = 'sprint-1'
                   AND task_id = 'task-1'
                   AND effect_kind = 'RunCommand'",
                [],
                |row| row.get::<_, String>(0),
            )
            .expect("load the exact task command effect identity");
        let validated = ledger
            .load_effect(&command_effect_id)
            .expect("fully validate the task command before the corruption cut");

        ledger
            .connection
            .execute_batch("DROP TRIGGER effect_request_payloads_no_update;")
            .expect("open only the request immutability fence for the corruption probe");
        ledger
            .connection
            .execute(
                "UPDATE effect_request_payloads
                 SET request_bytes = X'00'
                 WHERE effect_id = ?1",
                [&command_effect_id],
            )
            .expect("corrupt the request after its complete lifecycle was loaded");

        assert!(matches!(
            command_domain_cleanup::load_task_done_command_domain_cleanup_completeness_from(
                &ledger.connection,
                "sprint-1",
                "launch-worker",
                "session-worker",
                CommandDomainBackend::LinuxCgroupV2,
                &[&validated],
            ),
            Err(LedgerError::Corrupt {
                entity: "effect request payload",
                ..
            })
        ));
    }

    #[test]
    fn task_done_rejects_missing_command_cleanup_and_crossed_snapshot() {
        let missing_database = TestDatabase::new();
        let mut missing = open_v21_test_ledger(&missing_database);
        let _ = prepare_completion_evidence(&mut missing);
        missing
            .connection
            .execute_batch(
                "DROP TRIGGER command_domain_cleanup_proofs_no_delete;
                 DELETE FROM command_domain_cleanup_proofs
                 WHERE proof_id = 'command-cleanup-task-1';",
            )
            .expect("inject missing command cleanup");
        let assessment = missing
            .assess_task_done("sprint-1", "task-1")
            .expect("missing proof is incomplete, not authority");
        assert!(!assessment.is_done());
        assert_eq!(assessment.proof, None);
        assert_eq!(
            assessment.unmet_requirements,
            [TaskDoneRequirement::CommandDomainCleanupProven]
        );

        let crossed_database = TestDatabase::new();
        let mut crossed = open_v21_test_ledger(&crossed_database);
        let _ = prepare_completion_evidence(&mut crossed);
        let alternate_snapshot = WorkspaceSnapshot {
            snapshot_id: digest('9'),
            grant_hash: digest('a'),
            created_at_unix_ms: 1_205,
        };
        crossed
            .persist_workspace_snapshot("sprint-1", &alternate_snapshot)
            .expect("persist alternate corruption target snapshot");
        crossed
            .connection
            .execute_batch("DROP TRIGGER task_integration_receipts_no_update;")
            .expect("disable integration receipt immutability for corruption");
        crossed
            .connection
            .execute(
                "UPDATE task_integration_receipts
                 SET result_snapshot = ?1
                 WHERE receipt_id = 'integration-task-1'",
                [alternate_snapshot.snapshot_id.as_str()],
            )
            .expect("inject crossed integration snapshot");
        assert!(matches!(
            crossed.assess_task_done("sprint-1", "task-1"),
            Err(LedgerError::Corrupt {
                entity: "task integration receipt",
                ..
            })
        ));
    }

    #[test]
    fn recovery_application_provenance_survives_completion_and_restart() {
        let database = TestDatabase::new();
        let expected = {
            let mut ledger = open_v21_test_ledger(&database);
            let (report, receipt, event) = prepare_recovery_completion_evidence(&mut ledger);
            record_pre_v24_successful_completion_for_test(&mut ledger, &report, &receipt, &event)
                .expect("complete through recovery application validation")
        };

        let ledger = EventLedger::open(&database.path)
            .expect("migrate historical recovery completion for readback");
        let restored = load_migrated_pre_v24_completion(&ledger, &expected);
        let PersistedCompletionApplication::Applied {
            application_evidence,
            ..
        } = &restored.application
        else {
            panic!("restored completion must retain application evidence");
        };
        assert_eq!(
            application_evidence.validation.mode,
            ApplicationValidationMode::RecoveryApplierReconciliation
        );
        assert_eq!(
            application_evidence.receipt.applier_session_id,
            "session-applier"
        );
        assert_eq!(
            application_evidence.validation.runner_session_id,
            "session-application-recovery-completion"
        );
    }

    #[test]
    fn completion_rejects_missing_or_mismatched_artifacts_without_writes() {
        let database = TestDatabase::new();
        let mut ledger = open_v21_test_ledger(&database);
        let (report, receipt, completion_event) = prepare_completion_evidence(&mut ledger);

        let mut bad_receipt = receipt.clone();
        bad_receipt.grant_hash = digest('9');
        assert!(matches!(
            ledger.record_successful_completion(&report, &bad_receipt, &completion_event),
            Err(LedgerError::ReferenceMismatch {
                entity: "completion receipt",
                ..
            })
        ));
        assert_no_completion_writes(&ledger);

        let mut bad_receipt = receipt.clone();
        bad_receipt
            .verification_receipts
            .push("missing-verification".into());
        bad_receipt.verification_receipts.sort();
        assert!(matches!(
            ledger.record_successful_completion(&report, &bad_receipt, &completion_event),
            Err(LedgerError::ReferenceMismatch {
                entity: "completion receipt",
                ..
            })
        ));
        assert_no_completion_writes(&ledger);

        let mut bad_receipt = receipt.clone();
        bad_receipt.provider_model = "different-model".into();
        assert!(matches!(
            ledger.record_successful_completion(&report, &bad_receipt, &completion_event),
            Err(LedgerError::ReferenceMismatch {
                entity: "completion receipt",
                ..
            })
        ));
        assert_no_completion_writes(&ledger);

        let mut bad_report = report.clone();
        bad_report.report_id = "different-report".into();
        assert!(matches!(
            ledger.record_successful_completion(&bad_report, &receipt, &completion_event),
            Err(LedgerError::ReferenceMismatch {
                entity: "completion receipt",
                ..
            })
        ));
        assert_no_completion_writes(&ledger);

        let mut wrong_sprint_report = report.clone();
        wrong_sprint_report.sprint_id = "sprint-2".into();
        assert!(matches!(
            ledger.record_successful_completion(&wrong_sprint_report, &receipt, &completion_event),
            Err(LedgerError::ReferenceMismatch {
                entity: "completion receipt",
                ..
            })
        ));
        assert_no_completion_writes(&ledger);

        let mut missing_final_report = report.clone();
        missing_final_report.final_snapshot = digest('8');
        let mut missing_final_receipt = receipt.clone();
        missing_final_receipt.final_snapshot = digest('8');
        assert!(matches!(
            ledger.record_successful_completion(
                &missing_final_report,
                &missing_final_receipt,
                &completion_event
            ),
            Err(LedgerError::ArtifactNotFound {
                entity: "workspace snapshot",
                ..
            })
        ));
        assert_no_completion_writes(&ledger);
    }

    #[test]
    fn completion_rejects_bad_event_and_cross_sprint_verification_then_retries() {
        let database = TestDatabase::new();
        let mut ledger = open_v21_test_ledger(&database);
        let (report, receipt, completion_event) = prepare_completion_evidence(&mut ledger);
        let mut bad_event = completion_event.clone();
        bad_event.occurred_at_unix_ms += 1;
        assert!(matches!(
            ledger.record_successful_completion(&report, &receipt, &bad_event),
            Err(LedgerError::ReferenceMismatch {
                entity: "completion event",
                ..
            })
        ));
        assert_no_completion_writes(&ledger);

        let mut bad_event = completion_event.clone();
        bad_event.payload = AgentEventKind::CompletionRecorded("wrong-receipt".into());
        assert!(matches!(
            ledger.record_successful_completion(&report, &receipt, &bad_event),
            Err(LedgerError::ReferenceMismatch {
                entity: "completion event",
                ..
            })
        ));
        assert_no_completion_writes(&ledger);

        let (mut second_spec, second_graph) = sprint_fixture();
        second_spec.sprint_id = "sprint-2".into();
        ledger
            .create_sprint(&second_spec, &second_graph, 1_001)
            .expect("persist second sprint");
        let (_, second_snapshot, _, mut second_verification, _, _, _, _) = completion_artifacts();
        ledger
            .persist_workspace_snapshot("sprint-2", &second_snapshot)
            .expect("persist second sprint snapshot");
        second_verification.receipt_id = "verify-other-sprint".into();
        second_verification.sprint_id = "sprint-2".into();
        ledger
            .persist_verification_receipt(&second_verification)
            .expect("persist second sprint verification");
        let mut cross_sprint_receipt = receipt.clone();
        cross_sprint_receipt
            .verification_receipts
            .push(second_verification.receipt_id.clone());
        cross_sprint_receipt.verification_receipts.sort();
        assert!(matches!(
            ledger.record_successful_completion(&report, &cross_sprint_receipt, &completion_event),
            Err(LedgerError::ReferenceMismatch {
                entity: "completion receipt",
                ..
            })
        ));
        assert_no_completion_writes(&ledger);

        record_pre_v24_successful_completion_for_test(
            &mut ledger,
            &report,
            &receipt,
            &completion_event,
        )
        .expect("valid completion remains retryable");
    }

    #[test]
    fn completion_transaction_rejects_acceptance_and_task_set_mismatches() {
        let database = TestDatabase::new();
        let mut ledger = open_v21_test_ledger(&database);
        let (report, receipt, event) = prepare_completion_evidence(&mut ledger);

        let mut missing_acceptance = receipt.clone();
        missing_acceptance.criterion_evidence_receipt_ids = vec!["missing-acceptance".into()];
        assert!(matches!(
            ledger.record_successful_completion(&report, &missing_acceptance, &event),
            Err(LedgerError::ArtifactNotFound {
                entity: "acceptance receipt",
                ..
            })
        ));
        assert_no_completion_writes(&ledger);

        let mut wrong_criteria = receipt.clone();
        wrong_criteria.satisfied_criterion_ids = vec!["undeclared-criterion".into()];
        assert!(matches!(
            ledger.record_successful_completion(&report, &wrong_criteria, &event),
            Err(LedgerError::ReferenceMismatch {
                entity: "completion receipt",
                ..
            })
        ));
        assert_no_completion_writes(&ledger);

        let mut unknown_task = receipt.clone();
        unknown_task.task_integration_receipt_ids = vec!["unknown-integration".into()];
        assert!(matches!(
            ledger.record_successful_completion(&report, &unknown_task, &event),
            Err(LedgerError::ReferenceMismatch {
                entity: "completion receipt",
                ..
            })
        ));
        assert_no_completion_writes(&ledger);

        let mut missing_required_task = receipt;
        missing_required_task.task_integration_receipt_ids.clear();
        assert!(matches!(
            ledger.record_successful_completion(&report, &missing_required_task, &event),
            Err(LedgerError::ReferenceMismatch {
                entity: "completion receipt",
                ..
            })
        ));
        assert_no_completion_writes(&ledger);
    }

    #[test]
    fn completion_transaction_rolls_back_after_late_sql_failure() {
        let database = TestDatabase::new();
        let mut ledger = open_v21_test_ledger(&database);
        let (report, receipt, event) = prepare_completion_evidence(&mut ledger);
        ledger
            .connection
            .execute_batch(
                "CREATE TRIGGER test_abort_terminal
                 BEFORE INSERT ON sprint_completion_proof_states
                 BEGIN SELECT RAISE(ABORT, 'injected late failure'); END;",
            )
            .expect("install test-only late failure");

        assert!(matches!(
            ledger.record_successful_completion(&report, &receipt, &event),
            Err(LedgerError::Sql(_))
        ));
        assert_no_completion_writes(&ledger);
        ledger
            .connection
            .execute_batch("DROP TRIGGER test_abort_terminal;")
            .expect("remove failure injection");
        record_pre_v24_successful_completion_for_test(&mut ledger, &report, &receipt, &event)
            .expect("retry atomic completion");
    }

    #[test]
    fn every_artifact_and_terminal_table_is_immutable() {
        let database = TestDatabase::new();
        let mut ledger = open_v21_test_ledger(&database);
        let (report, receipt, event) = prepare_completion_evidence(&mut ledger);
        let expected =
            record_pre_v24_successful_completion_for_test(&mut ledger, &report, &receipt, &event)
                .expect("record completion");

        for statement in [
            "UPDATE workspace_snapshots SET grant_hash = grant_hash",
            "DELETE FROM workspace_snapshots",
            "UPDATE change_sets SET change_set_id = change_set_id",
            "DELETE FROM change_sets",
            "UPDATE verification_receipts SET passed = passed",
            "DELETE FROM verification_receipts",
            "UPDATE acceptance_receipts SET criterion_id = criterion_id",
            "DELETE FROM acceptance_receipts",
            "UPDATE final_reports SET content_digest = content_digest",
            "DELETE FROM final_reports",
            "UPDATE verification_effect_evidence SET output_evidence_digest = output_evidence_digest",
            "DELETE FROM verification_effect_evidence",
            "UPDATE task_integration_receipts SET task_id = task_id",
            "DELETE FROM task_integration_receipts",
            "UPDATE task_integration_verification_receipts SET ordinal = ordinal",
            "DELETE FROM task_integration_verification_receipts",
            "UPDATE application_receipts SET transaction_id = transaction_id",
            "DELETE FROM application_receipts",
            "UPDATE worker_cleanup_receipts SET surviving_processes = surviving_processes",
            "DELETE FROM worker_cleanup_receipts",
            "UPDATE rollback_references SET transaction_id = transaction_id",
            "DELETE FROM rollback_references",
            "UPDATE v9_completion_receipts SET provider_model = provider_model",
            "DELETE FROM v9_completion_receipts",
            "UPDATE v9_completion_cleanup_receipts SET ordinal = ordinal",
            "DELETE FROM v9_completion_cleanup_receipts",
            "UPDATE v9_completion_verification_receipts SET ordinal = ordinal",
            "DELETE FROM v9_completion_verification_receipts",
            "UPDATE v9_completion_task_integration_receipts SET ordinal = ordinal",
            "DELETE FROM v9_completion_task_integration_receipts",
            "UPDATE v9_completion_acceptance_receipts SET ordinal = ordinal",
            "DELETE FROM v9_completion_acceptance_receipts",
            "UPDATE sprint_completion_proof_states SET proof_state = proof_state",
            "DELETE FROM sprint_completion_proof_states",
            "UPDATE sprint_graph_provenance SET provenance_kind = provenance_kind",
            "DELETE FROM sprint_graph_provenance",
        ] {
            assert!(
                ledger.connection.execute_batch(statement).is_err(),
                "mutation unexpectedly succeeded: {statement}"
            );
        }
        assert!(
            ledger
                .connection
                .execute_batch(
                    "INSERT INTO workspace_snapshots (
                        sprint_id, snapshot_id, grant_hash, contract_version,
                        created_at_unix_ms, snapshot_json
                     )
                     SELECT sprint_id,
                            '2222222222222222222222222222222222222222222222222222222222222222',
                            grant_hash, contract_version, created_at_unix_ms + 1, snapshot_json
                     FROM workspace_snapshots
                     WHERE sprint_id = 'sprint-1'
                     LIMIT 1;",
                )
                .is_err(),
            "terminal database trigger accepted a new artifact"
        );
        assert_eq!(row_count(&ledger, "workspace_snapshots"), 2);
        drop(ledger);
        let ledger = EventLedger::open(&database.path)
            .expect("migrate immutable completion before authoritative readback");
        let completion = load_migrated_pre_v24_completion(&ledger, &expected);
        assert_eq!(completion.receipt, receipt);
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "the immutability regression exercises every terminal artifact fence in one fixture"
    )]
    fn effect_tables_are_immutable_and_terminal_sprints_fence_new_effects() {
        let database = TestDatabase::new();
        let mut ledger = open_v21_test_ledger(&database);
        let (report, receipt, mut completion_event) = prepare_completion_evidence(&mut ledger);
        let preexisting_effects = row_count(&ledger, "effect_intents");
        let mut intent = effect_intent("effect-before-completion", "key-before-completion", 1_700);
        intent.task_id = None;
        intent.worker_id = None;
        intent.kind = EffectKind::ProviderRequest;
        let proposal = effect_proposal_event(
            &intent,
            ledger.next_sequence("sprint-1").expect("proposal sequence"),
            "event-before-completion",
        );
        record_test_effect_intent(&mut ledger, &intent, &proposal)
            .expect("record pre-completion intent");
        let observation = effect_observation(
            &intent,
            "observation-before-completion",
            EffectOutcome::Succeeded {
                evidence_digest: effect_evidence_digest(),
            },
            1_800,
        );
        let terminal = effect_terminal_event(
            &intent,
            &proposal.event_id,
            &observation,
            ledger.next_sequence("sprint-1").expect("terminal sequence"),
            "event-effect-terminal",
        );
        record_test_effect_observation(&mut ledger, &observation, &terminal)
            .expect("record pre-completion observation");

        for statement in [
            "UPDATE effect_intents SET effect_kind = effect_kind",
            "DELETE FROM effect_intents",
            "UPDATE effect_observations SET outcome = outcome",
            "DELETE FROM effect_observations",
            "UPDATE effect_request_payloads SET request_bytes = request_bytes",
            "DELETE FROM effect_request_payloads",
            "UPDATE effect_evidence_payloads SET evidence_bytes = evidence_bytes",
            "DELETE FROM effect_evidence_payloads",
        ] {
            assert!(
                ledger.connection.execute_batch(statement).is_err(),
                "effect mutation unexpectedly succeeded: {statement}"
            );
        }

        completion_event.sequence = ledger
            .next_sequence("sprint-1")
            .expect("completion sequence");
        record_pre_v24_successful_completion_for_test(
            &mut ledger,
            &report,
            &receipt,
            &completion_event,
        )
        .expect("complete after all effects are known");

        let post_terminal_intent =
            effect_intent("effect-after-terminal", "key-after-terminal", 2_100);
        let post_terminal_event = effect_proposal_event(
            &post_terminal_intent,
            completion_event.sequence + 1,
            "event-after-terminal",
        );
        assert!(matches!(
            record_test_effect_intent(
                &mut ledger,
                &post_terminal_intent,
                &post_terminal_event
            ),
            Err(LedgerError::SprintAlreadyTerminal(sprint_id)) if sprint_id == "sprint-1"
        ));
        assert!(
            ledger
                .connection
                .execute_batch(
                    "INSERT INTO effect_intents (
                        effect_id, sprint_id, idempotency_key, task_id, worker_id,
                        causation_event_id, correlation_id, effect_kind,
                        request_digest, policy_hash, input_snapshot,
                        proposed_event_id, contract_version, created_at_unix_ms,
                        intent_json
                     )
                     SELECT 'direct-after-terminal', sprint_id,
                            'direct-key-after-terminal', task_id, worker_id,
                            causation_event_id, correlation_id, effect_kind,
                            request_digest, policy_hash, input_snapshot,
                            proposed_event_id, contract_version,
                            created_at_unix_ms, intent_json
                     FROM effect_intents
                     WHERE effect_id = 'effect-before-completion';",
                )
                .is_err(),
            "effect-intent terminal fence accepted a direct insert"
        );
        assert_eq!(
            row_count(&ledger, "effect_intents"),
            preexisting_effects + 1
        );
        assert_eq!(
            row_count(&ledger, "effect_observations"),
            preexisting_effects + 1
        );
    }

    #[test]
    fn completion_rejects_unfinished_and_unknown_effects_without_terminal_writes() {
        for unknown_terminal in [false, true] {
            let database = TestDatabase::new();
            let mut ledger = open_v21_test_ledger(&database);
            let (report, receipt, mut completion_event) = prepare_completion_evidence(&mut ledger);
            let suffix = if unknown_terminal {
                "unknown"
            } else {
                "unfinished"
            };
            let mut intent =
                effect_intent(&format!("effect-{suffix}"), &format!("key-{suffix}"), 1_700);
            intent.task_id = None;
            intent.worker_id = None;
            intent.kind = EffectKind::ProviderRequest;
            let proposal = effect_proposal_event(
                &intent,
                ledger.next_sequence("sprint-1").expect("proposal sequence"),
                &format!("event-proposal-{suffix}"),
            );
            record_test_effect_intent(&mut ledger, &intent, &proposal)
                .expect("record effect intent");
            completion_event.sequence = ledger
                .next_sequence("sprint-1")
                .expect("unfinished completion sequence");

            if unknown_terminal {
                let observation = effect_observation(
                    &intent,
                    "observation-unknown-completion",
                    EffectOutcome::Unknown {
                        evidence_digest: effect_evidence_digest(),
                    },
                    1_800,
                );
                let terminal = effect_terminal_event(
                    &intent,
                    &proposal.event_id,
                    &observation,
                    ledger
                        .next_sequence("sprint-1")
                        .expect("unknown terminal sequence"),
                    "event-unknown-completion",
                );
                record_test_effect_observation(&mut ledger, &observation, &terminal)
                    .expect("record honest unknown outcome");
                completion_event.sequence = ledger
                    .next_sequence("sprint-1")
                    .expect("unknown completion sequence");
            }

            assert!(matches!(
                ledger.record_successful_completion(&report, &receipt, &completion_event),
                Err(LedgerError::ReferenceMismatch {
                    entity: "completion receipt",
                    detail,
                }) if detail.contains("requires reconciliation evidence")
            ));
            assert_no_completion_writes(&ledger);
        }
    }

    #[test]
    fn schema_terminal_trigger_rejects_unfinished_effect_even_if_api_is_bypassed() {
        let database = TestDatabase::new();
        let mut ledger = open_v21_test_ledger(&database);
        let (report, receipt, mut completion_event) = prepare_completion_evidence(&mut ledger);
        let mut intent = effect_intent("effect-schema-fence", "key-schema-fence", 1_700);
        intent.task_id = None;
        intent.worker_id = None;
        intent.kind = EffectKind::ProviderRequest;
        let proposal = effect_proposal_event(
            &intent,
            ledger.next_sequence("sprint-1").expect("proposal sequence"),
            "event-schema-fence",
        );
        record_test_effect_intent(&mut ledger, &intent, &proposal)
            .expect("record unfinished effect");
        completion_event.sequence = ledger
            .next_sequence("sprint-1")
            .expect("completion sequence");
        let durable_event_count = row_count(&ledger, "agent_events");

        let transaction = ledger
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .expect("start direct completion transaction");
        insert_final_report(&transaction, &report).expect("insert direct report");
        insert_completion_receipt(&transaction, &receipt).expect("insert direct receipt");
        insert_agent_event(&transaction, &completion_event)
            .expect("insert direct completion event");
        let terminal = transaction.execute(
            "INSERT INTO sprint_completion_proof_states (
                sprint_id, proof_state, completion_receipt_id,
                completion_event_id, contract_version, terminal_at_unix_ms
             ) VALUES (?1, 'ProvenV9', ?2, ?3, ?4, ?5)",
            params![
                receipt.sprint_id,
                receipt.receipt_id,
                completion_event.event_id,
                i64::from(CONTRACT_VERSION),
                sqlite_integer(
                    "completion_receipt.completed_at_unix_ms",
                    receipt.completed_at_unix_ms
                )
                .expect("timestamp fits")
            ],
        );
        assert!(terminal.is_err());
        transaction.rollback().expect("rollback direct bypass");
        assert_no_completion_writes(&ledger);
        assert_eq!(row_count(&ledger, "agent_events"), durable_event_count);
    }

    #[test]
    fn effect_readback_rejects_redundant_column_corruption() {
        let database = TestDatabase::new();
        let mut ledger = EventLedger::open(&database.path).expect("open ledger");
        prepare_effect_input(&mut ledger);
        let intent = effect_intent("effect-corrupt", "key-corrupt", 1_200);
        let proposal = effect_proposal_event(&intent, 1, "event-corrupt-proposal");
        record_test_effect_intent(&mut ledger, &intent, &proposal).expect("record intent");
        let observation = effect_observation(
            &intent,
            "observation-corrupt",
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
            "event-corrupt-terminal",
        );
        record_test_effect_observation(&mut ledger, &observation, &terminal)
            .expect("record observation");
        ledger
            .connection
            .execute_batch(
                "DROP TRIGGER effect_observations_no_update;
                 UPDATE effect_observations
                 SET request_digest =
                     '8888888888888888888888888888888888888888888888888888888888888888';",
            )
            .expect("simulate observation indexed-column corruption");

        assert!(matches!(
            ledger.load_effect("effect-corrupt"),
            Err(LedgerError::Corrupt {
                entity: "effect observation",
                ..
            })
        ));
    }

    #[test]
    fn effect_readback_rehashes_request_and_evidence_bytes() {
        let database = TestDatabase::new();
        let mut ledger = EventLedger::open(&database.path).expect("open ledger");
        prepare_effect_input(&mut ledger);
        let intent = effect_intent("effect-byte-corrupt", "key-byte-corrupt", 1_200);
        let proposal = effect_proposal_event(&intent, 1, "event-byte-corrupt-proposal");
        record_test_effect_intent(&mut ledger, &intent, &proposal).expect("record request bytes");
        let observation = effect_observation(
            &intent,
            "observation-byte-corrupt",
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
            "event-byte-corrupt-terminal",
        );
        record_test_effect_observation(&mut ledger, &observation, &terminal)
            .expect("record evidence bytes");

        ledger
            .connection
            .execute_batch(
                "DROP TRIGGER effect_request_payloads_no_update;
                 UPDATE effect_request_payloads SET request_bytes = X'00';",
            )
            .expect("simulate request-byte corruption");
        assert!(matches!(
            ledger.load_effect(&intent.effect_id),
            Err(LedgerError::Corrupt {
                entity: "effect request payload",
                ..
            })
        ));
        ledger
            .connection
            .execute(
                "UPDATE effect_request_payloads SET request_bytes = ?1",
                params![EFFECT_REQUEST_BYTES],
            )
            .expect("restore exact request bytes for second corruption check");
        ledger
            .load_effect(&intent.effect_id)
            .expect("restored request validates");

        ledger
            .connection
            .execute_batch(
                "DROP TRIGGER effect_evidence_payloads_no_update;
                 UPDATE effect_evidence_payloads SET evidence_bytes = X'00';",
            )
            .expect("simulate evidence-byte corruption");
        assert!(matches!(
            ledger.load_effect(&intent.effect_id),
            Err(LedgerError::Corrupt {
                entity: "effect evidence payload",
                ..
            })
        ));

        ledger
            .connection
            .execute_batch(
                "DROP TRIGGER effect_request_payloads_no_delete;
                 DELETE FROM effect_request_payloads;",
            )
            .expect("simulate missing non-legacy request payload");
        assert!(matches!(
            ledger.load_effect(&intent.effect_id),
            Err(LedgerError::Corrupt {
                entity: "effect payload relationship",
                ..
            })
        ));
    }

    #[test]
    fn readback_rejects_redundant_column_corruption() {
        let database = TestDatabase::new();
        let mut ledger = EventLedger::open(&database.path).expect("open ledger");
        let (spec, graph) = sprint_fixture();
        ledger
            .create_sprint(&spec, &graph, 1_000)
            .expect("persist sprint");
        let (base, _, _, _, _, _, _, _) = completion_artifacts();
        ledger
            .persist_workspace_snapshot("sprint-1", &base)
            .expect("persist snapshot");
        ledger
            .connection
            .execute_batch(
                "DROP TRIGGER workspace_snapshots_no_update;
                 UPDATE workspace_snapshots
                 SET grant_hash = 'dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd';",
            )
            .expect("simulate indexed-column corruption");

        assert!(matches!(
            ledger.load_workspace_snapshot("sprint-1", &base.snapshot_id),
            Err(LedgerError::Corrupt {
                entity: "workspace snapshot",
                ..
            })
        ));
    }

    fn begin_post_completion_rollback(
        database: &TestDatabase,
        operation_id: &str,
        effect_id: &str,
        created_at_unix_ms: u64,
    ) -> (
        EventLedger,
        PersistedCompletion,
        PostCompletionRollbackIntent,
        CompiledExecutionPolicy,
        RunnerLaunchIntent,
        RunnerSessionPolicyRecord,
    ) {
        let expected = {
            let mut legacy = open_v21_test_ledger(database);
            let (report, receipt, event) = prepare_completion_evidence(&mut legacy);
            record_pre_v24_successful_completion_for_test(&mut legacy, &report, &receipt, &event)
                .expect("record immutable pre-v24 completion before migration")
        };
        let mut ledger = EventLedger::open(&database.path)
            .expect("migrate completion before post-completion rollback");
        let completion = load_migrated_pre_v24_completion(&ledger, &expected);
        let intent = ledger
            .build_post_completion_rollback_intent(
                "sprint-1",
                operation_id.into(),
                format!("idempotency-{operation_id}"),
                effect_id.into(),
                created_at_unix_ms,
            )
            .expect("build rollback intent from durable completion bytes");
        assert_eq!(
            ledger
                .record_post_completion_rollback_intent(&intent)
                .expect("persist rollback intent")
                .status(),
            PostCompletionRollbackStatus::IntentRecorded
        );
        let policy = compiled_test_policy("policy-applier");
        let mut launch = runner_launch(
            &format!("launch-{operation_id}"),
            &format!("session-{operation_id}"),
            RunnerSessionPurpose::Applier,
            None,
            &policy,
            created_at_unix_ms + 100,
        );
        launch.private_state_digest = Digest::sha256(b"launch-applier");
        ledger
            .record_post_completion_rollback_applier_launch(
                operation_id,
                PostCompletionRollbackApplierRole::Executor,
                &launch,
                &policy,
            )
            .expect("persist fresh rollback executor launch");
        let session = runner_session(&launch, created_at_unix_ms + 150);
        ledger
            .register_post_completion_rollback_applier_session(operation_id, &session, &policy)
            .expect("register fresh rollback executor session");
        (ledger, completion, intent, policy, launch, session)
    }

    #[allow(clippy::too_many_arguments)] // Test fixture exposes every identity and time boundary explicitly.
    fn post_completion_success(
        ledger: &mut EventLedger,
        intent: &PostCompletionRollbackIntent,
        executor_launch: &RunnerLaunchIntent,
        executor_session: &RunnerSessionPolicyRecord,
        validator_launch: &RunnerLaunchIntent,
        validator_session: &RunnerSessionPolicyRecord,
        validation_mode: RollbackValidationMode,
        effect_started_at_unix_ms: u64,
        observed_at_unix_ms: u64,
        record: bool,
    ) -> PostCompletionRollbackObservation {
        let (_, _, change_set, _, _, _, _, _) = completion_artifacts();
        let precondition = PostCompletionRollbackPreconditionEvidence::new(
            vec![PostCompletionRollbackEndpointObservation {
                path: PathBuf::from("report.txt"),
                expected_application_hash: Some(digest('d')),
                observed_hash: Some(digest('d')),
            }],
            effect_started_at_unix_ms,
        )
        .expect("build exact application-endpoint precondition");
        let observation = PostCompletionRollbackObservation {
            contract_version: CONTRACT_VERSION,
            observation_id: format!("observation-{}", intent.operation_id),
            operation_id: intent.operation_id.clone(),
            sprint_id: intent.sprint_id.clone(),
            rollback_effect_id: intent.rollback_effect_id.clone(),
            request_digest: intent.request_digest.clone(),
            executor_launch_id: executor_launch.launch_id.clone(),
            executor_session_id: executor_session.session_id.clone(),
            outcome: PostCompletionRollbackOutcome::Succeeded {
                precondition,
                rollback_evidence: RollbackEvidence {
                    contract_version: CONTRACT_VERSION,
                    receipt: RollbackReceipt {
                        contract_version: CONTRACT_VERSION,
                        receipt_id: format!("receipt-{}", intent.operation_id),
                        sprint_id: intent.sprint_id.clone(),
                        effect_id: intent.rollback_effect_id.clone(),
                        observation_id: format!("observation-{}", intent.operation_id),
                        application_receipt_id: intent.request.application_receipt_id.clone(),
                        application_transaction_id: intent
                            .request
                            .application_transaction_id
                            .clone(),
                        restored_base_snapshot: digest('b'),
                        restored_endpoints_digest: change_set
                            .restored_base_endpoints_digest()
                            .expect("digest restored endpoints"),
                        live_manifest_digest: digest('b'),
                        unresolved_conflicts: 0,
                        completed_at_unix_ms: observed_at_unix_ms,
                    },
                    validation: crate::RollbackValidationEvidence {
                        mode: validation_mode,
                        runner_launch_id: validator_launch.launch_id.clone(),
                        runner_session_id: validator_session.session_id.clone(),
                        policy_hash: validator_launch.policy_hash.clone(),
                        grant_hash: validator_launch.grant_hash.clone(),
                        policy_version: validator_launch.policy_version,
                        private_state_digest: validator_launch.private_state_digest.clone(),
                    },
                },
            },
            effect_started_at_unix_ms,
            observed_at_unix_ms,
        };
        if record {
            ledger
                .record_post_completion_rollback_observation(&observation)
                .expect("persist successful rollback observation");
        }
        observation
    }

    fn finish_post_completion_cleanup(
        ledger: &mut EventLedger,
        intent: &PostCompletionRollbackIntent,
        launch: &RunnerLaunchIntent,
        ordinal: &str,
        intent_at_unix_ms: u64,
        observed_at_unix_ms: u64,
    ) -> PostCompletionRollbackCleanupEvidence {
        let request = WorkerCleanupRequest {
            contract_version: CONTRACT_VERSION,
            sprint_id: intent.sprint_id.clone(),
            launch_id: launch.launch_id.clone(),
            session_id: launch.session_id.clone(),
            policy_hash: launch.policy_hash.clone(),
            grant_hash: launch.grant_hash.clone(),
            policy_version: launch.policy_version,
            platform_backend: WorkerCleanupBackend::TrustedApplierDirectChildWait,
        };
        let cleanup_intent = PostCompletionRollbackCleanupIntent::new(
            intent.operation_id.clone(),
            format!("cleanup-effect-{ordinal}"),
            request,
            intent_at_unix_ms,
        )
        .expect("build cleanup intent");
        ledger
            .record_post_completion_rollback_cleanup_intent(&cleanup_intent)
            .expect("persist cleanup intent before cleanup execution");
        let os_evidence_bytes = format!("zero descendants for {ordinal}").into_bytes();
        let cleanup = PostCompletionRollbackCleanupEvidence {
            contract_version: CONTRACT_VERSION,
            operation_id: intent.operation_id.clone(),
            cleanup_effect_id: cleanup_intent.cleanup_effect_id.clone(),
            request_digest: cleanup_intent.request_digest.clone(),
            evidence: WorkerCleanupEvidence {
                receipt: WorkerCleanupReceipt {
                    contract_version: CONTRACT_VERSION,
                    receipt_id: format!("cleanup-receipt-{ordinal}"),
                    sprint_id: intent.sprint_id.clone(),
                    launch_id: launch.launch_id.clone(),
                    effect_id: cleanup_intent.cleanup_effect_id,
                    observation_id: format!("cleanup-observation-{ordinal}"),
                    session_id: launch.session_id.clone(),
                    worker_lease: None,
                    policy_hash: launch.policy_hash.clone(),
                    grant_hash: launch.grant_hash.clone(),
                    policy_version: launch.policy_version,
                    platform_backend: WorkerCleanupBackend::TrustedApplierDirectChildWait,
                    os_evidence_digest: Digest::sha256(&os_evidence_bytes),
                    surviving_processes: 0,
                    cleaned_at_unix_ms: observed_at_unix_ms,
                },
                os_evidence_bytes,
            },
        };
        ledger
            .record_post_completion_rollback_cleanup(&cleanup)
            .expect("persist exact cleanup observation");
        cleanup
    }

    #[test]
    #[allow(clippy::too_many_lines)] // One lifecycle case verifies intent through restart-safe terminal readback.
    fn post_completion_direct_rollback_is_separate_idempotent_and_restart_safe() {
        let database = TestDatabase::new();
        let (completion, intent, _policy, launch, session, artifact_authority) = {
            let fixture = begin_post_completion_rollback(
                &database,
                "rollback-operation-direct",
                "rollback-effect-direct",
                2_100,
            );
            let (mut ledger, completion, intent, policy, launch, session) = fixture;
            let operation_authority = ledger
                .load_post_completion_rollback_application_artifact_authority(&intent.operation_id)
                .expect("load operation-local application artifact authority");
            let PostCompletionRollbackApplicationArtifactAuthorityState::Authoritative {
                authority,
                authority_digest,
            } = &operation_authority
            else {
                panic!("new v12 operation must retain authoritative application artifact")
            };
            assert_eq!(authority.operation_id, intent.operation_id);
            assert_eq!(
                authority.application_receipt_id,
                intent.request.application_receipt_id
            );
            assert_eq!(
                Digest::sha256(
                    &encode(
                        "post-completion application artifact authority",
                        authority.as_ref()
                    )
                    .expect("encode operation authority")
                ),
                *authority_digest
            );
            assert_eq!(
                ledger
                    .load_post_completion_rollback(&intent.operation_id)
                    .expect("load operation with authority")
                    .application_artifact_authority,
                operation_authority
            );
            let early_direct = post_completion_success(
                &mut ledger,
                &intent,
                &launch,
                &session,
                &launch,
                &session,
                RollbackValidationMode::DirectEffectResponse,
                session.registered_at_unix_ms - 1,
                2_350,
                false,
            );
            assert!(matches!(
                ledger.record_post_completion_rollback_observation(&early_direct),
                Err(LedgerError::ReferenceMismatch { .. })
            ));
            let observation = post_completion_success(
                &mut ledger,
                &intent,
                &launch,
                &session,
                &launch,
                &session,
                RollbackValidationMode::DirectEffectResponse,
                2_300,
                2_350,
                true,
            );
            assert_eq!(
                ledger
                    .load_post_completion_rollback(&intent.operation_id)
                    .expect("load outcome awaiting cleanup")
                    .status(),
                PostCompletionRollbackStatus::OutcomeAwaitingCleanup(
                    PostCompletionRollbackOutcomeKind::Succeeded
                )
            );
            let cleanup = finish_post_completion_cleanup(
                &mut ledger,
                &intent,
                &launch,
                "direct",
                2_400,
                2_450,
            );
            let terminal = PostCompletionRollbackTerminal {
                contract_version: CONTRACT_VERSION,
                terminal_id: "rollback-terminal-direct".into(),
                operation_id: intent.operation_id.clone(),
                sprint_id: intent.sprint_id.clone(),
                application_receipt_id: intent.request.application_receipt_id.clone(),
                outcome_id: observation.observation_id,
                kind: PostCompletionRollbackOutcomeKind::Succeeded,
                cleanup_receipt_ids: vec![cleanup.evidence.receipt.receipt_id.clone()],
                terminal_at_unix_ms: 2_500,
            };
            let persisted = ledger
                .finalize_post_completion_rollback(&terminal)
                .expect("terminalize successful operation after cleanup");
            assert_eq!(
                persisted.status(),
                PostCompletionRollbackStatus::Terminal(
                    PostCompletionRollbackOutcomeKind::Succeeded
                )
            );
            assert_eq!(persisted.cleanup_intents.len(), 1);
            assert_eq!(persisted.cleanups.len(), 1);
            assert_eq!(
                ledger
                    .finalize_post_completion_rollback(&terminal)
                    .expect("exact terminal replay is idempotent"),
                persisted
            );
            assert_eq!(
                ledger
                    .load_completion("sprint-1")
                    .expect("reload immutable completion"),
                Some(completion.clone())
            );
            assert!(matches!(
                ledger.append_event(&AgentEvent {
                    contract_version: CONTRACT_VERSION,
                    sequence: ledger.next_sequence("sprint-1").expect("sequence"),
                    event_id: "post-rollback-sprint-event".into(),
                    sprint_id: "sprint-1".into(),
                    task_id: None,
                    worker_id: None,
                    causation_id: None,
                    correlation_id: "post-rollback".into(),
                    policy_hash: None,
                    occurred_at_unix_ms: 2_600,
                    payload: AgentEventKind::Diagnostic("must stay fenced".into()),
                }),
                Err(LedgerError::SprintAlreadyTerminal(id)) if id == "sprint-1"
            ));
            (
                completion,
                intent,
                policy,
                launch,
                session,
                operation_authority,
            )
        };

        let reader = EventLedger::open(&database.path)
            .expect("migrate historical post-completion rollback for readback");
        assert_eq!(
            reader
                .load_post_completion_rollback(&intent.operation_id)
                .expect("restore rollback operation")
                .status(),
            PostCompletionRollbackStatus::Terminal(PostCompletionRollbackOutcomeKind::Succeeded)
        );
        assert_eq!(
            reader
                .load_completion("sprint-1")
                .expect("restore original completion"),
            Some(completion)
        );
        assert_eq!(launch.session_id, session.session_id);
        assert_eq!(
            reader
                .load_post_completion_rollback_application_artifact_authority(&intent.operation_id,)
                .expect("restore exact operation authority"),
            artifact_authority
        );
    }

    #[test]
    #[allow(clippy::too_many_lines)] // Coexistence, immutable corruption, launch gating, and absence are one closed classification case.
    fn post_completion_authority_rejects_crossing_and_cannot_authorize_fresh_launch() {
        let database = TestDatabase::new();
        let (mut ledger, _completion, intent, policy, launch, _session) =
            begin_post_completion_rollback(
                &database,
                "rollback-operation-authority-corruption",
                "rollback-effect-authority-corruption",
                2_100,
            );
        for statement in [
            "UPDATE post_completion_application_artifact_authorities SET artifact_digest = artifact_digest",
            "DELETE FROM post_completion_application_artifact_authorities",
        ] {
            assert!(
                ledger.connection.execute_batch(statement).is_err(),
                "operation authority mutation unexpectedly succeeded: {statement}"
            );
        }
        ledger
            .connection
            .execute_batch(
                "DROP TRIGGER legacy_post_completion_application_artifact_gaps_no_insert;",
            )
            .expect("isolate post-completion coexistence invariant");
        ledger
            .connection
            .execute(
                "INSERT INTO legacy_post_completion_application_artifact_gaps (
                    operation_id, sprint_id, application_receipt_id, gap_kind,
                    contract_version
                 ) VALUES (?1, ?2, ?3, 'LegacyMissing', ?4)",
                params![
                    intent.operation_id,
                    intent.sprint_id,
                    intent.request.application_receipt_id,
                    i64::from(CONTRACT_VERSION),
                ],
            )
            .expect("simulate crossed post-completion legacy marker");
        assert!(matches!(
            ledger
                .load_post_completion_rollback_application_artifact_authority(&intent.operation_id),
            Err(LedgerError::Corrupt {
                entity: "post-completion application artifact authority",
                ..
            })
        ));
        ledger
            .connection
            .execute_batch(
                "DROP TRIGGER legacy_post_completion_application_artifact_gaps_no_delete;
                 DELETE FROM legacy_post_completion_application_artifact_gaps;",
            )
            .expect("remove simulated post-completion marker");
        ledger
            .load_post_completion_rollback_application_artifact_authority(&intent.operation_id)
            .expect("single operation authority is readable");

        ledger
            .connection
            .execute_batch(
                "DROP TRIGGER post_completion_application_artifact_authorities_no_update;
                 UPDATE post_completion_application_artifact_authorities
                 SET artifact_digest =
                     'ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff';",
            )
            .expect("simulate indexed operation authority corruption");
        assert!(matches!(
            ledger.load_post_completion_rollback(&intent.operation_id),
            Err(LedgerError::Corrupt {
                entity: "post-completion application artifact authority",
                ..
            })
        ));
        let mut recovery_launch = runner_launch(
            "launch-corrupt-authority-recovery",
            "session-corrupt-authority-recovery",
            RunnerSessionPurpose::Applier,
            None,
            &policy,
            2_300,
        );
        recovery_launch.private_state_digest = launch.private_state_digest;
        let launches_before = row_count(&ledger, "post_completion_rollback_applier_launches");
        assert!(matches!(
            ledger.record_post_completion_rollback_applier_launch(
                &intent.operation_id,
                PostCompletionRollbackApplierRole::RecoveryValidator,
                &recovery_launch,
                &policy,
            ),
            Err(LedgerError::Corrupt {
                entity: "post-completion application artifact authority",
                ..
            })
        ));
        assert_eq!(
            row_count(&ledger, "post_completion_rollback_applier_launches"),
            launches_before
        );

        ledger
            .connection
            .execute_batch(
                "DROP TRIGGER post_completion_application_artifact_authorities_no_delete;
                 DELETE FROM post_completion_application_artifact_authorities;",
            )
            .expect("simulate missing operation authority");
        assert!(matches!(
            ledger
                .load_post_completion_rollback_application_artifact_authority(&intent.operation_id),
            Err(LedgerError::Corrupt {
                entity: "post-completion application artifact authority",
                ..
            })
        ));
    }

    #[test]
    #[allow(clippy::too_many_lines)] // Recovery authority and both cleanup proofs form one adversarial lifecycle.
    fn post_completion_recovery_requires_distinct_authority_and_every_cleanup() {
        let database = TestDatabase::new();
        let (mut ledger, _completion, intent, policy, executor_launch, executor_session) =
            begin_post_completion_rollback(
                &database,
                "rollback-operation-recovery",
                "rollback-effect-recovery",
                2_100,
            );
        let mut recovery_launch = runner_launch(
            "launch-post-rollback-recovery",
            "session-post-rollback-recovery",
            RunnerSessionPurpose::Applier,
            None,
            &policy,
            2_300,
        );
        recovery_launch.private_state_digest = executor_launch.private_state_digest.clone();
        ledger
            .record_post_completion_rollback_applier_launch(
                &intent.operation_id,
                PostCompletionRollbackApplierRole::RecoveryValidator,
                &recovery_launch,
                &policy,
            )
            .expect("persist distinct recovery launch");
        let recovery_session = runner_session(&recovery_launch, 2_350);
        ledger
            .register_post_completion_rollback_applier_session(
                &intent.operation_id,
                &recovery_session,
                &policy,
            )
            .expect("register distinct recovery session");

        let prepositioned_recovery = post_completion_success(
            &mut ledger,
            &intent,
            &executor_launch,
            &executor_session,
            &recovery_launch,
            &recovery_session,
            RollbackValidationMode::RecoveryApplierReconciliation,
            recovery_launch.created_at_unix_ms + 1,
            2_400,
            false,
        );
        assert!(matches!(
            ledger.record_post_completion_rollback_observation(&prepositioned_recovery),
            Err(LedgerError::ReferenceMismatch { .. })
        ));

        let mut crossed = post_completion_success(
            &mut ledger,
            &intent,
            &executor_launch,
            &executor_session,
            &recovery_launch,
            &recovery_session,
            RollbackValidationMode::RecoveryApplierReconciliation,
            2_250,
            2_400,
            false,
        );
        if let PostCompletionRollbackOutcome::Succeeded {
            rollback_evidence, ..
        } = &mut crossed.outcome
        {
            rollback_evidence.validation.runner_launch_id = executor_launch.launch_id.clone();
            rollback_evidence.validation.runner_session_id = executor_session.session_id.clone();
        }
        assert!(matches!(
            ledger.record_post_completion_rollback_observation(&crossed),
            Err(LedgerError::ReferenceMismatch { .. })
        ));
        assert_eq!(
            row_count(&ledger, "post_completion_rollback_observations"),
            0
        );

        let observation = post_completion_success(
            &mut ledger,
            &intent,
            &executor_launch,
            &executor_session,
            &recovery_launch,
            &recovery_session,
            RollbackValidationMode::RecoveryApplierReconciliation,
            2_250,
            2_400,
            true,
        );
        let executor_cleanup = finish_post_completion_cleanup(
            &mut ledger,
            &intent,
            &executor_launch,
            "recovery-executor",
            2_450,
            2_500,
        );
        let incomplete = PostCompletionRollbackTerminal {
            contract_version: CONTRACT_VERSION,
            terminal_id: "rollback-terminal-recovery".into(),
            operation_id: intent.operation_id.clone(),
            sprint_id: intent.sprint_id.clone(),
            application_receipt_id: intent.request.application_receipt_id.clone(),
            outcome_id: observation.observation_id.clone(),
            kind: PostCompletionRollbackOutcomeKind::Succeeded,
            cleanup_receipt_ids: vec![executor_cleanup.evidence.receipt.receipt_id.clone()],
            terminal_at_unix_ms: 2_550,
        };
        assert!(matches!(
            ledger.finalize_post_completion_rollback(&incomplete),
            Err(LedgerError::ReferenceMismatch { .. })
        ));
        let recovery_cleanup = finish_post_completion_cleanup(
            &mut ledger,
            &intent,
            &recovery_launch,
            "recovery-validator",
            2_510,
            2_560,
        );
        let mut terminal = incomplete;
        terminal.cleanup_receipt_ids = vec![
            executor_cleanup.evidence.receipt.receipt_id,
            recovery_cleanup.evidence.receipt.receipt_id,
        ];
        terminal.cleanup_receipt_ids.sort();
        terminal.terminal_at_unix_ms = 2_600;
        let persisted = ledger
            .finalize_post_completion_rollback(&terminal)
            .expect("terminalize after exact executor and recovery cleanup set");
        assert_eq!(persisted.appliers.len(), 2);
        assert_eq!(persisted.cleanups.len(), 2);
        assert_eq!(
            persisted.status(),
            PostCompletionRollbackStatus::Terminal(PostCompletionRollbackOutcomeKind::Succeeded)
        );
    }

    fn direct_validation(
        launch: &RunnerLaunchIntent,
        session: &RunnerSessionPolicyRecord,
    ) -> crate::RollbackValidationEvidence {
        crate::RollbackValidationEvidence {
            mode: RollbackValidationMode::DirectEffectResponse,
            runner_launch_id: launch.launch_id.clone(),
            runner_session_id: session.session_id.clone(),
            policy_hash: launch.policy_hash.clone(),
            grant_hash: launch.grant_hash.clone(),
            policy_version: launch.policy_version,
            private_state_digest: launch.private_state_digest.clone(),
        }
    }

    fn post_completion_live_conflict(
        intent: &PostCompletionRollbackIntent,
        launch: &RunnerLaunchIntent,
        session: &RunnerSessionPolicyRecord,
        conflicts: Vec<crate::LivePathConflict>,
    ) -> PostCompletionRollbackObservation {
        PostCompletionRollbackObservation {
            contract_version: CONTRACT_VERSION,
            observation_id: format!("observation-conflict-{}", intent.operation_id),
            operation_id: intent.operation_id.clone(),
            sprint_id: intent.sprint_id.clone(),
            rollback_effect_id: intent.rollback_effect_id.clone(),
            request_digest: intent.request_digest.clone(),
            executor_launch_id: launch.launch_id.clone(),
            executor_session_id: session.session_id.clone(),
            outcome: PostCompletionRollbackOutcome::LiveConflict {
                conflict_receipt: crate::LiveConflictReceipt {
                    contract_version: CONTRACT_VERSION,
                    receipt_id: format!("receipt-conflict-{}", intent.operation_id),
                    sprint_id: intent.sprint_id.clone(),
                    application_receipt_id: intent.request.application_receipt_id.clone(),
                    transaction_id: intent.request.application_transaction_id.clone(),
                    conflicts,
                    live_manifest_digest: digest('e'),
                    required_user_decision:
                        crate::LiveConflictUserDecision::ChoosePreservedEndpointAndReconcile,
                    observed_at_unix_ms: 2_350,
                },
                validation: direct_validation(launch, session),
            },
            effect_started_at_unix_ms: 2_300,
            observed_at_unix_ms: 2_350,
        }
    }

    #[test]
    fn post_completion_expected_endpoint_digest_covers_delete_absence() {
        let create = FileOperation::Create {
            path: PathBuf::from("created.txt"),
            result_hash: digest('d'),
        };
        let modify = FileOperation::Modify {
            path: PathBuf::from("modified.txt"),
            base_hash: digest('b'),
            result_hash: digest('e'),
        };
        let delete = FileOperation::Delete {
            path: PathBuf::from("deleted.txt"),
            base_hash: digest('c'),
        };
        assert_eq!(
            post_completion_rollback_expected_endpoint_digest(&create),
            digest('d')
        );
        assert_eq!(
            post_completion_rollback_expected_endpoint_digest(&modify),
            digest('e')
        );
        assert_eq!(
            post_completion_rollback_expected_endpoint_digest(&delete),
            Digest::sha256(b"grok-build.post-completion-rollback.endpoint.absent.v1\0")
        );
        assert_ne!(
            post_completion_rollback_expected_endpoint_digest(&delete),
            digest('c')
        );
    }

    #[test]
    #[allow(clippy::too_many_lines)] // Invalid path/set probes and the valid terminal share one immutable fixture.
    fn post_completion_live_conflict_binds_exact_application_endpoint_and_allows_retry() {
        let database = TestDatabase::new();
        let (mut ledger, _completion, intent, _policy, launch, session) =
            begin_post_completion_rollback(
                &database,
                "rollback-operation-conflict",
                "rollback-effect-conflict",
                2_100,
            );
        let outside_change_set = post_completion_live_conflict(
            &intent,
            &launch,
            &session,
            vec![crate::LivePathConflict {
                path: PathBuf::from("unrelated.txt"),
                expected_endpoint_digest: digest('d'),
                observed_endpoint_digest: digest('e'),
            }],
        );
        assert!(matches!(
            ledger.record_post_completion_rollback_observation(&outside_change_set),
            Err(LedgerError::ReferenceMismatch { .. })
        ));
        let substituted_endpoint = post_completion_live_conflict(
            &intent,
            &launch,
            &session,
            vec![crate::LivePathConflict {
                path: PathBuf::from("report.txt"),
                expected_endpoint_digest: digest('c'),
                observed_endpoint_digest: digest('e'),
            }],
        );
        assert!(matches!(
            ledger.record_post_completion_rollback_observation(&substituted_endpoint),
            Err(LedgerError::ReferenceMismatch { .. })
        ));
        let duplicate_paths = post_completion_live_conflict(
            &intent,
            &launch,
            &session,
            vec![
                crate::LivePathConflict {
                    path: PathBuf::from("report.txt"),
                    expected_endpoint_digest: digest('d'),
                    observed_endpoint_digest: digest('e'),
                },
                crate::LivePathConflict {
                    path: PathBuf::from("report.txt"),
                    expected_endpoint_digest: digest('d'),
                    observed_endpoint_digest: digest('f'),
                },
            ],
        );
        assert!(matches!(
            ledger.record_post_completion_rollback_observation(&duplicate_paths),
            Err(LedgerError::Contract(_))
        ));
        let observation = post_completion_live_conflict(
            &intent,
            &launch,
            &session,
            vec![crate::LivePathConflict {
                path: PathBuf::from("report.txt"),
                expected_endpoint_digest: digest('d'),
                observed_endpoint_digest: digest('e'),
            }],
        );
        ledger
            .record_post_completion_rollback_observation(&observation)
            .expect("persist exact touched post-application conflict");
        let cleanup = finish_post_completion_cleanup(
            &mut ledger,
            &intent,
            &launch,
            "live-conflict",
            2_400,
            2_450,
        );
        ledger
            .finalize_post_completion_rollback(&PostCompletionRollbackTerminal {
                contract_version: CONTRACT_VERSION,
                terminal_id: "rollback-terminal-live-conflict".into(),
                operation_id: intent.operation_id.clone(),
                sprint_id: intent.sprint_id.clone(),
                application_receipt_id: intent.request.application_receipt_id.clone(),
                outcome_id: observation.observation_id,
                kind: PostCompletionRollbackOutcomeKind::LiveConflict,
                cleanup_receipt_ids: vec![cleanup.evidence.receipt.receipt_id],
                terminal_at_unix_ms: 2_500,
            })
            .expect("terminalize exact live conflict after cleanup");
        let retry = ledger
            .build_post_completion_rollback_intent(
                "sprint-1",
                "rollback-operation-after-conflict".into(),
                "idempotency-after-conflict".into(),
                "rollback-effect-after-conflict".into(),
                2_600,
            )
            .expect("build retry after live conflict");
        ledger
            .record_post_completion_rollback_intent(&retry)
            .expect("LiveConflict terminal permits a later explicit retry");
    }

    #[test]
    #[allow(clippy::too_many_lines)] // Launch failure, cleanup, collision, and safe-retry invariants are inseparable.
    fn post_completion_no_effect_launch_failure_cleans_up_and_allows_retry() {
        let database = TestDatabase::new();
        let expected = {
            let mut legacy = open_v21_test_ledger(&database);
            let (report, receipt, event) = prepare_completion_evidence(&mut legacy);
            record_pre_v24_successful_completion_for_test(&mut legacy, &report, &receipt, &event)
                .expect("record immutable pre-v24 completion")
        };
        let mut ledger = EventLedger::open(&database.path)
            .expect("migrate completion before post-completion launch failure");
        let completion = load_migrated_pre_v24_completion(&ledger, &expected);
        let intent = ledger
            .build_post_completion_rollback_intent(
                "sprint-1",
                "rollback-operation-no-effect".into(),
                "idempotency-no-effect".into(),
                "rollback-effect-no-effect".into(),
                2_100,
            )
            .expect("build rollback intent");
        ledger
            .record_post_completion_rollback_intent(&intent)
            .expect("record rollback intent");
        let policy = compiled_test_policy("policy-applier");
        let mut launch = runner_launch(
            "launch-rollback-no-effect",
            "session-rollback-no-effect",
            RunnerSessionPurpose::Applier,
            None,
            &policy,
            2_200,
        );
        launch.private_state_digest = Digest::sha256(b"launch-applier");
        ledger
            .record_post_completion_rollback_applier_launch(
                &intent.operation_id,
                PostCompletionRollbackApplierRole::Executor,
                &launch,
                &policy,
            )
            .expect("commit fresh launch before spawn");
        let failure_evidence_bytes = b"admission refused before operating-system spawn".to_vec();
        let failure = PostCompletionRollbackLaunchFailure {
            contract_version: CONTRACT_VERSION,
            failure_id: "launch-failure-no-effect".into(),
            operation_id: intent.operation_id.clone(),
            sprint_id: intent.sprint_id.clone(),
            launch_id: launch.launch_id.clone(),
            expected_session_id: launch.session_id.clone(),
            launch_role: PostCompletionRollbackApplierRole::Executor,
            kind: PostCompletionRollbackLaunchFailureKind::LaunchRefusedBeforeSpawn,
            failure_evidence_digest: Digest::sha256(&failure_evidence_bytes),
            failure_evidence_bytes,
            failed_at_unix_ms: 2_250,
        };
        let persisted = ledger
            .record_post_completion_rollback_launch_failure(&failure)
            .expect("persist provable pre-spawn no-effect outcome");
        assert_eq!(persisted.launch_failure, Some(failure.clone()));
        assert!(persisted.appliers[0].session.is_none());
        assert_eq!(
            persisted.status(),
            PostCompletionRollbackStatus::OutcomeAwaitingCleanup(
                PostCompletionRollbackOutcomeKind::NoEffect
            )
        );
        assert!(matches!(
            ledger.register_post_completion_rollback_applier_session(
                &intent.operation_id,
                &runner_session(&launch, 2_300),
                &policy,
            ),
            Err(LedgerError::ReferenceMismatch { .. })
        ));
        let cleanup = finish_post_completion_cleanup(
            &mut ledger,
            &intent,
            &launch,
            "no-effect",
            2_300,
            2_350,
        );
        let terminal = PostCompletionRollbackTerminal {
            contract_version: CONTRACT_VERSION,
            terminal_id: "rollback-terminal-no-effect".into(),
            operation_id: intent.operation_id.clone(),
            sprint_id: intent.sprint_id.clone(),
            application_receipt_id: intent.request.application_receipt_id.clone(),
            outcome_id: failure.failure_id.clone(),
            kind: PostCompletionRollbackOutcomeKind::NoEffect,
            cleanup_receipt_ids: vec![cleanup.evidence.receipt.receipt_id.clone()],
            terminal_at_unix_ms: 2_400,
        };
        assert_eq!(
            ledger
                .finalize_post_completion_rollback(&terminal)
                .expect("terminalize only after launch-domain cleanup")
                .status(),
            PostCompletionRollbackStatus::Terminal(PostCompletionRollbackOutcomeKind::NoEffect)
        );

        let old_effect_error = ledger
            .connection
            .execute(
                r#"INSERT INTO effect_intents (
                    effect_id, sprint_id, idempotency_key, task_id, worker_id,
                    causation_event_id, correlation_id, effect_kind,
                    request_digest, policy_hash, input_snapshot,
                    proposed_event_id, contract_version, created_at_unix_ms,
                    intent_json
                 ) VALUES (
                    ?1, 'sprint-1', 'old-effect-collision', NULL, NULL, NULL,
                    'old-effect-collision', 'SearchLiteral', ?2, ?3, ?4,
                    'missing-proposal', ?5, 2500,
                    CAST('{"worker_lease":null}' AS BLOB)
                 )"#,
                params![
                    cleanup.cleanup_effect_id,
                    digest('a').as_str(),
                    digest('d').as_str(),
                    digest('b').as_str(),
                    CONTRACT_VERSION,
                ],
            )
            .expect_err("old effect table must reject a post-completion cleanup effect id");
        assert!(
            old_effect_error
                .to_string()
                .contains("effect identity must be globally unique")
        );
        let old_observation_error = ledger
            .connection
            .execute(
                r#"INSERT INTO effect_observations (
                    observation_id, effect_id, sprint_id, idempotency_key,
                    task_id, worker_id, correlation_id, effect_kind,
                    request_digest, policy_hash, input_snapshot, outcome,
                    evidence_digest, terminal_event_id, contract_version,
                    observed_at_unix_ms, observation_json
                 ) VALUES (
                    ?1, 'missing-effect', 'sprint-1', 'old-observation-collision',
                    NULL, NULL, 'old-observation-collision', 'SearchLiteral',
                    ?2, ?3, ?4, 'Succeeded', ?5, 'missing-terminal', ?6,
                    2500, CAST('{"worker_lease":null}' AS BLOB)
                 )"#,
                params![
                    cleanup.evidence.receipt.observation_id,
                    digest('a').as_str(),
                    digest('d').as_str(),
                    digest('b').as_str(),
                    digest('e').as_str(),
                    CONTRACT_VERSION,
                ],
            )
            .expect_err("old observation table must reject a post-completion cleanup observation");
        assert!(
            old_observation_error
                .to_string()
                .contains("effect observation identity must be globally unique")
        );
        let old_launch_error = ledger
            .connection
            .execute(
                r#"INSERT INTO runner_launch_intents (
                    launch_id, sprint_id, session_id, purpose, worker_id,
                    policy_hash, runner_binary_digest, protocol_digest,
                    private_state_digest, grant_hash, policy_version,
                    contract_version, created_at_unix_ms, intent_json,
                    execution_policy_json
                 ) VALUES (
                    ?1, 'sprint-1', 'old-session-cross-collision', 'Applier',
                    NULL, ?2, ?3, ?4, ?5, ?6, ?7, ?8, 2500,
                    CAST('{"worker_lease":null}' AS BLOB), X'7B7D'
                 )"#,
                params![
                    launch.session_id,
                    launch.policy_hash.as_str(),
                    launch.runner_binary_digest.as_str(),
                    launch.protocol_digest.as_str(),
                    launch.private_state_digest.as_str(),
                    launch.grant_hash.as_str(),
                    launch.policy_version,
                    CONTRACT_VERSION,
                ],
            )
            .expect_err("old launch table must reject a post-completion session identity");
        assert!(
            old_launch_error
                .to_string()
                .contains("runner launch and session identities must be globally unique")
        );

        let collision = ledger
            .build_post_completion_rollback_intent(
                "sprint-1",
                "rollback-operation-effect-collision".into(),
                "idempotency-effect-collision".into(),
                cleanup.cleanup_effect_id.clone(),
                2_500,
            )
            .expect("build collision probe");
        assert!(matches!(
            ledger.record_post_completion_rollback_intent(&collision),
            Err(LedgerError::ArtifactAlreadyExists { .. })
        ));
        let retry = ledger
            .build_post_completion_rollback_intent(
                "sprint-1",
                "rollback-operation-after-no-effect".into(),
                "idempotency-after-no-effect".into(),
                "rollback-effect-after-no-effect".into(),
                2_500,
            )
            .expect("build safe retry after provable no-effect");
        ledger
            .record_post_completion_rollback_intent(&retry)
            .expect("NoEffect terminal releases the active slot");
        let mut crossed_launch = runner_launch(
            &launch.session_id,
            "session-after-no-effect",
            RunnerSessionPurpose::Applier,
            None,
            &policy,
            2_600,
        );
        crossed_launch.private_state_digest = launch.private_state_digest.clone();
        assert!(matches!(
            ledger.record_post_completion_rollback_applier_launch(
                &retry.operation_id,
                PostCompletionRollbackApplierRole::Executor,
                &crossed_launch,
                &policy,
            ),
            Err(LedgerError::ArtifactAlreadyExists { .. })
        ));
        assert_eq!(
            ledger
                .load_completion("sprint-1")
                .expect("completion remains immutable"),
            Some(completion)
        );
        let mut ambiguous = failure.clone();
        ambiguous.kind = PostCompletionRollbackLaunchFailureKind::InitializationOutcomeUnknown;
        assert_eq!(
            ambiguous.outcome_kind(),
            PostCompletionRollbackOutcomeKind::Unknown
        );
        ambiguous.launch_role = PostCompletionRollbackApplierRole::RecoveryValidator;
        ambiguous.kind = PostCompletionRollbackLaunchFailureKind::SpawnFailedBeforeChild;
        assert_eq!(
            ambiguous.outcome_kind(),
            PostCompletionRollbackOutcomeKind::Unknown
        );
    }

    #[test]
    #[allow(clippy::too_many_lines)] // API, restart, and raw-SQL replay fences share one Unknown terminal fixture.
    fn post_completion_unknown_is_truthful_terminal_and_permanently_fences_replay() {
        let database = TestDatabase::new();
        let (mut ledger, completion, intent, _policy, launch, session) =
            begin_post_completion_rollback(
                &database,
                "rollback-operation-unknown",
                "rollback-effect-unknown",
                2_100,
            );
        let second = ledger
            .build_post_completion_rollback_intent(
                "sprint-1",
                "rollback-operation-after-unknown".into(),
                "idempotency-after-unknown".into(),
                "rollback-effect-after-unknown".into(),
                2_700,
            )
            .expect("build potential follow-up intent");
        assert!(matches!(
            ledger.record_post_completion_rollback_intent(&second),
            Err(LedgerError::ReferenceMismatch { .. })
        ));
        let unknown_bytes = b"journal outcome could not be reconciled".to_vec();
        let observation = PostCompletionRollbackObservation {
            contract_version: CONTRACT_VERSION,
            observation_id: "observation-rollback-unknown".into(),
            operation_id: intent.operation_id.clone(),
            sprint_id: intent.sprint_id.clone(),
            rollback_effect_id: intent.rollback_effect_id.clone(),
            request_digest: intent.request_digest.clone(),
            executor_launch_id: launch.launch_id.clone(),
            executor_session_id: session.session_id.clone(),
            outcome: PostCompletionRollbackOutcome::Unknown {
                evidence: PostCompletionRollbackUnknownEvidence {
                    evidence_id: "unknown-evidence-post-rollback".into(),
                    reason: "neither success nor unchanged live state can be proven".into(),
                    reconciliation_evidence_digest: Digest::sha256(&unknown_bytes),
                    reconciliation_evidence_bytes: unknown_bytes,
                },
                validation: direct_validation(&launch, &session),
            },
            effect_started_at_unix_ms: 2_300,
            observed_at_unix_ms: 2_350,
        };
        ledger
            .record_post_completion_rollback_observation(&observation)
            .expect("persist truthful unknown outcome");
        let cleanup =
            finish_post_completion_cleanup(&mut ledger, &intent, &launch, "unknown", 2_400, 2_450);
        ledger
            .finalize_post_completion_rollback(&PostCompletionRollbackTerminal {
                contract_version: CONTRACT_VERSION,
                terminal_id: "rollback-terminal-unknown".into(),
                operation_id: intent.operation_id,
                sprint_id: intent.sprint_id,
                application_receipt_id: intent.request.application_receipt_id,
                outcome_id: observation.observation_id,
                kind: PostCompletionRollbackOutcomeKind::Unknown,
                cleanup_receipt_ids: vec![cleanup.evidence.receipt.receipt_id],
                terminal_at_unix_ms: 2_500,
            })
            .expect("terminalize unknown operation only after cleanup");
        drop(ledger);
        let mut ledger = EventLedger::open(&database.path).expect("restart writable ledger");
        assert!(matches!(
            ledger.record_post_completion_rollback_intent(&second),
            Err(LedgerError::ReferenceMismatch { .. })
        ));
        let request_bytes =
            encode("post-completion rollback request", &second.request).expect("encode request");
        let intent_bytes =
            encode("post-completion rollback intent", &second).expect("encode intent");
        let direct_sql_error = ledger
            .connection
            .execute(
                "INSERT INTO post_completion_rollback_operations (
                    operation_id, idempotency_key, rollback_effect_id, sprint_id,
                    completion_receipt_id, application_receipt_id,
                    rollback_reference_id, request_digest,
                    completion_receipt_digest, application_evidence_digest,
                    rollback_reference_evidence_digest, policy_hash, grant_hash,
                    policy_version, contract_version, created_at_unix_ms,
                    request_json, intent_json
                 ) VALUES (
                    ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12,
                    ?13, ?14, ?15, ?16, ?17, ?18
                 )",
                params![
                    second.operation_id,
                    second.idempotency_key,
                    second.rollback_effect_id,
                    second.sprint_id,
                    second.completion_receipt_id,
                    second.request.application_receipt_id,
                    second.request.rollback_reference_id,
                    second.request_digest.as_str(),
                    second.completion_receipt_digest.as_str(),
                    second.application_evidence_digest.as_str(),
                    second.rollback_reference_evidence_digest.as_str(),
                    second.policy_hash.as_str(),
                    second.grant_hash.as_str(),
                    i64::from(second.policy_version),
                    i64::from(second.contract_version),
                    i64::try_from(second.created_at_unix_ms).expect("timestamp fits SQLite"),
                    request_bytes,
                    intent_bytes,
                ],
            )
            .expect_err("v10 trigger must reject replay after unknown");
        assert!(
            direct_sql_error
                .to_string()
                .contains("without prior success or unknown effect")
        );
        assert_eq!(
            ledger
                .load_completion("sprint-1")
                .expect("completion remains immutable"),
            Some(completion)
        );
    }

    #[test]
    fn current_task_cleanup_non_success_rejects_generic_observation_before_any_write() {
        let database = TestDatabase::new();
        let mut ledger = EventLedger::open(&database.path).expect("open ledger");
        let (_policy, launch, _session) = prepare_command_domain_session(&mut ledger);
        let admission = ledger
            .load_runner_launch_cleanup_admission(&launch.sprint_id, &launch.launch_id)
            .expect("load task cleanup admission");
        let lease = launch.worker_lease.as_ref().expect("task-worker lease");
        let event_count = row_count(&ledger, "agent_events");
        let evidence_count = row_count(&ledger, "effect_evidence_payloads");
        let observation_count = row_count(&ledger, "effect_observations");

        for (index, outcome_name) in [
            "failed-before-effect",
            "failed-after-known-effect",
            "cancelled-before-effect",
            "unknown",
        ]
        .into_iter()
        .enumerate()
        {
            let evidence_bytes = format!("current task cleanup {outcome_name}").into_bytes();
            let evidence_digest = Digest::sha256(&evidence_bytes);
            let outcome = match index {
                0 => EffectOutcome::FailedBeforeEffect { evidence_digest },
                1 => EffectOutcome::FailedAfterKnownEffect { evidence_digest },
                2 => EffectOutcome::CancelledBeforeEffect { evidence_digest },
                3 => EffectOutcome::Unknown { evidence_digest },
                _ => unreachable!("closed cleanup outcome table"),
            };
            let observation = effect_observation(
                &admission.cleanup_effect.intent,
                &format!("observation-current-cleanup-{outcome_name}"),
                outcome,
                1_400 + u64::try_from(index).expect("small outcome index"),
            );
            let terminal = effect_terminal_event(
                &admission.cleanup_effect.intent,
                &admission.cleanup_effect.proposed_event.event_id,
                &observation,
                ledger
                    .next_sequence(&launch.sprint_id)
                    .expect("cleanup terminal sequence"),
                &format!("event-current-cleanup-{outcome_name}"),
            );
            assert!(matches!(
                ledger.record_effect_observation(&observation, &evidence_bytes, &terminal),
                Err(LedgerError::ReferenceMismatch {
                    entity: "worker cleanup observation",
                    ..
                })
            ));
            assert_eq!(row_count(&ledger, "agent_events"), event_count);
            assert_eq!(
                row_count(&ledger, "effect_evidence_payloads"),
                evidence_count
            );
            assert_eq!(row_count(&ledger, "effect_observations"), observation_count);
        }

        drop(ledger);
        let ledger = EventLedger::open_read_only(&database.path).expect("reopen read-only ledger");
        assert!(
            ledger
                .load_effect(&admission.cleanup_effect.intent.effect_id)
                .expect("reload cleanup effect")
                .observation
                .is_none()
        );
        assert_eq!(
            ledger
                .load_active_worker_leases(&launch.sprint_id)
                .expect("reload active leases"),
            vec![lease.clone()]
        );
        assert_eq!(row_count(&ledger, "task_attempt_dispositions"), 0);
    }

    #[test]
    #[allow(clippy::too_many_lines)] // Exercises immediate coverage rejection and deferred commit rollback through reopen.
    fn current_task_cleanup_receipt_requires_exact_disposition_and_release_coverage() {
        let database = TestDatabase::new();
        let mut ledger = EventLedger::open(&database.path).expect("open ledger");
        let (_policy, launch, _session) = prepare_command_domain_session(&mut ledger);
        let cleanup = cleanup_terminal_record(&ledger, &launch, "cleanup-coverage", 1_400);
        let cleanup_bytes =
            encode("worker cleanup evidence", &cleanup.evidence).expect("encode cleanup evidence");
        let lease = launch.worker_lease.as_ref().expect("task-worker lease");
        let attempt = ledger
            .load_task_attempt(&lease.lease_id)
            .expect("load current attempt");
        let event_count = row_count(&ledger, "agent_events");
        let finish_id_count = row_count(&ledger, "finish_receipt_ids");
        let evidence_count = row_count(&ledger, "effect_evidence_payloads");

        {
            let transaction = ledger
                .connection
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .expect("start uncovered cleanup transaction");
            insert_finish_receipt_id(
                &transaction,
                &cleanup.evidence.receipt.receipt_id,
                &launch.sprint_id,
                "WorkerCleanup",
            )
            .expect("stage cleanup receipt identity");
            insert_effect_evidence_payload(&transaction, &cleanup.observation, &cleanup_bytes)
                .expect("stage cleanup evidence");
            let error =
                insert_worker_cleanup_receipt(&transaction, &cleanup.evidence, &cleanup_bytes)
                    .expect_err("receipt without v15 coverage must fail immediately");
            assert!(
                error
                    .to_string()
                    .contains("requires deferred disposition and release coverage"),
                "unexpected receipt fence: {error}"
            );
            transaction
                .rollback()
                .expect("roll back uncovered cleanup transaction");
        }

        {
            let transaction = ledger
                .connection
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .expect("start crossed cleanup coverage transaction");
            let mut crossed_receipt = cleanup.evidence.receipt.clone();
            crossed_receipt.receipt_id = "cleanup-coverage-crossed".into();
            crossed_receipt.effect_id = "cleanup-effect-crossed".into();
            let error = task_attempt_authority::insert_cleanup_result_coverage(
                &transaction,
                "cleanup-disposition-crossed",
                &attempt,
                &crossed_receipt,
            )
            .expect_err("crossed cleanup effect cannot reserve coverage");
            assert!(
                error.to_string().contains(
                    "coverage must precede one exact current receipt, disposition, and release"
                ),
                "unexpected crossed coverage fence: {error}"
            );
            transaction
                .rollback()
                .expect("roll back crossed coverage transaction");
        }

        {
            let transaction = ledger
                .connection
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .expect("start deferred cleanup transaction");
            task_attempt_authority::insert_cleanup_result_coverage(
                &transaction,
                "cleanup-disposition-deferred",
                &attempt,
                &cleanup.evidence.receipt,
            )
            .expect("reserve exact cleanup coverage");
            insert_finish_receipt_id(
                &transaction,
                &cleanup.evidence.receipt.receipt_id,
                &launch.sprint_id,
                "WorkerCleanup",
            )
            .expect("stage covered receipt identity");
            insert_effect_evidence_payload(&transaction, &cleanup.observation, &cleanup_bytes)
                .expect("stage covered cleanup evidence");
            insert_worker_cleanup_receipt(&transaction, &cleanup.evidence, &cleanup_bytes)
                .expect("stage covered cleanup receipt");
            insert_agent_event(&transaction, &cleanup.event).expect("stage cleanup terminal event");
            insert_effect_observation(&transaction, &cleanup.observation, &cleanup.event.event_id)
                .expect("stage cleanup observation");
            let error = transaction
                .commit()
                .expect_err("coverage cannot commit without disposition and release");
            assert!(
                error.to_string().contains("FOREIGN KEY constraint failed"),
                "unexpected deferred coverage fence: {error}"
            );
        }

        drop(ledger);
        let ledger = EventLedger::open_read_only(&database.path).expect("reopen read-only ledger");
        assert_eq!(row_count(&ledger, "agent_events"), event_count);
        assert_eq!(row_count(&ledger, "finish_receipt_ids"), finish_id_count);
        assert_eq!(
            row_count(&ledger, "effect_evidence_payloads"),
            evidence_count
        );
        assert_eq!(row_count(&ledger, "effect_observations"), 0);
        assert_eq!(row_count(&ledger, "worker_cleanup_receipts"), 0);
        assert_eq!(
            row_count(&ledger, "task_attempt_cleanup_result_coverage"),
            0
        );
        assert_eq!(row_count(&ledger, "task_attempt_dispositions"), 0);
        assert_eq!(row_count(&ledger, "worker_lease_releases"), 0);
        assert_eq!(
            ledger
                .load_active_worker_leases(&launch.sprint_id)
                .expect("reload active lease"),
            vec![lease.clone()]
        );
    }

    #[test]
    #[allow(clippy::too_many_lines)] // API and direct-SQL release paths share one staged exact cleanup proof.
    fn worker_lease_release_requires_disposition_and_waits_for_every_effect_to_finish() {
        let database = TestDatabase::new();
        let mut ledger = EventLedger::open(&database.path).expect("open ledger");
        let (_policy, launch, _session) = prepare_command_domain_session(&mut ledger);
        let (pending, proposal, pending_permit) =
            persist_command_domain_intent(&mut ledger, &launch, "pending-before-cleanup", 1_200);
        let first_cleanup = cleanup_terminal_record(&ledger, &launch, "cleanup-pending", 1_400);
        let cleanup_bytes = encode("worker cleanup evidence", &first_cleanup.evidence)
            .expect("encode staged cleanup");
        let lease = launch.worker_lease.as_ref().expect("task-worker lease");
        let attempt = ledger
            .load_task_attempt(&lease.lease_id)
            .expect("load current command-domain attempt");

        let transaction = ledger
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .expect("stage direct-SQL cleanup proof");
        task_attempt_authority::insert_cleanup_result_coverage(
            &transaction,
            "direct-sql-cleanup-disposition",
            &attempt,
            &first_cleanup.evidence.receipt,
        )
        .expect("stage deferred cleanup coverage");
        insert_finish_receipt_id(
            &transaction,
            &first_cleanup.evidence.receipt.receipt_id,
            &launch.sprint_id,
            "WorkerCleanup",
        )
        .expect("stage cleanup receipt identity");
        insert_effect_evidence_payload(&transaction, &first_cleanup.observation, &cleanup_bytes)
            .expect("stage cleanup evidence payload");
        insert_worker_cleanup_receipt(&transaction, &first_cleanup.evidence, &cleanup_bytes)
            .expect("stage cleanup receipt");
        insert_agent_event(&transaction, &first_cleanup.event).expect("stage cleanup event");
        insert_effect_observation(
            &transaction,
            &first_cleanup.observation,
            &first_cleanup.event.event_id,
        )
        .expect("stage cleanup observation");
        let sql_error = transaction
            .execute(
                "INSERT INTO worker_lease_releases (
                    lease_id, sprint_id, lease_epoch, cleanup_receipt_id,
                    cleanup_effect_id, cleanup_observation_id,
                    released_at_unix_ms, contract_version
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                params![
                    lease.lease_id,
                    lease.sprint_id,
                    sqlite_integer("test lease epoch", lease.lease_epoch)
                        .expect("lease epoch fits SQLite"),
                    first_cleanup.evidence.receipt.receipt_id,
                    first_cleanup.evidence.receipt.effect_id,
                    first_cleanup.evidence.receipt.observation_id,
                    sqlite_integer(
                        "test cleanup timestamp",
                        first_cleanup.evidence.receipt.cleaned_at_unix_ms,
                    )
                    .expect("cleanup timestamp fits SQLite"),
                    i64::from(CONTRACT_VERSION),
                ],
            )
            .expect_err("direct SQL cannot release around an unfinished effect");
        assert!(
            sql_error.to_string().contains(
                "current task-attempt cleanup release requires its exact prior disposition"
            ),
            "unexpected release fence: {sql_error}"
        );
        transaction.rollback().expect("roll back staged direct SQL");

        let outcome = TaskAttemptKnownCleanupOutcome::PermanentFailure(
            crate::TaskAttemptPermanentFailureCause::PermanentContractViolation {
                violation_id: "unfinished-command-domain-contract".into(),
                evidence: crate::TaskAttemptEvidence::new(
                    "unfinished-command-domain-evidence".into(),
                    crate::TaskAttemptEvidenceKind::PermanentContractViolation,
                    b"command-domain attempt cannot complete its immutable contract".to_vec(),
                )
                .expect("construct permanent command-domain evidence"),
            },
        );
        ledger
            .record_task_attempt_cleanup_outcome_authority(&attempt, &outcome, 1_350)
            .expect("record independent permanent-failure authority");
        let first_metadata = TaskAttemptDispositionMetadata {
            contract_version: CONTRACT_VERSION,
            disposition_id: "unfinished-command-domain-disposition".into(),
            attempt: attempt.clone(),
            from_state: TaskState::Running,
            state_transition_event_id: "unfinished-command-domain-failed".into(),
            disposed_at_unix_ms: 1_450,
        };
        let first_transition = AgentEvent {
            contract_version: CONTRACT_VERSION,
            sequence: first_cleanup.event.sequence + 1,
            event_id: first_metadata.state_transition_event_id.clone(),
            sprint_id: launch.sprint_id.clone(),
            task_id: Some(lease.task_id.clone()),
            worker_id: Some(lease.worker_id.clone()),
            causation_id: Some(attempt.opening_event_id.clone()),
            correlation_id: "unfinished-command-domain-lifecycle".into(),
            policy_hash: Some(launch.policy_hash.clone()),
            occurred_at_unix_ms: first_metadata.disposed_at_unix_ms,
            payload: AgentEventKind::TaskStateChanged {
                from: "Running".into(),
                to: "Failed".into(),
            },
        };
        let callback_invoked = Arc::new(AtomicBool::new(false));
        let rejected_callback_invoked = Arc::clone(&callback_invoked);
        let api_error = ledger
            .with_task_attempt_cleanup_disposition_exclusion(
                &first_metadata,
                &outcome,
                "unfinished-command-domain-release",
                &first_transition,
                move |_| {
                    rejected_callback_invoked.store(true, Ordering::SeqCst);
                    panic!("unresolved lease effect must reject before native cleanup")
                },
            )
            .expect_err("disposition cannot clean while another lease effect is pending");
        assert!(matches!(
            api_error,
            LedgerError::ReferenceMismatch {
                entity: "task attempt cleanup disposition",
                ..
            }
        ));
        assert!(!callback_invoked.load(Ordering::SeqCst));
        assert_eq!(
            ledger.load_active_worker_leases("sprint-1").unwrap(),
            vec![lease.clone()]
        );
        assert!(
            ledger
                .load_effect(&first_cleanup.observation.effect_id)
                .expect("cleanup intent remains")
                .observation
                .is_none()
        );

        persist_command_domain_observation(
            &mut ledger,
            &pending,
            &proposal,
            pending_permit,
            EffectOutcome::FailedBeforeEffect {
                evidence_digest: effect_evidence_digest(),
            },
            1_300,
        );
        let retry_cleanup =
            cleanup_terminal_record(&ledger, &launch, "cleanup-after-terminal", 1_500);
        let final_metadata = TaskAttemptDispositionMetadata {
            contract_version: CONTRACT_VERSION,
            disposition_id: "terminal-command-domain-disposition".into(),
            attempt: attempt.clone(),
            from_state: TaskState::Running,
            state_transition_event_id: "terminal-command-domain-failed".into(),
            disposed_at_unix_ms: 1_550,
        };
        let final_transition = AgentEvent {
            contract_version: CONTRACT_VERSION,
            sequence: retry_cleanup.event.sequence + 1,
            event_id: final_metadata.state_transition_event_id.clone(),
            sprint_id: launch.sprint_id.clone(),
            task_id: Some(lease.task_id.clone()),
            worker_id: Some(lease.worker_id.clone()),
            causation_id: Some(attempt.opening_event_id.clone()),
            correlation_id: "terminal-command-domain-lifecycle".into(),
            policy_hash: Some(launch.policy_hash.clone()),
            occurred_at_unix_ms: final_metadata.disposed_at_unix_ms,
            payload: AgentEventKind::TaskStateChanged {
                from: "Running".into(),
                to: "Failed".into(),
            },
        };
        let disposition = ledger
            .with_task_attempt_cleanup_disposition_exclusion(
                &final_metadata,
                &outcome,
                "terminal-command-domain-release",
                &final_transition,
                |claim| {
                    assert_eq!(claim.next_event_sequence(), retry_cleanup.event.sequence);
                    Ok(retry_cleanup.clone())
                },
            )
            .expect("cleanup and disposition succeed after every lease effect is terminal");
        assert!(matches!(
            disposition,
            TaskAttemptDisposition::PermanentFailure(_)
        ));
        assert!(
            ledger
                .load_active_worker_leases("sprint-1")
                .expect("load active leases")
                .is_empty()
        );
        assert_eq!(
            ledger
                .load_task_attempt_disposition(&final_metadata.disposition_id)
                .expect("reload covered cleanup disposition"),
            disposition
        );
        assert_eq!(
            ledger
                .load_worker_cleanup_receipt(&retry_cleanup.evidence.receipt.receipt_id)
                .expect("reload cleanup receipt with exact release"),
            retry_cleanup.evidence.receipt
        );
        ledger
            .connection
            .execute_batch(
                "DROP TRIGGER task_attempt_cleanup_result_coverage_no_delete;
                 DELETE FROM task_attempt_cleanup_result_coverage;",
            )
            .expect("remove cleanup coverage through corruption bypass");
        assert!(matches!(
            ledger.load_task_attempt_disposition(&final_metadata.disposition_id),
            Err(LedgerError::Corrupt {
                entity: "task attempt cleanup-result coverage",
                ..
            })
        ));
        ledger
            .connection
            .execute_batch(
                "DROP TRIGGER worker_lease_releases_no_delete;
                 DELETE FROM worker_lease_releases;",
            )
            .expect("remove lease release through corruption bypass");
        assert!(matches!(
            ledger.load_worker_cleanup_receipt(&retry_cleanup.evidence.receipt.receipt_id),
            Err(LedgerError::Corrupt {
                entity: "worker lease release",
                ..
            })
        ));
    }

