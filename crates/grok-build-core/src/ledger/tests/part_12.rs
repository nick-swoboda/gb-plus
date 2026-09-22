    fn assert_legacy_effect_payload_is_unreadable(ledger: &EventLedger) {
        assert!(matches!(
            ledger.load_effect("legacy-effect"),
            Err(LedgerError::LegacyEffectPayloadMissing {
                entity: "request",
                effect_id,
            }) if effect_id == "legacy-effect"
        ));
        assert!(matches!(
            ledger.load_effect_by_idempotency_key("sprint-1", "legacy-key"),
            Err(LedgerError::LegacyEffectPayloadMissing {
                entity: "request",
                ..
            })
        ));
        assert!(matches!(
            ledger.load_sprint("sprint-1"),
            Err(LedgerError::LegacyEffectPayloadMissing {
                entity: "request",
                ..
            })
        ));
        assert!(matches!(
            ledger.load_unfinished_effects("sprint-1"),
            Err(LedgerError::LegacyEffectPayloadMissing {
                entity: "request",
                ..
            })
        ));
        assert!(matches!(
            ledger.load_completion("sprint-1"),
            Err(LedgerError::LegacyGraphUnproven(id)) if id == "sprint-1"
        ));
    }

    #[test]
    fn standalone_verification_cannot_authorize_automated_acceptance() {
        let database = TestDatabase::new();
        let mut ledger = EventLedger::open(&database.path).expect("open ledger");
        let (spec, graph) = sprint_fixture();
        ledger
            .create_sprint(&spec, &graph, 1_000)
            .expect("persist sprint");
        let (_, final_snapshot, _, mut verification, acceptance, _, _, _) = completion_artifacts();
        ledger
            .persist_workspace_snapshot("sprint-1", &final_snapshot)
            .expect("persist snapshot");
        verification.command.arguments = vec!["check".into()];
        ledger
            .persist_verification_receipt(&verification)
            .expect("persist otherwise valid verification");

        assert!(matches!(
            ledger.persist_acceptance_receipt(&acceptance),
            Err(LedgerError::ArtifactNotFound {
                entity: "verification effect evidence",
                ..
            })
        ));
        assert_eq!(row_count(&ledger, "acceptance_receipts"), 0);
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "legacy byte preservation and current typed-write fencing share one restart boundary"
    )]
    fn historical_verification_reads_exactly_while_current_writes_require_typed_termination() {
        let database = TestDatabase::new();
        let mut ledger = EventLedger::open(&database.path).expect("open ledger");
        let (spec, graph) = sprint_fixture();
        ledger
            .create_sprint(&spec, &graph, 1_000)
            .expect("persist sprint");
        let (_, final_snapshot, _, mut historical, _, _, _, _) = completion_artifacts();
        ledger
            .persist_workspace_snapshot("sprint-1", &final_snapshot)
            .expect("persist snapshot");

        historical.receipt_id = "historical-untyped-verification".into();
        historical.termination = None;
        assert_eq!(historical.validate(), Ok(()));
        assert!(matches!(
            ledger.persist_verification_receipt(&historical),
            Err(LedgerError::Contract(error))
                if error.field() == "verification_receipt.termination"
        ));
        assert_eq!(row_count(&ledger, "verification_receipts"), 0);

        let historical_bytes =
            encode("historical verification receipt", &historical).expect("encode historical row");
        assert!(
            !historical_bytes
                .windows(b"termination".len())
                .any(|window| { window == b"termination" })
        );
        ledger
            .connection
            .execute(
                "INSERT INTO verification_receipts (
                    receipt_id, sprint_id, snapshot_id, passed, contract_version,
                    finished_at_unix_ms, receipt_json
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                params![
                    historical.receipt_id,
                    historical.sprint_id,
                    historical.snapshot_id.as_str(),
                    1_i64,
                    i64::from(CONTRACT_VERSION),
                    i64::try_from(historical.finished_at_unix_ms)
                        .expect("historical timestamp fits SQLite"),
                    &historical_bytes,
                ],
            )
            .expect("insert exact historical receipt bytes");
        drop(ledger);

        let mut ledger = EventLedger::open(&database.path).expect("reopen ledger");
        let loaded = ledger
            .load_verification_receipt(&historical.receipt_id)
            .expect("load historical receipt");
        assert_eq!(loaded, historical);
        assert!(loaded.passed());
        let stored_bytes: Vec<u8> = ledger
            .connection
            .query_row(
                "SELECT receipt_json FROM verification_receipts WHERE receipt_id = ?1",
                [&historical.receipt_id],
                |row| row.get(0),
            )
            .expect("read historical receipt bytes");
        assert_eq!(stored_bytes, historical_bytes);
        assert_eq!(
            encode("historical verification receipt", &loaded)
                .expect("re-encode historical receipt"),
            historical_bytes
        );

        let mut noncanonical = historical.clone();
        noncanonical.receipt_id = "historical-noncanonical-verification".into();
        let mut noncanonical_bytes = encode("noncanonical verification receipt", &noncanonical)
            .expect("encode noncanonical fixture base");
        assert_eq!(noncanonical_bytes.pop(), Some(b'}'));
        noncanonical_bytes.extend_from_slice(br#","unknown":true}"#);
        ledger
            .connection
            .execute(
                "INSERT INTO verification_receipts (
                    receipt_id, sprint_id, snapshot_id, passed, contract_version,
                    finished_at_unix_ms, receipt_json
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                params![
                    noncanonical.receipt_id,
                    noncanonical.sprint_id,
                    noncanonical.snapshot_id.as_str(),
                    1_i64,
                    i64::from(CONTRACT_VERSION),
                    i64::try_from(noncanonical.finished_at_unix_ms)
                        .expect("noncanonical timestamp fits SQLite"),
                    noncanonical_bytes,
                ],
            )
            .expect("insert decodable noncanonical historical receipt");
        assert!(matches!(
            ledger.load_verification_receipt(&noncanonical.receipt_id),
            Err(LedgerError::Corrupt {
                entity: "verification receipt",
                detail,
            }) if detail.contains("noncanonical")
        ));

        let mut signaled = historical;
        signaled.receipt_id = "current-signaled-verification".into();
        signaled.exit_status = None;
        signaled.termination = Some(CommandTerminationV1::Signaled { signal: 9 });
        ledger
            .persist_verification_receipt(&signaled)
            .expect("persist typed non-exit verification");
        assert_eq!(
            ledger
                .load_verification_receipt(&signaled.receipt_id)
                .expect("load typed non-exit verification"),
            signaled
        );
        let passed: i64 = ledger
            .connection
            .query_row(
                "SELECT passed FROM verification_receipts WHERE receipt_id = ?1",
                [&signaled.receipt_id],
                |row| row.get(0),
            )
            .expect("read typed non-exit pass index");
        assert_eq!(passed, 0);
        assert!(!signaled.passed());
    }

    #[test]
    #[allow(clippy::too_many_lines)] // API and direct-SQL bypasses form one adversarial case.
    fn successful_integration_requires_an_atomic_typed_receipt() {
        let database = TestDatabase::new();
        let mut ledger = EventLedger::open(&database.path).expect("open ledger");
        let pending = prepare_pending_task_integration(&mut ledger);
        let change_set = ledger
            .load_change_set(
                &pending.evidence.receipt.sprint_id,
                &pending.evidence.receipt.change_set_id,
            )
            .expect("load admitted integration change set");
        let request = TaskIntegrationRequest {
            contract_version: CONTRACT_VERSION,
            change_set,
            artifact: pending.evidence.artifact.clone(),
        };
        let request_bytes = encode("task integration request", &request)
            .expect("encode exact admitted integration request");
        let admitted = ledger
            .load_effect(&pending.evidence.receipt.effect_id)
            .expect("load pending admitted integration effect");
        let mut direct_intent = admitted.intent;
        direct_intent.effect_id = "direct-integration-without-kind".into();
        direct_intent.idempotency_key = "direct-integration-key".into();
        let direct_proposal = effect_proposal_event(
            &direct_intent,
            ledger.next_sequence("sprint-1").expect("direct sequence"),
            "direct-integration-proposed",
        );
        let effects_before = row_count(&ledger, "effect_intents");
        let finish_kinds_before = row_count(&ledger, "finish_effect_kinds");
        let transaction = ledger
            .connection
            .transaction()
            .expect("start intent bypass");
        insert_agent_event(&transaction, &direct_proposal).expect("insert proposal first");
        insert_effect_request_payload(&transaction, &direct_intent, &request_bytes)
            .expect("insert request first");
        assert!(
            insert_effect_intent(&transaction, &direct_intent, &direct_proposal.event_id).is_err(),
            "schema must reject an integration intent without its closed finish-kind and phase admission rows"
        );
        transaction.rollback().expect("rollback intent bypass");
        assert_eq!(row_count(&ledger, "effect_intents"), effects_before);
        assert_eq!(
            row_count(&ledger, "finish_effect_kinds"),
            finish_kinds_before
        );

        let evidence_bytes = encode("task integration evidence", &pending.evidence)
            .expect("encode pending typed integration evidence");
        let observations_before = row_count(&ledger, "effect_observations");
        let events_before_terminal = row_count(&ledger, "agent_events");
        assert!(matches!(
            ledger.record_effect_observation(
                &pending.observation,
                &evidence_bytes,
                &pending.terminal,
            ),
            Err(LedgerError::FinishReceiptRequired {
                effect_id,
                kind: EffectKind::IntegrateChangeSet,
            }) if effect_id == pending.evidence.receipt.effect_id
        ));
        assert!(
            ledger
                .load_effect(&pending.evidence.receipt.effect_id)
                .expect("load rejected integration")
                .observation
                .is_none()
        );

        let transaction = ledger.connection.transaction().expect("start SQL bypass");
        insert_agent_event(&transaction, &pending.terminal).expect("insert terminal event first");
        insert_effect_evidence_payload(&transaction, &pending.observation, &evidence_bytes)
            .expect("insert typed evidence first");
        assert!(
            insert_effect_observation(
                &transaction,
                &pending.observation,
                &pending.terminal.event_id,
            )
            .is_err(),
            "schema must reject a successful integration without its atomic typed receipt"
        );
        transaction.rollback().expect("rollback SQL bypass");
        assert_eq!(
            row_count(&ledger, "effect_observations"),
            observations_before
        );
        assert_eq!(row_count(&ledger, "task_integration_receipts"), 0);
        assert_eq!(row_count(&ledger, "agent_events"), events_before_terminal);
    }

    #[test]
    fn recovery_applier_validation_is_atomic_and_reopens_exactly() {
        let database = TestDatabase::new();
        let expected = {
            let (mut ledger, mut pending) =
                prepare_migrated_v16_pending_task_integration(&database);
            let recovery_policy = compiled_test_policy("integration-recovery-applier-policy");
            let recovery = register_integration_validator(
                &mut ledger,
                "launch-integration-recovery",
                "session-integration-recovery",
                RunnerSessionPurpose::Applier,
                &recovery_policy,
                pending.worker_launch.private_state_digest.clone(),
                1_440,
            );
            bind_recovery_validation(&mut pending, &recovery);
            refresh_pending_integration_digest(&ledger, &mut pending);
            let (disposition, transition_event) = pending_integration_disposition(&pending);
            integrate_pending_task_attempt(
                &mut ledger,
                &mut pending,
                &disposition,
                &transition_event,
            )
            .expect("persist recovery-validated integration");
            assert_eq!(
                ledger
                    .load_task_integration_evidence(&pending.evidence.receipt.receipt_id)
                    .expect("load recovery evidence before restart"),
                pending.evidence
            );
            assert_eq!(
                ledger
                    .load_task_attempt_disposition(disposition.metadata().disposition_id.as_str())
                    .expect("read exact recovery integration replay"),
                disposition
            );
            pending.evidence
        };

        let ledger = EventLedger::open_read_only(&database.path)
            .expect("reopen recovery integration read-only");
        let restored = ledger
            .load_task_integration_evidence(&expected.receipt.receipt_id)
            .expect("restore exact recovery validation evidence");
        assert_eq!(restored, expected);
        assert_eq!(
            restored.validation.mode,
            TaskIntegrationValidationMode::RecoveryApplierReconciliation
        );
        assert_ne!(
            restored.validation.runner_session_id,
            restored.receipt.worker_session_id
        );
    }

    #[test]
    #[allow(clippy::too_many_lines)] // Every authority dimension gets an isolated transaction.
    fn integration_validation_rejects_crossed_or_weakened_authority() {
        let unregistered = rejected_pending_integration(|_, pending| {
            pending.evidence.validation.mode =
                TaskIntegrationValidationMode::RecoveryApplierReconciliation;
            pending.evidence.validation.runner_launch_id = "launch-unregistered".into();
            pending.evidence.validation.runner_session_id = "session-unregistered".into();
        });
        assert!(matches!(
            unregistered,
            LedgerError::ArtifactNotFound {
                entity: "runner session policy",
                ..
            }
        ));

        let wrong_purpose = rejected_pending_integration(|ledger, pending| {
            let verifier_policy = compiled_test_policy("wrong-purpose-verifier-policy");
            let launch = register_integration_validator(
                ledger,
                "launch-wrong-purpose",
                "session-wrong-purpose",
                RunnerSessionPurpose::FinalVerifier,
                &verifier_policy,
                pending.worker_launch.private_state_digest.clone(),
                1_440,
            );
            bind_recovery_validation(pending, &launch);
        });
        assert!(matches!(
            wrong_purpose,
            LedgerError::ReferenceMismatch {
                entity: "task integration evidence",
                ..
            }
        ));

        let wrong_policy = rejected_pending_integration(|ledger, pending| {
            let other_policy = compiled_test_policy("wrong-recovery-policy");
            let launch = register_integration_validator(
                ledger,
                "launch-wrong-policy",
                "session-wrong-policy",
                RunnerSessionPurpose::Applier,
                &other_policy,
                pending.worker_launch.private_state_digest.clone(),
                1_440,
            );
            bind_recovery_validation(pending, &launch);
            pending.evidence.validation.policy_hash =
                pending.evidence.receipt.worker_policy_hash.clone();
        });
        assert!(matches!(
            wrong_policy,
            LedgerError::ReferenceMismatch {
                entity: "task integration evidence",
                ..
            }
        ));

        let wrong_grant = rejected_pending_integration(|ledger, pending| {
            let applier_policy = compiled_test_policy("wrong-grant-applier-policy");
            let launch = register_integration_validator(
                ledger,
                "launch-wrong-grant-claim",
                "session-wrong-grant-claim",
                RunnerSessionPurpose::Applier,
                &applier_policy,
                pending.worker_launch.private_state_digest.clone(),
                1_440,
            );
            bind_recovery_validation(pending, &launch);
            pending.evidence.validation.grant_hash = digest('9');
        });
        assert!(matches!(
            wrong_grant,
            LedgerError::ReferenceMismatch {
                entity: "task integration evidence",
                ..
            }
        ));

        let wrong_private_state = rejected_pending_integration(|ledger, pending| {
            let applier_policy = compiled_test_policy("wrong-private-applier-policy");
            let launch = register_integration_validator(
                ledger,
                "launch-wrong-private-state",
                "session-wrong-private-state",
                RunnerSessionPurpose::Applier,
                &applier_policy,
                digest('9'),
                1_440,
            );
            bind_recovery_validation(pending, &launch);
        });
        assert!(matches!(
            wrong_private_state,
            LedgerError::ReferenceMismatch {
                entity: "task integration evidence",
                ..
            }
        ));

        let crossed_runtime_identity = rejected_pending_integration(|ledger, pending| {
            let applier_policy = compiled_test_policy("crossed-runtime-applier-policy");
            let mut launch = runner_launch(
                "launch-crossed-runtime",
                "session-crossed-runtime",
                RunnerSessionPurpose::Applier,
                None,
                &applier_policy,
                1_420,
            );
            launch.private_state_digest = pending.worker_launch.private_state_digest.clone();
            launch.runner_binary_digest = digest('8');
            launch.protocol_digest = digest('9');
            admit_test_runner_launch(ledger, &launch, &applier_policy);
            ledger
                .register_runner_session(&runner_session(&launch, 1_440), &applier_policy)
                .expect("persist alternate runtime session");
            bind_recovery_validation(pending, &launch);
        });
        assert!(matches!(
            crossed_runtime_identity,
            LedgerError::ReferenceMismatch {
                entity: "task integration evidence",
                ..
            }
        ));

        let registered_later = rejected_pending_integration(|ledger, pending| {
            let applier_policy = compiled_test_policy("late-applier-policy");
            let launch = register_integration_validator(
                ledger,
                "launch-too-late",
                "session-too-late",
                RunnerSessionPurpose::Applier,
                &applier_policy,
                pending.worker_launch.private_state_digest.clone(),
                1_451,
            );
            bind_recovery_validation(pending, &launch);
        });
        assert!(matches!(
            registered_later,
            LedgerError::ReferenceMismatch {
                entity: "task integration evidence",
                ..
            }
        ));

        let crossed_lifecycle = rejected_pending_integration(|ledger, pending| {
            let applier_policy = compiled_test_policy("crossed-applier-policy");
            let first = register_integration_validator(
                ledger,
                "launch-crossed-first",
                "session-crossed-first",
                RunnerSessionPurpose::Applier,
                &applier_policy,
                pending.worker_launch.private_state_digest.clone(),
                1_440,
            );
            let second = register_integration_validator(
                ledger,
                "launch-crossed-second",
                "session-crossed-second",
                RunnerSessionPurpose::Applier,
                &applier_policy,
                pending.worker_launch.private_state_digest.clone(),
                1_441,
            );
            bind_recovery_validation(pending, &first);
            pending.evidence.validation.runner_session_id = second.session_id;
        });
        assert!(matches!(
            crossed_lifecycle,
            LedgerError::ReferenceMismatch {
                entity: "task integration evidence",
                ..
            }
        ));

        let wrong_sprint = rejected_pending_integration(|ledger, pending| {
            let (mut spec, mut graph) = sprint_fixture();
            spec.sprint_id = "sprint-2".into();
            spec.workspace_grant.grant_id = "grant-2".into();
            graph.graph_id = "graph-2".into();
            ledger
                .create_sprint(&spec, &graph, 1_000)
                .expect("persist unrelated sprint");
            let (base, _, _, _, _, _, _, _) = completion_artifacts();
            ledger
                .persist_workspace_snapshot(&spec.sprint_id, &base)
                .expect("persist unrelated sprint base snapshot");
            let applier_policy = compiled_test_policy("other-sprint-applier-policy");
            let mut launch = runner_launch(
                "launch-other-sprint",
                "session-other-sprint",
                RunnerSessionPurpose::Applier,
                None,
                &applier_policy,
                1_420,
            );
            launch.sprint_id = spec.sprint_id;
            launch.private_state_digest = pending.worker_launch.private_state_digest.clone();
            admit_test_runner_launch(ledger, &launch, &applier_policy);
            ledger
                .register_runner_session(&runner_session(&launch, 1_440), &applier_policy)
                .expect("persist other-sprint session");
            bind_recovery_validation(pending, &launch);
        });
        assert!(matches!(
            wrong_sprint,
            LedgerError::ArtifactNotFound {
                entity: "runner session policy",
                ..
            }
        ));

        let crossed_artifact = rejected_pending_integration(|_, pending| {
            pending.evidence.artifact.artifact_digest = digest('9');
        });
        assert!(matches!(
            crossed_artifact,
            LedgerError::ReferenceMismatch {
                entity: "task integration evidence",
                ..
            }
        ));
    }

    #[test]
    fn direct_application_evidence_is_atomic_and_reopens_exactly() {
        let database = TestDatabase::new();
        let expected = {
            let mut ledger = open_v21_test_ledger(&database);
            let pending = prepare_pending_application(&mut ledger);
            ledger
                .record_application_effect_observation_with_rollback(
                    &pending.observation,
                    &pending.terminal,
                    &pending.evidence,
                    &pending.rollback_reference,
                )
                .expect("persist direct application evidence");
            assert_eq!(
                ledger
                    .load_application_evidence(&pending.evidence.receipt.receipt_id)
                    .expect("load direct application evidence"),
                pending.evidence
            );
            assert!(matches!(
                ledger.record_application_effect_observation_with_rollback(
                    &pending.observation,
                    &pending.terminal,
                    &pending.evidence,
                    &pending.rollback_reference,
                ),
                Err(LedgerError::ArtifactAlreadyExists {
                    entity: "effect observation",
                    ..
                })
            ));
            pending.evidence
        };
        let ledger = EventLedger::open(&database.path)
            .expect("migrate direct historical application for readback");
        assert_eq!(
            ledger
                .load_application_evidence(&expected.receipt.receipt_id)
                .expect("restore direct application evidence"),
            expected
        );
    }

    #[test]
    fn application_request_artifact_authority_is_exact_immutable_and_restart_safe() {
        let database = TestDatabase::new();
        let (effect_id, expected_request) = {
            let mut ledger = open_v21_test_ledger(&database);
            let pending = prepare_pending_application(&mut ledger);
            let classification = ledger
                .load_application_request_artifact_authority(&pending.intent.effect_id)
                .expect("load exact application request authority");
            assert_eq!(
                classification,
                ApplicationRequestArtifactAuthority::ArtifactBound(Box::new(
                    pending.request.clone()
                ))
            );
            assert_eq!(classification.artifact(), Some(&pending.artifact));
            assert_eq!(
                Digest::sha256(&pending.request_bytes),
                pending.intent.request_digest
            );
            assert_eq!(
                ledger
                    .load_effect(&pending.intent.effect_id)
                    .expect("load artifact-bound effect")
                    .proposed_event,
                pending.proposal
            );
            assert_eq!(
                row_count(&ledger, "application_request_artifact_authorities"),
                1
            );
            assert_eq!(row_count(&ledger, "legacy_application_request_gaps"), 0);
            for statement in [
                "UPDATE application_request_artifact_authorities SET artifact_digest = artifact_digest",
                "DELETE FROM application_request_artifact_authorities",
            ] {
                assert!(
                    ledger.connection.execute_batch(statement).is_err(),
                    "application authority mutation unexpectedly succeeded: {statement}"
                );
            }
            (pending.intent.effect_id, pending.request)
        };
        let ledger = EventLedger::open(&database.path)
            .expect("migrate historical application authority for readback");
        assert_eq!(
            ledger
                .load_application_request_artifact_authority(&effect_id)
                .expect("reload exact application authority"),
            ApplicationRequestArtifactAuthority::ArtifactBound(Box::new(expected_request))
        );
    }

    #[test]
    #[allow(clippy::too_many_lines)] // Both public admission paths and all zero-write assertions share one setup.
    fn new_application_admission_rejects_bare_and_unbound_requests_without_writes() {
        let database = TestDatabase::new();
        let mut ledger = EventLedger::open(&database.path).expect("open application ledger");
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
        let policy = compiled_test_policy("unbound-application-policy");
        let launch = runner_launch(
            "launch-unbound-application",
            "session-unbound-application",
            RunnerSessionPurpose::Applier,
            None,
            &policy,
            1_210,
        );
        admit_test_runner_launch(&mut ledger, &launch, &policy);
        ledger
            .register_runner_session(&runner_session(&launch, 1_250), &policy)
            .expect("persist application session");
        let effects_before = row_count(&ledger, "effect_intents");

        let bare_bytes =
            encode("legacy bare application request", &change_set).expect("encode bare ChangeSet");
        let bare_intent = EffectIntent {
            contract_version: CONTRACT_VERSION,
            effect_id: "effect-bare-application-v12".into(),
            idempotency_key: "key-bare-application-v12".into(),
            sprint_id: spec.sprint_id.clone(),
            task_id: None,
            worker_id: None,
            worker_lease: None,
            causation_event_id: None,
            correlation_id: "correlation-bare-application-v12".into(),
            kind: EffectKind::ApplyChangeSet,
            request_digest: Digest::sha256(&bare_bytes),
            policy_hash: launch.policy_hash.clone(),
            input_snapshot: base.snapshot_id.clone(),
            created_at_unix_ms: 1_300,
        };
        let bare_proposal = effect_proposal_event(
            &bare_intent,
            ledger
                .next_sequence(&spec.sprint_id)
                .expect("next sequence"),
            "event-bare-application-v12",
        );
        let events_before = row_count(&ledger, "agent_events");
        assert!(matches!(
            ledger.record_runner_effect_intent(
                &bare_intent,
                &bare_bytes,
                &bare_proposal,
                &launch.session_id,
            ),
            Err(LedgerError::Json {
                entity: "application request",
                ..
            })
        ));
        assert_eq!(row_count(&ledger, "agent_events"), events_before);
        assert_eq!(row_count(&ledger, "effect_intents"), effects_before);
        assert_eq!(
            row_count(&ledger, "application_request_artifact_authorities"),
            0
        );
        assert_eq!(row_count(&ledger, "legacy_application_request_gaps"), 0);

        let artifact = test_application_artifact(&change_set, "unbound-v12");
        let typed_bytes = application_request_bytes(&ledger, &change_set, &artifact);
        let mut unbound_intent = bare_intent;
        unbound_intent.effect_id = "effect-unbound-application-v12".into();
        unbound_intent.idempotency_key = "key-unbound-application-v12".into();
        unbound_intent.correlation_id = "correlation-unbound-application-v12".into();
        unbound_intent.request_digest = Digest::sha256(&typed_bytes);
        let unbound_proposal = effect_proposal_event(
            &unbound_intent,
            ledger
                .next_sequence(&spec.sprint_id)
                .expect("next sequence"),
            "event-unbound-application-v12",
        );
        assert!(matches!(
            ledger.record_effect_intent(&unbound_intent, &typed_bytes, &unbound_proposal),
            Err(LedgerError::ReferenceMismatch {
                entity: "application request",
                ..
            })
        ));
        assert_eq!(row_count(&ledger, "agent_events"), events_before);
        assert_eq!(row_count(&ledger, "effect_intents"), effects_before);
        assert_eq!(
            row_count(&ledger, "application_request_artifact_authorities"),
            0
        );
    }

    #[test]
    fn application_schema_rejects_json_to_index_artifact_crossing_at_insert() {
        let database = TestDatabase::new();
        let mut ledger = open_v21_test_ledger(&database);
        let pending = prepare_pending_application(&mut ledger);
        let intent = EffectIntent {
            effect_id: "effect-direct-sql-crossed-application".into(),
            idempotency_key: "key-direct-sql-crossed-application".into(),
            correlation_id: "correlation-direct-sql-crossed-application".into(),
            created_at_unix_ms: 1_320,
            ..pending.intent.clone()
        };
        let proposal = effect_proposal_event(
            &intent,
            ledger
                .next_sequence(&intent.sprint_id)
                .expect("direct SQL proposal sequence"),
            "event-direct-sql-crossed-application",
        );
        let effects_before = row_count(&ledger, "effect_intents");
        let events_before = row_count(&ledger, "agent_events");
        let authorities_before = row_count(&ledger, "application_request_artifact_authorities");
        let transaction = ledger
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .expect("start direct SQL crossing transaction");
        insert_agent_event(&transaction, &proposal).expect("stage exact proposal");
        insert_effect_request_payload(&transaction, &intent, &pending.request_bytes)
            .expect("stage exact request payload");
        insert_finish_effect_kind(&transaction, &intent).expect("stage semantic effect kind");
        transaction
            .execute(
                "INSERT INTO application_request_artifact_authorities (
                    effect_id, sprint_id, request_digest, change_set_id,
                    base_snapshot, result_snapshot, artifact_format_version,
                    artifact_digest, contract_version, request_json
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
                params![
                    intent.effect_id,
                    intent.sprint_id,
                    intent.request_digest.as_str(),
                    pending.change_set.change_set_id,
                    pending.change_set.base_snapshot.as_str(),
                    pending.change_set.result_snapshot.as_str(),
                    i64::from(pending.artifact.format_version),
                    digest('f').as_str(),
                    i64::from(CONTRACT_VERSION),
                    &pending.request_bytes,
                ],
            )
            .expect("stage adversarial indexed artifact");
        let error = insert_effect_intent(&transaction, &intent, &proposal.event_id)
            .expect_err("JSON/index crossing must reject the effect insert");
        assert!(
            error
                .to_string()
                .contains("ApplyChangeSet requires exact artifact-bound request authority")
        );
        transaction.rollback().expect("rollback rejected crossing");
        assert_eq!(row_count(&ledger, "effect_intents"), effects_before);
        assert_eq!(row_count(&ledger, "agent_events"), events_before);
        assert_eq!(
            row_count(&ledger, "application_request_artifact_authorities"),
            authorities_before
        );
    }

    #[test]
    fn application_authority_readback_rejects_both_and_neither_classifications() {
        let database = TestDatabase::new();
        let mut ledger = open_v21_test_ledger(&database);
        let pending = prepare_pending_application(&mut ledger);
        ledger
            .connection
            .execute_batch("DROP TRIGGER legacy_application_request_gaps_no_insert;")
            .expect("isolate coexistence invariant");
        ledger
            .connection
            .execute(
                "INSERT INTO legacy_application_request_gaps (
                    effect_id, sprint_id, request_digest, request_kind,
                    contract_version
                 ) VALUES (?1, ?2, ?3, 'PreV12Unbound', ?4)",
                params![
                    pending.intent.effect_id,
                    pending.intent.sprint_id,
                    pending.intent.request_digest.as_str(),
                    i64::from(CONTRACT_VERSION),
                ],
            )
            .expect("simulate crossed legacy marker");
        assert!(matches!(
            ledger.load_application_request_artifact_authority(&pending.intent.effect_id),
            Err(LedgerError::Corrupt {
                entity: "application request artifact authority",
                ..
            })
        ));
        ledger
            .connection
            .execute_batch(
                "DROP TRIGGER legacy_application_request_gaps_no_delete;
                 DELETE FROM legacy_application_request_gaps;",
            )
            .expect("remove simulated coexistence marker");
        ledger
            .load_application_request_artifact_authority(&pending.intent.effect_id)
            .expect("single typed classification is readable");
        ledger
            .connection
            .execute_batch(
                "DROP TRIGGER application_request_artifact_authorities_no_delete;
                 DELETE FROM application_request_artifact_authorities;",
            )
            .expect("simulate missing application authority");
        assert!(matches!(
            ledger.load_application_request_artifact_authority(&pending.intent.effect_id),
            Err(LedgerError::Corrupt {
                entity: "application request artifact authority",
                ..
            })
        ));
    }

    #[test]
    fn recovery_application_evidence_preserves_executor_and_reopens_exactly() {
        let database = TestDatabase::new();
        let expected = {
            let mut ledger = open_v21_test_ledger(&database);
            let mut pending = prepare_pending_application(&mut ledger);
            let recovery = register_validation_runner(
                &mut ledger,
                &pending.executor_launch,
                "launch-application-recovery",
                "session-application-recovery",
                RunnerSessionPurpose::Applier,
                &pending.applier_policy,
                pending.executor_launch.private_state_digest.clone(),
                1_350,
                1_400,
            );
            bind_application_recovery(&mut pending, &recovery);
            refresh_pending_application_digest(&ledger, &mut pending);
            ledger
                .record_application_effect_observation_with_rollback(
                    &pending.observation,
                    &pending.terminal,
                    &pending.evidence,
                    &pending.rollback_reference,
                )
                .expect("persist recovery application evidence");
            assert_eq!(
                pending.evidence.receipt.applier_session_id,
                pending.executor_launch.session_id
            );
            assert_ne!(
                pending.evidence.validation.runner_session_id,
                pending.evidence.receipt.applier_session_id
            );
            pending.evidence
        };
        let ledger = EventLedger::open(&database.path)
            .expect("migrate recovery historical application for readback");
        assert_eq!(
            ledger
                .load_application_evidence(&expected.receipt.receipt_id)
                .expect("restore recovery application evidence"),
            expected
        );
    }

    #[test]
    fn direct_rollback_evidence_is_atomic_and_reopens_exactly() {
        let database = TestDatabase::new();
        let expected = {
            let mut ledger = open_v21_test_ledger(&database);
            let pending = prepare_pending_rollback(&mut ledger);
            ledger
                .record_rollback_effect_observation(
                    &pending.observation,
                    &pending.terminal,
                    &pending.evidence,
                )
                .expect("persist direct rollback evidence");
            assert_eq!(
                ledger
                    .load_rollback_evidence(&pending.evidence.receipt.receipt_id)
                    .expect("load direct rollback evidence"),
                pending.evidence
            );
            pending.evidence
        };
        let ledger = EventLedger::open(&database.path)
            .expect("migrate direct historical rollback for readback");
        assert_eq!(
            ledger
                .load_rollback_evidence(&expected.receipt.receipt_id)
                .expect("restore direct rollback evidence"),
            expected
        );
    }

    #[test]
    fn recovery_rollback_evidence_preserves_executor_and_reopens_exactly() {
        let database = TestDatabase::new();
        let expected = {
            let mut ledger = open_v21_test_ledger(&database);
            let mut pending = prepare_pending_rollback(&mut ledger);
            let recovery = register_validation_runner(
                &mut ledger,
                &pending.executor_launch,
                "launch-rollback-recovery",
                "session-rollback-recovery",
                RunnerSessionPurpose::Applier,
                &pending.applier_policy,
                pending.executor_launch.private_state_digest.clone(),
                1_520,
                1_550,
            );
            bind_rollback_recovery(&mut pending, &recovery);
            refresh_pending_rollback_digest(&ledger, &mut pending);
            ledger
                .record_rollback_effect_observation(
                    &pending.observation,
                    &pending.terminal,
                    &pending.evidence,
                )
                .expect("persist recovery rollback evidence");
            assert_ne!(
                pending.evidence.validation.runner_session_id,
                pending.executor_launch.session_id
            );
            pending.evidence
        };
        let ledger = EventLedger::open(&database.path)
            .expect("migrate recovery historical rollback for readback");
        assert_eq!(
            ledger
                .load_rollback_evidence(&expected.receipt.receipt_id)
                .expect("restore recovery rollback evidence"),
            expected
        );
    }

    #[test]
    #[allow(clippy::too_many_lines)] // Every recovery authority dimension gets an isolated ledger.
    fn application_recovery_rejects_crossed_or_weakened_provenance() {
        let unregistered = rejected_pending_application(|_, pending| {
            pending.evidence.validation.mode =
                ApplicationValidationMode::RecoveryApplierReconciliation;
            pending.evidence.validation.runner_launch_id = "launch-unregistered-application".into();
            pending.evidence.validation.runner_session_id =
                "session-unregistered-application".into();
        });
        assert!(matches!(
            unregistered,
            LedgerError::ArtifactNotFound {
                entity: "runner session policy",
                ..
            }
        ));

        let crossed = rejected_pending_application(|ledger, pending| {
            let first =
                matching_application_recovery(ledger, pending, "crossed-first", 1_350, 1_390);
            let second =
                matching_application_recovery(ledger, pending, "crossed-second", 1_351, 1_391);
            bind_application_recovery(pending, &first);
            pending.evidence.validation.runner_session_id = second.session_id;
        });
        assert!(matches!(
            crossed,
            LedgerError::ReferenceMismatch {
                entity: "application evidence",
                ..
            }
        ));

        let same_session = rejected_pending_application(|_, pending| {
            pending.evidence.validation.mode =
                ApplicationValidationMode::RecoveryApplierReconciliation;
        });
        assert!(matches!(
            same_session,
            LedgerError::Contract(error)
                if error.field() == "application_evidence.validation"
        ));

        let wrong_purpose = rejected_pending_application(|ledger, pending| {
            let launch = register_validation_runner(
                ledger,
                &pending.executor_launch,
                "launch-application-wrong-purpose",
                "session-application-wrong-purpose",
                RunnerSessionPurpose::FinalVerifier,
                &pending.applier_policy,
                pending.executor_launch.private_state_digest.clone(),
                1_350,
                1_400,
            );
            bind_application_recovery(pending, &launch);
        });
        assert!(matches!(
            wrong_purpose,
            LedgerError::ReferenceMismatch {
                entity: "application evidence",
                ..
            }
        ));

        let wrong_sprint = rejected_pending_application(|ledger, pending| {
            let launch = register_other_sprint_validator(
                ledger,
                &pending.executor_launch,
                &pending.applier_policy,
                "application-other",
                1_350,
                1_400,
            );
            bind_application_recovery(pending, &launch);
        });
        assert!(matches!(
            wrong_sprint,
            LedgerError::ArtifactNotFound {
                entity: "runner session policy",
                ..
            }
        ));

        let wrong_policy = rejected_pending_application(|ledger, pending| {
            let policy = compiled_test_policy("application-wrong-policy");
            let launch = register_validation_runner(
                ledger,
                &pending.executor_launch,
                "launch-application-wrong-policy",
                "session-application-wrong-policy",
                RunnerSessionPurpose::Applier,
                &policy,
                pending.executor_launch.private_state_digest.clone(),
                1_350,
                1_400,
            );
            bind_application_recovery(pending, &launch);
            pending.evidence.validation.policy_hash = pending.evidence.receipt.policy_hash.clone();
        });
        assert!(matches!(
            wrong_policy,
            LedgerError::ReferenceMismatch {
                entity: "application evidence",
                ..
            }
        ));

        let wrong_grant = rejected_pending_application(|ledger, pending| {
            let launch =
                matching_application_recovery(ledger, pending, "wrong-grant", 1_350, 1_400);
            bind_application_recovery(pending, &launch);
            pending.evidence.validation.grant_hash = digest('9');
        });
        assert!(matches!(
            wrong_grant,
            LedgerError::Contract(error)
                if error.field() == "application_evidence.validation"
        ));

        let wrong_policy_version = rejected_pending_application(|ledger, pending| {
            let launch =
                matching_application_recovery(ledger, pending, "wrong-version", 1_350, 1_400);
            bind_application_recovery(pending, &launch);
            pending.evidence.validation.policy_version += 1;
        });
        assert!(matches!(
            wrong_policy_version,
            LedgerError::Contract(error)
                if error.field() == "application_evidence.validation"
        ));

        let wrong_private_state = rejected_pending_application(|ledger, pending| {
            let launch = register_validation_runner(
                ledger,
                &pending.executor_launch,
                "launch-application-wrong-private",
                "session-application-wrong-private",
                RunnerSessionPurpose::Applier,
                &pending.applier_policy,
                digest('9'),
                1_350,
                1_400,
            );
            bind_application_recovery(pending, &launch);
        });
        assert!(matches!(
            wrong_private_state,
            LedgerError::ReferenceMismatch {
                entity: "application evidence",
                ..
            }
        ));

        let wrong_runtime = rejected_pending_application(|ledger, pending| {
            let mut launch = runner_launch(
                "launch-application-wrong-runtime",
                "session-application-wrong-runtime",
                RunnerSessionPurpose::Applier,
                None,
                &pending.applier_policy,
                1_350,
            );
            launch.private_state_digest = pending.executor_launch.private_state_digest.clone();
            launch.runner_binary_digest = digest('8');
            launch.protocol_digest = digest('9');
            admit_test_runner_launch(ledger, &launch, &pending.applier_policy);
            ledger
                .register_runner_session(&runner_session(&launch, 1_400), &pending.applier_policy)
                .expect("persist alternate application runtime session");
            bind_application_recovery(pending, &launch);
        });
        assert!(matches!(
            wrong_runtime,
            LedgerError::ReferenceMismatch {
                entity: "application evidence",
                ..
            }
        ));

        let late = rejected_pending_application(|ledger, pending| {
            let launch = matching_application_recovery(ledger, pending, "late", 1_350, 1_451);
            bind_application_recovery(pending, &launch);
        });
        assert!(matches!(
            late,
            LedgerError::ReferenceMismatch {
                entity: "application evidence",
                ..
            }
        ));

        let pre_intent_launch = rejected_pending_application(|ledger, pending| {
            let launch = matching_application_recovery(ledger, pending, "pre-intent", 1_290, 1_400);
            bind_application_recovery(pending, &launch);
        });
        assert!(matches!(
            pre_intent_launch,
            LedgerError::ReferenceMismatch {
                entity: "application evidence",
                ..
            }
        ));
    }

    #[test]
    #[allow(clippy::too_many_lines)] // Every recovery authority dimension gets an isolated ledger.
    fn rollback_recovery_rejects_crossed_or_weakened_provenance() {
        let unregistered = rejected_pending_rollback(|_, pending| {
            pending.evidence.validation.mode =
                RollbackValidationMode::RecoveryApplierReconciliation;
            pending.evidence.validation.runner_launch_id = "launch-unregistered-rollback".into();
            pending.evidence.validation.runner_session_id = "session-unregistered-rollback".into();
        });
        assert!(matches!(
            unregistered,
            LedgerError::ArtifactNotFound {
                entity: "runner session policy",
                ..
            }
        ));

        let crossed = rejected_pending_rollback(|ledger, pending| {
            let first = matching_rollback_recovery(ledger, pending, "crossed-first", 1_520, 1_550);
            let second =
                matching_rollback_recovery(ledger, pending, "crossed-second", 1_521, 1_551);
            bind_rollback_recovery(pending, &first);
            pending.evidence.validation.runner_session_id = second.session_id;
        });
        assert!(matches!(
            crossed,
            LedgerError::ReferenceMismatch {
                entity: "rollback evidence",
                ..
            }
        ));

        let same_session = rejected_pending_rollback(|_, pending| {
            pending.evidence.validation.mode =
                RollbackValidationMode::RecoveryApplierReconciliation;
        });
        assert!(matches!(
            same_session,
            LedgerError::ReferenceMismatch {
                entity: "rollback evidence",
                ..
            }
        ));

        let wrong_purpose = rejected_pending_rollback(|ledger, pending| {
            let launch = register_validation_runner(
                ledger,
                &pending.executor_launch,
                "launch-rollback-wrong-purpose",
                "session-rollback-wrong-purpose",
                RunnerSessionPurpose::FinalVerifier,
                &pending.applier_policy,
                pending.executor_launch.private_state_digest.clone(),
                1_520,
                1_550,
            );
            bind_rollback_recovery(pending, &launch);
        });
        assert!(matches!(
            wrong_purpose,
            LedgerError::ReferenceMismatch {
                entity: "rollback evidence",
                ..
            }
        ));

        let wrong_sprint = rejected_pending_rollback(|ledger, pending| {
            let launch = register_other_sprint_validator(
                ledger,
                &pending.executor_launch,
                &pending.applier_policy,
                "rollback-other",
                1_520,
                1_550,
            );
            bind_rollback_recovery(pending, &launch);
        });
        assert!(matches!(
            wrong_sprint,
            LedgerError::ArtifactNotFound {
                entity: "runner session policy",
                ..
            }
        ));

        let wrong_policy = rejected_pending_rollback(|ledger, pending| {
            let policy = compiled_test_policy("rollback-wrong-policy");
            let launch = register_validation_runner(
                ledger,
                &pending.executor_launch,
                "launch-rollback-wrong-policy",
                "session-rollback-wrong-policy",
                RunnerSessionPurpose::Applier,
                &policy,
                pending.executor_launch.private_state_digest.clone(),
                1_520,
                1_550,
            );
            bind_rollback_recovery(pending, &launch);
        });
        assert!(matches!(
            wrong_policy,
            LedgerError::ReferenceMismatch {
                entity: "rollback evidence",
                ..
            }
        ));

        let wrong_grant = rejected_pending_rollback(|ledger, pending| {
            let launch = matching_rollback_recovery(ledger, pending, "wrong-grant", 1_520, 1_550);
            bind_rollback_recovery(pending, &launch);
            pending.evidence.validation.grant_hash = digest('9');
        });
        assert!(matches!(
            wrong_grant,
            LedgerError::ReferenceMismatch {
                entity: "rollback evidence",
                ..
            }
        ));

        let wrong_policy_version = rejected_pending_rollback(|ledger, pending| {
            let launch = matching_rollback_recovery(ledger, pending, "wrong-version", 1_520, 1_550);
            bind_rollback_recovery(pending, &launch);
            pending.evidence.validation.policy_version += 1;
        });
        assert!(matches!(
            wrong_policy_version,
            LedgerError::ReferenceMismatch {
                entity: "rollback evidence",
                ..
            }
        ));

        let wrong_private_state = rejected_pending_rollback(|ledger, pending| {
            let launch = register_validation_runner(
                ledger,
                &pending.executor_launch,
                "launch-rollback-wrong-private",
                "session-rollback-wrong-private",
                RunnerSessionPurpose::Applier,
                &pending.applier_policy,
                digest('9'),
                1_520,
                1_550,
            );
            bind_rollback_recovery(pending, &launch);
        });
        assert!(matches!(
            wrong_private_state,
            LedgerError::ReferenceMismatch {
                entity: "rollback evidence",
                ..
            }
        ));

        let wrong_runtime = rejected_pending_rollback(|ledger, pending| {
            let mut launch = runner_launch(
                "launch-rollback-wrong-runtime",
                "session-rollback-wrong-runtime",
                RunnerSessionPurpose::Applier,
                None,
                &pending.applier_policy,
                1_520,
            );
            launch.private_state_digest = pending.executor_launch.private_state_digest.clone();
            launch.runner_binary_digest = digest('8');
            launch.protocol_digest = digest('9');
            admit_test_runner_launch(ledger, &launch, &pending.applier_policy);
            ledger
                .register_runner_session(&runner_session(&launch, 1_550), &pending.applier_policy)
                .expect("persist alternate rollback runtime session");
            bind_rollback_recovery(pending, &launch);
        });
        assert!(matches!(
            wrong_runtime,
            LedgerError::ReferenceMismatch {
                entity: "rollback evidence",
                ..
            }
        ));

        let late = rejected_pending_rollback(|ledger, pending| {
            let launch = matching_rollback_recovery(ledger, pending, "late", 1_520, 1_601);
            bind_rollback_recovery(pending, &launch);
        });
        assert!(matches!(
            late,
            LedgerError::ReferenceMismatch {
                entity: "rollback evidence",
                ..
            }
        ));

        let pre_intent_launch = rejected_pending_rollback(|ledger, pending| {
            let launch = matching_rollback_recovery(ledger, pending, "pre-intent", 1_490, 1_550);
            bind_rollback_recovery(pending, &launch);
        });
        assert!(matches!(
            pre_intent_launch,
            LedgerError::ReferenceMismatch {
                entity: "rollback evidence",
                ..
            }
        ));
    }

    #[test]
    fn verification_output_corruption_cannot_authorize_completion() {
        let database = TestDatabase::new();
        let mut ledger = open_v21_test_ledger(&database);
        let (report, receipt, event) = prepare_completion_evidence(&mut ledger);
        ledger
            .connection
            .execute_batch(
                "DROP TRIGGER verification_effect_evidence_no_update;
                 UPDATE verification_effect_evidence
                 SET output_evidence_bytes = X'00'
                 WHERE verification_receipt_id = 'verify-final';",
            )
            .expect("inject retained-output corruption");
        assert!(matches!(
            ledger.load_verification_effect_evidence("verify-final"),
            Err(LedgerError::Corrupt {
                entity: "verification effect evidence",
                ..
            })
        ));
        assert!(matches!(
            ledger.record_successful_completion(&report, &receipt, &event),
            Err(LedgerError::Corrupt {
                entity: "verification effect evidence",
                ..
            })
        ));
        assert_no_completion_writes(&ledger);
    }

    fn prepare_human_acceptance_prompt_fixture() -> (V15CandidateFixture, HumanAcceptancePromptV1) {
        let mut fixture = prepare_v15_candidate_fixture(false);
        let (_, _, disposition) =
            integrate_v15_candidate(&mut fixture, "human-acceptance-v28", false);
        let task_cleanup = cleanup_terminal_record(
            &fixture.ledger,
            &fixture.launch,
            "cleanup-human-acceptance-v28-task",
            1_450,
        );
        fixture
            .ledger
            .with_integrated_task_attempt_cleanup_exclusion(
                &disposition.metadata().disposition_id,
                |_| Ok(task_cleanup),
            )
            .expect("close human-acceptance TaskDone worker");
        assert!(
            fixture
                .ledger
                .assess_task_done(&fixture.spec.sprint_id, "task-1")
                .expect("assess human-acceptance TaskDone")
                .is_done()
        );
        let awaiting = AgentEvent {
            contract_version: CONTRACT_VERSION,
            sequence: fixture
                .ledger
                .next_sequence(&fixture.spec.sprint_id)
                .expect("human acceptance phase sequence"),
            event_id: "event-human-acceptance-v28-awaiting".into(),
            sprint_id: fixture.spec.sprint_id.clone(),
            task_id: None,
            worker_id: None,
            causation_id: None,
            correlation_id: "correlation-human-acceptance-v28".into(),
            policy_hash: None,
            occurred_at_unix_ms: 1_500,
            payload: AgentEventKind::SprintStateChanged {
                from: "Running".into(),
                to: "AwaitingAcceptance".into(),
            },
        };
        fixture
            .ledger
            .append_event(&awaiting)
            .expect("enter AwaitingAcceptance for one human criterion");
        let prompt = fixture
            .ledger
            .issue_human_acceptance_prompt_v1(
                "prompt-human-acceptance-v28",
                "ui-session-human-acceptance-v28",
                &fixture.spec.sprint_id,
                "tests",
                Digest::sha256(b"rendered one-to-one claim"),
            )
            .expect("mint exact one-to-one human prompt");
        (fixture, prompt)
    }

    fn build_awaiting_acceptance_final_verification_fixture(
        fixture: &mut V15CandidateFixture,
    ) -> V21FinalVerificationFixture {
        let final_snapshot = fixture.result_snapshot.snapshot_id.clone();
        let mut final_fixture =
            build_v21_final_verification_fixture(&mut fixture.ledger, final_snapshot);
        let AgentEventKind::SprintStateChanged { from, to } =
            &mut final_fixture.phase_event.payload
        else {
            unreachable!("final-verification fixture carries a sprint phase event");
        };
        *from = "AwaitingAcceptance".into();
        assert_eq!(to, "FinalVerification");
        final_fixture
    }

    #[test]
    fn legacy_human_acceptance_is_diagnostic_only_in_schema_v28() {
        let database = TestDatabase::new();
        let mut ledger = EventLedger::open(&database.path).expect("open ledger");
        let (mut spec, graph) = sprint_fixture();
        spec.acceptance_criteria[0].kind = AcceptanceKind::HumanJudgment;
        ledger
            .create_sprint(&spec, &graph, 1_000)
            .expect("persist human-judgment sprint");
        let (_, final_snapshot, _, _, _, _, _, _) = completion_artifacts();
        ledger
            .persist_workspace_snapshot("sprint-1", &final_snapshot)
            .expect("persist decision snapshot");
        let mut acceptance = AcceptanceReceipt {
            receipt_id: "acceptance-human".into(),
            sprint_id: "sprint-1".into(),
            criterion_id: "tests".into(),
            snapshot_id: final_snapshot.snapshot_id,
            evidence: AcceptanceEvidence::HumanJudgment {
                decision_id: "decision-1".into(),
                accepted: false,
            },
            accepted_at_unix_ms: 1_500,
        };
        assert_eq!(
            acceptance
                .validate()
                .expect_err("rejection is not an acceptance receipt")
                .field(),
            "acceptance_receipt.accepted"
        );

        acceptance.evidence = AcceptanceEvidence::HumanJudgment {
            decision_id: "decision-1".into(),
            accepted: true,
        };
        assert!(matches!(
            ledger.persist_acceptance_receipt(&acceptance),
            Err(LedgerError::Sql(_))
        ));
        assert_eq!(row_count(&ledger, "acceptance_receipts"), 0);
    }

    #[test]
    #[allow(clippy::too_many_lines)] // One test keeps issuance, consumption, replay, and restart on the same evidence chain.
    fn human_acceptance_v28_is_one_to_one_atomic_restart_safe_and_replay_fenced() {
        let (mut fixture, prompt) = prepare_human_acceptance_prompt_fixture();
        assert_eq!(
            prompt.criterion_text_digest,
            Digest::sha256(fixture.spec.acceptance_criteria[0].description.as_bytes())
        );
        assert_eq!(prompt.snapshot_digest, fixture.result_snapshot.snapshot_id);
        assert_eq!(
            prompt.workspace_grant_hash,
            fixture.spec.workspace_grant.grant_hash
        );
        assert_eq!(prompt.backing, HumanAcceptanceBackingV1::OneToOne);
        assert!(matches!(
            fixture.ledger.consume_human_acceptance_prompt_v1(
                &prompt.prompt_id,
                "crossed-ui-session",
                "criterion-evidence-human-v28",
                HumanAcceptanceDecisionOutcomeV1::AcceptedByYou,
                1_510,
            ),
            Err(LedgerError::ReferenceMismatch {
                entity: "human acceptance decision",
                ..
            })
        ));
        assert_eq!(
            row_count(&fixture.ledger, "human_acceptance_decisions_v1"),
            0
        );
        assert!(
            fixture
                .ledger
                .consume_human_acceptance_prompt_v1(
                    &prompt.prompt_id,
                    &prompt.ui_session_id,
                    "",
                    HumanAcceptanceDecisionOutcomeV1::AcceptedByYou,
                    1_510,
                )
                .is_err(),
            "a blank evidence identity must roll back prompt consumption"
        );
        assert_eq!(
            row_count(&fixture.ledger, "human_acceptance_decisions_v1"),
            0
        );
        let accepted = fixture
            .ledger
            .consume_human_acceptance_prompt_v1(
                &prompt.prompt_id,
                &prompt.ui_session_id,
                "criterion-evidence-human-v28",
                HumanAcceptanceDecisionOutcomeV1::AcceptedByYou,
                1_510,
            )
            .expect("atomically accept one exact prompt");
        assert_eq!(
            accepted.decision.outcome,
            HumanAcceptanceDecisionOutcomeV1::AcceptedByYou
        );
        let evidence = accepted
            .criterion_evidence
            .expect("accepted-by-you creates exact criterion evidence");
        assert!(matches!(
            &evidence,
            CriterionEvidenceReceiptV2::AcceptedByYou {
                prompt_id,
                human_decision_id,
                backing: HumanAcceptanceBackingV1::OneToOne,
                ..
            } if prompt_id == &prompt.prompt_id
                && human_decision_id == &accepted.decision.decision_id
        ));
        assert!(matches!(
            fixture.ledger.consume_human_acceptance_prompt_v1(
                &prompt.prompt_id,
                &prompt.ui_session_id,
                "criterion-evidence-human-replay-v28",
                HumanAcceptanceDecisionOutcomeV1::AcceptedByYou,
                1_511,
            ),
            Err(LedgerError::ArtifactAlreadyExists { .. })
        ));

        let path = fixture.database.path.clone();
        let expected_decision = accepted.decision;
        drop(fixture.ledger);
        let mut reopened = EventLedger::open(&path).expect("reopen v28 human acceptance ledger");
        assert_eq!(
            reopened
                .load_human_acceptance_prompt_v1(&prompt.prompt_id)
                .expect("restart-read prompt"),
            prompt
        );
        assert_eq!(
            load_human_acceptance_decision_v1_from(
                &reopened.connection,
                &expected_decision.decision_id,
            )
            .expect("restart-read decision"),
            expected_decision
        );
        assert_eq!(
            reopened
                .load_criterion_evidence_receipt_v2(evidence.receipt_id())
                .expect("restart-read accepted criterion evidence"),
            evidence
        );
        assert!(
            reopened
                .consume_human_acceptance_prompt_v1(
                    &prompt.prompt_id,
                    &prompt.ui_session_id,
                    "criterion-evidence-human-restart-replay-v28",
                    HumanAcceptanceDecisionOutcomeV1::AcceptedByYou,
                    1_512,
                )
                .is_err()
        );
    }

    #[test]
    fn human_acceptance_v28_rederives_decision_identity_in_sql_and_readback() {
        let (mut fixture, prompt) = prepare_human_acceptance_prompt_fixture();
        let forged = HumanAcceptanceDecisionV1 {
            decision_id: "caller-manufactured-decision-v28".into(),
            prompt_id: prompt.prompt_id.clone(),
            outcome: HumanAcceptanceDecisionOutcomeV1::AcceptedByYou,
            consumed_event_sequence: prompt.issued_event_sequence,
            decided_at: 1_510,
        };
        forged
            .validate()
            .expect("forged local envelope is canonical");
        let forged_bytes = encode("forged human decision", &forged)
            .expect("encode canonical caller-manufactured decision");
        let error = fixture
            .ledger
            .connection
            .execute(
                "INSERT INTO human_acceptance_decisions_v1 (
                    decision_id, prompt_id, sprint_id, outcome,
                    consumed_event_sequence, decided_at_unix_ms, decision_json
                 ) VALUES (?1, ?2, ?3, 'AcceptedByYou', ?4, ?5, ?6)",
                params![
                    forged.decision_id,
                    forged.prompt_id,
                    prompt.sprint_id,
                    sqlite_integer(
                        "forged decision event sequence",
                        forged.consumed_event_sequence,
                    )
                    .expect("forged decision sequence fits SQLite"),
                    sqlite_integer("forged decision time", forged.decided_at)
                        .expect("forged decision time fits SQLite"),
                    forged_bytes,
                ],
            )
            .expect_err("SQL must reject a canonical but non-derived decision identity");
        assert!(
            error
                .to_string()
                .contains("exact unchanged prompt event cut")
        );
        assert_eq!(
            row_count(&fixture.ledger, "human_acceptance_decisions_v1"),
            0
        );

        let transaction = fixture
            .ledger
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .expect("start rollback-only forged decision readback probe");
        transaction
            .execute_batch("DROP TRIGGER human_acceptance_decisions_v1_prompt_match;")
            .expect("isolate Rust readback from the SQL identity guard");
        transaction
            .execute(
                "INSERT INTO human_acceptance_decisions_v1 (
                    decision_id, prompt_id, sprint_id, outcome,
                    consumed_event_sequence, decided_at_unix_ms, decision_json
                 ) VALUES (?1, ?2, ?3, 'AcceptedByYou', ?4, ?5, ?6)",
                params![
                    forged.decision_id,
                    forged.prompt_id,
                    prompt.sprint_id,
                    sqlite_integer(
                        "forged readback event sequence",
                        forged.consumed_event_sequence,
                    )
                    .expect("forged readback sequence fits SQLite"),
                    sqlite_integer("forged readback time", forged.decided_at)
                        .expect("forged readback time fits SQLite"),
                    encode("forged readback decision", &forged)
                        .expect("encode forged readback decision"),
                ],
            )
            .expect("inject forged identity only inside rollback transaction");
        assert!(matches!(
            load_human_acceptance_decision_v1_from(&transaction, &forged.decision_id),
            Err(LedgerError::ReferenceMismatch {
                entity: "human acceptance decision",
                ..
            })
        ));
        drop(transaction);
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "one negative chain proves rejection and stale prompt behavior at both SQL and product API boundaries"
    )]
    fn rejected_and_stale_human_prompts_never_create_success_evidence() {
        let (mut rejected_fixture, rejected_prompt) = prepare_human_acceptance_prompt_fixture();
        assert!(
            rejected_fixture
                .ledger
                .consume_human_acceptance_prompt_v1(
                    &rejected_prompt.prompt_id,
                    &rejected_prompt.ui_session_id,
                    "must-not-be-reserved",
                    HumanAcceptanceDecisionOutcomeV1::RejectedByYou,
                    1_510,
                )
                .is_err(),
            "rejection cannot reserve a successful evidence identity"
        );
        let rejected = rejected_fixture
            .ledger
            .consume_human_acceptance_prompt_v1(
                &rejected_prompt.prompt_id,
                &rejected_prompt.ui_session_id,
                "",
                HumanAcceptanceDecisionOutcomeV1::RejectedByYou,
                1_510,
            )
            .expect("persist exact rejected-by-you decision");
        assert_eq!(
            rejected.decision.outcome,
            HumanAcceptanceDecisionOutcomeV1::RejectedByYou
        );
        assert!(rejected.criterion_evidence.is_none());
        assert_eq!(
            row_count(&rejected_fixture.ledger, "criterion_evidence_receipts_v2"),
            0
        );

        let (mut stale_fixture, stale_prompt) = prepare_human_acceptance_prompt_fixture();
        let leave_acceptance = AgentEvent {
            contract_version: CONTRACT_VERSION,
            sequence: stale_fixture
                .ledger
                .next_sequence(&stale_fixture.spec.sprint_id)
                .expect("stale prompt phase sequence"),
            event_id: "event-human-acceptance-v28-stale".into(),
            sprint_id: stale_fixture.spec.sprint_id.clone(),
            task_id: None,
            worker_id: None,
            causation_id: None,
            correlation_id: "correlation-human-acceptance-v28".into(),
            policy_hash: None,
            occurred_at_unix_ms: 1_505,
            payload: AgentEventKind::SprintStateChanged {
                from: "AwaitingAcceptance".into(),
                to: "Running".into(),
            },
        };
        stale_fixture
            .ledger
            .append_event(&leave_acceptance)
            .expect("change the prompt phase and event cut");
        let stale_decision = HumanAcceptanceDecisionV1 {
            decision_id: human_acceptance_decision_id(
                &stale_prompt,
                HumanAcceptanceDecisionOutcomeV1::AcceptedByYou,
                stale_prompt.issued_event_sequence,
                1_510,
            )
            .expect("derive otherwise-valid stale decision identity"),
            prompt_id: stale_prompt.prompt_id.clone(),
            outcome: HumanAcceptanceDecisionOutcomeV1::AcceptedByYou,
            consumed_event_sequence: stale_prompt.issued_event_sequence,
            decided_at: 1_510,
        };
        let error = stale_fixture
            .ledger
            .connection
            .execute(
                "INSERT INTO human_acceptance_decisions_v1 (
                    decision_id, prompt_id, sprint_id, outcome,
                    consumed_event_sequence, decided_at_unix_ms, decision_json
                 ) VALUES (?1, ?2, ?3, 'AcceptedByYou', ?4, ?5, ?6)",
                params![
                    stale_decision.decision_id,
                    stale_decision.prompt_id,
                    stale_prompt.sprint_id,
                    sqlite_integer(
                        "stale decision event sequence",
                        stale_decision.consumed_event_sequence,
                    )
                    .expect("stale decision sequence fits SQLite"),
                    sqlite_integer("stale decision time", stale_decision.decided_at)
                        .expect("stale decision time fits SQLite"),
                    encode("stale human acceptance decision", &stale_decision)
                        .expect("encode stale decision"),
                ],
            )
            .expect_err("SQL must reject a derived decision after the prompt event cut changes");
        assert!(
            error
                .to_string()
                .contains("exact unchanged prompt event cut")
        );
        assert!(matches!(
            stale_fixture.ledger.consume_human_acceptance_prompt_v1(
                &stale_prompt.prompt_id,
                &stale_prompt.ui_session_id,
                "criterion-evidence-stale-v28",
                HumanAcceptanceDecisionOutcomeV1::AcceptedByYou,
                1_510,
            ),
            Err(LedgerError::ReferenceMismatch {
                entity: "human acceptance prompt",
                ..
            })
        ));
        assert_eq!(
            row_count(&stale_fixture.ledger, "human_acceptance_decisions_v1"),
            0
        );
    }

    #[test]
    fn awaiting_acceptance_final_verification_requires_complete_human_evidence() {
        let (mut fixture, _prompt) = prepare_human_acceptance_prompt_fixture();
        let final_fixture = build_awaiting_acceptance_final_verification_fixture(&mut fixture);

        assert!(matches!(
            fixture
                .ledger
                .admit_sprint_final_verification_with_output_capture_for_dispatch(
                    &final_fixture.admission,
                    &final_fixture.phase_event,
                    &final_fixture.intent,
                    &final_fixture.proposed_event,
                    &final_fixture.capture_intent,
                ),
            Err(LedgerError::ReferenceMismatch {
                entity: "sprint final-verification human acceptance",
                ..
            })
        ));
        assert_eq!(
            current_sprint_phase_state(&fixture.ledger.connection, &fixture.spec.sprint_id)
                .expect("read phase after rejected awaiting admission"),
            SprintState::AwaitingAcceptance
        );
        assert_eq!(
            row_count(&fixture.ledger, "sprint_final_verification_admissions"),
            0
        );

        let transaction = fixture
            .ledger
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .expect("begin raw awaiting final-verification bypass attempt");
        insert_agent_event(&transaction, &final_fixture.phase_event)
            .expect("insert raw awaiting final phase inside rollback transaction");
        let error = insert_sprint_final_verification_admission(
            &transaction,
            &final_fixture.admission,
            &final_fixture.command_bytes,
        )
        .expect_err("schema v28 must independently reject missing human evidence");
        assert!(
            error
                .to_string()
                .contains("exact closed TaskDone snapshot authority"),
            "unexpected raw awaiting-admission rejection: {error:?}"
        );
        transaction
            .rollback()
            .expect("roll back raw awaiting final-verification bypass attempt");
    }

    #[test]
    fn human_criteria_cannot_bypass_acceptance_through_running_final_verification() {
        let (mut fixture, _prompt) = prepare_human_acceptance_prompt_fixture();
        let return_to_running = AgentEvent {
            contract_version: CONTRACT_VERSION,
            sequence: fixture
                .ledger
                .next_sequence(&fixture.spec.sprint_id)
                .expect("human bypass Running sequence"),
            event_id: "event-human-final-bypass-running".into(),
            sprint_id: fixture.spec.sprint_id.clone(),
            task_id: None,
            worker_id: None,
            causation_id: None,
            correlation_id: "correlation-human-final-bypass".into(),
            policy_hash: None,
            occurred_at_unix_ms: 1_510,
            payload: AgentEventKind::SprintStateChanged {
                from: "AwaitingAcceptance".into(),
                to: "Running".into(),
            },
        };
        fixture
            .ledger
            .append_event(&return_to_running)
            .expect("return human-bearing sprint to Running");
        let final_snapshot = fixture.result_snapshot.snapshot_id.clone();
        let final_fixture =
            build_v21_final_verification_fixture(&mut fixture.ledger, final_snapshot);

        assert!(matches!(
            fixture
                .ledger
                .admit_sprint_final_verification_with_output_capture_for_dispatch(
                    &final_fixture.admission,
                    &final_fixture.phase_event,
                    &final_fixture.intent,
                    &final_fixture.proposed_event,
                    &final_fixture.capture_intent,
                ),
            Err(LedgerError::ReferenceMismatch {
                entity: "sprint final-verification human acceptance",
                ..
            })
        ));
        assert_eq!(
            row_count(&fixture.ledger, "sprint_final_verification_admissions"),
            0
        );
    }

    #[test]
    fn accepted_awaiting_final_verification_is_restart_safe_and_readback_guarded() {
        let (mut fixture, prompt) = prepare_human_acceptance_prompt_fixture();
        let accepted = fixture
            .ledger
            .consume_human_acceptance_prompt_v1(
                &prompt.prompt_id,
                &prompt.ui_session_id,
                "criterion-evidence-human-final-admission",
                HumanAcceptanceDecisionOutcomeV1::AcceptedByYou,
                1_510,
            )
            .expect("accept exact human prompt before final verification");
        let evidence = accepted
            .criterion_evidence
            .expect("accepted prompt creates typed evidence");
        let final_fixture = build_awaiting_acceptance_final_verification_fixture(&mut fixture);
        let admitted = fixture
            .ledger
            .admit_sprint_final_verification_with_output_capture_for_dispatch(
                &final_fixture.admission,
                &final_fixture.phase_event,
                &final_fixture.intent,
                &final_fixture.proposed_event,
                &final_fixture.capture_intent,
            )
            .expect("accepted AwaitingAcceptance source admits final verification");
        let SprintFinalVerificationDispatchAdmission::Fresh { permit, .. } = admitted else {
            panic!("first accepted awaiting admission must be Fresh");
        };
        drop(permit);
        assert_eq!(
            fixture
                .ledger
                .load_sprint_final_verification_admission(&final_fixture.admission.admission_id)
                .expect("read accepted awaiting final admission"),
            final_fixture.admission
        );

        let path = fixture.database.path.clone();
        drop(fixture.ledger);
        let mut reopened = EventLedger::open(&path).expect("reopen accepted awaiting admission");
        assert_eq!(
            reopened
                .load_sprint_final_verification_admission(&final_fixture.admission.admission_id)
                .expect("restart-read accepted awaiting final admission"),
            final_fixture.admission
        );
        assert!(matches!(
            reopened
                .admit_sprint_final_verification_with_output_capture_for_dispatch(
                    &final_fixture.admission,
                    &final_fixture.phase_event,
                    &final_fixture.intent,
                    &final_fixture.proposed_event,
                    &final_fixture.capture_intent,
                )
                .expect("restart replay accepted awaiting final admission"),
            SprintFinalVerificationDispatchAdmission::Existing { .. }
        ));

        reopened
            .connection
            .execute_batch("DROP TRIGGER criterion_evidence_receipts_v2_no_delete")
            .expect("open corruption aperture for accepted evidence");
        reopened
            .connection
            .execute(
                "DELETE FROM criterion_evidence_receipts_v2 WHERE receipt_id = ?1",
                [evidence.receipt_id()],
            )
            .expect("delete accepted evidence through corruption aperture");
        assert!(matches!(
            reopened
                .load_sprint_final_verification_admission(&final_fixture.admission.admission_id),
            Err(LedgerError::ReferenceMismatch {
                entity: "sprint final-verification human acceptance",
                ..
            })
        ));
    }

    #[test]
    fn completion_receipt_digest_uses_each_canonical_wire_image_without_reencoding() {
        let (_, _, _, _, _, _, receipt, _) = completion_artifacts();
        let current = encode("current completion receipt", &receipt)
            .expect("encode current completion receipt");
        let legacy = encode_legacy_completion_receipt(&receipt)
            .expect("encode historical completion receipt");
        assert_ne!(current, legacy);
        assert_eq!(
            canonical_stored_completion_receipt_digest(&receipt, &current)
                .expect("classify current completion bytes"),
            Some(Digest::sha256(&current))
        );
        assert_eq!(
            canonical_stored_completion_receipt_digest(&receipt, &legacy)
                .expect("classify historical completion bytes"),
            Some(Digest::sha256(&legacy))
        );

        let database = TestDatabase::new();
        let ledger = EventLedger::open(&database.path).expect("open scalar-function test ledger");
        assert_eq!(
            persisted_or_current_completion_receipt_digest(&ledger.connection, &receipt)
                .expect("derive current pre-parent completion digest"),
            Digest::sha256(&current)
        );
        for bytes in [&current, &legacy] {
            let sqlite_digest: String = ledger
                .connection
                .query_row(
                    "SELECT grok_canonical_completion_receipt_digest(?1)",
                    [bytes],
                    |row| row.get(0),
                )
                .expect("digest either canonical completion encoding in SQLite");
            assert_eq!(sqlite_digest, Digest::sha256(bytes).as_str());
        }

        let historical_database = TestDatabase::new();
        let historical = open_v21_test_ledger(&historical_database);
        assert_eq!(
            persisted_or_current_completion_receipt_digest(&historical.connection, &receipt)
                .expect("derive historical pre-parent completion digest"),
            Digest::sha256(&legacy)
        );

        let mut noncanonical = legacy;
        noncanonical.push(b' ');
        assert_eq!(
            canonical_stored_completion_receipt_digest(&receipt, &noncanonical)
                .expect("reject noncanonical historical completion bytes"),
            None
        );
        assert!(
            ledger
                .connection
                .query_row(
                    "SELECT grok_canonical_completion_receipt_digest(?1)",
                    [&noncanonical],
                    |row| row.get::<_, String>(0),
                )
                .is_err(),
            "SQLite canonicalization must reject altered historical bytes"
        );
    }

    #[test]
    #[allow(clippy::too_many_lines)] // One isolated schema fixture proves every exact-link rejection and the valid terminal insert.
    fn v28_sql_terminal_gate_requires_exact_current_criterion_link_rows() {
        const V28_TRIGGER: &str =
            "sprint_completion_proof_states_v28_current_criterion_evidence_required";
        let database = TestDatabase::new();
        schema_template::install_exact_database_at(28, &database.path);
        let mut connection = Connection::open(&database.path).expect("open isolated v28 schema");
        register_schema_functions(&connection).expect("register v28 schema functions");
        connection
            .pragma_update(None, "foreign_keys", false)
            .expect("disable unrelated foreign keys for isolated trigger probe");

        // Isolate the v28 branch gate from older proof, parent, and verification
        // admission triggers. The positive production tests exercise the
        // complete trigger conjunction; this fixture directly seeds immutable
        // verification rows only to prove the new terminal gate itself.
        let trigger_names = {
            let mut statement = connection
                .prepare(
                    "SELECT name FROM sqlite_schema
                     WHERE type = 'trigger'
                       AND tbl_name IN (
                           'v9_completion_receipts',
                           'sprint_completion_proof_states',
                           'verification_receipts'
                       )
                       AND name != ?1",
                )
                .expect("prepare isolated trigger query");
            statement
                .query_map([V28_TRIGGER], |row| row.get::<_, String>(0))
                .expect("query unrelated completion triggers")
                .collect::<Result<Vec<_>, _>>()
                .expect("collect unrelated completion triggers")
        };
        for trigger_name in trigger_names {
            let quoted = trigger_name.replace('"', "\"\"");
            connection
                .execute_batch(&format!("DROP TRIGGER \"{quoted}\";"))
                .expect("drop unrelated completion trigger");
        }

        let (mut spec, _graph) = sprint_fixture();
        let (_, _, _, verification, acceptance, _, mut receipt, _) = completion_artifacts();
        let alpha_command = CommandSpec {
            program: "cargo".into(),
            arguments: vec!["test".into(), "alpha".into()],
            working_directory: PathBuf::new(),
        };
        spec.acceptance_criteria.push(AcceptanceCriterion {
            criterion_id: "alpha".into(),
            description: "Alpha verification passes".into(),
            kind: AcceptanceKind::Automated(alpha_command.clone()),
        });
        assert_eq!(
            spec.acceptance_criteria
                .iter()
                .map(|criterion| criterion.criterion_id.as_str())
                .collect::<Vec<_>>(),
            ["tests", "alpha"],
            "fixture declaration order must differ from canonical completion order"
        );
        let alpha_verification = VerificationReceipt {
            receipt_id: "verify-alpha".into(),
            command: alpha_command,
            finished_at_unix_ms: verification.finished_at_unix_ms + 1,
            ..verification.clone()
        };
        let alpha_evidence = CriterionEvidenceReceiptV2::Verified {
            receipt_id: "acceptance-alpha".into(),
            sprint_id: acceptance.sprint_id.clone(),
            criterion_id: "alpha".into(),
            snapshot_digest: acceptance.snapshot_id.clone(),
            verification_receipt_id: alpha_verification.receipt_id.clone(),
            recorded_at: acceptance.accepted_at_unix_ms + 1,
        };
        let criterion_evidence = CriterionEvidenceReceiptV2::Verified {
            receipt_id: acceptance.receipt_id.clone(),
            sprint_id: acceptance.sprint_id.clone(),
            criterion_id: acceptance.criterion_id.clone(),
            snapshot_digest: acceptance.snapshot_id.clone(),
            verification_receipt_id: verification.receipt_id.clone(),
            recorded_at: acceptance.accepted_at_unix_ms,
        };
        receipt.satisfied_criterion_ids = vec!["alpha".into(), "tests".into()];
        receipt.criterion_evidence_receipt_ids = vec![
            alpha_evidence.receipt_id().to_owned(),
            criterion_evidence.receipt_id().to_owned(),
        ];
        receipt.verification_receipts = vec![
            alpha_verification.receipt_id.clone(),
            verification.receipt_id.clone(),
            "verify-task-1".into(),
        ];
        receipt
            .validate()
            .expect("reversed-declaration completion receipt remains canonical");
        connection
            .execute(
                "INSERT INTO sprints (
                    sprint_id, contract_version, spec_json, graph_json,
                    created_at_unix_ms
                 ) VALUES (?1, ?2, ?3, ?4, 1000)",
                params![
                    spec.sprint_id,
                    i64::from(CONTRACT_VERSION),
                    encode("isolated v28 sprint", &spec).expect("encode isolated v28 sprint"),
                    Vec::<u8>::new(),
                ],
            )
            .expect("insert isolated v28 sprint specification");
        for verification in [&alpha_verification, &verification] {
            connection
                .execute(
                    "INSERT INTO verification_receipts (
                        receipt_id, sprint_id, snapshot_id, passed, contract_version,
                        finished_at_unix_ms, receipt_json
                     ) VALUES (?1, ?2, ?3, 1, ?4, ?5, ?6)",
                    params![
                        verification.receipt_id,
                        verification.sprint_id,
                        verification.snapshot_id.as_str(),
                        i64::from(CONTRACT_VERSION),
                        sqlite_integer(
                            "isolated v28 verification time",
                            verification.finished_at_unix_ms,
                        )
                        .expect("verification time fits SQLite"),
                        encode("isolated v28 verification", verification)
                            .expect("encode isolated v28 verification"),
                    ],
                )
                .expect("insert isolated passing criterion verification");
        }
        for evidence in [&alpha_evidence, &criterion_evidence] {
            let CriterionEvidenceReceiptV2::Verified {
                verification_receipt_id,
                ..
            } = evidence
            else {
                unreachable!("isolated criterion fixtures are automated")
            };
            connection
                .execute(
                    "INSERT INTO criterion_evidence_receipts_v2 (
                        receipt_id, sprint_id, criterion_id, snapshot_digest,
                        evidence_kind, verification_receipt_id, human_decision_id,
                        prompt_id, backing, recorded_at_unix_ms, receipt_json
                     ) VALUES (?1, ?2, ?3, ?4, 'Verified', ?5, NULL, NULL, NULL, ?6, ?7)",
                    params![
                        evidence.receipt_id(),
                        evidence.sprint_id(),
                        evidence.criterion_id(),
                        evidence.snapshot_digest().as_str(),
                        verification_receipt_id,
                        sqlite_integer(
                            "isolated v28 criterion evidence time",
                            evidence.recorded_at(),
                        )
                        .expect("criterion evidence time fits SQLite"),
                        encode("isolated v28 criterion evidence", evidence)
                            .expect("encode isolated v28 criterion evidence"),
                    ],
                )
                .expect("insert isolated typed criterion evidence");
        }
        let CompletionApplication::Applied {
            application_receipt_id,
            rollback_reference_id,
        } = &receipt.application
        else {
            panic!("isolated v28 trigger fixture requires Applied completion");
        };
        connection
            .execute(
                "INSERT INTO v9_completion_receipts (
                    receipt_id, sprint_id, final_snapshot, grant_hash,
                    policy_version, final_verification_receipt_id,
                    application_kind, application_receipt_id,
                    rollback_reference_id, verified_no_op_receipt_id,
                    final_report_id, provider_backend, provider_model,
                    contract_version, completed_at_unix_ms, receipt_json
                 ) VALUES (
                    ?1, ?2, ?3, ?4, ?5, ?6, 'Applied', ?7, ?8, NULL,
                    ?9, ?10, ?11, ?12, ?13, ?14
                 )",
                params![
                    receipt.receipt_id,
                    receipt.sprint_id,
                    receipt.final_snapshot.as_str(),
                    receipt.grant_hash.as_str(),
                    i64::from(receipt.policy_version),
                    receipt.final_verification_receipt_id,
                    application_receipt_id,
                    rollback_reference_id,
                    receipt.final_report_id,
                    receipt.provider_backend,
                    receipt.provider_model,
                    i64::from(receipt.contract_version),
                    sqlite_integer(
                        "isolated_v28_completion.completed_at_unix_ms",
                        receipt.completed_at_unix_ms,
                    )
                    .expect("completion timestamp fits SQLite"),
                    encode("isolated current completion receipt", &receipt)
                        .expect("encode isolated current receipt"),
                ],
            )
            .expect("insert isolated current completion parent");
        for (ordinal, verification_receipt_id) in receipt.verification_receipts.iter().enumerate() {
            connection
                .execute(
                    "INSERT INTO v9_completion_verification_receipts (
                        completion_receipt_id, sprint_id, ordinal,
                        verification_receipt_id
                     ) VALUES (?1, ?2, ?3, ?4)",
                    params![
                        receipt.receipt_id,
                        receipt.sprint_id,
                        i64::try_from(ordinal).expect("verification ordinal fits SQLite"),
                        verification_receipt_id,
                    ],
                )
                .expect("insert isolated completion verification link");
        }

        let insert_proof = |connection: &Connection, completion_event_id: &str| {
            connection.execute(
                "INSERT INTO sprint_completion_proof_states (
                    sprint_id, proof_state, completion_receipt_id,
                    completion_event_id, contract_version, terminal_at_unix_ms
                 ) VALUES (?1, 'ProvenV9', ?2, ?3, ?4, ?5)",
                params![
                    receipt.sprint_id,
                    receipt.receipt_id,
                    completion_event_id,
                    i64::from(receipt.contract_version),
                    sqlite_integer(
                        "isolated_v28_completion.completed_at_unix_ms",
                        receipt.completed_at_unix_ms,
                    )
                    .expect("completion timestamp fits SQLite"),
                ],
            )
        };
        let error = insert_proof(&connection, "isolated-missing-link-event")
            .expect_err("missing typed criterion link set must reject");
        assert!(
            error
                .to_string()
                .contains("exact typed criterion-evidence child links")
        );
        assert_eq!(
            connection
                .query_row(
                    "SELECT COUNT(*) FROM sprint_completion_proof_states",
                    [],
                    |row| row.get::<_, i64>(0),
                )
                .expect("count refused completion proofs"),
            0
        );

        for (ordinal, criterion_evidence_receipt_id) in
            receipt.criterion_evidence_receipt_ids.iter().enumerate()
        {
            connection
                .execute(
                    "INSERT INTO v28_completion_criterion_evidence_receipts (
                        completion_receipt_id, sprint_id, ordinal,
                        criterion_evidence_receipt_id
                     ) VALUES (?1, ?2, ?3, ?4)",
                    params![
                        receipt.receipt_id,
                        receipt.sprint_id,
                        i64::try_from(ordinal).expect("criterion ordinal fits SQLite"),
                        criterion_evidence_receipt_id,
                    ],
                )
                .expect("insert exact isolated typed criterion link");
        }

        let crossed_evidence = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .expect("start crossed criterion-evidence transaction");
        crossed_evidence
            .execute_batch("DROP TRIGGER criterion_evidence_receipts_v2_no_update;")
            .expect("drop criterion-evidence immutability only inside rollback probe");
        crossed_evidence
            .execute(
                "UPDATE criterion_evidence_receipts_v2
                 SET criterion_id = 'crossed-criterion'
                 WHERE receipt_id = ?1",
                [criterion_evidence.receipt_id()],
            )
            .expect("cross isolated criterion evidence");
        let error = crossed_evidence
            .execute(
                "INSERT INTO sprint_completion_proof_states (
                    sprint_id, proof_state, completion_receipt_id,
                    completion_event_id, contract_version, terminal_at_unix_ms
                 ) VALUES (?1, 'ProvenV9', ?2, 'crossed-evidence-event', ?3, ?4)",
                params![
                    receipt.sprint_id,
                    receipt.receipt_id,
                    i64::from(receipt.contract_version),
                    sqlite_integer(
                        "crossed v28 criterion completion time",
                        receipt.completed_at_unix_ms,
                    )
                    .expect("crossed completion time fits SQLite"),
                ],
            )
            .expect_err("criterion evidence crossed from SprintSpec must reject");
        assert!(
            error
                .to_string()
                .contains("exact typed criterion-evidence child links")
        );
        drop(crossed_evidence);

        let mut crossed_receipt = receipt.clone();
        crossed_receipt.satisfied_criterion_ids = vec!["alpha".into(), "crossed-criterion".into()];
        let crossed_satisfied = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .expect("start crossed satisfied-criterion transaction");
        crossed_satisfied
            .execute(
                "UPDATE v9_completion_receipts SET receipt_json = ?1
                 WHERE receipt_id = ?2",
                params![
                    encode("crossed current completion", &crossed_receipt)
                        .expect("encode crossed completion"),
                    receipt.receipt_id,
                ],
            )
            .expect("cross completion satisfied criterion array");
        let error = crossed_satisfied
            .execute(
                "INSERT INTO sprint_completion_proof_states (
                    sprint_id, proof_state, completion_receipt_id,
                    completion_event_id, contract_version, terminal_at_unix_ms
                 ) VALUES (?1, 'ProvenV9', ?2, 'crossed-satisfied-event', ?3, ?4)",
                params![
                    receipt.sprint_id,
                    receipt.receipt_id,
                    i64::from(receipt.contract_version),
                    sqlite_integer(
                        "crossed v28 satisfied completion time",
                        receipt.completed_at_unix_ms,
                    )
                    .expect("crossed satisfied time fits SQLite"),
                ],
            )
            .expect_err("satisfied criterion crossed from SprintSpec must reject");
        assert!(
            error
                .to_string()
                .contains("exact typed criterion-evidence child links")
        );
        drop(crossed_satisfied);

        let future_evidence = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .expect("start future criterion-evidence transaction");
        future_evidence
            .execute_batch("DROP TRIGGER criterion_evidence_receipts_v2_no_update;")
            .expect("drop criterion-evidence immutability only inside rollback probe");
        future_evidence
            .execute(
                "UPDATE criterion_evidence_receipts_v2
                 SET recorded_at_unix_ms = ?1
                 WHERE receipt_id = ?2",
                params![
                    sqlite_integer(
                        "future criterion evidence time",
                        receipt.completed_at_unix_ms + 1,
                    )
                    .expect("future evidence time fits SQLite"),
                    alpha_evidence.receipt_id(),
                ],
            )
            .expect("move criterion evidence after completion inside rollback probe");
        let error = future_evidence
            .execute(
                "INSERT INTO sprint_completion_proof_states (
                    sprint_id, proof_state, completion_receipt_id,
                    completion_event_id, contract_version, terminal_at_unix_ms
                 ) VALUES (?1, 'ProvenV9', ?2, 'future-evidence-event', ?3, ?4)",
                params![
                    receipt.sprint_id,
                    receipt.receipt_id,
                    i64::from(receipt.contract_version),
                    sqlite_integer(
                        "future evidence completion time",
                        receipt.completed_at_unix_ms,
                    )
                    .expect("completion time fits SQLite"),
                ],
            )
            .expect_err("criterion evidence recorded after completion must reject");
        assert!(
            error
                .to_string()
                .contains("exact typed criterion-evidence child links")
        );
        drop(future_evidence);

        let missing_verification_link = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .expect("start missing criterion-verification link transaction");
        missing_verification_link
            .execute_batch("DROP TRIGGER v9_completion_verification_no_delete;")
            .expect("drop verification-link immutability only inside rollback probe");
        missing_verification_link
            .execute(
                "DELETE FROM v9_completion_verification_receipts
                 WHERE completion_receipt_id = ?1
                   AND verification_receipt_id = ?2",
                params![receipt.receipt_id, alpha_verification.receipt_id],
            )
            .expect("remove criterion verification link inside rollback probe");
        let error = missing_verification_link
            .execute(
                "INSERT INTO sprint_completion_proof_states (
                    sprint_id, proof_state, completion_receipt_id,
                    completion_event_id, contract_version, terminal_at_unix_ms
                 ) VALUES (?1, 'ProvenV9', ?2, 'missing-verification-link-event', ?3, ?4)",
                params![
                    receipt.sprint_id,
                    receipt.receipt_id,
                    i64::from(receipt.contract_version),
                    sqlite_integer(
                        "missing verification-link completion time",
                        receipt.completed_at_unix_ms,
                    )
                    .expect("completion time fits SQLite"),
                ],
            )
            .expect_err("verified criterion absent from completion verification set must reject");
        assert!(
            error
                .to_string()
                .contains("exact typed criterion-evidence child links")
        );
        drop(missing_verification_link);

        insert_proof(&connection, "isolated-completion-event")
            .expect("nonlexically declared exact typed criterion set satisfies v28 SQL gate");
    }

