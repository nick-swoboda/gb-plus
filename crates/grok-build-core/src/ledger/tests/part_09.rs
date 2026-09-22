    #[test]
    fn current_readback_rejects_historical_rollback_terminal_without_cleanup() {
        let database = TestDatabase::new();
        {
            let mut historical = open_v12_test_ledger(&database);
            let pending = prepare_pending_rollback(&mut historical);
            historical
                .record_rollback_effect_observation(
                    &pending.observation,
                    &pending.terminal,
                    &pending.evidence,
                )
                .expect("persist pre-cleanup-admission rollback");
            let evidence = terminal_evidence(
                "historical-rollback-terminal-without-cleanup",
                NonSuccessTerminalState::Failed,
            );
            let proof = SprintTerminalProof::Rollback(pending.evidence.receipt.clone());
            assert!(matches!(
                historical.record_unsuccessful_terminal_outcome_with_proof(&evidence, &proof),
                Err(LedgerError::ReferenceMismatch {
                    entity: "worker cleanup set",
                    ..
                })
            ));

            let evidence_bytes =
                encode("sprint terminal evidence", &evidence).expect("encode terminal evidence");
            let evidence_digest = Digest::sha256(&evidence_bytes);
            let event = normalized_terminal_event(
                &evidence,
                evidence_digest.clone(),
                historical
                    .next_sequence(&evidence.sprint_id)
                    .expect("historical terminal sequence"),
            );
            let transaction = historical
                .connection
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .expect("start historical SQL-bypass transaction");
            insert_terminal_proof(
                &transaction,
                &evidence,
                &evidence_digest,
                &event,
                TerminalProofAdmission::Known(&proof),
            )
            .expect("stage historical rollback terminal proof");
            insert_non_success_terminal_outcome(
                &transaction,
                &evidence,
                &evidence_bytes,
                &evidence_digest,
            )
            .expect("stage historical rollback terminal outcome");
            insert_agent_event(&transaction, &event)
                .expect("stage historical rollback terminal event");
            transaction
                .commit()
                .expect("commit deliberately bypassed historical terminal");
        }

        let reader = EventLedger::open(&database.path)
            .expect("migrate historical unclean terminal to current schema");
        assert!(matches!(
            reader.load_terminal_outcome("sprint-1"),
            Err(LedgerError::Corrupt {
                entity: "sprint terminal outcome",
                ref detail,
            }) if detail.contains("known terminal cleanup set is invalid")
                && detail.contains("worker cleanup set")
        ));
    }

    #[test]
    fn v22_application_dropped_fresh_permit_never_remints_after_reopen() {
        let mut fixture = prepare_v22_application_admission_fixture();
        drop(
            fixture
                .permit
                .take()
                .expect("drop sole fresh v22 application permit"),
        );
        let V22ApplicationAdmissionFixture {
            candidate,
            admission,
            assembly,
            phase_event,
            intent,
            proposal,
            ..
        } = fixture;
        let V15CandidateFixture {
            database, ledger, ..
        } = candidate;
        let database_path = database.path.clone();
        drop(ledger);

        let mut reopened = EventLedger::open(&database_path)
            .expect("reopen dropped-permit v22 application ledger");
        assert!(matches!(
            reopened.admit_sprint_application_for_dispatch(
                &admission,
                &phase_event,
                &intent,
                &proposal,
            ),
            Ok(SprintApplicationDispatchAdmission::Existing {
                admission: ref replay_admission,
                assembly: ref replay_assembly,
                ref effect,
            }) if replay_admission == &admission
                && replay_assembly == &assembly
                && effect.dispatch_claim.is_none()
                && effect.observation.is_none()
        ));
    }

    #[test]
    fn v22_application_claim_only_restart_is_reconciliation_only() {
        let mut fixture = prepare_v22_application_admission_fixture();
        let (claimed, transport) = fixture
            .candidate
            .ledger
            .claim_runner_effect_dispatch(
                FreshRunnerEffectDispatchPermit::SprintApplication(
                    fixture
                        .permit
                        .take()
                        .expect("claim sole v22 application permit"),
                ),
                OPAQUE_RUNNER_TRANSPORT_REQUEST_BYTES,
            )
            .expect("durably claim v22 application before restart");
        assert!(matches!(
            claimed.dispatch_claim.as_ref().map(|claim| &claim.authority),
            Some(RunnerEffectRequestAuthority::SprintApplication {
                sprint_phase_event_id,
            }) if sprint_phase_event_id == &fixture.phase_event.event_id
        ));
        drop(transport);

        let V22ApplicationAdmissionFixture {
            candidate,
            admission,
            assembly,
            phase_event,
            intent,
            proposal,
            ..
        } = fixture;
        let V15CandidateFixture {
            database, ledger, ..
        } = candidate;
        let database_path = database.path.clone();
        drop(ledger);
        let mut reopened =
            EventLedger::open(&database_path).expect("reopen claim-only v22 application ledger");
        assert!(matches!(
            reopened.admit_sprint_application_for_dispatch(
                &admission,
                &phase_event,
                &intent,
                &proposal,
            ),
            Ok(SprintApplicationDispatchAdmission::Existing {
                admission: ref replay_admission,
                assembly: ref replay_assembly,
                ref effect,
            }) if replay_admission == &admission
                && replay_assembly == &assembly
                && effect.dispatch_claim == claimed.dispatch_claim
                && effect.observation.is_none()
        ));
    }

    #[test]
    #[allow(clippy::too_many_lines)] // Crossed raw contenders and the exact competing claim share one immutable admission.
    fn v22_application_two_connection_raw_claim_wins_once_and_stales_fresh_permit() {
        let mut fixture = prepare_v22_application_admission_fixture();
        let permit = fixture
            .permit
            .take()
            .expect("retain first-connection v22 application permit");
        let mut competitor = EventLedger::open(&fixture.candidate.database.path)
            .expect("open competing v22 application ledger");
        let exact_claim = PersistedRunnerEffectDispatchClaim {
            dispatch_claim_id: runner_effect_dispatch_claim_id(&fixture.intent.effect_id),
            effect_id: fixture.intent.effect_id.clone(),
            sprint_id: fixture.intent.sprint_id.clone(),
            launch_id: fixture.applier_launch.launch_id.clone(),
            session_id: fixture.applier_session.session_id.clone(),
            running_boundary_id: None,
            authority: RunnerEffectRequestAuthority::SprintApplication {
                sprint_phase_event_id: fixture.phase_event.event_id.clone(),
            },
            request_digest: fixture.intent.request_digest.clone(),
            opaque_transport_request_digest: Digest::sha256(OPAQUE_RUNNER_TRANSPORT_REQUEST_BYTES),
            policy_hash: fixture.intent.policy_hash.clone(),
            input_snapshot: fixture.intent.input_snapshot.clone(),
            contract_version: CONTRACT_VERSION,
        };

        let mut crossed_class = exact_claim.clone();
        crossed_class.authority = RunnerEffectRequestAuthority::SprintFinalVerification {
            sprint_phase_event_id: fixture.phase_event.event_id.clone(),
        };
        let transaction = competitor
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .expect("start crossed-class raw claim");
        insert_runner_effect_dispatch_claim_authority(&transaction, &crossed_class)
            .expect("pre-parent crossed companion is structurally storable");
        assert!(
            insert_runner_effect_dispatch_claim(&transaction, &crossed_class).is_err(),
            "raw claim parent must reject a crossed phase authority class"
        );
        transaction
            .rollback()
            .expect("roll back crossed-class raw claim");

        let mut crossed_session = exact_claim.clone();
        crossed_session.session_id = "session-v21-final".into();
        let transaction = competitor
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .expect("start crossed-session raw claim");
        insert_runner_effect_dispatch_claim_authority(&transaction, &crossed_session)
            .expect("pre-parent exact application companion");
        assert!(
            insert_runner_effect_dispatch_claim(&transaction, &crossed_session).is_err(),
            "raw claim parent must reject a crossed runner session"
        );
        transaction
            .rollback()
            .expect("roll back crossed-session raw claim");

        let transaction = competitor
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .expect("start exact competing raw claim");
        insert_runner_effect_dispatch_claim_authority(&transaction, &exact_claim)
            .expect("insert exact v22 application claim companion");
        insert_runner_effect_dispatch_claim(&transaction, &exact_claim)
            .expect("insert exact competing v22 application claim");
        transaction.commit().expect("commit competing v22 claim");
        assert_eq!(
            competitor
                .load_effect(&fixture.intent.effect_id)
                .expect("load exact raw competing claim")
                .dispatch_claim,
            Some(exact_claim.clone())
        );
        assert!(
            fixture
                .candidate
                .ledger
                .claim_runner_effect_dispatch(
                    FreshRunnerEffectDispatchPermit::SprintApplication(permit),
                    OPAQUE_RUNNER_TRANSPORT_REQUEST_BYTES,
                )
                .is_err(),
            "durable competing claim must stale the original in-memory permit"
        );
        assert_eq!(
            fixture
                .candidate
                .ledger
                .load_effect(&fixture.intent.effect_id)
                .expect("load winning claim on original connection")
                .dispatch_claim,
            Some(exact_claim)
        );
    }

    #[test]
    fn v22_preparation_rejects_crossed_cut_before_atomic_fresh_write() {
        let mut fixture = prepare_v22_application_admission_fixture_with_crosses(true);
        assert_eq!(
            row_count(&fixture.candidate.ledger, "application_artifact_assemblies"),
            1
        );
        assert_eq!(
            row_count(&fixture.candidate.ledger, "sprint_application_admissions"),
            1
        );
        drop(
            fixture
                .permit
                .take()
                .expect("discard crossed-cut test's sole fresh permit"),
        );
    }

    #[test]
    #[allow(clippy::too_many_lines)] // The test proves classification plus every zero-write invariant.
    fn v22_preparation_explicit_empty_task_done_is_verified_no_op_and_never_apply() {
        let mut fixture = prepare_v22_explicit_empty_preparation_fixture_with_requirement_at_v23(
            CandidateTaskRequirement::Required,
        );
        assert_eq!(
            fixture
                .candidate
                .ledger
                .connection
                .pragma_query_value(None, "user_version", |row| row.get::<_, u32>(0))
                .expect("read historical pre-v24 fixture schema generation"),
            23,
            "legacy standalone no-op authority must be exercised only before schema v24"
        );
        let preparation = fixture
            .candidate
            .ledger
            .assess_sprint_application_preparation(
                &fixture.candidate.spec.sprint_id,
                &fixture.final_evidence.verification.receipt_id,
                "assembly-v22-explicit-empty-probe",
                2_400,
            )
            .expect("classify exact explicit-empty TaskDone source");
        assert!(matches!(
            preparation,
            SprintApplicationPreparation::VerifiedNoOpRequired {
                ref final_verification_receipt_id,
                ref base_snapshot,
            } if final_verification_receipt_id
                == &fixture.final_evidence.verification.receipt_id
                && base_snapshot == &fixture.candidate.spec.base_snapshot
        ));
        assert_eq!(
            fixture
                .candidate
                .ledger
                .connection
                .query_row(
                    "SELECT COUNT(*) FROM finish_effect_kinds
                     WHERE sprint_id = ?1 AND effect_kind = 'ApplyChangeSet'",
                    [&fixture.candidate.spec.sprint_id],
                    |row| row.get::<_, i64>(0),
                )
                .expect("count explicit-empty Apply effects"),
            0
        );
        assert_eq!(
            row_count(&fixture.candidate.ledger, "application_artifact_assemblies"),
            0
        );
        assert_eq!(
            row_count(&fixture.candidate.ledger, "sprint_application_admissions"),
            0
        );

        let artifact = fixture
            .candidate
            .ledger
            .load_task_integration_evidence(
                &fixture
                    .candidate
                    .ledger
                    .assess_task_done(&fixture.candidate.spec.sprint_id, "task-1")
                    .expect("assess explicit-empty TaskDone")
                    .proof
                    .expect("explicit-empty task is done")
                    .integration_receipt
                    .receipt_id,
            )
            .expect("load explicit-empty integration artifact")
            .artifact;
        assert!(
            ApplicationRequest {
                contract_version: CONTRACT_VERSION,
                change_set: fixture.candidate.change_set.clone(),
                artifact,
            }
            .validate()
            .is_err()
        );
        let mut nonempty_net_zero = fixture.candidate.change_set.clone();
        nonempty_net_zero
            .operations
            .push(crate::FileOperation::Create {
                path: PathBuf::from("net-zero-is-not-no-op.txt"),
                result_hash: digest('7'),
            });
        assert_eq!(
            nonempty_net_zero.base_snapshot,
            nonempty_net_zero.result_snapshot
        );
        assert!(nonempty_net_zero.validate().is_err());

        let no_op = VerifiedNoOpReceipt {
            contract_version: CONTRACT_VERSION,
            receipt_id: "verified-no-op-v22-explicit-empty".into(),
            sprint_id: fixture.candidate.spec.sprint_id.clone(),
            final_verification_receipt_id: fixture.final_evidence.verification.receipt_id.clone(),
            base_snapshot: fixture.candidate.spec.base_snapshot.clone(),
            live_manifest_digest: fixture.candidate.spec.base_snapshot.clone(),
            grant_hash: fixture.candidate.spec.workspace_grant.grant_hash.clone(),
            policy_version: fixture.candidate.spec.workspace_grant.policy_version,
            observed_at_unix_ms: 2_400,
        };
        fixture
            .candidate
            .ledger
            .persist_verified_no_op_receipt(&no_op)
            .expect("persist exact v22 explicit-empty no-op proof");
        assert_eq!(
            fixture
                .candidate
                .ledger
                .load_verified_no_op_receipt(&no_op.receipt_id)
                .expect("reload exact v22 no-op proof"),
            no_op
        );
    }

    #[test]
    #[allow(clippy::too_many_lines)] // Claimed final authority is required even to prove that the source set is empty.
    fn v22_preparation_rejects_zero_integrated_sources() {
        let database = TestDatabase::new();
        let mut ledger = EventLedger::open(&database.path).expect("open zero-source v22 ledger");
        let (spec, mut graph) = sprint_fixture();
        graph.tasks[0].required = false;
        ledger
            .create_sprint(&spec, &graph, 1_000)
            .expect("persist zero-source optional sprint");
        let (base, _, _, _, _, _, _, _) = completion_artifacts();
        ledger
            .persist_workspace_snapshot(&spec.sprint_id, &base)
            .expect("persist zero-source sprint base");
        let final_fixture =
            build_v21_final_verification_fixture(&mut ledger, spec.base_snapshot.clone());
        let permit = admit_test_final_verification(&mut ledger, &final_fixture);
        let (authority, acquired) =
            claim_test_final_verification(&mut ledger, &final_fixture, permit);
        let (observation, event, evidence) =
            v21_final_verification_terminal(&ledger, &final_fixture);
        complete_test_final_verification(
            &mut ledger,
            &final_fixture,
            authority,
            acquired.as_ref(),
            &observation,
            &event,
            &evidence,
        );
        let command = ledger
            .load_command_domain_effect_bindings(
                &spec.sprint_id,
                &final_fixture.launch.launch_id,
                &final_fixture.session.session_id,
            )
            .expect("load zero-source final command binding")
            .into_iter()
            .find(|binding| binding.effect_id == final_fixture.intent.effect_id)
            .expect("find zero-source final command binding");
        ensure_test_command_domain_cleanup(
            &mut ledger,
            &command,
            "command-cleanup-v22-zero-source-final",
            CommandDomainBackend::LinuxCgroupV2,
            CommandDomainCleanupDisposition::ReapedZeroSurvivors,
            2_320,
        );
        persist_cleanup_evidence(
            &mut ledger,
            &final_fixture.launch,
            &spec.base_snapshot,
            "cleanup-v22-zero-source-final",
            WorkerCleanupBackend::LinuxCgroupV2,
            2_310,
            2_340,
        );
        let error = ledger
            .assess_sprint_application_preparation(
                &spec.sprint_id,
                &evidence.verification.receipt_id,
                "assembly-v22-zero-source",
                2_400,
            )
            .expect_err("zero integrated sources cannot form application or no-op authority");
        assert!(matches!(
            error,
            LedgerError::ReferenceMismatch {
                entity: "application artifact assembly",
                ref detail,
            } if detail.contains("exactly one explicit TaskDone source")
        ));
        assert_eq!(row_count(&ledger, "application_artifact_assemblies"), 0);
        assert_eq!(row_count(&ledger, "sprint_application_admissions"), 0);
    }

    #[test]
    #[allow(clippy::too_many_lines)] // The real two-winner chain proves gate-one rejection without synthetic rows.
    fn v22_preparation_rejects_two_exact_task_done_sources_without_writes() {
        let second_task = optional_task("task-2", digest('b'));
        let mut fixture = prepare_v15_candidate_fixture_with_graph_options(
            false,
            false,
            false,
            false,
            CandidateTaskRequirement::Required,
            Some(second_task),
        );

        let (_, first_integration, first_disposition) =
            integrate_v15_candidate(&mut fixture, "z-v22-multi-source-ordinal-zero", false);
        let first_cleanup = cleanup_terminal_record(
            &fixture.ledger,
            &fixture.launch,
            "cleanup-v22-multi-source-first",
            1_480,
        );
        fixture
            .ledger
            .with_integrated_task_attempt_cleanup_exclusion(
                &first_disposition.metadata().disposition_id,
                |_| Ok(first_cleanup),
            )
            .expect("close first exact TaskDone winner");
        assert!(
            fixture
                .ledger
                .assess_task_done(&fixture.spec.sprint_id, "task-1")
                .expect("assess first exact TaskDone winner")
                .is_done()
        );

        advance_v15_fixture_to_second_human_candidate(&mut fixture);
        let (_, second_integration, second_disposition) =
            integrate_v15_candidate(&mut fixture, "a-v22-multi-source-ordinal-one", false);
        let second_cleanup = cleanup_terminal_record(
            &fixture.ledger,
            &fixture.launch,
            "cleanup-v22-multi-source-second",
            1_700,
        );
        fixture
            .ledger
            .with_integrated_task_attempt_cleanup_exclusion(
                &second_disposition.metadata().disposition_id,
                |_| Ok(second_cleanup),
            )
            .expect("close second exact TaskDone winner");
        for task_id in ["task-1", "task-2"] {
            assert!(
                fixture
                    .ledger
                    .assess_task_done(&fixture.spec.sprint_id, task_id)
                    .expect("assess exact TaskDone winner")
                    .is_done()
            );
        }

        let awaiting = AgentEvent {
            contract_version: CONTRACT_VERSION,
            sequence: fixture
                .ledger
                .next_sequence(&fixture.spec.sprint_id)
                .expect("two-source human acceptance phase sequence"),
            event_id: "event-v22-multi-source-awaiting-acceptance".into(),
            sprint_id: fixture.spec.sprint_id.clone(),
            task_id: None,
            worker_id: None,
            causation_id: None,
            correlation_id: "correlation-v22-multi-source-acceptance".into(),
            policy_hash: None,
            occurred_at_unix_ms: 1_750,
            payload: AgentEventKind::SprintStateChanged {
                from: "Running".into(),
                to: "AwaitingAcceptance".into(),
            },
        };
        fixture
            .ledger
            .append_event(&awaiting)
            .expect("enter two-source AwaitingAcceptance");
        let prompt = fixture
            .ledger
            .issue_human_acceptance_prompt_v1(
                "prompt-v22-multi-source-final",
                "ui-session-v22-multi-source-final",
                &fixture.spec.sprint_id,
                "tests",
                Digest::sha256(b"rendered v22 two-source acceptance"),
            )
            .expect("issue two-source human acceptance prompt");
        fixture
            .ledger
            .consume_human_acceptance_prompt_v1(
                &prompt.prompt_id,
                &prompt.ui_session_id,
                "criterion-evidence-v22-multi-source-final",
                HumanAcceptanceDecisionOutcomeV1::AcceptedByYou,
                1_760,
            )
            .expect("accept two-source human criterion");
        let final_fixture = build_awaiting_acceptance_final_verification_fixture(&mut fixture);
        let permit = admit_test_final_verification(&mut fixture.ledger, &final_fixture);
        let (authority, acquired) =
            claim_test_final_verification(&mut fixture.ledger, &final_fixture, permit);
        let (observation, terminal, evidence) =
            v21_final_verification_terminal(&fixture.ledger, &final_fixture);
        complete_test_final_verification(
            &mut fixture.ledger,
            &final_fixture,
            authority,
            acquired.as_ref(),
            &observation,
            &terminal,
            &evidence,
        );
        let command = fixture
            .ledger
            .load_command_domain_effect_bindings(
                &fixture.spec.sprint_id,
                &final_fixture.launch.launch_id,
                &final_fixture.session.session_id,
            )
            .expect("load two-source final command binding")
            .into_iter()
            .find(|binding| binding.effect_id == final_fixture.intent.effect_id)
            .expect("find two-source final command binding");
        ensure_test_command_domain_cleanup(
            &mut fixture.ledger,
            &command,
            "command-cleanup-v22-multi-source-final",
            CommandDomainBackend::LinuxCgroupV2,
            CommandDomainCleanupDisposition::ReapedZeroSurvivors,
            2_320,
        );
        persist_cleanup_evidence(
            &mut fixture.ledger,
            &final_fixture.launch,
            &fixture.result_snapshot.snapshot_id,
            "cleanup-v22-multi-source-final",
            WorkerCleanupBackend::LinuxCgroupV2,
            2_310,
            2_340,
        );

        let event_count_before = row_count(&fixture.ledger, "agent_events");
        let effect_count_before = row_count(&fixture.ledger, "effect_intents");
        let preparation = fixture
            .ledger
            .assess_sprint_application_preparation(
                &fixture.spec.sprint_id,
                &evidence.verification.receipt_id,
                "assembly-v22-multi-source",
                2_400,
            )
            .expect("classify two exact TaskDone sources");
        assert_eq!(
            preparation,
            SprintApplicationPreparation::MultipleIntegratedSourcesUnsupported {
                integrated_source_count: 2,
            }
        );
        assert_eq!(
            row_count(&fixture.ledger, "application_artifact_assemblies"),
            0
        );
        assert_eq!(
            row_count(&fixture.ledger, "sprint_application_admissions"),
            0
        );
        assert_eq!(
            row_count(&fixture.ledger, "agent_events"),
            event_count_before
        );
        assert_eq!(
            row_count(&fixture.ledger, "effect_intents"),
            effect_count_before
        );
        assert_eq!(
            fixture
                .ledger
                .connection
                .query_row(
                    "SELECT COUNT(*) FROM finish_effect_kinds
                     WHERE sprint_id = ?1 AND effect_kind = 'ApplyChangeSet'",
                    [&fixture.spec.sprint_id],
                    |row| row.get::<_, i64>(0),
                )
                .expect("count two-source Apply effects"),
            0
        );
        assert_eq!(
            current_sprint_phase_state(&fixture.ledger.connection, &fixture.spec.sprint_id)
                .expect("load phase after two-source classification"),
            SprintState::FinalVerification
        );

        let mut cleanup_receipt_ids = vec![
            "cleanup-v22-multi-source-first".into(),
            "cleanup-v22-multi-source-second".into(),
            "cleanup-v22-multi-source-final".into(),
        ];
        cleanup_receipt_ids.sort();
        let ordinal_order = vec![
            first_integration.receipt.receipt_id.clone(),
            second_integration.receipt.receipt_id.clone(),
        ];
        assert!(ordinal_order[0] > ordinal_order[1]);
        let completion_order_probe = CompletionReceipt {
            contract_version: CONTRACT_VERSION,
            receipt_id: "completion-v22-multi-source-order-probe".into(),
            sprint_id: fixture.spec.sprint_id.clone(),
            grant_hash: fixture.spec.workspace_grant.grant_hash.clone(),
            policy_version: fixture.spec.workspace_grant.policy_version,
            final_snapshot: fixture.result_snapshot.snapshot_id.clone(),
            final_verification_receipt_id: evidence.verification.receipt_id.clone(),
            application: CompletionApplication::VerifiedNoOp {
                verified_no_op_receipt_id: "verified-no-op-order-probe".into(),
            },
            worker_cleanup_receipt_ids: cleanup_receipt_ids,
            satisfied_criterion_ids: vec!["tests".into()],
            criterion_evidence_receipt_ids: vec!["acceptance-order-probe".into()],
            task_integration_receipt_ids: ordinal_order,
            verification_receipts: vec![evidence.verification.receipt_id.clone()],
            provider_backend: fixture.spec.provider.backend_id.clone(),
            provider_model: fixture.spec.provider.model_id.clone(),
            final_report_id: "report-order-probe".into(),
            completed_at_unix_ms: 2_500,
        };
        assert!(completion_order_probe.validate().is_ok());
        let (_, graph, _) = load_sprint_inputs(&fixture.ledger.connection, &fixture.spec.sprint_id)
            .expect("load two-source graph for completion-order probe");
        assert!(
            validate_completion_tasks(
                &fixture.ledger.connection,
                &fixture.spec,
                &graph,
                &completion_order_probe,
                &evidence.verification,
            )
            .is_ok()
        );
        let mut swapped_order = completion_order_probe;
        swapped_order.task_integration_receipt_ids.swap(0, 1);
        assert!(swapped_order.validate().is_ok());
        assert!(
            validate_completion_tasks(
                &fixture.ledger.connection,
                &fixture.spec,
                &graph,
                &swapped_order,
                &evidence.verification,
            )
            .is_err()
        );
    }

    #[test]
    #[allow(clippy::too_many_lines)] // Optional TaskDone, application, assessment, and atomic completion are one proof.
    fn v22_optional_completion_records_nonempty_integrated_task() {
        let mut fixture = prepare_v22_application_admission_fixture_with_options_at_v23(
            false,
            CandidateTaskRequirement::Optional,
        );
        let terminal = persist_v22_claimed_application_fixture(&mut fixture);
        persist_cleanup_evidence(
            &mut fixture.candidate.ledger,
            &fixture.applier_launch,
            &fixture.request.change_set.result_snapshot,
            "cleanup-v22-optional-application-applier",
            WorkerCleanupBackend::TrustedApplierDirectChildWait,
            2_520,
            2_540,
        );
        let acceptance = AcceptanceReceipt {
            receipt_id: "acceptance-v22-optional-application".into(),
            sprint_id: fixture.candidate.spec.sprint_id.clone(),
            criterion_id: "tests".into(),
            snapshot_id: fixture.request.change_set.result_snapshot.clone(),
            evidence: AcceptanceEvidence::Automated {
                verification_receipt_id: fixture.admission.final_verification_receipt_id.clone(),
            },
            accepted_at_unix_ms: 2_550,
        };
        fixture
            .candidate
            .ledger
            .persist_acceptance_receipt(&acceptance)
            .expect("persist optional application acceptance");
        let integration = fixture
            .candidate
            .ledger
            .load_task_integration_receipt(&fixture.assembly.sources[0].task_integration_receipt_id)
            .expect("load optional application integration receipt");
        let body = "Optional nonempty TaskDone was applied and verified.".to_owned();
        let report = FinalReport {
            report_id: "report-v22-optional-application".into(),
            sprint_id: fixture.candidate.spec.sprint_id.clone(),
            final_snapshot: fixture.request.change_set.result_snapshot.clone(),
            content_digest: FinalReport::digest_body(&body),
            body,
            created_at_unix_ms: 2_600,
        };
        let mut cleanup_ids = vec![
            "cleanup-v22-application-worker".into(),
            "cleanup-v22-final".into(),
            "cleanup-v22-optional-application-applier".into(),
        ];
        cleanup_ids.sort();
        let mut verification_ids = integration.task_verification_receipt_ids.clone();
        verification_ids.push(fixture.admission.final_verification_receipt_id.clone());
        verification_ids.sort();
        let receipt = CompletionReceipt {
            contract_version: CONTRACT_VERSION,
            receipt_id: "completion-v22-optional-application".into(),
            sprint_id: fixture.candidate.spec.sprint_id.clone(),
            grant_hash: fixture.candidate.spec.workspace_grant.grant_hash.clone(),
            policy_version: fixture.candidate.spec.workspace_grant.policy_version,
            final_snapshot: fixture.request.change_set.result_snapshot.clone(),
            final_verification_receipt_id: fixture.admission.final_verification_receipt_id.clone(),
            application: CompletionApplication::Applied {
                application_receipt_id: terminal.receipt.receipt_id.clone(),
                rollback_reference_id: terminal.rollback.reference.reference_id.clone(),
            },
            worker_cleanup_receipt_ids: cleanup_ids,
            satisfied_criterion_ids: vec!["tests".into()],
            criterion_evidence_receipt_ids: vec![acceptance.receipt_id.clone()],
            task_integration_receipt_ids: vec![integration.receipt_id.clone()],
            verification_receipts: verification_ids,
            provider_backend: fixture.candidate.spec.provider.backend_id.clone(),
            provider_model: fixture.candidate.spec.provider.model_id.clone(),
            final_report_id: report.report_id.clone(),
            completed_at_unix_ms: 2_700,
        };
        let event = AgentEvent {
            contract_version: CONTRACT_VERSION,
            sequence: fixture
                .candidate
                .ledger
                .next_sequence(&receipt.sprint_id)
                .expect("optional application completion sequence"),
            event_id: "event-v22-optional-application-completed".into(),
            sprint_id: receipt.sprint_id.clone(),
            task_id: None,
            worker_id: None,
            causation_id: Some(terminal.event.event_id.clone()),
            correlation_id: "v22-optional-application-completion".into(),
            policy_hash: None,
            occurred_at_unix_ms: receipt.completed_at_unix_ms,
            payload: AgentEventKind::CompletionRecorded(receipt.receipt_id.clone()),
        };
        let assessment = fixture
            .candidate
            .ledger
            .assess_completion_eligibility(&report, &receipt, &event)
            .expect("assess optional application completion");
        assert!(assessment.is_eligible(), "unexpected unmet: {assessment:?}");
        let mut omitted_optional = receipt.clone();
        omitted_optional.task_integration_receipt_ids.clear();
        let omitted = fixture
            .candidate
            .ledger
            .assess_completion_eligibility(&report, &omitted_optional, &event)
            .expect("diagnose omitted optional application TaskDone");
        assert!(
            omitted
                .unmet_requirements
                .contains(&CompletionEligibilityRequirement::AllIntegratedTasksDoneAndLinked)
        );
        let completed = record_pre_v24_successful_completion_for_test(
            &mut fixture.candidate.ledger,
            &report,
            &receipt,
            &event,
        )
        .expect("atomically complete optional nonempty integration");
        assert!(matches!(
            completed.receipt.application,
            CompletionApplication::Applied { .. }
        ));
    }

    #[test]
    #[allow(clippy::too_many_lines)] // Optional explicit-empty TaskDone remains linked through no-op completion.
    fn v22_optional_no_op_completion_requires_typed_live_manifest_capture_authority() {
        let mut fixture = prepare_v22_explicit_empty_preparation_fixture_with_requirement_at_v23(
            CandidateTaskRequirement::Optional,
        );
        let proof = fixture
            .candidate
            .ledger
            .assess_task_done(&fixture.candidate.spec.sprint_id, "task-1")
            .expect("assess optional explicit-empty TaskDone")
            .proof
            .expect("optional explicit-empty task is done");
        let no_op = VerifiedNoOpReceipt {
            contract_version: CONTRACT_VERSION,
            receipt_id: "verified-no-op-v22-optional".into(),
            sprint_id: fixture.candidate.spec.sprint_id.clone(),
            final_verification_receipt_id: fixture.final_evidence.verification.receipt_id.clone(),
            base_snapshot: fixture.candidate.spec.base_snapshot.clone(),
            live_manifest_digest: fixture.candidate.spec.base_snapshot.clone(),
            grant_hash: fixture.candidate.spec.workspace_grant.grant_hash.clone(),
            policy_version: fixture.candidate.spec.workspace_grant.policy_version,
            observed_at_unix_ms: 2_400,
        };
        fixture
            .candidate
            .ledger
            .persist_verified_no_op_receipt(&no_op)
            .expect("persist optional explicit-empty no-op proof");
        let acceptance = AcceptanceReceipt {
            receipt_id: "acceptance-v22-optional-no-op".into(),
            sprint_id: fixture.candidate.spec.sprint_id.clone(),
            criterion_id: "tests".into(),
            snapshot_id: fixture.candidate.spec.base_snapshot.clone(),
            evidence: AcceptanceEvidence::Automated {
                verification_receipt_id: fixture.final_evidence.verification.receipt_id.clone(),
            },
            accepted_at_unix_ms: 2_450,
        };
        fixture
            .candidate
            .ledger
            .persist_acceptance_receipt(&acceptance)
            .expect("persist optional no-op acceptance");
        let body = "Optional explicit-empty TaskDone was retained as no-op authority.".to_owned();
        let report = FinalReport {
            report_id: "report-v22-optional-no-op".into(),
            sprint_id: fixture.candidate.spec.sprint_id.clone(),
            final_snapshot: fixture.candidate.spec.base_snapshot.clone(),
            content_digest: FinalReport::digest_body(&body),
            body,
            created_at_unix_ms: 2_500,
        };
        let mut cleanup_ids = vec![
            "cleanup-v22-explicit-empty-worker".into(),
            "cleanup-v22-explicit-empty-final".into(),
        ];
        cleanup_ids.sort();
        let mut verification_ids = proof
            .integration_receipt
            .task_verification_receipt_ids
            .clone();
        verification_ids.push(fixture.final_evidence.verification.receipt_id.clone());
        verification_ids.sort();
        let receipt = CompletionReceipt {
            contract_version: CONTRACT_VERSION,
            receipt_id: "completion-v22-optional-no-op".into(),
            sprint_id: fixture.candidate.spec.sprint_id.clone(),
            grant_hash: fixture.candidate.spec.workspace_grant.grant_hash.clone(),
            policy_version: fixture.candidate.spec.workspace_grant.policy_version,
            final_snapshot: fixture.candidate.spec.base_snapshot.clone(),
            final_verification_receipt_id: fixture.final_evidence.verification.receipt_id.clone(),
            application: CompletionApplication::VerifiedNoOp {
                verified_no_op_receipt_id: no_op.receipt_id.clone(),
            },
            worker_cleanup_receipt_ids: cleanup_ids,
            satisfied_criterion_ids: vec!["tests".into()],
            criterion_evidence_receipt_ids: vec![acceptance.receipt_id.clone()],
            task_integration_receipt_ids: vec![proof.integration_receipt.receipt_id.clone()],
            verification_receipts: verification_ids,
            provider_backend: fixture.candidate.spec.provider.backend_id.clone(),
            provider_model: fixture.candidate.spec.provider.model_id.clone(),
            final_report_id: report.report_id.clone(),
            completed_at_unix_ms: 2_600,
        };
        let event = AgentEvent {
            contract_version: CONTRACT_VERSION,
            sequence: fixture
                .candidate
                .ledger
                .next_sequence(&receipt.sprint_id)
                .expect("optional no-op completion sequence"),
            event_id: "event-v22-optional-no-op-completed".into(),
            sprint_id: receipt.sprint_id.clone(),
            task_id: None,
            worker_id: None,
            causation_id: None,
            correlation_id: "v22-optional-no-op-completion".into(),
            policy_hash: None,
            occurred_at_unix_ms: receipt.completed_at_unix_ms,
            payload: AgentEventKind::CompletionRecorded(receipt.receipt_id.clone()),
        };
        let assessment = fixture
            .candidate
            .ledger
            .assess_completion_eligibility(&report, &receipt, &event)
            .expect("assess optional no-op completion");
        assert!(!assessment.is_eligible());
        assert!(assessment.unmet_requirements.contains(
            &CompletionEligibilityRequirement::VerifiedNoOpLiveManifestCaptureAuthorized
        ));
        assert!(
            assessment
                .unmet_requirements
                .contains(&CompletionEligibilityRequirement::ApplicationOrVerifiedNoOpExact)
        );
        let mut omitted_optional = receipt.clone();
        omitted_optional.task_integration_receipt_ids.clear();
        let omitted = fixture
            .candidate
            .ledger
            .assess_completion_eligibility(&report, &omitted_optional, &event)
            .expect("diagnose omitted optional no-op TaskDone");
        assert!(
            omitted
                .unmet_requirements
                .contains(&CompletionEligibilityRequirement::AllIntegratedTasksDoneAndLinked)
        );
        let error = fixture
            .candidate
            .ledger
            .record_successful_completion(&report, &receipt, &event)
            .expect_err("caller-populated no-op manifest cannot atomically complete");
        assert!(matches!(
            error,
            LedgerError::ReferenceMismatch {
                entity: "verified no-op live-manifest capture authority",
                ..
            }
        ));
        assert_no_completion_writes(&fixture.candidate.ledger);
    }

    #[cfg(unix)]
    #[test]
    fn v22_postcommit_application_uncertainty_returns_no_retry_custody_and_reopens() {
        let mut fixture = prepare_v22_application_admission_fixture();
        let terminal = v22_application_terminal_fixture(&fixture);
        let (_, transport) = fixture
            .candidate
            .ledger
            .claim_runner_effect_dispatch(
                FreshRunnerEffectDispatchPermit::SprintApplication(
                    fixture
                        .permit
                        .take()
                        .expect("claim postcommit v22 application permit"),
                ),
                OPAQUE_RUNNER_TRANSPORT_REQUEST_BYTES,
            )
            .expect("claim postcommit v22 application");
        let authority = transport
            .validate_transport_request(
                &fixture.intent,
                &fixture.request_bytes,
                &fixture.applier_launch,
                &fixture.applier_session,
                None,
                OPAQUE_RUNNER_TRANSPORT_REQUEST_BYTES,
            )
            .expect("validate postcommit v22 application transport");
        let hardlink = fixture
            .candidate
            .database
            .directory
            .join("v22-application-postcommit-hardlink.sqlite3");
        fs::hard_link(&fixture.candidate.database.path, &hardlink)
            .expect("inject v22 application postcommit hardening fault");
        let failure = fixture
            .candidate
            .ledger
            .record_claimed_application_effect_observation_with_rollback(
                authority,
                &terminal.observation,
                &terminal.event,
                &terminal.evidence,
                &terminal.rollback,
            )
            .expect_err("postcommit application hardening uncertainty must surface");
        fs::remove_file(&hardlink).expect("remove v22 application hardening fault");
        assert!(matches!(
            failure.error(),
            LedgerError::PostCommitStateUncertain {
                operation: "claimed application observation",
                recovery_id,
                ..
            } if recovery_id == &fixture.intent.effect_id
        ));
        assert!(!failure.has_retry_authority());
        assert!(failure.into_parts().1.is_none());
        assert_eq!(
            fixture
                .candidate
                .ledger
                .load_application_evidence(&terminal.receipt.receipt_id)
                .expect("reconcile committed v22 application evidence"),
            terminal.evidence
        );
        assert_eq!(
            fixture
                .candidate
                .ledger
                .load_rollback_reference(&terminal.rollback.reference.reference_id)
                .expect("reconcile committed v22 rollback reference"),
            terminal.rollback
        );
        assert_eq!(
            fixture
                .candidate
                .ledger
                .load_effect(&fixture.intent.effect_id)
                .expect("reconcile committed v22 application effect")
                .observation,
            Some(terminal.observation)
        );
    }

    #[test]
    fn v22_migration_preserves_v21_apply_as_historical_and_fences_new_unadmitted_apply() {
        let database = TestDatabase::new();
        let historical = {
            let mut ledger = open_v21_test_ledger(&database);
            let pending = prepare_pending_application(&mut ledger);
            assert_eq!(
                ledger
                    .connection
                    .pragma_query_value(None, "user_version", |row| row.get::<_, i64>(0))
                    .expect("read v21 schema version"),
                21
            );
            pending
        };
        let mut migrated = EventLedger::open(&database.path).expect("migrate v21 Apply to v22");
        assert_eq!(
            migrated
                .connection
                .pragma_query_value(None, "user_version", |row| row.get::<_, i64>(0))
                .expect("read migrated v22 schema version"),
            SCHEMA_VERSION
        );
        let restored = migrated
            .load_effect(&historical.intent.effect_id)
            .expect("reload historical v21 Apply after v22 migration");
        assert_eq!(restored.intent, historical.intent);
        assert!(restored.dispatch_claim.is_none());
        assert!(matches!(
            migrated.load_sprint_application_admission("missing-v21-application-admission"),
            Err(LedgerError::ArtifactNotFound { .. })
        ));
        for schema_name in [
            "application_artifact_assemblies",
            "application_artifact_assembly_sources",
            "sprint_application_admissions",
            "pre_v22_completion_authority_exemptions",
            "effect_intents_v22_application_admission_required",
            "sprint_completion_task_attempt_predicate",
        ] {
            assert!(
                migrated
                    .connection
                    .query_row(
                        "SELECT 1 FROM sqlite_schema WHERE name = ?1",
                        [schema_name],
                        |_| Ok(()),
                    )
                    .optional()
                    .expect("query v22 schema guard")
                    .is_some()
            );
        }

        let mut unadmitted_intent = historical.intent.clone();
        unadmitted_intent.effect_id = "effect-v22-unadmitted-apply".into();
        unadmitted_intent.idempotency_key = "key-v22-unadmitted-apply".into();
        unadmitted_intent.correlation_id = "correlation-v22-unadmitted-apply".into();
        unadmitted_intent.created_at_unix_ms += 1;
        let proposal = effect_proposal_event(
            &unadmitted_intent,
            migrated
                .next_sequence(&unadmitted_intent.sprint_id)
                .expect("unadmitted v22 Apply sequence"),
            "event-v22-unadmitted-apply-proposed",
        );
        assert!(
            migrated
                .record_runner_effect_intent(
                    &unadmitted_intent,
                    &historical.request_bytes,
                    &proposal,
                    &historical.executor_launch.session_id,
                )
                .is_err()
        );
        assert!(matches!(
            migrated.load_effect(&unadmitted_intent.effect_id),
            Err(LedgerError::ArtifactNotFound { .. })
        ));
    }

    #[test]
    fn v22_migration_marks_only_already_completed_v21_proof_as_exempt() {
        let database = TestDatabase::new();
        let expected = {
            let mut ledger = open_v21_test_ledger(&database);
            let (report, receipt, event) = prepare_completion_evidence(&mut ledger);
            record_pre_v24_successful_completion_for_test(&mut ledger, &report, &receipt, &event)
                .expect("record exact v21 completion before migration")
        };
        let migrated = EventLedger::open(&database.path).expect("migrate completed v21 ledger");
        let completed = load_migrated_pre_v24_completion(&migrated, &expected);
        assert_eq!(
            migrated
                .connection
                .query_row(
                    "SELECT completion_receipt_id
                     FROM pre_v22_completion_authority_exemptions
                     WHERE sprint_id = ?1",
                    [&completed.receipt.sprint_id],
                    |row| row.get::<_, String>(0),
                )
                .expect("load migration-only v22 completion exemption"),
            completed.receipt.receipt_id
        );
        assert!(
            migrated
                .connection
                .execute(
                    "INSERT INTO pre_v22_completion_authority_exemptions (
                    sprint_id, completion_receipt_id, completion_event_id,
                    marked_at_schema_version
                 ) VALUES ('forged', 'forged', 'forged', 22)",
                    [],
                )
                .is_err()
        );
    }

    #[test]
    fn v22_migration_sql_immutability_and_apply_admission_fence_survive_reopen() {
        let mut fixture = prepare_v22_application_admission_fixture();
        drop(
            fixture
                .permit
                .take()
                .expect("discard v22 immutability fixture permit"),
        );
        for statement in [
            "UPDATE application_artifact_assemblies SET assembly_id = assembly_id",
            "DELETE FROM application_artifact_assemblies",
            "UPDATE application_artifact_assembly_sources SET task_id = task_id",
            "DELETE FROM application_artifact_assembly_sources",
            "UPDATE sprint_application_admissions SET admission_id = admission_id",
            "DELETE FROM sprint_application_admissions",
        ] {
            assert!(
                fixture
                    .candidate
                    .ledger
                    .connection
                    .execute_batch(statement)
                    .is_err()
            );
        }

        let mut forged = fixture.intent.clone();
        forged.effect_id = "effect-v22-raw-unadmitted-apply".into();
        forged.idempotency_key = "key-v22-raw-unadmitted-apply".into();
        forged.correlation_id = "correlation-v22-raw-unadmitted-apply".into();
        forged.created_at_unix_ms += 1;
        let forged_request = fixture.request_bytes.clone();
        let proposal = effect_proposal_event(
            &forged,
            fixture
                .candidate
                .ledger
                .next_sequence(&forged.sprint_id)
                .expect("raw unadmitted Apply sequence"),
            "event-v22-raw-unadmitted-apply-proposed",
        );
        let transaction = fixture
            .candidate
            .ledger
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .expect("start raw unadmitted v22 Apply");
        insert_agent_event(&transaction, &proposal).expect("insert raw Apply proposal");
        insert_effect_request_payload(&transaction, &forged, &forged_request)
            .expect("insert raw Apply request");
        insert_finish_effect_kind(&transaction, &forged).expect("insert raw Apply finish kind");
        application_artifact_authority::insert_application_request_artifact_authority(
            &transaction,
            &forged,
            &fixture.request,
            &forged_request,
        )
        .expect("insert raw Apply artifact authority");
        transaction
            .execute(
                "INSERT INTO effect_session_bindings (
                    effect_id, sprint_id, launch_id, session_id, contract_version
                 ) VALUES (?1, ?2, ?3, ?4, ?5)",
                params![
                    forged.effect_id,
                    forged.sprint_id,
                    fixture.applier_launch.launch_id,
                    fixture.applier_session.session_id,
                    i64::from(CONTRACT_VERSION),
                ],
            )
            .expect("insert raw Apply session binding");
        assert!(
            insert_effect_intent(&transaction, &forged, &proposal.event_id).is_err(),
            "all raw Apply intents require their exact atomic v22 admission"
        );
        transaction
            .rollback()
            .expect("roll back raw unadmitted Apply");
        assert!(matches!(
            fixture.candidate.ledger.load_effect(&forged.effect_id),
            Err(LedgerError::ArtifactNotFound { .. })
        ));

        let V22ApplicationAdmissionFixture { candidate, .. } = fixture;
        let V15CandidateFixture {
            database, ledger, ..
        } = candidate;
        let path = database.path.clone();
        drop(ledger);
        let reopened = EventLedger::open(&path).expect("reopen v22 immutable admission ledger");
        assert!(
            reopened
                .connection
                .execute_batch(
                    "UPDATE sprint_application_admissions SET admission_id = admission_id"
                )
                .is_err()
        );
    }

    #[test]
    #[allow(clippy::too_many_lines)] // Claimless bypass, typed failure custody, and exact retry are one terminal-boundary proof.
    fn v21_claimed_final_terminal_rejects_claimless_and_preserves_precommit_retry_custody() {
        let database = TestDatabase::new();
        let mut ledger = open_v21_test_ledger(&database);
        let fixture = prepare_v21_final_verification_fixture(&mut ledger);
        let SprintFinalVerificationDispatchAdmission::Fresh { permit, .. } = ledger
            .admit_sprint_final_verification_for_dispatch(
                &fixture.admission,
                &fixture.phase_event,
                &fixture.intent,
                &fixture.proposed_event,
            )
            .expect("admit v21 claimed final")
        else {
            panic!("new v21 admission must be Fresh");
        };
        let (claimed, transport) = ledger
            .claim_runner_effect_dispatch(
                FreshRunnerEffectDispatchPermit::SprintFinalVerification(permit),
                OPAQUE_RUNNER_TRANSPORT_REQUEST_BYTES,
            )
            .expect("claim v21 final transport");
        assert!(matches!(
            claimed
                .dispatch_claim
                .as_ref()
                .map(|claim| &claim.authority),
            Some(RunnerEffectRequestAuthority::SprintFinalVerification { sprint_phase_event_id })
                if sprint_phase_event_id == &fixture.phase_event.event_id
        ));
        let authority = transport
            .validate_transport_request(
                &fixture.intent,
                &fixture.command_bytes,
                &fixture.launch,
                &fixture.session,
                None,
                OPAQUE_RUNNER_TRANSPORT_REQUEST_BYTES,
            )
            .expect("validate exact v21 transport bytes");
        let (observation, event, evidence) = v21_final_verification_terminal(&ledger, &fixture);

        assert!(matches!(
            ledger.record_verification_effect_observation(&observation, &event, &evidence),
            Err(LedgerError::ReferenceMismatch {
                entity: "verification effect observation",
                ..
            })
        ));
        assert!(
            ledger
                .load_effect(&fixture.intent.effect_id)
                .expect("load still-unobserved claimed final")
                .observation
                .is_none()
        );

        ledger
            .connection
            .execute_batch(
                "CREATE TRIGGER v21_test_late_verification_failure
                 BEFORE INSERT ON verification_effect_evidence
                 BEGIN SELECT RAISE(ABORT, 'injected v21 verification evidence failure'); END;",
            )
            .expect("install v21 late precommit fault");
        let failure = ledger
            .record_claimed_final_verification_effect_observation(
                authority,
                &observation,
                &event,
                &evidence,
            )
            .expect_err("late verification insert must roll back");
        assert!(failure.has_retry_authority());
        let (_, retry_authority) = failure.into_parts();
        let retry_authority = retry_authority.expect("definite precommit failure returns custody");
        assert_eq!(row_count(&ledger, "verification_effect_evidence"), 2);
        assert!(
            ledger
                .load_effect(&fixture.intent.effect_id)
                .expect("load rolled-back v21 final")
                .observation
                .is_none()
        );
        ledger
            .connection
            .execute_batch("DROP TRIGGER v21_test_late_verification_failure;")
            .expect("remove v21 precommit fault");

        let persisted = ledger
            .record_claimed_final_verification_effect_observation(
                retry_authority,
                &observation,
                &event,
                &evidence,
            )
            .expect("retry exact v21 claimed final terminal");
        assert_eq!(persisted.observation.as_ref(), Some(&observation));
        assert_eq!(persisted.terminal_event.as_ref(), Some(&event));
        assert_eq!(
            persisted
                .dispatch_claim
                .as_ref()
                .map(|claim| claim.dispatch_claim_id.as_str()),
            Some(runner_effect_dispatch_claim_id(&fixture.intent.effect_id).as_str())
        );
        assert_eq!(
            ledger
                .load_verification_effect_evidence(&evidence.verification.receipt_id)
                .expect("reload claimed v21 evidence"),
            evidence
        );
    }

    #[test]
    fn v21_final_phase_freezes_task_events_and_running_race_invalidates_fresh_permit() {
        let database = TestDatabase::new();
        let mut ledger = open_v21_test_ledger(&database);
        let fixture = prepare_v21_final_verification_fixture(&mut ledger);
        let SprintFinalVerificationDispatchAdmission::Fresh { permit, .. } = ledger
            .admit_sprint_final_verification_for_dispatch(
                &fixture.admission,
                &fixture.phase_event,
                &fixture.intent,
                &fixture.proposed_event,
            )
            .expect("admit v21 phase-race final")
        else {
            panic!("new phase-race admission must be Fresh");
        };
        let frozen_task_event = AgentEvent {
            contract_version: CONTRACT_VERSION,
            sequence: ledger.next_sequence("sprint-1").expect("frozen sequence"),
            event_id: "event-v21-frozen-task".into(),
            sprint_id: "sprint-1".into(),
            task_id: Some("task-1".into()),
            worker_id: None,
            causation_id: None,
            correlation_id: "correlation-v21-frozen".into(),
            policy_hash: None,
            occurred_at_unix_ms: 2_220,
            payload: AgentEventKind::Diagnostic("must remain frozen".into()),
        };
        assert!(ledger.append_event(&frozen_task_event).is_err());

        let return_to_running = AgentEvent {
            task_id: None,
            event_id: "event-v21-return-running".into(),
            correlation_id: fixture.intent.correlation_id.clone(),
            policy_hash: Some(fixture.intent.policy_hash.clone()),
            occurred_at_unix_ms: 2_230,
            payload: AgentEventKind::SprintStateChanged {
                from: "FinalVerification".into(),
                to: "Running".into(),
            },
            ..frozen_task_event
        };
        ledger
            .append_event(&return_to_running)
            .expect("unclaimed final phase may return to Running");
        assert!(
            ledger
                .claim_runner_effect_dispatch(
                    FreshRunnerEffectDispatchPermit::SprintFinalVerification(permit),
                    OPAQUE_RUNNER_TRANSPORT_REQUEST_BYTES,
                )
                .is_err(),
            "stale fresh permit must not survive a phase race"
        );
        assert!(
            ledger
                .load_effect(&fixture.intent.effect_id)
                .expect("load phase-raced final effect")
                .dispatch_claim
                .is_none()
        );
    }

    #[test]
    fn v21_claimed_final_generic_success_requires_typed_receipt() {
        let database = TestDatabase::new();
        let mut ledger = open_v21_test_ledger(&database);
        let fixture = prepare_v21_final_verification_fixture(&mut ledger);
        let SprintFinalVerificationDispatchAdmission::Fresh { permit, .. } = ledger
            .admit_sprint_final_verification_for_dispatch(
                &fixture.admission,
                &fixture.phase_event,
                &fixture.intent,
                &fixture.proposed_event,
            )
            .expect("admit v21 generic-success final")
        else {
            panic!("new generic-success admission must be Fresh");
        };
        let (_, transport) = ledger
            .claim_runner_effect_dispatch(
                FreshRunnerEffectDispatchPermit::SprintFinalVerification(permit),
                OPAQUE_RUNNER_TRANSPORT_REQUEST_BYTES,
            )
            .expect("claim v21 generic-success transport");
        let authority = transport
            .validate_transport_request(
                &fixture.intent,
                &fixture.command_bytes,
                &fixture.launch,
                &fixture.session,
                None,
                OPAQUE_RUNNER_TRANSPORT_REQUEST_BYTES,
            )
            .expect("validate v21 generic-success transport");
        let (observation, event, evidence) = v21_final_verification_terminal(&ledger, &fixture);
        let evidence_bytes = encode("verification effect evidence", &evidence)
            .expect("encode v21 generic-success evidence");
        let observation_count = row_count(&ledger, "effect_observations");
        let verification_evidence_count = row_count(&ledger, "verification_effect_evidence");
        let failure = ledger
            .try_record_claimed_effect_observation(authority, &observation, &evidence_bytes, &event)
            .expect_err("generic success cannot terminalize claimed final authority");
        assert!(matches!(
            failure.error(),
            LedgerError::FinishReceiptRequired {
                effect_id,
                kind: EffectKind::RunCommand,
            } if effect_id == &fixture.intent.effect_id
        ));
        assert!(failure.has_retry_authority());
        assert_eq!(row_count(&ledger, "effect_observations"), observation_count);
        assert_eq!(
            row_count(&ledger, "verification_effect_evidence"),
            verification_evidence_count
        );
        let (_, authority) = failure.into_parts();
        ledger
            .record_claimed_final_verification_effect_observation(
                authority.expect("typed final path retains precommit custody"),
                &observation,
                &event,
                &evidence,
            )
            .expect("typed verification receipt remains the sole successful terminal path");
    }

    #[test]
    #[allow(clippy::too_many_lines)] // Every sprint phase and post-Unknown task-work path is checked against one live claim.
    fn v21_unobserved_claim_blocks_every_phase_and_unknown_terminal_fences_task_work() {
        let database = TestDatabase::new();
        let mut ledger = open_v21_test_ledger(&database);
        let fixture = prepare_v21_final_verification_fixture(&mut ledger);
        let SprintFinalVerificationDispatchAdmission::Fresh { permit, .. } = ledger
            .admit_sprint_final_verification_for_dispatch(
                &fixture.admission,
                &fixture.phase_event,
                &fixture.intent,
                &fixture.proposed_event,
            )
            .expect("admit v21 claim-fence final")
        else {
            panic!("new claim-fence admission must be Fresh");
        };
        let (_, transport) = ledger
            .claim_runner_effect_dispatch(
                FreshRunnerEffectDispatchPermit::SprintFinalVerification(permit),
                OPAQUE_RUNNER_TRANSPORT_REQUEST_BYTES,
            )
            .expect("claim v21 phase-fence transport");
        let authority = transport
            .validate_transport_request(
                &fixture.intent,
                &fixture.command_bytes,
                &fixture.launch,
                &fixture.session,
                None,
                OPAQUE_RUNNER_TRANSPORT_REQUEST_BYTES,
            )
            .expect("validate claimed v21 phase-fence transport");
        let mut contender = open_v21_test_ledger(&database);
        let sequence = contender
            .next_sequence("sprint-1")
            .expect("claimed phase movement sequence");
        let known = AgentEvent {
            contract_version: CONTRACT_VERSION,
            sequence,
            event_id: "event-v21-claimed-running".into(),
            sprint_id: "sprint-1".into(),
            task_id: None,
            worker_id: None,
            causation_id: Some(fixture.phase_event.event_id.clone()),
            correlation_id: fixture.intent.correlation_id.clone(),
            policy_hash: Some(fixture.intent.policy_hash.clone()),
            occurred_at_unix_ms: 2_240,
            payload: AgentEventKind::SprintStateChanged {
                from: "FinalVerification".into(),
                to: "Running".into(),
            },
        };
        assert!(contender.append_event(&known).is_err());
        let unknown = AgentEvent {
            event_id: "event-v21-claimed-unknown".into(),
            payload: AgentEventKind::SprintStateChanged {
                from: "FinalVerification".into(),
                to: "Unknown".into(),
            },
            ..known
        };
        assert!(
            contender.append_event(&unknown).is_err(),
            "an unresolved final claim cannot escape through a phase-level Unknown"
        );

        let claimed_phase_lease = WorkerLease::new(
            "sprint-1".into(),
            2,
            "task-1".into(),
            "worker-v21-during-final".into(),
            vec![PathScope::Workspace],
            2_250,
        )
        .expect("construct lease during claimed FinalVerification");
        let claimed_phase_acquisition = AgentEvent {
            contract_version: CONTRACT_VERSION,
            sequence: contender
                .next_sequence("sprint-1")
                .expect("claimed-phase lease sequence"),
            event_id: "event-v21-lease-during-final".into(),
            sprint_id: "sprint-1".into(),
            task_id: Some("task-1".into()),
            worker_id: Some("worker-v21-during-final".into()),
            causation_id: None,
            correlation_id: "correlation-v21-lease-during-final".into(),
            policy_hash: None,
            occurred_at_unix_ms: claimed_phase_lease.acquired_at_unix_ms,
            payload: AgentEventKind::TaskStateChanged {
                from: "Ready".into(),
                to: "Leased".into(),
            },
        };
        assert!(matches!(
            contender.acquire_task_attempt(&claimed_phase_lease, &claimed_phase_acquisition),
            Err(LedgerError::ReferenceMismatch {
                entity: "worker lease acquisition",
                detail,
            }) if detail.contains("current sprint phase Running")
        ));
        let claimed_phase_policy = compiled_shadow_test_policy("policy-v21-during-final");
        let mut claimed_phase_launch = runner_launch(
            "launch-v21-during-final",
            "session-v21-during-final",
            RunnerSessionPurpose::TaskWorker,
            Some("worker-v21-during-final"),
            &claimed_phase_policy,
            2_260,
        );
        claimed_phase_launch.worker_lease = Some(claimed_phase_lease.clone());
        let (claimed_phase_cleanup, _, claimed_phase_cleanup_bytes, claimed_phase_cleanup_event) =
            test_runner_launch_cleanup_contracts(
                &contender,
                &claimed_phase_launch,
                WorkerCleanupBackend::LinuxCgroupV2,
            )
            .expect("build claimed-phase launch cleanup contract");
        assert!(matches!(
            contender.admit_runner_launch_with_cleanup(
                &claimed_phase_launch,
                &claimed_phase_policy,
                &claimed_phase_cleanup,
                &claimed_phase_cleanup_bytes,
                &claimed_phase_cleanup_event,
            ),
            Err(LedgerError::ReferenceMismatch {
                entity: "task-worker launch admission",
                detail,
            }) if detail.contains("current sprint phase Running")
        ));
        let claimed_phase_request = b"task effect during claimed FinalVerification".to_vec();
        let claimed_phase_intent = EffectIntent {
            contract_version: CONTRACT_VERSION,
            effect_id: "effect-v21-during-final".into(),
            idempotency_key: "key-v21-during-final".into(),
            sprint_id: "sprint-1".into(),
            task_id: Some("task-1".into()),
            worker_id: Some("worker-v21-during-final".into()),
            worker_lease: Some(claimed_phase_lease),
            causation_event_id: None,
            correlation_id: "correlation-v21-effect-during-final".into(),
            kind: EffectKind::ProviderRequest,
            request_digest: Digest::sha256(&claimed_phase_request),
            policy_hash: claimed_phase_policy.contract().policy_hash.clone(),
            input_snapshot: fixture.admission.final_snapshot.clone(),
            created_at_unix_ms: 2_270,
        };
        let claimed_phase_proposal = effect_proposal_event(
            &claimed_phase_intent,
            contender
                .next_sequence("sprint-1")
                .expect("claimed-phase effect sequence"),
            "event-v21-effect-during-final-proposed",
        );
        assert!(matches!(
            contender.record_effect_intent(
                &claimed_phase_intent,
                &claimed_phase_request,
                &claimed_phase_proposal,
            ),
            Err(LedgerError::ReferenceMismatch {
                entity: "task or worker effect intent",
                detail,
            }) if detail.contains("current sprint phase Running")
        ));

        let terminal = SprintTerminalEvidence {
            contract_version: CONTRACT_VERSION,
            record_id: "terminal-v21-claimed-unknown".into(),
            sprint_id: fixture.intent.sprint_id.clone(),
            state: NonSuccessTerminalState::Unknown,
            reason: "final-verification dispatch may have started and has no terminal evidence"
                .into(),
            terminal_at_unix_ms: 2_400,
        };
        ledger
            .record_unsuccessful_terminal_outcome(&terminal)
            .expect("truthful Unknown uses the atomic terminal boundary");
        let frozen_task = AgentEvent {
            contract_version: CONTRACT_VERSION,
            sequence: ledger
                .next_sequence("sprint-1")
                .expect("terminal task sequence"),
            event_id: "event-v21-task-after-unknown-terminal".into(),
            sprint_id: "sprint-1".into(),
            task_id: Some("task-1".into()),
            worker_id: None,
            causation_id: Some(terminal.record_id.clone()),
            correlation_id: "correlation-v21-task-after-unknown".into(),
            policy_hash: None,
            occurred_at_unix_ms: 2_410,
            payload: AgentEventKind::Diagnostic(
                "task work must remain fenced after truthful Unknown".into(),
            ),
        };
        assert!(matches!(
            contender.append_event(&frozen_task),
            Err(LedgerError::SprintAlreadyTerminal(sprint_id)) if sprint_id == "sprint-1"
        ));

        let late_lease = WorkerLease::new(
            "sprint-1".into(),
            2,
            "task-1".into(),
            "worker-v21-after-unknown".into(),
            vec![PathScope::Workspace],
            2_420,
        )
        .expect("construct post-Unknown lease attempt");
        let late_acquisition = AgentEvent {
            contract_version: CONTRACT_VERSION,
            sequence: contender
                .next_sequence("sprint-1")
                .expect("post-Unknown lease sequence"),
            event_id: "event-v21-lease-after-unknown".into(),
            sprint_id: "sprint-1".into(),
            task_id: Some("task-1".into()),
            worker_id: Some("worker-v21-after-unknown".into()),
            causation_id: None,
            correlation_id: "correlation-v21-lease-after-unknown".into(),
            policy_hash: None,
            occurred_at_unix_ms: late_lease.acquired_at_unix_ms,
            payload: AgentEventKind::TaskStateChanged {
                from: "Ready".into(),
                to: "Leased".into(),
            },
        };
        assert!(matches!(
            contender.acquire_task_attempt(&late_lease, &late_acquisition),
            Err(LedgerError::SprintAlreadyTerminal(sprint_id)) if sprint_id == "sprint-1"
        ));

        let late_policy = compiled_shadow_test_policy("policy-v21-after-unknown");
        let mut late_launch = runner_launch(
            "launch-v21-after-unknown",
            "session-v21-after-unknown",
            RunnerSessionPurpose::TaskWorker,
            Some("worker-v21-after-unknown"),
            &late_policy,
            2_430,
        );
        late_launch.worker_lease = Some(late_lease);
        let (late_cleanup, _, late_cleanup_bytes, late_cleanup_event) =
            test_runner_launch_cleanup_contracts(
                &contender,
                &late_launch,
                WorkerCleanupBackend::LinuxCgroupV2,
            )
            .expect("build post-Unknown launch cleanup contract");
        assert!(matches!(
            contender.admit_runner_launch_with_cleanup(
                &late_launch,
                &late_policy,
                &late_cleanup,
                &late_cleanup_bytes,
                &late_cleanup_event,
            ),
            Err(LedgerError::SprintAlreadyTerminal(sprint_id)) if sprint_id == "sprint-1"
        ));

        let late_request = b"provider request after truthful Unknown".to_vec();
        let late_intent = EffectIntent {
            contract_version: CONTRACT_VERSION,
            effect_id: "effect-v21-after-unknown".into(),
            idempotency_key: "key-v21-after-unknown".into(),
            sprint_id: "sprint-1".into(),
            task_id: None,
            worker_id: None,
            worker_lease: None,
            causation_event_id: None,
            correlation_id: "correlation-v21-effect-after-unknown".into(),
            kind: EffectKind::ProviderRequest,
            request_digest: Digest::sha256(&late_request),
            policy_hash: fixture.intent.policy_hash.clone(),
            input_snapshot: fixture.admission.final_snapshot.clone(),
            created_at_unix_ms: 2_440,
        };
        let late_proposal = effect_proposal_event(
            &late_intent,
            contender
                .next_sequence("sprint-1")
                .expect("post-Unknown effect sequence"),
            "event-v21-effect-after-unknown-proposed",
        );
        assert!(matches!(
            contender.record_effect_intent(&late_intent, &late_request, &late_proposal),
            Err(LedgerError::SprintAlreadyTerminal(sprint_id)) if sprint_id == "sprint-1"
        ));
        drop(authority);
    }

    #[test]
    #[allow(clippy::too_many_lines)] // The complete non-Running phase matrix shares one canonical task/worker fixture.
    fn v21_every_non_running_phase_fences_task_events_and_late_task_worker_sessions() {
        let database = TestDatabase::new();
        let mut ledger = open_v21_test_ledger(&database);
        let (policy, launch, cleanup, _, cleanup_bytes, cleanup_event) =
            prepare_test_launch_admission(
                &mut ledger,
                "v21-phase-only",
                RunnerSessionPurpose::TaskWorker,
                Some("worker-1"),
                WorkerCleanupBackend::LinuxCgroupV2,
            );
        ledger
            .admit_runner_launch_with_cleanup(
                &launch,
                &policy,
                &cleanup,
                &cleanup_bytes,
                &cleanup_event,
            )
            .expect("admit uninitialized task-worker launch while Running");

        let phase_event = |ledger: &EventLedger,
                           from: &str,
                           to: &str,
                           event_id: &str,
                           occurred_at_unix_ms: u64| AgentEvent {
            contract_version: CONTRACT_VERSION,
            sequence: ledger
                .next_sequence("sprint-1")
                .expect("phase-only sprint sequence"),
            event_id: event_id.into(),
            sprint_id: "sprint-1".into(),
            task_id: None,
            worker_id: None,
            causation_id: None,
            correlation_id: "correlation-v21-phase-only".into(),
            policy_hash: None,
            occurred_at_unix_ms,
            payload: AgentEventKind::SprintStateChanged {
                from: from.into(),
                to: to.into(),
            },
        };
        let task_event =
            |ledger: &EventLedger, event_id: &str, occurred_at_unix_ms: u64| AgentEvent {
                contract_version: CONTRACT_VERSION,
                sequence: ledger
                    .next_sequence("sprint-1")
                    .expect("phase-only task sequence"),
                event_id: event_id.into(),
                sprint_id: "sprint-1".into(),
                task_id: Some("task-1".into()),
                worker_id: Some("worker-1".into()),
                causation_id: None,
                correlation_id: "correlation-v21-phase-only-task".into(),
                policy_hash: Some(launch.policy_hash.clone()),
                occurred_at_unix_ms,
                payload: AgentEventKind::Diagnostic(
                    "non-Running sprint phase must freeze task work".into(),
                ),
            };

        ledger
            .append_event(&phase_event(
                &ledger,
                "Running",
                "AwaitingAcceptance",
                "event-v21-awaiting-acceptance",
                1_300,
            ))
            .expect("enter phase-only AwaitingAcceptance");
        assert!(
            ledger
                .append_event(&task_event(&ledger, "event-v21-task-awaiting", 1_310))
                .is_err(),
            "AwaitingAcceptance must reject generic task/worker events"
        );
        let session = runner_session(&launch, 1_400);
        assert!(matches!(
            ledger.register_runner_session(&session, &policy),
            Err(LedgerError::ReferenceMismatch {
                entity: "task-worker session registration",
                detail,
            }) if detail.contains("current sprint phase Running")
        ));
        let transaction = ledger
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .expect("begin raw late-session insertion");
        let raw_session_error =
            insert_runner_session_policy(&transaction, &session, policy.contract())
                .expect_err("direct SQL cannot register a TaskWorker session outside Running");
        assert!(
            raw_session_error
                .to_string()
                .contains("task-worker session requires current sprint phase Running")
        );
        transaction
            .rollback()
            .expect("roll back raw late-session insertion");

        assert!(matches!(
            ledger.append_event(&phase_event(
                &ledger,
                "AwaitingAcceptance",
                "FinalVerification",
                "event-v21-forbidden-orphan-final",
                1_315,
            )),
            Err(LedgerError::ReferenceMismatch {
                entity: "agent event",
                detail,
            }) if detail.contains("every transition into FinalVerification")
        ));
        ledger
            .append_event(&phase_event(
                &ledger,
                "AwaitingAcceptance",
                "Running",
                "event-v21-return-running",
                1_320,
            ))
            .expect("return from AwaitingAcceptance to Running");

        let applying_database = TestDatabase::new();
        let mut applying_ledger = open_v21_test_ledger(&applying_database);
        let applying_fixture = prepare_v21_final_verification_fixture(&mut applying_ledger);
        let SprintFinalVerificationDispatchAdmission::Fresh { permit, .. } = applying_ledger
            .admit_sprint_final_verification_for_dispatch(
                &applying_fixture.admission,
                &applying_fixture.phase_event,
                &applying_fixture.intent,
                &applying_fixture.proposed_event,
            )
            .expect("admit proper v21 final authority before Applying")
        else {
            panic!("proper Applying fixture must mint a fresh final permit");
        };
        let (_, transport) = applying_ledger
            .claim_runner_effect_dispatch(
                FreshRunnerEffectDispatchPermit::SprintFinalVerification(permit),
                OPAQUE_RUNNER_TRANSPORT_REQUEST_BYTES,
            )
            .expect("claim proper final authority before Applying");
        let final_authority = transport
            .validate_transport_request(
                &applying_fixture.intent,
                &applying_fixture.command_bytes,
                &applying_fixture.launch,
                &applying_fixture.session,
                None,
                OPAQUE_RUNNER_TRANSPORT_REQUEST_BYTES,
            )
            .expect("validate proper final transport before Applying");
        let (final_observation, final_terminal, final_evidence) =
            v21_final_verification_terminal(&applying_ledger, &applying_fixture);
        applying_ledger
            .record_claimed_final_verification_effect_observation(
                final_authority,
                &final_observation,
                &final_terminal,
                &final_evidence,
            )
            .expect("terminalize proper final authority before Applying");
        applying_ledger
            .append_event(&phase_event(
                &applying_ledger,
                "FinalVerification",
                "Applying",
                "event-v21-phase-only-applying",
                2_350,
            ))
            .expect("enter Applying after exact terminal final verification");
        assert!(
            applying_ledger
                .append_event(&task_event(
                    &applying_ledger,
                    "event-v21-task-applying",
                    2_360,
                ))
                .is_err(),
            "Applying must reject generic task/worker events"
        );
        applying_ledger
            .append_event(&phase_event(
                &applying_ledger,
                "Applying",
                "Unknown",
                "event-v21-phase-only-unknown",
                2_370,
            ))
            .expect("enter phase-only Unknown without a terminal marker");
        assert!(
            applying_ledger
                .append_event(&task_event(
                    &applying_ledger,
                    "event-v21-task-phase-unknown",
                    2_380,
                ))
                .is_err(),
            "phase-only Unknown must reject generic task/worker events"
        );
    }

    #[test]
    fn v21_raw_admission_rejects_crossed_json_and_noncanonical_command_shape() {
        let database = TestDatabase::new();
        let mut ledger = open_v21_test_ledger(&database);
        let fixture = prepare_v21_final_verification_fixture(&mut ledger);
        let SprintFinalVerificationDispatchAdmission::Fresh { permit, .. } = ledger
            .admit_sprint_final_verification_for_dispatch(
                &fixture.admission,
                &fixture.phase_event,
                &fixture.intent,
                &fixture.proposed_event,
            )
            .expect("persist canonical v21 admission")
        else {
            panic!("canonical v21 admission must be Fresh");
        };
        drop(permit);

        let crossed = ledger.connection.execute(
            "INSERT INTO sprint_final_verification_admissions (
                admission_id, sprint_id, sprint_phase_event_id, final_snapshot,
                effect_id, runner_launch_id, runner_session_id, command_digest,
                command_bytes, contract_version, admitted_at_unix_ms, admission_json
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
            params![
                "admission-v21-crossed-json",
                fixture.admission.sprint_id,
                fixture.admission.sprint_phase_event_id,
                fixture.admission.final_snapshot.as_str(),
                "effect-v21-crossed-json",
                fixture.admission.runner_launch_id,
                fixture.admission.runner_session_id,
                Digest::sha256(&fixture.command_bytes).as_str(),
                &fixture.command_bytes,
                i64::from(CONTRACT_VERSION),
                2_201_i64,
                encode("sprint final-verification admission", &fixture.admission)
                    .expect("encode crossed admission JSON"),
            ],
        );
        assert!(crossed.is_err());

        let bad_command_text =
            r#"{"program":"cargo","arguments":[],"working_directory":"","extra":true}"#;
        let bad_command = bad_command_text.as_bytes();
        let bad_json = format!(
            "{{\"contract_version\":1,\"admission_id\":\"admission-v21-bad-command\",\"sprint_id\":\"sprint-1\",\"sprint_phase_event_id\":\"{}\",\"final_snapshot\":\"{}\",\"effect_id\":\"effect-v21-bad-command\",\"runner_launch_id\":\"{}\",\"runner_session_id\":\"{}\",\"command\":{},\"admitted_at_unix_ms\":2202}}",
            fixture.admission.sprint_phase_event_id,
            fixture.admission.final_snapshot,
            fixture.admission.runner_launch_id,
            fixture.admission.runner_session_id,
            bad_command_text,
        );
        let bad_shape = ledger.connection.execute(
            "INSERT INTO sprint_final_verification_admissions (
                admission_id, sprint_id, sprint_phase_event_id, final_snapshot,
                effect_id, runner_launch_id, runner_session_id, command_digest,
                command_bytes, contract_version, admitted_at_unix_ms, admission_json
             ) VALUES (?1, 'sprint-1', ?2, ?3, 'effect-v21-bad-command', ?4, ?5,
                       ?6, ?7, ?8, 2202, ?9)",
            params![
                "admission-v21-bad-command",
                fixture.admission.sprint_phase_event_id,
                fixture.admission.final_snapshot.as_str(),
                fixture.admission.runner_launch_id,
                fixture.admission.runner_session_id,
                Digest::sha256(bad_command).as_str(),
                bad_command,
                i64::from(CONTRACT_VERSION),
                bad_json.as_bytes(),
            ],
        );
        assert!(bad_shape.is_err());
        assert_eq!(
            row_count(&ledger, "sprint_final_verification_admissions"),
            1
        );
    }

    #[test]
    fn v21_raw_admission_rejects_invalid_prior_phase_lineage() {
        let database = TestDatabase::new();
        let mut ledger = open_v21_test_ledger(&database);
        let mut fixture = prepare_v21_final_verification_fixture(&mut ledger);
        let forged_prior = AgentEvent {
            contract_version: CONTRACT_VERSION,
            sequence: fixture.phase_event.sequence,
            event_id: "event-v21-forged-prior-phase".into(),
            sprint_id: "sprint-1".into(),
            task_id: None,
            worker_id: None,
            causation_id: None,
            correlation_id: "correlation-v21-forged-prior".into(),
            policy_hash: Some(fixture.intent.policy_hash.clone()),
            occurred_at_unix_ms: 2_180,
            payload: AgentEventKind::SprintStateChanged {
                from: "AwaitingAcceptance".into(),
                to: "Running".into(),
            },
        };
        fixture.phase_event.sequence += 1;
        fixture.proposed_event.sequence += 1;
        let transaction = ledger
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .expect("begin forged phase transaction");
        insert_agent_event(&transaction, &forged_prior).expect("raw-insert forged predecessor");
        insert_agent_event(&transaction, &fixture.phase_event).expect("raw-insert final phase");
        transaction.commit().expect("commit raw invalid lineage");

        let error = ledger
            .connection
            .execute(
                "INSERT INTO sprint_final_verification_admissions (
                    admission_id, sprint_id, sprint_phase_event_id, final_snapshot,
                    effect_id, runner_launch_id, runner_session_id, command_digest,
                    command_bytes, contract_version, admitted_at_unix_ms, admission_json
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
                params![
                    fixture.admission.admission_id,
                    fixture.admission.sprint_id,
                    fixture.admission.sprint_phase_event_id,
                    fixture.admission.final_snapshot.as_str(),
                    fixture.admission.effect_id,
                    fixture.admission.runner_launch_id,
                    fixture.admission.runner_session_id,
                    Digest::sha256(&fixture.command_bytes).as_str(),
                    &fixture.command_bytes,
                    i64::from(CONTRACT_VERSION),
                    i64::try_from(fixture.admission.admitted_at_unix_ms).unwrap(),
                    encode("sprint final-verification admission", &fixture.admission)
                        .expect("encode lineage admission"),
                ],
            )
            .expect_err("raw invalid phase lineage must reject admission");
        assert!(error.to_string().contains("TaskDone snapshot authority"));
        assert_eq!(
            row_count(&ledger, "sprint_final_verification_admissions"),
            0
        );
        assert!(matches!(
            ledger.load_sprint_final_verification_admission(&fixture.admission.admission_id),
            Err(LedgerError::ArtifactNotFound { .. })
        ));
    }

    #[test]
    fn v21_raw_admission_rejects_future_registered_verifier_session() {
        let database = TestDatabase::new();
        let mut ledger = open_v21_test_ledger(&database);
        let mut fixture = prepare_v21_final_verification_fixture(&mut ledger);
        assert_eq!(fixture.session.registered_at_unix_ms, 2_120);
        fixture.phase_event.occurred_at_unix_ms = 2_105;
        fixture.admission.admitted_at_unix_ms = 2_110;
        let transaction = ledger
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .expect("begin future-session raw phase");
        insert_agent_event(&transaction, &fixture.phase_event)
            .expect("raw-insert future-session phase");
        transaction.commit().expect("commit future-session phase");

        let error = ledger
            .connection
            .execute(
                "INSERT INTO sprint_final_verification_admissions (
                    admission_id, sprint_id, sprint_phase_event_id, final_snapshot,
                    effect_id, runner_launch_id, runner_session_id, command_digest,
                    command_bytes, contract_version, admitted_at_unix_ms, admission_json
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
                params![
                    fixture.admission.admission_id,
                    fixture.admission.sprint_id,
                    fixture.admission.sprint_phase_event_id,
                    fixture.admission.final_snapshot.as_str(),
                    fixture.admission.effect_id,
                    fixture.admission.runner_launch_id,
                    fixture.admission.runner_session_id,
                    Digest::sha256(&fixture.command_bytes).as_str(),
                    &fixture.command_bytes,
                    i64::from(CONTRACT_VERSION),
                    i64::try_from(fixture.admission.admitted_at_unix_ms).unwrap(),
                    encode("sprint final-verification admission", &fixture.admission)
                        .expect("encode future-session admission"),
                ],
            )
            .expect_err("future-registered FinalVerifier session cannot authorize admission");
        assert!(error.to_string().contains("TaskDone snapshot authority"));
        assert_eq!(
            row_count(&ledger, "sprint_final_verification_admissions"),
            0
        );
    }

    #[test]
    #[allow(clippy::too_many_lines)] // API rejection and direct readback corruption cover both sides of the timestamp fence.
    fn v21_final_admission_rejects_and_readback_detects_future_snapshot() {
        let database = TestDatabase::new();
        let mut ledger = open_v21_test_ledger(&database);
        let fixture = prepare_v21_final_verification_fixture(&mut ledger);
        let original_snapshot = ledger
            .load_workspace_snapshot("sprint-1", &fixture.admission.final_snapshot)
            .expect("load exact final snapshot");
        let mut future_snapshot = original_snapshot.clone();
        future_snapshot.created_at_unix_ms = fixture.admission.admitted_at_unix_ms + 1;
        future_snapshot
            .validate()
            .expect("future-dated snapshot remains structurally valid");
        ledger
            .connection
            .execute_batch("DROP TRIGGER workspace_snapshots_no_update;")
            .expect("allow adversarial snapshot timestamp rewrite");
        ledger
            .connection
            .execute(
                "UPDATE workspace_snapshots
                 SET created_at_unix_ms = ?1, snapshot_json = ?2
                 WHERE sprint_id = ?3 AND snapshot_id = ?4",
                params![
                    i64::try_from(future_snapshot.created_at_unix_ms).unwrap(),
                    encode("workspace snapshot", &future_snapshot).expect("encode future snapshot"),
                    fixture.admission.sprint_id,
                    fixture.admission.final_snapshot.as_str(),
                ],
            )
            .expect("install structurally exact future snapshot");
        let transaction = ledger
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .expect("begin future-snapshot raw phase");
        insert_agent_event(&transaction, &fixture.phase_event)
            .expect("raw-insert future-snapshot phase");
        transaction.commit().expect("commit future-snapshot phase");

        let error = ledger
            .connection
            .execute(
                "INSERT INTO sprint_final_verification_admissions (
                    admission_id, sprint_id, sprint_phase_event_id, final_snapshot,
                    effect_id, runner_launch_id, runner_session_id, command_digest,
                    command_bytes, contract_version, admitted_at_unix_ms, admission_json
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
                params![
                    fixture.admission.admission_id,
                    fixture.admission.sprint_id,
                    fixture.admission.sprint_phase_event_id,
                    fixture.admission.final_snapshot.as_str(),
                    fixture.admission.effect_id,
                    fixture.admission.runner_launch_id,
                    fixture.admission.runner_session_id,
                    Digest::sha256(&fixture.command_bytes).as_str(),
                    &fixture.command_bytes,
                    i64::from(CONTRACT_VERSION),
                    i64::try_from(fixture.admission.admitted_at_unix_ms).unwrap(),
                    encode("sprint final-verification admission", &fixture.admission)
                        .expect("encode future-snapshot admission"),
                ],
            )
            .expect_err("future-created final snapshot cannot authorize raw admission");
        assert!(error.to_string().contains("TaskDone snapshot authority"));
        assert_eq!(
            row_count(&ledger, "sprint_final_verification_admissions"),
            0
        );

        let readback_database = TestDatabase::new();
        let mut readback_ledger = open_v21_test_ledger(&readback_database);
        let readback_fixture = prepare_v21_final_verification_fixture(&mut readback_ledger);
        let SprintFinalVerificationDispatchAdmission::Fresh { permit, .. } = readback_ledger
            .admit_sprint_final_verification_for_dispatch(
                &readback_fixture.admission,
                &readback_fixture.phase_event,
                &readback_fixture.intent,
                &readback_fixture.proposed_event,
            )
            .expect("admit exact final verification before readback corruption")
        else {
            panic!("readback final admission must be Fresh");
        };
        drop(permit);
        let mut readback_snapshot = readback_ledger
            .load_workspace_snapshot(
                &readback_fixture.admission.sprint_id,
                &readback_fixture.admission.final_snapshot,
            )
            .expect("load readback final snapshot");
        readback_snapshot.created_at_unix_ms = readback_fixture.admission.admitted_at_unix_ms + 1;
        readback_ledger
            .connection
            .execute_batch("DROP TRIGGER workspace_snapshots_no_update;")
            .expect("allow readback snapshot timestamp corruption");
        readback_ledger
            .connection
            .execute(
                "UPDATE workspace_snapshots
                 SET created_at_unix_ms = ?1, snapshot_json = ?2
                 WHERE sprint_id = ?3 AND snapshot_id = ?4",
                params![
                    i64::try_from(readback_snapshot.created_at_unix_ms).unwrap(),
                    encode("workspace snapshot", &readback_snapshot)
                        .expect("encode readback future snapshot"),
                    readback_fixture.admission.sprint_id,
                    readback_fixture.admission.final_snapshot.as_str(),
                ],
            )
            .expect("corrupt admitted final snapshot timestamp");
        assert!(matches!(
            readback_ledger
                .load_sprint_final_verification_admission(&readback_fixture.admission.admission_id),
            Err(LedgerError::Corrupt {
                entity: "sprint final-verification admission",
                ..
            })
        ));
    }

    #[test]
    fn v21_raw_claim_accepts_exact_identity_and_rejects_crossed_policy() {
        let database = TestDatabase::new();
        let mut ledger = open_v21_test_ledger(&database);
        let fixture = prepare_v21_final_verification_fixture(&mut ledger);
        let SprintFinalVerificationDispatchAdmission::Fresh { permit, effect, .. } = ledger
            .admit_sprint_final_verification_for_dispatch(
                &fixture.admission,
                &fixture.phase_event,
                &fixture.intent,
                &fixture.proposed_event,
            )
            .expect("admit v21 raw-claim final")
        else {
            panic!("raw-claim admission must be Fresh");
        };
        let exact = PersistedRunnerEffectDispatchClaim {
            dispatch_claim_id: runner_effect_dispatch_claim_id(&fixture.intent.effect_id),
            effect_id: fixture.intent.effect_id.clone(),
            sprint_id: fixture.intent.sprint_id.clone(),
            launch_id: fixture.launch.launch_id.clone(),
            session_id: fixture.session.session_id.clone(),
            running_boundary_id: None,
            authority: RunnerEffectRequestAuthority::SprintFinalVerification {
                sprint_phase_event_id: fixture.phase_event.event_id.clone(),
            },
            request_digest: fixture.intent.request_digest.clone(),
            opaque_transport_request_digest: Digest::sha256(OPAQUE_RUNNER_TRANSPORT_REQUEST_BYTES),
            policy_hash: fixture.intent.policy_hash.clone(),
            input_snapshot: fixture.intent.input_snapshot.clone(),
            contract_version: CONTRACT_VERSION,
        };
        let mut crossed = exact.clone();
        crossed.policy_hash = digest('f');
        let claim_count_before_crossed = row_count(&ledger, "runner_effect_dispatch_claims");
        let authority_count_before_crossed =
            row_count(&ledger, "runner_effect_dispatch_claim_authorities");
        let final_authority_count_before_crossed: i64 = ledger
            .connection
            .query_row(
                "SELECT COUNT(*) FROM runner_effect_dispatch_claim_authorities
                 WHERE authority_class = 'SprintFinalVerification'",
                [],
                |row| row.get(0),
            )
            .expect("count SprintFinalVerification authorities before crossed claim");
        let transaction = ledger
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .expect("begin crossed raw claim");
        insert_runner_effect_dispatch_claim_authority(&transaction, &crossed)
            .expect("insert crossed companion first");
        assert!(insert_runner_effect_dispatch_claim(&transaction, &crossed).is_err());
        drop(transaction);
        assert_eq!(
            row_count(&ledger, "runner_effect_dispatch_claims"),
            claim_count_before_crossed
        );
        assert_eq!(
            row_count(&ledger, "runner_effect_dispatch_claim_authorities"),
            authority_count_before_crossed
        );
        assert_eq!(
            ledger
                .connection
                .query_row(
                    "SELECT COUNT(*) FROM runner_effect_dispatch_claim_authorities
                     WHERE authority_class = 'SprintFinalVerification'",
                    [],
                    |row| row.get::<_, i64>(0),
                )
                .expect("count SprintFinalVerification authorities after crossed claim"),
            final_authority_count_before_crossed
        );

        let transaction = ledger
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .expect("begin exact raw claim");
        insert_runner_effect_dispatch_claim_authority(&transaction, &exact)
            .expect("insert exact v21 companion");
        insert_runner_effect_dispatch_claim(&transaction, &exact)
            .expect("insert exact v21 raw claim");
        transaction.commit().expect("commit exact v21 raw claim");
        drop(permit);
        assert_eq!(
            ledger
                .load_effect(&effect.intent.effect_id)
                .expect("read exact raw v21 claim")
                .dispatch_claim,
            Some(exact)
        );
    }

    #[test]
    fn v21_claimed_final_postcommit_hardening_failure_returns_no_custody() {
        let database = TestDatabase::new();
        let mut ledger = open_v21_test_ledger(&database);
        let fixture = prepare_v21_final_verification_fixture(&mut ledger);
        let SprintFinalVerificationDispatchAdmission::Fresh { permit, .. } = ledger
            .admit_sprint_final_verification_for_dispatch(
                &fixture.admission,
                &fixture.phase_event,
                &fixture.intent,
                &fixture.proposed_event,
            )
            .expect("admit v21 hardening final")
        else {
            panic!("new v21 hardening admission must be Fresh");
        };
        let (_, transport) = ledger
            .claim_runner_effect_dispatch(
                FreshRunnerEffectDispatchPermit::SprintFinalVerification(permit),
                OPAQUE_RUNNER_TRANSPORT_REQUEST_BYTES,
            )
            .expect("claim v21 hardening transport");
        let authority = transport
            .validate_transport_request(
                &fixture.intent,
                &fixture.command_bytes,
                &fixture.launch,
                &fixture.session,
                None,
                OPAQUE_RUNNER_TRANSPORT_REQUEST_BYTES,
            )
            .expect("validate v21 hardening transport");
        let (observation, event, evidence) = v21_final_verification_terminal(&ledger, &fixture);
        let hardlink = database
            .directory
            .join("v21-final-postcommit-hardlink.sqlite3");
        fs::hard_link(&database.path, &hardlink).expect("install v21 hardening fault");
        let failure = ledger
            .record_claimed_final_verification_effect_observation(
                authority,
                &observation,
                &event,
                &evidence,
            )
            .expect_err("postcommit hardening must report uncertainty");
        assert!(!failure.has_retry_authority());
        assert!(matches!(
            failure.error(),
            LedgerError::PostCommitStateUncertain {
                operation: "claimed final-verification observation",
                ..
            }
        ));
        fs::remove_file(&hardlink).expect("remove v21 hardening fault");
        let persisted = ledger
            .load_effect(&fixture.intent.effect_id)
            .expect("reconcile committed v21 terminal");
        assert_eq!(persisted.observation.as_ref(), Some(&observation));
        assert_eq!(persisted.terminal_event.as_ref(), Some(&event));
    }

    #[test]
    fn v21_raw_admission_rejects_effect_before_phase_inversion() {
        let database = TestDatabase::new();
        let mut ledger = open_v21_test_ledger(&database);
        let mut fixture = prepare_v21_final_verification_fixture(&mut ledger);
        let mut inverted_intent = fixture.intent.clone();
        inverted_intent.causation_event_id = None;
        inverted_intent.correlation_id = "correlation-v21-inverted".into();
        inverted_intent.created_at_unix_ms = 2_180;
        let inverted_proposal = effect_proposal_event(
            &inverted_intent,
            fixture.phase_event.sequence,
            "event-v21-inverted-effect-proposed",
        );
        ledger
            .record_runner_effect_intent(
                &inverted_intent,
                &fixture.command_bytes,
                &inverted_proposal,
                &fixture.session.session_id,
            )
            .expect("legacy-style FinalVerifier effect is still possible before normalized phase");
        fixture.phase_event.sequence += 1;
        fixture.phase_event.correlation_id = inverted_intent.correlation_id.clone();
        let transaction = ledger
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .expect("begin raw inverted phase");
        insert_agent_event(&transaction, &fixture.phase_event)
            .expect("raw-insert inverted FinalVerification phase");
        transaction.commit().expect("commit raw inverted phase");
        fixture.admission.effect_id = inverted_intent.effect_id.clone();
        fixture.admission.admitted_at_unix_ms = 2_200;
        let error = ledger
            .connection
            .execute(
                "INSERT INTO sprint_final_verification_admissions (
                    admission_id, sprint_id, sprint_phase_event_id, final_snapshot,
                    effect_id, runner_launch_id, runner_session_id, command_digest,
                    command_bytes, contract_version, admitted_at_unix_ms, admission_json
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
                params![
                    fixture.admission.admission_id,
                    fixture.admission.sprint_id,
                    fixture.admission.sprint_phase_event_id,
                    fixture.admission.final_snapshot.as_str(),
                    fixture.admission.effect_id,
                    fixture.admission.runner_launch_id,
                    fixture.admission.runner_session_id,
                    Digest::sha256(&fixture.command_bytes).as_str(),
                    &fixture.command_bytes,
                    i64::from(CONTRACT_VERSION),
                    i64::try_from(fixture.admission.admitted_at_unix_ms).unwrap(),
                    encode("sprint final-verification admission", &fixture.admission)
                        .expect("encode inverted admission"),
                ],
            )
            .expect_err("admission-first ordering must reject a preexisting effect");
        assert!(error.to_string().contains("TaskDone snapshot authority"));
        assert_eq!(
            row_count(&ledger, "sprint_final_verification_admissions"),
            0
        );
    }

    #[test]
    fn v21_safe_terminal_nonintegrated_optional_contributes_no_snapshot() {
        let (mut candidate, _, _, _) = prepare_v18_completion_with_unattempted_optional();
        let first =
            acquire_optional_no_launch_attempt(&mut candidate.ledger, 2, "v21-retry", 2_010, None);
        let retry = close_optional_no_launch_attempt(
            &mut candidate.ledger,
            &first,
            "v21-retry",
            TaskState::Ready,
            2_020,
        );
        let second = acquire_optional_no_launch_attempt(
            &mut candidate.ledger,
            3,
            "v21-exhausted",
            2_030,
            Some(&retry.metadata().state_transition_event_id),
        );
        let exhausted = close_optional_no_launch_attempt(
            &mut candidate.ledger,
            &second,
            "v21-exhausted",
            TaskState::Failed,
            2_040,
        );
        assert!(matches!(
            exhausted,
            TaskAttemptDisposition::AttemptsExhausted(_)
        ));
        let fixture = build_v21_final_verification_fixture(&mut candidate.ledger, digest('b'));
        let admitted = candidate
            .ledger
            .admit_sprint_final_verification_for_dispatch(
                &fixture.admission,
                &fixture.phase_event,
                &fixture.intent,
                &fixture.proposed_event,
            )
            .expect("safely terminal optional task must not alter final snapshot");
        assert!(matches!(
            admitted,
            SprintFinalVerificationDispatchAdmission::Fresh { admission, .. }
                if admission.final_snapshot == digest('b')
        ));
    }

    #[test]
    fn v21_retryable_optional_blocks_final_verification() {
        let (mut candidate, _, _, _) = prepare_v18_completion_with_unattempted_optional();
        let attempt = acquire_optional_no_launch_attempt(
            &mut candidate.ledger,
            2,
            "v21-open-retry",
            2_010,
            None,
        );
        let retry = close_optional_no_launch_attempt(
            &mut candidate.ledger,
            &attempt,
            "v21-open-retry",
            TaskState::Ready,
            2_020,
        );
        assert!(matches!(retry, TaskAttemptDisposition::Retryable(_)));
        let fixture = build_v21_final_verification_fixture(&mut candidate.ledger, digest('b'));
        assert!(matches!(
            candidate
                .ledger
                .admit_sprint_final_verification_for_dispatch(
                    &fixture.admission,
                    &fixture.phase_event,
                    &fixture.intent,
                    &fixture.proposed_event,
                ),
            Err(LedgerError::ReferenceMismatch {
                entity: "attempted optional task closure",
                ..
            })
        ));
        assert_eq!(
            row_count(&candidate.ledger, "sprint_final_verification_admissions"),
            0
        );
    }

    #[test]
    fn v21_integrated_optional_non_noop_occupies_global_snapshot_chain() {
        let mut candidate = prepare_v15_candidate_fixture_with_graph_options(
            true,
            false,
            false,
            false,
            CandidateTaskRequirement::Optional,
            None,
        );
        assert!(!candidate.change_set.operations.is_empty());
        let (_, integration, disposition) =
            integrate_v15_candidate(&mut candidate, "v21-optional-nonnoop", false);
        let command = candidate
            .ledger
            .load_command_domain_effect_bindings(
                &candidate.spec.sprint_id,
                &candidate.launch.launch_id,
                &candidate.launch.session_id,
            )
            .expect("load optional non-noop command bindings")
            .into_iter()
            .find(|binding| binding.effect_id == "effect-v15-formal")
            .expect("find optional non-noop formal command");
        ensure_test_command_domain_cleanup(
            &mut candidate.ledger,
            &command,
            "command-cleanup-v21-optional-nonnoop",
            CommandDomainBackend::LinuxCgroupV2,
            CommandDomainCleanupDisposition::ReapedZeroSurvivors,
            1_400,
        );
        let cleanup = cleanup_terminal_record(
            &candidate.ledger,
            &candidate.launch,
            "cleanup-v21-optional-nonnoop",
            1_450,
        );
        candidate
            .ledger
            .with_integrated_task_attempt_cleanup_exclusion(
                &disposition.metadata().disposition_id,
                |_| Ok(cleanup),
            )
            .expect("cleanup optional non-noop integrated attempt");
        assert!(
            candidate
                .ledger
                .assess_task_done(&candidate.spec.sprint_id, "task-1")
                .expect("assess optional non-noop TaskDone")
                .is_done()
        );
        assert_eq!(integration.receipt.integration_ordinal, 0);
        let final_snapshot = candidate.result_snapshot.snapshot_id.clone();
        let fixture = build_v21_final_verification_fixture(&mut candidate.ledger, final_snapshot);
        let permit = admit_test_final_verification(&mut candidate.ledger, &fixture);
        assert_eq!(
            candidate
                .ledger
                .load_sprint_final_verification_admission(&fixture.admission.admission_id)
                .expect("load integrated optional final admission")
                .final_snapshot,
            candidate.result_snapshot.snapshot_id
        );
        drop(permit);
    }

    fn row_count(ledger: &EventLedger, table: &str) -> i64 {
        ledger
            .connection
            .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| {
                row.get(0)
            })
            .expect("count table rows")
    }

    fn assert_v27_capture_loader_rejects_transactional_corruption<F>(
        ledger: &mut EventLedger,
        capture_id: &str,
        drop_immutable_trigger_sql: &str,
        mutate: F,
    ) where
        F: FnOnce(&Transaction<'_>),
    {
        let transaction = ledger
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .expect("start transactional v27 capture corruption regression");
        transaction
            .execute_batch(drop_immutable_trigger_sql)
            .expect("drop immutable trigger inside rollback-only corruption regression");
        mutate(&transaction);
        let error = command_output_capture_authority::load_from_id(&transaction, capture_id)
            .expect_err("v27 capture loader must reject crossed redundant storage");
        assert!(
            matches!(error, LedgerError::Corrupt { .. }),
            "expected fail-closed corruption classification, got {error:?}"
        );
        drop(transaction);
    }

