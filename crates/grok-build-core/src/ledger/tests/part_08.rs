    #[test]
    fn unadmitted_final_verifier_cleanup_accepts_proven_session_absence() {
        let (mut candidate, fixture) =
            prepare_current_unadmitted_final_verifier_fixture(false, digest('b'));
        let ledger = &mut candidate.ledger;
        let exact_session_count: i64 = ledger
            .connection
            .query_row(
                "SELECT COUNT(*) FROM runner_session_policies
                 WHERE sprint_id = ?1 AND (session_id = ?2 OR launch_id = ?3)",
                params![
                    fixture.launch.sprint_id,
                    fixture.launch.session_id,
                    fixture.launch.launch_id,
                ],
                |row| row.get(0),
            )
            .expect("prove exact session absence");
        assert_eq!(exact_session_count, 0);

        let callback_invoked = Arc::new(AtomicBool::new(false));
        let callback_flag = Arc::clone(&callback_invoked);
        ledger
            .with_unadmitted_final_verifier_launch_cleanup_exclusion(
                &fixture.launch.sprint_id,
                &fixture.launch.launch_id,
                move |claim| {
                    callback_flag.store(true, Ordering::SeqCst);
                    assert!(claim.registered_session().is_none());
                    assert_eq!(
                        claim.minimum_terminal_at_unix_ms(),
                        runner_cleanup_minimum_terminal_time(
                            claim.admission(),
                            claim.preparation(),
                        )
                    );
                    Ok(cleanup_terminal_from_live_claim(
                        claim,
                        "unadmitted-final-session-absent",
                        2_300,
                    ))
                },
            )
            .expect("clean unadmitted launch with proven session absence");
        assert!(callback_invoked.load(Ordering::SeqCst));
    }

    #[test]
    fn unadmitted_final_verifier_cleanup_rejects_existing_phase_before_callback() {
        let (mut candidate, fixture) =
            prepare_current_unadmitted_final_verifier_fixture(true, digest('b'));
        let ledger = &mut candidate.ledger;
        let admitted = ledger
            .admit_sprint_final_verification_with_output_capture_for_dispatch(
                &fixture.admission,
                &fixture.phase_event,
                &fixture.intent,
                &fixture.proposed_event,
                &fixture.capture_intent,
            )
            .expect("admit exact final-verification phase first");
        drop(admitted);

        let callback_invoked = Arc::new(AtomicBool::new(false));
        let callback_flag = Arc::clone(&callback_invoked);
        let error = ledger
            .with_unadmitted_final_verifier_launch_cleanup_exclusion(
                &fixture.launch.sprint_id,
                &fixture.launch.launch_id,
                move |_| {
                    callback_flag.store(true, Ordering::SeqCst);
                    unreachable!("phase-owned launch must stop before native cleanup")
                },
            )
            .expect_err("phase-owned launch is not unadmitted cleanup authority");
        assert!(matches!(
            error,
            LedgerError::ReferenceMismatch {
                entity: "unadmitted final-verifier launch cleanup",
                ..
            }
        ));
        assert!(!callback_invoked.load(Ordering::SeqCst));
        assert!(
            ledger
                .load_effect(&fixture.admission.effect_id)
                .expect("phase effect remains intact")
                .observation
                .is_none()
        );
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn unadmitted_final_verifier_cleanup_rejects_wrong_role_snapshot_and_effect_binding() {
        {
            let database = TestDatabase::new();
            let mut ledger = EventLedger::open(&database.path).expect("open wrong-role ledger");
            let (policy, launch, intent, _, request_bytes, event) = prepare_test_launch_admission(
                &mut ledger,
                "unadmitted-final-wrong-role",
                RunnerSessionPurpose::TaskWorker,
                Some("worker-1"),
                WorkerCleanupBackend::LinuxCgroupV2,
            );
            ledger
                .admit_runner_launch_with_cleanup(&launch, &policy, &intent, &request_bytes, &event)
                .expect("admit wrong-role launch");
            let callback_invoked = Arc::new(AtomicBool::new(false));
            let callback_flag = Arc::clone(&callback_invoked);
            assert!(matches!(
                ledger.with_unadmitted_final_verifier_launch_cleanup_exclusion(
                    &launch.sprint_id,
                    &launch.launch_id,
                    move |_| {
                        callback_flag.store(true, Ordering::SeqCst);
                        unreachable!("wrong role must stop before native cleanup")
                    },
                ),
                Err(LedgerError::ReferenceMismatch {
                    entity: "unadmitted final-verifier launch cleanup",
                    ..
                })
            ));
            assert!(!callback_invoked.load(Ordering::SeqCst));
        }

        {
            let (mut candidate, fixture) =
                prepare_current_unadmitted_final_verifier_fixture(true, digest('c'));
            let ledger = &mut candidate.ledger;
            let callback_invoked = Arc::new(AtomicBool::new(false));
            let callback_flag = Arc::clone(&callback_invoked);
            assert!(matches!(
                ledger.with_unadmitted_final_verifier_launch_cleanup_exclusion(
                    &fixture.launch.sprint_id,
                    &fixture.launch.launch_id,
                    move |_| {
                        callback_flag.store(true, Ordering::SeqCst);
                        unreachable!("crossed snapshot must stop before native cleanup")
                    },
                ),
                Err(LedgerError::ReferenceMismatch {
                    entity: "unadmitted final-verifier launch cleanup",
                    ..
                })
            ));
            assert!(!callback_invoked.load(Ordering::SeqCst));
        }

        {
            let (mut candidate, fixture) =
                prepare_current_unadmitted_final_verifier_fixture(true, digest('b'));
            let ledger = &mut candidate.ledger;
            let mut bound_effect = effect_intent(
                "unadmitted-final-crossed-effect",
                "unadmitted-final-crossed-key",
                2_180,
            );
            bound_effect.policy_hash = fixture.launch.policy_hash.clone();
            bound_effect.input_snapshot = fixture.admission.final_snapshot.clone();
            bound_effect.request_digest = Digest::sha256(&fixture.command_bytes);
            let bound_event = effect_proposal_event(
                &bound_effect,
                ledger
                    .next_sequence(&fixture.launch.sprint_id)
                    .expect("bound effect proposal sequence"),
                "event-unadmitted-final-crossed-effect",
            );
            let transaction = ledger
                .connection
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .expect("begin adversarial bound-effect transaction");
            validate_new_event(&transaction, &bound_event)
                .expect("validate bound-effect proposal event");
            transaction
                .execute(
                    "INSERT INTO effect_session_bindings (
                        effect_id, sprint_id, launch_id, session_id, contract_version
                     ) VALUES (?1, ?2, ?3, ?4, ?5)",
                    params![
                        bound_effect.effect_id,
                        bound_effect.sprint_id,
                        fixture.launch.launch_id,
                        fixture.launch.session_id,
                        i64::from(bound_effect.contract_version),
                    ],
                )
                .expect("stage non-cleanup session binding under open cleanup authority");
            insert_agent_event(&transaction, &bound_event)
                .expect("persist bound-effect proposal event");
            insert_effect_request_payload(&transaction, &bound_effect, &fixture.command_bytes)
                .expect("persist bound-effect payload");
            insert_finish_effect_kind(&transaction, &bound_effect)
                .expect("persist bound-effect semantic kind");
            insert_effect_intent(&transaction, &bound_effect, &bound_event.event_id)
                .expect("persist adversarial non-cleanup session effect");
            transaction
                .commit()
                .expect("commit adversarial non-cleanup session effect");

            let callback_invoked = Arc::new(AtomicBool::new(false));
            let callback_flag = Arc::clone(&callback_invoked);
            assert!(matches!(
                ledger.with_unadmitted_final_verifier_launch_cleanup_exclusion(
                    &fixture.launch.sprint_id,
                    &fixture.launch.launch_id,
                    move |_| {
                        callback_flag.store(true, Ordering::SeqCst);
                        unreachable!("bound non-cleanup effect must stop before native cleanup")
                    },
                ),
                Err(LedgerError::ReferenceMismatch {
                    entity: "unadmitted final-verifier launch cleanup",
                    ..
                })
            ));
            assert!(!callback_invoked.load(Ordering::SeqCst));
        }
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "one adversarial test proves both impossible sessionless corruption and incomplete TaskDone stop before the callback"
    )]
    fn unadmitted_final_verifier_cleanup_rejects_sessionless_effect_and_incomplete_task_done() {
        {
            let (mut candidate, fixture) =
                prepare_current_unadmitted_final_verifier_fixture(false, digest('b'));
            let ledger = &mut candidate.ledger;
            let mut bound_effect = effect_intent(
                "unadmitted-final-sessionless-effect",
                "unadmitted-final-sessionless-key",
                2_180,
            );
            bound_effect.policy_hash = fixture.launch.policy_hash.clone();
            bound_effect.input_snapshot = fixture.admission.final_snapshot.clone();
            bound_effect.request_digest = Digest::sha256(&fixture.command_bytes);
            let bound_event = effect_proposal_event(
                &bound_effect,
                ledger
                    .next_sequence(&fixture.launch.sprint_id)
                    .expect("sessionless effect proposal sequence"),
                "event-unadmitted-final-sessionless-effect",
            );
            ledger
                .connection
                .execute_batch(
                    "DROP TRIGGER effect_session_bindings_require_cleanup_classification;",
                )
                .expect("disable schema guard to construct a corrupted sessionless binding");
            let transaction = ledger
                .connection
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .expect("begin sessionless launch-binding transaction");
            validate_new_event(&transaction, &bound_event)
                .expect("validate sessionless effect proposal event");
            transaction
                .execute(
                    "INSERT INTO effect_session_bindings (
                         effect_id, sprint_id, launch_id, session_id, contract_version
                     ) VALUES (?1, ?2, ?3, NULL, ?4)",
                    params![
                        bound_effect.effect_id,
                        bound_effect.sprint_id,
                        fixture.launch.launch_id,
                        i64::from(bound_effect.contract_version),
                    ],
                )
                .expect("bind non-cleanup effect to the sessionless launch");
            insert_agent_event(&transaction, &bound_event)
                .expect("persist sessionless effect proposal event");
            insert_effect_request_payload(&transaction, &bound_effect, &fixture.command_bytes)
                .expect("persist sessionless effect payload");
            insert_finish_effect_kind(&transaction, &bound_effect)
                .expect("persist sessionless effect kind");
            insert_effect_intent(&transaction, &bound_effect, &bound_event.event_id)
                .expect("persist sessionless effect intent");
            transaction
                .commit()
                .expect("commit sessionless launch-bound effect");

            let callback_invoked = Arc::new(AtomicBool::new(false));
            let callback_flag = Arc::clone(&callback_invoked);
            let error = ledger
                .with_unadmitted_final_verifier_launch_cleanup_exclusion(
                    &fixture.launch.sprint_id,
                    &fixture.launch.launch_id,
                    move |_| {
                        callback_flag.store(true, Ordering::SeqCst);
                        unreachable!("sessionless effect binding must stop before native cleanup")
                    },
                )
                .expect_err("sessionless non-cleanup binding closes cleanup authority");
            assert!(matches!(
                error,
                LedgerError::ReferenceMismatch {
                    entity: "unadmitted final-verifier launch cleanup",
                    ..
                }
            ));
            assert!(!callback_invoked.load(Ordering::SeqCst));
        }

        {
            let (mut candidate, fixture) =
                prepare_current_unadmitted_final_verifier_fixture_with_task_done(
                    true,
                    digest('b'),
                    false,
                );
            let ledger = &mut candidate.ledger;
            assert!(
                !ledger
                    .assess_task_done(&candidate.spec.sprint_id, "task-1")
                    .expect("assess intentionally incomplete TaskDone")
                    .is_done()
            );

            let callback_invoked = Arc::new(AtomicBool::new(false));
            let callback_flag = Arc::clone(&callback_invoked);
            let error = ledger
                .with_unadmitted_final_verifier_launch_cleanup_exclusion(
                    &fixture.launch.sprint_id,
                    &fixture.launch.launch_id,
                    move |_| {
                        callback_flag.store(true, Ordering::SeqCst);
                        unreachable!("incomplete TaskDone must stop before native cleanup")
                    },
                )
                .expect_err("incomplete TaskDone cannot authorize launch cleanup");
            assert!(matches!(
                error,
                LedgerError::ReferenceMismatch {
                    entity: "successful completion",
                    ..
                }
            ));
            assert!(!callback_invoked.load(Ordering::SeqCst));
        }
    }

    #[test]
    fn unadmitted_final_verifier_cleanup_replay_is_closed_before_callback() {
        let (mut candidate, fixture) =
            prepare_current_unadmitted_final_verifier_fixture(true, digest('b'));
        let ledger = &mut candidate.ledger;
        ledger
            .with_unadmitted_final_verifier_launch_cleanup_exclusion(
                &fixture.launch.sprint_id,
                &fixture.launch.launch_id,
                |claim| {
                    Ok(cleanup_terminal_from_live_claim(
                        claim,
                        "unadmitted-final-replay",
                        2_300,
                    ))
                },
            )
            .expect("close unadmitted final-verifier launch once");

        let callback_invoked = Arc::new(AtomicBool::new(false));
        let callback_flag = Arc::clone(&callback_invoked);
        assert!(matches!(
            ledger.with_unadmitted_final_verifier_launch_cleanup_exclusion(
                &fixture.launch.sprint_id,
                &fixture.launch.launch_id,
                move |_| {
                    callback_flag.store(true, Ordering::SeqCst);
                    unreachable!("closed cleanup must reject replay")
                },
            ),
            Err(LedgerError::ReferenceMismatch {
                entity: "runner launch cleanup admission",
                ..
            })
        ));
        assert!(!callback_invoked.load(Ordering::SeqCst));
    }

    struct UnadmittedApplicationApplierFixture {
        candidate: V15CandidateFixture,
        final_verification_receipt_id: String,
        applier_launch: RunnerLaunchIntent,
        applier_session: RunnerSessionPolicyRecord,
        application_admission: SprintApplicationAdmission,
        application_phase_event: AgentEvent,
        application_intent: EffectIntent,
        application_proposal: AgentEvent,
    }

    #[allow(clippy::too_many_lines)] // One visible chain establishes the exact application-ready cut before any application admission.
    fn prepare_unadmitted_application_applier_fixture(
        register_session: bool,
        cleanup_uses_application_base: bool,
    ) -> UnadmittedApplicationApplierFixture {
        let (mut candidate, mut final_fixture) =
            prepare_current_unadmitted_final_verifier_fixture_with_task_done_and_result(
                true,
                digest('c'),
                true,
                false,
            );
        let AcceptanceKind::Automated(final_command) = &candidate.spec.acceptance_criteria[0].kind
        else {
            panic!("unadmitted application fixture requires automated acceptance");
        };
        bind_v21_final_fixture_command(&mut final_fixture, final_command.clone());
        let final_permit = admit_test_final_verification(&mut candidate.ledger, &final_fixture);
        let (final_authority, final_acquired) =
            claim_test_final_verification(&mut candidate.ledger, &final_fixture, final_permit);
        let (final_observation, final_terminal, final_evidence) =
            v21_final_verification_terminal(&candidate.ledger, &final_fixture);
        complete_test_final_verification(
            &mut candidate.ledger,
            &final_fixture,
            final_authority,
            final_acquired.as_ref(),
            &final_observation,
            &final_terminal,
            &final_evidence,
        );
        let final_command = candidate
            .ledger
            .load_command_domain_effect_bindings(
                &candidate.spec.sprint_id,
                &final_fixture.launch.launch_id,
                &final_fixture.session.session_id,
            )
            .expect("load unadmitted-application final command binding")
            .into_iter()
            .find(|binding| binding.effect_id == final_fixture.intent.effect_id)
            .expect("find unadmitted-application final command binding");
        ensure_test_command_domain_cleanup(
            &mut candidate.ledger,
            &final_command,
            "command-cleanup-unadmitted-application-final",
            CommandDomainBackend::LinuxCgroupV2,
            CommandDomainCleanupDisposition::ReapedZeroSurvivors,
            2_320,
        );
        persist_cleanup_evidence(
            &mut candidate.ledger,
            &final_fixture.launch,
            &candidate.result_snapshot.snapshot_id,
            "cleanup-unadmitted-application-final",
            WorkerCleanupBackend::LinuxCgroupV2,
            2_310,
            2_340,
        );

        let applier_policy = compiled_test_policy("policy-unadmitted-application-applier");
        let applier_launch = runner_launch(
            "launch-unadmitted-application-applier",
            "session-unadmitted-application-applier",
            RunnerSessionPurpose::Applier,
            None,
            &applier_policy,
            2_350,
        );
        let (mut cleanup_intent, _, cleanup_request_bytes, cleanup_event) =
            test_runner_launch_cleanup_contracts(
                &candidate.ledger,
                &applier_launch,
                WorkerCleanupBackend::TrustedApplierDirectChildWait,
            )
            .expect("build unadmitted application-applier cleanup contracts");
        if !cleanup_uses_application_base {
            cleanup_intent.input_snapshot = candidate.result_snapshot.snapshot_id.clone();
        }
        let cleanup_event = effect_proposal_event(
            &cleanup_intent,
            cleanup_event.sequence,
            &cleanup_event.event_id,
        );
        candidate
            .ledger
            .admit_runner_launch_with_cleanup(
                &applier_launch,
                &applier_policy,
                &cleanup_intent,
                &cleanup_request_bytes,
                &cleanup_event,
            )
            .expect("admit unadmitted application-applier launch and cleanup");
        let applier_session = runner_session(&applier_launch, 2_360);
        if register_session {
            candidate
                .ledger
                .register_runner_session(&applier_session, &applier_policy)
                .expect("register unadmitted application-applier session");
        }

        let preparation = candidate
            .ledger
            .assess_sprint_application_preparation(
                &candidate.spec.sprint_id,
                &final_evidence.verification.receipt_id,
                "assembly-unadmitted-application",
                2_400,
            )
            .expect("derive unadmitted application assembly");
        let SprintApplicationPreparation::Ready(assembly) = preparation else {
            panic!("nonempty sole TaskDone source must be application-ready");
        };
        let request = ApplicationRequest {
            contract_version: CONTRACT_VERSION,
            change_set: assembly.change_set.clone(),
            artifact: assembly.artifact.clone(),
        };
        let request_bytes =
            encode("application request", &request).expect("encode unadmitted application request");
        let phase_sequence = candidate
            .ledger
            .next_sequence(&candidate.spec.sprint_id)
            .expect("unadmitted application phase sequence");
        let application_phase_event = AgentEvent {
            contract_version: CONTRACT_VERSION,
            sequence: phase_sequence,
            event_id: "event-unadmitted-application-phase".into(),
            sprint_id: candidate.spec.sprint_id.clone(),
            task_id: None,
            worker_id: None,
            causation_id: Some(final_terminal.event_id),
            correlation_id: "correlation-unadmitted-application".into(),
            policy_hash: Some(applier_launch.policy_hash.clone()),
            occurred_at_unix_ms: 2_400,
            payload: AgentEventKind::SprintStateChanged {
                from: "FinalVerification".into(),
                to: "Applying".into(),
            },
        };
        let application_intent = EffectIntent {
            contract_version: CONTRACT_VERSION,
            effect_id: "effect-unadmitted-application".into(),
            idempotency_key: "key-unadmitted-application".into(),
            sprint_id: candidate.spec.sprint_id.clone(),
            task_id: None,
            worker_id: None,
            worker_lease: None,
            causation_event_id: Some(application_phase_event.event_id.clone()),
            correlation_id: application_phase_event.correlation_id.clone(),
            kind: EffectKind::ApplyChangeSet,
            request_digest: Digest::sha256(&request_bytes),
            policy_hash: applier_launch.policy_hash.clone(),
            input_snapshot: candidate.spec.base_snapshot.clone(),
            created_at_unix_ms: 2_400,
        };
        let application_proposal = effect_proposal_event(
            &application_intent,
            phase_sequence + 1,
            "event-unadmitted-application-proposed",
        );
        let application_admission = SprintApplicationAdmission {
            contract_version: CONTRACT_VERSION,
            admission_id: "admission-unadmitted-application".into(),
            sprint_id: candidate.spec.sprint_id.clone(),
            sprint_phase_event_id: application_phase_event.event_id.clone(),
            final_verification_receipt_id: final_evidence.verification.receipt_id.clone(),
            artifact_assembly_id: assembly.assembly_id,
            effect_id: application_intent.effect_id.clone(),
            runner_launch_id: applier_launch.launch_id.clone(),
            runner_session_id: applier_session.session_id.clone(),
            request,
            admitted_at_unix_ms: application_intent.created_at_unix_ms,
        };
        UnadmittedApplicationApplierFixture {
            candidate,
            final_verification_receipt_id: final_evidence.verification.receipt_id,
            applier_launch,
            applier_session,
            application_admission,
            application_phase_event,
            application_intent,
            application_proposal,
        }
    }

    #[test]
    fn unadmitted_application_applier_cleanup_accepts_exact_registered_session() {
        let mut fixture = prepare_unadmitted_application_applier_fixture(true, true);
        assert_eq!(
            fixture
                .candidate
                .ledger
                .load_runner_session(
                    &fixture.applier_launch.sprint_id,
                    &fixture.applier_session.session_id,
                )
                .expect("load exact registered application-applier session"),
            fixture.applier_session
        );
        let expected_launch = fixture.applier_launch.clone();
        let expected_session = fixture.applier_session.clone();
        let expected_base = fixture.candidate.spec.base_snapshot.clone();
        let callback_invoked = Arc::new(AtomicBool::new(false));
        let callback_flag = Arc::clone(&callback_invoked);
        let persisted = fixture
            .candidate
            .ledger
            .with_unadmitted_application_applier_launch_cleanup_exclusion(
                &fixture.applier_launch.sprint_id,
                &fixture.applier_launch.launch_id,
                &fixture.final_verification_receipt_id,
                move |claim| {
                    callback_flag.store(true, Ordering::SeqCst);
                    assert_eq!(claim.admission().launch, expected_launch);
                    assert!(claim.admission().launch.worker_id.is_none());
                    assert!(claim.admission().launch.worker_lease.is_none());
                    assert_eq!(
                        claim.admission().cleanup_request.platform_backend,
                        WorkerCleanupBackend::TrustedApplierDirectChildWait
                    );
                    assert_eq!(
                        claim.admission().cleanup_effect.intent.input_snapshot,
                        expected_base
                    );
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
                        "unadmitted-application-session-present",
                        2_370,
                    ))
                },
            )
            .expect("clean exact unadmitted application-applier launch");
        assert!(callback_invoked.load(Ordering::SeqCst));
        assert!(matches!(
            persisted.finish_receipt,
            PersistedFinishReceipt::WorkerCleanup(_)
        ));
        assert_eq!(
            row_count(&fixture.candidate.ledger, "sprint_application_admissions"),
            0
        );
    }

    #[test]
    fn unadmitted_application_applier_cleanup_accepts_proven_session_absence() {
        let mut fixture = prepare_unadmitted_application_applier_fixture(false, true);
        let exact_session_count: i64 = fixture
            .candidate
            .ledger
            .connection
            .query_row(
                "SELECT COUNT(*) FROM runner_session_policies
                 WHERE sprint_id = ?1 AND (session_id = ?2 OR launch_id = ?3)",
                params![
                    fixture.applier_launch.sprint_id,
                    fixture.applier_launch.session_id,
                    fixture.applier_launch.launch_id,
                ],
                |row| row.get(0),
            )
            .expect("prove exact application-applier session absence");
        assert_eq!(exact_session_count, 0);

        let callback_invoked = Arc::new(AtomicBool::new(false));
        let callback_flag = Arc::clone(&callback_invoked);
        fixture
            .candidate
            .ledger
            .with_unadmitted_application_applier_launch_cleanup_exclusion(
                &fixture.applier_launch.sprint_id,
                &fixture.applier_launch.launch_id,
                &fixture.final_verification_receipt_id,
                move |claim| {
                    callback_flag.store(true, Ordering::SeqCst);
                    assert!(claim.registered_session().is_none());
                    assert_eq!(
                        claim.minimum_terminal_at_unix_ms(),
                        runner_cleanup_minimum_terminal_time(
                            claim.admission(),
                            claim.preparation(),
                        )
                    );
                    Ok(cleanup_terminal_from_live_claim(
                        claim,
                        "unadmitted-application-session-absent",
                        2_370,
                    ))
                },
            )
            .expect("clean unadmitted application-applier launch without a session");
        assert!(callback_invoked.load(Ordering::SeqCst));
    }

    #[test]
    fn unadmitted_application_applier_cleanup_claim_uses_transaction_current_registration() {
        let mut fixture = prepare_unadmitted_application_applier_fixture(false, true);
        assert!(matches!(
            fixture.candidate.ledger.load_runner_session(
                &fixture.applier_launch.sprint_id,
                &fixture.applier_session.session_id,
            ),
            Err(LedgerError::ArtifactNotFound {
                entity: "runner session policy",
                ..
            })
        ));

        let policy = compiled_test_policy("policy-unadmitted-application-applier");
        fixture
            .candidate
            .ledger
            .register_runner_session(&fixture.applier_session, &policy)
            .expect("register exact Applier after the earlier absence readback");
        let expected_session = fixture.applier_session.clone();
        let callback_invoked = Arc::new(AtomicBool::new(false));
        let callback_flag = Arc::clone(&callback_invoked);
        fixture
            .candidate
            .ledger
            .with_unadmitted_application_applier_launch_cleanup_exclusion(
                &fixture.applier_launch.sprint_id,
                &fixture.applier_launch.launch_id,
                &fixture.final_verification_receipt_id,
                move |claim| {
                    callback_flag.store(true, Ordering::SeqCst);
                    assert_eq!(claim.registered_session(), Some(&expected_session));
                    let expected_minimum = runner_cleanup_minimum_terminal_time(
                        claim.admission(),
                        claim.preparation(),
                    )
                    .max(expected_session.registered_at_unix_ms);
                    assert_eq!(claim.minimum_terminal_at_unix_ms(), expected_minimum);
                    Ok(cleanup_terminal_from_live_claim(
                        claim,
                        "unadmitted-application-transaction-current-session",
                        expected_minimum,
                    ))
                },
            )
            .expect("transaction-current registration authorizes exact cleanup");
        assert!(callback_invoked.load(Ordering::SeqCst));
    }

    #[test]
    fn unadmitted_application_applier_cleanup_rejects_terminal_before_registered_session() {
        let mut fixture = prepare_unadmitted_application_applier_fixture(true, true);
        let crossed_terminal_at = fixture
            .applier_session
            .registered_at_unix_ms
            .saturating_sub(1);
        let cleanup_effect_id = fixture
            .candidate
            .ledger
            .load_runner_launch_cleanup_admission(
                &fixture.applier_launch.sprint_id,
                &fixture.applier_launch.launch_id,
            )
            .expect("load registered Applier cleanup admission")
            .cleanup_effect
            .intent
            .effect_id;
        let callback_invoked = Arc::new(AtomicBool::new(false));
        let callback_flag = Arc::clone(&callback_invoked);
        let error = fixture
            .candidate
            .ledger
            .with_unadmitted_application_applier_launch_cleanup_exclusion(
                &fixture.applier_launch.sprint_id,
                &fixture.applier_launch.launch_id,
                &fixture.final_verification_receipt_id,
                move |claim| {
                    callback_flag.store(true, Ordering::SeqCst);
                    assert!(
                        claim.minimum_terminal_at_unix_ms() > crossed_terminal_at,
                        "registered session must raise the transaction-derived cleanup cut"
                    );
                    Ok(cleanup_terminal_from_live_claim(
                        claim,
                        "unadmitted-application-before-session",
                        crossed_terminal_at,
                    ))
                },
            )
            .expect_err("cleanup terminal cannot predate its registered Applier session");
        assert!(matches!(
            error,
            LedgerError::ReferenceMismatch {
                entity: "runner launch cleanup exclusion",
                ..
            }
        ));
        assert!(callback_invoked.load(Ordering::SeqCst));
        assert!(
            fixture
                .candidate
                .ledger
                .load_effect(&cleanup_effect_id)
                .expect("reload pending cleanup after rejected terminal timestamp")
                .observation
                .is_none()
        );
    }

    #[test]
    fn unadmitted_application_applier_cleanup_rejects_crossed_session_row_before_callback() {
        let mut fixture = prepare_unadmitted_application_applier_fixture(true, true);
        fixture
            .candidate
            .ledger
            .connection
            .execute_batch("DROP TRIGGER runner_session_policies_no_update;")
            .expect("disable immutable-session guard to construct crossed durable state");
        fixture
            .candidate
            .ledger
            .connection
            .pragma_update(None, "foreign_keys", "OFF")
            .expect("disable foreign keys to construct crossed durable state");
        fixture
            .candidate
            .ledger
            .connection
            .execute(
                "UPDATE runner_session_policies SET launch_id = ?1 WHERE session_id = ?2",
                params![
                    "crossed-unadmitted-application-launch",
                    fixture.applier_session.session_id,
                ],
            )
            .expect("cross the indexed Applier session launch");
        fixture
            .candidate
            .ledger
            .connection
            .pragma_update(None, "foreign_keys", "ON")
            .expect("restore foreign-key enforcement");

        let callback_invoked = Arc::new(AtomicBool::new(false));
        let callback_flag = Arc::clone(&callback_invoked);
        let error = fixture
            .candidate
            .ledger
            .with_unadmitted_application_applier_launch_cleanup_exclusion(
                &fixture.applier_launch.sprint_id,
                &fixture.applier_launch.launch_id,
                &fixture.final_verification_receipt_id,
                move |_| {
                    callback_flag.store(true, Ordering::SeqCst);
                    unreachable!("crossed session row must stop before native cleanup")
                },
            )
            .expect_err("crossed session row closes unadmitted cleanup authority");
        assert!(matches!(
            error,
            LedgerError::ReferenceMismatch {
                entity: "unadmitted application-applier launch cleanup",
                ..
            }
        ));
        assert!(!callback_invoked.load(Ordering::SeqCst));
    }

    #[test]
    fn unadmitted_application_applier_cleanup_rejects_existing_admission_before_callback() {
        let mut fixture = prepare_unadmitted_application_applier_fixture(true, true);
        let admitted = fixture
            .candidate
            .ledger
            .admit_sprint_application_for_dispatch(
                &fixture.application_admission,
                &fixture.application_phase_event,
                &fixture.application_intent,
                &fixture.application_proposal,
            )
            .expect("admit application before requesting launch cleanup");
        drop(admitted);

        let callback_invoked = Arc::new(AtomicBool::new(false));
        let callback_flag = Arc::clone(&callback_invoked);
        let error = fixture
            .candidate
            .ledger
            .with_unadmitted_application_applier_launch_cleanup_exclusion(
                &fixture.applier_launch.sprint_id,
                &fixture.applier_launch.launch_id,
                &fixture.final_verification_receipt_id,
                move |_| {
                    callback_flag.store(true, Ordering::SeqCst);
                    unreachable!("application-owned launch must stop before native cleanup")
                },
            )
            .expect_err("application admission closes unadmitted cleanup authority");
        assert!(matches!(
            error,
            LedgerError::ReferenceMismatch {
                entity: "unadmitted application-applier launch cleanup",
                ..
            }
        ));
        assert!(!callback_invoked.load(Ordering::SeqCst));
        assert_eq!(
            row_count(&fixture.candidate.ledger, "sprint_application_admissions"),
            1
        );
    }

    #[test]
    fn unadmitted_application_applier_cleanup_first_blocks_later_application_admission() {
        let mut fixture = prepare_unadmitted_application_applier_fixture(true, true);
        fixture
            .candidate
            .ledger
            .with_unadmitted_application_applier_launch_cleanup_exclusion(
                &fixture.applier_launch.sprint_id,
                &fixture.applier_launch.launch_id,
                &fixture.final_verification_receipt_id,
                |claim| {
                    Ok(cleanup_terminal_from_live_claim(
                        claim,
                        "unadmitted-application-cleanup-first",
                        2_370,
                    ))
                },
            )
            .expect("close application-applier launch before admission");

        fixture.application_phase_event.sequence = fixture
            .candidate
            .ledger
            .next_sequence(&fixture.applier_launch.sprint_id)
            .expect("post-cleanup application phase sequence");
        fixture.application_proposal = effect_proposal_event(
            &fixture.application_intent,
            fixture.application_phase_event.sequence + 1,
            &fixture.application_proposal.event_id,
        );
        let error = fixture
            .candidate
            .ledger
            .admit_sprint_application_for_dispatch(
                &fixture.application_admission,
                &fixture.application_phase_event,
                &fixture.application_intent,
                &fixture.application_proposal,
            )
            .expect_err("cleaned launch cannot later acquire application authority");
        assert!(matches!(
            error,
            LedgerError::ReferenceMismatch {
                entity: "runner launch cleanup admission",
                ..
            }
        ));
        assert_eq!(
            row_count(&fixture.candidate.ledger, "sprint_application_admissions"),
            0
        );
    }

    #[test]
    #[allow(clippy::too_many_lines)] // Independent ledgers prove each crossed authority stops before the native callback.
    fn unadmitted_application_applier_cleanup_rejects_role_backend_snapshot_and_binding() {
        {
            let mut fixture = prepare_unadmitted_application_applier_fixture(false, true);
            let wrong_policy = compiled_test_policy("policy-unadmitted-application-wrong-role");
            let wrong_launch = runner_launch(
                "launch-unadmitted-application-wrong-role",
                "session-unadmitted-application-wrong-role",
                RunnerSessionPurpose::FinalVerifier,
                None,
                &wrong_policy,
                2_380,
            );
            admit_test_runner_launch(&mut fixture.candidate.ledger, &wrong_launch, &wrong_policy);
            let callback_invoked = Arc::new(AtomicBool::new(false));
            let callback_flag = Arc::clone(&callback_invoked);
            assert!(matches!(
                fixture
                    .candidate
                    .ledger
                    .with_unadmitted_application_applier_launch_cleanup_exclusion(
                        &wrong_launch.sprint_id,
                        &wrong_launch.launch_id,
                        &fixture.final_verification_receipt_id,
                        move |_| {
                            callback_flag.store(true, Ordering::SeqCst);
                            unreachable!("non-Applier backend must stop before native cleanup")
                        },
                    ),
                Err(LedgerError::ReferenceMismatch {
                    entity: "unadmitted application-applier launch cleanup",
                    ..
                })
            ));
            assert!(!callback_invoked.load(Ordering::SeqCst));
        }

        {
            let mut fixture = prepare_unadmitted_application_applier_fixture(true, false);
            let callback_invoked = Arc::new(AtomicBool::new(false));
            let callback_flag = Arc::clone(&callback_invoked);
            assert!(matches!(
                fixture
                    .candidate
                    .ledger
                    .with_unadmitted_application_applier_launch_cleanup_exclusion(
                        &fixture.applier_launch.sprint_id,
                        &fixture.applier_launch.launch_id,
                        &fixture.final_verification_receipt_id,
                        move |_| {
                            callback_flag.store(true, Ordering::SeqCst);
                            unreachable!("crossed base snapshot must stop before native cleanup")
                        },
                    ),
                Err(LedgerError::ReferenceMismatch {
                    entity: "unadmitted application-applier launch cleanup",
                    ..
                })
            ));
            assert!(!callback_invoked.load(Ordering::SeqCst));
        }

        {
            let mut fixture = prepare_unadmitted_application_applier_fixture(true, true);
            fixture
                .candidate
                .ledger
                .connection
                .pragma_update(None, "foreign_keys", "OFF")
                .expect("disable foreign keys to construct crossed effect binding");
            fixture
                .candidate
                .ledger
                .connection
                .execute(
                    "INSERT INTO effect_session_bindings (
                         effect_id, sprint_id, launch_id, session_id, contract_version
                     ) VALUES (?1, ?2, ?3, ?4, ?5)",
                    params![
                        "effect-unadmitted-application-crossed-binding",
                        fixture.applier_launch.sprint_id,
                        fixture.applier_launch.launch_id,
                        fixture.applier_launch.session_id,
                        i64::from(CONTRACT_VERSION),
                    ],
                )
                .expect("insert crossed application-applier effect binding");
            fixture
                .candidate
                .ledger
                .connection
                .pragma_update(None, "foreign_keys", "ON")
                .expect("restore foreign-key enforcement");
            let callback_invoked = Arc::new(AtomicBool::new(false));
            let callback_flag = Arc::clone(&callback_invoked);
            assert!(matches!(
                fixture
                    .candidate
                    .ledger
                    .with_unadmitted_application_applier_launch_cleanup_exclusion(
                        &fixture.applier_launch.sprint_id,
                        &fixture.applier_launch.launch_id,
                        &fixture.final_verification_receipt_id,
                        move |_| {
                            callback_flag.store(true, Ordering::SeqCst);
                            unreachable!("bound non-cleanup effect must stop before native cleanup")
                        },
                    ),
                Err(LedgerError::ReferenceMismatch {
                    entity: "unadmitted application-applier launch cleanup",
                    ..
                })
            ));
            assert!(!callback_invoked.load(Ordering::SeqCst));
        }
    }

    #[test]
    fn unadmitted_application_applier_cleanup_replay_is_closed_before_callback() {
        let mut fixture = prepare_unadmitted_application_applier_fixture(true, true);
        fixture
            .candidate
            .ledger
            .with_unadmitted_application_applier_launch_cleanup_exclusion(
                &fixture.applier_launch.sprint_id,
                &fixture.applier_launch.launch_id,
                &fixture.final_verification_receipt_id,
                |claim| {
                    Ok(cleanup_terminal_from_live_claim(
                        claim,
                        "unadmitted-application-replay",
                        2_370,
                    ))
                },
            )
            .expect("close unadmitted application-applier launch once");

        let callback_invoked = Arc::new(AtomicBool::new(false));
        let callback_flag = Arc::clone(&callback_invoked);
        assert!(matches!(
            fixture
                .candidate
                .ledger
                .with_unadmitted_application_applier_launch_cleanup_exclusion(
                    &fixture.applier_launch.sprint_id,
                    &fixture.applier_launch.launch_id,
                    &fixture.final_verification_receipt_id,
                    move |_| {
                        callback_flag.store(true, Ordering::SeqCst);
                        unreachable!("closed cleanup must reject replay")
                    },
                ),
            Err(LedgerError::ReferenceMismatch {
                entity: "runner launch cleanup admission",
                ..
            })
        ));
        assert!(!callback_invoked.load(Ordering::SeqCst));
    }

    #[test]
    fn v21_final_verification_fresh_replay_and_reopen_never_remint() {
        let database = TestDatabase::new();
        let mut ledger = open_v21_test_ledger(&database);
        let fixture = prepare_v21_final_verification_fixture(&mut ledger);
        let first = ledger
            .admit_sprint_final_verification_for_dispatch(
                &fixture.admission,
                &fixture.phase_event,
                &fixture.intent,
                &fixture.proposed_event,
            )
            .expect("fresh v21 final admission");
        let SprintFinalVerificationDispatchAdmission::Fresh {
            admission,
            effect,
            permit,
        } = first
        else {
            panic!("first exact admission must be Fresh");
        };
        assert_eq!(admission, fixture.admission);
        assert_eq!(effect.intent, fixture.intent);

        let replay = ledger
            .admit_sprint_final_verification_for_dispatch(
                &fixture.admission,
                &fixture.phase_event,
                &fixture.intent,
                &fixture.proposed_event,
            )
            .expect("same-process exact replay");
        assert!(matches!(
            replay,
            SprintFinalVerificationDispatchAdmission::Existing { admission, effect }
                if admission == fixture.admission && effect.intent == fixture.intent
        ));
        let (observation, terminal, evidence) = v21_final_verification_terminal(&ledger, &fixture);
        let evidence_bytes = encode("verification effect evidence", &evidence)
            .expect("encode unclaimed final-verification evidence");
        assert!(matches!(
            ledger.record_effect_observation(&observation, &evidence_bytes, &terminal),
            Err(LedgerError::ReferenceMismatch {
                entity: "effect observation",
                ..
            })
        ));
        assert!(matches!(
            ledger.record_verification_effect_observation(&observation, &terminal, &evidence,),
            Err(LedgerError::ReferenceMismatch {
                entity: "verification effect observation",
                ..
            })
        ));
        drop(permit);
        drop(ledger);

        let mut reopened = EventLedger::open(&database.path).expect("reopen v21 ledger");
        let replay = reopened
            .admit_sprint_final_verification_for_dispatch(
                &fixture.admission,
                &fixture.phase_event,
                &fixture.intent,
                &fixture.proposed_event,
            )
            .expect("reopen exact replay");
        assert!(matches!(
            replay,
            SprintFinalVerificationDispatchAdmission::Existing { admission, effect }
                if admission == fixture.admission && effect.intent == fixture.intent
        ));
    }

    #[test]
    fn v21_claimed_final_effect_and_current_admission_readback_do_not_recurse() {
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
            .expect("admit v21 recursion final")
        else {
            panic!("new recursion admission must be Fresh");
        };
        let (claimed, transport) = ledger
            .claim_runner_effect_dispatch(
                FreshRunnerEffectDispatchPermit::SprintFinalVerification(permit),
                OPAQUE_RUNNER_TRANSPORT_REQUEST_BYTES,
            )
            .expect("claim v21 recursion transport");
        let reloaded_effect = ledger
            .load_effect(&fixture.intent.effect_id)
            .expect("claimed final effect readback must terminate");
        assert_eq!(reloaded_effect, claimed);
        assert_eq!(
            ledger
                .load_sprint_final_verification_admission(&fixture.admission.admission_id)
                .expect("current authoritative final admission readback must terminate"),
            fixture.admission
        );
        drop(transport);
    }

    struct V22ApplicationAdmissionFixture {
        candidate: V15CandidateFixture,
        admission: SprintApplicationAdmission,
        assembly: ApplicationArtifactAssembly,
        phase_event: AgentEvent,
        intent: EffectIntent,
        proposal: AgentEvent,
        request: ApplicationRequest,
        request_bytes: Vec<u8>,
        applier_launch: RunnerLaunchIntent,
        applier_session: RunnerSessionPolicyRecord,
        permit: Option<FreshApplicationDispatchPermit>,
    }

    #[allow(clippy::too_many_lines)] // Advances the shared two-task ledger through one independent human-judgment candidate.
    fn advance_v15_fixture_to_second_human_candidate(fixture: &mut V15CandidateFixture) {
        let result_snapshot = WorkspaceSnapshot {
            snapshot_id: digest('6'),
            grant_hash: fixture.spec.workspace_grant.grant_hash.clone(),
            created_at_unix_ms: 1_490,
        };
        let change_set = ChangeSet {
            change_set_id: "change-v22-second-task".into(),
            base_snapshot: fixture.result_snapshot.snapshot_id.clone(),
            result_snapshot: result_snapshot.snapshot_id.clone(),
            operations: vec![crate::FileOperation::Create {
                path: PathBuf::from("second-task.txt"),
                result_hash: digest('5'),
            }],
        };
        fixture
            .ledger
            .persist_workspace_snapshot(&fixture.spec.sprint_id, &result_snapshot)
            .expect("persist second-task result snapshot");
        fixture
            .ledger
            .persist_change_set(&fixture.spec.sprint_id, &change_set)
            .expect("persist second-task change set");
        let ready = AgentEvent {
            contract_version: CONTRACT_VERSION,
            sequence: fixture
                .ledger
                .next_sequence(&fixture.spec.sprint_id)
                .expect("second-task Ready sequence"),
            event_id: "event-v22-second-task-ready".into(),
            sprint_id: fixture.spec.sprint_id.clone(),
            task_id: Some("task-2".into()),
            worker_id: None,
            causation_id: None,
            correlation_id: "v22-second-task".into(),
            policy_hash: None,
            occurred_at_unix_ms: 1_500,
            payload: AgentEventKind::TaskStateChanged {
                from: "Planned".into(),
                to: "Ready".into(),
            },
        };
        fixture
            .ledger
            .append_event(&ready)
            .expect("enter second task Ready");
        let lease = WorkerLease::new(
            fixture.spec.sprint_id.clone(),
            2,
            "task-2".into(),
            "worker-2".into(),
            vec![PathScope::Workspace],
            1_510,
        )
        .expect("construct second-task lease");
        let acquired = AgentEvent {
            contract_version: CONTRACT_VERSION,
            sequence: fixture
                .ledger
                .next_sequence(&fixture.spec.sprint_id)
                .expect("second-task acquisition sequence"),
            event_id: "event-v22-second-task-acquired".into(),
            sprint_id: fixture.spec.sprint_id.clone(),
            task_id: Some(lease.task_id.clone()),
            worker_id: Some(lease.worker_id.clone()),
            causation_id: Some(ready.event_id),
            correlation_id: "v22-second-task".into(),
            policy_hash: None,
            occurred_at_unix_ms: lease.acquired_at_unix_ms,
            payload: AgentEventKind::TaskStateChanged {
                from: "Ready".into(),
                to: "Leased".into(),
            },
        };
        fixture
            .ledger
            .acquire_task_attempt(&lease, &acquired)
            .expect("acquire second-task attempt");
        let policy = compiled_shadow_test_policy("policy-v22-second-task");
        let mut launch = runner_launch(
            "launch-v22-second-task",
            "session-v22-second-task",
            RunnerSessionPurpose::TaskWorker,
            Some("worker-2"),
            &policy,
            1_520,
        );
        launch.worker_lease = Some(lease.clone());
        admit_test_runner_launch(&mut fixture.ledger, &launch, &policy);
        fixture
            .ledger
            .register_runner_session(&runner_session(&launch, 1_530), &policy)
            .expect("register second-task worker session");
        let attempt = fixture
            .ledger
            .load_task_attempt(&lease.lease_id)
            .expect("load second-task attempt");
        let running_event = AgentEvent {
            contract_version: CONTRACT_VERSION,
            sequence: fixture
                .ledger
                .next_sequence(&fixture.spec.sprint_id)
                .expect("second-task Running sequence"),
            event_id: "event-v22-second-task-running".into(),
            sprint_id: fixture.spec.sprint_id.clone(),
            task_id: Some(lease.task_id.clone()),
            worker_id: Some(lease.worker_id.clone()),
            causation_id: Some(attempt.opening_event_id.clone()),
            correlation_id: "v22-second-task".into(),
            policy_hash: Some(launch.policy_hash.clone()),
            occurred_at_unix_ms: 1_540,
            payload: AgentEventKind::TaskStateChanged {
                from: "Leased".into(),
                to: "Running".into(),
            },
        };
        let running = TaskAttemptRunningBoundary {
            contract_version: CONTRACT_VERSION,
            boundary_id: "boundary-v22-second-task-running".into(),
            attempt: attempt.clone(),
            runner_launch_id: launch.launch_id.clone(),
            runner_session_id: launch.session_id.clone(),
            transition_event_id: running_event.event_id.clone(),
            started_at_unix_ms: running_event.occurred_at_unix_ms,
        };
        fixture
            .ledger
            .start_task_attempt(&running, &running_event)
            .expect("enter second-task Running");
        let verification_event = AgentEvent {
            contract_version: CONTRACT_VERSION,
            sequence: fixture
                .ledger
                .next_sequence(&fixture.spec.sprint_id)
                .expect("second-task Verifying sequence"),
            event_id: "event-v22-second-task-verifying".into(),
            sprint_id: fixture.spec.sprint_id.clone(),
            task_id: Some(lease.task_id.clone()),
            worker_id: Some(lease.worker_id.clone()),
            causation_id: Some(running_event.event_id),
            correlation_id: "v22-second-task".into(),
            policy_hash: Some(launch.policy_hash.clone()),
            occurred_at_unix_ms: 1_550,
            payload: AgentEventKind::TaskStateChanged {
                from: "Running".into(),
                to: "Verifying".into(),
            },
        };
        let verification = TaskAttemptVerificationBoundary {
            contract_version: CONTRACT_VERSION,
            boundary_id: "boundary-v22-second-task-verifying".into(),
            attempt: attempt.clone(),
            runner_launch_id: launch.launch_id.clone(),
            runner_session_id: launch.session_id.clone(),
            change_set_id: change_set.change_set_id.clone(),
            sealed_snapshot: result_snapshot.snapshot_id.clone(),
            transition_event_id: verification_event.event_id.clone(),
            terminal_non_cleanup_effects: Vec::new(),
            sealed_at_unix_ms: verification_event.occurred_at_unix_ms,
        };
        fixture
            .ledger
            .transition_task_attempt_to_verifying(&verification, &verification_event)
            .expect("enter second-task Verifying");
        let candidate_event = AgentEvent {
            contract_version: CONTRACT_VERSION,
            sequence: fixture
                .ledger
                .next_sequence(&fixture.spec.sprint_id)
                .expect("second-task Candidate sequence"),
            event_id: "event-v22-second-task-candidate".into(),
            sprint_id: fixture.spec.sprint_id.clone(),
            task_id: Some(lease.task_id.clone()),
            worker_id: Some(lease.worker_id.clone()),
            causation_id: Some(verification_event.event_id),
            correlation_id: "v22-second-task".into(),
            policy_hash: Some(launch.policy_hash.clone()),
            occurred_at_unix_ms: 1_560,
            payload: AgentEventKind::TaskStateChanged {
                from: "Verifying".into(),
                to: "Candidate".into(),
            },
        };
        let candidate = TaskAttemptCandidateBoundary {
            contract_version: CONTRACT_VERSION,
            boundary_id: "boundary-v22-second-task-candidate".into(),
            attempt: attempt.clone(),
            verification_boundary_id: verification.boundary_id.clone(),
            change_set_id: change_set.change_set_id.clone(),
            sealed_snapshot: result_snapshot.snapshot_id.clone(),
            formal_check_ids: Vec::new(),
            verification_receipt_ids: Vec::new(),
            transition_event_id: candidate_event.event_id.clone(),
            admitted_at_unix_ms: candidate_event.occurred_at_unix_ms,
        };
        fixture
            .ledger
            .transition_task_attempt_to_candidate(&candidate, &candidate_event)
            .expect("enter second-task Candidate");
        fixture.result_snapshot = result_snapshot;
        fixture.change_set = change_set;
        fixture.launch = launch;
        fixture.attempt = attempt;
        fixture.running = running;
        fixture.verification = verification;
        fixture.formal_checks.clear();
        fixture.candidate = candidate;
        fixture.prior_attempt = None;
        fixture.prior_disposition = None;
        fixture.prior_launch = None;
        fixture.candidate_required = false;
    }

    #[allow(clippy::too_many_lines)] // One visible chain builds every v22 application admission prerequisite.
    fn prepare_v22_application_admission_fixture() -> V22ApplicationAdmissionFixture {
        prepare_v22_application_admission_fixture_with_options(
            false,
            CandidateTaskRequirement::Required,
        )
    }

    #[allow(clippy::too_many_lines)] // Optional crossed calls exercise the same exact pre-admission cut.
    fn prepare_v22_application_admission_fixture_with_crosses(
        exercise_crosses: bool,
    ) -> V22ApplicationAdmissionFixture {
        prepare_v22_application_admission_fixture_with_options(
            exercise_crosses,
            CandidateTaskRequirement::Required,
        )
    }

    #[allow(clippy::too_many_lines)] // Requirement variants share the same exact v22 authority chain.
    fn prepare_v22_application_admission_fixture_with_options(
        exercise_crosses: bool,
        candidate_requirement: CandidateTaskRequirement,
    ) -> V22ApplicationAdmissionFixture {
        prepare_v22_application_admission_fixture_with_options_at_generation(
            exercise_crosses,
            candidate_requirement,
            false,
            None,
        )
    }

    #[allow(clippy::too_many_lines)]
    fn prepare_v22_application_admission_fixture_with_options_at_v23(
        exercise_crosses: bool,
        candidate_requirement: CandidateTaskRequirement,
    ) -> V22ApplicationAdmissionFixture {
        prepare_v22_application_admission_fixture_with_options_at_generation(
            exercise_crosses,
            candidate_requirement,
            true,
            None,
        )
    }

    #[allow(clippy::too_many_lines)]
    fn prepare_v22_application_admission_fixture_with_snapshots(
        base_snapshot_id: Digest,
        result_snapshot_id: Digest,
    ) -> V22ApplicationAdmissionFixture {
        prepare_v22_application_admission_fixture_with_options_at_generation(
            false,
            CandidateTaskRequirement::Required,
            false,
            Some(V15SnapshotOverrides {
                base_snapshot_id,
                result_snapshot_id,
            }),
        )
    }

    #[allow(clippy::too_many_lines)]
    fn prepare_v22_application_admission_fixture_with_options_at_generation(
        exercise_crosses: bool,
        candidate_requirement: CandidateTaskRequirement,
        historical_v23: bool,
        snapshot_overrides: Option<V15SnapshotOverrides>,
    ) -> V22ApplicationAdmissionFixture {
        let mut candidate =
            prepare_v15_candidate_fixture_with_graph_options_at_generation_and_snapshot_overrides(
                true,
                false,
                false,
                false,
                candidate_requirement,
                None,
                false,
                snapshot_overrides,
                historical_v23,
            );
        let (_, integration_evidence, integration_disposition) =
            integrate_v15_candidate(&mut candidate, "v22-application", false);
        let worker_command = candidate
            .ledger
            .load_command_domain_effect_bindings(
                &candidate.spec.sprint_id,
                &candidate.launch.launch_id,
                &candidate.launch.session_id,
            )
            .expect("load v22 application worker command binding")
            .into_iter()
            .find(|binding| binding.effect_id == "effect-v15-formal")
            .expect("find v22 application worker command binding");
        ensure_test_command_domain_cleanup(
            &mut candidate.ledger,
            &worker_command,
            "command-cleanup-v22-application-worker",
            CommandDomainBackend::LinuxCgroupV2,
            CommandDomainCleanupDisposition::ReapedZeroSurvivors,
            1_400,
        );
        let worker_cleanup = cleanup_terminal_record(
            &candidate.ledger,
            &candidate.launch,
            "cleanup-v22-application-worker",
            1_450,
        );
        candidate
            .ledger
            .with_integrated_task_attempt_cleanup_exclusion(
                &integration_disposition.metadata().disposition_id,
                |_| Ok(worker_cleanup),
            )
            .expect("close v22 application TaskDone winner");
        assert!(
            candidate
                .ledger
                .assess_task_done(&candidate.spec.sprint_id, "task-1")
                .expect("assess v22 application TaskDone")
                .is_done()
        );

        let mut final_fixture = build_v21_final_verification_fixture(
            &mut candidate.ledger,
            candidate.result_snapshot.snapshot_id.clone(),
        );
        let AcceptanceKind::Automated(final_command) = &candidate.spec.acceptance_criteria[0].kind
        else {
            panic!("v22 application fixture requires automated acceptance");
        };
        bind_v21_final_fixture_command(&mut final_fixture, final_command.clone());
        let final_permit = admit_test_final_verification(&mut candidate.ledger, &final_fixture);
        let (final_authority, final_acquired) =
            claim_test_final_verification(&mut candidate.ledger, &final_fixture, final_permit);
        let (final_observation, final_terminal, final_evidence) =
            v21_final_verification_terminal(&candidate.ledger, &final_fixture);
        complete_test_final_verification(
            &mut candidate.ledger,
            &final_fixture,
            final_authority,
            final_acquired.as_ref(),
            &final_observation,
            &final_terminal,
            &final_evidence,
        );
        if exercise_crosses {
            assert!(
                candidate
                    .ledger
                    .assess_sprint_application_preparation(
                        &candidate.spec.sprint_id,
                        &final_evidence.verification.receipt_id,
                        "assembly-v22-before-final-cleanup",
                        2_310,
                    )
                    .is_err()
            );
        }
        let final_command = candidate
            .ledger
            .load_command_domain_effect_bindings(
                &candidate.spec.sprint_id,
                &final_fixture.launch.launch_id,
                &final_fixture.session.session_id,
            )
            .expect("load v22 final-verification command binding")
            .into_iter()
            .find(|binding| binding.effect_id == final_fixture.intent.effect_id)
            .expect("find v22 final-verification command binding");
        ensure_test_command_domain_cleanup(
            &mut candidate.ledger,
            &final_command,
            "command-cleanup-v22-final",
            CommandDomainBackend::LinuxCgroupV2,
            CommandDomainCleanupDisposition::ReapedZeroSurvivors,
            2_320,
        );
        persist_cleanup_evidence(
            &mut candidate.ledger,
            &final_fixture.launch,
            &candidate.result_snapshot.snapshot_id,
            "cleanup-v22-final",
            WorkerCleanupBackend::LinuxCgroupV2,
            2_310,
            2_340,
        );

        let applier_policy = compiled_test_policy("policy-v22-application-applier");
        let applier_launch = runner_launch(
            "launch-v22-application-applier",
            "session-v22-application-applier",
            RunnerSessionPurpose::Applier,
            None,
            &applier_policy,
            2_350,
        );
        admit_test_runner_launch(&mut candidate.ledger, &applier_launch, &applier_policy);
        let applier_session = runner_session(&applier_launch, 2_360);
        candidate
            .ledger
            .register_runner_session(&applier_session, &applier_policy)
            .expect("register v22 application Applier session");

        let preparation = candidate
            .ledger
            .assess_sprint_application_preparation(
                &candidate.spec.sprint_id,
                &final_evidence.verification.receipt_id,
                "assembly-v22-application",
                2_400,
            )
            .expect("derive exact v22 application assembly");
        let SprintApplicationPreparation::Ready(assembly) = preparation else {
            panic!("nonempty sole TaskDone source must produce a ready v22 assembly");
        };
        assert_eq!(assembly.change_set, candidate.change_set);
        assert_eq!(assembly.artifact, integration_evidence.artifact);
        assert_eq!(assembly.sources.len(), 1);
        assert_eq!(assembly.sources[0].source_ordinal, 0);

        let request = ApplicationRequest {
            contract_version: CONTRACT_VERSION,
            change_set: assembly.change_set.clone(),
            artifact: assembly.artifact.clone(),
        };
        let request_bytes =
            encode("application request", &request).expect("encode v22 application request");
        let phase_sequence = candidate
            .ledger
            .next_sequence(&candidate.spec.sprint_id)
            .expect("v22 Applying phase sequence");
        let phase_event = AgentEvent {
            contract_version: CONTRACT_VERSION,
            sequence: phase_sequence,
            event_id: "event-v22-application-phase".into(),
            sprint_id: candidate.spec.sprint_id.clone(),
            task_id: None,
            worker_id: None,
            causation_id: Some(final_terminal.event_id.clone()),
            correlation_id: "correlation-v22-application".into(),
            policy_hash: Some(applier_launch.policy_hash.clone()),
            occurred_at_unix_ms: 2_400,
            payload: AgentEventKind::SprintStateChanged {
                from: "FinalVerification".into(),
                to: "Applying".into(),
            },
        };
        let application_intent = EffectIntent {
            contract_version: CONTRACT_VERSION,
            effect_id: "effect-v22-application".into(),
            idempotency_key: "key-v22-application".into(),
            sprint_id: candidate.spec.sprint_id.clone(),
            task_id: None,
            worker_id: None,
            worker_lease: None,
            causation_event_id: Some(phase_event.event_id.clone()),
            correlation_id: phase_event.correlation_id.clone(),
            kind: EffectKind::ApplyChangeSet,
            request_digest: Digest::sha256(&request_bytes),
            policy_hash: applier_launch.policy_hash.clone(),
            input_snapshot: candidate.spec.base_snapshot.clone(),
            created_at_unix_ms: 2_400,
        };
        let application_proposal = effect_proposal_event(
            &application_intent,
            phase_sequence + 1,
            "event-v22-application-proposed",
        );
        let admission = SprintApplicationAdmission {
            contract_version: CONTRACT_VERSION,
            admission_id: "admission-v22-application".into(),
            sprint_id: candidate.spec.sprint_id.clone(),
            sprint_phase_event_id: phase_event.event_id.clone(),
            final_verification_receipt_id: final_evidence.verification.receipt_id.clone(),
            artifact_assembly_id: assembly.assembly_id.clone(),
            effect_id: application_intent.effect_id.clone(),
            runner_launch_id: applier_launch.launch_id.clone(),
            runner_session_id: applier_session.session_id.clone(),
            request: request.clone(),
            admitted_at_unix_ms: application_intent.created_at_unix_ms,
        };
        if exercise_crosses {
            let mut crossed_final = admission.clone();
            crossed_final.final_verification_receipt_id = "receipt-v15-formal".into();
            assert!(
                candidate
                    .ledger
                    .admit_sprint_application_for_dispatch(
                        &crossed_final,
                        &phase_event,
                        &application_intent,
                        &application_proposal,
                    )
                    .is_err()
            );

            let mut crossed_phase = phase_event.clone();
            crossed_phase.causation_id = Some(final_fixture.phase_event.event_id.clone());
            assert!(
                candidate
                    .ledger
                    .admit_sprint_application_for_dispatch(
                        &admission,
                        &crossed_phase,
                        &application_intent,
                        &application_proposal,
                    )
                    .is_err()
            );

            let mut crossed_session = admission.clone();
            crossed_session.runner_session_id = final_fixture.session.session_id.clone();
            assert!(
                candidate
                    .ledger
                    .admit_sprint_application_for_dispatch(
                        &crossed_session,
                        &phase_event,
                        &application_intent,
                        &application_proposal,
                    )
                    .is_err()
            );

            let mut crossed_artifact_admission = admission.clone();
            crossed_artifact_admission.request.artifact.artifact_digest = digest('f');
            let crossed_artifact_bytes = encode(
                "crossed v22 application request",
                &crossed_artifact_admission.request,
            )
            .expect("encode crossed v22 application request");
            let mut crossed_artifact_intent = application_intent.clone();
            crossed_artifact_intent.request_digest = Digest::sha256(&crossed_artifact_bytes);
            let crossed_artifact_proposal = effect_proposal_event(
                &crossed_artifact_intent,
                application_proposal.sequence,
                &application_proposal.event_id,
            );
            assert!(
                candidate
                    .ledger
                    .admit_sprint_application_for_dispatch(
                        &crossed_artifact_admission,
                        &phase_event,
                        &crossed_artifact_intent,
                        &crossed_artifact_proposal,
                    )
                    .is_err()
            );

            let raw_multi_source = candidate.ledger.connection.execute(
                "INSERT INTO application_artifact_assemblies (
                    assembly_id, sprint_id, final_verification_receipt_id,
                    change_set_id, base_snapshot, result_snapshot,
                    artifact_format_version, artifact_digest, source_count,
                    contract_version, assembled_at_unix_ms, assembly_json
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, 2, ?9, ?10, ?11)",
                params![
                    assembly.assembly_id,
                    assembly.sprint_id,
                    assembly.final_verification_receipt_id,
                    assembly.change_set.change_set_id,
                    assembly.change_set.base_snapshot.as_str(),
                    assembly.change_set.result_snapshot.as_str(),
                    i64::from(assembly.artifact.format_version),
                    assembly.artifact.artifact_digest.as_str(),
                    i64::from(CONTRACT_VERSION),
                    i64::try_from(assembly.assembled_at_unix_ms).unwrap(),
                    encode("application artifact assembly", &assembly)
                        .expect("encode raw multi-source assembly"),
                ],
            );
            assert!(raw_multi_source.is_err());
            assert_eq!(
                row_count(&candidate.ledger, "application_artifact_assemblies"),
                0
            );
            assert_eq!(
                row_count(&candidate.ledger, "sprint_application_admissions"),
                0
            );
        }
        let SprintApplicationDispatchAdmission::Fresh {
            admission: stored_admission,
            assembly: stored_assembly,
            effect,
            permit,
        } = candidate
            .ledger
            .admit_sprint_application_for_dispatch(
                &admission,
                &phase_event,
                &application_intent,
                &application_proposal,
            )
            .expect("atomically admit fresh v22 application")
        else {
            panic!("first v22 application admission must be Fresh");
        };
        assert_eq!(stored_admission, admission);
        assert_eq!(stored_assembly, assembly);
        assert_eq!(effect.intent, application_intent);
        assert!(matches!(
            candidate.ledger.admit_sprint_application_for_dispatch(
                &admission,
                &phase_event,
                &application_intent,
                &application_proposal,
            ),
            Ok(SprintApplicationDispatchAdmission::Existing {
                admission: ref replay_admission,
                assembly: ref replay_assembly,
                ref effect,
            }) if replay_admission == &admission
                && replay_assembly == &assembly
                && effect.dispatch_claim.is_none()
        ));
        V22ApplicationAdmissionFixture {
            candidate,
            admission,
            assembly,
            phase_event,
            intent: application_intent,
            proposal: application_proposal,
            request,
            request_bytes,
            applier_launch,
            applier_session,
            permit: Some(permit),
        }
    }

    struct V22ApplicationTerminalFixture {
        receipt: ApplicationReceipt,
        evidence: ApplicationEvidence,
        evidence_bytes: Vec<u8>,
        observation: EffectObservation,
        event: AgentEvent,
        rollback: RollbackReferenceEvidence,
    }

    fn v22_application_terminal_fixture(
        fixture: &V22ApplicationAdmissionFixture,
    ) -> V22ApplicationTerminalFixture {
        let application_receipt = ApplicationReceipt {
            contract_version: CONTRACT_VERSION,
            receipt_id: "receipt-v22-application".into(),
            sprint_id: fixture.candidate.spec.sprint_id.clone(),
            effect_id: fixture.intent.effect_id.clone(),
            observation_id: "observation-v22-application".into(),
            applier_session_id: fixture.applier_session.session_id.clone(),
            transaction_id: "transaction-v22-application".into(),
            change_set_id: fixture.request.change_set.change_set_id.clone(),
            base_snapshot: fixture.request.change_set.base_snapshot.clone(),
            result_snapshot: fixture.request.change_set.result_snapshot.clone(),
            policy_hash: fixture.applier_launch.policy_hash.clone(),
            grant_hash: fixture.applier_launch.grant_hash.clone(),
            policy_version: fixture.applier_launch.policy_version,
            applied_operations_digest: fixture
                .request
                .change_set
                .applied_operations_digest()
                .expect("digest v22 applied operations"),
            touched_path_endpoints_digest: fixture
                .request
                .change_set
                .touched_path_endpoints_digest()
                .expect("digest v22 touched endpoints"),
            live_manifest_digest: digest('9'),
            applied_at_unix_ms: 2_500,
        };
        let application_evidence = ApplicationEvidence {
            contract_version: CONTRACT_VERSION,
            validation: crate::ApplicationValidationEvidence {
                mode: ApplicationValidationMode::DirectEffectResponse,
                runner_launch_id: fixture.applier_launch.launch_id.clone(),
                runner_session_id: fixture.applier_session.session_id.clone(),
                policy_hash: fixture.applier_launch.policy_hash.clone(),
                grant_hash: fixture.applier_launch.grant_hash.clone(),
                policy_version: fixture.applier_launch.policy_version,
                private_state_digest: fixture.applier_launch.private_state_digest.clone(),
            },
            receipt: application_receipt.clone(),
        };
        let application_evidence_bytes = encode("application evidence", &application_evidence)
            .expect("encode v22 application evidence");
        let application_observation = effect_observation(
            &fixture.intent,
            &application_receipt.observation_id,
            EffectOutcome::Succeeded {
                evidence_digest: Digest::sha256(&application_evidence_bytes),
            },
            application_receipt.applied_at_unix_ms,
        );
        let application_terminal = effect_terminal_event(
            &fixture.intent,
            &fixture.proposal.event_id,
            &application_observation,
            fixture
                .candidate
                .ledger
                .next_sequence(&fixture.candidate.spec.sprint_id)
                .expect("v22 application terminal sequence"),
            "event-v22-application-finished",
        );
        let reopened_artifacts_bytes = b"v22 exact reopened rollback artifacts".to_vec();
        let rollback = RollbackReferenceEvidence {
            reference: RollbackReference {
                contract_version: CONTRACT_VERSION,
                reference_id: "rollback-reference-v22-application".into(),
                sprint_id: fixture.candidate.spec.sprint_id.clone(),
                application_receipt_id: application_receipt.receipt_id.clone(),
                transaction_id: application_receipt.transaction_id.clone(),
                journal_binding_digest: application_receipt
                    .journal_binding_digest()
                    .expect("digest v22 application journal binding"),
                base_snapshot: application_receipt.base_snapshot.clone(),
                touched_target_set_digest: fixture
                    .request
                    .change_set
                    .touched_target_set_digest()
                    .expect("digest v22 application target set"),
                reopened_artifacts_digest: Digest::sha256(&reopened_artifacts_bytes),
                validated_at_unix_ms: 2_510,
            },
            reopened_artifacts_bytes,
        };
        V22ApplicationTerminalFixture {
            receipt: application_receipt,
            evidence: application_evidence,
            evidence_bytes: application_evidence_bytes,
            observation: application_observation,
            event: application_terminal,
            rollback,
        }
    }

    fn persist_v22_claimed_application_fixture(
        fixture: &mut V22ApplicationAdmissionFixture,
    ) -> V22ApplicationTerminalFixture {
        let terminal = v22_application_terminal_fixture(fixture);
        let (_, transport) = fixture
            .candidate
            .ledger
            .claim_runner_effect_dispatch(
                FreshRunnerEffectDispatchPermit::SprintApplication(
                    fixture
                        .permit
                        .take()
                        .expect("claim fixture's sole v22 application permit"),
                ),
                OPAQUE_RUNNER_TRANSPORT_REQUEST_BYTES,
            )
            .expect("claim fixture v22 application dispatch");
        let authority = transport
            .validate_transport_request(
                &fixture.intent,
                &fixture.request_bytes,
                &fixture.applier_launch,
                &fixture.applier_session,
                None,
                OPAQUE_RUNNER_TRANSPORT_REQUEST_BYTES,
            )
            .expect("validate fixture v22 application transport");
        fixture
            .candidate
            .ledger
            .record_claimed_application_effect_observation_with_rollback(
                authority,
                &terminal.observation,
                &terminal.event,
                &terminal.evidence,
                &terminal.rollback,
            )
            .expect("persist fixture claimed application and rollback");
        terminal
    }

    struct V22ExplicitEmptyPreparationFixture {
        candidate: V15CandidateFixture,
        final_evidence: VerificationEffectEvidence,
    }

    #[allow(clippy::too_many_lines)] // Builds the exact TaskDone, claimed-final, and cleanup cut for no-op proof.
    fn prepare_v22_explicit_empty_preparation_fixture() -> V22ExplicitEmptyPreparationFixture {
        prepare_v22_explicit_empty_preparation_fixture_with_requirement(
            CandidateTaskRequirement::Required,
        )
    }

    #[allow(clippy::too_many_lines)] // Required and optional no-op winners share one exact gate.
    fn prepare_v22_explicit_empty_preparation_fixture_with_requirement(
        candidate_requirement: CandidateTaskRequirement,
    ) -> V22ExplicitEmptyPreparationFixture {
        prepare_v22_explicit_empty_preparation_fixture_with_requirement_and_snapshot_override(
            candidate_requirement,
            None,
            false,
        )
    }

    #[allow(clippy::too_many_lines)]
    fn prepare_v22_explicit_empty_preparation_fixture_with_requirement_at_v23(
        candidate_requirement: CandidateTaskRequirement,
    ) -> V22ExplicitEmptyPreparationFixture {
        prepare_v22_explicit_empty_preparation_fixture_with_requirement_and_snapshot_override(
            candidate_requirement,
            None,
            true,
        )
    }

    #[allow(clippy::too_many_lines)]
    fn prepare_v22_explicit_empty_preparation_fixture_with_base_snapshot(
        base_snapshot_id: Digest,
    ) -> V22ExplicitEmptyPreparationFixture {
        prepare_v22_explicit_empty_preparation_fixture_with_requirement_and_snapshot_override(
            CandidateTaskRequirement::Required,
            Some(base_snapshot_id),
            false,
        )
    }

    #[allow(clippy::too_many_lines)] // Snapshot override is test-only v24 manifest/snapshot plumbing.
    fn prepare_v22_explicit_empty_preparation_fixture_with_requirement_and_snapshot_override(
        candidate_requirement: CandidateTaskRequirement,
        base_snapshot_id: Option<Digest>,
        historical_v23: bool,
    ) -> V22ExplicitEmptyPreparationFixture {
        let mut candidate =
            prepare_v15_candidate_fixture_with_graph_options_at_generation_and_snapshot_overrides(
                true,
                true,
                false,
                false,
                candidate_requirement,
                None,
                false,
                base_snapshot_id.map(|snapshot_id| V15SnapshotOverrides {
                    base_snapshot_id: snapshot_id.clone(),
                    result_snapshot_id: snapshot_id,
                }),
                historical_v23,
            );
        let (_, _, integration_disposition) =
            integrate_v15_candidate(&mut candidate, "v22-explicit-empty", false);
        let worker_command = candidate
            .ledger
            .load_command_domain_effect_bindings(
                &candidate.spec.sprint_id,
                &candidate.launch.launch_id,
                &candidate.launch.session_id,
            )
            .expect("load explicit-empty worker command binding")
            .into_iter()
            .find(|binding| binding.effect_id == "effect-v15-formal")
            .expect("find explicit-empty worker command binding");
        ensure_test_command_domain_cleanup(
            &mut candidate.ledger,
            &worker_command,
            "command-cleanup-v22-explicit-empty-worker",
            CommandDomainBackend::LinuxCgroupV2,
            CommandDomainCleanupDisposition::ReapedZeroSurvivors,
            1_400,
        );
        let worker_cleanup = cleanup_terminal_record(
            &candidate.ledger,
            &candidate.launch,
            "cleanup-v22-explicit-empty-worker",
            1_450,
        );
        candidate
            .ledger
            .with_integrated_task_attempt_cleanup_exclusion(
                &integration_disposition.metadata().disposition_id,
                |_| Ok(worker_cleanup),
            )
            .expect("close explicit-empty TaskDone winner");

        let mut final_fixture = build_v21_final_verification_fixture(
            &mut candidate.ledger,
            candidate.spec.base_snapshot.clone(),
        );
        let AcceptanceKind::Automated(final_command) = &candidate.spec.acceptance_criteria[0].kind
        else {
            panic!("explicit-empty fixture requires automated acceptance");
        };
        bind_v21_final_fixture_command(&mut final_fixture, final_command.clone());
        let permit = admit_test_final_verification(&mut candidate.ledger, &final_fixture);
        let (authority, acquired) =
            claim_test_final_verification(&mut candidate.ledger, &final_fixture, permit);
        let (observation, event, final_evidence) =
            v21_final_verification_terminal(&candidate.ledger, &final_fixture);
        complete_test_final_verification(
            &mut candidate.ledger,
            &final_fixture,
            authority,
            acquired.as_ref(),
            &observation,
            &event,
            &final_evidence,
        );
        let final_command = candidate
            .ledger
            .load_command_domain_effect_bindings(
                &candidate.spec.sprint_id,
                &final_fixture.launch.launch_id,
                &final_fixture.session.session_id,
            )
            .expect("load explicit-empty final command binding")
            .into_iter()
            .find(|binding| binding.effect_id == final_fixture.intent.effect_id)
            .expect("find explicit-empty final command binding");
        ensure_test_command_domain_cleanup(
            &mut candidate.ledger,
            &final_command,
            "command-cleanup-v22-explicit-empty-final",
            CommandDomainBackend::LinuxCgroupV2,
            CommandDomainCleanupDisposition::ReapedZeroSurvivors,
            2_320,
        );
        persist_cleanup_evidence(
            &mut candidate.ledger,
            &final_fixture.launch,
            &candidate.spec.base_snapshot,
            "cleanup-v22-explicit-empty-final",
            WorkerCleanupBackend::LinuxCgroupV2,
            2_310,
            2_340,
        );
        V22ExplicitEmptyPreparationFixture {
            candidate,
            final_evidence,
        }
    }

    #[test]
    #[allow(clippy::too_many_lines)] // Claimless, generic, retry-custody, and reopen assertions share one exact authority chain.
    fn v22_application_fresh_claimed_terminal_replay_and_reopen() {
        let mut fixture = prepare_v22_application_admission_fixture();
        let terminal = v22_application_terminal_fixture(&fixture);
        let observation_count = row_count(&fixture.candidate.ledger, "effect_observations");
        let (_, application_transport) = fixture
            .candidate
            .ledger
            .claim_runner_effect_dispatch(
                FreshRunnerEffectDispatchPermit::SprintApplication(
                    fixture.permit.take().expect("fresh v22 application permit"),
                ),
                OPAQUE_RUNNER_TRANSPORT_REQUEST_BYTES,
            )
            .expect("claim fresh v22 application dispatch");
        let application_authority = application_transport
            .validate_transport_request(
                &fixture.intent,
                &fixture.request_bytes,
                &fixture.applier_launch,
                &fixture.applier_session,
                None,
                OPAQUE_RUNNER_TRANSPORT_REQUEST_BYTES,
            )
            .expect("validate exact v22 application transport");
        assert!(matches!(
            fixture
                .candidate
                .ledger
                .record_application_effect_observation_with_rollback(
                    &terminal.observation,
                    &terminal.event,
                    &terminal.evidence,
                    &terminal.rollback,
                ),
            Err(LedgerError::ReferenceMismatch {
                entity: "application effect observation",
                ..
            })
        ));
        let generic_failure = fixture
            .candidate
            .ledger
            .try_record_claimed_effect_observation(
                application_authority,
                &terminal.observation,
                &terminal.evidence_bytes,
                &terminal.event,
            )
            .expect_err("generic claimed success cannot close SprintApplication");
        assert!(matches!(
            generic_failure.error(),
            LedgerError::FinishReceiptRequired {
                effect_id,
                kind: EffectKind::ApplyChangeSet,
            } if effect_id == &fixture.intent.effect_id
        ));
        let (_, application_authority) = generic_failure.into_parts();
        fixture
            .candidate
            .ledger
            .connection
            .execute_batch(
                "CREATE TEMP TRIGGER inject_v22_application_late_precommit_failure
                 BEFORE INSERT ON application_receipts
                 BEGIN
                   SELECT RAISE(ABORT, 'injected v22 application precommit failure');
                 END;",
            )
            .expect("install v22 application precommit fault");
        let typed_failure = fixture
            .candidate
            .ledger
            .record_claimed_application_effect_observation_with_rollback(
                application_authority.expect("generic failure returns v22 application authority"),
                &terminal.observation,
                &terminal.event,
                &terminal.evidence,
                &terminal.rollback,
            )
            .expect_err("late v22 application insert must roll back");
        assert!(typed_failure.has_retry_authority());
        assert_eq!(
            row_count(&fixture.candidate.ledger, "application_receipts"),
            0
        );
        assert_eq!(
            row_count(&fixture.candidate.ledger, "rollback_references"),
            0
        );
        assert_eq!(
            row_count(&fixture.candidate.ledger, "effect_observations"),
            observation_count
        );
        let (_, application_authority) = typed_failure.into_parts();
        fixture
            .candidate
            .ledger
            .connection
            .execute_batch("DROP TRIGGER inject_v22_application_late_precommit_failure;")
            .expect("remove v22 application precommit fault");
        let persisted = fixture
            .candidate
            .ledger
            .record_claimed_application_effect_observation_with_rollback(
                application_authority.expect("precommit failure returns exact v22 authority"),
                &terminal.observation,
                &terminal.event,
                &terminal.evidence,
                &terminal.rollback,
            )
            .expect("atomically persist claimed v22 application and rollback on retry");
        assert_eq!(persisted.observation.as_ref(), Some(&terminal.observation));
        assert!(persisted.dispatch_claim.is_some());

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
            EventLedger::open(&database_path).expect("reopen v22 application ledger");
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
                && effect.observation.as_ref() == Some(&terminal.observation)
                && effect.dispatch_claim.is_some()
        ));
        assert_eq!(
            reopened
                .load_application_evidence(&terminal.receipt.receipt_id)
                .expect("reload v22 claimed application evidence"),
            terminal.evidence
        );
        assert_eq!(
            reopened
                .load_rollback_reference(&terminal.rollback.reference.reference_id)
                .expect("reload v22 rollback reference"),
            terminal.rollback
        );
    }

    #[test]
    #[allow(clippy::too_many_lines)] // One test proves both generic and real runner-bound V1 compatibility on the exact current schema.
    fn current_schema_v1_public_rollback_remains_operational() {
        let mut fixture = prepare_v22_application_admission_fixture();
        assert_eq!(
            fixture
                .candidate
                .ledger
                .connection
                .pragma_query_value(None, "user_version", |row| row.get::<_, i64>(0))
                .expect("read current schema version"),
            SCHEMA_VERSION
        );
        let application = persist_v22_claimed_application_fixture(&mut fixture);
        let request = RollbackRequest {
            contract_version: CONTRACT_VERSION,
            sprint_id: application.receipt.sprint_id.clone(),
            application_receipt_id: application.receipt.receipt_id.clone(),
            application_transaction_id: application.receipt.transaction_id.clone(),
            rollback_reference_id: application.rollback.reference.reference_id.clone(),
        };
        let request_bytes =
            encode("current rollback request", &request).expect("encode current rollback request");
        let intent = EffectIntent {
            contract_version: CONTRACT_VERSION,
            effect_id: "effect-current-claimless-rollback-reproducer".into(),
            idempotency_key: "key-current-claimless-rollback-reproducer".into(),
            sprint_id: application.receipt.sprint_id.clone(),
            task_id: None,
            worker_id: None,
            worker_lease: None,
            causation_event_id: Some(application.event.event_id.clone()),
            correlation_id: "correlation-current-claimless-rollback-reproducer".into(),
            kind: EffectKind::RollbackChangeSet,
            request_digest: Digest::sha256(&request_bytes),
            policy_hash: fixture.applier_launch.policy_hash.clone(),
            input_snapshot: application.receipt.result_snapshot.clone(),
            created_at_unix_ms: 2_600,
        };
        let proposal = effect_proposal_event(
            &intent,
            fixture
                .candidate
                .ledger
                .next_sequence(&intent.sprint_id)
                .expect("current rollback proposal sequence"),
            "event-current-claimless-rollback-proposed",
        );
        let ordinary = fixture
            .candidate
            .ledger
            .record_effect_intent(&intent, &request_bytes, &proposal)
            .expect("current schema preserves V1 generic rollback intent");
        assert_eq!(ordinary.intent, intent);
        assert!(ordinary.observation.is_none());

        let mut runner_fixture = prepare_v22_application_admission_fixture();
        let runner_application = persist_v22_claimed_application_fixture(&mut runner_fixture);
        let runner_request = RollbackRequest {
            contract_version: CONTRACT_VERSION,
            sprint_id: runner_application.receipt.sprint_id.clone(),
            application_receipt_id: runner_application.receipt.receipt_id.clone(),
            application_transaction_id: runner_application.receipt.transaction_id.clone(),
            rollback_reference_id: runner_application.rollback.reference.reference_id.clone(),
        };
        let runner_request_bytes =
            encode("current V1 runner rollback request", &runner_request).expect("encode request");
        let runner_intent = EffectIntent {
            contract_version: CONTRACT_VERSION,
            effect_id: "effect-current-v1-runner-rollback".into(),
            idempotency_key: "key-current-v1-runner-rollback".into(),
            sprint_id: runner_application.receipt.sprint_id.clone(),
            task_id: None,
            worker_id: None,
            worker_lease: None,
            causation_event_id: Some(runner_application.event.event_id.clone()),
            correlation_id: "correlation-current-v1-runner-rollback".into(),
            kind: EffectKind::RollbackChangeSet,
            request_digest: Digest::sha256(&runner_request_bytes),
            policy_hash: runner_fixture.applier_launch.policy_hash.clone(),
            input_snapshot: runner_application.receipt.result_snapshot.clone(),
            created_at_unix_ms: 2_600,
        };
        let runner_proposal = effect_proposal_event(
            &runner_intent,
            runner_fixture
                .candidate
                .ledger
                .next_sequence(&runner_intent.sprint_id)
                .expect("current V1 runner rollback proposal sequence"),
            "event-current-v1-runner-rollback-proposed",
        );
        runner_fixture
            .candidate
            .ledger
            .record_runner_effect_intent(
                &runner_intent,
                &runner_request_bytes,
                &runner_proposal,
                &runner_fixture.applier_session.session_id,
            )
            .expect("current schema preserves V1 runner rollback intent");
        let expected = RollbackEvidence {
            contract_version: CONTRACT_VERSION,
            receipt: RollbackReceipt {
                contract_version: CONTRACT_VERSION,
                receipt_id: "receipt-current-v1-runner-rollback".into(),
                sprint_id: runner_intent.sprint_id.clone(),
                effect_id: runner_intent.effect_id.clone(),
                observation_id: "observation-current-v1-runner-rollback".into(),
                application_receipt_id: runner_application.receipt.receipt_id.clone(),
                application_transaction_id: runner_application.receipt.transaction_id.clone(),
                restored_base_snapshot: runner_application.receipt.base_snapshot.clone(),
                restored_endpoints_digest: runner_fixture
                    .request
                    .change_set
                    .restored_base_endpoints_digest()
                    .expect("digest restored endpoints"),
                live_manifest_digest: digest('8'),
                unresolved_conflicts: 0,
                completed_at_unix_ms: 2_700,
            },
            validation: crate::RollbackValidationEvidence {
                mode: RollbackValidationMode::DirectEffectResponse,
                runner_launch_id: runner_fixture.applier_launch.launch_id.clone(),
                runner_session_id: runner_fixture.applier_session.session_id.clone(),
                policy_hash: runner_fixture.applier_launch.policy_hash.clone(),
                grant_hash: runner_fixture.applier_launch.grant_hash.clone(),
                policy_version: runner_fixture.applier_launch.policy_version,
                private_state_digest: runner_fixture.applier_launch.private_state_digest.clone(),
            },
        };
        let evidence_bytes =
            encode("current V1 rollback evidence", &expected).expect("encode evidence");
        let observation = effect_observation(
            &runner_intent,
            &expected.receipt.observation_id,
            EffectOutcome::Succeeded {
                evidence_digest: Digest::sha256(&evidence_bytes),
            },
            expected.receipt.completed_at_unix_ms,
        );
        let terminal = effect_terminal_event(
            &runner_intent,
            &runner_proposal.event_id,
            &observation,
            runner_fixture
                .candidate
                .ledger
                .next_sequence(&runner_intent.sprint_id)
                .expect("current V1 runner rollback terminal sequence"),
            "event-current-v1-runner-rollback-finished",
        );
        runner_fixture
            .candidate
            .ledger
            .record_rollback_effect_observation(&observation, &terminal, &expected)
            .expect("current schema preserves V1 runner-bound rollback success");
        assert_eq!(
            runner_fixture
                .candidate
                .ledger
                .load_rollback_evidence(&expected.receipt.receipt_id)
                .expect("read current V1 rollback exactly"),
            expected
        );
    }

    #[test]
    fn current_v2_public_rollback_paths_remain_fail_closed() {
        let database = TestDatabase::new();
        let mut ledger = EventLedger::open(&database.path).expect("open current V2 ledger");
        let (spec, graph) = current_v2_sprint_fixture("sprint-current-v2-rollback");
        ledger
            .create_current_sprint_authority_v32(&spec, &graph, 10)
            .expect("persist current V2 authority");
        let (intent, request_bytes, proposal, observation, terminal, evidence) =
            current_v2_rollback_contracts(&spec.sprint_id);

        for error in [
            ledger
                .record_effect_intent(&intent, &request_bytes, &proposal)
                .expect_err("current V2 rejects ordinary rollback intent"),
            ledger
                .record_runner_effect_intent(
                    &intent,
                    &request_bytes,
                    &proposal,
                    "session-current-v2-rollback",
                )
                .expect_err("current V2 rejects runner-bound rollback intent"),
        ] {
            assert!(matches!(
                error,
                LedgerError::ReferenceMismatch {
                    entity: "ordinary rollback request",
                    ref detail,
                } if detail.contains("phase-specific SprintRollback admission")
            ));
        }

        let evidence_bytes =
            encode("current V2 rollback evidence", &evidence).expect("encode rollback evidence");
        let generic = ledger
            .record_effect_observation(&observation, &evidence_bytes, &terminal)
            .expect_err("current V2 generic writer rejects claimless rollback success");
        assert!(matches!(
            generic,
            LedgerError::ReferenceMismatch {
                entity: "rollback effect observation",
                ..
            }
        ));
        let typed = ledger
            .record_rollback_effect_observation(&observation, &terminal, &evidence)
            .expect_err("current V2 typed writer rejects claimless rollback success");
        assert!(matches!(
            typed,
            LedgerError::ReferenceMismatch {
                entity: "rollback effect observation",
                ..
            }
        ));
        assert_eq!(row_count(&ledger, "effect_intents"), 0);
        assert_eq!(row_count(&ledger, "rollback_receipts"), 0);
    }

    #[test]
    fn current_v2_direct_sql_cannot_mint_ordinary_rollback_authority() {
        let database = TestDatabase::new();
        let mut ledger = EventLedger::open(&database.path).expect("open current V2 SQL ledger");
        let (spec, graph) = current_v2_sprint_fixture("sprint-current-v2-sql-rollback");
        ledger
            .create_current_sprint_authority_v32(&spec, &graph, 10)
            .expect("persist current V2 SQL authority");
        let (intent, _, proposal, observation, terminal, evidence) =
            current_v2_rollback_contracts(&spec.sprint_id);

        let transaction = ledger
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .expect("start direct SQL rollback intent probe");
        let intent_error = insert_effect_intent(&transaction, &intent, &proposal.event_id)
            .expect_err("v32 SQL rejects a complete normalized rollback effect-intent row");
        assert!(intent_error.to_string().contains(
            "current rollback effect intent requires phase-specific SprintRollback admission"
        ));
        transaction
            .rollback()
            .expect("roll back direct SQL rollback intent probe");

        let kind_error = ledger
            .connection
            .execute(
                "INSERT INTO finish_effect_kinds (
                    effect_id, sprint_id, effect_kind, contract_version
                 ) VALUES (?1, ?2, 'RollbackChangeSet', ?3)",
                params![
                    intent.effect_id,
                    spec.sprint_id,
                    i64::from(CONTRACT_VERSION)
                ],
            )
            .expect_err("v32 SQL rejects a fresh ordinary rollback semantic kind");
        assert!(
            kind_error
                .to_string()
                .contains("current rollback requires phase-specific SprintRollback admission")
        );
        let evidence_bytes =
            encode("current V2 rollback evidence", &evidence).expect("encode rollback evidence");
        let transaction = ledger
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .expect("start direct SQL rollback receipt probe");
        let receipt_error = insert_rollback_receipt(&transaction, &evidence, &evidence_bytes)
            .expect_err("v32 SQL rejects a current V2 rollback receipt");
        assert!(
            receipt_error
                .to_string()
                .contains("current rollback receipt requires claimed SprintRollback terminal")
        );
        transaction
            .rollback()
            .expect("roll back direct SQL rollback receipt probe");

        let transaction = ledger
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .expect("start direct SQL rollback observation probe");
        let observation_error =
            insert_effect_observation(&transaction, &observation, &terminal.event_id)
                .expect_err("v32 SQL rejects current V2 claimless rollback success");
        assert!(
            observation_error
                .to_string()
                .contains("current rollback success requires claimed SprintRollback terminal")
        );
        transaction
            .rollback()
            .expect("roll back direct SQL rollback observation probe");
        assert_eq!(row_count(&ledger, "effect_intents"), 0);
        assert_eq!(row_count(&ledger, "rollback_receipts"), 0);
    }

    #[test]
    fn migrated_pending_v1_rollback_remains_operational() {
        let database = TestDatabase::new();
        let pending = {
            let mut historical = open_v21_test_ledger(&database);
            prepare_pending_rollback(&mut historical)
        };
        let mut current = EventLedger::open(&database.path)
            .expect("migrate pending historical rollback to current schema");
        current
            .record_rollback_effect_observation(
                &pending.observation,
                &pending.terminal,
                &pending.evidence,
            )
            .expect("migrated V1 rollback keeps its exact historical authority");
        assert_eq!(
            current
                .load_rollback_evidence(&pending.evidence.receipt.receipt_id)
                .expect("read migrated V1 rollback exactly"),
            pending.evidence
        );
    }

    #[test]
    fn rollback_backed_known_terminal_requires_cleanup_and_reopens_exactly() {
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
                .expect("persist historical rollback evidence");
            let evidence = terminal_evidence(
                "terminal-after-clean-rollback",
                NonSuccessTerminalState::Failed,
            );
            let proof = SprintTerminalProof::Rollback(pending.evidence.receipt.clone());

            let unclean_error = ledger
                .record_unsuccessful_terminal_outcome_with_proof(&evidence, &proof)
                .expect_err("rollback proof cannot substitute for runner cleanup");
            assert!(matches!(
                unclean_error,
                LedgerError::ReferenceMismatch {
                    entity: "worker cleanup set",
                    ref detail,
                } if detail.contains("canonical exact registered-session set")
            ));

            let cleanup = cleanup_terminal_record(
                &ledger,
                &pending.executor_launch,
                "cleanup-rollback-terminal",
                1_700,
            );
            ledger
                .with_runner_launch_cleanup_exclusion(
                    &pending.executor_launch.sprint_id,
                    &pending.executor_launch.launch_id,
                    |claim| {
                        assert_eq!(claim.next_event_sequence(), cleanup.event.sequence);
                        Ok(cleanup.clone())
                    },
                )
                .expect("persist exact rollback executor cleanup");
            ledger
                .record_unsuccessful_terminal_outcome_with_proof(&evidence, &proof)
                .expect("clean rollback-backed terminal is admissible")
        };
        let reader = EventLedger::open(&database.path)
            .expect("migrate clean rollback-backed terminal to current schema");
        assert_eq!(
            reader
                .load_terminal_outcome("sprint-1")
                .expect("read exact migrated rollback terminal"),
            Some(expected)
        );
    }

