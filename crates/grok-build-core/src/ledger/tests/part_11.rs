    #[cfg(unix)]
    #[test]
    fn planned_task_attempt_cleanup_replays_across_reopen_without_callback() {
        let database = TestDatabase::new();
        let (attempt, plan, stored) = {
            let mut ledger = EventLedger::open(&database.path).expect("open planned replay ledger");
            let attempt = prepare_planned_refused_task_attempt(&mut ledger, "planned-replay", 2);
            let plan = ledger
                .plan_task_attempt_cleanup_disposition(&attempt)
                .expect("derive planned replay cleanup");
            let cleaned_at_unix_ms = plan.minimum_terminal_at_unix_ms() + 1;
            let stored = ledger
                .with_planned_task_attempt_cleanup_disposition_exclusion(&plan, |claim| {
                    Ok(cleanup_terminal_from_live_claim(
                        claim,
                        "planned-replay",
                        cleaned_at_unix_ms,
                    ))
                })
                .expect("commit planned replay cleanup");

            let invoked = Arc::new(AtomicBool::new(false));
            let callback_invoked = Arc::clone(&invoked);
            let replay = ledger
                .with_planned_task_attempt_cleanup_disposition_exclusion(&plan, move |_| {
                    callback_invoked.store(true, Ordering::SeqCst);
                    panic!("same-process exact replay must bypass cleanup")
                })
                .expect("same-process planned cleanup replay");
            assert_eq!(replay, stored);
            assert!(!invoked.load(Ordering::SeqCst));
            (attempt, plan, stored)
        };

        let mut reopened = EventLedger::open(&database.path).expect("reopen planned replay ledger");
        let replanned = reopened
            .plan_task_attempt_cleanup_disposition(&attempt)
            .expect("rederive exact plan after release and restart");
        assert_eq!(replanned, plan);
        let invoked = Arc::new(AtomicBool::new(false));
        let callback_invoked = Arc::clone(&invoked);
        let replay = reopened
            .with_planned_task_attempt_cleanup_disposition_exclusion(&replanned, move |_| {
                callback_invoked.store(true, Ordering::SeqCst);
                panic!("restart exact replay must bypass cleanup")
            })
            .expect("restart planned cleanup replay");
        assert_eq!(replay, stored);
        assert!(!invoked.load(Ordering::SeqCst));
        assert_eq!(row_count(&reopened, "worker_cleanup_receipts"), 1);
        assert_eq!(row_count(&reopened, "task_attempt_dispositions"), 1);
        assert_eq!(row_count(&reopened, "worker_lease_releases"), 1);
        assert_eq!(
            row_count(&reopened, "task_attempt_cleanup_result_coverage"),
            1
        );
    }

    #[cfg(unix)]
    #[test]
    fn terminal_cleanup_wins_before_stale_preparation_and_callback_never_runs() {
        let database = TestDatabase::new();
        let mut stale_ledger = EventLedger::open(&database.path).expect("open stale launch ledger");
        let (policy, launch, intent, _, request_bytes, event) = prepare_test_launch_admission(
            &mut stale_ledger,
            "cleanup-wins",
            RunnerSessionPurpose::FinalVerifier,
            None,
            WorkerCleanupBackend::LinuxCgroupV2,
        );
        let stale_admission = stale_ledger
            .admit_runner_launch_with_cleanup(&launch, &policy, &intent, &request_bytes, &event)
            .expect("admit stale candidate");
        let attempt = test_launch_preparation_attempt(&stale_admission, "cleanup-wins", 1_150);
        let mut cleanup_ledger =
            EventLedger::open(&database.path).expect("open cleanup winner ledger");
        let bypass = cleanup_terminal_for_admission(
            &stale_admission,
            cleanup_ledger
                .next_sequence(&launch.sprint_id)
                .expect("cleanup bypass sequence"),
            "cleanup-wins-bypass",
            1_190,
        );
        assert!(matches!(
            cleanup_ledger.record_worker_cleanup_effect_observation(
                &bypass.observation,
                &bypass.event,
                &bypass.evidence,
            ),
            Err(LedgerError::ReferenceMismatch {
                entity: "worker cleanup observation",
                ..
            })
        ));
        cleanup_ledger
            .with_runner_launch_cleanup_exclusion(&launch.sprint_id, &launch.launch_id, |claim| {
                Ok(cleanup_terminal_from_live_claim(
                    claim,
                    "cleanup-wins",
                    1_200,
                ))
            })
            .expect("cleanup terminalizes first");

        let invoked = Arc::new(AtomicBool::new(false));
        let callback_invoked = Arc::clone(&invoked);
        assert!(matches!(
            stale_ledger.with_runner_launch_preparation_claim(
                &stale_admission,
                &attempt,
                move |_| {
                    callback_invoked.store(true, Ordering::SeqCst);
                    held_child_preparation_outcome("cleanup-wins", 1_250)
                },
            ),
            Err(LedgerError::ReferenceMismatch {
                entity: "runner launch cleanup admission",
                ..
            })
        ));
        assert!(!invoked.load(Ordering::SeqCst));
        assert_eq!(
            row_count(&stale_ledger, "runner_launch_preparation_attempts"),
            0
        );
    }

    #[cfg(unix)]
    #[test]
    fn direct_cleanup_observation_cannot_bypass_authoritative_live_exclusion() {
        let database = TestDatabase::new();
        let mut ledger = EventLedger::open(&database.path).expect("open bypass-fence ledger");
        let (policy, launch, intent, _, request_bytes, event) = prepare_test_launch_admission(
            &mut ledger,
            "direct-cleanup-bypass",
            RunnerSessionPurpose::TaskWorker,
            Some("worker-1"),
            WorkerCleanupBackend::LinuxCgroupV2,
        );
        let admission = ledger
            .admit_runner_launch_with_cleanup(&launch, &policy, &intent, &request_bytes, &event)
            .expect("admit cleanup bypass candidate");
        let terminal = cleanup_terminal_for_admission(
            &admission,
            ledger
                .next_sequence(&launch.sprint_id)
                .expect("direct cleanup sequence"),
            "direct-cleanup-bypass",
            1_200,
        );
        assert!(matches!(
            ledger.record_worker_cleanup_effect_observation(
                &terminal.observation,
                &terminal.event,
                &terminal.evidence,
            ),
            Err(LedgerError::ReferenceMismatch {
                entity: "worker cleanup observation",
                ..
            })
        ));
        let pending = ledger
            .load_runner_launch_cleanup_admission(&launch.sprint_id, &launch.launch_id)
            .expect("reload pending cleanup after rejected bypass");
        assert!(pending.cleanup_effect.observation.is_none());
        assert!(pending.cleanup_effect.evidence_bytes.is_none());
        assert!(pending.cleanup_effect.terminal_event.is_none());
        assert_eq!(row_count(&ledger, "worker_cleanup_receipts"), 0);
    }

    #[cfg(unix)]
    #[test]
    fn one_preparation_attempt_is_permanent_and_failed_outcomes_fence_session_work() {
        let database = TestDatabase::new();
        let mut ledger = EventLedger::open(&database.path).expect("open one-attempt ledger");
        let (policy, launch, intent, _, request_bytes, event) = prepare_test_launch_admission(
            &mut ledger,
            "one-attempt",
            RunnerSessionPurpose::TaskWorker,
            Some("worker-1"),
            WorkerCleanupBackend::LinuxCgroupV2,
        );
        let admission = ledger
            .admit_runner_launch_with_cleanup(&launch, &policy, &intent, &request_bytes, &event)
            .expect("admit one-attempt launch");
        let attempt = test_launch_preparation_attempt(&admission, "one-attempt", 1_150);
        let refused = RunnerLaunchPreparationOutcome {
            disposition: RunnerLaunchPreparationDisposition::RefusedBeforeNativeEffect,
            native_evidence_bytes: b"native service refused before creating a domain".to_vec(),
            finished_at_unix_ms: 1_200,
        };
        ledger
            .with_runner_launch_preparation_claim(&admission, &attempt, |_| refused.clone())
            .expect("persist refused single attempt");

        let second_invoked = Arc::new(AtomicBool::new(false));
        let callback_invoked = Arc::clone(&second_invoked);
        let mut second_attempt = test_launch_preparation_attempt(&admission, "second", 1_250);
        second_attempt.launch_id = launch.launch_id.clone();
        second_attempt.cleanup_effect_id = intent.effect_id.clone();
        second_attempt.sprint_id = launch.sprint_id.clone();
        assert!(
            ledger
                .with_runner_launch_preparation_claim(&admission, &second_attempt, move |_| {
                    callback_invoked.store(true, Ordering::SeqCst);
                    held_child_preparation_outcome("second", 1_300)
                })
                .is_err()
        );
        assert!(!second_invoked.load(Ordering::SeqCst));
        assert_eq!(row_count(&ledger, "runner_launch_preparation_attempts"), 1);
        assert_eq!(row_count(&ledger, "runner_launch_preparation_outcomes"), 1);
        assert!(matches!(
            ledger.register_runner_session(&runner_session(&launch, 1_300), &policy),
            Err(LedgerError::ReferenceMismatch {
                entity: "runner launch preparation",
                ..
            })
        ));
    }

    #[cfg(unix)]
    #[test]
    fn post_native_readback_ambiguity_is_cleanup_only_and_never_retries() {
        let database = TestDatabase::new();
        let mut ledger = EventLedger::open(&database.path).expect("open ambiguity ledger");
        let (policy, launch, intent, _, request_bytes, event) = prepare_test_launch_admission(
            &mut ledger,
            "preparation-ambiguity",
            RunnerSessionPurpose::Applier,
            None,
            WorkerCleanupBackend::TrustedApplierDirectChildWait,
        );
        let admission = ledger
            .admit_runner_launch_with_cleanup(&launch, &policy, &intent, &request_bytes, &event)
            .expect("admit ambiguity launch");
        let attempt = test_launch_preparation_attempt(&admission, "preparation-ambiguity", 1_150);
        let hardlink = database
            .directory
            .join("preparation-outcome-hardlink.sqlite3");
        let database_path = database.path.clone();
        let outcome = held_child_preparation_outcome("preparation-ambiguity", 1_200);
        assert!(matches!(
            ledger.with_runner_launch_preparation_claim(&admission, &attempt, |_| {
                fs::hard_link(&database_path, &hardlink)
                    .expect("inject post-native hardening ambiguity");
                outcome.clone()
            }),
            Err(LedgerError::PostCommitStateUncertain {
                operation: "runner launch preparation outcome",
                recovery_id,
                ..
            }) if recovery_id == intent.effect_id
        ));
        fs::remove_file(&hardlink).expect("remove ambiguity hardlink");
        assert_eq!(
            ledger
                .load_runner_launch_preparation(&launch.sprint_id, &launch.launch_id)
                .expect("reconcile exact committed native outcome"),
            PersistedRunnerLaunchPreparation {
                attempt: attempt.clone(),
                outcome: Some(outcome),
            }
        );
        let invoked = Arc::new(AtomicBool::new(false));
        let callback_invoked = Arc::clone(&invoked);
        assert!(
            ledger
                .with_runner_launch_preparation_claim(&admission, &attempt, move |_| {
                    callback_invoked.store(true, Ordering::SeqCst);
                    held_child_preparation_outcome("forbidden-retry", 1_300)
                })
                .is_err()
        );
        assert!(!invoked.load(Ordering::SeqCst));
        let reopened =
            EventLedger::open_read_only(&database.path).expect("reopen ambiguity ledger");
        assert!(
            reopened
                .load_runner_launch_cleanup_admission(&launch.sprint_id, &launch.launch_id)
                .expect("cleanup obligation remains readable")
                .cleanup_effect
                .observation
                .is_none()
        );
    }

    #[cfg(unix)]
    #[test]
    fn cleanup_exclusion_rejects_a_terminal_record_substituted_from_another_launch() {
        let database = TestDatabase::new();
        let mut ledger = EventLedger::open(&database.path).expect("open substitution ledger");
        let (policy, first_launch, first_intent, _, first_request, first_event) =
            prepare_test_launch_admission(
                &mut ledger,
                "cleanup-substitution-first",
                RunnerSessionPurpose::FinalVerifier,
                None,
                WorkerCleanupBackend::LinuxCgroupV2,
            );
        let first = ledger
            .admit_runner_launch_with_cleanup(
                &first_launch,
                &policy,
                &first_intent,
                &first_request,
                &first_event,
            )
            .expect("admit first cleanup launch");
        let second_launch = runner_launch(
            "cleanup-substitution-second-launch",
            "cleanup-substitution-second-session",
            RunnerSessionPurpose::FinalVerifier,
            None,
            &policy,
            1_101,
        );
        let (second_intent, _, second_request, second_event) =
            test_runner_launch_cleanup_contracts(
                &ledger,
                &second_launch,
                WorkerCleanupBackend::LinuxCgroupV2,
            )
            .expect("build second cleanup contracts");
        let second = ledger
            .admit_runner_launch_with_cleanup(
                &second_launch,
                &policy,
                &second_intent,
                &second_request,
                &second_event,
            )
            .expect("admit second cleanup launch");

        assert!(matches!(
            ledger.with_runner_launch_cleanup_exclusion(
                &first_launch.sprint_id,
                &first_launch.launch_id,
                |claim| {
                    Ok(cleanup_terminal_for_admission(
                        &second,
                        claim.next_event_sequence(),
                        "substituted-second",
                        1_300,
                    ))
                },
            ),
            Err(LedgerError::Contract(_) | LedgerError::ReferenceMismatch { .. })
        ));
        assert!(
            ledger
                .load_runner_launch_cleanup_admission(
                    &first_launch.sprint_id,
                    &first_launch.launch_id,
                )
                .expect("first remains pending")
                .cleanup_effect
                .observation
                .is_none()
        );
        assert!(
            ledger
                .load_runner_launch_cleanup_admission(
                    &second_launch.sprint_id,
                    &second_launch.launch_id,
                )
                .expect("second remains pending")
                .cleanup_effect
                .observation
                .is_none()
        );
        assert_eq!(
            first.cleanup_effect.intent.effect_id,
            first_intent.effect_id
        );
    }

    #[cfg(unix)]
    #[test]
    fn runner_launch_and_session_postcommit_failures_return_cleanup_recovery_identity() {
        let database = TestDatabase::new();
        let mut ledger = EventLedger::open(&database.path).expect("open post-commit ledger");
        let (policy, launch, intent, _, request_bytes, event) = prepare_test_launch_admission(
            &mut ledger,
            "post-commit-recovery",
            RunnerSessionPurpose::Applier,
            None,
            WorkerCleanupBackend::TrustedApplierDirectChildWait,
        );
        let launch_hardlink = database.directory.join("launch-commit-hardlink.sqlite3");
        fs::hard_link(&database.path, &launch_hardlink)
            .expect("create launch post-commit hardening fault");
        assert!(matches!(
            ledger.admit_runner_launch_with_cleanup(
                &launch,
                &policy,
                &intent,
                &request_bytes,
                &event,
            ),
            Err(LedgerError::PostCommitStateUncertain {
                operation: "runner launch cleanup admission",
                recovery_id,
                ..
            }) if recovery_id == intent.effect_id
        ));
        fs::remove_file(&launch_hardlink).expect("remove launch hardlink fault");
        assert_eq!(
            ledger
                .load_runner_launch_cleanup_admission(&launch.sprint_id, &launch.launch_id)
                .expect("recover committed launch admission")
                .cleanup_effect
                .intent
                .effect_id,
            intent.effect_id
        );

        let session = runner_session(&launch, 1_150);
        let session_hardlink = database.directory.join("session-commit-hardlink.sqlite3");
        fs::hard_link(&database.path, &session_hardlink)
            .expect("create session post-commit hardening fault");
        assert!(matches!(
            ledger.register_runner_session(&session, &policy),
            Err(LedgerError::PostCommitStateUncertain {
                operation: "runner session registration",
                recovery_id,
                ..
            }) if recovery_id == intent.effect_id
        ));
        fs::remove_file(&session_hardlink).expect("remove session hardlink fault");
        assert_eq!(
            ledger
                .load_runner_session(&session.sprint_id, &session.session_id)
                .expect("recover committed runner session"),
            session
        );
    }

    #[test]
    #[allow(clippy::too_many_lines)] // Both irreversible transition paths share exact cleanup fixtures.
    fn terminal_runner_cleanup_blocks_late_session_and_all_fresh_runner_work() {
        let database = TestDatabase::new();
        let mut ledger = EventLedger::open(&database.path).expect("open cleanup-close ledger");
        let (worker_policy, worker_launch, worker_cleanup, _, worker_request_bytes, worker_event) =
            prepare_test_launch_admission(
                &mut ledger,
                "cleanup-before-session",
                RunnerSessionPurpose::FinalVerifier,
                None,
                WorkerCleanupBackend::LinuxCgroupV2,
            );
        ledger
            .admit_runner_launch_with_cleanup(
                &worker_launch,
                &worker_policy,
                &worker_cleanup,
                &worker_request_bytes,
                &worker_event,
            )
            .expect("admit uninitialized worker launch");

        let verifier_policy = compiled_test_policy("cleanup-before-new-work-policy");
        let verifier_launch = runner_launch(
            "cleanup-before-new-work-launch",
            "cleanup-before-new-work-session",
            RunnerSessionPurpose::FinalVerifier,
            None,
            &verifier_policy,
            1_101,
        );
        let (verifier_cleanup, _, verifier_request_bytes, verifier_event) =
            test_runner_launch_cleanup_contracts(
                &ledger,
                &verifier_launch,
                WorkerCleanupBackend::LinuxCgroupV2,
            )
            .expect("build verifier cleanup authority");
        ledger
            .admit_runner_launch_with_cleanup(
                &verifier_launch,
                &verifier_policy,
                &verifier_cleanup,
                &verifier_request_bytes,
                &verifier_event,
            )
            .expect("admit verifier launch");
        let verifier_session = runner_session(&verifier_launch, 1_150);
        ledger
            .register_runner_session(&verifier_session, &verifier_policy)
            .expect("register verifier before cleanup");

        persist_cleanup_evidence(
            &mut ledger,
            &worker_launch,
            &digest('b'),
            "cleanup-before-session-receipt",
            WorkerCleanupBackend::LinuxCgroupV2,
            1_200,
            1_250,
        );
        let worker_session = runner_session(&worker_launch, 1_300);
        let counts_before_late_session = (
            row_count(&ledger, "runner_session_policies"),
            row_count(&ledger, "agent_events"),
        );
        let late_session_error = ledger
            .register_runner_session(&worker_session, &worker_policy)
            .expect_err("terminal cleanup must block late session registration");
        assert!(
            matches!(
                &late_session_error,
                LedgerError::ReferenceMismatch {
                    entity: "runner launch cleanup admission",
                    ..
                }
            ),
            "unexpected late-session error: {late_session_error:?}"
        );
        assert_eq!(
            (
                row_count(&ledger, "runner_session_policies"),
                row_count(&ledger, "agent_events"),
            ),
            counts_before_late_session
        );

        persist_cleanup_evidence(
            &mut ledger,
            &verifier_launch,
            &digest('b'),
            "cleanup-before-new-work-receipt",
            WorkerCleanupBackend::LinuxCgroupV2,
            1_300,
            1_350,
        );
        let mut late_work = effect_intent(
            "effect-after-runner-cleanup",
            "key-after-runner-cleanup",
            1_400,
        );
        late_work.task_id = None;
        late_work.worker_id = None;
        late_work.policy_hash = verifier_launch.policy_hash.clone();
        let counts_before_late_work = (
            row_count(&ledger, "effect_intents"),
            row_count(&ledger, "effect_session_bindings"),
            row_count(&ledger, "effect_request_payloads"),
            row_count(&ledger, "agent_events"),
        );
        let late_binding_error = ledger
            .connection
            .execute(
                "INSERT INTO effect_session_bindings (
                    effect_id, sprint_id, launch_id, session_id, contract_version
                 ) VALUES (?1, ?2, ?3, ?4, ?5)",
                params![
                    late_work.effect_id,
                    late_work.sprint_id,
                    verifier_launch.launch_id,
                    verifier_session.session_id,
                    i64::from(CONTRACT_VERSION),
                ],
            )
            .expect_err("terminal cleanup must reject a raw fresh runner binding");
        assert!(late_binding_error.to_string().contains(
            "effect binding requires an open exact runner launch cleanup classification"
        ));
        assert_eq!(
            (
                row_count(&ledger, "effect_intents"),
                row_count(&ledger, "effect_session_bindings"),
                row_count(&ledger, "effect_request_payloads"),
                row_count(&ledger, "agent_events"),
            ),
            counts_before_late_work
        );
    }

    #[test]
    fn runner_launch_cleanup_invalid_joins_roll_back_every_row() {
        let cases = ["backend", "session", "timestamp", "event", "noncanonical"];
        for case in cases {
            let database = TestDatabase::new();
            let mut ledger = EventLedger::open(&database.path).expect("open rejection ledger");
            let (policy, launch, mut intent, mut request, mut request_bytes, mut event) =
                prepare_test_launch_admission(
                    &mut ledger,
                    case,
                    RunnerSessionPurpose::Applier,
                    None,
                    WorkerCleanupBackend::TrustedApplierDirectChildWait,
                );
            match case {
                "backend" => {
                    request.platform_backend = WorkerCleanupBackend::LinuxCgroupV2;
                    request_bytes =
                        encode("worker cleanup request", &request).expect("encode crossed backend");
                    intent.request_digest = Digest::sha256(&request_bytes);
                }
                "session" => {
                    request.session_id = "crossed-session".into();
                    request_bytes =
                        encode("worker cleanup request", &request).expect("encode crossed session");
                    intent.request_digest = Digest::sha256(&request_bytes);
                }
                "timestamp" => {
                    intent.created_at_unix_ms = launch.created_at_unix_ms - 1;
                    event.occurred_at_unix_ms = intent.created_at_unix_ms;
                }
                "event" => event.correlation_id = "crossed-correlation".into(),
                "noncanonical" => {
                    request_bytes.extend_from_slice(b"\n");
                    intent.request_digest = Digest::sha256(&request_bytes);
                }
                _ => unreachable!("closed rejection matrix"),
            }
            let error = ledger
                .admit_runner_launch_with_cleanup(&launch, &policy, &intent, &request_bytes, &event)
                .expect_err("crossed launch cleanup join must fail closed");
            assert!(matches!(
                error,
                LedgerError::ReferenceMismatch { .. }
                    | LedgerError::Json { .. }
                    | LedgerError::EffectDigestMismatch { .. }
            ));
            for table in [
                "runner_launch_intents",
                "runner_launch_cleanup_admissions",
                "legacy_runner_launch_cleanup_gaps",
                "effect_intents",
                "effect_request_payloads",
                "effect_session_bindings",
                "finish_effect_kinds",
                "agent_events",
            ] {
                assert_eq!(row_count(&ledger, table), 0, "case {case} wrote {table}");
            }
        }
    }

    #[test]
    fn legacy_launch_cleanup_pending_retry_is_serialized_across_connections_and_sql() {
        let database = TestDatabase::new();
        let (mut first, _, launch) =
            migrate_test_v12_legacy_launch(&database, "pending-cross-connection");
        let mut second = reopen_test_legacy_ledger(&database);
        let (first_intent, first_request, first_event) =
            legacy_launch_cleanup_contracts(&first, &launch, "pending-first", 1_200);
        let (second_intent, second_request, mut second_event) =
            legacy_launch_cleanup_contracts(&second, &launch, "pending-second", 1_300);

        first
            .record_cleanup_effect_intent_for_launch(
                &first_intent,
                &first_request,
                &first_event,
                &launch.launch_id,
            )
            .expect("first connection admits one legacy cleanup attempt");
        second_event.sequence = second
            .next_sequence(&launch.sprint_id)
            .expect("refresh second-connection proposal sequence");
        let counts_before_retry = (
            row_count(&second, "effect_intents"),
            row_count(&second, "effect_session_bindings"),
            row_count(&second, "agent_events"),
        );
        assert!(matches!(
            second.record_cleanup_effect_intent_for_launch(
                &second_intent,
                &second_request,
                &second_event,
                &launch.launch_id,
            ),
            Err(LedgerError::ReferenceMismatch {
                entity: "cleanup launch binding",
                ..
            })
        ));
        assert_eq!(
            (
                row_count(&second, "effect_intents"),
                row_count(&second, "effect_session_bindings"),
                row_count(&second, "agent_events"),
            ),
            counts_before_retry
        );

        let trigger_error = second
            .connection
            .execute(
                "INSERT INTO effect_session_bindings (
                    effect_id, sprint_id, launch_id, session_id, contract_version
                 ) VALUES (?1, ?2, ?3, NULL, ?4)",
                params![
                    "legacy-retry-sql-bypass-effect",
                    launch.sprint_id,
                    launch.launch_id,
                    i64::from(CONTRACT_VERSION),
                ],
            )
            .expect_err("schema must independently serialize legacy cleanup retries");
        assert!(trigger_error.to_string().contains(
            "legacy runner launch cleanup retry requires every prior attempt to be terminal non-success"
        ));
        assert_eq!(
            row_count(&second, "effect_session_bindings"),
            counts_before_retry.1
        );
    }

    #[test]
    fn legacy_cleanup_staged_bindings_cannot_bypass_sql_retry_lifecycle() {
        let database = TestDatabase::new();
        let (mut ledger, _, launch) =
            migrate_test_v12_legacy_launch(&database, "staged-sql-bindings");
        let (first_intent, first_request, first_event) =
            legacy_launch_cleanup_contracts(&ledger, &launch, "staged-first", 1_200);
        let (second_intent, second_request, mut second_event) =
            legacy_launch_cleanup_contracts(&ledger, &launch, "staged-second", 1_300);
        second_event.sequence = first_event.sequence + 1;

        let transaction = ledger
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .expect("start staged legacy cleanup transaction");
        for intent in [&first_intent, &second_intent] {
            transaction
                .execute(
                    "INSERT INTO effect_session_bindings (
                        effect_id, sprint_id, launch_id, session_id, contract_version
                     ) VALUES (?1, ?2, ?3, NULL, ?4)",
                    params![
                        intent.effect_id,
                        intent.sprint_id,
                        launch.launch_id,
                        i64::from(CONTRACT_VERSION),
                    ],
                )
                .expect("stage a deferred legacy cleanup binding");
        }
        insert_agent_event(&transaction, &first_event).expect("insert first cleanup proposal");
        insert_agent_event(&transaction, &second_event).expect("insert second cleanup proposal");
        insert_effect_request_payload(&transaction, &first_intent, &first_request)
            .expect("insert first cleanup request");
        insert_effect_request_payload(&transaction, &second_intent, &second_request)
            .expect("insert second cleanup request");
        insert_finish_effect_kind(&transaction, &first_intent)
            .expect("insert first cleanup semantic kind");
        insert_finish_effect_kind(&transaction, &second_intent)
            .expect("insert second cleanup semantic kind");
        insert_effect_intent(&transaction, &first_intent, &first_event.event_id)
            .expect("insert first staged cleanup effect");
        let error = insert_effect_intent(&transaction, &second_intent, &second_event.event_id)
            .expect_err("effect-time trigger must reject a second staged open cleanup");
        assert!(error.to_string().contains(
            "legacy runner launch cleanup retry requires every prior attempt to be terminal non-success"
        ));
        transaction
            .rollback()
            .expect("roll back staged cleanup bypass transaction");
        assert_eq!(row_count(&ledger, "effect_session_bindings"), 0);
        assert_eq!(row_count(&ledger, "effect_intents"), 0);
        assert_eq!(row_count(&ledger, "agent_events"), 0);
    }

    #[test]
    fn successful_legacy_launch_cleanup_permanently_closes_retries() {
        let database = TestDatabase::new();
        let (mut ledger, _, launch) = migrate_test_v12_legacy_launch(&database, "successful-close");
        let (first_intent, first_request, first_event) =
            legacy_launch_cleanup_contracts(&ledger, &launch, "successful-first", 1_200);
        ledger
            .record_cleanup_effect_intent_for_launch(
                &first_intent,
                &first_request,
                &first_event,
                &launch.launch_id,
            )
            .expect("admit legacy cleanup that will succeed");
        record_legacy_launch_cleanup_success(
            &mut ledger,
            &launch,
            &first_intent,
            &first_event,
            "successful-first",
            1_250,
        );

        let (retry_intent, retry_request, retry_event) =
            legacy_launch_cleanup_contracts(&ledger, &launch, "successful-retry", 1_300);
        assert!(matches!(
            ledger.record_cleanup_effect_intent_for_launch(
                &retry_intent,
                &retry_request,
                &retry_event,
                &launch.launch_id,
            ),
            Err(LedgerError::ReferenceMismatch {
                entity: "cleanup launch binding",
                ..
            })
        ));
        assert_eq!(row_count(&ledger, "effect_intents"), 1);
        assert_eq!(row_count(&ledger, "worker_cleanup_receipts"), 1);
    }

    #[test]
    fn terminal_non_successful_legacy_cleanup_allows_one_fresh_retry() {
        let database = TestDatabase::new();
        let (mut ledger, _, launch) = migrate_test_v12_legacy_launch(&database, "failed-retry");
        let (first_intent, first_request, first_event) =
            legacy_launch_cleanup_contracts(&ledger, &launch, "failed-first", 1_200);
        ledger
            .record_cleanup_effect_intent_for_launch(
                &first_intent,
                &first_request,
                &first_event,
                &launch.launch_id,
            )
            .expect("admit legacy cleanup that will fail before effect");
        let failure_bytes = b"legacy cleanup failed before effect".to_vec();
        let failure = effect_observation(
            &first_intent,
            "legacy-retry-observation-failed-first",
            EffectOutcome::FailedBeforeEffect {
                evidence_digest: Digest::sha256(&failure_bytes),
            },
            1_250,
        );
        let failure_event = effect_terminal_event(
            &first_intent,
            &first_event.event_id,
            &failure,
            ledger
                .next_sequence(&launch.sprint_id)
                .expect("legacy cleanup failure sequence"),
            "legacy-retry-finished-failed-first",
        );
        ledger
            .record_effect_observation(&failure, &failure_bytes, &failure_event)
            .expect("record terminal non-successful legacy cleanup");

        let (retry_intent, retry_request, retry_event) =
            legacy_launch_cleanup_contracts(&ledger, &launch, "failed-retry", 1_300);
        ledger
            .record_cleanup_effect_intent_for_launch(
                &retry_intent,
                &retry_request,
                &retry_event,
                &launch.launch_id,
            )
            .expect("terminal non-success allows one fresh cleanup attempt");
        assert_eq!(row_count(&ledger, "effect_intents"), 2);
        assert_eq!(row_count(&ledger, "effect_observations"), 1);
        assert_eq!(
            ledger
                .load_effect(&retry_intent.effect_id)
                .expect("load fresh legacy cleanup retry")
                .observation,
            None
        );
    }

    #[test]
    fn runner_launch_cleanup_storage_class_cannot_cross_semantic_subtype() {
        let database = TestDatabase::new();
        let mut ledger = open_v21_test_ledger(&database);
        let (policy, launch, intent, request, request_bytes, event) = prepare_test_launch_admission(
            &mut ledger,
            "semantic-subtype",
            RunnerSessionPurpose::Applier,
            None,
            WorkerCleanupBackend::TrustedApplierDirectChildWait,
        );
        let admission = runner_launch_cleanup_admission::validate_contract_join(
            &launch,
            &intent,
            &request,
            &event.event_id,
        )
        .expect("validate exact cleanup authority");
        let transaction = ledger
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .expect("start subtype-crossing transaction");
        runner_launch_cleanup_admission::insert_admission(&transaction, &admission)
            .expect("insert deferred cleanup authority");
        insert_runner_launch_intent(&transaction, &launch, policy.contract())
            .expect("insert exact launch");
        transaction
            .execute(
                "INSERT INTO effect_session_bindings (
                    effect_id, sprint_id, launch_id, session_id, contract_version
                 ) VALUES (?1, ?2, ?3, NULL, ?4)",
                params![
                    intent.effect_id,
                    intent.sprint_id,
                    launch.launch_id,
                    i64::from(CONTRACT_VERSION),
                ],
            )
            .expect("insert exact launch binding");
        insert_agent_event(&transaction, &event).expect("insert exact proposal event");
        insert_effect_request_payload(&transaction, &intent, &request_bytes)
            .expect("insert exact cleanup request");
        transaction
            .execute(
                "INSERT INTO finish_effect_kinds (
                    effect_id, sprint_id, effect_kind, contract_version
                 ) VALUES (?1, ?2, 'RollbackChangeSet', ?3)",
                params![
                    intent.effect_id,
                    intent.sprint_id,
                    i64::from(CONTRACT_VERSION),
                ],
            )
            .expect("inject crossed semantic subtype");

        let error = insert_effect_intent(&transaction, &intent, &event.event_id)
            .expect_err("normalized ApplyChangeSet storage must not hide crossed subtype");
        assert!(
            error
                .to_string()
                .contains("cleanup effect must match its exact atomic launch admission")
        );
        transaction
            .rollback()
            .expect("roll back rejected subtype transaction");
        for table in [
            "runner_launch_intents",
            "runner_launch_cleanup_admissions",
            "effect_intents",
            "effect_request_payloads",
            "effect_session_bindings",
            "finish_effect_kinds",
            "agent_events",
        ] {
            assert_eq!(
                row_count(&ledger, table),
                0,
                "subtype crossing wrote {table}"
            );
        }
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn runner_launch_cleanup_readback_rejects_classification_json_policy_and_binding_corruption() {
        for corruption in ["both", "neither", "json", "policy", "binding"] {
            let database = TestDatabase::new();
            let mut ledger = EventLedger::open(&database.path).expect("open corruption ledger");
            let (policy, launch, intent, _, request_bytes, event) = prepare_test_launch_admission(
                &mut ledger,
                corruption,
                RunnerSessionPurpose::Applier,
                None,
                WorkerCleanupBackend::TrustedApplierDirectChildWait,
            );
            ledger
                .admit_runner_launch_with_cleanup(&launch, &policy, &intent, &request_bytes, &event)
                .expect("persist corruption fixture");
            match corruption {
                "both" => {
                    ledger
                        .connection
                        .execute_batch("DROP TRIGGER legacy_runner_launch_cleanup_gaps_no_insert;")
                        .expect("open doubled-classification injection");
                    ledger
                        .connection
                        .execute(
                            "INSERT INTO legacy_runner_launch_cleanup_gaps (
                                launch_id, sprint_id, session_id, gap_kind, contract_version
                             ) VALUES (?1, ?2, ?3, 'PreV13Unbound', ?4)",
                            params![
                                launch.launch_id,
                                launch.sprint_id,
                                launch.session_id,
                                i64::from(CONTRACT_VERSION),
                            ],
                        )
                        .expect("inject doubled classification");
                }
                "neither" => {
                    ledger
                        .connection
                        .execute_batch(
                            "DROP TRIGGER runner_launch_cleanup_admissions_no_delete;
                             PRAGMA foreign_keys = OFF;
                             DELETE FROM runner_launch_cleanup_admissions;",
                        )
                        .expect("inject missing classification");
                }
                "json" => {
                    ledger
                        .connection
                        .execute_batch(
                            "DROP TRIGGER runner_launch_cleanup_admissions_no_update;
                             UPDATE runner_launch_cleanup_admissions
                             SET admission_json = CAST(json_set(
                                 CAST(admission_json AS TEXT),
                                 '$.session_id', 'crossed-session'
                             ) AS BLOB);",
                        )
                        .expect("inject admission JSON crossing");
                }
                "policy" => {
                    ledger
                        .connection
                        .execute_batch(
                            "DROP TRIGGER runner_launch_intents_no_update;
                             UPDATE runner_launch_intents SET policy_hash = 'ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff';",
                        )
                        .expect("inject indexed policy corruption");
                }
                "binding" => {
                    ledger
                        .connection
                        .execute_batch(
                            "DROP TRIGGER effect_session_bindings_no_update;
                             UPDATE effect_session_bindings SET contract_version = contract_version + 1;",
                        )
                        .expect("inject binding corruption");
                }
                _ => unreachable!("closed corruption matrix"),
            }
            assert!(matches!(
                ledger.load_runner_launch_intent(&launch.sprint_id, &launch.launch_id),
                Err(LedgerError::Corrupt { .. } | LedgerError::UnsupportedContractVersion { .. })
            ));
        }
    }

    #[test]
    fn successful_completion_rejects_missing_doubled_or_crossed_launch_cleanup_authority() {
        for corruption in ["both", "neither", "crossed"] {
            let database = TestDatabase::new();
            let mut ledger = open_v21_test_ledger(&database);
            let (report, receipt, event) = prepare_completion_evidence(&mut ledger);
            inject_runner_launch_cleanup_authority_corruption(&ledger, corruption);

            assert!(matches!(
                ledger.record_successful_completion(&report, &receipt, &event),
                Err(LedgerError::Corrupt { .. })
            ));
            assert_eq!(
                row_count(&ledger, "sprint_completion_proof_states"),
                0,
                "corruption case {corruption} wrote a completion proof"
            );
            assert_eq!(
                row_count(&ledger, "v9_completion_receipts"),
                0,
                "corruption case {corruption} wrote a completion receipt"
            );
        }
    }

    #[test]
    fn completion_readback_rejects_missing_doubled_or_crossed_launch_cleanup_authority() {
        for corruption in ["both", "neither", "crossed"] {
            let database = TestDatabase::new();
            let mut ledger = open_v21_test_ledger(&database);
            let (report, receipt, event) = prepare_completion_evidence(&mut ledger);
            let expected = record_pre_v24_successful_completion_for_test(
                &mut ledger,
                &report,
                &receipt,
                &event,
            )
            .expect("record valid completion before corruption");
            drop(ledger);
            let ledger = EventLedger::open(&database.path)
                .expect("migrate completion before readback corruption");
            load_migrated_pre_v24_completion(&ledger, &expected);
            inject_runner_launch_cleanup_authority_corruption(&ledger, corruption);

            assert!(matches!(
                ledger.load_completion(&receipt.sprint_id),
                Err(LedgerError::Corrupt { .. })
            ));
        }
    }

    #[test]
    #[allow(clippy::too_many_lines)] // Admission, readback, and bypass share one authority fixture.
    fn runner_role_policy_shape_is_enforced_at_every_durable_boundary() {
        let database = TestDatabase::new();
        let mut ledger = EventLedger::open(&database.path).expect("open ledger");
        prepare_effect_input(&mut ledger);

        let read_only = compiled_test_policy("role-read-only-policy");
        let shadow = compiled_shadow_test_policy("role-shadow-policy");
        let read_only_with_writes = compiled_test_policy_with_authority(
            "role-read-only-with-writes",
            MutationMode::ReadOnly,
            vec![PathScope::Workspace],
        );
        assert!(runner_role_policy_matches(
            RunnerSessionPurpose::TaskWorker,
            shadow.contract()
        ));
        assert!(runner_role_policy_matches(
            RunnerSessionPurpose::Applier,
            read_only.contract()
        ));
        assert!(!runner_role_policy_matches(
            RunnerSessionPurpose::TaskWorker,
            read_only.contract()
        ));
        assert!(!runner_role_policy_matches(
            RunnerSessionPurpose::FinalVerifier,
            read_only_with_writes.contract()
        ));

        let invalid_worker = runner_launch(
            "launch-invalid-worker-policy",
            "session-invalid-worker-policy",
            RunnerSessionPurpose::TaskWorker,
            Some("worker-1"),
            &read_only,
            1_100,
        );
        assert!(matches!(
            try_admit_test_runner_launch(&mut ledger, &invalid_worker, &read_only),
            Err(LedgerError::ReferenceMismatch {
                entity: "runner launch intent",
                ..
            })
        ));
        let invalid_applier = runner_launch(
            "launch-invalid-applier-policy",
            "session-invalid-applier-policy",
            RunnerSessionPurpose::Applier,
            None,
            &shadow,
            1_101,
        );
        assert!(matches!(
            try_admit_test_runner_launch(&mut ledger, &invalid_applier, &shadow),
            Err(LedgerError::ReferenceMismatch {
                entity: "runner launch intent",
                ..
            })
        ));
        let invalid_verifier = runner_launch(
            "launch-invalid-verifier-policy",
            "session-invalid-verifier-policy",
            RunnerSessionPurpose::FinalVerifier,
            None,
            &read_only_with_writes,
            1_102,
        );
        assert!(matches!(
            try_admit_test_runner_launch(&mut ledger, &invalid_verifier, &read_only_with_writes),
            Err(LedgerError::ReferenceMismatch {
                entity: "runner launch intent",
                ..
            })
        ));

        let valid_worker = runner_launch(
            "launch-valid-worker-policy",
            "session-valid-worker-policy",
            RunnerSessionPurpose::TaskWorker,
            Some("worker-1"),
            &shadow,
            1_110,
        );
        admit_test_runner_launch(&mut ledger, &valid_worker, &shadow);
        ledger
            .register_runner_session(&runner_session(&valid_worker, 1_120), &shadow)
            .expect("persist role-correct worker session");
        let valid_applier = runner_launch(
            "launch-valid-applier-policy",
            "session-valid-applier-policy",
            RunnerSessionPurpose::Applier,
            None,
            &read_only,
            1_111,
        );
        admit_test_runner_launch(&mut ledger, &valid_applier, &read_only);
        ledger
            .register_runner_session(&runner_session(&valid_applier, 1_121), &read_only)
            .expect("persist role-correct applier session");

        let transaction = ledger
            .connection
            .transaction()
            .expect("start invalid launch bypass");
        assert!(
            insert_runner_launch_intent(&transaction, &invalid_worker, read_only.contract())
                .is_err(),
            "schema must reject a standalone launch without cleanup authority"
        );
        transaction
            .rollback()
            .expect("rollback rejected invalid launch bypass");
        assert!(matches!(
            load_runner_launch_intent_from(
                &ledger.connection,
                &invalid_worker.sprint_id,
                &invalid_worker.launch_id
            ),
            Err(LedgerError::ArtifactNotFound {
                entity: "runner launch intent",
                ..
            })
        ));
        assert!(matches!(
            ledger.register_runner_session(&runner_session(&invalid_worker, 1_130), &read_only),
            Err(LedgerError::ArtifactNotFound {
                entity: "runner launch intent",
                ..
            })
        ));
    }

    #[test]
    fn exact_schema_verification_rejects_missing_integrity_trigger() {
        let database = TestDatabase::new();
        {
            let ledger = EventLedger::open(&database.path).expect("open ledger");
            ledger
                .connection
                .execute_batch("DROP TRIGGER agent_events_no_delete;")
                .expect("simulate a database with a falsified schema version");
        }

        assert!(matches!(
            EventLedger::open(&database.path),
            Err(LedgerError::Corrupt {
                entity: "ledger schema",
                ..
            })
        ));
    }

    #[cfg(unix)]
    #[test]
    fn database_hard_links_are_rejected() {
        let database = TestDatabase::new();
        fs::write(&database.path, []).expect("create candidate database file");
        fs::hard_link(&database.path, database.directory.join("second-link"))
            .expect("create hard link");

        assert!(matches!(
            EventLedger::open(&database.path),
            Err(LedgerError::InvalidDatabasePath { reason, .. })
                if reason.contains("exactly one hard link")
        ));
    }

    #[test]
    fn read_only_recovery_handle_loads_but_cannot_append() {
        let database = TestDatabase::new();
        let (spec, graph) = sprint_fixture();
        {
            let mut ledger = EventLedger::open(&database.path).expect("open writer");
            ledger
                .create_sprint(&spec, &graph, 1_000)
                .expect("persist sprint");
            ledger
                .append_event(&event(1, "event-1", None))
                .expect("append event");
        }

        let mut ledger = EventLedger::open_read_only(&database.path).expect("open recovery reader");
        assert!(ledger.is_read_only());
        assert_eq!(
            ledger
                .load_sprint("sprint-1")
                .expect("recover sprint")
                .events,
            vec![event(1, "event-1", None)]
        );
        assert!(matches!(
            ledger.append_event(&event(2, "event-2", Some("event-1"))),
            Err(LedgerError::ReadOnly)
        ));
    }

    #[test]
    fn non_success_terminal_states_round_trip_across_read_only_restart() {
        for (state, expected_state) in [
            (NonSuccessTerminalState::Blocked, SprintState::Blocked),
            (NonSuccessTerminalState::Failed, SprintState::Failed),
            (NonSuccessTerminalState::Canceled, SprintState::Canceled),
            (NonSuccessTerminalState::Unknown, SprintState::Unknown),
        ] {
            let database = TestDatabase::new();
            let record_id = format!("terminal-{state:?}");
            let evidence = terminal_evidence(&record_id, state);
            let expected = {
                let mut ledger = EventLedger::open(&database.path).expect("open writer");
                prepare_terminal_sprint(&mut ledger);
                if state == NonSuccessTerminalState::Unknown {
                    let intent = effect_intent("effect-unknown", "key-unknown", 1_500);
                    let proposal = effect_proposal_event(&intent, 1, "unknown-proposed");
                    record_test_effect_intent(&mut ledger, &intent, &proposal)
                        .expect("persist unresolved effect");
                } else {
                    let mut diagnostic = event(1, "before-terminal", None);
                    diagnostic.occurred_at_unix_ms = 1_500;
                    ledger.append_event(&diagnostic).expect("append diagnostic");
                }
                let outcome = record_test_terminal_outcome(&mut ledger, &evidence)
                    .expect("record terminal outcome");
                assert_eq!(
                    outcome.evidence_bytes,
                    encode("evidence", &evidence).unwrap()
                );
                assert_eq!(
                    outcome.evidence_digest,
                    Digest::sha256(&outcome.evidence_bytes)
                );
                assert_eq!(outcome.terminal_state, expected_state);
                assert_eq!(ledger.load_completion("sprint-1").unwrap(), None);
                outcome
            };

            let mut reader =
                EventLedger::open_read_only(&database.path).expect("open read-only ledger");
            let restored = reader
                .load_sprint("sprint-1")
                .expect("restore terminal sprint");
            assert_eq!(restored.completion, None);
            assert_eq!(restored.terminal_outcome, Some(expected.clone()));
            assert_eq!(restored.events.last(), Some(&expected.event));
            assert!(matches!(
                record_test_terminal_outcome(&mut reader, &evidence),
                Err(LedgerError::ReadOnly)
            ));
        }
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "the terminal-exclusivity regression must carry one valid current-schema capture authority to the completion writer"
    )]
    fn terminal_outcomes_are_exclusive_with_duplicates_and_completion() {
        let empty_manifest = DescriptorRelativeWorkspaceManifest::from_captured_entries(
            digest('a'),
            1,
            1,
            Vec::new(),
        )
        .expect("derive current terminal-exclusivity snapshot");
        let expected_snapshot = empty_manifest.manifest_digest;
        let prepared = prepare_v22_explicit_empty_preparation_fixture_with_base_snapshot(
            expected_snapshot.clone(),
        );
        let final_verification_receipt_id = prepared.final_evidence.verification.receipt_id;
        let V15CandidateFixture {
            database: _database,
            mut ledger,
            spec,
            ..
        } = prepared.candidate;
        let task_done = ledger
            .assess_task_done(&spec.sprint_id, "task-1")
            .expect("assess current terminal-exclusivity TaskDone")
            .proof
            .expect("current terminal-exclusivity task is done");
        let task_integration_receipt_id = task_done.integration_receipt.receipt_id.clone();
        let mut attempt = v23_adversarial_admit_attempt(
            &mut ledger,
            &spec,
            &final_verification_receipt_id,
            &task_integration_receipt_id,
            "terminal-exclusivity",
        );
        let capture = persist_v24_matching_empty_live_state_capture(&mut ledger, &mut attempt);
        let cleanup_effect = ledger
            .with_runner_launch_cleanup_exclusion(
                &spec.sprint_id,
                &attempt.launch.launch_id,
                |claim| {
                    Ok(cleanup_terminal_from_live_claim(
                        claim,
                        "terminal-exclusivity",
                        capture.receipt.captured_at_unix_ms.saturating_add(10),
                    ))
                },
            )
            .expect("close terminal-exclusivity live-state verifier");
        let verifier_cleanup = match cleanup_effect.finish_receipt {
            PersistedFinishReceipt::WorkerCleanup(evidence) => evidence,
            other => panic!("expected live-state verifier cleanup, got {other:?}"),
        };

        let accepted_at_unix_ms = verifier_cleanup
            .receipt
            .cleaned_at_unix_ms
            .saturating_add(10);
        let acceptance = AcceptanceReceipt {
            receipt_id: "acceptance-terminal-exclusivity".into(),
            sprint_id: spec.sprint_id.clone(),
            criterion_id: "tests".into(),
            snapshot_id: expected_snapshot.clone(),
            evidence: AcceptanceEvidence::Automated {
                verification_receipt_id: final_verification_receipt_id.clone(),
            },
            accepted_at_unix_ms,
        };
        ledger
            .persist_acceptance_receipt(&acceptance)
            .expect("persist terminal-exclusivity acceptance");
        let body = "The exact live state is ready for terminal-exclusivity testing.".to_owned();
        let report = FinalReport {
            report_id: "report-terminal-exclusivity".into(),
            sprint_id: spec.sprint_id.clone(),
            final_snapshot: expected_snapshot.clone(),
            content_digest: FinalReport::digest_body(&body),
            body,
            created_at_unix_ms: accepted_at_unix_ms.saturating_add(10),
        };
        let mut worker_cleanup_receipt_ids = attempt.plan.required_cleanup_receipt_ids.clone();
        worker_cleanup_receipt_ids.push(verifier_cleanup.receipt.receipt_id.clone());
        worker_cleanup_receipt_ids.sort();
        let mut verification_receipts = task_done
            .integration_receipt
            .task_verification_receipt_ids
            .clone();
        verification_receipts.push(final_verification_receipt_id.clone());
        verification_receipts.sort();
        let receipt = CompletionReceipt {
            contract_version: CONTRACT_VERSION,
            receipt_id: "completion-terminal-exclusivity".into(),
            sprint_id: spec.sprint_id.clone(),
            grant_hash: spec.workspace_grant.grant_hash.clone(),
            policy_version: spec.workspace_grant.policy_version,
            final_snapshot: expected_snapshot.clone(),
            final_verification_receipt_id,
            application: CompletionApplication::VerifiedNoOp {
                verified_no_op_receipt_id: "verified-no-op-terminal-exclusivity".into(),
            },
            worker_cleanup_receipt_ids,
            satisfied_criterion_ids: vec![acceptance.criterion_id.clone()],
            criterion_evidence_receipt_ids: vec![acceptance.receipt_id.clone()],
            task_integration_receipt_ids: vec![task_integration_receipt_id],
            verification_receipts,
            provider_backend: spec.provider.backend_id.clone(),
            provider_model: spec.provider.model_id.clone(),
            final_report_id: report.report_id.clone(),
            completed_at_unix_ms: report.created_at_unix_ms.saturating_add(10),
        };
        let completion_event = AgentEvent {
            contract_version: CONTRACT_VERSION,
            sequence: ledger
                .next_sequence(&spec.sprint_id)
                .expect("terminal-exclusivity completion sequence"),
            event_id: "event-terminal-exclusivity-completed".into(),
            sprint_id: spec.sprint_id.clone(),
            task_id: None,
            worker_id: None,
            causation_id: None,
            correlation_id: "terminal-exclusivity-completion".into(),
            policy_hash: None,
            occurred_at_unix_ms: receipt.completed_at_unix_ms,
            payload: AgentEventKind::CompletionRecorded(receipt.receipt_id.clone()),
        };

        let mut early = terminal_evidence("terminal-early", NonSuccessTerminalState::Failed);
        early.terminal_at_unix_ms = 999;
        assert!(matches!(
            record_test_terminal_outcome(&mut ledger, &early),
            Err(LedgerError::ReferenceMismatch { .. })
        ));
        let mut evidence = terminal_evidence("terminal-failed", NonSuccessTerminalState::Failed);
        evidence.terminal_at_unix_ms = receipt.completed_at_unix_ms.saturating_add(10);
        let unchanged =
            SprintTerminalProof::LiveWorkspaceUnchanged(LiveWorkspaceUnchangedReceipt {
                contract_version: CONTRACT_VERSION,
                receipt_id: format!("unchanged-{}", evidence.record_id),
                sprint_id: evidence.sprint_id.clone(),
                base_snapshot: expected_snapshot.clone(),
                live_manifest_digest: expected_snapshot,
                grant_hash: spec.workspace_grant.grant_hash.clone(),
                captured_at_unix_ms: evidence.terminal_at_unix_ms,
            });
        ledger
            .record_unsuccessful_terminal_outcome_with_proof(&evidence, &unchanged)
            .expect("record failed outcome");
        assert!(matches!(
            ledger.record_unsuccessful_terminal_outcome_with_proof(&evidence, &unchanged),
            Err(LedgerError::SprintAlreadyTerminal(id)) if id == "sprint-1"
        ));
        assert!(matches!(
            ledger.record_successful_completion_from_live_state_capture(
                &report,
                &receipt,
                &capture.receipt.receipt_id,
                &completion_event,
            ),
            Err(LedgerError::SprintAlreadyTerminal(id)) if id == "sprint-1"
        ));

        let database = TestDatabase::new();
        let mut ledger = open_v21_test_ledger(&database);
        let (report, receipt, event) = prepare_completion_evidence(&mut ledger);
        let expected =
            record_pre_v24_successful_completion_for_test(&mut ledger, &report, &receipt, &event)
                .expect("record successful completion");
        drop(ledger);
        let mut ledger = EventLedger::open(&database.path)
            .expect("migrate completion before terminal exclusivity checks");
        load_migrated_pre_v24_completion(&ledger, &expected);
        assert!(matches!(
            record_test_terminal_outcome(
                &mut ledger,
                &terminal_evidence(
                    "terminal-after-complete",
                    NonSuccessTerminalState::Canceled,
                ),
            ),
            Err(LedgerError::SprintAlreadyTerminal(id)) if id == "sprint-1"
        ));
        assert_eq!(
            ledger.load_sprint("sprint-1").unwrap().terminal_outcome,
            None
        );
    }

    #[test]
    fn terminal_effect_admission_distinguishes_known_and_unknown() {
        let database = TestDatabase::new();
        let mut ledger = EventLedger::open(&database.path).expect("open ledger");
        prepare_terminal_sprint(&mut ledger);
        assert!(matches!(
            ledger.record_unsuccessful_terminal_outcome(&terminal_evidence(
                "unknown-without-effect",
                NonSuccessTerminalState::Unknown,
            )),
            Err(LedgerError::ReferenceMismatch { .. })
        ));

        let database = TestDatabase::new();
        let mut ledger = EventLedger::open(&database.path).expect("open unresolved ledger");
        prepare_terminal_effect(&mut ledger, None);
        for state in [
            NonSuccessTerminalState::Blocked,
            NonSuccessTerminalState::Failed,
            NonSuccessTerminalState::Canceled,
        ] {
            assert!(matches!(
                ledger.record_unsuccessful_terminal_outcome(&terminal_evidence(
                    &format!("known-{state:?}"),
                    state,
                )),
                Err(LedgerError::ReferenceMismatch { .. })
            ));
        }
        ledger
            .record_unsuccessful_terminal_outcome(&terminal_evidence(
                "unknown-unresolved",
                NonSuccessTerminalState::Unknown,
            ))
            .expect("unresolved effect admits Unknown");

        let database = TestDatabase::new();
        let mut ledger = EventLedger::open(&database.path).expect("open known ledger");
        prepare_terminal_effect(
            &mut ledger,
            Some(EffectOutcome::Succeeded {
                evidence_digest: effect_evidence_digest(),
            }),
        );
        assert!(matches!(
            ledger.record_unsuccessful_terminal_outcome(&terminal_evidence(
                "unknown-after-known",
                NonSuccessTerminalState::Unknown,
            )),
            Err(LedgerError::ReferenceMismatch { .. })
        ));
        record_test_terminal_outcome(
            &mut ledger,
            &terminal_evidence("failed-after-known", NonSuccessTerminalState::Failed),
        )
        .expect("known effects admit Failed");
    }

    #[test]
    fn known_terminal_cleanup_allows_zero_launches_and_rejects_every_uncleaned_launch() {
        let zero_launch_database = TestDatabase::new();
        let expected = {
            let mut ledger =
                EventLedger::open(&zero_launch_database.path).expect("open zero-launch ledger");
            prepare_terminal_sprint(&mut ledger);
            let evidence =
                terminal_evidence("failed-before-any-launch", NonSuccessTerminalState::Failed);
            record_test_terminal_outcome(&mut ledger, &evidence)
                .expect("an exact zero-launch sprint has an empty cleanup obligation")
        };
        let reader = EventLedger::open_read_only(&zero_launch_database.path)
            .expect("reopen zero-launch terminal read-only");
        assert_eq!(
            reader
                .load_terminal_outcome("sprint-1")
                .expect("read zero-launch terminal"),
            Some(expected)
        );

        for state in [
            NonSuccessTerminalState::Blocked,
            NonSuccessTerminalState::Failed,
            NonSuccessTerminalState::Canceled,
        ] {
            let database = TestDatabase::new();
            let mut ledger = EventLedger::open(&database.path).expect("open unclean launch ledger");
            prepare_terminal_sprint(&mut ledger);
            let policy = compiled_test_policy(&format!("unclean-known-terminal-{state:?}"));
            let launch = runner_launch(
                &format!("unclean-known-terminal-launch-{state:?}"),
                &format!("unclean-known-terminal-session-{state:?}"),
                RunnerSessionPurpose::Applier,
                None,
                &policy,
                1_200,
            );
            admit_test_runner_launch(&mut ledger, &launch, &policy);

            let evidence = terminal_evidence(&format!("unclean-{state:?}"), state);
            let error = ledger
                .record_unsuccessful_terminal_outcome_with_proof(
                    &evidence,
                    &unchanged_terminal_proof(&evidence),
                )
                .expect_err("known terminal cannot strand one admitted runner launch");
            assert!(matches!(
                error,
                LedgerError::ReferenceMismatch {
                    entity: "worker cleanup set",
                    ref detail,
                } if detail.contains("canonical exact registered-session set")
            ));
            assert_eq!(
                ledger
                    .load_terminal_outcome("sprint-1")
                    .expect("failed terminal write remains atomic"),
                None
            );
        }
    }

    #[test]
    fn terminal_effect_admission_accepts_only_unknown_effect_evidence_for_unknown() {
        let database = TestDatabase::new();
        let mut ledger = EventLedger::open(&database.path).expect("open ledger");
        prepare_terminal_effect(
            &mut ledger,
            Some(EffectOutcome::Unknown {
                evidence_digest: effect_evidence_digest(),
            }),
        );
        assert!(matches!(
            ledger.record_unsuccessful_terminal_outcome(&terminal_evidence(
                "failed-with-unknown-effect",
                NonSuccessTerminalState::Failed,
            )),
            Err(LedgerError::ReferenceMismatch { .. })
        ));
        let expected = ledger
            .record_unsuccessful_terminal_outcome(&terminal_evidence(
                "unknown-with-unknown-effect",
                NonSuccessTerminalState::Unknown,
            ))
            .expect("Unknown observation admits Unknown sprint outcome");
        drop(ledger);

        let ledger = EventLedger::open_read_only(&database.path).expect("reopen read-only");
        assert_eq!(
            ledger.load_sprint("sprint-1").unwrap().terminal_outcome,
            Some(expected)
        );
    }

    #[test]
    fn terminal_evidence_rejects_oversize_and_malformed_utf8_corruption() {
        let database = TestDatabase::new();
        let mut ledger = EventLedger::open(&database.path).expect("open ledger");
        prepare_terminal_sprint(&mut ledger);
        let mut oversized = terminal_evidence("oversized", NonSuccessTerminalState::Blocked);
        oversized.reason = "x".repeat(crate::MAX_TERMINAL_REASON_BYTES + 1);
        assert!(matches!(
            record_test_terminal_outcome(&mut ledger, &oversized),
            Err(LedgerError::Contract(error))
                if error.field() == "sprint_terminal_evidence.reason"
        ));
        assert_eq!(
            row_count(&ledger, "sprint_non_success_terminal_outcomes"),
            0
        );

        let evidence = terminal_evidence("terminal-corrupt", NonSuccessTerminalState::Blocked);
        record_test_terminal_outcome(&mut ledger, &evidence).expect("record valid outcome");
        let malformed = vec![0xff, 0xfe, 0xfd];
        let malformed_digest = Digest::sha256(&malformed);
        ledger
            .connection
            .execute_batch("DROP TRIGGER sprint_non_success_terminal_outcomes_no_update;")
            .expect("disable immutability for corruption test");
        ledger
            .connection
            .execute(
                "UPDATE sprint_non_success_terminal_outcomes
                 SET evidence_json = ?1, evidence_digest = ?2
                 WHERE sprint_id = 'sprint-1'",
                params![malformed, malformed_digest.as_str()],
            )
            .expect("inject malformed UTF-8 evidence");
        assert!(matches!(
            ledger.load_sprint("sprint-1"),
            Err(LedgerError::Corrupt { .. })
        ));
    }

    #[test]
    fn terminal_events_require_the_atomic_outcome_api_and_deferred_pair() {
        let database = TestDatabase::new();
        let mut ledger = EventLedger::open(&database.path).expect("open ledger");
        prepare_terminal_sprint(&mut ledger);
        let evidence = terminal_evidence("terminal-orphan", NonSuccessTerminalState::Blocked);
        let evidence_bytes = encode("terminal evidence", &evidence).unwrap();
        let evidence_digest = Digest::sha256(&evidence_bytes);
        let terminal_event = normalized_terminal_event(&evidence, evidence_digest.clone(), 1);
        assert!(matches!(
            ledger.append_event(&terminal_event),
            Err(LedgerError::ReferenceMismatch { .. })
        ));

        {
            let transaction = ledger.connection.transaction().expect("start event bypass");
            assert!(
                insert_agent_event(&transaction, &terminal_event).is_err(),
                "schema must reject an orphan typed terminal event"
            );
            transaction.rollback().expect("rollback event bypass");
        }
        {
            let transaction = ledger
                .connection
                .transaction()
                .expect("start marker bypass");
            insert_terminal_proof(
                &transaction,
                &evidence,
                &evidence_digest,
                &terminal_event,
                TerminalProofAdmission::Known(&unchanged_terminal_proof(&evidence)),
            )
            .expect("persist the required cleanup proof first");
            insert_non_success_terminal_outcome(
                &transaction,
                &evidence,
                &evidence_bytes,
                &evidence_digest,
            )
            .expect("deferred event reference permits the first half");
            assert!(
                transaction.commit().is_err(),
                "deferred foreign key must reject an orphan outcome marker"
            );
        }
        assert_eq!(row_count(&ledger, "agent_events"), 0);
        assert_eq!(
            row_count(&ledger, "sprint_non_success_terminal_outcomes"),
            0
        );
        assert_eq!(row_count(&ledger, "terminal_cleanup_proofs"), 0);
        assert_eq!(row_count(&ledger, "live_workspace_unchanged_receipts"), 0);
    }

    #[test]
    fn terminal_effect_admission_is_enforced_by_schema_triggers() {
        let database = TestDatabase::new();
        let mut ledger = EventLedger::open(&database.path).expect("open ledger");
        prepare_terminal_effect(&mut ledger, None);
        let evidence = terminal_evidence("direct-failed", NonSuccessTerminalState::Failed);
        let bytes = encode("terminal evidence", &evidence).unwrap();
        let digest = Digest::sha256(&bytes);
        let transaction = ledger.connection.transaction().expect("start bypass");
        assert!(
            insert_non_success_terminal_outcome(&transaction, &evidence, &bytes, &digest).is_err(),
            "direct SQL cannot label an unresolved effect as Failed"
        );
        transaction.rollback().expect("rollback bypass");

        let database = TestDatabase::new();
        let mut ledger = EventLedger::open(&database.path).expect("open no-effect ledger");
        prepare_terminal_sprint(&mut ledger);
        let evidence = terminal_evidence("direct-unknown", NonSuccessTerminalState::Unknown);
        let bytes = encode("terminal evidence", &evidence).unwrap();
        let digest = Digest::sha256(&bytes);
        let transaction = ledger
            .connection
            .transaction()
            .expect("start unknown bypass");
        assert!(
            insert_non_success_terminal_outcome(&transaction, &evidence, &bytes, &digest).is_err(),
            "direct SQL cannot record Unknown without unresolved evidence"
        );
        transaction.rollback().expect("rollback unknown bypass");
    }

    #[test]
    fn non_success_terminal_marker_fences_later_work_and_is_immutable() {
        let database = TestDatabase::new();
        let mut ledger = EventLedger::open(&database.path).expect("open ledger");
        prepare_terminal_sprint(&mut ledger);
        record_test_terminal_outcome(
            &mut ledger,
            &terminal_evidence("terminal-blocked", NonSuccessTerminalState::Blocked),
        )
        .expect("record terminal marker");
        assert!(matches!(
            ledger.append_event(&event(2, "after-terminal", None)),
            Err(LedgerError::SprintAlreadyTerminal(_))
        ));
        let (base, _, _, _, _, _, _, _) = completion_artifacts();
        assert!(matches!(
            ledger.persist_workspace_snapshot("sprint-1", &base),
            Err(LedgerError::SprintAlreadyTerminal(_))
        ));
        let intent = effect_intent("after-terminal-effect", "after-terminal-key", 2_100);
        let proposal = effect_proposal_event(&intent, 2, "after-terminal-proposal");
        assert!(matches!(
            record_test_effect_intent(&mut ledger, &intent, &proposal),
            Err(LedgerError::SprintAlreadyTerminal(_))
        ));

        let transaction = ledger.connection.transaction().expect("start SQL bypass");
        assert!(insert_agent_event(&transaction, &event(2, "direct-event", None)).is_err());
        assert!(insert_workspace_snapshot(&transaction, "sprint-1", &base).is_err());
        transaction.rollback().expect("rollback SQL bypass");
        assert!(
            ledger
                .connection
                .execute(
                    "UPDATE sprint_non_success_terminal_outcomes
                 SET terminal_state = terminal_state",
                    [],
                )
                .is_err()
        );
        assert!(
            ledger
                .connection
                .execute("DELETE FROM sprint_non_success_terminal_outcomes", [])
                .is_err()
        );
    }

    #[test]
    fn terminal_readback_rejects_direct_sql_state_and_event_corruption() {
        let database = TestDatabase::new();
        let mut ledger = EventLedger::open(&database.path).expect("open ledger");
        prepare_terminal_sprint(&mut ledger);
        let evidence = terminal_evidence("terminal-index", NonSuccessTerminalState::Blocked);
        record_test_terminal_outcome(&mut ledger, &evidence).expect("record terminal outcome");
        ledger
            .connection
            .execute_batch("DROP TRIGGER sprint_non_success_terminal_outcomes_no_update;")
            .expect("disable outcome immutability");
        ledger
            .connection
            .execute(
                "UPDATE sprint_non_success_terminal_outcomes
                 SET terminal_state = 'Failed' WHERE sprint_id = 'sprint-1'",
                [],
            )
            .expect("corrupt indexed terminal state");
        assert!(matches!(
            ledger.load_terminal_outcome("sprint-1"),
            Err(LedgerError::Corrupt { .. })
        ));

        ledger
            .connection
            .execute(
                "UPDATE sprint_non_success_terminal_outcomes
                 SET terminal_state = 'Blocked' WHERE sprint_id = 'sprint-1'",
                [],
            )
            .expect("restore indexed state");
        ledger
            .connection
            .execute_batch("DROP TRIGGER agent_events_no_update;")
            .expect("disable event immutability");
        let mut corrupt_event = normalized_terminal_event(
            &evidence,
            Digest::sha256(&encode("evidence", &evidence).unwrap()),
            1,
        );
        corrupt_event.correlation_id = "wrong-correlation".into();
        ledger
            .connection
            .execute(
                "UPDATE agent_events SET event_json = ?1 WHERE event_id = ?2",
                params![
                    encode("event", &corrupt_event).unwrap(),
                    corrupt_event.event_id
                ],
            )
            .expect("corrupt normalized event");
        assert!(matches!(
            ledger.load_sprint("sprint-1"),
            Err(LedgerError::Corrupt { .. })
        ));
    }

    #[test]
    fn terminal_readback_rejects_effect_state_misclassification() {
        let database = TestDatabase::new();
        let mut ledger = EventLedger::open(&database.path).expect("open ledger");
        prepare_terminal_effect(
            &mut ledger,
            Some(EffectOutcome::Unknown {
                evidence_digest: effect_evidence_digest(),
            }),
        );
        let mut evidence =
            terminal_evidence("terminal-unknown-effect", NonSuccessTerminalState::Unknown);
        let outcome = ledger
            .record_unsuccessful_terminal_outcome(&evidence)
            .expect("record valid Unknown outcome");
        evidence.state = NonSuccessTerminalState::Failed;
        let evidence_bytes = encode("terminal evidence", &evidence).unwrap();
        let evidence_digest = Digest::sha256(&evidence_bytes);
        let event =
            normalized_terminal_event(&evidence, evidence_digest.clone(), outcome.event.sequence);
        ledger
            .connection
            .execute_batch(
                "DROP TRIGGER sprint_non_success_terminal_outcomes_no_update;
                 DROP TRIGGER agent_events_no_update;",
            )
            .expect("disable immutability for corruption test");
        ledger
            .connection
            .execute(
                "UPDATE sprint_non_success_terminal_outcomes
                 SET terminal_state = 'Failed', evidence_digest = ?1,
                     evidence_json = ?2 WHERE sprint_id = 'sprint-1'",
                params![evidence_digest.as_str(), evidence_bytes],
            )
            .expect("misclassify terminal evidence");
        ledger
            .connection
            .execute(
                "UPDATE agent_events SET event_json = ?1 WHERE event_id = ?2",
                params![encode("terminal event", &event).unwrap(), event.event_id],
            )
            .expect("correlate forged terminal event");
        assert!(matches!(
            ledger.load_sprint("sprint-1"),
            Err(LedgerError::Corrupt { entity, .. })
                if entity == "sprint terminal outcome"
        ));
    }

    #[test]
    fn v1_database_migrates_additively_to_exact_current_schema() {
        let database = TestDatabase::new();
        {
            let connection = Connection::open(&database.path).expect("create v1 database");
            connection
                .execute_batch("PRAGMA journal_mode = WAL;")
                .expect("select WAL mode");
            connection
                .execute_batch(MIGRATIONS[0])
                .expect("install v1 schema");
            connection
                .pragma_update(None, "user_version", 1_i64)
                .expect("mark v1 schema");
        }

        let mut ledger = EventLedger::open(&database.path).expect("upgrade to current schema");
        let version: i64 = ledger
            .connection
            .pragma_query_value(None, "user_version", |row| row.get(0))
            .expect("read upgraded version");
        assert_eq!(version, SCHEMA_VERSION);
        assert_eq!(row_count(&ledger, "legacy_effect_payload_gaps"), 0);
        verify_exact_schema(&ledger.connection).expect("schema exactly matches every migration");

        let (spec, graph) = sprint_fixture();
        ledger
            .create_sprint(&spec, &graph, 1_000)
            .expect("current APIs remain usable after migration");
        let (base, _, _, _, _, _, _, _) = completion_artifacts();
        ledger
            .persist_workspace_snapshot("sprint-1", &base)
            .expect("persist current artifact");
    }

    #[test]
    #[allow(clippy::too_many_lines)] // Historical bytes, schema, API, and fence checks are one migration case.
    fn v9_completed_database_migrates_through_v14_without_changing_history_or_terminal_fences() {
        let database = TestDatabase::new();
        let (expected, v9_bytes, v9_schema) = {
            schema_template::install_exact_database_at(9, &database.path);
            let connection = Connection::open(&database.path).expect("create v9 database");
            connection
                .execute_batch(
                    "PRAGMA foreign_keys = ON;
                     PRAGMA synchronous = FULL;
                     PRAGMA journal_mode = WAL;",
                )
                .expect("configure v9 database");
            let mut legacy = EventLedger {
                connection,
                database_path: database.path.clone(),
                read_only: false,
                instance_id: next_event_ledger_instance_id(),
            };
            let (report, receipt, event) = prepare_completion_evidence(&mut legacy);
            let expected = record_pre_v24_successful_completion_for_test(
                &mut legacy,
                &report,
                &receipt,
                &event,
            )
            .expect("record proven v9 completion");
            let durable_bytes = legacy
                .connection
                .query_row(
                    "SELECT completion.receipt_json, application.evidence_json,
                            rollback.evidence_json
                     FROM v9_completion_receipts completion
                     JOIN application_receipts application
                       ON application.receipt_id = completion.application_receipt_id
                     JOIN rollback_references rollback
                       ON rollback.reference_id = completion.rollback_reference_id
                     WHERE completion.sprint_id = 'sprint-1'",
                    [],
                    |row| {
                        Ok((
                            row.get::<_, Vec<u8>>(0)?,
                            row.get::<_, Vec<u8>>(1)?,
                            row.get::<_, Vec<u8>>(2)?,
                        ))
                    },
                )
                .expect("capture immutable v9 evidence bytes");
            let schema = load_schema_objects(&legacy.connection).expect("capture v9 schema");
            (expected, durable_bytes, schema)
        };

        let ledger = reopen_test_legacy_ledger(&database);
        for migration in MIGRATIONS.iter().take(14).skip(9) {
            ledger
                .connection
                .execute_batch(migration)
                .expect("install migration through exact v14");
        }
        ledger
            .connection
            .pragma_update(None, "user_version", 14_i64)
            .expect("mark exact v14 schema");
        let version: i64 = ledger
            .connection
            .pragma_query_value(None, "user_version", |row| row.get(0))
            .expect("read exact v14 schema version");
        assert_eq!(version, 14);
        let current_schema = load_schema_objects(&ledger.connection).expect("load v14 schema");
        for historical_object in &v9_schema {
            if matches!(
                historical_object.name.as_str(),
                "runner_launch_intents"
                    | "runner_session_policies"
                    | "effect_intents"
                    | "effect_observations"
                    | "task_integration_receipts"
                    | "task_integration_verification_receipts"
                    | "v9_completion_task_integration_receipts"
                    | "task_integration_worker_lease_idx"
                    | "task_integration_receipts_no_update"
                    | "task_integration_receipts_no_delete"
                    | "task_integration_receipts_terminal_fence"
                    | "worker_lease_bound_task_integration"
                    | "task_integration_verifications_no_update"
                    | "task_integration_verifications_no_delete"
                    | "task_integration_verifications_terminal_fence"
                    | "v9_completion_task_integration_no_update"
                    | "v9_completion_task_integration_no_delete"
                    | "worker_cleanup_receipts"
            ) {
                continue;
            }
            assert!(
                current_schema.contains(historical_object),
                "current schema must preserve existing v9 schema object {} byte-for-byte",
                historical_object.name
            );
        }
        let migrated_bytes = ledger
            .connection
            .query_row(
                "SELECT completion.receipt_json, application.evidence_json,
                        rollback.evidence_json
                 FROM v9_completion_receipts completion
                 JOIN application_receipts application
                   ON application.receipt_id = completion.application_receipt_id
                 JOIN rollback_references rollback
                   ON rollback.reference_id = completion.rollback_reference_id
                 WHERE completion.sprint_id = 'sprint-1'",
                [],
                |row| {
                    Ok((
                        row.get::<_, Vec<u8>>(0)?,
                        row.get::<_, Vec<u8>>(1)?,
                        row.get::<_, Vec<u8>>(2)?,
                    ))
                },
            )
            .expect("reload migrated evidence bytes");
        assert_eq!(migrated_bytes, v9_bytes);
        expected.assert_matches_pre_v24_rows(&ledger);
        drop(ledger);
        assert!(matches!(
            EventLedger::open(&database.path),
            Err(LedgerError::UnsafeV14TaskAttemptMigration {
                first_blocker: "pre-v14 worker-lease marker",
                first_authority_id,
                blocker_count: 1,
            }) if first_authority_id == "sprint-1"
        ));
        let mut ledger = reopen_test_legacy_ledger(&database);
        let version: i64 = ledger
            .connection
            .pragma_query_value(None, "user_version", |row| row.get(0))
            .expect("read unchanged schema after refused current migration");
        assert_eq!(version, 14);
        expected.assert_matches_pre_v24_rows(&ledger);
        assert!(matches!(
            ledger.append_event(&AgentEvent {
                contract_version: CONTRACT_VERSION,
                sequence: ledger.next_sequence("sprint-1").expect("sequence"),
                event_id: "event-after-v9-migration".into(),
                sprint_id: "sprint-1".into(),
                task_id: None,
                worker_id: None,
                causation_id: None,
                correlation_id: "migration-fence".into(),
                policy_hash: None,
                occurred_at_unix_ms: 2_200,
                payload: AgentEventKind::Diagnostic("must stay terminal".into()),
            }),
            Err(LedgerError::SprintAlreadyTerminal(_))
        ));
    }

    #[test]
    fn populated_v15_completion_migrates_to_v16_without_retroactive_evidence() {
        let database = TestDatabase::new();
        let expected = {
            schema_template::install_exact_database_at(15, &database.path);
            let connection = Connection::open(&database.path).expect("create v15 database");
            register_schema_functions(&connection).expect("register v15 schema functions");
            connection
                .execute_batch(
                    "PRAGMA foreign_keys = ON;
                     PRAGMA synchronous = FULL;
                     PRAGMA journal_mode = WAL;",
                )
                .expect("configure v15 database");
            let mut v15 = EventLedger {
                connection,
                database_path: database.path.clone(),
                read_only: false,
                instance_id: next_event_ledger_instance_id(),
            };
            let (report, receipt, event) = prepare_completion_evidence(&mut v15);
            let expected =
                record_pre_v24_successful_completion_for_test(&mut v15, &report, &receipt, &event)
                    .expect("record complete v15 proof");
            assert_eq!(row_count(&v15, "task_attempt_integration_admissions"), 1);
            assert_eq!(row_count(&v15, "task_integration_receipts"), 1);
            expected
        };

        let ledger = EventLedger::open(&database.path).expect("upgrade populated v15 database");
        let completion = load_migrated_pre_v24_completion(&ledger, &expected);
        let version: i64 = ledger
            .connection
            .pragma_query_value(None, "user_version", |row| row.get(0))
            .expect("read current schema version");
        assert_eq!(version, SCHEMA_VERSION);
        verify_exact_schema(&ledger.connection).expect("schema exactly matches v16");
        assert_eq!(row_count(&ledger, "task_attempt_integration_admissions"), 1);
        assert_eq!(row_count(&ledger, "task_integration_receipts"), 1);
        assert_eq!(
            ledger
                .connection
                .query_row(
                    "SELECT recorded_schema_ceiling
                     FROM pre_v16_completion_evidence_exemptions
                     WHERE sprint_id = 'sprint-1' AND completion_receipt_id = ?1",
                    [&completion.receipt.receipt_id],
                    |row| row.get::<_, i64>(0),
                )
                .expect("load immutable pre-v16 completion exemption"),
            15
        );
        assert_eq!(
            ledger
                .load_completion("sprint-1")
                .expect("load migrated completion"),
            Some(completion.clone())
        );
        assert!(
            ledger
                .connection
                .execute(
                    "UPDATE pre_v16_completion_evidence_exemptions
                     SET recorded_schema_ceiling = recorded_schema_ceiling
                     WHERE sprint_id = 'sprint-1'",
                    [],
                )
                .is_err()
        );
        assert!(
            ledger
                .connection
                .execute(
                    "DELETE FROM pre_v16_completion_evidence_exemptions
                     WHERE sprint_id = 'sprint-1'",
                    [],
                )
                .is_err()
        );
        let insert_error = ledger
            .connection
            .execute(
                "INSERT INTO pre_v16_completion_evidence_exemptions (
                     completion_receipt_id, sprint_id, recorded_schema_ceiling
                 ) VALUES (?1, 'sprint-1', 15)",
                [&completion.receipt.receipt_id],
            )
            .expect_err("runtime must not forge a pre-v16 exemption");
        assert!(
            insert_error
                .to_string()
                .contains("pre-v16 completion evidence exemptions are migration-only")
        );
    }

    #[test]
    fn v6_database_migrates_without_fabricating_terminal_outcomes() {
        let database = TestDatabase::new();
        let (spec, graph) = install_v6_planned_database(&database);
        let mut ledger = EventLedger::open(&database.path).expect("upgrade v6 ledger");
        let version: i64 = ledger
            .connection
            .pragma_query_value(None, "user_version", |row| row.get(0))
            .expect("read schema version");
        assert_eq!(version, SCHEMA_VERSION);
        verify_exact_schema(&ledger.connection).expect("schema exactly matches v7");
        assert_eq!(
            row_count(&ledger, "sprint_non_success_terminal_outcomes"),
            0
        );
        let restored = ledger.load_sprint("sprint-1").expect("load v6 sprint");
        assert_eq!(restored.spec, spec);
        assert_eq!(restored.graph, Some(graph));
        assert_eq!(restored.completion, None);
        assert_eq!(restored.terminal_outcome, None);

        let (base, _, _, _, _, _, _, _) = completion_artifacts();
        ledger
            .persist_workspace_snapshot("sprint-1", &base)
            .expect("persist the v9 terminal proof preimage");
        let outcome = record_test_terminal_outcome(
            &mut ledger,
            &terminal_evidence("terminal-after-v6", NonSuccessTerminalState::Blocked),
        )
        .expect("v9 terminal API works after additive migration");
        assert_eq!(outcome.terminal_state, SprintState::Blocked);
    }

    #[test]
    #[allow(clippy::too_many_lines)] // Migration truthfulness and all terminal fences form one case.
    fn v7_successful_mutation_migrates_to_legacy_unlinked_and_only_unknown() {
        let database = TestDatabase::new();
        let intent = install_v7_successful_mutation_database(&database);
        let mut ledger = EventLedger::open(&database.path).expect("upgrade v7 ledger");
        verify_exact_schema(&ledger.connection).expect("schema exactly matches v8");
        let restored = ledger
            .load_effect(&intent.effect_id)
            .expect("load legacy mutation");
        assert_eq!(
            restored.mutation_artifact,
            PersistedMutationArtifact::LegacyUnlinked
        );
        assert_eq!(
            restored.reconciliation(),
            EffectReconciliation::EvidenceRequired
        );
        let marker: (String, Option<String>, Option<String>, Option<Vec<u8>>) = ledger
            .connection
            .query_row(
                "SELECT link_status, result_snapshot, change_set_id, link_json
                 FROM mutation_artifact_links WHERE effect_id = ?1",
                [&intent.effect_id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .expect("read migration marker");
        assert_eq!(marker, ("LegacyUnlinked".into(), None, None, None));
        assert_eq!(row_count(&ledger, "workspace_snapshots"), 1);
        assert_eq!(row_count(&ledger, "change_sets"), 0);

        assert!(matches!(
            ledger.persist_workspace_snapshot(
                "sprint-1",
                &WorkspaceSnapshot {
                    snapshot_id: digest('c'),
                    grant_hash: digest('a'),
                    created_at_unix_ms: 1_400,
                },
            ),
            Err(LedgerError::LegacyMutationArtifactUnlinked { effect_id, .. })
                if effect_id == intent.effect_id
        ));
        assert!(matches!(
            ledger.append_event(&AgentEvent {
                contract_version: CONTRACT_VERSION,
                sequence: 3,
                event_id: "legacy-work-event".into(),
                sprint_id: "sprint-1".into(),
                task_id: None,
                worker_id: None,
                causation_id: None,
                correlation_id: "legacy-work".into(),
                policy_hash: None,
                occurred_at_unix_ms: 1_400,
                payload: AgentEventKind::Diagnostic("must be rejected".into()),
            }),
            Err(LedgerError::LegacyMutationArtifactUnlinked { .. })
        ));
        assert!(
            ledger
                .connection
                .execute(
                    "INSERT INTO workspace_snapshots (
                    sprint_id, snapshot_id, grant_hash, contract_version,
                    created_at_unix_ms, snapshot_json
                 ) VALUES ('sprint-1', ?1, ?2, ?3, 1400, X'7B7D')",
                    params![digest('c').as_str(), digest('a').as_str(), CONTRACT_VERSION],
                )
                .is_err()
        );
        assert!(
            ledger
                .connection
                .execute(
                    "INSERT INTO sprint_terminal_states (
                    sprint_id, terminal_state, completion_receipt_id,
                    completion_event_id, contract_version, terminal_at_unix_ms
                 ) VALUES ('sprint-1', 'Completed', 'missing', 'missing', ?1, 2000)",
                    [CONTRACT_VERSION],
                )
                .is_err()
        );

        for state in [
            NonSuccessTerminalState::Blocked,
            NonSuccessTerminalState::Failed,
            NonSuccessTerminalState::Canceled,
        ] {
            assert!(matches!(
                ledger.record_unsuccessful_terminal_outcome(&terminal_evidence(
                    &format!("legacy-known-{state:?}"),
                    state,
                )),
                Err(LedgerError::ReferenceMismatch {
                    entity: "sprint terminal evidence",
                    ..
                })
            ));
        }
        let terminal = ledger
            .record_unsuccessful_terminal_outcome(&terminal_evidence(
                "legacy-truthful-unknown",
                NonSuccessTerminalState::Unknown,
            ))
            .expect("legacy gap permits exactly Unknown terminalization");
        assert_eq!(terminal.terminal_state, SprintState::Unknown);
        assert_eq!(row_count(&ledger, "workspace_snapshots"), 1);
        assert_eq!(row_count(&ledger, "change_sets"), 0);

        drop(ledger);
        let reader = EventLedger::open_read_only(&database.path).expect("restart migrated ledger");
        let sprint = reader
            .load_sprint("sprint-1")
            .expect("inspect migrated sprint");
        assert_eq!(
            sprint.effects[0].mutation_artifact,
            PersistedMutationArtifact::LegacyUnlinked
        );
        assert_eq!(
            sprint
                .terminal_outcome
                .expect("Unknown terminal outcome")
                .terminal_state,
            SprintState::Unknown
        );
    }

    #[test]
    fn v8_successful_integration_migrates_to_unproven_and_only_unknown() {
        let database = TestDatabase::new();
        let intent = install_v8_successful_integration_database(&database);
        let mut ledger = EventLedger::open(&database.path).expect("upgrade v8 ledger");
        verify_exact_schema(&ledger.connection).expect("schema exactly matches v9");
        assert_eq!(row_count(&ledger, "finish_effect_kinds"), 1);
        assert_eq!(row_count(&ledger, "legacy_finish_receipt_gaps"), 1);
        let restored = ledger
            .load_effect(&intent.effect_id)
            .expect("load legacy integration");
        assert_eq!(
            restored.finish_receipt,
            PersistedFinishReceipt::LegacyTaskIntegrationUnproven
        );
        assert_eq!(
            restored.reconciliation(),
            EffectReconciliation::EvidenceRequired
        );
        assert!(matches!(
            ledger.append_event(&AgentEvent {
                contract_version: CONTRACT_VERSION,
                sequence: 3,
                event_id: "work-after-legacy-integration".into(),
                sprint_id: "sprint-1".into(),
                task_id: None,
                worker_id: None,
                causation_id: None,
                correlation_id: "legacy-integration-work".into(),
                policy_hash: None,
                occurred_at_unix_ms: 1_400,
                payload: AgentEventKind::Diagnostic("must remain fenced".into()),
            }),
            Err(LedgerError::LegacyFinishReceiptUnproven {
                effect_id,
                receipt_kind,
                ..
            }) if effect_id == intent.effect_id && receipt_kind == "TaskIntegration"
        ));
        assert!(matches!(
            ledger.persist_workspace_snapshot(
                "sprint-1",
                &WorkspaceSnapshot {
                    snapshot_id: digest('c'),
                    grant_hash: digest('a'),
                    created_at_unix_ms: 1_400,
                },
            ),
            Err(LedgerError::LegacyFinishReceiptUnproven { .. })
        ));
        assert!(
            ledger
                .connection
                .execute(
                    "INSERT INTO workspace_snapshots (
                        sprint_id, snapshot_id, grant_hash, contract_version,
                        created_at_unix_ms, snapshot_json
                     ) VALUES ('sprint-1', ?1, ?2, ?3, 1400, X'7B7D')",
                    params![digest('c').as_str(), digest('a').as_str(), CONTRACT_VERSION],
                )
                .is_err(),
            "schema must fence legacy finish gaps"
        );
        for state in [
            NonSuccessTerminalState::Blocked,
            NonSuccessTerminalState::Failed,
            NonSuccessTerminalState::Canceled,
        ] {
            assert!(matches!(
                record_test_terminal_outcome(
                    &mut ledger,
                    &terminal_evidence(&format!("legacy-finish-{state:?}"), state),
                ),
                Err(LedgerError::ReferenceMismatch {
                    entity: "sprint terminal evidence",
                    ..
                })
            ));
        }
        let terminal = ledger
            .record_unsuccessful_terminal_outcome(&terminal_evidence(
                "legacy-finish-unknown",
                NonSuccessTerminalState::Unknown,
            ))
            .expect("legacy finish gap admits exactly Unknown");
        assert_eq!(terminal.terminal_state, SprintState::Unknown);

        drop(ledger);
        let reader = EventLedger::open_read_only(&database.path).expect("restart migrated ledger");
        let sprint = reader
            .load_sprint("sprint-1")
            .expect("inspect migrated sprint");
        assert_eq!(
            sprint.effects[0].finish_receipt,
            PersistedFinishReceipt::LegacyTaskIntegrationUnproven
        );
        assert_eq!(
            sprint
                .terminal_outcome
                .expect("Unknown terminal outcome")
                .terminal_state,
            SprintState::Unknown
        );
    }

    #[test]
    fn v8_completion_migrates_as_diagnostic_not_v9_completed_authority() {
        let database = TestDatabase::new();
        let (report, receipt_bytes, event) = install_v8_completed_database(&database);
        let mut ledger = EventLedger::open(&database.path).expect("upgrade completed v8 ledger");
        verify_exact_schema(&ledger.connection).expect("schema exactly matches v9");
        assert_eq!(row_count(&ledger, "v9_completion_receipts"), 0);
        assert_eq!(row_count(&ledger, "sprint_completion_proof_states"), 1);
        let proof_state: String = ledger
            .connection
            .query_row(
                "SELECT proof_state FROM sprint_completion_proof_states
                 WHERE sprint_id = 'sprint-1'",
                [],
                |row| row.get(0),
            )
            .expect("read migrated proof state");
        assert_eq!(proof_state, "LegacyCompletionUnproven");
        assert_eq!(
            ledger.load_completion("sprint-1").expect("load completion"),
            None
        );
        let restored = ledger
            .load_sprint("sprint-1")
            .expect("load migrated sprint");
        assert_eq!(restored.completion, None);
        let legacy = restored
            .legacy_completion
            .expect("retain diagnostic legacy completion");
        assert_eq!(legacy.receipt_bytes, receipt_bytes);
        assert_eq!(legacy.receipt_digest, Digest::sha256(&receipt_bytes));
        assert_eq!(legacy.final_report, report);
        assert_eq!(legacy.event, event);
        assert!(matches!(
            ledger.append_event(&AgentEvent {
                contract_version: CONTRACT_VERSION,
                sequence: 2,
                event_id: "after-legacy-completion".into(),
                sprint_id: "sprint-1".into(),
                task_id: None,
                worker_id: None,
                causation_id: None,
                correlation_id: "after-legacy-completion".into(),
                policy_hash: None,
                occurred_at_unix_ms: 2_100,
                payload: AgentEventKind::Diagnostic("must remain terminal".into()),
            }),
            Err(LedgerError::SprintAlreadyTerminal(id)) if id == "sprint-1"
        ));
    }

    #[test]
    fn v2_database_migrates_additively_to_effect_protocol_schema() {
        let database = TestDatabase::new();
        {
            let connection = Connection::open(&database.path).expect("create v2 database");
            connection
                .execute_batch("PRAGMA journal_mode = WAL;")
                .expect("select WAL mode");
            connection
                .execute_batch(MIGRATIONS[0])
                .expect("install v1 schema");
            connection
                .execute_batch(MIGRATIONS[1])
                .expect("install v2 schema");
            connection
                .pragma_update(None, "user_version", 2_i64)
                .expect("mark v2 schema");
        }

        let mut ledger = EventLedger::open(&database.path).expect("upgrade v2 ledger");
        verify_exact_schema(&ledger.connection).expect("schema exactly matches v7");
        prepare_effect_input(&mut ledger);
        let intent = effect_intent("effect-after-v2", "key-after-v2", 1_200);
        let proposal = effect_proposal_event(&intent, 1, "event-after-v2");
        record_test_effect_intent(&mut ledger, &intent, &proposal)
            .expect("new effect protocol works after v2 upgrade");
        assert_eq!(row_count(&ledger, "effect_intents"), 1);
    }

    #[test]
    fn v4_migration_preserves_exact_graph_and_effect_evidence() {
        let database = TestDatabase::new();
        let (spec, graph, intent, observation) = install_v4_planned_effect_database(&database);
        let original_graph_json = encode("task graph", &graph).expect("encode expected graph");

        let mut ledger = EventLedger::open(&database.path).expect("upgrade v4 ledger");
        verify_exact_schema(&ledger.connection).expect("schema exactly matches v7");
        let legacy_graph_json: Vec<u8> = ledger
            .connection
            .query_row(
                "SELECT graph_json FROM sprints WHERE sprint_id = 'sprint-1'",
                [],
                |row| row.get(0),
            )
            .expect("read untouched legacy graph bytes");
        let migrated_graph_json: Vec<u8> = ledger
            .connection
            .query_row(
                "SELECT graph_json FROM sprint_task_graphs
                 WHERE sprint_id = 'sprint-1'",
                [],
                |row| row.get(0),
            )
            .expect("read additive graph record");
        assert_eq!(legacy_graph_json, original_graph_json);
        assert_eq!(migrated_graph_json, original_graph_json);

        let restored = ledger
            .load_sprint("sprint-1")
            .expect("load migrated sprint");
        assert_eq!(restored.spec, spec);
        assert_eq!(restored.graph, Some(graph));
        assert_eq!(
            restored.graph_provenance,
            TaskGraphProvenance::LegacyUnproven
        );
        let effect = ledger
            .load_effect(&intent.effect_id)
            .expect("load migrated effect");
        assert_eq!(effect.request_bytes, EFFECT_REQUEST_BYTES);
        assert_eq!(effect.observation, Some(observation));
        assert_eq!(
            effect.evidence_bytes.as_deref(),
            Some(EFFECT_EVIDENCE_BYTES)
        );
        assert_eq!(row_count(&ledger, "sprint_planning_states"), 1);
        assert_eq!(row_count(&ledger, "sprint_task_graphs"), 1);
        assert_eq!(row_count(&ledger, "sprint_graph_provenance"), 1);
        assert!(matches!(
            ledger.append_event(&event(3, "legacy-new-work", None)),
            Err(LedgerError::LegacyGraphUnproven(id)) if id == "sprint-1"
        ));
        let transaction = ledger
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .expect("start direct legacy write");
        assert!(
            insert_agent_event(&transaction, &event(3, "direct-legacy-work", None)).is_err(),
            "schema must reject work on legacy-unproven graphs"
        );
        transaction
            .rollback()
            .expect("rollback direct legacy write");
    }

    #[test]
    fn v5_graph_migrates_as_explicit_legacy_unproven_state() {
        let database = TestDatabase::new();
        let (spec, graph) = sprint_fixture();
        {
            schema_template::install_exact_database_at(5, &database.path);
            let mut connection = Connection::open(&database.path).expect("create v5 database");
            connection
                .execute_batch("PRAGMA foreign_keys = ON; PRAGMA journal_mode = WAL;")
                .expect("configure v5 database");
            let transaction = connection
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .expect("start v5 transaction");
            insert_sprint_definition(&transaction, &spec, 1_000).expect("insert v5 sprint");
            insert_sprint_planning_state(&transaction, &spec).expect("insert v5 planning state");
            insert_sprint_task_graph(&transaction, "sprint-1", &spec, &graph)
                .expect("insert v5 graph");
            transaction.commit().expect("commit v5 graph");
            connection
                .pragma_update(None, "user_version", 5_i64)
                .expect("mark v5 schema");
        }

        let mut ledger = EventLedger::open(&database.path).expect("migrate v5 to v6");
        let restored = ledger
            .load_sprint("sprint-1")
            .expect("inspect legacy graph");
        assert_eq!(restored.graph, Some(graph));
        assert_eq!(
            restored.graph_provenance,
            TaskGraphProvenance::LegacyUnproven
        );
        assert!(matches!(
            ledger.append_event(&event(1, "blocked-work", None)),
            Err(LedgerError::LegacyGraphUnproven(id)) if id == "sprint-1"
        ));
    }

    #[test]
    fn v3_effect_migration_never_fabricates_digest_preimages() {
        let database = TestDatabase::new();
        let intent = effect_intent("legacy-effect", "legacy-key", 1_200);
        let proposal = effect_proposal_event(&intent, 1, "legacy-proposal");
        {
            schema_template::install_exact_database_at(3, &database.path);
            let mut connection = Connection::open(&database.path).expect("create v3 database");
            connection
                .execute_batch("PRAGMA foreign_keys = ON; PRAGMA journal_mode = WAL;")
                .expect("configure legacy database");
            let (spec, graph) = sprint_fixture();
            let (base, _, _, _, _, _, _, _) = completion_artifacts();
            let transaction = connection
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .expect("start legacy effect transaction");
            transaction
                .execute(
                    "INSERT INTO sprints (
                        sprint_id, contract_version, spec_json, graph_json,
                        created_at_unix_ms
                     ) VALUES (?1, ?2, ?3, ?4, ?5)",
                    params![
                        spec.sprint_id,
                        i64::from(CONTRACT_VERSION),
                        encode("sprint specification", &spec).expect("encode spec"),
                        encode("task graph", &graph).expect("encode graph"),
                        1_000_i64
                    ],
                )
                .expect("insert legacy sprint");
            insert_workspace_snapshot(&transaction, "sprint-1", &base)
                .expect("insert legacy snapshot");
            insert_agent_event(&transaction, &proposal).expect("insert legacy proposal");
            insert_effect_intent(&transaction, &intent, &proposal.event_id)
                .expect("insert digest-only v3 intent");
            transaction.commit().expect("commit legacy intent");
            connection
                .pragma_update(None, "user_version", 3_i64)
                .expect("mark v3 schema");
        }

        let ledger = EventLedger::open(&database.path).expect("migrate v3 database to v4");
        let version: i64 = ledger
            .connection
            .pragma_query_value(None, "user_version", |row| row.get(0))
            .expect("read migrated version");
        assert_eq!(version, SCHEMA_VERSION);
        assert_eq!(row_count(&ledger, "legacy_effect_payload_gaps"), 1);
        assert_legacy_effect_payload_is_unreadable(&ledger);

        let backfill = ledger.connection.execute(
            "INSERT INTO effect_request_payloads (
                effect_id, sprint_id, request_digest, request_bytes,
                contract_version
             ) VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                intent.effect_id,
                intent.sprint_id,
                intent.request_digest.as_str(),
                EFFECT_REQUEST_BYTES,
                i64::from(CONTRACT_VERSION)
            ],
        );
        assert!(backfill.is_err(), "legacy preimage backfill must be fenced");
        assert_eq!(row_count(&ledger, "effect_request_payloads"), 0);
        assert!(
            ledger
                .connection
                .execute_batch(
                    "UPDATE legacy_effect_payload_gaps SET missing_request = 1;
                     DELETE FROM legacy_effect_payload_gaps;"
                )
                .is_err(),
            "legacy gap marker must remain immutable"
        );
    }

