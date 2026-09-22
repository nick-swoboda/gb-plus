    #[test]
    #[allow(clippy::too_many_lines)]
    fn final_verification_exact_success_reaches_ready_only_after_zero_survivor_cleanup() {
        let harness = Harness::new("final-verification-exact-success");
        let launches = Rc::new(Cell::new(0));
        let dispatches = Rc::new(Cell::new(0));
        let acknowledgements = Rc::new(Cell::new(0));
        let cleanups = Rc::new(Cell::new(0));
        let runner = FinalVerificationScriptRunnerLifecycle::new(
            FinalVerificationDispatchBehavior::Exact,
            Rc::clone(&launches),
            Rc::clone(&dispatches),
            Rc::clone(&acknowledgements),
            Rc::clone(&cleanups),
        );
        let mut coordinator = DurableWalkingSkeleton::open_with_runner_lifecycle(
            &harness.database,
            MutationProvider::new(Vec::new()),
            runner,
        )
        .expect("open exact final-verification coordinator");
        coordinator
            .create_draft(&harness.authority, &harness.spec, &harness.base, 1_001)
            .expect("create exact final-verification sprint");

        let status = coordinator
            .run_until_blocked(
                &harness.spec.sprint_id,
                &harness.authority,
                &harness.policy,
                &harness.shadow,
                2_000,
            )
            .expect("run exact final verification");
        let (final_snapshot, receipt_id) = match status {
            WalkingSkeletonStatus::ReadyForApplication {
                final_snapshot,
                verification_receipt_id,
            } => (final_snapshot, verification_receipt_id),
            other => panic!("unexpected exact final-verification state: {other:?}"),
        };
        assert_eq!(launches.get(), 1);
        assert_eq!(dispatches.get(), 1);
        assert_eq!(acknowledgements.get(), 1);
        assert_eq!(cleanups.get(), 1);

        let admission_id = final_verification_identity(&harness.spec.sprint_id, "admission");
        let admission = coordinator
            .ledger
            .load_sprint_final_verification_admission(&admission_id)
            .expect("load exact final-verification admission");
        assert_eq!(admission.final_snapshot, final_snapshot);
        assert_eq!(admission.command, final_verification_command());
        let evidence = coordinator
            .ledger
            .load_verification_effect_evidence(&receipt_id)
            .expect("load exact final-verification evidence");
        assert!(evidence.verification.passed());
        assert_eq!(evidence.verification.task_id, None);
        assert_eq!(evidence.verification.snapshot_id, final_snapshot);
        assert_eq!(evidence.verification.command, admission.command);
        let launch = coordinator
            .ledger
            .load_runner_launch_intent(&harness.spec.sprint_id, &admission.runner_launch_id)
            .expect("load exact final-verifier launch");
        assert_eq!(launch.purpose, RunnerSessionPurpose::FinalVerifier);
        assert!(launch.worker_id.is_none());
        assert!(launch.worker_lease.is_none());
        let sprint = coordinator
            .load_sprint(&harness.spec.sprint_id)
            .expect("load final-verification sprint");
        assert!(sprint.events.iter().any(|event| {
            event.event_id == admission.sprint_phase_event_id
                && matches!(
                    &event.payload,
                    AgentEventKind::SprintStateChanged { from, to }
                        if from == "Running" && to == "FinalVerification"
                )
        }));
        let task = &sprint.graph.as_ref().expect("attached graph").tasks[0];
        let history = coordinator
            .ledger
            .load_task_attempt_history(&harness.spec.sprint_id, &task.task_id)
            .expect("load accepted task history");
        let formal = &history
            .attempts
            .last()
            .expect("winning attempt")
            .formal_checks[0];
        let task_done = coordinator
            .ledger
            .assess_task_done(&harness.spec.sprint_id, &task.task_id)
            .expect("rederive exact TaskDone for criterion timestamp");
        let task_done_proof = task_done
            .proof
            .expect("exact TaskDone proof remains readable");
        let criterion_recorded_at = task_done_proof.integration_receipt.integrated_at_unix_ms;
        let criterion_evidence = coordinator
            .ledger
            .load_criterion_evidence_receipt_v2(&gate1_criterion_evidence_receipt_identity(
                &harness.spec.sprint_id,
                0,
            ))
            .expect("load deterministic Gate-1 criterion evidence");
        assert_eq!(criterion_evidence.criterion_id(), "fixture-ready");
        assert_eq!(criterion_evidence.snapshot_digest(), &final_snapshot);
        assert!(matches!(
            criterion_evidence,
            CriterionEvidenceReceiptV2::Verified {
                verification_receipt_id,
                recorded_at,
                ..
            } if verification_receipt_id == formal.verification_receipt.receipt_id
                && recorded_at == criterion_recorded_at
        ));
        assert!(
            formal.verification_receipt.finished_at_unix_ms <= criterion_recorded_at,
            "criterion evidence cannot predate its exact task formal verification"
        );
        assert!(
            criterion_recorded_at <= evidence.verification.finished_at_unix_ms,
            "TaskDone-bound criterion evidence must precede repository-wide final verification"
        );
        assert!(
            final_verification_cleanup_complete(&coordinator.ledger, &admission, &evidence,)
                .expect("assess exact final-verifier cleanup")
        );
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn gate1_acceptance_crash_gap_recovers_idempotently_without_rerunning_final_verification() {
        let mut harness = Harness::new("gate1-acceptance-crash-gap");
        harness.spec.acceptance_criteria =
            vec![automated_criterion("compile"), automated_criterion("tests")];
        let launches = Rc::new(Cell::new(0));
        let dispatches = Rc::new(Cell::new(0));
        let acknowledgements = Rc::new(Cell::new(0));
        let cleanups = Rc::new(Cell::new(0));
        let provider = MutationProvider::new(Vec::new());
        let runner = FinalVerificationScriptRunnerLifecycle::new(
            FinalVerificationDispatchBehavior::Exact,
            Rc::clone(&launches),
            Rc::clone(&dispatches),
            Rc::clone(&acknowledgements),
            Rc::clone(&cleanups),
        );
        let mut first = DurableWalkingSkeleton::open_with_runner_lifecycle(
            &harness.database,
            provider.clone(),
            runner,
        )
        .expect("open acceptance crash-gap coordinator");
        first
            .create_draft(&harness.authority, &harness.spec, &harness.base, 1_001)
            .expect("create acceptance crash-gap sprint");
        first.inject_acceptance_stop_after_receipts_for_test(1);
        assert!(matches!(
            first.run_until_blocked(
                &harness.spec.sprint_id,
                &harness.authority,
                &harness.policy,
                &harness.shadow,
                2_000,
            ),
            Err(DurableCoordinatorError::Protocol(ref message))
                if message == "test stop after deterministic Gate-1 acceptance receipt persistence"
        ));
        let first_receipt = first
            .ledger
            .load_criterion_evidence_receipt_v2(&gate1_criterion_evidence_receipt_identity(
                &harness.spec.sprint_id,
                0,
            ))
            .expect("first deterministic receipt survives crash gap");
        assert_eq!(first_receipt.criterion_id(), "compile");
        assert!(matches!(
            first.ledger.load_criterion_evidence_receipt_v2(
                &gate1_criterion_evidence_receipt_identity(&harness.spec.sprint_id, 1)
            ),
            Err(LedgerError::ArtifactNotFound { .. })
        ));
        drop(first);

        let restarted_runner = FinalVerificationScriptRunnerLifecycle::new(
            FinalVerificationDispatchBehavior::Exact,
            Rc::clone(&launches),
            Rc::clone(&dispatches),
            Rc::clone(&acknowledgements),
            Rc::clone(&cleanups),
        );
        let mut restarted = DurableWalkingSkeleton::open_with_runner_lifecycle(
            &harness.database,
            provider,
            restarted_runner,
        )
        .expect("reopen acceptance crash-gap coordinator");
        for now in [3_000_u64, 4_000] {
            assert!(matches!(
                restarted
                    .run_until_blocked(
                        &harness.spec.sprint_id,
                        &harness.authority,
                        &harness.policy,
                        &harness.shadow,
                        now,
                    )
                    .expect("resume exact acceptance closure"),
                WalkingSkeletonStatus::ReadyForApplication { .. }
            ));
        }
        assert_eq!(
            restarted
                .ledger
                .load_criterion_evidence_receipt_v2(&gate1_criterion_evidence_receipt_identity(
                    &harness.spec.sprint_id,
                    0,
                ))
                .expect("reload first acceptance receipt"),
            first_receipt
        );
        assert_eq!(
            restarted
                .ledger
                .load_criterion_evidence_receipt_v2(&gate1_criterion_evidence_receipt_identity(
                    &harness.spec.sprint_id,
                    1,
                ))
                .expect("load recovered second acceptance receipt")
                .criterion_id(),
            "tests"
        );
        assert_eq!(
            (
                launches.get(),
                dispatches.get(),
                acknowledgements.get(),
                cleanups.get()
            ),
            (1, 1, 1, 1),
            "acceptance recovery must not relaunch, redispatch, or repeat cleanup"
        );
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn gate1_acceptance_immutable_receipt_rejects_crossed_overwrite_before_final_cleanup() {
        let harness = Harness::new("gate1-acceptance-crossed-existing");
        let launches = Rc::new(Cell::new(0));
        let dispatches = Rc::new(Cell::new(0));
        let acknowledgements = Rc::new(Cell::new(0));
        let cleanups = Rc::new(Cell::new(0));
        let provider = MutationProvider::new(Vec::new());
        let runner = FinalVerificationScriptRunnerLifecycle::new(
            FinalVerificationDispatchBehavior::CleanupRequiredOnce,
            Rc::clone(&launches),
            Rc::clone(&dispatches),
            Rc::clone(&acknowledgements),
            Rc::clone(&cleanups),
        );
        let mut first = DurableWalkingSkeleton::open_with_runner_lifecycle(
            &harness.database,
            provider.clone(),
            runner,
        )
        .expect("open crossed-existing acceptance coordinator");
        first
            .create_draft(&harness.authority, &harness.spec, &harness.base, 1_001)
            .expect("create crossed-existing acceptance sprint");
        assert!(matches!(
            first
                .run_until_blocked(
                    &harness.spec.sprint_id,
                    &harness.authority,
                    &harness.policy,
                    &harness.shadow,
                    2_000,
                )
                .expect("stop before final cleanup proof"),
            WalkingSkeletonStatus::FinalVerificationCleanupRequired { .. }
        ));
        let sprint = first
            .load_sprint(&harness.spec.sprint_id)
            .expect("load pre-acceptance sprint");
        let task = &sprint.graph.as_ref().expect("attached graph").tasks[0];
        let history = first
            .ledger
            .load_task_attempt_history(&harness.spec.sprint_id, &task.task_id)
            .expect("load formal evidence");
        let formal = &history
            .attempts
            .last()
            .expect("winning attempt")
            .formal_checks[0];
        let final_evidence = first
            .ledger
            .load_verification_effect_evidence(&final_verification_identity(
                &harness.spec.sprint_id,
                "receipt",
            ))
            .expect("load final evidence");
        let crossed = CriterionEvidenceReceiptV2::Verified {
            receipt_id: gate1_criterion_evidence_receipt_identity(&harness.spec.sprint_id, 0),
            sprint_id: harness.spec.sprint_id.clone(),
            criterion_id: "fixture-ready".into(),
            snapshot_digest: formal.verification_receipt.snapshot_id.clone(),
            verification_receipt_id: formal.verification_receipt.receipt_id.clone(),
            recorded_at: final_evidence
                .verification
                .finished_at_unix_ms
                .checked_add(1)
                .expect("crossed criterion-evidence timestamp"),
        };
        let exact = first
            .ledger
            .load_criterion_evidence_receipt_v2(crossed.receipt_id())
            .expect("load pre-final exact criterion evidence");
        assert_ne!(exact, crossed);
        assert!(matches!(
            first
                .ledger
                .persist_verified_criterion_evidence_receipt_v2(&crossed),
            Err(LedgerError::ArtifactAlreadyExists { .. })
        ));
        drop(first);

        let restarted_runner = FinalVerificationScriptRunnerLifecycle::new(
            FinalVerificationDispatchBehavior::Exact,
            Rc::clone(&launches),
            Rc::clone(&dispatches),
            Rc::clone(&acknowledgements),
            Rc::clone(&cleanups),
        );
        let mut restarted = DurableWalkingSkeleton::open_with_runner_lifecycle(
            &harness.database,
            provider,
            restarted_runner,
        )
        .expect("reopen crossed-existing acceptance coordinator");
        assert!(matches!(
            restarted
                .run_until_blocked(
                    &harness.spec.sprint_id,
                    &harness.authority,
                    &harness.policy,
                    &harness.shadow,
                    3_000,
                )
                .expect("resume final cleanup with immutable exact criterion evidence"),
            WalkingSkeletonStatus::ReadyForApplication { .. }
        ));
        assert_eq!(
            restarted
                .ledger
                .load_criterion_evidence_receipt_v2(crossed.receipt_id())
                .expect("exact evidence remains immutable"),
            exact
        );
        assert_eq!(
            (
                launches.get(),
                dispatches.get(),
                acknowledgements.get(),
                cleanups.get()
            ),
            (1, 1, 1, 2)
        );
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "one table-driven acceptance-plan audit crosses each independently substitutable formal field while reusing one exact durable Gate-1 proof"
    )]
    fn gate1_acceptance_plan_rejects_missing_and_crossed_formal_authority() {
        let mut harness = Harness::new("gate1-acceptance-crossed-plan");
        harness.spec.acceptance_criteria =
            vec![automated_criterion("compile"), automated_criterion("tests")];
        let launches = Rc::new(Cell::new(0));
        let dispatches = Rc::new(Cell::new(0));
        let acknowledgements = Rc::new(Cell::new(0));
        let cleanups = Rc::new(Cell::new(0));
        let runner = FinalVerificationScriptRunnerLifecycle::new(
            FinalVerificationDispatchBehavior::Exact,
            launches,
            dispatches,
            acknowledgements,
            cleanups,
        );
        let mut coordinator = DurableWalkingSkeleton::open_with_runner_lifecycle(
            &harness.database,
            MutationProvider::new(Vec::new()),
            runner,
        )
        .expect("open crossed acceptance-plan coordinator");
        coordinator
            .create_draft(&harness.authority, &harness.spec, &harness.base, 1_001)
            .expect("create crossed acceptance-plan sprint");
        assert!(matches!(
            coordinator
                .run_until_blocked(
                    &harness.spec.sprint_id,
                    &harness.authority,
                    &harness.policy,
                    &harness.shadow,
                    2_000,
                )
                .expect("reach exact accepted Gate-1 boundary"),
            WalkingSkeletonStatus::ReadyForApplication { .. }
        ));

        let sprint = coordinator
            .load_sprint(&harness.spec.sprint_id)
            .expect("load accepted sprint");
        let task = sprint.graph.as_ref().expect("attached graph").tasks[0].clone();
        let task_done = coordinator
            .ledger
            .assess_task_done(&harness.spec.sprint_id, &task.task_id)
            .expect("rederive test TaskDone")
            .proof
            .expect("exact TaskDone proof");
        let history = coordinator
            .ledger
            .load_task_attempt_history(&harness.spec.sprint_id, &task.task_id)
            .expect("load exact formal checks");
        let formal_checks = history
            .attempts
            .iter()
            .find(|entry| entry.attempt == task_done.attempt)
            .expect("winning attempt")
            .formal_checks
            .clone();
        let final_snapshot = task_done.change_set.result_snapshot.clone();
        let exact = plan_gate1_criterion_evidence_receipts(
            &harness.spec,
            &task,
            &task_done,
            &formal_checks,
            &final_snapshot,
        )
        .expect("plan exact acceptance receipts");
        assert!(exact.human_criterion_ids.is_empty());
        assert_eq!(
            exact
                .verified_receipts
                .iter()
                .map(CriterionEvidenceReceiptV2::criterion_id)
                .collect::<Vec<_>>(),
            ["compile", "tests"]
        );

        let missing = plan_gate1_criterion_evidence_receipts(
            &harness.spec,
            &task,
            &task_done,
            &formal_checks[..1],
            &final_snapshot,
        )
        .expect_err("missing formal receipt must fail");
        assert!(matches!(missing, DurableCoordinatorError::Protocol(_)));

        let mut crossings = Vec::new();
        let mut criterion = formal_checks.clone();
        criterion[0].criterion_id = "crossed-criterion".into();
        crossings.push(("criterion", criterion));
        let mut receipt = formal_checks.clone();
        receipt[0].verification_receipt.receipt_id = "crossed-receipt".into();
        crossings.push(("receipt", receipt));
        let mut snapshot = formal_checks.clone();
        let crossed_snapshot = Digest::sha256(b"crossed acceptance snapshot");
        snapshot[0].sealed_snapshot = crossed_snapshot.clone();
        snapshot[0].verification_receipt.snapshot_id = crossed_snapshot;
        crossings.push(("snapshot", snapshot));
        let mut command = formal_checks.clone();
        command[0]
            .verification_receipt
            .command
            .arguments
            .push("crossed-command".into());
        crossings.push(("command", command));

        for (label, crossed) in crossings {
            let error = plan_gate1_criterion_evidence_receipts(
                &harness.spec,
                &task,
                &task_done,
                &crossed,
                &final_snapshot,
            )
            .expect_err("crossed formal authority must fail");
            assert!(
                matches!(error, DurableCoordinatorError::Protocol(_)),
                "unexpected {label} crossing result: {error}"
            );
        }

        let mut human_spec = harness.spec.clone();
        human_spec.acceptance_criteria[1] = human_criterion("tests");
        let mut human_task_done = task_done.clone();
        human_task_done.formal_check_ids.truncate(1);
        human_task_done
            .integration_receipt
            .task_verification_receipt_ids
            .truncate(1);
        let human = plan_gate1_criterion_evidence_receipts(
            &human_spec,
            &task,
            &human_task_done,
            &formal_checks[..1],
            &final_snapshot,
        )
        .expect("human criterion remains a non-writing draft");
        assert_eq!(human.task_id, task.task_id);
        assert_eq!(human.human_criterion_ids, ["tests"]);
        assert_eq!(
            human
                .verified_receipts
                .iter()
                .map(CriterionEvidenceReceiptV2::criterion_id)
                .collect::<Vec<_>>(),
            ["compile"]
        );
    }

    #[test]
    fn final_verification_terminal_retry_retains_custody_and_never_redispatches() {
        let harness = Harness::new("final-verification-terminal-retry");
        let launches = Rc::new(Cell::new(0));
        let dispatches = Rc::new(Cell::new(0));
        let acknowledgements = Rc::new(Cell::new(0));
        let cleanups = Rc::new(Cell::new(0));
        let runner = FinalVerificationScriptRunnerLifecycle::new(
            FinalVerificationDispatchBehavior::Exact,
            Rc::clone(&launches),
            Rc::clone(&dispatches),
            Rc::clone(&acknowledgements),
            Rc::clone(&cleanups),
        );
        let mut coordinator = DurableWalkingSkeleton::open_with_runner_lifecycle(
            &harness.database,
            MutationProvider::new(Vec::new()),
            runner,
        )
        .expect("open final-verification terminal-retry coordinator");
        coordinator
            .create_draft(&harness.authority, &harness.spec, &harness.base, 1_001)
            .expect("create final-verification terminal-retry sprint");
        coordinator.inject_final_terminal_precommit_failure_for_test(LedgerError::Io(
            io::Error::other("injected final-verification terminal contention"),
        ));
        assert!(matches!(
            coordinator.run_until_blocked(
                &harness.spec.sprint_id,
                &harness.authority,
                &harness.policy,
                &harness.shadow,
                2_000,
            ),
            Err(DurableCoordinatorError::Ledger(LedgerError::Io(_)))
        ));
        assert_eq!(
            (
                launches.get(),
                dispatches.get(),
                acknowledgements.get(),
                cleanups.get()
            ),
            (1, 1, 0, 0)
        );

        assert!(matches!(
            coordinator
                .run_until_blocked(
                    &harness.spec.sprint_id,
                    &harness.authority,
                    &harness.policy,
                    &harness.shadow,
                    3_000,
                )
                .expect("retry exact final-verification terminal and cleanup"),
            WalkingSkeletonStatus::ReadyForApplication { .. }
        ));
        assert_eq!(
            (
                launches.get(),
                dispatches.get(),
                acknowledgements.get(),
                cleanups.get()
            ),
            (1, 1, 1, 1)
        );
    }

    #[test]
    fn crossed_final_verification_evidence_is_reconciliation_only_after_restart() {
        let harness = Harness::new("final-verification-crossed-restart");
        let launches = Rc::new(Cell::new(0));
        let dispatches = Rc::new(Cell::new(0));
        let acknowledgements = Rc::new(Cell::new(0));
        let cleanups = Rc::new(Cell::new(0));
        let first_runner = FinalVerificationScriptRunnerLifecycle::new(
            FinalVerificationDispatchBehavior::CrossEvidence,
            Rc::clone(&launches),
            Rc::clone(&dispatches),
            Rc::clone(&acknowledgements),
            Rc::clone(&cleanups),
        );
        let mut first = DurableWalkingSkeleton::open_with_runner_lifecycle(
            &harness.database,
            MutationProvider::new(Vec::new()),
            first_runner,
        )
        .expect("open crossed final-verification coordinator");
        first
            .create_draft(&harness.authority, &harness.spec, &harness.base, 1_001)
            .expect("create crossed final-verification sprint");
        assert!(matches!(
            first.run_until_blocked(
                &harness.spec.sprint_id,
                &harness.authority,
                &harness.policy,
                &harness.shadow,
                2_000,
            ),
            Err(DurableCoordinatorError::Protocol(_) | DurableCoordinatorError::Contract(_))
        ));
        drop(first);

        let restarted_runner = FinalVerificationScriptRunnerLifecycle::new(
            FinalVerificationDispatchBehavior::Exact,
            Rc::clone(&launches),
            Rc::clone(&dispatches),
            Rc::clone(&acknowledgements),
            Rc::clone(&cleanups),
        );
        let mut restarted = DurableWalkingSkeleton::open_with_runner_lifecycle(
            &harness.database,
            MutationProvider::new(Vec::new()),
            restarted_runner,
        )
        .expect("reopen crossed final-verification coordinator");
        assert!(matches!(
            restarted
                .run_until_blocked(
                    &harness.spec.sprint_id,
                    &harness.authority,
                    &harness.policy,
                    &harness.shadow,
                    3_000,
                )
                .expect("recover claimed final verification without replay"),
            WalkingSkeletonStatus::ReconciliationRequired {
                kind: EffectKind::RunCommand,
                ..
            }
        ));
        assert_eq!(
            (
                launches.get(),
                dispatches.get(),
                acknowledgements.get(),
                cleanups.get()
            ),
            (1, 1, 0, 0)
        );
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "the transport matrix keeps first-run typed evidence and restart no-replay assertions adjacent"
    )]
    fn final_verification_transport_failures_are_typed_terminal_and_never_replayed() {
        for (label, behavior, expect_unknown, expected_evidence) in [
            (
                "zero",
                FinalVerificationDispatchBehavior::FailedBeforeEffect,
                false,
                FINAL_ZERO_FAILURE_EVIDENCE,
            ),
            (
                "partial",
                FinalVerificationDispatchBehavior::PartialWrite,
                true,
                FINAL_PARTIAL_FAILURE_EVIDENCE,
            ),
            (
                "correlated",
                FinalVerificationDispatchBehavior::CorrelatedReject,
                true,
                FINAL_CORRELATED_FAILURE_EVIDENCE,
            ),
        ] {
            let harness = Harness::new(&format!("final-verification-transport-{label}"));
            let launches = Rc::new(Cell::new(0));
            let dispatches = Rc::new(Cell::new(0));
            let acknowledgements = Rc::new(Cell::new(0));
            let cleanups = Rc::new(Cell::new(0));
            let runner = FinalVerificationScriptRunnerLifecycle::new(
                behavior,
                Rc::clone(&launches),
                Rc::clone(&dispatches),
                Rc::clone(&acknowledgements),
                Rc::clone(&cleanups),
            );
            let mut coordinator = DurableWalkingSkeleton::open_with_runner_lifecycle(
                &harness.database,
                MutationProvider::new(Vec::new()),
                runner,
            )
            .expect("open final-verification transport coordinator");
            coordinator
                .create_draft(&harness.authority, &harness.spec, &harness.base, 1_001)
                .expect("create final-verification transport sprint");
            let first_status = coordinator
                .run_until_blocked(
                    &harness.spec.sprint_id,
                    &harness.authority,
                    &harness.policy,
                    &harness.shadow,
                    2_000,
                )
                .expect("persist typed final-verification transport terminal");
            assert_eq!(
                matches!(
                    first_status,
                    WalkingSkeletonStatus::TaskEffectOutcomeUnknown { .. }
                ),
                expect_unknown
            );
            assert_eq!(
                matches!(
                    first_status,
                    WalkingSkeletonStatus::TaskEffectFailedBeforeEffect { .. }
                ),
                !expect_unknown
            );
            let effect_id = final_verification_identity(&harness.spec.sprint_id, "effect");
            assert_eq!(
                coordinator
                    .ledger
                    .load_effect(&effect_id)
                    .expect("load typed final-verification transport terminal")
                    .evidence_bytes
                    .as_deref(),
                Some(expected_evidence)
            );
            drop(coordinator);

            let restarted_runner = FinalVerificationScriptRunnerLifecycle::new(
                FinalVerificationDispatchBehavior::Exact,
                Rc::clone(&launches),
                Rc::clone(&dispatches),
                Rc::clone(&acknowledgements),
                Rc::clone(&cleanups),
            );
            let mut restarted = DurableWalkingSkeleton::open_with_runner_lifecycle(
                &harness.database,
                MutationProvider::new(Vec::new()),
                restarted_runner,
            )
            .expect("reopen typed final-verification transport coordinator");
            let recovered = restarted
                .run_until_blocked(
                    &harness.spec.sprint_id,
                    &harness.authority,
                    &harness.policy,
                    &harness.shadow,
                    3_000,
                )
                .expect("recover typed final-verification transport terminal");
            assert_eq!(
                matches!(
                    recovered,
                    WalkingSkeletonStatus::TaskEffectOutcomeUnknown { .. }
                ),
                expect_unknown
            );
            assert_eq!(
                (
                    launches.get(),
                    dispatches.get(),
                    acknowledgements.get(),
                    cleanups.get()
                ),
                (1, 1, 1, 1)
            );
        }
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "both terminal outcomes prove cleanup-only restart without final-verification redispatch"
    )]
    fn final_verification_terminal_cleanup_retries_after_restart_without_redispatch() {
        for (label, behavior, expected_outcome) in [
            (
                "failed-before-effect",
                FinalVerificationDispatchBehavior::FailedBeforeEffectCleanupRequiredOnce,
                WalkingSkeletonFinalVerificationTerminalOutcome::FailedBeforeEffect,
            ),
            (
                "unknown",
                FinalVerificationDispatchBehavior::PartialWriteCleanupRequiredOnce,
                WalkingSkeletonFinalVerificationTerminalOutcome::Unknown,
            ),
        ] {
            let harness = Harness::new(&format!("final-verification-terminal-cleanup-{label}"));
            let launches = Rc::new(Cell::new(0));
            let dispatches = Rc::new(Cell::new(0));
            let acknowledgements = Rc::new(Cell::new(0));
            let cleanups = Rc::new(Cell::new(0));
            let runner = FinalVerificationScriptRunnerLifecycle::new(
                behavior,
                Rc::clone(&launches),
                Rc::clone(&dispatches),
                Rc::clone(&acknowledgements),
                Rc::clone(&cleanups),
            );
            let mut coordinator = DurableWalkingSkeleton::open_with_runner_lifecycle(
                &harness.database,
                MutationProvider::new(Vec::new()),
                runner,
            )
            .expect("open terminal final-verification cleanup coordinator");
            coordinator
                .create_draft(&harness.authority, &harness.spec, &harness.base, 1_001)
                .expect("create terminal final-verification cleanup sprint");
            let first = coordinator
                .run_until_blocked(
                    &harness.spec.sprint_id,
                    &harness.authority,
                    &harness.policy,
                    &harness.shadow,
                    2_000,
                )
                .expect("persist terminal final-verification cleanup requirement");
            assert!(matches!(
                &first,
                WalkingSkeletonStatus::FinalVerificationTerminalCleanupRequired {
                    outcome,
                    ..
                } if *outcome == expected_outcome
            ));
            let admission_id = final_verification_identity(&harness.spec.sprint_id, "admission");
            let admission = coordinator
                .ledger
                .load_sprint_final_verification_admission(&admission_id)
                .expect("load pending terminal final-verification admission");
            let completed = coordinator
                .ledger
                .load_effect(&admission.effect_id)
                .expect("load pending terminal final-verification effect");
            let terminal_effect_id = completed.intent.effect_id.clone();
            let command_cleanup_is_already_closed = expected_outcome
                == WalkingSkeletonFinalVerificationTerminalOutcome::FailedBeforeEffect;
            assert_eq!(
                terminal_final_verification_command_domains_cleaned(
                    &coordinator.ledger,
                    &admission,
                    &completed,
                    expected_outcome,
                )
                .expect("evaluate missing terminal final-verification cleanup proof"),
                command_cleanup_is_already_closed,
                "only zero-byte FailedBefore carries atomic no-domain cleanup before final-verifier cleanup"
            );
            let bindings = coordinator
                .ledger
                .load_command_domain_effect_bindings(
                    &admission.sprint_id,
                    &admission.runner_launch_id,
                    &admission.runner_session_id,
                )
                .expect("load terminal final-verification command binding");
            let [binding] = bindings.as_slice() else {
                panic!("terminal final verification must have exactly one command binding")
            };
            let cleanup_admission = coordinator
                .ledger
                .load_runner_launch_cleanup_admission(
                    &admission.sprint_id,
                    &admission.runner_launch_id,
                )
                .expect("load terminal final-verifier cleanup admission");
            let backend = match cleanup_admission.cleanup_request.platform_backend {
                WorkerCleanupBackend::MacOsDedicatedIdentity => {
                    CommandDomainBackend::MacOsDedicatedIdentity
                }
                WorkerCleanupBackend::LinuxCgroupV2 => CommandDomainBackend::LinuxCgroupV2,
                WorkerCleanupBackend::TrustedApplierDirectChildWait => {
                    panic!("final verifier cannot use trusted-Applier cleanup authority")
                }
            };
            let crossed_platform_proof =
                format!("crossed-terminal-final-proof:{}", binding.effect_id).into_bytes();
            let crossed_proof = CommandDomainCleanupProof {
                contract_version: CONTRACT_VERSION,
                proof_id: format!("{}:crossed-command-cleanup", binding.effect_id),
                sprint_id: binding.sprint_id.clone(),
                launch_id: binding.launch_id.clone(),
                session_id: binding.session_id.clone(),
                effect_id: binding.effect_id.clone(),
                observation_id: Some(format!("{}:crossed-observation", binding.effect_id)),
                request_digest: binding.request_digest.clone(),
                backend,
                disposition: CommandDomainCleanupDisposition::ReapedZeroSurvivors,
                surviving_processes: 0,
                platform_proof_digest: Digest::sha256(&crossed_platform_proof),
                platform_proof_bytes: crossed_platform_proof,
                cleaned_at_unix_ms: completed
                    .observation
                    .as_ref()
                    .expect("terminal effect has an observation")
                    .observed_at_unix_ms
                    .saturating_add(1),
            };
            assert!(
                coordinator
                    .ledger
                    .record_command_domain_cleanup_proof(&crossed_proof)
                    .is_err(),
                "a crossed observation must never satisfy terminal command cleanup"
            );
            assert_eq!(
                terminal_final_verification_command_domains_cleaned(
                    &coordinator.ledger,
                    &admission,
                    &completed,
                    expected_outcome,
                )
                .expect("evaluate terminal cleanup after rejected crossed proof"),
                command_cleanup_is_already_closed,
                "a rejected crossed proof must not alter exact command cleanup state"
            );
            let pending_capture = coordinator
                .ledger
                .load_command_output_capture_for_effect(&terminal_effect_id)
                .expect("load pending terminal final-verification capture");
            let pending_terminal = pending_capture
                .terminal
                .as_ref()
                .expect("terminal final verification has immutable capture terminal");
            match expected_outcome {
                WalkingSkeletonFinalVerificationTerminalOutcome::FailedBeforeEffect => {
                    assert_eq!(
                        pending_terminal.disposition,
                        CommandOutputCaptureTerminalDispositionV1::Abandoned
                    );
                    assert!(pending_capture.reconciliation_resolution.is_none());
                    assert_eq!(
                        pending_capture.reconciliation_obligation_closure.as_ref(),
                        Some(&pending_terminal.terminal_anchor_digest)
                    );
                }
                WalkingSkeletonFinalVerificationTerminalOutcome::Unknown => {
                    assert_eq!(
                        pending_terminal.disposition,
                        CommandOutputCaptureTerminalDispositionV1::ReconciliationRequired
                    );
                    assert!(pending_capture.reconciliation_resolution.is_none());
                    assert!(pending_capture.reconciliation_obligation_closure.is_none());
                    let (_, store, _) = strict_fake_command_output_store(
                        &harness.authority,
                        &admission.runner_launch_id,
                    )
                    .expect("open pending strict fake command-output store");
                    let physical = store
                        .reopen_capture(&pending_capture.intent.capture_id)
                        .expect("reopen pending strict fake Unknown capture");
                    assert_eq!(
                        physical.state(),
                        CommandOutputCaptureJournalStateV1::Acquired
                    );
                    assert_eq!(
                        physical.store_head(),
                        &pending_capture
                            .acquired
                            .as_ref()
                            .expect("Unknown capture remains acquired")
                            .store_head
                    );
                }
                WalkingSkeletonFinalVerificationTerminalOutcome::SensitiveOutputRejected => {
                    unreachable!("sensitive rejection has a dedicated v29 restart fixture")
                }
            }
            assert_eq!(
                (
                    launches.get(),
                    dispatches.get(),
                    acknowledgements.get(),
                    cleanups.get()
                ),
                (1, 1, 1, 1)
            );
            drop(coordinator);

            let restarted_runner = FinalVerificationScriptRunnerLifecycle::new(
                FinalVerificationDispatchBehavior::Exact,
                Rc::clone(&launches),
                Rc::clone(&dispatches),
                Rc::clone(&acknowledgements),
                Rc::clone(&cleanups),
            );
            let mut restarted = DurableWalkingSkeleton::open_with_runner_lifecycle(
                &harness.database,
                MutationProvider::new(Vec::new()),
                restarted_runner,
            )
            .expect("reopen terminal final-verification cleanup coordinator");
            let recovered = restarted
                .run_until_blocked(
                    &harness.spec.sprint_id,
                    &harness.authority,
                    &harness.policy,
                    &harness.shadow,
                    3_000,
                )
                .expect("complete terminal final-verification cleanup after restart");
            match expected_outcome {
                WalkingSkeletonFinalVerificationTerminalOutcome::FailedBeforeEffect => {
                    assert!(matches!(
                        recovered,
                        WalkingSkeletonStatus::TaskEffectFailedBeforeEffect { .. }
                    ));
                    let closed_capture = restarted
                        .ledger
                        .load_command_output_capture_for_effect(&terminal_effect_id)
                        .expect("load closed FailedBefore final-verification capture");
                    let terminal = closed_capture
                        .terminal
                        .as_ref()
                        .expect("FailedBefore capture retains immutable terminal");
                    assert_eq!(
                        terminal.disposition,
                        CommandOutputCaptureTerminalDispositionV1::Abandoned
                    );
                    assert!(closed_capture.reconciliation_resolution.is_none());
                    assert_eq!(
                        closed_capture.reconciliation_obligation_closure.as_ref(),
                        Some(&terminal.terminal_anchor_digest)
                    );
                }
                WalkingSkeletonFinalVerificationTerminalOutcome::Unknown => {
                    assert!(matches!(
                        recovered,
                        WalkingSkeletonStatus::TaskEffectOutcomeUnknown { .. }
                    ));
                    let resolved_capture = restarted
                        .ledger
                        .load_command_output_capture_for_effect(&terminal_effect_id)
                        .expect("load resolved terminal final-verification capture");
                    let terminal = resolved_capture
                        .terminal
                        .as_ref()
                        .expect("resolved Unknown retains immutable terminal");
                    let resolution = resolved_capture
                        .reconciliation_resolution
                        .as_ref()
                        .expect("resolved Unknown carries exact reconciliation resolution");
                    assert_eq!(
                        resolution.disposition,
                        CommandOutputCaptureTerminalDispositionV1::Abandoned
                    );
                    assert_eq!(
                        resolution.terminal_anchor_digest,
                        terminal.terminal_anchor_digest
                    );
                    assert_eq!(
                        resolved_capture.reconciliation_obligation_closure.as_ref(),
                        Some(&terminal.terminal_anchor_digest)
                    );
                    let (_, store, _) = strict_fake_command_output_store(
                        &harness.authority,
                        &admission.runner_launch_id,
                    )
                    .expect("open resolved strict fake command-output store");
                    let physical = store
                        .reopen_capture(&resolved_capture.intent.capture_id)
                        .expect("reopen resolved strict fake Unknown capture");
                    assert_eq!(
                        physical.state(),
                        CommandOutputCaptureJournalStateV1::Cleaned
                    );
                    assert_eq!(physical.store_head(), &resolution.store_head);
                    assert_eq!(
                        physical.cleaned_record_digest(),
                        Some(&resolution.resolution_record_digest)
                    );
                }
                WalkingSkeletonFinalVerificationTerminalOutcome::SensitiveOutputRejected => {
                    unreachable!("sensitive rejection has a dedicated v29 restart fixture")
                }
            }
            assert_eq!(
                (
                    launches.get(),
                    dispatches.get(),
                    acknowledgements.get(),
                    cleanups.get()
                ),
                (1, 1, 1, 2)
            );
        }
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "the focused crash-cut regression keeps exact v1/v2 prelaunch custody, Core resolution, restart closure, and no-redispatch assertions adjacent"
    )]
    fn writer_attached_prelaunch_unknown_converges_to_abandoned_without_redispatch() {
        let harness = Harness::new("writer-attached-prelaunch-unknown");
        let launches = Rc::new(Cell::new(0));
        let dispatches = Rc::new(Cell::new(0));
        let acknowledgements = Rc::new(Cell::new(0));
        let cleanups = Rc::new(Cell::new(0));
        let provider = MutationProvider::new(Vec::new());
        let runner = FinalVerificationScriptRunnerLifecycle::new(
            FinalVerificationDispatchBehavior::WriterAttachedPartialWriteCleanupRequiredOnce,
            Rc::clone(&launches),
            Rc::clone(&dispatches),
            Rc::clone(&acknowledgements),
            Rc::clone(&cleanups),
        );
        let mut first = DurableWalkingSkeleton::open_with_runner_lifecycle(
            &harness.database,
            provider.clone(),
            runner,
        )
        .expect("open writer-attached prelaunch coordinator");
        first
            .create_draft(&harness.authority, &harness.spec, &harness.base, 1_001)
            .expect("create writer-attached prelaunch sprint");
        assert!(matches!(
            first
                .run_until_blocked(
                    &harness.spec.sprint_id,
                    &harness.authority,
                    &harness.policy,
                    &harness.shadow,
                    2_000,
                )
                .expect("persist writer-attached prelaunch cleanup handoff"),
            WalkingSkeletonStatus::FinalVerificationTerminalCleanupRequired {
                outcome: WalkingSkeletonFinalVerificationTerminalOutcome::Unknown,
                ..
            }
        ));

        let admission_id = final_verification_identity(&harness.spec.sprint_id, "admission");
        let admission = first
            .ledger
            .load_sprint_final_verification_admission(&admission_id)
            .expect("load writer-attached final-verification admission");
        let pending_capture = first
            .ledger
            .load_command_output_capture_for_effect(&admission.effect_id)
            .expect("load pending writer-attached Core capture");
        assert!(pending_capture.reconciliation_resolution.is_none());
        assert!(pending_capture.reconciliation_obligation_closure.is_none());
        let acquired = pending_capture
            .acquired
            .as_ref()
            .expect("writer-attached Core capture retains exact acquisition");
        let (_, store, _) =
            strict_fake_command_output_store(&harness.authority, &admission.runner_launch_id)
                .expect("open writer-attached strict-fake output store");
        let pending_v1 = store
            .reopen_capture(&pending_capture.intent.capture_id)
            .expect("reopen pending writer-attached v1 capture");
        let pending_v2 = store
            .reopen_optional_sensitive_output_journal_v2_diagnostic(
                &pending_capture.intent.capture_id,
            )
            .expect("diagnostically reopen pending writer-attached v2 capture")
            .expect("writer-attached current-policy capture retains v2 custody");
        let grok_build_runner::SensitiveOutputJournalStageV2::WriterAttached {
            writer_attached_store_head,
        } = pending_v2.stage()
        else {
            panic!("prelaunch crash cut must stop at exact v2 WriterAttached")
        };
        assert_eq!(pending_v2.head().generation, 3);
        assert_eq!(pending_v2.acquired(), Some(acquired));
        assert!(pending_v2.launch_intended_store_head().is_none());
        assert_eq!(
            pending_v1.state(),
            CommandOutputCaptureJournalStateV1::WriterAttached
        );
        assert_eq!(pending_v1.store_head(), writer_attached_store_head);
        assert_eq!(
            pending_v1.writer_attached_store_head(),
            Some(writer_attached_store_head)
        );
        assert!(pending_v1.launch_intended_store_head().is_none());
        let provider_calls_before_restart = provider.turn_calls();
        drop(first);

        let restarted_runner = FinalVerificationScriptRunnerLifecycle::new(
            FinalVerificationDispatchBehavior::Exact,
            Rc::clone(&launches),
            Rc::clone(&dispatches),
            Rc::clone(&acknowledgements),
            Rc::clone(&cleanups),
        );
        let mut restarted = DurableWalkingSkeleton::open_with_runner_lifecycle(
            &harness.database,
            provider.clone(),
            restarted_runner,
        )
        .expect("reopen writer-attached prelaunch coordinator");
        assert!(matches!(
            restarted
                .run_until_blocked(
                    &harness.spec.sprint_id,
                    &harness.authority,
                    &harness.policy,
                    &harness.shadow,
                    3_000,
                )
                .expect("resolve writer-attached prelaunch capture after restart"),
            WalkingSkeletonStatus::TaskEffectOutcomeUnknown { .. }
        ));

        let resolved = restarted
            .ledger
            .load_command_output_capture_for_effect(&admission.effect_id)
            .expect("load resolved writer-attached Core capture");
        let terminal = resolved
            .terminal
            .as_ref()
            .expect("resolved writer-attached capture retains immutable Unknown terminal");
        let resolution = resolved
            .reconciliation_resolution
            .as_ref()
            .expect("writer-attached capture persists exact Core resolution");
        assert_eq!(
            resolution.disposition,
            CommandOutputCaptureTerminalDispositionV1::Abandoned
        );
        assert_eq!(
            resolution.terminal_anchor_digest,
            terminal.terminal_anchor_digest
        );
        assert!(resolution.artifact_reference.is_none());
        assert_eq!(
            resolved.reconciliation_obligation_closure.as_ref(),
            Some(&terminal.terminal_anchor_digest)
        );
        assert!(matches!(
            restarted
                .ledger
                .load_command_output_clean_scan_resolution_receipt_for_effect(&admission.effect_id),
            Err(LedgerError::ArtifactNotFound { .. })
        ));
        let resolved_v1 = store
            .reopen_capture(&resolved.intent.capture_id)
            .expect("reopen resolved writer-attached v1 capture");
        let resolved_v2 = store
            .reopen_optional_sensitive_output_journal_v2_diagnostic(&resolved.intent.capture_id)
            .expect("diagnostically reopen resolved writer-attached v2 capture")
            .expect("resolved current-policy capture retains immutable v2 prefix");
        assert_eq!(
            resolved_v1.state(),
            CommandOutputCaptureJournalStateV1::Cleaned
        );
        assert_eq!(resolved_v1.store_head(), &resolution.store_head);
        assert_eq!(
            resolved_v1.cleaned_record_digest(),
            Some(&resolution.resolution_record_digest)
        );
        assert_eq!(resolved_v2.head().generation, 3);
        assert_eq!(resolved_v2.stage(), pending_v2.stage());
        assert!(resolved_v2.launch_intended_store_head().is_none());
        assert_eq!(provider.turn_calls(), provider_calls_before_restart);
        assert_eq!(
            (
                launches.get(),
                dispatches.get(),
                acknowledgements.get(),
                cleanups.get()
            ),
            (1, 1, 1, 2),
            "restart may clean and resolve only; it must not relaunch or redispatch"
        );
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "one restart scenario proves v29 final-verification cleanup, receipt absence, exact readback, and no redispatch"
    )]
    fn sensitive_final_verification_restart_uses_v29_cleanup_without_receipt_or_redispatch() {
        let harness = Harness::new("sensitive-final-verification-v29");
        let launches = Rc::new(Cell::new(0));
        let dispatches = Rc::new(Cell::new(0));
        let acknowledgements = Rc::new(Cell::new(0));
        let cleanups = Rc::new(Cell::new(0));
        let runner = FinalVerificationScriptRunnerLifecycle::new(
            FinalVerificationDispatchBehavior::SensitiveOutputRejectedCleanupRequiredOnce,
            Rc::clone(&launches),
            Rc::clone(&dispatches),
            Rc::clone(&acknowledgements),
            Rc::clone(&cleanups),
        );
        let mut first = DurableWalkingSkeleton::open_with_runner_lifecycle(
            &harness.database,
            MutationProvider::new(Vec::new()),
            runner,
        )
        .expect("open sensitive final-verification coordinator");
        first
            .create_draft(&harness.authority, &harness.spec, &harness.base, 1_001)
            .expect("create sensitive final-verification sprint");
        assert!(matches!(
            first
                .run_until_blocked(
                    &harness.spec.sprint_id,
                    &harness.authority,
                    &harness.policy,
                    &harness.shadow,
                    2_000,
                )
                .expect("persist sensitive final-verification terminal cleanup requirement"),
            WalkingSkeletonStatus::FinalVerificationTerminalCleanupRequired {
                outcome: WalkingSkeletonFinalVerificationTerminalOutcome::SensitiveOutputRejected,
                ..
            }
        ));

        let admission_id = final_verification_identity(&harness.spec.sprint_id, "admission");
        let admission = first
            .ledger
            .load_sprint_final_verification_admission(&admission_id)
            .expect("load sensitive final-verification admission");
        let completed = first
            .ledger
            .load_effect(&admission.effect_id)
            .expect("load sensitive final-verification effect");
        assert!(matches!(
            completed.observation.as_ref().map(|value| &value.outcome),
            Some(EffectOutcome::FailedAfterKnownEffect { .. })
        ));
        first
            .ledger
            .load_command_output_sensitive_rejection_for_effect(&admission.effect_id)
            .expect("load authoritative final-verification v29 rejection");
        let command_cleanup = first
            .ledger
            .load_command_domain_cleanup_proof(&admission.effect_id)
            .expect("load sensitive final-verification zero-survivor proof");
        assert_eq!(
            command_cleanup.proof.disposition,
            CommandDomainCleanupDisposition::ReapedZeroSurvivors
        );
        assert_eq!(command_cleanup.proof.surviving_processes, 0);
        let receipt_id = final_verification_identity(&harness.spec.sprint_id, "receipt");
        assert!(matches!(
            first.ledger.load_verification_receipt(&receipt_id),
            Err(LedgerError::ArtifactNotFound { .. })
        ));
        assert_eq!(
            (
                launches.get(),
                dispatches.get(),
                acknowledgements.get(),
                cleanups.get()
            ),
            (1, 1, 1, 1)
        );
        drop(first);

        let restarted_runner = FinalVerificationScriptRunnerLifecycle::new(
            FinalVerificationDispatchBehavior::Exact,
            Rc::clone(&launches),
            Rc::clone(&dispatches),
            Rc::clone(&acknowledgements),
            Rc::clone(&cleanups),
        );
        let mut restarted = DurableWalkingSkeleton::open_with_runner_lifecycle(
            &harness.database,
            MutationProvider::new(Vec::new()),
            restarted_runner,
        )
        .expect("reopen sensitive final-verification coordinator");
        assert!(matches!(
            restarted
                .run_until_blocked(
                    &harness.spec.sprint_id,
                    &harness.authority,
                    &harness.policy,
                    &harness.shadow,
                    3_000,
                )
                .expect("complete sensitive final-verification cleanup after restart"),
            WalkingSkeletonStatus::SensitiveOutputRejected { .. }
        ));
        assert_eq!(
            (
                launches.get(),
                dispatches.get(),
                acknowledgements.get(),
                cleanups.get()
            ),
            (1, 1, 1, 2)
        );
        restarted
            .ledger
            .load_command_output_sensitive_rejection_for_effect(&admission.effect_id)
            .expect("read back authoritative final-verification v29 rejection after cleanup");
        assert!(matches!(
            restarted.ledger.load_verification_receipt(&receipt_id),
            Err(LedgerError::ArtifactNotFound { .. })
        ));
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "the regression keeps the failed claim, physical fence, immediate successor, and final durable resolution assertions adjacent"
    )]
    fn strict_fake_unknown_resolution_precommit_failure_releases_for_fenced_retry() {
        let harness = Harness::new("strict-fake-unknown-resolution-precommit-retry");
        let launches = Rc::new(Cell::new(0));
        let dispatches = Rc::new(Cell::new(0));
        let acknowledgements = Rc::new(Cell::new(0));
        let cleanups = Rc::new(Cell::new(0));
        let runner = FinalVerificationScriptRunnerLifecycle::new(
            FinalVerificationDispatchBehavior::PartialWriteCleanupRequiredOnce,
            Rc::clone(&launches),
            Rc::clone(&dispatches),
            Rc::clone(&acknowledgements),
            Rc::clone(&cleanups),
        );
        let mut coordinator = DurableWalkingSkeleton::open_with_runner_lifecycle(
            &harness.database,
            MutationProvider::new(Vec::new()),
            runner,
        )
        .expect("open strict-fake Unknown precommit retry coordinator");
        coordinator
            .create_draft(&harness.authority, &harness.spec, &harness.base, 1_001)
            .expect("create strict-fake Unknown precommit retry sprint");
        assert!(matches!(
            coordinator
                .run_until_blocked(
                    &harness.spec.sprint_id,
                    &harness.authority,
                    &harness.policy,
                    &harness.shadow,
                    2_000,
                )
                .expect("persist strict-fake Unknown cleanup requirement"),
            WalkingSkeletonStatus::FinalVerificationTerminalCleanupRequired {
                outcome: WalkingSkeletonFinalVerificationTerminalOutcome::Unknown,
                ..
            }
        ));

        let admission_id = final_verification_identity(&harness.spec.sprint_id, "admission");
        let admission = coordinator
            .ledger
            .load_sprint_final_verification_admission(&admission_id)
            .expect("load strict-fake Unknown final-verification admission");
        let effect_id = admission.effect_id.clone();
        arm_strict_fake_unknown_resolution_precommit_failure();
        let failure = coordinator
            .run_until_blocked(
                &harness.spec.sprint_id,
                &harness.authority,
                &harness.policy,
                &harness.shadow,
                3_000,
            )
            .expect_err("injected post-fence precommit failure must escape after claim release");
        assert!(failure.to_string().contains(
            "injected strict-fake Unknown resolution failure after physical fencing and before core commit"
        ));
        let pending = coordinator
            .ledger
            .load_command_output_capture_for_effect(&effect_id)
            .expect("load strict-fake Unknown capture after precommit failure");
        assert!(pending.reconciliation_resolution.is_none());
        assert!(pending.reconciliation_obligation_closure.is_none());

        let retried = coordinator
            .run_until_blocked(
                &harness.spec.sprint_id,
                &harness.authority,
                &harness.policy,
                &harness.shadow,
                4_000,
            )
            .expect("released strict-fake claim permits an immediate retry");
        assert!(matches!(
            retried,
            WalkingSkeletonStatus::TaskEffectOutcomeUnknown { .. }
        ));

        let observations = take_strict_fake_unknown_resolution_observations();
        let [(first_claim, first_physical), (retry_claim, retry_physical)] =
            observations.as_slice()
        else {
            panic!(
                "strict-fake Unknown retry must produce exactly two fenced observations: {observations:?}"
            );
        };
        assert_eq!(first_claim.claim_epoch, 1);
        assert_eq!(retry_claim.claim_epoch, first_claim.claim_epoch + 1);
        assert_eq!(
            retry_claim.previous_claim_id.as_deref(),
            Some(first_claim.claim_id.as_str())
        );
        assert_ne!(retry_claim.claim_id, first_claim.claim_id);
        assert_ne!(retry_claim.fencing_token, first_claim.fencing_token);
        assert_eq!(&first_physical.reconciliation_claim, first_claim);
        assert_eq!(&retry_physical.reconciliation_claim, retry_claim);
        assert_eq!(first_physical.physical_fence_chain_length, 1);
        assert_eq!(first_physical.predecessor_fence_digest, None);
        assert_eq!(retry_physical.physical_fence_chain_length, 2);
        assert_eq!(
            retry_physical.predecessor_fence_digest.as_ref(),
            Some(&first_physical.physical_fence_digest)
        );

        let resolved = coordinator
            .ledger
            .load_command_output_capture_for_effect(&effect_id)
            .expect("load resolved strict-fake Unknown capture after retry");
        let resolution = resolved
            .reconciliation_resolution
            .as_ref()
            .expect("immediate retry persists the exact Unknown resolution");
        assert_eq!(resolution.reconciliation_claim_id, retry_claim.claim_id);
        assert_eq!(
            resolution.reconciliation_fencing_token,
            retry_claim.fencing_token
        );
        assert_eq!(
            resolved.reconciliation_obligation_closure.as_ref(),
            resolved
                .terminal
                .as_ref()
                .map(|terminal| &terminal.terminal_anchor_digest)
        );
        assert_eq!(
            (
                launches.get(),
                dispatches.get(),
                acknowledgements.get(),
                cleanups.get()
            ),
            (1, 1, 1, 3),
            "precommit recovery must neither relaunch nor redispatch the final verifier"
        );
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "the regression keeps current-policy clean terminal custody, successor Core fencing, exact clean-scan resolution, and no-replay assertions adjacent"
    )]
    fn clean_v2_unknown_resolution_precommit_failure_uses_successor_claim_without_replay() {
        let harness = Harness::new("clean-v2-unknown-resolution-precommit-successor");
        let provider = MutationProvider::new(vec![ProviderToolIntent::RunCommand {
            command: fixture_acceptance_command(),
        }]);
        let dispatches = Rc::new(Cell::new(0));
        let runner = ScriptedRunnerLifecycle::new(
            ScriptedDispatchBehavior::SuccessfulCommandUnknownAfterDispatch,
            Rc::clone(&dispatches),
        );
        let mut coordinator = DurableWalkingSkeleton::open_with_runner_lifecycle(
            &harness.database,
            provider.clone(),
            runner,
        )
        .expect("open clean-v2 Unknown successor-claim coordinator");
        coordinator
            .create_draft(&harness.authority, &harness.spec, &harness.base, 1_001)
            .expect("create clean-v2 Unknown successor-claim sprint");

        arm_strict_fake_unknown_resolution_precommit_failure();
        let failure = coordinator
            .run_until_blocked(
                &harness.spec.sprint_id,
                &harness.authority,
                &harness.policy,
                &harness.shadow,
                2_000,
            )
            .expect_err("post-physical clean-v2 failure must escape after Core claim release");
        assert!(failure.to_string().contains(
            "injected strict-fake Unknown resolution failure after physical fencing and before core commit"
        ));
        assert_eq!(dispatches.get(), 1);
        assert_eq!(provider.turn_calls(), 1);
        let pending_sprint = coordinator
            .load_sprint(&harness.spec.sprint_id)
            .expect("load clean-v2 Unknown sprint after precommit failure");
        let effect_id = pending_sprint
            .effects
            .iter()
            .find(|effect| effect.intent.kind == EffectKind::RunCommand)
            .expect("clean-v2 Unknown retains its exact command effect")
            .intent
            .effect_id
            .clone();
        let pending = coordinator
            .ledger
            .load_command_output_capture_for_effect(&effect_id)
            .expect("load clean-v2 capture after precommit failure");
        assert!(pending.reconciliation_resolution.is_none());
        assert!(pending.reconciliation_obligation_closure.is_none());

        let retried = coordinator
            .run_until_blocked(
                &harness.spec.sprint_id,
                &harness.authority,
                &harness.policy,
                &harness.shadow,
                4_000,
            )
            .expect("successor Core claim closes already-terminal clean-v2 custody");
        assert!(
            matches!(&retried, WalkingSkeletonStatus::SprintUnknown { .. }),
            "successor-claim handoff returned {retried:?}"
        );
        let observations = take_strict_fake_unknown_resolution_observations();
        let [(first_claim, first_physical), (retry_claim, retry_physical)] =
            observations.as_slice()
        else {
            panic!(
                "clean-v2 Unknown retry must produce exactly two fenced observations: {observations:?}"
            );
        };
        assert_eq!(first_claim.claim_epoch, 1);
        assert_eq!(retry_claim.claim_epoch, first_claim.claim_epoch + 1);
        assert_eq!(
            retry_claim.previous_claim_id.as_deref(),
            Some(first_claim.claim_id.as_str())
        );
        assert_ne!(retry_claim.claim_id, first_claim.claim_id);
        assert_ne!(retry_claim.fencing_token, first_claim.fencing_token);
        assert_eq!(&first_physical.reconciliation_claim, first_claim);
        assert_eq!(&retry_physical.reconciliation_claim, retry_claim);
        assert_eq!(
            first_physical.resolution_action,
            CommandOutputCapturePhysicalResolutionActionV1::TerminalReadback
        );
        assert_eq!(
            retry_physical.resolution_action,
            CommandOutputCapturePhysicalResolutionActionV1::TerminalReadback
        );
        assert_eq!(
            first_physical.final_state,
            CommandOutputCaptureRestartStateV1::TerminalPrepared
        );
        assert_eq!(
            retry_physical.final_state,
            CommandOutputCaptureRestartStateV1::TerminalPrepared
        );
        assert_eq!(
            first_physical.final_store_head,
            retry_physical.final_store_head
        );
        assert_eq!(first_physical.physical_fence_chain_length, 1);
        assert_eq!(retry_physical.physical_fence_chain_length, 2);
        assert_eq!(
            retry_physical.predecessor_fence_digest.as_ref(),
            Some(&first_physical.physical_fence_digest)
        );

        let resolved = coordinator
            .ledger
            .load_command_output_capture_for_effect(&effect_id)
            .expect("load successor-claim clean-v2 resolution");
        let terminal = resolved
            .terminal
            .as_ref()
            .expect("clean-v2 Unknown retains its immutable Core terminal");
        let resolution = resolved
            .reconciliation_resolution
            .as_ref()
            .expect("successor claim persists exact clean-v2 resolution");
        assert_eq!(
            resolution.disposition,
            CommandOutputCaptureTerminalDispositionV1::Published
        );
        assert_eq!(resolution.reconciliation_claim_id, retry_claim.claim_id);
        assert_eq!(
            resolution.reconciliation_fencing_token,
            retry_claim.fencing_token
        );
        assert_eq!(
            resolved.reconciliation_obligation_closure.as_ref(),
            Some(&terminal.terminal_anchor_digest)
        );
        let clean_resolution = coordinator
            .ledger
            .load_command_output_clean_scan_resolution_receipt_for_effect(&effect_id)
            .expect("load successor-claim clean-scan resolution receipt");
        assert_eq!(clean_resolution.intent, resolved.intent);
        assert_eq!(
            &clean_resolution.acquired,
            resolved
                .acquired
                .as_ref()
                .expect("clean-v2 resolution retains acquisition")
        );
        assert_eq!(&clean_resolution.unknown_terminal, terminal);
        assert_eq!(&clean_resolution.resolution, resolution);
        assert_eq!(dispatches.get(), 1);
        assert_eq!(provider.turn_calls(), 1);
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "passing cleanup retry and known nonzero cleanup share one restart-stability audit"
    )]
    fn final_verification_cleanup_and_known_failure_are_restart_stable_without_rerun() {
        for (label, behavior, expect_failed) in [
            (
                "cleanup-retry",
                FinalVerificationDispatchBehavior::CleanupRequiredOnce,
                false,
            ),
            (
                "known-nonzero",
                FinalVerificationDispatchBehavior::NonzeroExit,
                true,
            ),
        ] {
            let harness = Harness::new(&format!("final-verification-{label}"));
            let launches = Rc::new(Cell::new(0));
            let dispatches = Rc::new(Cell::new(0));
            let acknowledgements = Rc::new(Cell::new(0));
            let cleanups = Rc::new(Cell::new(0));
            let runner = FinalVerificationScriptRunnerLifecycle::new(
                behavior,
                Rc::clone(&launches),
                Rc::clone(&dispatches),
                Rc::clone(&acknowledgements),
                Rc::clone(&cleanups),
            );
            let mut first = DurableWalkingSkeleton::open_with_runner_lifecycle(
                &harness.database,
                MutationProvider::new(Vec::new()),
                runner,
            )
            .expect("open final-verification cleanup/failure coordinator");
            first
                .create_draft(&harness.authority, &harness.spec, &harness.base, 1_001)
                .expect("create final-verification cleanup/failure sprint");
            let first_status = first
                .run_until_blocked(
                    &harness.spec.sprint_id,
                    &harness.authority,
                    &harness.policy,
                    &harness.shadow,
                    2_000,
                )
                .expect("run final-verification cleanup/failure case");
            if expect_failed {
                assert!(matches!(
                    first_status,
                    WalkingSkeletonStatus::FinalVerificationFailed {
                        termination: CommandTerminationV1::Exited { code: 17 },
                        ..
                    }
                ));
                assert_eq!(cleanups.get(), 1, "known failure must still clean");
            } else {
                assert!(matches!(
                    first_status,
                    WalkingSkeletonStatus::FinalVerificationCleanupRequired { .. }
                ));
                assert_eq!(cleanups.get(), 1);
            }
            drop(first);

            let restarted_runner = FinalVerificationScriptRunnerLifecycle::new(
                FinalVerificationDispatchBehavior::Exact,
                Rc::clone(&launches),
                Rc::clone(&dispatches),
                Rc::clone(&acknowledgements),
                Rc::clone(&cleanups),
            );
            let mut restarted = DurableWalkingSkeleton::open_with_runner_lifecycle(
                &harness.database,
                MutationProvider::new(Vec::new()),
                restarted_runner,
            )
            .expect("reopen final-verification cleanup/failure coordinator");
            let recovered = restarted
                .run_until_blocked(
                    &harness.spec.sprint_id,
                    &harness.authority,
                    &harness.policy,
                    &harness.shadow,
                    3_000,
                )
                .expect("recover final-verification cleanup/failure case");
            if expect_failed {
                assert!(matches!(
                    recovered,
                    WalkingSkeletonStatus::FinalVerificationFailed {
                        termination: CommandTerminationV1::Exited { code: 17 },
                        ..
                    }
                ));
                assert_eq!(cleanups.get(), 1, "completed cleanup is not repeated");
                let sprint = restarted
                    .load_sprint(&harness.spec.sprint_id)
                    .expect("load restart-stable known final-verification failure");
                assert!(
                    sprint.terminal_outcome.is_none(),
                    "this tranche exposes a non-resumable pre-Gate1 blocker without inventing a sprint-failure terminal"
                );
            } else {
                assert!(matches!(
                    recovered,
                    WalkingSkeletonStatus::ReadyForApplication { .. }
                ));
                assert_eq!(cleanups.get(), 2);
            }
            assert_eq!(
                (launches.get(), dispatches.get(), acknowledgements.get()),
                (1, 1, 1)
            );
        }
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "one restart audit proves cleanup retention, exact closure evidence, and replay non-authority"
    )]
    fn final_verifier_launch_without_phase_admission_is_closed_cleanup_only_after_restart() {
        let harness = Harness::new("final-verifier-launch-before-admission");
        let launches = Rc::new(Cell::new(0));
        let dispatches = Rc::new(Cell::new(0));
        let acknowledgements = Rc::new(Cell::new(0));
        let cleanups = Rc::new(Cell::new(0));
        let runner = FinalVerificationScriptRunnerLifecycle::new(
            FinalVerificationDispatchBehavior::LaunchThenError,
            Rc::clone(&launches),
            Rc::clone(&dispatches),
            Rc::clone(&acknowledgements),
            Rc::clone(&cleanups),
        );
        let mut first = DurableWalkingSkeleton::open_with_runner_lifecycle(
            &harness.database,
            MutationProvider::new(Vec::new()),
            runner,
        )
        .expect("open launch-before-admission coordinator");
        first
            .create_draft(&harness.authority, &harness.spec, &harness.base, 1_001)
            .expect("create launch-before-admission sprint");
        assert!(matches!(
            first.run_until_blocked(
                &harness.spec.sprint_id,
                &harness.authority,
                &harness.policy,
                &harness.shadow,
                2_000,
            ),
            Err(DurableCoordinatorError::Protocol(_))
        ));
        assert_eq!((launches.get(), dispatches.get()), (1, 0));

        let expected_launch_id = final_verification_identity(&harness.spec.sprint_id, "launch");
        let expected_session_id = final_verification_identity(&harness.spec.sprint_id, "session");
        let expected_admission_id =
            final_verification_identity(&harness.spec.sprint_id, "admission");
        let open_cleanup = first
            .ledger
            .load_runner_launch_cleanup_admission(&harness.spec.sprint_id, &expected_launch_id)
            .expect("load exact open unadmitted final-verifier cleanup");
        let persisted = first
            .ledger
            .load_sprint(&harness.spec.sprint_id)
            .expect("load launch-before-phase sprint");
        let task_id = &persisted
            .graph
            .as_ref()
            .expect("launch-before-phase sprint has its exact graph")
            .tasks[0]
            .task_id;
        let final_snapshot = first
            .ledger
            .assess_task_done(&harness.spec.sprint_id, task_id)
            .expect("rederive launch-before-phase TaskDone")
            .proof
            .expect("launch-before-phase has exact TaskDone")
            .integration_receipt
            .result_snapshot;
        let expected_cleanup_effect_id = open_cleanup.cleanup_effect.intent.effect_id.clone();
        assert_eq!(open_cleanup.launch.launch_id, expected_launch_id);
        assert_eq!(open_cleanup.launch.session_id, expected_session_id);
        assert_eq!(open_cleanup.cleanup_request.launch_id, expected_launch_id);
        assert_eq!(open_cleanup.cleanup_request.session_id, expected_session_id);
        assert_eq!(
            open_cleanup.cleanup_effect.intent.kind,
            EffectKind::CleanupWorkerDomain
        );
        assert_eq!(
            open_cleanup.cleanup_effect.intent.input_snapshot,
            final_snapshot
        );
        assert!(open_cleanup.cleanup_effect.dispatch_claim.is_none());
        assert!(open_cleanup.cleanup_effect.observation.is_none());
        assert!(open_cleanup.cleanup_effect.evidence_bytes.is_none());
        assert!(open_cleanup.cleanup_effect.terminal_event.is_none());
        assert_eq!(
            open_cleanup.cleanup_effect.finish_receipt,
            PersistedFinishReceipt::NotRequired
        );

        let assert_no_phase_or_completion = |ledger: &EventLedger| {
            assert!(matches!(
                ledger.load_sprint_final_verification_admission(&expected_admission_id),
                Err(LedgerError::ArtifactNotFound { .. })
            ));
            assert!(
                ledger
                    .load_command_domain_effect_bindings(
                        &harness.spec.sprint_id,
                        &expected_launch_id,
                        &expected_session_id,
                    )
                    .expect("load absent unadmitted final-verifier command bindings")
                    .is_empty()
            );
            let sprint = ledger
                .load_sprint(&harness.spec.sprint_id)
                .expect("load nonterminal unadmitted final-verifier sprint");
            assert!(sprint.completion.is_none());
            assert!(sprint.terminal_outcome.is_none());
            assert!(sprint.events.iter().all(|event| !matches!(
                event.payload,
                AgentEventKind::CompletionRecorded(_)
                    | AgentEventKind::SprintTerminalRecorded { .. }
            )));
        };
        assert_no_phase_or_completion(&first.ledger);
        drop(first);

        let pending_runner = FinalVerificationScriptRunnerLifecycle::new(
            FinalVerificationDispatchBehavior::CleanupRequiredOnce,
            Rc::clone(&launches),
            Rc::clone(&dispatches),
            Rc::clone(&acknowledgements),
            Rc::clone(&cleanups),
        );
        let mut pending = DurableWalkingSkeleton::open_with_runner_lifecycle(
            &harness.database,
            MutationProvider::new(Vec::new()),
            pending_runner,
        )
        .expect("reopen launch-before-admission coordinator with retained cleanup custody");
        assert_eq!(
            pending
                .run_until_blocked(
                    &harness.spec.sprint_id,
                    &harness.authority,
                    &harness.policy,
                    &harness.shadow,
                    3_000,
                )
                .expect("retain unadmitted final-verifier cleanup custody"),
            WalkingSkeletonStatus::FinalVerifierLaunchCleanupRequired {
                launch_id: expected_launch_id.clone(),
                reason: "test unadmitted final-verifier cleanup handoff remains pending".into(),
            }
        );
        assert_eq!(
            (
                launches.get(),
                dispatches.get(),
                acknowledgements.get(),
                cleanups.get()
            ),
            (1, 0, 0, 1)
        );
        assert_eq!(
            pending
                .ledger
                .load_effect(&expected_cleanup_effect_id)
                .expect("load still-open retained final-verifier cleanup effect"),
            open_cleanup.cleanup_effect
        );
        assert_no_phase_or_completion(&pending.ledger);
        drop(pending);

        let cleanup_runner = FinalVerificationScriptRunnerLifecycle::new(
            FinalVerificationDispatchBehavior::Exact,
            Rc::clone(&launches),
            Rc::clone(&dispatches),
            Rc::clone(&acknowledgements),
            Rc::clone(&cleanups),
        );
        let mut cleaned = DurableWalkingSkeleton::open_with_runner_lifecycle(
            &harness.database,
            MutationProvider::new(Vec::new()),
            cleanup_runner,
        )
        .expect("reopen launch-before-admission coordinator with exact cleanup custody");
        let expected_closed_status =
            WalkingSkeletonStatus::FinalVerifierLaunchCleanedWithoutPhase {
                launch_id: expected_launch_id.clone(),
                cleanup_effect_id: expected_cleanup_effect_id.clone(),
            };
        assert_eq!(
            cleaned
                .run_until_blocked(
                    &harness.spec.sprint_id,
                    &harness.authority,
                    &harness.policy,
                    &harness.shadow,
                    4_000,
                )
                .expect("close final-verifier launch without phase admission"),
            expected_closed_status
        );
        assert_eq!(
            (
                launches.get(),
                dispatches.get(),
                acknowledgements.get(),
                cleanups.get()
            ),
            (1, 0, 0, 2),
            "cleanup retry must neither relaunch nor dispatch final verification"
        );
        let closed_cleanup = cleaned
            .ledger
            .load_runner_launch_cleanup_admission(&harness.spec.sprint_id, &expected_launch_id)
            .expect("load closed unadmitted final-verifier cleanup");
        assert_eq!(closed_cleanup.launch, open_cleanup.launch);
        assert_eq!(closed_cleanup.cleanup_request, open_cleanup.cleanup_request);
        assert_eq!(
            closed_cleanup.cleanup_effect.intent,
            open_cleanup.cleanup_effect.intent
        );
        assert_eq!(
            closed_cleanup.cleanup_effect.request_bytes,
            open_cleanup.cleanup_effect.request_bytes
        );
        assert_eq!(
            closed_cleanup.cleanup_effect.proposed_event,
            open_cleanup.cleanup_effect.proposed_event
        );
        let completed = cleaned
            .ledger
            .load_effect(&expected_cleanup_effect_id)
            .expect("load exact completed unadmitted final-verifier cleanup effect");
        assert_eq!(completed, closed_cleanup.cleanup_effect);
        assert!(completed.dispatch_claim.is_none());
        let observation = completed
            .observation
            .as_ref()
            .expect("closed cleanup has exact successful observation");
        let PersistedFinishReceipt::WorkerCleanup(evidence) = &completed.finish_receipt else {
            panic!("closed cleanup must retain typed zero-survivor evidence")
        };
        evidence
            .validate()
            .expect("validate exact unadmitted final-verifier cleanup evidence");
        assert_eq!(evidence.receipt.sprint_id, harness.spec.sprint_id);
        assert_eq!(evidence.receipt.launch_id, expected_launch_id);
        assert_eq!(evidence.receipt.session_id, expected_session_id);
        assert_eq!(evidence.receipt.effect_id, expected_cleanup_effect_id);
        assert_eq!(evidence.receipt.observation_id, observation.observation_id);
        assert_eq!(evidence.receipt.worker_lease, None);
        assert_eq!(evidence.receipt.surviving_processes, 0);
        assert_eq!(
            evidence.receipt.platform_backend,
            closed_cleanup.cleanup_request.platform_backend
        );
        assert_eq!(
            Digest::sha256(&evidence.os_evidence_bytes),
            evidence.receipt.os_evidence_digest
        );
        let canonical_evidence =
            serde_json::to_vec(evidence).expect("encode exact cleanup evidence");
        assert_eq!(
            observation.outcome,
            EffectOutcome::Succeeded {
                evidence_digest: Digest::sha256(&canonical_evidence),
            }
        );
        assert_eq!(
            completed.evidence_bytes.as_deref(),
            Some(canonical_evidence.as_slice())
        );
        assert!(matches!(
            completed
                .terminal_event
                .as_ref()
                .map(|event| &event.payload),
            Some(AgentEventKind::ToolFinished {
                tool_call_id,
                succeeded: true,
            }) if tool_call_id == &completed.intent.idempotency_key
        ));
        assert_no_phase_or_completion(&cleaned.ledger);
        drop(cleaned);

        let replay_runner = FinalVerificationScriptRunnerLifecycle::new(
            FinalVerificationDispatchBehavior::Exact,
            Rc::clone(&launches),
            Rc::clone(&dispatches),
            Rc::clone(&acknowledgements),
            Rc::clone(&cleanups),
        );
        let mut replayed = DurableWalkingSkeleton::open_with_runner_lifecycle(
            &harness.database,
            MutationProvider::new(Vec::new()),
            replay_runner,
        )
        .expect("reopen closed unadmitted final-verifier cleanup");
        assert_eq!(
            replayed
                .run_until_blocked(
                    &harness.spec.sprint_id,
                    &harness.authority,
                    &harness.policy,
                    &harness.shadow,
                    5_000,
                )
                .expect("read back closed unadmitted final-verifier cleanup"),
            WalkingSkeletonStatus::FinalVerifierLaunchCleanedWithoutPhase {
                launch_id: expected_launch_id.clone(),
                cleanup_effect_id: expected_cleanup_effect_id,
            }
        );
        assert_eq!(
            (
                launches.get(),
                dispatches.get(),
                acknowledgements.get(),
                cleanups.get()
            ),
            (1, 0, 0, 2),
            "closed restart readback never relaunches, dispatches, acknowledges, or repeats cleanup"
        );
        assert_eq!(
            replayed
                .ledger
                .load_runner_launch_cleanup_admission(
                    &harness.spec.sprint_id,
                    &closed_cleanup.launch.launch_id,
                )
                .expect("replay exact closed cleanup admission"),
            closed_cleanup
        );
        assert_no_phase_or_completion(&replayed.ledger);
    }

    #[test]
    fn unadmitted_final_verifier_false_completed_without_durable_terminal_is_rejected() {
        let harness = Harness::new("unadmitted-final-verifier-false-completed");
        let launches = Rc::new(Cell::new(0));
        let dispatches = Rc::new(Cell::new(0));
        let acknowledgements = Rc::new(Cell::new(0));
        let cleanups = Rc::new(Cell::new(0));
        let runner = FinalVerificationScriptRunnerLifecycle::new(
            FinalVerificationDispatchBehavior::LaunchThenError,
            Rc::clone(&launches),
            Rc::clone(&dispatches),
            Rc::clone(&acknowledgements),
            Rc::clone(&cleanups),
        );
        let mut first = DurableWalkingSkeleton::open_with_runner_lifecycle(
            &harness.database,
            MutationProvider::new(Vec::new()),
            runner,
        )
        .expect("open false-completed unadmitted cleanup fixture");
        first
            .create_draft(&harness.authority, &harness.spec, &harness.base, 1_001)
            .expect("create false-completed unadmitted cleanup sprint");
        assert!(matches!(
            first.run_until_blocked(
                &harness.spec.sprint_id,
                &harness.authority,
                &harness.policy,
                &harness.shadow,
                2_000,
            ),
            Err(DurableCoordinatorError::Protocol(_))
        ));
        let launch_id = final_verification_identity(&harness.spec.sprint_id, "launch");
        let phase_admission_id = final_verification_identity(&harness.spec.sprint_id, "admission");
        let open_cleanup = first
            .ledger
            .load_runner_launch_cleanup_admission(&harness.spec.sprint_id, &launch_id)
            .expect("load open false-completed cleanup admission");
        drop(first);

        let false_completed_runner = FinalVerificationScriptRunnerLifecycle::new(
            FinalVerificationDispatchBehavior::UnadmittedFalseCompleted,
            Rc::clone(&launches),
            Rc::clone(&dispatches),
            Rc::clone(&acknowledgements),
            Rc::clone(&cleanups),
        );
        let mut restarted = DurableWalkingSkeleton::open_with_runner_lifecycle(
            &harness.database,
            MutationProvider::new(Vec::new()),
            false_completed_runner,
        )
        .expect("reopen false-completed unadmitted cleanup fixture");
        assert!(matches!(
            restarted.run_until_blocked(
                &harness.spec.sprint_id,
                &harness.authority,
                &harness.policy,
                &harness.shadow,
                3_000,
            ),
            Err(DurableCoordinatorError::Protocol(detail))
                if detail
                    == "unadmitted final-verifier cleanup returned without exact durable zero-survivor readback"
        ));
        assert_eq!(
            (
                launches.get(),
                dispatches.get(),
                acknowledgements.get(),
                cleanups.get()
            ),
            (1, 0, 0, 1),
            "a false Completed claim must not mint launch, dispatch, acknowledgement, or cleanup authority"
        );
        assert_eq!(
            restarted
                .ledger
                .load_runner_launch_cleanup_admission(&harness.spec.sprint_id, &launch_id)
                .expect("read back unchanged open cleanup after false Completed"),
            open_cleanup
        );
        assert!(matches!(
            restarted
                .ledger
                .load_sprint_final_verification_admission(&phase_admission_id),
            Err(LedgerError::ArtifactNotFound { .. })
        ));
        let sprint = restarted
            .ledger
            .load_sprint(&harness.spec.sprint_id)
            .expect("load nonterminal sprint after false Completed rejection");
        assert!(sprint.completion.is_none());
        assert!(sprint.terminal_outcome.is_none());
    }

    #[test]
    fn integration_terminal_retry_retains_custody_and_never_redispatches() {
        let harness = Harness::new("integration-terminal-retry-custody");
        let provider = MutationProvider::new(Vec::new());
        let preparations = Rc::new(Cell::new(0));
        let dispatches = Rc::new(Cell::new(0));
        let acknowledgements = Rc::new(Cell::new(0));
        let cleanups = Rc::new(Cell::new(0));
        let runner = IntegrationScriptRunnerLifecycle::new(
            IntegrationDispatchBehavior::Exact,
            Rc::clone(&preparations),
            Rc::clone(&dispatches),
            Rc::clone(&acknowledgements),
            Rc::clone(&cleanups),
        );
        let mut coordinator =
            DurableWalkingSkeleton::open_with_runner_lifecycle(&harness.database, provider, runner)
                .expect("open integration retry coordinator");
        coordinator
            .create_draft(&harness.authority, &harness.spec, &harness.base, 1_001)
            .expect("create integration retry sprint");
        coordinator.inject_integration_terminal_precommit_failure_for_test(LedgerError::Io(
            io::Error::other("injected integration terminal precommit contention"),
        ));
        assert!(matches!(
            coordinator.run_until_blocked(
                &harness.spec.sprint_id,
                &harness.authority,
                &harness.policy,
                &harness.shadow,
                2_000,
            ),
            Err(DurableCoordinatorError::Ledger(LedgerError::Io(_)))
        ));
        assert_eq!(preparations.get(), 1);
        assert_eq!(dispatches.get(), 1);
        assert_eq!(acknowledgements.get(), 0);
        assert_eq!(cleanups.get(), 0);

        assert!(matches!(
            coordinator
                .run_until_blocked(
                    &harness.spec.sprint_id,
                    &harness.authority,
                    &harness.policy,
                    &harness.shadow,
                    3_000,
                )
                .expect("retry exact integration terminal then finish cleanup"),
            WalkingSkeletonStatus::ReadyForApplication { .. }
        ));
        assert_eq!(preparations.get(), 1);
        assert_eq!(dispatches.get(), 1);
        assert_eq!(acknowledgements.get(), 1);
        assert_eq!(cleanups.get(), 1);
    }

    #[test]
    fn crossed_integration_evidence_recovers_without_prepare_or_redispatch() {
        let harness = Harness::new("integration-crossed-recovery-no-redispatch");
        let provider = MutationProvider::new(Vec::new());
        let preparations = Rc::new(Cell::new(0));
        let dispatches = Rc::new(Cell::new(0));
        let acknowledgements = Rc::new(Cell::new(0));
        let cleanups = Rc::new(Cell::new(0));
        let runner = IntegrationScriptRunnerLifecycle::new(
            IntegrationDispatchBehavior::CrossEvidence,
            Rc::clone(&preparations),
            Rc::clone(&dispatches),
            Rc::clone(&acknowledgements),
            Rc::clone(&cleanups),
        );
        let mut first = DurableWalkingSkeleton::open_with_runner_lifecycle(
            &harness.database,
            provider.clone(),
            runner,
        )
        .expect("open crossed integration coordinator");
        first
            .create_draft(&harness.authority, &harness.spec, &harness.base, 1_001)
            .expect("create crossed integration sprint");
        assert!(matches!(
            first.run_until_blocked(
                &harness.spec.sprint_id,
                &harness.authority,
                &harness.policy,
                &harness.shadow,
                2_000,
            ),
            Err(DurableCoordinatorError::Contract(_) | DurableCoordinatorError::Protocol(_))
        ));
        assert_eq!(preparations.get(), 1);
        assert_eq!(dispatches.get(), 1);
        assert_eq!(acknowledgements.get(), 0);
        drop(first);

        let restarted_runner = IntegrationScriptRunnerLifecycle::new(
            IntegrationDispatchBehavior::Exact,
            Rc::clone(&preparations),
            Rc::clone(&dispatches),
            Rc::clone(&acknowledgements),
            Rc::clone(&cleanups),
        );
        let mut restarted = DurableWalkingSkeleton::open_with_runner_lifecycle(
            &harness.database,
            provider,
            restarted_runner,
        )
        .expect("reopen crossed integration coordinator");
        assert!(matches!(
            restarted
                .run_until_blocked(
                    &harness.spec.sprint_id,
                    &harness.authority,
                    &harness.policy,
                    &harness.shadow,
                    3_000,
                )
                .expect("recovered claimed Candidate remains reconciliation-only"),
            WalkingSkeletonStatus::ReconciliationRequired {
                kind: EffectKind::IntegrateChangeSet,
                ..
            }
        ));
        assert_eq!(preparations.get(), 1);
        assert_eq!(dispatches.get(), 1);
        assert_eq!(acknowledgements.get(), 0);
        assert_eq!(cleanups.get(), 0);
    }

    #[test]
    fn integration_transport_failures_are_terminal_and_never_cleanup_or_replay() {
        for (label, behavior, expect_unknown, expected_evidence) in [
            (
                "zero",
                IntegrationDispatchBehavior::FailedBeforeEffect,
                false,
                INTEGRATION_ZERO_FAILURE_EVIDENCE,
            ),
            (
                "partial",
                IntegrationDispatchBehavior::PartialWrite,
                true,
                INTEGRATION_PARTIAL_FAILURE_EVIDENCE,
            ),
            (
                "correlated",
                IntegrationDispatchBehavior::CorrelatedReject,
                true,
                INTEGRATION_CORRELATED_FAILURE_EVIDENCE,
            ),
        ] {
            let harness = Harness::new(&format!("integration-transport-{label}"));
            let provider = MutationProvider::new(Vec::new());
            let preparations = Rc::new(Cell::new(0));
            let dispatches = Rc::new(Cell::new(0));
            let acknowledgements = Rc::new(Cell::new(0));
            let cleanups = Rc::new(Cell::new(0));
            let runner = IntegrationScriptRunnerLifecycle::new(
                behavior,
                Rc::clone(&preparations),
                Rc::clone(&dispatches),
                Rc::clone(&acknowledgements),
                Rc::clone(&cleanups),
            );
            let mut coordinator = DurableWalkingSkeleton::open_with_runner_lifecycle(
                &harness.database,
                provider,
                runner,
            )
            .expect("open integration transport coordinator");
            coordinator
                .create_draft(&harness.authority, &harness.spec, &harness.base, 1_001)
                .expect("create integration transport sprint");
            let status = coordinator
                .run_until_blocked(
                    &harness.spec.sprint_id,
                    &harness.authority,
                    &harness.policy,
                    &harness.shadow,
                    2_000,
                )
                .expect("persist claimed integration transport terminal");
            assert_eq!(
                matches!(
                    status,
                    WalkingSkeletonStatus::TaskEffectOutcomeUnknown { .. }
                ),
                expect_unknown
            );
            if !expect_unknown {
                assert!(matches!(
                    status,
                    WalkingSkeletonStatus::TaskEffectFailedBeforeEffect { .. }
                ));
            }
            assert_eq!(preparations.get(), 1);
            assert_eq!(dispatches.get(), 1);
            assert_eq!(acknowledgements.get(), 1);
            assert_eq!(cleanups.get(), 0);
            let sprint = coordinator
                .load_sprint(&harness.spec.sprint_id)
                .expect("load integration transport evidence");
            let integration = sprint
                .effects
                .iter()
                .find(|effect| effect.intent.kind == EffectKind::IntegrateChangeSet)
                .expect("integration effect exists");
            assert_eq!(
                integration.evidence_bytes.as_deref(),
                Some(expected_evidence)
            );
            let repeated = coordinator
                .run_until_blocked(
                    &harness.spec.sprint_id,
                    &harness.authority,
                    &harness.policy,
                    &harness.shadow,
                    3_000,
                )
                .expect("recovered integration terminal remains non-replayable");
            assert_eq!(
                matches!(
                    repeated,
                    WalkingSkeletonStatus::TaskEffectOutcomeUnknown { .. }
                ),
                expect_unknown
            );
            assert_eq!(preparations.get(), 1);
            assert_eq!(dispatches.get(), 1);
            assert_eq!(cleanups.get(), 0);
        }
    }

    #[test]
    fn integrated_cleanup_gate_recovers_without_integration_redispatch_then_proves_task_done() {
        let harness = Harness::new("integrated-cleanup-recovery-task-done");
        let provider = MutationProvider::new(Vec::new());
        let preparations = Rc::new(Cell::new(0));
        let dispatches = Rc::new(Cell::new(0));
        let acknowledgements = Rc::new(Cell::new(0));
        let cleanups = Rc::new(Cell::new(0));
        let runner = IntegrationScriptRunnerLifecycle::new(
            IntegrationDispatchBehavior::CleanupRequiredOnce,
            Rc::clone(&preparations),
            Rc::clone(&dispatches),
            Rc::clone(&acknowledgements),
            Rc::clone(&cleanups),
        );
        let mut first = DurableWalkingSkeleton::open_with_runner_lifecycle(
            &harness.database,
            provider.clone(),
            runner,
        )
        .expect("open cleanup-gated integration coordinator");
        first
            .create_draft(&harness.authority, &harness.spec, &harness.base, 1_001)
            .expect("create cleanup-gated integration sprint");
        assert!(matches!(
            first
                .run_until_blocked(
                    &harness.spec.sprint_id,
                    &harness.authority,
                    &harness.policy,
                    &harness.shadow,
                    2_000,
                )
                .expect("integration succeeds but cleanup truthfully remains pending"),
            WalkingSkeletonStatus::TaskIntegratedCleanupRequired { .. }
        ));
        assert_eq!(preparations.get(), 1);
        assert_eq!(dispatches.get(), 1);
        assert_eq!(acknowledgements.get(), 1);
        assert_eq!(cleanups.get(), 1);
        let sprint = first
            .load_sprint(&harness.spec.sprint_id)
            .expect("load cleanup-gated Integrated sprint");
        let task = &sprint.graph.as_ref().expect("attached graph").tasks[0];
        let pending = first
            .ledger
            .assess_task_done(&harness.spec.sprint_id, &task.task_id)
            .expect("assess cleanup-gated TaskDone");
        assert!(!pending.is_done());
        drop(first);

        let restarted_runner = IntegrationScriptRunnerLifecycle::new(
            IntegrationDispatchBehavior::Exact,
            Rc::clone(&preparations),
            Rc::clone(&dispatches),
            Rc::clone(&acknowledgements),
            Rc::clone(&cleanups),
        );
        let mut restarted = DurableWalkingSkeleton::open_with_runner_lifecycle(
            &harness.database,
            provider,
            restarted_runner,
        )
        .expect("reopen cleanup-gated integration coordinator");
        assert!(matches!(
            restarted
                .run_until_blocked(
                    &harness.spec.sprint_id,
                    &harness.authority,
                    &harness.policy,
                    &harness.shadow,
                    3_000,
                )
                .expect("recovered Integrated state closes cleanup and lease"),
            WalkingSkeletonStatus::ReadyForApplication { .. }
        ));
        assert_eq!(preparations.get(), 1);
        assert_eq!(dispatches.get(), 1);
        assert_eq!(acknowledgements.get(), 1);
        assert_eq!(cleanups.get(), 2);
        let sprint = restarted
            .load_sprint(&harness.spec.sprint_id)
            .expect("load recovered TaskDone sprint");
        let task = &sprint.graph.as_ref().expect("attached graph").tasks[0];
        assert!(
            restarted
                .ledger
                .assess_task_done(&harness.spec.sprint_id, &task.task_id)
                .expect("recompute recovered TaskDone")
                .is_done()
        );
    }

    #[test]
    fn recovered_running_attempt_never_mints_a_formal_admission() {
        let mut harness = Harness::new("formal-recovered-running-no-remint");
        harness.spec.acceptance_criteria = vec![automated_criterion("only")];
        let provider = MutationProvider::new(Vec::new());
        let mut first = DurableWalkingSkeleton::open_with_runner_lifecycle(
            &harness.database,
            provider.clone(),
            PersistRunningThenStopLifecycle {
                strict: StrictFakeRunnerLifecycle,
            },
        )
        .expect("open Running-boundary stop coordinator");
        first
            .create_draft(&harness.authority, &harness.spec, &harness.base, 1_001)
            .expect("create recovered-Running sprint");
        assert!(matches!(
            first.run_until_blocked(
                &harness.spec.sprint_id,
                &harness.authority,
                &harness.policy,
                &harness.shadow,
                2_000,
            ),
            Err(DurableCoordinatorError::Protocol(ref message))
                if message == "test stop after the exact Running boundary became durable"
        ));
        let first_sprint = first
            .load_sprint(&harness.spec.sprint_id)
            .expect("load durable Running sprint");
        let task = &first_sprint.graph.as_ref().expect("attached graph").tasks[0];
        assert_eq!(
            first
                .ledger
                .load_task_attempt_history(&harness.spec.sprint_id, &task.task_id)
                .expect("load durable Running history")
                .task_state,
            TaskState::Running
        );
        drop(first);

        let mut restarted = DurableWalkingSkeleton::open_with_runner_lifecycle(
            &harness.database,
            provider,
            RecoveryOnlyNoLiveHandleLifecycle,
        )
        .expect("reopen recovered-Running coordinator without a live handle");
        let recovered_status = restarted
            .run_until_blocked(
                &harness.spec.sprint_id,
                &harness.authority,
                &harness.policy,
                &harness.shadow,
                3_000,
            )
            .expect("recovered Running stops before recreating its missing provider turn");
        assert!(
            matches!(
                recovered_status,
                WalkingSkeletonStatus::TaskPhaseReconciliationRequired {
                    phase: "RunningProviderTurn",
                    ..
                }
            ),
            "unexpected recovered status: {recovered_status:?}"
        );
        let recovered = restarted
            .load_sprint(&harness.spec.sprint_id)
            .expect("load recovery-only Running sprint");
        let task = &recovered.graph.as_ref().expect("attached graph").tasks[0];
        let history = restarted
            .ledger
            .load_task_attempt_history(&harness.spec.sprint_id, &task.task_id)
            .expect("load recovery-only Running history");
        assert_eq!(history.task_state, TaskState::Running);
        assert!(
            history
                .active_attempt()
                .expect("active recovered attempt")
                .formal_checks
                .is_empty()
        );
        assert!(
            recovered
                .effects
                .iter()
                .all(|effect| { !effect.intent.idempotency_key.contains("criterion-0000") })
        );
    }

    #[test]
    fn failed_formal_check_blocks_later_declared_checks_and_candidate() {
        let mut harness = Harness::new("formal-failure-blocks");
        harness.spec.acceptance_criteria = vec![
            automated_criterion("first"),
            automated_criterion("second"),
            automated_criterion("third"),
        ];
        let provider = MutationProvider::new(Vec::new());
        let order = Rc::new(RefCell::new(Vec::new()));
        let acknowledgements = Rc::new(Cell::new(0));
        let runner = FormalScriptRunnerLifecycle::new(
            FormalDispatchBehavior::FailOrdinal(1),
            Rc::clone(&order),
            Rc::clone(&acknowledgements),
        );
        let mut coordinator =
            DurableWalkingSkeleton::open_with_runner_lifecycle(&harness.database, provider, runner)
                .expect("open failing formal coordinator");
        coordinator
            .create_draft(&harness.authority, &harness.spec, &harness.base, 1_001)
            .expect("create failing formal sprint");

        let status = coordinator
            .run_until_blocked(
                &harness.spec.sprint_id,
                &harness.authority,
                &harness.policy,
                &harness.shadow,
                2_000,
            )
            .expect("record known failed formal check");
        assert!(matches!(
            status,
            WalkingSkeletonStatus::FormalCheckFailed {
                ref criterion_id,
                termination: CommandTerminationV1::Exited { code: 1 },
                ..
            } if criterion_id == "second"
        ));
        assert_eq!(order.borrow().as_slice(), ["first", "second"]);
        assert_eq!(acknowledgements.get(), 2);
        let sprint = coordinator
            .load_sprint(&harness.spec.sprint_id)
            .expect("load failed formal sprint");
        let task = &sprint.graph.as_ref().expect("attached graph").tasks[0];
        let history = coordinator
            .ledger
            .load_task_attempt_history(&harness.spec.sprint_id, &task.task_id)
            .expect("load failed formal history");
        assert_eq!(history.task_state, TaskState::Verifying);
        let active = history.active_attempt().expect("active Verifying attempt");
        assert_eq!(active.formal_checks.len(), 2);
        assert!(active.candidate_boundary.is_none());
        assert!(sprint.effects.iter().all(|effect| {
            effect
                .intent
                .idempotency_key
                .find("criterion-0002")
                .is_none()
        }));
    }
