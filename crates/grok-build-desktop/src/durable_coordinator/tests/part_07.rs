    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "one restart scenario proves formal rejection, attempt disposal, cleanup, receipt absence, and no redispatch"
    )]
    fn sensitive_formal_check_stops_without_verification_receipt_or_restart_dispatch() {
        let mut harness = Harness::new("sensitive-formal-check-v29");
        harness.spec.acceptance_criteria = vec![automated_criterion("sensitive")];
        let provider = MutationProvider::new(Vec::new());
        let order = Rc::new(RefCell::new(Vec::new()));
        let acknowledgements = Rc::new(Cell::new(0));
        let runner = FormalScriptRunnerLifecycle::new(
            FormalDispatchBehavior::SensitiveOutputRejected,
            Rc::clone(&order),
            Rc::clone(&acknowledgements),
        );
        let first_cleanup_count = runner.sensitive_cleanup_count();
        let mut first = DurableWalkingSkeleton::open_with_runner_lifecycle(
            &harness.database,
            provider.clone(),
            runner,
        )
        .expect("open sensitive formal coordinator");
        first
            .create_draft(&harness.authority, &harness.spec, &harness.base, 1_001)
            .expect("create sensitive formal sprint");
        let status = first
            .run_until_blocked(
                &harness.spec.sprint_id,
                &harness.authority,
                &harness.policy,
                &harness.shadow,
                2_000,
            )
            .expect("persist sensitive formal rejection");
        assert!(matches!(
            status,
            WalkingSkeletonStatus::TaskAttemptsExhausted { .. }
        ));
        assert_eq!(order.borrow().as_slice(), ["sensitive"]);
        assert_eq!(acknowledgements.get(), 1);
        assert_eq!(first_cleanup_count.get(), 1);
        let sprint = first
            .load_sprint(&harness.spec.sprint_id)
            .expect("load sensitive formal sprint");
        let task = &sprint.graph.as_ref().expect("attached graph").tasks[0];
        let history = first
            .ledger
            .load_task_attempt_history(&harness.spec.sprint_id, &task.task_id)
            .expect("load sensitive formal history");
        assert_eq!(history.task_state, TaskState::Failed);
        assert!(history.active_attempt().is_none());
        let attempt = history.attempts.last().expect("disposed sensitive attempt");
        let effect_id = formal_check_identity(
            &harness.spec.sprint_id,
            &attempt.attempt.attempt_id,
            0,
            "effect",
        );
        let receipt_id = formal_check_identity(
            &harness.spec.sprint_id,
            &attempt.attempt.attempt_id,
            0,
            "receipt",
        );
        let check_id = formal_check_identity(
            &harness.spec.sprint_id,
            &attempt.attempt.attempt_id,
            0,
            "check",
        );
        assert!(attempt.formal_checks.is_empty());
        assert_eq!(
            attempt
                .disposition
                .as_ref()
                .and_then(sensitive_output_disposition_effect_id),
            Some(effect_id.as_str())
        );
        assert!(matches!(
            first.ledger.load_verification_receipt(&receipt_id),
            Err(LedgerError::ArtifactNotFound { .. })
        ));
        assert!(matches!(
            first.ledger.load_task_attempt_formal_check(&check_id),
            Err(LedgerError::ArtifactNotFound { .. })
        ));
        let completed = first
            .ledger
            .load_effect(&effect_id)
            .expect("load sensitive formal effect");
        assert!(matches!(
            completed.observation.as_ref().map(|value| &value.outcome),
            Some(EffectOutcome::FailedAfterKnownEffect { .. })
        ));
        first
            .ledger
            .load_command_output_sensitive_rejection_for_effect(&effect_id)
            .expect("load authoritative formal v29 rejection");

        let dispatches_before_restart = order.borrow().len();
        drop(first);
        let restarted_runner = FormalScriptRunnerLifecycle::new(
            FormalDispatchBehavior::Exact,
            Rc::clone(&order),
            Rc::clone(&acknowledgements),
        );
        let restart_cleanup_count = restarted_runner.sensitive_cleanup_count();
        let mut restarted = DurableWalkingSkeleton::open_with_runner_lifecycle(
            &harness.database,
            provider,
            restarted_runner,
        )
        .expect("reopen sensitive formal coordinator");
        let recovered = restarted
            .run_until_blocked(
                &harness.spec.sprint_id,
                &harness.authority,
                &harness.policy,
                &harness.shadow,
                4_000,
            )
            .expect("recover exhausted sensitive formal rejection");
        assert_eq!(recovered, status);
        assert_eq!(order.borrow().len(), dispatches_before_restart);
        assert_eq!(restart_cleanup_count.get(), 0);
        assert!(matches!(
            restarted.ledger.load_verification_receipt(&receipt_id),
            Err(LedgerError::ArtifactNotFound { .. })
        ));
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "one end-to-end regression proves prompt presentation, one-to-one consumption, completion, restart readback, and exported vocabulary"
    )]
    fn human_judgment_remains_truthfully_awaiting_acceptance() {
        let mut harness = Harness::new("formal-human-awaiting");
        harness.spec.acceptance_criteria =
            vec![automated_criterion("automated"), human_criterion("review")];
        let provider = MutationProvider::new(Vec::new());
        let order = Rc::new(RefCell::new(Vec::new()));
        let acknowledgements = Rc::new(Cell::new(0));
        let runner = FormalScriptRunnerLifecycle::new(
            FormalDispatchBehavior::Exact,
            Rc::clone(&order),
            Rc::clone(&acknowledgements),
        );
        let mut coordinator =
            DurableWalkingSkeleton::open_with_runner_lifecycle(&harness.database, provider, runner)
                .expect("open human acceptance coordinator");
        coordinator
            .create_draft(&harness.authority, &harness.spec, &harness.base, 1_001)
            .expect("create human acceptance sprint");
        let status = coordinator
            .run_until_blocked(
                &harness.spec.sprint_id,
                &harness.authority,
                &harness.policy,
                &harness.shadow,
                2_000,
            )
            .expect("run automated prefix and await human judgment");
        assert!(matches!(
            status,
            WalkingSkeletonStatus::AwaitingAcceptance {
                ref criterion_ids,
                ..
            } if criterion_ids == &["review"]
        ));
        assert_eq!(order.borrow().as_slice(), ["automated"]);
        assert_eq!(acknowledgements.get(), 1);
        let sprint = coordinator
            .load_sprint(&harness.spec.sprint_id)
            .expect("load awaiting acceptance sprint");
        let task = &sprint.graph.as_ref().expect("attached graph").tasks[0];
        let history = coordinator
            .ledger
            .load_task_attempt_history(&harness.spec.sprint_id, &task.task_id)
            .expect("load awaiting acceptance history");
        assert_eq!(history.task_state, TaskState::Integrated);
        assert!(history.active_attempt().is_none());
        assert!(
            coordinator
                .ledger
                .assess_task_done(&harness.spec.sprint_id, &task.task_id)
                .expect("rederive awaiting TaskDone")
                .proof
                .is_some()
        );
        assert!(matches!(
            coordinator
                .ledger
                .load_criterion_evidence_receipt_v2(
                    &gate1_criterion_evidence_receipt_identity(&harness.spec.sprint_id, 0,)
                )
                .expect("load exact machine evidence"),
            CriterionEvidenceReceiptV2::Verified { ref criterion_id, .. }
                if criterion_id == "automated"
        ));
        assert!(matches!(
            coordinator.ledger.load_criterion_evidence_receipt_v2(
                &gate1_criterion_evidence_receipt_identity(&harness.spec.sprint_id, 1,)
            ),
            Err(LedgerError::ArtifactNotFound { .. })
        ));
        assert!(matches!(
            sprint.events.last().map(|event| &event.payload),
            Some(AgentEventKind::SprintStateChanged { from, to })
                if from == "Running" && to == "AwaitingAcceptance"
        ));
        assert!(matches!(
            coordinator.ledger.load_sprint_final_verification_admission(
                &final_verification_identity(&harness.spec.sprint_id, "admission")
            ),
            Err(LedgerError::ArtifactNotFound { .. })
        ));

        let presentation = coordinator
            .issue_human_acceptance_prompt_for_ui(
                &harness.spec.sprint_id,
                "trusted-ui-session",
                "review",
            )
            .expect("issue one exact human prompt");
        assert_eq!(
            presentation.prompt.backing,
            HumanAcceptanceBackingV1::OneToOne
        );
        assert_eq!(
            presentation.prompt.rendered_claim_digest,
            Digest::sha256(presentation.rendered_claim.as_bytes())
        );
        assert!(presentation.rendered_claim.contains("backing=1:1"));
        assert!(presentation.rendered_claim.contains("accepted-by-you"));
        assert!(
            !presentation
                .rendered_claim
                .contains("claim-if-chosen=verified")
        );
        let exact_prompt = presentation.prompt.clone();
        drop(coordinator);

        let restart_order = Rc::new(RefCell::new(Vec::new()));
        let restart_acknowledgements = Rc::new(Cell::new(0));
        let mut restarted = DurableWalkingSkeleton::open_with_runner_lifecycle(
            &harness.database,
            MutationProvider::new(Vec::new()),
            FormalScriptRunnerLifecycle::new(
                FormalDispatchBehavior::Exact,
                Rc::clone(&restart_order),
                Rc::clone(&restart_acknowledgements),
            ),
        )
        .expect("reopen awaiting human acceptance");
        assert_eq!(
            restarted
                .issue_human_acceptance_prompt_for_ui(
                    &harness.spec.sprint_id,
                    "trusted-ui-session",
                    "review",
                )
                .expect("read back unchanged prompt")
                .prompt,
            exact_prompt
        );
        let decided_at = restarted
            .load_sprint(&harness.spec.sprint_id)
            .expect("reload exact human prompt event cut")
            .events
            .into_iter()
            .find(|event| event.sequence == exact_prompt.issued_event_sequence)
            .expect("human prompt names one exact durable sprint event")
            .occurred_at_unix_ms
            .checked_add(1)
            .expect("human decision fixture timestamp remains representable");
        let replayed_at = decided_at
            .checked_add(1)
            .expect("human replay fixture timestamp remains representable");
        let resumed_at = replayed_at
            .checked_add(1)
            .expect("accepted sprint resume timestamp remains representable");
        let consumed = restarted
            .consume_human_acceptance_prompt_from_ui(
                &exact_prompt.prompt_id,
                "trusted-ui-session",
                HumanAcceptanceDecisionOutcomeV1::AcceptedByYou,
                decided_at,
            )
            .expect("consume exactly one human prompt");
        assert_eq!(
            consumed.decision.outcome,
            HumanAcceptanceDecisionOutcomeV1::AcceptedByYou
        );
        assert!(matches!(
            consumed.criterion_evidence,
            Some(CriterionEvidenceReceiptV2::AcceptedByYou {
                ref criterion_id,
                backing: HumanAcceptanceBackingV1::OneToOne,
                ..
            }) if criterion_id == "review"
        ));
        assert!(matches!(
            restarted.consume_human_acceptance_prompt_from_ui(
                &exact_prompt.prompt_id,
                "trusted-ui-session",
                HumanAcceptanceDecisionOutcomeV1::AcceptedByYou,
                replayed_at,
            ),
            Err(DurableCoordinatorError::Ledger(
                LedgerError::ArtifactAlreadyExists { .. }
            ))
        ));
        assert!(matches!(
            restarted
                .run_until_blocked(
                    &harness.spec.sprint_id,
                    &harness.authority,
                    &harness.policy,
                    &harness.shadow,
                    resumed_at,
                )
                .expect("advance accepted sprint through final verification"),
            WalkingSkeletonStatus::ReadyForApplication { .. }
        ));
        assert!(restart_order.borrow().is_empty());
        assert_eq!(restart_acknowledgements.get(), 0);
    }

    #[test]
    fn formal_terminal_retry_and_postcommit_readback_never_redispatch() {
        let mut retry = Harness::new("formal-precommit-retry");
        retry.spec.acceptance_criteria =
            vec![automated_criterion("first"), automated_criterion("second")];
        let provider = MutationProvider::new(Vec::new());
        let order = Rc::new(RefCell::new(Vec::new()));
        let acknowledgements = Rc::new(Cell::new(0));
        let runner = FormalScriptRunnerLifecycle::new(
            FormalDispatchBehavior::Exact,
            Rc::clone(&order),
            Rc::clone(&acknowledgements),
        );
        let mut coordinator = DurableWalkingSkeleton::open_with_runner_lifecycle(
            &retry.database,
            provider.clone(),
            runner,
        )
        .expect("open formal retry coordinator");
        coordinator
            .create_draft(&retry.authority, &retry.spec, &retry.base, 1_001)
            .expect("create formal retry sprint");
        coordinator.inject_claimed_terminal_precommit_failure_for_test(LedgerError::Io(
            io::Error::other("injected formal precommit contention"),
        ));
        assert!(matches!(
            coordinator.run_until_blocked(
                &retry.spec.sprint_id,
                &retry.authority,
                &retry.policy,
                &retry.shadow,
                2_000,
            ),
            Err(DurableCoordinatorError::Ledger(LedgerError::Io(_)))
        ));
        assert_eq!(order.borrow().as_slice(), ["first"]);
        assert_eq!(acknowledgements.get(), 0);
        assert!(matches!(
            coordinator
                .run_until_blocked(
                    &retry.spec.sprint_id,
                    &retry.authority,
                    &retry.policy,
                    &retry.shadow,
                    3_000,
                )
                .expect("retry exact first terminal then run second criterion"),
            WalkingSkeletonStatus::ReadyForApplication { .. }
        ));
        assert_eq!(order.borrow().as_slice(), ["first", "second"]);
        assert_eq!(acknowledgements.get(), 2);

        let mut postcommit = Harness::new("formal-postcommit-readback");
        postcommit.spec.acceptance_criteria = vec![automated_criterion("only")];
        let post_order = Rc::new(RefCell::new(Vec::new()));
        let post_acknowledgements = Rc::new(Cell::new(0));
        let post_runner = FormalScriptRunnerLifecycle::new(
            FormalDispatchBehavior::Exact,
            Rc::clone(&post_order),
            Rc::clone(&post_acknowledgements),
        );
        let mut post = DurableWalkingSkeleton::open_with_runner_lifecycle(
            &postcommit.database,
            MutationProvider::new(Vec::new()),
            post_runner,
        )
        .expect("open formal postcommit coordinator");
        post.create_draft(
            &postcommit.authority,
            &postcommit.spec,
            &postcommit.base,
            1_001,
        )
        .expect("create formal postcommit sprint");
        post.inject_formal_terminal_postcommit_uncertainty_for_test();
        assert!(matches!(
            post.run_until_blocked(
                &postcommit.spec.sprint_id,
                &postcommit.authority,
                &postcommit.policy,
                &postcommit.shadow,
                2_000,
            )
            .expect("exact typed readback resolves injected postcommit uncertainty"),
            WalkingSkeletonStatus::ReadyForApplication { .. }
        ));
        assert_eq!(post_order.borrow().as_slice(), ["only"]);
        assert_eq!(post_acknowledgements.get(), 1);
    }

    #[test]
    fn crossed_or_recovered_formal_authority_never_remints_or_redispatches() {
        let mut harness = Harness::new("formal-crossed-restart");
        harness.spec.acceptance_criteria = vec![automated_criterion("only")];
        let provider = MutationProvider::new(Vec::new());
        let order = Rc::new(RefCell::new(Vec::new()));
        let acknowledgements = Rc::new(Cell::new(0));
        let runner = FormalScriptRunnerLifecycle::new(
            FormalDispatchBehavior::CrossResponse,
            Rc::clone(&order),
            Rc::clone(&acknowledgements),
        );
        let mut first = DurableWalkingSkeleton::open_with_runner_lifecycle(
            &harness.database,
            provider.clone(),
            runner,
        )
        .expect("open crossed formal coordinator");
        first
            .create_draft(&harness.authority, &harness.spec, &harness.base, 1_001)
            .expect("create crossed formal sprint");
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
        assert_eq!(order.borrow().as_slice(), ["only"]);
        assert_eq!(acknowledgements.get(), 0);
        drop(first);

        let restarted_runner = FormalScriptRunnerLifecycle::new(
            FormalDispatchBehavior::Exact,
            Rc::clone(&order),
            Rc::clone(&acknowledgements),
        );
        let mut restarted = DurableWalkingSkeleton::open_with_runner_lifecycle(
            &harness.database,
            provider,
            restarted_runner,
        )
        .expect("reopen crossed formal coordinator");
        assert!(matches!(
            restarted
                .run_until_blocked(
                    &harness.spec.sprint_id,
                    &harness.authority,
                    &harness.policy,
                    &harness.shadow,
                    3_000,
                )
                .expect("recovered claimed admission is reconciliation-only"),
            WalkingSkeletonStatus::ReconciliationRequired {
                kind: EffectKind::RunCommand,
                ..
            }
        ));
        assert_eq!(order.borrow().as_slice(), ["only"]);
        assert_eq!(acknowledgements.get(), 0);
    }

    #[test]
    fn formal_transport_failures_stop_before_later_criteria_with_exact_evidence() {
        for (label, behavior, expect_unknown, expected_evidence) in [
            (
                "zero",
                FormalDispatchBehavior::FailedBeforeEffect,
                false,
                FORMAL_ZERO_FAILURE_EVIDENCE,
            ),
            (
                "partial",
                FormalDispatchBehavior::PartialWrite,
                true,
                FORMAL_PARTIAL_FAILURE_EVIDENCE,
            ),
            (
                "correlated",
                FormalDispatchBehavior::CorrelatedReject,
                true,
                FORMAL_CORRELATED_FAILURE_EVIDENCE,
            ),
        ] {
            let mut harness = Harness::new(&format!("formal-transport-{label}"));
            harness.spec.acceptance_criteria =
                vec![automated_criterion("first"), automated_criterion("later")];
            let order = Rc::new(RefCell::new(Vec::new()));
            let acknowledgements = Rc::new(Cell::new(0));
            let runner = FormalScriptRunnerLifecycle::new(
                behavior,
                Rc::clone(&order),
                Rc::clone(&acknowledgements),
            );
            let mut coordinator = DurableWalkingSkeleton::open_with_runner_lifecycle(
                &harness.database,
                MutationProvider::new(Vec::new()),
                runner,
            )
            .expect("open formal transport failure coordinator");
            coordinator
                .create_draft(&harness.authority, &harness.spec, &harness.base, 1_001)
                .expect("create formal transport failure sprint");
            let status = coordinator
                .run_until_blocked(
                    &harness.spec.sprint_id,
                    &harness.authority,
                    &harness.policy,
                    &harness.shadow,
                    2_000,
                )
                .expect("persist exact claimed formal transport terminal");
            assert_eq!(
                matches!(status, WalkingSkeletonStatus::SprintUnknown { .. }),
                expect_unknown
            );
            if !expect_unknown {
                assert!(matches!(
                    status,
                    WalkingSkeletonStatus::TaskEffectFailedBeforeEffect { .. }
                ));
            }
            assert_eq!(order.borrow().as_slice(), ["first"]);
            assert_eq!(acknowledgements.get(), 1);
            let sprint = coordinator
                .load_sprint(&harness.spec.sprint_id)
                .expect("load formal failure evidence");
            let formal = sprint
                .effects
                .iter()
                .find(|effect| {
                    effect.intent.kind == EffectKind::RunCommand
                        && effect.intent.idempotency_key.contains("criterion-0000")
                })
                .expect("first formal effect");
            assert_eq!(formal.evidence_bytes.as_deref(), Some(expected_evidence));
            assert!(
                sprint
                    .effects
                    .iter()
                    .all(|effect| !effect.intent.idempotency_key.contains("criterion-0001"))
            );
        }
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "the test verifies the complete Unknown terminal tuple, durable closure evidence, and restart non-replay in one scenario"
    )]
    fn formal_command_unknown_closes_exactly_and_restart_is_readback_only() {
        let mut harness = Harness::new("formal-command-unknown-finished-restart");
        harness.spec.acceptance_criteria = vec![automated_criterion("only")];
        let order = Rc::new(RefCell::new(Vec::new()));
        let acknowledgements = Rc::new(Cell::new(0));
        let mut first = DurableWalkingSkeleton::open_with_runner_lifecycle(
            &harness.database,
            MutationProvider::new(Vec::new()),
            FormalScriptRunnerLifecycle::new(
                FormalDispatchBehavior::PartialWrite,
                Rc::clone(&order),
                Rc::clone(&acknowledgements),
            ),
        )
        .expect("open formal Unknown closure coordinator");
        first
            .create_draft(&harness.authority, &harness.spec, &harness.base, 1_001)
            .expect("create formal Unknown closure sprint");
        let finished = first
            .run_until_blocked(
                &harness.spec.sprint_id,
                &harness.authority,
                &harness.policy,
                &harness.shadow,
                2_000,
            )
            .expect("close exact formal command Unknown");
        let WalkingSkeletonStatus::SprintUnknown {
            terminal_record_id,
            marker_id,
            disposition_id,
            effect_id,
        } = &finished
        else {
            panic!("formal command Unknown did not reach its finished state: {finished:?}");
        };
        assert_eq!(
            terminal_record_id,
            &task_command_unknown_identity(effect_id, "sprint-unknown-terminal")
        );
        assert_eq!(
            marker_id,
            &task_command_unknown_identity(effect_id, "sprint-unknown-marker")
        );
        assert_eq!(
            disposition_id,
            &task_command_unknown_identity(effect_id, "unknown-cleaned-disposition")
        );
        let task_id = first
            .ledger
            .load_sprint(&harness.spec.sprint_id)
            .expect("load formal Unknown sprint graph")
            .graph
            .expect("formal Unknown graph exists")
            .tasks
            .into_iter()
            .next()
            .expect("formal Unknown task exists")
            .task_id;
        let history = first
            .ledger
            .load_task_attempt_history(&harness.spec.sprint_id, &task_id)
            .expect("load exact closed formal attempt");
        let unknown = history
            .attempts
            .iter()
            .find_map(|entry| match entry.disposition.as_ref() {
                Some(TaskAttemptDisposition::UnknownCleaned(unknown)) => Some(unknown),
                _ => None,
            })
            .expect("formal Unknown has exact UnknownCleaned disposition");
        assert_eq!(&unknown.metadata.disposition_id, disposition_id);
        assert_eq!(&unknown.unknown_evidence.effect_id, effect_id);
        assert!(
            unknown
                .cleanup_release
                .cleanup_receipt
                .worker_lease
                .is_some()
        );
        assert!(history.unknown_terminalization_pending.is_none());
        let capture = first
            .ledger
            .load_command_output_capture_for_effect(effect_id)
            .expect("load resolved formal Unknown capture");
        assert!(capture.reconciliation_resolution.is_some());
        assert!(capture.reconciliation_obligation_closure.is_some());
        assert!(matches!(
            first
                .ledger
                .load_terminal_outcome(&harness.spec.sprint_id)
                .expect("load formal Unknown terminal"),
            Some(terminal)
                if terminal.evidence.record_id == *terminal_record_id
                    && terminal.evidence.state == NonSuccessTerminalState::Unknown
        ));
        assert_eq!(order.borrow().as_slice(), ["only"]);
        assert_eq!(acknowledgements.get(), 1);
        drop(first);

        let mut restarted = DurableWalkingSkeleton::open_with_runner_lifecycle(
            &harness.database,
            MutationProvider::new(Vec::new()),
            FormalScriptRunnerLifecycle::new(
                FormalDispatchBehavior::Exact,
                Rc::clone(&order),
                Rc::clone(&acknowledgements),
            ),
        )
        .expect("reopen finished formal Unknown sprint");
        let readback = restarted
            .run_until_blocked(
                &harness.spec.sprint_id,
                &harness.authority,
                &harness.policy,
                &harness.shadow,
                3_000,
            )
            .expect("read back finished formal Unknown without execution");
        assert_eq!(readback, finished);
        assert_eq!(order.borrow().as_slice(), ["only"]);
        assert_eq!(acknowledgements.get(), 1);
    }

    #[test]
    fn ordinary_command_unknown_uses_the_same_finished_restart_path() {
        let harness = Harness::new("ordinary-command-unknown-finished-restart");
        let provider = MutationProvider::new(vec![ProviderToolIntent::RunCommand {
            command: fixture_acceptance_command(),
        }]);
        let dispatches = Rc::new(Cell::new(0));
        let mut first = DurableWalkingSkeleton::open_with_runner_lifecycle(
            &harness.database,
            provider.clone(),
            ScriptedRunnerLifecycle::new(
                ScriptedDispatchBehavior::SuccessfulCommandUnknownAfterDispatch,
                Rc::clone(&dispatches),
            ),
        )
        .expect("open ordinary command Unknown coordinator");
        first
            .create_draft(&harness.authority, &harness.spec, &harness.base, 1_001)
            .expect("create ordinary command Unknown sprint");
        let finished = first
            .run_until_blocked(
                &harness.spec.sprint_id,
                &harness.authority,
                &harness.policy,
                &harness.shadow,
                2_000,
            )
            .expect("close ordinary command Unknown");
        assert!(matches!(
            finished,
            WalkingSkeletonStatus::SprintUnknown { .. }
        ));
        assert_eq!(dispatches.get(), 1);
        let persisted = first
            .load_sprint(&harness.spec.sprint_id)
            .expect("load ordinary command Unknown sprint");
        let command_effect = persisted
            .effects
            .iter()
            .find(|effect| effect.intent.kind == EffectKind::RunCommand)
            .expect("ordinary command Unknown retains its exact command effect");
        let capture = first
            .ledger
            .load_command_output_capture_for_effect(&command_effect.intent.effect_id)
            .expect("load policy-bound ordinary command Unknown capture");
        let unknown_terminal = capture
            .terminal
            .as_ref()
            .expect("ordinary command Unknown retains an immutable capture terminal");
        let resolution = capture
            .reconciliation_resolution
            .as_ref()
            .expect("policy-bound ordinary command Unknown has exact capture resolution");
        assert_eq!(
            resolution.disposition,
            CommandOutputCaptureTerminalDispositionV1::Published
        );
        assert_eq!(
            capture.reconciliation_obligation_closure.as_ref(),
            Some(&unknown_terminal.terminal_anchor_digest)
        );
        let clean_resolution = first
            .ledger
            .load_command_output_clean_scan_resolution_receipt_for_effect(
                &command_effect.intent.effect_id,
            )
            .expect("load policy-bound ordinary command clean-scan resolution receipt");
        assert_eq!(clean_resolution.intent, capture.intent);
        assert_eq!(
            &clean_resolution.acquired,
            capture
                .acquired
                .as_ref()
                .expect("policy-bound ordinary command capture retains its acquisition")
        );
        assert_eq!(&clean_resolution.unknown_terminal, unknown_terminal);
        assert_eq!(&clean_resolution.resolution, resolution);
        drop(first);

        let mut restarted = DurableWalkingSkeleton::open_with_runner_lifecycle(
            &harness.database,
            provider.clone(),
            ScriptedRunnerLifecycle::new(ScriptedDispatchBehavior::Exact, Rc::clone(&dispatches)),
        )
        .expect("reopen ordinary command Unknown sprint");
        let readback = restarted
            .run_until_blocked(
                &harness.spec.sprint_id,
                &harness.authority,
                &harness.policy,
                &harness.shadow,
                3_000,
            )
            .expect("read back ordinary command Unknown without replay");
        assert_eq!(readback, finished);
        assert_eq!(dispatches.get(), 1);
        assert_eq!(provider.turn_calls(), 1);
    }

    #[test]
    fn crossed_mutation_deltas_commit_nothing_and_never_replay() {
        for (label, behavior) in [
            (
                "extra-file",
                ScriptedDispatchBehavior::ExtraShadowFileAfterMutation,
            ),
            (
                "wrong-bytes",
                ScriptedDispatchBehavior::WrongShadowBytesAfterMutation,
            ),
            (
                "crossed-snapshot",
                ScriptedDispatchBehavior::CrossMutationResultSnapshot,
            ),
        ] {
            let harness = Harness::new(&format!("mutation-delta-reject-{label}"));
            let provider = MutationProvider::new(vec![ProviderToolIntent::CreateRegularFile {
                path: PathBuf::from("docs/claimed.txt"),
                contents: b"claimed bytes\n".to_vec(),
            }]);
            let dispatch_count = Rc::new(Cell::new(0));
            let runner = ScriptedRunnerLifecycle::new(behavior, Rc::clone(&dispatch_count));
            let mut coordinator = DurableWalkingSkeleton::open_with_runner_lifecycle(
                &harness.database,
                provider.clone(),
                runner,
            )
            .expect("open mutation rejection coordinator");
            coordinator
                .create_draft(&harness.authority, &harness.spec, &harness.base, 1_001)
                .expect("create mutation rejection sprint");

            let error = coordinator
                .run_until_blocked(
                    &harness.spec.sprint_id,
                    &harness.authority,
                    &harness.policy,
                    &harness.shadow,
                    2_000,
                )
                .expect_err("crossed mutation delta must fail before observation persistence");
            assert!(matches!(error, DurableCoordinatorError::Protocol(_)));
            assert_eq!(dispatch_count.get(), 1);
            assert_eq!(provider.turn_calls(), 1);
            let before = coordinator
                .load_sprint(&harness.spec.sprint_id)
                .expect("load rejected mutation claim");
            let rejected = before
                .effects
                .iter()
                .find(|effect| effect.intent.kind == EffectKind::CreateRegularFile)
                .expect("rejected mutation effect");
            assert!(rejected.dispatch_claim.is_some());
            assert!(rejected.observation.is_none());
            assert!(matches!(
                rejected.mutation_artifact,
                PersistedMutationArtifact::NotRequired
            ));
            let effect_count = before.effects.len();
            let event_count = before.events.len();

            let resumed = coordinator
                .run_until_blocked(
                    &harness.spec.sprint_id,
                    &harness.authority,
                    &harness.policy,
                    &harness.shadow,
                    3_000,
                )
                .expect("claimed rejected mutation resumes reconciliation-only");
            assert!(matches!(
                resumed,
                WalkingSkeletonStatus::ReconciliationRequired {
                    kind: EffectKind::CreateRegularFile,
                    ..
                }
            ));
            assert_eq!(dispatch_count.get(), 1, "{label} replayed native dispatch");
            assert_eq!(provider.turn_calls(), 1, "{label} replayed provider turn");
            let after = coordinator
                .load_sprint(&harness.spec.sprint_id)
                .expect("reload reconciliation-only rejected mutation");
            assert_eq!(after.effects.len(), effect_count);
            assert_eq!(after.events.len(), event_count);
        }
    }

    #[test]
    fn walking_skeleton_persists_the_pre_edit_command_and_stops_before_mutation() {
        let harness = Harness::new("pre-edit-command-block");
        let provider = CountingProvider::default();
        harness.initialize(provider.clone());
        let mut coordinator = harness.coordinator(provider.clone());

        let first_status = coordinator
            .run_until_blocked(
                &harness.spec.sprint_id,
                &harness.authority,
                &harness.policy,
                &harness.shadow,
                2_000,
            )
            .expect("run to durable pre-edit command block");
        let command_effect_id = match &first_status {
            WalkingSkeletonStatus::ContainmentNotReady { effect_id, reason } => {
                assert!(reason.contains("did not begin"));
                effect_id.clone()
            }
            other => panic!("unexpected stop state: {other:?}"),
        };
        assert_eq!(provider.planning_calls(), 1);
        assert_eq!(provider.turn_calls(), 4);
        assert_eq!(
            harness.spec.acceptance_criteria,
            vec![AcceptanceCriterion {
                criterion_id: "fixture-ready".into(),
                description: "The deterministic fixture test passes".into(),
                kind: AcceptanceKind::Automated(fixture_acceptance_command()),
            }]
        );

        let before_restart = coordinator
            .load_sprint(&harness.spec.sprint_id)
            .expect("load pre-edit block");
        assert_durable_pre_edit_block(&harness, &before_restart, &command_effect_id);
        let effect_count = before_restart.effects.len();
        let event_count = before_restart.events.len();
        drop(coordinator);

        let mut restarted = harness.coordinator(provider.clone());
        let second_status = restarted
            .run_until_blocked(
                &harness.spec.sprint_id,
                &harness.authority,
                &harness.policy,
                &harness.shadow,
                4_000,
            )
            .expect("restart at containment block");
        assert_eq!(second_status, first_status);
        assert_eq!(provider.planning_calls(), 1);
        assert_eq!(provider.turn_calls(), 4);
        let after_restart = restarted
            .load_sprint(&harness.spec.sprint_id)
            .expect("reload deduplicated sprint");
        assert_eq!(after_restart.effects.len(), effect_count);
        assert_eq!(after_restart.events.len(), event_count);
        assert_durable_pre_edit_block(&harness, &after_restart, &command_effect_id);
    }

    #[test]
    fn canonical_planning_evidence_detects_tampering() {
        let harness = Harness::new("tampered-evidence");
        let provider = CountingProvider::default();
        harness.initialize(provider.clone());
        let mut coordinator = harness.coordinator(provider);
        coordinator
            .run_until_blocked_inner(
                &harness.spec.sprint_id,
                &harness.authority,
                &harness.policy,
                &harness.shadow,
                2_000,
                PlanningPause::AfterObservation,
                false,
                false,
            )
            .expect("persist strict planning evidence");
        let sprint = coordinator
            .load_sprint(&harness.spec.sprint_id)
            .expect("load planning effect");
        let planning = sprint.effects.first().expect("planning effect");
        assert_eq!(
            decode_planning_request(&planning.request_bytes).expect("strict planning request"),
            harness.spec
        );
        let mut tampered = planning
            .evidence_bytes
            .clone()
            .expect("planning evidence bytes");
        let sprint_id = harness.spec.sprint_id.as_bytes();
        let offset = tampered
            .windows(sprint_id.len())
            .position(|window| window == sprint_id)
            .expect("sprint identity in response");
        tampered[offset] ^= 1;
        assert!(decode_planning_evidence(&harness.spec, &tampered).is_err());
        assert_ne!(
            Digest::sha256(&tampered),
            planning
                .observation
                .as_ref()
                .expect("planning observation")
                .outcome
                .evidence_digest()
                .clone()
        );
    }

    #[test]
    fn restart_accepts_an_exact_recreated_base_shadow_without_replay() {
        let harness = Harness::new("recreated-base-shadow");
        let provider = CountingProvider::default();
        harness.initialize(provider.clone());
        let mut coordinator = harness.coordinator(provider.clone());
        let first_status = coordinator
            .run_until_blocked(
                &harness.spec.sprint_id,
                &harness.authority,
                &harness.policy,
                &harness.shadow,
                2_000,
            )
            .expect("reach containment block");
        assert!(matches!(
            &first_status,
            WalkingSkeletonStatus::ContainmentNotReady { .. }
        ));
        drop(coordinator);
        let recreated_base = harness.fresh_base_shadow("recreated-base");

        let mut restarted = harness.coordinator(provider.clone());
        let restarted_status = restarted
            .run_until_blocked(
                &harness.spec.sprint_id,
                &harness.authority,
                &harness.policy,
                &recreated_base,
                4_000,
            )
            .expect("exact base shadow remains valid before any mutation");
        assert_eq!(restarted_status, first_status);
        assert_eq!(provider.planning_calls(), 1);
        assert_eq!(provider.turn_calls(), 4);
        assert_eq!(
            fs::read(recreated_base.root().join("src/lib.rs"))
                .expect("read recreated unchanged source"),
            FIXTURE_SOURCE.as_bytes()
        );
        assert!(!recreated_base.root().join("docs/report.txt").exists());
    }

    #[test]
    fn restart_rejects_out_of_band_shadow_tampering_before_any_replay() {
        let harness = Harness::new("shadow-tamper");
        let provider = CountingProvider::default();
        harness.initialize(provider.clone());
        let mut coordinator = harness.coordinator(provider.clone());
        assert!(matches!(
            coordinator
                .run_until_blocked(
                    &harness.spec.sprint_id,
                    &harness.authority,
                    &harness.policy,
                    &harness.shadow,
                    2_000,
                )
                .expect("reach containment block"),
            WalkingSkeletonStatus::ContainmentNotReady { .. }
        ));
        drop(coordinator);
        fs::write(
            harness.shadow.root().join("src/lib.rs"),
            b"out-of-band tamper\n",
        )
        .expect("tamper private shadow");

        let mut restarted = harness.coordinator(provider.clone());
        let error = restarted
            .run_until_blocked(
                &harness.spec.sprint_id,
                &harness.authority,
                &harness.policy,
                &harness.shadow,
                4_000,
            )
            .expect_err("out-of-band shadow change must fail closed");
        assert!(matches!(
            error,
            DurableCoordinatorError::Protocol(message)
                if message.contains("outside the durable effect chain")
        ));
        assert_eq!(provider.planning_calls(), 1);
        assert_eq!(provider.turn_calls(), 4);
    }

    #[test]
    fn durable_ui_projection_is_identical_live_and_after_restart() {
        let harness = Harness::new("ui-live-restart");
        let provider = CountingProvider::default();
        harness.initialize(provider.clone());
        let mut coordinator = harness.coordinator(provider.clone());
        assert!(matches!(
            coordinator
                .run_until_blocked(
                    &harness.spec.sprint_id,
                    &harness.authority,
                    &harness.policy,
                    &harness.shadow,
                    2_000,
                )
                .expect("reach durable containment"),
            WalkingSkeletonStatus::ContainmentNotReady { .. }
        ));

        let live_sprint = coordinator
            .load_sprint(&harness.spec.sprint_id)
            .expect("load live durable image");
        let live =
            DurableUiProjection::from_persisted(&live_sprint).expect("project live durable image");
        let live_bytes = live.canonical_bytes().expect("encode live projection");
        assert!(!live.is_done());
        assert!(
            live.events()
                .iter()
                .any(|event| matches!(event.payload(), DurableUiEventKind::EffectProposed { .. }))
        );
        assert!(
            live.events()
                .iter()
                .any(|event| matches!(event.payload(), DurableUiEventKind::EffectRunning { .. }))
        );
        assert!(
            live.events()
                .iter()
                .any(|event| matches!(event.payload(), DurableUiEventKind::EffectSucceeded { .. }))
        );
        assert!(live.events().iter().any(|event| matches!(
            event.payload(),
            DurableUiEventKind::EffectFailedBefore { .. }
        )));
        assert!(live.events().iter().any(|event| matches!(
            event.payload(),
            DurableUiEventKind::ContainmentBlocked { .. }
        )));
        assert!(
            !live
                .events()
                .iter()
                .any(|event| matches!(event.payload(), DurableUiEventKind::SprintCompleted { .. }))
        );

        assert!(
            !live
                .events()
                .iter()
                .any(|event| matches!(event.payload(), DurableUiEventKind::SnapshotLinked { .. }))
        );
        drop(coordinator);

        let restarted = harness.coordinator(provider);
        let restarted_sprint = restarted
            .load_sprint(&harness.spec.sprint_id)
            .expect("load restarted durable image");
        let restarted_projection = DurableUiProjection::from_persisted(&restarted_sprint)
            .expect("project restarted image");
        assert_eq!(restarted_projection, live);
        assert_eq!(
            restarted_projection
                .canonical_bytes()
                .expect("encode restarted projection"),
            live_bytes
        );
    }

    #[test]
    fn durable_ui_projection_marks_unobserved_intent_unknown_without_running() {
        let harness = Harness::new("ui-unobserved");
        let provider = CountingProvider::default();
        harness.initialize(provider.clone());
        let mut coordinator = harness.coordinator(provider.clone());
        assert!(matches!(
            coordinator
                .run_until_blocked_inner(
                    &harness.spec.sprint_id,
                    &harness.authority,
                    &harness.policy,
                    &harness.shadow,
                    2_000,
                    PlanningPause::AfterIntent,
                    false,
                    false,
                )
                .expect("persist intent only"),
            WalkingSkeletonStatus::PlanningIntentDurable { .. }
        ));
        let sprint = coordinator
            .load_sprint(&harness.spec.sprint_id)
            .expect("load intent-only sprint");
        let projection =
            DurableUiProjection::from_persisted(&sprint).expect("project intent-only sprint");
        assert_eq!(projection.events().len(), 2);
        assert!(matches!(
            projection.events()[0].payload(),
            DurableUiEventKind::EffectProposed { .. }
        ));
        assert!(matches!(
            projection.events()[1].payload(),
            DurableUiEventKind::EffectUnknown {
                evidence_digest: None,
                reason: UiUnknownReason::MissingObservation,
                ..
            }
        ));
        assert!(!projection.events().iter().any(|event| matches!(
            event.payload(),
            DurableUiEventKind::EffectRunning { .. } | DurableUiEventKind::EffectSucceeded { .. }
        )));
        assert!(!projection.is_done());
        assert_eq!(provider.planning_calls(), 0);
    }

    #[test]
    fn durable_ui_projection_rejects_tampered_and_unreadable_evidence() {
        let harness = Harness::new("ui-evidence-tamper");
        let provider = CountingProvider::default();
        harness.initialize(provider.clone());
        let mut coordinator = harness.coordinator(provider);
        coordinator
            .run_until_blocked(
                &harness.spec.sprint_id,
                &harness.authority,
                &harness.policy,
                &harness.shadow,
                2_000,
            )
            .expect("reach containment");
        let original = coordinator
            .load_sprint(&harness.spec.sprint_id)
            .expect("load durable evidence");

        let mut tampered = original.clone();
        let read = tampered
            .effects
            .iter_mut()
            .find(|effect| effect.intent.kind == EffectKind::ReadRelativeFile)
            .expect("read effect");
        read.evidence_bytes.as_mut().expect("read evidence")[0] ^= 1;
        assert!(matches!(
            DurableUiProjection::from_persisted(&tampered),
            Err(UiProjectionError::InvalidEffect { .. })
        ));

        let mut unreadable = original;
        let command = unreadable
            .effects
            .iter_mut()
            .find(|effect| effect.intent.kind == EffectKind::RunCommand)
            .expect("command effect");
        let invalid_utf8 = vec![0xff, b'\n'];
        command.evidence_bytes = Some(invalid_utf8.clone());
        command
            .observation
            .as_mut()
            .expect("command observation")
            .outcome = EffectOutcome::FailedBeforeEffect {
            evidence_digest: Digest::sha256(&invalid_utf8),
        };
        assert!(matches!(
            DurableUiProjection::from_persisted(&unreadable),
            Err(UiProjectionError::InvalidEffect { .. })
        ));
    }

    #[test]
    fn active_attempt_refuses_terminal_block_without_writing_terminal_rows() {
        let harness = Harness::new("ui-terminal-block");
        let provider = CountingProvider::default();
        harness.initialize(provider.clone());
        let mut coordinator = harness.coordinator(provider.clone());
        coordinator
            .run_until_blocked(
                &harness.spec.sprint_id,
                &harness.authority,
                &harness.policy,
                &harness.shadow,
                2_000,
            )
            .expect("reach containment");
        let before = coordinator
            .load_sprint(&harness.spec.sprint_id)
            .expect("load active attempt before terminal refusal");
        drop(coordinator);

        let evidence = SprintTerminalEvidence {
            contract_version: CONTRACT_VERSION,
            record_id: format!("{}:terminal-blocked", harness.spec.sprint_id),
            sprint_id: harness.spec.sprint_id.clone(),
            state: NonSuccessTerminalState::Blocked,
            reason: "command containment is not ready".into(),
            terminal_at_unix_ms: 10_000,
        };
        let mut ledger = EventLedger::open(&harness.database).expect("open terminal ledger");
        let proof = SprintTerminalProof::LiveWorkspaceUnchanged(LiveWorkspaceUnchangedReceipt {
            contract_version: CONTRACT_VERSION,
            receipt_id: format!("{}:unchanged", harness.spec.sprint_id),
            sprint_id: harness.spec.sprint_id.clone(),
            base_snapshot: harness.spec.base_snapshot.clone(),
            live_manifest_digest: harness.spec.base_snapshot.clone(),
            grant_hash: harness.spec.workspace_grant.grant_hash.clone(),
            captured_at_unix_ms: evidence.terminal_at_unix_ms,
        });
        let error = ledger
            .record_unsuccessful_terminal_outcome_with_proof(&evidence, &proof)
            .expect_err("active attempt must fence sprint terminalization");
        assert!(matches!(
            error,
            LedgerError::ReferenceMismatch { ref detail, .. }
                if detail.contains("active worker lease")
        ));
        drop(ledger);

        let restarted = harness.coordinator(provider);
        let after = restarted
            .load_sprint(&harness.spec.sprint_id)
            .expect("load sprint after terminal refusal");
        assert_eq!(after, before);
        assert!(after.completion.is_none());
        assert!(after.terminal_outcome.is_none());
    }

    #[test]
    fn durable_ui_projection_rejects_legacy_unproven_completion() {
        let harness = Harness::new("ui-legacy-completion");
        let provider = CountingProvider::default();
        harness.initialize(provider.clone());
        let mut coordinator = harness.coordinator(provider);
        coordinator
            .run_until_blocked(
                &harness.spec.sprint_id,
                &harness.authority,
                &harness.policy,
                &harness.shadow,
                2_000,
            )
            .expect("reach containment");
        let mut sprint = coordinator
            .load_sprint(&harness.spec.sprint_id)
            .expect("load durable sprint");
        let legacy_bytes = b"legacy-v8-completion".to_vec();
        let event = sprint.events.last().expect("durable event").clone();
        let report_body = "Legacy completion is diagnostics only.";
        sprint.legacy_completion = Some(grok_build_core::LegacyCompletionUnproven {
            receipt_id: "legacy-receipt".into(),
            receipt_digest: Digest::sha256(&legacy_bytes),
            receipt_bytes: legacy_bytes,
            final_report: grok_build_core::FinalReport {
                report_id: "legacy-report".into(),
                sprint_id: harness.spec.sprint_id.clone(),
                final_snapshot: harness.spec.base_snapshot.clone(),
                content_digest: grok_build_core::FinalReport::digest_body(report_body),
                body: report_body.into(),
                created_at_unix_ms: 3_000,
            },
            terminal_at_unix_ms: 3_001,
            event,
        });

        assert!(matches!(
            DurableUiProjection::from_persisted(&sprint),
            Err(UiProjectionError::InvalidTerminal(reason))
                if reason.contains("legacy v1-v8") && reason.contains("not proven")
        ));
    }

    #[test]
    fn replaced_workspace_root_invalidates_resume_before_provider_call() {
        let harness = Harness::new("root-replaced");
        let provider = CountingProvider::default();
        harness.initialize(provider.clone());
        let original = harness
            .workspace
            .parent()
            .expect("workspace parent")
            .join("workspace-original");
        fs::rename(&harness.workspace, &original).expect("move trusted workspace object");
        fs::create_dir(&harness.workspace).expect("replace workspace at trusted path");

        let mut coordinator = harness.coordinator(provider.clone());
        let error = coordinator
            .run_until_blocked(
                &harness.spec.sprint_id,
                &harness.authority,
                &harness.policy,
                &harness.shadow,
                2_000,
            )
            .expect_err("replaced root must invalidate authority");
        assert!(matches!(error, DurableCoordinatorError::Contract(_)));
        assert_eq!(provider.planning_calls(), 0);
        assert_eq!(provider.turn_calls(), 0);
    }

    /// Strict-fake lifecycle whose registered session and `Leased -> Running`
    /// boundary are stamped from the host wall clock, exactly as the production
    /// `RunnerLifecycleClient` stamps `registered_at_unix_ms` after a real spawn
    /// and wire handshake. Every other seam is the strict fake's own.
    struct HostClockRunnerLifecycle;

    impl WalkingSkeletonRunnerLifecycle for HostClockRunnerLifecycle {
        fn ensure_task_attempt_running(
            &mut self,
            ledger: &mut EventLedger,
            start: WalkingSkeletonRunnerStart<'_>,
        ) -> Result<TaskAttemptRunningBoundary, DurableCoordinatorError> {
            strict_fake_ensure_task_attempt_running(
                ledger,
                &start,
                StrictFakeRunningClock::HostWallClock,
            )
        }

        fn dispatch_task_effect(
            &mut self,
            ledger: &mut EventLedger,
            dispatch: WalkingSkeletonTaskEffectDispatch<'_>,
        ) -> Result<WalkingSkeletonClaimedTaskEffectResponse, DurableCoordinatorError> {
            StrictFakeRunnerLifecycle.dispatch_task_effect(ledger, dispatch)
        }
    }

    /// Provider and verification timestamps must follow the wall-clock
    /// `Leased -> Running` boundary. Resynchronize the durable timestamp cursor
    /// after the launch handshake so both schema-v15 phase fences admit them.
    #[test]
    fn wall_clock_running_boundary_still_admits_every_running_phase_effect() {
        let harness = Harness::new("wall-clock-running-boundary");
        let mut coordinator = DurableWalkingSkeleton::open_with_runner_lifecycle(
            &harness.database,
            MutationProvider::new(Vec::new()),
            HostClockRunnerLifecycle,
        )
        .expect("open wall-clock coordinator");
        coordinator
            .create_draft(&harness.authority, &harness.spec, &harness.base, 1_001)
            .expect("create wall-clock draft");
        let before_run = host_wall_clock_unix_ms().expect("host clock before the run");
        let status = coordinator
            .run_until_blocked_inner(
                &harness.spec.sprint_id,
                &harness.authority,
                &harness.policy,
                &harness.shadow,
                2_000,
                PlanningPause::None,
                false,
                false,
            )
            .expect("a wall-clock Running boundary must not refuse its own task effects");
        let after_run = host_wall_clock_unix_ms().expect("host clock after the run");
        assert!(matches!(
            status,
            WalkingSkeletonStatus::FormalChecksReady { .. }
        ));

        let sprint = coordinator
            .load_sprint(&harness.spec.sprint_id)
            .expect("load wall-clock sprint");
        let task = &sprint.graph.as_ref().expect("attached graph").tasks[0];
        let history = coordinator
            .ledger
            .load_task_attempt_history(&harness.spec.sprint_id, &task.task_id)
            .expect("load wall-clock attempt history");
        let active = history.active_attempt().expect("active wall-clock attempt");
        let running = active
            .running_boundary
            .as_ref()
            .expect("durable wall-clock Running boundary");

        // The boundary really is a wall-clock instant, not the fixture cursor:
        // it was sampled during this run and is billions of units past the
        // `2_000` the coordinator entered with.
        assert!(running.started_at_unix_ms >= before_run);
        assert!(running.started_at_unix_ms <= after_run);
        assert!(running.started_at_unix_ms > 2_000);
        let session = coordinator
            .ledger
            .load_runner_session(&harness.spec.sprint_id, &running.runner_session_id)
            .expect("load wall-clock session registration");
        assert_eq!(session.registered_at_unix_ms, running.started_at_unix_ms);

        // Exactly the fence predicate, for every phase-fenced effect the
        // attempt owns. The cursor must have jumped past the boundary, so each
        // one is strictly later than it. Launch-cleanup admissions are excluded
        // here for the same reason the trigger excludes them: they commit
        // atomically with the launch, before the session ever registers.
        let attempt_effects: Vec<_> = sprint
            .effects
            .iter()
            .filter(|effect| {
                effect.intent.worker_lease.as_ref() == Some(&active.attempt.worker_lease)
                    && effect.intent.kind != EffectKind::CleanupWorkerDomain
            })
            .collect();
        assert!(
            attempt_effects
                .iter()
                .any(|effect| effect.intent.kind == EffectKind::ProviderRequest),
            "the Running-phase provider turn must be durably admitted"
        );
        for effect in &attempt_effects {
            assert!(
                effect.intent.created_at_unix_ms > running.started_at_unix_ms,
                "effect {} was stamped at {} before its own Running boundary {}",
                effect.intent.effect_id,
                effect.intent.created_at_unix_ms,
                running.started_at_unix_ms
            );
        }

        // The sealed verification boundary is fenced against the same instant.
        let verification = active
            .verification_boundary
            .as_ref()
            .expect("durable wall-clock verification boundary");
        assert!(verification.sealed_at_unix_ms >= running.started_at_unix_ms);

        // Monotonicity: no later event may carry an earlier stamp than an
        // earlier one, which is exactly what a stale cursor produces right
        // after the wall-clock transition event.
        let mut ordered = sprint.events.clone();
        ordered.sort_by_key(|event| event.sequence);
        for pair in ordered.windows(2) {
            assert!(
                pair[0].occurred_at_unix_ms <= pair[1].occurred_at_unix_ms,
                "event {} at {} precedes event {} at {}",
                pair[0].event_id,
                pair[0].occurred_at_unix_ms,
                pair[1].event_id,
                pair[1].occurred_at_unix_ms
            );
        }
    }
