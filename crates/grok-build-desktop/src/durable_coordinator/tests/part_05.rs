    #[test]
    fn dropped_fresh_and_unobserved_claim_never_remint_or_redispatch() {
        for (label, behavior, expected_claim) in [
            (
                "application-drop-fresh",
                ApplicationDispatchBehavior::DropFreshBeforeClaim,
                false,
            ),
            (
                "application-claim-before-observation",
                ApplicationDispatchBehavior::ClaimThenError,
                true,
            ),
        ] {
            let mut scenario = ApplicationScenario::new(label, behavior, true);
            scenario
                .continue_application(8_000)
                .expect_err("simulate application crash boundary");
            assert_eq!(scenario.launch_count.get(), 1);
            assert_eq!(scenario.dispatch_count.get(), 1);
            let effect = scenario
                .coordinator
                .ledger
                .load_effect(&application_identity(
                    &scenario.harness.spec.sprint_id,
                    "effect",
                ))
                .expect("load stranded immutable application effect");
            assert_eq!(effect.dispatch_claim.is_some(), expected_claim);
            assert!(effect.observation.is_none());
            let mut restarted = scenario.restart(ApplicationDispatchBehavior::Exact);
            let status = restarted
                .continue_application(9_000)
                .expect("filesystem-reopened admission is reconciliation-only");
            assert!(matches!(
                status,
                WalkingSkeletonStatus::ReconciliationRequired {
                    kind: EffectKind::ApplyChangeSet,
                    ..
                }
            ));
            assert_eq!(restarted.launch_count.get(), 0, "existing did not relaunch");
            assert_eq!(
                restarted.dispatch_count.get(),
                0,
                "existing did not redispatch"
            );
            assert_eq!(restarted.cleanup_count.get(), 0);
        }
    }

    #[test]
    fn application_transport_phase_controls_terminal_kind_and_cleanup_retry() {
        for (label, behavior, terminal) in [
            (
                "application-zero-byte-cleanup",
                ApplicationDispatchBehavior::FailedBeforeCleanupRequiredOnce,
                WalkingSkeletonApplicationTerminalOutcome::FailedBeforeEffect,
            ),
            (
                "application-partial-cleanup",
                ApplicationDispatchBehavior::PartialCleanupRequiredOnce,
                WalkingSkeletonApplicationTerminalOutcome::Unknown,
            ),
            (
                "application-correlated-cleanup",
                ApplicationDispatchBehavior::CorrelatedCleanupRequiredOnce,
                WalkingSkeletonApplicationTerminalOutcome::Unknown,
            ),
        ] {
            let mut scenario = ApplicationScenario::new(label, behavior, true);
            let first = scenario
                .continue_application(8_000)
                .expect("persist non-success terminal before surfacing cleanup");
            assert!(matches!(
                first,
                WalkingSkeletonStatus::ApplicationTerminalCleanupRequired {
                    outcome,
                    ..
                } if outcome == terminal
            ));
            assert_eq!(scenario.launch_count.get(), 1);
            assert_eq!(scenario.dispatch_count.get(), 1);
            assert_eq!(scenario.cleanup_count.get(), 1);
            let effect = scenario
                .coordinator
                .ledger
                .load_effect(&application_identity(
                    &scenario.harness.spec.sprint_id,
                    "effect",
                ))
                .expect("load exact non-success application terminal");
            match terminal {
                WalkingSkeletonApplicationTerminalOutcome::FailedBeforeEffect => assert!(matches!(
                    effect.observation.as_ref().map(|value| &value.outcome),
                    Some(EffectOutcome::FailedBeforeEffect { .. })
                )),
                WalkingSkeletonApplicationTerminalOutcome::Unknown => assert!(matches!(
                    effect.observation.as_ref().map(|value| &value.outcome),
                    Some(EffectOutcome::Unknown { .. })
                )),
            }
            let mut restarted = scenario.restart(ApplicationDispatchBehavior::Exact);
            let second = restarted
                .continue_application(9_000)
                .expect("recover cleanup from the filesystem without replaying application");
            assert!(match terminal {
                WalkingSkeletonApplicationTerminalOutcome::FailedBeforeEffect => matches!(
                    second,
                    WalkingSkeletonStatus::TaskEffectFailedBeforeEffect { .. }
                ),
                WalkingSkeletonApplicationTerminalOutcome::Unknown => matches!(
                    second,
                    WalkingSkeletonStatus::TaskEffectOutcomeUnknown { .. }
                ),
            });
            assert_eq!(restarted.launch_count.get(), 0);
            assert_eq!(restarted.dispatch_count.get(), 0);
            assert_eq!(restarted.cleanup_count.get(), 1);
        }
    }

    #[test]
    fn successful_application_cleanup_retries_without_relaunch_or_redispatch() {
        let mut scenario = ApplicationScenario::new(
            "application-success-cleanup-retry",
            ApplicationDispatchBehavior::CleanupRequiredOnce,
            true,
        );
        assert!(matches!(
            scenario
                .continue_application(8_000)
                .expect("persist application before pending cleanup"),
            WalkingSkeletonStatus::ApplicationCleanupRequired { .. }
        ));
        assert_eq!(scenario.launch_count.get(), 1);
        assert_eq!(scenario.dispatch_count.get(), 1);
        assert_eq!(scenario.cleanup_count.get(), 1);
        let mut restarted = scenario.restart(ApplicationDispatchBehavior::Exact);
        assert!(matches!(
            restarted
                .continue_application(9_000)
                .expect("filesystem restart retries only trusted-Applier cleanup"),
            WalkingSkeletonStatus::ApplicationApplied { .. }
        ));
        assert_eq!(restarted.launch_count.get(), 0);
        assert_eq!(restarted.dispatch_count.get(), 0);
        assert_eq!(restarted.cleanup_count.get(), 1);
    }

    #[test]
    fn crossed_application_response_bundle_leaves_claim_reconciliation_only() {
        let mut scenario = ApplicationScenario::new(
            "application-crossed-response-bundle",
            ApplicationDispatchBehavior::CrossBundle,
            true,
        );
        scenario
            .continue_application(8_000)
            .expect_err("crossed application response must fail closed");
        let effect = scenario
            .coordinator
            .ledger
            .load_effect(&application_identity(
                &scenario.harness.spec.sprint_id,
                "effect",
            ))
            .expect("load crossed claimed effect");
        assert!(effect.dispatch_claim.is_some());
        assert!(effect.observation.is_none());
        let mut restarted = scenario.restart(ApplicationDispatchBehavior::Exact);
        assert!(matches!(
            restarted
                .continue_application(9_000)
                .expect("filesystem-reopen crossed response reconciliation-only"),
            WalkingSkeletonStatus::ReconciliationRequired { .. }
        ));
        assert_eq!(restarted.launch_count.get(), 0);
        assert_eq!(restarted.dispatch_count.get(), 0);
    }

    fn write_file(path: &Path, contents: &str) {
        fs::write(path, contents.as_bytes()).expect("write fixture file");
    }

    #[allow(
        clippy::too_many_lines,
        reason = "one assertion helper audits the complete persisted pre-edit boundary"
    )]
    fn assert_durable_pre_edit_block(
        harness: &Harness,
        sprint: &PersistedSprint,
        command_effect_id: &str,
    ) {
        assert_eq!(
            fs::read(harness.shadow.root().join("src/lib.rs"))
                .expect("read unchanged shadow source"),
            FIXTURE_SOURCE.as_bytes()
        );
        assert_eq!(
            fs::read(harness.workspace.join("src/lib.rs")).expect("read unchanged live source"),
            FIXTURE_SOURCE.as_bytes()
        );
        assert!(!harness.shadow.root().join("docs/report.txt").exists());
        assert!(sprint.completion.is_none());
        assert_eq!(sprint.spec.base_snapshot, harness.base.snapshot_id);
        assert_eq!(sprint.effects.len(), 10);
        assert_eq!(
            sprint
                .effects
                .iter()
                .filter(|effect| effect.intent.kind == EffectKind::ProviderRequest)
                .count(),
            5
        );
        for required_kind in [
            EffectKind::ProviderRequest,
            EffectKind::ReadRelativeFile,
            EffectKind::SearchLiteral,
            EffectKind::RunCommand,
        ] {
            assert!(
                sprint
                    .effects
                    .iter()
                    .any(|effect| effect.intent.kind == required_kind),
                "missing durable effect kind {required_kind:?}"
            );
        }
        assert!(
            sprint
                .effects
                .iter()
                .all(|effect| !is_mutating_tool(effect.intent.kind))
        );
        let task_effects = sprint
            .effects
            .iter()
            .filter(|effect| effect.intent.task_id.is_some())
            .collect::<Vec<_>>();
        let exact_lease = task_effects
            .first()
            .and_then(|effect| effect.intent.worker_lease.as_ref())
            .expect("task effects carry one exact attempt lease");
        assert!(task_effects.iter().all(|effect| {
            effect.intent.worker_id.as_deref() == Some(WORKER_ID)
                && effect.intent.worker_lease.as_ref() == Some(exact_lease)
        }));
        assert!(task_effects.iter().all(|effect| {
            effect.intent.kind == EffectKind::ProviderRequest || effect.dispatch_claim.is_some()
        }));
        assert!(sprint.effects.iter().all(|effect| {
            if effect.intent.kind == EffectKind::ProviderRequest && effect.intent.task_id.is_none()
            {
                effect.intent.worker_lease.is_none()
            } else if effect.intent.kind == EffectKind::CleanupWorkerDomain {
                effect.intent.task_id.is_none()
                    && effect.intent.worker_id.is_none()
                    && effect.intent.worker_lease.as_ref() == Some(exact_lease)
            } else {
                true
            }
        }));
        assert!(sprint.effects.iter().all(|effect| matches!(
            &effect.mutation_artifact,
            PersistedMutationArtifact::NotRequired
        )));
        let command_effect = sprint
            .effects
            .iter()
            .find(|effect| effect.intent.effect_id == command_effect_id)
            .expect("durable command effect");
        assert!(command_effect.dispatch_claim.is_some());
        assert_eq!(
            command_effect.intent.input_snapshot,
            harness.base.snapshot_id
        );
        let command: CommandSpec = serde_json::from_slice(&command_effect.request_bytes)
            .expect("decode exact baseline core command");
        assert_eq!(command, fixture_acceptance_command());
        let causal_call = ProviderToolCall {
            sprint_id: harness.spec.sprint_id.clone(),
            task_id: sprint
                .graph
                .as_ref()
                .and_then(|graph| graph.tasks.first())
                .map(|task| task.task_id.clone())
                .expect("persisted fake graph has its exact task identity"),
            sequence: 4,
            call_id: "fake-baseline-test".into(),
            idempotency_key: "fake-v1-04-baseline-test".into(),
            intent: ProviderToolIntent::RunCommand { command },
        };
        assert_eq!(
            command_effect.intent.correlation_id,
            provider_call_effect_correlation_id(
                &harness.spec.sprint_id,
                &causal_call,
                EffectKind::RunCommand,
            )
            .expect("derive exact command/provider causal join")
        );
        assert!(matches!(
            command_effect
                .observation
                .as_ref()
                .map(|observation| &observation.outcome),
            Some(EffectOutcome::FailedBeforeEffect { .. })
        ));
        assert!(
            decode_tool_result(
                command_effect
                    .evidence_bytes
                    .as_deref()
                    .expect("containment evidence")
            )
            .is_err()
        );
    }

    #[test]
    fn crash_after_planning_intent_never_replays_provider_request() {
        let harness = Harness::new("crash-after-intent");
        let provider = CountingProvider::default();
        harness.initialize(provider.clone());

        let mut first_process = harness.coordinator(provider.clone());
        let paused = first_process
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
            .expect("persist planning intent");
        assert!(matches!(
            paused,
            WalkingSkeletonStatus::PlanningIntentDurable { .. }
        ));
        assert_eq!(provider.planning_calls(), 0);
        drop(first_process);

        let mut restarted = harness.coordinator(provider.clone());
        let status = restarted
            .run_until_blocked(
                &harness.spec.sprint_id,
                &harness.authority,
                &harness.policy,
                &harness.shadow,
                3_000,
            )
            .expect("restart must fail closed");
        assert!(matches!(
            status,
            WalkingSkeletonStatus::ReconciliationRequired {
                kind: EffectKind::ProviderRequest,
                ..
            }
        ));
        assert_eq!(provider.planning_calls(), 0);
        let sprint = restarted
            .load_sprint(&harness.spec.sprint_id)
            .expect("reload sprint");
        assert!(sprint.graph.is_none());
        assert_eq!(sprint.effects.len(), 1);
        assert!(sprint.effects[0].observation.is_none());
    }

    #[test]
    fn provider_profile_drift_is_rejected_before_intent_or_call() {
        let harness = Harness::new("provider-profile-drift");
        harness.initialize(CountingProvider::default());
        let provider = ProfileDriftProvider::default();
        let mut coordinator = DurableWalkingSkeleton::open(&harness.database, provider.clone())
            .expect("open drift coordinator");

        let error = coordinator
            .run_until_blocked(
                &harness.spec.sprint_id,
                &harness.authority,
                &harness.policy,
                &harness.shadow,
                2_000,
            )
            .expect_err("profile drift must fail closed");

        assert!(matches!(
            error,
            DurableCoordinatorError::Provider(ProviderError::ProfileMismatch { .. })
        ));
        assert_eq!(provider.calls.get(), 0);
        assert!(
            coordinator
                .load_sprint(&harness.spec.sprint_id)
                .expect("load untouched draft")
                .effects
                .is_empty()
        );
    }

    #[test]
    fn crash_after_provider_response_before_observation_never_replays() {
        let harness = Harness::new("crash-after-uncommitted-response");
        let provider = CountingProvider::default();
        harness.initialize(provider.clone());

        let mut first_process = harness.coordinator(provider.clone());
        let paused = first_process
            .run_until_blocked_inner(
                &harness.spec.sprint_id,
                &harness.authority,
                &harness.policy,
                &harness.shadow,
                2_000,
                PlanningPause::AfterProviderResponse,
                false,
                false,
            )
            .expect("invoke provider after durable intent");
        assert!(matches!(
            paused,
            WalkingSkeletonStatus::PlanningResponseNotDurable { .. }
        ));
        assert_eq!(provider.planning_calls(), 1);
        drop(first_process);

        let mut restarted = harness.coordinator(provider.clone());
        let status = restarted
            .run_until_blocked(
                &harness.spec.sprint_id,
                &harness.authority,
                &harness.policy,
                &harness.shadow,
                3_000,
            )
            .expect("restart must require reconciliation");
        assert!(matches!(
            status,
            WalkingSkeletonStatus::ReconciliationRequired {
                kind: EffectKind::ProviderRequest,
                ..
            }
        ));
        assert_eq!(provider.planning_calls(), 1);
        let sprint = restarted
            .load_sprint(&harness.spec.sprint_id)
            .expect("reload uncertain planning effect");
        assert!(sprint.graph.is_none());
        assert!(sprint.effects[0].observation.is_none());
    }

    #[test]
    fn absent_runner_lifecycle_reconciles_the_same_leased_attempt_without_new_effects() {
        let harness = Harness::new("runner-lifecycle-absent");
        let provider = CountingProvider::default();
        harness.initialize(provider.clone());

        let mut first = DurableWalkingSkeleton::open(&harness.database, provider.clone())
            .expect("open fail-closed coordinator");
        let error = first
            .run_until_blocked(
                &harness.spec.sprint_id,
                &harness.authority,
                &harness.policy,
                &harness.shadow,
                2_000,
            )
            .expect_err("absent runner authority must fail closed");
        assert!(matches!(
            error,
            DurableCoordinatorError::Protocol(ref message)
                if message.contains("runner lifecycle authority is unavailable")
        ));
        assert_eq!(provider.planning_calls(), 1);
        assert_eq!(provider.turn_calls(), 0);
        let before = first
            .load_sprint(&harness.spec.sprint_id)
            .expect("load leased fail-closed sprint");
        assert_eq!(before.effects.len(), 1);
        let task_id = before
            .graph
            .as_ref()
            .and_then(|graph| graph.tasks.first())
            .expect("attached one-task graph")
            .task_id
            .clone();
        let before_history = first
            .ledger
            .load_task_attempt_history(&harness.spec.sprint_id, &task_id)
            .expect("load exact leased attempt");
        assert_eq!(before_history.task_state, TaskState::Leased);
        let attempt = before_history
            .active_attempt()
            .expect("one active leased attempt")
            .attempt
            .clone();
        drop(first);

        let mut restarted = DurableWalkingSkeleton::open(&harness.database, provider.clone())
            .expect("reopen fail-closed coordinator");
        restarted
            .run_until_blocked(
                &harness.spec.sprint_id,
                &harness.authority,
                &harness.policy,
                &harness.shadow,
                4_000,
            )
            .expect_err("restart without runner authority must remain fail closed");
        assert_eq!(provider.planning_calls(), 1);
        assert_eq!(provider.turn_calls(), 0);
        let after = restarted
            .load_sprint(&harness.spec.sprint_id)
            .expect("reload unchanged leased sprint");
        assert_eq!(after.effects, before.effects);
        let after_history = restarted
            .ledger
            .load_task_attempt_history(&harness.spec.sprint_id, &task_id)
            .expect("reload exact leased attempt");
        assert_eq!(after_history.attempts.len(), 1);
        assert_eq!(
            after_history.active_attempt().map(|entry| &entry.attempt),
            Some(&attempt)
        );
        drop(restarted);

        let mut admitted = harness.coordinator(provider.clone());
        assert!(matches!(
            admitted
                .run_until_blocked(
                    &harness.spec.sprint_id,
                    &harness.authority,
                    &harness.policy,
                    &harness.shadow,
                    6_000,
                )
                .expect("injected lifecycle resumes the exact leased attempt"),
            WalkingSkeletonStatus::ContainmentNotReady { .. }
        ));
        let admitted_history = admitted
            .ledger
            .load_task_attempt_history(&harness.spec.sprint_id, &task_id)
            .expect("load resumed exact attempt");
        assert_eq!(admitted_history.task_state, TaskState::Running);
        assert_eq!(admitted_history.attempts.len(), 1);
        assert_eq!(
            admitted_history
                .active_attempt()
                .map(|entry| &entry.attempt),
            Some(&attempt)
        );
        assert_eq!(provider.planning_calls(), 1);
        assert_eq!(provider.turn_calls(), 4);
    }

    #[test]
    fn unpersisted_runner_boundary_is_rejected_before_any_task_effect() {
        let harness = Harness::new("runner-lifecycle-unpersisted");
        let provider = CountingProvider::default();
        harness.initialize(provider.clone());
        let mut coordinator = DurableWalkingSkeleton::open_with_runner_lifecycle(
            &harness.database,
            provider.clone(),
            UnpersistedRunnerLifecycle,
        )
        .expect("open mismatched runner coordinator");

        let error = coordinator
            .run_until_blocked(
                &harness.spec.sprint_id,
                &harness.authority,
                &harness.policy,
                &harness.shadow,
                2_000,
            )
            .expect_err("unpersisted Running boundary must fail closed");
        assert!(matches!(
            error,
            DurableCoordinatorError::Protocol(ref message)
                if message.contains("readback does not prove")
        ));
        assert_eq!(provider.planning_calls(), 1);
        assert_eq!(provider.turn_calls(), 0);
        let sprint = coordinator
            .load_sprint(&harness.spec.sprint_id)
            .expect("load fail-closed sprint");
        assert_eq!(sprint.effects.len(), 1);
        assert!(sprint.effects[0].intent.task_id.is_none());
    }

    #[test]
    fn task_tool_without_runner_session_binding_leaves_zero_new_rows() {
        let harness = Harness::new("task-tool-unbound");
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
            .expect("reach exact Running containment boundary");
        let before = coordinator
            .load_sprint(&harness.spec.sprint_id)
            .expect("load sprint before unbound proposal");
        let exemplar = before
            .effects
            .iter()
            .find(|effect| effect.intent.kind == EffectKind::ReadRelativeFile)
            .expect("bound task read exemplar");
        let mut unbound = exemplar.intent.clone();
        unbound.effect_id.push_str(":unbound");
        unbound.idempotency_key.push_str(":unbound");
        unbound.created_at_unix_ms = before
            .events
            .iter()
            .map(|event| event.occurred_at_unix_ms)
            .max()
            .expect("durable event time")
            .checked_add(1)
            .expect("test timestamp");

        let error = coordinator
            .commit_intent(&unbound, &exemplar.request_bytes, None)
            .expect_err("task tool without runner binding must fail before persistence");
        assert!(matches!(
            error,
            DurableCoordinatorError::Protocol(ref message)
                if message.contains("missing its exact runner-session binding")
        ));
        let after = coordinator
            .load_sprint(&harness.spec.sprint_id)
            .expect("reload sprint after unbound refusal");
        assert_eq!(after, before);
    }

    #[test]
    fn substituted_dispatch_authority_never_becomes_an_observation_or_replays() {
        for (label, behavior) in [
            (
                "dispatch-cross-attempt",
                ScriptedDispatchBehavior::SubstituteAttempt,
            ),
            (
                "dispatch-cross-session",
                ScriptedDispatchBehavior::SubstituteSession,
            ),
            (
                "dispatch-cross-intent",
                ScriptedDispatchBehavior::SubstituteIntent,
            ),
            (
                "dispatch-cross-request",
                ScriptedDispatchBehavior::SubstituteRequest,
            ),
            (
                "dispatch-cross-snapshot",
                ScriptedDispatchBehavior::SubstituteSnapshot,
            ),
            (
                "dispatch-cross-lease",
                ScriptedDispatchBehavior::SubstituteLease,
            ),
        ] {
            let harness = Harness::new(label);
            let provider = CountingProvider::default();
            harness.initialize(provider.clone());
            let dispatch_count = Rc::new(Cell::new(0));
            let mut coordinator = harness.coordinator_with_runner(
                provider.clone(),
                ScriptedRunnerLifecycle::new(behavior, Rc::clone(&dispatch_count)),
            );

            let error = coordinator
                .run_until_blocked(
                    &harness.spec.sprint_id,
                    &harness.authority,
                    &harness.policy,
                    &harness.shadow,
                    2_000,
                )
                .expect_err("crossed dispatcher response must fail closed");
            assert!(matches!(
                error,
                DurableCoordinatorError::Protocol(ref message)
                    if message.contains("runner response crossed")
            ));
            assert_eq!(dispatch_count.get(), 1);
            let sprint = coordinator
                .load_sprint(&harness.spec.sprint_id)
                .expect("load crossed response sprint");
            let unobserved = sprint
                .effects
                .iter()
                .find(|effect| {
                    effect.intent.kind != EffectKind::ProviderRequest
                        && effect.intent.kind != EffectKind::CleanupWorkerDomain
                })
                .expect("durable runner effect precedes dispatch");
            assert!(unobserved.observation.is_none());
            assert!(unobserved.dispatch_claim.is_some());
            drop(coordinator);

            let mut restarted = harness.coordinator_with_runner(
                provider,
                ScriptedRunnerLifecycle::new(
                    ScriptedDispatchBehavior::Exact,
                    Rc::clone(&dispatch_count),
                ),
            );
            let status = restarted
                .run_until_blocked(
                    &harness.spec.sprint_id,
                    &harness.authority,
                    &harness.policy,
                    &harness.shadow,
                    4_000,
                )
                .expect("crossed response leaves reconciliation-only intent");
            assert!(matches!(
                status,
                WalkingSkeletonStatus::ReconciliationRequired {
                    kind: EffectKind::ReadRelativeFile,
                    ..
                }
            ));
            assert_eq!(dispatch_count.get(), 1);
        }
    }

    #[test]
    fn a_response_from_the_previous_effect_cannot_cross_into_the_next_effect() {
        let harness = Harness::new("dispatch-cross-previous-response");
        let provider = CountingProvider::default();
        harness.initialize(provider.clone());
        let dispatch_count = Rc::new(Cell::new(0));
        let mut coordinator = harness.coordinator_with_runner(
            provider.clone(),
            ScriptedRunnerLifecycle::new(
                ScriptedDispatchBehavior::CrossPreviousResponse,
                Rc::clone(&dispatch_count),
            ),
        );

        let error = coordinator
            .run_until_blocked(
                &harness.spec.sprint_id,
                &harness.authority,
                &harness.policy,
                &harness.shadow,
                2_000,
            )
            .expect_err("a prior response cannot observe a later effect");
        assert!(matches!(
            error,
            DurableCoordinatorError::Protocol(ref message)
                if message.contains("runner response crossed")
        ));
        assert_eq!(dispatch_count.get(), 2);
        let sprint = coordinator
            .load_sprint(&harness.spec.sprint_id)
            .expect("load response-crossing sprint");
        let runner_effects = sprint
            .effects
            .iter()
            .filter(|effect| {
                effect.intent.kind != EffectKind::ProviderRequest
                    && effect.intent.kind != EffectKind::CleanupWorkerDomain
            })
            .collect::<Vec<_>>();
        assert_eq!(runner_effects.len(), 2);
        assert!(matches!(
            runner_effects[0]
                .observation
                .as_ref()
                .map(|observation| &observation.outcome),
            Some(EffectOutcome::Succeeded { .. })
        ));
        assert!(runner_effects[0].dispatch_claim.is_some());
        assert!(runner_effects[1].observation.is_none());
        assert!(runner_effects[1].dispatch_claim.is_some());
    }

    #[test]
    fn correlated_unknown_after_dispatch_is_terminal_and_never_redispatched() {
        let harness = Harness::new("dispatch-correlated-unknown");
        let provider = CountingProvider::default();
        harness.initialize(provider.clone());
        let dispatch_count = Rc::new(Cell::new(0));
        let mut first = harness.coordinator_with_runner(
            provider.clone(),
            ScriptedRunnerLifecycle::new(
                ScriptedDispatchBehavior::ClaimedUnknownAfterDispatch,
                Rc::clone(&dispatch_count),
            ),
        );
        let status = first
            .run_until_blocked(
                &harness.spec.sprint_id,
                &harness.authority,
                &harness.policy,
                &harness.shadow,
                2_000,
            )
            .expect("correlated ambiguity becomes typed Unknown evidence");
        assert!(matches!(
            status,
            WalkingSkeletonStatus::TaskEffectOutcomeUnknown { .. }
        ));
        assert_eq!(dispatch_count.get(), 1);
        let sprint = first
            .load_sprint(&harness.spec.sprint_id)
            .expect("load unknown dispatch result");
        let effect = sprint
            .effects
            .iter()
            .find(|effect| effect.intent.kind == EffectKind::ReadRelativeFile)
            .expect("unknown runner read");
        assert!(matches!(
            effect
                .observation
                .as_ref()
                .map(|observation| &observation.outcome),
            Some(EffectOutcome::Unknown { .. })
        ));
        assert!(effect.dispatch_claim.is_some());
        assert_eq!(
            effect.evidence_bytes.as_deref(),
            Some(CLAIMED_STARTED_FAILURE_EVIDENCE)
        );
        let effect_id = effect.intent.effect_id.clone();
        drop(first);

        let mut restarted = harness.coordinator_with_runner(
            provider,
            ScriptedRunnerLifecycle::new(
                ScriptedDispatchBehavior::Exact,
                Rc::clone(&dispatch_count),
            ),
        );
        let status = restarted
            .run_until_blocked(
                &harness.spec.sprint_id,
                &harness.authority,
                &harness.policy,
                &harness.shadow,
                4_000,
            )
            .expect("terminal Unknown remains exact typed readback");
        assert!(matches!(
            status,
            WalkingSkeletonStatus::TaskEffectOutcomeUnknown {
                effect_id: recovered_effect_id,
                reason,
            } if recovered_effect_id == effect_id
                && reason == "recovered task effect has an unresolved external outcome"
        ));
        assert_eq!(dispatch_count.get(), 1);
    }

    #[test]
    fn correlated_pre_effect_failure_is_terminal_and_never_redispatched() {
        let harness = Harness::new("dispatch-correlated-pre-effect-failure");
        let provider = CountingProvider::default();
        harness.initialize(provider.clone());
        let dispatch_count = Rc::new(Cell::new(0));
        let mut first = harness.coordinator_with_runner(
            provider.clone(),
            ScriptedRunnerLifecycle::new(
                ScriptedDispatchBehavior::ClaimedFailedBeforeEffect,
                Rc::clone(&dispatch_count),
            ),
        );
        let status = first
            .run_until_blocked(
                &harness.spec.sprint_id,
                &harness.authority,
                &harness.policy,
                &harness.shadow,
                2_000,
            )
            .expect("correlated refusal becomes typed failed-before-effect evidence");
        assert!(matches!(
            status,
            WalkingSkeletonStatus::TaskEffectFailedBeforeEffect { .. }
        ));
        assert_eq!(dispatch_count.get(), 1);
        let sprint = first
            .load_sprint(&harness.spec.sprint_id)
            .expect("load claimed pre-effect result");
        let effect = sprint
            .effects
            .iter()
            .find(|effect| effect.intent.kind == EffectKind::ReadRelativeFile)
            .expect("claimed failed-before runner read");
        assert_eq!(
            effect.evidence_bytes.as_deref(),
            Some(CLAIMED_ZERO_FAILURE_EVIDENCE)
        );
        let effect_id = effect.intent.effect_id.clone();
        drop(first);

        let mut restarted = harness.coordinator_with_runner(
            provider,
            ScriptedRunnerLifecycle::new(
                ScriptedDispatchBehavior::Exact,
                Rc::clone(&dispatch_count),
            ),
        );
        let status = restarted
            .run_until_blocked(
                &harness.spec.sprint_id,
                &harness.authority,
                &harness.policy,
                &harness.shadow,
                4_000,
            )
            .expect("terminal pre-effect failure remains exact typed readback");
        assert!(matches!(
            status,
            WalkingSkeletonStatus::TaskEffectFailedBeforeEffect {
                effect_id: recovered_effect_id,
                reason,
            } if recovered_effect_id == effect_id
                && reason == "recovered task effect is durably terminal before native execution"
        ));
        assert_eq!(dispatch_count.get(), 1);
    }

    #[test]
    fn transient_claimed_terminal_precommit_retries_exact_unknown_and_refusal_without_redispatch() {
        for (label, behavior, expect_unknown) in [
            (
                "unknown",
                ScriptedDispatchBehavior::ClaimedUnknownAfterDispatch,
                true,
            ),
            (
                "refusal",
                ScriptedDispatchBehavior::ClaimedFailedBeforeEffect,
                false,
            ),
        ] {
            let harness = Harness::new(&format!("claimed-terminal-retry-{label}"));
            let provider = CountingProvider::default();
            harness.initialize(provider.clone());
            let dispatch_count = Rc::new(Cell::new(0));
            let mut coordinator = harness.coordinator_with_runner(
                provider.clone(),
                ScriptedRunnerLifecycle::new(behavior, Rc::clone(&dispatch_count)),
            );
            coordinator.inject_claimed_terminal_precommit_failure_for_test(LedgerError::Io(
                io::Error::other("injected transient precommit failure"),
            ));

            let error = coordinator
                .run_until_blocked(
                    &harness.spec.sprint_id,
                    &harness.authority,
                    &harness.policy,
                    &harness.shadow,
                    2_000,
                )
                .expect_err("injected terminal persistence failure retains exact retry custody");
            assert!(matches!(
                error,
                DurableCoordinatorError::Ledger(LedgerError::Io(_))
            ));
            assert_eq!(dispatch_count.get(), 1, "{label} dispatched once");
            assert_eq!(provider.turn_calls(), 1, "{label} called provider once");

            let status = coordinator
                .run_until_blocked(
                    &harness.spec.sprint_id,
                    &harness.authority,
                    &harness.policy,
                    &harness.shadow,
                    3_000,
                )
                .expect("retry persists the same terminal preimage before any new action");
            assert_eq!(
                matches!(
                    status,
                    WalkingSkeletonStatus::TaskEffectOutcomeUnknown { .. }
                ),
                expect_unknown,
                "{label} preserves the claimed terminal class"
            );
            assert_eq!(
                dispatch_count.get(),
                1,
                "{label} did not redispatch native work"
            );
            assert_eq!(
                provider.turn_calls(),
                1,
                "{label} did not rerun the provider"
            );
        }
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "the regression proves crossed-sprint rejection, durable nonmutation, and retained move-only retry custody in one lifecycle"
    )]
    fn pending_claimed_terminal_custody_rejects_cross_sprint_calls_and_remains_retryable() {
        let harness = Harness::new("claimed-terminal-cross-sprint");
        let provider = CountingProvider::default();
        let dispatch_count = Rc::new(Cell::new(0));
        let mut coordinator = harness.coordinator_with_runner(
            provider.clone(),
            ScriptedRunnerLifecycle::new(
                ScriptedDispatchBehavior::ClaimedFailedBeforeEffect,
                Rc::clone(&dispatch_count),
            ),
        );

        coordinator
            .create_draft(&harness.authority, &harness.spec, &harness.base, 1_001)
            .expect("create custody sprint");
        let mut other_spec = harness.spec.clone();
        other_spec.sprint_id = format!("{}-other", harness.spec.sprint_id);
        coordinator
            .create_draft(&harness.authority, &other_spec, &harness.base, 1_002)
            .expect("create other sprint");

        coordinator.inject_claimed_terminal_precommit_failure_for_test(LedgerError::Io(
            io::Error::other("injected custody-sprint terminal failure"),
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
                provider.planning_calls(),
                provider.turn_calls(),
                dispatch_count.get(),
            ),
            (1, 1, 1)
        );

        let custody_snapshot_before = coordinator
            .load_sprint(&harness.spec.sprint_id)
            .expect("load custody sprint before crossed call");
        let untouched_draft_before = coordinator
            .load_sprint(&other_spec.sprint_id)
            .expect("load other sprint before crossed call");
        let pending_effect_id = custody_snapshot_before
            .effects
            .iter()
            .find(|effect| effect.dispatch_claim.is_some() && effect.observation.is_none())
            .expect("custody sprint retains one exact unobserved claimed effect")
            .intent
            .effect_id
            .clone();

        let expected_error = format!(
            "pending claimed-terminal custody is bound to sprint '{}', not requested sprint '{}'",
            harness.spec.sprint_id, other_spec.sprint_id
        );
        let error = coordinator
            .run_until_blocked(
                &other_spec.sprint_id,
                &harness.authority,
                &harness.policy,
                &harness.shadow,
                3_000,
            )
            .expect_err("other sprint cannot consume retained custody");
        assert!(matches!(
            error,
            DurableCoordinatorError::Protocol(ref message) if message == &expected_error
        ));
        assert_eq!(
            (
                provider.planning_calls(),
                provider.turn_calls(),
                dispatch_count.get(),
            ),
            (1, 1, 1),
            "crossed call performed no provider or runner work"
        );
        assert_eq!(
            coordinator
                .load_sprint(&harness.spec.sprint_id)
                .expect("reload unchanged custody sprint"),
            custody_snapshot_before,
            "crossed call did not mutate the custody sprint"
        );
        assert_eq!(
            coordinator
                .load_sprint(&other_spec.sprint_id)
                .expect("reload unchanged other sprint"),
            untouched_draft_before,
            "crossed call did not mutate the other sprint"
        );

        assert!(matches!(
            coordinator
                .run_until_blocked(
                    &harness.spec.sprint_id,
                    &harness.authority,
                    &harness.policy,
                    &harness.shadow,
                    4_000,
                )
                .expect("custody sprint retains exact retry authority"),
            WalkingSkeletonStatus::TaskEffectFailedBeforeEffect {
                effect_id,
                reason,
            } if effect_id == pending_effect_id
                && reason == "claimed transport accepted zero request bytes"
        ));
        assert_eq!(
            (
                provider.planning_calls(),
                provider.turn_calls(),
                dispatch_count.get(),
            ),
            (1, 1, 1),
            "retry persisted the original terminal without replay"
        );
        assert_eq!(
            coordinator
                .load_sprint(&other_spec.sprint_id)
                .expect("other sprint remains unchanged after custody retry"),
            untouched_draft_before
        );
    }

    #[test]
    fn successful_generic_and_mutation_terminals_retry_without_replaying_effects() {
        let generic = Harness::new("claimed-terminal-generic-retry");
        let generic_provider = CountingProvider::default();
        generic.initialize(generic_provider.clone());
        let generic_dispatches = Rc::new(Cell::new(0));
        let mut generic_coordinator = generic.coordinator_with_runner(
            generic_provider.clone(),
            ScriptedRunnerLifecycle::new(
                ScriptedDispatchBehavior::Exact,
                Rc::clone(&generic_dispatches),
            ),
        );
        generic_coordinator.inject_claimed_terminal_precommit_failure_for_test(LedgerError::Io(
            io::Error::other("injected generic terminal failure"),
        ));
        generic_coordinator
            .run_until_blocked(
                &generic.spec.sprint_id,
                &generic.authority,
                &generic.policy,
                &generic.shadow,
                2_000,
            )
            .expect_err("first read terminal write is intentionally transiently unavailable");
        assert_eq!(generic_dispatches.get(), 1);
        assert_eq!(generic_provider.turn_calls(), 1);
        assert!(matches!(
            generic_coordinator
                .run_until_blocked(
                    &generic.spec.sprint_id,
                    &generic.authority,
                    &generic.policy,
                    &generic.shadow,
                    3_000,
                )
                .expect("retry records exact read and resumes only from durable transcript"),
            WalkingSkeletonStatus::ContainmentNotReady { .. }
        ));
        assert_eq!(
            generic_dispatches.get(),
            4,
            "each of the four provider tool effects was dispatched exactly once"
        );
        assert_eq!(
            generic_provider.turn_calls(),
            4,
            "first provider turn was recovered"
        );

        let mutation = Harness::new("claimed-terminal-mutation-retry");
        let mutation_provider =
            MutationProvider::new(vec![ProviderToolIntent::CreateRegularFile {
                path: PathBuf::from("docs/retry.txt"),
                contents: b"exact mutation\n".to_vec(),
            }]);
        let mutation_dispatches = Rc::new(Cell::new(0));
        let mut mutation_coordinator = DurableWalkingSkeleton::open_with_runner_lifecycle(
            &mutation.database,
            mutation_provider.clone(),
            ScriptedRunnerLifecycle::new(
                ScriptedDispatchBehavior::Exact,
                Rc::clone(&mutation_dispatches),
            ),
        )
        .expect("open mutation retry coordinator");
        mutation_coordinator
            .create_draft(&mutation.authority, &mutation.spec, &mutation.base, 1_001)
            .expect("create mutation retry sprint");
        mutation_coordinator.inject_claimed_terminal_precommit_failure_for_test(LedgerError::Io(
            io::Error::other("injected mutation terminal failure"),
        ));
        mutation_coordinator
            .run_until_blocked(
                &mutation.spec.sprint_id,
                &mutation.authority,
                &mutation.policy,
                &mutation.shadow,
                2_000,
            )
            .expect_err("mutation terminal write is intentionally transiently unavailable");
        assert_eq!(mutation_dispatches.get(), 1);
        assert_eq!(mutation_provider.turn_calls(), 1);
        assert!(matches!(
            mutation_coordinator
                .run_until_blocked(
                    &mutation.spec.sprint_id,
                    &mutation.authority,
                    &mutation.policy,
                    &mutation.shadow,
                    3_000,
                )
                .expect("retry commits the original mutation artifacts"),
            WalkingSkeletonStatus::ReadyForApplication { .. }
        ));
        assert_eq!(mutation_dispatches.get(), 1, "mutation was not replayed");
        assert_eq!(
            mutation_provider.turn_calls(),
            2,
            "mutation turn was recovered"
        );
    }

    #[test]
    fn pending_terminal_custody_is_not_reminted_after_restart_and_semantic_failures_do_not_loop() {
        let restart = Harness::new("claimed-terminal-crash-no-remint");
        let restart_provider = CountingProvider::default();
        restart.initialize(restart_provider.clone());
        let dispatch_count = Rc::new(Cell::new(0));
        let mut first = restart.coordinator_with_runner(
            restart_provider.clone(),
            ScriptedRunnerLifecycle::new(
                ScriptedDispatchBehavior::Exact,
                Rc::clone(&dispatch_count),
            ),
        );
        first.inject_claimed_terminal_precommit_failure_for_test(LedgerError::Io(
            io::Error::other("injected crash-window precommit failure"),
        ));
        first
            .run_until_blocked(
                &restart.spec.sprint_id,
                &restart.authority,
                &restart.policy,
                &restart.shadow,
                2_000,
            )
            .expect_err("retain in-memory custody before simulated crash");
        assert_eq!(dispatch_count.get(), 1);
        drop(first);
        let mut restarted = restart.coordinator_with_runner(
            restart_provider.clone(),
            ScriptedRunnerLifecycle::new(
                ScriptedDispatchBehavior::Exact,
                Rc::clone(&dispatch_count),
            ),
        );
        assert!(matches!(
            restarted
                .run_until_blocked(
                    &restart.spec.sprint_id,
                    &restart.authority,
                    &restart.policy,
                    &restart.shadow,
                    3_000,
                )
                .expect("restart observes the unobserved claim as reconciliation-only"),
            WalkingSkeletonStatus::ReconciliationRequired {
                kind: EffectKind::ReadRelativeFile,
                ..
            }
        ));
        assert_eq!(
            dispatch_count.get(),
            1,
            "restart did not remint or redispatch"
        );
        assert_eq!(
            restart_provider.turn_calls(),
            1,
            "restart did not replay provider turn"
        );

        let semantic = Harness::new("claimed-terminal-semantic-no-loop");
        let semantic_provider = CountingProvider::default();
        semantic.initialize(semantic_provider.clone());
        let semantic_dispatches = Rc::new(Cell::new(0));
        let mut coordinator = semantic.coordinator_with_runner(
            semantic_provider.clone(),
            ScriptedRunnerLifecycle::new(
                ScriptedDispatchBehavior::Exact,
                Rc::clone(&semantic_dispatches),
            ),
        );
        coordinator.inject_claimed_terminal_precommit_failure_for_test(LedgerError::ReadOnly);
        assert!(matches!(
            coordinator
                .run_until_blocked(
                    &semantic.spec.sprint_id,
                    &semantic.authority,
                    &semantic.policy,
                    &semantic.shadow,
                    2_000,
                )
                .expect_err("synthetic deterministic write rejection is surfaced once"),
            DurableCoordinatorError::Ledger(LedgerError::ReadOnly)
        ));
        assert!(matches!(
            coordinator
                .run_until_blocked(
                    &semantic.spec.sprint_id,
                    &semantic.authority,
                    &semantic.policy,
                    &semantic.shadow,
                    3_000,
                )
                .expect("semantic rejection does not retain a retry loop"),
            WalkingSkeletonStatus::ReconciliationRequired {
                kind: EffectKind::ReadRelativeFile,
                ..
            }
        ));
        assert_eq!(semantic_dispatches.get(), 1);
        assert_eq!(semantic_provider.turn_calls(), 1);
    }

    #[test]
    fn claimed_terminal_retry_bound_ends_in_reconciliation_without_redispatch() {
        let harness = Harness::new("claimed-terminal-retry-bound");
        let provider = CountingProvider::default();
        harness.initialize(provider.clone());
        let dispatch_count = Rc::new(Cell::new(0));
        let mut coordinator = harness.coordinator_with_runner(
            provider.clone(),
            ScriptedRunnerLifecycle::new(
                ScriptedDispatchBehavior::Exact,
                Rc::clone(&dispatch_count),
            ),
        );
        for now in [2_000_u64, 3_000] {
            coordinator.inject_claimed_terminal_precommit_failure_for_test(LedgerError::Io(
                io::Error::other("injected bounded retry failure"),
            ));
            assert!(matches!(
                coordinator.run_until_blocked(
                    &harness.spec.sprint_id,
                    &harness.authority,
                    &harness.policy,
                    &harness.shadow,
                    now,
                ),
                Err(DurableCoordinatorError::Ledger(LedgerError::Io(_)))
            ));
        }
        coordinator.inject_claimed_terminal_precommit_failure_for_test(LedgerError::Io(
            io::Error::other("injected final bounded retry failure"),
        ));
        assert!(matches!(
            coordinator
                .run_until_blocked(
                    &harness.spec.sprint_id,
                    &harness.authority,
                    &harness.policy,
                    &harness.shadow,
                    4_000,
                )
                .expect("second retry exhaustion is reconciliation-only"),
            WalkingSkeletonStatus::ReconciliationRequired {
                kind: EffectKind::ReadRelativeFile,
                ..
            }
        ));
        assert_eq!(dispatch_count.get(), 1);
        assert_eq!(provider.turn_calls(), 1);
    }

    #[test]
    fn unfinished_dispatch_is_never_duplicated_after_restart() {
        let harness = Harness::new("dispatch-unfinished-no-replay");
        let provider = CountingProvider::default();
        harness.initialize(provider.clone());
        let dispatch_count = Rc::new(Cell::new(0));
        let mut first = harness.coordinator_with_runner(
            provider.clone(),
            ScriptedRunnerLifecycle::new(
                ScriptedDispatchBehavior::ErrorAfterDispatch,
                Rc::clone(&dispatch_count),
            ),
        );
        first
            .run_until_blocked(
                &harness.spec.sprint_id,
                &harness.authority,
                &harness.policy,
                &harness.shadow,
                2_000,
            )
            .expect_err("transport loss leaves an unobserved durable intent");
        assert_eq!(dispatch_count.get(), 1);
        let before = first
            .load_sprint(&harness.spec.sprint_id)
            .expect("load unfinished dispatch");
        assert!(before.effects.iter().any(|effect| {
            effect.intent.kind == EffectKind::ReadRelativeFile
                && effect.observation.is_none()
                && effect.dispatch_claim.is_some()
        }));
        drop(first);

        let mut restarted = harness.coordinator_with_runner(
            provider,
            ScriptedRunnerLifecycle::new(
                ScriptedDispatchBehavior::Exact,
                Rc::clone(&dispatch_count),
            ),
        );
        let status = restarted
            .run_until_blocked(
                &harness.spec.sprint_id,
                &harness.authority,
                &harness.policy,
                &harness.shadow,
                4_000,
            )
            .expect("unfinished dispatch requires reconciliation");
        assert!(matches!(
            status,
            WalkingSkeletonStatus::ReconciliationRequired {
                kind: EffectKind::ReadRelativeFile,
                ..
            }
        ));
        assert_eq!(dispatch_count.get(), 1);
        assert_eq!(
            restarted
                .load_sprint(&harness.spec.sprint_id)
                .expect("reload unchanged unfinished dispatch")
                .effects,
            before.effects
        );
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "the focused restart test asserts the complete physical capture and cleanup lifecycle"
    )]
    fn command_containment_dispatch_abandons_exact_capture_and_restart_does_not_redispatch() {
        let harness = Harness::new("command-permit-pretransport-refusal");
        let provider = CountingProvider::default();
        harness.initialize(provider.clone());
        let dispatch_count = Rc::new(Cell::new(0));
        let mut coordinator = harness.coordinator_with_runner(
            provider.clone(),
            ScriptedRunnerLifecycle::new(
                ScriptedDispatchBehavior::Exact,
                Rc::clone(&dispatch_count),
            ),
        );

        let status = coordinator
            .run_until_blocked(
                &harness.spec.sprint_id,
                &harness.authority,
                &harness.policy,
                &harness.shadow,
                2_000,
            )
            .expect("command remains durably refused before native dispatch");
        assert!(matches!(
            status,
            WalkingSkeletonStatus::ContainmentNotReady { .. }
        ));

        let sprint = coordinator
            .load_sprint(&harness.spec.sprint_id)
            .expect("load pretransport containment evidence");
        let non_command_dispatches = sprint
            .effects
            .iter()
            .filter(|effect| {
                !matches!(
                    effect.intent.kind,
                    EffectKind::ProviderRequest
                        | EffectKind::CleanupWorkerDomain
                        | EffectKind::RunCommand
                )
            })
            .count();
        assert_eq!(
            usize::try_from(dispatch_count.get()).expect("dispatch count fits usize"),
            non_command_dispatches + 1
        );
        let command = sprint
            .effects
            .iter()
            .find(|effect| effect.intent.kind == EffectKind::RunCommand)
            .expect("one durable command refusal");
        assert!(command.dispatch_claim.is_some());
        assert!(matches!(
            command
                .observation
                .as_ref()
                .map(|observation| &observation.outcome),
            Some(EffectOutcome::FailedBeforeEffect { .. })
        ));
        let capture = coordinator
            .ledger
            .load_command_output_capture_for_effect(&command.intent.effect_id)
            .expect("load exact ordinary command capture");
        let terminal = capture
            .terminal
            .as_ref()
            .expect("ordinary command capture is terminal");
        assert!(capture.acquired.is_some());
        assert_eq!(
            terminal.disposition,
            CommandOutputCaptureTerminalDispositionV1::Abandoned
        );
        assert_eq!(
            capture.reconciliation_obligation_closure.as_ref(),
            Some(&terminal.terminal_anchor_digest)
        );
        let cleanup = coordinator
            .ledger
            .load_command_domain_cleanup_proof(&command.intent.effect_id)
            .expect("load exact ordinary command no-domain proof");
        assert_eq!(
            cleanup.proof.disposition,
            CommandDomainCleanupDisposition::NoDomainCreatedBeforeEffect
        );
        assert_eq!(cleanup.proof.surviving_processes, 0);
        let (_, store, _) = strict_fake_command_output_store(
            &harness.authority,
            &capture.intent.source.runner_launch_id,
        )
        .expect("open exact strict-fake command store");
        let recovered_capture = store
            .reopen_capture(&capture.intent.capture_id)
            .expect("reopen exact abandoned capture");
        assert_eq!(
            recovered_capture.state(),
            CommandOutputCaptureJournalStateV1::Cleaned
        );

        let dispatches_before_restart = dispatch_count.get();
        drop(coordinator);
        let mut restarted = harness.coordinator_with_runner(
            provider,
            ScriptedRunnerLifecycle::new(
                ScriptedDispatchBehavior::Exact,
                Rc::clone(&dispatch_count),
            ),
        );
        let restarted_status = restarted
            .run_until_blocked(
                &harness.spec.sprint_id,
                &harness.authority,
                &harness.policy,
                &harness.shadow,
                4_000,
            )
            .expect("restart reads exact abandoned command without redispatch");
        assert!(matches!(
            restarted_status,
            WalkingSkeletonStatus::ContainmentNotReady { .. }
        ));
        assert_eq!(dispatch_count.get(), dispatches_before_restart);
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "the focused restart test proves both provider-call causality and command capture/cleanup closure before refusing redispatch"
    )]
    fn successful_ordinary_command_restart_rejoins_call_capture_artifacts_and_cleanup() {
        let harness = Harness::new("successful-command-restart-readback");
        let provider = FailAtProviderTurn::new(5);
        harness.initialize(provider.clone());
        let dispatch_count = Rc::new(Cell::new(0));
        let mut first = harness.coordinator_with_runner(
            provider.clone(),
            ScriptedRunnerLifecycle::new(
                ScriptedDispatchBehavior::SuccessfulCommand,
                Rc::clone(&dispatch_count),
            ),
        );

        first
            .run_until_blocked(
                &harness.spec.sprint_id,
                &harness.authority,
                &harness.policy,
                &harness.shadow,
                2_000,
            )
            .expect_err("injected provider stop follows the first successful ordinary command");
        assert_eq!(provider.turn_calls(), 5);
        let sprint = first
            .load_sprint(&harness.spec.sprint_id)
            .expect("load first successful ordinary command");
        let graph = sprint.graph.as_ref().expect("load command task graph");
        let task = graph.tasks.first().expect("load command task");
        let active = first
            .ledger
            .load_task_attempt_history(&harness.spec.sprint_id, &task.task_id)
            .expect("load command attempt history")
            .active_attempt()
            .expect("provider ambiguity retains the exact active attempt")
            .attempt
            .clone();
        let command_key = task_lease_provider_call_effect_key(
            &active.worker_lease.lease_id,
            "fake-v1-04-baseline-test",
        );
        let command = sprint
            .effects
            .iter()
            .find(|effect| effect.intent.idempotency_key == command_key)
            .expect("load exact first ordinary command");
        assert!(matches!(
            command
                .observation
                .as_ref()
                .map(|observation| &observation.outcome),
            Some(EffectOutcome::Succeeded { .. })
        ));
        let result = decode_tool_result(
            command
                .evidence_bytes
                .as_deref()
                .expect("ordinary success has provider result evidence"),
        )
        .expect("decode ordinary command provider result");
        validate_recovered_command_terminal(&first.ledger, command, &result)
            .expect("freshly committed command has exact restart closure");
        let projection = DurableUiProjection::from_persisted(&sprint)
            .expect("project successful command from its exact causal provider turn");
        assert!(projection.events().iter().any(|event| matches!(
            event.payload(),
            DurableUiEventKind::EffectSucceeded { effect_id, .. }
                if effect_id == &command.intent.effect_id
        )));
        let capture = first
            .ledger
            .load_command_output_capture_for_effect(&command.intent.effect_id)
            .expect("load ordinary command capture");
        let terminal = capture
            .terminal
            .as_ref()
            .expect("ordinary command has published capture terminal");
        assert_eq!(
            terminal.disposition,
            CommandOutputCaptureTerminalDispositionV1::Published
        );
        assert_eq!(
            terminal.observation_class,
            CommandOutputCaptureObservationClassV1::Succeeded
        );
        assert!(terminal.artifact_reference.is_some());
        assert_eq!(
            capture.reconciliation_obligation_closure.as_ref(),
            Some(&terminal.terminal_anchor_digest)
        );
        let cleanup = first
            .ledger
            .load_command_domain_cleanup_proof(&command.intent.effect_id)
            .expect("load exact successful command cleanup proof");
        assert_eq!(cleanup.binding.state, CommandDomainEffectState::Succeeded);
        assert_eq!(
            cleanup.proof.disposition,
            CommandDomainCleanupDisposition::ReapedZeroSurvivors
        );
        assert_eq!(cleanup.proof.surviving_processes, 0);

        let dispatches_before_restart = dispatch_count.get();
        let provider_calls_before_restart = provider.turn_calls();
        drop(first);
        let mut restarted = harness.coordinator_with_runner(
            provider.clone(),
            ScriptedRunnerLifecycle::new(
                ScriptedDispatchBehavior::SuccessfulCommand,
                Rc::clone(&dispatch_count),
            ),
        );
        let status = restarted
            .run_until_blocked(
                &harness.spec.sprint_id,
                &harness.authority,
                &harness.policy,
                &harness.shadow,
                4_000,
            )
            .expect("restart replays durable success before the known provider ambiguity");
        assert!(matches!(
            status,
            WalkingSkeletonStatus::ReconciliationRequired {
                kind: EffectKind::ProviderRequest,
                ..
            }
        ));
        assert_eq!(dispatch_count.get(), dispatches_before_restart);
        assert_eq!(provider.turn_calls(), provider_calls_before_restart);
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "one end-to-end scenario proves v29 rejection, cleanup, receipt absence, restart readback, and no redispatch"
    )]
    fn sensitive_ordinary_command_is_v29_closed_without_verification_or_redispatch() {
        let harness = Harness::new("sensitive-ordinary-command-v29");
        let provider = FailAtProviderTurn::new(5);
        harness.initialize(provider.clone());
        let dispatch_count = Rc::new(Cell::new(0));
        let first_runner = ScriptedRunnerLifecycle::new(
            ScriptedDispatchBehavior::SensitiveOutputRejected,
            Rc::clone(&dispatch_count),
        );
        let first_cleanup_count = first_runner.sensitive_cleanup_count();
        let mut first = harness.coordinator_with_runner(provider.clone(), first_runner);

        let status = first
            .run_until_blocked(
                &harness.spec.sprint_id,
                &harness.authority,
                &harness.policy,
                &harness.shadow,
                2_000,
            )
            .expect("persist typed sensitive-output rejection");
        let WalkingSkeletonStatus::TaskAttemptsExhausted {
            ref attempt_id,
            ref launch_id,
            ..
        } = status
        else {
            panic!("unexpected sensitive ordinary status: {status:?}")
        };
        assert_eq!(first_cleanup_count.get(), 1);
        let sprint = first
            .load_sprint(&harness.spec.sprint_id)
            .expect("load sensitive ordinary sprint effects");
        let effect_id = sprint
            .effects
            .iter()
            .find(|effect| {
                effect.intent.kind == EffectKind::RunCommand
                    && matches!(
                        effect.observation.as_ref().map(|value| &value.outcome),
                        Some(EffectOutcome::FailedAfterKnownEffect { .. })
                    )
            })
            .map(|effect| effect.intent.effect_id.clone())
            .expect("find exact rejected ordinary command");
        let completed = first
            .ledger
            .load_effect(&effect_id)
            .expect("load sensitive ordinary effect");
        assert!(matches!(
            completed.observation.as_ref().map(|value| &value.outcome),
            Some(EffectOutcome::FailedAfterKnownEffect { .. })
        ));
        assert_eq!(
            completed.finish_receipt,
            PersistedFinishReceipt::NotRequired
        );
        let rejection = first
            .ledger
            .load_command_output_sensitive_rejection_for_effect(&effect_id)
            .expect("load authoritative ordinary v29 rejection");
        assert_eq!(rejection.anchor.termination, CommandTerminationV1::Canceled);
        assert_eq!(rejection.anchor.effect_id, effect_id);
        let capture = first
            .ledger
            .load_command_output_capture_for_effect(&effect_id)
            .expect("load rejected ordinary capture");
        assert!(capture.terminal.is_none());
        let cleanup = first
            .ledger
            .load_command_domain_cleanup_proof(&effect_id)
            .expect("load ordinary zero-survivor proof");
        assert_eq!(
            cleanup.proof.disposition,
            CommandDomainCleanupDisposition::ReapedZeroSurvivors
        );
        assert_eq!(cleanup.proof.surviving_processes, 0);
        assert!(matches!(
            first
                .ledger
                .load_verification_receipt(&final_verification_identity(
                    &harness.spec.sprint_id,
                    "receipt"
                )),
            Err(LedgerError::ArtifactNotFound { .. })
        ));
        // `PersistedSprint` carries only the caller-shapeable v27 effect image;
        // it does not carry the independently loaded v29 cleanup/closure join.
        let caller_shaped_v27_image = first
            .load_sprint(&harness.spec.sprint_id)
            .expect("load sensitive ordinary sprint");
        assert!(DurableUiProjection::from_persisted(&caller_shaped_v27_image).is_err());
        let projection = DurableUiProjection::from_ledger(&first.ledger, &harness.spec.sprint_id)
            .expect("project sensitive ordinary effect only from exact durable v29 authority");
        assert!(projection.events().iter().any(|event| matches!(
            event.payload(),
            DurableUiEventKind::SensitiveOutputRejected {
                effect_id: projected,
                ..
            } if projected == &effect_id
        )));
        let graph = sprint
            .graph
            .as_ref()
            .expect("load sensitive ordinary graph");
        let history = first
            .ledger
            .load_task_attempt_history(&harness.spec.sprint_id, &graph.tasks[0].task_id)
            .expect("load exhausted sensitive ordinary attempt");
        assert_eq!(history.task_state, TaskState::Failed);
        assert!(history.active_attempt().is_none());
        let disposed = history.attempts.last().expect("load disposed attempt");
        assert_eq!(&disposed.attempt.attempt_id, attempt_id);
        let disposition = disposed.disposition.as_ref().expect("load disposition");
        assert_eq!(
            sensitive_output_disposition_effect_id(disposition),
            Some(effect_id.as_str())
        );
        assert_eq!(
            known_cleanup_disposition_launch_id(disposition),
            Some(launch_id.as_str())
        );

        let dispatches_before_restart = dispatch_count.get();
        drop(first);
        let restart_runner = ScriptedRunnerLifecycle::new(
            ScriptedDispatchBehavior::Exact,
            Rc::clone(&dispatch_count),
        );
        let restart_cleanup_count = restart_runner.sensitive_cleanup_count();
        let mut restarted = harness.coordinator_with_runner(provider, restart_runner);
        let recovered = restarted
            .run_until_blocked(
                &harness.spec.sprint_id,
                &harness.authority,
                &harness.policy,
                &harness.shadow,
                4_000,
            )
            .expect("recover exhausted ordinary sensitive rejection");
        assert_eq!(recovered, status);
        assert_eq!(dispatch_count.get(), dispatches_before_restart);
        assert_eq!(restart_cleanup_count.get(), 0);
    }

    struct SensitiveCleanRetryHandoff {
        final_snapshot: Digest,
        verification_receipt_id: String,
        winning_lease: WorkerLease,
        rejected_effect_id: String,
    }

    #[allow(
        clippy::too_many_lines,
        reason = "the helper lets the retry and TaskDone stack unwind at the durable handoff before the separate completion continuation"
    )]
    fn drive_sensitive_clean_retry_to_task_done(
        harness: &Harness,
        provider: &MutationProvider,
        dispatch_count: Rc<Cell<u32>>,
    ) -> SensitiveCleanRetryHandoff {
        let runner = ScriptedRunnerLifecycle::new(
            ScriptedDispatchBehavior::SensitiveOutputRejectedOnce,
            dispatch_count,
        );
        let cleanup_count = runner.sensitive_cleanup_count();
        let mut coordinator = Box::new(harness.coordinator_with_runner(provider.clone(), runner));
        coordinator
            .create_draft(&harness.authority, &harness.spec, &harness.base, 1_001)
            .expect("create clean-retry draft");

        let status = coordinator
            .run_until_blocked(
                &harness.spec.sprint_id,
                &harness.authority,
                &harness.policy,
                &harness.shadow,
                2_000,
            )
            .expect("clean second attempt reaches the post-TaskDone application handoff");
        let WalkingSkeletonStatus::ReadyForApplication {
            final_snapshot,
            verification_receipt_id,
        } = status
        else {
            panic!("clean retry did not reach ReadyForApplication: {status:?}")
        };
        assert_eq!(cleanup_count.get(), 1);

        let sprint = coordinator
            .ledger
            .load_sprint(&harness.spec.sprint_id)
            .expect("load clean-retry sprint");
        let graph = sprint.graph.as_ref().expect("load clean-retry task graph");
        let task = graph.tasks.first().expect("load clean-retry task");
        let history = coordinator
            .ledger
            .load_task_attempt_history(&harness.spec.sprint_id, &task.task_id)
            .expect("load both clean-retry attempts");
        assert_eq!(history.attempts.len(), 2);
        assert!(history.active_attempt().is_none());
        let first = &history.attempts[0];
        let second = &history.attempts[1];
        assert_ne!(first.attempt.attempt_id, second.attempt.attempt_id);
        let TaskAttemptDisposition::Retryable(first_retry) = first
            .disposition
            .as_ref()
            .expect("first sensitive attempt is durably disposed")
        else {
            panic!("first sensitive attempt was not retryable")
        };
        let TaskAttemptRetryableCause::SensitiveOutputRejected {
            effect_id: rejected_effect_id,
            ..
        } = &first_retry.cause
        else {
            panic!("first retry cause was not the exact sensitive-output rejection")
        };
        let TaskAttemptDisposition::Integrated(second_integrated) = second
            .disposition
            .as_ref()
            .expect("second attempt is durably disposed")
        else {
            panic!("second clean attempt was not integrated")
        };
        assert_eq!(
            second_integrated
                .integration_receipt
                .worker_lease
                .as_ref()
                .map(|lease| lease.lease_id.as_str()),
            Some(second.attempt.worker_lease.lease_id.as_str())
        );
        assert!(sprint.effects.iter().all(|effect| {
            effect.intent.worker_lease.as_ref().is_none_or(|lease| {
                lease.lease_id != first.attempt.worker_lease.lease_id
                    || !effect.intent.kind.is_regular_file_mutation()
            })
        }));
        coordinator
            .ledger
            .load_command_output_sensitive_rejection_for_effect(rejected_effect_id)
            .expect("read back first attempt's exact v29 rejection");

        let task_done = coordinator
            .ledger
            .assess_task_done(&harness.spec.sprint_id, &task.task_id)
            .expect("re-derive TaskDone after clean retry")
            .proof
            .expect("clean retry satisfies the complete TaskDone conjunction");
        assert_eq!(task_done.attempt, second.attempt);
        assert_eq!(task_done.non_winning_attempts.len(), 1);
        assert_eq!(task_done.non_winning_attempts[0].attempt, first.attempt);
        assert_eq!(
            sensitive_output_disposition_effect_id(&task_done.non_winning_attempts[0].disposition),
            Some(rejected_effect_id.as_str())
        );
        assert_eq!(
            task_done.integration_receipt,
            second_integrated.integration_receipt
        );
        SensitiveCleanRetryHandoff {
            final_snapshot,
            verification_receipt_id,
            winning_lease: second.attempt.worker_lease.clone(),
            rejected_effect_id: rejected_effect_id.clone(),
        }
    }

    fn capture_sensitive_clean_retry_live_state(
        harness: &Harness,
        provider: MutationProvider,
        final_snapshot: &Digest,
        verification_receipt_id: &str,
    ) -> String {
        let mut finisher = Box::new(
            DurableWalkingSkeleton::open_with_runner_lifecycle(
                &harness.database,
                provider,
                StrictFakeRunnerLifecycle,
            )
            .expect("reopen clean winner for application and live-state capture"),
        );
        assert!(matches!(
            finisher
                .run_application_until_blocked(
                    &harness.spec.sprint_id,
                    &harness.authority,
                    &harness.policy,
                    final_snapshot,
                    verification_receipt_id,
                    4_000,
                )
                .expect("advance only the clean winner through no-op application closure"),
            WalkingSkeletonStatus::VerifiedNoOpCaptureRequired { .. }
        ));
        let live_state = finisher
            .run_live_state_capture_until_blocked(
                &harness.spec.sprint_id,
                &harness.authority,
                &harness.policy,
                verification_receipt_id,
                6_000,
            )
            .expect("capture the clean winner's exact live state");
        let WalkingSkeletonStatus::LiveStateCaptured {
            capture_receipt_id,
            matches_expected_snapshot: true,
            ..
        } = live_state
        else {
            panic!("clean winner did not reach exact live-state capture: {live_state:?}")
        };
        capture_receipt_id
    }

    fn terminalize_sensitive_clean_retry_completion(
        harness: &Harness,
        capture_receipt_id: &str,
        winning_lease: &WorkerLease,
        rejected_effect_id: &str,
    ) -> (WalkingSkeletonStatus, usize) {
        let mut finisher = Box::new(
            DurableWalkingSkeleton::open_with_runner_lifecycle(
                &harness.database,
                CountingProvider::default(),
                StrictFakeRunnerLifecycle,
            )
            .expect("reopen clean winner for completion"),
        );
        assert!(matches!(
            finisher
                .run_completion_until_blocked(
                    &harness.spec.sprint_id,
                    &harness.authority,
                    capture_receipt_id,
                    8_000,
                )
                .expect("terminalize the distinct clean winner"),
            WalkingSkeletonStatus::Completed { .. }
        ));
        let completion = finisher
            .ledger
            .load_completion(&harness.spec.sprint_id)
            .expect("load clean-retry completion")
            .expect("clean-retry completion is durable");
        assert_eq!(completion.task_integrations.len(), 1);
        assert_eq!(
            completion.task_integrations[0].worker_lease.as_ref(),
            Some(winning_lease)
        );
        assert_ne!(
            completion.task_integrations[0].effect_id,
            rejected_effect_id
        );
        let status = completed_status(&completion);
        let event_count = finisher
            .ledger
            .load_sprint(&harness.spec.sprint_id)
            .expect("load completed clean-retry event set")
            .events
            .len();
        (status, event_count)
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "the regression keeps the rejected nonwinner, distinct clean winner, TaskDone proof, completion, and restart readback in one audit boundary"
    )]
    fn sensitive_ordinary_command_retries_to_distinct_completed_winner_without_borrowed_evidence() {
        let mut harness = Harness::new_empty("sensitive-ordinary-command-clean-retry");
        harness.spec.budget.max_attempts_per_task = 2;
        let provider = MutationProvider::new(vec![ProviderToolIntent::RunCommand {
            command: fixture_acceptance_command(),
        }]);
        let dispatch_count = Rc::new(Cell::new(0));
        let SensitiveCleanRetryHandoff {
            final_snapshot,
            verification_receipt_id,
            winning_lease,
            rejected_effect_id,
        } = drive_sensitive_clean_retry_to_task_done(
            &harness,
            &provider,
            Rc::clone(&dispatch_count),
        );

        let capture_receipt_id = capture_sensitive_clean_retry_live_state(
            &harness,
            provider,
            &final_snapshot,
            &verification_receipt_id,
        );
        let (completed, events_before_restart) = terminalize_sensitive_clean_retry_completion(
            &harness,
            &capture_receipt_id,
            &winning_lease,
            &rejected_effect_id,
        );

        let dispatches_before_restart = dispatch_count.get();
        let restart_provider = CountingProvider::default();
        let mut restarted = Box::new(
            DurableWalkingSkeleton::open_with_runner_lifecycle(
                &harness.database,
                restart_provider.clone(),
                ScriptedRunnerLifecycle::new(
                    ScriptedDispatchBehavior::SensitiveOutputRejected,
                    Rc::clone(&dispatch_count),
                ),
            )
            .expect("reopen completed clean-retry sprint with hostile callbacks"),
        );
        assert_eq!(
            restarted
                .run_completion_until_blocked(
                    &harness.spec.sprint_id,
                    &harness.authority,
                    &capture_receipt_id,
                    0,
                )
                .expect("Completed clean winner is exact readback"),
            completed
        );
        assert_eq!(
            restarted
                .ledger
                .load_sprint(&harness.spec.sprint_id)
                .expect("reload completed clean-retry event set")
                .events
                .len(),
            events_before_restart
        );
        assert_eq!(dispatch_count.get(), dispatches_before_restart);
        assert_eq!(restart_provider.planning_calls(), 0);
        assert_eq!(restart_provider.turn_calls(), 0);
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "the adversarial scenario keeps fresh permit creation, unpersisted substitution, pre-dispatch refusal, and durable readback together"
    )]
    fn fresh_permit_cannot_authorize_an_unpersisted_substitute() {
        let harness = Harness::new("dispatch-unpersisted-intent");
        let provider = CountingProvider::default();
        harness.initialize(provider.clone());
        let dispatch_count = Rc::new(Cell::new(0));
        let mut coordinator = harness.coordinator_with_runner(
            provider,
            ScriptedRunnerLifecycle::new(
                ScriptedDispatchBehavior::Exact,
                Rc::clone(&dispatch_count),
            ),
        );
        coordinator
            .run_until_blocked(
                &harness.spec.sprint_id,
                &harness.authority,
                &harness.policy,
                &harness.shadow,
                2_000,
            )
            .expect("reach the exact containment boundary");
        let sprint = coordinator
            .load_sprint(&harness.spec.sprint_id)
            .expect("load exact runner effects");
        let exemplar = sprint
            .effects
            .iter()
            .find(|effect| effect.intent.kind == EffectKind::ReadRelativeFile)
            .expect("runner read exemplar");
        let provider_call =
            decode_tool_call(&exemplar.request_bytes).expect("decode exact exemplar provider call");
        let mut fresh_intent = exemplar.intent.clone();
        fresh_intent.effect_id.push_str(":fresh-authority");
        fresh_intent.idempotency_key.push_str(":fresh-authority");
        fresh_intent.created_at_unix_ms = sprint
            .events
            .iter()
            .map(|event| event.occurred_at_unix_ms)
            .max()
            .expect("durable event time")
            .checked_add(1)
            .expect("test timestamp");
        let task = sprint
            .graph
            .as_ref()
            .and_then(|graph| graph.tasks.first())
            .expect("one task");
        let running = coordinator
            .ledger
            .load_task_attempt_history(&harness.spec.sprint_id, &task.task_id)
            .expect("load running attempt")
            .active_attempt()
            .and_then(|attempt| attempt.running_boundary.clone())
            .expect("exact running boundary");
        assert!(matches!(
            validate_task_effect_dispatch_authority(
                &harness.spec,
                &harness.authority,
                &harness.policy,
                &running,
                &fresh_intent,
                &exemplar.request_bytes,
            ),
            Err(DurableCoordinatorError::Protocol(message))
                if message.contains("dispatch request is crossed")
        ));
        let (fresh, permit) = coordinator
            .commit_runner_intent_for_dispatch(
                &fresh_intent,
                &exemplar.request_bytes,
                &running.runner_session_id,
            )
            .expect("commit one fresh exact dispatch authority");
        let mut phantom = fresh.clone();
        phantom.intent.effect_id.push_str(":never-persisted");
        let before_dispatches = dispatch_count.get();
        let mut post_response_timestamps =
            TimestampCursor::from_next_for_test(fresh.intent.created_at_unix_ms.saturating_add(1));

        let error = coordinator
            .dispatch_task_effect(
                &harness.spec,
                &harness.authority,
                &harness.policy,
                &running,
                &phantom,
                permit,
                &provider_call,
                &harness.shadow,
                &mut post_response_timestamps,
            )
            .expect_err("unpersisted intent must fail before dispatch");
        assert!(matches!(
            error,
            DurableCoordinatorError::Ledger(LedgerError::ArtifactNotFound { .. })
        ));
        assert_eq!(dispatch_count.get(), before_dispatches);
        let fresh_readback = coordinator
            .ledger
            .load_effect(&fresh.intent.effect_id)
            .expect("fresh exact effect remains durable");
        assert!(fresh_readback.observation.is_none());
        assert!(fresh_readback.dispatch_claim.is_none());
    }

    #[test]
    fn multi_task_plan_fails_closed_before_worker_or_integration_authority() {
        let mut harness = Harness::new("multi-task-plan-requires-rebase");
        harness.spec.budget.max_tasks = 2;
        let provider = MutationProvider::new(Vec::new()).with_two_independent_tasks();
        let mut coordinator = DurableWalkingSkeleton::open_with_runner_lifecycle(
            &harness.database,
            provider.clone(),
            StrictFakeRunnerLifecycle,
        )
        .expect("open multi-task fail-closed coordinator");
        coordinator
            .create_draft(&harness.authority, &harness.spec, &harness.base, 1_001)
            .expect("create multi-task sprint");

        let error = coordinator
            .run_until_blocked(
                &harness.spec.sprint_id,
                &harness.authority,
                &harness.policy,
                &harness.shadow,
                2_000,
            )
            .expect_err("multi-task graph must require unavailable rebase authority");
        assert!(matches!(
            &error,
            DurableCoordinatorError::Protocol(message)
                if message.contains("exactly one task") && message.contains("rebase authority")
        ));
        assert_eq!(provider.turn_calls(), 0);
        let sprint = coordinator
            .load_sprint(&harness.spec.sprint_id)
            .expect("load fail-closed multi-task sprint");
        assert_eq!(
            sprint.graph.as_ref().expect("attached graph").tasks.len(),
            2
        );
        assert!(sprint.effects.iter().all(|effect| {
            effect.intent.task_id.is_none()
                && effect.intent.worker_id.is_none()
                && effect.intent.worker_lease.is_none()
        }));
        assert!(matches!(
            coordinator.ledger.load_criterion_evidence_receipt_v2(
                &gate1_criterion_evidence_receipt_identity(&harness.spec.sprint_id, 0,)
            ),
            Err(LedgerError::ArtifactNotFound { .. })
        ));
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "the competing-ledger race keeps permit mint, terminal winner, dispatch refusal, and durable readback in one visible regression"
    )]
    fn terminal_observation_from_another_connection_invalidates_the_fresh_permit() {
        let harness = Harness::new("dispatch-stale-before-claim");
        let provider = CountingProvider::default();
        harness.initialize(provider.clone());
        let dispatch_count = Rc::new(Cell::new(0));
        let mut coordinator = harness.coordinator_with_runner(
            provider,
            ScriptedRunnerLifecycle::new(
                ScriptedDispatchBehavior::Exact,
                Rc::clone(&dispatch_count),
            ),
        );
        coordinator
            .run_until_blocked(
                &harness.spec.sprint_id,
                &harness.authority,
                &harness.policy,
                &harness.shadow,
                2_000,
            )
            .expect("reach the exact containment boundary");
        let sprint = coordinator
            .load_sprint(&harness.spec.sprint_id)
            .expect("load exact runner effects");
        let exemplar = sprint
            .effects
            .iter()
            .find(|effect| effect.intent.kind == EffectKind::ReadRelativeFile)
            .expect("runner read exemplar");
        let provider_call =
            decode_tool_call(&exemplar.request_bytes).expect("decode exact exemplar provider call");
        let mut stale_intent = exemplar.intent.clone();
        stale_intent.effect_id.push_str(":stale-before-claim");
        stale_intent.idempotency_key.push_str(":stale-before-claim");
        stale_intent.created_at_unix_ms = sprint
            .events
            .iter()
            .map(|event| event.occurred_at_unix_ms)
            .max()
            .expect("durable event time")
            .checked_add(1)
            .expect("test timestamp");
        let task = sprint
            .graph
            .as_ref()
            .and_then(|graph| graph.tasks.first())
            .expect("one task");
        let running = coordinator
            .ledger
            .load_task_attempt_history(&harness.spec.sprint_id, &task.task_id)
            .expect("load running attempt")
            .active_attempt()
            .and_then(|attempt| attempt.running_boundary.clone())
            .expect("exact running boundary");
        let (fresh, permit) = coordinator
            .commit_runner_intent_for_dispatch(
                &stale_intent,
                &exemplar.request_bytes,
                &running.runner_session_id,
            )
            .expect("commit one fresh exact dispatch authority");

        let evidence = b"terminalized-before-dispatch-claim";
        let observed_at = fresh
            .intent
            .created_at_unix_ms
            .checked_add(1)
            .expect("test observation timestamp");
        let (observation, event) = coordinator
            .build_observation(
                &fresh,
                EffectOutcome::FailedBeforeEffect {
                    evidence_digest: Digest::sha256(evidence),
                },
                observed_at,
            )
            .expect("build exact competing observation");
        let mut competing = EventLedger::open(&harness.database).expect("open competing ledger");
        competing
            .record_effect_observation(&observation, evidence, &event)
            .expect("terminal observation wins before dispatch claim");
        drop(competing);
        let before_dispatches = dispatch_count.get();
        let mut post_response_timestamps =
            TimestampCursor::from_next_for_test(observed_at.saturating_add(1));

        let error = coordinator
            .dispatch_task_effect(
                &harness.spec,
                &harness.authority,
                &harness.policy,
                &running,
                &fresh,
                permit,
                &provider_call,
                &harness.shadow,
                &mut post_response_timestamps,
            )
            .expect_err("stale fresh permit must fail before lifecycle dispatch");
        assert!(matches!(
            error,
            DurableCoordinatorError::Protocol(ref message)
                if message.contains("exact durable unobserved intent")
        ));
        assert_eq!(dispatch_count.get(), before_dispatches);
        let readback = coordinator
            .ledger
            .load_effect(&fresh.intent.effect_id)
            .expect("load competing terminal result");
        assert!(readback.observation.is_some());
        assert!(readback.dispatch_claim.is_none());
    }

    #[test]
    fn crash_after_durable_planning_response_attaches_without_provider_replay() {
        let harness = Harness::new("crash-after-response");
        let provider = CountingProvider::default();
        harness.initialize(provider.clone());

        let mut first_process = harness.coordinator(provider.clone());
        let paused = first_process
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
            .expect("persist planning evidence");
        assert!(matches!(
            paused,
            WalkingSkeletonStatus::PlanningEvidenceDurable { .. }
        ));
        assert_eq!(provider.planning_calls(), 1);
        assert!(
            first_process
                .load_sprint(&harness.spec.sprint_id)
                .expect("load draft")
                .graph
                .is_none()
        );
        drop(first_process);

        let mut restarted = harness.coordinator(provider.clone());
        let status = restarted
            .run_until_blocked(
                &harness.spec.sprint_id,
                &harness.authority,
                &harness.policy,
                &harness.shadow,
                3_000,
            )
            .expect("resume from planning evidence");
        assert!(matches!(
            status,
            WalkingSkeletonStatus::ContainmentNotReady { .. }
        ));
        assert_eq!(provider.planning_calls(), 1);
        assert_eq!(provider.turn_calls(), 4);
        let sprint = restarted
            .load_sprint(&harness.spec.sprint_id)
            .expect("load attached sprint");
        assert!(matches!(
            sprint.graph_provenance,
            TaskGraphProvenance::ProviderEffect { .. }
        ));
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "the sequential regression audits each exact per-effect delta and its atomic artifact chain"
    )]
    fn sequential_mutations_commit_exact_pre_post_deltas() {
        let harness = Harness::new("sequential-mutation-deltas");
        let first = b"first mutation\n".to_vec();
        let second = b"second mutation\n".to_vec();
        let third = b"third mutation\n".to_vec();
        let path = PathBuf::from("docs/sequential.txt");
        let first_hash = Digest::sha256(&first);
        let second_hash = Digest::sha256(&second);
        let third_hash = Digest::sha256(&third);
        let provider = MutationProvider::new(vec![
            ProviderToolIntent::CreateRegularFile {
                path: path.clone(),
                contents: first,
            },
            ProviderToolIntent::ReplaceRegularFile {
                path: path.clone(),
                expected_hash: first_hash.clone(),
                contents: second,
            },
            ProviderToolIntent::DeleteRegularFile {
                path: path.clone(),
                expected_hash: second_hash.clone(),
            },
            ProviderToolIntent::CreateRegularFile {
                path: path.clone(),
                contents: third.clone(),
            },
        ]);
        let dispatch_count = Rc::new(Cell::new(0));
        let runner = ScriptedRunnerLifecycle::new(
            ScriptedDispatchBehavior::Exact,
            Rc::clone(&dispatch_count),
        );
        let mut coordinator = DurableWalkingSkeleton::open_with_runner_lifecycle(
            &harness.database,
            provider.clone(),
            runner,
        )
        .expect("open sequential mutation coordinator");
        coordinator
            .create_draft(&harness.authority, &harness.spec, &harness.base, 1_001)
            .expect("create sequential mutation sprint");

        let status = coordinator
            .run_until_blocked(
                &harness.spec.sprint_id,
                &harness.authority,
                &harness.policy,
                &harness.shadow,
                2_000,
            )
            .expect("commit four exact sequential mutation deltas");
        let final_snapshot = match status {
            WalkingSkeletonStatus::ReadyForApplication { final_snapshot, .. } => final_snapshot,
            other => panic!("unexpected sequential mutation state: {other:?}"),
        };
        assert_eq!(provider.turn_calls(), 5);
        assert_eq!(dispatch_count.get(), 4);
        assert_eq!(
            fs::read(harness.shadow.root().join(&path)).expect("read final sequential file"),
            third
        );

        let sprint = coordinator
            .load_sprint(&harness.spec.sprint_id)
            .expect("load sequential mutation artifacts");
        let mut effects = sprint
            .effects
            .iter()
            .filter(|effect| is_mutating_tool(effect.intent.kind))
            .collect::<Vec<_>>();
        effects.sort_by(|left, right| left.intent.effect_id.cmp(&right.intent.effect_id));
        assert_eq!(effects.len(), 4);
        let expected = [
            FileOperation::Create {
                path: path.clone(),
                result_hash: first_hash.clone(),
            },
            FileOperation::Modify {
                path: path.clone(),
                base_hash: first_hash,
                result_hash: second_hash.clone(),
            },
            FileOperation::Delete {
                path: path.clone(),
                base_hash: second_hash,
            },
            FileOperation::Create {
                path,
                result_hash: third_hash,
            },
        ];
        let mut head = harness.base.snapshot_id.clone();
        for (effect, expected_operation) in effects.into_iter().zip(expected) {
            assert!(effect.dispatch_claim.is_some());
            assert!(matches!(
                effect
                    .observation
                    .as_ref()
                    .map(|observation| &observation.outcome),
                Some(EffectOutcome::Succeeded { .. })
            ));
            let PersistedMutationArtifact::Linked {
                link,
                snapshot,
                change_set,
            } = &effect.mutation_artifact
            else {
                panic!("mutation effect omitted its atomic artifact link")
            };
            assert_eq!(effect.intent.input_snapshot, head);
            assert_eq!(change_set.base_snapshot, head);
            assert_eq!(change_set.operations.as_slice(), [expected_operation]);
            assert_eq!(change_set.result_snapshot, snapshot.snapshot_id);
            assert_eq!(link.input_snapshot, change_set.base_snapshot);
            assert_eq!(link.result_snapshot, change_set.result_snapshot);
            head.clone_from(&snapshot.snapshot_id);
        }
        assert_eq!(head, final_snapshot);
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "the success audit checks serialized task verification, integration, TaskDone, final verification, and both cleanup domains"
    )]
    fn formal_checks_dispatch_in_sprint_order_and_reach_ready_for_application() {
        let mut harness = Harness::new("formal-success-candidate");
        harness.spec.acceptance_criteria =
            vec![automated_criterion("compile"), automated_criterion("tests")];
        let provider = MutationProvider::new(Vec::new()).with_reversed_acceptance_checks();
        let order = Rc::new(RefCell::new(Vec::new()));
        let acknowledgements = Rc::new(Cell::new(0));
        let runner = FormalScriptRunnerLifecycle::new(
            FormalDispatchBehavior::Exact,
            Rc::clone(&order),
            Rc::clone(&acknowledgements),
        );
        let mut coordinator = DurableWalkingSkeleton::open_with_runner_lifecycle(
            &harness.database,
            provider.clone(),
            runner,
        )
        .expect("open formal success coordinator");
        coordinator
            .create_draft(&harness.authority, &harness.spec, &harness.base, 1_001)
            .expect("create formal success sprint");

        let status = coordinator
            .run_until_blocked(
                &harness.spec.sprint_id,
                &harness.authority,
                &harness.policy,
                &harness.shadow,
                2_000,
            )
            .expect("run every serialized formal check");
        assert!(matches!(
            status,
            WalkingSkeletonStatus::ReadyForApplication { .. }
        ));
        assert_eq!(order.borrow().as_slice(), ["compile", "tests"]);
        assert_eq!(acknowledgements.get(), 2);

        let sprint = coordinator
            .load_sprint(&harness.spec.sprint_id)
            .expect("load formal TaskDone sprint");
        let task = &sprint.graph.as_ref().expect("attached graph").tasks[0];
        assert_eq!(
            task.acceptance_checks.as_slice(),
            ["tests", "compile"],
            "fixture proves SprintSpec order wins over reversed graph references"
        );
        let history = coordinator
            .ledger
            .load_task_attempt_history(&harness.spec.sprint_id, &task.task_id)
            .expect("load exact Integrated attempt history");
        assert_eq!(history.task_state, TaskState::Integrated);
        let active = history.attempts.last().expect("winning Integrated attempt");
        assert_eq!(
            active
                .formal_checks
                .iter()
                .map(|check| check.criterion_id.as_str())
                .collect::<Vec<_>>(),
            ["compile", "tests"]
        );
        assert!(
            active
                .formal_checks
                .iter()
                .all(|check| check.verification_receipt.passed())
        );
        for (index, check) in active.formal_checks.iter().enumerate() {
            let ordinal = u32::try_from(index).expect("fixture criterion ordinal");
            let evidence = coordinator
                .ledger
                .load_criterion_evidence_receipt_v2(&gate1_criterion_evidence_receipt_identity(
                    &harness.spec.sprint_id,
                    ordinal,
                ))
                .expect("load declared-order Gate-1 criterion evidence");
            assert_eq!(evidence.criterion_id(), check.criterion_id);
            assert_eq!(evidence.snapshot_digest(), &check.sealed_snapshot);
            assert!(matches!(
                evidence,
                CriterionEvidenceReceiptV2::Verified {
                    verification_receipt_id,
                    ..
                } if verification_receipt_id == check.verification_receipt.receipt_id
            ));
        }
        let verification = active
            .verification_boundary
            .as_ref()
            .expect("exact verification boundary");
        let mut exact_earlier_terminal_effects = sprint
            .effects
            .iter()
            .filter(|effect| {
                effect.intent.worker_lease.as_ref() == Some(&active.attempt.worker_lease)
                    && effect.intent.kind != EffectKind::CleanupWorkerDomain
                    && effect.intent.created_at_unix_ms < verification.sealed_at_unix_ms
            })
            .map(|effect| TaskAttemptTerminalEffect {
                effect_id: effect.intent.effect_id.clone(),
                observation_id: effect
                    .observation
                    .as_ref()
                    .expect("every earlier sealed effect is terminal")
                    .observation_id
                    .clone(),
            })
            .collect::<Vec<_>>();
        exact_earlier_terminal_effects.sort_by(|left, right| left.effect_id.cmp(&right.effect_id));
        assert_eq!(
            verification.terminal_non_cleanup_effects, exact_earlier_terminal_effects,
            "the Verifying boundary seals the complete exact earlier lease-bound terminal set"
        );
        let cumulative = coordinator
            .ledger
            .load_change_set(&harness.spec.sprint_id, &verification.change_set_id)
            .expect("load cumulative task change set");
        assert!(cumulative.operations.is_empty());
        assert_eq!(cumulative.base_snapshot, cumulative.result_snapshot);
        assert_eq!(cumulative.result_snapshot, verification.sealed_snapshot);
        assert_eq!(
            sprint
                .effects
                .iter()
                .filter(|effect| effect.intent.kind == EffectKind::IntegrateChangeSet)
                .count(),
            1
        );
        assert!(sprint.effects.iter().any(|effect| {
            effect.intent.kind == EffectKind::CleanupWorkerDomain
                && matches!(
                    effect.observation.as_ref().map(|value| &value.outcome),
                    Some(EffectOutcome::Succeeded { .. })
                )
        }));
        let done = coordinator
            .ledger
            .assess_task_done(&harness.spec.sprint_id, &task.task_id)
            .expect("compute exact TaskDone");
        assert!(done.is_done());
        let proof = done.proof.expect("TaskDone retains its complete proof");
        assert_eq!(proof.integration_receipt.integration_ordinal, 0);
        assert_eq!(
            proof.integration_receipt.input_snapshot,
            harness.base.snapshot_id
        );
        assert_eq!(
            proof.integration_receipt.result_snapshot,
            verification.sealed_snapshot
        );
        assert_eq!(proof.runner_cleanup.receipt.surviving_processes, 0);
        assert_eq!(proof.command_domain_cleanup.entries.len(), 2);
        assert_eq!(provider.turn_calls(), 1);
    }
