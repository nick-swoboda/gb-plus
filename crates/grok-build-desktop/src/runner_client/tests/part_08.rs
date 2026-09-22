    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "the failure regression keeps the initial atomic rollback, retained-custody retry, no-reopen proof, and unchanged lease/effect assertions contiguous"
    )]
    fn lifecycle_owner_restart_native_failure_writes_nothing_and_retries_retained_custody_without_reopening()
     {
        let label = "lifecycle-owner-restart-native-cleanup-failure";
        let RestartIntegratedNativeCleanupFixture {
            harness,
            mut ledger,
            disposition,
            cleanup_admission,
            cleanup_authority,
            cleanup_at_unix_ms,
            prepare_count,
            release_count,
        } = restart_integrated_native_cleanup_fixture(label);
        let pending_cleanup = ledger
            .load_effect(&cleanup_admission.cleanup_effect.intent.effect_id)
            .expect("load pending cleanup before restart failure");
        let reopen_count = Rc::new(Cell::new(0));
        let cleanup_count = Rc::new(Cell::new(0));
        let claims = Rc::new(RefCell::new(Vec::new()));
        let reopener: Box<dyn NativeLaunchCleanupReopener> =
            Box::new(ScriptedNativeCleanupReopener {
                authority: cleanup_authority,
                reopen_count: Rc::clone(&reopen_count),
                cleanup_count: Rc::clone(&cleanup_count),
                mutation: ScriptedNativeCleanupMutation::CrossedObservation,
                claims: Rc::clone(&claims),
            });
        let mut owner = DesktopRunnerLifecycleOwner::with_native_cleanup_reopener(
            RunnerLifecycleOwnerConfig {
                runner_binary: harness.runner_binary.clone(),
                private_state_root: harness.private_state.clone(),
            },
            reopener,
        )
        .expect("construct restarted owner with failing cleanup-only journal");

        let first = crate::WalkingSkeletonRunnerLifecycle::cleanup_integrated_task_attempt(
            &mut owner,
            &mut ledger,
            crate::WalkingSkeletonIntegratedTaskCleanup {
                sprint_spec: &harness.sprint_spec,
                disposition: &disposition,
                cleanup_at_unix_ms,
            },
        )
        .expect("native mismatch remains a typed retained cleanup requirement");
        assert!(matches!(
            first,
            crate::WalkingSkeletonIntegratedTaskCleanupOutcome::CleanupRequired { .. }
        ));
        assert_eq!(reopen_count.get(), 1);
        assert_eq!(cleanup_count.get(), 1);
        assert_eq!(claims.borrow().len(), 1);
        assert_eq!(prepare_count.get(), 1, "restart failure must not prepare");
        assert_eq!(release_count.get(), 1, "restart failure must not release");
        assert!(matches!(
            owner.state(),
            DesktopRunnerLifecycleStateView::CleanupRequired { cleanup, .. }
                if cleanup.has_native_cleanup_custody()
        ));
        assert_eq!(
            ledger
                .load_effect(&cleanup_admission.cleanup_effect.intent.effect_id)
                .expect("native mismatch must leave cleanup unobserved"),
            pending_cleanup
        );
        assert_eq!(
            ledger
                .load_active_worker_leases(&harness.sprint_id)
                .expect("native mismatch must retain the integrated lease"),
            vec![harness.worker_lease.clone()]
        );

        let retry = crate::WalkingSkeletonRunnerLifecycle::cleanup_integrated_task_attempt(
            &mut owner,
            &mut ledger,
            crate::WalkingSkeletonIntegratedTaskCleanup {
                sprint_spec: &harness.sprint_spec,
                disposition: &disposition,
                cleanup_at_unix_ms: cleanup_at_unix_ms.saturating_add(1),
            },
        )
        .expect("cached crossed evidence remains a typed cleanup requirement");
        assert!(matches!(
            retry,
            crate::WalkingSkeletonIntegratedTaskCleanupOutcome::CleanupRequired { .. }
        ));
        assert_eq!(reopen_count.get(), 1, "retained custody must not reopen");
        assert_eq!(
            cleanup_count.get(),
            1,
            "retained custody must reconcile its cached journal observation"
        );
        assert_eq!(claims.borrow().len(), 1);
        assert_eq!(prepare_count.get(), 1);
        assert_eq!(release_count.get(), 1);
        assert_eq!(
            ledger
                .load_effect(&cleanup_admission.cleanup_effect.intent.effect_id)
                .expect("retry still must not write a partial cleanup terminal"),
            pending_cleanup
        );
        assert_eq!(
            ledger
                .load_active_worker_leases(&harness.sprint_id)
                .expect("retry still must retain the integrated lease"),
            vec![harness.worker_lease.clone()]
        );
        assert!(matches!(
            owner.state(),
            DesktopRunnerLifecycleStateView::CleanupRequired { cleanup, .. }
                if cleanup.has_native_cleanup_custody()
        ));
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "the regression proves one admitted reopener remains reusable across two distinct durable launch claims"
    )]
    fn lifecycle_owner_restart_reopener_is_reusable_across_distinct_completed_launches() {
        let mut first =
            restart_integrated_native_cleanup_fixture("lifecycle-owner-reusable-reopener-first");
        let mut second =
            restart_integrated_native_cleanup_fixture("lifecycle-owner-reusable-reopener-second");
        let first_next_event_sequence = first
            .ledger
            .next_sequence(&first.harness.sprint_id)
            .expect("read first cleanup event sequence");
        let second_next_event_sequence = second
            .ledger
            .next_sequence(&second.harness.sprint_id)
            .expect("read second cleanup event sequence");
        let reopen_count = Rc::new(Cell::new(0));
        let cleanup_count = Rc::new(Cell::new(0));
        let claims = Rc::new(RefCell::new(Vec::new()));
        let reopener: Box<dyn NativeLaunchCleanupReopener> =
            Box::new(ReusableScriptedNativeCleanupReopener {
                authorities: vec![
                    first.cleanup_authority.clone(),
                    second.cleanup_authority.clone(),
                ],
                reopen_count: Rc::clone(&reopen_count),
                cleanup_count: Rc::clone(&cleanup_count),
                claims: Rc::clone(&claims),
            });
        let mut owner = DesktopRunnerLifecycleOwner::with_native_cleanup_reopener(
            RunnerLifecycleOwnerConfig {
                runner_binary: first.harness.runner_binary.clone(),
                private_state_root: first.harness.private_state.clone(),
            },
            reopener,
        )
        .expect("construct owner with reusable cleanup-only journal access");

        for fixture in [&mut first, &mut second] {
            let outcome = crate::WalkingSkeletonRunnerLifecycle::cleanup_integrated_task_attempt(
                &mut owner,
                &mut fixture.ledger,
                crate::WalkingSkeletonIntegratedTaskCleanup {
                    sprint_spec: &fixture.harness.sprint_spec,
                    disposition: &fixture.disposition,
                    cleanup_at_unix_ms: fixture.cleanup_at_unix_ms,
                },
            )
            .expect("reusable reopener completes the exact recovered launch");
            assert!(matches!(
                outcome,
                crate::WalkingSkeletonIntegratedTaskCleanupOutcome::Completed(_)
            ));
            assert!(matches!(
                owner.state(),
                DesktopRunnerLifecycleStateView::Idle
            ));
        }

        assert_eq!(reopen_count.get(), 2);
        assert_eq!(cleanup_count.get(), 2);
        assert_eq!(first.prepare_count.get(), 1);
        assert_eq!(first.release_count.get(), 1);
        assert_eq!(second.prepare_count.get(), 1);
        assert_eq!(second.release_count.get(), 1);
        assert_eq!(
            claims.borrow().as_slice(),
            &[
                CleanupReopenClaimTrace {
                    sprint_id: first.cleanup_admission.launch.sprint_id.clone(),
                    launch_id: first.cleanup_admission.launch.launch_id.clone(),
                    session_id: first.cleanup_admission.launch.session_id.clone(),
                    cleanup_effect_id: first
                        .cleanup_admission
                        .cleanup_effect
                        .intent
                        .effect_id
                        .clone(),
                    next_event_sequence: first_next_event_sequence,
                },
                CleanupReopenClaimTrace {
                    sprint_id: second.cleanup_admission.launch.sprint_id.clone(),
                    launch_id: second.cleanup_admission.launch.launch_id.clone(),
                    session_id: second.cleanup_admission.launch.session_id.clone(),
                    cleanup_effect_id: second
                        .cleanup_admission
                        .cleanup_effect
                        .intent
                        .effect_id
                        .clone(),
                    next_event_sequence: second_next_event_sequence,
                },
            ]
        );
        for fixture in [&first, &second] {
            assert!(matches!(
                fixture
                    .ledger
                    .load_effect(&fixture.cleanup_admission.cleanup_effect.intent.effect_id,)
                    .expect("reload completed cleanup")
                    .observation
                    .as_ref()
                    .map(|observation| &observation.outcome),
                Some(EffectOutcome::Succeeded { .. })
            ));
            assert!(
                fixture
                    .ledger
                    .load_active_worker_leases(&fixture.harness.sprint_id)
                    .expect("reload released worker lease")
                    .is_empty()
            );
        }
    }

    #[test]
    fn lifecycle_owner_retained_custody_free_cleanup_reopens_inside_atomic_exclusion() {
        let mut fixture = restart_integrated_native_cleanup_fixture(
            "lifecycle-owner-retained-custody-free-cleanup",
        );
        let session = fixture
            .ledger
            .load_runner_session(
                &fixture.cleanup_admission.launch.sprint_id,
                &fixture.cleanup_admission.launch.session_id,
            )
            .expect("reload exact retained runner session");
        let retained = admitted_cleanup_without_native_custody(
            fixture.cleanup_admission.clone(),
            session,
            fixture.cleanup_authority.platform_binding().clone(),
        );
        let reopen_count = Rc::new(Cell::new(0));
        let cleanup_count = Rc::new(Cell::new(0));
        let claims = Rc::new(RefCell::new(Vec::new()));
        let reopener: Box<dyn NativeLaunchCleanupReopener> =
            Box::new(ScriptedNativeCleanupReopener {
                authority: fixture.cleanup_authority.clone(),
                reopen_count: Rc::clone(&reopen_count),
                cleanup_count: Rc::clone(&cleanup_count),
                mutation: ScriptedNativeCleanupMutation::Exact,
                claims: Rc::clone(&claims),
            });
        let mut owner =
            DesktopRunnerLifecycleOwner::from_custody_free_worker_cleanup_with_reopener_for_test(
                RunnerLifecycleOwnerConfig {
                    runner_binary: fixture.harness.runner_binary.clone(),
                    private_state_root: fixture.harness.private_state.clone(),
                },
                retained,
                reopener,
            )
            .expect("construct exact retained custody-free cleanup state");

        let outcome = crate::WalkingSkeletonRunnerLifecycle::cleanup_integrated_task_attempt(
            &mut owner,
            &mut fixture.ledger,
            crate::WalkingSkeletonIntegratedTaskCleanup {
                sprint_spec: &fixture.harness.sprint_spec,
                disposition: &fixture.disposition,
                cleanup_at_unix_ms: fixture.cleanup_at_unix_ms,
            },
        )
        .expect("retained durable authority reopens native custody atomically");
        assert!(matches!(
            outcome,
            crate::WalkingSkeletonIntegratedTaskCleanupOutcome::Completed(_)
        ));
        assert_eq!(reopen_count.get(), 1);
        assert_eq!(cleanup_count.get(), 1);
        assert_eq!(claims.borrow().len(), 1);
        assert!(matches!(
            owner.state(),
            DesktopRunnerLifecycleStateView::Idle
        ));
        assert!(
            fixture
                .ledger
                .load_active_worker_leases(&fixture.harness.sprint_id)
                .expect("reload cleanup-coupled lease release")
                .is_empty()
        );
    }

    #[test]
    fn lifecycle_owner_retained_custody_free_cleanup_rejects_crossed_durable_admission() {
        let mut fixture = restart_integrated_native_cleanup_fixture(
            "lifecycle-owner-retained-custody-free-crossed-admission",
        );
        let pending_cleanup = fixture
            .ledger
            .load_effect(&fixture.cleanup_admission.cleanup_effect.intent.effect_id)
            .expect("load pending exact cleanup effect");
        let session = fixture
            .ledger
            .load_runner_session(
                &fixture.cleanup_admission.launch.sprint_id,
                &fixture.cleanup_admission.launch.session_id,
            )
            .expect("reload exact retained runner session");
        let mut crossed_admission = fixture.cleanup_admission.clone();
        crossed_admission
            .cleanup_effect
            .intent
            .effect_id
            .push_str(":crossed");
        let retained = admitted_cleanup_without_native_custody(
            crossed_admission,
            session,
            fixture.cleanup_authority.platform_binding().clone(),
        );
        let reopen_count = Rc::new(Cell::new(0));
        let cleanup_count = Rc::new(Cell::new(0));
        let claims = Rc::new(RefCell::new(Vec::new()));
        let reopener: Box<dyn NativeLaunchCleanupReopener> =
            Box::new(ScriptedNativeCleanupReopener {
                authority: fixture.cleanup_authority.clone(),
                reopen_count: Rc::clone(&reopen_count),
                cleanup_count: Rc::clone(&cleanup_count),
                mutation: ScriptedNativeCleanupMutation::Exact,
                claims: Rc::clone(&claims),
            });
        let mut owner =
            DesktopRunnerLifecycleOwner::from_custody_free_worker_cleanup_with_reopener_for_test(
                RunnerLifecycleOwnerConfig {
                    runner_binary: fixture.harness.runner_binary.clone(),
                    private_state_root: fixture.harness.private_state.clone(),
                },
                retained,
                reopener,
            )
            .expect("construct crossed retained cleanup for durable comparison");

        let error = crate::WalkingSkeletonRunnerLifecycle::cleanup_integrated_task_attempt(
            &mut owner,
            &mut fixture.ledger,
            crate::WalkingSkeletonIntegratedTaskCleanup {
                sprint_spec: &fixture.harness.sprint_spec,
                disposition: &fixture.disposition,
                cleanup_at_unix_ms: fixture.cleanup_at_unix_ms,
            },
        )
        .expect_err("crossed retained admission must fail before native reopening");
        assert!(error.to_string().contains("durable cleanup admission"));
        assert_eq!(reopen_count.get(), 0);
        assert_eq!(cleanup_count.get(), 0);
        assert!(claims.borrow().is_empty());
        assert_eq!(
            fixture
                .ledger
                .load_effect(&fixture.cleanup_admission.cleanup_effect.intent.effect_id,)
                .expect("crossed admission cannot alter cleanup effect"),
            pending_cleanup
        );
        assert!(matches!(
            owner.state(),
            DesktopRunnerLifecycleStateView::CleanupRequired { cleanup, .. }
                if !cleanup.has_native_cleanup_custody()
        ));
    }

    #[test]
    fn lifecycle_owner_exact_active_start_refuses_crossing_without_losing_client() {
        let (harness, mut ledger) = TestHarness::new("lifecycle-owner-active-binding");
        let launch = harness.launch("lifecycle-owner-active-binding");
        let mut client = RunnerLifecycleClient::launch_with_spawner(
            &mut ledger,
            &harness.authority,
            &harness.policy,
            launch.clone(),
            transport(
                unique_nonce("lifecycle-owner-active-binding"),
                harness.identity(),
                ScriptMode::Good,
                true,
                Vec::new(),
            ),
        )
        .expect("initialize active owner client");
        client.captured_base = true;
        client.shadow_created = true;
        client.shadow_snapshot = Some(harness.base_snapshot.clone());
        let running = client
            .task_attempt_running_boundary()
            .expect("worker Running boundary")
            .clone();
        let persisted = ledger
            .load_sprint(&harness.sprint_id)
            .expect("load active owner sprint");
        let task = persisted.graph.as_ref().expect("fixture graph").tasks[0].clone();
        let config = RunnerLifecycleOwnerConfig {
            runner_binary: harness.runner_binary.clone(),
            private_state_root: harness.private_state.clone(),
        };
        let mut owner = DesktopRunnerLifecycleOwner::from_active_client(config, launch, client)
            .expect("inject exact test client");
        let exact = crate::WalkingSkeletonRunnerLifecycle::ensure_task_attempt_running(
            &mut owner,
            &mut ledger,
            crate::WalkingSkeletonRunnerStart {
                sprint_spec: &harness.sprint_spec,
                task: &task,
                attempt: &running.attempt,
                authority: &harness.authority,
                policy: &harness.policy,
                shadow_root: &harness.shadow,
                input_snapshot: &harness.base_snapshot,
                requested_at_unix_ms: running.started_at_unix_ms + 1,
            },
        )
        .expect("exact active attempt returns stored boundary");
        assert_eq!(exact, running);

        let mut crossed = running.attempt.clone();
        crossed.attempt_id.push_str("-crossed");
        assert!(
            crate::WalkingSkeletonRunnerLifecycle::ensure_task_attempt_running(
                &mut owner,
                &mut ledger,
                crate::WalkingSkeletonRunnerStart {
                    sprint_spec: &harness.sprint_spec,
                    task: &task,
                    attempt: &crossed,
                    authority: &harness.authority,
                    policy: &harness.policy,
                    shadow_root: &harness.shadow,
                    input_snapshot: &harness.base_snapshot,
                    requested_at_unix_ms: running.started_at_unix_ms + 2,
                },
            )
            .is_err()
        );
        assert!(matches!(
            owner.state(),
            DesktopRunnerLifecycleStateView::ActiveClient { .. }
        ));
        owner
            .shutdown_active()
            .expect("crossed start retained the exact client for shutdown");
        assert!(matches!(
            owner.state(),
            DesktopRunnerLifecycleStateView::CleanupRequired { .. }
        ));
    }

    #[test]
    fn lifecycle_owner_consuming_shutdown_failure_retains_cleanup_custody() {
        let (harness, mut ledger) = TestHarness::new("lifecycle-owner-shutdown-failure");
        let launch = harness.launch("lifecycle-owner-shutdown-failure");
        let client = RunnerLifecycleClient::launch_with_spawner(
            &mut ledger,
            &harness.authority,
            &harness.policy,
            launch.clone(),
            transport(
                unique_nonce("lifecycle-owner-shutdown-failure"),
                harness.identity(),
                ScriptMode::EofAt(1),
                false,
                Vec::new(),
            ),
        )
        .expect("initialize shutdown-failure owner client");
        let mut owner = DesktopRunnerLifecycleOwner::from_active_client(
            RunnerLifecycleOwnerConfig {
                runner_binary: harness.runner_binary.clone(),
                private_state_root: harness.private_state.clone(),
            },
            launch,
            client,
        )
        .expect("inject shutdown-failure client");
        assert!(owner.shutdown_active().is_err());
        assert!(matches!(
            owner.state(),
            DesktopRunnerLifecycleStateView::CleanupRequired { cleanup, .. }
                if cleanup.session().is_some()
        ));
    }

    #[test]
    fn lifecycle_owner_recovered_running_never_launches_a_replacement() {
        let (harness, mut ledger) = TestHarness::new("lifecycle-owner-recovered-running");
        let client = RunnerLifecycleClient::launch_with_spawner(
            &mut ledger,
            &harness.authority,
            &harness.policy,
            harness.launch("lifecycle-owner-recovered-running"),
            transport(
                unique_nonce("lifecycle-owner-recovered-running"),
                harness.identity(),
                ScriptMode::Good,
                false,
                Vec::new(),
            ),
        )
        .expect("initialize client whose durable Running state will be recovered");
        let running = client
            .task_attempt_running_boundary()
            .expect("recovered fixture Running boundary")
            .clone();
        let _cleanup = client
            .shutdown()
            .expect("close direct child while leaving durable cleanup unproven");
        let persisted = ledger
            .load_sprint(&harness.sprint_id)
            .expect("load recovered owner sprint");
        let task = persisted.graph.as_ref().expect("fixture graph").tasks[0].clone();
        let config = RunnerLifecycleOwnerConfig {
            runner_binary: harness.runner_binary.clone(),
            private_state_root: harness.private_state.clone(),
        };
        let mut owner = DesktopRunnerLifecycleOwner::new(config)
            .expect("construct recovered production-shaped owner");
        assert!(
            crate::WalkingSkeletonRunnerLifecycle::ensure_task_attempt_running(
                &mut owner,
                &mut ledger,
                crate::WalkingSkeletonRunnerStart {
                    sprint_spec: &harness.sprint_spec,
                    task: &task,
                    attempt: &running.attempt,
                    authority: &harness.authority,
                    policy: &harness.policy,
                    shadow_root: &harness.shadow,
                    input_snapshot: &harness.base_snapshot,
                    requested_at_unix_ms: running.started_at_unix_ms + 1,
                },
            )
            .is_err()
        );
        assert!(matches!(
            owner.state(),
            DesktopRunnerLifecycleStateView::ReconciliationRequired {
                requirement: RunnerLifecycleReconciliation::RecoveredDurableAuthority {
                    running: Some(recovered),
                    ..
                },
                custody: ReconciliationCustodyView::DurableOnly,
            } if recovered == &running
        ));
        let forbidden_replacement = format!("{}:worker-launch-v1", running.attempt.attempt_id);
        assert!(
            ledger
                .load_runner_launch_intent(&harness.sprint_id, &forbidden_replacement)
                .is_err(),
            "recovery must not persist a replacement launch"
        );
    }

    #[test]
    fn lifecycle_owner_recovery_preserves_exact_unobserved_dispatch_claim() {
        let (harness, mut ledger) = TestHarness::new("lifecycle-owner-recovered-claim");
        let mut client = RunnerLifecycleClient::launch_with_spawner(
            &mut ledger,
            &harness.authority,
            &harness.policy,
            harness.launch("lifecycle-owner-recovered-claim"),
            transport(
                unique_nonce("lifecycle-owner-recovered-claim"),
                harness.identity(),
                ScriptMode::Good,
                true,
                b"claimed but unobserved\n".to_vec(),
            ),
        )
        .expect("initialize claimed recovery client");
        client.captured_base = true;
        client.shadow_created = true;
        client.shadow_snapshot = Some(harness.base_snapshot.clone());
        let running = client
            .task_attempt_running_boundary()
            .expect("claimed recovery Running boundary")
            .clone();
        let (_persisted, permit, intent, request_bytes, request) =
            precommit_worker_read(&harness, &mut ledger, &client, "recovered-claim");
        let (client, claimed) = client
            .send_precommitted_effect(&mut ledger, permit, &intent, &request_bytes, request)
            .expect("enter exact transport claim before simulated crash");
        drop(claimed);
        let exact_claim = ledger
            .load_effect(&intent.effect_id)
            .expect("load simulated-crash effect")
            .dispatch_claim
            .expect("transport claim is durable");
        let _cleanup = client
            .shutdown()
            .expect("close direct child without proving platform cleanup");

        let persisted = ledger
            .load_sprint(&harness.sprint_id)
            .expect("load claimed recovery sprint");
        let task = persisted.graph.as_ref().expect("fixture graph").tasks[0].clone();
        let mut owner = DesktopRunnerLifecycleOwner::new(RunnerLifecycleOwnerConfig {
            runner_binary: harness.runner_binary.clone(),
            private_state_root: harness.private_state.clone(),
        })
        .expect("construct owner after simulated crash");
        assert!(
            crate::WalkingSkeletonRunnerLifecycle::ensure_task_attempt_running(
                &mut owner,
                &mut ledger,
                crate::WalkingSkeletonRunnerStart {
                    sprint_spec: &harness.sprint_spec,
                    task: &task,
                    attempt: &running.attempt,
                    authority: &harness.authority,
                    policy: &harness.policy,
                    shadow_root: &harness.shadow,
                    input_snapshot: &harness.base_snapshot,
                    requested_at_unix_ms: running.started_at_unix_ms + 1,
                },
            )
            .is_err()
        );
        assert!(matches!(
            owner.state(),
            DesktopRunnerLifecycleStateView::ReconciliationRequired {
                requirement: RunnerLifecycleReconciliation::RecoveredDurableAuthority {
                    unresolved_effect: Some(effect),
                    ..
                },
                custody: ReconciliationCustodyView::DurableOnly,
            } if effect.intent.effect_id == intent.effect_id
                && effect.dispatch_claim.as_ref() == Some(&exact_claim)
                && effect.observation.is_none()
        ));
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "the owner regression keeps phase mapping, exact evidence persistence, authority, acknowledgement, and cleanup custody contiguous"
    )]
    fn lifecycle_owner_maps_claimed_transport_phase_and_persists_the_same_evidence() {
        for (label, progress, failed_before_effect) in [
            ("zero", ScriptWriteProgress::None, true),
            ("partial", ScriptWriteProgress::One, false),
        ] {
            let fixture_label = format!("lifecycle-owner-claimed-failure-{label}");
            let (harness, mut ledger) = TestHarness::new(&fixture_label);
            let manifest = WorkspaceManifest::capture(&harness.authority, 1_200)
                .expect("capture claimed-failure owner base");
            let owner_shadow = ShadowWorkspace::create(
                &harness.authority,
                &manifest,
                harness.root.join(format!("claimed-failure-shadow-{label}")),
            )
            .expect("create claimed-failure owner shadow");
            let mut launch = harness.launch(&fixture_label);
            launch.shadow_root = Some(owner_shadow.root().to_path_buf());
            let mut client = RunnerLifecycleClient::launch_with_spawner(
                &mut ledger,
                &harness.authority,
                &harness.policy,
                launch.clone(),
                transport(
                    unique_nonce(&fixture_label),
                    harness.identity(),
                    ScriptMode::WriteFailureAt(1, progress),
                    true,
                    Vec::new(),
                ),
            )
            .expect("initialize claimed-failure owner client");
            client.captured_base = true;
            client.shadow_created = true;
            client.shadow_snapshot = Some(harness.base_snapshot.clone());
            let running = client
                .task_attempt_running_boundary()
                .expect("claimed-failure Running boundary")
                .clone();
            let session = client.session().clone();
            let runner_launch = ledger
                .load_runner_launch_intent(&harness.sprint_id, &session.launch_id)
                .expect("load claimed-failure launch");
            let (persisted, permit, intent, request_bytes, _request) =
                precommit_worker_read(&harness, &mut ledger, &client, label);
            let provider_call =
                decode_tool_call(&request_bytes).expect("decode exact owner provider call");
            let mut owner = DesktopRunnerLifecycleOwner::from_active_client(
                RunnerLifecycleOwnerConfig {
                    runner_binary: harness.runner_binary.clone(),
                    private_state_root: harness.private_state.clone(),
                },
                launch,
                client,
            )
            .expect("inject claimed-failure owner client");

            let claimed = crate::WalkingSkeletonRunnerLifecycle::dispatch_task_effect(
                &mut owner,
                &mut ledger,
                crate::WalkingSkeletonTaskEffectDispatch {
                    sprint_spec: &harness.sprint_spec,
                    workspace_grant: &harness.authority,
                    policy: &harness.policy,
                    running_boundary: &running,
                    runner_launch: &runner_launch,
                    runner_session: &session,
                    intent: &intent,
                    request_bytes: &request_bytes,
                    provider_call: &provider_call,
                    post_response_timestamps:
                        &mut crate::durable_coordinator::TimestampCursor::from_next_for_test(
                            intent.created_at_unix_ms.saturating_add(1),
                        ),
                    shadow: &owner_shadow,
                    dispatch_permit: permit,
                },
            )
            .expect("claimed transport failure maps to a terminalizable typed response");
            assert!(matches!(
                (&claimed.response().outcome, failed_before_effect),
                (
                    crate::WalkingSkeletonTaskEffectOutcome::FailedBeforeEffect { .. },
                    true
                ) | (
                    crate::WalkingSkeletonTaskEffectOutcome::UnknownAfterDispatch { .. },
                    false
                )
            ));
            assert!(matches!(
                owner.state(),
                DesktopRunnerLifecycleStateView::ReconciliationRequired {
                    requirement: RunnerLifecycleReconciliation::AwaitingTerminalObservation { .. },
                    custody: ReconciliationCustodyView::Cleanup { .. },
                }
            ));
            let (_response, observation_authority, failure_evidence) = claimed.into_parts();
            let (failure_phase, failure_evidence) =
                failure_evidence.expect("owner transfers exact claimed failure evidence");
            assert_eq!(
                matches!(
                    failure_phase,
                    RunnerEffectFailurePhase::NoRequestBytesWritten
                ),
                failed_before_effect
            );
            let evidence_value: serde_json::Value = serde_json::from_slice(&failure_evidence)
                .expect("decode owner claimed failure evidence");
            assert_eq!(
                evidence_value["dispatch_claim_id"].as_str(),
                ledger
                    .load_effect(&intent.effect_id)
                    .expect("reload owner claimed effect")
                    .dispatch_claim
                    .as_ref()
                    .map(|claim| claim.dispatch_claim_id.as_str())
            );
            let outcome = if failed_before_effect {
                EffectOutcome::FailedBeforeEffect {
                    evidence_digest: Digest::sha256(&failure_evidence),
                }
            } else {
                EffectOutcome::Unknown {
                    evidence_digest: Digest::sha256(&failure_evidence),
                }
            };
            let observation = observation(
                &intent,
                format!("owner-claimed-failure-observation-{label}"),
                outcome,
                intent.created_at_unix_ms + 1,
            );
            let terminal = terminal_event(
                &ledger,
                &intent,
                &persisted.proposed_event.event_id,
                &observation,
            );
            let completed = ledger
                .record_claimed_effect_observation(
                    observation_authority,
                    &observation,
                    &failure_evidence,
                    &terminal,
                )
                .expect("persist same claimed owner failure evidence");
            crate::WalkingSkeletonRunnerLifecycle::acknowledge_task_effect_observation(
                &mut owner, &ledger, &completed,
            )
            .expect("acknowledge claimed owner failure terminal");
            assert!(if failed_before_effect {
                matches!(
                    owner.state(),
                    DesktopRunnerLifecycleStateView::ReconciliationRequired {
                        requirement: RunnerLifecycleReconciliation::EffectDispatchFailed { .. },
                        custody: ReconciliationCustodyView::Cleanup { .. },
                    }
                )
            } else {
                matches!(
                    owner.state(),
                    DesktopRunnerLifecycleStateView::ReconciliationRequired {
                        requirement: RunnerLifecycleReconciliation::RunnerRequestedReconciliation { .. },
                        custody: ReconciliationCustodyView::Cleanup { .. },
                    }
                )
            });
            assert_eq!(
                completed.evidence_bytes.as_deref(),
                Some(failure_evidence.as_slice())
            );
        }
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "the test keeps claim, transport, terminal persistence, owner acknowledgement, and cleanup in one exact end-to-end fixture"
    )]
    fn lifecycle_owner_claims_once_and_waits_for_exact_terminal_acknowledgement() {
        let (harness, mut ledger) = TestHarness::new("lifecycle-owner-dispatch");
        let manifest = WorkspaceManifest::capture(&harness.authority, 1_200)
            .expect("capture owner dispatch shadow base");
        let owner_shadow = ShadowWorkspace::create(
            &harness.authority,
            &manifest,
            harness.root.join("owner-dispatch-shadow"),
        )
        .expect("create owner dispatch shadow");
        let mut launch = harness.launch("lifecycle-owner-dispatch");
        launch.shadow_root = Some(owner_shadow.root().to_path_buf());
        let exchange_count = Rc::new(Cell::new(0));
        let expected_bytes = b"owner lifecycle read\n".to_vec();
        let mut client = RunnerLifecycleClient::launch_with_spawner(
            &mut ledger,
            &harness.authority,
            &harness.policy,
            launch.clone(),
            transport_with_exchange_count(
                unique_nonce("lifecycle-owner-dispatch"),
                harness.identity(),
                ScriptMode::Good,
                true,
                expected_bytes.clone(),
                Rc::clone(&exchange_count),
            ),
        )
        .expect("initialize owner dispatch client");
        client.captured_base = true;
        client.shadow_created = true;
        client.shadow_snapshot = Some(harness.base_snapshot.clone());
        let running = client
            .task_attempt_running_boundary()
            .expect("owner dispatch Running boundary")
            .clone();
        let session = client.session().clone();
        let runner_launch = ledger
            .load_runner_launch_intent(&harness.sprint_id, &session.launch_id)
            .expect("load exact owner launch");
        let (persisted, permit, intent, request_bytes, _request) =
            precommit_worker_read(&harness, &mut ledger, &client, "owner");
        let provider_call =
            decode_tool_call(&request_bytes).expect("decode exact owner provider call");
        let config = RunnerLifecycleOwnerConfig {
            runner_binary: harness.runner_binary.clone(),
            private_state_root: harness.private_state.clone(),
        };
        let mut owner = DesktopRunnerLifecycleOwner::from_active_client(config, launch, client)
            .expect("inject prepared owner client");

        let claimed = crate::WalkingSkeletonRunnerLifecycle::dispatch_task_effect(
            &mut owner,
            &mut ledger,
            crate::WalkingSkeletonTaskEffectDispatch {
                sprint_spec: &harness.sprint_spec,
                workspace_grant: &harness.authority,
                policy: &harness.policy,
                running_boundary: &running,
                runner_launch: &runner_launch,
                runner_session: &session,
                intent: &intent,
                request_bytes: &request_bytes,
                provider_call: &provider_call,
                post_response_timestamps:
                    &mut crate::durable_coordinator::TimestampCursor::from_next_for_test(
                        intent.created_at_unix_ms.saturating_add(1),
                    ),
                shadow: &owner_shadow,
                dispatch_permit: permit,
            },
        )
        .expect("dispatch exact precommitted owner read");
        let result = match &claimed.response().outcome {
            crate::WalkingSkeletonTaskEffectOutcome::Succeeded(result) => result.as_ref().clone(),
            outcome => panic!("unexpected owner read outcome: {outcome:?}"),
        };
        assert!(matches!(
            &result.output,
            grok_build_providers::ProviderToolOutput::RelativeFileRead { contents, .. }
                if contents == &expected_bytes
        ));
        assert_eq!(exchange_count.get(), 2);
        assert!(matches!(
            owner.state(),
            DesktopRunnerLifecycleStateView::ReconciliationRequired {
                requirement: RunnerLifecycleReconciliation::AwaitingTerminalObservation { .. },
                custody: ReconciliationCustodyView::LiveClient { .. },
            }
        ));
        let (_typed_response, observation_authority, claimed_failure_evidence) =
            claimed.into_parts();
        assert!(claimed_failure_evidence.is_none());
        let evidence = encode_tool_result(&result).expect("encode exact owner result evidence");
        let observed_at = intent.created_at_unix_ms + 1;
        let observation = EffectObservation {
            contract_version: CONTRACT_VERSION,
            observation_id: format!("{}:observation", intent.effect_id),
            effect_id: intent.effect_id.clone(),
            idempotency_key: intent.idempotency_key.clone(),
            sprint_id: intent.sprint_id.clone(),
            task_id: intent.task_id.clone(),
            worker_id: intent.worker_id.clone(),
            worker_lease: intent.worker_lease.clone(),
            correlation_id: intent.correlation_id.clone(),
            kind: intent.kind,
            request_digest: intent.request_digest.clone(),
            policy_hash: intent.policy_hash.clone(),
            input_snapshot: intent.input_snapshot.clone(),
            outcome: EffectOutcome::Succeeded {
                evidence_digest: Digest::sha256(&evidence),
            },
            observed_at_unix_ms: observed_at,
        };
        let terminal = AgentEvent {
            contract_version: CONTRACT_VERSION,
            sequence: ledger
                .next_sequence(&harness.sprint_id)
                .expect("next owner terminal sequence"),
            event_id: format!("{}:finished", intent.effect_id),
            sprint_id: intent.sprint_id.clone(),
            task_id: intent.task_id.clone(),
            worker_id: intent.worker_id.clone(),
            causation_id: Some(persisted.proposed_event.event_id.clone()),
            correlation_id: intent.correlation_id.clone(),
            policy_hash: Some(intent.policy_hash.clone()),
            occurred_at_unix_ms: observed_at,
            payload: AgentEventKind::ToolFinished {
                tool_call_id: intent.idempotency_key.clone(),
                succeeded: true,
            },
        };
        let completed = ledger
            .record_claimed_effect_observation(
                observation_authority,
                &observation,
                &evidence,
                &terminal,
            )
            .expect("terminalize exact owner dispatch claim");
        crate::WalkingSkeletonRunnerLifecycle::acknowledge_task_effect_observation(
            &mut owner, &ledger, &completed,
        )
        .expect("acknowledge exact durable terminal effect");
        assert!(matches!(
            owner.state(),
            DesktopRunnerLifecycleStateView::ActiveClient { .. }
        ));
        owner
            .shutdown_active()
            .expect("shutdown acknowledged owner");
        assert_eq!(exchange_count.get(), 3);
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "the regression retains claim, raw response digest, observation authority, terminal evidence, lifecycle custody, and restart fencing for both adaptation failures"
    )]
    fn lifecycle_owner_terminalizes_correlated_provider_adaptation_rejections() {
        for (label, response, search) in [
            (
                "oversized-search",
                RunnerResponse::LiteralSearch {
                    path: "README.md".into(),
                    file_digest: Digest::sha256(b"oversized search fixture"),
                    file_length: 2,
                    matches: vec![
                        grok_build_runner::WireLiteralMatch {
                            byte_offset: 0,
                            line: 1,
                            column: 1,
                        },
                        grok_build_runner::WireLiteralMatch {
                            byte_offset: 1,
                            line: 1,
                            column: 2,
                        },
                    ],
                },
                true,
            ),
            (
                "invalid-diagnostic",
                RunnerResponse::Failed {
                    code: "invalid_provider_diagnostic".into(),
                    class: WireFailureClass::BeforeEffect,
                    reconciliation: None,
                    message: "line one\nline two".into(),
                },
                false,
            ),
        ] {
            let fixture_label = format!("owner-adaptation-{label}");
            let (harness, mut ledger) = TestHarness::new(&fixture_label);
            let manifest = WorkspaceManifest::capture(&harness.authority, 1_200)
                .expect("capture adaptation owner base");
            let owner_shadow = ShadowWorkspace::create(
                &harness.authority,
                &manifest,
                harness.root.join(format!("adaptation-shadow-{label}")),
            )
            .expect("create adaptation owner shadow");
            let mut launch = harness.launch(&fixture_label);
            launch.shadow_root = Some(owner_shadow.root().to_path_buf());
            let exchange_count = Rc::new(Cell::new(0));
            let mut client = RunnerLifecycleClient::launch_with_spawner(
                &mut ledger,
                &harness.authority,
                &harness.policy,
                launch.clone(),
                transport_with_worker_response(
                    unique_nonce(&fixture_label),
                    harness.identity(),
                    response,
                    Rc::clone(&exchange_count),
                ),
            )
            .expect("initialize adaptation owner client");
            client.captured_base = true;
            client.shadow_created = true;
            client.shadow_snapshot = Some(harness.base_snapshot.clone());
            let running = client
                .task_attempt_running_boundary()
                .expect("adaptation owner Running boundary")
                .clone();
            let session = client.session().clone();
            let runner_launch = ledger
                .load_runner_launch_intent(&harness.sprint_id, &session.launch_id)
                .expect("load adaptation owner launch");
            let (persisted, permit, intent, request_bytes, _request) = if search {
                precommit_worker_search(&harness, &mut ledger, &client, label)
            } else {
                precommit_worker_read(&harness, &mut ledger, &client, label)
            };
            let provider_call =
                decode_tool_call(&request_bytes).expect("decode exact owner provider call");
            let mut owner = DesktopRunnerLifecycleOwner::from_active_client(
                RunnerLifecycleOwnerConfig {
                    runner_binary: harness.runner_binary.clone(),
                    private_state_root: harness.private_state.clone(),
                },
                launch,
                client,
            )
            .expect("inject adaptation owner client");

            let claimed = crate::WalkingSkeletonRunnerLifecycle::dispatch_task_effect(
                &mut owner,
                &mut ledger,
                crate::WalkingSkeletonTaskEffectDispatch {
                    sprint_spec: &harness.sprint_spec,
                    workspace_grant: &harness.authority,
                    policy: &harness.policy,
                    running_boundary: &running,
                    runner_launch: &runner_launch,
                    runner_session: &session,
                    intent: &intent,
                    request_bytes: &request_bytes,
                    provider_call: &provider_call,
                    post_response_timestamps:
                        &mut crate::durable_coordinator::TimestampCursor::from_next_for_test(
                            intent.created_at_unix_ms.saturating_add(1),
                        ),
                    shadow: &owner_shadow,
                    dispatch_permit: permit,
                },
            )
            .expect("adaptation rejection returns terminalizable claimed Unknown");
            assert!(matches!(
                claimed.response().outcome,
                crate::WalkingSkeletonTaskEffectOutcome::UnknownAfterDispatch { .. }
            ));
            assert!(claimed.response().mutation_receipt.is_none());
            assert_eq!(exchange_count.get(), 2);
            assert!(matches!(
                owner.state(),
                DesktopRunnerLifecycleStateView::ReconciliationRequired {
                    requirement: RunnerLifecycleReconciliation::AwaitingTerminalObservation { .. },
                    custody: ReconciliationCustodyView::LiveClient { .. },
                }
            ));
            let (_response, observation_authority, failure_evidence) = claimed.into_parts();
            let (phase, evidence) =
                failure_evidence.expect("adaptation rejection retains canonical claimed evidence");
            assert_eq!(phase, RunnerEffectFailurePhase::CorrelatedResponseRejected);
            let evidence_value: serde_json::Value =
                serde_json::from_slice(&evidence).expect("decode adaptation rejection evidence");
            assert_eq!(
                evidence_value["phase"].as_str(),
                Some("correlated-response-rejected")
            );
            assert_eq!(
                evidence_value["accepted_request_bytes"].as_u64(),
                evidence_value["request_frame_bytes"].as_u64()
            );
            assert!(
                evidence_value["correlated_response_frame_digest"]
                    .as_str()
                    .is_some()
            );
            let exact_claim = ledger
                .load_effect(&intent.effect_id)
                .expect("load adaptation claim")
                .dispatch_claim
                .expect("adaptation dispatch claim");
            assert_eq!(
                evidence_value["dispatch_claim_id"].as_str(),
                Some(exact_claim.dispatch_claim_id.as_str())
            );

            let observed = observation(
                &intent,
                format!("adaptation-observation-{label}"),
                EffectOutcome::Unknown {
                    evidence_digest: Digest::sha256(&evidence),
                },
                intent.created_at_unix_ms + 1,
            );
            let terminal = terminal_event(
                &ledger,
                &intent,
                &persisted.proposed_event.event_id,
                &observed,
            );
            let completed = ledger
                .record_claimed_effect_observation(
                    observation_authority,
                    &observed,
                    &evidence,
                    &terminal,
                )
                .expect("terminalize adaptation rejection as Unknown");
            crate::WalkingSkeletonRunnerLifecycle::acknowledge_task_effect_observation(
                &mut owner, &ledger, &completed,
            )
            .expect("acknowledge adaptation rejection terminal");
            assert!(matches!(
                owner.state(),
                DesktopRunnerLifecycleStateView::ReconciliationRequired {
                    requirement: RunnerLifecycleReconciliation::RunnerRequestedReconciliation { .. },
                    custody: ReconciliationCustodyView::LiveClient { .. },
                }
            ));
            owner
                .prepare_reconciliation_cleanup()
                .expect("convert adaptation reconciliation to cleanup custody");
            assert!(matches!(
                owner.state(),
                DesktopRunnerLifecycleStateView::ReconciliationRequired {
                    requirement: RunnerLifecycleReconciliation::RunnerRequestedReconciliation { .. },
                    custody: ReconciliationCustodyView::Cleanup { .. },
                }
            ));
            assert_eq!(exchange_count.get(), 3);
            drop(owner);

            let persisted_sprint = ledger
                .load_sprint(&harness.sprint_id)
                .expect("load adaptation sprint before restart");
            let task = persisted_sprint
                .graph
                .as_ref()
                .expect("adaptation graph")
                .tasks[0]
                .clone();
            let mut restarted = DesktopRunnerLifecycleOwner::new(RunnerLifecycleOwnerConfig {
                runner_binary: harness.runner_binary.clone(),
                private_state_root: harness.private_state.clone(),
            })
            .expect("construct restarted adaptation owner");
            assert!(
                crate::WalkingSkeletonRunnerLifecycle::ensure_task_attempt_running(
                    &mut restarted,
                    &mut ledger,
                    crate::WalkingSkeletonRunnerStart {
                        sprint_spec: &harness.sprint_spec,
                        task: &task,
                        attempt: &running.attempt,
                        authority: &harness.authority,
                        policy: &harness.policy,
                        shadow_root: owner_shadow.root(),
                        input_snapshot: &harness.base_snapshot,
                        requested_at_unix_ms: intent.created_at_unix_ms + 2,
                    },
                )
                .is_err()
            );
            assert!(matches!(
                restarted.state(),
                DesktopRunnerLifecycleStateView::ReconciliationRequired {
                    custody: ReconciliationCustodyView::DurableOnly,
                    ..
                }
            ));
            let reloaded = ledger
                .load_effect(&intent.effect_id)
                .expect("reload adaptation effect after restart fencing");
            assert_eq!(reloaded.dispatch_claim.as_ref(), Some(&exact_claim));
            assert!(matches!(
                reloaded
                    .observation
                    .as_ref()
                    .map(|observation| &observation.outcome),
                Some(EffectOutcome::Unknown { .. })
            ));
            assert_eq!(
                reloaded.evidence_bytes.as_deref(),
                Some(evidence.as_slice())
            );
            assert_eq!(exchange_count.get(), 3, "{label} replayed after restart");
        }
    }
