    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "the production restart regression keeps the exact reopen claim, zero-survivor receipt, durable readback, and final owner state contiguous"
    )]
    fn lifecycle_owner_terminal_final_verifier_restart_reopens_once_and_persists_exact_cleanup() {
        let label = "lifecycle-owner-terminal-final-verifier-restart";
        let RestartTerminalFinalVerifierCleanupFixture {
            harness,
            mut ledger,
            admission,
            completed,
            cleanup_admission,
            cleanup_authority,
            cleanup_at_unix_ms,
            prepare_count,
            release_count,
        } = restart_terminal_final_verifier_cleanup_fixture(label);
        let reopen_count = Rc::new(Cell::new(0));
        let cleanup_count = Rc::new(Cell::new(0));
        let claims = Rc::new(RefCell::new(Vec::new()));
        let expected_next_event_sequence = ledger
            .next_sequence(&harness.sprint_id)
            .expect("read final-verifier cleanup event sequence");
        let mut owner = DesktopRunnerLifecycleOwner::with_native_cleanup_reopener(
            RunnerLifecycleOwnerConfig {
                runner_binary: harness.runner_binary.clone(),
                private_state_root: harness.private_state.clone(),
            },
            Box::new(ScriptedNativeCleanupReopener {
                authority: cleanup_authority,
                reopen_count: Rc::clone(&reopen_count),
                cleanup_count: Rc::clone(&cleanup_count),
                mutation: ScriptedNativeCleanupMutation::Exact,
                claims: Rc::clone(&claims),
            }),
        )
        .expect("construct restarted final-verifier cleanup owner");

        let cleanup_effect =
            match crate::WalkingSkeletonRunnerLifecycle::cleanup_terminal_sprint_final_verification(
                &mut owner,
                &mut ledger,
                crate::WalkingSkeletonFinalVerificationTerminalCleanup {
                    sprint_spec: &harness.sprint_spec,
                    admission: &admission,
                    completed: &completed,
                    outcome:
                        crate::WalkingSkeletonFinalVerificationTerminalOutcome::FailedBeforeEffect,
                    cleanup_at_unix_ms,
                },
            )
            .expect("production owner completes terminal final-verifier restart cleanup")
            {
                crate::WalkingSkeletonFinalVerificationCleanupOutcome::Completed(completed) => {
                    completed
                }
                crate::WalkingSkeletonFinalVerificationCleanupOutcome::CleanupRequired {
                    reason,
                } => {
                    panic!(
                        "exact terminal final-verifier restart cleanup remained pending: {reason}"
                    )
                }
            };

        assert_eq!(reopen_count.get(), 1);
        assert_eq!(cleanup_count.get(), 1);
        assert_eq!(prepare_count.get(), 1, "restart must not prepare again");
        assert_eq!(release_count.get(), 1, "restart must not release again");
        assert_eq!(
            claims.borrow().as_slice(),
            &[CleanupReopenClaimTrace {
                sprint_id: cleanup_admission.launch.sprint_id.clone(),
                launch_id: cleanup_admission.launch.launch_id.clone(),
                session_id: cleanup_admission.launch.session_id.clone(),
                cleanup_effect_id: cleanup_admission.cleanup_effect.intent.effect_id.clone(),
                next_event_sequence: expected_next_event_sequence,
            }]
        );
        assert_eq!(
            cleanup_effect.intent,
            cleanup_admission.cleanup_effect.intent
        );
        assert!(matches!(
            cleanup_effect
                .observation
                .as_ref()
                .map(|observation| &observation.outcome),
            Some(EffectOutcome::Succeeded { .. })
        ));
        let PersistedFinishReceipt::WorkerCleanup(cleanup_evidence) =
            &cleanup_effect.finish_receipt
        else {
            panic!("terminal final-verifier cleanup must retain WorkerCleanup evidence")
        };
        assert_eq!(cleanup_evidence.receipt.surviving_processes, 0);
        assert_eq!(
            cleanup_evidence.receipt.platform_backend,
            cleanup_admission.cleanup_request.platform_backend
        );
        assert_eq!(
            ledger
                .load_effect(&cleanup_admission.cleanup_effect.intent.effect_id)
                .expect("reload terminal final-verifier cleanup effect"),
            cleanup_effect
        );
        assert!(matches!(
            owner.state(),
            DesktopRunnerLifecycleStateView::Idle
        ));
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "the custody-collision regression keeps the rejected unadmitted attempt and the succeeding terminal cleanup in one exact state transition"
    )]
    fn lifecycle_owner_terminal_final_verifier_custody_rejects_unadmitted_then_closes_once() {
        let label = "lifecycle-owner-terminal-final-verifier-custody-collision";
        let RestartTerminalFinalVerifierCleanupFixture {
            harness,
            mut ledger,
            admission,
            completed,
            cleanup_admission,
            cleanup_authority,
            cleanup_at_unix_ms,
            prepare_count,
            release_count,
        } = restart_terminal_final_verifier_cleanup_fixture(label);
        let session = ledger
            .load_runner_session(
                &cleanup_admission.launch.sprint_id,
                &cleanup_admission.launch.session_id,
            )
            .expect("reload terminal final-verifier session for custody collision");
        let retained = admitted_cleanup_without_native_custody(
            cleanup_admission.clone(),
            session,
            cleanup_authority.platform_binding().clone(),
        );
        let pending_cleanup = ledger
            .load_effect(&cleanup_admission.cleanup_effect.intent.effect_id)
            .expect("load pending terminal final-verifier cleanup");
        let reopen_count = Rc::new(Cell::new(0));
        let cleanup_count = Rc::new(Cell::new(0));
        let claims = Rc::new(RefCell::new(Vec::new()));
        let mut owner = DesktopRunnerLifecycleOwner::from_custody_free_final_verifier_cleanup_with_reopener_for_test(
            RunnerLifecycleOwnerConfig {
                runner_binary: harness.runner_binary.clone(),
                private_state_root: harness.private_state.clone(),
            },
            retained,
            admission.final_snapshot.clone(),
            Box::new(ScriptedNativeCleanupReopener {
                authority: cleanup_authority,
                reopen_count: Rc::clone(&reopen_count),
                cleanup_count: Rc::clone(&cleanup_count),
                mutation: ScriptedNativeCleanupMutation::Exact,
                claims: Rc::clone(&claims),
            }),
        )
        .expect("construct retained terminal final-verifier cleanup owner");

        let Err(wrong_path_error) =
            crate::WalkingSkeletonRunnerLifecycle::cleanup_unadmitted_sprint_final_verifier_launch(
                &mut owner,
                &mut ledger,
                crate::WalkingSkeletonUnadmittedFinalVerifierCleanup {
                    sprint_spec: &harness.sprint_spec,
                    launch_id: &cleanup_admission.launch.launch_id,
                    final_snapshot: &admission.final_snapshot,
                    cleanup_at_unix_ms,
                },
            )
        else {
            panic!("terminal final-verifier custody entered the unadmitted cleanup path")
        };
        assert!(
            wrong_path_error
                .to_string()
                .contains("command-effect authority"),
            "unexpected wrong-path rejection: {wrong_path_error}"
        );
        assert_eq!((reopen_count.get(), cleanup_count.get()), (0, 0));
        assert!(claims.borrow().is_empty());
        assert_eq!(
            ledger
                .load_effect(&cleanup_admission.cleanup_effect.intent.effect_id)
                .expect("wrong cleanup path cannot write a terminal"),
            pending_cleanup
        );
        assert!(matches!(
            owner.state(),
            DesktopRunnerLifecycleStateView::FinalVerifierCleanupRequired { cleanup, .. }
                if !cleanup.has_native_cleanup_custody()
        ));

        let cleanup_effect =
            match crate::WalkingSkeletonRunnerLifecycle::cleanup_terminal_sprint_final_verification(
                &mut owner,
                &mut ledger,
                crate::WalkingSkeletonFinalVerificationTerminalCleanup {
                    sprint_spec: &harness.sprint_spec,
                    admission: &admission,
                    completed: &completed,
                    outcome:
                        crate::WalkingSkeletonFinalVerificationTerminalOutcome::FailedBeforeEffect,
                    cleanup_at_unix_ms,
                },
            )
            .expect("exact terminal cleanup succeeds after the unadmitted path rejects")
            {
                crate::WalkingSkeletonFinalVerificationCleanupOutcome::Completed(completed) => {
                    completed
                }
                crate::WalkingSkeletonFinalVerificationCleanupOutcome::CleanupRequired {
                    reason,
                } => {
                    panic!("exact terminal final-verifier cleanup remained pending: {reason}")
                }
            };
        assert_eq!((reopen_count.get(), cleanup_count.get()), (1, 1));
        assert_eq!(claims.borrow().len(), 1);
        assert_eq!((prepare_count.get(), release_count.get()), (1, 1));
        assert_eq!(
            cleanup_effect.intent,
            cleanup_admission.cleanup_effect.intent
        );
        assert!(matches!(
            cleanup_effect
                .observation
                .as_ref()
                .map(|observation| &observation.outcome),
            Some(EffectOutcome::Succeeded { .. })
        ));
        assert_eq!(
            ledger
                .load_effect(&cleanup_admission.cleanup_effect.intent.effect_id)
                .expect("reload collision-regression cleanup terminal"),
            cleanup_effect
        );
        assert!(matches!(
            owner.state(),
            DesktopRunnerLifecycleStateView::Idle
        ));
    }

    #[test]
    fn lifecycle_owner_terminal_final_verifier_restart_without_reopener_stays_cleanup_required() {
        let label = "lifecycle-owner-terminal-final-verifier-missing-reopener";
        let RestartTerminalFinalVerifierCleanupFixture {
            harness,
            mut ledger,
            admission,
            completed,
            cleanup_admission,
            cleanup_authority: _,
            cleanup_at_unix_ms,
            prepare_count,
            release_count,
        } = restart_terminal_final_verifier_cleanup_fixture(label);
        let pending_cleanup = ledger
            .load_effect(&cleanup_admission.cleanup_effect.intent.effect_id)
            .expect("load pending final-verifier cleanup before missing-reopener retry");
        let mut owner = DesktopRunnerLifecycleOwner::new(RunnerLifecycleOwnerConfig {
            runner_binary: harness.runner_binary.clone(),
            private_state_root: harness.private_state.clone(),
        })
        .expect("construct restarted owner without cleanup-only journal access");

        let outcome =
            crate::WalkingSkeletonRunnerLifecycle::cleanup_terminal_sprint_final_verification(
                &mut owner,
                &mut ledger,
                crate::WalkingSkeletonFinalVerificationTerminalCleanup {
                    sprint_spec: &harness.sprint_spec,
                    admission: &admission,
                    completed: &completed,
                    outcome:
                        crate::WalkingSkeletonFinalVerificationTerminalOutcome::FailedBeforeEffect,
                    cleanup_at_unix_ms,
                },
            )
            .expect("missing reopener remains a typed cleanup requirement");
        assert!(matches!(
            outcome,
            crate::WalkingSkeletonFinalVerificationCleanupOutcome::CleanupRequired { ref reason }
                if reason.contains("reopener")
        ));
        assert_eq!(prepare_count.get(), 1, "restart must not prepare again");
        assert_eq!(release_count.get(), 1, "restart must not release again");
        assert_eq!(
            ledger
                .load_effect(&cleanup_admission.cleanup_effect.intent.effect_id)
                .expect("missing reopener cannot write cleanup terminal"),
            pending_cleanup
        );
        assert!(matches!(
            owner.state(),
            DesktopRunnerLifecycleStateView::Idle
        ));
    }

    #[test]
    fn lifecycle_owner_terminal_final_verifier_crossed_reopener_retains_custody_without_native_call()
     {
        let label = "lifecycle-owner-terminal-final-verifier-crossed-reopener";
        let RestartTerminalFinalVerifierCleanupFixture {
            harness,
            mut ledger,
            admission,
            completed,
            cleanup_admission,
            mut cleanup_authority,
            cleanup_at_unix_ms,
            prepare_count,
            release_count,
        } = restart_terminal_final_verifier_cleanup_fixture(label);
        let session = ledger
            .load_runner_session(
                &cleanup_admission.launch.sprint_id,
                &cleanup_admission.launch.session_id,
            )
            .expect("reload exact final-verifier session for retained cleanup");
        let retained = admitted_cleanup_without_native_custody(
            cleanup_admission.clone(),
            session,
            cleanup_authority.platform_binding().clone(),
        );
        cleanup_authority.expected_platform_binding_digest =
            Digest::sha256(b"crossed-terminal-final-verifier-cleanup-authority");
        let pending_cleanup = ledger
            .load_effect(&cleanup_admission.cleanup_effect.intent.effect_id)
            .expect("load pending terminal final-verifier cleanup");
        let reopen_count = Rc::new(Cell::new(0));
        let cleanup_count = Rc::new(Cell::new(0));
        let claims = Rc::new(RefCell::new(Vec::new()));
        let mut owner = DesktopRunnerLifecycleOwner::from_custody_free_final_verifier_cleanup_with_reopener_for_test(
            RunnerLifecycleOwnerConfig {
                runner_binary: harness.runner_binary.clone(),
                private_state_root: harness.private_state.clone(),
            },
            retained,
            admission.final_snapshot.clone(),
            Box::new(UncheckedNativeCleanupReopener {
                authority: cleanup_authority,
                reopen_count: Rc::clone(&reopen_count),
                cleanup_count: Rc::clone(&cleanup_count),
                claims: Rc::clone(&claims),
            }),
        )
        .expect("construct crossed retained final-verifier cleanup owner");

        for (index, requested_at_unix_ms) in
            [cleanup_at_unix_ms, cleanup_at_unix_ms.saturating_add(1)]
                .into_iter()
                .enumerate()
        {
            let outcome = crate::WalkingSkeletonRunnerLifecycle::cleanup_terminal_sprint_final_verification(
                &mut owner,
                &mut ledger,
                crate::WalkingSkeletonFinalVerificationTerminalCleanup {
                    sprint_spec: &harness.sprint_spec,
                    admission: &admission,
                    completed: &completed,
                    outcome: crate::WalkingSkeletonFinalVerificationTerminalOutcome::FailedBeforeEffect,
                    cleanup_at_unix_ms: requested_at_unix_ms,
                },
            )
            .expect("crossed final-verifier custody remains a typed cleanup requirement");
            assert!(matches!(
                outcome,
                crate::WalkingSkeletonFinalVerificationCleanupOutcome::CleanupRequired { .. }
            ));
            assert_eq!(
                reopen_count.get(),
                1,
                "same cleanup claim must not reopen on pass {index}"
            );
            assert_eq!(
                cleanup_count.get(),
                0,
                "crossed authority must reject before native cleanup on pass {index}"
            );
            assert_eq!(claims.borrow().len(), 1);
            assert_eq!(
                ledger
                    .load_effect(&cleanup_admission.cleanup_effect.intent.effect_id)
                    .expect("crossed authority leaves cleanup effect pending"),
                pending_cleanup
            );
            assert!(matches!(
                owner.state(),
                DesktopRunnerLifecycleStateView::FinalVerifierCleanupRequired { cleanup, .. }
                    if cleanup.has_native_cleanup_custody()
            ));
        }
        assert_eq!(prepare_count.get(), 1);
        assert_eq!(release_count.get(), 1);
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum LiveStateEffectScript {
        Success,
        AdaptationRejected,
        NoRequestBytesWritten,
    }

    struct UnadmittedLiveStateOwnerFixture {
        harness: TestHarness,
        ledger: EventLedger,
        plan: SprintLiveStateCapturePlan,
        owner: DesktopRunnerLifecycleOwner,
        cleanup_at_unix_ms: u64,
        launch_cleanup_admission: PersistedRunnerLaunchCleanupAdmission,
        cleanup_authority: NativeLaunchCleanupAuthority,
        prepare_count: Rc<Cell<u64>>,
        release_count: Rc<Cell<u64>>,
        native_cleanup_count: Rc<Cell<u64>>,
        exchange_count: Rc<Cell<u64>>,
    }

    struct SessionlessUnadmittedLiveStateRestartFixture {
        harness: TestHarness,
        ledger: EventLedger,
        policy: CompiledExecutionPolicy,
        plan: SprintLiveStateCapturePlan,
        session: RunnerSessionPolicyRecord,
        launch_cleanup_admission: PersistedRunnerLaunchCleanupAdmission,
        cleanup_authority: NativeLaunchCleanupAuthority,
        cleanup_at_unix_ms: u64,
    }

    fn sessionless_unadmitted_live_state_restart_fixture(
        label: &str,
    ) -> SessionlessUnadmittedLiveStateRestartFixture {
        let (harness, mut ledger) = TestHarness::new(label);
        let AuthoritativePostCompletionPreparation::UnlaunchedLiveState(prepared) =
            prepare_authoritative_post_completion_dispatch_inner(
                &harness,
                &mut ledger,
                label,
                AuthoritativePostCompletionFixtureMode::StopBeforeLiveStateLaunch,
            )
        else {
            unreachable!("sessionless live-state fixture crossed its prelaunch stop")
        };
        let UnlaunchedLiveStatePreparation { policy, plan } = prepared;
        let launch = launch_live_state_completion_role_with_registration(
            &harness,
            &mut ledger,
            &policy,
            &plan,
            &format!("{label}-sessionless-live-state"),
            false,
        );
        let launch_cleanup_admission = ledger
            .load_runner_launch_cleanup_admission(&harness.sprint_id, &launch.launch.launch_id)
            .expect("reload sessionless live-state launch cleanup admission");
        assert_eq!(launch_cleanup_admission.launch, launch.launch);
        assert!(matches!(
            ledger.load_runner_session(&harness.sprint_id, &launch.session.session_id),
            Err(LedgerError::ArtifactNotFound { .. })
        ));
        let (cleanup_authority, cleanup_at_unix_ms) = persist_scripted_native_preparation_authority(
            &harness,
            &mut ledger,
            &policy,
            &launch_cleanup_admission,
            label,
        );
        SessionlessUnadmittedLiveStateRestartFixture {
            harness,
            ledger,
            policy,
            plan,
            session: launch.session,
            launch_cleanup_admission,
            cleanup_authority,
            cleanup_at_unix_ms,
        }
    }

    #[allow(
        clippy::too_many_lines,
        reason = "the fixture keeps the exact post-application plan, native launch, active production owner, and cleanup journal authority contiguous"
    )]
    fn unadmitted_live_state_owner_fixture(
        label: &str,
        mutation: ScriptedNativeCleanupMutation,
    ) -> UnadmittedLiveStateOwnerFixture {
        let (harness, mut ledger) = TestHarness::new(label);
        let AuthoritativePostCompletionPreparation::UnlaunchedLiveState(prepared) =
            prepare_authoritative_post_completion_dispatch_inner(
                &harness,
                &mut ledger,
                label,
                AuthoritativePostCompletionFixtureMode::StopBeforeLiveStateLaunch,
            )
        else {
            unreachable!("unadmitted live-state fixture crossed its prelaunch stop")
        };
        let UnlaunchedLiveStatePreparation { policy, plan } = prepared;
        let prepare_count = Rc::new(Cell::new(0));
        let release_count = Rc::new(Cell::new(0));
        let native_cleanup_count = Rc::new(Cell::new(0));
        let exchange_count = Rc::new(Cell::new(0));
        let service = AdversarialNativeLaunchService::new(
            RunnerLaunchPreparationDisposition::HeldChildPrepared,
            NativeReleaseMutation::Exact,
            transport_with_optional_effect_response(
                unique_nonce(&format!("{label}-unadmitted-live-state")),
                harness.identity(),
                ScriptMode::Good,
                None,
                Rc::clone(&exchange_count),
            ),
            Rc::clone(&prepare_count),
            Rc::clone(&release_count),
        )
        .with_cleanup_script(Rc::clone(&native_cleanup_count), mutation);
        let mut launch_request = harness.launch(&format!("{label}-unadmitted-live-state"));
        launch_request.role = RunnerRole::LiveStateVerifier;
        launch_request.worker_id = None;
        launch_request.worker_lease = None;
        launch_request.shadow_root = None;
        launch_request.expected_base_snapshot = plan.expected_snapshot.clone();
        launch_request.created_at_unix_ms = plan.planned_at_unix_ms.saturating_add(1);
        let retained_request = launch_request.clone();
        let client = RunnerLifecycleClient::launch_live_state_verifier_with_native_service(
            &mut ledger,
            &harness.authority,
            &policy,
            &plan,
            launch_request,
            Box::new(service),
        )
        .expect("launch exact unadmitted live-state verifier");
        let launch_cleanup_admission = client
            .launch_cleanup_admission()
            .expect("unadmitted live-state verifier retains cleanup admission")
            .clone();
        let preparation = ledger
            .load_runner_launch_preparation(
                &launch_cleanup_admission.launch.sprint_id,
                &launch_cleanup_admission.launch.launch_id,
            )
            .expect("reload unadmitted live-state native preparation");
        let cleanup_authority = NativeLaunchCleanupAuthority::from_expected_state(
            &launch_cleanup_admission,
            Some(&preparation),
            client
                .platform_launch_binding
                .as_deref()
                .expect("unadmitted live-state verifier retains platform binding"),
        );
        let owner = DesktopRunnerLifecycleOwner::from_active_live_state_verifier_for_test(
            RunnerLifecycleOwnerConfig {
                runner_binary: harness.runner_binary.clone(),
                private_state_root: harness.private_state.clone(),
            },
            retained_request,
            client,
            plan.clone(),
        )
        .expect("construct exact active unadmitted live-state owner");
        let cleanup_at_unix_ms =
            native_cleanup_requested_at_unix_ms(&ledger, &launch_cleanup_admission)
                .saturating_add(1);
        UnadmittedLiveStateOwnerFixture {
            harness,
            ledger,
            plan,
            owner,
            cleanup_at_unix_ms,
            launch_cleanup_admission,
            cleanup_authority,
            prepare_count,
            release_count,
            native_cleanup_count,
            exchange_count,
        }
    }

    #[test]
    fn lifecycle_owner_unadmitted_live_state_active_cleanup_retains_retries_and_closes() {
        let mut fixture = unadmitted_live_state_owner_fixture(
            "lifecycle-owner-unadmitted-live-state-active",
            ScriptedNativeCleanupMutation::FailOnceBeforeObservation,
        );
        let pending_cleanup = fixture.launch_cleanup_admission.cleanup_effect.clone();
        let first = crate::WalkingSkeletonRunnerLifecycle::cleanup_unadmitted_sprint_live_state_verifier_launch(
            &mut fixture.owner,
            &mut fixture.ledger,
            crate::WalkingSkeletonUnadmittedLiveStateVerifierCleanup {
                sprint_spec: &fixture.harness.sprint_spec,
                launch_id: &fixture.launch_cleanup_admission.launch.launch_id,
                plan: &fixture.plan,
                cleanup_at_unix_ms: fixture.cleanup_at_unix_ms,
            },
        )
        .expect("first live unadmitted verifier cleanup remains a typed requirement");
        assert!(matches!(
            first,
            crate::WalkingSkeletonUnadmittedLiveStateVerifierCleanupOutcome::CleanupRequired { .. }
        ));
        assert_eq!(fixture.native_cleanup_count.get(), 1);
        assert_eq!(fixture.exchange_count.get(), 2);
        assert!(matches!(
            fixture.owner.state(),
            DesktopRunnerLifecycleStateView::LiveStateVerifierCleanupRequired { cleanup, .. }
                if cleanup.has_native_cleanup_custody()
        ));
        assert_eq!(
            fixture
                .ledger
                .load_effect(&pending_cleanup.intent.effect_id)
                .expect("failed native cleanup leaves exact obligation pending"),
            pending_cleanup
        );

        let mut crossed_plan = fixture.plan.clone();
        crossed_plan.expected_snapshot = Digest::sha256(b"crossed-unadmitted-live-state-plan");
        crate::WalkingSkeletonRunnerLifecycle::cleanup_unadmitted_sprint_live_state_verifier_launch(
            &mut fixture.owner,
            &mut fixture.ledger,
            crate::WalkingSkeletonUnadmittedLiveStateVerifierCleanup {
                sprint_spec: &fixture.harness.sprint_spec,
                launch_id: &fixture.launch_cleanup_admission.launch.launch_id,
                plan: &crossed_plan,
                cleanup_at_unix_ms: fixture.cleanup_at_unix_ms.saturating_add(1),
            },
        )
        .expect_err("crossed plan cannot consume retained native custody");
        assert_eq!(fixture.native_cleanup_count.get(), 1);
        assert!(matches!(
            fixture.owner.state(),
            DesktopRunnerLifecycleStateView::LiveStateVerifierCleanupRequired { cleanup, .. }
                if cleanup.has_native_cleanup_custody()
        ));

        let completed = crate::WalkingSkeletonRunnerLifecycle::cleanup_unadmitted_sprint_live_state_verifier_launch(
            &mut fixture.owner,
            &mut fixture.ledger,
            crate::WalkingSkeletonUnadmittedLiveStateVerifierCleanup {
                sprint_spec: &fixture.harness.sprint_spec,
                launch_id: &fixture.launch_cleanup_admission.launch.launch_id,
                plan: &fixture.plan,
                cleanup_at_unix_ms: fixture.cleanup_at_unix_ms.saturating_add(2),
            },
        )
        .expect("exact retained live-state cleanup retry completes");
        let crate::WalkingSkeletonUnadmittedLiveStateVerifierCleanupOutcome::Completed(completed) =
            completed
        else {
            panic!("exact retained live-state cleanup retry remained pending")
        };
        assert_eq!(fixture.native_cleanup_count.get(), 2);
        assert_eq!(
            (fixture.prepare_count.get(), fixture.release_count.get()),
            (1, 1)
        );
        assert_eq!(
            fixture
                .ledger
                .load_effect(&completed.intent.effect_id)
                .expect("reload exact live-state launch-gap cleanup"),
            completed
        );
        assert!(matches!(
            fixture.owner.state(),
            DesktopRunnerLifecycleStateView::Idle
        ));
    }

    #[test]
    fn lifecycle_owner_unadmitted_live_state_sessionless_restart_reopens_and_closes() {
        let SessionlessUnadmittedLiveStateRestartFixture {
            harness,
            mut ledger,
            policy: _,
            plan,
            session,
            launch_cleanup_admission,
            cleanup_authority,
            cleanup_at_unix_ms,
        } = sessionless_unadmitted_live_state_restart_fixture(
            "lifecycle-owner-unadmitted-live-state-sessionless-restart",
        );
        let reopen_count = Rc::new(Cell::new(0));
        let cleanup_count = Rc::new(Cell::new(0));
        let claims = Rc::new(RefCell::new(Vec::new()));
        let mut owner = DesktopRunnerLifecycleOwner::with_native_cleanup_reopener(
            RunnerLifecycleOwnerConfig {
                runner_binary: harness.runner_binary.clone(),
                private_state_root: harness.private_state.clone(),
            },
            Box::new(ScriptedNativeCleanupReopener {
                authority: cleanup_authority,
                reopen_count: Rc::clone(&reopen_count),
                cleanup_count: Rc::clone(&cleanup_count),
                mutation: ScriptedNativeCleanupMutation::Exact,
                claims: Rc::clone(&claims),
            }),
        )
        .expect("construct sessionless live-state restart owner");
        let outcome = crate::WalkingSkeletonRunnerLifecycle::cleanup_unadmitted_sprint_live_state_verifier_launch(
            &mut owner,
            &mut ledger,
            crate::WalkingSkeletonUnadmittedLiveStateVerifierCleanup {
                sprint_spec: &harness.sprint_spec,
                launch_id: &launch_cleanup_admission.launch.launch_id,
                plan: &plan,
                cleanup_at_unix_ms,
            },
        )
        .expect("sessionless live-state restart closes exact launch");
        let crate::WalkingSkeletonUnadmittedLiveStateVerifierCleanupOutcome::Completed(completed) =
            outcome
        else {
            panic!("sessionless live-state restart remained cleanup-required")
        };
        assert_eq!((reopen_count.get(), cleanup_count.get()), (1, 1));
        assert_eq!(claims.borrow().len(), 1);
        assert!(matches!(
            ledger.load_runner_session(&harness.sprint_id, &session.session_id),
            Err(LedgerError::ArtifactNotFound { .. })
        ));
        assert_eq!(
            ledger
                .load_effect(&completed.intent.effect_id)
                .expect("reload sessionless live-state cleanup terminal"),
            completed
        );
        assert!(matches!(
            owner.state(),
            DesktopRunnerLifecycleStateView::Idle
        ));
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "the restart regression keeps sessionless reopening, failed native custody, late exact registration, timestamp flooring, and retained retry contiguous"
    )]
    fn lifecycle_owner_unadmitted_live_state_retained_sessionless_custody_adopts_late_registration()
    {
        let SessionlessUnadmittedLiveStateRestartFixture {
            harness,
            mut ledger,
            policy,
            plan,
            mut session,
            launch_cleanup_admission,
            cleanup_authority,
            cleanup_at_unix_ms,
        } = sessionless_unadmitted_live_state_restart_fixture(
            "lifecycle-owner-unadmitted-live-state-late-registration",
        );
        let reopen_count = Rc::new(Cell::new(0));
        let cleanup_count = Rc::new(Cell::new(0));
        let mut owner = DesktopRunnerLifecycleOwner::with_native_cleanup_reopener(
            RunnerLifecycleOwnerConfig {
                runner_binary: harness.runner_binary.clone(),
                private_state_root: harness.private_state.clone(),
            },
            Box::new(ScriptedNativeCleanupReopener {
                authority: cleanup_authority,
                reopen_count: Rc::clone(&reopen_count),
                cleanup_count: Rc::clone(&cleanup_count),
                mutation: ScriptedNativeCleanupMutation::FailOnceBeforeObservation,
                claims: Rc::new(RefCell::new(Vec::new())),
            }),
        )
        .expect("construct sessionless retained live-state restart owner");
        let first = crate::WalkingSkeletonRunnerLifecycle::cleanup_unadmitted_sprint_live_state_verifier_launch(
            &mut owner,
            &mut ledger,
            crate::WalkingSkeletonUnadmittedLiveStateVerifierCleanup {
                sprint_spec: &harness.sprint_spec,
                launch_id: &launch_cleanup_admission.launch.launch_id,
                plan: &plan,
                cleanup_at_unix_ms,
            },
        )
        .expect("failed sessionless native cleanup retains exact custody");
        assert!(matches!(
            first,
            crate::WalkingSkeletonUnadmittedLiveStateVerifierCleanupOutcome::CleanupRequired { .. }
        ));
        assert_eq!((reopen_count.get(), cleanup_count.get()), (1, 1));
        assert!(matches!(
            owner.state(),
            DesktopRunnerLifecycleStateView::LiveStateVerifierCleanupRequired { cleanup, .. }
                if matches!(
                    cleanup.session_registration(),
                    RunnerSessionRegistrationState::NotRegistered
                ) && cleanup.has_native_cleanup_custody()
        ));

        session.registered_at_unix_ms = cleanup_at_unix_ms.saturating_add(10);
        ledger
            .register_live_state_verifier_session(&plan, &session, &policy)
            .expect("register exact live-state session after retained native attempt");
        let second = crate::WalkingSkeletonRunnerLifecycle::cleanup_unadmitted_sprint_live_state_verifier_launch(
            &mut owner,
            &mut ledger,
            crate::WalkingSkeletonUnadmittedLiveStateVerifierCleanup {
                sprint_spec: &harness.sprint_spec,
                launch_id: &launch_cleanup_admission.launch.launch_id,
                plan: &plan,
                cleanup_at_unix_ms: session.registered_at_unix_ms.saturating_add(1),
            },
        )
        .expect("retained live-state cleanup adopts late exact registration");
        let crate::WalkingSkeletonUnadmittedLiveStateVerifierCleanupOutcome::Completed(completed) =
            second
        else {
            panic!("late-registration live-state retry remained cleanup-required")
        };
        assert_eq!((reopen_count.get(), cleanup_count.get()), (1, 2));
        let PersistedFinishReceipt::WorkerCleanup(evidence) = &completed.finish_receipt else {
            panic!("late-registration cleanup must persist worker-cleanup evidence")
        };
        assert_eq!(evidence.receipt.session_id, session.session_id);
        assert_eq!(
            evidence.receipt.cleaned_at_unix_ms,
            session.registered_at_unix_ms.saturating_add(1)
        );
        assert!(matches!(
            owner.state(),
            DesktopRunnerLifecycleStateView::Idle
        ));
    }

    #[test]
    fn lifecycle_owner_unadmitted_live_state_idle_restart_reopens_once_and_closes() {
        let UnadmittedLiveStateOwnerFixture {
            harness,
            mut ledger,
            plan,
            owner,
            cleanup_at_unix_ms,
            launch_cleanup_admission,
            cleanup_authority,
            prepare_count,
            release_count,
            native_cleanup_count: original_native_cleanup_count,
            exchange_count,
        } = unadmitted_live_state_owner_fixture(
            "lifecycle-owner-unadmitted-live-state-restart",
            ScriptedNativeCleanupMutation::Exact,
        );
        drop(owner);
        let reopen_count = Rc::new(Cell::new(0));
        let cleanup_count = Rc::new(Cell::new(0));
        let claims = Rc::new(RefCell::new(Vec::new()));
        let next_event_sequence = ledger
            .next_sequence(&harness.sprint_id)
            .expect("read launch-gap restart cleanup event sequence");
        let mut owner = DesktopRunnerLifecycleOwner::with_native_cleanup_reopener(
            RunnerLifecycleOwnerConfig {
                runner_binary: harness.runner_binary.clone(),
                private_state_root: harness.private_state.clone(),
            },
            Box::new(ScriptedNativeCleanupReopener {
                authority: cleanup_authority,
                reopen_count: Rc::clone(&reopen_count),
                cleanup_count: Rc::clone(&cleanup_count),
                mutation: ScriptedNativeCleanupMutation::FailOnceBeforeObservation,
                claims: Rc::clone(&claims),
            }),
        )
        .expect("construct launch-gap live-state restart owner");
        let make_cleanup =
            |cleanup_at_unix_ms| crate::WalkingSkeletonUnadmittedLiveStateVerifierCleanup {
                sprint_spec: &harness.sprint_spec,
                launch_id: &launch_cleanup_admission.launch.launch_id,
                plan: &plan,
                cleanup_at_unix_ms,
            };
        let first = crate::WalkingSkeletonRunnerLifecycle::cleanup_unadmitted_sprint_live_state_verifier_launch(
            &mut owner,
            &mut ledger,
            make_cleanup(cleanup_at_unix_ms),
        )
        .expect("first reopened launch-gap cleanup remains pending");
        assert!(matches!(
            first,
            crate::WalkingSkeletonUnadmittedLiveStateVerifierCleanupOutcome::CleanupRequired { .. }
        ));
        assert_eq!((reopen_count.get(), cleanup_count.get()), (1, 1));
        assert!(matches!(
            owner.state(),
            DesktopRunnerLifecycleStateView::LiveStateVerifierCleanupRequired { cleanup, .. }
                if cleanup.has_native_cleanup_custody()
        ));

        let second = crate::WalkingSkeletonRunnerLifecycle::cleanup_unadmitted_sprint_live_state_verifier_launch(
            &mut owner,
            &mut ledger,
            make_cleanup(cleanup_at_unix_ms.saturating_add(1)),
        )
        .expect("retained reopened launch-gap cleanup completes");
        let crate::WalkingSkeletonUnadmittedLiveStateVerifierCleanupOutcome::Completed(completed) =
            second
        else {
            panic!("retained reopened launch-gap cleanup remained pending")
        };
        assert_eq!((reopen_count.get(), cleanup_count.get()), (1, 2));
        assert_eq!(original_native_cleanup_count.get(), 0);
        assert_eq!((prepare_count.get(), release_count.get()), (1, 1));
        assert_eq!(exchange_count.get(), 1);
        assert_eq!(
            claims.borrow().as_slice(),
            &[CleanupReopenClaimTrace {
                sprint_id: launch_cleanup_admission.launch.sprint_id.clone(),
                launch_id: launch_cleanup_admission.launch.launch_id.clone(),
                session_id: launch_cleanup_admission.launch.session_id.clone(),
                cleanup_effect_id: launch_cleanup_admission
                    .cleanup_effect
                    .intent
                    .effect_id
                    .clone(),
                next_event_sequence,
            }]
        );
        assert_eq!(
            ledger
                .load_effect(&completed.intent.effect_id)
                .expect("reload reopened launch-gap cleanup"),
            completed
        );
        assert!(matches!(
            owner.state(),
            DesktopRunnerLifecycleStateView::Idle
        ));
    }

    #[test]
    fn lifecycle_owner_unadmitted_live_state_restart_without_reopener_writes_nothing() {
        let UnadmittedLiveStateOwnerFixture {
            harness,
            mut ledger,
            plan,
            owner,
            cleanup_at_unix_ms,
            launch_cleanup_admission,
            cleanup_authority: _,
            prepare_count,
            release_count,
            native_cleanup_count,
            exchange_count,
        } = unadmitted_live_state_owner_fixture(
            "lifecycle-owner-unadmitted-live-state-missing-reopener",
            ScriptedNativeCleanupMutation::Exact,
        );
        drop(owner);
        let pending = ledger
            .load_effect(&launch_cleanup_admission.cleanup_effect.intent.effect_id)
            .expect("load pending launch-gap cleanup before missing reopener");
        let mut owner = DesktopRunnerLifecycleOwner::new(RunnerLifecycleOwnerConfig {
            runner_binary: harness.runner_binary.clone(),
            private_state_root: harness.private_state.clone(),
        })
        .expect("construct live-state restart owner without reopener");
        let outcome = crate::WalkingSkeletonRunnerLifecycle::cleanup_unadmitted_sprint_live_state_verifier_launch(
            &mut owner,
            &mut ledger,
            crate::WalkingSkeletonUnadmittedLiveStateVerifierCleanup {
                sprint_spec: &harness.sprint_spec,
                launch_id: &launch_cleanup_admission.launch.launch_id,
                plan: &plan,
                cleanup_at_unix_ms,
            },
        )
        .expect("missing reopener is a typed cleanup-required stop");
        assert!(matches!(
            outcome,
            crate::WalkingSkeletonUnadmittedLiveStateVerifierCleanupOutcome::CleanupRequired { ref reason }
                if reason.contains("reopener")
        ));
        assert_eq!((prepare_count.get(), release_count.get()), (1, 1));
        assert_eq!(native_cleanup_count.get(), 0);
        assert_eq!(exchange_count.get(), 1);
        assert_eq!(
            ledger
                .load_effect(&launch_cleanup_admission.cleanup_effect.intent.effect_id)
                .expect("missing reopener cannot close launch-gap cleanup"),
            pending
        );
        assert!(matches!(
            owner.state(),
            DesktopRunnerLifecycleStateView::Idle
        ));
    }

    #[test]
    fn lifecycle_owner_unadmitted_live_state_crossed_reopener_retains_custody_once() {
        let UnadmittedLiveStateOwnerFixture {
            harness,
            mut ledger,
            plan,
            owner,
            cleanup_at_unix_ms,
            launch_cleanup_admission,
            mut cleanup_authority,
            prepare_count,
            release_count,
            native_cleanup_count,
            exchange_count,
        } = unadmitted_live_state_owner_fixture(
            "lifecycle-owner-unadmitted-live-state-crossed-reopener",
            ScriptedNativeCleanupMutation::Exact,
        );
        drop(owner);
        cleanup_authority.expected_platform_binding_digest =
            Digest::sha256(b"crossed-unadmitted-live-state-cleanup-authority");
        let pending = ledger
            .load_effect(&launch_cleanup_admission.cleanup_effect.intent.effect_id)
            .expect("load pending crossed launch-gap cleanup");
        let reopen_count = Rc::new(Cell::new(0));
        let cleanup_count = Rc::new(Cell::new(0));
        let claims = Rc::new(RefCell::new(Vec::new()));
        let mut owner = DesktopRunnerLifecycleOwner::with_native_cleanup_reopener(
            RunnerLifecycleOwnerConfig {
                runner_binary: harness.runner_binary.clone(),
                private_state_root: harness.private_state.clone(),
            },
            Box::new(UncheckedNativeCleanupReopener {
                authority: cleanup_authority,
                reopen_count: Rc::clone(&reopen_count),
                cleanup_count: Rc::clone(&cleanup_count),
                claims: Rc::clone(&claims),
            }),
        )
        .expect("construct crossed launch-gap cleanup reopener");
        for requested_at_unix_ms in [cleanup_at_unix_ms, cleanup_at_unix_ms.saturating_add(1)] {
            let outcome = crate::WalkingSkeletonRunnerLifecycle::cleanup_unadmitted_sprint_live_state_verifier_launch(
                &mut owner,
                &mut ledger,
                crate::WalkingSkeletonUnadmittedLiveStateVerifierCleanup {
                    sprint_spec: &harness.sprint_spec,
                    launch_id: &launch_cleanup_admission.launch.launch_id,
                    plan: &plan,
                    cleanup_at_unix_ms: requested_at_unix_ms,
                },
            )
            .expect("crossed reopened launch-gap custody remains cleanup-required");
            assert!(matches!(
                outcome,
                crate::WalkingSkeletonUnadmittedLiveStateVerifierCleanupOutcome::CleanupRequired { .. }
            ));
            assert_eq!(reopen_count.get(), 1);
            assert_eq!(cleanup_count.get(), 0);
            assert_eq!(claims.borrow().len(), 1);
            assert_eq!(
                ledger
                    .load_effect(&launch_cleanup_admission.cleanup_effect.intent.effect_id)
                    .expect("crossed launch-gap custody leaves cleanup pending"),
                pending
            );
            assert!(matches!(
                owner.state(),
                DesktopRunnerLifecycleStateView::LiveStateVerifierCleanupRequired { cleanup, .. }
                    if cleanup.has_native_cleanup_custody()
            ));
        }
        assert_eq!((prepare_count.get(), release_count.get()), (1, 1));
        assert_eq!(native_cleanup_count.get(), 0);
        assert_eq!(exchange_count.get(), 1);
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "the behavior regression proves launch, injected readback failure, shutdown custody transfer, relaunch fencing, and retained cleanup retry end to end"
    )]
    fn lifecycle_owner_live_state_post_launch_readback_failure_retains_exact_cleanup_custody() {
        let label = "lifecycle-owner-live-state-post-launch-readback-failure";
        let (harness, mut ledger) = TestHarness::new(label);
        let AuthoritativePostCompletionPreparation::UnlaunchedLiveState(prepared) =
            prepare_authoritative_post_completion_dispatch_inner(
                &harness,
                &mut ledger,
                label,
                AuthoritativePostCompletionFixtureMode::StopBeforeLiveStateLaunch,
            )
        else {
            unreachable!("post-launch readback fixture crossed its prelaunch stop")
        };
        let UnlaunchedLiveStatePreparation { policy, plan } = prepared;
        let prepare_count = Rc::new(Cell::new(0));
        let release_count = Rc::new(Cell::new(0));
        let native_cleanup_count = Rc::new(Cell::new(0));
        let exchange_count = Rc::new(Cell::new(0));
        let readback_count = Rc::new(Cell::new(0_u64));
        let service = AdversarialNativeLaunchService::new(
            RunnerLaunchPreparationDisposition::HeldChildPrepared,
            NativeReleaseMutation::Exact,
            transport_with_optional_effect_response(
                unique_nonce(label),
                harness.identity(),
                ScriptMode::Good,
                None,
                Rc::clone(&exchange_count),
            ),
            Rc::clone(&prepare_count),
            Rc::clone(&release_count),
        )
        .with_cleanup_script(
            Rc::clone(&native_cleanup_count),
            ScriptedNativeCleanupMutation::FailOnceBeforeObservation,
        );
        let requested_at_unix_ms = plan.planned_at_unix_ms.saturating_add(1);
        let mut owner = DesktopRunnerLifecycleOwner::new(RunnerLifecycleOwnerConfig {
            runner_binary: harness.runner_binary.clone(),
            private_state_root: harness.private_state.clone(),
        })
        .expect("construct live-state post-launch readback owner");
        let prepare_count_for_fault = Rc::clone(&prepare_count);
        let release_count_for_fault = Rc::clone(&release_count);
        let exchange_count_for_fault = Rc::clone(&exchange_count);
        let readback_count_for_fault = Rc::clone(&readback_count);
        owner
            .ensure_sprint_live_state_verifier_with_test_io(
                &mut ledger,
                &crate::WalkingSkeletonLiveStateVerifierStart {
                    sprint_spec: &harness.sprint_spec,
                    workspace_grant: &harness.authority,
                    policy: &policy,
                    plan: &plan,
                    requested_at_unix_ms,
                },
                |ledger, request| {
                    RunnerLifecycleClient::launch_live_state_verifier_with_native_service(
                        ledger,
                        &harness.authority,
                        &policy,
                        &plan,
                        request,
                        Box::new(service),
                    )
                },
                move |ledger, sprint_id, launch_id| {
                    assert_eq!(prepare_count_for_fault.get(), 1);
                    assert_eq!(release_count_for_fault.get(), 1);
                    assert_eq!(exchange_count_for_fault.get(), 1);
                    let session = ledger
                        .load_runner_session(
                            sprint_id,
                            &format!("{sprint_id}:walking-skeleton-live-state-capture-v1:session"),
                        )
                        .expect("session initialization precedes injected readback failure");
                    assert_eq!(session.launch_id, launch_id);
                    readback_count_for_fault.set(readback_count_for_fault.get().saturating_add(1));
                    Err(LedgerError::Corrupt {
                        entity: "injected post-launch live-state readback",
                        detail: "test-only transient readback fault".into(),
                    })
                },
            )
            .expect_err("injected post-launch readback must retain cleanup custody");
        assert_eq!(readback_count.get(), 1);
        assert_eq!((prepare_count.get(), release_count.get()), (1, 1));
        assert_eq!(exchange_count.get(), 2);
        assert_eq!(native_cleanup_count.get(), 0);
        let launch_id = format!(
            "{}:walking-skeleton-live-state-capture-v1:launch",
            harness.sprint_id
        );
        let durable_launch = ledger
            .load_runner_launch_intent(&harness.sprint_id, &launch_id)
            .expect("injected transient fault leaves exact durable launch readable");
        let cleanup_admission = ledger
            .load_runner_launch_cleanup_admission(&harness.sprint_id, &launch_id)
            .expect("read exact post-launch cleanup admission");
        match owner.state() {
            DesktopRunnerLifecycleStateView::LiveStateVerifierCleanupRequired {
                binding,
                cleanup,
            } => {
                assert_eq!(binding.sprint_id, harness.sprint_id);
                assert_eq!(binding.launch_id, launch_id);
                assert_eq!(binding.session_id, durable_launch.session_id);
                assert_eq!(binding.plan, &plan);
                assert_eq!(cleanup.launch(), &durable_launch);
                assert_eq!(cleanup.launch_cleanup_admission(), Some(&cleanup_admission));
                assert!(cleanup.has_native_cleanup_custody());
                assert!(matches!(
                    cleanup.session_registration(),
                    RunnerSessionRegistrationState::Registered(session)
                        if session.session_id == durable_launch.session_id
                ));
            }
            _ => panic!("post-launch readback failure lost exact live-state cleanup custody"),
        }
        crate::WalkingSkeletonRunnerLifecycle::ensure_sprint_live_state_verifier(
            &mut owner,
            &mut ledger,
            crate::WalkingSkeletonLiveStateVerifierStart {
                sprint_spec: &harness.sprint_spec,
                workspace_grant: &harness.authority,
                policy: &policy,
                plan: &plan,
                requested_at_unix_ms: requested_at_unix_ms.saturating_add(1),
            },
        )
        .expect_err("retained post-launch custody must fence replacement launch");
        assert_eq!(
            (
                prepare_count.get(),
                release_count.get(),
                exchange_count.get()
            ),
            (1, 1, 2)
        );

        let cleanup_at_unix_ms =
            native_cleanup_requested_at_unix_ms(&ledger, &cleanup_admission).saturating_add(1);
        let first = crate::WalkingSkeletonRunnerLifecycle::cleanup_unadmitted_sprint_live_state_verifier_launch(
            &mut owner,
            &mut ledger,
            crate::WalkingSkeletonUnadmittedLiveStateVerifierCleanup {
                sprint_spec: &harness.sprint_spec,
                launch_id: &launch_id,
                plan: &plan,
                cleanup_at_unix_ms,
            },
        )
        .expect("first retained post-launch cleanup remains pending");
        assert!(matches!(
            first,
            crate::WalkingSkeletonUnadmittedLiveStateVerifierCleanupOutcome::CleanupRequired { .. }
        ));
        assert_eq!(native_cleanup_count.get(), 1);
        let second = crate::WalkingSkeletonRunnerLifecycle::cleanup_unadmitted_sprint_live_state_verifier_launch(
            &mut owner,
            &mut ledger,
            crate::WalkingSkeletonUnadmittedLiveStateVerifierCleanup {
                sprint_spec: &harness.sprint_spec,
                launch_id: &launch_id,
                plan: &plan,
                cleanup_at_unix_ms: cleanup_at_unix_ms.saturating_add(1),
            },
        )
        .expect("exact retained post-launch cleanup retry completes");
        assert!(matches!(
            second,
            crate::WalkingSkeletonUnadmittedLiveStateVerifierCleanupOutcome::Completed(_)
        ));
        assert_eq!(native_cleanup_count.get(), 2);
        assert_eq!(exchange_count.get(), 2);
        assert!(matches!(
            owner.state(),
            DesktopRunnerLifecycleStateView::Idle
        ));
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "the behavior regression keeps TaskDone preparation, native launch, injected readback failure, shutdown custody, and exact cleanup retry visible end to end"
    )]
    fn lifecycle_owner_final_verifier_post_launch_readback_failure_retains_exact_cleanup_custody() {
        let label = "lifecycle-owner-final-post-launch-readback-failure";
        let mut integrated =
            restart_integrated_native_cleanup_fixture(&format!("{label}-integrated"));
        let worker_reopen_count = Rc::new(Cell::new(0));
        let worker_cleanup_count = Rc::new(Cell::new(0));
        let mut worker_owner = DesktopRunnerLifecycleOwner::with_native_cleanup_reopener(
            RunnerLifecycleOwnerConfig {
                runner_binary: integrated.harness.runner_binary.clone(),
                private_state_root: integrated.harness.private_state.clone(),
            },
            Box::new(ScriptedNativeCleanupReopener {
                authority: integrated.cleanup_authority.clone(),
                reopen_count: Rc::clone(&worker_reopen_count),
                cleanup_count: Rc::clone(&worker_cleanup_count),
                mutation: ScriptedNativeCleanupMutation::Exact,
                claims: Rc::new(RefCell::new(Vec::new())),
            }),
        )
        .expect("construct TaskDone cleanup owner before final readback fault");
        assert!(matches!(
            crate::WalkingSkeletonRunnerLifecycle::cleanup_integrated_task_attempt(
                &mut worker_owner,
                &mut integrated.ledger,
                crate::WalkingSkeletonIntegratedTaskCleanup {
                    sprint_spec: &integrated.harness.sprint_spec,
                    disposition: &integrated.disposition,
                    cleanup_at_unix_ms: integrated.cleanup_at_unix_ms,
                },
            )
            .expect("complete worker cleanup before final-verifier launch"),
            crate::WalkingSkeletonIntegratedTaskCleanupOutcome::Completed(_)
        ));
        let TaskAttemptDisposition::Integrated(task_integrated) = &integrated.disposition else {
            unreachable!("final readback fixture starts from Integrated")
        };
        let final_snapshot = task_integrated.integration_receipt.result_snapshot.clone();
        let policy = read_only_policy(&integrated.harness, &format!("{label}-policy"));
        let prepare_count = Rc::new(Cell::new(0));
        let release_count = Rc::new(Cell::new(0));
        let native_cleanup_count = Rc::new(Cell::new(0));
        let exchange_count = Rc::new(Cell::new(0));
        let readback_count = Rc::new(Cell::new(0_u64));
        let service = AdversarialNativeLaunchService::new(
            RunnerLaunchPreparationDisposition::HeldChildPrepared,
            NativeReleaseMutation::Exact,
            transport_with_exchange_count(
                unique_nonce(label),
                integrated.harness.identity(),
                ScriptMode::Good,
                true,
                Vec::new(),
                Rc::clone(&exchange_count),
            ),
            Rc::clone(&prepare_count),
            Rc::clone(&release_count),
        )
        .with_cleanup_script(
            Rc::clone(&native_cleanup_count),
            ScriptedNativeCleanupMutation::FailOnceBeforeObservation,
        );
        let requested_at_unix_ms = task_integrated
            .integration_receipt
            .integrated_at_unix_ms
            .saturating_add(10);
        let mut owner = DesktopRunnerLifecycleOwner::new(RunnerLifecycleOwnerConfig {
            runner_binary: integrated.harness.runner_binary.clone(),
            private_state_root: integrated.harness.private_state.clone(),
        })
        .expect("construct final-verifier post-launch readback owner");
        let prepare_count_for_fault = Rc::clone(&prepare_count);
        let release_count_for_fault = Rc::clone(&release_count);
        let exchange_count_for_fault = Rc::clone(&exchange_count);
        let readback_count_for_fault = Rc::clone(&readback_count);
        owner
            .ensure_sprint_final_verifier_with_test_io(
                &mut integrated.ledger,
                &crate::WalkingSkeletonFinalVerifierStart {
                    sprint_spec: &integrated.harness.sprint_spec,
                    workspace_grant: &integrated.harness.authority,
                    policy: &policy,
                    shadow_root: &integrated.harness.shadow,
                    final_snapshot: &final_snapshot,
                    requested_at_unix_ms,
                },
                |ledger, request| {
                    RunnerLifecycleClient::launch_with_native_service(
                        ledger,
                        &integrated.harness.authority,
                        &policy,
                        request,
                        Box::new(service),
                    )
                },
                move |ledger, sprint_id, launch_id| {
                    assert_eq!(prepare_count_for_fault.get(), 1);
                    assert_eq!(release_count_for_fault.get(), 1);
                    assert_eq!(exchange_count_for_fault.get(), 1);
                    let session_id =
                        format!("{sprint_id}:walking-skeleton-final-verification-v1:session");
                    let session = ledger
                        .load_runner_session(sprint_id, &session_id)
                        .expect("final session initialization precedes readback failure");
                    assert_eq!(session.launch_id, launch_id);
                    readback_count_for_fault.set(readback_count_for_fault.get().saturating_add(1));
                    Err(LedgerError::Corrupt {
                        entity: "injected post-launch final-verifier readback",
                        detail: "test-only transient readback fault".into(),
                    })
                },
            )
            .expect_err("injected final-verifier readback fault retains cleanup custody");
        assert_eq!(readback_count.get(), 1);
        assert_eq!((prepare_count.get(), release_count.get()), (1, 1));
        assert_eq!(exchange_count.get(), 2);
        assert_eq!(native_cleanup_count.get(), 0);
        let launch_id = format!(
            "{}:walking-skeleton-final-verification-v1:launch",
            integrated.harness.sprint_id
        );
        let durable_launch = integrated
            .ledger
            .load_runner_launch_intent(&integrated.harness.sprint_id, &launch_id)
            .expect("transient final readback fault leaves durable launch readable");
        let cleanup_admission = integrated
            .ledger
            .load_runner_launch_cleanup_admission(&integrated.harness.sprint_id, &launch_id)
            .expect("read exact final post-launch cleanup admission");
        match owner.state() {
            DesktopRunnerLifecycleStateView::FinalVerifierCleanupRequired { binding, cleanup } => {
                assert_eq!(binding.sprint_id, integrated.harness.sprint_id);
                assert_eq!(binding.launch_id, launch_id);
                assert_eq!(binding.session_id, durable_launch.session_id);
                assert_eq!(binding.final_snapshot, &final_snapshot);
                assert_eq!(cleanup.launch(), &durable_launch);
                assert_eq!(cleanup.launch_cleanup_admission(), Some(&cleanup_admission));
                assert!(cleanup.has_native_cleanup_custody());
            }
            _ => panic!("post-launch final readback fault lost exact cleanup custody"),
        }
        crate::WalkingSkeletonRunnerLifecycle::ensure_sprint_final_verifier(
            &mut owner,
            &mut integrated.ledger,
            crate::WalkingSkeletonFinalVerifierStart {
                sprint_spec: &integrated.harness.sprint_spec,
                workspace_grant: &integrated.harness.authority,
                policy: &policy,
                shadow_root: &integrated.harness.shadow,
                final_snapshot: &final_snapshot,
                requested_at_unix_ms: requested_at_unix_ms.saturating_add(1),
            },
        )
        .expect_err("retained final post-launch custody fences replacement launch");
        let cleanup_at_unix_ms =
            native_cleanup_requested_at_unix_ms(&integrated.ledger, &cleanup_admission)
                .saturating_add(1);
        let first =
            crate::WalkingSkeletonRunnerLifecycle::cleanup_unadmitted_sprint_final_verifier_launch(
                &mut owner,
                &mut integrated.ledger,
                crate::WalkingSkeletonUnadmittedFinalVerifierCleanup {
                    sprint_spec: &integrated.harness.sprint_spec,
                    launch_id: &launch_id,
                    final_snapshot: &final_snapshot,
                    cleanup_at_unix_ms,
                },
            )
            .expect("first final post-launch cleanup remains pending");
        assert!(matches!(
            first,
            crate::WalkingSkeletonUnadmittedFinalVerifierCleanupOutcome::CleanupRequired { .. }
        ));
        assert_eq!(native_cleanup_count.get(), 1);
        let second =
            crate::WalkingSkeletonRunnerLifecycle::cleanup_unadmitted_sprint_final_verifier_launch(
                &mut owner,
                &mut integrated.ledger,
                crate::WalkingSkeletonUnadmittedFinalVerifierCleanup {
                    sprint_spec: &integrated.harness.sprint_spec,
                    launch_id: &launch_id,
                    final_snapshot: &final_snapshot,
                    cleanup_at_unix_ms: cleanup_at_unix_ms.saturating_add(1),
                },
            )
            .expect("exact final post-launch cleanup retry completes");
        assert!(matches!(
            second,
            crate::WalkingSkeletonUnadmittedFinalVerifierCleanupOutcome::Completed(_)
        ));
        assert_eq!(native_cleanup_count.get(), 2);
        assert_eq!(exchange_count.get(), 2);
        assert!(matches!(
            owner.state(),
            DesktopRunnerLifecycleStateView::Idle
        ));
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "the behavior regression keeps trusted-Applier launch, injected readback failure, pre-recovery shutdown custody, crossed cleanup fencing, and exact retry visible end to end"
    )]
    fn lifecycle_owner_application_post_launch_readback_failure_retains_exact_cleanup_custody() {
        let label = "lifecycle-owner-application-post-launch-readback-failure";
        let (harness, mut ledger) = TestHarness::new(label);
        let UnadmittedApplicationPreparation {
            policy,
            final_verification_receipt_id,
            final_verification_terminal,
            application,
            request,
            stage_bundle,
            artifact_assembly_id: _,
        } = prepare_unadmitted_application_fixture(&harness, &mut ledger, label, true);
        let crossed_launch_id = application.launch.launch_id;
        let prepare_count = Rc::new(Cell::new(0));
        let release_count = Rc::new(Cell::new(0));
        let native_cleanup_count = Rc::new(Cell::new(0));
        let exchange_count = Rc::new(Cell::new(0));
        let readback_count = Rc::new(Cell::new(0_u64));
        let service = AdversarialNativeLaunchService::new(
            RunnerLaunchPreparationDisposition::HeldChildPrepared,
            NativeReleaseMutation::Exact,
            transport_with_optional_effect_response(
                unique_nonce(label),
                harness.identity(),
                ScriptMode::Good,
                None,
                Rc::clone(&exchange_count),
            ),
            Rc::clone(&prepare_count),
            Rc::clone(&release_count),
        )
        .with_cleanup_script(
            Rc::clone(&native_cleanup_count),
            ScriptedNativeCleanupMutation::FailOnceBeforeObservation,
        );
        let requested_at_unix_ms = final_verification_terminal
            .occurred_at_unix_ms
            .saturating_add(20);
        let mut owner = DesktopRunnerLifecycleOwner::new(RunnerLifecycleOwnerConfig {
            runner_binary: harness.runner_binary.clone(),
            private_state_root: harness.private_state.clone(),
        })
        .expect("construct application post-launch readback owner");
        let prepare_count_for_fault = Rc::clone(&prepare_count);
        let release_count_for_fault = Rc::clone(&release_count);
        let exchange_count_for_fault = Rc::clone(&exchange_count);
        let readback_count_for_fault = Rc::clone(&readback_count);
        owner
            .ensure_sprint_application_applier_with_test_io(
                &mut ledger,
                &crate::WalkingSkeletonApplicationStart {
                    sprint_spec: &harness.sprint_spec,
                    workspace_grant: &harness.authority,
                    policy: &policy,
                    request: &request,
                    stage_bundle: &stage_bundle,
                    requested_at_unix_ms,
                },
                |ledger, request| {
                    RunnerLifecycleClient::launch_with_native_service(
                        ledger,
                        &harness.authority,
                        &policy,
                        request,
                        Box::new(service),
                    )
                },
                move |ledger, sprint_id, launch_id| {
                    assert_eq!(prepare_count_for_fault.get(), 1);
                    assert_eq!(release_count_for_fault.get(), 1);
                    assert_eq!(
                        exchange_count_for_fault.get(),
                        1,
                        "readback failure must precede both Applier recovery controls"
                    );
                    let session_id = format!("{sprint_id}:walking-skeleton-application-v1:session");
                    let session = ledger
                        .load_runner_session(sprint_id, &session_id)
                        .expect("Applier session initialization precedes readback failure");
                    assert_eq!(session.launch_id, launch_id);
                    readback_count_for_fault.set(readback_count_for_fault.get().saturating_add(1));
                    Err(LedgerError::Corrupt {
                        entity: "injected post-launch application readback",
                        detail: "test-only transient readback fault".into(),
                    })
                },
            )
            .expect_err("injected application readback fault retains cleanup custody");
        assert_eq!(readback_count.get(), 1);
        assert_eq!((prepare_count.get(), release_count.get()), (1, 1));
        assert_eq!(exchange_count.get(), 2);
        assert_eq!(native_cleanup_count.get(), 0);
        let launch_id = format!(
            "{}:walking-skeleton-application-v1:launch",
            harness.sprint_id
        );
        let durable_launch = ledger
            .load_runner_launch_intent(&harness.sprint_id, &launch_id)
            .expect("transient application readback fault leaves durable launch readable");
        let cleanup_admission = ledger
            .load_runner_launch_cleanup_admission(&harness.sprint_id, &launch_id)
            .expect("read exact application post-launch cleanup admission");
        match owner.state() {
            DesktopRunnerLifecycleStateView::ApplicationCleanupRequired { binding, cleanup } => {
                assert_eq!(binding.sprint_id, harness.sprint_id);
                assert_eq!(binding.launch_id, launch_id);
                assert_eq!(binding.session_id, durable_launch.session_id);
                assert_eq!(binding.request, &request);
                assert_eq!(binding.stage_bundle, &stage_bundle);
                assert_eq!(cleanup.launch(), &durable_launch);
                assert_eq!(cleanup.launch_cleanup_admission(), Some(&cleanup_admission));
                assert!(cleanup.has_native_cleanup_custody());
                assert!(matches!(
                    cleanup.session_registration(),
                    RunnerSessionRegistrationState::Registered(session)
                        if session.session_id == durable_launch.session_id
                ));
            }
            _ => panic!("post-launch application readback fault lost exact cleanup custody"),
        }
        crate::WalkingSkeletonRunnerLifecycle::ensure_sprint_application_applier(
            &mut owner,
            &mut ledger,
            crate::WalkingSkeletonApplicationStart {
                sprint_spec: &harness.sprint_spec,
                workspace_grant: &harness.authority,
                policy: &policy,
                request: &request,
                stage_bundle: &stage_bundle,
                requested_at_unix_ms: requested_at_unix_ms.saturating_add(1),
            },
        )
        .expect_err("retained application post-launch custody fences replacement launch");
        assert_eq!(
            (
                prepare_count.get(),
                release_count.get(),
                exchange_count.get()
            ),
            (1, 1, 2)
        );

        let cleanup_at_unix_ms =
            native_cleanup_requested_at_unix_ms(&ledger, &cleanup_admission).saturating_add(1);
        let first = crate::WalkingSkeletonRunnerLifecycle::cleanup_unadmitted_sprint_application_applier_launch(
            &mut owner,
            &mut ledger,
            crate::WalkingSkeletonUnadmittedApplicationApplierCleanup {
                sprint_spec: &harness.sprint_spec,
                launch_id: &launch_id,
                final_verification_receipt_id: &final_verification_receipt_id,
                base_snapshot: &request.change_set.base_snapshot,
                cleanup_at_unix_ms,
            },
        )
        .expect("first application post-launch cleanup remains pending");
        assert!(matches!(
            first,
            crate::WalkingSkeletonUnadmittedApplicationApplierCleanupOutcome::CleanupRequired { .. }
        ));
        assert_eq!(native_cleanup_count.get(), 1);
        crate::WalkingSkeletonRunnerLifecycle::cleanup_unadmitted_sprint_application_applier_launch(
            &mut owner,
            &mut ledger,
            crate::WalkingSkeletonUnadmittedApplicationApplierCleanup {
                sprint_spec: &harness.sprint_spec,
                launch_id: &crossed_launch_id,
                final_verification_receipt_id: &final_verification_receipt_id,
                base_snapshot: &request.change_set.base_snapshot,
                cleanup_at_unix_ms: cleanup_at_unix_ms.saturating_add(1),
            },
        )
        .expect_err("crossed application cleanup cannot consume retained native custody");
        assert_eq!(native_cleanup_count.get(), 1);
        let second = crate::WalkingSkeletonRunnerLifecycle::cleanup_unadmitted_sprint_application_applier_launch(
            &mut owner,
            &mut ledger,
            crate::WalkingSkeletonUnadmittedApplicationApplierCleanup {
                sprint_spec: &harness.sprint_spec,
                launch_id: &launch_id,
                final_verification_receipt_id: &final_verification_receipt_id,
                base_snapshot: &request.change_set.base_snapshot,
                cleanup_at_unix_ms: cleanup_at_unix_ms.saturating_add(2),
            },
        )
        .expect("exact application post-launch cleanup retry completes");
        assert!(matches!(
            second,
            crate::WalkingSkeletonUnadmittedApplicationApplierCleanupOutcome::Completed(_)
        ));
        assert_eq!(native_cleanup_count.get(), 2);
        assert_eq!(exchange_count.get(), 2);
        assert!(matches!(
            owner.state(),
            DesktopRunnerLifecycleStateView::Idle
        ));
    }

    #[test]
    fn lifecycle_owner_unadmitted_live_state_capture_collision_preserves_active_custody() {
        let mut fixture = admitted_live_state_owner_fixture(
            "lifecycle-owner-unadmitted-live-state-collision",
            ScriptedNativeCleanupMutation::Exact,
            LiveStateEffectScript::Success,
        );
        let pending_cleanup = fixture.launch_cleanup_admission.cleanup_effect.clone();
        crate::WalkingSkeletonRunnerLifecycle::cleanup_unadmitted_sprint_live_state_verifier_launch(
            &mut fixture.owner,
            &mut fixture.ledger,
            crate::WalkingSkeletonUnadmittedLiveStateVerifierCleanup {
                sprint_spec: &fixture.harness.sprint_spec,
                launch_id: &fixture.launch_cleanup_admission.launch.launch_id,
                plan: &fixture.admission.plan,
                cleanup_at_unix_ms: fixture.cleanup_at_unix_ms,
            },
        )
        .expect_err("capture admission must fence launch-only cleanup before shutdown");
        assert_eq!(fixture.native_cleanup_count.get(), 0);
        assert_eq!(fixture.exchange_count.get(), 1);
        assert!(fixture.dispatch_permit.is_some());
        assert!(matches!(
            fixture.owner.state(),
            DesktopRunnerLifecycleStateView::ActiveLiveStateVerifier { .. }
        ));
        assert_eq!(
            fixture
                .ledger
                .load_effect(&pending_cleanup.intent.effect_id)
                .expect("collision leaves cleanup effect pristine"),
            pending_cleanup
        );
    }

    struct AdmittedLiveStateOwnerFixture {
        harness: TestHarness,
        ledger: EventLedger,
        policy: CompiledExecutionPolicy,
        admission: SprintLiveStateCaptureAdmission,
        intent: EffectIntent,
        proposed_event_id: String,
        verifier: crate::WalkingSkeletonLiveStateVerifierBoundary,
        owner: DesktopRunnerLifecycleOwner,
        dispatch_permit: Option<FreshLiveStateCaptureDispatchPermit>,
        receipt_id: String,
        observation_id: String,
        observed_at_unix_ms: u64,
        cleanup_at_unix_ms: u64,
        launch_cleanup_admission: PersistedRunnerLaunchCleanupAdmission,
        cleanup_authority: NativeLaunchCleanupAuthority,
        prepare_count: Rc<Cell<u64>>,
        release_count: Rc<Cell<u64>>,
        native_cleanup_count: Rc<Cell<u64>>,
        exchange_count: Rc<Cell<u64>>,
    }

    impl AdmittedLiveStateOwnerFixture {
        fn dispatch(&mut self) -> crate::WalkingSkeletonClaimedLiveStateCaptureResponse {
            let dispatch_permit = self
                .dispatch_permit
                .take()
                .expect("live-state dispatch permit remains fresh");
            crate::WalkingSkeletonRunnerLifecycle::dispatch_sprint_live_state_capture(
                &mut self.owner,
                &mut self.ledger,
                crate::WalkingSkeletonLiveStateCaptureDispatch {
                    sprint_spec: &self.harness.sprint_spec,
                    workspace_grant: &self.harness.authority,
                    policy: &self.policy,
                    verifier: &self.verifier,
                    admission: &self.admission,
                    intent: &self.intent,
                    receipt_id: &self.receipt_id,
                    observation_id: &self.observation_id,
                    dispatch_permit,
                },
            )
            .expect("dispatch exact admitted live-state capture through production owner")
        }
    }

    #[allow(
        clippy::too_many_lines,
        reason = "the fixture keeps the complete post-application plan, native verifier launch, fresh capture permit, and production owner contiguous"
    )]
    fn admitted_live_state_owner_fixture(
        label: &str,
        mutation: ScriptedNativeCleanupMutation,
        effect_script: LiveStateEffectScript,
    ) -> AdmittedLiveStateOwnerFixture {
        let (harness, mut ledger) = TestHarness::new(label);
        let AuthoritativePostCompletionPreparation::UnlaunchedLiveState(prepared) =
            prepare_authoritative_post_completion_dispatch_inner(
                &harness,
                &mut ledger,
                label,
                AuthoritativePostCompletionFixtureMode::StopBeforeLiveStateLaunch,
            )
        else {
            unreachable!("active live-state fixture crossed its prelaunch stop")
        };
        let UnlaunchedLiveStatePreparation { policy, plan } = prepared;
        let capture_started_at_unix_ms = current_unix_ms()
            .expect("read active live-state fixture time")
            .max(plan.planned_at_unix_ms)
            .saturating_add(60_000);
        let captured_at_unix_ms = capture_started_at_unix_ms.saturating_add(1);
        let manifest = DescriptorRelativeWorkspaceManifest::from_captured_entries(
            harness.authority.contract().grant_hash.clone(),
            capture_started_at_unix_ms,
            captured_at_unix_ms,
            vec![DescriptorRelativeManifestEntry {
                path: format!("src/{label}.rs"),
                content_digest: Digest::sha256(
                    format!("post-completion-result-{label}").as_bytes(),
                ),
                byte_length: 1,
                unix_mode: 0o600,
            }],
        )
        .expect("construct exact live-state response manifest");
        assert_eq!(manifest.manifest_digest, plan.expected_snapshot);
        let (transport_mode, response) = match effect_script {
            LiveStateEffectScript::Success | LiveStateEffectScript::AdaptationRejected => (
                ScriptMode::Good,
                Some(RunnerResponse::LiveWorkspaceCaptured {
                    manifest: Box::new(manifest.clone()),
                }),
            ),
            LiveStateEffectScript::NoRequestBytesWritten => (
                ScriptMode::WriteFailureAt(1, ScriptWriteProgress::None),
                None,
            ),
        };
        let prepare_count = Rc::new(Cell::new(0));
        let release_count = Rc::new(Cell::new(0));
        let native_cleanup_count = Rc::new(Cell::new(0));
        let exchange_count = Rc::new(Cell::new(0));
        let service = AdversarialNativeLaunchService::new(
            RunnerLaunchPreparationDisposition::HeldChildPrepared,
            NativeReleaseMutation::Exact,
            transport_with_optional_effect_response(
                unique_nonce(&format!("{label}-active-live-state")),
                harness.identity(),
                transport_mode,
                response,
                Rc::clone(&exchange_count),
            ),
            Rc::clone(&prepare_count),
            Rc::clone(&release_count),
        )
        .with_cleanup_script(Rc::clone(&native_cleanup_count), mutation);
        let mut launch_request = harness.launch(&format!("{label}-active-live-state"));
        launch_request.role = RunnerRole::LiveStateVerifier;
        launch_request.worker_id = None;
        launch_request.worker_lease = None;
        launch_request.shadow_root = None;
        launch_request.expected_base_snapshot = plan.expected_snapshot.clone();
        launch_request.created_at_unix_ms = plan.planned_at_unix_ms.saturating_add(1);
        let retained_request = launch_request.clone();
        let client = RunnerLifecycleClient::launch_live_state_verifier_with_native_service(
            &mut ledger,
            &harness.authority,
            &policy,
            &plan,
            launch_request,
            Box::new(service),
        )
        .expect("launch exact active live-state verifier");
        let launch_cleanup_admission = client
            .launch_cleanup_admission()
            .expect("live-state verifier retains atomic cleanup admission")
            .clone();
        let preparation = ledger
            .load_runner_launch_preparation(
                &launch_cleanup_admission.launch.sprint_id,
                &launch_cleanup_admission.launch.launch_id,
            )
            .expect("reload live-state verifier native preparation");
        let cleanup_authority = NativeLaunchCleanupAuthority::from_expected_state(
            &launch_cleanup_admission,
            Some(&preparation),
            client
                .platform_launch_binding
                .as_deref()
                .expect("live-state verifier retains exact platform binding"),
        );
        let session = client.session().clone();
        let request = SprintLiveStateCaptureRequest::from_plan(plan.clone())
            .expect("construct exact active live-state request");
        let request_bytes = serde_json::to_vec(&request).expect("encode active live-state request");
        let intent = EffectIntent {
            contract_version: CONTRACT_VERSION,
            effect_id: format!("live-state-effect-{label}"),
            idempotency_key: format!("live-state-key-{label}"),
            sprint_id: harness.sprint_id.clone(),
            task_id: None,
            worker_id: None,
            worker_lease: None,
            causation_event_id: Some(
                launch_cleanup_admission
                    .cleanup_effect
                    .proposed_event
                    .event_id
                    .clone(),
            ),
            correlation_id: format!("live-state-correlation-{label}"),
            kind: EffectKind::CaptureWorkspaceState,
            request_digest: Digest::sha256(&request_bytes),
            policy_hash: plan.policy_hash.clone(),
            input_snapshot: plan.expected_snapshot.clone(),
            created_at_unix_ms: session.registered_at_unix_ms.saturating_add(1),
        };
        let proposed = proposal(
            &intent,
            ledger
                .next_sequence(&harness.sprint_id)
                .expect("next active live-state proposal sequence"),
        );
        let admission = SprintLiveStateCaptureAdmission {
            contract_version: CONTRACT_VERSION,
            admission_id: format!("live-state-admission-{label}"),
            plan: plan.clone(),
            request,
            effect_id: intent.effect_id.clone(),
            runner_launch_id: client.launch.launch_id.clone(),
            runner_session_id: session.session_id.clone(),
            admitted_at_unix_ms: intent.created_at_unix_ms,
        };
        let SprintLiveStateCaptureDispatchAdmission::Fresh {
            admission: stored_admission,
            effect: stored_effect,
            permit,
        } = ledger
            .admit_sprint_live_state_capture_for_dispatch(&admission, &intent, &proposed)
            .expect("atomically admit exact active live-state capture")
        else {
            panic!("fresh active live-state capture must mint one dispatch permit")
        };
        assert_eq!(stored_admission, admission);
        assert_eq!(stored_effect.intent, intent);
        let verifier = crate::WalkingSkeletonLiveStateVerifierBoundary {
            runner_launch: client.launch.clone(),
            runner_session: session,
            plan: plan.clone(),
        };
        let owner = DesktopRunnerLifecycleOwner::from_active_live_state_verifier_for_test(
            RunnerLifecycleOwnerConfig {
                runner_binary: harness.runner_binary.clone(),
                private_state_root: harness.private_state.clone(),
            },
            retained_request,
            client,
            plan.clone(),
        )
        .expect("construct exact active live-state production owner");
        let receipt_id = if effect_script == LiveStateEffectScript::AdaptationRejected {
            String::new()
        } else {
            format!("live-state-receipt-{label}")
        };
        let cleanup_at_unix_ms =
            native_cleanup_requested_at_unix_ms(&ledger, &launch_cleanup_admission)
                .max(captured_at_unix_ms)
                .saturating_add(1);
        AdmittedLiveStateOwnerFixture {
            harness,
            ledger,
            policy,
            admission,
            intent,
            proposed_event_id: proposed.event_id,
            verifier,
            owner,
            dispatch_permit: Some(permit),
            receipt_id,
            observation_id: format!("live-state-observation-{label}"),
            observed_at_unix_ms: captured_at_unix_ms,
            cleanup_at_unix_ms,
            launch_cleanup_admission,
            cleanup_authority,
            prepare_count,
            release_count,
            native_cleanup_count,
            exchange_count,
        }
    }

    fn persist_admitted_live_state_success(
        fixture: &mut AdmittedLiveStateOwnerFixture,
        claimed: crate::WalkingSkeletonClaimedLiveStateCaptureResponse,
    ) -> (PersistedEffect, LiveStateCaptureEvidence) {
        let crate::WalkingSkeletonLiveStateCaptureOutcome::Succeeded(evidence) =
            &claimed.response().outcome
        else {
            panic!("exact scripted live-state capture must succeed")
        };
        let evidence = evidence.as_ref().clone();
        let crate::durable_coordinator::WalkingSkeletonLiveStateCaptureTerminalCustody::Success(
            terminal,
        ) = claimed.into_terminal_custody()
        else {
            panic!("successful live-state capture must retain sealed terminal custody")
        };
        assert_eq!(terminal.evidence(), &evidence);
        let observed = observation(
            &fixture.intent,
            fixture.observation_id.clone(),
            EffectOutcome::Succeeded {
                evidence_digest: Digest::sha256(
                    &serde_json::to_vec(&evidence).expect("encode exact capture evidence"),
                ),
            },
            evidence.receipt.captured_at_unix_ms,
        );
        let event = terminal_event(
            &fixture.ledger,
            &fixture.intent,
            &fixture.proposed_event_id,
            &observed,
        );
        let completed = terminal
            .persist(&mut fixture.ledger, &observed, &event)
            .expect("persist exact claimed live-state evidence");
        crate::WalkingSkeletonRunnerLifecycle::acknowledge_task_effect_observation(
            &mut fixture.owner,
            &fixture.ledger,
            &completed,
        )
        .expect("acknowledge exact live-state terminal");
        (completed, evidence)
    }

    fn persist_admitted_live_state_failure(
        fixture: &mut AdmittedLiveStateOwnerFixture,
        claimed: crate::WalkingSkeletonClaimedLiveStateCaptureResponse,
        expected_phase: RunnerEffectFailurePhase,
    ) -> PersistedEffect {
        let crate::durable_coordinator::WalkingSkeletonLiveStateCaptureTerminalCustody::ClaimedFailure {
            observation_authority,
            phase,
            evidence_bytes,
        } = claimed.into_terminal_custody()
        else {
            panic!("scripted live-state failure must retain claimed terminal custody")
        };
        assert_eq!(phase, expected_phase);
        let outcome = match expected_phase {
            RunnerEffectFailurePhase::NoRequestBytesWritten => EffectOutcome::FailedBeforeEffect {
                evidence_digest: Digest::sha256(&evidence_bytes),
            },
            RunnerEffectFailurePhase::RequestWriteStarted { .. }
            | RunnerEffectFailurePhase::CorrelatedResponseRejected => EffectOutcome::Unknown {
                evidence_digest: Digest::sha256(&evidence_bytes),
            },
        };
        let observed = observation(
            &fixture.intent,
            fixture.observation_id.clone(),
            outcome,
            fixture.observed_at_unix_ms,
        );
        let event = terminal_event(
            &fixture.ledger,
            &fixture.intent,
            &fixture.proposed_event_id,
            &observed,
        );
        let completed = fixture
            .ledger
            .record_claimed_effect_observation(
                observation_authority,
                &observed,
                &evidence_bytes,
                &event,
            )
            .expect("persist exact claimed live-state failure evidence");
        crate::WalkingSkeletonRunnerLifecycle::acknowledge_task_effect_observation(
            &mut fixture.owner,
            &fixture.ledger,
            &completed,
        )
        .expect("acknowledge exact failed live-state terminal");
        completed
    }

    struct RestartAdmittedLiveStateTerminalFixture {
        harness: TestHarness,
        ledger: EventLedger,
        admission: SprintLiveStateCaptureAdmission,
        completed: PersistedEffect,
        cleanup_at_unix_ms: u64,
        launch_cleanup_admission: PersistedRunnerLaunchCleanupAdmission,
        cleanup_authority: NativeLaunchCleanupAuthority,
        prepare_count: Rc<Cell<u64>>,
        release_count: Rc<Cell<u64>>,
        original_native_cleanup_count: Rc<Cell<u64>>,
        exchange_count: Rc<Cell<u64>>,
    }

    fn restart_admitted_live_state_terminal_fixture(
        label: &str,
        script: LiveStateEffectScript,
    ) -> RestartAdmittedLiveStateTerminalFixture {
        assert!(matches!(
            script,
            LiveStateEffectScript::Success | LiveStateEffectScript::NoRequestBytesWritten
        ));
        let mut fixture =
            admitted_live_state_owner_fixture(label, ScriptedNativeCleanupMutation::Exact, script);
        let claimed = fixture.dispatch();
        let completed = match script {
            LiveStateEffectScript::Success => {
                persist_admitted_live_state_success(&mut fixture, claimed).0
            }
            LiveStateEffectScript::NoRequestBytesWritten => persist_admitted_live_state_failure(
                &mut fixture,
                claimed,
                RunnerEffectFailurePhase::NoRequestBytesWritten,
            ),
            LiveStateEffectScript::AdaptationRejected => unreachable!(
                "restart observed-terminal fixture intentionally excludes Unknown recovery"
            ),
        };
        let AdmittedLiveStateOwnerFixture {
            harness,
            ledger,
            admission,
            owner,
            cleanup_at_unix_ms,
            launch_cleanup_admission,
            cleanup_authority,
            prepare_count,
            release_count,
            native_cleanup_count,
            exchange_count,
            ..
        } = fixture;
        // Simulate process loss after the capture terminal is durable but
        // before native cleanup. No process-local client or cleanup handoff is
        // carried into the restarted owner.
        drop(owner);
        RestartAdmittedLiveStateTerminalFixture {
            harness,
            ledger,
            admission,
            completed,
            cleanup_at_unix_ms,
            launch_cleanup_admission,
            cleanup_authority,
            prepare_count,
            release_count,
            original_native_cleanup_count: native_cleanup_count,
            exchange_count,
        }
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "the two-row restart table binds observed success and FailedBeforeEffect terminals to the same custody-free reopen and exact durable cleanup assertions"
    )]
    fn lifecycle_owner_live_state_observed_terminal_restart_reopens_once_and_closes() {
        for (label, script) in [
            (
                "lifecycle-owner-live-state-success-restart",
                LiveStateEffectScript::Success,
            ),
            (
                "lifecycle-owner-live-state-failed-before-effect-restart",
                LiveStateEffectScript::NoRequestBytesWritten,
            ),
        ] {
            let RestartAdmittedLiveStateTerminalFixture {
                harness,
                mut ledger,
                admission,
                completed,
                cleanup_at_unix_ms,
                launch_cleanup_admission,
                cleanup_authority,
                prepare_count,
                release_count,
                original_native_cleanup_count,
                exchange_count,
            } = restart_admitted_live_state_terminal_fixture(label, script);
            let reopen_count = Rc::new(Cell::new(0));
            let cleanup_count = Rc::new(Cell::new(0));
            let claims = Rc::new(RefCell::new(Vec::new()));
            let next_event_sequence = ledger
                .next_sequence(&harness.sprint_id)
                .expect("read custody-free live-state cleanup event sequence");
            let mut owner = DesktopRunnerLifecycleOwner::with_native_cleanup_reopener(
                RunnerLifecycleOwnerConfig {
                    runner_binary: harness.runner_binary.clone(),
                    private_state_root: harness.private_state.clone(),
                },
                Box::new(ScriptedNativeCleanupReopener {
                    authority: cleanup_authority,
                    reopen_count: Rc::clone(&reopen_count),
                    cleanup_count: Rc::clone(&cleanup_count),
                    mutation: ScriptedNativeCleanupMutation::Exact,
                    claims: Rc::clone(&claims),
                }),
            )
            .expect("construct custody-free live-state restart owner");

            let outcome = crate::WalkingSkeletonRunnerLifecycle::cleanup_sprint_live_state_capture(
                &mut owner,
                &mut ledger,
                crate::WalkingSkeletonLiveStateCaptureCleanup {
                    sprint_spec: &harness.sprint_spec,
                    admission: &admission,
                    completed: &completed,
                    cleanup_at_unix_ms,
                },
            )
            .expect("custody-free observed live-state terminal reopens and cleans exactly once");
            let crate::WalkingSkeletonLiveStateCaptureCleanupOutcome::Completed(cleanup) = outcome
            else {
                panic!("exact custody-free live-state restart cleanup remained pending")
            };

            assert_eq!((reopen_count.get(), cleanup_count.get()), (1, 1));
            assert_eq!(original_native_cleanup_count.get(), 0);
            assert_eq!((prepare_count.get(), release_count.get()), (1, 1));
            assert_eq!(exchange_count.get(), 2);
            assert_eq!(
                claims.borrow().as_slice(),
                &[CleanupReopenClaimTrace {
                    sprint_id: launch_cleanup_admission.launch.sprint_id.clone(),
                    launch_id: launch_cleanup_admission.launch.launch_id.clone(),
                    session_id: launch_cleanup_admission.launch.session_id.clone(),
                    cleanup_effect_id: launch_cleanup_admission
                        .cleanup_effect
                        .intent
                        .effect_id
                        .clone(),
                    next_event_sequence,
                }]
            );
            assert_eq!(
                cleanup.intent,
                launch_cleanup_admission.cleanup_effect.intent
            );
            assert_eq!(
                ledger
                    .load_effect(&cleanup.intent.effect_id)
                    .expect("reload custody-free live-state cleanup"),
                cleanup
            );
            assert!(matches!(
                owner.state(),
                DesktopRunnerLifecycleStateView::Idle
            ));
        }
    }

    #[test]
    fn lifecycle_owner_live_state_observed_terminal_restart_without_reopener_writes_nothing() {
        let RestartAdmittedLiveStateTerminalFixture {
            harness,
            mut ledger,
            admission,
            completed,
            cleanup_at_unix_ms,
            launch_cleanup_admission,
            original_native_cleanup_count,
            ..
        } = restart_admitted_live_state_terminal_fixture(
            "lifecycle-owner-live-state-missing-reopener",
            LiveStateEffectScript::Success,
        );
        let pending = launch_cleanup_admission.cleanup_effect.clone();
        let mut owner = DesktopRunnerLifecycleOwner::new(RunnerLifecycleOwnerConfig {
            runner_binary: harness.runner_binary.clone(),
            private_state_root: harness.private_state.clone(),
        })
        .expect("construct custody-free live-state owner without reopener");

        let outcome = crate::WalkingSkeletonRunnerLifecycle::cleanup_sprint_live_state_capture(
            &mut owner,
            &mut ledger,
            crate::WalkingSkeletonLiveStateCaptureCleanup {
                sprint_spec: &harness.sprint_spec,
                admission: &admission,
                completed: &completed,
                cleanup_at_unix_ms,
            },
        )
        .expect("missing reopener remains an exact cleanup-required stop");
        assert!(matches!(
            outcome,
            crate::WalkingSkeletonLiveStateCaptureCleanupOutcome::CleanupRequired { ref reason }
                if reason.contains("reopener")
        ));
        assert_eq!(original_native_cleanup_count.get(), 0);
        assert_eq!(
            ledger
                .load_effect(&pending.intent.effect_id)
                .expect("missing reopener leaves live-state cleanup pending"),
            pending
        );
        assert!(matches!(
            owner.state(),
            DesktopRunnerLifecycleStateView::Idle
        ));
    }

    #[test]
    fn lifecycle_owner_live_state_observed_terminal_crossed_reopener_retains_custody_once() {
        let RestartAdmittedLiveStateTerminalFixture {
            harness,
            mut ledger,
            admission,
            completed,
            cleanup_at_unix_ms,
            launch_cleanup_admission,
            mut cleanup_authority,
            original_native_cleanup_count,
            ..
        } = restart_admitted_live_state_terminal_fixture(
            "lifecycle-owner-live-state-crossed-reopener",
            LiveStateEffectScript::Success,
        );
        cleanup_authority.expected_platform_binding_digest =
            Digest::sha256(b"crossed-live-state-restart-cleanup-authority");
        let pending = launch_cleanup_admission.cleanup_effect.clone();
        let reopen_count = Rc::new(Cell::new(0));
        let cleanup_count = Rc::new(Cell::new(0));
        let claims = Rc::new(RefCell::new(Vec::new()));
        let mut owner = DesktopRunnerLifecycleOwner::with_native_cleanup_reopener(
            RunnerLifecycleOwnerConfig {
                runner_binary: harness.runner_binary.clone(),
                private_state_root: harness.private_state.clone(),
            },
            Box::new(UncheckedNativeCleanupReopener {
                authority: cleanup_authority,
                reopen_count: Rc::clone(&reopen_count),
                cleanup_count: Rc::clone(&cleanup_count),
                claims: Rc::clone(&claims),
            }),
        )
        .expect("construct crossed live-state cleanup reopener");

        for cleanup_at_unix_ms in [cleanup_at_unix_ms, cleanup_at_unix_ms.saturating_add(1)] {
            let outcome = crate::WalkingSkeletonRunnerLifecycle::cleanup_sprint_live_state_capture(
                &mut owner,
                &mut ledger,
                crate::WalkingSkeletonLiveStateCaptureCleanup {
                    sprint_spec: &harness.sprint_spec,
                    admission: &admission,
                    completed: &completed,
                    cleanup_at_unix_ms,
                },
            )
            .expect("crossed live-state custody remains a typed cleanup requirement");
            assert!(matches!(
                outcome,
                crate::WalkingSkeletonLiveStateCaptureCleanupOutcome::CleanupRequired { .. }
            ));
            assert_eq!(reopen_count.get(), 1);
            assert_eq!(cleanup_count.get(), 0);
            assert_eq!(claims.borrow().len(), 1);
            assert_eq!(original_native_cleanup_count.get(), 0);
            assert_eq!(
                ledger
                    .load_effect(&pending.intent.effect_id)
                    .expect("crossed reopener leaves live-state cleanup pending"),
                pending
            );
            assert!(matches!(
                owner.state(),
                DesktopRunnerLifecycleStateView::LiveStateVerifierCleanupRequired { cleanup, .. }
                    if cleanup.has_native_cleanup_custody()
            ));
        }
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "the regression keeps active and retained crossed-authority checks, fail-once custody, retry, and durable readback contiguous"
    )]
    fn lifecycle_owner_live_state_success_rejects_crossed_active_and_retained_authority_then_retries_cleanup()
     {
        let mut fixture = admitted_live_state_owner_fixture(
            "lifecycle-owner-live-state-success-retry",
            ScriptedNativeCleanupMutation::FailOnceBeforeObservation,
            LiveStateEffectScript::Success,
        );
        assert_eq!(
            (fixture.prepare_count.get(), fixture.release_count.get()),
            (1, 1)
        );
        assert_eq!(fixture.exchange_count.get(), 1);
        let claimed = fixture.dispatch();
        assert_eq!(fixture.exchange_count.get(), 2);
        assert!(matches!(
            fixture.owner.state(),
            DesktopRunnerLifecycleStateView::ReconciliationRequired {
                requirement: RunnerLifecycleReconciliation::AwaitingTerminalObservation { .. },
                custody: ReconciliationCustodyView::LiveStateVerifier { .. },
            }
        ));
        let (completed, _evidence) = persist_admitted_live_state_success(&mut fixture, claimed);
        assert!(matches!(
            fixture.owner.state(),
            DesktopRunnerLifecycleStateView::ActiveLiveStateVerifier { .. }
        ));
        let pending_cleanup = fixture.launch_cleanup_admission.cleanup_effect.clone();

        let mut crossed_spec = fixture.harness.sprint_spec.clone();
        crossed_spec
            .objective
            .push_str(" crossed-active-live-state");
        crate::WalkingSkeletonRunnerLifecycle::cleanup_sprint_live_state_capture(
            &mut fixture.owner,
            &mut fixture.ledger,
            crate::WalkingSkeletonLiveStateCaptureCleanup {
                sprint_spec: &crossed_spec,
                admission: &fixture.admission,
                completed: &completed,
                cleanup_at_unix_ms: fixture.cleanup_at_unix_ms,
            },
        )
        .expect_err("same-ID crossed sprint must reject before live verifier shutdown");
        assert_eq!(
            (
                fixture.exchange_count.get(),
                fixture.native_cleanup_count.get()
            ),
            (2, 0)
        );
        assert!(matches!(
            fixture.owner.state(),
            DesktopRunnerLifecycleStateView::ActiveLiveStateVerifier { .. }
        ));

        let first = crate::WalkingSkeletonRunnerLifecycle::cleanup_sprint_live_state_capture(
            &mut fixture.owner,
            &mut fixture.ledger,
            crate::WalkingSkeletonLiveStateCaptureCleanup {
                sprint_spec: &fixture.harness.sprint_spec,
                admission: &fixture.admission,
                completed: &completed,
                cleanup_at_unix_ms: fixture.cleanup_at_unix_ms,
            },
        )
        .expect("first native cleanup failure returns typed retained custody");
        assert!(matches!(
            first,
            crate::WalkingSkeletonLiveStateCaptureCleanupOutcome::CleanupRequired { .. }
        ));
        assert_eq!(
            (
                fixture.exchange_count.get(),
                fixture.native_cleanup_count.get()
            ),
            (3, 1)
        );
        assert_eq!(
            fixture
                .ledger
                .load_effect(&pending_cleanup.intent.effect_id)
                .expect("failed live-state native cleanup remains pending"),
            pending_cleanup
        );
        assert!(matches!(
            fixture.owner.state(),
            DesktopRunnerLifecycleStateView::LiveStateVerifierCleanupRequired { ref binding, .. }
                if binding.launch_id == fixture.admission.runner_launch_id
                    && binding.session_id == fixture.admission.runner_session_id
        ));

        crossed_spec
            .objective
            .push_str(" crossed-retained-live-state");
        crate::WalkingSkeletonRunnerLifecycle::cleanup_sprint_live_state_capture(
            &mut fixture.owner,
            &mut fixture.ledger,
            crate::WalkingSkeletonLiveStateCaptureCleanup {
                sprint_spec: &crossed_spec,
                admission: &fixture.admission,
                completed: &completed,
                cleanup_at_unix_ms: fixture.cleanup_at_unix_ms,
            },
        )
        .expect_err("crossed retained sprint must reject before a second native cleanup effect");
        assert_eq!(
            (
                fixture.exchange_count.get(),
                fixture.native_cleanup_count.get()
            ),
            (3, 1)
        );
        assert!(matches!(
            fixture.owner.state(),
            DesktopRunnerLifecycleStateView::LiveStateVerifierCleanupRequired { .. }
        ));

        let cleanup = crate::WalkingSkeletonRunnerLifecycle::cleanup_sprint_live_state_capture(
            &mut fixture.owner,
            &mut fixture.ledger,
            crate::WalkingSkeletonLiveStateCaptureCleanup {
                sprint_spec: &fixture.harness.sprint_spec,
                admission: &fixture.admission,
                completed: &completed,
                cleanup_at_unix_ms: fixture.cleanup_at_unix_ms.saturating_add(1),
            },
        )
        .expect("retained exact live-state cleanup completes on retry");
        let crate::WalkingSkeletonLiveStateCaptureCleanupOutcome::Completed(cleanup) = cleanup
        else {
            panic!("retained live-state cleanup must complete on exact retry")
        };
        assert_eq!(
            (
                fixture.exchange_count.get(),
                fixture.native_cleanup_count.get()
            ),
            (3, 2)
        );
        assert_eq!(
            cleanup.intent,
            fixture.launch_cleanup_admission.cleanup_effect.intent
        );
        assert_eq!(
            fixture
                .ledger
                .load_effect(&cleanup.intent.effect_id)
                .expect("reload completed live-state verifier cleanup"),
            cleanup
        );
        assert!(matches!(
            fixture.owner.state(),
            DesktopRunnerLifecycleStateView::Idle
        ));
    }

    #[test]
    fn lifecycle_owner_live_state_failed_before_effect_and_unknown_retained_reconciliation_table() {
        for (label, script, phase, unknown) in [
            (
                "lifecycle-owner-live-state-failed-before-effect",
                LiveStateEffectScript::NoRequestBytesWritten,
                RunnerEffectFailurePhase::NoRequestBytesWritten,
                false,
            ),
            (
                "lifecycle-owner-live-state-unknown-prepared",
                LiveStateEffectScript::AdaptationRejected,
                RunnerEffectFailurePhase::CorrelatedResponseRejected,
                true,
            ),
        ] {
            let mut fixture = admitted_live_state_owner_fixture(
                label,
                ScriptedNativeCleanupMutation::Exact,
                script,
            );
            let claimed = fixture.dispatch();
            assert_eq!(fixture.exchange_count.get(), 2);
            if unknown {
                assert!(matches!(
                    fixture.owner.state(),
                    DesktopRunnerLifecycleStateView::ReconciliationRequired {
                        requirement: RunnerLifecycleReconciliation::AwaitingTerminalObservation { .. },
                        custody: ReconciliationCustodyView::LiveStateVerifier { .. },
                    }
                ));
                fixture
                    .owner
                    .prepare_reconciliation_cleanup()
                    .expect("prepare exact live Unknown cleanup custody");
                assert_eq!(fixture.exchange_count.get(), 3);
            }
            let completed = persist_admitted_live_state_failure(&mut fixture, claimed, phase);
            if unknown {
                assert!(matches!(
                    fixture.owner.state(),
                    DesktopRunnerLifecycleStateView::ReconciliationRequired {
                        requirement: RunnerLifecycleReconciliation::RunnerRequestedReconciliation { .. },
                        custody: ReconciliationCustodyView::LiveStateVerifierCleanup { .. },
                    }
                ));
            } else {
                assert!(matches!(
                    fixture.owner.state(),
                    DesktopRunnerLifecycleStateView::ReconciliationRequired {
                        requirement: RunnerLifecycleReconciliation::EffectDispatchFailed { .. },
                        custody: ReconciliationCustodyView::LiveStateVerifierCleanup { .. },
                    }
                ));
            }
            let cleanup = crate::WalkingSkeletonRunnerLifecycle::cleanup_sprint_live_state_capture(
                &mut fixture.owner,
                &mut fixture.ledger,
                crate::WalkingSkeletonLiveStateCaptureCleanup {
                    sprint_spec: &fixture.harness.sprint_spec,
                    admission: &fixture.admission,
                    completed: &completed,
                    cleanup_at_unix_ms: fixture.cleanup_at_unix_ms,
                },
            )
            .expect("retained failure reconciliation closes exact verifier cleanup");
            assert!(matches!(
                cleanup,
                crate::WalkingSkeletonLiveStateCaptureCleanupOutcome::Completed(_)
            ));
            assert_eq!(fixture.native_cleanup_count.get(), 1);
            assert_eq!(fixture.exchange_count.get(), if unknown { 3 } else { 2 });
            assert!(matches!(
                fixture.owner.state(),
                DesktopRunnerLifecycleStateView::Idle
            ));
        }
    }

    #[test]
    fn lifecycle_owner_claimed_live_state_same_process_live_custody_closes_atomically() {
        let mut fixture = admitted_live_state_owner_fixture(
            "lifecycle-owner-claimed-live-state-same-process",
            ScriptedNativeCleanupMutation::Exact,
            LiveStateEffectScript::Success,
        );
        let claimed = fixture.dispatch();
        let crate::durable_coordinator::WalkingSkeletonLiveStateCaptureTerminalCustody::Success(
            terminal,
        ) = claimed.into_terminal_custody()
        else {
            panic!("successful capture response must retain live claimed custody")
        };
        let pending = terminal.claimed_effect().clone();
        drop(terminal);
        assert!(matches!(
            fixture.owner.state(),
            DesktopRunnerLifecycleStateView::ReconciliationRequired {
                requirement: RunnerLifecycleReconciliation::AwaitingTerminalObservation { effect },
                custody: ReconciliationCustodyView::LiveStateVerifier { .. },
            } if effect.as_ref() == &pending
        ));
        let evidence_bytes = b"same-process live-state response custody was lost".to_vec();
        let observed = observation(
            &fixture.intent,
            fixture.observation_id.clone(),
            EffectOutcome::Unknown {
                evidence_digest: Digest::sha256(&evidence_bytes),
            },
            fixture.observed_at_unix_ms,
        );
        let event = terminal_event(
            &fixture.ledger,
            &fixture.intent,
            &fixture.proposed_event_id,
            &observed,
        );
        let outcome =
            crate::WalkingSkeletonRunnerLifecycle::reconcile_claimed_sprint_live_state_capture(
                &mut fixture.owner,
                &mut fixture.ledger,
                crate::WalkingSkeletonClaimedLiveStateCaptureRecovery {
                    sprint_spec: &fixture.harness.sprint_spec,
                    admission: &fixture.admission,
                    observation: &observed,
                    evidence_bytes: &evidence_bytes,
                    event: &event,
                    cleanup_at_unix_ms: fixture.cleanup_at_unix_ms,
                },
            )
            .expect("same-process live custody closes claimed capture and verifier atomically");
        let crate::WalkingSkeletonClaimedLiveStateCaptureRecoveryOutcome::Completed {
            capture,
            cleanup,
        } = outcome
        else {
            panic!("exact same-process live cleanup must complete atomically")
        };
        assert_eq!(capture.observation.as_ref(), Some(&observed));
        assert!(matches!(
            cleanup.observation.as_ref().map(|value| &value.outcome),
            Some(EffectOutcome::Succeeded { .. })
        ));
        assert_eq!(
            (
                fixture.exchange_count.get(),
                fixture.native_cleanup_count.get()
            ),
            (3, 1)
        );
        assert!(matches!(
            fixture.owner.state(),
            DesktopRunnerLifecycleStateView::Idle
        ));
    }
