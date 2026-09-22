    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "the restart regression keeps the claimed capture, fail-once native custody, atomic retry, exact readback, and owner state contiguous"
    )]
    fn lifecycle_owner_claimed_live_state_restart_reuses_custody_and_closes_atomically() {
        let label = "lifecycle-owner-claimed-live-state-restart";
        let (harness, mut ledger) = TestHarness::new(label);
        let AuthoritativePostCompletionPreparation::ClaimedLiveState(prepared) =
            prepare_authoritative_post_completion_dispatch_inner(
                &harness,
                &mut ledger,
                label,
                AuthoritativePostCompletionFixtureMode::StopAfterLiveStateClaim,
            )
        else {
            unreachable!("claimed live-state fixture unexpectedly completed the sprint")
        };
        let ClaimedLiveStateRestartPreparation {
            policy,
            plan,
            verifier,
            admission,
            intent,
            proposed_event,
            claimed,
        } = prepared;
        assert_eq!(
            verifier.launch.purpose,
            RunnerSessionPurpose::LiveStateVerifier
        );
        assert_eq!(verifier.task_attempt_running, None);
        assert_eq!(admission.plan, plan);
        assert_eq!(claimed.intent, intent);
        assert!(claimed.dispatch_claim.is_some());
        assert!(claimed.observation.is_none());

        let cleanup_admission = ledger
            .load_runner_launch_cleanup_admission(&harness.sprint_id, &verifier.launch.launch_id)
            .expect("reload claimed live-state cleanup admission");
        let platform_binding = PlatformLaunchBinding::try_from_admission(
            &cleanup_admission,
            &harness.authority,
            &policy,
        )
        .expect("reconstruct exact live-state platform binding");
        let preparation_attempt = RunnerLaunchPreparationAttempt {
            contract_version: CONTRACT_VERSION,
            attempt_id: format!("native-preparation-{label}"),
            sprint_id: harness.sprint_id.clone(),
            launch_id: verifier.launch.launch_id.clone(),
            cleanup_effect_id: cleanup_admission.cleanup_effect.intent.effect_id.clone(),
            native_journal_id: format!("native-journal-{label}"),
            expected_platform_binding_digest: platform_binding.binding_digest().clone(),
            claimed_at_unix_ms: cleanup_admission
                .cleanup_effect
                .intent
                .created_at_unix_ms
                .saturating_add(1),
        };
        let preparation_outcome = RunnerLaunchPreparationOutcome {
            disposition: RunnerLaunchPreparationDisposition::HeldChildPrepared,
            native_evidence_bytes: format!("held-live-state-child-{label}").into_bytes(),
            finished_at_unix_ms: preparation_attempt.claimed_at_unix_ms.saturating_add(1),
        };
        let expected_preparation_outcome = preparation_outcome.clone();
        let preparation = ledger
            .with_runner_launch_preparation_claim(&cleanup_admission, &preparation_attempt, |_| {
                expected_preparation_outcome
            })
            .expect("persist exact live-state native preparation");
        assert_eq!(preparation.attempt, preparation_attempt);
        assert_eq!(preparation.outcome.as_ref(), Some(&preparation_outcome));
        let cleanup_authority = NativeLaunchCleanupAuthority::from_expected_state(
            &cleanup_admission,
            Some(&preparation),
            &platform_binding,
        );

        let evidence_bytes = format!("lost claimed live-state response for {label}").into_bytes();
        let observed_at_unix_ms = intent
            .created_at_unix_ms
            .max(preparation_outcome.finished_at_unix_ms)
            .saturating_add(1);
        let unknown_observation = observation(
            &intent,
            format!("observation-{label}"),
            EffectOutcome::Unknown {
                evidence_digest: Digest::sha256(&evidence_bytes),
            },
            observed_at_unix_ms,
        );
        let unknown_event = terminal_event(
            &ledger,
            &intent,
            &proposed_event.event_id,
            &unknown_observation,
        );
        let cleanup_at_unix_ms = observed_at_unix_ms.saturating_add(1);
        let reopen_count = Rc::new(Cell::new(0));
        let native_cleanup_count = Rc::new(Cell::new(0));
        let claims = Rc::new(RefCell::new(Vec::new()));
        let mut owner = DesktopRunnerLifecycleOwner::with_native_cleanup_reopener(
            RunnerLifecycleOwnerConfig {
                runner_binary: harness.runner_binary.clone(),
                private_state_root: harness.private_state.clone(),
            },
            Box::new(ScriptedNativeCleanupReopener {
                authority: cleanup_authority,
                reopen_count: Rc::clone(&reopen_count),
                cleanup_count: Rc::clone(&native_cleanup_count),
                mutation: ScriptedNativeCleanupMutation::FailOnceBeforeObservation,
                claims: Rc::clone(&claims),
            }),
        )
        .expect("construct restarted production live-state owner");

        let first =
            crate::WalkingSkeletonRunnerLifecycle::reconcile_claimed_sprint_live_state_capture(
                &mut owner,
                &mut ledger,
                crate::WalkingSkeletonClaimedLiveStateCaptureRecovery {
                    sprint_spec: &harness.sprint_spec,
                    admission: &admission,
                    observation: &unknown_observation,
                    evidence_bytes: &evidence_bytes,
                    event: &unknown_event,
                    cleanup_at_unix_ms,
                },
            )
            .expect("transient native cleanup failure remains a typed cleanup requirement");
        assert!(matches!(
            first,
            crate::WalkingSkeletonClaimedLiveStateCaptureRecoveryOutcome::CleanupRequired { .. }
        ));
        assert_eq!((reopen_count.get(), native_cleanup_count.get()), (1, 1));
        assert_eq!(claims.borrow().len(), 1);
        assert_eq!(
            ledger
                .load_effect(&intent.effect_id)
                .expect("transient failure leaves capture pending"),
            claimed
        );
        assert_eq!(
            ledger
                .load_effect(&cleanup_admission.cleanup_effect.intent.effect_id)
                .expect("transient failure leaves runner cleanup pending"),
            cleanup_admission.cleanup_effect
        );
        assert!(matches!(
            owner.state(),
            DesktopRunnerLifecycleStateView::ReconciliationRequired {
                requirement: RunnerLifecycleReconciliation::AwaitingTerminalObservation { effect },
                custody: ReconciliationCustodyView::LiveStateVerifierCleanup { binding, cleanup },
            } if effect.as_ref() == &claimed
                && binding.sprint_id == harness.sprint_id
                && binding.launch_id == verifier.launch.launch_id
                && binding.session_id == verifier.session.session_id
                && binding.plan == &plan
                && cleanup.has_native_cleanup_custody()
        ));

        let (capture, cleanup) = match crate::WalkingSkeletonRunnerLifecycle::reconcile_claimed_sprint_live_state_capture(
            &mut owner,
            &mut ledger,
            crate::WalkingSkeletonClaimedLiveStateCaptureRecovery {
                sprint_spec: &harness.sprint_spec,
                admission: &admission,
                observation: &unknown_observation,
                evidence_bytes: &evidence_bytes,
                event: &unknown_event,
                cleanup_at_unix_ms: cleanup_at_unix_ms.saturating_add(1),
            },
        )
        .expect("retained live-state custody completes the atomic retry")
        {
            crate::WalkingSkeletonClaimedLiveStateCaptureRecoveryOutcome::Completed {
                capture,
                cleanup,
            } => (capture, cleanup),
            crate::WalkingSkeletonClaimedLiveStateCaptureRecoveryOutcome::CleanupRequired {
                reason,
            } => panic!("retained live-state cleanup remained pending: {reason}"),
        };
        assert_eq!((reopen_count.get(), native_cleanup_count.get()), (1, 2));
        assert_eq!(claims.borrow().len(), 1, "retained custody must not reopen");
        assert_eq!(capture.observation.as_ref(), Some(&unknown_observation));
        assert_eq!(
            capture.evidence_bytes.as_deref(),
            Some(evidence_bytes.as_slice())
        );
        assert_eq!(capture.terminal_event.as_ref(), Some(&unknown_event));
        assert!(matches!(
            cleanup.observation.as_ref().map(|value| &value.outcome),
            Some(EffectOutcome::Succeeded { .. })
        ));
        let PersistedFinishReceipt::WorkerCleanup(cleanup_evidence) = &cleanup.finish_receipt
        else {
            panic!("live-state recovery must persist WorkerCleanup evidence")
        };
        assert_eq!(cleanup_evidence.receipt.surviving_processes, 0);
        assert_eq!(
            ledger
                .load_effect(&intent.effect_id)
                .expect("reload atomic Unknown capture"),
            capture
        );
        assert_eq!(
            ledger
                .load_effect(&cleanup_admission.cleanup_effect.intent.effect_id)
                .expect("reload atomic live-state cleanup"),
            cleanup
        );
        assert!(matches!(
            owner.state(),
            DesktopRunnerLifecycleStateView::Idle
        ));

        let replay =
            crate::WalkingSkeletonRunnerLifecycle::reconcile_claimed_sprint_live_state_capture(
                &mut owner,
                &mut ledger,
                crate::WalkingSkeletonClaimedLiveStateCaptureRecovery {
                    sprint_spec: &harness.sprint_spec,
                    admission: &admission,
                    observation: &unknown_observation,
                    evidence_bytes: &evidence_bytes,
                    event: &unknown_event,
                    cleanup_at_unix_ms: cleanup_at_unix_ms.saturating_add(2),
                },
            )
            .expect_err("terminal live-state authority must reject claimed recovery replay");
        assert!(matches!(
            replay,
            crate::DurableCoordinatorError::Protocol(message)
                if message
                    == "claimed live-state recovery crossed its durable claim, admission, Unknown terminal, event, or interval"
        ));
        assert_eq!(
            (reopen_count.get(), native_cleanup_count.get()),
            (1, 2),
            "closed authority must reject before reopening or native cleanup"
        );
        assert_eq!(claims.borrow().len(), 1);
        assert_eq!(
            ledger
                .load_effect(&intent.effect_id)
                .expect("closed replay leaves atomic Unknown capture unchanged"),
            capture
        );
        assert_eq!(
            ledger
                .load_effect(&cleanup_admission.cleanup_effect.intent.effect_id)
                .expect("closed replay leaves atomic live-state cleanup unchanged"),
            cleanup
        );
        assert!(matches!(
            owner.state(),
            DesktopRunnerLifecycleStateView::Idle
        ));
    }

    #[test]
    fn lifecycle_owner_starts_idle_with_exact_config_view() {
        let (harness, _ledger) = TestHarness::new("lifecycle-owner-idle");
        let config = RunnerLifecycleOwnerConfig {
            runner_binary: harness.runner_binary.clone(),
            private_state_root: harness.private_state.clone(),
        };
        let owner = DesktopRunnerLifecycleOwner::new(config.clone())
            .expect("construct idle production-shaped owner");
        assert_eq!(owner.config(), &config);
        assert!(matches!(
            owner.state(),
            DesktopRunnerLifecycleStateView::Idle
        ));

        let relative = RunnerLifecycleOwnerConfig {
            runner_binary: PathBuf::from("runner"),
            private_state_root: harness.private_state.clone(),
        };
        assert!(DesktopRunnerLifecycleOwner::new(relative).is_err());

        let overlapping = RunnerLifecycleOwnerConfig {
            runner_binary: harness.runner_binary.clone(),
            private_state_root: harness
                .runner_binary
                .parent()
                .expect("test binary parent")
                .to_path_buf(),
        };
        assert!(DesktopRunnerLifecycleOwner::new(overlapping).is_err());
    }

    #[test]
    fn lifecycle_owner_restart_intent_only_capture_commits_exact_prelaunch_failure() {
        let mut fixture =
            RestartOrdinaryCommandFixture::new("lifecycle-owner-restart-intent-only", false);
        let mut owner = DesktopRunnerLifecycleOwner::new(RunnerLifecycleOwnerConfig {
            runner_binary: fixture.harness.runner_binary.clone(),
            private_state_root: fixture.harness.private_state.clone(),
        })
        .expect("construct production restart owner");
        let outcome = fixture
            .reconcile(&mut owner)
            .expect("reconcile exact intent-only physical cut");
        let crate::durable_coordinator::WalkingSkeletonTaskCommandRestartOutcome::Terminal(
            completed,
        ) = outcome
        else {
            panic!("intent-only restart must terminalize before effect")
        };
        assert!(completed.dispatch_claim.is_none());
        assert!(matches!(
            completed.observation.as_ref().map(|value| &value.outcome),
            Some(EffectOutcome::FailedBeforeEffect { .. })
        ));
        let capture = fixture
            .ledger
            .load_command_output_capture_for_effect(&completed.intent.effect_id)
            .expect("reload intent-only restart capture");
        assert!(capture.acquired.is_none());
        assert!(matches!(
            capture.terminal.as_ref().map(|value| value.disposition),
            Some(CommandOutputCaptureTerminalDispositionV1::Abandoned)
        ));
        assert_eq!(
            capture.reconciliation_obligation_closure.as_ref(),
            capture
                .terminal
                .as_ref()
                .map(|terminal| &terminal.terminal_anchor_digest)
        );
        let cleanup = fixture
            .ledger
            .load_command_domain_cleanup_proof(&completed.intent.effect_id)
            .expect("reload atomic prelaunch command cleanup");
        assert_eq!(
            cleanup.proof.disposition,
            CommandDomainCleanupDisposition::NoDomainCreatedBeforeEffect
        );
        assert_eq!(cleanup.proof.surviving_processes, 0);
        assert!(matches!(
            owner.state(),
            DesktopRunnerLifecycleStateView::Idle
        ));
    }

    #[test]
    fn lifecycle_owner_restart_generation_two_uses_only_exact_prelaunch_abort() {
        let mut fixture =
            RestartOrdinaryCommandFixture::new("lifecycle-owner-restart-generation-two", true);
        let store = CapabilityCommandOutputStore::open(&fixture.harness.private_state)
            .expect("open generation-two restart store");
        let before = store
            .reopen_sensitive_output_journal_v2(&fixture.capture_intent.capture_id)
            .expect("reopen exact generation-two journal");
        assert_eq!(before.head().generation, 2);
        assert!(matches!(
            before.stage(),
            grok_build_runner::SensitiveOutputJournalStageV2::AcquiredBound
        ));

        let mut owner = DesktopRunnerLifecycleOwner::new(RunnerLifecycleOwnerConfig {
            runner_binary: fixture.harness.runner_binary.clone(),
            private_state_root: fixture.harness.private_state.clone(),
        })
        .expect("construct production generation-two restart owner");
        let outcome = fixture
            .reconcile(&mut owner)
            .expect("generation-two restart closes only through prelaunch abort");
        let crate::durable_coordinator::WalkingSkeletonTaskCommandRestartOutcome::Terminal(
            completed,
        ) = outcome
        else {
            panic!("generation-two restart must terminalize before effect")
        };
        assert!(matches!(
            completed.observation.as_ref().map(|value| &value.outcome),
            Some(EffectOutcome::FailedBeforeEffect { .. })
        ));
        let v2_after = store
            .reopen_sensitive_output_journal_v2(&fixture.capture_intent.capture_id)
            .expect("read back immutable generation-two prefix after prelaunch abort");
        assert_eq!(v2_after, before);
        let v1_after = store
            .reopen_capture(&fixture.capture_intent.capture_id)
            .expect("read back exact prelaunch-aborted v1 capture");
        assert_eq!(
            v1_after.state(),
            CommandOutputCaptureJournalStateV1::Cleaned
        );
        assert!(v1_after.launch_intended_store_head().is_none());
        assert!(v1_after.expected_reference().is_none());
        assert!(matches!(
            owner.state(),
            DesktopRunnerLifecycleStateView::Idle
        ));
    }

    #[test]
    fn lifecycle_owner_restart_writer_attached_without_v1_launch_remains_prelaunch() {
        let mut fixture = RestartOrdinaryCommandFixture::new(
            "lifecycle-owner-restart-writer-attached-prelaunch",
            true,
        );
        fixture.persist_writer_attached_prelaunch_cut();
        let store = CapabilityCommandOutputStore::open(&fixture.harness.private_state)
            .expect("open writer-attached prelaunch restart store");
        let v2_before = store
            .reopen_sensitive_output_journal_v2(&fixture.capture_intent.capture_id)
            .expect("read writer-attached prelaunch v2 cut");

        let mut owner = DesktopRunnerLifecycleOwner::new(RunnerLifecycleOwnerConfig {
            runner_binary: fixture.harness.runner_binary.clone(),
            private_state_root: fixture.harness.private_state.clone(),
        })
        .expect("construct writer-attached prelaunch owner");
        let outcome = fixture
            .reconcile(&mut owner)
            .expect("writer-attached state without v1 launch closes only as prelaunch");
        let crate::durable_coordinator::WalkingSkeletonTaskCommandRestartOutcome::Terminal(
            completed,
        ) = outcome
        else {
            panic!("writer-attached state without v1 launch must terminalize before effect")
        };
        assert!(matches!(
            completed.observation.as_ref().map(|value| &value.outcome),
            Some(EffectOutcome::FailedBeforeEffect { .. })
        ));
        let v1_after = store
            .reopen_capture(&fixture.capture_intent.capture_id)
            .expect("read exact writer-attached prelaunch cleanup");
        assert_eq!(
            v1_after.state(),
            CommandOutputCaptureJournalStateV1::Cleaned
        );
        assert!(v1_after.launch_intended_store_head().is_none());
        assert_eq!(
            store
                .reopen_sensitive_output_journal_v2(&fixture.capture_intent.capture_id)
                .expect("writer-attached prelaunch v2 prefix remains immutable"),
            v2_before
        );
        assert!(matches!(
            owner.state(),
            DesktopRunnerLifecycleStateView::Idle
        ));
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "the generation-four regression keeps independent native cleanup, zero-only quarantine, immutable v2 readback, and core Unknown closure adjacent"
    )]
    fn lifecycle_owner_restart_generation_four_quarantines_only_after_native_cleanup() {
        let mut fixture =
            RestartOrdinaryCommandFixture::new("lifecycle-owner-restart-generation-four", true);
        fixture.persist_launch_intended_cut();
        let store = CapabilityCommandOutputStore::open(&fixture.harness.private_state)
            .expect("open generation-four restart store");
        let v2_before = store
            .reopen_sensitive_output_journal_v2(&fixture.capture_intent.capture_id)
            .expect("read exact generation-four v2 cut");
        assert_eq!(v2_before.head().generation, 4);
        assert!(matches!(
            v2_before.stage(),
            grok_build_runner::SensitiveOutputJournalStageV2::LaunchIntended { .. }
        ));
        assert_eq!(
            store
                .reopen_capture(&fixture.capture_intent.capture_id)
                .expect("read generation-four v1 cut")
                .state(),
            CommandOutputCaptureJournalStateV1::LaunchIntended
        );

        let cleanup_admission = fixture
            .ledger
            .load_runner_launch_cleanup_admission(
                &fixture.harness.sprint_id,
                &fixture.launch.launch_id,
            )
            .expect("load generation-four cleanup admission");
        let (cleanup_authority, _) = persist_scripted_native_preparation_authority(
            &fixture.harness,
            &mut fixture.ledger,
            &fixture.harness.policy,
            &cleanup_admission,
            "restart-generation-four",
        );
        let command_cleanup_count = Rc::new(Cell::new(0));
        let reopen_count = Rc::new(Cell::new(0));
        let launch_cleanup_count = Rc::new(Cell::new(0));
        let mut owner = DesktopRunnerLifecycleOwner::with_native_cleanup_reopener(
            RunnerLifecycleOwnerConfig {
                runner_binary: fixture.harness.runner_binary.clone(),
                private_state_root: fixture.harness.private_state.clone(),
            },
            Box::new(RestartTaskUnknownCleanupReopener {
                authority: cleanup_authority,
                command_cleanup_count: Rc::clone(&command_cleanup_count),
                reopen_count: Rc::clone(&reopen_count),
                launch_cleanup_count: Rc::clone(&launch_cleanup_count),
                return_crossed_linux_proof: false,
                command_cleanup_proof: None,
            }),
        )
        .expect("construct native-cleanup generation-four owner");
        let outcome = fixture
            .reconcile(&mut owner)
            .expect("generation-four restart closes only after native cleanup and quarantine");
        let crate::durable_coordinator::WalkingSkeletonTaskCommandRestartOutcome::Terminal(
            completed,
        ) = outcome
        else {
            panic!("generation-four restart must commit conservative Unknown")
        };
        assert!(matches!(
            completed.observation.as_ref().map(|value| &value.outcome),
            Some(EffectOutcome::Unknown { .. })
        ));
        assert_eq!(command_cleanup_count.get(), 1);
        assert_eq!(reopen_count.get(), 0);
        assert_eq!(launch_cleanup_count.get(), 0);
        let physical_bytes = completed
            .evidence_bytes
            .as_deref()
            .expect("generation-four Unknown retains only physical evidence");
        assert!(
            !physical_bytes
                .windows(b"clean prefix that must not become restart evidence".len())
                .any(|window| window == b"clean prefix that must not become restart evidence")
        );
        assert!(
            !physical_bytes
                .windows(b"stderr prefix that must not become restart evidence".len())
                .any(|window| window == b"stderr prefix that must not become restart evidence")
        );
        let physical: grok_build_core::CommandOutputCapturePhysicalReconciliationV1 =
            serde_json::from_slice(physical_bytes)
                .expect("decode generation-four physical Unknown evidence");
        assert_eq!(
            physical.final_state,
            grok_build_core::CommandOutputCaptureRestartStateV1::Cleaned
        );
        assert!(physical.finished_store_head.is_none());
        assert!(physical.published_store_head.is_none());
        assert!(physical.artifact_reference.is_none());
        assert!(physical.terminal_prepared.is_none());
        assert!(matches!(
            physical.launch_history,
            grok_build_core::CommandOutputCaptureLaunchHistoryV1::ExactLaunchEvidence { .. }
        ));
        let v1_after = store
            .reopen_capture(&fixture.capture_intent.capture_id)
            .expect("read exact quarantined v1 capture");
        assert_eq!(
            v1_after.state(),
            CommandOutputCaptureJournalStateV1::Cleaned
        );
        assert!(v1_after.expected_reference().is_none());
        assert_eq!(
            store
                .reopen_sensitive_output_journal_v2(&fixture.capture_intent.capture_id)
                .expect("generation-four v2 classification remains unchanged"),
            v2_before
        );
        assert!(matches!(
            owner.state(),
            DesktopRunnerLifecycleStateView::Idle
        ));
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "the split-launch regression keeps exact dual-journal classification, native cleanup, no redispatch, zero-only evidence, and core Unknown closure adjacent"
    )]
    fn lifecycle_owner_restart_split_launch_is_unknown_without_redispatch() {
        let mut fixture =
            RestartOrdinaryCommandFixture::new("lifecycle-owner-restart-split-launch", true);
        fixture.persist_split_launch_cut();
        let store = CapabilityCommandOutputStore::open(&fixture.harness.private_state)
            .expect("open split-launch restart store");
        let v2_before = store
            .reopen_sensitive_output_journal_v2(&fixture.capture_intent.capture_id)
            .expect("read exact split-launch v2 cut");
        assert_eq!(v2_before.head().generation, 3);
        assert!(matches!(
            v2_before.stage(),
            grok_build_runner::SensitiveOutputJournalStageV2::WriterAttached { .. }
        ));
        let v1_before = store
            .reopen_capture(&fixture.capture_intent.capture_id)
            .expect("read exact split-launch v1 cut");
        assert_eq!(
            v1_before.state(),
            CommandOutputCaptureJournalStateV1::LaunchIntended
        );
        let split_launch_head = v1_before
            .launch_intended_store_head()
            .expect("split-launch v1 cut carries one immutable launch head")
            .clone();

        let cleanup_admission = fixture
            .ledger
            .load_runner_launch_cleanup_admission(
                &fixture.harness.sprint_id,
                &fixture.launch.launch_id,
            )
            .expect("load split-launch cleanup admission");
        let (cleanup_authority, _) = persist_scripted_native_preparation_authority(
            &fixture.harness,
            &mut fixture.ledger,
            &fixture.harness.policy,
            &cleanup_admission,
            "restart-split-launch",
        );
        let command_cleanup_count = Rc::new(Cell::new(0));
        let reopen_count = Rc::new(Cell::new(0));
        let launch_cleanup_count = Rc::new(Cell::new(0));
        let mut owner = DesktopRunnerLifecycleOwner::with_native_cleanup_reopener(
            RunnerLifecycleOwnerConfig {
                runner_binary: fixture.harness.runner_binary.clone(),
                private_state_root: fixture.harness.private_state.clone(),
            },
            Box::new(RestartTaskUnknownCleanupReopener {
                authority: cleanup_authority,
                command_cleanup_count: Rc::clone(&command_cleanup_count),
                reopen_count: Rc::clone(&reopen_count),
                launch_cleanup_count: Rc::clone(&launch_cleanup_count),
                return_crossed_linux_proof: false,
                command_cleanup_proof: None,
            }),
        )
        .expect("construct native-cleanup split-launch owner");
        let outcome = fixture
            .reconcile(&mut owner)
            .expect("split launch closes only after native cleanup and zero-first quarantine");
        let crate::durable_coordinator::WalkingSkeletonTaskCommandRestartOutcome::Terminal(
            completed,
        ) = outcome
        else {
            panic!("split launch must commit conservative Unknown")
        };
        assert!(matches!(
            completed.observation.as_ref().map(|value| &value.outcome),
            Some(EffectOutcome::Unknown { .. })
        ));
        assert_eq!(command_cleanup_count.get(), 1);
        assert_eq!(
            reopen_count.get(),
            0,
            "split-launch recovery must not reopen or redispatch a runner"
        );
        assert_eq!(
            launch_cleanup_count.get(),
            0,
            "split-launch recovery must not synthesize launch-level cleanup"
        );
        let physical_bytes = completed
            .evidence_bytes
            .as_deref()
            .expect("split-launch Unknown retains only physical evidence");
        for forbidden in [
            b"split-launch clean stdout prefix that must be zeroed".as_slice(),
            b"split-launch clean stderr prefix that must be zeroed".as_slice(),
        ] {
            assert!(
                !physical_bytes
                    .windows(forbidden.len())
                    .any(|window| window == forbidden),
                "split-launch output prefix cannot become core Unknown evidence"
            );
        }
        let physical: grok_build_core::CommandOutputCapturePhysicalReconciliationV1 =
            serde_json::from_slice(physical_bytes)
                .expect("decode split-launch physical Unknown evidence");
        assert_eq!(
            physical.final_state,
            grok_build_core::CommandOutputCaptureRestartStateV1::Cleaned
        );
        assert!(physical.finished_store_head.is_none());
        assert!(physical.published_store_head.is_none());
        assert!(physical.artifact_reference.is_none());
        assert!(physical.terminal_prepared.is_none());
        assert!(matches!(
            physical.launch_history,
            grok_build_core::CommandOutputCaptureLaunchHistoryV1::ExactLaunchEvidence { .. }
        ));
        let v1_after = store
            .reopen_capture(&fixture.capture_intent.capture_id)
            .expect("read exact quarantined split-launch v1 capture");
        assert_eq!(
            v1_after.state(),
            CommandOutputCaptureJournalStateV1::Cleaned
        );
        assert_eq!(
            v1_after.launch_intended_store_head(),
            Some(&split_launch_head)
        );
        assert!(v1_after.expected_reference().is_none());
        assert_eq!(
            store
                .reopen_sensitive_output_journal_v2(&fixture.capture_intent.capture_id)
                .expect("split-launch v2 prefix remains unchanged"),
            v2_before
        );
        assert!(matches!(
            owner.state(),
            DesktopRunnerLifecycleStateView::Idle
        ));
    }

    #[test]
    fn lifecycle_owner_restart_generation_four_rejects_crossed_native_backend_before_output_mutation()
     {
        let mut fixture = RestartOrdinaryCommandFixture::new_with_backend(
            "lifecycle-owner-restart-generation-four-crossed-backend",
            true,
            WorkerCleanupBackend::MacOsDedicatedIdentity,
        );
        fixture.persist_launch_intended_cut();
        let store = CapabilityCommandOutputStore::open(&fixture.harness.private_state)
            .expect("open crossed-backend generation-four store");
        let v1_before = store
            .reopen_capture(&fixture.capture_intent.capture_id)
            .expect("read exact crossed-backend v1 cut");
        let v2_before = store
            .reopen_sensitive_output_journal_v2(&fixture.capture_intent.capture_id)
            .expect("read exact crossed-backend v2 cut");
        let cleanup_admission = fixture
            .ledger
            .load_runner_launch_cleanup_admission(
                &fixture.harness.sprint_id,
                &fixture.launch.launch_id,
            )
            .expect("load crossed-backend cleanup admission");
        let (cleanup_authority, _) = persist_scripted_native_preparation_authority(
            &fixture.harness,
            &mut fixture.ledger,
            &fixture.harness.policy,
            &cleanup_admission,
            "restart-generation-four-crossed-backend",
        );
        let command_cleanup_count = Rc::new(Cell::new(0));
        let mut owner = DesktopRunnerLifecycleOwner::with_native_cleanup_reopener(
            RunnerLifecycleOwnerConfig {
                runner_binary: fixture.harness.runner_binary.clone(),
                private_state_root: fixture.harness.private_state.clone(),
            },
            Box::new(RestartTaskUnknownCleanupReopener {
                authority: cleanup_authority,
                command_cleanup_count: Rc::clone(&command_cleanup_count),
                reopen_count: Rc::new(Cell::new(0)),
                launch_cleanup_count: Rc::new(Cell::new(0)),
                return_crossed_linux_proof: true,
                command_cleanup_proof: None,
            }),
        )
        .expect("construct crossed-backend generation-four owner");
        let error = fixture
            .reconcile(&mut owner)
            .expect_err("crossed native backend must fail before output quarantine");
        assert!(
            error.to_string().contains("crossed restart backend")
                || error.to_string().contains("backend or request authority"),
            "unexpected crossed-backend error: {error}"
        );
        assert_eq!(command_cleanup_count.get(), 1);
        assert_eq!(
            store
                .reopen_capture(&fixture.capture_intent.capture_id)
                .expect("crossed proof leaves v1 custody unchanged"),
            v1_before
        );
        assert_eq!(
            store
                .reopen_sensitive_output_journal_v2(&fixture.capture_intent.capture_id)
                .expect("crossed proof leaves v2 custody unchanged"),
            v2_before
        );
        assert!(
            fixture
                .ledger
                .load_effect(&fixture.effect.intent.effect_id)
                .expect("crossed proof leaves effect unobserved")
                .observation
                .is_none()
        );
        assert!(matches!(
            owner.state(),
            DesktopRunnerLifecycleStateView::Idle
        ));
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "the rejection-cut regression proves no mutation before native proof, then exact observation-backed zero-first abandonment"
    )]
    fn lifecycle_owner_restart_detected_output_waits_for_native_proof_then_closes_rejection() {
        let mut fixture =
            RestartOrdinaryCommandFixture::new("lifecycle-owner-restart-sensitive-detected", true);
        let native_proof = fixture.persist_sensitive_output_rejection_cut(
            SensitiveOutputRejectionTestCutV1::SensitiveOutputDetected,
        );
        let store = CapabilityCommandOutputStore::open(&fixture.harness.private_state)
            .expect("open detected-output restart store");
        let v1_before = store
            .reopen_capture(&fixture.capture_intent.capture_id)
            .expect("read detected-output v1 cut");
        let v2_before = store
            .reopen_sensitive_output_journal_v2(&fixture.capture_intent.capture_id)
            .expect("read detected-output v2 cut");
        assert_eq!(
            v1_before.state(),
            CommandOutputCaptureJournalStateV1::LaunchIntended
        );
        assert!(matches!(
            v2_before.stage(),
            grok_build_runner::SensitiveOutputJournalStageV2::SensitiveOutputDetected { .. }
        ));

        let mut owner_without_native =
            DesktopRunnerLifecycleOwner::new(RunnerLifecycleOwnerConfig {
                runner_binary: fixture.harness.runner_binary.clone(),
                private_state_root: fixture.harness.private_state.clone(),
            })
            .expect("construct no-native detected-output owner");
        let first = fixture
            .reconcile(&mut owner_without_native)
            .expect("missing native proof is a typed cleanup-required outcome");
        assert!(matches!(
            first,
            crate::durable_coordinator::WalkingSkeletonTaskCommandRestartOutcome::CleanupRequired { .. }
        ));
        assert_eq!(
            store
                .reopen_capture(&fixture.capture_intent.capture_id)
                .expect("missing proof leaves v1 unchanged"),
            v1_before
        );
        assert_eq!(
            store
                .reopen_sensitive_output_journal_v2(&fixture.capture_intent.capture_id)
                .expect("missing proof leaves v2 unchanged"),
            v2_before
        );

        let cleanup_admission = fixture
            .ledger
            .load_runner_launch_cleanup_admission(
                &fixture.harness.sprint_id,
                &fixture.launch.launch_id,
            )
            .expect("load detected-output cleanup admission");
        let (cleanup_authority, _) = persist_scripted_native_preparation_authority(
            &fixture.harness,
            &mut fixture.ledger,
            &fixture.harness.policy,
            &cleanup_admission,
            "restart-sensitive-detected",
        );
        let command_cleanup_count = Rc::new(Cell::new(0));
        let mut owner = DesktopRunnerLifecycleOwner::with_native_cleanup_reopener(
            RunnerLifecycleOwnerConfig {
                runner_binary: fixture.harness.runner_binary.clone(),
                private_state_root: fixture.harness.private_state.clone(),
            },
            Box::new(RestartTaskUnknownCleanupReopener {
                authority: cleanup_authority,
                command_cleanup_count: Rc::clone(&command_cleanup_count),
                reopen_count: Rc::new(Cell::new(0)),
                launch_cleanup_count: Rc::new(Cell::new(0)),
                return_crossed_linux_proof: false,
                command_cleanup_proof: Some(native_proof),
            }),
        )
        .expect("construct native-proof detected-output owner");
        let second = fixture
            .reconcile(&mut owner)
            .expect("detected output advances through exact observation-backed rejection");
        let crate::durable_coordinator::WalkingSkeletonTaskCommandRestartOutcome::Terminal(
            completed,
        ) = second
        else {
            panic!("observation-backed detected output must terminalize as rejection")
        };
        assert!(
            matches!(
                completed.observation.as_ref().map(|value| &value.outcome),
                Some(EffectOutcome::FailedAfterKnownEffect { .. })
            ),
            "detected output must never become success or inferred pre-effect failure"
        );
        assert_eq!(command_cleanup_count.get(), 1);
        let v1_after = store
            .reopen_capture(&fixture.capture_intent.capture_id)
            .expect("read rejected v1 capture");
        assert_eq!(
            v1_after.state(),
            CommandOutputCaptureJournalStateV1::Cleaned
        );
        assert!(v1_after.cleaned_store_head().is_some());
        assert!(v1_after.expected_reference().is_none());
        let v2_after = store
            .reopen_sensitive_output_journal_v2(&fixture.capture_intent.capture_id)
            .expect("read terminal rejected v2 journal");
        assert!(matches!(
            v2_after.stage(),
            grok_build_runner::SensitiveOutputJournalStageV2::SensitiveOutputRejected { .. }
        ));
        assert_eq!(
            fixture
                .ledger
                .load_effect(&fixture.effect.intent.effect_id)
                .expect("reload terminal rejected effect"),
            *completed
        );
        assert!(matches!(
            owner.state(),
            DesktopRunnerLifecycleStateView::Idle
        ));
    }

    #[test]
    fn lifecycle_owner_restart_exact_partial_clean_continues_at_generations_five_six_and_seven() {
        for (label, cut) in [
            (
                "lifecycle-owner-restart-partial-clean-g5",
                SensitiveOutputCleanTestCutV1::ScannedClean,
            ),
            (
                "lifecycle-owner-restart-partial-clean-g6",
                SensitiveOutputCleanTestCutV1::Finished,
            ),
            (
                "lifecycle-owner-restart-partial-clean-g7",
                SensitiveOutputCleanTestCutV1::Published,
            ),
        ] {
            let mut fixture = RestartOrdinaryCommandFixture::new(label, true);
            let native_proof = fixture.persist_sensitive_output_clean_cut(cut);
            let command_cleanup_count = Rc::new(Cell::new(0));
            let mut owner = fixture.restart_owner_with_native_command_proof(
                label,
                native_proof,
                Rc::clone(&command_cleanup_count),
            );
            let outcome = fixture
                .reconcile(&mut owner)
                .expect("exact partial clean restart reaches one terminal outcome");
            let completed = match outcome {
                crate::durable_coordinator::WalkingSkeletonTaskCommandRestartOutcome::Terminal(
                    completed,
                ) => completed,
                other @ crate::durable_coordinator::WalkingSkeletonTaskCommandRestartOutcome::CleanupRequired {
                    ..
                } => panic!(
                    "exact partial clean restart must reconstruct success at {cut:?}: {other:?}"
                ),
            };
            assert!(matches!(
                completed.observation.as_ref().map(|value| &value.outcome),
                Some(EffectOutcome::Succeeded { .. })
            ));
            assert_eq!(command_cleanup_count.get(), 1);
            let store = CapabilityCommandOutputStore::open(&fixture.harness.private_state)
                .expect("open recovered partial clean store");
            assert_eq!(
                store
                    .reopen_capture(&fixture.capture_intent.capture_id)
                    .expect("read exact partial clean v1 terminal")
                    .state(),
                CommandOutputCaptureJournalStateV1::TerminalPrepared
            );
            assert!(matches!(
                store
                    .reopen_sensitive_output_journal_v2(&fixture.capture_intent.capture_id)
                    .expect("read exact partial clean v2 terminal")
                    .stage(),
                grok_build_runner::SensitiveOutputJournalStageV2::TerminalPrepared { .. }
            ));
            let provider_result = grok_build_providers::decode_tool_result(
                completed
                    .evidence_bytes
                    .as_deref()
                    .expect("partial clean success retains exact provider evidence"),
            )
            .expect("decode recovered partial clean result");
            assert!(matches!(
                provider_result.output,
                grok_build_providers::ProviderToolOutput::CommandFinished {
                    termination: grok_build_providers::CommandTermination::Exit(0),
                    ref stdout,
                    ref stderr,
                    ..
                } if stdout == b"recovered partial clean stdout\n"
                    && stderr == b"recovered partial clean stderr\n"
            ));
            assert!(matches!(
                owner.state(),
                DesktopRunnerLifecycleStateView::Idle
            ));
        }
    }

    #[test]
    fn lifecycle_owner_restart_exact_partial_rejection_continues_at_generations_five_six_and_seven()
    {
        for (label, cut) in [
            (
                "lifecycle-owner-restart-partial-rejection-g5",
                SensitiveOutputRejectionTestCutV1::SensitiveOutputDetected,
            ),
            (
                "lifecycle-owner-restart-partial-rejection-g6",
                SensitiveOutputRejectionTestCutV1::CleanupIntended,
            ),
            (
                "lifecycle-owner-restart-partial-rejection-g7",
                SensitiveOutputRejectionTestCutV1::Cleaned,
            ),
        ] {
            let mut fixture = RestartOrdinaryCommandFixture::new(label, true);
            let native_proof = fixture.persist_sensitive_output_rejection_cut(cut);
            let command_cleanup_count = Rc::new(Cell::new(0));
            let mut owner = fixture.restart_owner_with_native_command_proof(
                label,
                native_proof,
                Rc::clone(&command_cleanup_count),
            );
            let outcome = fixture
                .reconcile(&mut owner)
                .expect("exact partial rejection restart reaches one terminal outcome");
            let crate::durable_coordinator::WalkingSkeletonTaskCommandRestartOutcome::Terminal(
                completed,
            ) = outcome
            else {
                panic!("exact partial rejection must terminalize at {cut:?}")
            };
            assert!(matches!(
                completed.observation.as_ref().map(|value| &value.outcome),
                Some(EffectOutcome::FailedAfterKnownEffect { .. })
            ));
            assert_eq!(command_cleanup_count.get(), 1);
            let store = CapabilityCommandOutputStore::open(&fixture.harness.private_state)
                .expect("open recovered partial rejection store");
            let v1 = store
                .reopen_capture(&fixture.capture_intent.capture_id)
                .expect("read exact partial rejection v1 terminal");
            assert_eq!(v1.state(), CommandOutputCaptureJournalStateV1::Cleaned);
            assert!(v1.expected_reference().is_none());
            assert!(matches!(
                store
                    .reopen_sensitive_output_journal_v2(&fixture.capture_intent.capture_id)
                    .expect("read exact partial rejection v2 terminal")
                    .stage(),
                grok_build_runner::SensitiveOutputJournalStageV2::SensitiveOutputRejected { .. }
            ));
            fixture
                .ledger
                .load_command_output_sensitive_rejection_for_effect(&completed.intent.effect_id)
                .expect("read exact core rejection closure");
            assert!(matches!(
                owner.state(),
                DesktopRunnerLifecycleStateView::Idle
            ));
        }
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "the three rejection cuts keep crossed launch backing, exact observation, native cleanup, unchanged v2 history, and conservative core Unknown adjacent"
    )]
    fn lifecycle_owner_restart_partial_rejection_with_crossed_launch_closes_unknown() {
        for (label, cut) in [
            (
                "lifecycle-owner-restart-crossed-launch-rejection-g5",
                SensitiveOutputRejectionTestCutV1::SensitiveOutputDetected,
            ),
            (
                "lifecycle-owner-restart-crossed-launch-rejection-g6",
                SensitiveOutputRejectionTestCutV1::CleanupIntended,
            ),
            (
                "lifecycle-owner-restart-crossed-launch-rejection-g7",
                SensitiveOutputRejectionTestCutV1::Cleaned,
            ),
        ] {
            let mut fixture = RestartOrdinaryCommandFixture::new(label, true);
            let native_proof =
                fixture.persist_sensitive_output_rejection_cut_with_transport(cut, true);
            let store = CapabilityCommandOutputStore::open(&fixture.harness.private_state)
                .expect("open crossed-launch partial rejection store");
            let v2_before = store
                .reopen_sensitive_output_journal_v2(&fixture.capture_intent.capture_id)
                .expect("read crossed-launch rejection prefix");
            let command_cleanup_count = Rc::new(Cell::new(0));
            let mut owner = fixture.restart_owner_with_native_command_proof(
                label,
                native_proof,
                Rc::clone(&command_cleanup_count),
            );
            let outcome = fixture
                .reconcile(&mut owner)
                .expect("crossed launch backing must converge to conservative Unknown");
            let crate::durable_coordinator::WalkingSkeletonTaskCommandRestartOutcome::Terminal(
                completed,
            ) = outcome
            else {
                panic!("crossed launch rejection must terminalize Unknown at {cut:?}")
            };
            assert!(matches!(
                completed.observation.as_ref().map(|value| &value.outcome),
                Some(EffectOutcome::Unknown { .. })
            ));
            assert_eq!(command_cleanup_count.get(), 1);
            let physical: grok_build_core::CommandOutputCapturePhysicalReconciliationV1 =
                serde_json::from_slice(
                    completed
                        .evidence_bytes
                        .as_deref()
                        .expect("crossed launch Unknown retains exact physical evidence"),
                )
                .expect("decode crossed launch Unknown physical evidence");
            assert_eq!(
                physical.final_state,
                grok_build_core::CommandOutputCaptureRestartStateV1::Cleaned
            );
            assert!(physical.artifact_reference.is_none());
            assert_eq!(
                store
                    .reopen_sensitive_output_journal_v2(&fixture.capture_intent.capture_id)
                    .expect("crossed launch rejection leaves v2 prefix unchanged"),
                v2_before
            );
            let capture = fixture
                .ledger
                .load_command_output_capture_for_effect(&completed.intent.effect_id)
                .expect("read crossed launch rejection core capture");
            assert!(matches!(
                capture.terminal.as_ref().map(|value| value.disposition),
                Some(CommandOutputCaptureTerminalDispositionV1::ReconciliationRequired)
            ));
            assert!(matches!(
                owner.state(),
                DesktopRunnerLifecycleStateView::Idle
            ));
        }
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "the six crash cuts keep typed Unknown, unchanged v2 history, zeroed versus immutable v1 custody, and core evidence adjacent"
    )]
    fn lifecycle_owner_restart_missing_partial_terminal_observation_closes_typed_unknown() {
        for (label, cut, retains_immutable_artifact) in [
            (
                "lifecycle-owner-restart-missing-clean-g5",
                SensitiveOutputCleanTestCutV1::ScannedClean,
                false,
            ),
            (
                "lifecycle-owner-restart-missing-clean-g6",
                SensitiveOutputCleanTestCutV1::Finished,
                false,
            ),
            (
                "lifecycle-owner-restart-missing-clean-g7",
                SensitiveOutputCleanTestCutV1::Published,
                true,
            ),
        ] {
            let mut fixture = RestartOrdinaryCommandFixture::new(label, true);
            let native_proof = fixture.persist_sensitive_output_clean_cut(cut);
            let store = CapabilityCommandOutputStore::open(&fixture.harness.private_state)
                .expect("open missing-observation clean store");
            let v2_before = store
                .reopen_sensitive_output_journal_v2(&fixture.capture_intent.capture_id)
                .expect("read missing-observation clean prefix");
            fixture.remove_sensitive_output_terminal_observation();
            let command_cleanup_count = Rc::new(Cell::new(0));
            let mut owner = fixture.restart_owner_with_native_command_proof(
                label,
                native_proof,
                Rc::clone(&command_cleanup_count),
            );
            let outcome = fixture
                .reconcile(&mut owner)
                .expect("missing clean sidecar converges to typed Unknown");
            let crate::durable_coordinator::WalkingSkeletonTaskCommandRestartOutcome::Terminal(
                completed,
            ) = outcome
            else {
                panic!("missing clean sidecar must close Unknown at {cut:?}")
            };
            assert!(matches!(
                completed.observation.as_ref().map(|value| &value.outcome),
                Some(EffectOutcome::Unknown { .. })
            ));
            assert_eq!(command_cleanup_count.get(), 1);
            let physical: grok_build_core::CommandOutputCapturePhysicalReconciliationV1 =
                serde_json::from_slice(
                    completed
                        .evidence_bytes
                        .as_deref()
                        .expect("Unknown retains exact physical evidence"),
                )
                .expect("decode missing-observation clean physical evidence");
            assert_eq!(
                physical.artifact_reference.is_some(),
                retains_immutable_artifact
            );
            assert_eq!(
                physical.final_state,
                if retains_immutable_artifact {
                    grok_build_core::CommandOutputCaptureRestartStateV1::Published
                } else {
                    grok_build_core::CommandOutputCaptureRestartStateV1::Cleaned
                }
            );
            assert_eq!(
                store
                    .reopen_sensitive_output_journal_v2(&fixture.capture_intent.capture_id)
                    .expect("missing clean sidecar leaves v2 prefix unchanged"),
                v2_before
            );
            let capture = fixture
                .ledger
                .load_command_output_capture_for_effect(&completed.intent.effect_id)
                .expect("read missing-observation clean core capture");
            assert!(matches!(
                capture.terminal.as_ref().map(|value| value.disposition),
                Some(CommandOutputCaptureTerminalDispositionV1::ReconciliationRequired)
            ));
            assert!(matches!(
                owner.state(),
                DesktopRunnerLifecycleStateView::Idle
            ));
        }

        for (label, cut) in [
            (
                "lifecycle-owner-restart-missing-rejection-g5",
                SensitiveOutputRejectionTestCutV1::SensitiveOutputDetected,
            ),
            (
                "lifecycle-owner-restart-missing-rejection-g6",
                SensitiveOutputRejectionTestCutV1::CleanupIntended,
            ),
            (
                "lifecycle-owner-restart-missing-rejection-g7",
                SensitiveOutputRejectionTestCutV1::Cleaned,
            ),
        ] {
            let mut fixture = RestartOrdinaryCommandFixture::new(label, true);
            let native_proof = fixture.persist_sensitive_output_rejection_cut(cut);
            let store = CapabilityCommandOutputStore::open(&fixture.harness.private_state)
                .expect("open missing-observation rejection store");
            let v2_before = store
                .reopen_sensitive_output_journal_v2(&fixture.capture_intent.capture_id)
                .expect("read missing-observation rejection prefix");
            fixture.remove_sensitive_output_terminal_observation();
            let command_cleanup_count = Rc::new(Cell::new(0));
            let mut owner = fixture.restart_owner_with_native_command_proof(
                label,
                native_proof,
                Rc::clone(&command_cleanup_count),
            );
            let outcome = fixture
                .reconcile(&mut owner)
                .expect("missing rejection sidecar converges to typed Unknown");
            let crate::durable_coordinator::WalkingSkeletonTaskCommandRestartOutcome::Terminal(
                completed,
            ) = outcome
            else {
                panic!("missing rejection sidecar must close Unknown at {cut:?}")
            };
            assert!(matches!(
                completed.observation.as_ref().map(|value| &value.outcome),
                Some(EffectOutcome::Unknown { .. })
            ));
            assert_eq!(command_cleanup_count.get(), 1);
            let physical: grok_build_core::CommandOutputCapturePhysicalReconciliationV1 =
                serde_json::from_slice(
                    completed
                        .evidence_bytes
                        .as_deref()
                        .expect("Unknown rejection retains exact physical evidence"),
                )
                .expect("decode missing-observation rejection physical evidence");
            assert_eq!(
                physical.final_state,
                grok_build_core::CommandOutputCaptureRestartStateV1::Cleaned
            );
            assert!(physical.artifact_reference.is_none());
            assert_eq!(
                store
                    .reopen_sensitive_output_journal_v2(&fixture.capture_intent.capture_id)
                    .expect("missing rejection sidecar leaves v2 prefix unchanged"),
                v2_before
            );
            let capture = fixture
                .ledger
                .load_command_output_capture_for_effect(&completed.intent.effect_id)
                .expect("read missing-observation rejection core capture");
            assert!(matches!(
                capture.terminal.as_ref().map(|value| value.disposition),
                Some(CommandOutputCaptureTerminalDispositionV1::ReconciliationRequired)
            ));
            assert!(matches!(
                owner.state(),
                DesktopRunnerLifecycleStateView::Idle
            ));
        }
    }

    #[test]
    fn lifecycle_owner_restart_terminal_rejection_rejects_crossed_transport_before_native_cleanup()
    {
        let mut fixture = RestartOrdinaryCommandFixture::new(
            "lifecycle-owner-restart-terminal-rejection-crossed-transport",
            true,
        );
        let _native_proof =
            fixture.persist_terminal_sensitive_output_rejection_with_transport(true);
        let store = CapabilityCommandOutputStore::open(&fixture.harness.private_state)
            .expect("open crossed-rejection restart store");
        let v1_before = store
            .reopen_capture(&fixture.capture_intent.capture_id)
            .expect("read crossed-rejection v1 custody");
        let v2_before = store
            .reopen_sensitive_output_journal_v2(&fixture.capture_intent.capture_id)
            .expect("read crossed-rejection v2 custody");
        let mut owner = DesktopRunnerLifecycleOwner::new(RunnerLifecycleOwnerConfig {
            runner_binary: fixture.harness.runner_binary.clone(),
            private_state_root: fixture.harness.private_state.clone(),
        })
        .expect("construct crossed-rejection restart owner");
        let error = fixture
            .reconcile(&mut owner)
            .expect_err("crossed terminal rejection transport must fail before native cleanup");
        assert!(
            error.to_string().contains("request")
                || error.to_string().contains("transport")
                || error.to_string().contains("binding"),
            "unexpected crossed-rejection error: {error}"
        );
        assert_eq!(
            store
                .reopen_capture(&fixture.capture_intent.capture_id)
                .expect("crossed terminal rejection leaves v1 unchanged"),
            v1_before
        );
        assert_eq!(
            store
                .reopen_sensitive_output_journal_v2(&fixture.capture_intent.capture_id)
                .expect("crossed terminal rejection leaves v2 unchanged"),
            v2_before
        );
        assert!(
            fixture
                .ledger
                .load_effect(&fixture.effect.intent.effect_id)
                .expect("crossed terminal rejection leaves effect unobserved")
                .observation
                .is_none()
        );
        assert!(matches!(
            owner.state(),
            DesktopRunnerLifecycleStateView::Idle
        ));
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "the terminal-rejection regression keeps journal rejoin, native proof, length-free core evidence, and atomic claim consumption in one boundary"
    )]
    fn lifecycle_owner_restart_terminal_sensitive_output_rejoins_and_commits_exact_rejection() {
        let mut fixture = RestartOrdinaryCommandFixture::new(
            "lifecycle-owner-restart-terminal-sensitive-rejection",
            true,
        );
        let native_proof = fixture.persist_terminal_sensitive_output_rejection();
        let cleanup_admission = fixture
            .ledger
            .load_runner_launch_cleanup_admission(
                &fixture.harness.sprint_id,
                &fixture.launch.launch_id,
            )
            .expect("load terminal-rejection cleanup admission");
        let (cleanup_authority, _) = persist_scripted_native_preparation_authority(
            &fixture.harness,
            &mut fixture.ledger,
            &fixture.harness.policy,
            &cleanup_admission,
            "restart-terminal-sensitive-rejection",
        );
        let command_cleanup_count = Rc::new(Cell::new(0));
        let mut owner = DesktopRunnerLifecycleOwner::with_native_cleanup_reopener(
            RunnerLifecycleOwnerConfig {
                runner_binary: fixture.harness.runner_binary.clone(),
                private_state_root: fixture.harness.private_state.clone(),
            },
            Box::new(RestartTaskUnknownCleanupReopener {
                authority: cleanup_authority,
                command_cleanup_count: Rc::clone(&command_cleanup_count),
                reopen_count: Rc::new(Cell::new(0)),
                launch_cleanup_count: Rc::new(Cell::new(0)),
                return_crossed_linux_proof: false,
                command_cleanup_proof: Some(native_proof.clone()),
            }),
        )
        .expect("construct terminal-rejection restart owner");
        let outcome = fixture
            .reconcile(&mut owner)
            .expect("terminal rejection rejoins independent native proof");
        let crate::durable_coordinator::WalkingSkeletonTaskCommandRestartOutcome::Terminal(
            completed,
        ) = outcome
        else {
            panic!("terminal rejection must commit one exact terminal effect")
        };
        assert!(matches!(
            completed.observation.as_ref().map(|value| &value.outcome),
            Some(EffectOutcome::FailedAfterKnownEffect { .. })
        ));
        assert_eq!(command_cleanup_count.get(), 1);
        let evidence = completed
            .evidence_bytes
            .as_deref()
            .expect("terminal rejection retains length-free anchor evidence");
        assert!(
            !evidence
                .windows(b"gb-secret-canary-runner-owned-proof-box-v1".len())
                .any(|window| window == b"gb-secret-canary-runner-owned-proof-box-v1")
        );
        let rejection = fixture
            .ledger
            .load_command_output_sensitive_rejection_for_effect(&completed.intent.effect_id)
            .expect("read exact core terminal rejection");
        assert_eq!(
            rejection
                .anchor
                .runner_cleanup
                .command_domain_cleanup_proof_id,
            native_proof.os_evidence_digest().as_str()
        );
        assert_eq!(
            rejection.cleanup.command_domain_cleanup_proof_id,
            native_proof.os_evidence_digest().as_str()
        );
        let command_cleanup = fixture
            .ledger
            .load_command_domain_cleanup_proof(&completed.intent.effect_id)
            .expect("read exact terminal-rejection native cleanup proof");
        assert_eq!(
            command_cleanup.proof.platform_proof_digest,
            *native_proof.os_evidence_digest()
        );
        assert_eq!(
            command_cleanup.proof.platform_proof_bytes,
            native_proof.os_evidence_bytes()
        );
        let capture = fixture
            .ledger
            .load_command_output_capture_for_effect(&completed.intent.effect_id)
            .expect("read exact rejected core capture");
        assert!(
            capture.terminal.is_none(),
            "typed rejection closure must not be projected into the generic publication terminal"
        );
        let private_capture = CapabilityCommandOutputStore::open(&fixture.harness.private_state)
            .expect("open terminal-rejection private store")
            .reopen_capture(&fixture.capture_intent.capture_id)
            .expect("read terminal-rejection private capture");
        assert_eq!(
            private_capture.state(),
            CommandOutputCaptureJournalStateV1::Cleaned
        );
        assert!(private_capture.expected_reference().is_none());
        assert!(matches!(
            owner.state(),
            DesktopRunnerLifecycleStateView::Idle
        ));
    }

    #[test]
    fn lifecycle_owner_restart_terminal_prepared_reconstructs_exact_success() {
        let mut fixture = RestartOrdinaryCommandFixture::new(
            "lifecycle-owner-restart-terminal-prepared-success",
            true,
        );
        fixture.persist_valid_terminal_prepared();
        let mut owner = DesktopRunnerLifecycleOwner::new(RunnerLifecycleOwnerConfig {
            runner_binary: fixture.harness.runner_binary.clone(),
            private_state_root: fixture.harness.private_state.clone(),
        })
        .expect("construct production TerminalPrepared restart owner");
        let outcome = fixture
            .reconcile(&mut owner)
            .expect("strict TerminalPrepared restart reconstructs exact success");
        let crate::durable_coordinator::WalkingSkeletonTaskCommandRestartOutcome::Terminal(
            completed,
        ) = outcome
        else {
            panic!("valid TerminalPrepared restart must return one terminal success")
        };
        assert!(matches!(
            completed.observation.as_ref().map(|value| &value.outcome),
            Some(EffectOutcome::Succeeded { .. })
        ));
        let result = grok_build_providers::decode_tool_result(
            completed
                .evidence_bytes
                .as_deref()
                .expect("recovered success retains provider-visible evidence"),
        )
        .expect("decode exact recovered provider result");
        assert_eq!(result.call, fixture.provider_call);
        assert!(matches!(
            result.output,
            grok_build_providers::ProviderToolOutput::CommandFinished {
                termination: grok_build_providers::CommandTermination::Exit(0),
                ref stdout,
                stdout_total_bytes: 25,
                stdout_truncated: false,
                ref stderr,
                stderr_total_bytes: 0,
                stderr_truncated: false,
                ..
            } if stdout == b"recovered restart output\n" && stderr.is_empty()
        ));
        let capture = fixture
            .ledger
            .load_command_output_capture_for_effect(&completed.intent.effect_id)
            .expect("reload successful TerminalPrepared capture");
        assert!(matches!(
            capture.terminal.as_ref().map(|value| value.disposition),
            Some(CommandOutputCaptureTerminalDispositionV1::Published)
        ));
        assert_eq!(
            capture.reconciliation_obligation_closure.as_ref(),
            capture
                .terminal
                .as_ref()
                .map(|terminal| &terminal.terminal_anchor_digest)
        );
        let cleanup = fixture
            .ledger
            .load_command_domain_cleanup_proof(&completed.intent.effect_id)
            .expect("reload recovered success cleanup proof");
        assert_eq!(
            cleanup.proof.disposition,
            CommandDomainCleanupDisposition::ReapedZeroSurvivors
        );
        assert_eq!(cleanup.proof.surviving_processes, 0);
        assert!(matches!(
            owner.state(),
            DesktopRunnerLifecycleStateView::Idle
        ));
    }

    #[test]
    fn lifecycle_owner_restart_partial_clean_v2_refuses_generic_v1_reconciliation() {
        let mut fixture =
            RestartOrdinaryCommandFixture::new("lifecycle-owner-restart-invalid-published", true);
        fixture.persist_invalid_semantic_launch(false);
        let store = CapabilityCommandOutputStore::open(&fixture.harness.private_state)
            .expect("open partial-clean restart store");
        let v1_before = store
            .reopen_capture(&fixture.capture_intent.capture_id)
            .expect("read exact Published v1 cut");
        let v2_before = store
            .reopen_sensitive_output_journal_v2(&fixture.capture_intent.capture_id)
            .expect("read exact Published v2 cut");
        assert_eq!(
            v1_before.state(),
            CommandOutputCaptureJournalStateV1::Published
        );
        assert!(matches!(
            v2_before.stage(),
            grok_build_runner::SensitiveOutputJournalStageV2::Published { .. }
        ));

        let mut owner = DesktopRunnerLifecycleOwner::new(RunnerLifecycleOwnerConfig {
            runner_binary: fixture.harness.runner_binary.clone(),
            private_state_root: fixture.harness.private_state.clone(),
        })
        .expect("construct production partial-clean restart owner");
        let outcome = fixture
            .reconcile(&mut owner)
            .expect("partial clean-v2 state returns typed cleanup-required");
        let crate::durable_coordinator::WalkingSkeletonTaskCommandRestartOutcome::CleanupRequired {
            reason,
        } = outcome
        else {
            panic!("partial clean-v2 state must not be projected into generic v1 Unknown")
        };
        assert!(
            reason.contains("native command-domain cleanup reopener"),
            "unexpected reason: {reason}"
        );
        assert!(
            fixture
                .ledger
                .load_effect(&fixture.effect.intent.effect_id)
                .expect("reload unobserved partial-clean effect")
                .observation
                .is_none()
        );
        assert_eq!(
            store
                .reopen_capture(&fixture.capture_intent.capture_id)
                .expect("partial clean-v2 v1 custody remains unchanged"),
            v1_before
        );
        assert_eq!(
            store
                .reopen_sensitive_output_journal_v2(&fixture.capture_intent.capture_id)
                .expect("partial clean-v2 journal remains unchanged"),
            v2_before
        );
        assert!(matches!(
            owner.state(),
            DesktopRunnerLifecycleStateView::Idle
        ));
    }

    #[test]
    fn lifecycle_owner_restart_terminal_prepared_semantic_rejection_converges_unknown() {
        let mut fixture = RestartOrdinaryCommandFixture::new(
            "lifecycle-owner-restart-invalid-terminal-prepared",
            true,
        );
        fixture.persist_invalid_semantic_launch(true);
        let mut owner = DesktopRunnerLifecycleOwner::new(RunnerLifecycleOwnerConfig {
            runner_binary: fixture.harness.runner_binary.clone(),
            private_state_root: fixture.harness.private_state.clone(),
        })
        .expect("construct production TerminalPrepared restart owner");
        let outcome = fixture
            .reconcile(&mut owner)
            .expect("TerminalPrepared semantic rejection conservatively closes Unknown");
        let crate::durable_coordinator::WalkingSkeletonTaskCommandRestartOutcome::Terminal(
            completed,
        ) = outcome
        else {
            panic!("TerminalPrepared semantic rejection must commit Unknown")
        };
        assert!(matches!(
            completed.observation.as_ref().map(|value| &value.outcome),
            Some(EffectOutcome::Unknown { .. })
        ));
        let physical: grok_build_core::CommandOutputCapturePhysicalReconciliationV1 =
            serde_json::from_slice(
                completed
                    .evidence_bytes
                    .as_deref()
                    .expect("Unknown retains exact physical receipt"),
            )
            .expect("decode exact physical Unknown evidence");
        assert_eq!(
            physical.final_state,
            grok_build_core::CommandOutputCaptureRestartStateV1::TerminalPrepared
        );
        let capture = fixture
            .ledger
            .load_command_output_capture_for_effect(&completed.intent.effect_id)
            .expect("reload launch-bearing Unknown capture");
        let terminal = capture
            .terminal
            .as_ref()
            .expect("Unknown capture has immutable terminal");
        assert_eq!(
            terminal.disposition,
            CommandOutputCaptureTerminalDispositionV1::ReconciliationRequired
        );
        assert_eq!(terminal.store_head, physical.final_store_head);
        assert_eq!(
            terminal.terminal_record_digest,
            physical.reconciliation_digest
        );
        assert!(capture.reconciliation_obligation_closure.is_none());
        assert!(matches!(
            owner.state(),
            DesktopRunnerLifecycleStateView::Idle
        ));
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "the regression keeps production restart classification, cleanup-only native reopening, coordinator same-call continuation, and final Unknown closure in one assertion boundary"
    )]
    fn lifecycle_owner_restart_terminal_prepared_semantic_failure_closes_unknown_same_call() {
        let mut fixture = RestartOrdinaryCommandFixture::new(
            "lifecycle-owner-restart-terminal-prepared-same-call-unknown",
            true,
        );
        fixture.persist_invalid_semantic_launch(true);
        let cleanup_admission = fixture
            .ledger
            .load_runner_launch_cleanup_admission(
                &fixture.harness.sprint_id,
                &fixture.launch.launch_id,
            )
            .expect("load exact restart launch cleanup admission");
        let (cleanup_authority, _) = persist_scripted_native_preparation_authority(
            &fixture.harness,
            &mut fixture.ledger,
            &fixture.harness.policy,
            &cleanup_admission,
            "restart-terminal-prepared-same-call-unknown",
        );
        let command_cleanup_count = Rc::new(Cell::new(0));
        let reopen_count = Rc::new(Cell::new(0));
        let launch_cleanup_count = Rc::new(Cell::new(0));
        let reopener = RestartTaskUnknownCleanupReopener {
            authority: cleanup_authority,
            command_cleanup_count: Rc::clone(&command_cleanup_count),
            reopen_count: Rc::clone(&reopen_count),
            launch_cleanup_count: Rc::clone(&launch_cleanup_count),
            return_crossed_linux_proof: false,
            command_cleanup_proof: None,
        };
        let owner = DesktopRunnerLifecycleOwner::with_native_cleanup_reopener(
            RunnerLifecycleOwnerConfig {
                runner_binary: fixture.harness.runner_binary.clone(),
                private_state_root: fixture.harness.private_state.clone(),
            },
            Box::new(reopener),
        )
        .expect("construct cleanup-capable production restart owner");
        let mut coordinator = crate::DurableWalkingSkeleton::open_with_runner_lifecycle(
            &fixture.harness.database,
            grok_build_providers::FakeProvider::new(),
            owner,
        )
        .expect("open focused production restart coordinator");
        let status = coordinator
            .reconcile_task_command_and_finish_unknown_for_test(
                &fixture.harness.sprint_spec,
                &fixture.harness.authority,
                &fixture.harness.policy,
                &fixture.running,
                &fixture.effect,
                &fixture.provider_call,
                2_000,
            )
            .expect("TerminalPrepared semantic rejection closes Unknown in the same call");
        assert!(
            matches!(status, crate::WalkingSkeletonStatus::SprintUnknown { .. }),
            "unexpected same-call Unknown status: {status:?}"
        );
        assert_eq!(command_cleanup_count.get(), 1);
        assert_eq!(reopen_count.get(), 1);
        assert_eq!(launch_cleanup_count.get(), 1);
        assert!(matches!(
            coordinator.runner_lifecycle().state(),
            DesktopRunnerLifecycleStateView::Idle
        ));
        let completed = fixture
            .ledger
            .load_effect(&fixture.effect.intent.effect_id)
            .expect("reload same-call Unknown effect");
        assert!(matches!(
            completed.observation.as_ref().map(|value| &value.outcome),
            Some(EffectOutcome::Unknown { .. })
        ));
        let physical: grok_build_core::CommandOutputCapturePhysicalReconciliationV1 =
            serde_json::from_slice(
                completed
                    .evidence_bytes
                    .as_deref()
                    .expect("Unknown effect retains exact physical restart evidence"),
            )
            .expect("decode exact physical restart receipt");
        assert_eq!(
            physical.final_state,
            grok_build_core::CommandOutputCaptureRestartStateV1::TerminalPrepared
        );
        let capture = fixture
            .ledger
            .load_command_output_capture_for_effect(&completed.intent.effect_id)
            .expect("reload same-call resolved Unknown capture");
        assert!(capture.reconciliation_resolution.is_some());
        assert!(capture.reconciliation_obligation_closure.is_some());
        let history = fixture
            .ledger
            .load_task_attempt_history(
                &fixture.harness.sprint_id,
                &fixture.running.attempt.worker_lease.task_id,
            )
            .expect("reload same-call Unknown attempt history");
        assert!(history.attempts.iter().any(|entry| matches!(
            entry.disposition,
            Some(TaskAttemptDisposition::UnknownCleaned(_))
        )));
        assert!(history.unknown_terminalization_pending.is_none());
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "the regression joins a current clean-v2 terminal, live semantic Unknown, production cleanup-only reopening, policy-bound fenced resolution, and exact core closure"
    )]
    fn lifecycle_owner_policy_bound_clean_v2_live_unknown_uses_exact_recovery_branch() {
        let mut fixture = RestartOrdinaryCommandFixture::new(
            "lifecycle-owner-policy-bound-clean-v2-live-unknown",
            true,
        );
        fixture.persist_valid_terminal_prepared();
        fixture.persist_live_ambiguous_unknown();
        let capture_before = fixture
            .ledger
            .load_command_output_capture_for_effect(&fixture.effect.intent.effect_id)
            .expect("load unresolved policy-bound live Unknown capture");
        let terminal_before = capture_before
            .terminal
            .as_ref()
            .expect("policy-bound live Unknown has its immutable terminal")
            .clone();
        assert_eq!(
            terminal_before.store_head,
            fixture
                .acquired
                .as_ref()
                .expect("policy-bound live Unknown has exact acquisition")
                .store_head
        );
        let store = CapabilityCommandOutputStore::open(&fixture.harness.private_state)
            .expect("open policy-bound clean-v2 output store");
        let physical_before = store
            .reopen_capture(&fixture.capture_intent.capture_id)
            .expect("reopen policy-bound TerminalPrepared v1 capture");
        assert_eq!(
            physical_before.state(),
            CommandOutputCaptureJournalStateV1::TerminalPrepared
        );
        assert!(physical_before.store_head().generation > terminal_before.store_head.generation);
        let clean_before = store
            .reopen_sensitive_output_clean_v2(&fixture.capture_intent.capture_id)
            .expect("reopen exact clean-v2 receipt before Unknown resolution")
            .expect("policy-bound TerminalPrepared capture has a complete clean-v2 receipt");
        assert_eq!(
            physical_before.store_head(),
            &clean_before.terminal_prepared_store_head
        );

        let cleanup_admission = fixture
            .ledger
            .load_runner_launch_cleanup_admission(
                &fixture.harness.sprint_id,
                &fixture.launch.launch_id,
            )
            .expect("load policy-bound Unknown launch cleanup admission");
        let (cleanup_authority, _) = persist_scripted_native_preparation_authority(
            &fixture.harness,
            &mut fixture.ledger,
            &fixture.harness.policy,
            &cleanup_admission,
            "policy-bound-clean-v2-live-unknown",
        );
        let command_cleanup_count = Rc::new(Cell::new(0));
        let reopen_count = Rc::new(Cell::new(0));
        let launch_cleanup_count = Rc::new(Cell::new(0));
        let owner = DesktopRunnerLifecycleOwner::with_native_cleanup_reopener(
            RunnerLifecycleOwnerConfig {
                runner_binary: fixture.harness.runner_binary.clone(),
                private_state_root: fixture.harness.private_state.clone(),
            },
            Box::new(RestartTaskUnknownCleanupReopener {
                authority: cleanup_authority,
                command_cleanup_count: Rc::clone(&command_cleanup_count),
                reopen_count: Rc::clone(&reopen_count),
                launch_cleanup_count: Rc::clone(&launch_cleanup_count),
                return_crossed_linux_proof: false,
                command_cleanup_proof: None,
            }),
        )
        .expect("construct policy-bound Unknown cleanup owner");
        let mut coordinator = crate::DurableWalkingSkeleton::open_with_runner_lifecycle(
            &fixture.harness.database,
            grok_build_providers::FakeProvider::new(),
            owner,
        )
        .expect("open policy-bound Unknown cleanup coordinator");
        let status = coordinator
            .finish_existing_task_command_unknown_for_test(&fixture.harness.sprint_spec, 2_000)
            .expect("policy-bound clean-v2 Unknown closes through exact branch-specific recovery");
        assert!(
            matches!(&status, crate::WalkingSkeletonStatus::SprintUnknown { .. }),
            "policy-bound Unknown cleanup returned {status:?}"
        );
        assert_eq!(command_cleanup_count.get(), 1);
        assert_eq!(reopen_count.get(), 1);
        assert_eq!(launch_cleanup_count.get(), 1);

        let capture_after = fixture
            .ledger
            .load_command_output_capture_for_effect(&fixture.effect.intent.effect_id)
            .expect("load exact policy-bound Unknown resolution");
        let resolution = capture_after
            .reconciliation_resolution
            .as_ref()
            .expect("policy-bound Unknown capture has an exact resolution");
        assert_eq!(
            resolution.disposition,
            CommandOutputCaptureTerminalDispositionV1::Published
        );
        assert_eq!(
            resolution.store_head,
            clean_before.terminal_prepared_store_head
        );
        assert_eq!(
            capture_after.reconciliation_obligation_closure.as_ref(),
            Some(&terminal_before.terminal_anchor_digest)
        );
        let clean_resolution = fixture
            .ledger
            .load_command_output_clean_scan_resolution_receipt_for_effect(
                &fixture.effect.intent.effect_id,
            )
            .expect("load exact policy-bound clean-scan resolution receipt");
        assert_eq!(clean_resolution.unknown_terminal, terminal_before);
        assert_eq!(&clean_resolution.resolution, resolution);
        assert_eq!(
            clean_resolution.detector_policy,
            clean_before.detector_policy
        );
        assert_eq!(
            store
                .reopen_sensitive_output_clean_v2(&fixture.capture_intent.capture_id)
                .expect("reopen clean-v2 receipt after Unknown resolution"),
            Some(clean_before)
        );
        let physical_after = store
            .reopen_capture(&fixture.capture_intent.capture_id)
            .expect("reopen policy-bound physical capture after resolution");
        assert_eq!(
            physical_after.state(),
            CommandOutputCaptureJournalStateV1::TerminalPrepared
        );
        assert_eq!(physical_after.store_head(), &resolution.store_head);
        assert_eq!(
            physical_after.head_digest(),
            &resolution.resolution_record_digest
        );
        assert!(matches!(
            coordinator.runner_lifecycle().state(),
            DesktopRunnerLifecycleStateView::Idle
        ));
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "the regression joins a live Unknown terminal, split launch, fenced resolution, and exact no-mutation repeat readback"
    )]
    fn lifecycle_owner_split_live_unknown_resolution_repeat_is_read_only() {
        let mut fixture = RestartOrdinaryCommandFixture::new(
            "lifecycle-owner-unknown-launch-cut-advancing-receipt",
            true,
        );
        fixture.persist_invalid_semantic_launch_cut();
        fixture.persist_live_ambiguous_unknown();
        let capture_before = fixture
            .ledger
            .load_command_output_capture_for_effect(&fixture.effect.intent.effect_id)
            .expect("load unresolved live Unknown capture");
        let terminal_before = capture_before
            .terminal
            .as_ref()
            .expect("live Unknown has its immutable terminal")
            .clone();
        assert_eq!(
            terminal_before.store_head,
            fixture
                .acquired
                .as_ref()
                .expect("live Unknown has exact acquisition")
                .store_head
        );
        let cleanup_admission = fixture
            .ledger
            .load_runner_launch_cleanup_admission(
                &fixture.harness.sprint_id,
                &fixture.launch.launch_id,
            )
            .expect("load advancing launch cleanup admission");
        let (cleanup_authority, _) = persist_scripted_native_preparation_authority(
            &fixture.harness,
            &mut fixture.ledger,
            &fixture.harness.policy,
            &cleanup_admission,
            "unknown-launch-cut-advancing-receipt",
        );
        let command_cleanup_count = Rc::new(Cell::new(0));
        let reopen_count = Rc::new(Cell::new(0));
        let launch_cleanup_count = Rc::new(Cell::new(0));
        let owner = DesktopRunnerLifecycleOwner::with_native_cleanup_reopener(
            RunnerLifecycleOwnerConfig {
                runner_binary: fixture.harness.runner_binary.clone(),
                private_state_root: fixture.harness.private_state.clone(),
            },
            Box::new(RestartTaskUnknownCleanupReopener {
                authority: cleanup_authority,
                command_cleanup_count: Rc::clone(&command_cleanup_count),
                reopen_count: Rc::clone(&reopen_count),
                launch_cleanup_count: Rc::clone(&launch_cleanup_count),
                return_crossed_linux_proof: false,
                command_cleanup_proof: None,
            }),
        )
        .expect("construct advancing Unknown cleanup owner");
        let mut coordinator = crate::DurableWalkingSkeleton::open_with_runner_lifecycle(
            &fixture.harness.database,
            grok_build_providers::FakeProvider::new(),
            owner,
        )
        .expect("open advancing Unknown cleanup coordinator");
        let status = coordinator
            .finish_existing_task_command_unknown_for_test(&fixture.harness.sprint_spec, 2_000)
            .expect("head-advancing Unknown closure commits with exact physical receipt");
        assert!(
            matches!(&status, crate::WalkingSkeletonStatus::SprintUnknown { .. }),
            "advancing Unknown cleanup returned {status:?}"
        );
        assert_eq!(command_cleanup_count.get(), 1);
        assert_eq!(reopen_count.get(), 1);
        assert_eq!(launch_cleanup_count.get(), 1);
        let capture_after = fixture
            .ledger
            .load_command_output_capture_for_effect(&fixture.effect.intent.effect_id)
            .expect("load physical-receipt-backed advancing resolution");
        let resolution = capture_after
            .reconciliation_resolution
            .as_ref()
            .expect("advancing Unknown capture has exact resolution");
        assert_eq!(
            resolution.disposition,
            CommandOutputCaptureTerminalDispositionV1::Abandoned
        );
        assert!(resolution.store_head.generation > terminal_before.store_head.generation);
        assert_eq!(
            capture_after.reconciliation_obligation_closure.as_ref(),
            Some(&terminal_before.terminal_anchor_digest)
        );
        let store = CapabilityCommandOutputStore::open(&fixture.harness.private_state)
            .expect("open advanced physical output store");
        let physical = store
            .reopen_capture(&fixture.capture_intent.capture_id)
            .expect("reopen advanced physical output capture");
        assert_eq!(
            physical.state(),
            CommandOutputCaptureJournalStateV1::Cleaned
        );
        assert_eq!(physical.store_head(), &resolution.store_head);
        assert_eq!(physical.head_digest(), &resolution.resolution_record_digest);
        let v2_after_first = store
            .reopen_sensitive_output_journal_v2(&fixture.capture_intent.capture_id)
            .expect("reopen split v2 prefix after first resolution");
        assert!(matches!(
            v2_after_first.stage(),
            grok_build_runner::SensitiveOutputJournalStageV2::WriterAttached { .. }
        ));

        let durable_effect = fixture
            .ledger
            .load_effect(&fixture.effect.intent.effect_id)
            .expect("reload exact split-live Unknown effect");
        let durable_cleanup = fixture
            .ledger
            .load_effect(&cleanup_admission.cleanup_effect.intent.effect_id)
            .expect("reload exact completed runner cleanup");
        lifecycle_owner::repeat_task_unknown_capture_resolution_for_test(
            &mut fixture.ledger,
            &fixture.harness.private_state,
            &durable_effect,
            &durable_cleanup,
            2_000,
            &fixture.harness.worker_lease,
        )
        .expect("repeat split-live Unknown resolution uses read-only terminal join");
        assert_eq!(
            command_cleanup_count.get(),
            1,
            "repeat must not rerun command cleanup"
        );
        assert_eq!(reopen_count.get(), 1, "repeat must not reopen the runner");
        assert_eq!(
            launch_cleanup_count.get(),
            1,
            "repeat must not rerun launch cleanup"
        );
        let capture_after_repeat = fixture
            .ledger
            .load_command_output_capture_for_effect(&fixture.effect.intent.effect_id)
            .expect("load repeat split-live Unknown resolution");
        assert_eq!(
            capture_after_repeat, capture_after,
            "repeat must not mutate core capture resolution"
        );
        assert_eq!(
            store
                .reopen_capture(&fixture.capture_intent.capture_id)
                .expect("repeat leaves exact v1 terminal unchanged"),
            physical
        );
        assert_eq!(
            store
                .reopen_sensitive_output_journal_v2(&fixture.capture_intent.capture_id)
                .expect("repeat leaves exact v2 prefix unchanged"),
            v2_after_first
        );
        assert!(matches!(
            coordinator.runner_lifecycle().state(),
            DesktopRunnerLifecycleStateView::Idle
        ));
    }

    #[test]
    fn lifecycle_owner_unknown_physical_producer_failure_releases_claim_for_immediate_retry() {
        let mut fixture = RestartOrdinaryCommandFixture::new(
            "lifecycle-owner-unknown-producer-failure-claim-release",
            true,
        );
        fixture.persist_live_ambiguous_unknown();
        let capture = fixture
            .ledger
            .load_command_output_capture_for_effect(&fixture.effect.intent.effect_id)
            .expect("load unresolved Unknown capture before producer failure");
        let terminal = capture
            .terminal
            .as_ref()
            .expect("unresolved Unknown capture has its immutable terminal");
        let claimed_at_unix_ms = current_unix_ms()
            .expect("read first physical producer claim time")
            .max(terminal.anchored_at_unix_ms);
        let expires_at_unix_ms = claimed_at_unix_ms
            .checked_add(grok_build_core::MAX_COMMAND_OUTPUT_CAPTURE_RECONCILIATION_TTL_MS)
            .expect("first physical producer claim time remains bounded");
        let first_claim_id = Digest::sha256(b"desktop-unknown-producer-failure-first-claim")
            .as_str()
            .to_owned();
        let CommandOutputCaptureReconciliationAdmission::Fresh {
            claim: first_claim,
            permit: first_permit,
        } = fixture
            .ledger
            .claim_command_output_capture_reconciliation(
                &capture.intent.capture_id,
                &first_claim_id,
                "desktop-unknown-producer-failure-test-v1",
                claimed_at_unix_ms,
                expires_at_unix_ms,
            )
            .expect("claim exact first physical producer fence")
        else {
            panic!("unresolved Unknown capture must issue a fresh first claim")
        };

        lifecycle_owner::fail_unknown_physical_resolution_producer_for_test(
            &mut fixture.ledger,
            first_permit,
        )
        .expect("physical producer failure releases its exact claim");

        let retry_at_unix_ms = current_unix_ms()
            .expect("read immediate retry claim time")
            .max(claimed_at_unix_ms);
        let retry_expires_at_unix_ms = retry_at_unix_ms
            .checked_add(grok_build_core::MAX_COMMAND_OUTPUT_CAPTURE_RECONCILIATION_TTL_MS)
            .expect("retry physical producer claim time remains bounded");
        let retry_claim_id = Digest::sha256(b"desktop-unknown-producer-failure-retry-claim")
            .as_str()
            .to_owned();
        let CommandOutputCaptureReconciliationAdmission::Fresh {
            claim: retry_claim,
            permit: retry_permit,
        } = fixture
            .ledger
            .claim_command_output_capture_reconciliation(
                &capture.intent.capture_id,
                &retry_claim_id,
                "desktop-unknown-producer-failure-test-v1",
                retry_at_unix_ms,
                retry_expires_at_unix_ms,
            )
            .expect("producer failure permits an immediate higher-epoch retry")
        else {
            panic!("released producer claim must not return Busy on immediate retry")
        };
        assert_eq!(retry_claim.claim_epoch, first_claim.claim_epoch + 1);
        assert_eq!(
            retry_claim.previous_claim_id.as_deref(),
            Some(first_claim.claim_id.as_str())
        );
        assert_ne!(retry_claim.fencing_token, first_claim.fencing_token);
        assert_eq!(
            fixture
                .ledger
                .release_command_output_capture_reconciliation(retry_permit, retry_at_unix_ms,)
                .expect("release exact retry claim after assertions"),
            retry_claim
        );
    }

    #[test]
    fn lifecycle_owner_unknown_core_precommit_failure_releases_claim_for_immediate_retry() {
        let mut fixture = RestartOrdinaryCommandFixture::new(
            "lifecycle-owner-unknown-core-precommit-claim-release",
            true,
        );
        fixture.persist_live_ambiguous_unknown();
        let capture = fixture
            .ledger
            .load_command_output_capture_for_effect(&fixture.effect.intent.effect_id)
            .expect("load unresolved Unknown capture before core precommit failure");
        let terminal = capture
            .terminal
            .as_ref()
            .expect("unresolved Unknown capture has its immutable terminal");
        let claimed_at_unix_ms = current_unix_ms()
            .expect("read first core precommit claim time")
            .max(terminal.anchored_at_unix_ms);
        let expires_at_unix_ms = claimed_at_unix_ms
            .checked_add(grok_build_core::MAX_COMMAND_OUTPUT_CAPTURE_RECONCILIATION_TTL_MS)
            .expect("first core precommit claim time remains bounded");
        let first_claim_id = Digest::sha256(b"desktop-unknown-core-precommit-first-claim")
            .as_str()
            .to_owned();
        let CommandOutputCaptureReconciliationAdmission::Fresh {
            claim: first_claim,
            permit: first_permit,
        } = fixture
            .ledger
            .claim_command_output_capture_reconciliation(
                &capture.intent.capture_id,
                &first_claim_id,
                "desktop-unknown-core-precommit-test-v1",
                claimed_at_unix_ms,
                expires_at_unix_ms,
            )
            .expect("claim exact first core precommit fence")
        else {
            panic!("unresolved Unknown capture must issue a fresh first claim")
        };

        lifecycle_owner::fail_unknown_core_resolution_precommit_for_test(
            &mut fixture.ledger,
            first_permit,
            &capture,
        )
        .expect("definite core precommit failure releases its returned exact claim");

        let retry_at_unix_ms = current_unix_ms()
            .expect("read immediate core retry claim time")
            .max(claimed_at_unix_ms);
        let retry_expires_at_unix_ms = retry_at_unix_ms
            .checked_add(grok_build_core::MAX_COMMAND_OUTPUT_CAPTURE_RECONCILIATION_TTL_MS)
            .expect("retry core claim time remains bounded");
        let retry_claim_id = Digest::sha256(b"desktop-unknown-core-precommit-retry-claim")
            .as_str()
            .to_owned();
        let CommandOutputCaptureReconciliationAdmission::Fresh {
            claim: retry_claim,
            permit: retry_permit,
        } = fixture
            .ledger
            .claim_command_output_capture_reconciliation(
                &capture.intent.capture_id,
                &retry_claim_id,
                "desktop-unknown-core-precommit-test-v1",
                retry_at_unix_ms,
                retry_expires_at_unix_ms,
            )
            .expect("core precommit failure permits an immediate higher-epoch retry")
        else {
            panic!("released core precommit claim must not return Busy on immediate retry")
        };
        assert_eq!(retry_claim.claim_epoch, first_claim.claim_epoch + 1);
        assert_eq!(
            retry_claim.previous_claim_id.as_deref(),
            Some(first_claim.claim_id.as_str())
        );
        assert_ne!(retry_claim.fencing_token, first_claim.fencing_token);
        assert_eq!(
            fixture
                .ledger
                .release_command_output_capture_reconciliation(retry_permit, retry_at_unix_ms,)
                .expect("release exact core retry claim after assertions"),
            retry_claim
        );
    }

    #[test]
    fn lifecycle_owner_restart_releases_preterminal_claim_before_immediate_retry() {
        let mut fixture = RestartOrdinaryCommandFixture::new(
            "lifecycle-owner-restart-release-before-retry",
            false,
        );
        let mut owner = DesktopRunnerLifecycleOwner::new(RunnerLifecycleOwnerConfig {
            runner_binary: fixture.harness.runner_binary.clone(),
            private_state_root: fixture.harness.private_state.clone(),
        })
        .expect("construct production claim-release restart owner");
        let displaced = fixture.harness.root.join("private-displaced");
        fs::rename(&fixture.harness.private_state, &displaced)
            .expect("displace exact private store");
        fs::write(
            &fixture.harness.private_state,
            b"not a private-state directory",
        )
        .expect("install deterministic store-open rejection");
        let first = fixture.reconcile(&mut owner);
        fs::remove_file(&fixture.harness.private_state).expect("remove store-open rejection");
        fs::rename(&displaced, &fixture.harness.private_state)
            .expect("restore exact private store identity");
        assert!(first.is_err(), "first physical reopen must reject");

        let retry = fixture
            .reconcile(&mut owner)
            .expect("released claim permits immediate exact retry");
        let crate::durable_coordinator::WalkingSkeletonTaskCommandRestartOutcome::Terminal(
            completed,
        ) = retry
        else {
            panic!("immediate retry must reacquire and terminalize, not report Busy")
        };
        assert!(matches!(
            completed.observation.as_ref().map(|value| &value.outcome),
            Some(EffectOutcome::FailedBeforeEffect { .. })
        ));
    }

    /// The public production launch is fail-closed on every target, but the
    /// shape of "fail closed" differs by whether the target has a
    /// descriptor-exec bridge, and this pins both shapes.
    ///
    /// Without a bridge (macOS, ADR-0011) the launch refuses before it inspects
    /// or persists anything, so no launch intent exists and the owner stays
    /// idle. With a bridge (Linux) the launch is real: the atomic launch/cleanup
    /// admission commits *before* the child exists, so a non-runner image
    /// produces durable launch authority and mandatory cleanup custody rather
    /// than an idle owner that quietly forgot a process it started.
    #[test]
    fn lifecycle_owner_public_launch_is_fail_closed_on_this_target() {
        let (harness, mut ledger) = TestHarness::new("lifecycle-owner-public-gate");
        let persisted = ledger
            .load_sprint(&harness.sprint_id)
            .expect("load public-gate sprint");
        let task = persisted.graph.as_ref().expect("fixture graph").tasks[0].clone();
        let attempt = ledger
            .load_task_attempt_history(&harness.sprint_id, &task.task_id)
            .expect("load public-gate attempt")
            .active_attempt()
            .expect("active leased attempt")
            .attempt
            .clone();
        // A target that really executes the image must not be handed this test
        // binary: the launch would run the whole suite again as its "runner".
        #[cfg(target_os = "linux")]
        let runner_binary = {
            let fixture = harness.root.join("public-gate-runner");
            copy_linux_fixture(&["/usr/bin/true", "/bin/true"], &fixture);
            fs::canonicalize(&fixture).expect("canonical public-gate runner fixture")
        };
        #[cfg(not(target_os = "linux"))]
        let runner_binary = harness.runner_binary.clone();
        let mut owner = DesktopRunnerLifecycleOwner::new(RunnerLifecycleOwnerConfig {
            runner_binary,
            private_state_root: harness.private_state.clone(),
        })
        .expect("construct public-gate owner");
        assert!(
            crate::WalkingSkeletonRunnerLifecycle::ensure_task_attempt_running(
                &mut owner,
                &mut ledger,
                crate::WalkingSkeletonRunnerStart {
                    sprint_spec: &harness.sprint_spec,
                    task: &task,
                    attempt: &attempt,
                    authority: &harness.authority,
                    policy: &harness.policy,
                    shadow_root: &harness.shadow,
                    input_snapshot: &harness.base_snapshot,
                    requested_at_unix_ms: 1_200,
                },
            )
            .is_err()
        );
        let launch_id = format!("{}:worker-launch-v1", attempt.attempt_id);
        #[cfg(not(target_os = "linux"))]
        {
            assert!(matches!(
                owner.state(),
                DesktopRunnerLifecycleStateView::Idle
            ));
            assert!(
                ledger
                    .load_runner_launch_intent(&harness.sprint_id, &launch_id)
                    .is_err(),
                "a target with no descriptor-exec bridge must refuse before launch persistence"
            );
        }
        #[cfg(target_os = "linux")]
        {
            let DesktopRunnerLifecycleStateView::CleanupRequired { binding, cleanup } =
                owner.state()
            else {
                panic!("a started child must leave mandatory cleanup custody, never an idle owner");
            };
            assert_eq!(binding.launch_id, launch_id);
            assert!(
                cleanup.launch_cleanup_admission().is_some(),
                "the retained cleanup must carry its atomic launch/cleanup admission"
            );
            assert!(
                !cleanup.has_native_cleanup_custody(),
                "a direct child creates no native accounting domain, so it holds no native custody"
            );
            let stored = ledger
                .load_runner_launch_intent(&harness.sprint_id, &launch_id)
                .expect("the admitted launch is durable before the child exists");
            assert_eq!(stored.launch_id, launch_id);
            assert!(
                ledger
                    .load_runner_session(&harness.sprint_id, &attempt.attempt_id)
                    .is_err(),
                "an uninitialized child must register no runner session"
            );
        }
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "the regression keeps native custody, command proof ordering, durable cleanup, and the cleanup-coupled lease release in one lifecycle boundary"
    )]
    fn lifecycle_owner_integrated_native_cleanup_waits_for_command_proof_then_releases_atomically()
    {
        let label = "lifecycle-owner-integrated-native-cleanup";
        let (harness, mut ledger) = TestHarness::new(label);
        let prepare_count = Rc::new(Cell::new(0));
        let release_count = Rc::new(Cell::new(0));
        let native_cleanup_count = Rc::new(Cell::new(0));
        let service = AdversarialNativeLaunchService::new(
            RunnerLaunchPreparationDisposition::HeldChildPrepared,
            NativeReleaseMutation::Exact,
            transport(
                unique_nonce(label),
                harness.identity(),
                ScriptMode::Good,
                true,
                Vec::new(),
            ),
            Rc::clone(&prepare_count),
            Rc::clone(&release_count),
        )
        .with_cleanup_script(
            Rc::clone(&native_cleanup_count),
            ScriptedNativeCleanupMutation::Exact,
        );
        let launch_request = harness.launch(label);
        let client = RunnerLifecycleClient::launch_with_native_service(
            &mut ledger,
            &harness.authority,
            &harness.policy,
            launch_request.clone(),
            Box::new(service),
        )
        .expect("initialize exact native task worker");
        assert_eq!(prepare_count.get(), 1);
        assert_eq!(release_count.get(), 1);
        let cleanup_admission = client
            .launch_cleanup_admission()
            .expect("native task worker retains atomic cleanup admission")
            .clone();
        let session = client.session().clone();
        let (disposition, command_effect_id) =
            persist_integrated_task_with_terminal_command(&harness, &mut ledger, &client, label);
        let TaskAttemptDisposition::Integrated(integrated) = &disposition else {
            unreachable!("cleanup fixture always returns Integrated")
        };
        let first_cleanup_at = integrated
            .integration_receipt
            .integrated_at_unix_ms
            .saturating_add(1);
        let mut owner = DesktopRunnerLifecycleOwner::from_active_client(
            RunnerLifecycleOwnerConfig {
                runner_binary: harness.runner_binary.clone(),
                private_state_root: harness.private_state.clone(),
            },
            launch_request,
            client,
        )
        .expect("inject exact native task worker into lifecycle owner");

        let first = crate::WalkingSkeletonRunnerLifecycle::cleanup_integrated_task_attempt(
            &mut owner,
            &mut ledger,
            crate::WalkingSkeletonIntegratedTaskCleanup {
                sprint_spec: &harness.sprint_spec,
                disposition: &disposition,
                cleanup_at_unix_ms: first_cleanup_at,
            },
        )
        .expect("missing command proof returns a typed pending outcome");
        assert!(matches!(
            first,
            crate::WalkingSkeletonIntegratedTaskCleanupOutcome::CleanupRequired { ref reason }
                if reason.contains("command-domain cleanup must complete")
        ));
        assert_eq!(native_cleanup_count.get(), 0);
        assert!(matches!(
            owner.state(),
            DesktopRunnerLifecycleStateView::CleanupRequired { cleanup, .. }
                if cleanup.has_native_cleanup_custody()
        ));
        assert!(
            ledger
                .load_effect(&cleanup_admission.cleanup_effect.intent.effect_id)
                .expect("load still-open native cleanup effect")
                .observation
                .is_none()
        );
        assert_eq!(
            ledger
                .load_active_worker_leases(&harness.sprint_id)
                .expect("load lease retained while command proof is missing"),
            vec![harness.worker_lease.clone()]
        );
        let pending_history = ledger
            .load_task_attempt_history(&harness.sprint_id, "task-1")
            .expect("load pending integrated cleanup history");
        assert!(pending_history.attempts[0].lease_state.is_active());

        let bindings = ledger
            .load_command_domain_effect_bindings(
                &harness.sprint_id,
                &cleanup_admission.launch.launch_id,
                &session.session_id,
            )
            .expect("load exact command-domain binding");
        assert_eq!(bindings.len(), 1);
        let binding = &bindings[0];
        assert_eq!(binding.effect_id, command_effect_id);
        let backend = match cleanup_admission.cleanup_request.platform_backend {
            WorkerCleanupBackend::MacOsDedicatedIdentity => {
                CommandDomainBackend::MacOsDedicatedIdentity
            }
            WorkerCleanupBackend::LinuxCgroupV2 => CommandDomainBackend::LinuxCgroupV2,
            WorkerCleanupBackend::TrustedApplierDirectChildWait => {
                panic!("task worker cannot use trusted-Applier cleanup")
            }
        };
        let command_proof_bytes =
            format!("no command domain was created for {command_effect_id}").into_bytes();
        let command_cleaned_at = first_cleanup_at.saturating_add(1);
        ledger
            .record_command_domain_cleanup_proof(&CommandDomainCleanupProof {
                contract_version: CONTRACT_VERSION,
                proof_id: format!("proof-integrated-native-cleanup-{label}"),
                sprint_id: binding.sprint_id.clone(),
                launch_id: binding.launch_id.clone(),
                session_id: binding.session_id.clone(),
                effect_id: binding.effect_id.clone(),
                observation_id: binding.observation_id.clone(),
                request_digest: binding.request_digest.clone(),
                backend,
                disposition: CommandDomainCleanupDisposition::NoDomainCreatedBeforeEffect,
                surviving_processes: 0,
                platform_proof_digest: Digest::sha256(&command_proof_bytes),
                platform_proof_bytes: command_proof_bytes,
                cleaned_at_unix_ms: command_cleaned_at,
            })
            .expect("persist exact command-domain no-effect proof");

        let second_cleanup_at = command_cleaned_at.saturating_add(1);
        let completed =
            match crate::WalkingSkeletonRunnerLifecycle::cleanup_integrated_task_attempt(
                &mut owner,
                &mut ledger,
                crate::WalkingSkeletonIntegratedTaskCleanup {
                    sprint_spec: &harness.sprint_spec,
                    disposition: &disposition,
                    cleanup_at_unix_ms: second_cleanup_at,
                },
            )
            .expect("complete native cleanup after command-domain proof")
            {
                crate::WalkingSkeletonIntegratedTaskCleanupOutcome::Completed(completed) => {
                    completed
                }
                crate::WalkingSkeletonIntegratedTaskCleanupOutcome::CleanupRequired { reason } => {
                    panic!("exact command proof must unblock native cleanup: {reason}")
                }
            };
        assert_eq!(native_cleanup_count.get(), 1);
        assert!(matches!(
            owner.state(),
            DesktopRunnerLifecycleStateView::Idle
        ));
        assert_eq!(completed.intent, cleanup_admission.cleanup_effect.intent);
        assert!(matches!(
            completed
                .observation
                .as_ref()
                .map(|observation| &observation.outcome),
            Some(EffectOutcome::Succeeded { .. })
        ));
        assert_eq!(
            ledger
                .load_effect(&cleanup_admission.cleanup_effect.intent.effect_id)
                .expect("reload completed native cleanup effect"),
            completed
        );
        assert!(
            ledger
                .load_active_worker_leases(&harness.sprint_id)
                .expect("load leases after cleanup-coupled release")
                .is_empty()
        );
        let cleanup_evidence: WorkerCleanupEvidence = serde_json::from_slice(
            completed
                .evidence_bytes
                .as_deref()
                .expect("native cleanup retains exact evidence bytes"),
        )
        .expect("decode exact native cleanup evidence");
        let released_history = ledger
            .load_task_attempt_history(&harness.sprint_id, "task-1")
            .expect("load released integrated cleanup history");
        assert!(matches!(
            &released_history.attempts[0].lease_state,
            grok_build_core::TaskAttemptLeaseState::Released {
                release_id,
                released_at_unix_ms,
            } if release_id == &harness.worker_lease.lease_id
                && *released_at_unix_ms == cleanup_evidence.receipt.cleaned_at_unix_ms
        ));
    }

    #[test]
    fn lifecycle_owner_restart_reopens_cleanup_only_once_and_releases_integrated_lease_atomically()
    {
        let label = "lifecycle-owner-restart-integrated-native-cleanup";
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
        let reopen_count = Rc::new(Cell::new(0));
        let cleanup_count = Rc::new(Cell::new(0));
        let claims = Rc::new(RefCell::new(Vec::new()));
        let expected_next_event_sequence = ledger
            .next_sequence(&harness.sprint_id)
            .expect("read exact pre-cleanup event sequence");
        let reopener: Box<dyn NativeLaunchCleanupReopener> =
            Box::new(ScriptedNativeCleanupReopener {
                authority: cleanup_authority,
                reopen_count: Rc::clone(&reopen_count),
                cleanup_count: Rc::clone(&cleanup_count),
                mutation: ScriptedNativeCleanupMutation::Exact,
                claims: Rc::clone(&claims),
            });
        let mut owner = DesktopRunnerLifecycleOwner::with_native_cleanup_reopener(
            RunnerLifecycleOwnerConfig {
                runner_binary: harness.runner_binary.clone(),
                private_state_root: harness.private_state.clone(),
            },
            reopener,
        )
        .expect("construct restarted owner with cleanup-only journal access");

        let completed =
            match crate::WalkingSkeletonRunnerLifecycle::cleanup_integrated_task_attempt(
                &mut owner,
                &mut ledger,
                crate::WalkingSkeletonIntegratedTaskCleanup {
                    sprint_spec: &harness.sprint_spec,
                    disposition: &disposition,
                    cleanup_at_unix_ms,
                },
            )
            .expect("restart reopener completes exact integrated cleanup")
            {
                crate::WalkingSkeletonIntegratedTaskCleanupOutcome::Completed(completed) => {
                    completed
                }
                crate::WalkingSkeletonIntegratedTaskCleanupOutcome::CleanupRequired { reason } => {
                    panic!("exact cleanup-only restart journal must complete: {reason}")
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
        assert_eq!(completed.intent, cleanup_admission.cleanup_effect.intent);
        assert!(matches!(
            completed
                .observation
                .as_ref()
                .map(|observation| &observation.outcome),
            Some(EffectOutcome::Succeeded { .. })
        ));
        assert_eq!(
            ledger
                .load_effect(&cleanup_admission.cleanup_effect.intent.effect_id)
                .expect("reload restart-completed cleanup effect"),
            completed
        );
        assert!(
            ledger
                .load_active_worker_leases(&harness.sprint_id)
                .expect("load cleanup-coupled lease release after restart")
                .is_empty()
        );
        assert!(matches!(
            owner.state(),
            DesktopRunnerLifecycleStateView::Idle
        ));
    }
