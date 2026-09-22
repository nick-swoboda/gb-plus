    #[allow(
        clippy::too_many_lines,
        reason = "the fixture keeps the passing final-verification cut, absent application phase, optional live Applier, and exact native cleanup journal contiguous"
    )]
    fn unadmitted_application_owner_fixture_inner(
        label: &str,
        register_session: bool,
        retain_active: bool,
        mutation: ScriptedNativeCleanupMutation,
        effect_script: ApplicationEffectScript,
    ) -> UnadmittedApplicationOwnerFixture {
        assert!(
            register_session || !retain_active,
            "a sessionless trusted-Applier launch cannot retain a live client"
        );
        let (harness, mut ledger) = TestHarness::new(label);
        let UnadmittedApplicationPreparation {
            policy,
            final_verification_receipt_id,
            final_verification_terminal,
            application,
            request,
            stage_bundle,
            artifact_assembly_id,
        } = prepare_unadmitted_application_fixture(&harness, &mut ledger, label, register_session);
        let manual_cleanup_admission = ledger
            .load_runner_launch_cleanup_admission(&harness.sprint_id, &application.launch.launch_id)
            .expect("reload pre-admission trusted-Applier cleanup admission");
        assert_eq!(manual_cleanup_admission.launch, application.launch);
        assert_eq!(
            manual_cleanup_admission.cleanup_effect.intent,
            application.cleanup_intent
        );
        assert_eq!(
            manual_cleanup_admission.cleanup_request,
            application.cleanup_request
        );
        assert_eq!(
            manual_cleanup_admission
                .cleanup_effect
                .proposed_event
                .event_id,
            application.cleanup_proposed_event_id
        );

        let prepare_count = Rc::new(Cell::new(0));
        let release_count = Rc::new(Cell::new(0));
        let native_cleanup_count = Rc::new(Cell::new(0));
        let exchange_count = Rc::new(Cell::new(0));
        let (
            cleanup_admission,
            cleanup_authority,
            cleanup_session,
            cleanup_at_unix_ms,
            active,
            crossed_launch_id,
        ) = if retain_active {
            let (transport_mode, response) = match effect_script {
                ApplicationEffectScript::Unused => (ScriptMode::Good, None),
                ApplicationEffectScript::Success => (
                    ScriptMode::Good,
                    Some(scripted_application_success_response(
                        &harness,
                        &policy,
                        &application.session,
                        &request,
                        &stage_bundle,
                        label,
                    )),
                ),
                ApplicationEffectScript::AdaptationRejected => {
                    let mut response = scripted_application_success_response(
                        &harness,
                        &policy,
                        &application.session,
                        &request,
                        &stage_bundle,
                        label,
                    );
                    let RunnerResponse::ApplicationApplied { evidence } = &mut response else {
                        unreachable!("scripted application response has one exact shape")
                    };
                    evidence.applied_operations_digest =
                        Digest::sha256(b"rejected-application-operations");
                    (ScriptMode::Good, Some(response))
                }
                ApplicationEffectScript::NoRequestBytesWritten => (
                    ScriptMode::WriteFailureAt(3, ScriptWriteProgress::None),
                    None,
                ),
            };
            let service = AdversarialNativeLaunchService::new(
                RunnerLaunchPreparationDisposition::HeldChildPrepared,
                NativeReleaseMutation::Exact,
                transport_with_optional_effect_response(
                    unique_nonce(&format!("{label}-active-applier")),
                    harness.identity(),
                    transport_mode,
                    response,
                    Rc::clone(&exchange_count),
                ),
                Rc::clone(&prepare_count),
                Rc::clone(&release_count),
            )
            .with_cleanup_script(Rc::clone(&native_cleanup_count), mutation);
            let mut launch_request = harness.launch(&format!("{label}-active-applier"));
            launch_request.role = RunnerRole::Applier;
            launch_request.worker_id = None;
            launch_request.worker_lease = None;
            launch_request.shadow_root = None;
            launch_request.expected_base_snapshot = request.change_set.base_snapshot.clone();
            launch_request.created_at_unix_ms = final_verification_terminal
                .occurred_at_unix_ms
                .saturating_add(10);
            let retained_request = launch_request.clone();
            let client = RunnerLifecycleClient::launch_with_native_service(
                &mut ledger,
                &harness.authority,
                &policy,
                launch_request,
                Box::new(service),
            )
            .expect("launch exact live pre-admission trusted Applier");
            let cleanup_admission = client
                .launch_cleanup_admission()
                .expect("live trusted Applier retains atomic cleanup admission")
                .clone();
            let preparation = ledger
                .load_runner_launch_preparation(
                    &cleanup_admission.launch.sprint_id,
                    &cleanup_admission.launch.launch_id,
                )
                .expect("reload live trusted-Applier native preparation");
            let cleanup_authority = NativeLaunchCleanupAuthority::from_expected_state(
                &cleanup_admission,
                Some(&preparation),
                client
                    .platform_launch_binding
                    .as_deref()
                    .expect("live trusted Applier retains exact platform binding"),
            );
            let (client, _) = client
                .send_control(RunnerRequest::ApplierRecoverPending)
                .expect("complete mandatory trusted-Applier recovery");
            let capture_at_unix_ms = client.session().registered_at_unix_ms;
            let (client, _) = client
                .send_control(RunnerRequest::ApplierCaptureLive {
                    created_at_unix_ms: capture_at_unix_ms,
                })
                .expect("complete mandatory trusted-Applier live capture");
            let crossed_launch_id = if mutation
                == ScriptedNativeCleanupMutation::FailOnceBeforeObservation
                && matches!(effect_script, ApplicationEffectScript::Unused)
            {
                launch_ordinary_completion_role_with_registration(
                    &harness,
                    &mut ledger,
                    &policy,
                    &format!("{label}-crossed-applier"),
                    RunnerRole::Applier,
                    true,
                    Some(
                        final_verification_terminal
                            .occurred_at_unix_ms
                            .saturating_add(20),
                    ),
                    None,
                )
                .launch
                .launch_id
            } else {
                manual_cleanup_admission.launch.launch_id.clone()
            };
            let cleanup_at_unix_ms =
                native_cleanup_requested_at_unix_ms(&ledger, &cleanup_admission)
                    .max(client.session().registered_at_unix_ms)
                    .saturating_add(1);
            let cleanup_session = client.session().clone();
            (
                cleanup_admission,
                cleanup_authority,
                cleanup_session,
                cleanup_at_unix_ms,
                Some((retained_request, client)),
                Some(crossed_launch_id),
            )
        } else {
            let restart_application = launch_ordinary_completion_role_with_registration(
                &harness,
                &mut ledger,
                &policy,
                &format!("{label}-restart-applier"),
                RunnerRole::Applier,
                register_session,
                Some(
                    final_verification_terminal
                        .occurred_at_unix_ms
                        .saturating_add(1),
                ),
                None,
            );
            let restart_cleanup_admission = ledger
                .load_runner_launch_cleanup_admission(
                    &harness.sprint_id,
                    &restart_application.launch.launch_id,
                )
                .expect("reload correctly ordered restart trusted-Applier admission");
            let (cleanup_authority, cleanup_at_unix_ms) =
                persist_scripted_native_preparation_authority(
                    &harness,
                    &mut ledger,
                    &policy,
                    &restart_cleanup_admission,
                    label,
                );
            (
                restart_cleanup_admission,
                cleanup_authority,
                restart_application.session,
                cleanup_at_unix_ms,
                None,
                Some(manual_cleanup_admission.launch.launch_id.clone()),
            )
        };
        UnadmittedApplicationOwnerFixture {
            harness,
            ledger,
            policy,
            final_verification_receipt_id,
            final_verification_terminal,
            request,
            stage_bundle,
            artifact_assembly_id,
            cleanup_admission,
            cleanup_authority,
            cleanup_session,
            cleanup_at_unix_ms,
            active,
            crossed_launch_id,
            prepare_count,
            release_count,
            native_cleanup_count,
            exchange_count,
        }
    }

    struct AdmittedApplicationOwnerFixture {
        harness: TestHarness,
        ledger: EventLedger,
        policy: CompiledExecutionPolicy,
        request: ApplicationRequest,
        stage_bundle: StageBundleReference,
        admission: SprintApplicationAdmission,
        intent: EffectIntent,
        proposed_event_id: String,
        applier: crate::WalkingSkeletonApplicationBoundary,
        owner: DesktopRunnerLifecycleOwner,
        dispatch_permit: Option<FreshApplicationDispatchPermit>,
        application_receipt_id: String,
        rollback_reference_id: String,
        observation_id: String,
        observed_at_unix_ms: u64,
        rollback_validated_at_unix_ms: u64,
        cleanup_at_unix_ms: u64,
        launch_cleanup_admission: PersistedRunnerLaunchCleanupAdmission,
        cleanup_authority: NativeLaunchCleanupAuthority,
        prepare_count: Rc<Cell<u64>>,
        release_count: Rc<Cell<u64>>,
        native_cleanup_count: Rc<Cell<u64>>,
        exchange_count: Rc<Cell<u64>>,
    }

    impl AdmittedApplicationOwnerFixture {
        fn dispatch(&mut self) -> crate::WalkingSkeletonClaimedApplicationResponse {
            let permit = self
                .dispatch_permit
                .take()
                .expect("application dispatch permit remains fresh");
            crate::WalkingSkeletonRunnerLifecycle::dispatch_sprint_application(
                &mut self.owner,
                &mut self.ledger,
                crate::WalkingSkeletonApplicationDispatch {
                    sprint_spec: &self.harness.sprint_spec,
                    workspace_grant: &self.harness.authority,
                    policy: &self.policy,
                    applier: &self.applier,
                    admission: &self.admission,
                    intent: &self.intent,
                    request: &self.request,
                    stage_bundle: &self.stage_bundle,
                    application_receipt_id: &self.application_receipt_id,
                    rollback_reference_id: &self.rollback_reference_id,
                    observation_id: &self.observation_id,
                    observed_at_unix_ms: self.observed_at_unix_ms,
                    rollback_validated_at_unix_ms: self.rollback_validated_at_unix_ms,
                    dispatch_permit: permit,
                },
            )
            .expect("dispatch exact admitted application through production owner")
        }
    }

    #[allow(
        clippy::too_many_lines,
        reason = "the admitted fixture keeps the exact pre-admission cleanup, Applying transition, fresh permit, and live production owner in one authority chain"
    )]
    fn admitted_application_owner_fixture(
        label: &str,
        mutation: ScriptedNativeCleanupMutation,
        effect_script: ApplicationEffectScript,
    ) -> AdmittedApplicationOwnerFixture {
        let UnadmittedApplicationOwnerFixture {
            harness,
            mut ledger,
            policy,
            final_verification_receipt_id,
            final_verification_terminal,
            request,
            stage_bundle,
            artifact_assembly_id,
            cleanup_admission,
            cleanup_authority,
            cleanup_session,
            cleanup_at_unix_ms,
            active,
            crossed_launch_id,
            prepare_count,
            release_count,
            native_cleanup_count,
            exchange_count,
            ..
        } = active_admitted_application_fixture(label, mutation, effect_script);
        let (launch_request, client) = active.expect("fixture retains exact live trusted Applier");
        let admitted_at_unix_ms = cleanup_at_unix_ms
            .max(cleanup_session.registered_at_unix_ms)
            .saturating_add(1);

        let unrelated_launch_id =
            crossed_launch_id.expect("fixture retains its pre-admission manual Applier launch");
        assert_ne!(unrelated_launch_id, cleanup_admission.launch.launch_id);
        let unrelated_admission = ledger
            .load_runner_launch_cleanup_admission(&harness.sprint_id, &unrelated_launch_id)
            .expect("reload pre-admission manual Applier cleanup authority");
        let unrelated_session = ledger
            .load_runner_session(&harness.sprint_id, &unrelated_admission.launch.session_id)
            .expect("reload pre-admission manual Applier session");
        persist_cleanup_evidence(
            &mut ledger,
            &CompletionRoleAdmission {
                launch: unrelated_admission.launch.clone(),
                cleanup_request: unrelated_admission.cleanup_request.clone(),
                cleanup_intent: unrelated_admission.cleanup_effect.intent.clone(),
                cleanup_proposed_event_id: unrelated_admission
                    .cleanup_effect
                    .proposed_event
                    .event_id
                    .clone(),
                session: unrelated_session.clone(),
                task_attempt_running: None,
            },
            &unrelated_session,
            None,
            &format!("cleanup-pre-admission-{label}"),
            admitted_at_unix_ms.saturating_sub(1),
        );

        let request_bytes = serde_json::to_vec(&request).expect("encode admitted application");
        let phase_sequence = ledger
            .next_sequence(&harness.sprint_id)
            .expect("next admitted application phase sequence");
        let phase_event = AgentEvent {
            contract_version: CONTRACT_VERSION,
            sequence: phase_sequence,
            event_id: format!("sprint-applying-{label}"),
            sprint_id: harness.sprint_id.clone(),
            task_id: None,
            worker_id: None,
            causation_id: Some(final_verification_terminal.event_id),
            correlation_id: format!("correlation-application-{label}"),
            policy_hash: Some(cleanup_admission.launch.policy_hash.clone()),
            occurred_at_unix_ms: admitted_at_unix_ms,
            payload: AgentEventKind::SprintStateChanged {
                from: "FinalVerification".into(),
                to: "Applying".into(),
            },
        };
        let intent = EffectIntent {
            contract_version: CONTRACT_VERSION,
            effect_id: format!("application-effect-{label}"),
            idempotency_key: format!("application-key-{label}"),
            sprint_id: harness.sprint_id.clone(),
            task_id: None,
            worker_id: None,
            worker_lease: None,
            causation_event_id: Some(phase_event.event_id.clone()),
            correlation_id: phase_event.correlation_id.clone(),
            kind: EffectKind::ApplyChangeSet,
            request_digest: Digest::sha256(&request_bytes),
            policy_hash: cleanup_admission.launch.policy_hash.clone(),
            input_snapshot: request.change_set.base_snapshot.clone(),
            created_at_unix_ms: admitted_at_unix_ms,
        };
        let proposed = proposal(&intent, phase_sequence.saturating_add(1));
        let admission = SprintApplicationAdmission {
            contract_version: CONTRACT_VERSION,
            admission_id: format!("application-admission-{label}"),
            sprint_id: harness.sprint_id.clone(),
            sprint_phase_event_id: phase_event.event_id.clone(),
            final_verification_receipt_id,
            artifact_assembly_id,
            effect_id: intent.effect_id.clone(),
            runner_launch_id: cleanup_admission.launch.launch_id.clone(),
            runner_session_id: cleanup_admission.launch.session_id.clone(),
            request: request.clone(),
            admitted_at_unix_ms,
        };
        let SprintApplicationDispatchAdmission::Fresh {
            admission: stored_admission,
            effect: stored_effect,
            permit,
            ..
        } = ledger
            .admit_sprint_application_for_dispatch(&admission, &phase_event, &intent, &proposed)
            .expect("atomically admit exact application phase")
        else {
            panic!("fresh admitted application must mint one dispatch permit")
        };
        assert_eq!(stored_admission, admission);
        assert_eq!(stored_effect.intent, intent);

        let applier = crate::WalkingSkeletonApplicationBoundary {
            runner_launch: cleanup_admission.launch.clone(),
            runner_session: cleanup_session,
            request: request.clone(),
            stage_bundle: stage_bundle.clone(),
        };
        let owner = DesktopRunnerLifecycleOwner::from_active_application_applier_for_test(
            RunnerLifecycleOwnerConfig {
                runner_binary: harness.runner_binary.clone(),
                private_state_root: harness.private_state.clone(),
            },
            launch_request,
            client,
            request.clone(),
            stage_bundle.clone(),
        )
        .expect("construct admitted live trusted-Applier owner");
        let observed_at_unix_ms = admitted_at_unix_ms.saturating_add(1);
        let rollback_validated_at_unix_ms = observed_at_unix_ms.saturating_add(1);
        AdmittedApplicationOwnerFixture {
            harness,
            ledger,
            policy,
            request,
            stage_bundle,
            admission,
            intent,
            proposed_event_id: proposed.event_id,
            applier,
            owner,
            dispatch_permit: Some(permit),
            application_receipt_id: format!("application-receipt-{label}"),
            rollback_reference_id: format!("rollback-reference-{label}"),
            observation_id: format!("application-observation-{label}"),
            observed_at_unix_ms,
            rollback_validated_at_unix_ms,
            cleanup_at_unix_ms: rollback_validated_at_unix_ms.saturating_add(1),
            launch_cleanup_admission: cleanup_admission,
            cleanup_authority,
            prepare_count,
            release_count,
            native_cleanup_count,
            exchange_count,
        }
    }

    fn persist_admitted_application_success(
        fixture: &mut AdmittedApplicationOwnerFixture,
        claimed: crate::WalkingSkeletonClaimedApplicationResponse,
    ) -> (PersistedEffect, crate::AdaptedApplicationEvidence) {
        let (response, authority, failure_evidence) = claimed.into_parts();
        assert!(failure_evidence.is_none());
        let crate::WalkingSkeletonApplicationOutcome::Succeeded(evidence) = response.outcome else {
            panic!("exact scripted application must succeed")
        };
        let evidence = *evidence;
        let observed = observation(
            &fixture.intent,
            fixture.observation_id.clone(),
            EffectOutcome::Succeeded {
                evidence_digest: evidence.canonical_evidence.digest.clone(),
            },
            fixture.observed_at_unix_ms,
        );
        let terminal = terminal_event(
            &fixture.ledger,
            &fixture.intent,
            &fixture.proposed_event_id,
            &observed,
        );
        let completed = fixture
            .ledger
            .record_claimed_application_effect_observation_with_rollback(
                authority,
                &observed,
                &terminal,
                &evidence.application_evidence,
                &evidence.rollback_reference,
            )
            .expect("persist exact claimed application and rollback evidence");
        crate::WalkingSkeletonRunnerLifecycle::acknowledge_task_effect_observation(
            &mut fixture.owner,
            &fixture.ledger,
            &completed,
        )
        .expect("acknowledge exact successful application terminal");
        (completed, evidence)
    }

    fn persist_admitted_application_failure(
        fixture: &mut AdmittedApplicationOwnerFixture,
        claimed: crate::WalkingSkeletonClaimedApplicationResponse,
        expected_phase: RunnerEffectFailurePhase,
        terminal_outcome: crate::WalkingSkeletonApplicationTerminalOutcome,
    ) -> PersistedEffect {
        let (response, authority, failure_evidence) = claimed.into_parts();
        match terminal_outcome {
            crate::WalkingSkeletonApplicationTerminalOutcome::FailedBeforeEffect => {
                assert!(matches!(
                    response.outcome,
                    crate::WalkingSkeletonApplicationOutcome::FailedBeforeEffect { .. }
                ));
            }
            crate::WalkingSkeletonApplicationTerminalOutcome::Unknown => assert!(matches!(
                response.outcome,
                crate::WalkingSkeletonApplicationOutcome::UnknownAfterDispatch { .. }
            )),
        }
        let (phase, evidence) =
            failure_evidence.expect("claimed application failure retains canonical evidence");
        assert_eq!(phase, expected_phase);
        let outcome = match terminal_outcome {
            crate::WalkingSkeletonApplicationTerminalOutcome::FailedBeforeEffect => {
                EffectOutcome::FailedBeforeEffect {
                    evidence_digest: Digest::sha256(&evidence),
                }
            }
            crate::WalkingSkeletonApplicationTerminalOutcome::Unknown => EffectOutcome::Unknown {
                evidence_digest: Digest::sha256(&evidence),
            },
        };
        let observed = observation(
            &fixture.intent,
            fixture.observation_id.clone(),
            outcome,
            fixture.observed_at_unix_ms,
        );
        let terminal = terminal_event(
            &fixture.ledger,
            &fixture.intent,
            &fixture.proposed_event_id,
            &observed,
        );
        let completed = fixture
            .ledger
            .record_claimed_effect_observation(authority, &observed, &evidence, &terminal)
            .expect("persist exact claimed application failure evidence");
        crate::WalkingSkeletonRunnerLifecycle::acknowledge_task_effect_observation(
            &mut fixture.owner,
            &fixture.ledger,
            &completed,
        )
        .expect("acknowledge exact failed application terminal");
        completed
    }

    enum RestartAdmittedApplicationTerminal {
        Succeeded(Box<crate::AdaptedApplicationEvidence>),
        FailedBeforeEffect,
        Unknown,
    }

    struct RestartAdmittedApplicationTerminalFixture {
        harness: TestHarness,
        ledger: EventLedger,
        admission: SprintApplicationAdmission,
        completed: PersistedEffect,
        terminal: RestartAdmittedApplicationTerminal,
        cleanup_at_unix_ms: u64,
        launch_cleanup_admission: PersistedRunnerLaunchCleanupAdmission,
        cleanup_authority: NativeLaunchCleanupAuthority,
        prepare_count: Rc<Cell<u64>>,
        release_count: Rc<Cell<u64>>,
        original_native_cleanup_count: Rc<Cell<u64>>,
        exchange_count: Rc<Cell<u64>>,
    }

    fn restart_admitted_application_terminal_fixture(
        label: &str,
        script: ApplicationEffectScript,
    ) -> RestartAdmittedApplicationTerminalFixture {
        assert!(!matches!(script, ApplicationEffectScript::Unused));
        let mut fixture =
            admitted_application_owner_fixture(label, ScriptedNativeCleanupMutation::Exact, script);
        let claimed = fixture.dispatch();
        let (completed, terminal) = match script {
            ApplicationEffectScript::Success => {
                let (completed, evidence) =
                    persist_admitted_application_success(&mut fixture, claimed);
                (
                    completed,
                    RestartAdmittedApplicationTerminal::Succeeded(Box::new(evidence)),
                )
            }
            ApplicationEffectScript::NoRequestBytesWritten => (
                persist_admitted_application_failure(
                    &mut fixture,
                    claimed,
                    RunnerEffectFailurePhase::NoRequestBytesWritten,
                    crate::WalkingSkeletonApplicationTerminalOutcome::FailedBeforeEffect,
                ),
                RestartAdmittedApplicationTerminal::FailedBeforeEffect,
            ),
            ApplicationEffectScript::AdaptationRejected => (
                persist_admitted_application_failure(
                    &mut fixture,
                    claimed,
                    RunnerEffectFailurePhase::CorrelatedResponseRejected,
                    crate::WalkingSkeletonApplicationTerminalOutcome::Unknown,
                ),
                RestartAdmittedApplicationTerminal::Unknown,
            ),
            ApplicationEffectScript::Unused => {
                unreachable!("admitted application restart fixture requires one observed terminal")
            }
        };
        let AdmittedApplicationOwnerFixture {
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
        // Simulate process loss after the application terminal is durable but
        // before the trusted Applier's direct-child cleanup is persisted.
        drop(owner);
        RestartAdmittedApplicationTerminalFixture {
            harness,
            ledger,
            admission,
            completed,
            terminal,
            cleanup_at_unix_ms,
            launch_cleanup_admission,
            cleanup_authority,
            prepare_count,
            release_count,
            original_native_cleanup_count: native_cleanup_count,
            exchange_count,
        }
    }

    fn cleanup_restarted_admitted_application(
        owner: &mut DesktopRunnerLifecycleOwner,
        ledger: &mut EventLedger,
        sprint_spec: &SprintSpec,
        admission: &SprintApplicationAdmission,
        completed: &PersistedEffect,
        terminal: &RestartAdmittedApplicationTerminal,
        cleanup_at_unix_ms: u64,
    ) -> Result<crate::WalkingSkeletonApplicationCleanupOutcome, crate::DurableCoordinatorError>
    {
        match terminal {
            RestartAdmittedApplicationTerminal::Succeeded(evidence) => {
                crate::WalkingSkeletonRunnerLifecycle::cleanup_sprint_application(
                    owner,
                    ledger,
                    crate::WalkingSkeletonApplicationCleanup {
                        sprint_spec,
                        admission,
                        evidence: &evidence.application_evidence,
                        rollback_reference: &evidence.rollback_reference,
                        cleanup_at_unix_ms,
                    },
                )
            }
            RestartAdmittedApplicationTerminal::FailedBeforeEffect => {
                crate::WalkingSkeletonRunnerLifecycle::cleanup_terminal_sprint_application(
                    owner,
                    ledger,
                    crate::WalkingSkeletonApplicationTerminalCleanup {
                        sprint_spec,
                        admission,
                        completed,
                        outcome:
                            crate::WalkingSkeletonApplicationTerminalOutcome::FailedBeforeEffect,
                        cleanup_at_unix_ms,
                    },
                )
            }
            RestartAdmittedApplicationTerminal::Unknown => {
                crate::WalkingSkeletonRunnerLifecycle::cleanup_terminal_sprint_application(
                    owner,
                    ledger,
                    crate::WalkingSkeletonApplicationTerminalCleanup {
                        sprint_spec,
                        admission,
                        completed,
                        outcome: crate::WalkingSkeletonApplicationTerminalOutcome::Unknown,
                        cleanup_at_unix_ms,
                    },
                )
            }
        }
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "the three observed application terminals share one custody-free fail-once reopen, retained retry, and exact durable readback matrix"
    )]
    fn lifecycle_owner_admitted_application_observed_terminal_idle_restart_table() {
        for (label, script) in [
            (
                "lifecycle-owner-application-success-idle-restart",
                ApplicationEffectScript::Success,
            ),
            (
                "lifecycle-owner-application-failed-before-effect-idle-restart",
                ApplicationEffectScript::NoRequestBytesWritten,
            ),
            (
                "lifecycle-owner-application-unknown-idle-restart",
                ApplicationEffectScript::AdaptationRejected,
            ),
        ] {
            let RestartAdmittedApplicationTerminalFixture {
                harness,
                mut ledger,
                admission,
                completed,
                terminal,
                cleanup_at_unix_ms,
                launch_cleanup_admission,
                cleanup_authority,
                prepare_count,
                release_count,
                original_native_cleanup_count,
                exchange_count,
            } = restart_admitted_application_terminal_fixture(label, script);
            let pending_cleanup = launch_cleanup_admission.cleanup_effect.clone();
            let application_before_cleanup = ledger
                .load_effect(&completed.intent.effect_id)
                .expect("snapshot observed application before restart cleanup");
            let reopen_count = Rc::new(Cell::new(0));
            let cleanup_count = Rc::new(Cell::new(0));
            let claims = Rc::new(RefCell::new(Vec::new()));
            let next_event_sequence = ledger
                .next_sequence(&harness.sprint_id)
                .expect("read application restart cleanup event sequence");
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
            .expect("construct admitted application Idle restart owner");

            let first = cleanup_restarted_admitted_application(
                &mut owner,
                &mut ledger,
                &harness.sprint_spec,
                &admission,
                &completed,
                &terminal,
                cleanup_at_unix_ms,
            )
            .expect("first reopened application cleanup remains a typed requirement");
            assert!(matches!(
                first,
                crate::WalkingSkeletonApplicationCleanupOutcome::CleanupRequired { .. }
            ));
            assert_eq!((reopen_count.get(), cleanup_count.get()), (1, 1));
            assert_eq!(claims.borrow().len(), 1);
            assert!(matches!(
                owner.state(),
                DesktopRunnerLifecycleStateView::ApplicationCleanupRequired { cleanup, .. }
                    if cleanup.has_native_cleanup_custody()
            ));
            assert_eq!(
                ledger
                    .load_effect(&pending_cleanup.intent.effect_id)
                    .expect("first restart cleanup failure leaves obligation pending"),
                pending_cleanup
            );

            let second = cleanup_restarted_admitted_application(
                &mut owner,
                &mut ledger,
                &harness.sprint_spec,
                &admission,
                &completed,
                &terminal,
                cleanup_at_unix_ms.saturating_add(1),
            )
            .expect("retained application cleanup custody completes without reopening");
            let crate::WalkingSkeletonApplicationCleanupOutcome::Completed(cleanup) = second else {
                panic!("retained application restart cleanup remained pending")
            };
            assert_eq!((reopen_count.get(), cleanup_count.get()), (1, 2));
            assert_eq!(original_native_cleanup_count.get(), 0);
            assert_eq!((prepare_count.get(), release_count.get()), (1, 1));
            assert_eq!(exchange_count.get(), 4);
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
                    .expect("reload admitted application restart cleanup"),
                cleanup
            );
            assert_eq!(
                ledger
                    .load_effect(&completed.intent.effect_id)
                    .expect("restart cleanup leaves application terminal unchanged"),
                application_before_cleanup
            );
            assert!(matches!(
                owner.state(),
                DesktopRunnerLifecycleStateView::Idle
            ));
        }
    }

    #[test]
    fn lifecycle_owner_admitted_application_observed_terminal_missing_reopener_table() {
        for (label, script) in [
            (
                "lifecycle-owner-application-success-missing-reopener",
                ApplicationEffectScript::Success,
            ),
            (
                "lifecycle-owner-application-failed-before-effect-missing-reopener",
                ApplicationEffectScript::NoRequestBytesWritten,
            ),
            (
                "lifecycle-owner-application-unknown-missing-reopener",
                ApplicationEffectScript::AdaptationRejected,
            ),
        ] {
            let RestartAdmittedApplicationTerminalFixture {
                harness,
                mut ledger,
                admission,
                completed,
                terminal,
                cleanup_at_unix_ms,
                launch_cleanup_admission,
                original_native_cleanup_count,
                exchange_count,
                ..
            } = restart_admitted_application_terminal_fixture(label, script);
            let pending_cleanup = launch_cleanup_admission.cleanup_effect.clone();
            let application_before_cleanup = ledger
                .load_effect(&completed.intent.effect_id)
                .expect("snapshot application before missing-reopener stop");
            let mut owner = DesktopRunnerLifecycleOwner::new(RunnerLifecycleOwnerConfig {
                runner_binary: harness.runner_binary.clone(),
                private_state_root: harness.private_state.clone(),
            })
            .expect("construct admitted application owner without reopener");

            let outcome = cleanup_restarted_admitted_application(
                &mut owner,
                &mut ledger,
                &harness.sprint_spec,
                &admission,
                &completed,
                &terminal,
                cleanup_at_unix_ms,
            )
            .expect("missing application reopener remains cleanup-required");
            assert!(matches!(
                outcome,
                crate::WalkingSkeletonApplicationCleanupOutcome::CleanupRequired { ref reason }
                    if reason.contains("reopener")
            ));
            assert_eq!(original_native_cleanup_count.get(), 0);
            assert_eq!(exchange_count.get(), 4);
            assert_eq!(
                ledger
                    .load_effect(&pending_cleanup.intent.effect_id)
                    .expect("missing reopener leaves application cleanup pending"),
                pending_cleanup
            );
            assert_eq!(
                ledger
                    .load_effect(&completed.intent.effect_id)
                    .expect("missing reopener leaves application terminal unchanged"),
                application_before_cleanup
            );
            assert!(matches!(
                owner.state(),
                DesktopRunnerLifecycleStateView::Idle
            ));
        }
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "the three observed application terminals share the same crossed-reopener custody-retention and no-native-effect assertions"
    )]
    fn lifecycle_owner_admitted_application_observed_terminal_crossed_reopener_table() {
        for (label, script) in [
            (
                "lifecycle-owner-application-success-crossed-reopener",
                ApplicationEffectScript::Success,
            ),
            (
                "lifecycle-owner-application-failed-before-effect-crossed-reopener",
                ApplicationEffectScript::NoRequestBytesWritten,
            ),
            (
                "lifecycle-owner-application-unknown-crossed-reopener",
                ApplicationEffectScript::AdaptationRejected,
            ),
        ] {
            let RestartAdmittedApplicationTerminalFixture {
                harness,
                mut ledger,
                admission,
                completed,
                terminal,
                cleanup_at_unix_ms,
                launch_cleanup_admission,
                mut cleanup_authority,
                original_native_cleanup_count,
                exchange_count,
                ..
            } = restart_admitted_application_terminal_fixture(label, script);
            cleanup_authority.expected_platform_binding_digest =
                Digest::sha256(format!("crossed-admitted-application-restart-{label}").as_bytes());
            let pending_cleanup = launch_cleanup_admission.cleanup_effect.clone();
            let application_before_cleanup = ledger
                .load_effect(&completed.intent.effect_id)
                .expect("snapshot application before crossed-reopener stop");
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
            .expect("construct crossed admitted application cleanup reopener");

            for cleanup_at_unix_ms in [cleanup_at_unix_ms, cleanup_at_unix_ms.saturating_add(1)] {
                let outcome = cleanup_restarted_admitted_application(
                    &mut owner,
                    &mut ledger,
                    &harness.sprint_spec,
                    &admission,
                    &completed,
                    &terminal,
                    cleanup_at_unix_ms,
                )
                .expect("crossed application custody remains a typed cleanup requirement");
                assert!(matches!(
                    outcome,
                    crate::WalkingSkeletonApplicationCleanupOutcome::CleanupRequired { .. }
                ));
                assert_eq!(reopen_count.get(), 1);
                assert_eq!(cleanup_count.get(), 0);
                assert_eq!(claims.borrow().len(), 1);
                assert_eq!(original_native_cleanup_count.get(), 0);
                assert_eq!(exchange_count.get(), 4);
                assert_eq!(
                    ledger
                        .load_effect(&pending_cleanup.intent.effect_id)
                        .expect("crossed reopener leaves application cleanup pending"),
                    pending_cleanup
                );
                assert_eq!(
                    ledger
                        .load_effect(&completed.intent.effect_id)
                        .expect("crossed reopener leaves application terminal unchanged"),
                    application_before_cleanup
                );
                assert!(matches!(
                    owner.state(),
                    DesktopRunnerLifecycleStateView::ApplicationCleanupRequired { cleanup, .. }
                        if cleanup.has_native_cleanup_custody()
                ));
            }
        }
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "the regression keeps admitted application success, live native cleanup failure, crossed retry refusal, retained custody, and exact durable readback in one audit"
    )]
    fn lifecycle_owner_admitted_application_success_live_failure_retains_and_retries_without_reopen()
     {
        let mut fixture = admitted_application_owner_fixture(
            "lifecycle-owner-admitted-application-success-live-retry",
            ScriptedNativeCleanupMutation::FailOnceBeforeObservation,
            ApplicationEffectScript::Success,
        );
        assert_eq!(
            (fixture.prepare_count.get(), fixture.release_count.get()),
            (1, 1)
        );
        assert_eq!(fixture.exchange_count.get(), 3);
        let claimed = fixture.dispatch();
        assert_eq!(fixture.exchange_count.get(), 4);
        assert!(matches!(
            fixture.owner.state(),
            DesktopRunnerLifecycleStateView::ReconciliationRequired {
                requirement: RunnerLifecycleReconciliation::AwaitingTerminalObservation { .. },
                custody: ReconciliationCustodyView::LiveApplicationApplier { .. },
            }
        ));
        let (_application, evidence) = persist_admitted_application_success(&mut fixture, claimed);
        assert!(matches!(
            fixture.owner.state(),
            DesktopRunnerLifecycleStateView::ActiveApplicationApplier { .. }
        ));
        let pending_cleanup = fixture.launch_cleanup_admission.cleanup_effect.clone();

        let first_cleanup = crate::WalkingSkeletonRunnerLifecycle::cleanup_sprint_application(
            &mut fixture.owner,
            &mut fixture.ledger,
            crate::WalkingSkeletonApplicationCleanup {
                sprint_spec: &fixture.harness.sprint_spec,
                admission: &fixture.admission,
                evidence: &evidence.application_evidence,
                rollback_reference: &evidence.rollback_reference,
                cleanup_at_unix_ms: fixture.cleanup_at_unix_ms,
            },
        )
        .expect("first native cleanup failure returns typed retained custody");
        assert!(matches!(
            first_cleanup,
            crate::WalkingSkeletonApplicationCleanupOutcome::CleanupRequired { .. }
        ));
        assert_eq!(fixture.native_cleanup_count.get(), 1);
        assert_eq!(fixture.exchange_count.get(), 5);
        assert_eq!(
            fixture
                .ledger
                .load_effect(&pending_cleanup.intent.effect_id)
                .expect("failed native cleanup remains pending"),
            pending_cleanup
        );
        assert!(matches!(
            fixture.owner.state(),
            DesktopRunnerLifecycleStateView::ApplicationCleanupRequired { ref binding, .. }
                if binding.launch_id == fixture.admission.runner_launch_id
                    && binding.session_id == fixture.admission.runner_session_id
        ));

        let mut crossed_spec = fixture.harness.sprint_spec.clone();
        crossed_spec.objective.push_str(" crossed-retained-cleanup");
        crate::WalkingSkeletonRunnerLifecycle::cleanup_sprint_application(
            &mut fixture.owner,
            &mut fixture.ledger,
            crate::WalkingSkeletonApplicationCleanup {
                sprint_spec: &crossed_spec,
                admission: &fixture.admission,
                evidence: &evidence.application_evidence,
                rollback_reference: &evidence.rollback_reference,
                cleanup_at_unix_ms: fixture.cleanup_at_unix_ms,
            },
        )
        .expect_err("retained application cleanup must reject a same-ID crossed sprint");
        assert_eq!(fixture.native_cleanup_count.get(), 1);
        assert_eq!(fixture.exchange_count.get(), 5);
        assert!(matches!(
            fixture.owner.state(),
            DesktopRunnerLifecycleStateView::ApplicationCleanupRequired { .. }
        ));

        let cleanup = crate::WalkingSkeletonRunnerLifecycle::cleanup_sprint_application(
            &mut fixture.owner,
            &mut fixture.ledger,
            crate::WalkingSkeletonApplicationCleanup {
                sprint_spec: &fixture.harness.sprint_spec,
                admission: &fixture.admission,
                evidence: &evidence.application_evidence,
                rollback_reference: &evidence.rollback_reference,
                cleanup_at_unix_ms: fixture.cleanup_at_unix_ms,
            },
        )
        .expect("retry persists the retained exact native cleanup");
        let crate::WalkingSkeletonApplicationCleanupOutcome::Completed(cleanup) = cleanup else {
            panic!("retained application cleanup must complete on retry")
        };
        assert_eq!(fixture.native_cleanup_count.get(), 2);
        assert_eq!(fixture.exchange_count.get(), 5);
        assert_eq!(
            cleanup.intent,
            fixture.launch_cleanup_admission.cleanup_effect.intent
        );
        assert_eq!(
            fixture
                .ledger
                .load_effect(&cleanup.intent.effect_id)
                .expect("reload completed application cleanup"),
            cleanup
        );
        assert!(matches!(
            fixture.owner.state(),
            DesktopRunnerLifecycleStateView::Idle
        ));
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "the table keeps both direct and prepared Unknown reconciliation paths, retained native custody, exact retry, and durable readback contiguous"
    )]
    fn lifecycle_owner_terminal_application_unknown_live_reconciliation_failure_retains_cleanup_and_retries_without_reopen()
     {
        for prepare_first in [false, true] {
            let label = format!(
                "lifecycle-owner-terminal-application-unknown-{}",
                if prepare_first { "prepared" } else { "direct" }
            );
            let mut fixture = admitted_application_owner_fixture(
                &label,
                ScriptedNativeCleanupMutation::FailOnceBeforeObservation,
                ApplicationEffectScript::AdaptationRejected,
            );
            let claimed = fixture.dispatch();
            assert_eq!(fixture.exchange_count.get(), 4);
            let completed = persist_admitted_application_failure(
                &mut fixture,
                claimed,
                RunnerEffectFailurePhase::CorrelatedResponseRejected,
                crate::WalkingSkeletonApplicationTerminalOutcome::Unknown,
            );
            assert!(matches!(
                fixture.owner.state(),
                DesktopRunnerLifecycleStateView::ReconciliationRequired {
                    requirement: RunnerLifecycleReconciliation::RunnerRequestedReconciliation { .. },
                    custody: ReconciliationCustodyView::LiveApplicationApplier { .. },
                }
            ));
            if prepare_first {
                fixture
                    .owner
                    .prepare_reconciliation_cleanup()
                    .expect("prepare exact application reconciliation cleanup custody");
                assert!(matches!(
                    fixture.owner.state(),
                    DesktopRunnerLifecycleStateView::ReconciliationRequired {
                        requirement: RunnerLifecycleReconciliation::RunnerRequestedReconciliation { .. },
                        custody: ReconciliationCustodyView::ApplicationCleanup { .. },
                    }
                ));
            }
            assert_eq!(
                fixture.exchange_count.get(),
                if prepare_first { 5 } else { 4 }
            );

            let first_cleanup =
                crate::WalkingSkeletonRunnerLifecycle::cleanup_terminal_sprint_application(
                    &mut fixture.owner,
                    &mut fixture.ledger,
                    crate::WalkingSkeletonApplicationTerminalCleanup {
                        sprint_spec: &fixture.harness.sprint_spec,
                        admission: &fixture.admission,
                        completed: &completed,
                        outcome: crate::WalkingSkeletonApplicationTerminalOutcome::Unknown,
                        cleanup_at_unix_ms: fixture.cleanup_at_unix_ms,
                    },
                )
                .expect("first terminal native cleanup failure returns typed retained custody");
            assert!(matches!(
                first_cleanup,
                crate::WalkingSkeletonApplicationCleanupOutcome::CleanupRequired { .. }
            ));
            assert_eq!(fixture.native_cleanup_count.get(), 1);
            assert_eq!(fixture.exchange_count.get(), 5);
            assert!(matches!(
                fixture.owner.state(),
                DesktopRunnerLifecycleStateView::ReconciliationRequired {
                    requirement: RunnerLifecycleReconciliation::RunnerRequestedReconciliation { .. },
                    custody: ReconciliationCustodyView::ApplicationCleanup { .. },
                }
            ));

            let cleanup =
                crate::WalkingSkeletonRunnerLifecycle::cleanup_terminal_sprint_application(
                    &mut fixture.owner,
                    &mut fixture.ledger,
                    crate::WalkingSkeletonApplicationTerminalCleanup {
                        sprint_spec: &fixture.harness.sprint_spec,
                        admission: &fixture.admission,
                        completed: &completed,
                        outcome: crate::WalkingSkeletonApplicationTerminalOutcome::Unknown,
                        cleanup_at_unix_ms: fixture.cleanup_at_unix_ms,
                    },
                )
                .expect("retry persists exact terminal application cleanup");
            let crate::WalkingSkeletonApplicationCleanupOutcome::Completed(cleanup_effect) =
                cleanup
            else {
                panic!("terminal Unknown application cleanup must complete on exact retry")
            };
            assert_eq!(
                cleanup_effect.intent,
                fixture.launch_cleanup_admission.cleanup_effect.intent
            );
            assert_eq!(
                fixture
                    .ledger
                    .load_effect(&cleanup_effect.intent.effect_id)
                    .expect("reload terminal Unknown application cleanup"),
                cleanup_effect
            );
            assert_eq!(fixture.native_cleanup_count.get(), 2);
            assert_eq!(fixture.exchange_count.get(), 5);
            assert!(matches!(
                fixture.owner.state(),
                DesktopRunnerLifecycleStateView::Idle
            ));
        }
    }

    #[test]
    fn lifecycle_owner_terminal_application_failed_before_effect_cleanup_reconciliation_closes_once()
     {
        let mut fixture = admitted_application_owner_fixture(
            "lifecycle-owner-terminal-application-failed-before-effect",
            ScriptedNativeCleanupMutation::Exact,
            ApplicationEffectScript::NoRequestBytesWritten,
        );
        let claimed = fixture.dispatch();
        assert_eq!(fixture.exchange_count.get(), 4);
        let completed = persist_admitted_application_failure(
            &mut fixture,
            claimed,
            RunnerEffectFailurePhase::NoRequestBytesWritten,
            crate::WalkingSkeletonApplicationTerminalOutcome::FailedBeforeEffect,
        );
        assert!(matches!(
            completed.mutation_artifact,
            PersistedMutationArtifact::NotRequired
        ));
        assert!(matches!(
            completed.finish_receipt,
            PersistedFinishReceipt::NotRequired
        ));
        assert!(matches!(
            fixture.owner.state(),
            DesktopRunnerLifecycleStateView::ReconciliationRequired {
                requirement: RunnerLifecycleReconciliation::EffectDispatchFailed { .. },
                custody: ReconciliationCustodyView::ApplicationCleanup { .. },
            }
        ));
        assert!(matches!(
            fixture
                .ledger
                .load_application_evidence(&fixture.application_receipt_id),
            Err(LedgerError::ArtifactNotFound { .. })
        ));
        assert!(matches!(
            fixture
                .ledger
                .load_rollback_reference(&fixture.rollback_reference_id),
            Err(LedgerError::ArtifactNotFound { .. })
        ));

        let cleanup = crate::WalkingSkeletonRunnerLifecycle::cleanup_terminal_sprint_application(
            &mut fixture.owner,
            &mut fixture.ledger,
            crate::WalkingSkeletonApplicationTerminalCleanup {
                sprint_spec: &fixture.harness.sprint_spec,
                admission: &fixture.admission,
                completed: &completed,
                outcome: crate::WalkingSkeletonApplicationTerminalOutcome::FailedBeforeEffect,
                cleanup_at_unix_ms: fixture.cleanup_at_unix_ms,
            },
        )
        .expect("exact FailedBeforeEffect cleanup reconciliation closes once");
        let crate::WalkingSkeletonApplicationCleanupOutcome::Completed(cleanup_effect) = cleanup
        else {
            panic!("FailedBeforeEffect application cleanup must complete exactly once")
        };
        assert_eq!(
            cleanup_effect.intent,
            fixture.launch_cleanup_admission.cleanup_effect.intent
        );
        assert_eq!(
            fixture
                .ledger
                .load_effect(&cleanup_effect.intent.effect_id)
                .expect("reload FailedBeforeEffect application cleanup"),
            cleanup_effect
        );
        assert_eq!(fixture.native_cleanup_count.get(), 1);
        assert_eq!(fixture.exchange_count.get(), 4);
        assert!(matches!(
            fixture.owner.state(),
            DesktopRunnerLifecycleStateView::Idle
        ));
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "the adversarial table crosses each terminal application cleanup authority and proves zero shutdown, native cleanup, or durable mutation"
    )]
    fn lifecycle_owner_admitted_application_terminal_cleanup_crossed_authority_has_no_shutdown_or_native_effect()
     {
        #[derive(Clone, Copy)]
        enum CrossedAuthority {
            SprintSpec,
            Admission,
            Completed,
            Outcome,
        }

        for crossed in [
            CrossedAuthority::SprintSpec,
            CrossedAuthority::Admission,
            CrossedAuthority::Completed,
            CrossedAuthority::Outcome,
        ] {
            let suffix = match crossed {
                CrossedAuthority::SprintSpec => "sprint-spec",
                CrossedAuthority::Admission => "admission",
                CrossedAuthority::Completed => "completed",
                CrossedAuthority::Outcome => "outcome",
            };
            let mut fixture = admitted_application_owner_fixture(
                &format!("lifecycle-owner-terminal-application-crossed-{suffix}"),
                ScriptedNativeCleanupMutation::Exact,
                ApplicationEffectScript::AdaptationRejected,
            );
            let claimed = fixture.dispatch();
            let completed = persist_admitted_application_failure(
                &mut fixture,
                claimed,
                RunnerEffectFailurePhase::CorrelatedResponseRejected,
                crate::WalkingSkeletonApplicationTerminalOutcome::Unknown,
            );
            assert!(matches!(
                fixture.owner.state(),
                DesktopRunnerLifecycleStateView::ReconciliationRequired {
                    requirement: RunnerLifecycleReconciliation::RunnerRequestedReconciliation { .. },
                    custody: ReconciliationCustodyView::LiveApplicationApplier { .. },
                }
            ));
            let rightful_application = fixture
                .ledger
                .load_effect(&fixture.intent.effect_id)
                .expect("snapshot rightful terminal application");
            let pending_cleanup = fixture
                .ledger
                .load_effect(
                    &fixture
                        .launch_cleanup_admission
                        .cleanup_effect
                        .intent
                        .effect_id,
                )
                .expect("snapshot rightful pending application cleanup");
            let mut sprint_spec = fixture.harness.sprint_spec.clone();
            let mut admission = fixture.admission.clone();
            let mut crossed_completed = completed.clone();
            let mut outcome = crate::WalkingSkeletonApplicationTerminalOutcome::Unknown;
            match crossed {
                CrossedAuthority::SprintSpec => sprint_spec.objective.push_str("-crossed"),
                CrossedAuthority::Admission => {
                    admission.runner_session_id.push_str("-crossed");
                }
                CrossedAuthority::Completed => crossed_completed.request_bytes.push(b' '),
                CrossedAuthority::Outcome => {
                    outcome = crate::WalkingSkeletonApplicationTerminalOutcome::FailedBeforeEffect;
                }
            }

            crate::WalkingSkeletonRunnerLifecycle::cleanup_terminal_sprint_application(
                &mut fixture.owner,
                &mut fixture.ledger,
                crate::WalkingSkeletonApplicationTerminalCleanup {
                    sprint_spec: &sprint_spec,
                    admission: &admission,
                    completed: &crossed_completed,
                    outcome,
                    cleanup_at_unix_ms: fixture.cleanup_at_unix_ms,
                },
            )
            .expect_err("crossed terminal application authority must fail before shutdown");
            assert_eq!(fixture.exchange_count.get(), 4, "crossed {suffix}");
            assert_eq!(fixture.native_cleanup_count.get(), 0, "crossed {suffix}");
            assert_eq!(
                fixture
                    .ledger
                    .load_effect(&fixture.intent.effect_id)
                    .expect("crossed cleanup leaves application unchanged"),
                rightful_application,
                "crossed {suffix}"
            );
            assert_eq!(
                fixture
                    .ledger
                    .load_effect(
                        &fixture
                            .launch_cleanup_admission
                            .cleanup_effect
                            .intent
                            .effect_id
                    )
                    .expect("crossed cleanup leaves native cleanup pending"),
                pending_cleanup,
                "crossed {suffix}"
            );
            assert!(matches!(
                fixture.owner.state(),
                DesktopRunnerLifecycleStateView::ReconciliationRequired {
                    custody: ReconciliationCustodyView::LiveApplicationApplier { ref binding },
                    ..
                } if binding.launch_id == fixture.admission.runner_launch_id
                    && binding.session_id == fixture.admission.runner_session_id
                    && binding.request == &fixture.request
                    && binding.stage_bundle == &fixture.stage_bundle
            ));
        }
    }

    #[test]
    fn lifecycle_owner_unadmitted_application_applier_registered_restart_reopens_once_and_closes() {
        let label = "lifecycle-owner-unadmitted-application-registered-restart";
        let UnadmittedApplicationOwnerFixture {
            harness,
            mut ledger,
            final_verification_receipt_id,
            request,
            cleanup_admission,
            cleanup_authority,
            ..
        } = restart_unadmitted_application_fixture(label, true);
        let registered = ledger
            .load_runner_session(
                &cleanup_admission.launch.sprint_id,
                &cleanup_admission.launch.session_id,
            )
            .expect("reload registered unadmitted trusted-Applier session");
        assert_eq!(registered.purpose, RunnerSessionPurpose::Applier);
        let early_cleanup_at_unix_ms = cleanup_admission.launch.created_at_unix_ms;
        assert!(early_cleanup_at_unix_ms < registered.registered_at_unix_ms);
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
        .expect("construct registered trusted-Applier restart owner");

        let completed = match crate::WalkingSkeletonRunnerLifecycle::cleanup_unadmitted_sprint_application_applier_launch(
            &mut owner,
            &mut ledger,
            crate::WalkingSkeletonUnadmittedApplicationApplierCleanup {
                sprint_spec: &harness.sprint_spec,
                launch_id: &cleanup_admission.launch.launch_id,
                final_verification_receipt_id: &final_verification_receipt_id,
                base_snapshot: &request.change_set.base_snapshot,
                cleanup_at_unix_ms: early_cleanup_at_unix_ms,
            },
        )
        .expect("registered restart closes exact unadmitted trusted-Applier launch")
        {
            crate::WalkingSkeletonUnadmittedApplicationApplierCleanupOutcome::Completed(
                completed,
            ) => completed,
            crate::WalkingSkeletonUnadmittedApplicationApplierCleanupOutcome::CleanupRequired {
                reason,
            } => panic!("registered trusted-Applier cleanup remained pending: {reason}"),
        };
        assert_eq!((reopen_count.get(), cleanup_count.get()), (1, 1));
        assert_eq!(claims.borrow().len(), 1);
        assert_eq!(completed.intent, cleanup_admission.cleanup_effect.intent);
        let PersistedFinishReceipt::WorkerCleanup(evidence) = &completed.finish_receipt else {
            panic!("registered trusted-Applier cleanup must persist WorkerCleanup evidence")
        };
        assert_eq!(evidence.receipt.surviving_processes, 0);
        assert_eq!(
            evidence.receipt.cleaned_at_unix_ms, registered.registered_at_unix_ms,
            "registered cleanup time must be raised to the durable session boundary"
        );
        assert_eq!(
            evidence.receipt.platform_backend,
            WorkerCleanupBackend::TrustedApplierDirectChildWait
        );
        assert_eq!(
            ledger
                .load_effect(&cleanup_admission.cleanup_effect.intent.effect_id)
                .expect("reload registered trusted-Applier cleanup terminal"),
            completed
        );
        assert!(matches!(
            owner.state(),
            DesktopRunnerLifecycleStateView::Idle
        ));
    }

    #[test]
    fn lifecycle_owner_unadmitted_application_applier_sessionless_restart_closes_without_session() {
        let label = "lifecycle-owner-unadmitted-application-sessionless-restart";
        let UnadmittedApplicationOwnerFixture {
            harness,
            mut ledger,
            final_verification_receipt_id,
            request,
            cleanup_admission,
            cleanup_authority,
            cleanup_at_unix_ms,
            ..
        } = restart_unadmitted_application_fixture(label, false);
        assert!(matches!(
            ledger.load_runner_session(
                &cleanup_admission.launch.sprint_id,
                &cleanup_admission.launch.session_id,
            ),
            Err(LedgerError::ArtifactNotFound { .. })
        ));
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
                mutation: ScriptedNativeCleanupMutation::Exact,
                claims: Rc::new(RefCell::new(Vec::new())),
            }),
        )
        .expect("construct sessionless trusted-Applier restart owner");
        let outcome = crate::WalkingSkeletonRunnerLifecycle::cleanup_unadmitted_sprint_application_applier_launch(
            &mut owner,
            &mut ledger,
            crate::WalkingSkeletonUnadmittedApplicationApplierCleanup {
                sprint_spec: &harness.sprint_spec,
                launch_id: &cleanup_admission.launch.launch_id,
                final_verification_receipt_id: &final_verification_receipt_id,
                base_snapshot: &request.change_set.base_snapshot,
                cleanup_at_unix_ms,
            },
        )
        .expect("sessionless restart closes exact unadmitted trusted-Applier launch");
        assert!(matches!(
            outcome,
            crate::WalkingSkeletonUnadmittedApplicationApplierCleanupOutcome::Completed(_)
        ));
        assert_eq!((reopen_count.get(), cleanup_count.get()), (1, 1));
        assert!(matches!(
            ledger.load_runner_session(
                &cleanup_admission.launch.sprint_id,
                &cleanup_admission.launch.session_id,
            ),
            Err(LedgerError::ArtifactNotFound { .. })
        ));
        assert!(matches!(
            owner.state(),
            DesktopRunnerLifecycleStateView::Idle
        ));
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "the late-registration regression keeps the first failed native attempt, durable session insert, retained custody, retry, and exact terminal floor visible"
    )]
    fn lifecycle_owner_unadmitted_application_applier_retained_sessionless_custody_adopts_late_exact_registration()
     {
        let label = "lifecycle-owner-unadmitted-application-late-registration";
        let UnadmittedApplicationOwnerFixture {
            harness,
            mut ledger,
            policy,
            final_verification_receipt_id,
            request,
            cleanup_admission,
            cleanup_authority,
            mut cleanup_session,
            cleanup_at_unix_ms,
            ..
        } = restart_unadmitted_application_fixture(label, false);
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
                mutation: ScriptedNativeCleanupMutation::FailOnceBeforeObservation,
                claims: Rc::clone(&claims),
            }),
        )
        .expect("construct sessionless fail-once trusted-Applier restart owner");

        let first = crate::WalkingSkeletonRunnerLifecycle::cleanup_unadmitted_sprint_application_applier_launch(
            &mut owner,
            &mut ledger,
            crate::WalkingSkeletonUnadmittedApplicationApplierCleanup {
                sprint_spec: &harness.sprint_spec,
                launch_id: &cleanup_admission.launch.launch_id,
                final_verification_receipt_id: &final_verification_receipt_id,
                base_snapshot: &request.change_set.base_snapshot,
                cleanup_at_unix_ms,
            },
        )
        .expect("first sessionless native failure retains exact cleanup custody");
        assert!(matches!(
            first,
            crate::WalkingSkeletonUnadmittedApplicationApplierCleanupOutcome::CleanupRequired { .. }
        ));
        assert_eq!((reopen_count.get(), cleanup_count.get()), (1, 1));
        assert!(matches!(
            owner.state(),
            DesktopRunnerLifecycleStateView::ApplicationCleanupRequired { cleanup, .. }
                if cleanup.has_native_cleanup_custody()
                    && matches!(
                        cleanup.session_registration(),
                        RunnerSessionRegistrationState::NotRegistered
                    )
        ));

        cleanup_session.registered_at_unix_ms = cleanup_at_unix_ms.saturating_add(50);
        ledger
            .register_runner_session(&cleanup_session, &policy)
            .expect("register the exact session after sessionless custody was retained");
        let completed = match crate::WalkingSkeletonRunnerLifecycle::cleanup_unadmitted_sprint_application_applier_launch(
            &mut owner,
            &mut ledger,
            crate::WalkingSkeletonUnadmittedApplicationApplierCleanup {
                sprint_spec: &harness.sprint_spec,
                launch_id: &cleanup_admission.launch.launch_id,
                final_verification_receipt_id: &final_verification_receipt_id,
                base_snapshot: &request.change_set.base_snapshot,
                cleanup_at_unix_ms,
            },
        )
        .expect("retained custody adopts the transaction-current exact late registration")
        {
            crate::WalkingSkeletonUnadmittedApplicationApplierCleanupOutcome::Completed(
                completed,
            ) => completed,
            crate::WalkingSkeletonUnadmittedApplicationApplierCleanupOutcome::CleanupRequired {
                reason,
            } => panic!("late-registration retry remained pending: {reason}"),
        };
        assert_eq!((reopen_count.get(), cleanup_count.get()), (1, 2));
        assert_eq!(claims.borrow().len(), 1);
        let PersistedFinishReceipt::WorkerCleanup(evidence) = &completed.finish_receipt else {
            panic!("late-registration retry must persist WorkerCleanup evidence")
        };
        assert_eq!(
            evidence.receipt.cleaned_at_unix_ms,
            cleanup_session.registered_at_unix_ms
        );
        assert!(matches!(
            owner.state(),
            DesktopRunnerLifecycleStateView::Idle
        ));
    }

    fn assert_retained_application_registration_mismatch_stops_before_reopen(
        label: &str,
        register_session: bool,
        cross_candidate: bool,
    ) {
        let UnadmittedApplicationOwnerFixture {
            harness,
            mut ledger,
            final_verification_receipt_id,
            request,
            stage_bundle,
            cleanup_admission,
            cleanup_authority,
            mut cleanup_session,
            cleanup_at_unix_ms,
            ..
        } = restart_unadmitted_application_fixture(label, register_session);
        if cross_candidate {
            cleanup_session.session_nonce = unique_nonce(&format!("{label}-crossed-candidate"));
        }
        let retained = admitted_cleanup_without_native_custody(
            cleanup_admission.clone(),
            cleanup_session.clone(),
            cleanup_authority.platform_binding().clone(),
        );
        let pending = cleanup_admission.cleanup_effect.clone();
        let reopen_count = Rc::new(Cell::new(0));
        let cleanup_count = Rc::new(Cell::new(0));
        let claims = Rc::new(RefCell::new(Vec::new()));
        let mut owner =
            DesktopRunnerLifecycleOwner::from_application_cleanup_with_reopener_for_test(
                RunnerLifecycleOwnerConfig {
                    runner_binary: harness.runner_binary.clone(),
                    private_state_root: harness.private_state.clone(),
                },
                retained,
                request.clone(),
                stage_bundle,
                Box::new(ScriptedNativeCleanupReopener {
                    authority: cleanup_authority,
                    reopen_count: Rc::clone(&reopen_count),
                    cleanup_count: Rc::clone(&cleanup_count),
                    mutation: ScriptedNativeCleanupMutation::Exact,
                    claims: Rc::clone(&claims),
                }),
            )
            .expect("construct retained registered trusted-Applier cleanup owner");

        let error = crate::WalkingSkeletonRunnerLifecycle::cleanup_unadmitted_sprint_application_applier_launch(
            &mut owner,
            &mut ledger,
            crate::WalkingSkeletonUnadmittedApplicationApplierCleanup {
                sprint_spec: &harness.sprint_spec,
                launch_id: &cleanup_admission.launch.launch_id,
                final_verification_receipt_id: &final_verification_receipt_id,
                base_snapshot: &request.change_set.base_snapshot,
                cleanup_at_unix_ms,
            },
        )
        .expect_err("transaction-current session mismatch must reject before native reopening");
        assert!(matches!(
            error,
            crate::DurableCoordinatorError::Ledger(LedgerError::ReferenceMismatch {
                entity: "specialized runner cleanup registration",
                ..
            })
        ));
        assert_eq!((reopen_count.get(), cleanup_count.get()), (0, 0));
        assert!(claims.borrow().is_empty());
        assert_eq!(
            ledger
                .load_effect(&cleanup_admission.cleanup_effect.intent.effect_id)
                .expect("registration mismatch leaves cleanup pending"),
            pending
        );
        assert!(matches!(
            owner.state(),
            DesktopRunnerLifecycleStateView::ApplicationCleanupRequired { cleanup, .. }
                if !cleanup.has_native_cleanup_custody()
                    && cleanup.session_registration()
                        == &RunnerSessionRegistrationState::Registered(cleanup_session)
        ));
    }

    #[test]
    fn lifecycle_owner_unadmitted_application_applier_retained_registered_rejects_transaction_absence_before_reopen()
     {
        assert_retained_application_registration_mismatch_stops_before_reopen(
            "lifecycle-owner-unadmitted-application-retained-registration-absent",
            false,
            false,
        );
    }

    #[test]
    fn lifecycle_owner_unadmitted_application_applier_retained_crossed_registration_rejects_before_reopen()
     {
        assert_retained_application_registration_mismatch_stops_before_reopen(
            "lifecycle-owner-unadmitted-application-retained-registration-crossed",
            true,
            true,
        );
    }

    #[test]
    fn lifecycle_owner_unadmitted_application_applier_same_process_active_closes_once() {
        let label = "lifecycle-owner-unadmitted-application-active";
        let UnadmittedApplicationOwnerFixture {
            harness,
            mut ledger,
            final_verification_receipt_id,
            request,
            stage_bundle,
            cleanup_admission,
            cleanup_at_unix_ms,
            active,
            prepare_count,
            release_count,
            native_cleanup_count,
            ..
        } = active_unadmitted_application_fixture(label, ScriptedNativeCleanupMutation::Exact);
        let (launch_request, client) = active.expect("fixture retains exact live trusted Applier");
        let mut owner = DesktopRunnerLifecycleOwner::from_active_application_applier_for_test(
            RunnerLifecycleOwnerConfig {
                runner_binary: harness.runner_binary.clone(),
                private_state_root: harness.private_state.clone(),
            },
            launch_request,
            client,
            request.clone(),
            stage_bundle.clone(),
        )
        .expect("construct exact active trusted-Applier owner");
        assert!(matches!(
            owner.state(),
            DesktopRunnerLifecycleStateView::ActiveApplicationApplier { ref binding }
                if binding.sprint_id == harness.sprint_id
                    && binding.launch_id == cleanup_admission.launch.launch_id
                    && binding.session_id == cleanup_admission.launch.session_id
                    && binding.request == &request
                    && binding.stage_bundle == &stage_bundle
        ));

        let completed = match crate::WalkingSkeletonRunnerLifecycle::cleanup_unadmitted_sprint_application_applier_launch(
            &mut owner,
            &mut ledger,
            crate::WalkingSkeletonUnadmittedApplicationApplierCleanup {
                sprint_spec: &harness.sprint_spec,
                launch_id: &cleanup_admission.launch.launch_id,
                final_verification_receipt_id: &final_verification_receipt_id,
                base_snapshot: &request.change_set.base_snapshot,
                cleanup_at_unix_ms,
            },
        )
        .expect("same-process active trusted Applier closes atomically")
        {
            crate::WalkingSkeletonUnadmittedApplicationApplierCleanupOutcome::Completed(
                completed,
            ) => completed,
            crate::WalkingSkeletonUnadmittedApplicationApplierCleanupOutcome::CleanupRequired {
                reason,
            } => panic!("same-process trusted-Applier cleanup remained pending: {reason}"),
        };
        assert_eq!((prepare_count.get(), release_count.get()), (1, 1));
        assert_eq!(native_cleanup_count.get(), 1);
        assert_eq!(completed.intent, cleanup_admission.cleanup_effect.intent);
        assert_eq!(
            ledger
                .load_effect(&cleanup_admission.cleanup_effect.intent.effect_id)
                .expect("reload same-process trusted-Applier cleanup terminal"),
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
        reason = "the retained-custody regression keeps native failure, crossed refusal, exact retry, and durable readback in one audit"
    )]
    fn lifecycle_owner_unadmitted_application_applier_retains_exact_custody_across_crossed_retry() {
        let label = "lifecycle-owner-unadmitted-application-retained-crossed";
        let UnadmittedApplicationOwnerFixture {
            harness,
            mut ledger,
            final_verification_receipt_id,
            request,
            stage_bundle,
            cleanup_admission,
            cleanup_at_unix_ms,
            active,
            crossed_launch_id,
            prepare_count,
            release_count,
            native_cleanup_count,
            ..
        } = active_unadmitted_application_fixture(
            label,
            ScriptedNativeCleanupMutation::FailOnceBeforeObservation,
        );
        let crossed_launch_id =
            crossed_launch_id.expect("active fixture retains a second open Applier launch");
        let crossed_cleanup_admission = ledger
            .load_runner_launch_cleanup_admission(&harness.sprint_id, &crossed_launch_id)
            .expect("reload crossed unadmitted trusted-Applier launch");
        let (launch_request, client) = active.expect("fixture retains exact live trusted Applier");
        let mut owner = DesktopRunnerLifecycleOwner::from_active_application_applier_for_test(
            RunnerLifecycleOwnerConfig {
                runner_binary: harness.runner_binary.clone(),
                private_state_root: harness.private_state.clone(),
            },
            launch_request,
            client,
            request.clone(),
            stage_bundle,
        )
        .expect("construct fail-once active trusted-Applier owner");

        let first = crate::WalkingSkeletonRunnerLifecycle::cleanup_unadmitted_sprint_application_applier_launch(
            &mut owner,
            &mut ledger,
            crate::WalkingSkeletonUnadmittedApplicationApplierCleanup {
                sprint_spec: &harness.sprint_spec,
                launch_id: &cleanup_admission.launch.launch_id,
                final_verification_receipt_id: &final_verification_receipt_id,
                base_snapshot: &request.change_set.base_snapshot,
                cleanup_at_unix_ms,
            },
        )
        .expect("transient native failure becomes exact retained cleanup custody");
        assert!(matches!(
            first,
            crate::WalkingSkeletonUnadmittedApplicationApplierCleanupOutcome::CleanupRequired { .. }
        ));
        assert_eq!(native_cleanup_count.get(), 1);
        assert!(matches!(
            owner.state(),
            DesktopRunnerLifecycleStateView::ApplicationCleanupRequired { ref binding, cleanup }
                if binding.launch_id == cleanup_admission.launch.launch_id
                    && cleanup.has_native_cleanup_custody()
        ));

        let crossed = crate::WalkingSkeletonRunnerLifecycle::cleanup_unadmitted_sprint_application_applier_launch(
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
        .expect_err("crossed launch must not consume retained trusted-Applier custody");
        assert!(
            matches!(
            &crossed,
            crate::DurableCoordinatorError::Protocol(message)
                if message
                    == "unadmitted trusted-Applier cleanup crossed retained cleanup authority"
            ),
            "unexpected crossed retained-custody error: {crossed:?}"
        );
        assert_eq!(native_cleanup_count.get(), 1);
        assert!(
            crossed_cleanup_admission
                .cleanup_effect
                .observation
                .is_none()
        );
        assert!(matches!(
            owner.state(),
            DesktopRunnerLifecycleStateView::ApplicationCleanupRequired { ref binding, cleanup }
                if binding.launch_id == cleanup_admission.launch.launch_id
                    && cleanup.has_native_cleanup_custody()
        ));

        let completed = match crate::WalkingSkeletonRunnerLifecycle::cleanup_unadmitted_sprint_application_applier_launch(
            &mut owner,
            &mut ledger,
            crate::WalkingSkeletonUnadmittedApplicationApplierCleanup {
                sprint_spec: &harness.sprint_spec,
                launch_id: &cleanup_admission.launch.launch_id,
                final_verification_receipt_id: &final_verification_receipt_id,
                base_snapshot: &request.change_set.base_snapshot,
                cleanup_at_unix_ms: cleanup_at_unix_ms.saturating_add(2),
            },
        )
        .expect("exact retained trusted-Applier custody completes on retry")
        {
            crate::WalkingSkeletonUnadmittedApplicationApplierCleanupOutcome::Completed(
                completed,
            ) => completed,
            crate::WalkingSkeletonUnadmittedApplicationApplierCleanupOutcome::CleanupRequired {
                reason,
            } => panic!("retained trusted-Applier cleanup remained pending: {reason}"),
        };
        assert_eq!((prepare_count.get(), release_count.get()), (1, 1));
        assert_eq!(native_cleanup_count.get(), 2);
        assert_eq!(
            ledger
                .load_effect(&cleanup_admission.cleanup_effect.intent.effect_id)
                .expect("reload retained trusted-Applier cleanup terminal"),
            completed
        );
        assert_eq!(
            ledger
                .load_effect(&crossed_cleanup_admission.cleanup_effect.intent.effect_id)
                .expect("crossed trusted-Applier launch remains open"),
            crossed_cleanup_admission.cleanup_effect
        );
        assert!(matches!(
            owner.state(),
            DesktopRunnerLifecycleStateView::Idle
        ));
    }

    #[test]
    fn lifecycle_owner_unadmitted_application_applier_missing_reopener_writes_nothing() {
        let label = "lifecycle-owner-unadmitted-application-missing-reopener";
        let UnadmittedApplicationOwnerFixture {
            harness,
            mut ledger,
            final_verification_receipt_id,
            request,
            cleanup_admission,
            cleanup_at_unix_ms,
            ..
        } = restart_unadmitted_application_fixture(label, true);
        let pending = ledger
            .load_effect(&cleanup_admission.cleanup_effect.intent.effect_id)
            .expect("load pending unadmitted trusted-Applier cleanup");
        let mut owner = DesktopRunnerLifecycleOwner::new(RunnerLifecycleOwnerConfig {
            runner_binary: harness.runner_binary.clone(),
            private_state_root: harness.private_state.clone(),
        })
        .expect("construct trusted-Applier restart owner without reopener");
        let outcome = crate::WalkingSkeletonRunnerLifecycle::cleanup_unadmitted_sprint_application_applier_launch(
            &mut owner,
            &mut ledger,
            crate::WalkingSkeletonUnadmittedApplicationApplierCleanup {
                sprint_spec: &harness.sprint_spec,
                launch_id: &cleanup_admission.launch.launch_id,
                final_verification_receipt_id: &final_verification_receipt_id,
                base_snapshot: &request.change_set.base_snapshot,
                cleanup_at_unix_ms,
            },
        )
        .expect("missing reopener is an exact cleanup-required stop");
        assert!(matches!(
            outcome,
            crate::WalkingSkeletonUnadmittedApplicationApplierCleanupOutcome::CleanupRequired { ref reason }
                if reason.contains("reopener")
        ));
        assert_eq!(
            ledger
                .load_effect(&cleanup_admission.cleanup_effect.intent.effect_id)
                .expect("missing reopener leaves trusted-Applier cleanup pending"),
            pending
        );
        assert!(matches!(
            owner.state(),
            DesktopRunnerLifecycleStateView::Idle
        ));
    }

    #[test]
    fn lifecycle_owner_unadmitted_application_applier_crossed_reopener_has_no_native_effect() {
        let label = "lifecycle-owner-unadmitted-application-crossed-reopener";
        let UnadmittedApplicationOwnerFixture {
            harness,
            mut ledger,
            final_verification_receipt_id,
            request,
            cleanup_admission,
            mut cleanup_authority,
            cleanup_at_unix_ms,
            ..
        } = restart_unadmitted_application_fixture(label, true);
        cleanup_authority.expected_platform_binding_digest =
            Digest::sha256(b"crossed-unadmitted-application-applier-cleanup-authority");
        let pending = cleanup_admission.cleanup_effect.clone();
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
        .expect("construct crossed trusted-Applier cleanup reopener");

        for requested_at_unix_ms in [cleanup_at_unix_ms, cleanup_at_unix_ms.saturating_add(1)] {
            let outcome = crate::WalkingSkeletonRunnerLifecycle::cleanup_unadmitted_sprint_application_applier_launch(
                &mut owner,
                &mut ledger,
                crate::WalkingSkeletonUnadmittedApplicationApplierCleanup {
                    sprint_spec: &harness.sprint_spec,
                    launch_id: &cleanup_admission.launch.launch_id,
                    final_verification_receipt_id: &final_verification_receipt_id,
                    base_snapshot: &request.change_set.base_snapshot,
                    cleanup_at_unix_ms: requested_at_unix_ms,
                },
            )
            .expect("crossed reopened trusted-Applier custody remains cleanup-required");
            assert!(matches!(
                outcome,
                crate::WalkingSkeletonUnadmittedApplicationApplierCleanupOutcome::CleanupRequired { .. }
            ));
            assert_eq!(reopen_count.get(), 1);
            assert_eq!(cleanup_count.get(), 0);
            assert_eq!(claims.borrow().len(), 1);
            assert_eq!(
                ledger
                    .load_effect(&cleanup_admission.cleanup_effect.intent.effect_id)
                    .expect("crossed reopener leaves trusted-Applier cleanup pending"),
                pending
            );
            assert!(matches!(
                owner.state(),
                DesktopRunnerLifecycleStateView::ApplicationCleanupRequired { cleanup, .. }
                    if cleanup.has_native_cleanup_custody()
            ));
        }
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "the collision regression keeps the exact admitted phase, live Applier, callback fence, durable cleanup, and owner custody visible"
    )]
    fn lifecycle_owner_unadmitted_application_applier_admitted_phase_collision_preserves_active_custody()
     {
        let label = "lifecycle-owner-unadmitted-application-admitted-collision";
        let UnadmittedApplicationOwnerFixture {
            harness,
            mut ledger,
            final_verification_receipt_id,
            final_verification_terminal,
            request,
            stage_bundle,
            artifact_assembly_id,
            cleanup_admission,
            cleanup_at_unix_ms,
            active,
            crossed_launch_id,
            prepare_count,
            release_count,
            native_cleanup_count,
            ..
        } = active_unadmitted_application_fixture(label, ScriptedNativeCleanupMutation::Exact);
        let (launch_request, client) = active.expect("fixture retains exact live trusted Applier");
        let mut owner = DesktopRunnerLifecycleOwner::from_active_application_applier_for_test(
            RunnerLifecycleOwnerConfig {
                runner_binary: harness.runner_binary.clone(),
                private_state_root: harness.private_state.clone(),
            },
            launch_request,
            client,
            request.clone(),
            stage_bundle,
        )
        .expect("construct active trusted-Applier collision owner");
        let registered_at_unix_ms = ledger
            .load_runner_session(
                &cleanup_admission.launch.sprint_id,
                &cleanup_admission.launch.session_id,
            )
            .expect("reload admitted-collision trusted-Applier session")
            .registered_at_unix_ms;
        let collision_at_unix_ms = cleanup_at_unix_ms.max(registered_at_unix_ms);
        let unrelated_launch_id =
            crossed_launch_id.expect("collision fixture retains its earlier manual Applier launch");
        let unrelated_admission = ledger
            .load_runner_launch_cleanup_admission(&harness.sprint_id, &unrelated_launch_id)
            .expect("reload unrelated manual trusted-Applier cleanup admission");
        let unrelated_session = ledger
            .load_runner_session(&harness.sprint_id, &unrelated_admission.launch.session_id)
            .expect("reload unrelated manual trusted-Applier session");
        persist_cleanup_evidence(
            &mut ledger,
            &CompletionRoleAdmission {
                launch: unrelated_admission.launch.clone(),
                cleanup_request: unrelated_admission.cleanup_request.clone(),
                cleanup_intent: unrelated_admission.cleanup_effect.intent.clone(),
                cleanup_proposed_event_id: unrelated_admission
                    .cleanup_effect
                    .proposed_event
                    .event_id
                    .clone(),
                session: unrelated_session.clone(),
                task_attempt_running: None,
            },
            &unrelated_session,
            None,
            &format!("cleanup-unrelated-{label}"),
            collision_at_unix_ms,
        );
        let request_bytes =
            serde_json::to_vec(&request).expect("encode admitted collision application request");
        let phase_sequence = ledger
            .next_sequence(&harness.sprint_id)
            .expect("next admitted collision phase sequence");
        let phase_event = AgentEvent {
            contract_version: CONTRACT_VERSION,
            sequence: phase_sequence,
            event_id: format!("sprint-applying-{label}"),
            sprint_id: harness.sprint_id.clone(),
            task_id: None,
            worker_id: None,
            causation_id: Some(final_verification_terminal.event_id),
            correlation_id: format!("correlation-application-{label}"),
            policy_hash: Some(cleanup_admission.launch.policy_hash.clone()),
            occurred_at_unix_ms: collision_at_unix_ms,
            payload: AgentEventKind::SprintStateChanged {
                from: "FinalVerification".into(),
                to: "Applying".into(),
            },
        };
        let intent = EffectIntent {
            contract_version: CONTRACT_VERSION,
            effect_id: format!("application-effect-{label}"),
            idempotency_key: format!("application-key-{label}"),
            sprint_id: harness.sprint_id.clone(),
            task_id: None,
            worker_id: None,
            worker_lease: None,
            causation_event_id: Some(phase_event.event_id.clone()),
            correlation_id: phase_event.correlation_id.clone(),
            kind: EffectKind::ApplyChangeSet,
            request_digest: Digest::sha256(&request_bytes),
            policy_hash: cleanup_admission.launch.policy_hash.clone(),
            input_snapshot: request.change_set.base_snapshot.clone(),
            created_at_unix_ms: collision_at_unix_ms,
        };
        let proposed = proposal(&intent, phase_sequence.saturating_add(1));
        let admission = SprintApplicationAdmission {
            contract_version: CONTRACT_VERSION,
            admission_id: format!("application-admission-{label}"),
            sprint_id: harness.sprint_id.clone(),
            sprint_phase_event_id: phase_event.event_id.clone(),
            final_verification_receipt_id: final_verification_receipt_id.clone(),
            artifact_assembly_id,
            effect_id: intent.effect_id.clone(),
            runner_launch_id: cleanup_admission.launch.launch_id.clone(),
            runner_session_id: cleanup_admission.launch.session_id.clone(),
            request: request.clone(),
            admitted_at_unix_ms: collision_at_unix_ms,
        };
        let SprintApplicationDispatchAdmission::Fresh { permit, .. } = ledger
            .admit_sprint_application_for_dispatch(&admission, &phase_event, &intent, &proposed)
            .expect("admit exact application phase before unadmitted collision")
        else {
            panic!("fresh admitted collision must mint one application permit")
        };
        drop(permit);
        let pending = cleanup_admission.cleanup_effect.clone();

        let collision = crate::WalkingSkeletonRunnerLifecycle::cleanup_unadmitted_sprint_application_applier_launch(
            &mut owner,
            &mut ledger,
            crate::WalkingSkeletonUnadmittedApplicationApplierCleanup {
                sprint_spec: &harness.sprint_spec,
                launch_id: &cleanup_admission.launch.launch_id,
                final_verification_receipt_id: &final_verification_receipt_id,
                base_snapshot: &request.change_set.base_snapshot,
                cleanup_at_unix_ms: collision_at_unix_ms.saturating_add(1),
            },
        )
        .expect_err("admitted application phase must fence the unadmitted cleanup seam");
        assert!(matches!(
            collision,
            crate::DurableCoordinatorError::Ledger(LedgerError::ReferenceMismatch { .. })
        ));
        assert_eq!((prepare_count.get(), release_count.get()), (1, 1));
        assert_eq!(native_cleanup_count.get(), 0);
        assert_eq!(
            ledger
                .load_effect(&cleanup_admission.cleanup_effect.intent.effect_id)
                .expect("admitted collision leaves rightful cleanup pending"),
            pending
        );
        assert!(matches!(
            owner.state(),
            DesktopRunnerLifecycleStateView::ActiveApplicationApplier { ref binding }
                if binding.launch_id == cleanup_admission.launch.launch_id
                    && binding.session_id == cleanup_admission.launch.session_id
        ));
    }

    struct RestartTerminalFinalVerifierCleanupFixture {
        harness: TestHarness,
        ledger: EventLedger,
        admission: SprintFinalVerificationAdmission,
        completed: PersistedEffect,
        cleanup_admission: PersistedRunnerLaunchCleanupAdmission,
        cleanup_authority: NativeLaunchCleanupAuthority,
        cleanup_at_unix_ms: u64,
        prepare_count: Rc<Cell<u64>>,
        release_count: Rc<Cell<u64>>,
    }

    #[allow(
        clippy::too_many_lines,
        reason = "the fixture constructs the exact TaskDone, native final-verifier launch, claimed terminal, and command-domain proof needed to exercise production restart cleanup"
    )]
    fn restart_terminal_final_verifier_cleanup_fixture(
        label: &str,
    ) -> RestartTerminalFinalVerifierCleanupFixture {
        let mut integrated =
            restart_integrated_native_cleanup_fixture(&format!("{label}-integrated"));
        let worker_reopen_count = Rc::new(Cell::new(0));
        let worker_cleanup_count = Rc::new(Cell::new(0));
        let worker_claims = Rc::new(RefCell::new(Vec::new()));
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
                claims: worker_claims,
            }),
        )
        .expect("construct TaskDone cleanup owner");
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
        assert_eq!(worker_reopen_count.get(), 1);
        assert_eq!(worker_cleanup_count.get(), 1);
        assert!(matches!(
            worker_owner.state(),
            DesktopRunnerLifecycleStateView::Idle
        ));

        let TaskAttemptDisposition::Integrated(task_integrated) = &integrated.disposition else {
            unreachable!("terminal final-verifier fixture starts from Integrated")
        };
        let final_snapshot = task_integrated.integration_receipt.result_snapshot.clone();
        let final_policy = read_only_policy(&integrated.harness, &format!("{label}-policy"));
        let prepare_count = Rc::new(Cell::new(0));
        let release_count = Rc::new(Cell::new(0));
        let launch_cleanup_count = Rc::new(Cell::new(0));
        let service = AdversarialNativeLaunchService::new(
            RunnerLaunchPreparationDisposition::HeldChildPrepared,
            NativeReleaseMutation::Exact,
            transport(
                unique_nonce(&format!("{label}-final-verifier")),
                integrated.harness.identity(),
                ScriptMode::Good,
                true,
                Vec::new(),
            ),
            Rc::clone(&prepare_count),
            Rc::clone(&release_count),
        )
        .with_cleanup_script(launch_cleanup_count, ScriptedNativeCleanupMutation::Exact);
        let mut request = integrated
            .harness
            .launch(&format!("{label}-final-verifier"));
        request.role = RunnerRole::FinalVerifier;
        request.worker_id = None;
        request.worker_lease = None;
        request.expected_base_snapshot = final_snapshot.clone();
        request.created_at_unix_ms = task_integrated
            .integration_receipt
            .integrated_at_unix_ms
            .saturating_add(10);
        let client = RunnerLifecycleClient::launch_with_native_service(
            &mut integrated.ledger,
            &integrated.harness.authority,
            &final_policy,
            request,
            Box::new(service),
        )
        .expect("launch exact native final verifier");
        assert_eq!(prepare_count.get(), 1);
        assert_eq!(release_count.get(), 1);
        let cleanup_admission = client
            .launch_cleanup_admission()
            .expect("final verifier retains its atomic cleanup admission")
            .clone();
        let preparation = integrated
            .ledger
            .load_runner_launch_preparation(
                &cleanup_admission.launch.sprint_id,
                &cleanup_admission.launch.launch_id,
            )
            .expect("reload final-verifier native preparation");
        let cleanup_authority = NativeLaunchCleanupAuthority::from_expected_state(
            &cleanup_admission,
            Some(&preparation),
            client
                .platform_launch_binding
                .as_deref()
                .expect("final verifier retains exact platform binding"),
        );
        let session = client.session().clone();

        let command = CommandSpec {
            program: "true".into(),
            arguments: Vec::new(),
            working_directory: PathBuf::new(),
        };
        let command_bytes =
            serde_json::to_vec(&command).expect("encode terminal final-verifier command");
        let phase_at_unix_ms = session.registered_at_unix_ms.saturating_add(10);
        let (awaiting_event, _) = persist_one_to_one_human_acceptance(
            &mut integrated.ledger,
            &cleanup_admission.launch,
            "criterion-1",
            &final_snapshot,
            label,
            phase_at_unix_ms.saturating_sub(1),
            phase_at_unix_ms,
        );
        let phase_sequence = integrated
            .ledger
            .next_sequence(&integrated.harness.sprint_id)
            .expect("next terminal final-verification phase sequence");
        let phase_event = AgentEvent {
            contract_version: CONTRACT_VERSION,
            sequence: phase_sequence,
            event_id: format!("event-terminal-final-verification-{label}"),
            sprint_id: integrated.harness.sprint_id.clone(),
            task_id: None,
            worker_id: None,
            causation_id: Some(awaiting_event.event_id),
            correlation_id: format!("correlation-terminal-final-verification-{label}"),
            policy_hash: Some(final_policy.contract().policy_hash.clone()),
            occurred_at_unix_ms: phase_at_unix_ms,
            payload: AgentEventKind::SprintStateChanged {
                from: "AwaitingAcceptance".into(),
                to: "FinalVerification".into(),
            },
        };
        let admitted_at_unix_ms = phase_at_unix_ms.saturating_add(1);
        let intent = EffectIntent {
            contract_version: CONTRACT_VERSION,
            effect_id: format!("effect-terminal-final-verification-{label}"),
            idempotency_key: format!("key-terminal-final-verification-{label}"),
            sprint_id: integrated.harness.sprint_id.clone(),
            task_id: None,
            worker_id: None,
            worker_lease: None,
            causation_event_id: Some(phase_event.event_id.clone()),
            correlation_id: phase_event.correlation_id.clone(),
            kind: EffectKind::RunCommand,
            request_digest: Digest::sha256(&command_bytes),
            policy_hash: final_policy.contract().policy_hash.clone(),
            input_snapshot: final_snapshot.clone(),
            created_at_unix_ms: admitted_at_unix_ms,
        };
        let proposed = proposal(&intent, phase_sequence.saturating_add(1));
        let admission = SprintFinalVerificationAdmission {
            contract_version: CONTRACT_VERSION,
            admission_id: format!("admission-terminal-final-verification-{label}"),
            sprint_id: integrated.harness.sprint_id.clone(),
            sprint_phase_event_id: phase_event.event_id.clone(),
            final_snapshot,
            effect_id: intent.effect_id.clone(),
            runner_launch_id: cleanup_admission.launch.launch_id.clone(),
            runner_session_id: session.session_id.clone(),
            command,
            admitted_at_unix_ms,
        };
        let output_capture_intent = fresh_command_output_capture_intent(
            &intent,
            &cleanup_admission.launch,
            &session,
            &final_policy,
        )
        .expect("construct terminal final-verification capture intent");
        let SprintFinalVerificationDispatchAdmission::Fresh { permit, .. } = integrated
            .ledger
            .admit_sprint_final_verification_with_output_capture_for_dispatch(
                &admission,
                &phase_event,
                &intent,
                &proposed,
                &output_capture_intent,
            )
            .expect("admit terminal final-verification command")
        else {
            panic!("terminal final-verification fixture must be fresh")
        };
        let dispatch_permit = FreshRunnerEffectDispatchPermit::SprintFinalVerification(permit);
        let dispatch_claim_id = dispatch_permit
            .expected_output_capture_dispatch_claim_id()
            .expect("terminal final-verification permit carries capture authority");
        let output_store = CapabilityCommandOutputStore::open(&integrated.harness.private_state)
            .expect("open exact terminal final-verification output store");
        let acquired = output_store
            .reserve_anchored_capture(
                &output_capture_intent,
                &dispatch_claim_id,
                admitted_at_unix_ms,
            )
            .expect("reserve terminal final-verification output capture")
            .into_acquired_anchor_for_handoff()
            .expect("synchronize terminal final-verification acquisition");
        let (_, transport_authority) = integrated
            .ledger
            .claim_command_output_capture_dispatch(
                dispatch_permit,
                acquired.clone(),
                &command_bytes,
            )
            .expect("claim terminal final-verification dispatch");
        let observation_authority = transport_authority
            .validate_transport_request(
                &intent,
                &command_bytes,
                &cleanup_admission.launch,
                &session,
                None,
                &command_bytes,
            )
            .expect("validate terminal final-verification transport authority");
        let failure_evidence =
            format!("no final-verification request bytes were accepted for {label}").into_bytes();
        let observed_at_unix_ms = admitted_at_unix_ms.saturating_add(1);
        let observed = observation(
            &intent,
            format!("observation-terminal-final-verification-{label}"),
            EffectOutcome::FailedBeforeEffect {
                evidence_digest: Digest::sha256(&failure_evidence),
            },
            observed_at_unix_ms,
        );
        let reconciliation_claim_id =
            Digest::sha256(format!("terminal-final-verifier-cleanup-{label}").as_bytes())
                .as_str()
                .to_owned();
        let CommandOutputCaptureReconciliationAdmission::Fresh {
            claim: reconciliation_claim,
            permit: reconciliation_permit,
        } = integrated
            .ledger
            .claim_command_output_capture_reconciliation(
                &output_capture_intent.capture_id,
                &reconciliation_claim_id,
                "runner-client-test-terminal-final-verifier",
                observed_at_unix_ms,
                observed_at_unix_ms.saturating_add(1_000),
            )
            .expect("claim exact zero-byte capture cleanup authority")
        else {
            panic!("fresh terminal final-verifier capture requires one cleanup claim")
        };
        let cleaned_capture = output_store
            .cleanup_capture(&reconciliation_claim, &acquired.store_head)
            .expect("clean exact zero-byte terminal final-verification capture");
        let command_cleaned_at_unix_ms = observed_at_unix_ms.saturating_add(1);
        integrated
            .ledger
            .release_command_output_capture_reconciliation(
                reconciliation_permit,
                command_cleaned_at_unix_ms,
            )
            .expect("release exact zero-byte capture cleanup fence");
        let capture_terminal = CommandOutputCaptureTerminalAnchorV1::try_new(
            &output_capture_intent,
            Some(&acquired),
            &observed,
            CommandOutputCaptureTerminalDispositionV1::Abandoned,
            cleaned_capture
                .cleaned_store_head()
                .expect("zero-byte cleanup exposes exact Cleaned head")
                .clone(),
            cleaned_capture
                .cleaned_record_digest()
                .expect("zero-byte cleanup exposes exact Cleaned record digest")
                .clone(),
            None,
            command_cleaned_at_unix_ms,
        )
        .expect("construct exact abandoned terminal final-verification capture");
        let terminal = terminal_event(&integrated.ledger, &intent, &proposed.event_id, &observed);
        let backend = match cleanup_admission.cleanup_request.platform_backend {
            WorkerCleanupBackend::MacOsDedicatedIdentity => {
                CommandDomainBackend::MacOsDedicatedIdentity
            }
            WorkerCleanupBackend::LinuxCgroupV2 => CommandDomainBackend::LinuxCgroupV2,
            WorkerCleanupBackend::TrustedApplierDirectChildWait => {
                panic!("final verifier cannot use trusted-Applier cleanup")
            }
        };
        let platform_proof_bytes =
            format!("no final-verifier command domain was created for {label}").into_bytes();
        let command_cleanup = CommandDomainCleanupProof {
            contract_version: CONTRACT_VERSION,
            proof_id: format!("proof-terminal-final-verification-{label}"),
            sprint_id: admission.sprint_id.clone(),
            launch_id: admission.runner_launch_id.clone(),
            session_id: admission.runner_session_id.clone(),
            effect_id: intent.effect_id.clone(),
            observation_id: Some(observed.observation_id.clone()),
            request_digest: intent.request_digest.clone(),
            backend,
            disposition: CommandDomainCleanupDisposition::NoDomainCreatedBeforeEffect,
            surviving_processes: 0,
            platform_proof_digest: Digest::sha256(&platform_proof_bytes),
            platform_proof_bytes,
            cleaned_at_unix_ms: command_cleaned_at_unix_ms,
        };
        let completed = integrated
            .ledger
            .record_claimed_command_effect_observation_with_output_capture(
                observation_authority,
                &observed,
                &failure_evidence,
                &terminal,
                &capture_terminal,
                None,
                &command_cleanup,
            )
            .expect("persist claimed FailedBeforeEffect final verification and capture");
        let bindings = integrated
            .ledger
            .load_command_domain_effect_bindings(
                &admission.sprint_id,
                &admission.runner_launch_id,
                &admission.runner_session_id,
            )
            .expect("load terminal final-verifier command binding");
        let [binding] = bindings.as_slice() else {
            panic!("terminal final verifier must bind exactly one RunCommand")
        };
        assert_eq!(binding.effect_id, completed.intent.effect_id);

        // The original process-local final-verifier client is gone. Only the
        // durable journal and an admitted cleanup-only reopener remain.
        drop(client);
        RestartTerminalFinalVerifierCleanupFixture {
            harness: integrated.harness,
            ledger: integrated.ledger,
            admission,
            completed,
            cleanup_admission,
            cleanup_authority,
            cleanup_at_unix_ms: command_cleaned_at_unix_ms.saturating_add(1),
            prepare_count,
            release_count,
        }
    }
